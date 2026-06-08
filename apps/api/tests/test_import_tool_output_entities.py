"""Integration tests: _import_tool_output must persist Entity rows when create_entities=True
and must not create duplicates on repeated import of identical output."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from sqlalchemy import select

from adbygod_api.core.ai_operator.tools.exec_tools import HANDLERS
from adbygod_api.models import Entity

_AUTHZ = "adbygod_api.core.security.authorization.require_assessment_write_access"

NMAP_OUTPUT = (
    "Nmap scan report for WS99.corp.local (10.0.0.9)\n"
    "88/tcp open  kerberos-sec\n"
    "445/tcp open  microsoft-ds\n"
)

NXC_OUTPUT = (
    "SMB  10.0.0.5  445  DC01  [+] corp.local\\admin:Password1 (Pwn3d!)\n"
)


@pytest.mark.asyncio
async def test_import_nmap_creates_entity_row(test_app):
    factory = test_app["db"]
    sm = test_app["session_maker"]

    user = await factory.create_user("importer", "import@corp.local", is_superadmin=True)
    assessment = await factory.create_assessment(
        "ImportTest", "corp.local", workspace_id=None, created_by=user.id
    )
    aid = str(assessment.id)

    async with sm() as session:
        ctx = MagicMock()
        ctx.assessment_id = aid
        ctx.current_user = user
        ctx.db = session
        ctx.memory_store = None

        with patch(_AUTHZ, new=AsyncMock()):
            result = await HANDLERS["import_tool_output"](
                {"tool_name": "nmap", "raw_output": NMAP_OUTPUT,
                 "create_entities": True, "assessment_id": aid},
                ctx,
            )

    assert result["entities_parsed"] == 1
    assert result["entities_created"] == 1

    async with sm() as session:
        rows = (await session.execute(
            select(Entity).where(Entity.assessment_id == assessment.id)
        )).scalars().all()
    assert len(rows) == 1
    assert rows[0].entity_type.value == "COMPUTER"


@pytest.mark.asyncio
async def test_import_nmap_duplicate_not_created(test_app):
    factory = test_app["db"]
    sm = test_app["session_maker"]

    user = await factory.create_user("importer2", "import2@corp.local", is_superadmin=True)
    assessment = await factory.create_assessment(
        "DedupTest", "corp.local", workspace_id=None, created_by=user.id
    )
    aid = str(assessment.id)

    args = {"tool_name": "nmap", "raw_output": NMAP_OUTPUT,
            "create_entities": True, "assessment_id": aid}

    # First import
    async with sm() as session:
        ctx = MagicMock()
        ctx.assessment_id = aid
        ctx.current_user = user
        ctx.db = session
        ctx.memory_store = None
        with patch(_AUTHZ, new=AsyncMock()):
            r1 = await HANDLERS["import_tool_output"](args, ctx)

    assert r1["entities_created"] == 1

    # Second import — same output
    async with sm() as session:
        ctx2 = MagicMock()
        ctx2.assessment_id = aid
        ctx2.current_user = user
        ctx2.db = session
        ctx2.memory_store = None
        with patch(_AUTHZ, new=AsyncMock()):
            r2 = await HANDLERS["import_tool_output"](args, ctx2)

    assert r2["entities_created"] == 0

    async with sm() as session:
        rows = (await session.execute(
            select(Entity).where(Entity.assessment_id == assessment.id)
        )).scalars().all()
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_import_nxc_creates_entity_row(test_app):
    factory = test_app["db"]
    sm = test_app["session_maker"]

    user = await factory.create_user("importer3", "import3@corp.local", is_superadmin=True)
    assessment = await factory.create_assessment(
        "NxcTest", "corp.local", workspace_id=None, created_by=user.id
    )
    aid = str(assessment.id)

    async with sm() as session:
        ctx = MagicMock()
        ctx.assessment_id = aid
        ctx.current_user = user
        ctx.db = session
        ctx.memory_store = None
        with patch(_AUTHZ, new=AsyncMock()):
            result = await HANDLERS["import_tool_output"](
                {"tool_name": "nxc", "raw_output": NXC_OUTPUT,
                 "create_entities": True, "assessment_id": aid},
                ctx,
            )

    assert result["entities_created"] == 1

    async with sm() as session:
        rows = (await session.execute(
            select(Entity).where(Entity.assessment_id == assessment.id)
        )).scalars().all()
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_import_create_entities_false_does_not_persist(test_app):
    factory = test_app["db"]
    sm = test_app["session_maker"]

    user = await factory.create_user("importer4", "import4@corp.local", is_superadmin=True)
    assessment = await factory.create_assessment(
        "NoEntityTest", "corp.local", workspace_id=None, created_by=user.id
    )
    aid = str(assessment.id)

    async with sm() as session:
        ctx = MagicMock()
        ctx.assessment_id = aid
        ctx.current_user = user
        ctx.db = session
        ctx.memory_store = None
        with patch(_AUTHZ, new=AsyncMock()):
            result = await HANDLERS["import_tool_output"](
                {"tool_name": "nmap", "raw_output": NMAP_OUTPUT,
                 "create_entities": False, "assessment_id": aid},
                ctx,
            )

    assert result["entities_created"] == 0

    async with sm() as session:
        rows = (await session.execute(
            select(Entity).where(Entity.assessment_id == assessment.id)
        )).scalars().all()
    assert len(rows) == 0
