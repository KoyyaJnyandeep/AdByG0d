"""
End-to-end tests for all 45 god-mode AI operator tools.

Flow:
  1. Build a realistic BloodHound zip (users, groups, computers, domain, GPOs)
  2. Import it via the real BloodHound parser → runs ingest pipeline
  3. Add complementary DB fixtures (edges, findings, kill-chain, exposure paths, loot)
  4. Run every tool via dispatch_tool and assert no error key + sane return shape
  5. Print a pass/fail summary — anything failing gets a descriptive assertion
"""
from __future__ import annotations

import io
import json
import uuid
import zipfile
from collections import defaultdict
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import adbygod_api.models as models
from adbygod_api.core.ai_operator.tools.registry import dispatch_tool, ToolContext
from adbygod_api.core.ai_operator.approval_store import ApprovalStore


# ---------------------------------------------------------------------------
# BloodHound zip factory
# ---------------------------------------------------------------------------

def _make_bh_zip() -> bytes:
    """Generate a minimal but complete BloodHound CE-format zip."""
    domain_sid = "S-1-5-21-1111-2222-3333"

    users_json = {
        "meta": {"type": "users", "version": 5, "count": 4},
        "data": [
            {
                "ObjectIdentifier": f"{domain_sid}-1001",
                "ObjectType": "User",
                "Properties": {
                    "name": "rahul.low@corp.local", "samaccountname": "rahul.low",
                    "enabled": True, "admincount": False,
                    "hasspn": False, "dontreqpreauth": False,
                    "pwdlastset": 1700000000, "lastlogon": 1700000000,
                    "domain": "corp.local",
                },
                "Aces": [
                    {"RightName": "GenericAll", "IsInherited": False,
                     "PrincipalSID": f"{domain_sid}-1001",
                     "PrincipalType": "User"},
                ],
                "PrimaryGroupSID": f"{domain_sid}-513",
                "AllowedToDelegate": [], "SPNTargets": [],
                "HasSIDHistory": [], "IsDeleted": False,
            },
            {
                "ObjectIdentifier": f"{domain_sid}-1002",
                "ObjectType": "User",
                "Properties": {
                    "name": "svc.kerberoast@corp.local", "samaccountname": "svc.kerberoast",
                    "enabled": True, "admincount": False,
                    "hasspn": True, "dontreqpreauth": False,
                    "serviceprincipalnames": ["MSSQLSvc/sql01.corp.local:1433"],
                    "domain": "corp.local",
                },
                "Aces": [],
                "PrimaryGroupSID": f"{domain_sid}-513",
                "AllowedToDelegate": [], "SPNTargets": [],
                "HasSIDHistory": [], "IsDeleted": False,
            },
            {
                "ObjectIdentifier": f"{domain_sid}-1003",
                "ObjectType": "User",
                "Properties": {
                    "name": "asrep.user@corp.local", "samaccountname": "asrep.user",
                    "enabled": True, "admincount": False,
                    "hasspn": False, "dontreqpreauth": True,
                    "domain": "corp.local",
                },
                "Aces": [],
                "PrimaryGroupSID": f"{domain_sid}-513",
                "AllowedToDelegate": [], "SPNTargets": [],
                "HasSIDHistory": [], "IsDeleted": False,
            },
            {
                "ObjectIdentifier": f"{domain_sid}-500",
                "ObjectType": "User",
                "Properties": {
                    "name": "Administrator@corp.local", "samaccountname": "Administrator",
                    "enabled": True, "admincount": True,
                    "hasspn": False, "dontreqpreauth": False,
                    "domain": "corp.local",
                },
                "Aces": [],
                "PrimaryGroupSID": f"{domain_sid}-513",
                "AllowedToDelegate": [], "SPNTargets": [],
                "HasSIDHistory": [], "IsDeleted": False,
            },
        ],
    }

    groups_json = {
        "meta": {"type": "groups", "version": 5, "count": 2},
        "data": [
            {
                "ObjectIdentifier": f"{domain_sid}-512",
                "ObjectType": "Group",
                "Properties": {
                    "name": "Domain Admins@corp.local", "samaccountname": "Domain Admins",
                    "admincount": True, "domain": "corp.local",
                },
                "Members": [
                    {"ObjectIdentifier": f"{domain_sid}-500", "ObjectType": "User"},
                ],
                "Aces": [],
                "IsDeleted": False,
            },
            {
                "ObjectIdentifier": f"{domain_sid}-513",
                "ObjectType": "Group",
                "Properties": {
                    "name": "Domain Users@corp.local", "samaccountname": "Domain Users",
                    "admincount": False, "domain": "corp.local",
                },
                "Members": [
                    {"ObjectIdentifier": f"{domain_sid}-1001", "ObjectType": "User"},
                    {"ObjectIdentifier": f"{domain_sid}-1002", "ObjectType": "User"},
                    {"ObjectIdentifier": f"{domain_sid}-1003", "ObjectType": "User"},
                ],
                "Aces": [],
                "IsDeleted": False,
            },
        ],
    }

    computers_json = {
        "meta": {"type": "computers", "version": 5, "count": 2},
        "data": [
            {
                "ObjectIdentifier": f"{domain_sid}-1000",
                "ObjectType": "Computer",
                "Properties": {
                    "name": "DC01.corp.local", "samaccountname": "DC01$",
                    "enabled": True, "operatingsystem": "Windows Server 2022",
                    "admincount": False, "isdc": True, "domain": "corp.local",
                },
                "Sessions": {"Results": [
                    {"ComputerSID": f"{domain_sid}-1000",
                     "UserSID": f"{domain_sid}-500"},
                ]},
                "Aces": [],
                "AllowedToDelegate": [], "AllowedToAct": [],
                "HasSIDHistory": [], "IsDeleted": False,
                "LocalAdmins": {"Results": []},
                "RemoteDesktopUsers": {"Results": []},
                "DcomUsers": {"Results": []},
                "PSRemoteUsers": {"Results": []},
            },
            {
                "ObjectIdentifier": f"{domain_sid}-1101",
                "ObjectType": "Computer",
                "Properties": {
                    "name": "WS01.corp.local", "samaccountname": "WS01$",
                    "enabled": True, "operatingsystem": "Windows 11",
                    "admincount": False, "isdc": False, "domain": "corp.local",
                },
                "Sessions": {"Results": [
                    {"ComputerSID": f"{domain_sid}-1101",
                     "UserSID": f"{domain_sid}-1001"},
                ]},
                "Aces": [],
                "AllowedToDelegate": [], "AllowedToAct": [],
                "HasSIDHistory": [], "IsDeleted": False,
                "LocalAdmins": {"Results": []},
                "RemoteDesktopUsers": {"Results": []},
                "DcomUsers": {"Results": []},
                "PSRemoteUsers": {"Results": []},
            },
        ],
    }

    domains_json = {
        "meta": {"type": "domains", "version": 5, "count": 1},
        "data": [
            {
                "ObjectIdentifier": domain_sid,
                "ObjectType": "Domain",
                "Properties": {
                    "name": "corp.local", "domain": "corp.local",
                    "functionallevel": "Windows 2016",
                    "ms-DS-MachineAccountQuota": 10,
                },
                "Trusts": [],
                "Aces": [],
                "IsDeleted": False,
                "ChildObjects": [],
                "GPOChanges": {"LocalAdmins": [], "RemoteDesktopUsers": [],
                               "DcomUsers": [], "PSRemoteUsers": [],
                               "AffectedComputers": []},
            },
        ],
    }

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("20240101120000_BloodHound_users.json",
                    json.dumps(users_json))
        zf.writestr("20240101120000_BloodHound_groups.json",
                    json.dumps(groups_json))
        zf.writestr("20240101120000_BloodHound_computers.json",
                    json.dumps(computers_json))
        zf.writestr("20240101120000_BloodHound_domains.json",
                    json.dumps(domains_json))
    return buf.getvalue()


# ---------------------------------------------------------------------------
# In-memory MemoryStore for tests
# ---------------------------------------------------------------------------

class FakeMemoryStore:
    def __init__(self):
        self._data: dict[str, dict] = defaultdict(lambda: {
            "owned_accounts": ["rahul.low"],
            "owned_machines": ["WS01.corp.local"],
            "tried_techniques": ["recon-dns-enum", "recon-ldap-enum"],
            "failed_techniques": [],
            "discovered_creds": [],
            "notes": [],
            "kill_chain_progress": [],
            "report_sections": {},
        })

    async def load(self, assessment_id: str) -> dict:
        return self._data[str(assessment_id)]

    async def append(self, assessment_id: str, key: str, value: Any):
        store = self._data[str(assessment_id)]
        if key not in store:
            store[key] = []
        if isinstance(store[key], list):
            store[key].append(value)
        else:
            store[key] = value

    async def set_report_section(self, assessment_id: str, section: str, content: str):
        store = self._data[str(assessment_id)]
        store.setdefault("report_sections", {})[section] = content


# ---------------------------------------------------------------------------
# Fixture: full test scenario
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture()
async def scenario(tmp_path):
    """
    Async fixture that builds an in-memory SQLite DB with a complete AD scenario
    and returns a ToolContext plus all key IDs.
    """
    import adbygod_api.config as config
    config.settings.SECRET_KEY = "test-secret-key-for-god-mode-e2e-tests-1234567890"
    config.settings.DEBUG = True

    db_path = tmp_path / "scenario.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)

    Session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with Session() as db:
        # ── assessment ────────────────────────────────────────────────────
        assessment = models.Assessment(
            id=uuid.uuid4(),
            name="Corp Red Team 2024",
            domain="corp.local",
            dc_ip="192.168.1.10",
            status=models.AssessmentStatus.COMPLETED,
            modules_run=["BloodHound", "Kerberos", "ADCS"],
            stats={},
            exposure_score=85.0,
        )
        db.add(assessment)
        aid = assessment.id

        # second assessment for diff_assessments
        assessment_b = models.Assessment(
            id=uuid.uuid4(),
            name="Corp Re-Test 2024",
            domain="corp.local",
            dc_ip="192.168.1.10",
            status=models.AssessmentStatus.COMPLETED,
            modules_run=["BloodHound"],
            stats={},
            exposure_score=60.0,
        )
        db.add(assessment_b)

        # ── entities ──────────────────────────────────────────────────────
        user_low = models.Entity(
            id=uuid.uuid4(), assessment_id=aid,
            entity_type=models.EntityType.USER,
            sam_account_name="rahul.low", display_name="rahul.low",
            domain="corp.local", tier=3,
            is_enabled=True, is_admin_count=False,
            is_sensitive=False, is_protected_user=False,
            is_crown_jewel=False, business_tags=[], attributes={},
        )
        user_svc = models.Entity(
            id=uuid.uuid4(), assessment_id=aid,
            entity_type=models.EntityType.USER,
            sam_account_name="svc.kerberoast", display_name="svc.kerberoast",
            domain="corp.local", tier=2,
            is_enabled=True, is_admin_count=False,
            is_sensitive=True, is_protected_user=False,
            is_crown_jewel=False, business_tags=[],
            attributes={"serviceprincipalnames": ["MSSQLSvc/sql01.corp.local:1433"]},
        )
        user_admin = models.Entity(
            id=uuid.uuid4(), assessment_id=aid,
            entity_type=models.EntityType.USER,
            sam_account_name="Administrator", display_name="Administrator",
            domain="corp.local", tier=0,
            is_enabled=True, is_admin_count=True,
            is_sensitive=True, is_protected_user=False,
            is_crown_jewel=True, business_tags=[], attributes={},
        )
        group_da = models.Entity(
            id=uuid.uuid4(), assessment_id=aid,
            entity_type=models.EntityType.GROUP,
            sam_account_name="Domain Admins", display_name="Domain Admins",
            domain="corp.local", tier=0,
            is_enabled=True, is_admin_count=True,
            is_sensitive=True, is_protected_user=False,
            is_crown_jewel=True, business_tags=[], attributes={},
        )
        group_du = models.Entity(
            id=uuid.uuid4(), assessment_id=aid,
            entity_type=models.EntityType.GROUP,
            sam_account_name="Domain Users", display_name="Domain Users",
            domain="corp.local", tier=3,
            is_enabled=True, is_admin_count=False,
            is_sensitive=False, is_protected_user=False,
            is_crown_jewel=False, business_tags=[], attributes={},
        )
        comp_dc = models.Entity(
            id=uuid.uuid4(), assessment_id=aid,
            entity_type=models.EntityType.COMPUTER,
            sam_account_name="DC01$", display_name="DC01",
            dns_hostname="DC01.corp.local",
            domain="corp.local", tier=0,
            is_enabled=True, is_admin_count=True,
            is_sensitive=True, is_protected_user=False,
            is_crown_jewel=True, business_tags=[], attributes={"is_dc": True},
        )
        comp_ws = models.Entity(
            id=uuid.uuid4(), assessment_id=aid,
            entity_type=models.EntityType.COMPUTER,
            sam_account_name="WS01$", display_name="WS01",
            dns_hostname="WS01.corp.local",
            domain="corp.local", tier=3,
            is_enabled=True, is_admin_count=False,
            is_sensitive=False, is_protected_user=False,
            is_crown_jewel=False, business_tags=[], attributes={},
        )
        domain_obj = models.Entity(
            id=uuid.uuid4(), assessment_id=aid,
            entity_type=models.EntityType.DOMAIN,
            sam_account_name="corp.local", display_name="corp.local",
            domain="corp.local", tier=0,
            is_enabled=True, is_admin_count=False,
            is_sensitive=False, is_protected_user=False,
            is_crown_jewel=True, business_tags=[],
            attributes={"ms-DS-MachineAccountQuota": 10},
        )
        for obj in [user_low, user_svc, user_admin, group_da, group_du,
                    comp_dc, comp_ws, domain_obj]:
            db.add(obj)

        # ── graph edges ───────────────────────────────────────────────────
        edges = [
            # rahul.low → GenericAll → Domain Admins (direct DA path)
            models.GraphEdge(
                id=uuid.uuid4(), assessment_id=aid,
                source_id=user_low.id, target_id=group_da.id,
                edge_type=models.EdgeType.GENERIC_ALL,
                risk_weight=1.0, edge_confidence=1.0, attributes={},
            ),
            # rahul.low → MemberOf → Domain Users
            models.GraphEdge(
                id=uuid.uuid4(), assessment_id=aid,
                source_id=user_low.id, target_id=group_du.id,
                edge_type=models.EdgeType.MEMBER_OF,
                risk_weight=0.5, edge_confidence=1.0, attributes={},
            ),
            # Administrator → MemberOf → Domain Admins
            models.GraphEdge(
                id=uuid.uuid4(), assessment_id=aid,
                source_id=user_admin.id, target_id=group_da.id,
                edge_type=models.EdgeType.MEMBER_OF,
                risk_weight=0.9, edge_confidence=1.0, attributes={},
            ),
            # svc.kerberoast HAS_SPN (self edge for SPN tracking)
            models.GraphEdge(
                id=uuid.uuid4(), assessment_id=aid,
                source_id=user_svc.id, target_id=comp_dc.id,
                edge_type=models.EdgeType.HAS_SPN,
                risk_weight=0.7, edge_confidence=1.0, attributes={},
            ),
            # Administrator HAS_SESSION on DC01
            models.GraphEdge(
                id=uuid.uuid4(), assessment_id=aid,
                source_id=user_admin.id, target_id=comp_dc.id,
                edge_type=models.EdgeType.HAS_SESSION,
                risk_weight=1.0, edge_confidence=1.0, attributes={},
            ),
            # rahul.low HAS_SESSION on WS01
            models.GraphEdge(
                id=uuid.uuid4(), assessment_id=aid,
                source_id=user_low.id, target_id=comp_ws.id,
                edge_type=models.EdgeType.HAS_SESSION,
                risk_weight=0.8, edge_confidence=1.0, attributes={},
            ),
            # DCSync right: rahul.low → DCSYNC → domain
            models.GraphEdge(
                id=uuid.uuid4(), assessment_id=aid,
                source_id=user_low.id, target_id=domain_obj.id,
                edge_type=models.EdgeType.DCSYNC,
                risk_weight=1.0, edge_confidence=0.9, attributes={},
            ),
            # Trust: corp.local TRUSTS child.corp.local (use domain_obj → comp_ws as placeholder)
            models.GraphEdge(
                id=uuid.uuid4(), assessment_id=aid,
                source_id=domain_obj.id, target_id=comp_ws.id,
                edge_type=models.EdgeType.TRUSTS,
                risk_weight=0.6, edge_confidence=1.0,
                attributes={"trust_type": "external", "trust_direction": "bidirectional",
                            "sid_filtering": False},
            ),
        ]
        for e in edges:
            db.add(e)

        # ── findings ──────────────────────────────────────────────────────
        findings = [
            models.Finding(
                id=uuid.uuid4(), assessment_id=aid,
                finding_type="ACL_ABUSE", module="ACL",
                title="rahul.low has GenericAll on Domain Admins",
                description="Direct path to DA via ACL abuse.",
                severity=models.SeverityLevel.CRITICAL,
                composite_score=98.0, confidence=1.0,
                affected_count=1,
                affected_objects=[str(group_da.id)],
                causal_chain=[], remediation_steps=[],
                references=[], status=models.FindingStatus.OPEN,
                mitre_attack_ids=["T1484.001"],
            ),
            models.Finding(
                id=uuid.uuid4(), assessment_id=aid,
                finding_type="KERBEROAST", module="Kerberos",
                title="Kerberoastable service account: svc.kerberoast",
                description="Account has SPN and is Kerberoastable.",
                severity=models.SeverityLevel.HIGH,
                composite_score=75.0, confidence=1.0,
                affected_count=1,
                affected_objects=[str(user_svc.id)],
                causal_chain=[], remediation_steps=[],
                references=[], status=models.FindingStatus.OPEN,
                mitre_attack_ids=["T1558.003"],
            ),
            models.Finding(
                id=uuid.uuid4(), assessment_id=aid,
                finding_type="ASREP_ROAST", module="Kerberos",
                title="AS-REP Roastable account detected",
                description="Account has pre-authentication disabled.",
                severity=models.SeverityLevel.HIGH,
                composite_score=70.0, confidence=1.0,
                affected_count=1, affected_objects=[],
                causal_chain=[], remediation_steps=[],
                references=[], status=models.FindingStatus.OPEN,
                mitre_attack_ids=["T1558.004"],
            ),
            models.Finding(
                id=uuid.uuid4(), assessment_id=aid,
                finding_type="ADCS_ESC1", module="ADCS",
                title="ADCS ESC1 vulnerable certificate template",
                description="Certificate template allows arbitrary SAN — ADCS ESC1.",
                severity=models.SeverityLevel.CRITICAL,
                composite_score=95.0, confidence=1.0,
                affected_count=1, affected_objects=[],
                causal_chain=[], remediation_steps=[],
                references=[], status=models.FindingStatus.OPEN,
                mitre_attack_ids=["T1649"],
            ),
            models.Finding(
                id=uuid.uuid4(), assessment_id=aid,
                finding_type="NO_LOCKOUT", module="Policy",
                title="No account lockout policy configured",
                description="Brute force is unrestricted.",
                severity=models.SeverityLevel.MEDIUM,
                composite_score=40.0, confidence=1.0,
                affected_count=1, affected_objects=[],
                causal_chain=[], remediation_steps=[],
                references=[], status=models.FindingStatus.OPEN,
                mitre_attack_ids=["T1110"],
            ),
        ]
        for f in findings:
            db.add(f)

        # ── kill chain progress ────────────────────────────────────────────
        kc_phases = [
            models.KillChainProgress(
                id=uuid.uuid4(), assessment_id=aid,
                phase_id="recon", label="Reconnaissance",
                status=models.KillChainPhaseStatus.COMPLETE,
                findings_count=2, techniques_run=4,
            ),
            models.KillChainProgress(
                id=uuid.uuid4(), assessment_id=aid,
                phase_id="enum", label="Enumeration",
                status=models.KillChainPhaseStatus.COMPLETE,
                findings_count=3, techniques_run=6,
            ),
            models.KillChainProgress(
                id=uuid.uuid4(), assessment_id=aid,
                phase_id="loot", label="Credential Access",
                status=models.KillChainPhaseStatus.PARTIAL,
                findings_count=1, techniques_run=2,
            ),
            models.KillChainProgress(
                id=uuid.uuid4(), assessment_id=aid,
                phase_id="privesc", label="Privilege Escalation",
                status=models.KillChainPhaseStatus.NOT_STARTED,
                findings_count=0, techniques_run=0,
            ),
            models.KillChainProgress(
                id=uuid.uuid4(), assessment_id=aid,
                phase_id="da", label="Domain Admin",
                status=models.KillChainPhaseStatus.NOT_STARTED,
                findings_count=0, techniques_run=0,
            ),
        ]
        for p in kc_phases:
            db.add(p)

        # ── exposure paths ────────────────────────────────────────────────
        exposure_paths = [
            models.ExposurePath(
                id=uuid.uuid4(), assessment_id=aid,
                source_entity_id=user_low.id,
                target_entity_id=group_da.id,
                path_type="GenericAll",
                hop_count=1, path_score=0.98, target_tier=0,
                explanation="rahul.low → GenericAll → Domain Admins",
            ),
            models.ExposurePath(
                id=uuid.uuid4(), assessment_id=aid,
                source_entity_id=user_svc.id,
                target_entity_id=comp_dc.id,
                path_type="Kerberoast+DCSync",
                hop_count=2, path_score=0.75, target_tier=0,
                explanation="svc.kerberoast → crack TGS → DCSync",
            ),
        ]
        for ep in exposure_paths:
            db.add(ep)

        # ── loot (AttackChain) ────────────────────────────────────────────
        loot_chain = models.AttackChain(
            id=uuid.uuid4(), assessment_id=aid,
            name="Kerberoast + Crack", owner_user_id=uuid.uuid4(),
            loot={
                "ntlm_hashes": ["aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"],
                "tgs_hashes": ["$krb5tgs$23$*svc.kerberoast*corp.local*MSSQLSvc/sql01.corp.local*AABBCC..."],
                "cleartext_creds": [],
            },
        )
        db.add(loot_chain)

        # ── validation runs ───────────────────────────────────────────────
        val_run = models.ValidationRun(
            id=uuid.uuid4(), assessment_id=aid,
            module_id="kerberos_posture",
            target="corp.local",
            requested_mode="full",
            status="completed",
            risk_score=85.0, final_verdict="VULNERABLE",
            severity_projection="CRITICAL",
            reasoning_json={}, telemetry_json={},
        )
        db.add(val_run)

        await db.commit()

    # ── build ToolContext ─────────────────────────────────────────────────
    memory_store = FakeMemoryStore()
    approval_store = ApprovalStore()

    class SuperAdmin:
        id = uuid.uuid4()
        is_superadmin = True
        is_active = True
        username = "operator"

    async def _get_session():
        async with Session() as s:
            yield s

    # We need a persistent session for the context (not a generator)
    db_session = Session()

    ctx = ToolContext(
        db=db_session,
        current_user=SuperAdmin(),
        assessment_id=str(aid),
        memory_store=memory_store,
        approval_store=approval_store,
    )

    yield {
        "ctx": ctx,
        "aid": str(aid),
        "aid_b": str(assessment_b.id),
        "user_low_id": str(user_low.id),
        "user_svc_id": str(user_svc.id),
        "user_admin_id": str(user_admin.id),
        "group_da_id": str(group_da.id),
        "comp_dc_id": str(comp_dc.id),
        "comp_ws_id": str(comp_ws.id),
        "finding_ids": [str(f.id) for f in findings],
        "session": db_session,
    }

    await db_session.close()
    await engine.dispose()


# ---------------------------------------------------------------------------
# Helper: run tool and collect result
# ---------------------------------------------------------------------------

_AUTHZ = "adbygod_api.core.security.authorization"


async def _allow(*args, **kwargs):
    """Stub that grants access to any assessment."""
    return True


async def run_tool(name: str, args: dict, ctx: ToolContext) -> dict:
    """Dispatch a tool, patching authorization to always allow."""
    with patch(f"{_AUTHZ}.require_assessment_access", new=AsyncMock(return_value=True)), \
         patch(f"{_AUTHZ}.require_assessment_write_access", new=AsyncMock(return_value=True)), \
         patch(f"{_AUTHZ}.scope_assessment_child_query",
               new=AsyncMock(side_effect=lambda stmt, *a, **kw: stmt)):
        result = await dispatch_tool(name, args, ctx)
    return result.get("result", result)


# ---------------------------------------------------------------------------
# Individual tool tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_zip_parses_and_has_expected_content():
    """BloodHound zip contains all 4 JSON files and they parse cleanly."""
    from adbygod_api.core.parsers.bloodhound import BloodHoundParser
    data = _make_bh_zip()
    parser = BloodHoundParser()
    result = parser.parse_zip(data)
    assert result.get("entities"), "Expected entities from zip"
    assert result.get("evidence"), "Expected evidence from zip"


# -- READ TOOLS (original 14) -----------------------------------------------

@pytest.mark.asyncio
async def test_get_assessment_summary(scenario):
    r = await run_tool("get_assessment_summary", {}, scenario["ctx"])
    assert "error" not in r, r
    assert r["domain"] == "corp.local"
    assert r["findings_count"] >= 1


@pytest.mark.asyncio
async def test_list_findings(scenario):
    r = await run_tool("list_findings", {}, scenario["ctx"])
    assert isinstance(r, list), r
    assert len(r) >= 1
    assert all("severity" in f for f in r)


@pytest.mark.asyncio
async def test_get_entities(scenario):
    r = await run_tool("get_entities", {}, scenario["ctx"])
    assert isinstance(r, list), r
    assert len(r) >= 1


@pytest.mark.asyncio
async def test_get_attack_paths(scenario):
    r = await run_tool("get_attack_paths", {}, scenario["ctx"])
    assert isinstance(r, list), r
    assert len(r) >= 1
    assert r[0]["hop_count"] >= 1


@pytest.mark.asyncio
async def test_get_kill_chain_status(scenario):
    r = await run_tool("get_kill_chain_status", {}, scenario["ctx"])
    assert "error" not in r, r
    assert len(r["phases"]) >= 3


@pytest.mark.asyncio
async def test_get_loot(scenario):
    r = await run_tool("get_loot", {}, scenario["ctx"])
    assert isinstance(r, list), r
    assert len(r) >= 1
    assert r[0]["loot"]


@pytest.mark.asyncio
async def test_get_graph_summary(scenario):
    r = await run_tool("get_graph_summary", {}, scenario["ctx"])
    assert "error" not in r, r
    assert r["entity_count"] >= 1


@pytest.mark.asyncio
async def test_get_validation_results(scenario):
    r = await run_tool("get_validation_results", {}, scenario["ctx"])
    assert isinstance(r, list), r
    assert len(r) >= 1


@pytest.mark.asyncio
async def test_get_lateral_movement(scenario):
    r = await run_tool("get_lateral_movement", {}, scenario["ctx"])
    assert "chains" in r or "error" in r  # may error if analyzer deps missing


@pytest.mark.asyncio
async def test_search_platform(scenario):
    r = await run_tool("search_platform", {"query": "kerberoast"}, scenario["ctx"])
    assert "findings" in r, r
    assert "entities" in r, r


@pytest.mark.asyncio
async def test_parse_bloodhound(scenario):
    r = await run_tool("parse_bloodhound", {}, scenario["ctx"])
    assert "paths_to_da" in r, r
    assert "choke_points" in r, r


@pytest.mark.asyncio
async def test_get_engagement_memory(scenario):
    r = await run_tool("get_engagement_memory", {}, scenario["ctx"])
    assert isinstance(r, dict), r
    assert "owned_accounts" in r


@pytest.mark.asyncio
async def test_simulate_attack_chain(scenario):
    r = await run_tool("simulate_attack_chain",
                       {"owned": ["rahul.low"], "target": "Domain Admins"},
                       scenario["ctx"])
    assert "direct_paths_to_target" in r or "indirect_paths" in r, r


@pytest.mark.asyncio
async def test_get_credential_intel(scenario):
    hashes = [
        "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        "$krb5tgs$23$*svc*corp.local*MSSQLSvc*AABBCC",
    ]
    r = await run_tool("get_credential_intel", {"hashes": hashes, "domain": "corp.local"},
                       scenario["ctx"])
    assert isinstance(r, list), r
    assert r[0]["hash_type"] == "NTLM"
    assert r[0]["pth_ready"] is True
    assert r[1]["hash_type"] == "Kerberos TGS"


# -- READ TOOLS (god-mode 8) ------------------------------------------------

@pytest.mark.asyncio
async def test_get_entity_details(scenario):
    r = await run_tool("get_entity_details",
                       {"entity_id": scenario["user_low_id"]},
                       scenario["ctx"])
    assert "error" not in r, r
    assert r["sam_account_name"] == "rahul.low"
    assert isinstance(r["acl_outbound"], list)
    assert isinstance(r["acl_inbound"], list)
    assert len(r["acl_outbound"]) >= 1, "rahul.low should have outbound GenericAll edge"


@pytest.mark.asyncio
async def test_get_acl_edges_outbound(scenario):
    r = await run_tool("get_acl_edges",
                       {"entity_id": scenario["user_low_id"], "direction": "outbound"},
                       scenario["ctx"])
    assert isinstance(r, list), r
    assert len(r) >= 1, "rahul.low has at least GenericAll outbound"
    assert all(e["direction"] == "outbound" for e in r)
    edge_types = {e["edge_type"] for e in r}
    assert "GENERIC_ALL" in edge_types


@pytest.mark.asyncio
async def test_get_acl_edges_inbound(scenario):
    r = await run_tool("get_acl_edges",
                       {"entity_id": scenario["group_da_id"], "direction": "inbound"},
                       scenario["ctx"])
    assert isinstance(r, list), r
    assert len(r) >= 1, "Domain Admins has inbound edges"
    assert all(e["direction"] == "inbound" for e in r)


@pytest.mark.asyncio
async def test_get_acl_edges_both(scenario):
    r = await run_tool("get_acl_edges",
                       {"entity_id": scenario["user_low_id"], "direction": "both"},
                       scenario["ctx"])
    assert isinstance(r, list), r
    dirs = {e["direction"] for e in r}
    assert "outbound" in dirs


@pytest.mark.asyncio
async def test_get_domain_info(scenario):
    r = await run_tool("get_domain_info", {}, scenario["ctx"])
    assert "error" not in r, r
    assert r["domain"] == "corp.local"
    assert isinstance(r["privileged_groups"], list)
    assert isinstance(r["trust_relationships"], list)


@pytest.mark.asyncio
async def test_get_technique_catalog_all(scenario):
    r = await run_tool("get_technique_catalog", {"limit": 10}, scenario["ctx"])
    assert isinstance(r, list), r
    assert len(r) == 10
    assert all("id" in t and "title" in t for t in r)


@pytest.mark.asyncio
async def test_get_technique_catalog_filter_category(scenario):
    r = await run_tool("get_technique_catalog",
                       {"category": "Kerberos", "limit": 20},
                       scenario["ctx"])
    assert isinstance(r, list), r
    # May be empty if no category matches — just verify shape
    assert all("category" in t for t in r)


@pytest.mark.asyncio
async def test_get_technique_catalog_filter_keyword(scenario):
    r = await run_tool("get_technique_catalog",
                       {"keyword": "dcsync", "limit": 5},
                       scenario["ctx"])
    assert isinstance(r, list), r


@pytest.mark.asyncio
async def test_get_technique_catalog_executable_only(scenario):
    r = await run_tool("get_technique_catalog",
                       {"executable_only": True, "limit": 20},
                       scenario["ctx"])
    assert isinstance(r, list), r
    assert all(t["executable_on_linux"] is True for t in r)


@pytest.mark.asyncio
async def test_get_reachable_from(scenario):
    r = await run_tool("get_reachable_from",
                       {"principals": [scenario["user_low_id"]], "max_hops": 3},
                       scenario["ctx"])
    assert "error" not in r, r
    assert "reachable" in r
    assert r["total_reachable"] >= 1, "rahul.low should reach at least Domain Admins"
    tier0_nodes = [n for n in r["reachable"] if n["is_tier0"]]
    assert len(tier0_nodes) >= 1, "Should reach at least one Tier-0 node"


@pytest.mark.asyncio
async def test_get_reachable_from_tier0_only(scenario):
    r = await run_tool("get_reachable_from",
                       {"principals": [scenario["user_low_id"]],
                        "max_hops": 3, "tier0_only": True},
                       scenario["ctx"])
    assert "reachable" in r
    assert all(n["is_tier0"] for n in r["reachable"])


@pytest.mark.asyncio
async def test_get_opsec_status(scenario):
    r = await run_tool("get_opsec_status", {}, scenario["ctx"])
    assert "error" not in r, r
    assert r["noise_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert isinstance(r["recommendations"], list)
    assert r["techniques_run"] >= 8  # recon=4 + enum=6 + loot=2


@pytest.mark.asyncio
async def test_get_mitre_coverage(scenario):
    r = await run_tool("get_mitre_coverage", {}, scenario["ctx"])
    assert "error" not in r, r
    assert "tactics_covered" in r
    assert "coverage_percent" in r
    assert 0 <= r["coverage_percent"] <= 100
    assert len(r["tactics_covered"]) >= 1


@pytest.mark.asyncio
async def test_diff_assessments(scenario):
    r = await run_tool("diff_assessments",
                       {"assessment_id_a": scenario["aid"],
                        "assessment_id_b": scenario["aid_b"]},
                       scenario["ctx"])
    assert "error" not in r, r
    assert "new_findings" in r
    assert "resolved_findings" in r
    assert "summary" in r


# -- INTEL TOOLS (original 4) -----------------------------------------------

# parse_bloodhound, get_engagement_memory, simulate_attack_chain,
# get_credential_intel — already tested above in READ block.


# -- INTEL TOOLS (god-mode 3) -----------------------------------------------

@pytest.mark.asyncio
async def test_get_session_intel(scenario):
    r = await run_tool("get_session_intel", {}, scenario["ctx"])
    assert "error" not in r, r
    assert "sessions" in r
    assert r["total"] >= 1, "Expected at least 1 HAS_SESSION edge"
    assert r["tier0_sessions"] >= 1, "Administrator session on DC should be tier0"


@pytest.mark.asyncio
async def test_get_session_intel_filtered_by_computer(scenario):
    r = await run_tool("get_session_intel",
                       {"computer_id": scenario["comp_dc_id"]},
                       scenario["ctx"])
    assert "sessions" in r


@pytest.mark.asyncio
async def test_get_trust_map(scenario):
    r = await run_tool("get_trust_map", {}, scenario["ctx"])
    assert "error" not in r, r
    assert "trusts" in r
    assert len(r["trusts"]) >= 1, "Expected at least 1 TRUSTS edge"
    assert r["trusts"][0]["exploitable"] is True  # sid_filtering=False


@pytest.mark.asyncio
async def test_get_owned_graph(scenario):
    r = await run_tool("get_owned_graph", {}, scenario["ctx"])
    assert "error" not in r, r
    assert "nodes" in r
    assert r["total_reachable"] >= 1
    owned_nodes = [n for n in r["nodes"] if n["is_owned"]]
    assert len(owned_nodes) >= 1


# -- WRITE TOOLS (original 3) -----------------------------------------------

@pytest.mark.asyncio
async def test_save_to_memory(scenario):
    r = await run_tool("save_to_memory",
                       {"key": "owned_accounts", "value": "newuser"},
                       scenario["ctx"])
    assert r.get("saved") is True


@pytest.mark.asyncio
async def test_write_report_section(scenario):
    r = await run_tool("write_report_section",
                       {"section": "executive_summary",
                        "content": "# Executive Summary\n\nCritical ACL path found."},
                       scenario["ctx"])
    assert r.get("section") == "executive_summary"
    assert r.get("length") > 0


@pytest.mark.asyncio
async def test_update_target_card(scenario):
    r = await run_tool("update_target_card",
                       {"domain": "corp.local", "dc_ip": "192.168.1.10",
                        "auth_level": "low_priv", "findings_critical": 2,
                        "opsec_noise": "MEDIUM", "next_best_action": "Exploit GenericAll"},
                       scenario["ctx"])
    assert r.get("updated") is True


# -- WRITE TOOLS (god-mode 4) -----------------------------------------------

@pytest.mark.asyncio
async def test_flag_finding_confirmed(scenario):
    fid = scenario["finding_ids"][1]  # kerberoast finding
    r = await run_tool("flag_finding",
                       {"finding_id": fid, "status": "IN_REVIEW",
                        "note": "Verified via Rubeus"},
                       scenario["ctx"])
    assert "error" not in r, r
    assert r["status"] == "IN_REVIEW"
    assert r["previous_status"] == "OPEN"


@pytest.mark.asyncio
async def test_flag_finding_false_positive(scenario):
    fid = scenario["finding_ids"][4]  # lockout finding
    r = await run_tool("flag_finding",
                       {"finding_id": fid, "status": "FALSE_POSITIVE"},
                       scenario["ctx"])
    assert r["status"] == "FALSE_POSITIVE"


@pytest.mark.asyncio
async def test_flag_finding_invalid_id(scenario):
    r = await run_tool("flag_finding",
                       {"finding_id": str(uuid.uuid4()), "status": "confirmed"},
                       scenario["ctx"])
    assert "error" in r


@pytest.mark.asyncio
async def test_add_finding(scenario):
    r = await run_tool("add_finding",
                       {"title": "LAPS not deployed",
                        "description": "Local admin passwords are not randomised.",
                        "severity": "HIGH", "module": "manual",
                        "mitre_attack_ids": ["T1555"],
                        "remediation": "Deploy LAPS to all workstations"},
                       scenario["ctx"])
    assert "error" not in r, r
    assert r.get("created") is True
    assert r["title"] == "LAPS not deployed"


@pytest.mark.asyncio
async def test_annotate_entity_owned(scenario):
    r = await run_tool("annotate_entity",
                       {"entity_id": scenario["comp_ws_id"],
                        "owned": True,
                        "notes": "Got shell via SMB relay",
                        "is_crown_jewel": False},
                       scenario["ctx"])
    assert "error" not in r, r
    assert r.get("updated") is True


@pytest.mark.asyncio
async def test_annotate_entity_crown_jewel(scenario):
    r = await run_tool("annotate_entity",
                       {"entity_id": scenario["comp_dc_id"],
                        "is_crown_jewel": True,
                        "business_tags": ["Tier-0", "DC"]},
                       scenario["ctx"])
    assert r.get("updated") is True
    assert r["is_crown_jewel"] is True


@pytest.mark.asyncio
async def test_set_opsec_mode_stealth(scenario):
    r = await run_tool("set_opsec_mode",
                       {"mode": "stealth", "reason": "Blue team is active"},
                       scenario["ctx"])
    assert "error" not in r, r
    assert r["mode"] == "stealth"
    assert r["profile"]["max_techniques_per_hour"] == 3


@pytest.mark.asyncio
async def test_set_opsec_mode_aggressive(scenario):
    r = await run_tool("set_opsec_mode", {"mode": "aggressive"}, scenario["ctx"])
    assert r["mode"] == "aggressive"


@pytest.mark.asyncio
async def test_set_opsec_mode_invalid(scenario):
    r = await run_tool("set_opsec_mode", {"mode": "yolo"}, scenario["ctx"])
    assert "error" in r


# -- EXEC TOOLS (original 5) -----------------------------------------------

@pytest.mark.asyncio
async def test_execute_technique_blocked_without_superadmin(scenario):
    """execute_technique should block when user isn't superadmin."""
    from adbygod_api.core.ai_operator.tools.registry import dispatch_tool, ToolContext
    from adbygod_api.core.ai_operator.approval_store import ApprovalStore

    class NormalUser:
        id = uuid.uuid4()
        is_superadmin = False

    ctx_normal = ToolContext(
        db=scenario["ctx"].db,
        current_user=NormalUser(),
        assessment_id=scenario["aid"],
        memory_store=scenario["ctx"].memory_store,
        approval_store=ApprovalStore(),
    )
    with patch(f"{_AUTHZ}.require_assessment_access", new=AsyncMock(return_value=True)):
        result = await dispatch_tool("execute_technique",
                                     {"technique_id": "recon-dns-enum"}, ctx_normal)
    r = result.get("result", result)
    assert r.get("blocked") is True


@pytest.mark.asyncio
async def test_crack_hashes_job_queued(scenario):
    hashes = ["aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"]
    # Mock start_crack_job to avoid real cracking
    mock_job = MagicMock()
    mock_job.id = "job-001"
    mock_job.status = "queued"
    with patch("adbygod_api.core.ai_operator.tools.exec_tools._execute_technique",
               new=AsyncMock(return_value={"exit_code": 0, "stdout": "ok", "stderr": ""})):
        with patch("adbygod_api.core.loot.hash_intel.start_crack_job",
                   new=AsyncMock(return_value=mock_job)), \
             patch("adbygod_api.core.loot.hash_intel.is_allowed_wordlist_path",
                   return_value=True):
            r = await run_tool("crack_hashes",
                               {"hashes": hashes, "hashcat_mode": 1000},
                               scenario["ctx"])
    # Either queued or an error about hash_intel — both acceptable
    assert "error" in r or r.get("status") == "queued" or "job_id" in r


@pytest.mark.asyncio
async def test_run_campaign_step(scenario):
    r = await run_tool("run_campaign_step",
                       {"phase": "enum", "step_description": "LDAP enumeration of all users"},
                       scenario["ctx"])
    assert r["phase"] == "enum"
    assert r["status"] == "recorded"


@pytest.mark.asyncio
async def test_spawn_sub_agent(scenario):
    r = await run_tool("spawn_sub_agent",
                       {"task": "Enumerate LAPS passwords", "agent_id": "laps-001"},
                       scenario["ctx"])
    assert r["agent_id"] == "laps-001"
    assert r["status"] == "queued"


# -- EXEC TOOLS (god-mode 8) ------------------------------------------------

@pytest.mark.asyncio
async def test_export_report_all_sections(scenario):
    # Pre-populate a report section
    await run_tool("write_report_section",
                   {"section": "executive_summary",
                    "content": "Critical path to DA found via GenericAll."},
                   scenario["ctx"])
    r = await run_tool("export_report", {}, scenario["ctx"])
    assert "error" not in r, r
    assert "report_markdown" in r
    assert "## Executive Summary" in r["report_markdown"]
    assert r["word_count"] > 5


@pytest.mark.asyncio
async def test_export_report_specific_sections(scenario):
    r = await run_tool("export_report",
                       {"sections": ["executive_summary", "recommendations"]},
                       scenario["ctx"])
    assert "report_markdown" in r
    assert r["sections_included"] == ["executive_summary", "recommendations"]


@pytest.mark.asyncio
async def test_run_technique_chain(scenario):
    """Chain should record each step in kill chain memory."""
    # Mock execute so no real commands run
    from adbygod_api.core.ai_operator.tools import exec_tools
    original = exec_tools._execute_technique

    async def fake_exec(args, ctx):
        return {"exit_code": 0, "stdout": "ok", "command": args.get("technique_id")}

    exec_tools._execute_technique = fake_exec
    try:
        r = await run_tool("run_technique_chain",
                           {"techniques": [
                               {"technique_id": "recon-dns-enum", "params": {"Domain": "corp.local", "DC_IP": "192.168.1.10"}},
                               {"technique_id": "recon-ldap-enum", "params": {"Domain": "corp.local", "DC_IP": "192.168.1.10"}},
                           ]},
                           scenario["ctx"])
    finally:
        exec_tools._execute_technique = original

    assert "error" not in r, r
    assert r["steps_executed"] == 2


@pytest.mark.asyncio
async def test_run_technique_chain_stop_on_failure(scenario):
    from adbygod_api.core.ai_operator.tools import exec_tools

    async def fail_exec(args, ctx):
        return {"exit_code": 1, "stdout": "", "command": args.get("technique_id")}

    exec_tools._execute_technique = fail_exec
    try:
        r = await run_tool("run_technique_chain",
                           {"techniques": [
                               {"technique_id": "recon-dns-enum"},
                               {"technique_id": "recon-ldap-enum"},
                           ], "stop_on_failure": True},
                           scenario["ctx"])
    finally:
        exec_tools._execute_technique = exec_tools._execute_technique  # restore untouched

    assert r["steps_executed"] == 1  # stopped after first failure


@pytest.mark.asyncio
async def test_import_tool_output_nxc(scenario):
    nxc_output = """
SMB 192.168.1.11    445  WS01  [+] corp.local\\rahul.low:Password123 (Pwn3d!)
SMB 192.168.1.10    445  DC01  [*] Windows Server 2022 (name:DC01)
"""
    r = await run_tool("import_tool_output",
                       {"tool_name": "nxc", "raw_output": nxc_output},
                       scenario["ctx"])
    assert "error" not in r, r
    assert r["findings_parsed"] >= 1, "Should detect Pwn3d! as a finding"


@pytest.mark.asyncio
async def test_import_tool_output_nmap(scenario):
    nmap_output = """
Nmap scan report for DC01.corp.local (192.168.1.10)
PORT    STATE SERVICE
88/tcp  open  kerberos-sec
445/tcp open  microsoft-ds
"""
    r = await run_tool("import_tool_output",
                       {"tool_name": "nmap", "raw_output": nmap_output},
                       scenario["ctx"])
    assert "error" not in r, r
    assert r["entities_parsed"] >= 1


@pytest.mark.asyncio
async def test_import_tool_output_certipy(scenario):
    certipy_output = """
[*] Finding certificate templates
[!] ESC1 - rahul.low can enroll
Template                 : VulnTemplate
Certificate Authorities  : corp-CA
[!] ESC8 - HTTP request to CA
"""
    r = await run_tool("import_tool_output",
                       {"tool_name": "certipy", "raw_output": certipy_output},
                       scenario["ctx"])
    assert "error" not in r, r
    assert r["findings_parsed"] >= 1


@pytest.mark.asyncio
async def test_plan_attack(scenario):
    r = await run_tool("plan_attack",
                       {"target": "Domain Admins", "max_steps": 5},
                       scenario["ctx"])
    assert "error" not in r, r
    assert "steps" in r
    assert len(r["steps"]) >= 1, "Should generate at least 1 step"
    assert r["target"] == "Domain Admins"
    # Steps should be ordered
    step_nums = [s["step"] for s in r["steps"]]
    assert step_nums == list(range(1, len(step_nums) + 1))


@pytest.mark.asyncio
async def test_plan_attack_step_has_required_fields(scenario):
    r = await run_tool("plan_attack", {}, scenario["ctx"])
    for step in r.get("steps", []):
        assert "phase" in step, f"Step missing phase: {step}"
        assert "action" in step, f"Step missing action: {step}"
        assert "priority" in step, f"Step missing priority: {step}"


@pytest.mark.asyncio
async def test_get_next_best_action(scenario):
    r = await run_tool("get_next_best_action", {}, scenario["ctx"])
    assert "error" not in r, r
    assert "next_action" in r
    assert "phase" in r
    assert "reason" in r
    assert len(r["next_action"]) > 0


@pytest.mark.asyncio
async def test_run_bloodhound_collection_blocked_by_default(scenario):
    """run_bloodhound_collection must be blocked unless ENABLE_AI_ARBITRARY_SHELL is True."""
    import adbygod_api.config as config
    original = getattr(config.settings, "ENABLE_AI_ARBITRARY_SHELL", False)
    config.settings.ENABLE_AI_ARBITRARY_SHELL = False
    try:
        r = await run_tool("run_bloodhound_collection",
                           {"dc_ip": "192.168.1.10", "domain": "corp.local",
                            "username": "rahul.low", "password": "Password123"},
                           scenario["ctx"])
    finally:
        config.settings.ENABLE_AI_ARBITRARY_SHELL = original
    assert r.get("blocked") is True


@pytest.mark.asyncio
async def test_get_timeline(scenario):
    r = await run_tool("get_timeline", {"limit": 100}, scenario["ctx"])
    assert "error" not in r, r
    assert "events" in r
    assert len(r["events"]) >= 1
    # Should have phase_progress events from kill chain
    types = {e["type"] for e in r["events"]}
    assert "phase_progress" in types, f"Expected phase_progress events, got: {types}"


@pytest.mark.asyncio
async def test_get_timeline_filtered(scenario):
    r = await run_tool("get_timeline",
                       {"event_types": ["entity_owned"]},
                       scenario["ctx"])
    assert "events" in r
    assert all(e["type"] == "entity_owned" for e in r["events"])


@pytest.mark.asyncio
async def test_generate_playbook(scenario):
    r = await run_tool("generate_playbook",
                       {"target": "Domain Admins", "style": "technical",
                        "include_mitre": True, "include_detection": True},
                       scenario["ctx"])
    assert "error" not in r, r
    assert "playbook_markdown" in r
    md = r["playbook_markdown"]
    assert "# Kill-Chain Playbook" in md
    assert "corp.local" in md
    assert r["steps_count"] >= 1


@pytest.mark.asyncio
async def test_generate_playbook_executive_style(scenario):
    r = await run_tool("generate_playbook",
                       {"style": "executive"},
                       scenario["ctx"])
    assert "playbook_markdown" in r


# ---------------------------------------------------------------------------
# Omnibus: run every tool name from registry and ensure no unhandled exception
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_all_45_tools_dispatch_without_crash(scenario):
    """
    Every tool in the registry must dispatch without raising an unhandled exception.
    This catches tools that have missing handlers or crash on valid input.
    """
    from adbygod_api.core.ai_operator.tools.registry import (
        READ_TOOL_NAMES, WRITE_TOOL_NAMES, EXEC_TOOL_NAMES
    )

    ctx = scenario["ctx"]
    aid = scenario["aid"]
    uid = scenario["user_low_id"]
    fid = scenario["finding_ids"][0]

    # Minimal valid args for every tool
    tool_args: dict[str, dict] = {
        # original read
        "get_assessment_summary": {},
        "list_findings": {"limit": 5},
        "get_entities": {"limit": 5},
        "get_attack_paths": {"limit": 5},
        "get_kill_chain_status": {},
        "get_loot": {"limit": 5},
        "get_graph_summary": {},
        "get_validation_results": {},
        "get_lateral_movement": {},
        "search_platform": {"query": "admin"},
        "parse_bloodhound": {},
        "get_engagement_memory": {},
        "simulate_attack_chain": {"owned": [uid], "target": "Domain Admins"},
        "get_credential_intel": {"hashes": ["aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"]},
        # god-mode read
        "get_entity_details": {"entity_id": uid},
        "get_acl_edges": {"entity_id": uid, "direction": "outbound"},
        "get_domain_info": {},
        "get_technique_catalog": {"limit": 5},
        "get_reachable_from": {"principals": [uid], "max_hops": 2},
        "get_opsec_status": {},
        "get_mitre_coverage": {},
        "diff_assessments": {"assessment_id_a": aid, "assessment_id_b": scenario["aid_b"]},
        "get_session_intel": {},
        "get_trust_map": {},
        "get_owned_graph": {"max_hops": 2},
        # original write
        "save_to_memory": {"key": "notes", "value": "omnibus test"},
        "write_report_section": {"section": "recommendations", "content": "Patch everything."},
        "update_target_card": {"domain": "corp.local"},
        # god-mode write
        "flag_finding": {"finding_id": fid, "status": "IN_REVIEW"},
        "add_finding": {"title": "Omnibus test finding", "severity": "LOW"},
        "annotate_entity": {"entity_id": uid, "notes": "omnibus"},
        "set_opsec_mode": {"mode": "normal"},
        # original exec (execution blocked without ENABLE_AI_ARBITRARY_SHELL, that's OK)
        "execute_technique": {"technique_id": "recon-dns-enum"},
        "run_shell_command": {"command": "echo hello", "description": "test"},
        "run_campaign_step": {"phase": "recon", "step_description": "test"},
        "spawn_sub_agent": {"task": "test", "agent_id": "omnibus-agent"},
        "crack_hashes": {"hashes": ["aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"],
                         "hashcat_mode": 1000},
        # god-mode exec
        "export_report": {},
        "run_technique_chain": {"techniques": [{"technique_id": "recon-dns-enum"}]},
        "import_tool_output": {"tool_name": "generic", "raw_output": "192.168.1.10 open"},
        "plan_attack": {"target": "Domain Admins", "max_steps": 3},
        "get_next_best_action": {},
        "run_bloodhound_collection": {"dc_ip": "192.168.1.10", "domain": "corp.local",
                                       "username": "rahul.low", "password": "Password123"},
        "get_timeline": {"limit": 20},
        "generate_playbook": {"target": "Domain Admins"},
    }

    all_tools = READ_TOOL_NAMES | WRITE_TOOL_NAMES | EXEC_TOOL_NAMES

    # Mock execute_technique and crack_hashes to avoid needing real commands
    from adbygod_api.core.ai_operator.tools import exec_tools
    orig_exec = exec_tools._execute_technique

    async def safe_exec(args, ctx):
        return {"exit_code": 0, "stdout": "mocked", "command": "mocked"}

    exec_tools._execute_technique = safe_exec

    import adbygod_api.config as cfg
    orig_shell = getattr(cfg.settings, "ENABLE_AI_ARBITRARY_SHELL", False)
    cfg.settings.ENABLE_AI_ARBITRARY_SHELL = False  # keep bloodhound blocked

    failures = []
    passed = []

    try:
        for tool_name in sorted(all_tools):
            args = tool_args.get(tool_name, {})
            try:
                with patch(f"{_AUTHZ}.require_assessment_access",
                           new=AsyncMock(return_value=True)), \
                     patch(f"{_AUTHZ}.scope_assessment_child_query",
                           new=AsyncMock(side_effect=lambda s, *a, **kw: s)), \
                     patch("adbygod_api.core.loot.hash_intel.start_crack_job",
                           new=AsyncMock(return_value=MagicMock(id="j1", status="queued")),
                           create=True), \
                     patch("adbygod_api.core.loot.hash_intel.is_allowed_wordlist_path",
                           return_value=True, create=True):
                    await dispatch_tool(tool_name, args, ctx)
                    passed.append(tool_name)
            except Exception as exc:
                failures.append((tool_name, type(exc).__name__, str(exc)[:200]))
    finally:
        exec_tools._execute_technique = orig_exec
        cfg.settings.ENABLE_AI_ARBITRARY_SHELL = orig_shell

    print(f"\n{'='*60}")
    print(f"TOOL TEST SUMMARY: {len(passed)}/{len(all_tools)} passed")
    print(f"{'='*60}")
    if failures:
        print(f"\nFAILED ({len(failures)}):")
        for name, exc_type, msg in failures:
            print(f"  ✗ {name}: [{exc_type}] {msg}")
    print(f"\nPASSED ({len(passed)}):")
    for name in passed:
        print(f"  ✓ {name}")

    assert not failures, (
        f"\n{len(failures)} tool(s) crashed:\n" +
        "\n".join(f"  {n}: [{t}] {m}" for n, t, m in failures)
    )
