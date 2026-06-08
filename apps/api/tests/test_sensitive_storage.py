from __future__ import annotations

import asyncio
import uuid
from uuid import UUID

from sqlalchemy import text

from adbygod_api.models import (
    Assessment,
    AttackChain,
    ChainStatus,
    ConnectivityMode,
    ConnectivityProfile,
    JobOutput,
    OffensiveJob,
    OffensiveJobStatus,
    OpsecProfile,
)
from adbygod_api.core.security.at_rest import redact_sensitive_mapping


def test_assessment_detail_redacts_collection_secrets_and_db_storage_is_protected(test_app):
    client = test_app["client"]
    db = test_app["db"]
    user = db.run(db.create_user("storage-admin", "storage-admin@example.invalid", is_superadmin=True))
    secret_password = "Sc@nner-Lab#2026!"

    create = client.post(
        "/api/v1/assessments",
        headers=test_app["headers_for"](user),
        json={
            "name": "Protected Assessment",
            "domain": "lab.local",
            "dc_ip": "192.168.56.10",
            "collection_mode": "LINUX_REMOTE",
            "collection_config": {
                "target": {"username": "scanner", "password": secret_password},
                "modules": ["kerberos"],
            },
        },
    )
    assert create.status_code == 201
    assessment_id = create.json()["id"]

    detail = client.get(
        f"/api/v1/assessments/{assessment_id}",
        headers=test_app["headers_for"](user),
    )
    assert detail.status_code == 200
    detail_body = detail.json()
    assert detail_body["collection_config"]["target"]["username"] == "scanner"
    assert detail_body["collection_config"]["target"]["password"] == "<redacted>"

    async def _inspect() -> tuple[str, dict]:
        async with test_app["session_maker"]() as session:
            raw = (
                await session.execute(
                    text("SELECT collection_config FROM assessments WHERE id = :id"),
                    {"id": assessment_id},
                )
            ).scalar_one()
            loaded = await session.get(Assessment, UUID(assessment_id))
            assert loaded is not None
            return str(raw), dict(loaded.collection_config or {})

    raw, loaded_config = asyncio.run(_inspect())
    assert secret_password not in raw
    assert loaded_config["target"]["password"] == secret_password


def test_redaction_matches_sensitive_key_patterns_recursively():
    payload = {
        "normal": "keep",
        "nested": {
            "db_password": "secret",
            "api-key": "key",
            "private-key": "pem",
            "credential_id": "cred",
        },
        "items": [
            {"passwd": "pw", "username": "user"},
            {"hash_value": "hash", "safe": "value"},
        ],
    }

    redacted = redact_sensitive_mapping(payload)

    assert redacted["normal"] == "keep"
    assert redacted["nested"]["db_password"] == "<redacted>"
    assert redacted["nested"]["api-key"] == "<redacted>"
    assert redacted["nested"]["private-key"] == "<redacted>"
    assert redacted["nested"]["credential_id"] == "<redacted>"
    assert redacted["items"][0]["passwd"] == "<redacted>"
    assert redacted["items"][0]["username"] == "user"
    assert redacted["items"][1]["hash_value"] == "<redacted>"
    assert redacted["items"][1]["safe"] == "value"


def test_sensitive_chain_job_output_and_connectivity_data_are_encrypted_at_rest(test_app):
    db = test_app["db"]
    user = db.run(db.create_user("ops-storage", "ops-storage@example.invalid", is_superadmin=True))
    password = "Chain-Step-Pass#2026"
    nt_hash = "0123456789abcdef0123456789abcdef"
    auth_token = "relay-auth-token-very-secret"

    async def _seed_and_inspect():
        async with test_app["session_maker"]() as session:
            profile = ConnectivityProfile(
                id=uuid.uuid4(),
                name="Protected Chisel",
                mode=ConnectivityMode.CHISEL,
                config={"auth_token": auth_token, "socks_port": 1080},
                created_by=user.id,
            )
            chain = AttackChain(
                id=uuid.uuid4(),
                owner_user_id=user.id,
                name="Protected chain",
                status=ChainStatus.PENDING,
                target="192.168.56.10",
                domain="lab.local",
                path_nodes=["scanner", "DA"],
                steps=[{"technique_id": "dcsync", "params": {"password": password, "hashes": nt_hash}}],
                current_step=0,
                loot={"da_hashes": [nt_hash]},
                job_ids=[],
                params={"password": password, "hashes": nt_hash},
                all_paths=[],
                failed_steps=[],
            )
            job = OffensiveJob(
                id=uuid.uuid4(),
                technique_id="dcsync",
                target="192.168.56.10",
                params={"password": password, "hashes": nt_hash},
                executor="impacket",
                opsec_profile=OpsecProfile.BALANCED,
                status=OffensiveJobStatus.COMPLETED,
                owner_user_id=user.id,
            )
            output = JobOutput(
                id=uuid.uuid4(),
                job_id=job.id,
                stream="stdout",
                line=f"captured password={password} hash={nt_hash}",
            )
            session.add_all([profile, chain, job, output])
            await session.commit()

            raw_chain = (
                await session.execute(
                    text("SELECT steps, loot, params FROM attack_chains WHERE id = :id"),
                    {"id": str(chain.id)},
                )
            ).one()
            raw_job_params = (
                await session.execute(
                    text("SELECT params FROM offensive_jobs WHERE id = :id"),
                    {"id": str(job.id)},
                )
            ).scalar_one()
            raw_line = (
                await session.execute(
                    text("SELECT line FROM job_outputs WHERE id = :id"),
                    {"id": str(output.id)},
                )
            ).scalar_one()
            raw_profile = (
                await session.execute(
                    text("SELECT config FROM connectivity_profiles WHERE id = :id"),
                    {"id": str(profile.id)},
                )
            ).scalar_one()

            loaded_chain = await session.get(AttackChain, chain.id)
            loaded_job = await session.get(OffensiveJob, job.id)
            loaded_output = await session.get(JobOutput, output.id)
            loaded_profile = await session.get(ConnectivityProfile, profile.id)
            assert loaded_chain is not None
            assert loaded_job is not None
            assert loaded_output is not None
            assert loaded_profile is not None

            return {
                "raw": "\n".join(map(str, [*raw_chain, raw_job_params, raw_line, raw_profile])),
                "chain": loaded_chain,
                "job": loaded_job,
                "output": loaded_output,
                "profile": loaded_profile,
            }

    inspected = asyncio.run(_seed_and_inspect())
    raw = inspected["raw"]
    assert password not in raw
    assert nt_hash not in raw
    assert auth_token not in raw

    chain = inspected["chain"]
    job = inspected["job"]
    output = inspected["output"]
    profile = inspected["profile"]
    assert chain.steps[0]["params"]["password"] == password
    assert chain.loot["da_hashes"][0] == nt_hash
    assert job.params["hashes"] == nt_hash
    assert password in output.line
    assert profile.config["auth_token"] == auth_token
