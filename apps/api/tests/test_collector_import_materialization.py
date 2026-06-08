from __future__ import annotations

from adbygod_api.routes.import_data import _collector_rule_data_to_ingest


def test_collector_rule_data_to_ingest_materializes_graph_payload() -> None:
    payload = _collector_rule_data_to_ingest(
        manifest={
            "domain": "corp.local",
            "dc_ip": "10.0.0.10",
            "collected_at": "2026-05-17T00:00:00Z",
            "collector_version": "native/1.0",
        },
        module_ids=["enum", "acl"],
        rule_data={
            "entities": [{"id": "u1", "entity_type": "USER", "sam_account_name": "alice"}],
            "edges": [{"source_id": "u1", "target_id": "g1", "edge_type": "MEMBER_OF"}],
            "cert_templates": [{"name": "UserTemplate", "esc1_vulnerable": True}],
            "ca_flags": [{"ca_name": "CORP-CA", "edit_flags": 1}],
            "domain_info": {"dns_root": "corp.local", "machine_account_quota": 10},
            "password_policy": {"min_password_length": 12},
            "trusts": [{"name": "child.corp.local"}],
            "network_config": {"smb_signing_required": False},
        },
    )

    assert payload.collection_mode == "WINDOWS_LOCAL"
    assert payload.domain == "corp.local"
    assert payload.dc_ip == "10.0.0.10"
    assert payload.collector_version == "native/1.0"
    assert payload.modules_run == ["enum", "acl"]
    assert payload.entities[0]["id"] == "u1"
    assert payload.edges[0]["edge_type"] == "MEMBER_OF"
    assert payload.cert_templates[0]["name"] == "UserTemplate"
    assert payload.ca_flags[0]["ca_name"] == "CORP-CA"
    assert payload.metadata["domain_info"]["machine_account_quota"] == 10
    assert payload.metadata["password_policy"]["min_password_length"] == 12
    assert payload.metadata["trusts"][0]["name"] == "child.corp.local"
    assert payload.metadata["network_config"]["smb_signing_required"] is False
