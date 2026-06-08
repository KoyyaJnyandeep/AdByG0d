from __future__ import annotations

from adbygod_api.routes.ingest import _materialize_trust_metadata
from adbygod_api.schemas import CollectorIngest


def test_trust_metadata_becomes_trust_entity_and_graph_edge() -> None:
    payload = CollectorIngest(
        collection_mode="IMPORT",
        domain="lab.local",
        collected_at="imported",
        collector_version="test",
        modules_run=["trusts"],
        entities=[
            {
                "id": "DOMAIN-LAB",
                "entity_type": "DOMAIN",
                "sam_account_name": "lab.local",
                "display_name": "lab.local",
                "domain": "lab.local",
            }
        ],
        edges=[],
        evidence=[],
        findings=[],
        cert_templates=[],
        metadata={
            "trusts": [
                {
                    "partner": "child.lab.local",
                    "partner_sid": "S-1-5-21-2000",
                    "trust_type": "FOREST",
                    "trust_direction": 3,
                    "transitive": True,
                    "sid_filtering_enabled": False,
                }
            ]
        },
    )

    _materialize_trust_metadata(payload)

    trust_entities = [entity for entity in payload.entities if entity.get("entity_type") == "TRUST"]
    assert len(trust_entities) == 1
    trust_entity = trust_entities[0]
    assert trust_entity["display_name"] == "child.lab.local"
    assert trust_entity["attributes"]["direction"] == "BIDIRECTIONAL"
    assert trust_entity["attributes"]["sid_filtering"] is False
    assert trust_entity["is_sensitive"] is True

    trust_edges = [edge for edge in payload.edges if edge.get("edge_type") == "TRUSTS"]
    assert len(trust_edges) == 1
    assert trust_edges[0]["source_id"] == "DOMAIN-LAB"
    assert trust_edges[0]["target_id"] == trust_entity["id"]
    assert trust_edges[0]["risk_weight"] == 0.90


def test_trust_materialization_is_idempotent() -> None:
    payload = CollectorIngest(
        collection_mode="LINUX_REMOTE",
        domain="corp.local",
        collected_at="live",
        collector_version="test",
        modules_run=["trusts"],
        entities=[{"id": "DOMAIN-CORP", "entity_type": "DOMAIN", "domain": "corp.local"}],
        edges=[],
        evidence=[],
        findings=[],
        cert_templates=[],
        metadata={"trusts": [{"partner": "other.local", "sid_filtering_enabled": True}]},
    )

    _materialize_trust_metadata(payload)
    _materialize_trust_metadata(payload)

    trust_entities = [entity for entity in payload.entities if entity.get("entity_type") == "TRUST"]
    trust_edges = [edge for edge in payload.edges if edge.get("edge_type") == "TRUSTS"]
    assert len(trust_entities) == 1
    assert len(trust_edges) == 1
