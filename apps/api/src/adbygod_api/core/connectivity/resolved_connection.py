from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from adbygod_api.models import Assessment, ConnectivityProfile


@dataclass(frozen=True)
class ResolvedConnection:
    domain: str
    dc_ip: str | None
    dc_hostname: str | None
    dns_server: str | None
    base_dn: str | None
    target_subnets: list[str] = field(default_factory=list)
    profile_id: str | None = None
    transport_mode: str = "DIRECT"

    def collection_overrides(self) -> dict[str, Any]:
        target = {
            "target_domain": self.domain,
            "dc_ip": self.dc_ip,
            "dc_hostname": self.dc_hostname,
            "dns_server": self.dns_server,
            "base_dn": self.base_dn,
            "target_subnets": self.target_subnets,
            "connectivity_profile_id": self.profile_id,
            "transport_mode": self.transport_mode,
        }
        return {
            "domain": self.domain,
            "dc_ip": self.dc_ip or self.dc_hostname,
            "resolved_target": {k: v for k, v in target.items() if v not in (None, "", [])},
        }


def _base_dn_from_domain(domain: str) -> str | None:
    parts = [p.strip() for p in domain.split(".") if p.strip()]
    if not parts:
        return None
    return ",".join(f"DC={part}" for part in parts)


def _config_value(config: dict[str, Any], key: str) -> Any:
    value = config.get(key)
    if value not in (None, "", []):
        return value
    nested = config.get("target")
    if isinstance(nested, dict):
        nested_value = nested.get(key)
        if nested_value not in (None, "", []):
            return nested_value
    return None


def resolve_connection(
    assessment: Assessment,
    profile: ConnectivityProfile | None = None,
) -> ResolvedConnection:
    profile_config = dict(profile.config or {}) if profile else {}
    assessment_config = dict(assessment.collection_config or {})
    assessment_target = assessment_config.get("target")
    if not isinstance(assessment_target, dict):
        assessment_target = {}

    domain = (
        _config_value(profile_config, "target_domain")
        or assessment_target.get("target_domain")
        or assessment.domain
    )
    dc_ip = (
        _config_value(profile_config, "dc_ip")
        or assessment_target.get("dc_ip")
        or assessment.dc_ip
    )
    dc_hostname = _config_value(profile_config, "dc_hostname") or assessment_target.get("dc_hostname")
    dns_server = _config_value(profile_config, "dns_server") or assessment_target.get("dns_server")
    base_dn = _config_value(profile_config, "base_dn") or assessment_target.get("base_dn") or _base_dn_from_domain(str(domain))
    target_subnets = _config_value(profile_config, "target_subnets") or assessment_target.get("target_subnets") or []
    if isinstance(target_subnets, str):
        target_subnets = [item.strip() for item in target_subnets.split(",") if item.strip()]

    return ResolvedConnection(
        domain=str(domain),
        dc_ip=str(dc_ip) if dc_ip else None,
        dc_hostname=str(dc_hostname) if dc_hostname else None,
        dns_server=str(dns_server) if dns_server else None,
        base_dn=str(base_dn) if base_dn else None,
        target_subnets=[str(item) for item in target_subnets],
        profile_id=str(profile.id) if profile else None,
        transport_mode=profile.mode.value if profile else "DIRECT",
    )
