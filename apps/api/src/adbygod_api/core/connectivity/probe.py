from __future__ import annotations

import asyncio
import time
from typing import Any

from adbygod_api.core.connectivity.transport import ProxyTransport

# Port → (service_name, ad_capability)
AD_PORTS: dict[int, tuple[str, str]] = {
    53:   ("dns",      "DNS resolution — required for Kerberos + LDAP hostname lookup"),
    88:   ("kerberos", "Kerberos auth — required for all ticket-based attacks"),
    135:  ("rpc",      "RPC endpoint mapper — required for impacket RPC techniques"),
    389:  ("ldap",     "LDAP — required for collection, enumeration, ACL analysis"),
    445:  ("smb",      "SMB — required for secretsdump, lateral movement, shares"),
    636:  ("ldaps",    "LDAPS — secure LDAP (optional but preferred)"),
    3268: ("gc",       "Global Catalog — required for forest-wide queries"),
    3269: ("gc_ssl",   "Global Catalog SSL — secure GC queries"),
    5985: ("winrm",    "WinRM HTTP — required for winrm/psexec techniques"),
    5986: ("winrm_ssl","WinRM HTTPS — secure WinRM"),
}

# Capability → required ports (all must be open)
CAPABILITY_REQUIREMENTS: dict[str, list[int]] = {
    "ldap_collection":   [389],
    "ldaps_collection":  [636],
    "kerberoast":        [88, 389],
    "asreproast":        [88, 389],
    "dcsync":            [445, 135],
    "secretsdump":       [445, 135],
    "lateral_movement":  [445],
    "winrm":             [5985],
    "winrm_ssl":         [5986],
    "global_catalog":    [3268],
    "global_catalog_ssl":[3269],
    "dns_resolution":    [53],
}


async def tcp_probe(host: str, port: int, transport: ProxyTransport, timeout: float = 3.0) -> dict[str, Any]:
    """Attempt TCP connect to host:port via the given transport."""
    start = time.perf_counter()
    error: str | None = None
    success = False

    if transport.via_tun or not (transport.proxy_host and transport.proxy_port):
        try:
            conn = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
            conn[1].close()
            success = True
        except Exception as exc:
            error = str(exc)
    else:
        def _socks_connect():
            import socks as pysocks
            s = pysocks.socksocket()
            s.set_proxy(pysocks.SOCKS5, transport.proxy_host, transport.proxy_port)
            s.settimeout(timeout)
            s.connect((host, port))
            s.close()

        try:
            await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(None, _socks_connect),
                timeout=timeout + 1,
            )
            success = True
        except Exception as exc:
            error = str(exc)

    latency_ms = int((time.perf_counter() - start) * 1000)
    return {
        "success": success,
        "latency_ms": latency_ms if success else None,
        "error": error,
        "host": host,
        "port": port,
        "transport_mode": transport.mode,
    }


async def multi_probe(host: str, transport: ProxyTransport) -> dict[str, Any]:
    """Probe all 10 AD-relevant ports in parallel. Returns probes + capability matrix."""
    ports = list(AD_PORTS.keys())
    results = await asyncio.gather(
        *[tcp_probe(host, p, transport) for p in ports],
        return_exceptions=True,
    )

    probes: dict[str, Any] = {}
    open_ports: set[int] = set()
    min_latency: int | None = None

    for port, result in zip(ports, results, strict=True):
        service, _ = AD_PORTS[port]
        if isinstance(result, Exception):
            probes[service] = {"success": False, "error": str(result), "port": port}
        else:
            probes[service] = {**result, "port": port}
            if result["success"]:
                open_ports.add(port)
                lat = result.get("latency_ms")
                if lat is not None:
                    min_latency = lat if min_latency is None else min(min_latency, lat)

    # Build capability matrix
    capabilities: dict[str, bool] = {
        cap: all(p in open_ports for p in required)
        for cap, required in CAPABILITY_REQUIREMENTS.items()
    }

    # Overall readiness score
    critical_caps = ["ldap_collection", "kerberoast", "dcsync", "secretsdump"]
    ready_critical = sum(1 for c in critical_caps if capabilities.get(c))
    readiness_pct = int(ready_critical / len(critical_caps) * 100)
    ldap_ready = capabilities["ldap_collection"] or capabilities["ldaps_collection"]
    status = "ONLINE" if ldap_ready else ("DEGRADED" if open_ports else "OFFLINE")

    return {
        "success": ldap_ready,
        "status": status,
        "latency_ms": min_latency,
        "probes": probes,
        "capabilities": capabilities,
        "readiness_pct": readiness_pct,
        "open_ports": sorted(open_ports),
        "host": host,
        "transport_mode": transport.mode,
    }
