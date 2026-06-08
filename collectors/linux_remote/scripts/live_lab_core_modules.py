#!/usr/bin/env python3
"""Manual live-lab harness for validating core AD collection modules.

This script intentionally performs network operations against a domain
controller. It is not a pytest test and must be run explicitly.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import traceback
from dataclasses import dataclass


@dataclass(frozen=True)
class LabConfig:
    dc_ip: str
    domain: str
    username: str
    password: str
    base_dn: str


def parse_args() -> LabConfig:
    parser = argparse.ArgumentParser(description="Run live AdByG0d core-module checks against a lab DC")
    parser.add_argument("--dc-ip", default=os.getenv("ADBYG0D_LAB_DC_IP", ""))
    parser.add_argument("--domain", default=os.getenv("ADBYG0D_LAB_DOMAIN", ""))
    parser.add_argument("--username", default=os.getenv("ADBYG0D_LAB_USERNAME", ""))
    parser.add_argument("--password", default=os.getenv("ADBYG0D_LAB_PASSWORD", ""))
    parser.add_argument("--base-dn", default=os.getenv("ADBYG0D_LAB_BASE_DN", ""))
    args = parser.parse_args()

    missing = [name for name in ("dc_ip", "domain", "username", "base_dn") if not getattr(args, name)]
    if missing:
        parser.error(
            "missing required lab settings: "
            + ", ".join(missing)
            + ". Pass CLI flags or set ADBYG0D_LAB_* environment variables."
        )

    password = args.password or getpass.getpass("Lab password: ")
    if not password:
        parser.error("password is required via --password, ADBYG0D_LAB_PASSWORD, or prompt input")

    return LabConfig(
        dc_ip=args.dc_ip,
        domain=args.domain,
        username=args.username,
        password=password,
        base_dn=args.base_dn,
    )


def run_live_checks(cfg: LabConfig) -> int:
    results: list[str] = []

    def record(module: str, passed: bool, key_result: str, error: str | None = None) -> None:
        status = "PASS" if passed else "FAIL"
        err_str = f" | ERR: {error}" if error else ""
        results.append(f"{module:<22} | {status} | {key_result}{err_str}")

    print("[1/6] SMBCollector...")
    try:
        from adbygod_api.core.collection.smb_collector import SMBCollector
        col = SMBCollector(cfg.dc_ip, cfg.domain, cfg.username, cfg.password)
        shares = col.collect_shares()
        rpcdump = col.collect_rpcdump()
        record(
            "SMBCollector",
            bool(shares) or bool(rpcdump),
            f"shares={len(shares) if shares else 0}, rpcdump_entries={len(rpcdump) if rpcdump else 0}",
        )
    except Exception as exc:
        record("SMBCollector", False, "n/a", str(exc))
        traceback.print_exc()

    print("[2/6] NmapCollector...")
    try:
        from adbygod_api.core.collection.nmap_collector import NmapCollector
        col = NmapCollector(cfg.dc_ip)
        disc = col.host_discovery()
        scan = col.ad_service_scan()
        hosts_up = disc.get("hosts_up", []) if disc else []
        open_ports = scan.get("open_ports", []) if scan else []
        record("NmapCollector", bool(hosts_up) and bool(open_ports), f"hosts_up={len(hosts_up)}, open_ports={len(open_ports)}")
    except Exception as exc:
        record("NmapCollector", False, "n/a", str(exc))
        traceback.print_exc()

    print("[3-6/6] Building LDAP connection...")
    conn = None
    try:
        from ldap3 import Connection, NTLM, SAFE_SYNC, Server
        server = Server(cfg.dc_ip, port=389)
        conn = Connection(
            server,
            user=f"{cfg.domain}\\{cfg.username}",
            password=cfg.password,
            authentication=NTLM,
            client_strategy=SAFE_SYNC,
            auto_bind=True,
        )
        print(f"  LDAP bound: {conn.bound}")
    except Exception as exc:
        print(f"  LDAP bind FAILED: {exc}")
        traceback.print_exc()

    print("[3/6] DelegationAnalyzer...")
    try:
        from adbygod_api.core.analyzers.delegation_analyzer import DelegationAnalyzer
        if conn is None:
            raise RuntimeError("No LDAP connection")
        result = DelegationAnalyzer(conn, cfg.base_dn).analyze()
        key = (
            f"unconstrained={len(result.get('unconstrained', []))}, "
            f"constrained={len(result.get('constrained', []))}, "
            f"rbcd={len(result.get('rbcd', []))}"
        )
        record("DelegationAnalyzer", all(k in result for k in ("unconstrained", "constrained", "rbcd")), key)
    except Exception as exc:
        record("DelegationAnalyzer", False, "n/a", str(exc))
        traceback.print_exc()

    print("[4/6] GPOAnalyzer...")
    try:
        from adbygod_api.core.analyzers.gpo_analyzer import GPOAnalyzer
        if conn is None:
            raise RuntimeError("No LDAP connection")
        result = GPOAnalyzer(conn, cfg.base_dn).analyze()
        count = result.get("gpo_count", 0)
        record("GPOAnalyzer", count > 0, f"gpo_count={count}")
    except Exception as exc:
        record("GPOAnalyzer", False, "n/a", str(exc))
        traceback.print_exc()

    print("[5/6] TrustAnalyzer...")
    try:
        from adbygod_api.core.analyzers.trust_analyzer import TrustAnalyzer
        if conn is None:
            raise RuntimeError("No LDAP connection")
        result = TrustAnalyzer(conn, cfg.base_dn).analyze()
        record("TrustAnalyzer", "trusts" in result, f"trusts_found={len(result.get('trusts', []))}")
    except Exception as exc:
        record("TrustAnalyzer", False, "n/a", str(exc))
        traceback.print_exc()

    print("[6/6] ACLAnalyzer...")
    try:
        from adbygod_api.core.analyzers.acl_analyzer import ACLAnalyzer
        if conn is None:
            raise RuntimeError("No LDAP connection")
        result = ACLAnalyzer(conn, cfg.base_dn, cfg.domain, cfg.username, cfg.password, cfg.dc_ip).analyze()
        count = result.get("sd_objects_count", 0)
        record("ACLAnalyzer", count > 0, f"sd_objects_count={count}")
    except Exception as exc:
        record("ACLAnalyzer", False, "n/a", str(exc))
        traceback.print_exc()

    print("\n" + "=" * 80)
    print(f"{'MODULE':<22} | {'STATUS'} | KEY RESULT / ERROR")
    print("=" * 80)
    for row in results:
        print(row)
    print("=" * 80)

    passes = sum(1 for row in results if "| PASS |" in row)
    print(f"\n{passes}/{len(results)} modules PASSED")
    return 0 if passes == len(results) else 1


def main() -> int:
    return run_live_checks(parse_args())


if __name__ == "__main__":
    sys.exit(main())
