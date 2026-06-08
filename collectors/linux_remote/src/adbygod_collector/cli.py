#!/usr/bin/env python3
"""
AdByG0d Platform — Linux Remote Collector v1.0
Enterprise Identity Exposure Assessment — Authorized use only.

Wraps the existing module engine and outputs canonical platform JSON.
Can upload directly to the API or save to file for offline analysis.

Usage:
  # Direct output to file
  ADBYGOD_PASSWORD='replace-me' python3 collect.py -d corp.local -u admin -dc-ip 10.10.10.1

  # Upload to platform API
  ADBYGOD_PASSWORD='replace-me' python3 collect.py -d corp.local -u admin -dc-ip 10.10.10.1 \
    --api-url http://localhost:8000 --assessment-id <uuid>

  # Specific modules only
  python3 collect.py -d corp.local -u admin --password-file ./collector.pass -dc-ip 10.10.10.1 \
    -m enum,kerberos,adcs

Prefer ADBYGOD_PASSWORD, --password-file, or the interactive prompt over -p.
Authorized defensive security assessment use only.
"""

import argparse
import getpass
import os
import sys
import time
from datetime import datetime

# Resolve core/ and modules/ from the project root (../../ relative to this file)
_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_HERE, '..', '..'))
sys.path.insert(0, _PROJECT_ROOT)

from .core.banner import (  # noqa: E402
    C, print_banner, section_header, info, success, error, warning,
    print_summary
)
from .core.connector import ADConnector  # noqa: E402
from .core.reporter import Reporter  # noqa: E402
from .canonical_output import (  # noqa: E402
    CanonicalOutput
)

from .modules.enumeration import EnumerationModule  # noqa: E402
from .modules.kerberos_attacks import KerberosModule  # noqa: E402
from .modules.acl_abuse import ACLModule  # noqa: E402
from .modules.adcs import ADCSModule  # noqa: E402
from .modules.smb_attacks import SMBModule  # noqa: E402
from .modules.coercion import CoercionModule  # noqa: E402
from .modules.passwords import PasswordModule  # noqa: E402
from .modules.persistence import PersistenceModule  # noqa: E402


MODULES = {
    "enum":         ("Domain Enumeration",          EnumerationModule),
    "kerberos":     ("Kerberos Exposure",           KerberosModule),
    "acl":          ("ACL Exposure",                ACLModule),
    "adcs":         ("AD CS Exposure",              ADCSModule),
    "smb":          ("SMB Posture",                 SMBModule),
    "coercion":     ("Coercion Exposure",           CoercionModule),
    "passwords":    ("Password Exposure",           PasswordModule),
    "persistence":  ("Persistence Indicators",      PersistenceModule),
}


def parse_args():
    parser = argparse.ArgumentParser(
        description=f"{C.BRED}AdByG0d v1.0{C.RST} — Enterprise Identity Exposure Assessment Collector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    target = parser.add_argument_group("Target")
    target.add_argument("-d", "--domain", help="Target domain FQDN")
    target.add_argument("-dc-ip", "--dc-ip", help="Domain Controller IP")

    auth = parser.add_argument_group("Authentication")
    auth.add_argument("-u", "--username", help="Username")
    auth.add_argument("-p", "--password", help="Password (discouraged: visible in shell history and process listings)")
    auth.add_argument("--password-file", help="Read password from file instead of passing it on the command line")
    auth.add_argument("-H", "--hashes", help="NTLM hashes (LM:NT or :NT)")
    auth.add_argument("--null", action="store_true", help="Null session")
    auth.add_argument("--no-prompt-password", action="store_true", help="Fail instead of prompting when a password is required but not supplied")

    mods = parser.add_argument_group("Modules")
    mods.add_argument("-m", "--modules", default="all", help="Modules to run (default: all)")
    mods.add_argument("--list-modules", action="store_true", help="List modules and exit")

    conn = parser.add_argument_group("Connection")
    conn.add_argument("--ssl", action="store_true", help="Use LDAPS")
    conn.add_argument("--timeout", type=int, default=10)
    conn.add_argument("--no-smb", action="store_true", help="Skip SMB")

    output = parser.add_argument_group("Output")
    output.add_argument("-o", "--output-dir", default="output", help="Output directory")
    output.add_argument("--canonical", action="store_true", default=True,
                        help="Save canonical JSON (default: true)")
    output.add_argument("--no-html", action="store_true", help="Skip HTML report")
    output.add_argument("--no-json", action="store_true", help="Skip legacy JSON report")
    output.add_argument("--fast", action="store_true", help="Skip banner animations")

    platform = parser.add_argument_group("Platform Integration")
    platform.add_argument("--api-url", help="Platform API URL (e.g. http://localhost:8000)")
    platform.add_argument("--assessment-id", help="Assessment UUID to ingest into")

    args = parser.parse_args()

    if args.password and args.password_file:
        parser.error("use either --password or --password-file, not both")

    if not args.list_modules:
        missing = []
        if not args.domain:
            missing.append("-d/--domain")
        if not args.dc_ip:
            missing.append("-dc-ip/--dc-ip")
        if missing:
            parser.error(f"the following arguments are required: {', '.join(missing)}")

    return args


def _resolve_password(args) -> str | None:
    if args.password:
        warning("Password supplied on the command line may be exposed via shell history and process listings")
        return args.password

    if args.password_file:
        with open(args.password_file, "r", encoding="utf-8") as handle:
            return handle.read().rstrip("\r\n")

    env_password = os.environ.get("ADBYGOD_PASSWORD")
    if env_password:
        return env_password

    if args.null or args.hashes or not args.username:
        return None

    if args.no_prompt_password:
        error("Password required but not supplied. Use --password-file, ADBYGOD_PASSWORD, or interactive prompt.")
        sys.exit(1)

    if not sys.stdin.isatty():
        error("Password required but no TTY available. Use --password-file, ADBYGOD_PASSWORD, or --no-prompt-password.")
        sys.exit(1)

    return getpass.getpass("AD password: ")


def run_modules(module_keys, connector, reporter):
    for key in module_keys:
        if key not in MODULES:
            warning(f"Unknown module: {key}")
            continue
        name, cls = MODULES[key]
        try:
            module = cls(connector, reporter)
            module.run()
        except KeyboardInterrupt:
            warning(f"Module {name} interrupted")
        except Exception as e:
            error(f"Module {name} failed: {str(e)}")
            import traceback
            traceback.print_exc()


def build_canonical(reporter, connector, domain, dc_ip):
    """Convert Reporter output to canonical platform format."""
    output = CanonicalOutput(domain=domain, dc_ip=dc_ip, collection_mode="LINUX_REMOTE")
    output.from_legacy_reporter(reporter)

    # Add domain metadata
    output.set_domain_info({
        "domain": domain,
        "dc_ip": dc_ip,
        "total_users": reporter.findings_dict.get("total_users", 0) if hasattr(reporter, 'findings_dict') else 0,
    })

    return output


def main():
    args = parse_args()
    args.password = _resolve_password(args)

    print_banner(fast=args.fast)

    if args.list_modules:
        for key, (name, cls) in MODULES.items():
            cls.DESCRIPTION if hasattr(cls, 'DESCRIPTION') else ""
            print(f"  {C.BYELLOW}{key:15s}{C.RST}  {name}")
        sys.exit(0)

    if not args.null and not args.username:
        error("Authentication required. Use -u/-p, -H, or --null")
        sys.exit(1)

    # ── Connect ──────────────────────────────────────────────────
    section_header("Connection Phase", "")
    connector = ADConnector(
        target=args.dc_ip,
        domain=args.domain,
        username=args.username,
        password=args.password,
        hashes=args.hashes,
        dc_ip=args.dc_ip,
        use_ssl=args.ssl,
        timeout=args.timeout,
    )

    info("Establishing LDAP connection...")
    if not connector.connect_ldap():
        error("Failed to establish LDAP connection.")
        sys.exit(1)

    if not args.no_smb:
        info("Establishing SMB connection...")
        connector.connect_smb()

    # ── Initialize output ────────────────────────────────────────
    os.makedirs(args.output_dir, exist_ok=True)
    reporter = Reporter(args.domain, args.output_dir)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    # ── Run modules ──────────────────────────────────────────────
    section_header("Assessment Modules", "")
    start_time = time.time()

    if args.modules == "all":
        module_keys = list(MODULES.keys())
    else:
        module_keys = [m.strip() for m in args.modules.split(",")]

    info(f"Running {len(module_keys)} module(s): {', '.join(module_keys)}")
    run_modules(module_keys, connector, reporter)

    elapsed = time.time() - start_time

    # ── Generate reports ─────────────────────────────────────────
    section_header("Output Generation", "")
    reporter.scan_end = datetime.now()

    if not args.no_json:
        reporter.generate_json()
    if not args.no_html:
        reporter.generate_html()

    # ── Build canonical output ───────────────────────────────────
    canonical = CanonicalOutput(
        domain=args.domain,
        dc_ip=args.dc_ip,
        collection_mode="LINUX_REMOTE",
    )
    canonical.from_legacy_reporter(reporter)
    canonical.modules_run = module_keys

    canonical_path = os.path.join(
        args.output_dir,
        f"adbygod_canonical_{args.domain}_{timestamp}.json"
    )
    canonical.save(canonical_path)

    # ── Platform upload ──────────────────────────────────────────
    if args.api_url and args.assessment_id:
        info(f"Uploading to platform API: {args.api_url}")
        success_upload = canonical.upload_to_api(args.api_url, args.assessment_id)
        if success_upload:
            success("Assessment data uploaded to platform")
        else:
            warning(f"Upload failed — canonical JSON saved locally at {canonical_path}")

    # ── Summary ──────────────────────────────────────────────────
    stats = reporter.get_stats()
    print_summary(stats)

    print(f"\n  {C.DIM}  Execution time: {elapsed:.1f}s{C.RST}")
    print(f"  {C.DIM}  Canonical output: {canonical_path}{C.RST}")
    print(f"\n  {C.BRED}{C.BOLD}  AdByG0d v1.0 — Assessment complete.{C.RST}\n")

    connector.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {C.BYELLOW}  [!] Interrupted by user.{C.RST}\n")
        sys.exit(130)
