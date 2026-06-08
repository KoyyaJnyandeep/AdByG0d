from __future__ import annotations

import asyncio
import logging
import socket
import subprocess
import urllib.request
import uuid
from datetime import datetime, timezone

from adbygod_api.core.celery_app import celery_app
from adbygod_api.core.recon.parsers.ldap_parser import parse_ldap_output
from adbygod_api.core.recon.parsers.smb_parser import parse_smb_output
from adbygod_api.core.recon.parsers.rid_parser import parse_rid_output
from adbygod_api.core.recon.parsers.dns_parser import parse_dns_output
from adbygod_api.core.recon.parsers.cert_parser import parse_cert_json
from adbygod_api.core.kill_chain.mitre_map import enrich_technique

log = logging.getLogger(__name__)
PROBE_TIMEOUT = 30


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


@celery_app.task(
    bind=True,
    name="adbygod.run_recon_scan",
    queue="recon_jobs",
    acks_late=True,
    max_retries=0,
    reject_on_worker_lost=True,
)
def run_recon_scan(self, scan_id: str) -> None:
    asyncio.run(_execute_scan(scan_id))


async def _execute_scan(scan_id: str) -> None:
    from adbygod_api.config import settings
    from adbygod_api.database import AsyncSessionLocal
    from adbygod_api.models import ReconScan, ReconScanStatus
    from adbygod_api.core.streaming import store_and_publish_line
    import redis.asyncio as aioredis

    scan_uuid = uuid.UUID(scan_id)
    redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)

    async with AsyncSessionLocal() as db:
        scan = await db.get(ReconScan, scan_uuid)
        if not scan:
            log.error("ReconScan %s not found", scan_id)
            await redis_client.aclose()
            return
        dc_ip = scan.target_dc_ip or ""
        domain = scan.domain or ""
        scan.status = ReconScanStatus.RUNNING
        scan.started_at = _utcnow()
        await db.commit()

    async def emit(msg: str, stream: str = "stdout") -> None:
        try:
            await store_and_publish_line(redis_client, scan_id, {"line": msg, "stream": stream, "job_id": scan_id})
        except Exception:
            pass

    async def run_probe(probe_fn, *args):
        try:
            return await asyncio.get_event_loop().run_in_executor(None, probe_fn, *args)
        except Exception as exc:
            log.warning("Recon probe %s failed: %s", probe_fn.__name__, exc)
            return None

    findings: list[dict] = []

    await emit(f"[*] Phase 0 Recon Scan starting — DC: {dc_ip}, domain: {domain}")

    # Probe 1: LDAP anon bind
    await emit("[*] Probe 1/11: LDAP Anonymous Bind...")
    r = await run_probe(_ldap_probe, dc_ip)
    if r and r.get("anon_bind"):
        await emit(f"[+] LDAP anon bind SUCCESS — base: {r.get('defaultNamingContext', '?')}")
        findings.append(enrich_technique("recon-ldap-anon", {
            "type": "ldap_exposure", "severity": "HIGH",
            "title": "Anonymous LDAP Binding Enabled",
            "detail": f"DC {dc_ip} accepts unauthenticated LDAP. BaseDN: {r.get('defaultNamingContext', '')}",
            "finding_type": "ANONYMOUS_LDAP_ENABLED", "raw": r,
        }))
    elif r:
        await emit(f"[-] LDAP: Anonymous bind rejected on {dc_ip}")

    # Probe 2: SMB null session
    await emit("[*] Probe 2/11: SMB Null Session...")
    r = await run_probe(_smb_probe, dc_ip)
    if r and r.get("null_session"):
        shares = r.get("shares", [])
        await emit(f"[+] SMB null session OPEN — shares: {', '.join(shares)}")
        findings.append(enrich_technique("recon-smb-null", {
            "type": "smb_null", "severity": "HIGH",
            "title": "SMB Null Session Permitted",
            "detail": f"Host {dc_ip} allows null SMB session. Shares: {shares}",
            "finding_type": "SMB_NULL_SESSION", "raw": r,
        }))
    elif r:
        await emit(f"[-] SMB: Null session rejected on {dc_ip}")

    # Probe 3: RID cycling
    await emit("[*] Probe 3/11: RID Cycling...")
    r = await run_probe(_rid_probe, dc_ip, domain)
    if r:
        users = r.get("users", [])
        if users:
            await emit(f"[+] RID: {len(users)} user(s): {', '.join(users[:10])}{'...' if len(users) > 10 else ''}")
            findings.append(enrich_technique("recon-rid-cycling", {
                "type": "user_enum", "severity": "HIGH",
                "title": f"RID Cycling: {len(users)} Domain Accounts Enumerated",
                "detail": f"Null session RID cycling revealed {len(users)} accounts",
                "finding_type": "RID_CYCLING_SUCCESS",
                "raw": {"users": users, "groups": r.get("groups", [])},
            }))
        else:
            await emit("[-] RID: No accounts returned")

    # Probe 4: SNTP/Timeroasting
    await emit("[*] Probe 4/11: MS-SNTP Timeroasting probe...")
    r = await run_probe(_sntp_probe, dc_ip)
    if r and r.get("reachable"):
        await emit(f"[+] SNTP: NTP port reachable on {dc_ip} — Timeroasting may be possible")
        findings.append(enrich_technique("ia-timeroast", {
            "type": "timeroast_exposure", "severity": "HIGH",
            "title": "MS-SNTP Hash Extraction Possible (Timeroasting)",
            "detail": f"DC {dc_ip} NTP port accessible. Run timeroast.py for full extraction.",
            "finding_type": "TIMEROAST_EXPOSURE", "raw": r,
        }))
    else:
        await emit("[-] SNTP: NTP port unreachable")

    # Probe 5: DNS records
    await emit("[*] Probe 5/11: DNS Record Enumeration...")
    r = await run_probe(_dns_probe, dc_ip, domain)
    if r:
        types = r.get("record_types", [])
        if types:
            await emit(f"[+] DNS: Record types: {', '.join(types)}")
            if r.get("zone_transfer"):
                findings.append(enrich_technique("recon-dns-enum", {
                    "type": "dns_exposure", "severity": "MEDIUM",
                    "title": "DNS Records Enumerated",
                    "detail": f"Record types: {types}",
                    "finding_type": "DNS_ZONE_TRANSFER", "raw": r,
                }))

    # Probe 6: Certificate transparency
    await emit("[*] Probe 6/11: Certificate Transparency (crt.sh)...")
    r = await run_probe(_cert_probe, domain)
    if r:
        domains_found = r.get("domains", [])
        if domains_found:
            await emit(f"[+] Cert: {len(domains_found)} subdomain(s) via crt.sh")
            findings.append(enrich_technique("recon-cert-transparency", {
                "type": "cert_exposure", "severity": "LOW",
                "title": f"Certificate Transparency: {len(domains_found)} Subdomains",
                "detail": f"crt.sh: {', '.join(domains_found[:10])}",
                "finding_type": "CERT_TRANSPARENCY", "raw": r,
            }))

    # Probe 7: Kerberos user enumeration
    await emit("[*] Probe 7/11: Kerberos User Enumeration (nmap krb5-enum-users)...")
    r = await run_probe(_kerbrute_probe, dc_ip, domain)
    if r and r.get("valid_users"):
        users = r["valid_users"]
        await emit(f"[+] Kerbrute: {len(users)} valid user(s): {', '.join(users[:5])}")
        findings.append(enrich_technique("recon-kerbrute", {
            "type": "user_enum", "severity": "MEDIUM",
            "title": f"Kerberos Valid Users: {len(users)} Enumerated",
            "detail": f"nmap krb5-enum-users found {len(users)} valid accounts: {', '.join(users[:5])}",
            "finding_type": "KERBRUTE_USER_ENUM", "raw": r,
        }))
    elif r and r.get("skipped"):
        await emit(f"[-] Kerbrute: skipped — {r.get('reason')}")
    else:
        await emit("[-] Kerbrute: no valid users found or wordlist unavailable")

    # Probe 8: SNMP default community
    await emit("[*] Probe 8/11: SNMP Default Community String Probe...")
    r = await run_probe(_snmp_probe, dc_ip)
    if r and r.get("accessible"):
        await emit(f"[+] SNMP: community '{r['community']}' accepted on {dc_ip}")
        findings.append(enrich_technique("recon-snmp-enum", {
            "type": "snmp_exposure", "severity": "MEDIUM",
            "title": f"SNMP Default Community Accepted: '{r['community']}'",
            "detail": f"DC {dc_ip} responds to SNMP community '{r['community']}'. Info: {r.get('info', '')[:100]}",
            "finding_type": "SNMP_DEFAULT_COMMUNITY", "raw": r,
        }))
    else:
        await emit(f"[-] SNMP: no default community accepted on {dc_ip}")

    # Probe 9: NetBIOS
    await emit("[*] Probe 9/11: NetBIOS / NBT Name Discovery...")
    r = await run_probe(_netbios_probe, dc_ip)
    if r and r.get("accessible"):
        await emit(f"[+] NetBIOS: name='{r.get('name', '?')}' domain='{r.get('domain', '?')}'")
        findings.append(enrich_technique("recon-nbtscan", {
            "type": "netbios_info", "severity": "LOW",
            "title": "NetBIOS Name Service Accessible",
            "detail": f"Host: {r.get('name', '?')}, Domain/Workgroup: {r.get('domain', '?')}",
            "finding_type": "NETBIOS_ACCESSIBLE", "raw": r,
        }))
    else:
        await emit(f"[-] NetBIOS: not responding on {dc_ip}")

    # Probe 10: WinRM
    await emit("[*] Probe 10/11: WinRM Service Discovery...")
    r = await run_probe(_winrm_probe, dc_ip)
    if r:
        open_ports = [str(p) for p, k in ((5985, "port_5985"), (5986, "port_5986")) if r.get(k)]
        if open_ports:
            await emit(f"[+] WinRM: port(s) {', '.join(open_ports)} open on {dc_ip}")
            findings.append(enrich_technique("recon-winrm-rdp", {
                "type": "winrm_exposure", "severity": "MEDIUM",
                "title": f"WinRM Service Exposed (port {', '.join(open_ports)})",
                "detail": f"DC {dc_ip} has WinRM on port(s) {', '.join(open_ports)}. Lateral movement surface.",
                "finding_type": "WINRM_EXPOSED", "raw": r,
            }))
        else:
            await emit(f"[-] WinRM: ports 5985/5986 closed on {dc_ip}")

    # Probe 11: SMB signing
    await emit("[*] Probe 11/11: SMB Signing Check (relay prerequisite)...")
    r = await run_probe(_smb_signing_probe, dc_ip)
    if r and r.get("relay_possible"):
        await emit(f"[+] SMB: signing NOT required on {dc_ip} — NTLM relay possible!")
        findings.append(enrich_technique("recon-nmap-vuln", {
            "type": "smb_relay", "severity": "HIGH",
            "title": "SMB Signing Not Required — NTLM Relay Possible",
            "detail": f"DC {dc_ip} has SMB signing 'enabled but not required'. NTLM relay attacks are viable.",
            "finding_type": "SMB_SIGNING_NOT_REQUIRED", "raw": r,
        }))
    elif r:
        await emit(f"[-] SMB: signing required on {dc_ip} — relay not possible")

    summary = {
        "total": len(findings),
        "critical": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
        "high":     sum(1 for f in findings if f.get("severity") == "HIGH"),
        "medium":   sum(1 for f in findings if f.get("severity") == "MEDIUM"),
        "low":      sum(1 for f in findings if f.get("severity") == "LOW"),
    }
    await emit(f"[*] Scan complete — {summary['total']} finding(s): {summary['critical']} CRIT, {summary['high']} HIGH, {summary['medium']} MED, {summary['low']} LOW")

    async with AsyncSessionLocal() as db:
        scan = await db.get(ReconScan, scan_uuid)
        if scan:
            scan.status = ReconScanStatus.COMPLETED
            scan.completed_at = _utcnow()
            scan.findings = findings
            scan.summary = summary
            await db.commit()

    # Signal stream consumers that the scan is finished.
    try:
        await store_and_publish_line(redis_client, scan_id, {"done": True, "exit_code": 0})
    except Exception:
        pass

    await redis_client.aclose()


# ── Probe implementations (blocking, run in executor) ─────────────────────────

def _ldap_probe(dc_ip: str) -> dict:
    cmd = ["ldapsearch", "-x", "-H", f"ldap://{dc_ip}", "-b", "", "-s", "base",
           "(objectClass=*)", "defaultNamingContext", "namingContexts", "dnsHostName"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=PROBE_TIMEOUT)
    return parse_ldap_output(r.stdout, r.returncode)


def _smb_probe(dc_ip: str) -> dict:
    cmd = ["smbclient", "-N", "-L", f"//{dc_ip}"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=PROBE_TIMEOUT)
    return parse_smb_output(r.stdout or r.stderr, r.returncode)


def _rid_probe(dc_ip: str, domain: str) -> dict:
    target = f"{domain}/guest@{dc_ip}" if domain else f"guest@{dc_ip}"
    cmd = ["impacket-lookupsid", target, "-no-pass"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=PROBE_TIMEOUT)
    return parse_rid_output(r.stdout, r.returncode)


def _sntp_probe(dc_ip: str) -> dict:
    result: dict = {"reachable": False}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.connect((dc_ip, 123))
        sock.close()
        result["reachable"] = True
    except OSError:
        pass
    return result


def _dns_probe(dc_ip: str, domain: str) -> dict:
    cmd = ["dig", f"@{dc_ip}", domain, "ANY", "+noall", "+answer"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=PROBE_TIMEOUT)
    return parse_dns_output(r.stdout, r.returncode)


def _cert_probe(domain: str) -> dict:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return parse_cert_json(resp.read().decode())
    except Exception as exc:
        log.warning("crt.sh probe failed: %s", exc)
        return {"domains": [], "error": str(exc)}


def _kerbrute_probe(dc_ip: str, domain: str) -> dict:
    """Enumerate valid domain users via Kerberos pre-auth (nmap krb5-enum-users)."""
    import os
    wordlist = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
    if not os.path.exists(wordlist):
        return {"valid_users": [], "skipped": True, "reason": "wordlist not found"}
    cmd = [
        "nmap", "-p", "88", "--script", "krb5-enum-users",
        "--script-args", f"krb5-enum-users.realm={domain},userdb={wordlist}",
        dc_ip,
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=PROBE_TIMEOUT)
    valid_users: list[str] = []
    for line in r.stdout.splitlines():
        line = line.strip()
        if "Valid Kerberos credentials found" in line or "Valid user" in line:
            parts = line.split("\\")
            user = parts[-1].strip() if len(parts) > 1 else line.split()[-1]
            valid_users.append(user)
    return {"valid_users": valid_users, "raw": r.stdout[:500]}


def _snmp_probe(dc_ip: str) -> dict:
    """Probe UDP 161 for default SNMP community strings (public, private)."""
    result: dict = {"accessible": False, "community": None, "info": ""}
    for community in ("public", "private"):
        try:
            cmd = ["snmpwalk", "-v2c", "-c", community, "-t", "3", "-r", "1",
                   dc_ip, "1.3.6.1.2.1.1.1.0"]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if r.returncode == 0 and r.stdout.strip():
                result["accessible"] = True
                result["community"] = community
                result["info"] = r.stdout.strip()[:200]
                break
        except Exception:
            pass
    return result


def _netbios_probe(dc_ip: str) -> dict:
    """Query NetBIOS name table via nmblookup."""
    result: dict = {"accessible": False, "name": "", "domain": "", "raw": ""}
    try:
        cmd = ["nmblookup", "-A", dc_ip]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        result["raw"] = r.stdout[:400]
        if r.returncode == 0 and "ACTIVE" in r.stdout:
            result["accessible"] = True
            for line in r.stdout.splitlines():
                if "<00>" in line and "GROUP" not in line and not result["name"]:
                    result["name"] = line.strip().split()[0]
                elif "<00>" in line and "GROUP" in line and not result["domain"]:
                    result["domain"] = line.strip().split()[0]
    except Exception:
        pass
    return result


def _winrm_probe(dc_ip: str) -> dict:
    """Check if WinRM ports (5985/5986) are open via TCP connect."""
    result: dict = {"port_5985": False, "port_5986": False}
    for port, key in ((5985, "port_5985"), (5986, "port_5986")):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result[key] = sock.connect_ex((dc_ip, port)) == 0
            sock.close()
        except OSError:
            pass
    return result


def _smb_signing_probe(dc_ip: str) -> dict:
    """Check SMB signing configuration via nmap smb2-security-mode script."""
    result: dict = {"signing_required": True, "relay_possible": False, "raw": ""}
    try:
        cmd = ["nmap", "-p", "445", "--script", "smb2-security-mode", dc_ip]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=PROBE_TIMEOUT)
        result["raw"] = r.stdout[:400]
        if "Message signing enabled but not required" in r.stdout:
            result["signing_required"] = False
            result["relay_possible"] = True
        elif "Message signing enabled and required" in r.stdout:
            result["signing_required"] = True
    except Exception:
        pass
    return result
