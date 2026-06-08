from __future__ import annotations
from adbygod_api.core.recon.parsers.ldap_parser import parse_ldap_output
from adbygod_api.core.recon.parsers.smb_parser import parse_smb_output
from adbygod_api.core.recon.parsers.rid_parser import parse_rid_output
from adbygod_api.core.recon.parsers.dns_parser import parse_dns_output
from adbygod_api.core.recon.parsers.cert_parser import parse_cert_json


LDAP_ANON_STDOUT = """
dn:
defaultNamingContext: DC=corp,DC=local
dnsHostName: dc01.corp.local
"""

SMB_SHARES_STDOUT = """
\tSharename       Type      Comment
\t---------       ----      -------
\tADMIN$          Disk      Remote Admin
\tC$              Disk      Default share
\tIPC$            IPC       Remote IPC
\tSYSVOL          Disk      Logon server share
\tNETLOGON        Disk      Logon server share
"""

SMB_NULL_FAILED = "NT_STATUS_ACCESS_DENIED"

RID_STDOUT = """
[*] Brute forcing RIDs at 10.0.0.1
[*] 10.0.0.1: corp\\Administrator (SidTypeUser)
[*] 10.0.0.1: corp\\Guest (SidTypeUser)
[*] 10.0.0.1: corp\\krbtgt (SidTypeUser)
[*] 10.0.0.1: corp\\Domain Admins (SidTypeGroup)
[*] 10.0.0.1: corp\\jdoe (SidTypeUser)
"""

DNS_STDOUT = """
;; ANSWER SECTION:
corp.local.\t\t600 IN\tSOA\tdc01.corp.local. hostmaster.corp.local. 123 900 600 86400 3600
corp.local.\t\t600 IN\tNS\tdc01.corp.local.
_kerberos._tcp.corp.local. 600 IN SRV 0 100 88 dc01.corp.local.
"""

CERT_JSON = '[{"name_value": "corp.local"}, {"name_value": "*.corp.local"}, {"name_value": "mail.corp.local"}]'


def test_ldap_anon_detected():
    result = parse_ldap_output(LDAP_ANON_STDOUT, exit_code=0)
    assert result["anon_bind"] is True
    assert result.get("defaultNamingContext") == "DC=corp,DC=local"


def test_ldap_auth_failure_not_anon():
    result = parse_ldap_output("ldap_bind: Invalid credentials (49)", exit_code=49)
    assert result["anon_bind"] is False


def test_smb_shares_parsed():
    result = parse_smb_output(SMB_SHARES_STDOUT, exit_code=0)
    assert result["null_session"] is True
    assert "SYSVOL" in result["shares"]
    assert len(result["shares"]) >= 4


def test_smb_access_denied():
    result = parse_smb_output(SMB_NULL_FAILED, exit_code=1)
    assert result["null_session"] is False
    assert result["shares"] == []


def test_rid_users_parsed():
    result = parse_rid_output(RID_STDOUT, exit_code=0)
    assert len(result["users"]) >= 4
    assert "jdoe" in result["users"]
    assert "Administrator" in result["users"]


def test_dns_records_parsed():
    result = parse_dns_output(DNS_STDOUT, exit_code=0)
    assert result["zone_transfer"] is True
    assert "SOA" in result["record_types"]


def test_cert_transparency_parsed():
    result = parse_cert_json(CERT_JSON)
    assert "corp.local" in result["domains"]
    assert "mail.corp.local" in result["domains"]
