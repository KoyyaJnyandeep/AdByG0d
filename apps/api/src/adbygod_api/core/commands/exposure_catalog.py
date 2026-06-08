"""High-signal read-only exposure checks for assessment launchers."""

from __future__ import annotations

from typing import Any


EXPOSURE_QUICK_CHECK_MODULES: list[dict[str, Any]] = [
    {
        "id": "exposure_quick_checks",
        "name": "Exposure Quick Checks",
        "category": "identity-hygiene",
        "description": (
            "Fast read-only checks that surface common AD exposure signals in both "
            "remote Linux collection and Windows PowerShell ZIP collection."
        ),
        "supported_modes": ["WINDOWS_LOCAL", "WINDOWS_REMOTE", "LINUX_REMOTE", "IMPORT"],
        "read_only": False,
        "command_groups": [
            {
                "id": "windows-exposure-identity",
                "name": "Windows identity exposure",
                "description": "PowerShell AD-module checks for the account and host flags most often tied to findings.",
                "commands": [
                    {
                        "id": "quick-get-aduser-risk",
                        "title": "Collect risky user account flags",
                        "command": "Get-ADUser -Filter * -Properties SamAccountName,SID,Enabled,AdminCount,UserAccountControl,PasswordNeverExpires,DoesNotRequirePreAuth,ServicePrincipalName,TrustedForDelegation,TrustedToAuthForDelegation,AccountNotDelegated,LastLogonDate,PasswordLastSet,DistinguishedName,msDS-SupportedEncryptionTypes",
                        "notes": "Feeds AS-REP, Kerberoast, PASSWD_NOTREQD, delegation, stale, adminCount, and RC4-only detections.",
                    },
                    {
                        "id": "quick-get-adcomputer-risk",
                        "title": "Collect risky computer account flags",
                        "command": "Get-ADComputer -Filter * -Properties SamAccountName,SID,Name,Enabled,DNSHostName,OperatingSystem,UserAccountControl,TrustedForDelegation,TrustedToAuthForDelegation,ServicePrincipalName,DistinguishedName,ms-Mcs-AdmPwdExpirationTime,msLAPS-PasswordExpirationTime",
                        "notes": "Feeds unconstrained delegation, DC inventory, stale host, and LAPS coverage checks.",
                    },
                    {
                        "id": "quick-get-domain-policy",
                        "title": "Collect domain policy and MAQ",
                        "command": "Get-ADDomain | Select-Object DNSRoot,NetBIOSName,DomainMode,Forest,DistinguishedName,ms-DS-MachineAccountQuota",
                        "notes": "Feeds MachineAccountQuota and domain metadata checks.",
                    },
                    {
                        "id": "quick-get-tier0-groups",
                        "title": "Collect high-value group membership",
                        "command": "Get-ADGroup -LDAPFilter '(|(samAccountName=Domain Admins)(samAccountName=Enterprise Admins)(samAccountName=Schema Admins)(samAccountName=Administrators)(samAccountName=Protected Users))' -Properties member,adminCount",
                        "notes": "Tier-0 and Protected Users coverage without modifying group state.",
                    },
                ],
            },
            {
                "id": "windows-exposure-network",
                "name": "Windows network policy exposure",
                "description": "Registry and service-state checks that map to relay, NTLM downgrade, and remote-management findings.",
                "commands": [
                    {
                        "id": "quick-reg-smb-signing",
                        "title": "Check SMB signing requirement",
                        "command": "reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters /v RequireSecuritySignature",
                        "notes": "0 or missing indicates SMB signing is not required on the queried host.",
                    },
                    {
                        "id": "quick-reg-ldap-signing",
                        "title": "Check LDAP signing requirement",
                        "command": "reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters /v LDAPServerIntegrity",
                        "notes": "2 means LDAP signing is required on a DC.",
                    },
                    {
                        "id": "quick-reg-ldap-channel-binding",
                        "title": "Check LDAP channel binding",
                        "command": "reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters /v LdapEnforceChannelBinding",
                        "notes": "2 means LDAP channel binding is always enforced.",
                    },
                    {
                        "id": "quick-reg-lmcompat",
                        "title": "Check NTLM compatibility level",
                        "command": "reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v LmCompatibilityLevel",
                        "notes": "5 is the hardened setting: NTLMv2 only, refuse LM and NTLM.",
                    },
                    {
                        "id": "quick-winrm-service",
                        "title": "Check WinRM service listener policy",
                        "command": "winrm get winrm/config/service",
                        "notes": "Remote management exposure and authentication settings.",
                    },
                ],
            },
            {
                "id": "linux-exposure-ldap",
                "name": "Remote Linux LDAP exposure",
                "description": "Authenticated ldapsearch checks for account, policy, delegation, and LAPS posture.",
                "commands": [
                    {
                        "id": "quick-ldap-domain-policy",
                        "title": "Read domain policy",
                        "command": "ldapsearch -x -H ldap://<IP> -D <user> -w <pass> -b <base_dn> '(objectClass=domain)' minPwdLength lockoutThreshold pwdHistoryLength pwdProperties ms-DS-MachineAccountQuota msDS-Behavior-Version",
                        "notes": "Remote policy and MAQ baseline.",
                    },
                    {
                        "id": "quick-ldap-asrep",
                        "title": "Find AS-REP roastable accounts",
                        "command": "ldapsearch -x -H ldap://<IP> -D <user> -w <pass> -b <base_dn> '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' sAMAccountName userAccountControl",
                        "notes": "Flags DONT_REQUIRE_PREAUTH without requesting hashes.",
                    },
                    {
                        "id": "quick-ldap-spn-users",
                        "title": "Find SPN-bearing users",
                        "command": "ldapsearch -x -H ldap://<IP> -D <user> -w <pass> -b <base_dn> '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))' sAMAccountName servicePrincipalName msDS-SupportedEncryptionTypes adminCount",
                        "notes": "Remote Kerberoast surface inventory without requesting TGS tickets.",
                    },
                    {
                        "id": "quick-ldap-unconstrained",
                        "title": "Find unconstrained delegation",
                        "command": "ldapsearch -x -H ldap://<IP> -D <user> -w <pass> -b <base_dn> '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))' dNSHostName sAMAccountName userAccountControl",
                        "notes": "High-impact host delegation exposure.",
                    },
                    {
                        "id": "quick-ldap-laps",
                        "title": "Check LAPS coverage",
                        "command": "ldapsearch -x -H ldap://<IP> -D <user> -w <pass> -b <base_dn> '(|(ms-Mcs-AdmPwdExpirationTime=*)(msLAPS-PasswordExpirationTime=*))' dNSHostName ms-Mcs-AdmPwdExpirationTime msLAPS-PasswordExpirationTime",
                        "notes": "Coverage signal only; does not read managed passwords.",
                    },
                ],
            },
            {
                "id": "linux-exposure-network",
                "name": "Remote Linux network exposure",
                "description": "Safe network-level checks for AD service reachability and signing posture.",
                "commands": [
                    {
                        "id": "quick-nmap-ad-ports",
                        "title": "Check core AD ports",
                        "command": "nmap -Pn -p 53,88,135,389,445,464,636,3268,3269,5985,5986 <IP>",
                        "notes": "Confirms LDAP, Kerberos, SMB, GC, LDAPS, and WinRM exposure from the scanner host.",
                    },
                    {
                        "id": "quick-nmap-smb-signing",
                        "title": "Check SMB signing",
                        "command": "nmap -Pn -p445 --script smb2-security-mode,smb-security-mode <IP>",
                        "notes": "Identifies SMB signing enabled-but-not-required posture.",
                    },
                    {
                        "id": "quick-ldap-rootdse-controls",
                        "title": "Read LDAP RootDSE controls",
                        "command": "ldapsearch -x -H ldap://<IP> -s base -b '' supportedCapabilities supportedControl defaultNamingContext configurationNamingContext dnsHostName",
                        "notes": "LDAP feature and naming context discovery.",
                    },
                ],
            },
        ],
        "excluded_capabilities": [
            "credential dumping",
            "password spraying",
            "ticket requests",
            "relay execution",
            "directory modification",
        ],
    }
]


def merge_exposure_modules(modules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = {module["id"] for module in modules}
    return modules + [module for module in EXPOSURE_QUICK_CHECK_MODULES if module["id"] not in seen]
