export const ENTITY_LETTER: Record<string, string> = {
  USER: 'U', SERVICE_ACCOUNT: 'SA', GMSA: 'GA', DMSA: 'DA',
  COMPUTER: 'C', SERVER: 'SV', DC: 'DC', DOMAIN_CONTROLLER: 'DC',
  GROUP: 'G',
  DOMAIN: 'D', FOREST: 'F',
  GPO: 'GP', GROUP_POLICY_OBJECT: 'GP',
  CA: 'CA', PKI: 'PK', CERT_TEMPLATE: 'CT',
  OU: 'OU', ORGANIZATIONAL_UNIT: 'OU',
  CONTAINER: 'CO', TRUST: 'TR', SITE: 'SI',
  WELL_KNOWN_PRINCIPAL: 'WK', UNKNOWN: '?',
}
export const getLetter = (t: string) => ENTITY_LETTER[t?.toUpperCase()] ?? '?'

export const LEGEND = [
  { label: 'DC / Tier-0', color: '#ef4444' },
  { label: 'Crown Jewel', color: '#f97316' },
  { label: 'User / SA', color: '#8b5cf6' },
  { label: 'Group', color: '#06b6d4' },
  { label: 'Computer', color: '#3b82f6' },
  { label: 'CA / PKI', color: '#ec4899' },
]

export const COLOR_MODE_CONFIGS: Record<string, { label: string; stops: string[] }> = {
  risk:   { label: 'Risk Heat Map',       stops: ['#3f3f46','#22d3ee','#eab308','#f97316','#ef4444'] },
  degree: { label: 'Degree Centrality',   stops: ['#3b82f6','#06b6d4','#22d3ee','#ef4444'] },
  tier:   { label: 'Tier Coloring',       stops: ['#ef4444','#f97316','#eab308','#22c55e','#06b6d4','#6b7280'] },
}
export const TIER_LABELS = ['Tier-0', 'Tier-1', 'Tier-2', 'Tier-3', 'Tier-4', 'Untiered']

export const SHORTCUTS = [
  { key: 'F',          desc: 'Toggle fullscreen' },
  { key: 'L',          desc: 'Toggle edge labels' },
  { key: 'R',          desc: 'Restart simulation' },
  { key: 'A',          desc: 'Toggle analytics panel' },
  { key: 'Q',          desc: 'Toggle query panel' },
  { key: 'C',          desc: 'Cycle color mode' },
  { key: 'P',          desc: 'Toggle path particle animation' },
  { key: '+/-',        desc: 'Zoom in / out' },
  { key: '0',          desc: 'Fit graph to screen' },
  { key: 'Cmd+K',      desc: 'Open command palette' },
  { key: 'Esc',        desc: 'Clear selection / exit fullscreen' },
  { key: 'Shift+drag', desc: 'Box-select nodes' },
  { key: 'Dblclick',   desc: 'Pin / unpin node' },
  { key: 'Click edge', desc: 'Edge abuse details' },
  { key: 'Right-click',desc: 'Node context menu' },
  { key: '← →',        desc: 'Navigate connected nodes' },
]

export function edgeRiskColor(w: number): string {
  if (w >= 0.8) return '#ef4444'
  if (w >= 0.6) return '#f97316'
  if (w >= 0.4) return '#eab308'
  return '#52525b'
}
export function edgeRiskOpacity(w: number): number {
  if (w >= 0.8) return 0.75
  if (w >= 0.6) return 0.65
  if (w >= 0.4) return 0.55
  return 0.38
}

export const EDGE_ABUSE: Record<string, { summary: string; abuse: string; opsec: string; risk: string }> = {
  MemberOf:            { summary: 'Source is a member of the target group', abuse: 'Inherit all group permissions and ACLs automatically', opsec: 'Group membership enumeration is passive', risk: 'Low' },
  AdminTo:             { summary: 'Source has local admin rights on target', abuse: 'Mimikatz sekurlsa::logonpasswords, lateral movement via WMI/PSRemoting', opsec: 'Remote admin connections logged in 4624/4648', risk: 'Critical' },
  HasSession:          { summary: 'A user has an active session on source', abuse: 'Dump creds with Mimikatz to capture the user\'s token', opsec: 'Requires local admin on the session host', risk: 'High' },
  CanRDP:              { summary: 'Source can RDP into target computer', abuse: 'Interactive session → credential capture or lateral movement', opsec: '4624 logon type 10 events on target', risk: 'High' },
  GenericAll:          { summary: 'Source has full control over target object', abuse: 'Write DACL, force password reset, add group members, shadow credential attack', opsec: 'Object modifications logged in 5136/4670', risk: 'Critical' },
  GenericWrite:        { summary: 'Source can write most attributes on target', abuse: 'Write msDS-KeyCredentialLink (Shadow Credentials), set SPN (Kerberoast), modify logon script', opsec: 'Attribute changes generate 5136 events', risk: 'Critical' },
  DCSync:              { summary: 'Source can replicate directory changes from the DC', abuse: 'mimikatz lsadump::dcsync /domain:... /all — dumps ALL hashes', opsec: '4662 with GUID 1131f6ad/1131f6aa on all DCs', risk: 'Critical' },
  WriteDACL:           { summary: 'Source can modify the DACL of target', abuse: 'Grant self GenericAll, then escalate', opsec: '4670 on modified object', risk: 'Critical' },
  WriteOwner:          { summary: 'Source can take ownership of target', abuse: 'Take ownership → modify DACL → full control', opsec: '4661, 4670 events', risk: 'Critical' },
  AddMember:           { summary: 'Source can add principals to the target group', abuse: 'Add controlled account to privileged group', opsec: '4728/4732 group modification events', risk: 'High' },
  ForceChangePassword: { summary: 'Source can reset target user password without knowing current', abuse: 'Set-DomainUserPassword or net user /domain reset', opsec: '4723/4724 password change events', risk: 'High' },
  AllowedToDelegate:   { summary: 'Source is trusted for Kerberos constrained delegation to target', abuse: 'S4U2Self + S4U2Proxy to impersonate any user to target service', opsec: 'Kerberos TGS requests for service', risk: 'Critical' },
  AllowedToAct:        { summary: 'Source is in target\'s msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)', abuse: 'RBCD: create computer, set attribute, S4U2Proxy as any user', opsec: 'Kerberos events on DC', risk: 'Critical' },
  Owns:                { summary: 'Source is the owner of the target AD object', abuse: 'Owner has implicit WriteDACL — grant self GenericAll', opsec: '4670 ownership change', risk: 'Critical' },
  Contains:            { summary: 'Target OU/container contains the source object', abuse: 'GPO applied to OU inherits to all child objects', opsec: 'Passive relationship', risk: 'Low' },
  GpLink:              { summary: 'GPO is linked to the target OU/site/domain', abuse: 'Modify GPO to deploy malicious policy to all contained computers/users', opsec: '5136 on GPO object', risk: 'High' },
  TrustedBy:           { summary: 'Target domain is trusted by source domain', abuse: 'SID history injection, cross-domain lateral movement', opsec: 'Trust ticket requests on DCs', risk: 'High' },
  SyncLAPSPassword:    { summary: 'Source can read LAPS password attribute on target', abuse: 'Read ms-Mcs-AdmPwd / msLAPS-Password for local admin creds', opsec: 'Attribute read logged if auditing enabled', risk: 'Critical' },
  ReadLAPSPassword:    { summary: 'Source can read the LAPS local admin password for target', abuse: 'Get-LAPSPassword / Get-AdmPwdPassword for instant local admin', opsec: 'Attribute read logged if auditing enabled', risk: 'Critical' },
  HasSIDHistory:       { summary: 'Source has target\'s SID in its SIDHistory attribute', abuse: 'Treated as member of target\'s primary group — full privilege escalation', opsec: '4765 SID history added events', risk: 'Critical' },
  CanPSRemote:         { summary: 'Source can WinRM/PSRemote into target', abuse: 'Enter-PSSession for remote code execution', opsec: '4624 logon type 3/network on target', risk: 'High' },
  ExecuteDCOM:         { summary: 'Source can execute code on target via DCOM', abuse: 'Invoke-DCOM lateral movement (MMC20.Application etc.)', opsec: 'Process creation events on target', risk: 'High' },
  SQLAdmin:            { summary: 'Source is a SQL admin on target SQL server', abuse: 'xp_cmdshell for OS command execution', opsec: 'SQL audit logs', risk: 'High' },
  AddSelf:             { summary: 'Source can add itself to the target group', abuse: 'Self-add to privileged group', opsec: '4728/4732', risk: 'High' },
  WriteSPN:            { summary: 'Source can set an SPN on target user account', abuse: 'Set SPN → request TGS → Kerberoast offline', opsec: '5136 attribute write', risk: 'High' },
  AddKeyCredentialLink:{ summary: 'Source can write msDS-KeyCredentialLink on target', abuse: 'Shadow Credentials attack → obtain TGT as target without password', opsec: '5136 on target object', risk: 'Critical' },
  MEMBER_OF:            { summary: 'Source is a member of the target group', abuse: 'Inherited group rights can chain into local admin, ACL, GPO, or tier-0 control', opsec: 'Group membership reads are passive; changes log as 4728/4732', risk: 'Low' },
  ADMIN_TO:             { summary: 'Source has local admin rights on target', abuse: 'Remote administration, credential exposure, and lateral movement paths', opsec: '4624/4648 and remote service telemetry on target', risk: 'Critical' },
  HAS_CONTROL:          { summary: 'Source has effective control over target', abuse: 'Treat as a generic control edge and inspect underlying ACL/evidence before validation', opsec: 'Depends on the specific right that produced the edge', risk: 'High' },
  GENERIC_ALL:          { summary: 'Source has full control over target object', abuse: 'Write DACL, force password reset, add group members, or add shadow credentials', opsec: 'Object modifications log in 5136/4670', risk: 'Critical' },
  GENERIC_WRITE:        { summary: 'Source can write attributes on target', abuse: 'Shadow Credentials, targeted Kerberoast, profile-path coercion, or RBCD setup depending on target type', opsec: 'Attribute changes log in 5136', risk: 'Critical' },
  WRITE_DACL:           { summary: 'Source can modify the target DACL', abuse: 'Grant DCSync, GenericAll, AddMember, or other rights to a controlled principal', opsec: '4670 and 5136 events on modified object', risk: 'Critical' },
  WRITE_OWNER:          { summary: 'Source can take ownership of target', abuse: 'Take ownership, write DACL, then grant full control', opsec: '4661/4670 ownership and permission-change telemetry', risk: 'Critical' },
  FORCE_CHANGE_PASSWORD:{ summary: 'Source can reset target user password', abuse: 'Reset account password and authenticate as the target', opsec: '4723/4724 password-change events', risk: 'High' },
  ADD_MEMBER:           { summary: 'Source can add principals to the target group', abuse: 'Add a controlled account to privileged or path-enabling groups', opsec: '4728/4732 group modification events', risk: 'High' },
  ALLOWED_TO_DELEGATE:  { summary: 'Source is configured for constrained delegation', abuse: 'S4U2Self + S4U2Proxy to impersonate users to allowed SPNs; check protocol-transition state', opsec: 'Kerberos TGS requests visible on DCs', risk: 'Critical' },
  ALLOWED_TO_ACT:       { summary: 'Target allows source to act via RBCD', abuse: 'S4U chain can impersonate users to services on the target', opsec: 'msDS-AllowedToAct writes log in 5136; use targeted validation', risk: 'Critical' },
  HAS_SPN:              { summary: 'Principal has one or more SPNs', abuse: 'SPN-bearing user accounts can be Kerberoastable; SQL SPNs can reveal linked-server paths', opsec: 'SPN enumeration is low-noise; ticket requests add Kerberos telemetry', risk: 'Medium' },
  CAN_ENROLL:           { summary: 'Principal can enroll in a certificate template', abuse: 'If template flags map to ESC1-ESC16, certificate authentication can become privilege escalation', opsec: 'Certificate requests are logged by CA and Windows security events', risk: 'High' },
  TRUSTS:               { summary: 'Domain or forest trust relationship', abuse: 'Trust tickets, SID history, ExtraSID, foreign groups, or child-to-parent escalation may apply', opsec: 'Trust enumeration is passive; abuse creates Kerberos trust-ticket telemetry', risk: 'High' },
  LOCAL_ADMIN:          { summary: 'Source has local administrator rights', abuse: 'Can access admin shares, WinRM/RDP if allowed, and local credential material', opsec: 'Remote logon and service-control events on target', risk: 'High' },
  CAN_RDP:              { summary: 'Source can RDP into target computer', abuse: 'Interactive access may expose tokens, drives, sessions, or local admin paths', opsec: '4624 logon type 10 and terminal-services logs', risk: 'High' },
  CAN_WINRM:            { summary: 'Source can use WinRM/PowerShell Remoting', abuse: 'Remote PowerShell access for administration or lateral validation', opsec: '4624 type 3 plus PowerShell/WinRM logs', risk: 'High' },
  DCSYNC:               { summary: 'Source has directory replication rights', abuse: 'Can replicate domain secrets, krbtgt, and all domain hashes in authorized validation', opsec: '4662 with replication GUIDs from non-DC principals', risk: 'Critical' },
  READ_LAPS_PASSWORD:   { summary: 'Source can read the LAPS password for target computer', abuse: 'Retrieve local administrator credentials and pivot to the host', opsec: 'Directory attribute read auditing may record access', risk: 'Critical' },
  READ_GMSA_PASSWORD:   { summary: 'Source can read gMSA managed password material', abuse: 'Recover the gMSA hash and authenticate as the service identity', opsec: 'Directory attribute read auditing may record access', risk: 'High' },
  WRITE_SPN:            { summary: 'Source can write SPNs on the target account', abuse: 'Add an SPN, request a TGS, and crack the account offline', opsec: '5136 attribute modification events on target', risk: 'High' },
  ADD_KEY_CREDENTIAL_LINK: { summary: 'Source can add key credentials to target', abuse: 'Shadow Credentials attack for certificate-based authentication as target', opsec: '5136 on msDS-KeyCredentialLink', risk: 'Critical' },
  WRITE_GP_LINK:        { summary: 'Source can modify GPLink on a scope', abuse: 'Link attacker-controlled policy to domain, OU, or site scope', opsec: '5136 on gPLink attribute', risk: 'High' },
  WRITE_ACCOUNT_RESTRICTIONS: { summary: 'Source can write account restriction attributes', abuse: 'Create delegation or RBCD-enabling account state', opsec: '5136 account attribute changes', risk: 'High' },
  SQL_ADMIN:            { summary: 'Source is SQL admin on target SQL server', abuse: 'SQL admin may enable xp_cmdshell or linked-server lateral movement', opsec: 'SQL audit and host process creation logs', risk: 'High' },
  HAS_SESSION:          { summary: 'User has an active session on a host', abuse: 'Credential exposure input when attacker also controls the host', opsec: 'Session enumeration is passive', risk: 'Medium' },
  MANAGE_CA:            { summary: 'Source can manage the Certificate Authority', abuse: 'Alter CA configuration, officers, or issuance behavior', opsec: 'CA configuration changes and service events', risk: 'Critical' },
  MANAGE_CERTIFICATES:  { summary: 'Source can approve or manage certificate requests', abuse: 'Issue or approve certificates for privileged identities', opsec: 'CA request disposition events', risk: 'Critical' },
  CA_PRIVATE_KEY_CONTROL: { summary: 'Source controls CA private key material', abuse: 'Forge arbitrary certificates trusted by the domain', opsec: 'Key export/access telemetry depends on CA hardening', risk: 'Critical' },
  GOLDEN_CERT:          { summary: 'Source can perform Golden Certificate abuse', abuse: 'Forge long-lived certificates for privileged authentication', opsec: 'Forged cert use may only appear as certificate authentication', risk: 'Critical' },
  APPLIES_GPO:          { summary: 'A GPO applies to the target scope', abuse: 'Writable GPOs can push scheduled tasks, scripts, restricted groups, registry, or software install', opsec: 'GPO version changes, SYSVOL writes, and 5136 events', risk: 'High' },
  ADIDNS_CAN_WRITE:     { summary: 'Principal can write AD-integrated DNS records', abuse: 'Can create CNAME relay paths, stale records, wildcard records, or time-bomb names', opsec: 'DNS object modifications log as directory changes when audited', risk: 'High' },
  SCCM_MANAGES:         { summary: 'SCCM management relationship', abuse: 'Management points, site servers, NAA credentials, task sequences, or deploy actions can form domain paths', opsec: 'SCCM server, client, and deployment logs show activity', risk: 'High' },
  WSUS_CONTROLS:        { summary: 'WSUS can influence target update flow', abuse: 'HTTP WSUS or weak approvals can become command delivery in authorized labs', opsec: 'Windows Update and WSUS approval logs', risk: 'High' },
  EXCHANGE_PRIVILEGED:  { summary: 'Exchange role has elevated AD permissions', abuse: 'Exchange Windows Permissions/Trusted Subsystem can expose WriteDACL and mailbox-to-domain paths', opsec: 'Exchange admin audit and AD object changes', risk: 'High' },
  HYBRID_SYNC:          { summary: 'Hybrid identity sync relationship', abuse: 'Azure AD Connect, MSOL, PTA/PHS/ADFS, writeback, or sync-rule control can bridge cloud and on-prem', opsec: 'Entra audit logs and sync-server telemetry', risk: 'Critical' },
  CVE_CHAIN:            { summary: 'Known CVE-linked attack path', abuse: 'Patch and configuration state may permit direct escalation such as noPac, Certifried, or PrintNightmare', opsec: 'Exploit attempts are usually noisy and should be lab-gated', risk: 'Critical' },
}

export const EDGE_MITRE: Record<string, string[]> = {
  GENERIC_ALL:               ['T1222', 'T1098'],
  GENERIC_WRITE:             ['T1222', 'T1558.003'],
  HAS_CONTROL:               ['T1222'],
  WRITE_DACL:                ['T1222.001'],
  WRITE_OWNER:               ['T1222.001'],
  DCSYNC:                    ['T1003.006'],
  ALLOWED_TO_DELEGATE:       ['T1558.001'],
  ALLOWED_TO_ACT:            ['T1550.003'],
  ADD_MEMBER:                ['T1098.007'],
  FORCE_CHANGE_PASSWORD:     ['T1098'],
  LOCAL_ADMIN:               ['T1021', 'T1550.002'],
  ADMIN_TO:                  ['T1021', 'T1550.002'],
  CAN_RDP:                   ['T1021.001'],
  CAN_WINRM:                 ['T1021.006'],
  HAS_SPN:                   ['T1558.003'],
  CAN_ENROLL:                ['T1649'],
  TRUSTS:                    ['T1482', 'T1134.005'],
  MEMBER_OF:                 ['T1069'],
  WRITE_SPN:                 ['T1558.003'],
  READ_LAPS_PASSWORD:        ['T1555'],
  READ_GMSA_PASSWORD:        ['T1555'],
  WRITE_ACCOUNT_RESTRICTIONS:['T1098'],
  ADD_KEY_CREDENTIAL_LINK:   ['T1556.006'],
  WRITE_GP_LINK:             ['T1484.001'],
  APPLIES_GPO:               ['T1484.001'],
  MANAGE_CA:                 ['T1649'],
  MANAGE_CERTIFICATES:       ['T1649'],
  GOLDEN_CERT:               ['T1649'],
  CA_PRIVATE_KEY_CONTROL:    ['T1649'],
  HYBRID_SYNC:               ['T1484'],
  CVE_CHAIN:                 ['T1068'],
  SQL_ADMIN:                 ['T1505.001'],
  SCCM_MANAGES:              ['T1072'],
  WSUS_CONTROLS:             ['T1072'],
}
