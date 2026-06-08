import { CollectionModule } from './types'
import { obfuscateJobCommand, obfuscateScript, TechniqueId } from './powershellObfuscator'

export interface CollectorTarget {
  domain: string
  dcIp: string
  username: string
  password: string
}

export interface CollectorScriptResult {
  script: string
  runOneLiner: string
  moduleCount: number
  commandCount: number
  includedModules: CollectionModule[]
}

function isWindowsGroup(groupId: string): boolean {
  return !groupId.startsWith('linux') && !groupId.includes('-linux-')
}

const DESCRIPTION_VERBS = new Set([
  'review', 'audit', 'classify', 'detect', 'track', 'inventory', 'patch',
  'map', 'monitor', 'pth', 'pre-auth', 'takeover',
])

function isExecutableCommand(cmd: string): boolean {
  const trimmed = cmd.trim()
  const first = trimmed.split(/\s+/)[0]
  // comma in first token = comma-separated description list
  if (first.includes(',')) return false
  // known description verbs used as first token
  if (DESCRIPTION_VERBS.has(first.toLowerCase())) return false
  // token ending with ":" = flag-style description header (e.g. "quiet:")
  if (first.endsWith(':')) return false
  // word:number at start = hash type reference table (e.g. "NTLM:1000 Net-NTLMv1:5500")
  if (/^\w+:\d+/.test(trimmed)) return false
  // " + " separator = description chain (e.g. "SMB signing + LDAP signing + ...")
  if (trimmed.includes(' + ')) return false
  return true
}

// Tools that are Linux-native or too slow on Windows (UDP scans, subnet sweeps, Python scripts)
const LINUX_TOOLS = new Set([
  'nmap', 'crackmapexec', 'cme', 'bloodhound-python', 'ldapsearch', 'ldapdomaindump',
  'dig', 'host', 'dnstool.py', 'impacket-secretsdump', 'impacket-lookupsid',
  'impacket-reg', 'impacket-smbclient', 'impacket-psexec', 'impacket-wmiexec',
  'impacket-getTGT', 'impacket-getTGS', 'impacket-getST', 'impacket-GetNPUsers',
  'impacket-GetUserSPNs', 'ntlmrelayx.py', 'responder', 'kerbrute', 'enum4linux',
  'smbmap', 'rpcclient', 'smbclient', 'ldapdomaindump', 'python3', 'python',
])

function isWindowsCompatibleCommand(cmd: string): boolean {
  const first = cmd.trim().split(/\s+/)[0].toLowerCase().replace(/\.exe$/, '')
  return !LINUX_TOOLS.has(first)
}

// nmap-style comma-separated port args need quoting so PS doesn't treat commas as list syntax
function quoteNmapPorts(cmd: string): string {
  return cmd.replace(/(-p\d[\d,]+)/g, "'$1'")
}

function domainToBaseDn(domain: string): string {
  return (domain || 'corp.local')
    .split('.')
    .filter(Boolean)
    .map(part => `DC=${part}`)
    .join(',')
}

function enrichWindowsCommand(cmdId: string, cmd: string): string {
  switch (cmdId) {
    // ── Users ──────────────────────────────────────────────────────────────
    case 'get-aduser-all':
    case 'quick-get-aduser-risk':
      return "Get-ADUser -Filter * -Properties SamAccountName,objectSid,DistinguishedName,displayName,adminCount,Enabled,ServicePrincipalName,UserAccountControl,PasswordNeverExpires,DoesNotRequirePreAuth,TrustedForDelegation,TrustedToAuthForDelegation,AccountNotDelegated,LastLogonDate,PasswordLastSet,pwdLastSet,badPwdCount,'msDS-SupportedEncryptionTypes','msDS-AllowedToDelegateTo','msDS-AllowedToActOnBehalfOfOtherIdentity','msDS-KeyCredentialLink',sIDHistory,memberOf,description | Select-Object SamAccountName,objectSid,DistinguishedName,displayName,adminCount,Enabled,ServicePrincipalName,UserAccountControl,PasswordNeverExpires,DoesNotRequirePreAuth,TrustedForDelegation,TrustedToAuthForDelegation,AccountNotDelegated,LastLogonDate,PasswordLastSet,badPwdCount,'msDS-SupportedEncryptionTypes','msDS-AllowedToDelegateTo','msDS-AllowedToActOnBehalfOfOtherIdentity','msDS-KeyCredentialLink',sIDHistory,memberOf,description | ConvertTo-Json -Depth 3"

    // ── Computers ──────────────────────────────────────────────────────────
    case 'get-adcomputer-all':
    case 'quick-get-adcomputer-risk':
      return "Get-ADComputer -Filter * -Properties SamAccountName,objectSid,DistinguishedName,Name,dNSHostName,Enabled,UserAccountControl,OperatingSystem,OperatingSystemVersion,TrustedForDelegation,TrustedToAuthForDelegation,'msDS-AllowedToDelegateTo','msDS-AllowedToActOnBehalfOfOtherIdentity','ms-Mcs-AdmPwdExpirationTime','msLAPS-PasswordExpirationTime',description | Select-Object SamAccountName,objectSid,DistinguishedName,Name,dNSHostName,Enabled,UserAccountControl,OperatingSystem,OperatingSystemVersion,TrustedForDelegation,TrustedToAuthForDelegation,'msDS-AllowedToDelegateTo','msDS-AllowedToActOnBehalfOfOtherIdentity','ms-Mcs-AdmPwdExpirationTime','msLAPS-PasswordExpirationTime',description | ConvertTo-Json -Depth 3"

    // ── Groups ─────────────────────────────────────────────────────────────
    case 'get-adgroup-all':
      return "Get-ADGroup -Filter * -Properties SamAccountName,objectSid,DistinguishedName,Name,adminCount,GroupScope,GroupCategory,member | Select-Object SamAccountName,objectSid,DistinguishedName,Name,adminCount,GroupScope,GroupCategory,member | ConvertTo-Json -Depth 3"

    // ── OUs ────────────────────────────────────────────────────────────────
    case 'get-adou-all':
      return "Get-ADOrganizationalUnit -Filter * -Properties DistinguishedName,Name,gPLink,gPOptions,objectSid | Select-Object DistinguishedName,Name,gPLink,gPOptions,objectSid | ConvertTo-Json -Depth 2"

    // ── Domain ─────────────────────────────────────────────────────────────
    case 'get-addomain':
    case 'quick-get-domain-policy':
      return "Get-ADDomain | Select-Object DNSRoot,NetBIOSName,DomainMode,Forest,InfrastructureMaster,PDCEmulator,RIDMaster,DistinguishedName,DomainSID,'ms-DS-MachineAccountQuota' | ConvertTo-Json -Depth 3"

    // ── Trusts ─────────────────────────────────────────────────────────────
    case 'get-adtrust':
    case 'get-adtrust-topology':
      return "Get-ADTrust -Filter * -Properties Name,TrustType,Direction,TrustAttributes,SIDFilteringQuarantined,SIDFilteringForestAware,SelectiveAuthentication,FlatName,DistinguishedName | Select-Object Name,TrustType,Direction,TrustAttributes,SIDFilteringQuarantined,SIDFilteringForestAware,SelectiveAuthentication,FlatName,DistinguishedName | ConvertTo-Json -Depth 2"

    // ── Tier-0 groups ──────────────────────────────────────────────────────
    case 'quick-get-tier0-groups':
      return "Get-ADGroup -LDAPFilter '(|(samAccountName=Domain Admins)(samAccountName=Enterprise Admins)(samAccountName=Schema Admins)(samAccountName=Administrators)(samAccountName=Protected Users)(samAccountName=Account Operators)(samAccountName=Backup Operators)(samAccountName=Group Policy Creator Owners))' -Properties member,adminCount,objectSid,DistinguishedName,SamAccountName | Select-Object SamAccountName,objectSid,DistinguishedName,Name,adminCount,member | ConvertTo-Json -Depth 3"

    // ── Delegation ─────────────────────────────────────────────────────────
    case 'get-delegation-unconstrained':
      return "Get-ADObject -LDAPFilter '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))' -Properties SamAccountName,objectSid,DistinguishedName,TrustedForDelegation,'msDS-AllowedToDelegateTo','msDS-AllowedToActOnBehalfOfOtherIdentity' | Select-Object SamAccountName,objectSid,DistinguishedName,TrustedForDelegation,'msDS-AllowedToDelegateTo','msDS-AllowedToActOnBehalfOfOtherIdentity' | ConvertTo-Json -Depth 3"

    case 'get-delegation-constrained':
      return "Get-ADObject -LDAPFilter '(msDS-AllowedToDelegateTo=*)' -Properties SamAccountName,objectSid,DistinguishedName,'msDS-AllowedToDelegateTo','msDS-AllowedToActOnBehalfOfOtherIdentity' | Select-Object SamAccountName,objectSid,DistinguishedName,'msDS-AllowedToDelegateTo','msDS-AllowedToActOnBehalfOfOtherIdentity' | ConvertTo-Json -Depth 3"

    case 'get-delegation-rbcd':
      return "Get-ADObject -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' -Properties SamAccountName,objectSid,DistinguishedName,'msDS-AllowedToActOnBehalfOfOtherIdentity' | Select-Object SamAccountName,objectSid,DistinguishedName,'msDS-AllowedToActOnBehalfOfOtherIdentity' | ConvertTo-Json -Depth 3"

    // ── Shadow credentials ─────────────────────────────────────────────────
    case 'get-shadow-credentials':
      return "Get-ADObject -LDAPFilter '(msDS-KeyCredentialLink=*)' -Properties SamAccountName,objectSid,DistinguishedName,'msDS-KeyCredentialLink' | Select-Object SamAccountName,objectSid,DistinguishedName,@{N='msDS-KeyCredentialLink';E={@($_.\"msDS-KeyCredentialLink\").Count}} | ConvertTo-Json -Depth 2"

    // ── krbtgt age ─────────────────────────────────────────────────────────
    case 'get-krbtgt-age':
    case 'quick-krbtgt-age':
      return "Get-ADUser krbtgt -Properties SamAccountName,PasswordLastSet,pwdLastSet | Select-Object SamAccountName,PasswordLastSet | ConvertTo-Json -Depth 2"

    // ── Protected Users ────────────────────────────────────────────────────
    case 'get-protected-users-members':
      return "Get-ADGroupMember 'Protected Users' -Recursive | Get-ADObject -Properties objectSid,SamAccountName,DistinguishedName,objectClass | Select-Object objectSid,SamAccountName,DistinguishedName,objectClass | ConvertTo-Json -Depth 2"

    // ── Cert templates ─────────────────────────────────────────────────────
    case 'get-cert-templates':
      return "$_configNC = (Get-ADRootDSE).configurationNamingContext; Get-ADObject -LDAPFilter '(objectClass=pKICertificateTemplate)' -SearchBase \"CN=Certificate Templates,CN=Public Key Services,CN=Services,$_configNC\" -Properties cn,displayName,DistinguishedName,'msPKI-Certificate-Name-Flag','msPKI-Enrollment-Flag','msPKI-RA-Signature',pKIExtendedKeyUsage,'msPKI-Certificate-Application-Policy' | Select-Object cn,displayName,DistinguishedName,'msPKI-Certificate-Name-Flag','msPKI-Enrollment-Flag','msPKI-RA-Signature',pKIExtendedKeyUsage,'msPKI-Certificate-Application-Policy' | ConvertTo-Json -Depth 3"

    // ── CA info ────────────────────────────────────────────────────────────
    case 'get-ca-info':
    case 'get-adca-info':
      return "$_configNC = (Get-ADRootDSE).configurationNamingContext; Get-ADObject -LDAPFilter '(objectClass=pKIEnrollmentService)' -SearchBase \"CN=Enrollment Services,CN=Public Key Services,CN=Services,$_configNC\" -Properties cn,name,DistinguishedName,dNSHostName,certificateTemplates | Select-Object cn,name,DistinguishedName,dNSHostName,certificateTemplates | ConvertTo-Json -Depth 3"

    // ── GPOs (RSAT-free fallback) ──────────────────────────────────────────
    case 'get-adgpo-all':
      return "$_domDN = ([adsi]'').distinguishedName; Get-ADObject -LDAPFilter '(objectClass=groupPolicyContainer)' -SearchBase \"CN=Policies,CN=System,$_domDN\" -Properties cn,displayName,DistinguishedName,gPCFileSysPath | Select-Object cn,displayName,DistinguishedName,gPCFileSysPath | ConvertTo-Json -Depth 2"

    default:
      return cmd
  }
}

/**
 * Returns a PowerShell script block that builds the canonical entity/edge graph
 * and writes coverage_expansion.json to the run directory.
 * The backend processes this via the adbygod.coverage_expansion.v1 overlay gate.
 */
export function buildCanonicalDataBlock(target: CollectorTarget, runDirVar = '$runDir'): string {
  const domain = (target.domain || 'corp.local').replace(/'/g, "''")
  return `
# ── Canonical Graph Builder ────────────────────────────────────────────────────
Write-Host ""
Write-Host "  [*] Building canonical entity graph..." -ForegroundColor Cyan
$_cjStart = [System.Diagnostics.Stopwatch]::StartNew()

$_cjResult = Start-Job -ArgumentList '${domain}' -ScriptBlock {
    param([string]$Domain)

    $ErrorActionPreference = 'Continue'
    $ProgressPreference    = 'SilentlyContinue'

    $canonicalEntities  = [System.Collections.ArrayList]::new()
    $canonicalEdges     = [System.Collections.ArrayList]::new()
    $canonicalCertTmpls = [System.Collections.ArrayList]::new()
    $canonicalCAs       = [System.Collections.ArrayList]::new()
    $canonicalEvidence  = [System.Collections.ArrayList]::new()

    function Get-SidValue($raw) {
        if ($null -eq $raw) { return '' }
        if ($raw -is [System.Security.Principal.SecurityIdentifier]) { return $raw.Value }
        if ($raw -is [hashtable] -or $raw.GetType().Name -eq 'PSCustomObject') {
            $v = if ($null -ne $raw.Value) { $raw.Value } else { $raw.value }
            return if ($v) { "$v" } else { '' }
        }
        return "$raw"
    }

    $BaseDN   = (([adsi]'').distinguishedName)[0]
    $ConfigNC = "CN=Configuration,$BaseDN"

    # ── Domain entity ────────────────────────────────────────────────────────
    try {
        $dom    = Get-ADDomain -ErrorAction Stop
        $domSid = Get-SidValue $dom.DomainSID
        [void]$canonicalEntities.Add([PSCustomObject]@{
            id                  = if ($domSid) { $domSid } else { $dom.DNSRoot }
            entity_type         = 'DOMAIN'
            object_sid          = $domSid
            sam_account_name    = $dom.DNSRoot
            display_name        = $dom.DNSRoot
            distinguished_name  = "$($dom.DistinguishedName)"
            domain              = $dom.DNSRoot
            is_enabled          = $true
            is_admin_count      = $false
            is_sensitive        = $true
            is_protected_user   = $false
            is_crown_jewel      = $true
            tier                = 0
            attributes          = [PSCustomObject]@{ object_sid = $domSid }
            business_tags       = @()
        })
        [void]$canonicalEvidence.Add([PSCustomObject]@{
            id                = 'ps-domain'
            source_type       = 'powershell'
            collection_method = 'Get-ADDomain'
            origin            = 'COLLECTED'
            confidence        = 1.0
            raw_data          = [PSCustomObject]@{ domain = $dom.DNSRoot }
        })
    } catch { Write-Warning "Canonical: domain entity failed: $_" }

    # ── Groups + MEMBER_OF edges ─────────────────────────────────────────────
    try {
        $highValue = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators',
                       'Protected Users','Account Operators','Backup Operators','Print Operators',
                       'Server Operators','Group Policy Creator Owners','DnsAdmins')
        $groups = Get-ADGroup -Filter * -Properties member,adminCount,objectSid,DistinguishedName,SamAccountName,Name -ErrorAction SilentlyContinue
        foreach ($g in $groups) {
            $sid      = Get-SidValue $g.objectSid
            $isHV     = $highValue -contains $g.SamAccountName
            $entityId = if ($sid) { $sid } else { $g.SamAccountName }
            [void]$canonicalEntities.Add([PSCustomObject]@{
                id                 = $entityId
                entity_type        = 'GROUP'
                object_sid         = $sid
                sam_account_name   = $g.SamAccountName
                display_name       = $g.Name
                distinguished_name = "$($g.DistinguishedName)"
                domain             = $Domain
                is_enabled         = $true
                is_admin_count     = [bool]$g.adminCount
                is_sensitive       = $false
                is_protected_user  = $false
                is_crown_jewel     = $isHV
                tier               = if ($isHV -or $g.adminCount) { 0 } else { $null }
                attributes         = [PSCustomObject]@{ object_sid = $sid }
                business_tags      = @()
            })
            $members = if ($g.member -is [string]) { @($g.member) } elseif ($g.member) { @($g.member) } else { @() }
            foreach ($memberDN in $members) {
                if (-not $memberDN) { continue }
                [void]$canonicalEdges.Add([PSCustomObject]@{
                    source_id  = "$memberDN"
                    target_id  = $entityId
                    edge_type  = 'MEMBER_OF'
                    risk_weight = 0.4
                    provenance = 'PowerShell group membership'
                    attributes = [PSCustomObject]@{ member_dn = "$memberDN" }
                })
            }
        }
        [void]$canonicalEvidence.Add([PSCustomObject]@{
            id                = 'ps-groups'
            source_type       = 'powershell'
            collection_method = 'Get-ADGroup'
            origin            = 'COLLECTED'
            confidence        = 1.0
            raw_data          = [PSCustomObject]@{ count = $groups.Count; edge_count = $canonicalEdges.Count }
        })
    } catch { Write-Warning "Canonical: groups failed: $_" }

    # ── OUs ──────────────────────────────────────────────────────────────────
    $ouList = [System.Collections.ArrayList]::new()
    try {
        $ous = Get-ADOrganizationalUnit -Filter * -Properties gPLink,gPOptions,objectSid -ErrorAction SilentlyContinue
        foreach ($ou in $ous) {
            $sid   = Get-SidValue $ou.objectSid
            $gpLnk = if ($ou.gPLink) { "$($ou.gPLink)" } else { '' }
            [void]$canonicalEntities.Add([PSCustomObject]@{
                id                 = "$($ou.DistinguishedName)"
                entity_type        = 'OU'
                object_sid         = $sid
                sam_account_name   = "$($ou.Name)"
                display_name       = "$($ou.Name)"
                distinguished_name = "$($ou.DistinguishedName)"
                domain             = $Domain
                is_enabled         = $true
                is_admin_count     = $false
                is_sensitive       = $false
                is_protected_user  = $false
                is_crown_jewel     = $false
                tier               = $null
                attributes         = [PSCustomObject]@{
                    gp_link    = $gpLnk
                    gp_options = if ($ou.gPOptions) { $ou.gPOptions } else { 0 }
                }
                business_tags = @()
            })
            [void]$ouList.Add([PSCustomObject]@{ DistinguishedName = "$($ou.DistinguishedName)"; gPLink = $gpLnk })
        }
    } catch { Write-Warning "Canonical: OUs failed: $_" }

    # ── GPOs ─────────────────────────────────────────────────────────────────
    $gpoMap = @{}
    try {
        $gpoObjs = Get-ADObject -LDAPFilter '(objectClass=groupPolicyContainer)' -SearchBase "CN=Policies,CN=System,$BaseDN" -Properties displayName,cn,DistinguishedName,gPCFileSysPath -ErrorAction SilentlyContinue
        foreach ($gpo in $gpoObjs) {
            $gpoName = if ($gpo.displayName) { "$($gpo.displayName)" } else { "$($gpo.cn)" }
            $gpoDN   = "$($gpo.DistinguishedName)"
            [void]$canonicalEntities.Add([PSCustomObject]@{
                id                 = $gpoDN
                entity_type        = 'GPO'
                sam_account_name   = $gpoName
                display_name       = $gpoName
                distinguished_name = $gpoDN
                domain             = $Domain
                is_enabled         = $true
                is_admin_count     = $false
                is_sensitive       = $false
                is_protected_user  = $false
                is_crown_jewel     = $false
                tier               = $null
                attributes         = [PSCustomObject]@{ gpo_guid = "$($gpo.cn)" }
                business_tags      = @()
            })
            $gpoMap[$gpoDN.ToLower()] = $gpoDN
        }
    } catch { Write-Warning "Canonical: GPOs failed: $_" }

    # ── APPLIES_GPO edges from gPLink ─────────────────────────────────────────
    if ($gpoMap.Count -gt 0) {
        $allContainers = [System.Collections.ArrayList]::new()
        try {
            $domObj = Get-ADObject -LDAPFilter '(objectClass=domain)' -Properties gPLink,distinguishedName -SearchBase $BaseDN -SearchScope Base -ErrorAction SilentlyContinue
            if ($domObj) { [void]$allContainers.Add([PSCustomObject]@{ DistinguishedName = $BaseDN; gPLink = "$($domObj.gPLink)" }) }
        } catch {}
        foreach ($ou in $ouList) { [void]$allContainers.Add($ou) }

        $gplinkRegex = [regex]'\[LDAP://([^;]+);(\d+)\]'
        foreach ($container in $allContainers) {
            if (-not $container.gPLink) { continue }
            foreach ($m in $gplinkRegex.Matches($container.gPLink)) {
                $gpoDNRaw = $m.Groups[1].Value.Trim()
                $linkOpts = [int]$m.Groups[2].Value
                $disabled = $linkOpts -band 0x01
                $enforced = $linkOpts -band 0x02
                if ($disabled) { continue }
                $gpoId = $gpoMap[$gpoDNRaw.ToLower()]
                if (-not $gpoId) { $gpoId = $gpoDNRaw }
                [void]$canonicalEdges.Add([PSCustomObject]@{
                    source_id   = $gpoId
                    target_id   = $container.DistinguishedName
                    edge_type   = 'APPLIES_GPO'
                    risk_weight = if ($enforced) { 0.6 } else { 0.3 }
                    provenance  = "GPO linked to $($container.DistinguishedName)"
                    attributes  = [PSCustomObject]@{
                        enforced  = [bool]$enforced
                        gpo_dn    = $gpoDNRaw
                        target_dn = $container.DistinguishedName
                    }
                })
            }
        }
    }

    # ── Delegation edges ─────────────────────────────────────────────────────
    try {
        $unconstr = Get-ADObject -LDAPFilter '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))' -Properties objectSid,SamAccountName -ErrorAction SilentlyContinue
        foreach ($obj in $unconstr) {
            $sid = Get-SidValue $obj.objectSid
            [void]$canonicalEdges.Add([PSCustomObject]@{
                source_id   = if ($sid) { $sid } else { "$($obj.SamAccountName)" }
                target_id   = "domain:$Domain"
                edge_type   = 'ALLOWED_TO_DELEGATE'
                risk_weight = 0.9
                provenance  = 'Unconstrained delegation'
                attributes  = [PSCustomObject]@{ delegation_type = 'unconstrained' }
            })
        }
        $constr = Get-ADObject -LDAPFilter '(msDS-AllowedToDelegateTo=*)' -Properties objectSid,SamAccountName,'msDS-AllowedToDelegateTo' -ErrorAction SilentlyContinue
        foreach ($obj in $constr) {
            $sid  = Get-SidValue $obj.objectSid
            $src  = if ($sid) { $sid } else { "$($obj.SamAccountName)" }
            $spns = if ($obj.'msDS-AllowedToDelegateTo' -is [string]) { @($obj.'msDS-AllowedToDelegateTo') } else { @($obj.'msDS-AllowedToDelegateTo') }
            foreach ($spn in $spns) {
                if (-not $spn) { continue }
                [void]$canonicalEdges.Add([PSCustomObject]@{
                    source_id   = $src
                    target_id   = "$spn"
                    edge_type   = 'ALLOWED_TO_DELEGATE'
                    risk_weight = 0.7
                    provenance  = "Constrained delegation to $spn"
                    attributes  = [PSCustomObject]@{ delegation_type = 'constrained'; target_spn = "$spn" }
                })
            }
        }
        $rbcdObjs = Get-ADObject -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' -Properties objectSid,SamAccountName,DistinguishedName -ErrorAction SilentlyContinue
        foreach ($obj in $rbcdObjs) {
            $sid = Get-SidValue $obj.objectSid
            [void]$canonicalEdges.Add([PSCustomObject]@{
                source_id   = 'RBCD_TRUSTEE_PENDING'
                target_id   = if ($sid) { $sid } else { "$($obj.SamAccountName)" }
                edge_type   = 'ALLOWED_TO_ACT'
                risk_weight = 0.8
                provenance  = "RBCD on $($obj.SamAccountName)"
                attributes  = [PSCustomObject]@{ delegation_type = 'rbcd'; target_dn = "$($obj.DistinguishedName)" }
            })
        }
    } catch { Write-Warning "Canonical: delegation failed: $_" }

    # ── Shadow credentials ────────────────────────────────────────────────────
    try {
        $shadowObjs = Get-ADObject -LDAPFilter '(msDS-KeyCredentialLink=*)' -Properties objectSid,SamAccountName,DistinguishedName,'msDS-KeyCredentialLink' -ErrorAction SilentlyContinue
        foreach ($obj in $shadowObjs) {
            $sid      = Get-SidValue $obj.objectSid
            $keyCount = @($obj.'msDS-KeyCredentialLink').Count
            [void]$canonicalEdges.Add([PSCustomObject]@{
                source_id   = 'SHADOW_CRED_ATTACKER_PENDING'
                target_id   = if ($sid) { $sid } else { "$($obj.SamAccountName)" }
                edge_type   = 'ADD_KEY_CREDENTIAL_LINK'
                risk_weight = 0.95
                provenance  = "Shadow credential on $($obj.SamAccountName)"
                attributes  = [PSCustomObject]@{ target_dn = "$($obj.DistinguishedName)"; key_count = $keyCount }
            })
        }
    } catch { Write-Warning "Canonical: shadow credentials failed: $_" }

    # ── Users (needed for USR-005, USR-006, PER-003, KRB-006 rules) ──────────
    try {
        $usersAll = Get-ADUser -Filter * -Properties SamAccountName,objectSid,DistinguishedName,displayName,Enabled,UserAccountControl,description,primaryGroupID -ErrorAction SilentlyContinue
        foreach ($u in $usersAll) {
            $sid = Get-SidValue $u.objectSid
            $uac = [int]($u.UserAccountControl)
            [void]$canonicalEntities.Add([PSCustomObject]@{
                id                 = if ($sid) { $sid } else { $u.SamAccountName }
                entity_type        = 'USER'
                object_sid         = $sid
                sam_account_name   = $u.SamAccountName
                display_name       = "$($u.displayName)"
                distinguished_name = "$($u.DistinguishedName)"
                domain             = $Domain
                is_enabled         = [bool]$u.Enabled
                is_admin_count     = $false
                is_sensitive       = $false
                is_protected_user  = $false
                is_crown_jewel     = $false
                tier               = $null
                attributes         = [PSCustomObject]@{
                    description          = "$($u.description)"
                    primary_group_id     = "$($u.primaryGroupID)"
                    primaryGroupID       = "$($u.primaryGroupID)"
                    use_des_key_only     = [bool]($uac -band 0x200000)
                    uac_use_des_key_only = [bool]($uac -band 0x200000)
                }
                business_tags = @()
            })
        }
    } catch { Write-Warning "Canonical: users failed: $_" }

    # ── Computers + DCs (needed for HOST-001 legacy OS rule) ─────────────────
    try {
        $computersAll = Get-ADComputer -Filter * -Properties SamAccountName,objectSid,DistinguishedName,Name,dNSHostName,OperatingSystem,Enabled,UserAccountControl -ErrorAction SilentlyContinue
        $dcNames = try { @((Get-ADDomainController -Filter * -ErrorAction SilentlyContinue).HostName) } catch { @() }
        foreach ($c in $computersAll) {
            $sid   = Get-SidValue $c.objectSid
            $isDC  = $dcNames -contains "$($c.dNSHostName)"
            $etype = if ($isDC) { 'DC' } else { 'COMPUTER' }
            [void]$canonicalEntities.Add([PSCustomObject]@{
                id                 = if ($sid) { $sid } else { $c.SamAccountName }
                entity_type        = $etype
                object_sid         = $sid
                sam_account_name   = $c.SamAccountName
                display_name       = "$($c.Name)"
                distinguished_name = "$($c.DistinguishedName)"
                domain             = $Domain
                is_enabled         = [bool]$c.Enabled
                is_admin_count     = $false
                is_sensitive       = $isDC
                is_protected_user  = $false
                is_crown_jewel     = $isDC
                tier               = if ($isDC) { 0 } else { $null }
                attributes         = [PSCustomObject]@{
                    operating_system = "$($c.OperatingSystem)"
                    os               = "$($c.OperatingSystem)"
                }
                business_tags = @()
            })
        }
    } catch { Write-Warning "Canonical: computers failed: $_" }

    # ── Cert templates ────────────────────────────────────────────────────────
    $ENROLL_GUID = [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
    $LOW_PRIV_RE = [regex]'(?i)domain users|everyone|authenticated users|cert publishers|s-1-1-0|s-1-5-11'
    try {
        $tmplBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"
        $tmpls = Get-ADObject -LDAPFilter '(objectClass=pKICertificateTemplate)' -SearchBase $tmplBase -Properties cn,displayName,DistinguishedName,'msPKI-Certificate-Name-Flag','msPKI-Enrollment-Flag','msPKI-RA-Signature',pKIExtendedKeyUsage,'msPKI-Certificate-Application-Policy' -ErrorAction SilentlyContinue
        foreach ($t in $tmpls) {
            $nameFlag   = [int](if ($null -ne $t.'msPKI-Certificate-Name-Flag') { $t.'msPKI-Certificate-Name-Flag' } else { 0 })
            $enrollFlag = [int](if ($null -ne $t.'msPKI-Enrollment-Flag')        { $t.'msPKI-Enrollment-Flag'        } else { 0 })
            $raSig      = [int](if ($null -ne $t.'msPKI-RA-Signature')           { $t.'msPKI-RA-Signature'           } else { 0 })
            $ekus       = @($t.pKIExtendedKeyUsage) + @($t.'msPKI-Certificate-Application-Policy') | Where-Object { $_ }

            # ── Enrollment + write ACLs via ADSI (no RSAT required) ──────────
            $enrollRights    = @()
            $writeRights     = @()
            $hasLowPrivWrite = $false
            try {
                $adsi = [ADSI]"LDAP://$($t.DistinguishedName)"
                $sd   = $adsi.psbase.ObjectSecurity
                if ($sd) {
                    foreach ($ace in $sd.GetAccessRules($true, $false, [System.Security.Principal.NTAccount])) {
                        if ($ace.AccessControlType -ne 'Allow') { continue }
                        $trustee  = $ace.IdentityReference.Value
                        $rights   = $ace.ActiveDirectoryRights
                        $isLowP   = [bool]$LOW_PRIV_RE.IsMatch($trustee)
                        $isGenAll = [bool]($rights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll)
                        $isExtR   = [bool]($rights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight)
                        if ($isGenAll -or ($isExtR -and $ace.ObjectType -eq $ENROLL_GUID)) {
                            $enrollRights += [PSCustomObject]@{ principal_name = $trustee; is_low_privileged = [bool]$isLowP }
                        }
                        $isWD = [bool]($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl)
                        $isWO = [bool]($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner)
                        if (($isGenAll -or $isWD -or $isWO) -and $isLowP) {
                            $hasLowPrivWrite = $true
                            $writeRights += [PSCustomObject]@{ principal_name = $trustee; right = "$rights"; is_low_privileged = $true }
                        }
                    }
                }
            } catch { }

            $lowPrivEnroll = $enrollRights | Where-Object { $_.is_low_privileged }
            $esc1 = ($nameFlag -band 1) -and ($raSig -eq 0) -and -not ($enrollFlag -band 2) -and $lowPrivEnroll -and (
                    -not $ekus -or $ekus -contains '1.3.6.1.5.5.7.3.2' -or $ekus -contains '2.5.29.37.0')
            $esc2 = ($raSig -eq 0) -and -not ($enrollFlag -band 2) -and $lowPrivEnroll -and (-not $ekus -or $ekus -contains '2.5.29.37.0')
            $esc3 = -not ($enrollFlag -band 2) -and $lowPrivEnroll -and ($ekus -contains '1.3.6.1.4.1.311.20.2.1')
            [void]$canonicalCertTmpls.Add([PSCustomObject]@{
                name                           = "$($t.cn)"
                ca_name                        = ''
                distinguished_name             = "$($t.DistinguishedName)"
                enrollee_supplies_subject      = [bool]($nameFlag -band 1)
                requires_manager_approval      = [bool]($enrollFlag -band 2)
                authorized_signatures_required = $raSig
                ekus                           = @($ekus)
                enrollment_rights              = @($enrollRights)
                write_rights                   = @($writeRights)
                esc1_vulnerable                = [bool]$esc1
                esc2_vulnerable                = [bool]$esc2
                esc3_vulnerable                = [bool]$esc3
                esc4_vulnerable                = $hasLowPrivWrite
            })
        }
    } catch { Write-Warning "Canonical: cert templates failed: $_" }

    # ── CAs ───────────────────────────────────────────────────────────────────
    try {
        $caBase = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigNC"
        $cas = Get-ADObject -LDAPFilter '(objectClass=pKIEnrollmentService)' -SearchBase $caBase -Properties cn,name,DistinguishedName,dNSHostName,certificateTemplates -ErrorAction SilentlyContinue
        foreach ($ca in $cas) {
            $caName = "$($ca.cn)"
            $caDN   = "$($ca.DistinguishedName)"
            $caHost = "$($ca.dNSHostName)"
            [void]$canonicalEntities.Add([PSCustomObject]@{
                id                 = $caDN
                entity_type        = 'CA'
                sam_account_name   = $caName
                display_name       = $caName
                distinguished_name = $caDN
                domain             = $Domain
                is_enabled         = $true
                is_admin_count     = $false
                is_sensitive       = $true
                is_protected_user  = $false
                is_crown_jewel     = $true
                tier               = 0
                attributes         = [PSCustomObject]@{ dns_hostname = $caHost; published_templates = @($ca.certificateTemplates) }
                business_tags      = @('Certificate Authority')
            })
            $pubTmpls = @($ca.certificateTemplates)
            foreach ($tmpl in $canonicalCertTmpls) {
                if ($pubTmpls -contains $tmpl.name) { $tmpl.ca_name = $caName }
            }
        }
    } catch { Write-Warning "Canonical: CAs failed: $_" }

    # ── Return canonical payload ───────────────────────────────────────────────
    [PSCustomObject]@{
        module_id                = 'coverage_expansion'
        canonical_overlay_schema = 'adbygod.coverage_expansion.v1'
        canonical = [PSCustomObject]@{
            entities       = @($canonicalEntities)
            edges          = @($canonicalEdges)
            cert_templates = @($canonicalCertTmpls)
            ca_flags       = @()
            evidence       = @($canonicalEvidence)
        }
        commands = @([PSCustomObject]@{
            id          = 'canonical-build'
            title       = 'Canonical graph construction'
            output      = "OK"
            error       = $null
            duration_ms = 0
        })
    }
}

$_cjTimeout = 600
if (Wait-Job $_cjResult -Timeout $_cjTimeout) {
    $canonicalModule = Receive-Job $_cjResult -ErrorAction SilentlyContinue
    if ($canonicalModule) {
        $canonicalJson = $canonicalModule | ConvertTo-Json -Depth 20 -Compress
        [IO.File]::WriteAllText(
            (Join-Path ${runDirVar} 'coverage_expansion.json'),
            $canonicalJson,
            [System.Text.Encoding]::UTF8
        )
        Write-Host " done ($($canonicalModule.canonical.entities.Count) entities, $($canonicalModule.canonical.edges.Count) edges)" -ForegroundColor DarkGray
    }
} else {
    Stop-Job $_cjResult
    Write-Host " timed out — canonical graph skipped" -ForegroundColor DarkYellow
}
Remove-Job $_cjResult -Force -ErrorAction SilentlyContinue
$_cjStart.Stop()
`
}

function psStringLiteral(value: string): string {
  return value.replace(/`/g, '``').replace(/"/g, '`"')
}

export function substituteVars(cmd: string, t: CollectorTarget): string {
  const baseDn = domainToBaseDn(t.domain)
  return cmd
    .replace(/<domain>/gi,            t.domain   || 'corp.local')
    .replace(/<base_dn>/gi,           baseDn)
    .replace(/<IP\/CIDR>/gi,          `${t.dcIp  || '10.0.0.0'}/24`)
    .replace(/<IP>/g,                 t.dcIp     || '$DCServer')
    .replace(/<username>/gi,          t.username || '$Username')
    .replace(/<user>/gi,              t.username || '$Username')
    .replace(/<password>/gi,          '$Password')
    .replace(/<pass>/gi,              '$Password')
    .replace(/<hostname>/gi,          t.dcIp     || '$DCServer')
    .replace(/<computername>/gi,      '$env:COMPUTERNAME')
    .replace(/<domain_controller>/gi, t.dcIp     || '$DCServer')
    .replace(/<dc>/gi,                t.dcIp     || '$DCServer')
    .replace(/<RID>/gi,               '500')
    .replace(/<filepath>/gi,          'C:\\Windows\\System32')
    .replace(/<subnet>/gi,            `${t.dcIp  || '10.0.0.0'}/24`)
    .replace(/<[\w/.-]+>/g,           'PLACEHOLDER')
}

export interface CollectorOptions {
  obfuscate?: boolean
  technique?: TechniqueId
}

export function generateCollectorScript(
  modules: CollectionModule[],
  target: CollectorTarget,
  options: CollectorOptions = {},
): CollectorScriptResult {
  const { obfuscate = false, technique = 'auto' } = options
  const ts = new Date().toISOString()

  // Only Windows-capable modules
  const includedModules = modules.filter(m =>
    m.supported_modes.includes('WINDOWS_LOCAL') || m.supported_modes.includes('WINDOWS_REMOTE'),
  )

  let commandCount = 0

  // Build per-module PS blocks
  const moduleBlocks = includedModules.map(mod => {
    const winGroups = mod.command_groups.filter(g => isWindowsGroup(g.id))
    if (winGroups.length === 0) return null

    const cmdBlocks = winGroups.flatMap(g => g.commands)
      .filter(cmd => isExecutableCommand(cmd.command) && isWindowsCompatibleCommand(cmd.command))
      .map(cmd => {
        commandCount++
        const sub = quoteNmapPorts(substituteVars(enrichWindowsCommand(cmd.id, cmd.command), target))
        const subIE = psStringLiteral(sub)
        return `        try {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $_tj = Start-Job -ArgumentList $Domain,$DCServer,$Username,$Password -ScriptBlock {
                param($Domain,$DCServer,$Username,$Password)
                $_result = (${obfuscate ? obfuscateJobCommand(subIE, technique) : `Invoke-Expression "${subIE}"`}) 2>&1
                if ($_result -is [string]) {
                    $_result | Out-String
                } else {
                    $_result | Format-List * | Out-String
                }
            }
            if (Wait-Job $_tj -Timeout 60) {
                $out = (Receive-Job $_tj -ErrorAction SilentlyContinue | Out-String)
            } else {
                Stop-Job $_tj
                $out = 'TIMEOUT (60s)'
            }
            Remove-Job $_tj -Force -ErrorAction SilentlyContinue
            $sw.Stop()
            [void]$cmdResults.Add([PSCustomObject]@{
                id          = '${cmd.id.replace(/'/g, "''")}'
                title       = '${cmd.title.replace(/'/g, "''")}'
                output      = $out.Trim()
                error       = $null
                duration_ms = $sw.ElapsedMilliseconds
            })
        } catch {
            [void]$cmdResults.Add([PSCustomObject]@{
                id          = '${cmd.id.replace(/'/g, "''")}'
                title       = '${cmd.title.replace(/'/g, "''")}'
                output      = $null
                error       = $_.Exception.Message
                duration_ms = 0
            })
        }`
      }).join('\n\n')

    const modId = mod.id.replace(/'/g, "''")
    const modName = mod.name.replace(/'/g, "''")
    return `    # ── ${mod.name} ${'─'.repeat(Math.max(1, 52 - mod.name.length))}
    $ModuleName = '${modName}'
    Write-Host "  [*] $ModuleName..." -ForegroundColor Cyan -NoNewline
    $_mj = Start-Job -ArgumentList $Domain,$DCServer,$Username,$Password -ScriptBlock {
        param($Domain, $DCServer, $Username, $Password)
        $ProgressPreference    = 'SilentlyContinue'
        $ErrorActionPreference = 'Continue'
        $cmdResults = [System.Collections.ArrayList]::new()

${cmdBlocks}

        $cmdResults | ForEach-Object { $_ }
    }
    if (Wait-Job $_mj -Timeout 300) {
        $moduleOutputs['${modId}'] = [PSCustomObject]@{
            module_id = '${modId}'
            commands  = @(Receive-Job $_mj)
        }
    } else {
        Stop-Job $_mj
        $moduleOutputs['${modId}'] = [PSCustomObject]@{
            module_id = '${modId}'
            commands  = @()
        }
    }
    Remove-Job $_mj -Force
    Write-Host " done ($($moduleOutputs['${modId}'].commands.Count) cmds)" -ForegroundColor DarkGray`
  }).filter((b): b is string => b !== null).join('\n\n')

  const moduleListLiteral = [...includedModules.map(m => `'${m.id}'`), "'coverage_expansion'"].join(', ')

  const script = `#Requires -Version 5.1
<#
.SYNOPSIS
    AdByGod Native Collector
.DESCRIPTION
    Collects Active Directory reconnaissance data and exports a
    native zip importable by AdByGod.

    Generated : ${ts}
    Modules   : ${includedModules.map(m => m.id).join(', ')}
.PARAMETER Domain
    Target AD domain (e.g. corp.local)
.PARAMETER DCServer
    Domain controller IP or hostname
.PARAMETER Username
    Domain account for authenticated queries (optional for local host runs)
.PARAMETER Password
    Password for the domain account (optional for local host runs)
.PARAMETER OutputPath
    Directory where the collector writes the zip. Defaults to %TEMP%\\adbygod-collector.
.EXAMPLE
    .\\Invoke-AdByGodCollector.ps1 -Domain corp.local -DCServer 10.10.10.1
#>
param(
    [string]$Domain     = '${(target.domain || 'corp.local').replace(/'/g, "''")}',
    [string]$DCServer   = '${(target.dcIp   || '').replace(/'/g, "''")}',
    [string]$Username   = '${(target.username || '').replace(/'/g, "''")}',
    [string]$Password   = '',  # supply at runtime: -Password 'YourPassword'
    [string]$OutputPath = "$env:TEMP\\adbygod-collector"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ╔═══════════════════════════════╗" -ForegroundColor DarkMagenta
Write-Host "  ║   AdByGod Native Collector    ║" -ForegroundColor Magenta
Write-Host "  ╚═══════════════════════════════╝" -ForegroundColor DarkMagenta
Write-Host "  Domain  : $Domain"    -ForegroundColor Gray
Write-Host "  DC      : $DCServer"  -ForegroundColor Gray
Write-Host "  Modules : ${includedModules.length}"           -ForegroundColor Gray
Write-Host "  Output  : $OutputPath" -ForegroundColor Gray
Write-Host ""

# ── Setup ─────────────────────────────────────────────────────────────────────
$timestamp = Get-Date -Format 'yyyyMMddTHHmmss'
$runDir    = Join-Path $OutputPath $timestamp
New-Item -ItemType Directory -Force -Path $runDir | Out-Null

$moduleOutputs = [System.Collections.Hashtable]::new()

# ── Collection ────────────────────────────────────────────────────────────────
${moduleBlocks}

${buildCanonicalDataBlock(target, '$runDir')}

# ── Write JSON output files ───────────────────────────────────────────────────
Write-Host ""
Write-Host "  [+] Writing output files..." -ForegroundColor Green

foreach ($key in $moduleOutputs.Keys) {
    $json = $moduleOutputs[$key] | ConvertTo-Json -Depth 10 -Compress
    [IO.File]::WriteAllText(
        (Join-Path $runDir "$key.json"),
        $json,
        [System.Text.Encoding]::UTF8
    )
}

# manifest.json — required by AdByGod import
$manifest = [PSCustomObject]@{
    version        = '1.0'
    schema_version = '1.0'
    generator      = 'AdByGod-Native-Collector'
    domain       = $Domain
    dc_ip        = $DCServer
    collected_at = (Get-Date -Format 'o')
    modules      = @(${moduleListLiteral})
}
$manifest | ConvertTo-Json | Out-File -FilePath (Join-Path $runDir 'manifest.json') -Encoding UTF8

# ── Zip ───────────────────────────────────────────────────────────────────────
$zipName = "adbygod-$Domain-$timestamp.zip"
$zipPath = Join-Path $OutputPath $zipName
Compress-Archive -Path (Join-Path $runDir '*') -DestinationPath $zipPath -Force

# Clean up temp run dir
Remove-Item -Recurse -Force $runDir -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════╗" -ForegroundColor DarkGreen
Write-Host "  ║  Collection complete — drag the zip below     ║" -ForegroundColor Green
Write-Host "  ║  into AdByGod's Import drop zone to import.     ║" -ForegroundColor Green
Write-Host "  ╚═══════════════════════════════════════════════╝" -ForegroundColor DarkGreen
Write-Host ""
Write-Host "  $zipPath" -ForegroundColor Yellow
Write-Host ""
`

  const domain = (target.domain || 'corp.local').replace(/'/g, "''")
  const dcIp   = (target.dcIp   || '').replace(/'/g, "''")
  const user   = (target.username || '').replace(/'/g, "''")
  const runOneLiner = [
    'Set-ExecutionPolicy Bypass -Scope Process -Force;',
    `.\\Invoke-AdByGodCollector.ps1`,
    `-Domain '${domain}'`,
    dcIp   ? `-DCServer '${dcIp}'`   : '',
    user   ? `-Username '${user}'`   : '',
  ].filter(Boolean).join(' ')

  const finalScript = obfuscate ? obfuscateScript(script) : script

  return { script: finalScript, runOneLiner, moduleCount: includedModules.length, commandCount, includedModules }
}
