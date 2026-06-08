<#
.SYNOPSIS
    AdByG0d Platform — Windows Local Collector v4.0
    Enterprise Identity Exposure Assessment — PowerShell/.NET Host-Local Collection

.DESCRIPTION
    Performs high-fidelity local AD collection from a domain-joined Windows endpoint.
    Outputs canonical JSON for ingest by the AdByG0d platform API.

    Safe by default:
    - No credential dumping
    - No hash extraction
    - No brute force or spray
    - No lateral movement
    - No persistence installation
    - Non-destructive read-only LDAP/directory operations only

.PARAMETER Domain
    Target domain FQDN (e.g., corp.local)

.PARAMETER DomainController
    Specific DC to target (default: auto-discovered)

.PARAMETER OutputPath
    Path to save canonical JSON output

.PARAMETER ApiUrl
    Platform API URL for direct upload

.PARAMETER AssessmentId
    Assessment UUID for platform ingest

.PARAMETER Modules
    Comma-separated list of modules (default: all)

.EXAMPLE
    .\Collect-ADByG0d.ps1 -Domain corp.local -OutputPath C:\ADByG0d\output

.EXAMPLE
    .\Collect-ADByG0d.ps1 -Domain corp.local -ApiUrl http://localhost:8000 -AssessmentId <uuid>

.NOTES
    Author: AdByG0d Platform
    Version: 4.0.0
    For authorized security assessment use only.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Domain = $env:USERDNSDOMAIN,

    [Parameter(Mandatory = $false)]
    [string]$DomainController = "",

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\ADByG0d-Output",

    [Parameter(Mandatory = $false)]
    [string]$ApiUrl = "",

    [Parameter(Mandatory = $false)]
    [string]$AssessmentId = "",

    [Parameter(Mandatory = $false)]
    [string]$Modules = "all",

    [Parameter(Mandatory = $false)]
    [switch]$Verbose
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ─────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────

$SCHEMA_VERSION = "4.0"
$TOOL_NAME = "AdByG0d"
$COLLECTOR_VERSION = "4.0.0"
$COLLECTION_MODE = "WINDOWS_LOCAL"

# ─────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "HH:mm:ss"
    $color = switch ($Level) {
        "SUCCESS" { "Green" }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red" }
        "CRITICAL"{ "Magenta" }
        default   { "Cyan" }
    }
    Write-Host "  [$ts] " -NoNewline
    Write-Host "[$Level] " -ForegroundColor $color -NoNewline
    Write-Host $Message
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkOrange
    Write-Host "  ┃  $Title" -ForegroundColor White
    Write-Host "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkOrange
    Write-Host ""
}

# ─────────────────────────────────────────────────────────────────
# Output builder
# ─────────────────────────────────────────────────────────────────

$Output = [PSCustomObject]@{
    schema_version   = $SCHEMA_VERSION
    tool             = $TOOL_NAME
    collector_version = $COLLECTOR_VERSION
    collection_mode  = $COLLECTION_MODE
    domain           = $Domain
    dc_ip            = $DomainController
    collected_at     = (Get-Date -Format "o")
    modules_run      = @()
    entities         = @()
    edges            = @()
    evidence         = @()
    findings         = @()
    cert_templates   = @()
    metadata         = @{
        domain_info     = @{}
        password_policy = @{}
        trusts          = @()
    }
}

function New-UUID { return [Guid]::NewGuid().ToString() }

function Add-Entity {
    param([hashtable]$Entity)
    if (-not $Entity.id) { $Entity.id = New-UUID }
    $Output.entities += [PSCustomObject]$Entity
    return $Entity.id
}

function Add-Edge {
    param([string]$SourceId, [string]$TargetId, [string]$EdgeType,
          [string]$Provenance = "", [float]$RiskWeight = 1.0, [hashtable]$Attributes = @{})
    $Output.edges += [PSCustomObject]@{
        id = New-UUID; source_id = $SourceId; target_id = $TargetId
        edge_type = $EdgeType; provenance = $Provenance; risk_weight = $RiskWeight
        attributes = $Attributes
    }
}

function Add-Finding {
    param([hashtable]$Finding)
    if (-not $Finding.id) { $Finding.id = New-UUID }
    $Output.findings += [PSCustomObject]$Finding
}

function Add-Evidence {
    param([hashtable]$Evidence)
    if (-not $Evidence.id) { $Evidence.id = New-UUID }
    $Output.evidence += [PSCustomObject]$Evidence
    return $Evidence.id
}

# ─────────────────────────────────────────────────────────────────
# AD Query helpers (uses .NET System.DirectoryServices.ActiveDirectory)
# ─────────────────────────────────────────────────────────────────

function Get-ADObjects {
    param([string]$LdapFilter, [string[]]$Properties, [string]$SearchBase = "")
    try {
        Add-Type -AssemblyName System.DirectoryServices
        if ($SearchBase -eq "") {
            $context = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext(
                [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain, $Domain
            )
            $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($context)
            $SearchBase = $domainObj.GetDirectoryEntry().Properties["distinguishedName"][0]
        }
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$SearchBase")
        $searcher.Filter = $LdapFilter
        $searcher.PageSize = 1000
        foreach ($prop in $Properties) {
            [void]$searcher.PropertiesToLoad.Add($prop)
        }
        $results = $searcher.FindAll()
        return $results
    } catch {
        Write-Log "LDAP search failed for filter '$LdapFilter': $_" "WARN"
        return @()
    }
}

function Get-UAC { param([int]$UAC, [int]$Flag) return ($UAC -band $Flag) -ne 0 }

# ─────────────────────────────────────────────────────────────────
# Module: Domain Enumeration
# ─────────────────────────────────────────────────────────────────

function Invoke-EnumModule {
    Write-Section "Domain Enumeration"
    $Output.modules_run += "enum"

    # Password policy
    Write-Log "Collecting password policy..."
    $domainResults = Get-ADObjects "(objectClass=domain)" @(
        "minPwdLength","maxPwdAge","minPwdAge","pwdHistoryLength",
        "lockoutThreshold","lockoutDuration","pwdProperties",
        "ms-DS-MachineAccountQuota","distinguishedName","name"
    )
    foreach ($result in $domainResults) {
        $props = $result.Properties
        $minLen = if ($props["minpwdlength"].Count -gt 0) { [int]$props["minpwdlength"][0] } else { 7 }
        $lockout = if ($props["lockoutthreshold"].Count -gt 0) { [int]$props["lockoutthreshold"][0] } else { 0 }
        $pwdProps = if ($props["pwdproperties"].Count -gt 0) { [int]$props["pwdproperties"][0] } else { 0 }
        $complexity = ($pwdProps -band 1) -ne 0
        $maq = if ($props["ms-ds-machineaccountquota"].Count -gt 0) { [int]$props["ms-ds-machineaccountquota"][0] } else { 10 }

        $Output.metadata.password_policy = @{
            min_password_length = $minLen
            lockout_threshold   = $lockout
            complexity_required = $complexity
            machine_account_quota = $maq
        }
        $Output.metadata.domain_info.machine_account_quota = $maq

        # Findings
        if ($lockout -eq 0) {
            Add-Finding @{
                finding_type = "NO_LOCKOUT_POLICY"; module = "Password Policy"
                title = "No account lockout policy configured"
                description = "Domain has no lockout threshold. Unlimited password guessing possible."
                severity = "CRITICAL"; confidence = 1.0; affected_count = 1
                affected_objects = @("Default Domain Policy")
                root_cause = "lockoutThreshold = 0"; causal_chain = @()
                remediation = "Set lockout threshold to 5-10 in Default Domain Policy"
                remediation_steps = @(
                    "Open GPMC → Edit Default Domain Policy",
                    "Navigate to: Computer Configuration → Windows Settings → Security Settings → Account Policies → Account Lockout Policy",
                    "Set 'Account lockout threshold' to 5"
                )
                fix_complexity = "trivial"; references = @(); technical_severity = 9.0; reachability = 1.0
            }
        }

        if ($minLen -lt 12) {
            $sev = if ($minLen -lt 8) { "CRITICAL" } else { "HIGH" }
            Add-Finding @{
                finding_type = "WEAK_PASSWORD_LENGTH"; module = "Password Policy"
                title = "Minimum password length is $minLen characters (recommended: 14+)"
                description = "Short minimum password length enables brute-force attacks."
                severity = $sev; confidence = 1.0; affected_count = 1
                root_cause = "minPwdLength = $minLen"; causal_chain = @()
                remediation = "Increase minimum password length to 14+ characters"
                fix_complexity = "low"; references = @(); technical_severity = 7.0; reachability = 0.7
            }
        }

        if ($maq -gt 0) {
            Add-Finding @{
                finding_type = "MACHINE_ACCOUNT_QUOTA"; module = "Domain Config"
                title = "MachineAccountQuota is $maq — any user can create computer accounts"
                description = "Enables RBCD-based privilege escalation for any domain user."
                severity = "MEDIUM"; confidence = 1.0; affected_count = 1
                root_cause = "ms-DS-MachineAccountQuota = $maq"; causal_chain = @()
                remediation = "Set ms-DS-MachineAccountQuota to 0"
                fix_complexity = "low"; references = @(); technical_severity = 6.5; reachability = 0.6
            }
        }
    }

    # Users
    Write-Log "Enumerating users..."
    $userResults = Get-ADObjects "(&(objectCategory=person)(objectClass=user))" @(
        "sAMAccountName","userAccountControl","adminCount","memberOf",
        "lastLogonTimestamp","pwdLastSet","distinguishedName","objectSid",
        "servicePrincipalName","description","whenCreated","whenChanged"
    )

    $asrepRoastable = @()
    $passwdNotReqd = @()
    $kerberoastableAdmins = @()
    $domainAdmins = 0
    $totalUsers = 0; $enabledUsers = 0

    foreach ($result in $userResults) {
        $props = $result.Properties
        $totalUsers++
        $samName = if ($props["samaccountname"].Count -gt 0) { $props["samaccountname"][0] } else { "" }
        $uac = if ($props["useraccountcontrol"].Count -gt 0) { [int]$props["useraccountcontrol"][0] } else { 0 }
        $adminCount = if ($props["admincount"].Count -gt 0) { [int]$props["admincount"][0] } else { 0 }
        $dn = if ($props["distinguishedname"].Count -gt 0) { $props["distinguishedname"][0] } else { "" }
        $hasSPN = $props["serviceprincipalname"].Count -gt 0
        $isEnabled = -not ($uac -band 2)
        $isAdmin = $adminCount -eq 1
        $isPreAuthDisabled = ($uac -band 0x400000) -ne 0
        $isPasswdNotReqd = ($uac -band 0x20) -ne 0

        if ($isEnabled) { $enabledUsers++ }

        # Canonical entity
        $entityId = Add-Entity @{
            entity_type = "USER"
            sam_account_name = $samName
            distinguished_name = $dn
            domain = $Domain
            is_enabled = $isEnabled
            is_admin_count = $isAdmin
            tier = if ($isAdmin) { 0 } else { 2 }
            attributes = @{
                uac = $uac
                has_spn = $hasSPN
                uac_dont_require_preauth = $isPreAuthDisabled
                uac_passwd_notreqd = $isPasswdNotReqd
                uac_is_dc = ($uac -band 0x2000) -ne 0
            }
        }

        if ($isEnabled -and $isPreAuthDisabled) { $asrepRoastable += $samName }
        if ($isEnabled -and $isPasswdNotReqd) { $passwdNotReqd += $samName }
        if ($isEnabled -and $hasSPN -and $isAdmin) { $kerberoastableAdmins += $samName }
    }

    $Output.metadata.domain_info.total_users = $totalUsers

    if ($asrepRoastable.Count -gt 0) {
        $sev = if ($kerberoastableAdmins.Count -gt 0) { "CRITICAL" } else { "HIGH" }
        Add-Finding @{
            finding_type = "ASREP_ROASTABLE"; module = "Kerberos"
            title = "$($asrepRoastable.Count) accounts vulnerable to AS-REP roasting"
            severity = $sev; confidence = 1.0
            affected_count = $asrepRoastable.Count; affected_objects = $asrepRoastable
            root_cause = "DONT_REQUIRE_PREAUTH (UAC 0x400000) set"; causal_chain = @()
            remediation = "Enable Kerberos pre-authentication on all accounts"
            fix_complexity = "low"; references = @(); technical_severity = 8.0; reachability = 0.7
        }
    }

    if ($passwdNotReqd.Count -gt 0) {
        Add-Finding @{
            finding_type = "PASSWD_NOTREQD"; module = "User Accounts"
            title = "$($passwdNotReqd.Count) enabled accounts have PASSWD_NOTREQD flag"
            severity = "CRITICAL"; confidence = 1.0
            affected_count = $passwdNotReqd.Count; affected_objects = $passwdNotReqd
            root_cause = "PASSWD_NOTREQD (UAC 0x20) set"; causal_chain = @()
            remediation = "Clear PASSWD_NOTREQD and set passwords on all affected accounts"
            fix_complexity = "low"; references = @(); technical_severity = 9.5; reachability = 0.9
        }
    }

    if ($kerberoastableAdmins.Count -gt 0) {
        Add-Finding @{
            finding_type = "KERBEROASTABLE_ADMIN"; module = "Kerberos"
            title = "$($kerberoastableAdmins.Count) admin-level accounts are Kerberoastable"
            severity = "CRITICAL"; confidence = 1.0
            affected_count = $kerberoastableAdmins.Count; affected_objects = $kerberoastableAdmins
            root_cause = "SPN set on adminCount=1 accounts"; causal_chain = @()
            remediation = "Remove SPNs from admin accounts and migrate to gMSA"
            fix_complexity = "medium"; references = @(); technical_severity = 9.5; reachability = 0.9
            is_tier0_direct = $true
        }
    }

    Write-Log "Users: $totalUsers total, $enabledUsers enabled" "SUCCESS"
    Write-Log "AS-REP Roastable: $($asrepRoastable.Count), PASSWD_NOTREQD: $($passwdNotReqd.Count)"

    # Computers
    Write-Log "Enumerating computers..."
    $compResults = Get-ADObjects "(objectCategory=computer)" @(
        "sAMAccountName","userAccountControl","dNSHostName","operatingSystem",
        "distinguishedName","ms-Mcs-AdmPwdExpirationTime","msLAPS-PasswordExpirationTime"
    )

    $totalComps = 0; $lapsComps = 0; $unconstrainedDel = @()
    foreach ($result in $compResults) {
        $props = $result.Properties
        $totalComps++
        $samName = if ($props["samaccountname"].Count -gt 0) { $props["samaccountname"][0] } else { "" }
        $uac = if ($props["useraccountcontrol"].Count -gt 0) { [int]$props["useraccountcontrol"][0] } else { 0 }
        $dns = if ($props["dnshostname"].Count -gt 0) { $props["dnshostname"][0] } else { "" }
        $os = if ($props["operatingsystem"].Count -gt 0) { $props["operatingsystem"][0] } else { "" }
        $hasLaps = ($props["ms-mcs-admpwdexpirationtime"].Count -gt 0) -or `
                   ($props["mslaps-passwordexpirationtime"].Count -gt 0)
        $isDC = ($uac -band 0x2000) -ne 0
        $isUnconstrained = ($uac -band 0x80000) -ne 0

        if ($hasLaps) { $lapsComps++ }
        if ($isUnconstrained -and -not $isDC) { $unconstrainedDel += $samName.TrimEnd('$') }

        [void](Add-Entity @{
            entity_type = if ($isDC) { "DC" } else { "COMPUTER" }
            sam_account_name = $samName; dns_hostname = $dns
            domain = $Domain; is_enabled = -not ($uac -band 2)
            tier = if ($isDC) { 0 } else { 1 }
            attributes = @{
                operating_system = $os; uac = $uac; has_laps = $hasLaps
                uac_trusted_for_delegation = $isUnconstrained
                uac_is_dc = $isDC
            }
        })
    }

    $Output.metadata.domain_info.total_computers = $totalComps
    $Output.metadata.domain_info.laps_deployed = ($lapsComps -gt 0)
    $Output.metadata.domain_info.laps_coverage_pct = if ($totalComps -gt 0) { [int](($lapsComps / $totalComps) * 100) } else { 0 }

    if ($unconstrainedDel.Count -gt 0) {
        Add-Finding @{
            finding_type = "UNCONSTRAINED_DELEGATION"; module = "Kerberos"
            title = "$($unconstrainedDel.Count) non-DC computers configured with unconstrained delegation"
            severity = "CRITICAL"; confidence = 1.0
            affected_count = $unconstrainedDel.Count; affected_objects = $unconstrainedDel
            root_cause = "TRUSTED_FOR_DELEGATION (UAC 0x80000) set"; causal_chain = @()
            remediation = "Replace unconstrained delegation with constrained delegation or RBCD"
            fix_complexity = "medium"; references = @(); technical_severity = 9.0; reachability = 0.8
            is_tier0_direct = $true
        }
    }

    if ($lapsComps -eq 0) {
        Add-Finding @{
            finding_type = "NO_LAPS"; module = "Local Admin"
            title = "LAPS not deployed on any domain computers"
            severity = "HIGH"; confidence = 1.0
            affected_count = $totalComps; affected_objects = @("$totalComps computers at risk")
            root_cause = "Neither legacy nor Windows LAPS password-expiration metadata is present"; causal_chain = @()
            remediation = "Deploy Microsoft LAPS or Windows LAPS"
            fix_complexity = "medium"; references = @(); technical_severity = 8.0; reachability = 0.7
        }
    } elseif ($lapsComps -lt $totalComps) {
        $pct = [int](($lapsComps / $totalComps) * 100)
        if ($pct -lt 80) {
            Add-Finding @{
                finding_type = "INCOMPLETE_LAPS"; module = "Local Admin"
                title = "LAPS only deployed on $pct% of computers ($lapsComps / $totalComps)"
                severity = "MEDIUM"; confidence = 1.0
                affected_count = ($totalComps - $lapsComps)
                root_cause = "LAPS deployment incomplete"; causal_chain = @()
                remediation = "Extend LAPS deployment to all remaining computers"
                fix_complexity = "low"; references = @(); technical_severity = 6.0; reachability = 0.6
            }
        }
    }

    Write-Log "Computers: $totalComps total, LAPS: $lapsComps, Unconstrained delegation: $($unconstrainedDel.Count)" "SUCCESS"

    # Trusts
    Write-Log "Enumerating trusts..."
    $trustResults = Get-ADObjects "(objectClass=trustedDomain)" @(
        "cn","trustDirection","trustType","trustAttributes","trustPartner"
    )
    $trusts = @()
    foreach ($result in $trustResults) {
        $props = $result.Properties
        $name = if ($props["cn"].Count -gt 0) { $props["cn"][0] } else { "" }
        $attrs = if ($props["trustattributes"].Count -gt 0) { [int]$props["trustattributes"][0] } else { 0 }
        $sidFiltering = ($attrs -band 4) -ne 0
        $trust = @{ name = $name; partner = $name; sid_filtering_enabled = $sidFiltering; trust_attributes = $attrs }
        $trusts += $trust

        if (-not $sidFiltering) {
            Add-Finding @{
                finding_type = "TRUST_NO_SID_FILTERING"; module = "Trusts"
                title = "Trust to '$name' has SID filtering disabled"
                severity = "HIGH"; confidence = 0.95
                affected_count = 1; affected_objects = @($name)
                root_cause = "TRUST_ATTRIBUTE_QUARANTINED_DOMAIN (0x4) not set"
                remediation = "Enable SID filtering: netdom trust $Domain /domain:$name /quarantine:yes"
                fix_complexity = "medium"; references = @(); technical_severity = 8.5; reachability = 0.6
            }
        }
    }
    $Output.metadata.trusts = $trusts
    Write-Log "Trusts: $($trusts.Count)" "SUCCESS"
}

# ─────────────────────────────────────────────────────────────────
# Module: AD CS
# ─────────────────────────────────────────────────────────────────

function Invoke-ADCSModule {
    Write-Section "AD Certificate Services"
    $Output.modules_run += "adcs"

    Write-Log "Enumerating certificate templates..."

    # Get configuration NC
    $configNC = ""
    try {
        $root = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
        $configNC = $root.Properties["configurationNamingContext"][0]
    } catch {
        Write-Log "Could not get configNC: $_" "WARN"
        return
    }

    $templateResults = Get-ADObjects "(objectClass=pKICertificateTemplate)" @(
        "cn","displayName","msPKI-Certificate-Name-Flag","msPKI-Enrollment-Flag",
        "msPKI-RA-Signature","pKIExtendedKeyUsage","nTSecurityDescriptor",
        "msPKI-Template-Minor-Revision"
    ) -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

    $EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
    $EKU_PKINIT = "1.3.6.1.5.2.3.4"
    $EKU_SMART_CARD = "1.3.6.1.4.1.311.20.2.2"
    $EKU_ANY = "2.5.29.37.0"
    $CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
    $CT_FLAG_PEND_ALL_REQUESTS = 0x00000002

    foreach ($result in $templateResults) {
        $props = $result.Properties
        $name = if ($props["cn"].Count -gt 0) { $props["cn"][0] } else { "" }
        $nameFlags = if ($props["mspki-certificate-name-flag"].Count -gt 0) { [int]$props["mspki-certificate-name-flag"][0] } else { 0 }
        $enrollFlags = if ($props["mspki-enrollment-flag"].Count -gt 0) { [int]$props["mspki-enrollment-flag"][0] } else { 0 }
        $raSig = if ($props["mspki-ra-signature"].Count -gt 0) { [int]$props["mspki-ra-signature"][0] } else { 0 }
        $ekus = @()
        foreach ($eku in $props["pkiextendedkeyusage"]) { $ekus += $eku }

        $enrolleeSuppliesSubject = ($nameFlags -band $CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) -ne 0
        $requiresApproval = ($enrollFlags -band $CT_FLAG_PEND_ALL_REQUESTS) -ne 0
        $hasClientAuth = $ekus -contains $EKU_CLIENT_AUTH -or $ekus -contains $EKU_PKINIT -or
                         $ekus -contains $EKU_SMART_CARD -or $ekus -contains $EKU_ANY

        $esc1 = $enrolleeSuppliesSubject -and $hasClientAuth -and -not $requiresApproval -and $raSig -eq 0
        $esc2 = $ekus -contains $EKU_ANY

        $Output.cert_templates += [PSCustomObject]@{
            name                       = $name
            enrollee_supplies_subject  = $enrolleeSuppliesSubject
            requires_manager_approval  = $requiresApproval
            authorized_signatures_required = $raSig
            ekus                       = $ekus
            esc1_vulnerable            = $esc1
            esc2_vulnerable            = $esc2
            esc3_vulnerable            = $false
            esc4_vulnerable            = $false
        }

        if ($esc1) {
            Add-Finding @{
                finding_type = "ESC1"; module = "AD CS"
                title = "Certificate template '$name' is vulnerable to ESC1"
                description = "Template allows enrollee to supply SAN with Client Authentication EKU — can impersonate any user."
                severity = "CRITICAL"; confidence = 1.0
                affected_count = 1; affected_objects = @($name)
                root_cause = "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT + Client Auth EKU + no approval required"
                remediation = "Disable enrollee-supplied SAN on template '$name'"
                fix_complexity = "low"; references = @("https://posts.specterops.io/certified-pre-owned-d95910965cd2")
                technical_severity = 10.0; reachability = 0.9; is_tier0_direct = $true
            }
        }
    }

    Write-Log "Certificate templates: $($Output.cert_templates.Count)" "SUCCESS"
}

# ─────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor DarkOrange
Write-Host "  ║  AdByG0d Platform — Windows Local Collector v4.0            ║" -ForegroundColor DarkOrange
Write-Host "  ║  Enterprise Identity Exposure Assessment                     ║" -ForegroundColor DarkOrange
Write-Host "  ║  Authorized security assessment use only                     ║" -ForegroundColor DarkOrange
Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor DarkOrange
Write-Host ""

if (-not $Domain) {
    Write-Log "Domain parameter required. Use -Domain corp.local" "ERROR"
    exit 1
}

Write-Log "Target domain: $Domain" "INFO"
Write-Log "Collection mode: Windows Local (PowerShell/.NET)" "INFO"
Write-Log "Output: $OutputPath" "INFO"

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

$startTime = Get-Date

# Determine modules
$allModules = @("enum", "adcs")
if ($Modules -eq "all") {
    $runModules = $allModules
} else {
    $runModules = $Modules -split "," | ForEach-Object { $_.Trim() }
}

Write-Log "Running modules: $($runModules -join ', ')" "INFO"

foreach ($mod in $runModules) {
    switch ($mod) {
        "enum"  { Invoke-EnumModule }
        "adcs"  { Invoke-ADCSModule }
        default { Write-Log "Unknown module: $mod" "WARN" }
    }
}

# ── Save output ──────────────────────────────────────────────────
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outFile = Join-Path $OutputPath "adbygod_canonical_${Domain}_${timestamp}.json"

$json = $Output | ConvertTo-Json -Depth 20 -Compress:$false
[System.IO.File]::WriteAllText($outFile, $json, [System.Text.Encoding]::UTF8)
Write-Log "Canonical output saved: $outFile" "SUCCESS"

# ── API Upload ───────────────────────────────────────────────────
if ($ApiUrl -and $AssessmentId) {
    Write-Log "Uploading to platform API: $ApiUrl" "INFO"
    try {
        $uploadUrl = "$ApiUrl/api/v1/ingest/$AssessmentId"
        $response = Invoke-RestMethod -Uri $uploadUrl -Method POST -Body $json -ContentType "application/json"
        Write-Log "Upload successful: $($response | ConvertTo-Json -Compress)" "SUCCESS"
    } catch {
        Write-Log "Upload failed: $_" "WARN"
        Write-Log "Canonical JSON saved locally at: $outFile" "INFO"
    }
}

$elapsed = (Get-Date) - $startTime
Write-Host ""
Write-Host "  ═══════════════════════════════════════════════════════════════" -ForegroundColor DarkOrange
Write-Log "Assessment complete in $($elapsed.TotalSeconds.ToString('F1'))s" "SUCCESS"
Write-Log "Findings: $($Output.findings.Count)" "INFO"
Write-Log "Entities: $($Output.entities.Count)" "INFO"
Write-Host "  ═══════════════════════════════════════════════════════════════" -ForegroundColor DarkOrange
Write-Host ""
