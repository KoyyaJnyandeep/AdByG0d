<#
.SYNOPSIS
    AdByG0d Platform — CA EditFlags Collector
    Reads EDITF_ATTRIBUTESUBJECTALTNAME2 from CA policy registry. Read-only.

.DESCRIPTION
    Collects CA EditFlags (registry and certutil) to detect ESC6 risk.
    Safe by default:
    - Read-only registry access only
    - No certificate requests
    - No key generation
    - No NTLM relay or authentication coercion
    - No CA configuration changes

.PARAMETER OutputPath
    Path to save JSON output. Default: .\adbygod-ca-flags.json

.PARAMETER ApiUrl
    AdByG0d API base URL (e.g. http://kali:8000) for direct upload.

.PARAMETER AssessmentId
    Assessment UUID for direct upload to /ingest/<id>/ca-flags.

.PARAMETER ApiToken
    Bearer token for API authentication.

.PARAMETER CAName
    Specific CA name to check. If omitted, auto-discovers all CAs on this host.

.EXAMPLE
    .\Collect-AdByG0d-ADCS-CAFlags.ps1 -OutputPath C:\Tools\adbygod-ca-flags.json

.EXAMPLE
    .\Collect-AdByG0d-ADCS-CAFlags.ps1 -ApiUrl http://192.168.56.1:8000 -AssessmentId <uuid> -ApiToken <token>

.NOTES
    Author: AdByG0d Platform
    Version: 1.0.0
    Run as: Local Administrator or account with read access to HKLM\SYSTEM\CurrentControlSet\Services\CertSvc
    For authorized security assessment use only.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\adbygod-ca-flags.json",

    [Parameter(Mandatory = $false)]
    [string]$ApiUrl = "",

    [Parameter(Mandatory = $false)]
    [string]$AssessmentId = "",

    [Parameter(Mandatory = $false)]
    [string]$ApiToken = "",

    [Parameter(Mandatory = $false)]
    [string]$CAName = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$TOOL_NAME      = "AdByG0d"
$SCRIPT_VERSION = "1.0.0"
$EDITF_ATTRIBUTESUBJECTALTNAME2_BIT = 0x00040000

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
        default   { "Cyan" }
    }
    Write-Host "  [$ts] [$Level] $Message" -ForegroundColor $color
}

# ─────────────────────────────────────────────────────────────────
# CA Discovery
# ─────────────────────────────────────────────────────────────────

function Get-LocalCANames {
    <#
    Discovers all CAs installed on this host via CertSvc registry key.
    Returns a list of CA name strings.
    #>
    $caNames = @()
    $certSvcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration"

    if (-not (Test-Path $certSvcKey)) {
        Write-Log "CertSvc registry key not found — is this a CA server?" "WARN"
        return $caNames
    }

    try {
        $subKeys = Get-ChildItem -Path $certSvcKey -ErrorAction Stop
        foreach ($key in $subKeys) {
            $caNames += $key.PSChildName
        }
    } catch {
        Write-Log "Failed to enumerate CertSvc subkeys: $_" "ERROR"
    }
    return $caNames
}

# ─────────────────────────────────────────────────────────────────
# Registry EditFlags reader
# ─────────────────────────────────────────────────────────────────

function Get-CAEditFlagsFromRegistry {
    param([string]$CANameParam)
    <#
    Reads EditFlags from:
    HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CAName>\
        PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\EditFlags
    Returns hashtable with edit_flags (int), registry_path (string), error (string).
    Read-only — does not modify any value.
    #>
    $policyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CANameParam\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy"
    $result = @{
        edit_flags    = $null
        registry_path = $policyPath
        error         = ""
    }

    if (-not (Test-Path $policyPath)) {
        $result.error = "Registry path not found: $policyPath"
        Write-Log $result.error "WARN"
        return $result
    }

    try {
        $props = Get-ItemProperty -Path $policyPath -Name "EditFlags" -ErrorAction Stop
        $result.edit_flags = [int]$props.EditFlags
        Write-Log "Registry EditFlags for '$CANameParam': $($result.edit_flags) ($('{0:#010x}' -f $result.edit_flags))" "SUCCESS"
    } catch {
        $result.error = "Failed to read EditFlags: $_"
        Write-Log $result.error "WARN"
    }
    return $result
}

# ─────────────────────────────────────────────────────────────────
# certutil EditFlags reader
# ─────────────────────────────────────────────────────────────────

function Get-CAEditFlagsFromCertutil {
    param([string]$CANameParam)
    <#
    Runs: certutil -getreg policy\EditFlags
    (Uses -config if CAName provided and certutil supports it.)
    Read-only — certutil -getreg does not modify the registry.
    Returns hashtable with certutil_output (string), edit_flags (int|null), error (string).
    #>
    $result = @{
        certutil_output = ""
        edit_flags      = $null
        error           = ""
    }

    $certutilPath = "certutil.exe"
    try {
        # Try with CA name config string first, fall back to local default
        $configArg = if ($CANameParam) { "-config `"$($env:COMPUTERNAME)\$CANameParam`"" } else { "" }
        $cmd = "& $certutilPath $configArg -getreg policy\EditFlags 2>&1"
        $output = Invoke-Expression $cmd
        $result.certutil_output = $output -join "`n"

        # Parse the EditFlags value from output
        # Expected format: "EditFlags REG_DWORD = 0x00160004 (1441796)"
        $match = [regex]::Match($result.certutil_output, 'EditFlags\s+REG_DWORD\s*=\s*(0x[0-9a-fA-F]+)', 'IgnoreCase')
        if ($match.Success) {
            $result.edit_flags = [Convert]::ToInt32($match.Groups[1].Value, 16)
        } else {
            $matchDec = [regex]::Match($result.certutil_output, 'EditFlags\s+REG_DWORD\s*=\s*(\d+)', 'IgnoreCase')
            if ($matchDec.Success) {
                $result.edit_flags = [int]$matchDec.Groups[1].Value
            }
        }
        Write-Log "certutil EditFlags for '$CANameParam': $($result.edit_flags)" "INFO"
    } catch {
        $result.error = "certutil failed: $_"
        Write-Log $result.error "WARN"
    }
    return $result
}

# ─────────────────────────────────────────────────────────────────
# Main collection
# ─────────────────────────────────────────────────────────────────

Write-Log "AdByG0d CA EditFlags Collector v$SCRIPT_VERSION — read-only" "INFO"
Write-Log "Host: $($env:COMPUTERNAME)" "INFO"

$hostname = [System.Net.Dns]::GetHostEntry([System.Net.Dns]::GetHostName()).HostName
if (-not $hostname) { $hostname = $env:COMPUTERNAME }

# Determine which CAs to check
$caNames = @()
if ($CAName) {
    $caNames = @($CAName)
    Write-Log "Checking specified CA: $CAName" "INFO"
} else {
    $caNames = Get-LocalCANames
    if ($caNames.Count -eq 0) {
        Write-Log "No CAs found on this host. Specify -CAName explicitly." "WARN"
    } else {
        Write-Log "Discovered $($caNames.Count) CA(s): $($caNames -join ', ')" "INFO"
    }
}

$caFlagsResults = @()

foreach ($ca in $caNames) {
    Write-Log "Collecting EditFlags for CA: $ca" "INFO"

    # Try registry first (most reliable, lowest overhead)
    $regResult   = Get-CAEditFlagsFromRegistry -CANameParam $ca
    # Also run certutil for corroboration and human-readable output
    $certResult  = Get-CAEditFlagsFromCertutil -CANameParam $ca

    # Prefer registry value; fall back to certutil-parsed value
    $editFlagsInt = $null
    if ($null -ne $regResult.edit_flags) {
        $editFlagsInt = $regResult.edit_flags
    } elseif ($null -ne $certResult.edit_flags) {
        $editFlagsInt = $certResult.edit_flags
        Write-Log "Using certutil-parsed EditFlags (registry read failed)" "WARN"
    }

    $editFlagsHex = if ($null -ne $editFlagsInt) { "0x{0:x8}" -f $editFlagsInt } else { $null }

    # Determine if EDITF_ATTRIBUTESUBJECTALTNAME2 (0x00040000) is set
    $flagSet = $false
    if ($null -ne $editFlagsInt) {
        $flagSet = ($editFlagsInt -band $EDITF_ATTRIBUTESUBJECTALTNAME2_BIT) -ne 0
    } elseif ($certResult.certutil_output -match "EDITF_ATTRIBUTESUBJECTALTNAME2") {
        $flagSet = $true
        Write-Log "EDITF_ATTRIBUTESUBJECTALTNAME2 found in certutil output (no numeric EditFlags parsed)" "WARN"
    }

    $severity = if ($flagSet) { "CRITICAL — ESC6 VULNERABLE" } else { "OK" }
    Write-Log "CA '$ca': EDITF_ATTRIBUTESUBJECTALTNAME2 = $flagSet  ($severity)" $(if ($flagSet) { "ERROR" } else { "SUCCESS" })

    $caFlagsResults += [ordered]@{
        ca_name                             = $ca
        hostname                            = $hostname
        registry_path                       = $regResult.registry_path
        edit_flags                          = $editFlagsInt
        edit_flags_hex                      = $editFlagsHex
        editf_attribute_subject_alt_name_2  = $flagSet
        certutil_output                     = $certResult.certutil_output
        collection_method                   = "windows_ca_flags"
        collected_at                        = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
        registry_read_error                 = $regResult.error
        certutil_error                      = $certResult.error
    }
}

# ─────────────────────────────────────────────────────────────────
# Output
# ─────────────────────────────────────────────────────────────────

$output = [ordered]@{
    tool               = $TOOL_NAME
    script_version     = $SCRIPT_VERSION
    collection_mode    = "WINDOWS_CA_FLAGS"
    hostname           = $hostname
    collected_at       = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    ca_flags           = $caFlagsResults
}

$json = $output | ConvertTo-Json -Depth 10

# Save to file
if ($OutputPath) {
    try {
        $outputDir = Split-Path $OutputPath -Parent
        if ($outputDir -and -not (Test-Path $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        }
        $json | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
        Write-Log "Output saved to: $OutputPath" "SUCCESS"
    } catch {
        Write-Log "Failed to save output: $_" "ERROR"
    }
}

# Upload to API
if ($ApiUrl -and $AssessmentId) {
    $endpoint = "$ApiUrl/ingest/$AssessmentId/ca-flags"
    Write-Log "Uploading to API: $endpoint" "INFO"

    # The endpoint expects: {"ca_flags": [...]}
    $apiPayload = @{ ca_flags = $caFlagsResults } | ConvertTo-Json -Depth 10

    $headers = @{ "Content-Type" = "application/json" }
    if ($ApiToken) {
        $headers["Authorization"] = "Bearer $ApiToken"
    }

    try {
        $response = Invoke-RestMethod -Uri $endpoint -Method POST -Body $apiPayload -Headers $headers -ErrorAction Stop
        Write-Log "Upload successful. CAs evaluated: $($response.cas_evaluated), ESC6 findings: $($response.esc6_findings_created)" "SUCCESS"
    } catch {
        Write-Log "API upload failed: $_" "ERROR"
        Write-Log "Upload the JSON manually: POST $endpoint" "WARN"
    }
} elseif ($ApiUrl -or $AssessmentId) {
    Write-Log "Both -ApiUrl and -AssessmentId are required for direct upload. Saved to file only." "WARN"
}

# Print summary to console
Write-Host ""
Write-Host "  ── ESC6 Summary ──────────────────────────────────────" -ForegroundColor Cyan
foreach ($ca in $caFlagsResults) {
    $status = if ($ca.editf_attribute_subject_alt_name_2) { "[VULNERABLE]" } else { "[  SAFE    ]" }
    $color  = if ($ca.editf_attribute_subject_alt_name_2) { "Red" } else { "Green" }
    Write-Host ("  $status  $($ca.ca_name)  EditFlags=$($ca.edit_flags_hex)") -ForegroundColor $color
}
Write-Host ""

# Output the JSON to stdout as well so it can be piped
Write-Output $json
