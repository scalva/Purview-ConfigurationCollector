<#
.SYNOPSIS
  Purview Evidence Exporter - Operator-grade (v3.4.1)

.DESCRIPTION
  Collects operator-relevant configuration evidence for Microsoft Purview (core by default):
  CORE (default):
  - Sensitivity Labels
  - Label Publishing Policies + mapping
  - DLP Policies (operator-grade)
  - DLP Rules (operator-grade: conditions + effective actions + advanced rule JSON + embedded enforcement signals)
  - Retention Policies (operator-grade)
  - Retention Rules (operator-grade)
  - Retention Labels / Records (Compliance Tags + Storage)
  - Insider Risk (Policies + Entity Lists by valid enum types)
  - Audit (AdminAuditLogConfig + AuditConfig)

  OPTIONAL (OFF by default to stay <21 CSVs):
  - Session inventory (2 CSV)
  - Communication Compliance (2 CSV)
  - UnifiedAuditLogRetentionPolicy (1 CSV)
  - eDiscovery cases (1 CSV)

.AUTH
  Uses Connect-IPPSSession with:
  - -DisableWAM (if supported)
  - -UseRPSSession (if requested and supported)
  - DOES NOT introduce AuthMode

.NOTES
  v3.4.1 fix:
  - Remove dependency on Test-HasParam for Export-Csv quoting.
  - Sanitize preview/summaries to avoid multi-line cells that break downstream parsers.
#>

[CmdletBinding()]
param(
    [string]$OutputRoot = ".\output",
    [string]$LogsPath   = ".\logs",
    [string]$UserPrincipalName,
    [switch]$PreferRps,
    [switch]$DisableWAM,

    # Optional extras (OFF by default to avoid >21 CSVs)
    [switch]$IncludeSessionInventory,
    [switch]$IncludeCommunicationCompliance,
    [switch]$IncludeUnifiedAuditRetentionPolicy,
    [switch]$IncludeEDiscovery
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------

function Initialize-Folder {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Path $Path | Out-Null }
}

function Test-HasParam {
    param(
        [Parameter(Mandatory)][string]$Cmd,
        [Parameter(Mandatory)][string]$Param
    )
    $c = Get-Command $Cmd -ErrorAction SilentlyContinue
    if (-not $c) { return $false }
    return $c.Parameters.ContainsKey($Param)
}

function Get-PropValue {
    param(
        [Parameter(Mandatory)][object]$Obj,
        [Parameter(Mandatory)][string]$PropName
    )
    if ($null -eq $Obj) { return $null }
    if ($Obj.PSObject.Properties.Name -contains $PropName) { return $Obj.$PropName }
    return $null
}

function Join-Safe {
    param([object]$Value)
    if ($null -eq $Value) { return "" }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [System.Collections.IEnumerable]) {
        $arr = @()
        foreach ($v in $Value) { if ($null -ne $v) { $arr += $v.ToString() } }
        return ($arr -join "; ")
    }
    return $Value.ToString()
}

function ConvertTo-JsonSafe {
    param([object]$Value)

    try {
        if ($null -eq $Value) { return "" }

        # JSON comprimido (sin saltos)
        $json = $Value | ConvertTo-Json -Depth 25 -Compress

        # eliminar CRLF o tabs por paranoia máxima
        $json = $json -replace "`r",""
        $json = $json -replace "`n",""
        $json = $json -replace "`t"," "

        # BASE64 encode (CSV SAFE)
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        return [System.Convert]::ToBase64String($bytes)
    }
    catch {
        try {
            $fallback = ($Value | Out-String).Trim()
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($fallback)
            return [System.Convert]::ToBase64String($bytes)
        }
        catch {
            return ""
        }
    }
}

# ✅ Harden any human-text fields for CSV stability
function Sanitize-CsvField {
    param([object]$Value)
    if ($null -eq $Value) { return "" }

    $s = [string]$Value

    # Remove CR/LF/TAB to avoid row splitting in downstream parsers
    $s = $s -replace "(\r\n|\n|\r)", " "
    $s = $s -replace "`t", " "

    # Remove other control chars
    $s = [regex]::Replace($s, "[\x00-\x08\x0B\x0C\x0E-\x1F]", "")

    # Compact spaces
    $s = ($s -replace "\s{2,}", " ").Trim()

    return $s
}

function Is-GuidLike {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    return ($Value -match '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$')
}

function Get-StableHash {
    param([Parameter(Mandatory)][string]$Text)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join ""
}

function Get-RuleKey {
    param(
        [Parameter(Mandatory)][object]$Rule,
        [Parameter(Mandatory)][string]$PolicyKey
    )

    # Prefer real GUID-like properties if present
    foreach ($p in @("Guid","RuleGuid","Identity","ImmutableId","ObjectId","Id")) {
        $v = Get-PropValue -Obj $Rule -PropName $p
        if ($v) {
            $s = (Join-Safe $v)
            if (Is-GuidLike $s) { return $s }
            # sometimes Identity is like "xxx\GUID" or contains a GUID
            if ($s -match '([0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})') { return $Matches[1] }
        }
    }

    # Fallback deterministic hash (stable across runs if inputs unchanged)
    $name = (Join-Safe (Get-PropValue $Rule "Name"))
    $prio = (Join-Safe (Get-PropValue $Rule "Priority"))
    $wl   = (Join-Safe (Get-PropValue $Rule "Workload"))
    return Get-StableHash ("{0}|{1}|{2}|{3}" -f $PolicyKey,$name,$prio,$wl)
}

function Extract-DlpConditionsRows {
    param(
        [Parameter(Mandatory)][object]$Rule,
        [Parameter(Mandatory)][string]$RuleKey,
        [Parameter(Mandatory)][string]$PolicyKey
    )

    $rows = @()
    $adv = Get-PropValue $Rule "AdvancedRule"
    if (-not $adv) { return @() }

    try {
        $j = $adv
        if ($adv -is [string]) { $j = $adv | ConvertFrom-Json -ErrorAction Stop }

        $subConds = @($j.Condition.SubConditions)
        foreach ($sc in $subConds) {
            $name = [string]$sc.ConditionName

            if ($name -eq "ContentContainsSensitiveInformation" -and $sc.Value) {
                foreach ($v in @($sc.Value)) {
                    $rows += [pscustomobject]@{
                        PolicyKey     = $PolicyKey
                        RuleKey       = $RuleKey
                        ConditionType = "SensitiveInfoType"
                        Operator      = ">="
                        Value         = Sanitize-CsvField ([string]$v.name)
                        MinCount      = Sanitize-CsvField ([string]$v.mincount)
                        MinConfidence = Sanitize-CsvField ([string]$v.minconfidence)
                    }
                }
            }
            else {
                $rows += [pscustomobject]@{
                    PolicyKey     = $PolicyKey
                    RuleKey       = $RuleKey
                    ConditionType = Sanitize-CsvField $name
                    Operator      = ""
                    Value         = Sanitize-CsvField (Join-Safe $sc.Value)
                    MinCount      = ""
                    MinConfidence = ""
                }
            }
        }
    } catch {
        # keep exporter stable
    }

    return $rows
}

function Extract-DlpActionsRows {
    param(
        [Parameter(Mandatory)][object]$Rule,
        [Parameter(Mandatory)][string]$RuleKey,
        [Parameter(Mandatory)][string]$PolicyKey
    )

    $rows = @()

    function Add-ActionRow {
        param([string]$Type,[object]$Param)
        $rows += [pscustomobject]@{
            PolicyKey  = $PolicyKey
            RuleKey    = $RuleKey
            ActionType = Sanitize-CsvField $Type
            Parameter  = Sanitize-CsvField (Join-Safe $Param)
        }
    }

    if (Get-Boolish (Get-PropValue $Rule "BlockAccess")) { Add-ActionRow "BlockAccess" (Get-PropValue $Rule "BlockAccessScope") }
    if (Get-Boolish (Get-PropValue $Rule "Quarantine"))  { Add-ActionRow "Quarantine"  $true }

    $ra = Get-PropValue $Rule "RestrictAccess"
    if ($ra -and -not [string]::IsNullOrWhiteSpace((Join-Safe $ra))) { Add-ActionRow "RestrictAccess" $ra }

    $ga = Get-PropValue $Rule "GenerateAlert"
    if ($ga -and -not [string]::IsNullOrWhiteSpace((Join-Safe $ga))) { Add-ActionRow "GenerateAlert" $ga }

    $nu = Get-PropValue $Rule "NotifyUser"
    if ($nu -and -not [string]::IsNullOrWhiteSpace((Join-Safe $nu))) { Add-ActionRow "NotifyUser" $nu }

    $ir = Get-PropValue $Rule "GenerateIncidentReport"
    if ($ir -and -not [string]::IsNullOrWhiteSpace((Join-Safe $ir))) { Add-ActionRow "IncidentReport" $ir }

    $tip = Get-PropValue $Rule "NotifyPolicyTipDisplayOption"
    if ($tip -and -not [string]::IsNullOrWhiteSpace((Join-Safe $tip))) { Add-ActionRow "PolicyTip" $tip }

    return $rows
}
function ConvertTo-OneLine {
    param([string]$Value)
    if ($null -eq $Value) { return "" }
    $v = ($Value -replace "(\r\n|\n|\r)", " ")
    $v = ($v -replace "`t", " ")
    return $v.Trim()
}

function Get-TenantTag {
    param([string]$Upn)
    if ($Upn -and $Upn -match '@(.+)$') { return $Matches[1].ToLower() }
    return "unknown-tenant"
}

function New-Exporter {
    param(
        [Parameter(Mandatory)][string]$TenantTag,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$RunFolder
    )
    $script:__seq = 0
    return {
        param(
            [Parameter(Mandatory)][string]$ArtifactName,
            [object]$Data
        )

        $script:__seq++
        $nn = "{0:D2}" -f $script:__seq
        $safeArtifact = ($ArtifactName -replace '[^a-zA-Z0-9\-_]+', '_')
        $file = "{0}_{1}_{2}_{3}.csv" -f $TenantTag,$RunId,$nn,$safeArtifact
        $path = Join-Path $RunFolder $file

        if ($null -eq $Data) { $Data = @() }
        if ($Data -is [string]) { $Data = @([pscustomobject]@{ Value = $Data }) }
        elseif ($Data -isnot [System.Collections.IEnumerable]) { $Data = @($Data) }

        # ✅ PS7+ supports -UseQuotes Always; PS5.1 doesn't
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            $Data | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8 -UseQuotes Always
        }
        else {
            $Data | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        }

        Write-Host "Saved: $path" -ForegroundColor DarkGray
    }.GetNewClosure()
}

function Mask-GuidLike {
    param([string]$Value)
    if (-not $Value) { return "" }
    if ($Value -match '^[0-9a-fA-F]{8}\-' -or $Value -match '^[0-9a-fA-F]{32}$') {
        if ($Value.Length -ge 10) { return ($Value.Substring(0,6) + "…" + $Value.Substring($Value.Length-4,4)) }
    }
    return $Value
}

function Resolve-DlpPolicyRef {
    param([Parameter(Mandatory)][object]$Rule)
    foreach ($prop in @("Policy","ParentPolicyName","DlpCompliancePolicy","PolicyId")) {
        $v = Get-PropValue -Obj $Rule -PropName $prop
        if ($v) { return (Join-Safe $v) }
    }
    return ""
}

function Resolve-RetentionPolicyRef {
    param([Parameter(Mandatory)][object]$Rule)
    foreach ($prop in @("Policy","PolicyId","ParentPolicyName","RetentionCompliancePolicy")) {
        $v = Get-PropValue -Obj $Rule -PropName $prop
        if ($v) { return (Join-Safe $v) }
    }
    return ""
}

function Invoke-Collect {
    param(
        [Parameter(Mandatory)][string]$ArtifactName,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock
    )
    try {
        $data = & $ScriptBlock
        if ($null -eq $data) { $data = @() }
        return @($data)
    } catch {
        Write-Warning ("Collect failed for {0}: {1}" -f $ArtifactName, $_.Exception.Message)
        return @()
    }
}

function Export-IfCmdletExists {
    param(
        [Parameter(Mandatory)][string]$ArtifactName,
        [Parameter(Mandatory)][string]$CmdletName,
        [Parameter(Mandatory)][scriptblock]$Builder
    )
    if (Get-Command $CmdletName -ErrorAction SilentlyContinue) {
        $d = Invoke-Collect -ArtifactName $ArtifactName -ScriptBlock $Builder
        & $export -ArtifactName $ArtifactName -Data $d
    } else {
        Write-Host "$CmdletName not available. Exporting empty artifact: $ArtifactName" -ForegroundColor DarkGray
        & $export -ArtifactName $ArtifactName -Data @()
    }
}

# --- DLP helper funcs (operator-grade) ---
function Get-Boolish {
    param([object]$v)
    if ($null -eq $v) { return $false }
    if ($v -is [bool]) { return $v }

    if ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) {
        foreach ($item in $v) { if (Get-Boolish $item) { return $true } }
        return $false
    }

    $s = ($v | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($s)) { return $false }
    return ($s -match '\bTrue\b') -or ($s -match '\btrue\b') -or ($s -match '\b1\b')
}

function Summarize-DlpCondition {
    param([object]$Rule)

    $adv = Get-PropValue $Rule "AdvancedRule"
    if ($adv) {
        try {
            $j = $adv
            if ($adv -is [string]) { $j = $adv | ConvertFrom-Json -ErrorAction Stop }

            $subs = @()
            $subConds = $j.Condition.SubConditions
            foreach ($sc in $subConds) {
                $name = $sc.ConditionName

                if ($name -eq "ContentContainsSensitiveInformation" -and $sc.Value) {
                    foreach ($v in $sc.Value) {
                        $subs += ("SIT/Classifier='{0}' min={1} conf>={2}" -f $v.name,$v.mincount,$v.minconfidence)
                    }
                }
                elseif ($sc.Value) {
                    $subs += ("{0}={1}" -f $name,(Join-Safe $sc.Value))
                }
                else {
                    $subs += ("{0}" -f $name)
                }
            }

            if ($subs.Count -gt 0) { return ($subs -join " | ") }
        } catch { }
    }

    $ccsi = Get-PropValue $Rule "ContentContainsSensitiveInformation"
    if ($ccsi) {
        try {
            $vals = @()
            foreach ($k in @($ccsi)) { $vals += ($k | Out-String).Trim() }
            if ($vals.Count -gt 0) { return ($vals -join " | ") }
        } catch { }
    }

    return ""
}

function Summarize-DlpActions {
    param([object]$Rule)

    $parts = @()

    $block = Get-PropValue $Rule "BlockAccess"
    if (Get-Boolish $block) {
        $scope = Get-PropValue $Rule "BlockAccessScope"
        if ($scope) { $parts += ("BlockAccess=True ({0})" -f (Join-Safe $scope)) }
        else { $parts += "BlockAccess=True" }
    }

    $restrict = Get-PropValue $Rule "RestrictAccess"
    if ($restrict -and -not [string]::IsNullOrWhiteSpace((Join-Safe $restrict))) { $parts += "RestrictAccess=present" }

    $quar = Get-PropValue $Rule "Quarantine"
    if (Get-Boolish $quar) { $parts += "Quarantine=True" }

    $genAlert = Get-PropValue $Rule "GenerateAlert"
    if ($genAlert -and -not [string]::IsNullOrWhiteSpace((Join-Safe $genAlert))) { $parts += "GenerateAlert=present" }

    $notify = Get-PropValue $Rule "NotifyUser"
    if ($notify -and -not [string]::IsNullOrWhiteSpace((Join-Safe $notify))) { $parts += "NotifyUser=present" }

    $incident = Get-PropValue $Rule "GenerateIncidentReport"
    if ($incident -and -not [string]::IsNullOrWhiteSpace((Join-Safe $incident))) { $parts += "IncidentReport=present" }

    $tip = Get-PropValue $Rule "NotifyPolicyTipDisplayOption"
    if ($tip -and -not [string]::IsNullOrWhiteSpace((Join-Safe $tip))) { $parts += "PolicyTip=present" }

    return ($parts -join " | ")
}

function Get-AdvancedRuleJsonText {
    param([object]$Rule)

    $arj = Get-PropValue $Rule "AdvancedRuleJson"
    if ($arj -and -not [string]::IsNullOrWhiteSpace([string]$arj)) { return [string]$arj }

    $adv = Get-PropValue $Rule "AdvancedRule"
    if ($adv) {
        if ($adv -is [string]) { return [string]$adv }
        return (ConvertTo-JsonSafe $adv)
    }

    return ""
}

# ---------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------

Initialize-Folder -Path $OutputRoot
Initialize-Folder -Path $LogsPath

$runId     = Get-Date -Format "yyyyMMdd-HHmmss"
$tenantTag = Get-TenantTag -Upn $UserPrincipalName

$tenantFolder = Join-Path $OutputRoot $tenantTag
Initialize-Folder -Path $tenantFolder

$runFolder = Join-Path $tenantFolder $runId
Initialize-Folder -Path $runFolder

$transcriptPath = Join-Path $LogsPath "transcript-$runId.txt"
Start-Transcript -Path $transcriptPath -Append | Out-Null

$export = New-Exporter -TenantTag $tenantTag -RunId $runId -RunFolder $runFolder

Write-Host "Starting Purview Evidence Exporter v3.4.1" -ForegroundColor Cyan
Write-Host "Tenant: $tenantTag"
Write-Host "RunId : $runId"
Write-Host "Output: $runFolder"
Write-Host "PS    : $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion) @ $((Get-Process -Id $PID).Path)"
Write-Host ""

try {
    # -----------------------------------------------------------------
    # Connect
    # -----------------------------------------------------------------
    Import-Module ExchangeOnlineManagement -ErrorAction Stop

    $connectParams = @{}
    if ($UserPrincipalName) { $connectParams.UserPrincipalName = $UserPrincipalName }

    if ($DisableWAM) {
        if (Test-HasParam -Cmd "Connect-IPPSSession" -Param "DisableWAM") { $connectParams.DisableWAM = $true }
        else { Write-Warning "DisableWAM not supported by this build. Ignoring." }
    }

    if ($PreferRps) {
        if (Test-HasParam -Cmd "Connect-IPPSSession" -Param "UseRPSSession") { $connectParams.UseRPSSession = $true }
        else { Write-Warning "UseRPSSession not supported by this build. Ignoring." }
    }

    Write-Host "Connecting to Security & Compliance PowerShell..." -ForegroundColor Cyan
    Connect-IPPSSession @connectParams -ErrorAction Stop | Out-Null
    Write-Host "Connected." -ForegroundColor Green
    Write-Host ""

    # -----------------------------------------------------------------
    # OPTIONAL: Session inventory (2 CSV only) - OFF by default
    # -----------------------------------------------------------------
    if ($IncludeSessionInventory) {
        Write-Host "Collecting session inventory (2 CSV)..." -ForegroundColor Cyan

        $sessionModules = @(Get-Module | Select-Object Name, Version, ModuleType, Path)
        & $export -ArtifactName "Session_Modules" -Data $sessionModules

        $cmdletSets = @(
            @{ Category = "Compliance";        Regex = 'Compliance' },
            @{ Category = "DLP";               Regex = 'DlpCompliance|Dlp' },
            @{ Category = "InsiderRisk";       Regex = 'InsiderRisk|Insider' },
            @{ Category = "SupervisoryReview"; Regex = 'SupervisoryReview|Supervisory' },
            @{ Category = "Audit";             Regex = 'Audit|UnifiedAudit|AdminAudit' },
            @{ Category = "ComplianceTag";     Regex = 'ComplianceTag|RetentionLabel|Tag' }
        )

        $allSessionCommands = @(Get-Command -ErrorAction SilentlyContinue |
            Select-Object Name, CommandType, ModuleName, Source, Version)

        $sessionCmdletsAll = foreach ($set in $cmdletSets) {
            $cat   = $set.Category
            $regex = $set.Regex
            $allSessionCommands |
                Where-Object { $_.Name -match $regex } |
                Select-Object @{n="Category";e={$cat}}, Name, CommandType, ModuleName, Source, Version
        }

        $sessionCmdletsAll = @($sessionCmdletsAll | Sort-Object Category, Name -Unique)
        & $export -ArtifactName "Session_Cmdlets_All" -Data $sessionCmdletsAll
    }

    # -----------------------------------------------------------------
    # Sensitivity Labels
    # -----------------------------------------------------------------
    Write-Host "Collecting Sensitivity Labels..." -ForegroundColor Cyan
    Export-IfCmdletExists -ArtifactName "SensitivityLabels" -CmdletName "Get-Label" -Builder {
        Get-Label | Select-Object DisplayName,Name,Guid,Priority,Disabled,WhenCreated,WhenChanged
    }

    # -----------------------------------------------------------------
    # Label Policies + Mapping
    # -----------------------------------------------------------------
    Write-Host "Collecting Label Publishing Policies..." -ForegroundColor Cyan
    $rawLabelPolicies = @()
    if (Get-Command "Get-LabelPolicy" -ErrorAction SilentlyContinue) {
        $rawLabelPolicies = Invoke-Collect -ArtifactName "LabelPolicies" -ScriptBlock { Get-LabelPolicy }
        & $export -ArtifactName "LabelPolicies" -Data ($rawLabelPolicies | Select-Object Name,Guid,Enabled,Priority,DistributionStatus)

        Write-Host "Building Label Policy -> Published Labels mapping..." -ForegroundColor Cyan
        $labelPolicyMap = foreach ($p in $rawLabelPolicies) {
            $labelsProp = Get-PropValue -Obj $p -PropName "Labels"
            [pscustomobject]@{
                PolicyName          = $p.Name
                Enabled             = (Get-PropValue $p "Enabled")
                Priority            = (Get-PropValue $p "Priority")
                DistributionStatus  = (Get-PropValue $p "DistributionStatus")
                PublishedLabelCount = @($labelsProp).Count
                PublishedLabels     = (Join-Safe $labelsProp)
            }
        }
        & $export -ArtifactName "LabelPolicy_LabelMapping" -Data $labelPolicyMap
    } else {
        Write-Host "Get-LabelPolicy not available. Exporting empty artifacts." -ForegroundColor DarkGray
        & $export -ArtifactName "LabelPolicies" -Data @()
        & $export -ArtifactName "LabelPolicy_LabelMapping" -Data @()
    }

    # -----------------------------------------------------------------
    # DLP Policies
    # -----------------------------------------------------------------
    Write-Host "Collecting DLP Policies (operator-grade)..." -ForegroundColor Cyan
    Export-IfCmdletExists -ArtifactName "DLPPolicies_Operator" -CmdletName "Get-DlpCompliancePolicy" -Builder {
        Get-DlpCompliancePolicy | ForEach-Object {

    $policyKey = ""

    $guid = Get-PropValue $_ "Guid"

    if ($guid -and (Is-GuidLike $guid)) {
        $policyKey = $guid
    }
    else {
        $policyKey = $_.Name
    }

    [pscustomobject]@{

        PolicyKey              = $policyKey   # ⭐ NEW

        PolicyName             = $_.Name
        Enabled                = (Get-PropValue $_ "Enabled")
        Mode                   = (Get-PropValue $_ "Mode")
        Priority               = (Get-PropValue $_ "Priority")
        Workload               = (Join-Safe (Get-PropValue $_ "Workload"))

        DistributionStatus     = (Get-PropValue $_ "DistributionStatus")
        DistributionSyncStatus = (Get-PropValue $_ "DistributionSyncStatus")

        ExchangeLocation       = (Join-Safe (Get-PropValue $_ "ExchangeLocation"))
        SharePointLocation     = (Join-Safe (Get-PropValue $_ "SharePointLocation"))
        OneDriveLocation       = (Join-Safe (Get-PropValue $_ "OneDriveLocation"))
        TeamsLocation          = (Join-Safe (Get-PropValue $_ "TeamsLocation"))
        EndpointDlpLocation    = (Join-Safe (Get-PropValue $_ "EndpointDlpLocation"))

        WhenCreated            = (Get-PropValue $_ "WhenCreated")
        WhenChanged            = (Get-PropValue $_ "WhenChanged")
    }
}
    }
# -----------------------------------------------------------------
# DLP Rules (Operator-grade) - Option B (relational, Copilot-safe)
# -----------------------------------------------------------------
Write-Host "Collecting DLP Rules (operator-grade) [Option B: relational exports]..." -ForegroundColor Cyan

if (Get-Command "Get-DlpComplianceRule" -ErrorAction SilentlyContinue) {

    $dlpRulesRaw = @(Get-DlpComplianceRule)

    $dlpRules          = @()
    $dlpRuleConditions = @()
    $dlpRuleActions    = @()
    $dlpRuleEvidence   = @()   # optional annex

    foreach ($r in $dlpRulesRaw) {

        # ---- Policy correlation key ----
        $policyRef = Resolve-DlpPolicyRef -Rule $r
        $policyKey = ""
        if (Is-GuidLike $policyRef) { $policyKey = $policyRef }
        else { $policyKey = Sanitize-CsvField $policyRef }

        $policyMasked = Mask-GuidLike -Value $policyKey

        # ---- Rule correlation key ----
        $ruleKey = Get-RuleKey -Rule $r -PolicyKey $policyKey

        # ---- AdvancedRule evidence (optional annex) ----
        $advRule    = Get-PropValue $r "AdvancedRule"
        $advRuleB64 = ConvertTo-JsonSafe $advRule

        $advRuleJsonLength = 0
        if (-not [string]::IsNullOrWhiteSpace($advRuleB64)) {
            try {
                $advRuleJsonLength = ([System.Convert]::FromBase64String($advRuleB64)).Length
            } catch {
                $advRuleJsonLength = 0
            }
        }

        # ---- Effective actions (operator truth) ----
        $blockAccess = Get-Boolish (Get-PropValue $r "BlockAccess")
        $blockScope  = (Join-Safe (Get-PropValue $r "BlockAccessScope"))
        $quarantine  = Get-Boolish (Get-PropValue $r "Quarantine")

        $restrict    = (Join-Safe (Get-PropValue $r "RestrictAccess"))
        $genAlert    = (Join-Safe (Get-PropValue $r "GenerateAlert"))
        $notifyUser  = (Join-Safe (Get-PropValue $r "NotifyUser"))
        $genIncident = (Join-Safe (Get-PropValue $r "GenerateIncidentReport"))
        $isAdv       = Get-Boolish (Get-PropValue $r "IsAdvancedRule")

        # ---- Embedded enforcement signals ----
        $hasBlock    = $blockAccess -or $quarantine -or (-not [string]::IsNullOrWhiteSpace($restrict))
        $hasNotify   = (-not [string]::IsNullOrWhiteSpace($notifyUser))
        $hasIncident = (-not [string]::IsNullOrWhiteSpace($genIncident))
        $hasAlert    = (-not [string]::IsNullOrWhiteSpace($genAlert))

        # ---- Relational deconstruction ----
        $dlpRuleConditions += Extract-DlpConditionsRows -Rule $r -RuleKey $ruleKey -PolicyKey $policyKey
        $dlpRuleActions    += Extract-DlpActionsRows    -Rule $r -RuleKey $ruleKey -PolicyKey $policyKey

        # ---- Main Rules table (Copilot-safe: no blobs, no long summaries) ----
        $dlpRules += [pscustomobject]@{
            PolicyKey              = $policyKey
            PolicyNameMasked       = $policyMasked

            RuleKey                = $ruleKey
            RuleName               = (Get-PropValue $r "Name")
            DisplayName            = (Get-PropValue $r "DisplayName")
            ParentPolicyName       = (Get-PropValue $r "ParentPolicyName")

            Enabled                = -not (Get-Boolish (Get-PropValue $r "Disabled"))
            Priority               = (Get-PropValue $r "Priority")
            Mode                   = (Get-PropValue $r "Mode")
            Workload               = (Join-Safe (Get-PropValue $r "Workload"))
            ReportSeverityLevel    = (Get-PropValue $r "ReportSeverityLevel")

            BlockAccess            = $blockAccess
            BlockAccessScope       = Sanitize-CsvField $blockScope
            Quarantine             = $quarantine
            RestrictAccess         = Sanitize-CsvField $restrict
            GenerateAlert          = Sanitize-CsvField $genAlert
            NotifyUser             = Sanitize-CsvField $notifyUser
            GenerateIncidentReport = Sanitize-CsvField $genIncident

            HasBlockSignal         = $hasBlock
            HasNotifySignal        = $hasNotify
            HasIncidentSignal      = $hasIncident
            HasAlertSignal         = $hasAlert

            IsAdvancedRule         = $isAdv
            AdvancedRuleJsonLength = $advRuleJsonLength

            WhenCreated            = (Get-PropValue $r "WhenCreated")
            WhenChanged            = (Get-PropValue $r "WhenChanged")
        }

        # ---- Optional evidence annex (keep raw for audit, not for Copilot calc) ----
        $dlpRuleEvidence += [pscustomobject]@{
            PolicyKey       = $policyKey
            RuleKey         = $ruleKey
            RuleName        = (Get-PropValue $r "Name")
            AdvancedRuleB64 = $advRuleB64
        }
    }

    & $export -ArtifactName "DLPRules_Operator" -Data $dlpRules
    & $export -ArtifactName "DLPRuleConditions_Operator" -Data $dlpRuleConditions
    & $export -ArtifactName "DLPRuleActions_Operator" -Data $dlpRuleActions

    # If you don't want the evidence annex, comment this out:
    & $export -ArtifactName "DLPRules_AdvancedRuleEvidence" -Data $dlpRuleEvidence
}
else {
    & $export -ArtifactName "DLPRules_Operator" -Data @()
    & $export -ArtifactName "DLPRuleConditions_Operator" -Data @()
    & $export -ArtifactName "DLPRuleActions_Operator" -Data @()
    & $export -ArtifactName "DLPRules_AdvancedRuleEvidence" -Data @()
}

    # -----------------------------------------------------------------
    # Retention Policies + Rules
    # -----------------------------------------------------------------
    Write-Host "Collecting Retention Policies (operator-grade)..." -ForegroundColor Cyan
    Export-IfCmdletExists -ArtifactName "RetentionPolicies_Operator" -CmdletName "Get-RetentionCompliancePolicy" -Builder {
        Get-RetentionCompliancePolicy | ForEach-Object {
            [pscustomobject]@{
                PolicyName             = $_.Name
                Enabled                = (Get-PropValue $_ "Enabled")
                Mode                   = (Get-PropValue $_ "Mode")
                DistributionStatus     = (Get-PropValue $_ "DistributionStatus")
                DistributionSyncStatus = (Get-PropValue $_ "DistributionSyncStatus")
                Workload               = (Join-Safe (Get-PropValue $_ "Workload"))
                ExchangeLocation       = (Join-Safe (Get-PropValue $_ "ExchangeLocation"))
                SharePointLocation     = (Join-Safe (Get-PropValue $_ "SharePointLocation"))
                OneDriveLocation       = (Join-Safe (Get-PropValue $_ "OneDriveLocation"))
                TeamsLocation          = (Join-Safe (Get-PropValue $_ "TeamsLocation"))
                Comment                = (Get-PropValue $_ "Comment")
                WhenCreated            = (Get-PropValue $_ "WhenCreated")
                WhenChanged            = (Get-PropValue $_ "WhenChanged")
            }
        }
    }

    Write-Host "Collecting Retention Rules (operator-grade)..." -ForegroundColor Cyan
    Export-IfCmdletExists -ArtifactName "RetentionRules_Operator" -CmdletName "Get-RetentionComplianceRule" -Builder {
        Get-RetentionComplianceRule | ForEach-Object {
            $policyRef    = Resolve-RetentionPolicyRef -Rule $_
            $policyMasked = Mask-GuidLike -Value $policyRef
            [pscustomobject]@{
                PolicyNameMasked       = $policyMasked
                PolicyNameRaw          = $policyRef
                RuleName               = $_.Name
                Enabled                = -not [bool](Get-PropValue $_ "Disabled")
                Workload               = (Join-Safe (Get-PropValue $_ "Workload"))
                RetentionAction        = (Get-PropValue $_ "RetentionAction")
                RetentionDurationDays  = (Get-PropValue $_ "RetentionDuration")
                ContentMatchQuery      = (Get-PropValue $_ "ContentMatchQuery")
                KqlQuery               = (Get-PropValue $_ "KqlQuery")
                WhenCreated            = (Get-PropValue $_ "WhenCreated")
                WhenChanged            = (Get-PropValue $_ "WhenChanged")
            }
        }
    }

    # -----------------------------------------------------------------
    # Retention labels / records (Compliance Tags)
    # -----------------------------------------------------------------
    Write-Host "Collecting Retention Labels / Records (Compliance Tags)..." -ForegroundColor Cyan
    Export-IfCmdletExists -ArtifactName "RetentionLabels_ComplianceTag" -CmdletName "Get-ComplianceTag" -Builder {
        Get-ComplianceTag | Select-Object Name,Guid,Comment,RetentionAction,RetentionDuration,IsRecordLabel,DispositionReview,WhenCreated,WhenChanged
    }
    Export-IfCmdletExists -ArtifactName "RetentionLabels_ComplianceTagStorage" -CmdletName "Get-ComplianceTagStorage" -Builder {
        Get-ComplianceTagStorage | Select-Object *
    }

    # -----------------------------------------------------------------
    # Insider Risk
    # -----------------------------------------------------------------
    Write-Host "Collecting Insider Risk Management..." -ForegroundColor Cyan
    Export-IfCmdletExists -ArtifactName "InsiderRiskPolicies" -CmdletName "Get-InsiderRiskPolicy" -Builder {
        Get-InsiderRiskPolicy | Select-Object Name,Enabled,Mode,Priority,CreatedBy,WhenCreated,WhenChanged
    }

    $irmListTypes = @(
        "HveLists","DomainLists","CriticalAssetLists","WindowsFilePathRegexLists","SensitiveTypeLists","SiteLists","KeywordLists",
        "CustomDomainLists","CustomSiteLists","CustomKeywordLists","CustomFileTypeLists","CustomFilePathRegexLists",
        "CustomSensitiveInformationTypeLists","CustomMLClassifierTypeLists",
        "GlobalExclusionSGMapping","DlpPolicyLists","CcPolicyLists",
        "ApplicationLists","CustomApplicationLists","PrinterLists","CustomPrinterLists"
    )

    if (Get-Command "Get-InsiderRiskEntityList" -ErrorAction SilentlyContinue) {
        $allLists = @()
        foreach ($t in $irmListTypes) {
            $chunk = Invoke-Collect -ArtifactName ("InsiderRiskEntityLists_{0}" -f $t) -ScriptBlock {
                Get-InsiderRiskEntityList -Type $t | Select-Object Name,Type,Description,CreatedBy,WhenCreated,WhenChanged
            }
            foreach ($row in $chunk) { $allLists += $row }
        }
        & $export -ArtifactName "InsiderRiskEntityLists" -Data $allLists
    } else {
        & $export -ArtifactName "InsiderRiskEntityLists" -Data @()
    }

    # -----------------------------------------------------------------
    # OPTIONAL: Communication Compliance (Supervisory Review) - OFF by default
    # -----------------------------------------------------------------
    if ($IncludeCommunicationCompliance) {
        Write-Host "Collecting Communication Compliance / Supervisory Review..." -ForegroundColor Cyan
        Export-IfCmdletExists -ArtifactName "SupervisoryReviewPolicies" -CmdletName "Get-SupervisoryReviewPolicyV2" -Builder {
            Get-SupervisoryReviewPolicyV2 | Select-Object Name,Enabled,Mode,CreatedBy,WhenCreated,WhenChanged
        }
        Export-IfCmdletExists -ArtifactName "SupervisoryReviewRules" -CmdletName "Get-SupervisoryReviewRule" -Builder {
            Get-SupervisoryReviewRule | Select-Object Name,Policy,Enabled,CreatedBy,WhenCreated,WhenChanged
        }
    }

    # -----------------------------------------------------------------
    # Audit (CORE: AdminAuditLogConfig + AuditConfig)
    # -----------------------------------------------------------------
    Write-Host "Collecting Audit configuration..." -ForegroundColor Cyan
    Export-IfCmdletExists -ArtifactName "AdminAuditLogConfig" -CmdletName "Get-AdminAuditLogConfig" -Builder {
        Get-AdminAuditLogConfig | Select-Object *
    }
    Export-IfCmdletExists -ArtifactName "AuditConfig" -CmdletName "Get-AuditConfig" -Builder {
        Get-AuditConfig | Select-Object *
    }

    if ($IncludeUnifiedAuditRetentionPolicy) {
        Export-IfCmdletExists -ArtifactName "UnifiedAuditLogRetentionPolicy" -CmdletName "Get-UnifiedAuditLogRetentionPolicy" -Builder {
            Get-UnifiedAuditLogRetentionPolicy | Select-Object *
        }
    }

    if ($IncludeEDiscovery) {
        Write-Host "Collecting eDiscovery Cases (optional)..." -ForegroundColor Cyan
        Export-IfCmdletExists -ArtifactName "eDiscoveryCases" -CmdletName "Get-ComplianceCase" -Builder {
            Get-ComplianceCase | Select-Object Name,CaseType,Status,CreatedTime,LastModifiedTime
        }
    }

    $summary = @(
        "Purview Evidence Exporter v3.4.1",
        "Tenant: $tenantTag",
        "RunId : $runId",
        "Output: $runFolder",
        "Transcript: $transcriptPath",
        "",
        "Options:",
        "  IncludeSessionInventory            = $IncludeSessionInventory",
        "  IncludeCommunicationCompliance     = $IncludeCommunicationCompliance",
        "  IncludeUnifiedAuditRetentionPolicy = $IncludeUnifiedAuditRetentionPolicy",
        "  IncludeEDiscovery                  = $IncludeEDiscovery",
        "",
        "DLP Rules export mode:",
        "  Option B: DLPRules_Operator.csv (CSV-stable; preview/summaries sanitized)",
        "  Evidence: AdvancedRuleJsonB64 preserved"
    )
    $summaryPath = Join-Path $runFolder ("{0}_{1}_00_Summary.txt" -f $tenantTag,$runId)
    $summary | Out-File -Encoding UTF8 $summaryPath

    Write-Host ""
    $summary | ForEach-Object { Write-Host $_ }
    Write-Host ""
    Write-Host "Done." -ForegroundColor Green
}
catch {
    Write-Host ""
    Write-Error ("FAILED: {0}" -f $_.Exception.Message)
    Write-Host "---- Error details (transcript) ----" -ForegroundColor Yellow
    $_ | Format-List * -Force
    Write-Host "-----------------------------------" -ForegroundColor Yellow
    throw
}
finally {
    Stop-Transcript | Out-Null
}