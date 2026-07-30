#Requires -Version 7.2
<#
.SYNOPSIS
  Align module SemVer across manifest, UserAgent, and product-brief Status.

.DESCRIPTION
  **Safety tier: 2**

  Controlled write: updates version strings before a release commit/tag.
  Does not commit, push, or create tags — see docs/release.md.
  Supports -WhatIf. -CheckOnly verifies consistency without writing.

.PARAMETER Version
  Target SemVer (X.Y.Z). Required unless -CheckOnly.

.PARAMETER ReleaseNotes
  Optional short release note stored in the module manifest PSData.

.PARAMETER StatusSuffix
  Optional text after "vX.Y.Z — " on the product-brief Status line.
  When omitted on write, only the version token on that line is replaced.

.PARAMETER CheckOnly
  Exit 0 when ModuleVersion, defaults UserAgent, download fallback, and
  brief Status version agree; exit 1 on mismatch. Ignores -Version.

.PARAMETER AgentSummary
  One success-stream line: HMD-BUMP-OK | HMD-BUMP-FAIL | HMD-BUMP-CHECK-…

.EXAMPLE
  pwsh -NoProfile -File .\scripts\Invoke-HmdBumpVersion.ps1 -Version 0.2.1 -WhatIf

.EXAMPLE
  pwsh -NoProfile -File .\scripts\Invoke-HmdBumpVersion.ps1 -CheckOnly -AgentSummary
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $false)]
    [string]$Version,

    [Parameter(Mandatory = $false)]
    [string]$ReleaseNotes,

    [Parameter(Mandatory = $false)]
    [string]$StatusSuffix,

    [switch]$CheckOnly,

    [switch]$AgentSummary
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$psd1Path = Join-Path $repoRoot 'src\Hash.MassDownloader\Hash.MassDownloader.psd1'
$defaultsPath = Join-Path $repoRoot 'config\hmd.defaults.json'
$downloadPath = Join-Path $repoRoot 'src\Hash.MassDownloader\Private\Hmd.Download.ps1'
$briefPath = Join-Path $repoRoot 'docs\product-brief.md'

$uaPattern = 'Hash\.MassDownloader/\d+\.\d+\.\d+'
$semverPattern = '^\d+\.\d+\.\d+$'

function Get-HmdVersionSnapshot {
    $manifest = Import-PowerShellDataFile -Path $psd1Path
    $moduleVersion = [string]$manifest.ModuleVersion
    $defaults = Get-Content -LiteralPath $defaultsPath -Raw | ConvertFrom-Json
    $userAgent = [string]$defaults.UserAgent
    $downloadRaw = Get-Content -LiteralPath $downloadPath -Raw
    $downloadUa = $null
    if ($downloadRaw -match "UserAgent = '($uaPattern)'") {
        $downloadUa = $Matches[1]
    }
    $briefRaw = Get-Content -LiteralPath $briefPath -Raw
    $briefVersion = $null
    if ($briefRaw -match '\*\*Status:\*\* v(\d+\.\d+\.\d+)') {
        $briefVersion = $Matches[1]
    }
    [pscustomobject]@{
        ModuleVersion = $moduleVersion
        UserAgent     = $userAgent
        DownloadUa    = $downloadUa
        BriefVersion  = $briefVersion
        ExpectedUa    = "Hash.MassDownloader/$moduleVersion"
    }
}

function Write-HmdBumpSummary {
    param([string]$Line)
    if ($AgentSummary) {
        Write-Output $Line
    }
}

$snap = Get-HmdVersionSnapshot

if ($CheckOnly) {
    $ok = (
        $snap.UserAgent -eq $snap.ExpectedUa -and
        $snap.DownloadUa -eq $snap.ExpectedUa -and
        $snap.BriefVersion -eq $snap.ModuleVersion
    )
    if ($ok) {
        Write-HmdBumpSummary ("HMD-BUMP-CHECK-OK version={0}" -f $snap.ModuleVersion)
        if (-not $AgentSummary) {
            Write-Host ("Version sync OK: {0}" -f $snap.ModuleVersion)
        }
        exit 0
    }
    Write-HmdBumpSummary (
        'HMD-BUMP-CHECK-FAIL module={0} userAgent={1} downloadUa={2} brief={3}' -f
        $snap.ModuleVersion, $snap.UserAgent, $snap.DownloadUa, $snap.BriefVersion
    )
    if (-not $AgentSummary) {
        Write-Host (
            "Version mismatch: ModuleVersion={0}; UserAgent={1}; Download default={2}; brief Status={3}" -f
            $snap.ModuleVersion, $snap.UserAgent, $snap.DownloadUa, $snap.BriefVersion
        )
    }
    exit 1
}

if (-not $Version) {
    Write-HmdBumpSummary 'HMD-BUMP-FAIL reason=missing-Version'
    throw 'Specify -Version X.Y.Z (or use -CheckOnly).'
}
if ($Version -notmatch $semverPattern) {
    Write-HmdBumpSummary 'HMD-BUMP-FAIL reason=bad-Version'
    throw "Version must be SemVer X.Y.Z (got: $Version)."
}

$targetUa = "Hash.MassDownloader/$Version"
$changed = [System.Collections.Generic.List[string]]::new()

if (-not $PSCmdlet.ShouldProcess($repoRoot, "Bump version to $Version")) {
    Write-HmdBumpSummary ("HMD-BUMP-OK version={0} whatIf=1" -f $Version)
    exit 0
}

# Manifest ModuleVersion + optional ReleaseNotes
$psd1 = Get-Content -LiteralPath $psd1Path -Raw
$psd1New = [regex]::Replace(
    $psd1,
    "ModuleVersion\s*=\s*'[^']+'",
    "ModuleVersion     = '$Version'"
)
if ($ReleaseNotes) {
    $escaped = $ReleaseNotes.Replace("'", "''")
    if ($psd1New -match "ReleaseNotes\s*=") {
        $psd1New = [regex]::Replace(
            $psd1New,
            "ReleaseNotes\s*=\s*'[^']*'",
            "ReleaseNotes = '$escaped'"
        )
    }
}
if ($psd1New -ne $psd1) {
    Set-Content -LiteralPath $psd1Path -Value $psd1New -NoNewline -Encoding utf8
    $changed.Add('psd1')
}

# Defaults UserAgent
$defaultsObj = Get-Content -LiteralPath $defaultsPath -Raw | ConvertFrom-Json
if ([string]$defaultsObj.UserAgent -ne $targetUa) {
    $defaultsObj.UserAgent = $targetUa
    $json = $defaultsObj | ConvertTo-Json -Depth 5
    Set-Content -LiteralPath $defaultsPath -Value ($json + "`n") -NoNewline -Encoding utf8
    $changed.Add('defaults')
}

# Download fallback default
$downloadRaw = Get-Content -LiteralPath $downloadPath -Raw
$downloadNew = [regex]::Replace(
    $downloadRaw,
    "UserAgent = '$uaPattern'",
    "UserAgent = '$targetUa'"
)
if ($downloadNew -ne $downloadRaw) {
    Set-Content -LiteralPath $downloadPath -Value $downloadNew -NoNewline -Encoding utf8
    $changed.Add('download')
}

# Product brief Status version (and optional suffix)
$briefRaw = Get-Content -LiteralPath $briefPath -Raw
if ($PSBoundParameters.ContainsKey('StatusSuffix') -and $null -ne $StatusSuffix) {
    $statusLine = if ([string]::IsNullOrWhiteSpace($StatusSuffix)) {
        "**Status:** v$Version"
    }
    else {
        "**Status:** v$Version — $StatusSuffix"
    }
    $briefNew = [regex]::Replace(
        $briefRaw,
        '(?m)^\*\*Status:\*\*.*$',
        $statusLine
    )
}
else {
    $briefNew = [regex]::Replace(
        $briefRaw,
        '\*\*Status:\*\* v\d+\.\d+\.\d+',
        "**Status:** v$Version"
    )
}
if ($briefNew -ne $briefRaw) {
    Set-Content -LiteralPath $briefPath -Value $briefNew -NoNewline -Encoding utf8
    $changed.Add('brief')
}

# Scope in-scope heading version when present
$briefAfter = Get-Content -LiteralPath $briefPath -Raw
$briefScope = [regex]::Replace(
    $briefAfter,
    '(?m)^### In scope \(v\d+\.\d+\.\d+\)',
    "### In scope (v$Version)"
)
if ($briefScope -ne $briefAfter) {
    Set-Content -LiteralPath $briefPath -Value $briefScope -NoNewline -Encoding utf8
    if ($changed -notcontains 'brief') {
        $changed.Add('brief')
    }
}

Write-HmdBumpSummary (
    'HMD-BUMP-OK version={0} changed={1}' -f $Version, (($changed -join ',') )
)
if (-not $AgentSummary) {
    Write-Host ("Bumped to {0}; files: {1}" -f $Version, ($changed -join ', '))
}
exit 0
