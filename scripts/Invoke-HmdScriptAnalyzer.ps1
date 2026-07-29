#Requires -Version 7.2
<#
.SYNOPSIS
  Run PSScriptAnalyzer on Hash.MassDownloader scripts and module.

.DESCRIPTION
  **Safety tier: 1**

  Read-only static analysis on scripts/ (excluding _drafts) and src/.

.PARAMETER AgentSummary
  One success-stream line: HMD-LINT-OK | HMD-LINT-FAIL | HMD-LINT-MISS
#>
[CmdletBinding()]
param(
    [switch]$AgentSummary
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$settings = Join-Path $repoRoot 'PSScriptAnalyzerSettings.psd1'

if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
    if ($AgentSummary) {
        Write-Output 'HMD-LINT-MISS exit=2'
        exit 2
    }
    throw 'PSScriptAnalyzer is not installed.'
}

Import-Module PSScriptAnalyzer -ErrorAction Stop

$targets = @(
    (Join-Path $repoRoot 'scripts')
    (Join-Path $repoRoot 'src')
)

$findings = @()
foreach ($t in $targets) {
    if (-not (Test-Path -LiteralPath $t)) { continue }
    $items = Get-ChildItem -LiteralPath $t -Recurse -Include '*.ps1', '*.psm1', '*.psd1' |
        Where-Object { $_.FullName -notmatch '[\\/]_drafts[\\/]' }
    foreach ($item in $items) {
        $findings += @(Invoke-ScriptAnalyzer -Path $item.FullName -Settings $settings)
    }
}

$errorCount = @($findings | Where-Object Severity -eq 'Error').Count
$total = $findings.Count

if ($errorCount -gt 0) {
    $findings | Format-Table -AutoSize | Out-String | Write-Host
    if ($AgentSummary) {
        Write-Output ("HMD-LINT-FAIL exit=1 findings={0} errors={1}" -f $total, $errorCount)
    }
    exit 1
}

if ($AgentSummary) {
    Write-Output ("HMD-LINT-OK findings={0}" -f $total)
}
exit 0
