#Requires -Version 7.2
<#
.SYNOPSIS
  Repo-root validate gate: Pester then PSScriptAnalyzer.

.DESCRIPTION
  **Safety tier: 1**

  Ordered stages: Gallery dep check → Pester → ScriptAnalyzer.
  Prefer this entry for agents and CI discovery.

.PARAMETER SkipLint
  Skip PSScriptAnalyzer.

.PARAMETER AgentSummary
  One success-stream line: HMD-VALIDATE-OK | HMD-VALIDATE-FAIL stage=…

.EXAMPLE
  pwsh -NoProfile -File .\scripts\Invoke-HmdValidate.ps1 -AgentSummary
#>
[CmdletBinding()]
param(
    [switch]$SkipLint,
    [switch]$AgentSummary
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$pesterScript = Join-Path $repoRoot 'tests\Invoke-HmdPester.ps1'
$lintScript = Join-Path $PSScriptRoot 'Invoke-HmdScriptAnalyzer.ps1'

$missing = @()
$pester = Get-Module -ListAvailable -Name Pester |
    Sort-Object Version -Descending |
    Select-Object -First 1
if (-not $pester -or $pester.Version -lt [version]'5.5.0') {
    $missing += 'Pester>=5.5'
}
if (-not $SkipLint -and -not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
    $missing += 'PSScriptAnalyzer'
}
if ($missing.Count -gt 0) {
    if ($AgentSummary) {
        Write-Output ('HMD-VALIDATE-FAIL stage=deps exit=2 missing={0}' -f ($missing -join ','))
    }
    exit 2
}

& $pesterScript -AgentSummary
if ($LASTEXITCODE -ne 0) {
    if ($AgentSummary) {
        Write-Output ("HMD-VALIDATE-FAIL stage=pester exit={0}" -f $LASTEXITCODE)
    }
    exit $LASTEXITCODE
}

if (-not $SkipLint) {
    & $lintScript -AgentSummary
    if ($LASTEXITCODE -ne 0) {
        if ($AgentSummary) {
            Write-Output ("HMD-VALIDATE-FAIL stage=lint exit={0}" -f $LASTEXITCODE)
        }
        exit $LASTEXITCODE
    }
}

if ($AgentSummary) {
    Write-Output 'HMD-VALIDATE-OK'
}
exit 0
