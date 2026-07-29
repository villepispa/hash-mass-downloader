#Requires -Version 7.2
<#
.SYNOPSIS
  Runs Hash.MassDownloader Pester suites under tests/unit.

.DESCRIPTION
  **Safety tier: 1**

  Unit tests with mocked VirusTotal/download invokers (no live network required).

.PARAMETER AgentSummary
  One line: HMD-PESTER-OK passed=N | HMD-PESTER-FAIL exit=N
#>
[CmdletBinding()]
param(
    [string[]]$TestPath = @((Join-Path $PSScriptRoot 'unit')),

    [switch]$AgentSummary
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$pester = Get-Module Pester -ListAvailable |
    Sort-Object Version -Descending |
    Select-Object -First 1
if (-not $pester) {
    if ($AgentSummary) {
        Write-Output 'HMD-PESTER-FAIL exit=2 detail=Pester-not-installed'
        exit 2
    }
    throw 'Pester is not installed. Install-Module Pester -MinimumVersion 5.5.0 -Scope CurrentUser'
}

Import-Module Pester -MinimumVersion 5.5.0 -Force

$config = New-PesterConfiguration
$config.Run.Path = $TestPath
$config.Run.Exit = -not $AgentSummary
$config.Output.Verbosity = 'Detailed'
if ($AgentSummary) {
    $config.Run.PassThru = $true
}

$result = Invoke-Pester -Configuration $config

if ($AgentSummary) {
    if ($result.FailedCount -gt 0 -or $result.Result -ne 'Passed') {
        Write-Output ("HMD-PESTER-FAIL exit=1 failed={0} total={1}" -f $result.FailedCount, $result.TotalCount)
        exit 1
    }
    Write-Output ("HMD-PESTER-OK passed={0}" -f $result.PassedCount)
    exit 0
}
