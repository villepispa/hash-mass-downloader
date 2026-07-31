#Requires -Version 7.2
<#
.SYNOPSIS
  Store VirusTotal API key in Windows Credential Manager for HMD.

.DESCRIPTION
  **Safety tier: 2**

  Writes a generic credential (default target Hash.MassDownloader/VirusTotal)
  for the current user. Scheduled Task must run as this same user so
  Resolve-HmdApiKey can read it without VIRUSTOTAL_API_KEY on disk.

.PARAMETER ApiKey
  SecureString API key. If omitted, prompts securely.

.PARAMETER Target
  CredMan target name (default from config / Hash.MassDownloader/VirusTotal).

.PARAMETER LocalMachinePersist
  Use CRED_PERSIST_LOCAL_MACHINE instead of ENTERPRISE.

.PARAMETER AgentSummary
  One success-stream line: HMD-CREDMAN-OK|FAIL …

.EXAMPLE
  pwsh -NoProfile -File .\scripts\Register-HmdApiKeyCredential.ps1
#>
[CmdletBinding()]
param(
    [SecureString]$ApiKey,

    [string]$Target,

    [switch]$LocalMachinePersist,

    [switch]$AgentSummary
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Import-Module (Join-Path $repoRoot 'src\Hash.MassDownloader\Hash.MassDownloader.psd1') -Force

try {
    if ($null -eq $ApiKey) {
        $ApiKey = Read-Host -Prompt 'VirusTotal API key' -AsSecureString
    }
    $setParams = @{ ApiKey = $ApiKey }
    if (-not [string]::IsNullOrWhiteSpace($Target)) {
        $setParams['Target'] = $Target
    }
    if ($LocalMachinePersist) {
        $setParams['LocalMachinePersist'] = $true
    }
    Set-HmdApiKeyCredential @setParams
    $resolvedTarget = if ($Target) { $Target } else { Get-HmdDefaultApiKeyCredentialTarget }
    if ($AgentSummary) {
        Write-Output ("HMD-CREDMAN-OK target={0}" -f $resolvedTarget)
        exit 0
    }
    Write-Host "Stored credential target: $resolvedTarget"
    exit 0
}
catch {
    if ($AgentSummary) {
        $msg = ($_.Exception.Message -replace '\s+', ' ').Trim()
        if ($msg.Length -gt 120) { $msg = $msg.Substring(0, 120) }
        Write-Output ("HMD-CREDMAN-FAIL exit=1 detail={0}" -f $msg)
        exit 1
    }
    throw
}
