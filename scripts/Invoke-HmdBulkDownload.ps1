#Requires -Version 7.2
<#
.SYNOPSIS
  Entry point for Hash.MassDownloader bulk download + VirusTotal triage.

.DESCRIPTION
  **Safety tier: 2**

  Controlled network write: downloads URLs and optionally calls VirusTotal.
  API key from VIRUSTOTAL_API_KEY or -ApiKey. Sample upload is opt-in.
  Post-run host summary/log display follows config/hmd.defaults.json
  (`DisplaySummary`, `DisplayScanLog`, `DisplayArchiveScanLog`) unless
  -AgentSummary is set.
  Optional Clean deploy via -DeployMapPath (TXT sectioned map or CSV).
  Deploy-map http(s) File entries are harvested into the download queue
  (InputPath optional when the map has ≥1 URL). Local Defender scan is on
  by default; use -SkipLocalAvScan to disable.

.PARAMETER InputPath
  TXT or CSV URL list. Optional when -DeployMapPath includes http(s) entries.

.PARAMETER WorkRoot
  Output root (folders created under this path).

.PARAMETER ApiKey
  Optional SecureString API key (else VIRUSTOTAL_API_KEY).

.PARAMETER UploadUnknownSamples
  Upload unknown hashes to VirusTotal (default off).

.PARAMETER SkipVirusTotal
  Download and hash only (no VT API calls).

.PARAMETER SkipLocalAvScan
  Skip Microsoft Defender hard-gate scan (default on via LocalAvScanEnabled).

.PARAMETER NoFileNamePrefix
  Store files as sanitized URL leaf (no NNNN_ prefix). Collisions get _Index.

.PARAMETER DeployMapPath
  Optional TXT/CSV map of Clean files → destination folders (create if missing).
  File entries may be names, wildcards, or http(s) URLs (harvested + matched).

.PARAMETER AgentSummary
  One success-stream line for agents:
  HMD-RUN-OK input=N queued=N processed=N skipped=N clean=N … deploy=N priorScanlog=0|1
  Disables DisplaySummary/DisplayScanLog/DisplayArchiveScanLog unless
  overridden via module ConfigOverride.
  Suppresses full JSON on the success stream.

.EXAMPLE
  pwsh -NoProfile -File .\scripts\Invoke-HmdBulkDownload.ps1 `
    -InputPath .\examples\urls.sample.txt -WorkRoot .\out\run1 -SkipVirusTotal

.EXAMPLE
  pwsh -NoProfile -File .\scripts\Invoke-HmdBulkDownload.ps1 `
    -DeployMapPath .\examples\deploy.sample.txt -WorkRoot .\out\run1 `
    -SkipVirusTotal -SkipLocalAvScan

.EXAMPLE
  pwsh -NoProfile -File .\scripts\Invoke-HmdBulkDownload.ps1 `
    -InputPath .\examples\urls.sample.txt -WorkRoot .\out\run1 `
    -NoFileNamePrefix -DeployMapPath .\examples\deploy.sample.txt

.EXAMPLE
  pwsh -NoProfile -File .\scripts\Invoke-HmdBulkDownload.ps1 `
    -InputPath .\examples\urls.sample.txt -WorkRoot .\out\run1 -AgentSummary
#>
[CmdletBinding()]
param(
    [string]$InputPath,

    [Parameter(Mandatory)]
    [string]$WorkRoot,

    [SecureString]$ApiKey,

    [switch]$UploadUnknownSamples,

    [switch]$SkipVirusTotal,

    [switch]$SkipLocalAvScan,

    [switch]$NoFileNamePrefix,

    [string]$DeployMapPath,

    [switch]$AgentSummary
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$moduleManifest = Join-Path $repoRoot 'src\Hash.MassDownloader\Hash.MassDownloader.psd1'
Import-Module $moduleManifest -Force

$params = @{
    WorkRoot         = $WorkRoot
    SkipVirusTotal   = $SkipVirusTotal
    SkipLocalAvScan  = $SkipLocalAvScan
    AgentSummary     = $AgentSummary
    NoFileNamePrefix = $NoFileNamePrefix
}
if (-not [string]::IsNullOrWhiteSpace($InputPath)) {
    $params['InputPath'] = $InputPath
}
if ($PSBoundParameters.ContainsKey('ApiKey')) {
    $params['ApiKey'] = $ApiKey
}
if ($UploadUnknownSamples) {
    $params['UploadUnknownSamples'] = $true
}
if (-not [string]::IsNullOrWhiteSpace($DeployMapPath)) {
    $params['DeployMapPath'] = $DeployMapPath
}

try {
    $result = Invoke-HmdBulkDownload @params
    if ($AgentSummary) {
        Write-Output (
            'HMD-RUN-OK input={0} queued={1} processed={2} skipped={3} clean={4} suspicious={5} malicious={6} unknown={7} error={8} deploy={9} priorScanlog={10}' -f `
                $result.InputCount,
                $result.QueuedCount,
                $result.ProcessedCount,
                $result.SkippedByCheckpoint,
                $result.CleanCount,
                $result.SuspiciousCount,
                $result.MaliciousCount,
                $result.UnknownCount,
                $result.ErrorCount,
                $result.DeployedCount,
                $(if ($result.RecordsArePriorScanlog) { '1' } else { '0' })
        )
        exit 0
    }
    $result | ConvertTo-Json -Depth 4
    exit 0
}
catch {
    if ($AgentSummary) {
        $msg = ($_.Exception.Message -replace '\s+', ' ').Trim()
        if ($msg.Length -gt 160) {
            $msg = $msg.Substring(0, 160)
        }
        Write-Output ("HMD-RUN-FAIL exit=1 detail={0}" -f $msg)
        exit 1
    }
    throw
}
