#Requires -Version 7.2
<#
.SYNOPSIS
  Process one Hash.MassDownloader inbox job (serial queue worker).

.DESCRIPTION
  **Safety tier: 2**

  Controlled network write via Invoke-HmdBulkDownload. Claims one file from
  InboxRoot/incoming under a named mutex, writes WorkRootBase/<stem>_<stamp>,
  then moves the job to done/ or failed/. Optional sidecar
  <stem>.deploy.txt|.csv beside the input is passed as -DeployMapPath.
  API key: -ApiKey, Credential Manager (default Hash.MassDownloader/VirusTotal),
  or VIRUSTOTAL_API_KEY.

.PARAMETER InboxRoot
  Inbox root containing incoming/processing/done/failed.

.PARAMETER WorkRootBase
  Parent directory for per-job WorkRoot folders.

.PARAMETER ApiKey
  Optional SecureString (else CredMan / env).

.PARAMETER SkipVirusTotal
  Download and hash only.

.PARAMETER SkipLocalAvScan
  Skip Defender hard-gate.

.PARAMETER NoFileNamePrefix
  Pass through to bulk download.

.PARAMETER UploadUnknownSamples
  Opt-in VT upload.

.PARAMETER AgentSummary
  One success-stream line: HMD-INBOX-OK|IDLE|FAIL …

.EXAMPLE
  pwsh -NoProfile -File .\scripts\Invoke-HmdInboxWorker.ps1 `
    -InboxRoot .\out\inbox -WorkRootBase .\out\jobs -SkipVirusTotal -AgentSummary
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$InboxRoot,

    [Parameter(Mandatory)]
    [string]$WorkRootBase,

    [SecureString]$ApiKey,

    [string]$MutexName,

    [int]$MutexTimeoutMs = -1,

    [switch]$SkipVirusTotal,

    [switch]$SkipLocalAvScan,

    [switch]$NoFileNamePrefix,

    [switch]$UploadUnknownSamples,

    [switch]$AgentSummary
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$moduleManifest = Join-Path $repoRoot 'src\Hash.MassDownloader\Hash.MassDownloader.psd1'
Import-Module $moduleManifest -Force

$params = @{
    InboxRoot        = $InboxRoot
    WorkRootBase     = $WorkRootBase
    SkipVirusTotal   = $SkipVirusTotal
    SkipLocalAvScan  = $SkipLocalAvScan
    NoFileNamePrefix = $NoFileNamePrefix
    AgentSummary     = $AgentSummary
}
if ($PSBoundParameters.ContainsKey('ApiKey')) {
    $params['ApiKey'] = $ApiKey
}
if (-not [string]::IsNullOrWhiteSpace($MutexName)) {
    $params['MutexName'] = $MutexName
}
if ($MutexTimeoutMs -ge 0) {
    $params['MutexTimeoutMs'] = $MutexTimeoutMs
}
if ($UploadUnknownSamples) {
    $params['UploadUnknownSamples'] = $true
}

try {
    $result = Invoke-HmdInboxWorker @params
    if ($AgentSummary) {
        if ($result.Status -eq 'Idle') {
            Write-Output 'HMD-INBOX-IDLE jobs=0'
            exit 0
        }
        $bulk = $result.Result
        Write-Output (
            'HMD-INBOX-OK status=Done work={0} input={1} queued={2} processed={3} clean={4} error={5}' -f `
                $result.WorkRoot,
                $(if ($bulk) { $bulk.InputCount } else { 0 }),
                $(if ($bulk) { $bulk.QueuedCount } else { 0 }),
                $(if ($bulk) { $bulk.ProcessedCount } else { 0 }),
                $(if ($bulk) { $bulk.CleanCount } else { 0 }),
                $(if ($bulk) { $bulk.ErrorCount } else { 0 })
        )
        exit 0
    }
    $result | ConvertTo-Json -Depth 5
    exit 0
}
catch {
    if ($AgentSummary) {
        $msg = ($_.Exception.Message -replace '\s+', ' ').Trim()
        if ($msg.Length -gt 160) {
            $msg = $msg.Substring(0, 160)
        }
        Write-Output ("HMD-INBOX-FAIL exit=1 detail={0}" -f $msg)
        exit 1
    }
    throw
}
