#Requires -Version 7.2

function Invoke-HmdInboxWorker {
    <#
    .SYNOPSIS
        Process at most one inbox job under a single-instance mutex (HMD-028/035).
    .DESCRIPTION
        Claims the oldest incoming URL list, runs Invoke-HmdBulkDownload, then
        moves the job to done/ or failed/. API key via Resolve-HmdApiKey (HMD-034).
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

        [hashtable]$ConfigOverride = @{},

        [switch]$AgentSummary,

        [scriptblock]$BulkDownloadInvoker
    )

    $cfg = Get-HmdConfig -Override $ConfigOverride
    if ([string]::IsNullOrWhiteSpace($MutexName)) {
        if ($cfg.PSObject.Properties.Name -contains 'InboxMutexName' -and
            -not [string]::IsNullOrWhiteSpace([string]$cfg.InboxMutexName)) {
            $MutexName = [string]$cfg.InboxMutexName
        }
        else {
            $MutexName = 'Local\Hash.MassDownloader.Inbox'
        }
    }
    if ($MutexTimeoutMs -lt 0) {
        if ($cfg.PSObject.Properties.Name -contains 'InboxMutexTimeoutMs') {
            $MutexTimeoutMs = [int]$cfg.InboxMutexTimeoutMs
        }
        else {
            $MutexTimeoutMs = 0
        }
    }

    $null = Initialize-HmdInbox -InboxRoot $InboxRoot
    if (-not (Test-Path -LiteralPath $WorkRootBase)) {
        New-Item -ItemType Directory -Path $WorkRootBase -Force | Out-Null
    }

    $mutex = Enter-HmdInboxMutex -Name $MutexName -TimeoutMs $MutexTimeoutMs
    try {
        $job = Get-HmdInboxNextJob -InboxRoot $InboxRoot
        if ($null -eq $job) {
            return [pscustomobject]@{
                Status        = 'Idle'
                InputPath     = $null
                DeployMapPath = $null
                WorkRoot      = $null
                Result        = $null
            }
        }

        $stamp = Get-Date -UFormat '%Y%m%d-%H%M%S'
        $stem = [IO.Path]::GetFileNameWithoutExtension($job.SourceName)
        $safeStem = ($stem -replace '[^\w\.\-]+', '_').Trim('._')
        if ([string]::IsNullOrWhiteSpace($safeStem)) {
            $safeStem = 'job'
        }
        $workRoot = Join-Path $WorkRootBase ('{0}_{1}' -f $safeStem, $stamp)

        $bulkParams = @{
            InputPath        = $job.InputPath
            WorkRoot         = $workRoot
            SkipVirusTotal   = $SkipVirusTotal
            SkipLocalAvScan  = $SkipLocalAvScan
            NoFileNamePrefix = $NoFileNamePrefix
            AgentSummary     = $AgentSummary
            ConfigOverride   = $ConfigOverride
        }
        if ($PSBoundParameters.ContainsKey('ApiKey')) {
            $bulkParams['ApiKey'] = $ApiKey
        }
        if ($UploadUnknownSamples) {
            $bulkParams['UploadUnknownSamples'] = $true
        }
        if (-not [string]::IsNullOrWhiteSpace($job.DeployMapPath)) {
            $bulkParams['DeployMapPath'] = $job.DeployMapPath
        }

        try {
            if ($BulkDownloadInvoker) {
                $result = & $BulkDownloadInvoker $bulkParams
            }
            else {
                $result = Invoke-HmdBulkDownload @bulkParams
            }
            $null = Move-HmdInboxJob -InboxRoot $InboxRoot -InputPath $job.InputPath `
                -DeployMapPath $job.DeployMapPath -Disposition Done
            return [pscustomobject]@{
                Status        = 'Done'
                InputPath     = $job.InputPath
                DeployMapPath = $job.DeployMapPath
                WorkRoot      = $workRoot
                Result        = $result
            }
        }
        catch {
            $msg = $_.Exception.Message
            $null = Move-HmdInboxJob -InboxRoot $InboxRoot -InputPath $job.InputPath `
                -DeployMapPath $job.DeployMapPath -Disposition Failed -ErrorMessage $msg
            throw
        }
    }
    finally {
        Exit-HmdInboxMutex -Mutex $mutex
    }
}
