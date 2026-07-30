#Requires -Version 7.2

function Invoke-HmdBulkDownload {
    <#
    .SYNOPSIS
        Bulk-download URLs, check VirusTotal by SHA256, disposition and report.
    .DESCRIPTION
        Orchestrates parallel download and serialized VT lookups with cache,
        checkpoint resume, quarantine policy, and HTML/CSV artefacts.
        Optional Clean deploy; deploy-map http(s) URLs are harvested into the
        download queue (HMD-027). Local Defender scan hard-gates threats (HMD-026).
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

        [scriptblock]$VtInvoker,

        [scriptblock]$DownloadInvoker,

        [scriptblock]$LocalAvInvoker,

        [hashtable]$ConfigOverride = @{},

        [switch]$AgentSummary,

        [switch]$NoFileNamePrefix,

        [string]$DeployMapPath
    )

    $cfg = Get-HmdConfig -Override $ConfigOverride
    if ($PSBoundParameters.ContainsKey('UploadUnknownSamples')) {
        $cfg.UploadUnknownSamples = [bool]$UploadUnknownSamples
    }
    if ($NoFileNamePrefix) {
        $cfg.PrefixFileNames = $false
    }
    if ($SkipLocalAvScan) {
        $cfg.LocalAvScanEnabled = $false
    }
    # Agent-friendly one-liner: keep host noise off unless explicitly overridden.
    if ($AgentSummary) {
        if (-not $ConfigOverride.ContainsKey('DisplaySummary')) {
            $cfg.DisplaySummary = $false
        }
        if (-not $ConfigOverride.ContainsKey('DisplayScanLog')) {
            $cfg.DisplayScanLog = $false
        }
    }

    $work = Initialize-HmdWorkRoot -WorkRoot $WorkRoot
    $cachePath = Join-Path $work 'logs\hashcache.csv'
    $scanPath = Join-Path $work 'logs\scanlog.csv'
    $ckptPath = Join-Path $work 'checkpoint.json'
    $reportPath = Join-Path $work 'reports\report.html'

    $cache = Import-HmdHashCache -Path $cachePath
    $completed = Import-HmdCheckpoint -Path $ckptPath

    $mapRows = @()
    $harvested = [string[]]@()
    if (-not [string]::IsNullOrWhiteSpace($DeployMapPath)) {
        $mapRows = @(Import-HmdDeployMap -Path $DeployMapPath)
        $harvested = @(Get-HmdUrlsFromDeployMap -MapRows $mapRows)
    }

    $urlList = [System.Collections.Generic.List[string]]::new()
    $seenUrls = @{}
    if (-not [string]::IsNullOrWhiteSpace($InputPath)) {
        foreach ($u in [string[]]@(Import-HmdUrlList -Path $InputPath)) {
            if ($seenUrls.ContainsKey($u)) { continue }
            $seenUrls[$u] = $true
            $urlList.Add($u)
        }
    }
    foreach ($u in $harvested) {
        if ($seenUrls.ContainsKey($u)) { continue }
        $seenUrls[$u] = $true
        $urlList.Add($u)
    }
    $allUrls = [string[]]$urlList.ToArray()
    if ($allUrls.Count -eq 0) {
        throw 'No URLs to process: provide -InputPath and/or -DeployMapPath with http(s) File entries.'
    }

    $queuedList = [System.Collections.Generic.List[string]]::new()
    foreach ($u in $allUrls) {
        if (-not $completed.Contains([string]$u)) {
            $queuedList.Add([string]$u)
        }
    }
    $queued = [string[]]$queuedList.ToArray()

    $apiKeyPlain = $null
    if (-not $SkipVirusTotal) {
        $apiKeyPlain = Resolve-HmdApiKey -ApiKey $ApiKey
    }

    $localAvEnabled = $true
    if ($null -ne $cfg.PSObject.Properties['LocalAvScanEnabled']) {
        $localAvEnabled = [bool]$cfg.LocalAvScanEnabled
    }
    $localAvProvider = 'Defender'
    if ($null -ne $cfg.PSObject.Properties['LocalAvProvider'] -and
        -not [string]::IsNullOrWhiteSpace([string]$cfg.LocalAvProvider)) {
        $localAvProvider = [string]$cfg.LocalAvProvider
    }

    $downloadResults = [object[]]@()
    if ($queued.Count -gt 0) {
        $downloadResults = @(Start-HmdDownloadPool -Urls $queued -WorkRoot $work `
                -ThrottleLimit ([int]$cfg.DownloadThreads) `
                -MaxFileBytes ([long]$cfg.MaxFileBytes) `
                -MaxRetries ([int]$cfg.MaxDownloadRetries) `
                -UserAgent ([string]$cfg.UserAgent) `
                -PrefixFileNames ([bool]$cfg.PrefixFileNames) `
                -DownloadInvoker $DownloadInvoker)
        # Defensive: unwrap accidental one-level nest from older call patterns.
        $downloadResults = @(ConvertTo-HmdFlatArray -InputObject $downloadResults)
    }

    $scanRecords = [System.Collections.Generic.List[object]]::new()
    if (Test-Path -LiteralPath $scanPath) {
        foreach ($row in @(Import-Csv -LiteralPath $scanPath)) {
            $scanRecords.Add([pscustomobject]@{
                    Url             = $row.Url
                    FileName        = $row.FileName
                    LocalPath       = $row.LocalPath
                    Sha256          = $row.Sha256
                    Verdict         = $row.Verdict
                    Malicious       = [int]$(if ($null -ne $row.PSObject.Properties['Malicious']) { $row.Malicious } else { 0 })
                    Suspicious      = [int]$(if ($null -ne $row.PSObject.Properties['Suspicious']) { $row.Suspicious } else { 0 })
                    Undetected      = [int]$(if ($null -ne $row.PSObject.Properties['Undetected']) { $row.Undetected } else { 0 })
                    Harmless        = [int]$(if ($null -ne $row.PSObject.Properties['Harmless'] -and
                            -not [string]::IsNullOrWhiteSpace([string]$row.Harmless)) { $row.Harmless } else { 0 })
                    IgnoredEngines  = $(if ($null -ne $row.PSObject.Properties['IgnoredEngines']) {
                            [string]$row.IgnoredEngines
                        }
                        else { '' })
                    SignatureStatus = $row.SignatureStatus
                    Signer          = $row.Signer
                    DefenderStatus  = $(if ($null -ne $row.PSObject.Properties['DefenderStatus']) {
                            [string]$row.DefenderStatus
                        }
                        else { '' })
                    DefenderThreat  = $(if ($null -ne $row.PSObject.Properties['DefenderThreat']) {
                            [string]$row.DefenderThreat
                        }
                        else { '' })
                    ContentType     = $row.ContentType
                    Bytes           = $row.Bytes
                    CacheHit        = $row.CacheHit
                    Error           = $row.Error
                    ProcessedAt     = $row.ProcessedAt
                }) | Out-Null
        }
    }

    foreach ($dl in $downloadResults) {
        $record = [ordered]@{
            Url              = $dl.Url
            FileName         = $dl.FileName
            LocalPath        = ''
            Sha256           = ''
            Verdict          = 'Error'
            Malicious        = 0
            Suspicious       = 0
            Undetected       = 0
            Harmless         = 0
            IgnoredEngines   = ''
            SignatureStatus  = ''
            Signer           = ''
            DefenderStatus   = ''
            DefenderThreat   = ''
            ContentType      = $dl.ContentType
            Bytes            = $dl.Bytes
            CacheHit         = $false
            Error            = $dl.Error
            ProcessedAt      = (Get-Date).ToString('o')
        }

        try {
            if (-not $dl.Success -or [string]::IsNullOrWhiteSpace($dl.LocalPath)) {
                $record.Verdict = 'Error'
                $scanRecords.Add([pscustomobject]$record) | Out-Null
                $null = $completed.Add($dl.Url)
                Save-HmdCheckpoint -CompletedUrls $completed -Path $ckptPath
                continue
            }

            $sha = Get-HmdFileSha256 -Path $dl.LocalPath
            $record.Sha256 = $sha
            $sig = Get-HmdAuthenticodeInfo -Path $dl.LocalPath
            $record.SignatureStatus = $sig.Status
            $record.Signer = $sig.Signer

            $verdict = 'Unknown'
            $mal = 0; $sus = 0; $und = 0; $harm = 0
            $ignoredEngines = ''
            $fromCache = $false
            $skipVt = $false
            $ignoreList = @(Get-HmdIgnoreEngineList -IgnoreEngines $(
                    if ($null -ne $cfg.PSObject.Properties['IgnoreEngines']) { $cfg.IgnoreEngines } else { @() }
                ))

            # HMD-026: local AV hard gate before VT.
            if ($localAvEnabled) {
                $av = Invoke-HmdLocalAvScan -Path $dl.LocalPath -Provider $localAvProvider `
                    -Invoker $LocalAvInvoker
                $record.DefenderStatus = [string]$av.Status
                $record.DefenderThreat = [string]$av.ThreatName
                if ($av.Status -eq 'Threat') {
                    $verdict = 'Malicious'
                    $skipVt = $true
                    $record.Error = $(if (-not [string]::IsNullOrWhiteSpace([string]$av.ThreatName)) {
                            "LocalAv threat: $($av.ThreatName)"
                        }
                        else { 'LocalAv threat detected' })
                }
                elseif ($av.Status -eq 'Unavailable' -or $av.Status -eq 'Error') {
                    $verdict = 'Error'
                    $skipVt = $true
                    $detail = [string]$av.Raw
                    if ([string]::IsNullOrWhiteSpace($detail)) {
                        $detail = [string]$av.Status
                    }
                    $record.Error = "LocalAv $($av.Status): $detail"
                }
            }
            else {
                $record.DefenderStatus = 'Skipped'
            }

            if (-not $skipVt) {
                if ($cache.ContainsKey($sha) -and
                    (Test-HmdCacheEntryFresh -CachedAt $cache[$sha].CachedAt -TtlDays ([int]$cfg.CacheTtlDays))) {
                    $fromCache = $true
                    $c = $cache[$sha]
                    $verdict = $c.Verdict
                    $mal = [int]$c.Malicious
                    $sus = [int]$c.Suspicious
                    $und = [int]$c.Undetected
                    $harm = $(if ($null -ne $c.PSObject.Properties['Harmless']) { [int]$c.Harmless } else { 0 })
                    $ignoredEngines = $(if ($null -ne $c.PSObject.Properties['IgnoredEngines']) {
                            [string]$c.IgnoredEngines
                        }
                        else { '' })
                }
                elseif (-not $SkipVirusTotal) {
                    $report = Get-HmdHashReport -Sha256 $sha -ApiKey $apiKeyPlain `
                        -Invoker $VtInvoker -ApiDelaySeconds ([int]$cfg.ApiDelaySeconds)

                    if ($report.Found) {
                        $mal = [int]$report.Malicious
                        $sus = [int]$report.Suspicious
                        $und = [int]$report.Undetected
                        $harm = [int]$report.Harmless
                        $policy = Get-HmdPolicyStatsFromResults -AnalysisResults $report.Results `
                            -IgnoreEngines $ignoreList `
                            -RawMalicious $mal -RawSuspicious $sus -RawUndetected $und -RawHarmless $harm
                        $verdict = Get-HmdVerdictFromStats -Malicious $policy.Malicious -Suspicious $policy.Suspicious `
                            -Undetected $policy.Undetected -MaliciousThreshold ([int]$cfg.MaliciousThreshold) `
                            -SuspiciousThreshold ([int]$cfg.SuspiciousThreshold) -Known
                        if ($policy.IgnoredEngines.Count -gt 0) {
                            $ignoredEngines = ($policy.IgnoredEngines -join ';')
                        }
                    }
                    elseif ([bool]$cfg.UploadUnknownSamples) {
                        $upload = Submit-HmdFile -Path $dl.LocalPath -ApiKey $apiKeyPlain `
                            -Invoker $VtInvoker -ApiDelaySeconds ([int]$cfg.ApiDelaySeconds)
                        $analysisId = [string]$upload.data.id
                        $analysis = Get-HmdAnalysis -AnalysisId $analysisId -ApiKey $apiKeyPlain `
                            -Invoker $VtInvoker `
                            -PollSeconds ([int]$cfg.AnalysisPollSeconds) `
                            -MaxAttempts ([int]$cfg.AnalysisPollMaxAttempts) `
                            -ApiDelaySeconds ([int]$cfg.ApiDelaySeconds)
                        $mal = [int]$analysis.Malicious
                        $sus = [int]$analysis.Suspicious
                        $und = [int]$analysis.Undetected
                        $harm = [int]$analysis.Harmless
                        $policy = Get-HmdPolicyStatsFromResults -AnalysisResults $analysis.Results `
                            -IgnoreEngines $ignoreList `
                            -RawMalicious $mal -RawSuspicious $sus -RawUndetected $und -RawHarmless $harm
                        $verdict = Get-HmdVerdictFromStats -Malicious $policy.Malicious -Suspicious $policy.Suspicious `
                            -Undetected $policy.Undetected -MaliciousThreshold ([int]$cfg.MaliciousThreshold) `
                            -SuspiciousThreshold ([int]$cfg.SuspiciousThreshold) -Known
                        if ($policy.IgnoredEngines.Count -gt 0) {
                            $ignoredEngines = ($policy.IgnoredEngines -join ';')
                        }
                    }
                    else {
                        $verdict = 'Unknown'
                    }

                    $cache[$sha] = [pscustomobject]@{
                        Sha256         = $sha
                        Verdict        = $verdict
                        Malicious      = $mal
                        Suspicious     = $sus
                        Undetected     = $und
                        Harmless       = $harm
                        IgnoredEngines = $ignoredEngines
                        CachedAt       = Get-Date
                        Source         = 'VirusTotal'
                    }
                    Export-HmdHashCache -Cache $cache -Path $cachePath
                }
                else {
                    $verdict = 'Unknown'
                }
            }

            $record.CacheHit = $fromCache
            $record.Verdict = $verdict
            $record.Malicious = $mal
            $record.Suspicious = $sus
            $record.Undetected = $und
            $record.Harmless = $harm
            $record.IgnoredEngines = $ignoredEngines

            $moved = Move-HmdByVerdict -SourcePath $dl.LocalPath -WorkRoot $work `
                -Verdict $verdict `
                -QuarantineMalicious ([bool]$cfg.QuarantineMalicious) `
                -QuarantineSuspicious ([bool]$cfg.QuarantineSuspicious)
            $record.LocalPath = $moved.FinalPath
            if (-not $skipVt) {
                $record.Error = ''
            }
        }
        catch {
            $record.Verdict = 'Error'
            $record.Error = $_.Exception.Message
            if ($dl.LocalPath -and (Test-Path -LiteralPath $dl.LocalPath)) {
                $moved = Move-HmdByVerdict -SourcePath $dl.LocalPath -WorkRoot $work -Verdict Error `
                    -QuarantineMalicious $false -QuarantineSuspicious $false
                $record.LocalPath = $moved.FinalPath
            }
        }

        $scanRecords.Add([pscustomobject]$record) | Out-Null
        $null = $completed.Add([string]$dl.Url)
        Save-HmdCheckpoint -CompletedUrls $completed -Path $ckptPath
    }

    # Rewrite scan log cleanly (fixed columns so prior rows gain empty Defender fields)
    if ($scanRecords.Count -gt 0) {
        $scanRecords |
            ForEach-Object {
                [pscustomobject]@{
                    Url             = $_.Url
                    FileName        = $_.FileName
                    LocalPath       = $_.LocalPath
                    Sha256          = $_.Sha256
                    Verdict         = $_.Verdict
                    Malicious       = [int]$(if ($null -ne $_.PSObject.Properties['Malicious']) { $_.Malicious } else { 0 })
                    Suspicious      = [int]$(if ($null -ne $_.PSObject.Properties['Suspicious']) { $_.Suspicious } else { 0 })
                    Undetected      = [int]$(if ($null -ne $_.PSObject.Properties['Undetected']) { $_.Undetected } else { 0 })
                    Harmless        = [int]$(if ($null -ne $_.PSObject.Properties['Harmless'] -and
                            -not [string]::IsNullOrWhiteSpace([string]$_.Harmless)) { $_.Harmless } else { 0 })
                    IgnoredEngines  = $(if ($null -ne $_.PSObject.Properties['IgnoredEngines']) {
                            [string]$_.IgnoredEngines
                        }
                        else { '' })
                    SignatureStatus = $_.SignatureStatus
                    Signer          = $_.Signer
                    DefenderStatus  = $(if ($null -ne $_.PSObject.Properties['DefenderStatus']) {
                            [string]$_.DefenderStatus
                        }
                        else { '' })
                    DefenderThreat  = $(if ($null -ne $_.PSObject.Properties['DefenderThreat']) {
                            [string]$_.DefenderThreat
                        }
                        else { '' })
                    ContentType     = $_.ContentType
                    Bytes           = $_.Bytes
                    CacheHit        = $_.CacheHit
                    Error           = $_.Error
                    ProcessedAt     = $_.ProcessedAt
                }
            } |
            Export-Csv -LiteralPath $scanPath -NoTypeInformation -Encoding utf8
    }

    if ([bool]$cfg.GenerateReport -and $scanRecords.Count -gt 0) {
        New-HmdHtmlReport -Records @($scanRecords) -Path $reportPath | Out-Null
    }

    $deployedCount = 0
    $deployMissCount = 0
    $deployErrorCount = 0
    $deploySkipCount = 0
    $deployLog = $null
    if ($mapRows.Count -gt 0) {
        $deploy = Copy-HmdCleanDeploy -Records @($scanRecords) -MapRows $mapRows `
            -WorkRoot $work -Overwrite ([bool]$cfg.DeployOverwrite)
        $deployedCount = [int]$deploy.DeployedCount
        $deployMissCount = [int]$deploy.DeployMissCount
        $deployErrorCount = [int]$deploy.DeployErrorCount
        $deploySkipCount = [int]$deploy.DeploySkipCount
        $deployLog = $deploy.DeployLogPath
    }

    $errorCount = @($scanRecords | Where-Object { [string]$_.Verdict -eq 'Error' }).Count
    $malCount = @($scanRecords | Where-Object { [string]$_.Verdict -eq 'Malicious' }).Count
    $susCount = @($scanRecords | Where-Object { [string]$_.Verdict -eq 'Suspicious' }).Count
    $cleanCount = @($scanRecords | Where-Object { [string]$_.Verdict -eq 'Clean' }).Count
    $unknownCount = @($scanRecords | Where-Object { [string]$_.Verdict -eq 'Unknown' }).Count
    $undetectedSum = 0
    $harmlessSum = 0
    foreach ($rec in $scanRecords) {
        if ($null -ne $rec.PSObject.Properties['Undetected'] -and
            -not [string]::IsNullOrWhiteSpace([string]$rec.Undetected)) {
            $undetectedSum += [int]$rec.Undetected
        }
        if ($null -ne $rec.PSObject.Properties['Harmless'] -and
            -not [string]::IsNullOrWhiteSpace([string]$rec.Harmless)) {
            $harmlessSum += [int]$rec.Harmless
        }
    }

    $summary = [pscustomobject]@{
        WorkRoot               = $work
        InputCount             = $allUrls.Count
        QueuedCount            = $queued.Count
        SkippedByCheckpoint    = [Math]::Max(0, $allUrls.Count - $queued.Count)
        ProcessedCount         = $downloadResults.Count
        CleanCount             = $cleanCount
        SuspiciousCount        = $susCount
        MaliciousCount         = $malCount
        UnknownCount           = $unknownCount
        ErrorCount             = $errorCount
        UndetectedSum          = $undetectedSum
        HarmlessSum            = $harmlessSum
        DeployedCount          = $deployedCount
        DeployMissCount        = $deployMissCount
        DeployErrorCount       = $deployErrorCount
        DeploySkipCount        = $deploySkipCount
        DeployLog              = $deployLog
        PrefixFileNames        = [bool]$cfg.PrefixFileNames
        LocalAvScanEnabled     = $localAvEnabled
        ScanLog                = $scanPath
        HashCache              = $cachePath
        Report                 = $(if (Test-Path -LiteralPath $reportPath) { $reportPath } else { $null })
        RecordsArePriorScanlog = ($downloadResults.Count -eq 0 -and $scanRecords.Count -gt 0)
        Records                = @($scanRecords)
    }

    if ([bool]$cfg.DisplaySummary) {
        Write-Host ''
        Write-Host '=== Hash.MassDownloader summary ==='
        Write-Host ("WorkRoot:             {0}" -f $summary.WorkRoot)
        Write-Host ("Input / Queued:       {0} / {1}" -f $summary.InputCount, $summary.QueuedCount)
        Write-Host ("Skipped (checkpoint): {0}" -f $summary.SkippedByCheckpoint)
        Write-Host ("Processed this run:   {0}" -f $summary.ProcessedCount)
        Write-Host ("Verdicts (scanlog):   Clean={0} Suspicious={1} Malicious={2} Unknown={3} Error={4}" -f `
                $cleanCount, $susCount, $malCount, $unknownCount, $errorCount)
        Write-Host ("VT engines (sum):     Undetected={0} Harmless={1}" -f $undetectedSum, $harmlessSum)
        Write-Host ("Prefix file names:    {0}" -f $summary.PrefixFileNames)
        Write-Host ("Local AV scan:        {0}" -f $summary.LocalAvScanEnabled)
        if ($mapRows.Count -gt 0) {
            Write-Host ("Deploy:               copied={0} miss={1} error={2} skip={3}" -f `
                    $deployedCount, $deployMissCount, $deployErrorCount, $deploySkipCount)
            if ($summary.DeployLog) {
                Write-Host ("DeployLog:            {0}" -f $summary.DeployLog)
            }
        }
        Write-Host ("Prior scanlog only:   {0}" -f $summary.RecordsArePriorScanlog)
        Write-Host ("ScanLog:              {0}" -f $summary.ScanLog)
        Write-Host ("HashCache:            {0}" -f $summary.HashCache)
        if ($summary.Report) {
            Write-Host ("Report:               {0}" -f $summary.Report)
        }
        Write-Host '================================='
        Write-Host ''
    }

    if ([bool]$cfg.DisplayScanLog -and (Test-Path -LiteralPath $scanPath)) {
        Write-Host '=== scanlog.csv ==='
        Import-Csv -LiteralPath $scanPath |
            Format-Table -AutoSize Url, FileName, Verdict, Malicious, Suspicious, Undetected, Harmless, `
                DefenderStatus, CacheHit, Error |
            Out-String |
            Write-Host
        Write-Host '==================='
        Write-Host ''
    }

    # AgentSummary one-liner is emitted by scripts/Invoke-HmdBulkDownload.ps1
    # (Write-Output must not run under assignment capture inside this function).
    return $summary
}
