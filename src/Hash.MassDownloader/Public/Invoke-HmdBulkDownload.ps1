#Requires -Version 7.2

function Invoke-HmdBulkDownload {
    <#
    .SYNOPSIS
        Bulk-download URLs, check VirusTotal by SHA256, disposition and report.
    .DESCRIPTION
        Orchestrates parallel download and serialized VT lookups with cache,
        checkpoint resume, quarantine policy, and HTML/CSV artefacts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$InputPath,

        [Parameter(Mandatory)]
        [string]$WorkRoot,

        [SecureString]$ApiKey,

        [switch]$UploadUnknownSamples,

        [switch]$SkipVirusTotal,

        [scriptblock]$VtInvoker,

        [scriptblock]$DownloadInvoker,

        [hashtable]$ConfigOverride = @{},

        [switch]$AgentSummary
    )

    $cfg = Get-HmdConfig -Override $ConfigOverride
    if ($PSBoundParameters.ContainsKey('UploadUnknownSamples')) {
        $cfg.UploadUnknownSamples = [bool]$UploadUnknownSamples
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

    # Pipeline-enumerated lists — @() is correct here (one object per URL/result).
    $allUrls = [string[]]@(Import-HmdUrlList -Path $InputPath)

    $pendingList = [System.Collections.Generic.List[string]]::new()
    foreach ($u in $allUrls) {
        if (-not $completed.Contains([string]$u)) {
            $pendingList.Add([string]$u)
        }
    }
    $pending = [string[]]$pendingList.ToArray()

    $apiKeyPlain = $null
    if (-not $SkipVirusTotal) {
        $apiKeyPlain = Resolve-HmdApiKey -ApiKey $ApiKey
    }

    $downloadResults = [object[]]@()
    if ($pending.Count -gt 0) {
        $downloadResults = @(Start-HmdDownloadPool -Urls $pending -WorkRoot $work `
                -ThrottleLimit ([int]$cfg.DownloadThreads) `
                -MaxFileBytes ([long]$cfg.MaxFileBytes) `
                -MaxRetries ([int]$cfg.MaxDownloadRetries) `
                -UserAgent ([string]$cfg.UserAgent) `
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
                    SignatureStatus = $row.SignatureStatus
                    Signer          = $row.Signer
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
            SignatureStatus  = ''
            Signer           = ''
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
            $fromCache = $false

            if ($cache.ContainsKey($sha) -and
                (Test-HmdCacheEntryFresh -CachedAt $cache[$sha].CachedAt -TtlDays ([int]$cfg.CacheTtlDays))) {
                $fromCache = $true
                $c = $cache[$sha]
                $verdict = $c.Verdict
                $mal = [int]$c.Malicious
                $sus = [int]$c.Suspicious
                $und = [int]$c.Undetected
                $harm = $(if ($null -ne $c.PSObject.Properties['Harmless']) { [int]$c.Harmless } else { 0 })
            }
            elseif (-not $SkipVirusTotal) {
                $report = Get-HmdHashReport -Sha256 $sha -ApiKey $apiKeyPlain `
                    -Invoker $VtInvoker -ApiDelaySeconds ([int]$cfg.ApiDelaySeconds)

                if ($report.Found) {
                    $mal = [int]$report.Malicious
                    $sus = [int]$report.Suspicious
                    $und = [int]$report.Undetected
                    $harm = [int]$report.Harmless
                    $verdict = Get-HmdVerdictFromStats -Malicious $mal -Suspicious $sus `
                        -Undetected $und -MaliciousThreshold ([int]$cfg.MaliciousThreshold) `
                        -SuspiciousThreshold ([int]$cfg.SuspiciousThreshold) -Known
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
                    $verdict = Get-HmdVerdictFromStats -Malicious $mal -Suspicious $sus `
                        -Undetected $und -MaliciousThreshold ([int]$cfg.MaliciousThreshold) `
                        -SuspiciousThreshold ([int]$cfg.SuspiciousThreshold) -Known
                }
                else {
                    $verdict = 'Unknown'
                }

                $cache[$sha] = [pscustomobject]@{
                    Sha256     = $sha
                    Verdict    = $verdict
                    Malicious  = $mal
                    Suspicious = $sus
                    Undetected = $und
                    Harmless   = $harm
                    CachedAt   = Get-Date
                    Source     = 'VirusTotal'
                }
                Export-HmdHashCache -Cache $cache -Path $cachePath
            }
            else {
                $verdict = 'Unknown'
            }

            $record.CacheHit = $fromCache
            $record.Verdict = $verdict
            $record.Malicious = $mal
            $record.Suspicious = $sus
            $record.Undetected = $und
            $record.Harmless = $harm

            $moved = Move-HmdByVerdict -SourcePath $dl.LocalPath -WorkRoot $work `
                -Verdict $verdict `
                -QuarantineMalicious ([bool]$cfg.QuarantineMalicious) `
                -QuarantineSuspicious ([bool]$cfg.QuarantineSuspicious)
            $record.LocalPath = $moved.FinalPath
            $record.Error = ''
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

    # Rewrite scan log cleanly (fixed columns so prior rows gain Harmless=0)
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
                    SignatureStatus = $_.SignatureStatus
                    Signer          = $_.Signer
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
        PendingCount           = $pending.Count
        SkippedByCheckpoint    = [Math]::Max(0, $allUrls.Count - $pending.Count)
        ProcessedCount         = $downloadResults.Count
        CleanCount             = $cleanCount
        SuspiciousCount        = $susCount
        MaliciousCount         = $malCount
        UnknownCount           = $unknownCount
        ErrorCount             = $errorCount
        UndetectedSum          = $undetectedSum
        HarmlessSum            = $harmlessSum
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
        Write-Host ("Input / Pending:      {0} / {1}" -f $summary.InputCount, $summary.PendingCount)
        Write-Host ("Skipped (checkpoint): {0}" -f $summary.SkippedByCheckpoint)
        Write-Host ("Processed this run:   {0}" -f $summary.ProcessedCount)
        Write-Host ("Verdicts (scanlog):   Clean={0} Suspicious={1} Malicious={2} Unknown={3} Error={4}" -f `
                $cleanCount, $susCount, $malCount, $unknownCount, $errorCount)
        Write-Host ("VT engines (sum):     Undetected={0} Harmless={1}" -f $undetectedSum, $harmlessSum)
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
            Format-Table -AutoSize Url, FileName, Verdict, Malicious, Suspicious, Undetected, Harmless, CacheHit, Error |
            Out-String |
            Write-Host
        Write-Host '==================='
        Write-Host ''
    }

    # AgentSummary one-liner is emitted by scripts/Invoke-HmdBulkDownload.ps1
    # (Write-Output must not run under assignment capture inside this function).
    return $summary
}
