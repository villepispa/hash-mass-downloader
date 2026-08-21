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
        Optional archive inspection for ZIP/JAR/HPI/JPI (HMD-006). Live progress
        via Write-Progress / host lines and logs/progress.log (HMD-046).
        Archive members write logs/archive-scanlog.csv; host dump is
        DisplayArchiveScanLog (default false) so DisplayScanLog stays short (HMD-047).
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
        if (-not $ConfigOverride.ContainsKey('DisplayArchiveScanLog')) {
            $cfg.DisplayArchiveScanLog = $false
        }
        if (-not $ConfigOverride.ContainsKey('DisplayProgress')) {
            $cfg.DisplayProgress = $false
        }
    }

    $work = Initialize-HmdWorkRoot -WorkRoot $WorkRoot
    $hmdProgress = New-HmdProgressContext -Config $cfg -WorkRoot $work `
        -AgentSummary:$AgentSummary -ConfigOverride $ConfigOverride
    $cachePath = Join-Path $work 'logs\hashcache.csv'
    $scanPath = Join-Path $work 'logs\scanlog.csv'
    $archiveScanPath = Join-Path $work 'logs\archive-scanlog.csv'
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
        Write-HmdProgress -Context $hmdProgress -Phase Download -Status START `
            -Current 0 -Total $queued.Count `
            -Message ("threads={0}" -f [int]$cfg.DownloadThreads)
        $downloadResults = @(Start-HmdDownloadPool -Urls $queued -WorkRoot $work `
                -ThrottleLimit ([int]$cfg.DownloadThreads) `
                -MaxFileBytes ([long]$cfg.MaxFileBytes) `
                -MaxRetries ([int]$cfg.MaxDownloadRetries) `
                -UserAgent ([string]$cfg.UserAgent) `
                -PrefixFileNames ([bool]$cfg.PrefixFileNames) `
                -DownloadInvoker $DownloadInvoker)
        # Defensive: unwrap accidental one-level nest from older call patterns.
        $downloadResults = @(ConvertTo-HmdFlatArray -InputObject $downloadResults)
        $dlDone = 0
        foreach ($dlItem in $downloadResults) {
            $dlDone++
            $dlState = $(if ([bool]$dlItem.Success) { 'ok' } else { 'fail' })
            Write-HmdProgress -Context $hmdProgress -Phase Download -Status ITEM `
                -Current $dlDone -Total $downloadResults.Count `
                -Message ("{0} {1} bytes={2}" -f [string]$dlItem.FileName, $dlState, $dlItem.Bytes)
        }
        $dlOk = @($downloadResults | Where-Object { [bool]$_.Success }).Count
        Write-HmdProgress -Context $hmdProgress -Phase Download -Status DONE `
            -Current $downloadResults.Count -Total $downloadResults.Count `
            -Message ("ok={0} fail={1}" -f $dlOk, ($downloadResults.Count - $dlOk))
    }
    else {
        Write-HmdProgress -Context $hmdProgress -Phase Download -Status DONE `
            -Current 0 -Total 0 -Message 'checkpoint skip'
    }

    $scanRecords = [System.Collections.Generic.List[object]]::new()
    $seenScanKeys = @{}
    foreach ($row in @(
            @(Import-HmdScanLogCsv -Path $scanPath) +
            @(Import-HmdScanLogCsv -Path $archiveScanPath)
        )) {
        if ($null -eq $row) { continue }
        $scanKey = '{0}|{1}|{2}' -f [string]$row.Url, [string]$row.FileName, [string]$row.Sha256
        if ($seenScanKeys.ContainsKey($scanKey)) { continue }
        $seenScanKeys[$scanKey] = $true
        $scanRecords.Add((ConvertTo-HmdScanLogRow -InputObject $row)) | Out-Null
    }

    $dlTotal = $downloadResults.Count
    $dlIndex = 0
    Write-HmdProgress -Context $hmdProgress -Phase Process -Status START `
        -Current 0 -Total $dlTotal -Message 'hash AV VT disposition'
    foreach ($dl in $downloadResults) {
        $dlIndex++
        $progLeaf = [string]$dl.FileName
        if ([string]::IsNullOrWhiteSpace($progLeaf)) {
            $progLeaf = [string]$dl.Url
        }
        Write-HmdProgress -Context $hmdProgress -Phase Process -Status STEP `
            -Current $dlIndex -Total $dlTotal -Message "$progLeaf start"
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
        $archiveRows = [System.Collections.Generic.List[object]]::new()

        try {
            if (-not $dl.Success -or [string]::IsNullOrWhiteSpace($dl.LocalPath)) {
                $record.Verdict = 'Error'
                Write-HmdProgress -Context $hmdProgress -Phase Process -Status ITEM `
                    -Current $dlIndex -Total $dlTotal `
                    -Message "$progLeaf Verdict=Error"
                $scanRecords.Add([pscustomobject]$record) | Out-Null
                $null = $completed.Add($dl.Url)
                Save-HmdCheckpoint -CompletedUrls $completed -Path $ckptPath
                continue
            }

            Write-HmdProgress -Context $hmdProgress -Phase Process -Status STEP `
                -Current $dlIndex -Total $dlTotal -Message "$progLeaf Hash"
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
                Write-HmdProgress -Context $hmdProgress -Phase Process -Status STEP `
                    -Current $dlIndex -Total $dlTotal -Message "$progLeaf Defender"
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
                    Write-HmdProgress -Context $hmdProgress -Phase Process -Status STEP `
                        -Current $dlIndex -Total $dlTotal -Message "$progLeaf CacheHit"
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
                    Write-HmdProgress -Context $hmdProgress -Phase Process -Status STEP `
                        -Current $dlIndex -Total $dlTotal -Message "$progLeaf VirusTotal"
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

            # HMD-006 / HMD-045: optional ZIP-family member hash / selective VT.
            $archiveEnabled = $false
            if ($null -ne $cfg.PSObject.Properties['ArchiveInspectionEnabled']) {
                $archiveEnabled = [bool]$cfg.ArchiveInspectionEnabled
            }
            $archiveVtMode = Resolve-HmdArchiveVtMode -Config $cfg
            $archiveMaxMembers = 500
            if ($null -ne $cfg.PSObject.Properties['ArchiveMaxMembers'] -and
                [int]$cfg.ArchiveMaxMembers -gt 0) {
                $archiveMaxMembers = [int]$cfg.ArchiveMaxMembers
            }
            $archiveExts = @(Get-HmdDefaultArchiveExtensions)
            if ($null -ne $cfg.PSObject.Properties['ArchiveExtensions'] -and
                $null -ne $cfg.ArchiveExtensions) {
                $archiveExts = @($cfg.ArchiveExtensions | ForEach-Object { [string]$_ } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                if ($archiveExts.Count -eq 0) {
                    $archiveExts = @(Get-HmdDefaultArchiveExtensions)
                }
            }
            $interestExts = @(Get-HmdDefaultArchiveInterestingExtensions)
            if ($null -ne $cfg.PSObject.Properties['ArchiveInterestingExtensions'] -and
                $null -ne $cfg.ArchiveInterestingExtensions) {
                $interestExts = @($cfg.ArchiveInterestingExtensions | ForEach-Object { [string]$_ } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                if ($interestExts.Count -eq 0) {
                    $interestExts = @(Get-HmdDefaultArchiveInterestingExtensions)
                }
            }
            $interestKeys = @(Get-HmdDefaultArchiveInterestPathKeywords)
            if ($null -ne $cfg.PSObject.Properties['ArchiveInterestPathKeywords'] -and
                $null -ne $cfg.ArchiveInterestPathKeywords) {
                $interestKeys = @($cfg.ArchiveInterestPathKeywords | ForEach-Object { [string]$_ } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                if ($interestKeys.Count -eq 0) {
                    $interestKeys = @(Get-HmdDefaultArchiveInterestPathKeywords)
                }
            }
            $interestCheckMz = $true
            if ($null -ne $cfg.PSObject.Properties['ArchiveInterestCheckMz']) {
                $interestCheckMz = [bool]$cfg.ArchiveInterestCheckMz
            }

            if ($archiveEnabled -and
                -not [string]::IsNullOrWhiteSpace($dl.LocalPath) -and
                (Test-Path -LiteralPath $dl.LocalPath) -and
                (Test-HmdIsArchivePath -Path $dl.LocalPath -Extensions $archiveExts)) {
                Write-HmdProgress -Context $hmdProgress -Phase Process -Status STEP `
                    -Current $dlIndex -Total $dlTotal -Message "$progLeaf Archive"
                $insp = Invoke-HmdArchiveInspect -ArchivePath $dl.LocalPath -WorkRoot $work `
                    -ParentFileName ([string]$dl.FileName) -ParentSha256 $sha `
                    -MaxMembers $archiveMaxMembers -Extensions $archiveExts
                if (-not $insp.Success) {
                    $verdict = 'Error'
                    $record.Verdict = $verdict
                    $record.Error = [string]$insp.Error
                }
                else {
                    $memberVerdicts = [System.Collections.Generic.List[string]]::new()
                    $anyMemberVt = $false
                    foreach ($m in @($insp.Members)) {
                        $mVerdict = 'Unknown'
                        $mMal = 0; $mSus = 0; $mUnd = 0; $mHarm = 0
                        $mIgnored = ''
                        $mErr = [string]$m.Error
                        $mFromCache = $false
                        $mInterestReason = ''
                        $runMemberVt = $false
                        if ($archiveVtMode -eq 'All') {
                            $runMemberVt = $true
                        }
                        elseif ($archiveVtMode -eq 'Interesting') {
                            $interest = Get-HmdArchiveMemberInterest -EntryName ([string]$m.EntryName) `
                                -LocalPath ([string]$m.LocalPath) `
                                -InterestingExtensions $interestExts `
                                -PathKeywords $interestKeys `
                                -CheckMz $interestCheckMz
                            if ([bool]$interest.Interesting) {
                                $runMemberVt = $true
                                $mInterestReason = [string]$interest.Reason
                            }
                        }
                        if (-not [string]::IsNullOrWhiteSpace($mErr)) {
                            $mVerdict = 'Error'
                        }
                        elseif ($runMemberVt -and -not $SkipVirusTotal -and -not $skipVt -and
                            -not [string]::IsNullOrWhiteSpace([string]$m.Sha256)) {
                            $anyMemberVt = $true
                            $mSha = [string]$m.Sha256
                            if ($cache.ContainsKey($mSha) -and
                                (Test-HmdCacheEntryFresh -CachedAt $cache[$mSha].CachedAt `
                                    -TtlDays ([int]$cfg.CacheTtlDays))) {
                                $mFromCache = $true
                                $c = $cache[$mSha]
                                $mVerdict = $c.Verdict
                                $mMal = [int]$c.Malicious
                                $mSus = [int]$c.Suspicious
                                $mUnd = [int]$c.Undetected
                                $mHarm = $(if ($null -ne $c.PSObject.Properties['Harmless']) {
                                        [int]$c.Harmless
                                    }
                                    else { 0 })
                                $mIgnored = $(if ($null -ne $c.PSObject.Properties['IgnoredEngines']) {
                                        [string]$c.IgnoredEngines
                                    }
                                    else { '' })
                            }
                            else {
                                $mReport = Get-HmdHashReport -Sha256 $mSha -ApiKey $apiKeyPlain `
                                    -Invoker $VtInvoker -ApiDelaySeconds ([int]$cfg.ApiDelaySeconds)
                                if ($mReport.Found) {
                                    $mMal = [int]$mReport.Malicious
                                    $mSus = [int]$mReport.Suspicious
                                    $mUnd = [int]$mReport.Undetected
                                    $mHarm = [int]$mReport.Harmless
                                    $mPolicy = Get-HmdPolicyStatsFromResults -AnalysisResults $mReport.Results `
                                        -IgnoreEngines $ignoreList `
                                        -RawMalicious $mMal -RawSuspicious $mSus `
                                        -RawUndetected $mUnd -RawHarmless $mHarm
                                    $mVerdict = Get-HmdVerdictFromStats -Malicious $mPolicy.Malicious `
                                        -Suspicious $mPolicy.Suspicious -Undetected $mPolicy.Undetected `
                                        -MaliciousThreshold ([int]$cfg.MaliciousThreshold) `
                                        -SuspiciousThreshold ([int]$cfg.SuspiciousThreshold) -Known
                                    if ($mPolicy.IgnoredEngines.Count -gt 0) {
                                        $mIgnored = ($mPolicy.IgnoredEngines -join ';')
                                    }
                                    $cache[$mSha] = [pscustomobject]@{
                                        Sha256         = $mSha
                                        Verdict        = $mVerdict
                                        Malicious      = $mMal
                                        Suspicious     = $mSus
                                        Undetected     = $mUnd
                                        Harmless       = $mHarm
                                        IgnoredEngines = $mIgnored
                                        CachedAt       = Get-Date
                                        Source         = 'VirusTotal'
                                    }
                                    Export-HmdHashCache -Cache $cache -Path $cachePath
                                }
                                else {
                                    $mVerdict = 'Unknown'
                                }
                            }
                        }
                        $memberVerdicts.Add($mVerdict) | Out-Null
                        $errParts = [System.Collections.Generic.List[string]]::new()
                        if (-not [string]::IsNullOrWhiteSpace($mErr)) {
                            $errParts.Add($mErr) | Out-Null
                        }
                        else {
                            $errParts.Add("ParentSha256=$sha") | Out-Null
                            $errParts.Add("VtMode=$archiveVtMode") | Out-Null
                            if ($archiveVtMode -eq 'None') {
                                $errParts.Add('HashOnly=true') | Out-Null
                            }
                            if (-not [string]::IsNullOrWhiteSpace($mInterestReason)) {
                                $errParts.Add("Interest=$mInterestReason") | Out-Null
                            }
                        }
                        $archiveRows.Add([pscustomobject]@{
                                Url                   = [string]$dl.Url
                                FileName              = "#archive/$([string]$m.EntryName)"
                                LocalPath             = [string]$m.LocalPath
                                Sha256                = [string]$m.Sha256
                                Verdict               = $mVerdict
                                Malicious             = $mMal
                                Suspicious            = $mSus
                                Undetected            = $mUnd
                                Harmless              = $mHarm
                                IgnoredEngines        = $mIgnored
                                ArchiveInterestReason = $mInterestReason
                                SignatureStatus       = ''
                                Signer                = ''
                                DefenderStatus        = ''
                                DefenderThreat        = ''
                                ContentType           = 'archive-member'
                                Bytes                 = [long]$m.Bytes
                                CacheHit              = $mFromCache
                                Error                 = ($errParts.ToArray() -join ';')
                                ProcessedAt           = (Get-Date).ToString('o')
                            }) | Out-Null
                    }
                    $shouldMerge = ($archiveVtMode -eq 'All') -or
                        ($archiveVtMode -eq 'Interesting' -and $anyMemberVt)
                    if ($shouldMerge -and $memberVerdicts.Count -gt 0) {
                        $verdict = Get-HmdMergedVerdict -Verdicts @(
                            @($verdict) + [string[]]$memberVerdicts.ToArray()
                        )
                        $record.Verdict = $verdict
                    }
                }
            }

            $moved = Move-HmdByVerdict -SourcePath $dl.LocalPath -WorkRoot $work `
                -Verdict $verdict `
                -QuarantineMalicious ([bool]$cfg.QuarantineMalicious) `
                -QuarantineSuspicious ([bool]$cfg.QuarantineSuspicious)
            $record.LocalPath = $moved.FinalPath
            if (-not $skipVt -and $verdict -ne 'Error') {
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

        Write-HmdProgress -Context $hmdProgress -Phase Process -Status ITEM `
            -Current $dlIndex -Total $dlTotal `
            -Message ("{0} Verdict={1}" -f $progLeaf, [string]$record.Verdict)
        $scanRecords.Add([pscustomobject]$record) | Out-Null
        if ($null -ne $archiveRows) {
            foreach ($ar in $archiveRows) {
                if ($null -ne $ar) {
                    $scanRecords.Add($ar) | Out-Null
                }
            }
        }
        $null = $completed.Add([string]$dl.Url)
        Save-HmdCheckpoint -CompletedUrls $completed -Path $ckptPath
    }
    Write-HmdProgress -Context $hmdProgress -Phase Process -Status DONE `
        -Current $dlTotal -Total $dlTotal -Message 'processed'

    # Rewrite logs: top-level → scanlog.csv; #archive/ members → archive-scanlog.csv.
    if ($scanRecords.Count -gt 0) {
        $topScanRows = @($scanRecords | Where-Object {
                -not (Test-HmdIsArchiveScanRow -FileName ([string]$_.FileName))
            })
        $archiveScanRows = @($scanRecords | Where-Object {
                Test-HmdIsArchiveScanRow -FileName ([string]$_.FileName)
            })
        Export-HmdScanLogCsv -Records $topScanRows -Path $scanPath
        Export-HmdScanLogCsv -Records $archiveScanRows -Path $archiveScanPath
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
        Write-HmdProgress -Context $hmdProgress -Phase Deploy -Status START `
            -Current 0 -Total $mapRows.Count -Message ("mapRows={0}" -f $mapRows.Count)
        $deploy = Copy-HmdCleanDeploy -Records @($scanRecords) -MapRows $mapRows `
            -WorkRoot $work -Overwrite ([bool]$cfg.DeployOverwrite)
        $deployedCount = [int]$deploy.DeployedCount
        $deployMissCount = [int]$deploy.DeployMissCount
        $deployErrorCount = [int]$deploy.DeployErrorCount
        $deploySkipCount = [int]$deploy.DeploySkipCount
        $deployLog = $deploy.DeployLogPath
        Write-HmdProgress -Context $hmdProgress -Phase Deploy -Status DONE `
            -Current $mapRows.Count -Total $mapRows.Count `
            -Message ("copied={0} miss={1} error={2} skip={3}" -f `
                $deployedCount, $deployMissCount, $deployErrorCount, $deploySkipCount)
    }

    $topLevel = @($scanRecords | Where-Object {
            -not (Test-HmdIsArchiveScanRow -FileName ([string]$_.FileName))
        })
    $errorCount = @($topLevel | Where-Object { [string]$_.Verdict -eq 'Error' }).Count
    $malCount = @($topLevel | Where-Object { [string]$_.Verdict -eq 'Malicious' }).Count
    $susCount = @($topLevel | Where-Object { [string]$_.Verdict -eq 'Suspicious' }).Count
    $cleanCount = @($topLevel | Where-Object { [string]$_.Verdict -eq 'Clean' }).Count
    $unknownCount = @($topLevel | Where-Object { [string]$_.Verdict -eq 'Unknown' }).Count
    $undetectedSum = 0
    $harmlessSum = 0
    foreach ($rec in $topLevel) {
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
        ArchiveScanLog         = $archiveScanPath
        HashCache              = $cachePath
        ProgressLog            = $(if ($null -ne $hmdProgress.LogPath -and
                (Test-Path -LiteralPath $hmdProgress.LogPath)) { $hmdProgress.LogPath } else { $null })
        Report                 = $(if (Test-Path -LiteralPath $reportPath) { $reportPath } else { $null })
        RecordsArePriorScanlog = ($downloadResults.Count -eq 0 -and $scanRecords.Count -gt 0)
        Records                = @($scanRecords)
    }

    Write-HmdProgress -Context $hmdProgress -Phase Complete -Status DONE `
        -Current 1 -Total 1 -Message 'run complete' -Completed

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
        if (Test-Path -LiteralPath $summary.ArchiveScanLog) {
            Write-Host ("ArchiveScanLog:       {0}" -f $summary.ArchiveScanLog)
        }
        Write-Host ("HashCache:            {0}" -f $summary.HashCache)
        if ($summary.ProgressLog) {
            Write-Host ("ProgressLog:          {0}" -f $summary.ProgressLog)
        }
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

    $showArchiveScanLog = $false
    if ($null -ne $cfg.PSObject.Properties['DisplayArchiveScanLog']) {
        $showArchiveScanLog = [bool]$cfg.DisplayArchiveScanLog
    }
    if ($showArchiveScanLog -and (Test-Path -LiteralPath $archiveScanPath)) {
        Write-Host '=== archive-scanlog.csv ==='
        Import-Csv -LiteralPath $archiveScanPath |
            Format-Table -AutoSize Url, FileName, Verdict, Malicious, Suspicious, Undetected, Harmless, `
                ArchiveInterestReason, CacheHit, Error |
            Out-String |
            Write-Host
        Write-Host '==========================='
        Write-Host ''
    }

    # AgentSummary one-liner is emitted by scripts/Invoke-HmdBulkDownload.ps1
    # (Write-Output must not run under assignment capture inside this function).
    return $summary
}
