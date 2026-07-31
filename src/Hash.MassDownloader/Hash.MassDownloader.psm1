#Requires -Version 7.2

$private = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -ErrorAction SilentlyContinue)
$public = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' -ErrorAction SilentlyContinue)

foreach ($file in @($private + $public)) {
    . $file.FullName
}

Export-ModuleMember -Function @(
    'Get-HmdConfig'
    'Resolve-HmdApiKey'
    'ConvertTo-HmdFlatArray'
    'Import-HmdUrlList'
    'Initialize-HmdWorkRoot'
    'Get-HmdUrlLeafName'
    'Get-HmdSafeFileName'
    'Get-HmdDeployMatchKeys'
    'Test-HmdHttpUrl'
    'Get-HmdUrlsFromDeployMap'
    'Invoke-HmdLocalAvScan'
    'Get-HmdFileSha256'
    'Test-HmdCacheEntryFresh'
    'Import-HmdHashCache'
    'Export-HmdHashCache'
    'Get-HmdVerdictFromStats'
    'Get-HmdIgnoreEngineList'
    'Get-HmdPolicyStatsFromResults'
    'Import-HmdCheckpoint'
    'Save-HmdCheckpoint'
    'Invoke-HmdRest'
    'Get-HmdHashReport'
    'Submit-HmdFile'
    'Get-HmdAnalysis'
    'Start-HmdDownloadPool'
    'Get-HmdAuthenticodeInfo'
    'Move-HmdByVerdict'
    'New-HmdHtmlReport'
    'Import-HmdDeployMap'
    'Copy-HmdCleanDeploy'
    'Test-HmdDeployPatternIsGlob'
    'Get-HmdDefaultArchiveExtensions'
    'Get-HmdDefaultArchiveInterestingExtensions'
    'Get-HmdDefaultArchiveInterestPathKeywords'
    'Resolve-HmdArchiveVtMode'
    'Get-HmdArchiveMemberInterest'
    'Test-HmdIsArchivePath'
    'Test-HmdIsArchiveScanRow'
    'Get-HmdMergedVerdict'
    'Expand-HmdArchiveSafe'
    'Invoke-HmdArchiveInspect'
    'Invoke-HmdBulkDownload'
)
