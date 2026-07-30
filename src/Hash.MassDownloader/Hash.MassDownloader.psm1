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
    'Get-HmdFileSha256'
    'Test-HmdCacheEntryFresh'
    'Import-HmdHashCache'
    'Export-HmdHashCache'
    'Get-HmdVerdictFromStats'
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
    'Invoke-HmdBulkDownload'
)
