@{
    RootModule        = 'Hash.MassDownloader.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'c8e4a1b2-7f3d-4a9e-b5c1-0d8e2f6a4b19'
    Author            = 'Ville Pispa'
    CompanyName       = 'Independent'
    Copyright         = '(c) 2026 Ville Pispa. MIT License.'
    Description       = 'Bulk URL downloader with SHA256-first hash reputation (VirusTotal-first), cache, quarantine, and HTML reports.'
    PowerShellVersion = '7.2'
    FunctionsToExport = @(
        'Get-HmdConfig'
        'Resolve-HmdApiKey'
        'ConvertTo-HmdFlatArray'
        'Import-HmdUrlList'
        'Initialize-HmdWorkRoot'
        'Get-HmdSafeFileName'
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
        'Invoke-HmdBulkDownload'
    )
    PrivateData       = @{
        PSData = @{
            Tags         = @('Hash', 'Reputation', 'VirusTotal', 'Malware', 'Download', 'Security', 'PowerShell')
            LicenseUri   = 'https://opensource.org/licenses/MIT'
            ProjectUri   = 'https://github.com/villepispa/hash-mass-downloader'
            ReleaseNotes = 'v0.1.0 — Hash.MassDownloader MVP: SHA256-first VT, cache, quarantine, validate trio.'
        }
    }
}
