#Requires -Version 7.2

BeforeAll {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    Import-Module (Join-Path $repoRoot 'src\Hash.MassDownloader\Hash.MassDownloader.psd1') -Force
}

Describe 'Import-HmdUrlList' {
    It 'parses TXT with comments and blanks' {
        $tmp = Join-Path $TestDrive 'urls.txt'
        @"
# comment
https://a.example/x

https://b.example/y
https://a.example/x
"@ | Set-Content -LiteralPath $tmp -Encoding utf8
        $urls = Import-HmdUrlList -Path $tmp
        $urls.Count | Should -Be 2
        $urls[0] | Should -Be 'https://a.example/x'
    }

    It 'splits multiple URLs on one line' {
        $tmp = Join-Path $TestDrive 'urls-multi.txt'
        'https://a.example/x https://b.example/y' | Set-Content -LiteralPath $tmp -Encoding utf8
        $urls = Import-HmdUrlList -Path $tmp
        $urls.Count | Should -Be 2
        $urls[0] | Should -Be 'https://a.example/x'
        $urls[1] | Should -Be 'https://b.example/y'
    }

    It 'keeps two line URLs as two items when collected with @()' {
        $tmp = Join-Path $TestDrive 'urls-two.txt'
        @"
https://a.example/one
https://b.example/two
"@ | Set-Content -LiteralPath $tmp -Encoding utf8
        $urls = [string[]]@(Import-HmdUrlList -Path $tmp)
        $urls.Count | Should -Be 2
        $urls[0] | Should -Be 'https://a.example/one'
    }

    It 'parses CSV Url column' {
        $tmp = Join-Path $TestDrive 'urls.csv'
        @"
Url,Note
https://c.example/z,n1
https://d.example/w,n2
"@ | Set-Content -LiteralPath $tmp -Encoding utf8
        $urls = Import-HmdUrlList -Path $tmp
        $urls.Count | Should -Be 2
        $urls[1] | Should -Be 'https://d.example/w'
    }
}

Describe 'Get-HmdVerdictFromStats' {
    It 'returns Malicious when threshold met' {
        Get-HmdVerdictFromStats -Malicious 2 -Suspicious 0 -Undetected 50 -Known |
            Should -Be 'Malicious'
    }

    It 'returns Suspicious when only suspicious' {
        Get-HmdVerdictFromStats -Malicious 0 -Suspicious 3 -Undetected 40 -Known |
            Should -Be 'Suspicious'
    }

    It 'returns Clean when no detections' {
        Get-HmdVerdictFromStats -Malicious 0 -Suspicious 0 -Undetected 60 -Known |
            Should -Be 'Clean'
    }

    It 'returns Unknown when not known' {
        Get-HmdVerdictFromStats -Malicious 0 -Suspicious 0 -Undetected 0 |
            Should -Be 'Unknown'
    }

    It 'threshold-only: Malicious=1 is Clean when MaliciousThreshold=2' {
        Get-HmdVerdictFromStats -Malicious 1 -Suspicious 0 -Undetected 65 -Known `
            -MaliciousThreshold 2 |
            Should -Be 'Clean'
    }
}

Describe 'Get-HmdPolicyStatsFromResults (HMD-025)' {
    BeforeAll {
        $script:chromeResults = [pscustomobject]@{
            VirIT     = [pscustomobject]@{ category = 'malicious'; engine_name = 'VirIT'; result = 'Win95.Marburg' }
            Microsoft = [pscustomobject]@{ category = 'undetected'; engine_name = 'Microsoft'; result = $null }
            Google    = [pscustomobject]@{ category = 'undetected'; engine_name = 'Google'; result = $null }
        }
    }

    It 'ignore-only: drops VirIT so policy Malicious=0' {
        $p = Get-HmdPolicyStatsFromResults -AnalysisResults $chromeResults `
            -IgnoreEngines @('VirIT') `
            -RawMalicious 1 -RawSuspicious 0 -RawUndetected 2 -RawHarmless 0
        $p.Malicious | Should -Be 0
        $p.Undetected | Should -Be 2
        $p.PolicyFromResults | Should -BeTrue
        $p.IgnoredEngines | Should -Contain 'VirIT'
        Get-HmdVerdictFromStats -Malicious $p.Malicious -Suspicious $p.Suspicious `
            -Undetected $p.Undetected -Known | Should -Be 'Clean'
    }

    It 'ignore is case-insensitive' {
        $p = Get-HmdPolicyStatsFromResults -AnalysisResults $chromeResults `
            -IgnoreEngines @('virit') `
            -RawMalicious 1 -RawSuspicious 0 -RawUndetected 2 -RawHarmless 0
        $p.Malicious | Should -Be 0
        $p.IgnoredEngines | Should -Contain 'VirIT'
    }

    It 'both: ignore one of two malicious + threshold=2 → Clean' {
        $results = [pscustomobject]@{
            VirIT  = [pscustomobject]@{ category = 'malicious'; engine_name = 'VirIT' }
            Other  = [pscustomobject]@{ category = 'malicious'; engine_name = 'Other' }
            Clean1 = [pscustomobject]@{ category = 'undetected'; engine_name = 'Clean1' }
        }
        $p = Get-HmdPolicyStatsFromResults -AnalysisResults $results `
            -IgnoreEngines @('VirIT') `
            -RawMalicious 2 -RawSuspicious 0 -RawUndetected 1 -RawHarmless 0
        $p.Malicious | Should -Be 1
        Get-HmdVerdictFromStats -Malicious $p.Malicious -Suspicious $p.Suspicious `
            -Undetected $p.Undetected -Known -MaliciousThreshold 2 |
            Should -Be 'Clean'
        Get-HmdVerdictFromStats -Malicious $p.Malicious -Suspicious $p.Suspicious `
            -Undetected $p.Undetected -Known -MaliciousThreshold 1 |
            Should -Be 'Malicious'
    }

    It 'falls back to raw stats when IgnoreEngines empty' {
        $p = Get-HmdPolicyStatsFromResults -AnalysisResults $chromeResults `
            -IgnoreEngines @() `
            -RawMalicious 1 -RawSuspicious 0 -RawUndetected 65 -RawHarmless 0
        $p.Malicious | Should -Be 1
        $p.PolicyFromResults | Should -BeFalse
        $p.IgnoredEngines.Count | Should -Be 0
    }

    It 'falls back to raw when results missing but ignore configured' {
        $p = Get-HmdPolicyStatsFromResults -AnalysisResults $null `
            -IgnoreEngines @('VirIT') `
            -RawMalicious 1 -RawSuspicious 0 -RawUndetected 65 -RawHarmless 0
        $p.Malicious | Should -Be 1
        $p.PolicyFromResults | Should -BeFalse
        $p.IgnoredEngines.Count | Should -Be 0
    }
}

Describe 'Cache TTL and checkpoint' {
    It 'Test-HmdCacheEntryFresh respects TTL' {
        $old = (Get-Date).AddDays(-10)
        Test-HmdCacheEntryFresh -CachedAt $old -TtlDays 7 | Should -BeFalse
        Test-HmdCacheEntryFresh -CachedAt (Get-Date) -TtlDays 7 | Should -BeTrue
    }

    It 'round-trips hash cache' {
        $path = Join-Path $TestDrive 'hashcache.csv'
        $cache = @{
            'abc' = [pscustomobject]@{
                Sha256 = 'abc'; Verdict = 'Clean'; Malicious = 0
                Suspicious = 0; Undetected = 10; Harmless = 5; CachedAt = Get-Date; Source = 'test'
            }
        }
        Export-HmdHashCache -Cache $cache -Path $path
        $loaded = Import-HmdHashCache -Path $path
        $loaded['abc'].Verdict | Should -Be 'Clean'
        $loaded['abc'].Harmless | Should -Be 5
    }

    It 'round-trips checkpoint' {
        $path = Join-Path $TestDrive 'checkpoint.json'
        $set = [System.Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
        $null = $set.Add('https://x')
        Save-HmdCheckpoint -CompletedUrls $set -Path $path
        $loaded = Import-HmdCheckpoint -Path $path
        $loaded.Contains('https://x') | Should -BeTrue
    }
}

Describe 'ConvertTo-HmdFlatArray' {
    It 'unwraps a single nested array' {
        $inner = [string[]]@('a', 'b')
        $nested = [object[]]@($inner)
        $flat = ConvertTo-HmdFlatArray -InputObject $nested
        $flat.Count | Should -Be 2
        $flat[0] | Should -Be 'a'
    }
}

Describe 'Get-HmdSafeFileName' {
    It 'prefixes by default' {
        Get-HmdSafeFileName -Url 'https://mock.example/clean.bin' -Index 3 |
            Should -Be '0003_clean.bin'
    }

    It 'omits prefix when PrefixFileNames is false' {
        Get-HmdSafeFileName -Url 'https://mock.example/clean.bin' -Index 3 `
            -PrefixFileNames $false |
            Should -Be 'clean.bin'
    }

    It 'disambiguates collisions without prefix' {
        $occ = @{ 'clean.bin' = $true }
        Get-HmdSafeFileName -Url 'https://mock.example/clean.bin' -Index 2 `
            -PrefixFileNames $false -OccupiedNames $occ |
            Should -Be 'clean_2.bin'
    }
}

Describe 'Import-HmdDeployMap' {
    It 'parses sectioned TXT with @ destinations' {
        $tmp = Join-Path $TestDrive 'deploy.txt'
        @"
# comment
@C:\App1
tool.exe
helper.dll

@D:\Bin
tool.exe
"@ | Set-Content -LiteralPath $tmp -Encoding utf8
        $rows = @(Import-HmdDeployMap -Path $tmp)
        $rows.Count | Should -Be 3
        $rows[0].Destination | Should -Be 'C:\App1'
        $rows[0].File | Should -Be 'tool.exe'
        $rows[2].Destination | Should -Be 'D:\Bin'
    }

    It 'parses CSV Destination,File' {
        $tmp = Join-Path $TestDrive 'deploy.csv'
        @"
Destination,File
C:\App1,a.exe
D:\Bin,b.exe
"@ | Set-Content -LiteralPath $tmp -Encoding utf8
        $rows = @(Import-HmdDeployMap -Path $tmp)
        $rows.Count | Should -Be 2
        $rows[1].File | Should -Be 'b.exe'
    }
}

Describe 'Test-HmdDeployPatternIsGlob' {
    It 'detects * and ?' {
        Test-HmdDeployPatternIsGlob -Pattern '*.pgi' | Should -BeTrue
        Test-HmdDeployPatternIsGlob -Pattern 'file?.dll' | Should -BeTrue
        Test-HmdDeployPatternIsGlob -Pattern 'program.exe' | Should -BeFalse
    }
}

Describe 'Copy-HmdCleanDeploy globs' {
    It 'copies exact exe to one folder and *.pgi plugins to another' {
        $work = Join-Path $TestDrive 'glob-work'
        $null = Initialize-HmdWorkRoot -WorkRoot $work
        $cleanDir = Join-Path $work 'Clean'
        $appDir = Join-Path $TestDrive 'app'
        $plugDir = Join-Path $TestDrive 'plugins'
        Set-Content -LiteralPath (Join-Path $cleanDir 'program.exe') -Value 'exe' -Encoding utf8
        Set-Content -LiteralPath (Join-Path $cleanDir 'a.pgi') -Value 'p1' -Encoding utf8
        Set-Content -LiteralPath (Join-Path $cleanDir 'b.pgi') -Value 'p2' -Encoding utf8
        Set-Content -LiteralPath (Join-Path $cleanDir 'readme.txt') -Value 'x' -Encoding utf8

        $records = @(
            [pscustomobject]@{
                Verdict = 'Clean'; FileName = 'program.exe'; Url = 'https://mock.example/program.exe'
                LocalPath = (Join-Path $cleanDir 'program.exe')
            }
            [pscustomobject]@{
                Verdict = 'Clean'; FileName = 'a.pgi'; Url = 'https://mock.example/a.pgi'
                LocalPath = (Join-Path $cleanDir 'a.pgi')
            }
            [pscustomobject]@{
                Verdict = 'Clean'; FileName = 'b.pgi'; Url = 'https://mock.example/b.pgi'
                LocalPath = (Join-Path $cleanDir 'b.pgi')
            }
            [pscustomobject]@{
                Verdict = 'Clean'; FileName = 'readme.txt'; Url = 'https://mock.example/readme.txt'
                LocalPath = (Join-Path $cleanDir 'readme.txt')
            }
        )
        $map = @(
            [pscustomobject]@{ Destination = $appDir; File = 'program.exe' }
            [pscustomobject]@{ Destination = $plugDir; File = '*.pgi' }
        )

        $r = Copy-HmdCleanDeploy -Records $records -MapRows $map -WorkRoot $work
        $r.DeployedCount | Should -Be 3
        $r.DeployMissCount | Should -Be 0
        Test-Path -LiteralPath (Join-Path $appDir 'program.exe') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $plugDir 'a.pgi') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $plugDir 'b.pgi') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $plugDir 'readme.txt') | Should -BeFalse
    }

    It 'matches *.pgi against NNNN_ prefixed Clean names' {
        $work = Join-Path $TestDrive 'glob-prefix'
        $null = Initialize-HmdWorkRoot -WorkRoot $work
        $cleanDir = Join-Path $work 'Clean'
        $plugDir = Join-Path $TestDrive 'plugins-pfx'
        Set-Content -LiteralPath (Join-Path $cleanDir '0002_plug.pgi') -Value 'p' -Encoding utf8
        $records = @(
            [pscustomobject]@{
                Verdict = 'Clean'; FileName = '0002_plug.pgi'; Url = 'https://mock.example/plug.pgi'
                LocalPath = (Join-Path $cleanDir '0002_plug.pgi')
            }
        )
        $map = @([pscustomobject]@{ Destination = $plugDir; File = '*.pgi' })
        $r = Copy-HmdCleanDeploy -Records $records -MapRows $map -WorkRoot $work
        $r.DeployedCount | Should -Be 1
        Test-Path -LiteralPath (Join-Path $plugDir 'plug.pgi') | Should -BeTrue
    }
}

Describe 'Invoke-HmdBulkDownload with mocks' {
    It 'downloads, classifies Clean via mocked VT, and resumes' {
        $work = Join-Path $TestDrive 'run1'
        $input = Join-Path $TestDrive 'in.txt'
        "https://mock.example/clean.bin" | Set-Content -LiteralPath $input -Encoding utf8

        $downloadInvoker = {
            param($req)
            $bytes = [Text.Encoding]::UTF8.GetBytes('clean-payload')
            [IO.File]::WriteAllBytes($req.OutFile, $bytes)
            [pscustomobject]@{
                StatusCode  = 200
                ContentType = 'application/octet-stream'
                Bytes       = $bytes.Length
            }
        }

        $vtInvoker = {
            param($req)
            if ($req.Method -eq 'GET' -and $req.Uri -match '/files/') {
                return [pscustomobject]@{
                    data = [pscustomobject]@{
                        attributes = [pscustomobject]@{
                            last_analysis_stats = [pscustomobject]@{
                                malicious  = 0
                                suspicious = 0
                                undetected = 40
                                harmless   = 20
                            }
                        }
                    }
                }
            }
            throw "Unexpected VT call: $($req.Method) $($req.Uri)"
        }

        # SecureString placeholder — Resolve-HmdApiKey still used unless SkipVirusTotal
        $sec = ConvertTo-SecureString 'test-key' -AsPlainText -Force
        $r1 = Invoke-HmdBulkDownload -InputPath $input -WorkRoot $work `
            -ApiKey $sec -VtInvoker $vtInvoker -DownloadInvoker $downloadInvoker `
            -ConfigOverride @{
                ApiDelaySeconds = 0; GenerateReport = $true; DisplaySummary = $false; DisplayProgress = $false
                DisplayScanLog = $false; LocalAvScanEnabled = $false
            }

        $r1.ProcessedCount | Should -Be 1
        $r1.Records[0].Verdict | Should -Be 'Clean'
        [int]$r1.Records[0].Harmless | Should -Be 20
        [int]$r1.Records[0].Undetected | Should -Be 40
        $r1.HarmlessSum | Should -Be 20
        $r1.UndetectedSum | Should -Be 40
        Test-Path -LiteralPath $r1.Report | Should -BeTrue
        @(Get-ChildItem -LiteralPath (Join-Path $work 'Clean')).Count | Should -Be 1
        $scanCsv = Import-Csv -LiteralPath $r1.ScanLog
        $scanCsv[0].Harmless | Should -Be '20'
        $cacheCsv = Import-Csv -LiteralPath $r1.HashCache
        $cacheCsv[0].Harmless | Should -Be '20'

        # Resume: same URL should be skipped
        $r2 = Invoke-HmdBulkDownload -InputPath $input -WorkRoot $work `
            -ApiKey $sec -VtInvoker $vtInvoker -DownloadInvoker $downloadInvoker `
            -ConfigOverride @{
                ApiDelaySeconds = 0; DisplaySummary = $false; DisplayProgress = $false; DisplayScanLog = $false
                LocalAvScanEnabled = $false
            }
        $r2.QueuedCount | Should -Be 0
        $r2.ProcessedCount | Should -Be 0
    }

    It 'omits NNNN_ prefix and deploys Clean files from map' {
        $work = Join-Path $TestDrive 'run-deploy'
        $input = Join-Path $TestDrive 'deploy-in.txt'
        $map = Join-Path $TestDrive 'deploy-map.txt'
        $dest1 = Join-Path $TestDrive 'dest\app1'
        $dest2 = Join-Path $TestDrive 'dest\shared'
        "https://mock.example/tool.exe" | Set-Content -LiteralPath $input -Encoding utf8
        @"
@$dest1
tool.exe

@$dest2
tool.exe
"@ | Set-Content -LiteralPath $map -Encoding utf8

        $downloadInvoker = {
            param($req)
            $bytes = [Text.Encoding]::UTF8.GetBytes('tool-payload')
            [IO.File]::WriteAllBytes($req.OutFile, $bytes)
            [pscustomobject]@{ StatusCode = 200; ContentType = 'application/octet-stream'; Bytes = $bytes.Length }
        }
        $vtInvoker = {
            param($req)
            return [pscustomobject]@{
                data = [pscustomobject]@{
                    attributes = [pscustomobject]@{
                        last_analysis_stats = [pscustomobject]@{
                            malicious = 0; suspicious = 0; undetected = 40; harmless = 10
                        }
                    }
                }
            }
        }

        $sec = ConvertTo-SecureString 'test-key' -AsPlainText -Force
        $r = Invoke-HmdBulkDownload -InputPath $input -WorkRoot $work `
            -ApiKey $sec -VtInvoker $vtInvoker -DownloadInvoker $downloadInvoker `
            -NoFileNamePrefix -DeployMapPath $map `
            -ConfigOverride @{
                ApiDelaySeconds = 0; GenerateReport = $false; DisplaySummary = $false; DisplayProgress = $false
                DisplayScanLog = $false; LocalAvScanEnabled = $false
            }

        $r.Records[0].FileName | Should -Be 'tool.exe'
        $r.PrefixFileNames | Should -BeFalse
        $r.DeployedCount | Should -Be 2
        $r.DeployMissCount | Should -Be 0
        Test-Path -LiteralPath (Join-Path $dest1 'tool.exe') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $dest2 'tool.exe') | Should -BeTrue
        # Clean/ still holds the audit copy
        Test-Path -LiteralPath (Join-Path $work 'Clean\tool.exe') | Should -BeTrue
        Test-Path -LiteralPath $r.DeployLog | Should -BeTrue
    }

    It 'classifies Malicious and quarantines' {
        $work = Join-Path $TestDrive 'run-mal'
        $input = Join-Path $TestDrive 'mal.txt'
        "https://mock.example/bad.bin" | Set-Content -LiteralPath $input -Encoding utf8

        $downloadInvoker = {
            param($req)
            $bytes = [Text.Encoding]::UTF8.GetBytes('bad-payload-unique')
            [IO.File]::WriteAllBytes($req.OutFile, $bytes)
            [pscustomobject]@{ StatusCode = 200; ContentType = 'application/octet-stream'; Bytes = $bytes.Length }
        }
        $vtInvoker = {
            param($req)
            return [pscustomobject]@{
                data = [pscustomobject]@{
                    attributes = [pscustomobject]@{
                        last_analysis_stats = [pscustomobject]@{
                            malicious = 5; suspicious = 1; undetected = 30; harmless = 0
                        }
                    }
                }
            }
        }

        $sec = ConvertTo-SecureString 'test-key' -AsPlainText -Force
        $r = Invoke-HmdBulkDownload -InputPath $input -WorkRoot $work `
            -ApiKey $sec -VtInvoker $vtInvoker -DownloadInvoker $downloadInvoker `
            -ConfigOverride @{
                ApiDelaySeconds = 0; QuarantineMalicious = $true; DisplaySummary = $false; DisplayProgress = $false
                DisplayScanLog = $false; LocalAvScanEnabled = $false
            }

        $r.Records[0].Verdict | Should -Be 'Malicious'
        @(Get-ChildItem -LiteralPath (Join-Path $work 'Malicious')).Count | Should -Be 1
        @(Get-ChildItem -LiteralPath (Join-Path $work 'Quarantine')).Count | Should -Be 1
    }

    It 'IgnoreEngines VirIT → Clean while raw Malicious stays 1 (HMD-025)' {
        $work = Join-Path $TestDrive 'run-ignore-virit'
        $input = Join-Path $TestDrive 'ignore-virit.txt'
        "https://mock.example/chromedriver.zip" | Set-Content -LiteralPath $input -Encoding utf8

        $downloadInvoker = {
            param($req)
            $bytes = [Text.Encoding]::UTF8.GetBytes('chromedriver-zip-unique-payload')
            [IO.File]::WriteAllBytes($req.OutFile, $bytes)
            [pscustomobject]@{ StatusCode = 200; ContentType = 'application/zip'; Bytes = $bytes.Length }
        }
        $vtInvoker = {
            param($req)
            return [pscustomobject]@{
                data = [pscustomobject]@{
                    attributes = [pscustomobject]@{
                        last_analysis_stats = [pscustomobject]@{
                            malicious = 1; suspicious = 0; undetected = 65; harmless = 0
                        }
                        last_analysis_results = [pscustomobject]@{
                            VirIT = [pscustomobject]@{
                                category = 'malicious'; engine_name = 'VirIT'; result = 'Win95.Marburg'
                            }
                            Microsoft = [pscustomobject]@{
                                category = 'undetected'; engine_name = 'Microsoft'; result = $null
                            }
                        }
                    }
                }
            }
        }

        $sec = ConvertTo-SecureString 'test-key' -AsPlainText -Force
        $r = Invoke-HmdBulkDownload -InputPath $input -WorkRoot $work `
            -ApiKey $sec -VtInvoker $vtInvoker -DownloadInvoker $downloadInvoker `
            -ConfigOverride @{
                ApiDelaySeconds     = 0
                IgnoreEngines       = @('VirIT')
                QuarantineMalicious = $true
                DisplaySummary      = $false
                DisplayProgress     = $false
                DisplayScanLog      = $false
                GenerateReport      = $false
                LocalAvScanEnabled  = $false
            }

        $r.Records[0].Verdict | Should -Be 'Clean'
        $r.Records[0].Malicious | Should -Be 1
        $r.Records[0].IgnoredEngines | Should -Be 'VirIT'
        @(Get-ChildItem -LiteralPath (Join-Path $work 'Clean')).Count | Should -Be 1
        @(Get-ChildItem -LiteralPath (Join-Path $work 'Quarantine') -ErrorAction SilentlyContinue).Count |
            Should -Be 0
    }

    It 'processes two URLs as two records (no download-result nest)' {
        $work = Join-Path $TestDrive 'run-two'
        $input = Join-Path $TestDrive 'two.txt'
        @"
https://mock.example/a.bin
https://mock.example/b.bin
"@ | Set-Content -LiteralPath $input -Encoding utf8

        $downloadInvoker = {
            param($req)
            $bytes = [Text.Encoding]::UTF8.GetBytes("payload-$($req.Url)")
            [IO.File]::WriteAllBytes($req.OutFile, $bytes)
            [pscustomobject]@{ StatusCode = 200; ContentType = 'application/octet-stream'; Bytes = $bytes.Length }
        }
        $vtInvoker = {
            param($req)
            return [pscustomobject]@{
                data = [pscustomobject]@{
                    attributes = [pscustomobject]@{
                        last_analysis_stats = [pscustomobject]@{
                            malicious = 0; suspicious = 0; undetected = 40; harmless = 10
                        }
                    }
                }
            }
        }

        $sec = ConvertTo-SecureString 'test-key' -AsPlainText -Force
        $r = Invoke-HmdBulkDownload -InputPath $input -WorkRoot $work `
            -ApiKey $sec -VtInvoker $vtInvoker -DownloadInvoker $downloadInvoker `
            -ConfigOverride @{
                ApiDelaySeconds = 0; GenerateReport = $false; DisplaySummary = $false; DisplayProgress = $false
                DisplayScanLog = $false; LocalAvScanEnabled = $false
            }

        $r.InputCount | Should -Be 2
        $r.ProcessedCount | Should -Be 2
        $r.Records.Count | Should -Be 2
        $r.Records[0].Url | Should -BeOfType ([string])
        $r.Records[0].Verdict | Should -Be 'Clean'
        $r.Records[1].Verdict | Should -Be 'Clean'
    }

    It 'harvests deploy-map URL, matches by full URL, deploy-map-only (HMD-027)' {
        $work = Join-Path $TestDrive 'run-harvest'
        $map = Join-Path $TestDrive 'harvest-map.txt'
        $dest = Join-Path $TestDrive 'harvest-dest'
        $url = 'https://mock.example/harvested.zip'
        @"
@$dest
$url
extra-leaf.bin
"@ | Set-Content -LiteralPath $map -Encoding utf8

        $downloadInvoker = {
            param($req)
            $bytes = [Text.Encoding]::UTF8.GetBytes('harvested-zip-bytes')
            [IO.File]::WriteAllBytes($req.OutFile, $bytes)
            [pscustomobject]@{ StatusCode = 200; ContentType = 'application/zip'; Bytes = $bytes.Length }
        }
        $vtInvoker = {
            param($req)
            return [pscustomobject]@{
                data = [pscustomobject]@{
                    attributes = [pscustomobject]@{
                        last_analysis_stats = [pscustomobject]@{
                            malicious = 0; suspicious = 0; undetected = 40; harmless = 5
                        }
                    }
                }
            }
        }
        $avClean = {
            param($req)
            [pscustomobject]@{ Status = 'Clean'; ThreatName = ''; Provider = 'Defender' }
        }

        $sec = ConvertTo-SecureString 'test-key' -AsPlainText -Force
        $r = Invoke-HmdBulkDownload -DeployMapPath $map -WorkRoot $work `
            -ApiKey $sec -VtInvoker $vtInvoker -DownloadInvoker $downloadInvoker `
            -LocalAvInvoker $avClean -NoFileNamePrefix `
            -ConfigOverride @{ ApiDelaySeconds = 0; GenerateReport = $false; DisplaySummary = $false; DisplayProgress = $false; DisplayScanLog = $false }

        $r.InputCount | Should -Be 1
        $r.ProcessedCount | Should -Be 1
        $r.Records[0].Url | Should -Be $url
        $r.Records[0].Verdict | Should -Be 'Clean'
        $r.Records[0].DefenderStatus | Should -Be 'Clean'
        $r.DeployedCount | Should -Be 1
        $r.DeployMissCount | Should -Be 1
        Test-Path -LiteralPath (Join-Path $dest 'harvested.zip') | Should -BeTrue
    }

    It 'LocalAv Threat → Malicious hard gate, no deploy (HMD-026)' {
        $work = Join-Path $TestDrive 'run-av-threat'
        $input = Join-Path $TestDrive 'av-threat.txt'
        $map = Join-Path $TestDrive 'av-threat-map.txt'
        $dest = Join-Path $TestDrive 'av-threat-dest'
        $url = 'https://mock.example/evil.bin'
        $url | Set-Content -LiteralPath $input -Encoding utf8
        @"
@$dest
evil.bin
"@ | Set-Content -LiteralPath $map -Encoding utf8

        $downloadInvoker = {
            param($req)
            $bytes = [Text.Encoding]::UTF8.GetBytes('evil-payload')
            [IO.File]::WriteAllBytes($req.OutFile, $bytes)
            [pscustomobject]@{ StatusCode = 200; ContentType = 'application/octet-stream'; Bytes = $bytes.Length }
        }
        $vtInvoker = {
            param($req)
            throw 'VT must not be called after LocalAv threat'
        }
        $avThreat = {
            param($req)
            [pscustomobject]@{ Status = 'Threat'; ThreatName = 'Test:EICAR'; Provider = 'Defender' }
        }

        $sec = ConvertTo-SecureString 'test-key' -AsPlainText -Force
        $r = Invoke-HmdBulkDownload -InputPath $input -WorkRoot $work -DeployMapPath $map `
            -ApiKey $sec -VtInvoker $vtInvoker -DownloadInvoker $downloadInvoker `
            -LocalAvInvoker $avThreat -NoFileNamePrefix `
            -ConfigOverride @{
                ApiDelaySeconds = 0; GenerateReport = $false; DisplaySummary = $false; DisplayProgress = $false
                DisplayScanLog = $false; QuarantineMalicious = $true
            }

        $r.Records[0].Verdict | Should -Be 'Malicious'
        $r.Records[0].DefenderStatus | Should -Be 'Threat'
        $r.Records[0].DefenderThreat | Should -Be 'Test:EICAR'
        $r.DeployedCount | Should -Be 0
        @(Get-ChildItem -LiteralPath (Join-Path $work 'Malicious')).Count | Should -Be 1
        @(Get-ChildItem -LiteralPath (Join-Path $work 'Quarantine')).Count | Should -Be 1
        Test-Path -LiteralPath (Join-Path $dest 'evil.bin') | Should -BeFalse
    }

    It 'LocalAv Unavailable → Error verdict (HMD-026)' {
        $work = Join-Path $TestDrive 'run-av-unavail'
        $input = Join-Path $TestDrive 'av-unavail.txt'
        "https://mock.example/file.bin" | Set-Content -LiteralPath $input -Encoding utf8

        $downloadInvoker = {
            param($req)
            $bytes = [Text.Encoding]::UTF8.GetBytes('file-payload')
            [IO.File]::WriteAllBytes($req.OutFile, $bytes)
            [pscustomobject]@{ StatusCode = 200; ContentType = 'application/octet-stream'; Bytes = $bytes.Length }
        }
        $vtInvoker = {
            param($req)
            throw 'VT must not be called after LocalAv Unavailable'
        }
        $avUnavail = {
            param($req)
            [pscustomobject]@{
                Status = 'Unavailable'; ThreatName = ''; Provider = 'Defender'; Raw = 'no scanner'
            }
        }

        $sec = ConvertTo-SecureString 'test-key' -AsPlainText -Force
        $r = Invoke-HmdBulkDownload -InputPath $input -WorkRoot $work `
            -ApiKey $sec -VtInvoker $vtInvoker -DownloadInvoker $downloadInvoker `
            -LocalAvInvoker $avUnavail `
            -ConfigOverride @{ ApiDelaySeconds = 0; GenerateReport = $false; DisplaySummary = $false; DisplayProgress = $false; DisplayScanLog = $false }

        $r.Records[0].Verdict | Should -Be 'Error'
        $r.Records[0].DefenderStatus | Should -Be 'Unavailable'
        @(Get-ChildItem -LiteralPath (Join-Path $work 'Error')).Count | Should -Be 1
    }
}

Describe 'Get-HmdUrlsFromDeployMap and match keys (HMD-027)' {
    It 'Test-HmdHttpUrl detects schemes' {
        Test-HmdHttpUrl -Value 'https://a.example/x' | Should -BeTrue
        Test-HmdHttpUrl -Value 'HTTP://a.example/x' | Should -BeTrue
        Test-HmdHttpUrl -Value 'tool.exe' | Should -BeFalse
    }

    It 'harvests unique http(s) File entries in order' {
        $rows = @(
            [pscustomobject]@{ Destination = 'D:\a'; File = 'https://a.example/one.zip' }
            [pscustomobject]@{ Destination = 'D:\a'; File = 'leaf.bin' }
            [pscustomobject]@{ Destination = 'D:\b'; File = 'https://a.example/one.zip' }
            [pscustomobject]@{ Destination = 'D:\b'; File = 'https://b.example/two.zip' }
        )
        $urls = @(Get-HmdUrlsFromDeployMap -MapRows $rows)
        $urls.Count | Should -Be 2
        $urls[0] | Should -Be 'https://a.example/one.zip'
        $urls[1] | Should -Be 'https://b.example/two.zip'
    }

    It 'Get-HmdDeployMatchKeys includes full URL' {
        $keys = @(Get-HmdDeployMatchKeys -FileName '0000_one.zip' -Url 'https://a.example/one.zip')
        $keys | Should -Contain 'https://a.example/one.zip'
        $keys | Should -Contain 'one.zip'
        $keys | Should -Contain '0000_one.zip'
    }

    It 'Copy-HmdCleanDeploy matches full URL map entry' {
        $work = Join-Path $TestDrive 'url-match-work'
        $null = Initialize-HmdWorkRoot -WorkRoot $work
        $cleanDir = Join-Path $work 'Clean'
        $dest = Join-Path $TestDrive 'url-match-dest'
        Set-Content -LiteralPath (Join-Path $cleanDir '0000_one.zip') -Value 'z' -Encoding utf8
        $url = 'https://downloads.jee.com/example.zip'
        $records = @(
            [pscustomobject]@{
                Verdict = 'Clean'; FileName = '0000_one.zip'; Url = $url
                LocalPath = (Join-Path $cleanDir '0000_one.zip')
            }
        )
        $map = @([pscustomobject]@{ Destination = $dest; File = $url })
        $r = Copy-HmdCleanDeploy -Records $records -MapRows $map -WorkRoot $work
        $r.DeployedCount | Should -Be 1
        Test-Path -LiteralPath (Join-Path $dest 'example.zip') | Should -BeTrue
    }
}

Describe 'Invoke-HmdLocalAvScan invoker (HMD-026)' {
    It 'returns invoker Status/ThreatName' {
        $tmp = Join-Path $TestDrive 'av-dummy.bin'
        'x' | Set-Content -LiteralPath $tmp -Encoding utf8
        $r = Invoke-HmdLocalAvScan -Path $tmp -Invoker {
            param($req)
            [pscustomobject]@{ Status = 'Threat'; ThreatName = 'X'; Provider = 'Defender' }
        }
        $r.Status | Should -Be 'Threat'
        $r.ThreatName | Should -Be 'X'
    }
}

Describe 'Archive inspection helpers (HMD-006)' {
    BeforeAll {
        Add-Type -AssemblyName System.IO.Compression
        Add-Type -AssemblyName System.IO.Compression.FileSystem
    }

    It 'Test-HmdIsArchivePath matches zip/jar/hpi/jpi' {
        Test-HmdIsArchivePath -Path 'C:\x\plugin.hpi' | Should -BeTrue
        Test-HmdIsArchivePath -Path 'C:\x\tool.JAR' | Should -BeTrue
        Test-HmdIsArchivePath -Path 'C:\x\a.zip' | Should -BeTrue
        Test-HmdIsArchivePath -Path 'C:\x\a.jpi' | Should -BeTrue
        Test-HmdIsArchivePath -Path 'C:\x\a.exe' | Should -BeFalse
    }

    It 'Test-HmdIsArchiveScanRow detects #archive/ FileName' {
        Test-HmdIsArchiveScanRow -FileName '#archive/lib/x.dll' | Should -BeTrue
        Test-HmdIsArchiveScanRow -FileName '0000_tool.zip' | Should -BeFalse
    }

    It 'ConvertTo-HmdScanLogRow keeps ArchiveInterestReason' {
        $row = ConvertTo-HmdScanLogRow -InputObject ([pscustomobject]@{
                Url                   = 'https://a.example/x.zip'
                FileName              = '#archive/bin/a.exe'
                LocalPath             = 'C:\insp\a.exe'
                Sha256                = 'abc'
                Verdict               = 'Unknown'
                ArchiveInterestReason = 'ext:.exe'
            })
        $row.ArchiveInterestReason | Should -Be 'ext:.exe'
        $row.Malicious | Should -Be 0
        $row.FileName | Should -Be '#archive/bin/a.exe'
    }

    It 'Export-HmdScanLogCsv deletes the file when there are no rows' {
        $p = Join-Path $TestDrive 'empty-scan.csv'
        'stale' | Set-Content -LiteralPath $p -Encoding utf8
        Export-HmdScanLogCsv -Records @() -Path $p
        (Test-Path -LiteralPath $p) | Should -BeFalse
    }

    It 'Get-HmdMergedVerdict picks worst' {
        Get-HmdMergedVerdict -Verdicts @('Clean', 'Suspicious') | Should -Be 'Suspicious'
        Get-HmdMergedVerdict -Verdicts @('Clean', 'Malicious', 'Error') | Should -Be 'Malicious'
        Get-HmdMergedVerdict -Verdicts @('Unknown', 'Clean') | Should -Be 'Unknown'
    }

    It 'rejects zip-slip entries' {
        $zip = Join-Path $TestDrive 'slip.zip'
        $dest = Join-Path $TestDrive 'slip-out'
        $null = New-Item -ItemType Directory -Force -Path $dest
        if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
        $fs = [System.IO.File]::Open($zip, [System.IO.FileMode]::CreateNew)
        try {
            $za = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create)
            try {
                $e = $za.CreateEntry('../evil.txt')
                $es = $e.Open()
                try {
                    $bytes = [Text.Encoding]::UTF8.GetBytes('evil')
                    $es.Write($bytes, 0, $bytes.Length)
                }
                finally { $es.Dispose() }
            }
            finally { $za.Dispose() }
        }
        finally { $fs.Dispose() }

        $r = Expand-HmdArchiveSafe -ArchivePath $zip -DestinationRoot $dest -MaxMembers 50
        $r.Success | Should -BeFalse
        $r.Error | Should -Match 'zip-slip|unsafe'
    }

    It 'hashes members without VT when HashOnly' {
        $zip = Join-Path $TestDrive 'members.zip'
        $work = Join-Path $TestDrive 'arch-work'
        $null = Initialize-HmdWorkRoot -WorkRoot $work
        if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
        $fs = [System.IO.File]::Open($zip, [System.IO.FileMode]::CreateNew)
        try {
            $za = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create)
            try {
                $e = $za.CreateEntry('inner/hello.txt')
                $es = $e.Open()
                try {
                    $bytes = [Text.Encoding]::UTF8.GetBytes('hello-archive')
                    $es.Write($bytes, 0, $bytes.Length)
                }
                finally { $es.Dispose() }
            }
            finally { $za.Dispose() }
        }
        finally { $fs.Dispose() }

        $insp = Invoke-HmdArchiveInspect -ArchivePath $zip -WorkRoot $work `
            -ParentFileName '0000_members.zip' -ParentSha256 'abc' -MaxMembers 50
        $insp.Success | Should -BeTrue
        $insp.Members.Count | Should -Be 1
        $insp.Members[0].EntryName | Should -Be 'inner/hello.txt'
        $insp.Members[0].Sha256 | Should -Match '^[0-9a-f]{64}$'
        Test-Path -LiteralPath $insp.Members[0].LocalPath | Should -BeTrue
    }

    It 'Resolve-HmdArchiveVtMode maps HashOnly and explicit mode' {
        Resolve-HmdArchiveVtMode -Config ([pscustomobject]@{ ArchiveContentsHashOnly = $true }) |
            Should -Be 'None'
        Resolve-HmdArchiveVtMode -Config ([pscustomobject]@{ ArchiveContentsHashOnly = $false }) |
            Should -Be 'All'
        Resolve-HmdArchiveVtMode -Config ([pscustomobject]@{
                ArchiveVtMode = 'Interesting'; ArchiveContentsHashOnly = $true
            }) | Should -Be 'Interesting'
    }

    It 'Get-HmdArchiveMemberInterest matches ext, path, mz' {
        $txt = Get-HmdArchiveMemberInterest -EntryName 'docs/readme.txt' -CheckMz:$false
        $txt.Interesting | Should -BeFalse

        $exe = Get-HmdArchiveMemberInterest -EntryName 'tools/app.EXE' -CheckMz:$false
        $exe.Interesting | Should -BeTrue
        $exe.Reason | Should -Match 'ext:\.exe'

        $pathHit = Get-HmdArchiveMemberInterest -EntryName 'plugins/note.md' -CheckMz:$false
        $pathHit.Interesting | Should -BeTrue
        $pathHit.Reason | Should -Match 'path:plugins/'

        $mzPath = Join-Path $TestDrive 'fake.bin'
        [IO.File]::WriteAllBytes($mzPath, [byte[]](0x4D, 0x5A, 0x90, 0x00))
        $mz = Get-HmdArchiveMemberInterest -EntryName 'data/payload.bin' `
            -LocalPath $mzPath -CheckMz:$true `
            -InterestingExtensions @('.exe') -PathKeywords @('zzz/')
        $mz.Interesting | Should -BeTrue
        $mz.Reason | Should -Match 'mz'
    }
}

Describe 'Invoke-HmdBulkDownload archive inspection (HMD-006)' {
    It 'is off by default (no #archive rows)' {
        $work = Join-Path $TestDrive 'arch-off'
        $input = Join-Path $TestDrive 'arch-off-urls.txt'
        $zip = Join-Path $TestDrive 'payload-off.zip'
        if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
        Add-Type -AssemblyName System.IO.Compression
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $fs = [System.IO.File]::Open($zip, [System.IO.FileMode]::CreateNew)
        try {
            $za = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create)
            try {
                $e = $za.CreateEntry('a.txt')
                $es = $e.Open()
                try {
                    $b = [Text.Encoding]::UTF8.GetBytes('x')
                    $es.Write($b, 0, $b.Length)
                }
                finally { $es.Dispose() }
            }
            finally { $za.Dispose() }
        }
        finally { $fs.Dispose() }
        'https://example.test/payload-off.zip' | Set-Content -LiteralPath $input -Encoding utf8

        $downloadInvoker = {
            param($req)
            Copy-Item -LiteralPath $zip -Destination $req.OutFile -Force
            [pscustomobject]@{
                StatusCode  = 200
                ContentType = 'application/zip'
                Bytes       = (Get-Item -LiteralPath $req.OutFile).Length
            }
        }
        $vtInvoker = {
            param($req)
            if ($req.Method -eq 'GET' -and $req.Uri -match '/files/') {
                return [pscustomobject]@{
                    data = [pscustomobject]@{
                        attributes = [pscustomobject]@{
                            last_analysis_stats = [pscustomobject]@{
                                malicious = 0; suspicious = 0; undetected = 10; harmless = 0
                            }
                            last_analysis_results = [pscustomobject]@{}
                        }
                    }
                }
            }
            throw "Unexpected VT call: $($req.Method) $($req.Uri)"
        }
        $avClean = {
            param($req)
            [pscustomobject]@{ Status = 'Clean'; ThreatName = ''; Provider = 'Defender'; Raw = '' }
        }
        $sec = ConvertTo-SecureString 'test-key' -AsPlainText -Force
        $r = Invoke-HmdBulkDownload -InputPath $input -WorkRoot $work `
            -ApiKey $sec -VtInvoker $vtInvoker -DownloadInvoker $downloadInvoker `
            -LocalAvInvoker $avClean `
            -ConfigOverride @{
                ApiDelaySeconds = 0; GenerateReport = $false
                DisplaySummary = $false; DisplayProgress = $false; DisplayScanLog = $false
                LocalAvScanEnabled = $true
            }
        @($r.Records | Where-Object { Test-HmdIsArchiveScanRow -FileName $_.FileName }).Count |
            Should -Be 0
    }

    It 'when enabled + hash-only: emits #archive rows and does not VT members' {
        $work = Join-Path $TestDrive 'arch-on'
        $input = Join-Path $TestDrive 'arch-on-urls.txt'
        $zip = Join-Path $TestDrive 'payload-on.zip'
        if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
        Add-Type -AssemblyName System.IO.Compression
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $fs = [System.IO.File]::Open($zip, [System.IO.FileMode]::CreateNew)
        try {
            $za = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create)
            try {
                $e = $za.CreateEntry('nested/a.txt')
                $es = $e.Open()
                try {
                    $b = [Text.Encoding]::UTF8.GetBytes('member-body')
                    $es.Write($b, 0, $b.Length)
                }
                finally { $es.Dispose() }
            }
            finally { $za.Dispose() }
        }
        finally { $fs.Dispose() }
        'https://example.test/payload-on.zip' | Set-Content -LiteralPath $input -Encoding utf8

        $script:hmdArchiveVtCalls = 0
        $downloadInvoker = {
            param($req)
            Copy-Item -LiteralPath $zip -Destination $req.OutFile -Force
            [pscustomobject]@{
                StatusCode  = 200
                ContentType = 'application/zip'
                Bytes       = (Get-Item -LiteralPath $req.OutFile).Length
            }
        }
        $vtInvoker = {
            param($req)
            if ($req.Method -eq 'GET' -and $req.Uri -match '/files/') {
                $script:hmdArchiveVtCalls++
                return [pscustomobject]@{
                    data = [pscustomobject]@{
                        attributes = [pscustomobject]@{
                            last_analysis_stats = [pscustomobject]@{
                                malicious = 0; suspicious = 0; undetected = 10; harmless = 0
                            }
                            last_analysis_results = [pscustomobject]@{}
                        }
                    }
                }
            }
            throw "Unexpected VT call: $($req.Method) $($req.Uri)"
        }
        $avClean = {
            param($req)
            [pscustomobject]@{ Status = 'Clean'; ThreatName = ''; Provider = 'Defender'; Raw = '' }
        }
        $sec = ConvertTo-SecureString 'test-key' -AsPlainText -Force
        $r = Invoke-HmdBulkDownload -InputPath $input -WorkRoot $work `
            -ApiKey $sec -VtInvoker $vtInvoker -DownloadInvoker $downloadInvoker `
            -LocalAvInvoker $avClean `
            -ConfigOverride @{
                ApiDelaySeconds = 0; GenerateReport = $false
                DisplaySummary = $false; DisplayProgress = $false; DisplayScanLog = $false
                ArchiveInspectionEnabled = $true
                ArchiveContentsHashOnly = $true
            }
        $arch = @($r.Records | Where-Object { Test-HmdIsArchiveScanRow -FileName $_.FileName })
        $arch.Count | Should -Be 1
        $arch[0].FileName | Should -Be '#archive/nested/a.txt'
        $arch[0].Verdict | Should -Be 'Unknown'
        $arch[0].Sha256 | Should -Match '^[0-9a-f]{64}$'
        # Only container hash lookup (one files/{sha} GET), not a second for the member.
        $script:hmdArchiveVtCalls | Should -Be 1
        $r.CleanCount | Should -Be 1
        $scanCsv = @(Import-Csv -LiteralPath (Join-Path $work 'logs\scanlog.csv'))
        @($scanCsv | Where-Object { Test-HmdIsArchiveScanRow -FileName $_.FileName }).Count |
            Should -Be 0
        $archCsv = @(Import-Csv -LiteralPath (Join-Path $work 'logs\archive-scanlog.csv'))
        $archCsv.Count | Should -Be 1
        $archCsv[0].FileName | Should -Be '#archive/nested/a.txt'
        $r.ArchiveScanLog | Should -Match 'archive-scanlog\.csv$'
    }
}

Describe 'Invoke-HmdBulkDownload selective archive VT (HMD-045)' {
    It 'Interesting mode VTs exe member only' {
        $work = Join-Path $TestDrive 'arch-interest'
        $input = Join-Path $TestDrive 'arch-interest-urls.txt'
        $zip = Join-Path $TestDrive 'payload-interest.zip'
        if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
        Add-Type -AssemblyName System.IO.Compression
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $fs = [System.IO.File]::Open($zip, [System.IO.FileMode]::CreateNew)
        try {
            $za = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create)
            try {
                foreach ($pair in @(
                        @{ Name = 'nested/readme.txt'; Body = 'boring' },
                        @{ Name = 'bin/tool.exe'; Body = 'MZ-fake-exe' }
                    )) {
                    $e = $za.CreateEntry($pair.Name)
                    $es = $e.Open()
                    try {
                        $b = [Text.Encoding]::UTF8.GetBytes($pair.Body)
                        $es.Write($b, 0, $b.Length)
                    }
                    finally { $es.Dispose() }
                }
            }
            finally { $za.Dispose() }
        }
        finally { $fs.Dispose() }
        'https://example.test/payload-interest.zip' | Set-Content -LiteralPath $input -Encoding utf8

        $script:hmdInterestVtHashes = [System.Collections.Generic.List[string]]::new()
        $downloadInvoker = {
            param($req)
            Copy-Item -LiteralPath $zip -Destination $req.OutFile -Force
            [pscustomobject]@{
                StatusCode  = 200
                ContentType = 'application/zip'
                Bytes       = (Get-Item -LiteralPath $req.OutFile).Length
            }
        }
        $vtInvoker = {
            param($req)
            if ($req.Method -eq 'GET' -and $req.Uri -match '/files/([0-9a-f]+)') {
                $script:hmdInterestVtHashes.Add($Matches[1]) | Out-Null
                return [pscustomobject]@{
                    data = [pscustomobject]@{
                        attributes = [pscustomobject]@{
                            last_analysis_stats = [pscustomobject]@{
                                malicious = 0; suspicious = 0; undetected = 10; harmless = 0
                            }
                            last_analysis_results = [pscustomobject]@{}
                        }
                    }
                }
            }
            throw "Unexpected VT call: $($req.Method) $($req.Uri)"
        }
        $avClean = {
            param($req)
            [pscustomobject]@{ Status = 'Clean'; ThreatName = ''; Provider = 'Defender'; Raw = '' }
        }
        $sec = ConvertTo-SecureString 'test-key' -AsPlainText -Force
        $r = Invoke-HmdBulkDownload -InputPath $input -WorkRoot $work `
            -ApiKey $sec -VtInvoker $vtInvoker -DownloadInvoker $downloadInvoker `
            -LocalAvInvoker $avClean `
            -ConfigOverride @{
                ApiDelaySeconds = 0; GenerateReport = $false
                DisplaySummary = $false; DisplayProgress = $false; DisplayScanLog = $false
                ArchiveInspectionEnabled = $true
                ArchiveVtMode = 'Interesting'
                ArchiveContentsHashOnly = $true
            }
        $arch = @($r.Records | Where-Object { Test-HmdIsArchiveScanRow -FileName $_.FileName })
        $arch.Count | Should -Be 2
        $exeRow = $arch | Where-Object { $_.FileName -eq '#archive/bin/tool.exe' } | Select-Object -First 1
        $txtRow = $arch | Where-Object { $_.FileName -eq '#archive/nested/readme.txt' } | Select-Object -First 1
        $exeRow | Should -Not -BeNullOrEmpty
        $txtRow | Should -Not -BeNullOrEmpty
        $exeRow.ArchiveInterestReason | Should -Match 'ext:\.exe'
        $txtRow.ArchiveInterestReason | Should -BeNullOrEmpty
        # Container + interesting member only (not readme.txt).
        $script:hmdInterestVtHashes.Count | Should -Be 2
        $script:hmdInterestVtHashes | Should -Contain $exeRow.Sha256
        $script:hmdInterestVtHashes | Should -Not -Contain $txtRow.Sha256
        $scanCsv = @(Import-Csv -LiteralPath (Join-Path $work 'logs\scanlog.csv'))
        @($scanCsv | Where-Object { Test-HmdIsArchiveScanRow -FileName $_.FileName }).Count |
            Should -Be 0
        $archCsv = @(Import-Csv -LiteralPath (Join-Path $work 'logs\archive-scanlog.csv'))
        $archCsv.Count | Should -Be 2
    }

    It 'checkpoint resume splits a legacy mixed scanlog into archive-scanlog.csv' {
        $work = Join-Path $TestDrive 'arch-migrate'
        $null = Initialize-HmdWorkRoot -WorkRoot $work
        $url = 'https://example.test/legacy.zip'
        $mixed = @(
            [pscustomobject]@{
                Url = $url; FileName = '0000_legacy.zip'; LocalPath = ''
                Sha256 = 'aa'; Verdict = 'Clean'; Malicious = 0; Suspicious = 0
                Undetected = 10; Harmless = 0; CacheHit = $false; Error = ''
                ProcessedAt = '2026-01-01T00:00:00'
            }
            [pscustomobject]@{
                Url = $url; FileName = '#archive/a.txt'; LocalPath = ''
                Sha256 = 'bb'; Verdict = 'Unknown'; Malicious = 0; Suspicious = 0
                Undetected = 0; Harmless = 0; CacheHit = $false; Error = 'HashOnly=true'
                ArchiveInterestReason = ''; ProcessedAt = '2026-01-01T00:00:00'
            }
        )
        Export-HmdScanLogCsv -Records $mixed -Path (Join-Path $work 'logs\scanlog.csv')
        $done = [System.Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
        $null = $done.Add($url)
        Save-HmdCheckpoint -CompletedUrls $done -Path (Join-Path $work 'checkpoint.json')
        $input = Join-Path $TestDrive 'arch-migrate-urls.txt'
        $url | Set-Content -LiteralPath $input -Encoding utf8
        $sec = ConvertTo-SecureString 'test-key' -AsPlainText -Force
        $r = Invoke-HmdBulkDownload -InputPath $input -WorkRoot $work `
            -ApiKey $sec -SkipVirusTotal -SkipLocalAvScan `
            -ConfigOverride @{
                GenerateReport = $false
                DisplaySummary = $false; DisplayProgress = $false; DisplayScanLog = $false
            }
        $r.ProcessedCount | Should -Be 0
        $scanCsv = @(Import-Csv -LiteralPath (Join-Path $work 'logs\scanlog.csv'))
        $scanCsv.Count | Should -Be 1
        $scanCsv[0].FileName | Should -Be '0000_legacy.zip'
        $archCsv = @(Import-Csv -LiteralPath (Join-Path $work 'logs\archive-scanlog.csv'))
        $archCsv.Count | Should -Be 1
        $archCsv[0].FileName | Should -Be '#archive/a.txt'
        @($r.Records | Where-Object { Test-HmdIsArchiveScanRow -FileName $_.FileName }).Count |
            Should -Be 1
    }
}

Describe 'Inbox lifecycle and mutex (HMD-035)' {
    It 'creates inbox folders' {
        $root = Join-Path $TestDrive 'inbox1'
        $p = Initialize-HmdInbox -InboxRoot $root
        (Test-Path -LiteralPath $p.Incoming) | Should -BeTrue
        (Test-Path -LiteralPath $p.Processing) | Should -BeTrue
        (Test-Path -LiteralPath $p.Done) | Should -BeTrue
        (Test-Path -LiteralPath $p.Failed) | Should -BeTrue
    }

    It 'classifies input vs deploy sidecar names' {
        Test-HmdInboxInputFileName -FileName 'urls.txt' | Should -BeTrue
        Test-HmdInboxInputFileName -FileName 'urls.csv' | Should -BeTrue
        Test-HmdInboxInputFileName -FileName 'urls.deploy.txt' | Should -BeFalse
        Test-HmdInboxInputFileName -FileName 'urls.err.txt' | Should -BeFalse
    }

    It 'claims oldest job and optional deploy map' {
        $root = Join-Path $TestDrive 'inbox2'
        $p = Initialize-HmdInbox -InboxRoot $root
        'https://a.example/x' | Set-Content -LiteralPath (Join-Path $p.Incoming 'job.txt') -Encoding utf8
        '@C:\Deploy' | Set-Content -LiteralPath (Join-Path $p.Incoming 'job.deploy.txt') -Encoding utf8
        $job = Get-HmdInboxNextJob -InboxRoot $root
        $job | Should -Not -BeNullOrEmpty
        $job.InputPath | Should -Match 'processing[\\/]job\.txt$'
        $job.DeployMapPath | Should -Match 'processing[\\/]job\.deploy\.txt$'
        ( @(Get-ChildItem -LiteralPath $p.Incoming -File -ErrorAction SilentlyContinue) ).Count | Should -Be 0
    }

    It 'resolves csv sidecar and prefers .deploy.txt over .deploy.csv' {
        $dir = Join-Path $TestDrive 'sidecar-pref'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $input = Join-Path $dir 'urls.csv'
        'https://a.example/x' | Set-Content -LiteralPath $input -Encoding utf8
        (Get-HmdInboxDeployMapPath -InputPath $input) | Should -BeNullOrEmpty
        $csvSide = Join-Path $dir 'urls.deploy.csv'
        'Destination,File' | Set-Content -LiteralPath $csvSide -Encoding utf8
        (Get-HmdInboxDeployMapPath -InputPath $input) | Should -Be $csvSide
        $txtSide = Join-Path $dir 'urls.deploy.txt'
        '@C:\X' | Set-Content -LiteralPath $txtSide -Encoding utf8
        (Get-HmdInboxDeployMapPath -InputPath $input) | Should -Be $txtSide
    }

    It 'ignores orphan deploy sidecar without matching input' {
        $root = Join-Path $TestDrive 'inbox-orphan'
        $p = Initialize-HmdInbox -InboxRoot $root
        '@C:\Deploy' | Set-Content -LiteralPath (Join-Path $p.Incoming 'lonely.deploy.txt') -Encoding utf8
        $job = Get-HmdInboxNextJob -InboxRoot $root
        $job | Should -BeNullOrEmpty
        (Test-Path -LiteralPath (Join-Path $p.Incoming 'lonely.deploy.txt')) | Should -BeTrue
    }

    It 'moves claimed job to done' {
        $root = Join-Path $TestDrive 'inbox3'
        $p = Initialize-HmdInbox -InboxRoot $root
        'https://a.example/x' | Set-Content -LiteralPath (Join-Path $p.Incoming 'ok.txt') -Encoding utf8
        $job = Get-HmdInboxNextJob -InboxRoot $root
        $moved = Move-HmdInboxJob -InboxRoot $root -InputPath $job.InputPath -Disposition Done
        $moved.Disposition | Should -Be 'Done'
        (Test-Path -LiteralPath (Join-Path $p.Done 'ok.txt')) | Should -BeTrue
    }

    It 'writes .err.txt on failed disposition' {
        $root = Join-Path $TestDrive 'inbox4'
        $p = Initialize-HmdInbox -InboxRoot $root
        'https://a.example/x' | Set-Content -LiteralPath (Join-Path $p.Incoming 'bad.txt') -Encoding utf8
        $job = Get-HmdInboxNextJob -InboxRoot $root
        $moved = Move-HmdInboxJob -InboxRoot $root -InputPath $job.InputPath `
            -Disposition Failed -ErrorMessage 'boom'
        (Test-Path -LiteralPath "$($moved.InputPath).err.txt") | Should -BeTrue
        (Get-Content -LiteralPath "$($moved.InputPath).err.txt" -Raw).Trim() | Should -Be 'boom'
    }

    It 'fail-closed when mutex already held on another thread' {
        $name = 'Local\Hmd.Pester.' + [guid]::NewGuid().ToString('N')
        $rs = [runspacefactory]::CreateRunspace()
        $rs.Open()
        $ps = [powershell]::Create()
        $ps.Runspace = $rs
        $null = $ps.AddScript({
                param($MutexName)
                $createdNew = $false
                $m = [System.Threading.Mutex]::new($false, $MutexName, [ref]$createdNew)
                if (-not $m.WaitOne(0)) { throw 'holder failed to acquire' }
                Start-Sleep -Seconds 15
                $m.ReleaseMutex()
                $m.Dispose()
            }).AddArgument($name)
        $async = $ps.BeginInvoke()
        Start-Sleep -Milliseconds 300
        try {
            { Enter-HmdInboxMutex -Name $name -TimeoutMs 0 } | Should -Throw -ExpectedMessage '*mutex busy*'
        }
        finally {
            try { $ps.Stop() } catch { }
            $ps.Dispose()
            $rs.Dispose()
            if (-not $async.IsCompleted) {
                # best-effort; holder exits on Stop
            }
        }
    }
}

Describe 'Resolve-HmdApiKey order (HMD-034)' {
    It 'prefers -ApiKey SecureString over env' {
        $prev = $env:VIRUSTOTAL_API_KEY
        try {
            $env:VIRUSTOTAL_API_KEY = 'env-key-should-not-win'
            $sec = ConvertTo-SecureString 'param-key' -AsPlainText -Force
            Resolve-HmdApiKey -ApiKey $sec -SkipCredentialManager | Should -Be 'param-key'
        }
        finally {
            $env:VIRUSTOTAL_API_KEY = $prev
        }
    }

    It 'uses env when no ApiKey and CredMan skipped' {
        $prev = $env:VIRUSTOTAL_API_KEY
        try {
            $env:VIRUSTOTAL_API_KEY = 'env-only-key'
            Resolve-HmdApiKey -SkipCredentialManager | Should -Be 'env-only-key'
        }
        finally {
            $env:VIRUSTOTAL_API_KEY = $prev
        }
    }
}

Describe 'Invoke-HmdInboxWorker (HMD-028)' {
    It 'returns Idle when incoming is empty' {
        $inbox = Join-Path $TestDrive 'worker-idle-inbox'
        $jobs = Join-Path $TestDrive 'worker-idle-jobs'
        $mutex = 'Local\Hmd.Pester.Idle.' + [guid]::NewGuid().ToString('N')
        $r = Invoke-HmdInboxWorker -InboxRoot $inbox -WorkRootBase $jobs `
            -MutexName $mutex -SkipVirusTotal -SkipLocalAvScan `
            -BulkDownloadInvoker { throw 'should not run' }
        $r.Status | Should -Be 'Idle'
    }

    It 'runs one mocked bulk job and moves to done' {
        $inbox = Join-Path $TestDrive 'worker-run-inbox'
        $jobs = Join-Path $TestDrive 'worker-run-jobs'
        $mutex = 'Local\Hmd.Pester.Run.' + [guid]::NewGuid().ToString('N')
        $null = Initialize-HmdInbox -InboxRoot $inbox
        'https://a.example/x' | Set-Content -LiteralPath (Join-Path $inbox 'incoming\one.txt') -Encoding utf8
        $fake = [pscustomobject]@{
            InputCount = 1; QueuedCount = 1; ProcessedCount = 1
            CleanCount = 1; ErrorCount = 0
        }
        $r = Invoke-HmdInboxWorker -InboxRoot $inbox -WorkRootBase $jobs `
            -MutexName $mutex -SkipVirusTotal -SkipLocalAvScan `
            -BulkDownloadInvoker { param($p) $fake }
        $r.Status | Should -Be 'Done'
        $r.WorkRoot | Should -Not -BeNullOrEmpty
        (Test-Path -LiteralPath (Join-Path $inbox 'done\one.txt')) | Should -BeTrue
        ( @(Get-ChildItem -LiteralPath (Join-Path $inbox 'incoming') -File -ErrorAction SilentlyContinue) ).Count |
            Should -Be 0
    }

    It 'passes deploy sidecar as DeployMapPath and moves both to done' {
        $inbox = Join-Path $TestDrive 'worker-side-inbox'
        $jobs = Join-Path $TestDrive 'worker-side-jobs'
        $mutex = 'Local\Hmd.Pester.Side.' + [guid]::NewGuid().ToString('N')
        $null = Initialize-HmdInbox -InboxRoot $inbox
        'https://a.example/x' | Set-Content -LiteralPath (Join-Path $inbox 'incoming\urls.txt') -Encoding utf8
        '@C:\Deploy' | Set-Content -LiteralPath (Join-Path $inbox 'incoming\urls.deploy.txt') -Encoding utf8
        $script:hmdSeenDeploy = $null
        $fake = [pscustomobject]@{
            InputCount = 1; QueuedCount = 1; ProcessedCount = 1
            CleanCount = 1; ErrorCount = 0; DeployedCount = 1
        }
        $r = Invoke-HmdInboxWorker -InboxRoot $inbox -WorkRootBase $jobs `
            -MutexName $mutex -SkipVirusTotal -SkipLocalAvScan `
            -BulkDownloadInvoker {
                param($p)
                $script:hmdSeenDeploy = $p['DeployMapPath']
                $fake
            }
        $r.Status | Should -Be 'Done'
        $script:hmdSeenDeploy | Should -Match 'urls\.deploy\.txt$'
        $r.DeployMapPath | Should -Match 'urls\.deploy\.txt$'
        (Test-Path -LiteralPath (Join-Path $inbox 'done\urls.txt')) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path $inbox 'done\urls.deploy.txt')) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path $inbox 'incoming\urls.deploy.txt')) | Should -BeFalse
    }
}

Describe 'HMD-046 progress' {
    It 'Get-HmdProgressPercent clamps 0-100' {
        Get-HmdProgressPercent -Current 0 -Total 0 | Should -Be 0
        Get-HmdProgressPercent -Current 3 -Total 10 | Should -Be 30
        Get-HmdProgressPercent -Current 10 -Total 10 | Should -Be 100
        Get-HmdProgressPercent -Current 12 -Total 10 | Should -Be 100
    }

    It 'Format-HmdProgressLine includes phase, status, and fraction' {
        $ts = [datetime]::Parse('2026-08-17T12:00:00')
        $line = Format-HmdProgressLine -Phase Process -Status ITEM `
            -Current 3 -Total 10 -Message "0002_tool.exe Verdict=Clean" `
            -Timestamp $ts
        $line | Should -Match 'PHASE=Process'
        $line | Should -Match 'STATUS=ITEM'
        $line | Should -Match '3/10'
        $line | Should -Match '0002_tool.exe Verdict=Clean'
        $line | Should -Not -Match "`n"
    }

    It 'Format-HmdProgressLine strips newlines from the message' {
        $line = Format-HmdProgressLine -Phase Process -Status STEP `
            -Message "a`r`nb"
        $line | Should -Match ' a b$'
        $line | Should -Not -Match "`n"
    }

    It 'defaults include DisplayProgress and ProgressLog' {
        $c = Get-HmdConfig
        [bool]$c.DisplayProgress | Should -BeTrue
        [bool]$c.ProgressLog | Should -BeTrue
        [bool]$c.DisplayScanLog | Should -BeTrue
        [bool]$c.DisplayArchiveScanLog | Should -BeFalse
    }

    It 'New-HmdProgressContext AgentSummary quiets host but keeps log' {
        $cfg = Get-HmdConfig -Override @{ DisplayProgress = $true; ProgressLog = $true }
        $root = Join-Path $TestDrive 'progress-ctx'
        $ctx = New-HmdProgressContext -Config $cfg -WorkRoot $root `
            -AgentSummary -ConfigOverride @{}
        $ctx.WriteHost | Should -BeFalse
        $ctx.WriteBar | Should -BeFalse
        $ctx.LogPath | Should -Match 'progress\.log$'
    }

    It 'Write-HmdProgress appends to log when host is off' {
        $dir = Join-Path $TestDrive 'prog-log\logs'
        $null = New-Item -ItemType Directory -Path $dir -Force
        $path = Join-Path $dir 'progress.log'
        $ctx = [pscustomobject]@{
            WriteHost = $false
            WriteBar  = $false
            LogPath   = $path
        }
        Write-HmdProgress -Context $ctx -Phase Download -Status START `
            -Current 0 -Total 2 -Message 'threads=5'
        Write-HmdProgress -Context $ctx -Phase Download -Status DONE `
            -Current 2 -Total 2 -Message 'ok=2 fail=0'
        Test-Path -LiteralPath $path | Should -BeTrue
        $text = Get-Content -LiteralPath $path -Raw -Encoding utf8
        $text | Should -Match 'PHASE=Download STATUS=START 0/2 threads=5'
        $text | Should -Match 'PHASE=Download STATUS=DONE 2/2 ok=2 fail=0'
    }

    It 'bulk run writes progress.log with Download and Process phases' {
        $work = Join-Path $TestDrive 'run-progress'
        $input = Join-Path $TestDrive 'progress-in.txt'
        "https://mock.example/clean.bin" | Set-Content -LiteralPath $input -Encoding utf8

        $downloadInvoker = {
            param($req)
            $bytes = [Text.Encoding]::UTF8.GetBytes('progress-payload')
            [IO.File]::WriteAllBytes($req.OutFile, $bytes)
            [pscustomobject]@{
                StatusCode  = 200
                ContentType = 'application/octet-stream'
                Bytes       = $bytes.Length
            }
        }
        $vtInvoker = {
            param($req)
            return [pscustomobject]@{
                data = [pscustomobject]@{
                    attributes = [pscustomobject]@{
                        last_analysis_stats = [pscustomobject]@{
                            malicious = 0; suspicious = 0; undetected = 40; harmless = 10
                        }
                    }
                }
            }
        }

        $sec = ConvertTo-SecureString 'test-key' -AsPlainText -Force
        $r = Invoke-HmdBulkDownload -InputPath $input -WorkRoot $work `
            -ApiKey $sec -VtInvoker $vtInvoker -DownloadInvoker $downloadInvoker `
            -ConfigOverride @{
                ApiDelaySeconds  = 0
                GenerateReport   = $false
                DisplaySummary   = $false
                DisplayScanLog   = $false
                DisplayProgress  = $false
                ProgressLog      = $true
                LocalAvScanEnabled = $false
            }

        $r.ProgressLog | Should -Not -BeNullOrEmpty
        Test-Path -LiteralPath $r.ProgressLog | Should -BeTrue
        $text = Get-Content -LiteralPath $r.ProgressLog -Raw -Encoding utf8
        $text | Should -Match 'PHASE=Download STATUS=START'
        $text | Should -Match 'PHASE=Download STATUS=DONE'
        $text | Should -Match 'PHASE=Process STATUS=START'
        $text | Should -Match 'PHASE=Process STATUS=ITEM'
        $text | Should -Match 'Verdict=Clean'
        $text | Should -Match 'PHASE=Complete STATUS=DONE'
    }
}

