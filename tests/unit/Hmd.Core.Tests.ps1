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
            -ConfigOverride @{ ApiDelaySeconds = 0; GenerateReport = $true; DisplaySummary = $false; DisplayScanLog = $false }

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
            -ConfigOverride @{ ApiDelaySeconds = 0; DisplaySummary = $false; DisplayScanLog = $false }
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
            -ConfigOverride @{ ApiDelaySeconds = 0; GenerateReport = $false; DisplaySummary = $false; DisplayScanLog = $false }

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
            -ConfigOverride @{ ApiDelaySeconds = 0; QuarantineMalicious = $true; DisplaySummary = $false; DisplayScanLog = $false }

        $r.Records[0].Verdict | Should -Be 'Malicious'
        @(Get-ChildItem -LiteralPath (Join-Path $work 'Malicious')).Count | Should -Be 1
        @(Get-ChildItem -LiteralPath (Join-Path $work 'Quarantine')).Count | Should -Be 1
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
            -ConfigOverride @{ ApiDelaySeconds = 0; GenerateReport = $false; DisplaySummary = $false; DisplayScanLog = $false }

        $r.InputCount | Should -Be 2
        $r.ProcessedCount | Should -Be 2
        $r.Records.Count | Should -Be 2
        $r.Records[0].Url | Should -BeOfType ([string])
        $r.Records[0].Verdict | Should -Be 'Clean'
        $r.Records[1].Verdict | Should -Be 'Clean'
    }
}

