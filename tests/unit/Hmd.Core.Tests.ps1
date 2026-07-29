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
        $r2.PendingCount | Should -Be 0
        $r2.ProcessedCount | Should -Be 0
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
