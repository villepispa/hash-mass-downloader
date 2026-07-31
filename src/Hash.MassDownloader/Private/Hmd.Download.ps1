#Requires -Version 7.2

function Start-HmdDownloadPool {
    <#
    .SYNOPSIS
        Download URLs concurrently into Downloaded/ and return result objects.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Urls,
        [Parameter(Mandatory)]
        [string]$WorkRoot,
        [int]$ThrottleLimit = 5,
        [int]$MaxFileBytes = 104857600,
        [int]$MaxRetries = 3,
        [string]$UserAgent = 'Hash.MassDownloader/0.5.0',
        [bool]$PrefixFileNames = $true,
        [scriptblock]$DownloadInvoker
    )

    $downloadedDir = Join-Path $WorkRoot 'Downloaded'
    $indexPath = Join-Path $WorkRoot 'logs\download_index.csv'

    # Pre-assign unique names (needed when PrefixFileNames is false).
    $occupied = @{}
    $assignedNames = [string[]]::new($Urls.Count)
    for ($i = 0; $i -lt $Urls.Count; $i++) {
        $name = Get-HmdSafeFileName -Url $Urls[$i] -Index $i `
            -PrefixFileNames $PrefixFileNames -OccupiedNames $occupied
        $occupied[$name] = $true
        $assignedNames[$i] = $name
    }

    function Invoke-OneDownload {
        param(
            [string]$Url,
            [string]$FileName,
            [string]$DownloadedDir,
            [long]$MaxBytes,
            [int]$MaxRetries,
            [string]$UserAgent,
            [scriptblock]$Invoker
        )

        $dest = Join-Path $DownloadedDir $FileName
        $attempt = 0
        $ok = $false
        $status = 0
        $errorText = ''
        $contentType = ''
        $bytes = 0L

        while (-not $ok -and $attempt -lt $MaxRetries) {
            $attempt++
            try {
                if ($null -ne $Invoker) {
                    $r = & $Invoker @{
                        Url          = $Url
                        OutFile      = $dest
                        UserAgent    = $UserAgent
                        MaxFileBytes = $MaxBytes
                    }
                    $status = [int]$r.StatusCode
                    $contentType = [string]$r.ContentType
                    $bytes = [long]$r.Bytes
                    if ($status -ge 400) {
                        throw "HTTP $status"
                    }
                    $ok = $true
                }
                else {
                    $headers = @{ 'User-Agent' = $UserAgent }
                    try {
                        $head = Invoke-WebRequest -Uri $Url -Method Head -Headers $headers `
                            -MaximumRedirection 5 -ErrorAction Stop
                        if ($head.Headers['Content-Length']) {
                            $cl = [long]$head.Headers['Content-Length'][0]
                            if ($cl -gt $MaxBytes) {
                                throw "Content-Length $cl exceeds MaxFileBytes $MaxBytes"
                            }
                        }
                        if ($head.Headers['Content-Type']) {
                            $contentType = [string]$head.Headers['Content-Type'][0]
                        }
                    }
                    catch {
                        # HEAD may fail; continue with GET
                    }

                    Invoke-WebRequest -Uri $Url -OutFile $dest -Headers $headers `
                        -MaximumRedirection 5 -ErrorAction Stop | Out-Null
                    if (-not (Test-Path -LiteralPath $dest)) {
                        throw 'Download produced no file.'
                    }
                    $bytes = (Get-Item -LiteralPath $dest).Length
                    if ($bytes -gt $MaxBytes) {
                        Remove-Item -LiteralPath $dest -Force -ErrorAction SilentlyContinue
                        throw "Downloaded size $bytes exceeds MaxFileBytes $MaxBytes"
                    }
                    $status = 200
                    $ok = $true
                }
            }
            catch {
                $errorText = $_.Exception.Message
                if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                    $status = [int]$_.Exception.Response.StatusCode
                }
                elseif ($errorText -match '\b(404|403)\b') {
                    if ($errorText -match '404') { $status = 404 }
                    if ($errorText -match '403') { $status = 403 }
                }
                elseif ($errorText -match '429') {
                    $status = 429
                }

                if ($status -in 404, 403) {
                    break
                }
                if ($status -eq 429 -or $status -ge 500 -or $status -eq 0) {
                    Start-Sleep -Seconds ([Math]::Min(30, 2 * $attempt))
                    continue
                }
                break
            }
        }

        return [pscustomobject]@{
            Url          = $Url
            LocalPath    = $(if ($ok) { $dest } else { $null })
            FileName     = $FileName
            Success      = $ok
            StatusCode   = $status
            Attempts     = $attempt
            Bytes        = $bytes
            ContentType  = $contentType
            Error        = $(if ($ok) { '' } else { $errorText })
            DownloadedAt = (Get-Date).ToString('o')
        }
    }

    # Scriptblock invokers do not serialize under ForEach-Object -Parallel;
    # use sequential path for mocks / injected downloaders.
    if ($null -ne $DownloadInvoker) {
        $list = for ($i = 0; $i -lt $Urls.Count; $i++) {
            Invoke-OneDownload -Url $Urls[$i] -FileName $assignedNames[$i] `
                -DownloadedDir $downloadedDir `
                -MaxBytes $MaxFileBytes -MaxRetries $MaxRetries -UserAgent $UserAgent `
                -Invoker $DownloadInvoker
        }
        $list = @($list)
        $list | Export-Csv -LiteralPath $indexPath -NoTypeInformation -Encoding utf8
        foreach ($item in $list) {
            $item
        }
        return
    }

    $results = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
    $jobs = for ($i = 0; $i -lt $Urls.Count; $i++) {
        [pscustomobject]@{ Index = $i; Url = $Urls[$i]; FileName = $assignedNames[$i] }
    }

    $jobs | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
        $item = $_
        $url = [string]$item.Url
        $fileName = [string]$item.FileName
        $downloadedDir = $using:downloadedDir
        $maxBytes = $using:MaxFileBytes
        $maxRetries = $using:MaxRetries
        $userAgent = $using:UserAgent
        $bag = $using:results

        $dest = Join-Path $downloadedDir $fileName
        $attempt = 0
        $ok = $false
        $status = 0
        $errorText = ''
        $contentType = ''
        $bytes = 0L

        while (-not $ok -and $attempt -lt $maxRetries) {
            $attempt++
            try {
                $headers = @{ 'User-Agent' = $userAgent }
                try {
                    $head = Invoke-WebRequest -Uri $url -Method Head -Headers $headers `
                        -MaximumRedirection 5 -ErrorAction Stop
                    if ($head.Headers['Content-Length']) {
                        $cl = [long]$head.Headers['Content-Length'][0]
                        if ($cl -gt $maxBytes) {
                            throw "Content-Length $cl exceeds MaxFileBytes $maxBytes"
                        }
                    }
                    if ($head.Headers['Content-Type']) {
                        $contentType = [string]$head.Headers['Content-Type'][0]
                    }
                }
                catch { }

                Invoke-WebRequest -Uri $url -OutFile $dest -Headers $headers `
                    -MaximumRedirection 5 -ErrorAction Stop | Out-Null
                if (-not (Test-Path -LiteralPath $dest)) {
                    throw 'Download produced no file.'
                }
                $bytes = (Get-Item -LiteralPath $dest).Length
                if ($bytes -gt $maxBytes) {
                    Remove-Item -LiteralPath $dest -Force -ErrorAction SilentlyContinue
                    throw "Downloaded size $bytes exceeds MaxFileBytes $maxBytes"
                }
                $status = 200
                $ok = $true
            }
            catch {
                $errorText = $_.Exception.Message
                if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                    $status = [int]$_.Exception.Response.StatusCode
                }
                elseif ($errorText -match '404') { $status = 404 }
                elseif ($errorText -match '403') { $status = 403 }
                elseif ($errorText -match '429') { $status = 429 }

                if ($status -in 404, 403) { break }
                if ($status -eq 429 -or $status -ge 500 -or $status -eq 0) {
                    Start-Sleep -Seconds ([Math]::Min(30, 2 * $attempt))
                    continue
                }
                break
            }
        }

        $bag.Add([pscustomobject]@{
                Url          = $url
                LocalPath    = $(if ($ok) { $dest } else { $null })
                FileName     = $fileName
                Success      = $ok
                StatusCode   = $status
                Attempts     = $attempt
                Bytes        = $bytes
                ContentType  = $contentType
                Error        = $(if ($ok) { '' } else { $errorText })
                DownloadedAt = (Get-Date).ToString('o')
            }) | Out-Null
    }

    $list = @($results.ToArray() | Sort-Object FileName)
    $list | Export-Csv -LiteralPath $indexPath -NoTypeInformation -Encoding utf8
    foreach ($item in $list) {
        $item
    }
}
