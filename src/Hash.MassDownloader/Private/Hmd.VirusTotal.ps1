#Requires -Version 7.2

function Invoke-HmdRest {
    <#
    .SYNOPSIS
        HTTP helper with injectable -Invoker for tests.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Method,
        [Parameter(Mandatory)]
        [string]$Uri,
        [hashtable]$Headers = @{},
        [object]$Body,
        [string]$ContentType,
        [string]$OutFile,
        [scriptblock]$Invoker
    )

    if ($null -ne $Invoker) {
        return & $Invoker @{
            Method      = $Method
            Uri         = $Uri
            Headers     = $Headers
            Body        = $Body
            ContentType = $ContentType
            OutFile     = $OutFile
        }
    }

    $params = @{
        Method  = $Method
        Uri     = $Uri
        Headers = $Headers
    }
    if ($null -ne $Body) { $params['Body'] = $Body }
    if (-not [string]::IsNullOrWhiteSpace($ContentType)) {
        $params['ContentType'] = $ContentType
    }
    if (-not [string]::IsNullOrWhiteSpace($OutFile)) {
        $params['OutFile'] = $OutFile
    }

    return Invoke-RestMethod @params
}

function Get-HmdHashReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Sha256,
        [Parameter(Mandatory)]
        [string]$ApiKey,
        [scriptblock]$Invoker,
        [int]$ApiDelaySeconds = 0
    )

    if ($ApiDelaySeconds -gt 0) {
        Start-Sleep -Seconds $ApiDelaySeconds
    }

    $uri = "https://www.virustotal.com/api/v3/files/$Sha256"
    $headers = @{ 'x-apikey' = $ApiKey }

    try {
        $resp = Invoke-HmdRest -Method GET -Uri $uri -Headers $headers -Invoker $Invoker
        $stats = $resp.data.attributes.last_analysis_stats
        return [pscustomobject]@{
            Found      = $true
            Malicious  = [int]$stats.malicious
            Suspicious = [int]$stats.suspicious
            Undetected = [int]$stats.undetected
            Harmless   = [int]$stats.harmless
            Raw        = $resp
            StatusCode = 200
        }
    }
    catch {
        $code = 0
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
            $code = [int]$_.Exception.Response.StatusCode
        }
        elseif ($_.ErrorDetails.Message -match '"code"\s*:\s*"NotFoundError"' -or
                $_.Exception.Message -match '404') {
            $code = 404
        }

        if ($code -eq 404) {
            return [pscustomobject]@{
                Found      = $false
                Malicious  = 0
                Suspicious = 0
                Undetected = 0
                Harmless   = 0
                Raw        = $null
                StatusCode = 404
            }
        }
        throw
    }
}

function Submit-HmdFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$ApiKey,
        [scriptblock]$Invoker,
        [int]$ApiDelaySeconds = 0
    )

    if ($ApiDelaySeconds -gt 0) {
        Start-Sleep -Seconds $ApiDelaySeconds
    }

    if ($null -ne $Invoker) {
        return Invoke-HmdRest -Method POST -Uri 'https://www.virustotal.com/api/v3/files' `
            -Headers @{ 'x-apikey' = $ApiKey } -Body @{ Path = $Path } -Invoker $Invoker
    }

    # Multipart upload via .NET for live runs
    $uri = 'https://www.virustotal.com/api/v3/files'
    $boundary = [guid]::NewGuid().ToString('N')
    $fileBytes = [IO.File]::ReadAllBytes($Path)
    $fileName = [IO.Path]::GetFileName($Path)
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("--$boundary")
    [void]$sb.AppendLine("Content-Disposition: form-data; name=`"file`"; filename=`"$fileName`"")
    [void]$sb.AppendLine('Content-Type: application/octet-stream')
    [void]$sb.AppendLine()
    $headerBytes = [Text.Encoding]::UTF8.GetBytes($sb.ToString())
    $footerBytes = [Text.Encoding]::UTF8.GetBytes("`r`n--$boundary--`r`n")
    $body = New-Object byte[] ($headerBytes.Length + $fileBytes.Length + $footerBytes.Length)
    [Array]::Copy($headerBytes, 0, $body, 0, $headerBytes.Length)
    [Array]::Copy($fileBytes, 0, $body, $headerBytes.Length, $fileBytes.Length)
    [Array]::Copy($footerBytes, 0, $body, $headerBytes.Length + $fileBytes.Length, $footerBytes.Length)

    return Invoke-RestMethod -Method POST -Uri $uri `
        -Headers @{ 'x-apikey' = $ApiKey } `
        -ContentType "multipart/form-data; boundary=$boundary" `
        -Body $body
}

function Get-HmdAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AnalysisId,
        [Parameter(Mandatory)]
        [string]$ApiKey,
        [scriptblock]$Invoker,
        [int]$PollSeconds = 15,
        [int]$MaxAttempts = 20,
        [int]$ApiDelaySeconds = 0
    )

    $uri = "https://www.virustotal.com/api/v3/analyses/$AnalysisId"
    $headers = @{ 'x-apikey' = $ApiKey }

    for ($i = 0; $i -lt $MaxAttempts; $i++) {
        if ($ApiDelaySeconds -gt 0 -or $i -gt 0) {
            $sleep = if ($i -eq 0) { $ApiDelaySeconds } else { [Math]::Max($PollSeconds, $ApiDelaySeconds) }
            if ($sleep -gt 0) { Start-Sleep -Seconds $sleep }
        }

        $resp = Invoke-HmdRest -Method GET -Uri $uri -Headers $headers -Invoker $Invoker
        $status = [string]$resp.data.attributes.status
        if ($status -eq 'completed') {
            $stats = $resp.data.attributes.stats
            return [pscustomobject]@{
                Found      = $true
                Malicious  = [int]$stats.malicious
                Suspicious = [int]$stats.suspicious
                Undetected = [int]$stats.undetected
                Harmless   = [int]$stats.harmless
                Raw        = $resp
                StatusCode = 200
            }
        }
    }

    throw "Analysis $AnalysisId did not complete within $MaxAttempts attempts."
}
