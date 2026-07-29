#Requires -Version 7.2

function Add-HmdUrlCandidate {
    param(
        [System.Collections.Generic.List[string]]$Urls,
        [hashtable]$Seen,
        [string]$Candidate
    )

    if ([string]::IsNullOrWhiteSpace($Candidate)) { return }

    # Split accidental multi-URL lines (space / tab / comma / semicolon).
    $parts = @(
        $Candidate -split '[\s,;]+' |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )

    foreach ($part in $parts) {
        $u = $part.Trim().Trim('"').Trim("'")
        if ([string]::IsNullOrWhiteSpace($u)) { continue }
        if ($u -notmatch '^https?://') { continue }
        if ($Seen.ContainsKey($u)) { continue }
        $Seen[$u] = $true
        $Urls.Add($u)
    }
}

function Import-HmdUrlList {
    <#
    .SYNOPSIS
        Parse TXT or CSV input into a unique ordered list of URLs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Input path not found: $Path"
    }

    $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant()
    $urls = [System.Collections.Generic.List[string]]::new()
    $seen = @{}

    if ($ext -eq '.csv') {
        $rows = @(Import-Csv -LiteralPath $Path)
        foreach ($row in $rows) {
            $candidate = $null
            if ($row.PSObject.Properties.Name -contains 'Url') {
                $candidate = [string]$row.Url
            }
            elseif ($row.PSObject.Properties.Name -contains 'URL') {
                $candidate = [string]$row.URL
            }
            else {
                $first = $row.PSObject.Properties | Select-Object -First 1
                if ($null -ne $first) {
                    $candidate = [string]$first.Value
                }
            }
            Add-HmdUrlCandidate -Urls $urls -Seen $seen -Candidate $candidate
        }
    }
    else {
        $lines = Get-Content -LiteralPath $Path -Encoding utf8
        foreach ($line in $lines) {
            $t = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($t)) { continue }
            if ($t.StartsWith('#')) { continue }
            Add-HmdUrlCandidate -Urls $urls -Seen $seen -Candidate $t
        }
    }

    # Emit each URL to the pipeline so `@()` at the call site flattens correctly.
    foreach ($u in $urls) {
        $u
    }
}

function Initialize-HmdWorkRoot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WorkRoot
    )

    $folders = @(
        'Downloaded', 'Clean', 'Suspicious', 'Malicious', 'Quarantine',
        'Unknown', 'Error', 'logs', 'reports'
    )
    $null = New-Item -ItemType Directory -Force -Path $WorkRoot
    foreach ($name in $folders) {
        $null = New-Item -ItemType Directory -Force -Path (Join-Path $WorkRoot $name)
    }
    return (Resolve-Path -LiteralPath $WorkRoot).Path
}

function Get-HmdSafeFileName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Url,
        [int]$Index = 0
    )

    try {
        $uri = [Uri]$Url
        $leaf = [IO.Path]::GetFileName($uri.AbsolutePath)
    }
    catch {
        $leaf = $null
    }

    if ([string]::IsNullOrWhiteSpace($leaf)) {
        $leaf = "file_$Index.bin"
    }

    foreach ($c in [IO.Path]::GetInvalidFileNameChars()) {
        $leaf = $leaf.Replace([string]$c, '_')
    }
    if ($leaf.Length -gt 120) {
        $leaf = $leaf.Substring(0, 120)
    }
    return "{0:D4}_{1}" -f $Index, $leaf
}
