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
        'Unknown', 'Error', 'Inspected', 'logs', 'reports'
    )
    $null = New-Item -ItemType Directory -Force -Path $WorkRoot
    foreach ($name in $folders) {
        $null = New-Item -ItemType Directory -Force -Path (Join-Path $WorkRoot $name)
    }
    return (Resolve-Path -LiteralPath $WorkRoot).Path
}

function Get-HmdUrlLeafName {
    <#
    .SYNOPSIS
        Sanitize the URL path leaf for use as a local file name (no index prefix).
    #>
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
    return $leaf
}

function Get-HmdSafeFileName {
    <#
    .SYNOPSIS
        Build a staged download file name from a URL.
    .DESCRIPTION
        When -PrefixFileNames is set (default), returns NNNN_leaf. When off, returns
        the sanitized leaf; pass -OccupiedNames to disambiguate collisions as
        name_Index.ext.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Url,
        [int]$Index = 0,
        [bool]$PrefixFileNames = $true,
        [System.Collections.IDictionary]$OccupiedNames
    )

    $leaf = Get-HmdUrlLeafName -Url $Url -Index $Index
    if ($PrefixFileNames) {
        return "{0:D4}_{1}" -f $Index, $leaf
    }

    $candidate = $leaf
    if ($null -eq $OccupiedNames -or -not $OccupiedNames.ContainsKey($candidate)) {
        return $candidate
    }

    $stem = [IO.Path]::GetFileNameWithoutExtension($leaf)
    $ext = [IO.Path]::GetExtension($leaf)
    $candidate = "{0}_{1}{2}" -f $stem, $Index, $ext
    $n = 0
    while ($OccupiedNames.ContainsKey($candidate)) {
        $n++
        $candidate = "{0}_{1}_{2}{3}" -f $stem, $Index, $n, $ext
    }
    return $candidate
}

function Test-HmdHttpUrl {
    <#
    .SYNOPSIS
        True when the value looks like an http(s) URL (case-insensitive scheme).
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $false
    }
    return ($Value.Trim() -match '^https?://')
}

function Get-HmdUrlsFromDeployMap {
    <#
    .SYNOPSIS
        Unique ordered http(s) URLs from deploy-map File entries (HMD-027 harvest).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$MapRows
    )

    $urls = [System.Collections.Generic.List[string]]::new()
    $seen = @{}
    foreach ($row in @($MapRows)) {
        $file = [string]$row.File
        if (-not (Test-HmdHttpUrl -Value $file)) {
            continue
        }
        $u = $file.Trim()
        if ($seen.ContainsKey($u)) {
            continue
        }
        $seen[$u] = $true
        $urls.Add($u)
    }
    return [string[]]$urls.ToArray()
}

function Get-HmdDeployMatchKeys {
    <#
    .SYNOPSIS
        Candidate keys for matching a scan record to a deploy-map File entry.
    .DESCRIPTION
        Keys: staged FileName, leaf without NNNN_ prefix, URL path leaf, and full
        URL (HMD-027) when present.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FileName,
        [string]$Url = ''
    )

    $keys = [System.Collections.Generic.List[string]]::new()
    foreach ($k in @($FileName)) {
        if (-not [string]::IsNullOrWhiteSpace($k) -and -not $keys.Contains($k)) {
            $keys.Add($k)
        }
    }
    if ($FileName -match '^\d{4}_(.+)$') {
        $stripped = $Matches[1]
        if (-not $keys.Contains($stripped)) {
            $keys.Add($stripped)
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($Url)) {
        if (-not $keys.Contains($Url)) {
            $keys.Add($Url)
        }
        $urlLeaf = Get-HmdUrlLeafName -Url $Url -Index 0
        if (-not $keys.Contains($urlLeaf)) {
            $keys.Add($urlLeaf)
        }
    }
    return [string[]]$keys.ToArray()
}
