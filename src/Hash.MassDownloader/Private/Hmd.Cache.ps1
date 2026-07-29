#Requires -Version 7.2

function Get-HmdFileSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Test-HmdCacheEntryFresh {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [datetime]$CachedAt,
        [Parameter(Mandatory)]
        [int]$TtlDays,
        [datetime]$Now = (Get-Date)
    )

    return ($Now - $CachedAt).TotalDays -lt $TtlDays
}

function Import-HmdHashCache {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $map = @{}
    if (-not (Test-Path -LiteralPath $Path)) {
        return $map
    }

    $rows = @(Import-Csv -LiteralPath $Path)
    foreach ($row in $rows) {
        if ([string]::IsNullOrWhiteSpace($row.Sha256)) { continue }
        $key = $row.Sha256.ToLowerInvariant()
        $map[$key] = [pscustomobject]@{
            Sha256     = $key
            Verdict    = [string]$row.Verdict
            Malicious  = [int]$row.Malicious
            Suspicious = [int]$row.Suspicious
            Undetected = [int]$row.Undetected
            Harmless   = $(if ($null -ne $row.PSObject.Properties['Harmless'] -and
                    -not [string]::IsNullOrWhiteSpace([string]$row.Harmless)) {
                    [int]$row.Harmless
                }
                else { 0 })
            CachedAt   = [datetime]$row.CachedAt
            Source     = [string]$row.Source
        }
    }
    return $map
}

function Export-HmdHashCache {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Cache,
        [Parameter(Mandatory)]
        [string]$Path
    )

    $rows = @(
        foreach ($key in ($Cache.Keys | Sort-Object)) {
            $e = $Cache[$key]
            [pscustomobject]@{
                Sha256     = $e.Sha256
                Verdict    = $e.Verdict
                Malicious  = $e.Malicious
                Suspicious = $e.Suspicious
                Undetected = $e.Undetected
                Harmless   = $(if ($null -ne $e.PSObject.Properties['Harmless']) { [int]$e.Harmless } else { 0 })
                CachedAt   = ($e.CachedAt).ToString('o')
                Source     = $e.Source
            }
        }
    )
    $dir = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($dir)) {
        $null = New-Item -ItemType Directory -Force -Path $dir
    }
    $rows | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding utf8
}

function Get-HmdVerdictFromStats {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$Malicious,
        [Parameter(Mandatory)]
        [int]$Suspicious,
        [Parameter(Mandatory)]
        [int]$Undetected,
        [int]$MaliciousThreshold = 1,
        [int]$SuspiciousThreshold = 1,
        [switch]$Known
    )

    if (-not $Known) {
        return 'Unknown'
    }
    if ($Malicious -ge $MaliciousThreshold) {
        return 'Malicious'
    }
    if ($Suspicious -ge $SuspiciousThreshold) {
        return 'Suspicious'
    }
    return 'Clean'
}

function Import-HmdCheckpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        $empty = [System.Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
        return , $empty
    }

    $json = Get-Content -LiteralPath $Path -Raw -Encoding utf8 | ConvertFrom-Json
    $set = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($u in @($json.CompletedUrls)) {
        if (-not [string]::IsNullOrWhiteSpace($u)) {
            $null = $set.Add([string]$u)
        }
    }
    return , $set
}

function Save-HmdCheckpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.Generic.HashSet[string]]$CompletedUrls,
        [Parameter(Mandatory)]
        [string]$Path
    )

    $obj = [pscustomobject]@{
        UpdatedAt      = (Get-Date).ToString('o')
        CompletedUrls  = @($CompletedUrls)
    }
    $dir = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($dir)) {
        $null = New-Item -ItemType Directory -Force -Path $dir
    }
    ($obj | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath $Path -Encoding utf8
}
