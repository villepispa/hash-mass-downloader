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
            Sha256         = $key
            Verdict        = [string]$row.Verdict
            Malicious      = [int]$row.Malicious
            Suspicious     = [int]$row.Suspicious
            Undetected     = [int]$row.Undetected
            Harmless       = $(if ($null -ne $row.PSObject.Properties['Harmless'] -and
                    -not [string]::IsNullOrWhiteSpace([string]$row.Harmless)) {
                    [int]$row.Harmless
                }
                else { 0 })
            IgnoredEngines = $(if ($null -ne $row.PSObject.Properties['IgnoredEngines']) {
                    [string]$row.IgnoredEngines
                }
                else { '' })
            CachedAt       = [datetime]$row.CachedAt
            Source         = [string]$row.Source
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
                Sha256         = $e.Sha256
                Verdict        = $e.Verdict
                Malicious      = $e.Malicious
                Suspicious     = $e.Suspicious
                Undetected     = $e.Undetected
                Harmless       = $(if ($null -ne $e.PSObject.Properties['Harmless']) { [int]$e.Harmless } else { 0 })
                IgnoredEngines = $(if ($null -ne $e.PSObject.Properties['IgnoredEngines']) {
                        [string]$e.IgnoredEngines
                    }
                    else { '' })
                CachedAt       = ($e.CachedAt).ToString('o')
                Source         = $e.Source
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

function Get-HmdIgnoreEngineList {
    <#
    .SYNOPSIS
        Normalize config IgnoreEngines (array / single string / null) to string[].
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$IgnoreEngines
    )

    if ($null -eq $IgnoreEngines) {
        return [string[]]@()
    }

    $flat = ConvertTo-HmdFlatArray -InputObject $IgnoreEngines
    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($el in $flat) {
        if ($null -eq $el) { continue }
        $s = [string]$el
        if (-not [string]::IsNullOrWhiteSpace($s)) {
            $out.Add($s.Trim())
        }
    }
    return [string[]]$out.ToArray()
}

function Get-HmdPolicyStatsFromResults {
    <#
    .SYNOPSIS
        Recompute VT category counts excluding IgnoreEngines (case-insensitive).
    .DESCRIPTION
        When IgnoreEngines is empty or AnalysisResults is missing, returns the
        raw aggregate counts unchanged (PolicyFromResults = false). Otherwise
        recounts from per-engine results, skipping ignored engines.
        Scanlog/cache should still persist raw VT aggregates for audit.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$AnalysisResults,
        [string[]]$IgnoreEngines = @(),
        [Parameter(Mandatory)]
        [int]$RawMalicious,
        [Parameter(Mandatory)]
        [int]$RawSuspicious,
        [Parameter(Mandatory)]
        [int]$RawUndetected,
        [int]$RawHarmless = 0
    )

    $ignore = @(Get-HmdIgnoreEngineList -IgnoreEngines $IgnoreEngines)
    if ($ignore.Count -eq 0 -or $null -eq $AnalysisResults) {
        return [pscustomobject]@{
            Malicious         = $RawMalicious
            Suspicious        = $RawSuspicious
            Undetected        = $RawUndetected
            Harmless          = $RawHarmless
            IgnoredEngines    = [string[]]@()
            PolicyFromResults = $false
        }
    }

    $ignoreSet = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($n in $ignore) {
        $null = $ignoreSet.Add($n)
    }

    $mal = 0
    $sus = 0
    $und = 0
    $harm = 0
    $applied = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )

    foreach ($prop in @($AnalysisResults.PSObject.Properties)) {
        $engineKey = [string]$prop.Name
        $entry = $prop.Value
        $displayName = $engineKey
        if ($null -ne $entry -and
            $null -ne $entry.PSObject.Properties['engine_name'] -and
            -not [string]::IsNullOrWhiteSpace([string]$entry.engine_name)) {
            $displayName = [string]$entry.engine_name
        }

        if ($ignoreSet.Contains($engineKey) -or $ignoreSet.Contains($displayName)) {
            $null = $applied.Add($displayName)
            continue
        }

        $cat = ''
        if ($null -ne $entry -and $null -ne $entry.PSObject.Properties['category']) {
            $cat = [string]$entry.category
        }
        switch ($cat.ToLowerInvariant()) {
            'malicious' { $mal++; break }
            'suspicious' { $sus++; break }
            'undetected' { $und++; break }
            'harmless' { $harm++; break }
        }
    }

    return [pscustomobject]@{
        Malicious         = $mal
        Suspicious        = $sus
        Undetected        = $und
        Harmless          = $harm
        IgnoredEngines    = [string[]]@($applied | Sort-Object)
        PolicyFromResults = $true
    }
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
