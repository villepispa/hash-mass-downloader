#Requires -Version 7.2

function Test-HmdDeployDestinationLine {
    <#
    .SYNOPSIS
        True when a TXT map line is a destination header (@path or [path]).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Line
    )

    $t = $Line.Trim()
    if ($t.StartsWith('@')) {
        return -not [string]::IsNullOrWhiteSpace($t.Substring(1).Trim())
    }
    if ($t.StartsWith('[') -and $t.EndsWith(']') -and $t.Length -gt 2) {
        return $true
    }
    return $false
}

function Get-HmdDeployDestinationFromLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Line
    )

    $t = $Line.Trim()
    if ($t.StartsWith('@')) {
        return $t.Substring(1).Trim().Trim('"').Trim("'")
    }
    if ($t.StartsWith('[') -and $t.EndsWith(']')) {
        return $t.Substring(1, $t.Length - 2).Trim().Trim('"').Trim("'")
    }
    return $t
}

function Test-HmdDeployPatternIsGlob {
    <#
    .SYNOPSIS
        True when a map File entry uses * or ? wildcards.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Pattern
    )

    return ($Pattern.IndexOf('*') -ge 0) -or ($Pattern.IndexOf('?') -ge 0)
}

function Test-HmdDeployKeyMatches {
    <#
    .SYNOPSIS
        Match a candidate key to a map File pattern (exact or -like glob).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Key,
        [Parameter(Mandatory)]
        [string]$Pattern,
        [bool]$IsGlob = $false
    )

    if ($IsGlob) {
        return $Key -like $Pattern
    }
    return [string]::Equals($Key, $Pattern, [StringComparison]::OrdinalIgnoreCase)
}

function Import-HmdDeployMap {
    <#
    .SYNOPSIS
        Parse a Clean-deploy map (sectioned TXT or Destination,File CSV).
    .OUTPUTS
        Objects with Destination and File properties (one row per mapping).
        File may be an exact leaf or a wildcard (* / ?).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Deploy map not found: $Path"
    }

    $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant()
    $rows = [System.Collections.Generic.List[object]]::new()

    if ($ext -eq '.csv') {
        $csv = @(Import-Csv -LiteralPath $Path)
        foreach ($row in $csv) {
            $dest = $null
            $file = $null
            foreach ($name in @('Destination', 'Dest', 'Path', 'Target')) {
                if ($row.PSObject.Properties.Name -contains $name -and
                    -not [string]::IsNullOrWhiteSpace([string]$row.$name)) {
                    $dest = [string]$row.$name
                    break
                }
            }
            foreach ($name in @('File', 'FileName', 'Name', 'Leaf')) {
                if ($row.PSObject.Properties.Name -contains $name -and
                    -not [string]::IsNullOrWhiteSpace([string]$row.$name)) {
                    $file = [string]$row.$name
                    break
                }
            }
            if ([string]::IsNullOrWhiteSpace($dest) -or [string]::IsNullOrWhiteSpace($file)) {
                continue
            }
            $rows.Add([pscustomobject]@{
                    Destination = $dest.Trim().Trim('"').Trim("'")
                    File        = $file.Trim().Trim('"').Trim("'")
                }) | Out-Null
        }
    }
    else {
        $currentDest = $null
        foreach ($line in @(Get-Content -LiteralPath $Path -Encoding utf8)) {
            $t = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($t)) { continue }
            if ($t.StartsWith('#')) { continue }

            if (Test-HmdDeployDestinationLine -Line $t) {
                $currentDest = Get-HmdDeployDestinationFromLine -Line $t
                continue
            }

            if ([string]::IsNullOrWhiteSpace($currentDest)) {
                throw "Deploy map file entry before any destination: $t"
            }

            $file = $t.Trim('"').Trim("'")
            # Allow optional "file -> dest" one-liners under a section (ignore arrow dest).
            if ($file -match '^(.+?)\s*->\s*.+$') {
                $file = $Matches[1].Trim().Trim('"').Trim("'")
            }
            $rows.Add([pscustomobject]@{
                    Destination = $currentDest
                    File        = $file
                }) | Out-Null
        }
    }

    foreach ($r in $rows) {
        $r
    }
}

function Resolve-HmdDeployLeafOut {
    <#
    .SYNOPSIS
        Choose the destination leaf name for a matched Clean record.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Record,
        [Parameter(Mandatory)]
        [string]$Pattern,
        [bool]$IsGlob = $false
    )

    $srcPath = [string]$Record.LocalPath
    $leafOut = [IO.Path]::GetFileName($srcPath)

    if ($IsGlob) {
        # Prefer unprefixed leaf when the staged name has NNNN_ and the URL/leaf matches.
        if ($leafOut -match '^\d{4}_(.+)$') {
            $stripped = $Matches[1]
            $keys = Get-HmdDeployMatchKeys -FileName ([string]$Record.FileName) -Url ([string]$Record.Url)
            foreach ($k in $keys) {
                if ($k -eq $stripped -and ($stripped -like $Pattern)) {
                    return $stripped
                }
            }
        }
        return $leafOut
    }

    if ($Pattern -notmatch '^\d{4}_' -and $leafOut -match '^\d{4}_(.+)$' -and $Matches[1] -eq $Pattern) {
        return $Pattern
    }
    if ($Pattern -eq [IO.Path]::GetFileName($srcPath)) {
        return $Pattern
    }
    if ($Pattern -notmatch '[\\/]' -and $Pattern -ne [IO.Path]::GetFileName($srcPath)) {
        if ($Pattern -eq (Get-HmdUrlLeafName -Url ([string]$Record.Url) -Index 0) -or
            ($Record.FileName -match '^\d{4}_(.+)$' -and $Matches[1] -eq $Pattern)) {
            return $Pattern
        }
    }
    return $leafOut
}

function Copy-HmdCleanDeploy {
    <#
    .SYNOPSIS
        Copy Clean scan records to mapped destinations; create folders as needed.
    .DESCRIPTION
        Map File entries may be exact names or wildcards (* / ?). A glob expands
        to every matching Clean record (deduped by LocalPath).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Records,
        [Parameter(Mandatory)]
        [object[]]$MapRows,
        [Parameter(Mandatory)]
        [string]$WorkRoot,
        [bool]$Overwrite = $true
    )

    $logPath = Join-Path $WorkRoot 'logs\deploy_copy.csv'
    $results = [System.Collections.Generic.List[object]]::new()
    $clean = @($Records | Where-Object {
            [string]$_.Verdict -eq 'Clean' -and
            -not [string]::IsNullOrWhiteSpace([string]$_.LocalPath) -and
            (Test-Path -LiteralPath ([string]$_.LocalPath))
        })

    # Index Clean records by match keys.
    $byKey = @{}
    foreach ($rec in $clean) {
        $keys = Get-HmdDeployMatchKeys -FileName ([string]$rec.FileName) -Url ([string]$rec.Url)
        foreach ($k in $keys) {
            $lk = $k.ToLowerInvariant()
            if (-not $byKey.ContainsKey($lk)) {
                $byKey[$lk] = [System.Collections.Generic.List[object]]::new()
            }
            $byKey[$lk].Add($rec)
        }
    }

    foreach ($map in $MapRows) {
        $destRoot = [string]$map.Destination
        $want = [string]$map.File
        $isGlob = Test-HmdDeployPatternIsGlob -Pattern $want
        $candidates = [System.Collections.Generic.List[object]]::new()
        $seenPaths = @{}

        if ($isGlob) {
            foreach ($rec in $clean) {
                $keys = Get-HmdDeployMatchKeys -FileName ([string]$rec.FileName) -Url ([string]$rec.Url)
                $hit = $false
                foreach ($k in $keys) {
                    if (Test-HmdDeployKeyMatches -Key $k -Pattern $want -IsGlob $true) {
                        $hit = $true
                        break
                    }
                }
                if (-not $hit) { continue }
                $pathKey = ([string]$rec.LocalPath).ToLowerInvariant()
                if ($seenPaths.ContainsKey($pathKey)) { continue }
                $seenPaths[$pathKey] = $true
                $candidates.Add($rec) | Out-Null
            }
        }
        else {
            $lk = $want.ToLowerInvariant()
            if ($byKey.ContainsKey($lk)) {
                foreach ($rec in @($byKey[$lk])) {
                    $pathKey = ([string]$rec.LocalPath).ToLowerInvariant()
                    if ($seenPaths.ContainsKey($pathKey)) { continue }
                    $seenPaths[$pathKey] = $true
                    $candidates.Add($rec) | Out-Null
                }
            }
            # Prefer exact FileName match ordering for single-file semantics.
            if ($candidates.Count -gt 1) {
                $exact = @($candidates | Where-Object { [string]$_.FileName -eq $want })
                if ($exact.Count -gt 0) {
                    $candidates.Clear()
                    $candidates.Add($exact[0]) | Out-Null
                }
                else {
                    $first = $candidates[0]
                    $candidates.Clear()
                    $candidates.Add($first) | Out-Null
                }
            }
        }

        if ($candidates.Count -eq 0) {
            $results.Add([pscustomobject]@{
                    File        = $want
                    Destination = $destRoot
                    SourcePath  = ''
                    DestPath    = ''
                    Status      = 'Miss'
                    Error       = 'No Clean file matched map entry'
                    CopiedAt    = (Get-Date).ToString('o')
                }) | Out-Null
            continue
        }

        foreach ($srcRec in $candidates) {
            $srcPath = [string]$srcRec.LocalPath
            $leafOut = Resolve-HmdDeployLeafOut -Record $srcRec -Pattern $want -IsGlob $isGlob

            try {
                $null = New-Item -ItemType Directory -Force -Path $destRoot
                $destPath = Join-Path $destRoot $leafOut
                if ((Test-Path -LiteralPath $destPath) -and -not $Overwrite) {
                    $results.Add([pscustomobject]@{
                            File        = $want
                            Destination = $destRoot
                            SourcePath  = $srcPath
                            DestPath    = $destPath
                            Status      = 'SkippedExists'
                            Error       = ''
                            CopiedAt    = (Get-Date).ToString('o')
                        }) | Out-Null
                    continue
                }
                Copy-Item -LiteralPath $srcPath -Destination $destPath -Force
                $results.Add([pscustomobject]@{
                        File        = $want
                        Destination = $destRoot
                        SourcePath  = $srcPath
                        DestPath    = $destPath
                        Status      = 'Copied'
                        Error       = ''
                        CopiedAt    = (Get-Date).ToString('o')
                    }) | Out-Null
            }
            catch {
                $results.Add([pscustomobject]@{
                        File        = $want
                        Destination = $destRoot
                        SourcePath  = $srcPath
                        DestPath    = ''
                        Status      = 'Error'
                        Error       = $_.Exception.Message
                        CopiedAt    = (Get-Date).ToString('o')
                    }) | Out-Null
            }
        }
    }

    if ($results.Count -gt 0) {
        $results | Export-Csv -LiteralPath $logPath -NoTypeInformation -Encoding utf8
    }

    $copied = @($results | Where-Object { $_.Status -eq 'Copied' }).Count
    $miss = @($results | Where-Object { $_.Status -eq 'Miss' }).Count
    $err = @($results | Where-Object { $_.Status -eq 'Error' }).Count
    $skipped = @($results | Where-Object { $_.Status -eq 'SkippedExists' }).Count

    return [pscustomobject]@{
        DeployLogPath    = $(if (Test-Path -LiteralPath $logPath) { $logPath } else { $null })
        DeployedCount    = $copied
        DeployMissCount  = $miss
        DeployErrorCount = $err
        DeploySkipCount  = $skipped
        Results          = @($results)
    }
}
