#Requires -Version 7.2

function Get-HmdDefaultArchiveExtensions {
    <#
    .SYNOPSIS
        Default ZIP-family extensions for archive inspection (HMD-006).
    #>
    [CmdletBinding()]
    param()

    return @('.zip', '.jar', '.hpi', '.jpi')
}

function Get-HmdDefaultArchiveInterestingExtensions {
    <#
    .SYNOPSIS
        Default high-risk member extensions for selective VT (HMD-045).
    #>
    [CmdletBinding()]
    param()

    return @(
        '.exe', '.dll', '.ps1', '.bat', '.cmd', '.vbs', '.js',
        '.msi', '.scr', '.com', '.sys', '.jar', '.hpi', '.jpi'
    )
}

function Get-HmdDefaultArchiveInterestPathKeywords {
    <#
    .SYNOPSIS
        Default path substrings that mark an archive member interesting.
    #>
    [CmdletBinding()]
    param()

    return @('bin/', 'lib/', 'plugins/')
}

function Resolve-HmdArchiveVtMode {
    <#
    .SYNOPSIS
        Resolve ArchiveVtMode: None | All | Interesting (HMD-045).
    .DESCRIPTION
        Prefer explicit ArchiveVtMode. Else map ArchiveContentsHashOnly
        (true→None, false→All) for HMD-006 back-compat. Default None.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Config
    )

    if ($null -ne $Config.PSObject.Properties['ArchiveVtMode'] -and
        -not [string]::IsNullOrWhiteSpace([string]$Config.ArchiveVtMode)) {
        $raw = [string]$Config.ArchiveVtMode
        switch -Regex ($raw.Trim()) {
            '^(?i)none$' { return 'None' }
            '^(?i)all$' { return 'All' }
            '^(?i)interesting$' { return 'Interesting' }
            default {
                throw "Invalid ArchiveVtMode '$raw' (expected None, All, or Interesting)."
            }
        }
    }

    $hashOnly = $true
    if ($null -ne $Config.PSObject.Properties['ArchiveContentsHashOnly']) {
        $hashOnly = [bool]$Config.ArchiveContentsHashOnly
    }
    if ($hashOnly) {
        return 'None'
    }
    return 'All'
}

function Get-HmdArchiveMemberInterest {
    <#
    .SYNOPSIS
        Classify archive member interest for selective VT (HMD-045).
    .OUTPUTS
        PSCustomObject with Interesting (bool) and Reason (string; empty when not).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$EntryName,

        [string]$LocalPath = '',

        [string[]]$InterestingExtensions = @(),

        [string[]]$PathKeywords = @(),

        [bool]$CheckMz = $true
    )

    $reasons = [System.Collections.Generic.List[string]]::new()
    $exts = @($InterestingExtensions | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($exts.Count -eq 0) {
        $exts = @(Get-HmdDefaultArchiveInterestingExtensions)
    }
    $keys = @($PathKeywords | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($keys.Count -eq 0) {
        $keys = @(Get-HmdDefaultArchiveInterestPathKeywords)
    }

    $normEntry = ($EntryName -replace '\\', '/')
    $leafExt = [IO.Path]::GetExtension($normEntry)
    if (-not [string]::IsNullOrWhiteSpace($leafExt)) {
        foreach ($e in $exts) {
            $norm = [string]$e
            if (-not $norm.StartsWith('.')) {
                $norm = ".$norm"
            }
            if ($leafExt.Equals($norm, [StringComparison]::OrdinalIgnoreCase)) {
                $reasons.Add("ext:$($norm.ToLowerInvariant())") | Out-Null
                break
            }
        }
    }

    $entryLower = $normEntry.ToLowerInvariant()
    foreach ($k in $keys) {
        $kw = ([string]$k -replace '\\', '/').ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($kw)) { continue }
        if ($entryLower.Contains($kw)) {
            $reasons.Add("path:$kw") | Out-Null
            break
        }
    }

    if ($CheckMz -and -not [string]::IsNullOrWhiteSpace($LocalPath) -and
        (Test-Path -LiteralPath $LocalPath)) {
        try {
            $fs = [System.IO.File]::OpenRead($LocalPath)
            try {
                if ($fs.Length -ge 2) {
                    $b0 = $fs.ReadByte()
                    $b1 = $fs.ReadByte()
                    if ($b0 -eq 0x4D -and $b1 -eq 0x5A) {
                        $reasons.Add('mz') | Out-Null
                    }
                }
            }
            finally {
                $fs.Dispose()
            }
        }
        catch {
            # Interest classification must not fail the pipeline.
        }
    }

    $interesting = $reasons.Count -gt 0
    return [pscustomobject]@{
        Interesting = $interesting
        Reason      = $(if ($interesting) { ($reasons.ToArray() -join ';') } else { '' })
    }
}

function Test-HmdIsArchivePath {
    <#
    .SYNOPSIS
        True when the path leaf matches a configured archive extension.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [string[]]$Extensions = @()
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $false
    }
    $exts = @($Extensions | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($exts.Count -eq 0) {
        $exts = @(Get-HmdDefaultArchiveExtensions)
    }
    $leafExt = [IO.Path]::GetExtension($Path)
    if ([string]::IsNullOrWhiteSpace($leafExt)) {
        return $false
    }
    foreach ($e in $exts) {
        $norm = [string]$e
        if (-not $norm.StartsWith('.')) {
            $norm = ".$norm"
        }
        if ($leafExt.Equals($norm, [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Test-HmdIsArchiveScanRow {
    <#
    .SYNOPSIS
        True when a scanlog FileName is an archive-member audit row.
    #>
    [CmdletBinding()]
    param(
        [string]$FileName
    )

    if ([string]::IsNullOrWhiteSpace($FileName)) {
        return $false
    }
    return $FileName.StartsWith('#archive/', [StringComparison]::OrdinalIgnoreCase)
}

function Get-HmdMergedVerdict {
    <#
    .SYNOPSIS
        Worst-of merge for container + member verdicts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$Verdicts
    )

    $rank = @{
        Malicious  = 5
        Suspicious = 4
        Error      = 3
        Unknown    = 2
        Clean      = 1
    }
    $best = 'Clean'
    $bestRank = 0
    foreach ($v in $Verdicts) {
        $name = [string]$v
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $r = 0
        if ($rank.ContainsKey($name)) {
            $r = [int]$rank[$name]
        }
        if ($r -gt $bestRank) {
            $bestRank = $r
            $best = $name
        }
    }
    return $best
}

function Test-HmdArchiveEntrySafe {
    <#
    .SYNOPSIS
        Reject zip-slip / absolute archive entry names.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$EntryName,

        [Parameter(Mandatory)]
        [string]$DestinationRoot
    )

    if ([string]::IsNullOrWhiteSpace($EntryName)) {
        return $false
    }
    $normalized = $EntryName -replace '\\', '/'
    if ($normalized.StartsWith('/') -or $normalized -match '^[A-Za-z]:') {
        return $false
    }
    $parts = $normalized.Split('/', [StringSplitOptions]::RemoveEmptyEntries)
    foreach ($p in $parts) {
        if ($p -eq '..') {
            return $false
        }
    }

    $destRootFull = [IO.Path]::GetFullPath($DestinationRoot)
    $candidate = [IO.Path]::GetFullPath((Join-Path $DestinationRoot ($normalized -replace '/', [IO.Path]::DirectorySeparatorChar)))
    if (-not $candidate.StartsWith($destRootFull, [StringComparison]::OrdinalIgnoreCase)) {
        return $false
    }
    # Trailing separator edge: root itself is ok only for directories we skip.
    return $true
}

function Expand-HmdArchiveSafe {
    <#
    .SYNOPSIS
        Extract ZIP-family archive with zip-slip protection and member cap.
    .DESCRIPTION
        **Safety tier: 2**

        Controlled write under DestinationRoot only. Rejects unsafe entry names.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ArchivePath,

        [Parameter(Mandatory)]
        [string]$DestinationRoot,

        [int]$MaxMembers = 500
    )

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $null = New-Item -ItemType Directory -Force -Path $DestinationRoot
    $members = [System.Collections.Generic.List[object]]::new()

    try {
        $za = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
    }
    catch {
        return [pscustomobject]@{
            Success = $false
            Members = @()
            Error   = "Archive open failed: $($_.Exception.Message)"
        }
    }

    try {
        $fileEntries = @($za.Entries | Where-Object {
                -not [string]::IsNullOrWhiteSpace($_.FullName) -and
                -not $_.FullName.EndsWith('/') -and
                -not $_.FullName.EndsWith('\')
            })
        if ($fileEntries.Count -gt $MaxMembers) {
            return [pscustomobject]@{
                Success = $false
                Members = @()
                Error   = "Archive exceeds ArchiveMaxMembers ($MaxMembers): $($fileEntries.Count) files"
            }
        }

        foreach ($entry in $fileEntries) {
            $name = [string]$entry.FullName
            if (-not (Test-HmdArchiveEntrySafe -EntryName $name -DestinationRoot $DestinationRoot)) {
                return [pscustomobject]@{
                    Success = $false
                    Members = @()
                    Error   = "Unsafe archive entry (zip-slip): $name"
                }
            }

            $rel = ($name -replace '\\', '/')
            $outPath = Join-Path $DestinationRoot ($rel -replace '/', [IO.Path]::DirectorySeparatorChar)
            $parent = Split-Path -Parent $outPath
            if (-not [string]::IsNullOrWhiteSpace($parent)) {
                $null = New-Item -ItemType Directory -Force -Path $parent
            }

            $inStream = $entry.Open()
            try {
                $outStream = [System.IO.File]::Create($outPath)
                try {
                    $inStream.CopyTo($outStream)
                }
                finally {
                    $outStream.Dispose()
                }
            }
            finally {
                $inStream.Dispose()
            }

            $members.Add([pscustomobject]@{
                    EntryName = $rel
                    LocalPath = $outPath
                    Bytes     = [long]$entry.Length
                    Error     = ''
                }) | Out-Null
        }
    }
    finally {
        $za.Dispose()
    }

    return [pscustomobject]@{
        Success = $true
        Members = [object[]]$members.ToArray()
        Error   = ''
    }
}

function Invoke-HmdArchiveInspect {
    <#
    .SYNOPSIS
        Extract archive members under Inspected/ and compute SHA-256 per member.
    .DESCRIPTION
        **Safety tier: 2**

        Depth-1 ZIP-family inspection only (HMD-006). Does not call VirusTotal.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ArchivePath,

        [Parameter(Mandatory)]
        [string]$WorkRoot,

        [Parameter(Mandatory)]
        [string]$ParentFileName,

        [string]$ParentSha256 = '',

        [int]$MaxMembers = 500,

        [string[]]$Extensions = @()
    )

    if (-not (Test-Path -LiteralPath $ArchivePath)) {
        return [pscustomobject]@{
            Success = $false
            Members = @()
            Error   = "Archive not found: $ArchivePath"
        }
    }
    if (-not (Test-HmdIsArchivePath -Path $ArchivePath -Extensions $Extensions)) {
        return [pscustomobject]@{
            Success = $false
            Members = @()
            Error   = "Not an archive path: $ArchivePath"
        }
    }

    $safeLeaf = [IO.Path]::GetFileName($ParentFileName)
    if ([string]::IsNullOrWhiteSpace($safeLeaf)) {
        $safeLeaf = 'archive'
    }
    $destRoot = Join-Path (Join-Path $WorkRoot 'Inspected') $safeLeaf
    if (Test-Path -LiteralPath $destRoot) {
        Remove-Item -LiteralPath $destRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    $expanded = Expand-HmdArchiveSafe -ArchivePath $ArchivePath `
        -DestinationRoot $destRoot -MaxMembers $MaxMembers
    if (-not $expanded.Success) {
        return [pscustomobject]@{
            Success = $false
            Members = @()
            Error   = [string]$expanded.Error
        }
    }

    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($m in @($expanded.Members)) {
        $sha = ''
        $err = ''
        try {
            $sha = Get-HmdFileSha256 -Path $m.LocalPath
        }
        catch {
            $err = $_.Exception.Message
        }
        $out.Add([pscustomobject]@{
                EntryName     = [string]$m.EntryName
                LocalPath     = [string]$m.LocalPath
                Bytes         = [long]$m.Bytes
                Sha256        = $sha
                ParentSha256  = $ParentSha256
                Error         = $err
            }) | Out-Null
    }

    return [pscustomobject]@{
        Success = $true
        Members = [object[]]$out.ToArray()
        Error   = ''
    }
}
