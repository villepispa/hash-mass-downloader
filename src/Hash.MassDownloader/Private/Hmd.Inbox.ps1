#Requires -Version 7.2

function Get-HmdInboxPaths {
    <#
    .SYNOPSIS
        Resolve inbox subfolder paths under InboxRoot.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$InboxRoot
    )

    $root = $InboxRoot.TrimEnd('\', '/')
    return [pscustomobject]@{
        Root       = $root
        Incoming   = Join-Path $root 'incoming'
        Processing = Join-Path $root 'processing'
        Done       = Join-Path $root 'done'
        Failed     = Join-Path $root 'failed'
    }
}

function Initialize-HmdInbox {
    <#
    .SYNOPSIS
        Create inbox lifecycle folders if missing.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$InboxRoot
    )

    $paths = Get-HmdInboxPaths -InboxRoot $InboxRoot
    foreach ($dir in @($paths.Root, $paths.Incoming, $paths.Processing, $paths.Done, $paths.Failed)) {
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }
    return $paths
}

function Test-HmdInboxInputFileName {
    <#
    .SYNOPSIS
        True when the leaf is a claimable URL-list input (not deploy sidecar / err).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FileName
    )

    $leaf = [IO.Path]::GetFileName($FileName)
    if ($leaf -match '(?i)\.err\.txt$') {
        return $false
    }
    if ($leaf -match '(?i)\.deploy\.(txt|csv)$') {
        return $false
    }
    return ($leaf -match '(?i)\.(txt|csv)$')
}

function Get-HmdInboxDeployMapPath {
    <#
    .SYNOPSIS
        Optional deploy map beside an input: stem.deploy.txt / stem.deploy.csv.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$InputPath
    )

    $dir = Split-Path -Parent $InputPath
    $stem = [IO.Path]::GetFileNameWithoutExtension($InputPath)
    foreach ($ext in @('.deploy.txt', '.deploy.csv')) {
        $candidate = Join-Path $dir ($stem + $ext)
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }
    return $null
}

function Get-HmdInboxNextJob {
    <#
    .SYNOPSIS
        Claim the oldest incoming input file into processing/ (same volume Move-Item).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$InboxRoot
    )

    $paths = Initialize-HmdInbox -InboxRoot $InboxRoot
    $candidates = @(
        Get-ChildItem -LiteralPath $paths.Incoming -File -ErrorAction SilentlyContinue |
            Where-Object { Test-HmdInboxInputFileName -FileName $_.Name } |
            Sort-Object LastWriteTimeUtc, Name
    )
    if ($candidates.Count -eq 0) {
        return $null
    }

    $src = $candidates[0]
    $deploySrc = Get-HmdInboxDeployMapPath -InputPath $src.FullName

    $destInput = Join-Path $paths.Processing $src.Name
    if (Test-Path -LiteralPath $destInput) {
        $stamp = Get-Date -UFormat '%Y%m%d%H%M%S'
        $destInput = Join-Path $paths.Processing ('{0}_{1}{2}' -f `
                [IO.Path]::GetFileNameWithoutExtension($src.Name),
                $stamp,
                [IO.Path]::GetExtension($src.Name))
    }

    Move-Item -LiteralPath $src.FullName -Destination $destInput -Force

    $deployDest = $null
    if ($deploySrc -and (Test-Path -LiteralPath $deploySrc)) {
        $deployDest = Join-Path $paths.Processing ([IO.Path]::GetFileName($deploySrc))
        if (Test-Path -LiteralPath $deployDest) {
            $stamp = Get-Date -UFormat '%Y%m%d%H%M%S'
            $deployDest = Join-Path $paths.Processing ('{0}_{1}{2}' -f `
                    [IO.Path]::GetFileNameWithoutExtension($deploySrc),
                    $stamp,
                    [IO.Path]::GetExtension($deploySrc))
        }
        Move-Item -LiteralPath $deploySrc -Destination $deployDest -Force
    }

    return [pscustomobject]@{
        InputPath     = $destInput
        DeployMapPath = $deployDest
        SourceName    = $src.Name
    }
}

function Move-HmdInboxJob {
    <#
    .SYNOPSIS
        Move a claimed job from processing/ to done/ or failed/ (+ optional .err.txt).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$InboxRoot,

        [Parameter(Mandatory)]
        [string]$InputPath,

        [string]$DeployMapPath,

        [Parameter(Mandatory)]
        [ValidateSet('Done', 'Failed')]
        [string]$Disposition,

        [string]$ErrorMessage
    )

    $paths = Get-HmdInboxPaths -InboxRoot $InboxRoot
    $targetRoot = if ($Disposition -eq 'Done') { $paths.Done } else { $paths.Failed }
    if (-not (Test-Path -LiteralPath $targetRoot)) {
        New-Item -ItemType Directory -Path $targetRoot -Force | Out-Null
    }

    $moveOne = {
        param([string]$Path)
        if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
            return
        }
        $leaf = [IO.Path]::GetFileName($Path)
        $dest = Join-Path $targetRoot $leaf
        if (Test-Path -LiteralPath $dest) {
            $stamp = Get-Date -UFormat '%Y%m%d%H%M%S'
            $dest = Join-Path $targetRoot ('{0}_{1}{2}' -f `
                    [IO.Path]::GetFileNameWithoutExtension($leaf),
                    $stamp,
                    [IO.Path]::GetExtension($leaf))
        }
        Move-Item -LiteralPath $Path -Destination $dest -Force
        return $dest
    }

    $movedInput = & $moveOne $InputPath
    $movedDeploy = $null
    if (-not [string]::IsNullOrWhiteSpace($DeployMapPath)) {
        $movedDeploy = & $moveOne $DeployMapPath
    }

    if ($Disposition -eq 'Failed' -and -not [string]::IsNullOrWhiteSpace($ErrorMessage) -and $movedInput) {
        $errPath = "$movedInput.err.txt"
        $ErrorMessage | Set-Content -LiteralPath $errPath -Encoding utf8
    }

    return [pscustomobject]@{
        Disposition   = $Disposition
        InputPath     = $movedInput
        DeployMapPath = $movedDeploy
    }
}

function Enter-HmdInboxMutex {
    <#
    .SYNOPSIS
        Acquire the inbox single-instance mutex. Fail closed when timeout elapses.
    #>
    [CmdletBinding()]
    param(
        [string]$Name,

        [int]$TimeoutMs = 0
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        $Name = 'Local\Hash.MassDownloader.Inbox'
    }

    $createdNew = $false
    $mutex = [System.Threading.Mutex]::new($false, $Name, [ref]$createdNew)
    $acquired = $false
    try {
        $acquired = $mutex.WaitOne($TimeoutMs)
    }
    catch [System.Threading.AbandonedMutexException] {
        $acquired = $true
    }

    if (-not $acquired) {
        $mutex.Dispose()
        throw ("Inbox mutex busy (name={0}; timeoutMs={1}). Another HMD inbox worker holds the lock." -f $Name, $TimeoutMs)
    }

    return $mutex
}

function Exit-HmdInboxMutex {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Threading.Mutex]$Mutex
    )

    try {
        $Mutex.ReleaseMutex()
    }
    finally {
        $Mutex.Dispose()
    }
}
