#Requires -Version 7.2

function Get-HmdProgressPercent {
    <#
    .SYNOPSIS
        Map current/total to a 0-100 percent for Write-Progress.
    #>
    [CmdletBinding()]
    param(
        [int]$Current = 0,
        [int]$Total = 0
    )

    if ($Total -le 0) {
        return 0
    }
    $raw = [int][Math]::Floor((100.0 * $Current) / $Total)
    if ($raw -lt 0) { return 0 }
    if ($raw -gt 100) { return 100 }
    return $raw
}

function Format-HmdProgressLine {
    <#
    .SYNOPSIS
        Build one progress.log / host line (no secrets; newline-safe).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Phase,
        [Parameter(Mandatory)]
        [string]$Status,
        [string]$Message = '',
        [int]$Current = 0,
        [int]$Total = 0,
        [datetime]$Timestamp = (Get-Date)
    )

    $msg = [string]$Message
    if (-not [string]::IsNullOrEmpty($msg)) {
        $msg = ($msg -replace '[\r\n]+', ' ').Trim()
    }
    $stamp = $Timestamp.ToString('o')
    $frac = ''
    if ($Total -gt 0) {
        $frac = " $Current/$Total"
    }
    $tail = ''
    if (-not [string]::IsNullOrWhiteSpace($msg)) {
        $tail = " $msg"
    }
    return "$stamp PHASE=$Phase STATUS=$Status$frac$tail"
}

function New-HmdProgressContext {
    <#
    .SYNOPSIS
        Resolve DisplayProgress / ProgressLog into host, bar, and log path.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Config,
        [string]$WorkRoot,
        [switch]$AgentSummary,
        [hashtable]$ConfigOverride = @{}
    )

    $display = $true
    if ($null -ne $Config.PSObject.Properties['DisplayProgress']) {
        $display = [bool]$Config.DisplayProgress
    }
    if ($AgentSummary -and -not $ConfigOverride.ContainsKey('DisplayProgress')) {
        $display = $false
    }

    $logEnabled = $true
    if ($null -ne $Config.PSObject.Properties['ProgressLog']) {
        $logEnabled = [bool]$Config.ProgressLog
    }

    $logPath = $null
    if ($logEnabled -and -not [string]::IsNullOrWhiteSpace($WorkRoot)) {
        $logPath = [IO.Path]::Combine($WorkRoot, 'logs', 'progress.log')
    }

    return [pscustomobject]@{
        WriteHost = $display
        WriteBar  = $display
        LogPath   = $logPath
    }
}

function Write-HmdProgress {
    <#
    .SYNOPSIS
        Emit one progress event to the host, Write-Progress bar, and/or progress.log.
    .DESCRIPTION
        STEP events update the bar and log only (no host line). START / ITEM / DONE
        also Write-Host when the context allows it. Never logs secrets.
    #>
    [CmdletBinding()]
    param(
        [pscustomobject]$Context,
        [Parameter(Mandatory)]
        [string]$Phase,
        [Parameter(Mandatory)]
        [ValidateSet('START', 'ITEM', 'STEP', 'DONE')]
        [string]$Status,
        [string]$Message = '',
        [int]$Current = 0,
        [int]$Total = 0,
        [bool]$HostLine = $true,
        [switch]$Completed
    )

    $writeHost = $false
    $writeBar = $false
    $logPath = $null
    if ($null -ne $Context) {
        if ($null -ne $Context.PSObject.Properties['WriteHost']) {
            $writeHost = [bool]$Context.WriteHost
        }
        if ($null -ne $Context.PSObject.Properties['WriteBar']) {
            $writeBar = [bool]$Context.WriteBar
        }
        if ($null -ne $Context.PSObject.Properties['LogPath']) {
            $logPath = $Context.LogPath
        }
    }

    if ($Status -eq 'STEP') {
        $HostLine = $false
    }

    $line = Format-HmdProgressLine -Phase $Phase -Status $Status `
        -Message $Message -Current $Current -Total $Total

    if (-not [string]::IsNullOrWhiteSpace($logPath)) {
        $dir = Split-Path -Parent $logPath
        if (-not [string]::IsNullOrWhiteSpace($dir) -and
            -not (Test-Path -LiteralPath $dir)) {
            $null = New-Item -ItemType Directory -Path $dir -Force
        }
        [System.IO.File]::AppendAllText(
            $logPath,
            ($line + [Environment]::NewLine),
            [System.Text.UTF8Encoding]::new($false)
        )
    }

    if ($writeHost -and $HostLine) {
        Write-Host $line
    }

    if ($writeBar) {
        $percent = Get-HmdProgressPercent -Current $Current -Total $Total
        $activity = "Hash.MassDownloader — $Phase"
        if ($Completed -or ($Status -eq 'DONE' -and $Phase -eq 'Complete')) {
            Write-Progress -Id 1 -Activity $activity -Completed
        }
        else {
            $statusText = $Message
            if ([string]::IsNullOrWhiteSpace($statusText)) {
                $statusText = $Status
            }
            if ($Total -gt 0) {
                $statusText = "$Current/$Total $statusText"
            }
            Write-Progress -Id 1 -Activity $activity -Status $statusText `
                -PercentComplete $percent
        }
    }
}
