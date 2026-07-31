#Requires -Version 7.2
<#
.SYNOPSIS
  Register a Windows Scheduled Task that polls the HMD inbox worker.

.DESCRIPTION
  **Safety tier: 2**

  Creates (or replaces with -Force) a task that runs Invoke-HmdInboxWorker.ps1
  on a fixed interval under the current user. Does not elevate; registering for
  SYSTEM requires an elevated session and is out of scope for this helper.

.PARAMETER InboxRoot
  Absolute inbox root path.

.PARAMETER WorkRootBase
  Absolute work-root parent path.

.PARAMETER TaskName
  Scheduled Task name (default Hash.MassDownloader.InboxWorker).

.PARAMETER IntervalMinutes
  Poll interval (default 5).

.PARAMETER SkipVirusTotal
  Pass -SkipVirusTotal to the worker.

.PARAMETER SkipLocalAvScan
  Pass -SkipLocalAvScan to the worker.

.PARAMETER Force
  Unregister existing task with the same name first.

.PARAMETER AgentSummary
  One success-stream line: HMD-SCHTASK-OK|FAIL …

.EXAMPLE
  pwsh -NoProfile -File .\scripts\Register-HmdInboxScheduledTask.ps1 `
    -InboxRoot 'D:\Hmd\inbox' -WorkRootBase 'D:\Hmd\jobs' -Force
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$InboxRoot,

    [Parameter(Mandatory)]
    [string]$WorkRootBase,

    [string]$TaskName = 'Hash.MassDownloader.InboxWorker',

    [ValidateRange(1, 1440)]
    [int]$IntervalMinutes = 5,

    [switch]$SkipVirusTotal,

    [switch]$SkipLocalAvScan,

    [switch]$Force,

    [switch]$AgentSummary
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$worker = Join-Path $repoRoot 'scripts\Invoke-HmdInboxWorker.ps1'
if (-not (Test-Path -LiteralPath $worker)) {
    throw "Worker script not found: $worker"
}

$inboxAbs = (Resolve-Path -LiteralPath $InboxRoot -ErrorAction SilentlyContinue)
if (-not $inboxAbs) {
    New-Item -ItemType Directory -Path $InboxRoot -Force | Out-Null
    $inboxAbs = Resolve-Path -LiteralPath $InboxRoot
}
$workAbs = (Resolve-Path -LiteralPath $WorkRootBase -ErrorAction SilentlyContinue)
if (-not $workAbs) {
    New-Item -ItemType Directory -Path $WorkRootBase -Force | Out-Null
    $workAbs = Resolve-Path -LiteralPath $WorkRootBase
}

Import-Module (Join-Path $repoRoot 'src\Hash.MassDownloader\Hash.MassDownloader.psd1') -Force
$null = Initialize-HmdInbox -InboxRoot $inboxAbs.Path

$pwsh = (Get-Command pwsh -ErrorAction Stop).Source
$argList = @(
    '-NoProfile'
    '-File'
    $worker
    '-InboxRoot'
    $inboxAbs.Path
    '-WorkRootBase'
    $workAbs.Path
    '-AgentSummary'
)
if ($SkipVirusTotal) { $argList += '-SkipVirusTotal' }
if ($SkipLocalAvScan) { $argList += '-SkipLocalAvScan' }

try {
    if ($Force) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    }

    $action = New-ScheduledTaskAction -Execute $pwsh -Argument ($argList -join ' ')
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) -RepetitionDuration ([TimeSpan]::MaxValue)
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited

    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null

    if ($AgentSummary) {
        Write-Output ("HMD-SCHTASK-OK name={0} intervalMin={1} inbox={2}" -f $TaskName, $IntervalMinutes, $inboxAbs.Path)
        exit 0
    }
    Write-Host "Registered task '$TaskName' every $IntervalMinutes min → $worker"
    exit 0
}
catch {
    if ($AgentSummary) {
        $msg = ($_.Exception.Message -replace '\s+', ' ').Trim()
        if ($msg.Length -gt 140) { $msg = $msg.Substring(0, 140) }
        Write-Output ("HMD-SCHTASK-FAIL exit=1 detail={0}" -f $msg)
        exit 1
    }
    throw
}
