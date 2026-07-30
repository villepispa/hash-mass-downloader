#Requires -Version 7.2

function Invoke-HmdLocalAvScan {
    <#
    .SYNOPSIS
        Run a local antivirus custom scan on a file (Microsoft Defender first).
    .DESCRIPTION
        Hard-gate helper (HMD-026). Returns Status: Clean | Threat | Unavailable | Error.
        Pass -Invoker for tests (never calls real Defender).
    .OUTPUTS
        PSCustomObject with Status, ThreatName, Provider, Raw.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [string]$Provider = 'Defender',

        [scriptblock]$Invoker
    )

    if ($null -ne $Invoker) {
        $r = & $Invoker @{
            Path     = $Path
            Provider = $Provider
        }
        $status = [string]$r.Status
        if ([string]::IsNullOrWhiteSpace($status)) {
            $status = 'Error'
        }
        return [pscustomobject]@{
            Status     = $status
            ThreatName = [string]$(if ($null -ne $r.PSObject.Properties['ThreatName']) { $r.ThreatName } else { '' })
            Provider   = [string]$(if ($null -ne $r.PSObject.Properties['Provider'] -and
                    -not [string]::IsNullOrWhiteSpace([string]$r.Provider)) { $r.Provider } else { $Provider })
            Raw        = $(if ($null -ne $r.PSObject.Properties['Raw']) { $r.Raw } else { $null })
        }
    }

    if ($Provider -ne 'Defender') {
        return [pscustomobject]@{
            Status     = 'Unavailable'
            ThreatName = ''
            Provider   = $Provider
            Raw        = "Unsupported LocalAvProvider: $Provider"
        }
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{
            Status     = 'Error'
            ThreatName = ''
            Provider   = 'Defender'
            Raw        = "Path not found: $Path"
        }
    }

    $fullPath = (Resolve-Path -LiteralPath $Path).Path

    # Prefer Defender PowerShell cmdlets when present.
    $startMp = Get-Command -Name Start-MpScan -ErrorAction SilentlyContinue
    if ($null -ne $startMp) {
        try {
            Start-MpScan -ScanPath $fullPath -ScanType CustomScan -ErrorAction Stop
            $threatName = ''
            $getDet = Get-Command -Name Get-MpThreatDetection -ErrorAction SilentlyContinue
            if ($null -ne $getDet) {
                $dets = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object {
                        $res = [string]$_.Resources
                        $res -and ($res.IndexOf($fullPath, [StringComparison]::OrdinalIgnoreCase) -ge 0)
                    })
                if ($dets.Count -gt 0) {
                    $names = @(
                        $dets | ForEach-Object {
                            if ($null -ne $_.PSObject.Properties['ThreatName']) { [string]$_.ThreatName }
                            elseif ($null -ne $_.PSObject.Properties['ThreatID']) { "ThreatID=$($_.ThreatID)" }
                            else { 'Detected' }
                        } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
                    )
                    $threatName = ($names -join ';')
                    return [pscustomobject]@{
                        Status     = 'Threat'
                        ThreatName = $threatName
                        Provider   = 'Defender'
                        Raw        = $dets
                    }
                }
            }
            return [pscustomobject]@{
                Status     = 'Clean'
                ThreatName = ''
                Provider   = 'Defender'
                Raw        = 'Start-MpScan'
            }
        }
        catch {
            return [pscustomobject]@{
                Status     = 'Error'
                ThreatName = ''
                Provider   = 'Defender'
                Raw        = $_.Exception.Message
            }
        }
    }

    # Fallback: MpCmdRun.exe custom file scan (ScanType 3).
    $mpCandidates = @(
        (Join-Path ${env:ProgramFiles} 'Windows Defender\MpCmdRun.exe')
        (Join-Path ${env:ProgramFiles} 'Microsoft Defender\MpCmdRun.exe')
        (Join-Path ${env:ProgramFiles(x86)} 'Windows Defender\MpCmdRun.exe')
    )
    $mpCmd = $null
    foreach ($c in $mpCandidates) {
        if (-not [string]::IsNullOrWhiteSpace($c) -and (Test-Path -LiteralPath $c)) {
            $mpCmd = $c
            break
        }
    }
    if ($null -eq $mpCmd) {
        return [pscustomobject]@{
            Status     = 'Unavailable'
            ThreatName = ''
            Provider   = 'Defender'
            Raw        = 'Start-MpScan and MpCmdRun.exe not found'
        }
    }

    try {
        $psi = [System.Diagnostics.ProcessStartInfo]::new()
        $psi.FileName = $mpCmd
        $psi.ArgumentList.Add('-Scan')
        $psi.ArgumentList.Add('-ScanType')
        $psi.ArgumentList.Add('3')
        $psi.ArgumentList.Add('-File')
        $psi.ArgumentList.Add($fullPath)
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $stdout = $proc.StandardOutput.ReadToEnd()
        $stderr = $proc.StandardError.ReadToEnd()
        $proc.WaitForExit()
        $exit = $proc.ExitCode
        $raw = "exit=$exit`n$stdout`n$stderr".Trim()

        # MpCmdRun: 0 = no threats; non-zero often means threat or scan failure.
        # Prefer textual detection signals when present.
        $combined = "$stdout`n$stderr"
        if ($combined -match '(?i)threat\s+(found|detected)|malware|virus') {
            $name = 'MpCmdRunDetection'
            if ($combined -match '(?i)Threat\s+Name\s*:\s*(.+)') {
                $name = $Matches[1].Trim()
            }
            return [pscustomobject]@{
                Status     = 'Threat'
                ThreatName = $name
                Provider   = 'Defender'
                Raw        = $raw
            }
        }
        if ($exit -eq 0) {
            return [pscustomobject]@{
                Status     = 'Clean'
                ThreatName = ''
                Provider   = 'Defender'
                Raw        = $raw
            }
        }
        # Non-zero without clear threat text — treat as Error (hard gate: do not assume Clean).
        return [pscustomobject]@{
            Status     = 'Error'
            ThreatName = ''
            Provider   = 'Defender'
            Raw        = $raw
        }
    }
    catch {
        return [pscustomobject]@{
            Status     = 'Error'
            ThreatName = ''
            Provider   = 'Defender'
            Raw        = $_.Exception.Message
        }
    }
}
