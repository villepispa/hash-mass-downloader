#Requires -Version 7.2

function Get-HmdAuthenticodeInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path
        return [pscustomobject]@{
            Status    = [string]$sig.Status
            Signer    = $(if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' })
            IsSigned  = ($sig.Status -eq 'Valid' -or $sig.Status -eq 'UnknownError' -or $null -ne $sig.SignerCertificate)
        }
    }
    catch {
        return [pscustomobject]@{
            Status   = 'NotChecked'
            Signer   = ''
            IsSigned = $false
        }
    }
}

function Move-HmdByVerdict {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SourcePath,
        [Parameter(Mandatory)]
        [string]$WorkRoot,
        [Parameter(Mandatory)]
        [ValidateSet('Clean', 'Suspicious', 'Malicious', 'Unknown', 'Error')]
        [string]$Verdict,
        [bool]$QuarantineMalicious = $true,
        [bool]$QuarantineSuspicious = $false
    )

    $leaf = Split-Path -Leaf $SourcePath
    $destDir = Join-Path $WorkRoot $Verdict
    $dest = Join-Path $destDir $leaf
    if (Test-Path -LiteralPath $SourcePath) {
        Move-Item -LiteralPath $SourcePath -Destination $dest -Force
    }

    $quarantinePath = ''
    $doQuarantine = ($Verdict -eq 'Malicious' -and $QuarantineMalicious) -or
        ($Verdict -eq 'Suspicious' -and $QuarantineSuspicious)
    if ($doQuarantine -and (Test-Path -LiteralPath $dest)) {
        $q = Join-Path (Join-Path $WorkRoot 'Quarantine') $leaf
        Copy-Item -LiteralPath $dest -Destination $q -Force
        $quarantinePath = $q
    }

    return [pscustomobject]@{
        FinalPath      = $dest
        QuarantinePath = $quarantinePath
    }
}

function New-HmdHtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Records,
        [Parameter(Mandatory)]
        [string]$Path
    )

    $groups = $Records | Group-Object Verdict
    $counts = @{}
    foreach ($g in $groups) { $counts[$g.Name] = $g.Count }

    $kpi = @(
        'Clean', 'Suspicious', 'Malicious', 'Unknown', 'Error'
    ) | ForEach-Object {
        $n = if ($counts.ContainsKey($_)) { $counts[$_] } else { 0 }
        "<li><strong>${_}:</strong> $n</li>"
    }

    $rows = foreach ($r in $Records) {
        $url = [System.Net.WebUtility]::HtmlEncode([string]$r.Url)
        $hash = [System.Net.WebUtility]::HtmlEncode([string]$r.Sha256)
        $verdict = [System.Net.WebUtility]::HtmlEncode([string]$r.Verdict)
        $mal = [int]$r.Malicious
        $sus = [int]$r.Suspicious
        $sig = [System.Net.WebUtility]::HtmlEncode([string]$r.SignatureStatus)
        "<tr><td>$url</td><td>$hash</td><td>$verdict</td><td>$mal</td><td>$sus</td><td>$sig</td></tr>"
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Hash.MassDownloader report</title>
<style>
body { font-family: Segoe UI, sans-serif; margin: 1.5rem; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ccc; padding: 0.4rem 0.6rem; text-align: left; font-size: 0.9rem; }
th { background: #f4f4f4; }
</style>
</head>
<body>
<h1>Hash.MassDownloader report</h1>
<p>Generated: $([datetime]::Now.ToString('o'))</p>
<h2>KPIs</h2>
<ul>
$($kpi -join "`n")
</ul>
<h2>Inventory</h2>
<table>
<thead><tr><th>URL</th><th>SHA256</th><th>Verdict</th><th>Malicious</th><th>Suspicious</th><th>Signature</th></tr></thead>
<tbody>
$($rows -join "`n")
</tbody>
</table>
</body>
</html>
"@

    $dir = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($dir)) {
        $null = New-Item -ItemType Directory -Force -Path $dir
    }
    Set-Content -LiteralPath $Path -Value $html -Encoding utf8
    return $Path
}
