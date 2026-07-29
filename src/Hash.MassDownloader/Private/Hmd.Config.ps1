#Requires -Version 7.2

function Get-HmdRepoRoot {
    [CmdletBinding()]
    param()

    $here = $PSScriptRoot
    # Private → module → src → repo
    return (Resolve-Path -LiteralPath (Join-Path $here '..\..\..')).Path
}

function Get-HmdConfig {
    <#
    .SYNOPSIS
        Load defaults JSON and apply optional overrides.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Override = @{}
    )

    $defaultsPath = Join-Path (Get-HmdRepoRoot) 'config\hmd.defaults.json'
    if (-not (Test-Path -LiteralPath $defaultsPath)) {
        throw "Defaults config not found: $defaultsPath"
    }

    $raw = Get-Content -LiteralPath $defaultsPath -Raw -Encoding utf8
    $cfg = $raw | ConvertFrom-Json

    $map = [ordered]@{}
    foreach ($p in $cfg.PSObject.Properties) {
        $map[$p.Name] = $p.Value
    }
    foreach ($k in $Override.Keys) {
        $map[$k] = $Override[$k]
    }

    return [pscustomobject]$map
}

function Resolve-HmdApiKey {
    [CmdletBinding()]
    param(
        [SecureString]$ApiKey
    )

    if ($null -ne $ApiKey) {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ApiKey)
        try {
            return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }

    $envKey = $env:VIRUSTOTAL_API_KEY
    if ([string]::IsNullOrWhiteSpace($envKey)) {
        throw 'VirusTotal API key required: set VIRUSTOTAL_API_KEY or pass -ApiKey.'
    }
    return $envKey.Trim()
}

function ConvertTo-HmdFlatArray {
    <#
    .SYNOPSIS
        Normalize accidentally nested arrays to a flat object[].
    .DESCRIPTION
        Unwraps a single level of `Object[] { T[] }` nesting. Does not enumerate
        PSCustomObject property bags (avoids IEnumerable false positives).
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$InputObject
    )

    if ($null -eq $InputObject) {
        return [object[]]@()
    }

    $cur = $InputObject
    while (
        $cur -is [System.Array] -and
        $cur.Rank -eq 1 -and
        $cur.Length -eq 1 -and
        $null -ne $cur.GetValue(0) -and
        $cur.GetValue(0) -is [System.Array]
    ) {
        $cur = $cur.GetValue(0)
    }

    if ($cur -is [string]) {
        return [object[]]@($cur)
    }
    if ($cur -is [System.Array]) {
        $out = [System.Collections.Generic.List[object]]::new()
        foreach ($el in $cur) {
            $out.Add($el)
        }
        return [object[]]$out.ToArray()
    }
    return [object[]]@($cur)
}
