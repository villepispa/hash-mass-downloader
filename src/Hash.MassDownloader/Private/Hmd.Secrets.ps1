#Requires -Version 7.2

$script:HmdCredNative = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class HmdCredNative {
    public const int CRED_TYPE_GENERIC = 1;
    public const int CRED_PERSIST_LOCAL_MACHINE = 2;
    public const int CRED_PERSIST_ENTERPRISE = 3;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIAL {
        public int Flags;
        public int Type;
        public string TargetName;
        public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public int CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CredRead(string target, int type, int reservedFlag, out IntPtr credentialPtr);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CredWrite(ref CREDENTIAL userCredential, int flags);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool CredFree(IntPtr cred);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CredDelete(string target, int type, int flags);

    public static string ReadGeneric(string target) {
        IntPtr ptr;
        if (!CredRead(target, CRED_TYPE_GENERIC, 0, out ptr) || ptr == IntPtr.Zero) {
            return null;
        }
        try {
            var cred = (CREDENTIAL)Marshal.PtrToStructure(ptr, typeof(CREDENTIAL));
            if (cred.CredentialBlob == IntPtr.Zero || cred.CredentialBlobSize <= 0) {
                return null;
            }
            return Marshal.PtrToStringUni(cred.CredentialBlob, cred.CredentialBlobSize / 2);
        }
        finally {
            CredFree(ptr);
        }
    }

    public static void WriteGeneric(string target, string userName, string secret, bool machinePersist) {
        byte[] bytes = Encoding.Unicode.GetBytes(secret);
        IntPtr blob = Marshal.AllocHGlobal(bytes.Length);
        try {
            Marshal.Copy(bytes, 0, blob, bytes.Length);
            var cred = new CREDENTIAL();
            cred.Type = CRED_TYPE_GENERIC;
            cred.TargetName = target;
            cred.UserName = string.IsNullOrEmpty(userName) ? Environment.UserName : userName;
            cred.CredentialBlobSize = bytes.Length;
            cred.CredentialBlob = blob;
            cred.Persist = machinePersist ? CRED_PERSIST_LOCAL_MACHINE : CRED_PERSIST_ENTERPRISE;
            cred.AttributeCount = 0;
            cred.Attributes = IntPtr.Zero;
            if (!CredWrite(ref cred, 0)) {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        finally {
            Marshal.FreeHGlobal(blob);
        }
    }

    public static bool DeleteGeneric(string target) {
        return CredDelete(target, CRED_TYPE_GENERIC, 0);
    }
}
'@

function Initialize-HmdCredNative {
    [CmdletBinding()]
    param()

    if (-not ('HmdCredNative' -as [type])) {
        Add-Type -TypeDefinition $script:HmdCredNative -ErrorAction Stop
    }
}

function Get-HmdDefaultApiKeyCredentialTarget {
    [CmdletBinding()]
    param()

    return 'Hash.MassDownloader/VirusTotal'
}

function Get-HmdApiKeyFromCredentialManager {
    <#
    .SYNOPSIS
        Read VirusTotal API key from Windows Credential Manager (generic credential).
    #>
    [CmdletBinding()]
    param(
        [string]$Target
    )

    if ([string]::IsNullOrWhiteSpace($Target)) {
        $Target = Get-HmdDefaultApiKeyCredentialTarget
    }

    Initialize-HmdCredNative
    $secret = [HmdCredNative]::ReadGeneric($Target.Trim())
    if ([string]::IsNullOrWhiteSpace($secret)) {
        return $null
    }
    return $secret.Trim()
}

function Set-HmdApiKeyCredential {
    <#
    .SYNOPSIS
        Store VirusTotal API key as a generic Windows Credential Manager entry.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [SecureString]$ApiKey,

        [string]$Target,

        [string]$UserName = 'VirusTotal',

        [switch]$LocalMachinePersist
    )

    if ([string]::IsNullOrWhiteSpace($Target)) {
        $Target = Get-HmdDefaultApiKeyCredentialTarget
    }

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ApiKey)
    try {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }

    if ([string]::IsNullOrWhiteSpace($plain)) {
        throw 'ApiKey SecureString is empty.'
    }

    Initialize-HmdCredNative
    [HmdCredNative]::WriteGeneric($Target.Trim(), $UserName, $plain.Trim(), [bool]$LocalMachinePersist)
}

function Remove-HmdApiKeyCredential {
    [CmdletBinding()]
    param(
        [string]$Target
    )

    if ([string]::IsNullOrWhiteSpace($Target)) {
        $Target = Get-HmdDefaultApiKeyCredentialTarget
    }

    Initialize-HmdCredNative
    return [HmdCredNative]::DeleteGeneric($Target.Trim())
}

function Resolve-HmdApiKey {
    <#
    .SYNOPSIS
        Resolve VT API key: -ApiKey, then Credential Manager, then VIRUSTOTAL_API_KEY.
    #>
    [CmdletBinding()]
    param(
        [SecureString]$ApiKey,

        [string]$CredentialTarget,

        [switch]$SkipCredentialManager
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

    if (-not $SkipCredentialManager) {
        if ([string]::IsNullOrWhiteSpace($CredentialTarget)) {
            try {
                $cfg = Get-HmdConfig
                if ($cfg.PSObject.Properties.Name -contains 'ApiKeyCredentialTarget' -and
                    -not [string]::IsNullOrWhiteSpace([string]$cfg.ApiKeyCredentialTarget)) {
                    $CredentialTarget = [string]$cfg.ApiKeyCredentialTarget
                }
            }
            catch {
                $CredentialTarget = Get-HmdDefaultApiKeyCredentialTarget
            }
        }
        try {
            $fromCred = Get-HmdApiKeyFromCredentialManager -Target $CredentialTarget
            if (-not [string]::IsNullOrWhiteSpace($fromCred)) {
                return $fromCred
            }
        }
        catch {
            # CredMan unavailable or empty — fall through to env.
        }
    }

    $envKey = $env:VIRUSTOTAL_API_KEY
    if ([string]::IsNullOrWhiteSpace($envKey)) {
        throw 'VirusTotal API key required: pass -ApiKey, store CredMan target (default Hash.MassDownloader/VirusTotal), or set VIRUSTOTAL_API_KEY.'
    }
    return $envKey.Trim()
}
