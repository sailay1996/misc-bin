$src = "
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
public struct ALPC_SERVER_SESSION_INFORMATION
{
   public int SessionId;
   public int ProcessId;
}
"

Add-Type -TypeDefinition $src
$t = [ALPC_SERVER_SESSION_INFORMATION]
$r = Use-NtObject($p = Connect-NtAlpcClient '\RPC Control\ntsvcs') {
    Get-NtObjectInformation -Object $p -InformationClass 12 -AsType $t
}

Get-NtProcess -InfoOnly -ProcessId $r.ProcessId