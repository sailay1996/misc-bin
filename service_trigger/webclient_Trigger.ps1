$Source = @"
using System;
using System.Text;
using System.Security;
using System.Collections.Generic;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Diagnostics.CodeAnalysis;
namespace JosL.WebClient{
public static class Starter{
[StructLayout(LayoutKind.Explicit, Size=16)]
public class EVENT_DESCRIPTOR{
[FieldOffset(0)]ushort Id = 1;
[FieldOffset(2)]byte Version = 0;
[FieldOffset(3)]byte Channel = 0;
[FieldOffset(4)]byte Level = 4;
[FieldOffset(5)]byte Opcode = 0;
[FieldOffset(6)]ushort Task = 0;
[FieldOffset(8)]long Keyword = 0;
}
 
[StructLayout(LayoutKind.Explicit, Size = 16)]
public struct EventData{
[FieldOffset(0)]
internal UInt64 DataPointer;
[FieldOffset(8)]
internal uint Size;
[FieldOffset(12)]
internal int Reserved;
}
 
public static void startService(){
Guid webClientTrigger = new Guid(0x22B6D684, 0xFA63, 0x4578, 0x87, 0xC9, 0xEF, 0xFC, 0xBE, 0x66, 0x43, 0xC7);
 
long handle = 0;
uint output = EventRegister(ref webClientTrigger, IntPtr.Zero, IntPtr.Zero, ref handle);
 
bool success = false;
 
if (output == 0){
EVENT_DESCRIPTOR desc = new EVENT_DESCRIPTOR();
unsafe
{
uint writeOutput = EventWrite(handle, ref desc, 0, null);
success = writeOutput == 0;
EventUnregister(handle);
}
}
}
 
[DllImport("Advapi32.dll", SetLastError = true)]
public static extern uint EventRegister(ref Guid guid, [Optional] IntPtr EnableCallback, [Optional] IntPtr CallbackContext, [In][Out] ref long RegHandle);
 
[DllImport("Advapi32.dll", SetLastError = true)]
public static extern unsafe uint EventWrite(long RegHandle, ref EVENT_DESCRIPTOR EventDescriptor, uint UserDataCount, EventData* UserData);
 
[DllImport("Advapi32.dll", SetLastError = true)]
public static extern uint EventUnregister(long RegHandle);
}
}
"@
$compilerParameters = New-Object System.CodeDom.Compiler.CompilerParameters
$compilerParameters.CompilerOptions="/unsafe"
Add-Type -TypeDefinition $Source -Language CSharp -CompilerParameters $compilerParameters
[JosL.WebClient.Starter]::startService()
$sai = ((Get-Service -Name "WebClient").Status -eq "Running")
Write-Host "[+] " -NoNewLine -ForeGroundColor Green ; Write-Host "Trigger launched: $sai";
if ($sai = "True") {
Write-Host "[+] " -NoNewLine -ForeGroundColor Green ; Write-Host "WebClient Service is Start Running."
} else {
Write-Host "[+] " -NoNewLine -ForeGroundColor Green ; Write-Host "WebClient Service is not running."
}
