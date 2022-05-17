function Get-ProcessPipes{
    param(
        [Parameter(Mandatory=$false)]
        [string]$CSV
    )

    Add-Type -TypeDefinition  @"
        using System;
        using System.Diagnostics;
        using System.Runtime.InteropServices;
     
        public static class Kernel32
        {
            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern IntPtr CreateFile(
                  string filename,
                  System.IO.FileAccess access,
                  System.IO.FileShare share,
                  IntPtr securityAttributes,
                  System.IO.FileMode creationDisposition,
                  uint flagsAndAttributes,
                  IntPtr templateFile);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool GetNamedPipeServerProcessId(IntPtr hPipe, out int ClientProcessId);
        
            [DllImport("kernel32.dll", SetLastError=true)]
            public static extern bool CloseHandle(IntPtr hObject);
        }
"@

    #Get pipes
    $pipes = Get-ChildItem -Path \\.\pipe\ | select -ExpandProperty FullName
    $output = @()

    foreach($pipe in $pipes)
    {
        #Get handle to pipe
        $hPipe = [Kernel32]::CreateFile($pipe, [System.IO.FileAccess]::Read, [System.IO.FileShare]::None, [System.IntPtr]::Zero, [System.IO.FileMode]::Open, [System.UInt32]::0x80,[System.IntPtr]::Zero)

        #Get the owner of the pipe
        $pipeOwnerFound = [Kernel32]::GetNamedPipeServerProcessId([System.IntPtr]$hPipe, [ref]$pipeOwner)
        if ($pipeOwnerFound)
        {
            # Get process name
            $processName = Get-WmiObject -Query "SELECT Caption FROM Win32_Process WHERE ProcessID = $pipeOwner" | select -ExpandProperty Caption
            # Add to the output results

            $output += New-Object PSObject -Property @{
                ProcessID = $pipeOwner
                ProcessName = $processName
                NamedPipe = $pipe
            }

        }
        #close the handle
        $closeHandle = [Kernel32]::CloseHandle($hPipe)
        if(!$closeHandle)
        {
            Write-Host "[!] CloseHandle: Error closing pipe handle."
        }
    }

    if ($csv)
    {
        $output | Export-Csv $CSV -NoTypeInformation
    }
    else
    {
        $output
    }
}