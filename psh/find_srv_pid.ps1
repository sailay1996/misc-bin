Param([string]$Path)
Use-NtObject($f = Get-NtFile -Win32Path $Path -Access ReadAttributes) {
    $pids = $f.GetUsingProcessIds() | Write-Output
    Get-NtProcess -InfoOnly | ? { $_.ProcessId -in $pids }
}