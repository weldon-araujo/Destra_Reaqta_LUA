title = "Indirect Command Execution"
notes = "Adversaries may abuse these features"
impact = 100
tags = {"T1202","lolbin"}

if event.data.technique == "T1202" then
    if event.data.cmdLine:lower():find('"C:\Windows\system32\FORFILES.EXE" -p "C:\Backup\" /S /M *.* /D -3 /C "cmd /C del @path"') then
    	break
    else
        create_alert({event}, title, impact, notes, tags)
    end
end