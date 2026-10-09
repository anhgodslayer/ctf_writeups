## SAU
### Initial access

We find ssrf of request-basket on port 5555, after that we exploit  https://github.com/spookier/Maltrail-v0.53-Exploit.git in the 127.0.0.1:80 in ssrf we have and get reverse shell for initial access.

![[Assets/Screenshot from 2026-08-28 20-36-33.png]]

### Priv escalation
We use GTFOBIN or using dirtyfrag cuz system have gcc

```bash
puma@sau:/opt/maltrail$ sudo -l
sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
puma@sau:/opt/maltrail$ 

# cat root.txt
cat root.txt
726392248ac1761842657156de7c8008
# 


```

