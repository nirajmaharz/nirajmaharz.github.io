---
title: Vulnhub - Development
date: 2022-08-10 11:33:00 +0800
categories: [Vulnhub]
tags: [vulnhub]
math: true
mermaid: true
toc: true
comments: true
---

## Nmap Enumeration

Starting with nmap we found few open ports 22(ssh),139(NetBIOS-ssn), 445(NetBIOS-ssn), 8080(http-proxy). Nmap also indicates it as a ubuntu machine.

```bash
$nmap -sC -sV 192.168.1.124 -oN developement.nmap
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-25 19:21 +0545
Nmap scan report for 192.168.1.124
Host is up (0.0063s latency).
Not shown: 995 closed ports
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|_  2048 79:07:2b:2c:2c:4e:14:0a:e7:b3:63:46:c6:b3:ad:16 (RSA)
113/tcp  open  ident?
|_auth-owners: oident
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
|_auth-owners: root
445/tcp  open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
|_auth-owners: root
8080/tcp open  http-proxy  IIS 6.0
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Fri, 25 Jun 2021 13:41:01 GMT
|     Server: IIS 6.0
|     Last-Modified: Wed, 26 Dec 2018 01:55:41 GMT
|     ETag: "230-57de32091ad69"
|     Accept-Ranges: bytes
|     Content-Length: 560
|     Vary: Accept-Encoding
|     Connection: close
|     Content-Type: text/html
|     <html>
|     <head><title>DEVELOPMENT PORTAL. NOT FOR OUTSIDERS OR HACKERS!</title>
|     </head>
|     <body>
|     <p>Welcome to the Development Page.</p>
|     <br/>
|     <p>There are many projects in this box. View some of these projects at html_pages.</p>
|     <br/>
|     <p>WARNING! We are experimenting a host-based intrusion detection system. Report all false positives to patrick@goodtech.com.sg.</p>
|     <br/>
|     <br/>
|     <br/>
|     <hr>
|     <i>Powered by IIS 6.0</i>
|     </body>
|     <!-- Searching for development secret page... where could it be? -->
|     <!-- Patrick, Head of Development-->
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Fri, 25 Jun 2021 13:41:01 GMT
|     Server: IIS 6.0
|     Allow: GET,POST,OPTIONS,HEAD
|     Content-Length: 0
|     Connection: close
|     Content-Type: text/html
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Date: Fri, 25 Jun 2021 13:41:01 GMT
|     Server: IIS 6.0
|     Content-Length: 310
|     Connection: close
|     Content-Type: text/html; charset=iso-8859-1
|     <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
|     <html><head>
|     <title>400 Bad Request</title>
|     </head><body>
|     <h1>Bad Request</h1>
|     <p>Your browser sent a request that this server could not understand.<br />
|     </p>
|     <hr>
|     <address>IIS 6.0 Server at 2400-1A00-B050-ip6.wlink.com.np Port 8080</address>
|_    </body></html>
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: IIS 6.0
|_http-title: DEVELOPMENT PORTAL. NOT FOR OUTSIDERS OR HACKERS!
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.91%I=7%D=6/25%Time=60D5DBF3%P=x86_64-pc-linux-gnu%r(Ge
[...SNIP...]
MAC Address: 00:0C:29:53:15:AD (VMware)
Service Info: Host: DEVELOPMENT; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 4m10s, deviation: 0s, median: 4m09s
|_nbstat: NetBIOS name: DEVELOPMENT, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: development
|   NetBIOS computer name: DEVELOPMENT\x00
|   Domain name: \x00
|   FQDN: development
|_  System time: 2021-06-25T13:42:32+00:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-06-25T13:42:32
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 115.67 seconds
```

## Enumeration

Since port 8080 is running http-proxy we will start with browsing Target's IP address. Here we got some clue about html_pages.

![](/assets/Vulnhub/Development/1.png)

On reviewing the source code here they are talking about some Development secret page and Patrick is being mentioned, he could be a user:

![](/assets/Vulnhub/Development/2.png)

Moving through the html_pages mentioned earlier here, we found some html pages .

![](/assets/Vulnhub/Development/3.png)

After visiting the development.html page we found out that hackersecretpage was mentioned.

![](/assets/Vulnhub/Development/4.png)

Again after reviewing the source code of development.html page we found ./developmentsecretpage which might be the secret page we are looking for.

![](/assets/Vulnhub/Development/5.png)

On visiting the developmentsecretpage it is confirmed to be the Development secret page and a PHP file link named ‘Patrick’. is found

![](/assets/Vulnhub/Development/6.png)

If we visit the file link it opens a page with another file included in it named ‘Sitemap’.

![](/assets/Vulnhub/Development/7.png)

And when we visit /sitemap.php, we found a embedded link stating “Click here to logout”.

![](/assets/Vulnhub/Development/8.png)

When we click on the embeded link it turn out to be a login page.

![](/assets/Vulnhub/Development/9.png)

After trying some random user:pass we got some error on the page.

![](/assets/Vulnhub/Development/10.png)

when we googled about "slogin_lib.inc.php" we found an exploit on Exploit-db with the name of “/\[path\]/slog\_users.txt” which is vulnerable to RFI. Refer CVE code: 2008-5762/63.

![](/assets/Vulnhub/Development/11.png)

So, when we appeded `slog_users.txt` to our secret page `developmentsecretpage` we found some users and their password hashes which was in MD5 format.

![](/assets/Vulnhub/Development/12.png)

on decrypting their hashes, we got passwords in clear text for an intern, Patrick and qiu respectively but not for Admin.

![](/assets/Vulnhub/Development/13.png)

## Shell as intern
Since port 22 is open we can now try to login with ssh as a intern user which was successful and we got `restricted shell` as intern.

![](/assets/Vulnhub/Development/14.png)

we have found some files but we cannot see it's content since it is a restricted shell so we need to import a proper tty shell. we can import it with `echo os.system ("/bin/bash")`

![](/assets/Vulnhub/Development/15.png)

we now have a proper tty shell and we can view the contents of the files.

![](/assets/Vulnhub/Development/16.png)

## Shell as Patrick

We can now login as patrick user. On reviewing the sudo privilege for patrick user we can see that patrick can use `vim` and `nano` as root user.

![](/assets/Vulnhub/Development/17.png)

## Shell as root

using vim for privilege esclation:

>sudo /usr/bin/vim
>
>:!/bin/bash

![](/assets/Vulnhub/Development/18.png)
