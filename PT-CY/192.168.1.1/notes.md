---
title: Mr.robot

date: "2023-05-17"

author: MatDef

  

---

# Information Gathering

  

### Nmap
![](./images/20230524122622.png)

http-server with several videos and texts from the Mr. Robot series


## Enumeration

### Nikto

```bash
nikto -h http://192.168.1.1 > nikito
```
->nothing really interesting
wordpress- blog

### gobuster

![](./images/20230524123403.png)
-> intersting /wp-login -site
-> /robot
### wpscan
![](./images/20230524124830.png)
--> robots.txt with key-1-of-3.txt and fscocity.dic
key-1-of-3.txt: md5 hash
fscocity.dic: dictinary with usernames and password

![](./images/20230524132712.png)
because of many duplicates in the dict

![[Pasted image 20230524132712.png]]

# Exploitation
Find out username for wp-login
Get Post-String from Burpsuite.
Use http-post-form module from Hydra
Find out username for wp-login:
![](./images/20230524132641.png)
Find out password for wp-login:
![](./images/2023-05-24 17_07_34.png)
`elliot:ER28-0652`

Two ways to build in a php-rev shell:
- as 404.php template in the themes
- as a faulty plugin



# Privilege Escaltion


  
  

---

  

# References

  



  

<br>

  

___─ Written by MatDef ─___