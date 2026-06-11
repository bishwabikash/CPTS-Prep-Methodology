# Screenshot Guide — What to Capture and When

Every screenshot you skip during the exam is a finding you can't prove in the report. This guide maps to the attack phases in the methodology files so you know exactly when to hit `Print Screen`.

---

## Screenshot Rules

1. Every screenshot must show the command AND its output
2. Include the terminal prompt (shows username@hostname = proves which machine)
3. For web attacks, capture both the Burp request/response AND the browser result
4. Timestamp your screenshots (CherryTree does this automatically with `Ctrl+T`)
5. When in doubt, screenshot it — you can always discard later, but you can't go back

```bash
# Quick screenshot from Kali terminal (saves to file)
# Full screen
scrot ~/Documents/screenshots/$(date +%Y%m%d_%H%M%S).png

# Selected area
scrot -s ~/Documents/screenshots/$(date +%Y%m%d_%H%M%S).png

# Or just use Flameshot (better for annotations)
flameshot gui
```

---

## Phase 0: Network Discovery

| When | What to Screenshot |
|---|---|
| After host discovery | nmap/masscan output showing live hosts |
| After identifying DCs | DNS SRV query results or nmap showing port 88/389/636 |

```
CherryTree node: 1. Network Overview → Live Hosts
```

---

## Phase 1: Port Scanning & Service Enumeration

| When | What to Screenshot |
|---|---|
| After full port scan | nmap `-p-` output for each host (all open ports visible) |
| After service scan | nmap `-sC -sV` output showing service versions |
| After UDP scan | Top UDP results (especially SNMP 161, DNS 53) |

```
CherryTree node: 2. Host: <IP> → Port Scan Results
```

---

## Phase 2: Service-Specific Enumeration

| When | What to Screenshot |
|---|---|
| SMB null session success | netexec output showing shares or users |
| Anonymous FTP access | FTP listing showing accessible files |
| SNMP data leak | snmpwalk output showing usernames or processes |
| Web app discovery | whatweb output + browser showing the application |
| Vhost/subdomain found | ffuf output showing new hostname |
| Interesting file found | Content of config files, credentials, keys |

```
CherryTree node: 2. Host: <IP> → Service Enumeration Notes
```

---

## Phase 3: Initial Access / Foothold

This is the most critical phase for screenshots. The report must show HOW you got in.

| When | What to Screenshot |
|---|---|
| Vulnerability identified | The evidence that the vuln exists (e.g., error message, version number) |
| Exploit preparation | Payload generation command (msfvenom, script setup) |
| Exploit execution | The command that triggers the exploit |
| Shell received | Listener catching the connection + `whoami` / `id` output |
| Web shell upload | The upload request (Burp) + accessing the shell |
| SQLi exploitation | The injection point + sqlmap/manual output showing data |
| Credential found | The file/output containing the password or hash |
| Successful login | netexec/evil-winrm/ssh showing successful authentication |

```
CherryTree node: 2. Host: <IP> → Initial Access → Exploit Steps
```

### Proof of Foothold — Required Screenshot Format
```
┌─────────────────────────────────────────────┐
│  MUST SHOW ALL OF THESE IN ONE SCREENSHOT:  │
│                                             │
│  1. whoami (or id) output                   │
│  2. hostname                                │
│  3. ip a / ipconfig (shows target IP)       │
│                                             │
│  Example (Linux):                           │
│  $ whoami && hostname && ip a | grep inet   │
│                                             │
│  Example (Windows):                         │
│  > whoami & hostname & ipconfig             │
└─────────────────────────────────────────────┘
```

---

## Phase 4: Local Enumeration (Post-Foothold)

| When | What to Screenshot |
|---|---|
| sudo -l output | Shows what you can run — even if nothing useful |
| whoami /priv (Windows) | Shows token privileges |
| Interesting SUID binary | `find / -perm -4000` output highlighting the binary |
| Writable cron job | `cat /etc/crontab` or `crontab -l` showing the job |
| Stored credentials found | cmdkey /list, PowerShell history, config files |
| Internal services found | `ss -tulnp` or `netstat -ano` showing 127.0.0.1 listeners |
| Dual-homed interface | `ip a` or `ipconfig /all` showing multiple NICs |

```
CherryTree node: 2. Host: <IP> → Local Enumeration
```

---

## Phase 5: Privilege Escalation

Same importance as initial access — the report must show the full escalation chain.

| When | What to Screenshot |
|---|---|
| Vulnerability identified | The misconfiguration or CVE evidence |
| Exploit execution | The command/tool that escalates privileges |
| Root/SYSTEM obtained | `whoami` showing root/SYSTEM/Administrator |
| Flag captured | `cat /root/proof.txt` or `type C:\Users\Administrator\Desktop\proof.txt` |

```
CherryTree node: 2. Host: <IP> → Privilege Escalation → Exploit Steps
```

### Proof of Escalation — Required Screenshot Format
```
┌──────────────────────────────────────────────────────────────┐
│  MUST SHOW ALL OF THESE IN ONE SCREENSHOT:                   │
│                                                              │
│  1. whoami showing root / NT AUTHORITY\SYSTEM / Administrator│
│  2. hostname                                                 │
│  3. Flag file content                                        │
│  4. IP address of the target                                 │
│                                                              │
│  Linux:                                                      │
│  # whoami && hostname && cat /root/proof.txt && ip a         │
│                                                              │
│  Windows:                                                    │
│  # whoami & hostname & type C:\Users\Administrator\Desktop\proof.txt & ipconfig │
│                                                              │
│  OSCP specific:                                              │
│  Also capture: local.txt (low-priv) and proof.txt (root)     │
│  # cat /home/<USER>/local.txt                                │
│  # type C:\Users\<USER>\Desktop\local.txt                    │
└──────────────────────────────────────────────────────────────┘
```

---

## Phase 6: Post-Exploitation & Credential Harvesting

| When | What to Screenshot |
|---|---|
| Credentials dumped | secretsdump / mimikatz / SAM dump output |
| Hash cracked | hashcat/john showing cracked password |
| SSH key found | `cat` of the private key + where it was found |
| Database credentials | Config file showing DB connection strings |
| New credential works on another host | netexec output showing (Pwn3d!) on new target |

```
CherryTree node: 2. Host: <IP> → Post-Exploitation / Loot
Also update: 0. Credentials & Hashes
```

---

## Phase 7: Lateral Movement & Pivoting

| When | What to Screenshot |
|---|---|
| Pivot setup | Tunnel command + confirmation it's working |
| Internal scan results | nmap through pivot showing new hosts |
| Credential reuse success | netexec spray showing access on internal hosts |
| New host compromised | Repeat the foothold + privesc screenshots for each new host |

```
CherryTree node: 4. Pivoting & Lateral Movement
```

---

## Phase 8: Active Directory Attacks

| When | What to Screenshot |
|---|---|
| BloodHound path found | Screenshot of the shortest path graph in BloodHound |
| Kerberoast results | GetUserSPNs output showing captured TGS hashes |
| Hash cracked | hashcat output showing cracked service account password |
| ACL abuse | The command that modifies the ACL + confirmation |
| ADCS exploitation | certipy-ad req + auth commands and output |
| DCSync | secretsdump output showing Administrator NTLM hash |
| Domain Admin achieved | `whoami` on DC showing DA / Enterprise Admin |
| NTDS.dit dump | secretsdump output (even partial — shows you got it) |

```
CherryTree node: 3. Active Directory → Attack Path
```

### Proof of Domain Compromise — Required Screenshot
```
┌──────────────────────────────────────────────────────────────┐
│  On the Domain Controller:                                   │
│                                                              │
│  > whoami                                                    │
│  <DOMAIN>\Administrator  (or DA group member)                │
│  > hostname                                                  │
│  DC01                                                        │
│  > ipconfig                                                  │
│  <DC_IP>                                                     │
│  > type C:\Users\Administrator\Desktop\proof.txt             │
│  <FLAG>                                                      │
└──────────────────────────────────────────────────────────────┘
```

---

## Quick Reference: Screenshot Checklist Per Host

Print this or keep it open. Check off each item as you go.

```
Host: __________ IP: __________

□ Port scan (nmap -p- output)
□ Service scan (nmap -sC -sV output)
□ Vulnerability evidence (version, error, misconfiguration)
□ Exploit command + execution
□ Shell received (whoami + hostname + IP)
□ Local enumeration highlights (sudo -l, whoami /priv, etc.)
□ Privesc vulnerability evidence
□ Privesc exploit execution
□ Root/SYSTEM proof (whoami + hostname + flag + IP)
□ Credentials/hashes found
□ Network info (dual-homed? internal services?)
□ Interesting files / loot
```
