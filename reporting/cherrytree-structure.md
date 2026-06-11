# CherryTree Note Structure (Maps to SysReptor CPTS Template)

Set up this node tree before the exam starts. The structure mirrors the SysReptor HTB CPTS report sections so you can copy nodes directly into SysReptor when writing the report.

```
CherryTree node  →  copies into  →  SysReptor section
```

---

## Node Tree

```
📁 CPTS Exam — <DATE>
│
│  ══════════════════════════════════════════════════════
│  SECTION A: LIVE NOTES (use during hacking)
│  ══════════════════════════════════════════════════════
│
├── 📁 0. Credentials & Hashes                    → Appendix B in report
│   ├── 📄 Credential Table                        (see template below)
│   └── 📄 Hashes to Crack                         (raw hashes + hashcat modes)
│
├── 📁 1. Network Overview                         → Assessment Summary section
│   ├── 📄 Scope (IP ranges, domain names)
│   ├── 📄 Live Hosts (/etc/hosts entries)
│   └── 📄 Network Diagram (text sketch or screenshot)
│
├── 📁 2. Host: <IP> — <HOSTNAME>                  ← duplicate per host
│   ├── 📄 Port Scan                               → Appendix A
│   ├── 📄 Service Enumeration
│   ├── 📄 Web App Notes (if applicable)
│   ├── 📁 Foothold
│   │   ├── 📄 Enumeration (what you found)        → Finding detail: Enumeration
│   │   ├── 📄 Exploitation (how you got in)        → Finding detail: Exploitation
│   │   └── 📄 Proof (whoami + IP screenshot)
│   ├── 📁 Privilege Escalation
│   │   ├── 📄 Enumeration                          → Finding detail: Enumeration
│   │   ├── 📄 Exploitation                          → Finding detail: Exploitation
│   │   └── 📄 Proof (whoami root + flag + IP)
│   └── 📁 Post-Exploitation
│       ├── 📄 Credentials Found                    → update node 0
│       ├── 📄 Interesting Files
│       └── 📄 Network Info (dual-homed? routes?)   → pivot decision
│
├── 📁 3. Active Directory                          → Walkthrough + AD Findings
│   ├── 📄 BloodHound Data (screenshots of paths)
│   ├── 📄 Kerberoast / AS-REP Results
│   ├── 📄 ACL / Delegation / ADCS Abuse
│   ├── 📄 Domain Admin Proof (whoami + flag + IP)
│   └── 📄 DCSync / NTDS Output
│
├── 📁 4. Pivoting                                  → Walkthrough steps
│   ├── 📄 Pivot Setup (commands, tunnel config)
│   ├── 📄 Internal Scan Results
│   └── 📄 Lateral Movement Log (cred → host → method)
│
├── 📁 5. Activity Log                              → Walkthrough source
│   └── 📄 Timeline (running log — see format below)
│
│  ══════════════════════════════════════════════════════
│  SECTION B: REPORT PREP (use when writing report)
│  ══════════════════════════════════════════════════════
│
├── 📁 6. Walkthrough Draft                         → SysReptor: Internal Network Compromise Walkthrough
│   ├── 📄 Step-by-Step Summary (one-liners)        → Walkthrough: step list
│   └── 📄 Detailed Walkthrough (commands + screenshots) → Walkthrough: detailed
│
├── 📁 7. Findings                                  → SysReptor: Findings (one per vuln)
│   ├── 📄 Finding 1: <VULN_NAME>                   (use finding template below)
│   ├── 📄 Finding 2: <VULN_NAME>
│   └── 📄 Finding N: <VULN_NAME>
│
├── 📁 8. Executive Summary Draft                   → SysReptor: Executive Summary
│   ├── 📄 Assessment Overview (3-4 sentences)
│   └── 📄 Recommendations (short/medium/long term)
│
├── 📁 9. Remediation Summary                       → SysReptor: Remediation Summary
│   ├── 📄 Short-Term (immediate)
│   ├── 📄 Medium-Term (1-3 months)
│   └── 📄 Long-Term (3-6 months)
│
└── 📁 10. Exam Admin
    ├── 📄 Flag Submissions (flag values + hosts)
    ├── 📄 Report Checklist (see report-template.md)
    └── 📄 Stuck / Ideas / TODO
```

---

## Per-Host Node Template

Paste this into every new host node (node 2). Fill it in as you hack.

```
=== HOST: <IP> — <HOSTNAME> ===
OS:
Open Ports:
Services:

--- FOOTHOLD ---
Vulnerability:
CVE / CWE:
Enumeration steps:
1.
2.
Exploitation steps:
1.
2.
Screenshot: [paste here]
Shell type: (reverse shell / web shell / SSH / WinRM / RDP)
User obtained:

--- PRIVILEGE ESCALATION ---
Vulnerability:
CVE / CWE:
Enumeration steps:
1.
2.
Exploitation steps:
1.
2.
Screenshot: [paste here]
Root/Admin obtained: yes/no

--- PROOF ---
Flag location:
Flag value:
Screenshot: whoami + hostname + flag + IP (ALL IN ONE SCREENSHOT)

--- POST-EXPLOITATION ---
Credentials found: (update Credential Table in node 0)
SSH keys:
Interesting files:
Dual-homed: yes/no (ip a / ipconfig output)
Internal services on 127.0.0.1:
Pivot candidate: yes/no
```

---

## Finding Template

Paste this into each finding node (node 7). This maps directly to SysReptor's finding fields.

```
=== FINDING: <TITLE> ===

Severity: Critical / High / Medium / Low
CVSS Score: (use SysReptor calculator when transferring)
CVSS Vector: (fill in SysReptor)
CWE: CWE-XXX: <Name>
Affected Host(s): <IP> — <HOSTNAME> (port <PORT>)

## Enumeration
[What you found during recon that revealed this vulnerability]
[Commands + output]
[Screenshot]

## Exploitation
[How you exploited it — step by step]
[Commands + output]
[Screenshot of successful exploitation]

## Post-Exploitation (if applicable)
[What you did after — cred dump, pivot, persistence]
[Commands + output]
[Screenshot]

## Remediation
- [Specific fix 1]
- [Specific fix 2]
- [Specific fix 3]
```

---

## Walkthrough Step Template

Paste this into the Walkthrough Draft node (node 6). Each step becomes one line in the summary and one section in the detailed walkthrough.

```
--- STEP <N> ---
One-liner: The tester [action] on [host] and [result].
Command:
```bash
<COMMAND>
```
Output: (paste or screenshot)
Screenshot: [paste here]
```

---

## Credential Table

Keep this in node 0. Update every time you find a credential.

```
| # | Username   | Secret              | Type      | Found On    | Works On         | Admin? | How Found      |
|---|------------|---------------------|-----------|-------------|------------------|--------|----------------|
| 1 |            |                     | Plaintext |             |                  |        |                |
| 2 |            |                     | NTLM      |             |                  |        |                |
| 3 |            |                     | TGS       |             |                  |        |                |
```

---

## Activity Log Format

Keep a running log in node 5. This becomes the source for your walkthrough.

```
[DAY-HH:MM] Action — Result
[D1-09:00] nmap 192.168.50.0/24 — 5 live hosts found
[D1-09:15] nmap -p- 192.168.50.5 — ports 22, 80, 445, 5985
[D1-09:30] gobuster :80 — /admin, /api, /uploads
[D1-09:45] SQLi on /api/login — dumped users, got admin hash
[D1-10:00] Cracked: admin:Welcome1! — web app login
[D1-10:15] File upload bypass → shell as www-data
[D1-10:30] sudo -l → vim NOPASSWD → root *** SCREENSHOT ***
[D1-10:35] Found id_rsa in /root/.ssh/ → works on 192.168.50.10
[D1-10:40] ip a shows 192.168.60.0/24 interface → PIVOT
...
```

Mark `*** SCREENSHOT ***` every time you take a proof screenshot so you can find them later.

---

## Transfer Workflow: CherryTree → SysReptor

```
When you're ready to write the report:

Node 5 (Activity Log)     → Build the step-by-step summary in Node 6
Node 2 (Host nodes)       → Pull screenshots and commands into Node 6 detailed walkthrough
Node 6 (Walkthrough)      → Copy into SysReptor "Internal Network Compromise Walkthrough"

Node 2 (Host nodes)       → Group vulnerabilities into findings in Node 7
Node 7 (Findings)         → Copy each finding into SysReptor "Findings" section
                            → Set CVSS score using SysReptor calculator
                            → Select CWE from SysReptor dropdown

Node 8 (Exec Summary)     → Copy into SysReptor "Executive Summary"
Node 9 (Remediation)      → Copy into SysReptor "Remediation Summary"
Node 1 (Network Overview)  → Copy into SysReptor "Assessment Summary"
Node 0 (Credentials)      → Copy into SysReptor "Appendix"
Node 2 (Port Scans)       → Copy into SysReptor "Appendix"
```
