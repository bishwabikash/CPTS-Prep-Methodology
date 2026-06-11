# CherryTree → SysReptor Transfer Guide (HTB CPTS)

Your workflow: hack and take notes in CherryTree → transfer into SysReptor for the final PDF report.

This guide tells you exactly what to copy from which CherryTree node into which SysReptor section.

Official HTB SysReptor template: [github.com/Syslifters/HackTheBox-Reporting](https://github.com/Syslifters/HackTheBox-Reporting)
Free cloud: [htb.sysreptor.com/htb/signup](https://htb.sysreptor.com/htb/signup/)

---

## Before You Start Writing

```
1. Log into SysReptor cloud (or self-hosted instance)
2. Create new project → select "HTB CPTS" design
3. Fill in Document Control metadata (your name, dates, customer info)
   ⚠️  SysReptor uses {{ report.candidate.name }} to render your name
   ⚠️  NEVER put this inside backticks ` ` or it won't render
4. Open your CherryTree exam notes alongside SysReptor
5. Follow the transfer map below, section by section
```

---

## Transfer Map

```
CherryTree Node                    →  SysReptor Section
─────────────────────────────────────────────────────────────
Node 1: Network Overview           →  Assessment Summary
Node 5: Activity Log               →  (source for building walkthrough)
Node 6: Walkthrough Draft          →  Internal Network Compromise Walkthrough
  ├── Step-by-Step Summary         →    Walkthrough: step list
  └── Detailed Walkthrough         →    Walkthrough: detailed (commands + screenshots)
Node 7: Findings                   →  Findings (create one finding per node)
  ├── Finding title                →    Finding: Title field
  ├── CVSS / CWE                   →    Finding: CVSS calculator + CWE dropdown
  ├── Enumeration section          →    Finding: Details (markdown body)
  ├── Exploitation section         →    Finding: Details (markdown body)
  └── Remediation                  →    Finding: Recommendation field
Node 8: Executive Summary Draft    →  Executive Summary
  ├── Assessment Overview          →    Executive Summary: overview paragraph
  └── Recommendations              →    Executive Summary: recommendations
Node 9: Remediation Summary        →  Remediation Summary
  ├── Short-Term                   →    Short-term remediation
  ├── Medium-Term                  →    Medium-term remediation
  └── Long-Term                    →    Long-term remediation
Node 0: Credentials                →  Appendix B
Node 2: Host port scans            →  Appendix A
Node 3: AD / BloodHound graphs     →  Appendix C
```

---

## Section-by-Section: What to Write

### Assessment Summary (from Node 1)

Copy your scope info. SysReptor pre-fills most of this — just verify and update:

```
- Target network: <SUBNET>/24
- Hosts in scope: X
- Testing dates: <START> to <END>
- Tools: nmap, netexec, Burp Suite, BloodHound, certipy-ad, etc.
```

---

### Internal Network Compromise Walkthrough (from Nodes 5 + 6)

This is the longest section and the most important for passing.

#### Part 1: Step-by-Step Summary

Build this from your Activity Log (Node 5). Convert each log entry into a third-person sentence:

```
Activity Log entry:
  [D1-10:15] File upload bypass → shell as www-data

Becomes:
  The tester exploited a file upload vulnerability on 192.168.50.5 to obtain
  a reverse shell as the www-data user.
```

Write every step. Don't skip anything — even "obvious" steps like running nmap.

#### Part 2: Detailed Walkthrough

Expand each step with the command, output, and screenshot from your Host nodes (Node 2):

```markdown
#### Step 1: Port Scanning
The tester performed a full TCP port scan against the target.

​```bash
nmap -p- --min-rate 5000 -Pn 192.168.50.5
​```

![Nmap results showing ports 22, 80, 445, 5985](screenshot.png)
```

In SysReptor: paste the markdown, then drag-and-drop screenshots from your CherryTree exports or saved files.

---

### Findings (from Node 7)

For each finding node in CherryTree, create a new finding in SysReptor:

```
1. Click "Add Finding" in SysReptor
2. Set the Title (from your finding node title)
3. Click the CVSS field → use the interactive calculator
4. Select CWE from the dropdown
5. Set Affected Systems (IP + hostname)
6. Paste your Enumeration / Exploitation / Post-Exploitation sections
   into the finding Details field (markdown)
7. Paste remediation into the Recommendation field
```

Structure the Details markdown body like this:

```markdown
## Enumeration
The tester identified [what you found] on [host].

​```bash
<ENUMERATION_COMMAND>
​```

![Screenshot of enumeration](enum.png)

## Exploitation
The tester exploited [vulnerability] to [impact].

​```bash
<EXPLOIT_COMMAND>
​```

![Screenshot of exploitation](exploit.png)

## Post-Exploitation
The tester [extracted creds / escalated / pivoted].

​```bash
<POST_EXPLOIT_COMMAND>
​```

![Screenshot of post-exploitation](postexploit.png)
```

Rules:
- One vulnerability = one finding. Don't chain multiple vulns into one finding.
- SysReptor auto-sorts by CVSS score. You can toggle this off while writing.
- Redact hashes and passwords in screenshots (solid color block over them).

---

### Executive Summary (from Node 8)

Write this LAST — you need the full picture first.

#### Assessment Overview

3-4 sentences. Non-technical. Focus on impact.

```markdown
During the assessment, {{ report.candidate.name }} identified several critical
vulnerabilities across {{ report.customer_short }}'s infrastructure. Initial
access was obtained through [how you got in — plain language]. The tester
escalated privileges and pivoted into the internal network, ultimately achieving
full administrative control over the Active Directory domain. A total of [X]
findings were identified, including [X] Critical and [X] High severity issues.
```

#### Recommendations

```markdown
- Immediately patch [critical vulnerability] and rotate all compromised credentials
- Enforce strong password policies and deploy multi-factor authentication
- Implement network segmentation between DMZ and internal networks
- Conduct regular penetration testing to identify new vulnerabilities
```

No jargon. "Full control of the domain" not "DCSync'd the krbtgt hash."

---

### Remediation Summary (from Node 9)

```markdown
## Short-Term (immediate)
- Patch [CVE] on [host]
- Rotate all compromised credentials
- Disable LLMNR/NBT-NS via GPO

## Medium-Term (1-3 months)
- Enforce 14+ character password policy
- Deploy MFA for admin and remote access
- Harden AD ACLs and certificate templates

## Long-Term (3-6 months)
- Deploy EDR across all endpoints
- Implement SIEM with lateral movement alerting
- Establish quarterly penetration testing program
```

---

### Appendix (from Nodes 0, 2, 3)

```
Appendix A: Full nmap scan results     ← paste from Host nodes (Node 2) port scan sub-nodes
Appendix B: Credentials found          ← paste credential table from Node 0
Appendix C: BloodHound attack paths    ← paste screenshots from Node 3
Appendix D: Tools and versions         ← list tools you used
Appendix E: Flags                      ← flag values + locations (from Node 10)
```

---

## SysReptor Markdown Tips

```
- Paste screenshots: drag and drop into the editor
- Caption images: ![Description](image.png) — ALWAYS caption
- Code blocks: use ```bash or ```powershell for syntax highlighting
- Your name: {{ report.candidate.name }} — never inside backticks
- Bold: **text** — use sparingly
- Tables: standard markdown table syntax works
- Keep total PDF under 20 MB — prefer code blocks over screenshots where possible
```

---

## Writing Rules (from HTB exam requirements)

```
- Third person throughout: "The tester" not "I"
- Every step needs evidence: command + output or screenshot
- Redact passwords and hashes in screenshots
- Spell check everything
- No gaps in the attack chain — if you can't explain how you got from A to B,
  the examiner will notice
- Write the report as you go (during hacking days) — don't leave it all for the end
```

---

## Pre-Submission Checklist

```
□ PDF exported from SysReptor, under 20 MB
□ {{ report.candidate.name }} renders correctly (not raw template text)
□ All screenshots legible and captioned
□ Passwords/hashes redacted in screenshots
□ Every host has proof: whoami + flag + hostname + IP in one screenshot
□ Walkthrough covers complete chain with no gaps
□ Each finding has: CVSS, CWE, evidence, remediation
□ Findings sorted by severity (highest CVSS first)
□ Executive summary is non-technical, focuses on business impact
□ Third person throughout
□ Spell check done
□ Exported PDF reviewed page by page for rendering issues
□ Submitted to HTB exam portal before deadline
```
