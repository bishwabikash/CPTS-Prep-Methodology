# Reporting & Documentation Guide

> **Pick ONE flow on Day 0, do not mix mid-engagement:**
> - **SysReptor** (cloud or self-hosted, **recommended**) — auto-renders PDF, has the official HTB CPTS template, supports inline asset uploads, exam-grade workflow. Documented below.
> - **CherryTree** (legacy, file-based, manual PDF export) — fallback only if SysReptor is unavailable. Documented in [cherrytree-structure.md](cherrytree-structure.md).
>
> The two flows assume different note-taking systems for Days 1–7. Choose on Day 0 and stick with it through Day 10.

## Files in This Folder

| File | Purpose |
|---|---|
| [cherrytree-structure.md](cherrytree-structure.md) | CherryTree node layout that maps 1:1 to SysReptor CPTS sections (fallback flow) |
| [screenshot-guide.md](screenshot-guide.md) | Exactly when and what to screenshot at each attack phase |
| [report-template.md](report-template.md) | How to transfer CherryTree notes into SysReptor for the final PDF |

---

## SysReptor (HTB Official) — Primary Flow

Primary tool: **SysReptor** with the official **HTB CPTS design** (https://docs.sysreptor.com/demo-reports/). Cloud or self-hosted both work for the exam.

### Day 0 — SysReptor setup

```bash
# 1. Get an account at sysreptor.com (cloud) OR self-host:
git clone https://github.com/Syslifters/sysreptor.git
cd sysreptor/deploy && bash install.sh        # docker-compose stack on :8000

# 2. Download the HTB CPTS design + import:
curl -LO https://docs.sysreptor.com/assets/reports/htb-designs.tar.gz
tar xf htb-designs.tar.gz
# Import via UI: Designs → Import → htb-designs.tar.gz
# OR via CLI (see below — install reptor first)

# 3. Install the reptor CLI (Python pip):
pip install reptor
reptor conf                                    # interactive auth setup (URL + API token)
# Token: in SysReptor UI → User → API Tokens → Create
```

### Create the exam project

```bash
# Create project from HTB CPTS design
reptor createproject --name "CPTS Exam YYYYMMDD" --design "HTB CPTS"
# Output includes the project URL — bookmark it; this is where ALL findings go.

# Verify
reptor project --list
```

### Capture cadence — what to log to SysReptor at each phase boundary

> Don't write findings narrative until Day 8. DO log raw evidence (screenshots, output snippets, host states) into the project's **Notes** continuously — the Notes tree later gets reorganized into formal findings.

| Trigger | What to capture | How (SysReptor) |
|---|---|---|
| Got a foothold | shell screenshot + `whoami/id` + host IP + initial vector | Notes → host page → paste image (drag-drop) + command block |
| Found a credential | source path + decrypted/cracked value + reuse test result | Notes → "Credentials" tree node → row per cred |
| Privesc succeeded | before-after `whoami /priv` or `id` + exact exploit command | Notes → host page → "Privilege Escalation" subnode + screenshot |
| Lateral move | src host + tgt host + cred used + target shell screenshot | Notes → "Lateral Moves" tree → table row + image |
| BloodHound path | path graph PNG + Cypher query + edges traversed | Notes → "AD Paths" → image + code block |
| Domain compromise | DCSync output (truncated to a few hashes) + DA shell screenshot | Notes → "Domain Compromise" node — top-level highlight |
| Coerce/relay | responder/ntlmrelayx output showing the relay + cert/hash obtained | Notes → "Coerce-Relay" → command + output paste |
| AD CS abuse | `certipy find` snippet showing ESCx + the `req`/`auth` chain | Notes → "ADCS" → image + chain steps |

### `reptor` CLI — exam-day workflow

```bash
# Import nmap output as findings (auto-creates open-port findings)
reptor nmap -i nmap.xml --push-findings

# Pull a finding template by tag, fill placeholders, push to project
reptor findingfromtemplate --tags ad,kerberoast
reptor findingfromtemplate --tags adcs,esc1

# Push image → SysReptor (returns markdown link to embed in finding)
reptor file --upload screenshots/foothold.png
# → ![Image](/assets/<UUID>/foothold.png)  (paste into description)

# Export findings as TOML/JSON for backup
reptor exportfindings -o cpts-backup.json

# Generate the PDF
reptor render --project-id <UUID>             # or render via UI: Project → Render → PDF
```

### HTB CPTS finding fields (standard SysReptor schema)

When writing findings on Days 8-10, fill these fields per the HTB CPTS design:

| Field | Type | What goes here |
|---|---|---|
| `title` | string | Short identifier — "Domain Compromise via ESC8 NTLM Relay" |
| `cvss` | CVSS 3.1 vector | Use https://cvss.js.org for vector building; severity auto-derived |
| `cwe` | CWE selector | Pick the closest match — examiners check this |
| `affected_components` | list | Hosts/URLs/services impacted |
| `summary` (short_description) | string | One-line for executive summary |
| `description` | markdown | Technical explanation; **paste tool output here** |
| `impact` | markdown | Business consequence — "DA = full domain control = data exfil + ransomware" |
| `recommendation` | markdown | Specific patch, config change, or compensating control |
| `references` | list of URLs | NVD, vendor advisory, MITRE ATT&CK technique |
| `evidence` | list of images | Drag-drop screenshots; auto-uploaded to project |

### Daily cadence (10-day exam)

```text
End of every exam day:
  1. Open SysReptor project → Notes → ensure today's findings are captured
  2. reptor exportfindings -o backup-day-N.json   # off-host backup
  3. Update Notes "TOMORROW" node with first target for Day N+1
  4. Snapshot: zip the loot_<HOST>_<TIMESTAMP>/ dirs from recon scripts to a backup
```

### Report-day flow (Days 8-10)

```text
1. Open SysReptor project → "Findings" tab
2. For each Note tree node that's a real finding:
   a. Click "+ Finding" → pick template (by tag) or blank
   b. Fill the 10 schema fields above
   c. Drag-drop screenshots from disk into the description (auto-uploads)
   d. Set CVSS via the inline editor → severity auto-fills
3. Order: Critical → High → Medium → Low → Informational
4. Methodology section (HTB CPTS design has one): walk phase-by-phase
5. Executive Summary: 3-5 paragraphs — do this LAST after all findings written
6. Render → PDF → review for image breaks, broken links, copy-paste artifacts
7. Re-render after fixes. PDF is the deliverable — sysreptor.com/render is fast.
```

### Screenshot rules (CPTS examiners check these)

- **Capture exact commands.** Examiners want to reproduce.
- **Show the IP and hostname in every screenshot.** `PS1` with `\h@\u` or visible `ipconfig`/`ip a` adjacent.
- **Don't redact lab credentials.** HTB labs are fine to show. Real engagements: redact per RoE.
- **Capture FAILED attempts too** for the methodology section — shows you ruled out vectors.
- **Drag-drop directly into SysReptor.** Don't reference external file paths in markdown — uses inline asset uploads.

> **Scope reminder:** CPTS grading requires methodology demonstration, not just flags. A successful exploit with no documented methodology can still fail. Reverse: a documented attack chain with one missing flag often passes if walkthrough is solid.

> **Companion docs:** [cherrytree-structure.md](cherrytree-structure.md) — useful as a Notes-tree organizer mirror in SysReptor. [screenshot-guide.md](screenshot-guide.md) — capture-tooling tips. [report-template.md](report-template.md) — markdown template if SysReptor is unavailable.

---

## CherryTree (Fallback Flow)

```
1. BEFORE THE EXAM
   → Set up CherryTree with the node structure from cherrytree-structure.md
   → Open screenshot-guide.md alongside your methodology files
   → Sign up at https://htb.sysreptor.com/htb/signup/ (free) as a backup

2. DURING THE EXAM (hacking phase)
   → Follow the methodology files for attacks
   → Follow screenshot-guide.md for evidence collection
   → Take ALL notes in CherryTree — fill host nodes as you go
   → Update the credential table and activity log continuously
   → Write rough finding notes in CherryTree as you exploit each vuln

3. REPORT WRITING PHASE (CPTS: Days 8-10)
   → Open SysReptor → Create project → Select "HTB CPTS" template
   → Follow report-template.md to copy CherryTree nodes into SysReptor sections
   → Node 6 (Walkthrough) → SysReptor Walkthrough section
   → Node 7 (Findings) → SysReptor Findings (one per vuln)
   → Node 8 (Exec Summary) → SysReptor Executive Summary (write this LAST)
   → Export PDF → Review → Fix rendering → Re-export → Submit
```

### CherryTree tips

```bash
# Install CherryTree on Kali
sudo apt install cherrytree

# Launch
cherrytree &

# File location — save early, save often
# Recommended: ~/Documents/exam_notes.ctb
```

- Use `Ctrl+Shift+V` to paste as plain text (avoids formatting issues)
- Use `Ctrl+Alt+M` to insert a timestamp on every major action (CherryTree default for Insert Timestamp; `Ctrl+T` is reserved for inserting tables)
- Drag and drop screenshots directly into nodes
- Use the search (`Ctrl+F`) to find credentials across all nodes
- Export to HTML or PDF when building the final report
