# Reporting & Documentation Guide

> **⚠️ LEGACY / FALLBACK FLOW.** This directory documents the **CherryTree-based** workflow, kept as a fallback only. The **recommended** Day 0–10 reporting flow is **SysReptor + reptor CLI**, documented in the [main README → Reporting Workflow](../README.md#-reporting-workflow--sysreptor-htb-official) section. Pick ONE on Day 0 — do not mix CherryTree and SysReptor mid-engagement.

Everything you need to take notes, collect evidence, and write the final report during CPTS/OSCP exams and real engagements.

## Files in This Folder

| File | Purpose |
|---|---|
| [cherrytree-structure.md](cherrytree-structure.md) | CherryTree node layout that maps 1:1 to SysReptor CPTS sections |
| [screenshot-guide.md](screenshot-guide.md) | Exactly when and what to screenshot at each attack phase |
| [report-template.md](report-template.md) | How to transfer CherryTree notes into SysReptor for the final PDF |

## Workflow

```
1. BEFORE THE EXAM
   → Set up CherryTree with the node structure from cherrytree-structure.md
   → Open screenshot-guide.md alongside your methodology files
   → Sign up at https://htb.sysreptor.com/htb/signup/ (free)

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

## CherryTree Tips

```bash
# Install CherryTree on Kali
sudo apt install cherrytree

# Launch
cherrytree &

# File location — save early, save often
# Recommended: ~/Documents/exam_notes.ctb
```

- Use `Ctrl+Shift+V` to paste as plain text (avoids formatting issues)
- Use `Ctrl+T` to insert a timestamp on every major action
- Drag and drop screenshots directly into nodes
- Use the search (`Ctrl+F`) to find credentials across all nodes
- Export to HTML or PDF when building the final report
