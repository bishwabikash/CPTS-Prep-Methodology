# Repo rules

## No comment bloat (STRICT)

Do **not** add explanatory, narrating, or restating comments to code or scripts in this repo (`automation/*.py`, `*.ps1`, `*.sh`, and any code blocks in the `.md` methodology files). This is a hard rule, not a preference.

- Do NOT write comments that restate what the code already says (`# loop over users`, `// increment i`, `# set the password`).
- Do NOT add section-divider / banner comments (`# ===== SETUP =====`), changelog comments (`# added by ...`, `# new`, `# updated`), or "what I did" narration.
- Do NOT annotate edits with comments explaining the change — the diff already shows it.
- Do NOT add docstrings/headers to trivial functions whose name is self-explanatory.

**Allowed — this is a purple-team repo, so these comment types are expected and useful:**
- OPSEC notes (what event ID does this emit, what detection rule fires, how to reduce noise)
- Detection pairing (the Sigma rule / telemetry that would catch this technique)
- Non-obvious flag/parameter justification (why `/opsec` is needed, why raw LDAP not ADSI)
- Protocol gotchas that would cost hours without the note (clock skew, LDAP signing, etype constraint)
- Brief remediation pointer ("fix: restrict CreateChild on DMSAHolder OU")

**Not allowed regardless:**
- Restating what the code does (`# get the hash`, `# loop over users`)
- Section banners (`# ==== PHASE 2 ====`) unless the file already uses them consistently
- Changelog comments (`# updated to support hash auth`, `# added 2026`)
- Docstrings on functions whose name already explains everything

When editing existing files, match the surrounding comment density and style. Prefer clear names over comments — but in this repo a short OPSEC/detection note next to an exploit step is *expected*, not clutter.
