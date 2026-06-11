#!/usr/bin/env python3
"""
recon.py — Automated CPTS-style recon orchestrator.

Wraps standard Kali tooling (nmap, nxc/netexec, smbclient, rpcclient,
ldapsearch, dig, whatweb, ffuf, kerbrute, enum4linux-ng, snmpwalk) to
produce structured per-target output ready for branch decisions.

Defaults are AGGRESSIVE: full TCP (-p-), UDP top-100, web brute, AD enum,
SSL audit, vhost fuzz — just point it at an IP and walk away.

Usage:
    sudo ./recon.py <IP>                                  # everything on
    sudo ./recon.py <IP> --hostname dc01 --domain eighteen.htb
    sudo ./recon.py <IP> --fast                           # top-1000 TCP, no UDP
    sudo ./recon.py <IP> --quiet                          # disable live mirror

Output tree (default ./recon_<IP>_<timestamp>):
    nmap/        — full TCP, UDP, scripted vuln/discovery scans
    smb/         — shares, users, RID brute, null/guest, pass-pol
    ldap/        — rootDSE, anon bind, SPNs, AS-REP, admins
    web/         — whatweb, headers, robots, ffuf dirs+vhosts, ssl ciphers
    dns/         — AXFR, ANY, SRV records, version.bind
    kerberos/    — kerbrute userenum
    snmp/        — community brute, snmpwalk OID dumps
    other/       — FTP, SSH, SMTP user-enum, MSSQL, MySQL, NFS, IPMI, RDP, etc.
    run.log      — every command + exit code + duration
    summary.md   — branch decisions + next attack commands
    users.txt    — harvested usernames (deduped)
    hosts.txt    — /etc/hosts hint

Author: CPTS Methodology automation
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Cosmetics
# ---------------------------------------------------------------------------
class C:
    R = "\033[91m"
    G = "\033[92m"
    Y = "\033[93m"
    B = "\033[94m"
    M = "\033[95m"
    CY = "\033[96m"
    W = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RST = "\033[0m"

def info(msg: str) -> None: print(f"{C.B}[*]{C.RST} {msg}")
def ok(msg: str) -> None:   print(f"{C.G}[+]{C.RST} {msg}")
def warn(msg: str) -> None: print(f"{C.Y}[!]{C.RST} {msg}")
def err(msg: str) -> None:  print(f"{C.R}[-]{C.RST} {msg}")
def hdr(msg: str) -> None:  print(f"\n{C.BOLD}{C.CY}=== {msg} ==={C.RST}")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
TOOLS = {
    "nmap":          "nmap",
    "rustscan":      "rustscan",
    "naabu":         "naabu",
    "masscan":       "masscan",
    "nxc":           "nxc",            # netexec
    "smbclient":     "smbclient",
    "rpcclient":     "rpcclient",
    "ldapsearch":    "ldapsearch",
    "dig":           "dig",
    "whatweb":       "whatweb",
    "ffuf":          "ffuf",
    "kerbrute":      "kerbrute",
    "enum4linux-ng": "enum4linux-ng",
    "onesixtyone":   "onesixtyone",
    "snmpwalk":      "snmpwalk",
    "host":          "host",
    "curl":          "curl",
    "smtp-user-enum":"smtp-user-enum",
}

def have(tool: str) -> bool:
    return shutil.which(TOOLS.get(tool, tool)) is not None

# Module-level run state set by main()
RUN_LOG: Path | None = None        # master log of every command + rc
MIRROR: bool = True                 # live-tee tool output to console
import threading
_LOG_LOCK = threading.Lock()
_PRINT_LOCK = threading.Lock()

def _safe_print(line: str) -> None:
    """Thread-safe stdout write — used by live mirroring."""
    with _PRINT_LOCK:
        sys.stdout.write(line)
        sys.stdout.flush()

def _append_runlog(entry: str) -> None:
    if RUN_LOG is None:
        return
    with _LOG_LOCK:
        with RUN_LOG.open("a") as fh:
            fh.write(entry)

def run(cmd: list[str] | str, outfile: Path | None = None,
        timeout: int = 600, shell: bool = False,
        tag: str | None = None) -> tuple[int, str]:
    """Run a command, stream output live to console, and tee to outfile.

    - Live mirrors stdout+stderr to the terminal (when MIRROR is True) so the
      operator can act on partial findings immediately.
    - Always writes the captured output to ``outfile`` (if given).
    - Always appends a one-line entry to the master ``RUN_LOG``.
    """
    pretty = cmd if isinstance(cmd, str) else " ".join(cmd)
    label = tag or (Path(cmd[0]).name if isinstance(cmd, list) else pretty.split()[0])
    started = time.time()
    info(f"{C.DIM}{pretty}{C.RST}")

    # Mirror prefix so multi-threaded output is readable
    prefix = f"{C.DIM}│ {C.M}{label}{C.RST}{C.DIM} │ {C.RST}" if MIRROR else ""

    try:
        proc = subprocess.Popen(
            cmd, shell=shell,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, errors="replace", bufsize=1,
        )
    except FileNotFoundError:
        err(f"tool missing: {label}")
        _append_runlog(f"[{datetime.now().isoformat(timespec='seconds')}] rc=127 {pretty}\n")
        return 127, ""

    chunks: list[str] = []
    try:
        assert proc.stdout is not None
        while True:
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    break
                continue
            chunks.append(line)
            if MIRROR:
                _safe_print(prefix + line)
            # Cooperative timeout check
            if timeout and (time.time() - started) > timeout:
                proc.kill()
                err(f"timeout after {timeout}s: {pretty}")
                _append_runlog(
                    f"[{datetime.now().isoformat(timespec='seconds')}] rc=124 "
                    f"({time.time()-started:.0f}s) {pretty}\n"
                )
                rc = 124
                out = "".join(chunks)
                if outfile:
                    outfile.parent.mkdir(parents=True, exist_ok=True)
                    outfile.write_text(out)
                return rc, out
        rc = proc.wait()
    except KeyboardInterrupt:
        proc.kill()
        raise

    out = "".join(chunks)
    if outfile:
        outfile.parent.mkdir(parents=True, exist_ok=True)
        outfile.write_text(out)
    _append_runlog(
        f"[{datetime.now().isoformat(timespec='seconds')}] rc={rc} "
        f"({time.time()-started:.0f}s) {pretty}"
        + (f"  → {outfile}" if outfile else "")
        + "\n"
    )
    return rc, out

def is_root() -> bool:
    return os.geteuid() == 0

# ---------------------------------------------------------------------------
# Recon state
# ---------------------------------------------------------------------------
@dataclass
class Target:
    ip: str
    hostname: str | None = None
    domain: str | None = None
    fqdn: str | None = None
    open_tcp: list[int] = field(default_factory=list)
    open_udp: list[int] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)  # port -> banner/svc
    users: set[str] = field(default_factory=set)
    shares: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def addresses(self) -> list[str]:
        out = [self.ip]
        if self.hostname: out.append(self.hostname)
        if self.fqdn:     out.append(self.fqdn)
        return out

# ---------------------------------------------------------------------------
# Phase 0 — Host discovery (lightweight: liveness + reverse DNS only)
# ---------------------------------------------------------------------------
def phase0_host(t: Target, outdir: Path) -> None:
    hdr("Phase 0 — Host liveness")
    # ICMP / TCP-SYN / UDP probes — does the host respond at all?
    run(["nmap", "-sn", "-PE", "-PP", "-PS21,22,80,443,445,3389",
         "-PA80,443", "-PU53,161", t.ip],
        outfile=outdir / "nmap" / "host_discovery.txt", timeout=120,
        tag="nmap-ping")

    # Reverse DNS — free identity hint, no port required
    rc, out = run(["dig", "-x", t.ip, "+short", "+time=2", "+tries=1"],
                  timeout=15, tag="dig-ptr")
    # Accept only valid hostname-looking lines (letters/digits/dot/hyphen, no spaces)
    ptr = ""
    if rc == 0:
        for line in out.splitlines():
            line = line.strip().rstrip(".")
            if line and re.fullmatch(r"[A-Za-z0-9._-]+", line) and "." in line:
                ptr = line
                break
    if ptr:
        ok(f"PTR: {ptr}")
        if not t.fqdn: t.fqdn = ptr
        if not t.hostname: t.hostname = ptr.split(".")[0]
        if not t.domain and "." in ptr: t.domain = ".".join(ptr.split(".")[1:])
    else:
        warn("PTR: no usable reverse DNS (will rely on Phase 1.5 identity probes)")

# ---------------------------------------------------------------------------
# Phase 1.5 — Identity enrichment from port-scan findings
# ---------------------------------------------------------------------------
def phase1_5_enrich(t: Target, outdir: Path) -> None:
    """Use what Phase 1 found to learn hostname/domain BEFORE branching."""
    hdr("Phase 1.5 — Identity enrichment")

    # SMB name probe — only if 139/445 actually open
    if any(p in t.open_tcp for p in (139, 445)) and have("nxc"):
        rc, out = run(["nxc", "smb", t.ip], timeout=30, tag="nxc-id")
        m = re.search(r"name:(\S+).*domain:(\S+)", out)
        if m:
            t.hostname = t.hostname or m.group(1)
            t.domain   = t.domain   or m.group(2)
            t.fqdn     = t.fqdn     or f"{t.hostname}.{t.domain}".lower()
            ok(f"SMB → host={t.hostname} domain={t.domain}")

    # LDAP rootDSE — only if 389 open and still no domain
    if not t.domain and 389 in t.open_tcp:
        rc, out = run(["ldapsearch", "-x", "-H", f"ldap://{t.ip}",
                       "-s", "base", "-LLL", "namingcontexts", "dnsHostName"],
                      timeout=30, tag="ldap-id")
        m = re.search(r"namingContexts:\s*DC=([^,\s]+(?:,DC=[^,\s]+)*)", out)
        if m:
            t.domain = m.group(1).replace("DC=", "").replace(",", ".").lower()
            ok(f"LDAP → domain={t.domain}")
        m = re.search(r"dnsHostName:\s*(\S+)", out)
        if m and not t.fqdn:
            t.fqdn = m.group(1).lower()
            t.hostname = t.hostname or t.fqdn.split(".")[0]
            ok(f"LDAP → fqdn={t.fqdn}")

    # HTTPS cert CN/SAN — only if 443 open and still no hostname
    if not t.fqdn and 443 in t.open_tcp:
        rc, out = run(["bash", "-c",
                       f"echo | openssl s_client -connect {t.ip}:443 -servername {t.ip} 2>/dev/null "
                       f"| openssl x509 -noout -subject -ext subjectAltName 2>/dev/null"],
                      timeout=15, tag="tls-cert")
        m = re.search(r"DNS:([\w.\-]+)", out)
        if m:
            t.fqdn = m.group(1).lower()
            t.hostname = t.hostname or t.fqdn.split(".")[0]
            if not t.domain and "." in t.fqdn:
                t.domain = ".".join(t.fqdn.split(".")[1:])
            ok(f"TLS cert → fqdn={t.fqdn}")

    # Persist /etc/hosts hint AFTER enrichment so it has the best data
    hosts_line_parts = [t.ip]
    if t.fqdn:     hosts_line_parts.append(t.fqdn.lower())
    if t.hostname: hosts_line_parts.append(t.hostname.lower())
    if t.domain:   hosts_line_parts.append(t.domain.lower())
    hosts_line = " ".join(dict.fromkeys(hosts_line_parts))
    (outdir / "hosts.txt").write_text(hosts_line + "\n")
    ok(f"/etc/hosts hint → {hosts_line}")
    if t.fqdn or t.hostname:
        warn(f"Add to /etc/hosts:  sudo sh -c 'echo \"{hosts_line}\" >> /etc/hosts'")

# ---------------------------------------------------------------------------
# Phase 1 — Port scanning
# ---------------------------------------------------------------------------
TOP_UDP = "53,67,68,69,88,111,123,137,138,161,162,389,443,500,514,520,623,1434,1900,4500,5353,5060"

def _parse_open_tcp(text: str) -> list[int]:
    return sorted(set(int(p) for p in re.findall(r"^(\d+)/tcp\s+open", text, re.M)))

def _discover_ports_fast(t: Target, nmap_dir: Path, scan_type: str,
                         scope: str = "top1000") -> list[int]:
    """Pick the best fast port-discovery tool available.

    Tool comparison (TCP discovery only):
      - rustscan : fastest at -p- (~5–15s for full range), Rust-async, has -sV via nmap
                   pipeline. Best when scope=='full'.
      - naabu    : Go SYN scanner, fast top-N, accurate. Good for top-1000.
      - masscan  : fastest at huge ranges but noisy/lossy on single host; we skip.
      - nmap -sS : universally available, accurate, slower. Always works.

    Strategy:
      scope='top1000' → nmap top-1000 (we want -sCV scripts anyway, so no extra hop)
      scope='full'    → rustscan if available (much faster -p-), else naabu, else nmap
    Returns the discovered port list.
    """
    if scope == "top1000":
        # For top-1000 we always go straight to nmap -sCV (it's the bottleneck anyway).
        return []  # signal: caller does the nmap -sCV

    # scope == 'full'
    if have("rustscan"):
        ok("Port discovery: rustscan (fastest -p-)")
        rc, out = run(
            ["rustscan", "-a", t.ip, "--range", "1-65535",
             "--ulimit", "5000", "-b", "1500", "--accessible",
             "--no-config", "--scripts", "None"],
            outfile=nmap_dir / "rustscan.log", timeout=900, tag="rustscan",
        )
        # rustscan accessible output: "Open <ip>:<port>"
        ports = sorted(set(int(m.group(1))
                           for m in re.finditer(r"Open\s+\S+:(\d+)", out)))
        if not ports:
            # Some rustscan versions print "<ip>:<port>" only
            ports = sorted(set(int(m.group(1))
                               for m in re.finditer(r":(\d+)\s*$", out, re.M)))
        if ports:
            ok(f"rustscan found {len(ports)} ports")
            return ports
        warn("rustscan returned no ports — falling back to naabu/nmap")

    if have("naabu"):
        ok("Port discovery: naabu (Go SYN scanner)")
        rc, out = run(
            ["naabu", "-host", t.ip, "-p", "-", "-rate", "5000",
             "-silent", "-retries", "2", "-c", "100",
             "-o", str(nmap_dir / "naabu.txt")],
            outfile=nmap_dir / "naabu.log", timeout=1200, tag="naabu",
        )
        try:
            txt = (nmap_dir / "naabu.txt").read_text()
            ports = sorted(set(int(m.group(1))
                               for m in re.finditer(r":(\d+)", txt)))
            if ports:
                ok(f"naabu found {len(ports)} ports")
                return ports
        except FileNotFoundError:
            pass
        warn("naabu returned no ports — falling back to nmap")

    ok("Port discovery: nmap -p- (no faster scanner available)")
    rc, out = run(
        ["nmap", scan_type, "-Pn", "-n", "--min-rate=2000", "--max-retries=2",
         "-T4", "-p-", "-vv",
         "-oA", str(nmap_dir / f"{t.ip}_all_ports"), t.ip],
        timeout=2400, tag="nmap-tcp-full",
    )
    return _parse_open_tcp(out)

def _nmap_full_tcp(t: Target, nmap_dir: Path, scan_type: str) -> None:
    """Background full-range sweep using best available scanner.
    On finish: runs nmap -sCV against any newly-discovered ports."""
    full_ports = _discover_ports_fast(t, nmap_dir, scan_type, scope="full")
    new_ports = sorted(set(full_ports) - set(t.open_tcp))
    if new_ports:
        ok(f"Full sweep discovered NEW ports: {','.join(str(p) for p in new_ports)}")
        # Always use nmap for the deep -sC/-sV/script pass — irreplaceable
        run(["nmap", "-sC", "-sV", "-vv", "-Pn", "-n",
             "-p", ",".join(str(p) for p in new_ports),
             "-oA", str(nmap_dir / f"{t.ip}_all_ports_scripts"), t.ip],
            timeout=1200, tag="nmap-tcp-scripts-extra")
        t.open_tcp = sorted(set(t.open_tcp + new_ports))
    elif full_ports:
        ok("Full sweep: no additional ports beyond top-1000.")
    else:
        warn("Full sweep returned no results.")

def phase1_ports(t: Target, outdir: Path, full: bool, udp: bool) -> cf.Future | None:
    """Stage A (blocking): top-1000 -sCV scripted scan — fast wins.
    Stage B (background): full -p- sweep, scripted on new ports.
    Stage C (blocking): UDP top-100 if root.
    Returns the Stage-B Future so main() can join it before writing summary.
    """
    hdr("Phase 1 — Port scanning")
    nmap_dir = outdir / "nmap"
    nmap_dir.mkdir(parents=True, exist_ok=True)
    scan_type = "-sS" if is_root() else "-sT"

    # Stage A — top-1000  nmap -sS -sC -sV -vv  (BLOCKING; fast wins)
    # Falls back to -sT when not root (raw socket SYN scan requires CAP_NET_RAW).
    rc, out = run(
        ["nmap", scan_type, "-sC", "-sV", "-vv", "-Pn", "-n",
         "--top-ports=1000", "--min-rate=2000",
         "-O", "--osscan-guess",
         "--script-timeout=120s",
         "-oA", str(nmap_dir / t.ip), t.ip],
        timeout=1800, tag="nmap-top1000-sCV",
    )
    t.open_tcp = _parse_open_tcp(out)
    if not t.open_tcp:
        warn("No open TCP ports in top-1000.")
    else:
        ok(f"Open TCP (top-1000): {','.join(str(p) for p in t.open_tcp)}")
    # Parse service banners
    for line in out.splitlines():
        m = re.match(r"^(\d+)/tcp\s+open\s+(\S+)\s*(.*)$", line)
        if m:
            t.services[int(m.group(1))] = f"{m.group(2)} {m.group(3)}".strip()

    # Stage B — full -p- in BACKGROUND so Phase 2 can start immediately
    full_future: cf.Future | None = None
    if full:
        info("Launching -p- full TCP sweep in BACKGROUND (parallel with Phase 2)...")
        bg = cf.ThreadPoolExecutor(max_workers=1, thread_name_prefix="nmap-full")
        full_future = bg.submit(_nmap_full_tcp, t, nmap_dir, scan_type)
        bg.shutdown(wait=False)

    # Stage C — UDP top-100 (BLOCKING, root only)
    if udp and is_root():
        rc, out = run(
            ["nmap", "-sU", "-Pn", "-n", "--top-ports=100", "--max-retries=1",
             "-sV", "--version-intensity=0", "-vv",
             "-oA", str(nmap_dir / f"{t.ip}_udp"), t.ip],
            timeout=1800, tag="nmap-udp",
        )
        t.open_udp = sorted(set(int(p) for p in re.findall(r"^(\d+)/udp\s+open\s", out, re.M)))
        if t.open_udp:
            ok(f"Open UDP: {','.join(str(p) for p in t.open_udp)}")
    elif udp:
        warn("UDP scan skipped — re-run as root for raw UDP probes.")

    return full_future

# ---------------------------------------------------------------------------
# Phase 2 — Per-service enumeration
# ---------------------------------------------------------------------------
def enum_smb(t: Target, outdir: Path) -> None:
    hdr("SMB (139/445)")
    d = outdir / "smb"
    # Targeted nmap SMB scripts (vuln + discovery)
    run(["nmap", "-Pn", "-n", "-p", "139,445",
         "--script=smb-os-discovery,smb-protocols,smb-security-mode,"
         "smb-enum-shares,smb-enum-users,smb-enum-domains,smb-enum-groups,"
         "smb-enum-sessions,smb-vuln-ms17-010,smb-vuln-ms08-067,smb2-time,"
         "smb2-security-mode,smb2-capabilities", t.ip],
        outfile=d / "nmap_smb.txt", timeout=600, tag="nmap-smb")

    if have("nxc"):
        run(["nxc", "smb", t.ip, "--shares"],            outfile=d / "shares.txt", tag="nxc-shares")
        run(["nxc", "smb", t.ip, "--users"],             outfile=d / "users.txt",  tag="nxc-users")
        run(["nxc", "smb", t.ip, "--rid-brute", "10000"], outfile=d / "rid_brute.txt", timeout=1200, tag="nxc-rid")
        run(["nxc", "smb", t.ip, "--pass-pol"],          outfile=d / "pass_pol.txt", tag="nxc-passpol")
        run(["nxc", "smb", t.ip, "--loggedon-users"],    outfile=d / "loggedon.txt", tag="nxc-loggedon")
        run(["nxc", "smb", t.ip, "--sessions"],          outfile=d / "sessions.txt", tag="nxc-sessions")
        run(["nxc", "smb", t.ip, "-M", "spider_plus"],   outfile=d / "spider_plus.txt", timeout=900, tag="nxc-spider")
        # Try guest creds — common opening
        run(["nxc", "smb", t.ip, "-u", "guest", "-p", "", "--shares"],
            outfile=d / "guest_shares.txt", tag="nxc-guest")
        # Parse usernames from RID brute + users
        for fn in ("rid_brute.txt", "users.txt"):
            try:
                txt = (d / fn).read_text()
                for m in re.finditer(r"SidTypeUser\s+(\S+)\\(\S+)", txt):
                    t.users.add(m.group(2))
                for m in re.finditer(r"\\([A-Za-z0-9._$-]+)\s+\(", txt):
                    t.users.add(m.group(1))
            except FileNotFoundError:
                pass

    if have("smbclient"):
        run(["smbclient", "-L", f"//{t.ip}/", "-N"],
            outfile=d / "smbclient_list.txt", timeout=60, tag="smbclient")
    if have("rpcclient"):
        for cmd in ("srvinfo", "enumdomusers", "enumdomgroups", "enumalsgroups domain",
                    "enumalsgroups builtin", "querydominfo", "getdompwinfo",
                    "netshareenum", "netshareenumall", "lsaenumsid"):
            safe = cmd.replace(" ", "_")
            run(["rpcclient", "-U", "", "-N", t.ip, "-c", cmd],
                outfile=d / f"rpc_{safe}.txt", timeout=60, tag=f"rpc-{safe}")
    if have("enum4linux-ng"):
        run(["enum4linux-ng", "-A", "-oA", str(d / "enum4linux"), t.ip],
            timeout=1200, tag="enum4linux-ng")

def enum_ldap(t: Target, outdir: Path) -> None:
    hdr("LDAP (389/636)")
    d = outdir / "ldap"
    base_args = ["ldapsearch", "-x", "-H", f"ldap://{t.ip}", "-LLL"]
    rc, out = run(base_args + ["-s", "base", "namingcontexts", "defaultNamingContext",
                                "dnsHostName", "currentTime", "supportedLDAPVersion"],
        outfile=d / "rootdse.txt", timeout=30, tag="ldap-rootdse")
    # Auto-detect domain from rootDSE if not set
    if not t.domain:
        m = re.search(r"namingContexts:\s*DC=([^,]+(?:,DC=[^,\s]+)*)", out)
        if m:
            t.domain = m.group(1).replace("DC=", "").replace(",", ".").lower()
            ok(f"LDAP → domain={t.domain}")

    if t.domain:
        base_dn = ",".join(f"DC={p}" for p in t.domain.split("."))
        # Full anonymous dump
        run(base_args + ["-b", base_dn],
            outfile=d / "anon_dump.txt", timeout=300, tag="ldap-anon")
        # Kerberoastable
        run(base_args + ["-b", base_dn,
                         "(&(objectCategory=user)(servicePrincipalName=*))",
                         "samaccountname", "servicePrincipalName", "description"],
            outfile=d / "kerberoastable.txt", timeout=60, tag="ldap-spns")
        # AS-REP roastable (DONT_REQ_PREAUTH = 4194304)
        run(base_args + ["-b", base_dn,
                         "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
                         "samaccountname", "description"],
            outfile=d / "asreproastable.txt", timeout=60, tag="ldap-asrep")
        # Domain admins
        run(base_args + ["-b", base_dn,
                         "(&(objectCategory=group)(cn=Domain Admins))", "member"],
            outfile=d / "domain_admins.txt", timeout=60, tag="ldap-da")
        # Computers
        run(base_args + ["-b", base_dn,
                         "(objectCategory=computer)",
                         "dnsHostName", "operatingSystem", "operatingSystemVersion"],
            outfile=d / "computers.txt", timeout=120, tag="ldap-computers")
        # Trusts
        run(base_args + ["-b", base_dn,
                         "(objectClass=trustedDomain)"],
            outfile=d / "trusts.txt", timeout=60, tag="ldap-trusts")
        # Parse usernames from anon_dump
        try:
            txt = (d / "anon_dump.txt").read_text()
            for m in re.finditer(r"sAMAccountName:\s+([A-Za-z0-9._$-]+)", txt):
                u = m.group(1)
                if not u.endswith("$"):
                    t.users.add(u)
        except FileNotFoundError:
            pass

def enum_kerberos(t: Target, outdir: Path, wordlist: Path | None) -> None:
    hdr("Kerberos (88)")
    d = outdir / "kerberos"
    if not t.domain:
        warn("No domain set — skipping kerbrute (use --domain).")
        return
    if not have("kerbrute"):
        warn("kerbrute not installed.")
        return
    wl = wordlist or Path("/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt")
    if not wl.is_file():
        warn(f"username wordlist missing: {wl}")
        return
    run(["kerbrute", "userenum", "--dc", t.ip, "-d", t.domain, str(wl)],
        outfile=d / "kerbrute_userenum.txt", timeout=900)
    # Parse hits into users
    try:
        for line in (d / "kerbrute_userenum.txt").read_text().splitlines():
            m = re.search(r"VALID USERNAME:\s+(\S+)@", line)
            if m: t.users.add(m.group(1))
    except FileNotFoundError:
        pass

def enum_dns(t: Target, outdir: Path) -> None:
    hdr("DNS (53)")
    d = outdir / "dns"
    if t.domain:
        run(["dig", f"@{t.ip}", t.domain, "ANY", "+noall", "+answer"],
            outfile=d / "any.txt", timeout=30)
        run(["dig", f"@{t.ip}", "axfr", t.domain],
            outfile=d / "axfr.txt", timeout=30)
        for srv in ("_ldap._tcp.dc._msdcs", "_kerberos._tcp.dc._msdcs",
                    "_gc._tcp", "_kpasswd._tcp"):
            run(["dig", f"@{t.ip}", f"{srv}.{t.domain}", "SRV", "+noall", "+answer"],
                outfile=d / f"srv_{srv.replace('.','_')}.txt", timeout=15)
    run(["dig", f"@{t.ip}", "version.bind", "TXT", "CHAOS", "+short"],
        outfile=d / "version_bind.txt", timeout=15)

# ---------------------------------------------------------------------------
# Web helpers — hostname extraction + post-run cleanup
# ---------------------------------------------------------------------------
_HOSTNAME_RE = re.compile(
    r"(?<![A-Za-z0-9.-])([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?){1,})(?![A-Za-z0-9.-])",
    re.IGNORECASE,
)
_HOSTNAME_TLD_OK = {"htb", "local", "lab", "test", "internal", "corp", "intranet",
                    "dev", "stage", "prod", "com", "net", "org", "io"}
_HOSTNAME_REJECT_PREFIX = ("w3.org", "schemas.", "github.io", "cdn.", "fonts.",
                           "googleapis.", "jquery.", "bootstrap", "cloudflare.",
                           "example.", "localhost", "127.0.0.1")

def _candidate_hostnames(text: str) -> list[str]:
    out: list[str] = []
    for m in _HOSTNAME_RE.finditer(text):
        h = m.group(1).lower().strip(".")
        if any(h.startswith(p) or p in h for p in _HOSTNAME_REJECT_PREFIX):
            continue
        if re.fullmatch(r"\d+(\.\d+){3}", h):  # IPv4
            continue
        if h.endswith((".png", ".jpg", ".gif", ".css", ".js", ".ico", ".svg",
                       ".woff", ".woff2", ".ttf", ".eot", ".map")):
            continue
        tld = h.rsplit(".", 1)[-1]
        if tld not in _HOSTNAME_TLD_OK:
            continue
        if h not in out:
            out.append(h)
    return out

def _extract_hostname_hints(t: Target, web_dir: Path, body_paths: list[Path]) -> None:
    """Mine bodies + headers for hostname/domain hints; promote the first plausible match."""
    if t.hostname and t.domain:
        return  # already known
    sources: list[Path] = []
    headers = web_dir / "headers.txt"
    if headers.is_file():
        sources.append(headers)
    sources.extend(p for p in body_paths if p.is_file())
    # Probe files contain redirect URLs as well
    for probe in web_dir.glob("probe_*.txt"):
        sources.append(probe)
    seen: list[str] = []
    for f in sources:
        try:
            text = f.read_text(errors="replace")[:200_000]
        except OSError:
            continue
        for h in _candidate_hostnames(text):
            if h not in seen:
                seen.append(h)
    if not seen:
        return
    info(f"hostname candidates from web bodies: {', '.join(seen[:5])}")
    pick = seen[0]
    if "." in pick:
        if not t.fqdn:
            t.fqdn = pick
        if not t.hostname:
            t.hostname = pick.split(".", 1)[0]
        if not t.domain and pick.count(".") >= 1:
            t.domain = pick.split(".", 1)[1]
        ok(f"hostname inferred from web body \u2192 {t.hostname} / {t.domain}")

def _purge_empty_files(outdir: Path) -> None:
    """Drop zero-byte result files left over by failed/killed tools."""
    removed = 0
    for p in outdir.rglob("*"):
        if p.is_file() and p.name != "run.log" and p.stat().st_size == 0:
            try:
                p.unlink()
                removed += 1
            except OSError:
                pass
    if removed:
        info(f"cleanup: removed {removed} empty result file(s)")

def enum_web(t: Target, outdir: Path, port: int, tls: bool, do_brute: bool) -> None:
    proto = "https" if tls else "http"
    hdr(f"Web {proto.upper()} ({port})")
    d = outdir / "web" / f"{proto}_{port}"
    base_url = f"{proto}://{t.fqdn or t.ip}:{port}"
    base_url_ip = f"{proto}://{t.ip}:{port}"

    # Tech fingerprinting (with timeouts so curl/whatweb exit cleanly, not killed)
    if have("whatweb"):
        run(["whatweb", "-a", "3", "--no-errors", "--open-timeout=10",
             "--read-timeout=20", base_url],
            outfile=d / "whatweb.txt", timeout=60, tag=f"whatweb-{port}")
    run(["curl", "-skIL", "--max-time", "15", base_url],
        outfile=d / "headers.txt", timeout=20, tag=f"curl-head-{port}")

    # Common paths probe — write body ONLY when interesting (not 404, not 0-byte).
    # Use HEAD-then-conditional-GET pattern collapsed into single curl with --max-time.
    interesting_bodies: list[Path] = []
    for path in ("/", "/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.git/config",
                 "/.env", "/.svn/entries", "/.DS_Store", "/server-status",
                 "/server-info", "/phpinfo.php", "/info.php", "/admin", "/login",
                 "/wp-login.php", "/wp-admin/", "/api", "/api/v1", "/swagger.json",
                 "/openapi.json", "/actuator", "/actuator/env", "/console",
                 "/.well-known/security.txt", "/crossdomain.xml"):
        safe = path.replace("/", "_").strip("_") or "root"
        body_path = d / f"body_{safe}"
        rc, probe_out = run(
            ["curl", "-sk", "--max-time", "15", "-o", str(body_path),
             "-w", "HTTP %{http_code} %{size_download} %{redirect_url}\n",
             f"{base_url}{path}"],
            outfile=d / f"probe_{safe}.txt", timeout=20, tag=f"probe-{safe}")
        # Parse status + size; drop boring bodies (404 or empty), keep interesting ones.
        m = re.search(r"HTTP (\d+) (\d+)", probe_out)
        if m:
            status, size = int(m.group(1)), int(m.group(2))
            if status == 404 or size == 0 or (status in (301, 302, 303, 307, 308) and size < 500):
                if body_path.exists():
                    body_path.unlink()
            else:
                interesting_bodies.append(body_path)
        elif body_path.exists() and body_path.stat().st_size == 0:
            body_path.unlink()

    # Hostname/domain extraction from interesting bodies and headers
    _extract_hostname_hints(t, d, interesting_bodies)

    # nmap http-* scripts
    run(["nmap", "-sV", "-Pn", "-n", "-p", str(port),
         "--script=http-title,http-headers,http-methods,http-enum,http-shellshock,"
         "http-sql-injection,http-cors,http-csrf,http-default-accounts,http-robots.txt,"
         "http-git,http-config-backup,http-vuln-cve2017-5638", t.ip],
        outfile=d / "nmap_http.txt", timeout=600, tag=f"nmap-http-{port}")

    # SSL audit
    if tls and have("nmap"):
        run(["nmap", "-sV", "-Pn", "-n", "-p", str(port),
             "--script=ssl-enum-ciphers,ssl-cert,ssl-heartbleed,ssl-poodle,ssl-ccs-injection",
             t.ip],
            outfile=d / "ssl_audit.txt", timeout=300, tag=f"nmap-ssl-{port}")

    # vhost probe + fuzz — when hostname is known, fuzz subdomains under it
    if t.hostname and t.hostname != t.ip:
        run(["curl", "-sk", "-H", f"Host: {t.hostname}", base_url_ip,
             "-o", "/dev/null", "-w", "vhost(%{http_code}) %{size_download}B\n"],
            outfile=d / "vhost_probe.txt", timeout=30, tag=f"vhost-{port}")
    if t.domain and have("ffuf"):
        sub_wl = Path("/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
        if sub_wl.is_file():
            # -s suppresses progress spam; results still go to JSON/txt files.
            run(["ffuf", "-s", "-u", base_url_ip, "-H", f"Host: FUZZ.{t.domain}",
                 "-w", str(sub_wl), "-mc", "all",
                 "-fs", "0", "-ac", "-t", "40",
                 "-of", "json", "-o", str(d / "ffuf_vhosts.json")],
                outfile=d / "ffuf_vhosts.txt", timeout=900, tag=f"ffuf-vhost-{port}")

    if do_brute and have("ffuf"):
        wl = Path("/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt")
        if wl.is_file():
            run(["ffuf", "-s", "-u", f"{base_url}/FUZZ", "-w", str(wl),
                 "-mc", "200,204,301,302,307,401,403", "-ac", "-t", "40",
                 "-of", "json", "-o", str(d / "ffuf_dirs.json")],
                outfile=d / "ffuf_dirs.txt", timeout=1200, tag=f"ffuf-dirs-{port}")
        # Common file extensions
        ext_wl = Path("/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt")
        if ext_wl.is_file():
            run(["ffuf", "-s", "-u", f"{base_url}/FUZZ", "-w", str(ext_wl),
                 "-e", ".php,.asp,.aspx,.jsp,.bak,.zip,.tar.gz,.txt,.config",
                 "-mc", "200,204,301,302,307,401,403", "-ac", "-t", "40",
                 "-of", "json", "-o", str(d / "ffuf_files.json")],
                outfile=d / "ffuf_files.txt", timeout=1200, tag=f"ffuf-files-{port}")

def enum_other(t: Target, outdir: Path) -> None:
    d = outdir / "other"
    if 21 in t.open_tcp:
        hdr("FTP (21)")
        run(["nmap", "-sV", "-p", "21",
             "--script=ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor,ftp-proftpd-backdoor",
             t.ip], outfile=d / "ftp.txt", timeout=180, tag="nmap-ftp")
        # Try anon login + listing
        run(["bash", "-c",
             f"echo -e 'ls -la\\nbye' | curl -s ftp://anonymous:anonymous@{t.ip}/"],
            outfile=d / "ftp_anon_ls.txt", timeout=30, tag="ftp-anon")
    if 22 in t.open_tcp:
        hdr("SSH (22)")
        run(["nmap", "-sV", "-p", "22",
             "--script=ssh2-enum-algos,ssh-auth-methods,ssh-hostkey,ssh-publickey-acceptance",
             t.ip], outfile=d / "ssh.txt", timeout=120, tag="nmap-ssh")
    if 25 in t.open_tcp or 587 in t.open_tcp or 465 in t.open_tcp:
        hdr("SMTP (25/465/587)")
        ports = ",".join(str(p) for p in (25, 465, 587) if p in t.open_tcp)
        run(["nmap", "-sV", "-p", ports,
             "--script=smtp-commands,smtp-enum-users,smtp-open-relay,smtp-vuln-cve2010-4344,"
             "smtp-vuln-cve2011-1720,smtp-ntlm-info", t.ip],
            outfile=d / "smtp.txt", timeout=300, tag="nmap-smtp")
        if have("smtp-user-enum"):
            wl = Path("/usr/share/seclists/Usernames/Names/names.txt")
            if wl.is_file():
                run(["smtp-user-enum", "-M", "VRFY", "-U", str(wl), "-t", t.ip],
                    outfile=d / "smtp_user_enum.txt", timeout=600, tag="smtp-userenum")
    if 79 in t.open_tcp:
        hdr("Finger (79)")
        run(["nmap", "-sV", "-p", "79", "--script=finger", t.ip],
            outfile=d / "finger.txt", timeout=60, tag="nmap-finger")
    if 110 in t.open_tcp or 143 in t.open_tcp or 993 in t.open_tcp or 995 in t.open_tcp:
        hdr("POP3/IMAP")
        ports = ",".join(str(p) for p in (110, 143, 993, 995) if p in t.open_tcp)
        run(["nmap", "-sV", "-p", ports,
             "--script=pop3-capabilities,pop3-ntlm-info,imap-capabilities,imap-ntlm-info",
             t.ip], outfile=d / "mail.txt", timeout=180, tag="nmap-mail")
    if 111 in t.open_tcp or 2049 in t.open_tcp:
        hdr("NFS (111/2049)")
        run(["nmap", "-sV", "-p", "111,2049",
             "--script=nfs-ls,nfs-showmount,nfs-statfs,rpcinfo", t.ip],
            outfile=d / "nfs.txt", timeout=300, tag="nmap-nfs")
        if shutil.which("showmount"):
            run(["showmount", "-e", t.ip], outfile=d / "showmount.txt",
                timeout=30, tag="showmount")
    if 1433 in t.open_tcp:
        hdr("MSSQL (1433)")
        run(["nmap", "-sV", "-p", "1433",
             "--script=ms-sql-info,ms-sql-empty-password,ms-sql-config,ms-sql-ntlm-info",
             t.ip], outfile=d / "mssql_nmap.txt", timeout=180, tag="nmap-mssql")
        if have("nxc"):
            run(["nxc", "mssql", t.ip], outfile=d / "mssql.txt", timeout=60, tag="nxc-mssql")
    if 3306 in t.open_tcp:
        hdr("MySQL (3306)")
        run(["nmap", "-sV", "-p", "3306",
             "--script=mysql-info,mysql-empty-password,mysql-users,mysql-databases,mysql-variables",
             t.ip], outfile=d / "mysql.txt", timeout=180, tag="nmap-mysql")
    if 5432 in t.open_tcp:
        hdr("PostgreSQL (5432)")
        run(["nmap", "-sV", "-p", "5432", "--script=pgsql-brute", t.ip],
            outfile=d / "postgres.txt", timeout=180, tag="nmap-pgsql")
    if 6379 in t.open_tcp:
        hdr("Redis (6379)")
        run(["nmap", "-sV", "-p", "6379", "--script=redis-info,redis-brute", t.ip],
            outfile=d / "redis.txt", timeout=120, tag="nmap-redis")
    if 27017 in t.open_tcp:
        hdr("MongoDB (27017)")
        run(["nmap", "-sV", "-p", "27017",
             "--script=mongodb-info,mongodb-databases", t.ip],
            outfile=d / "mongodb.txt", timeout=120, tag="nmap-mongo")
    if 3389 in t.open_tcp:
        hdr("RDP (3389)")
        run(["nmap", "-sV", "-p", "3389",
             "--script=rdp-enum-encryption,rdp-ntlm-info,rdp-vuln-ms12-020", t.ip],
            outfile=d / "rdp.txt", timeout=180, tag="nmap-rdp")
        if have("nxc"):
            run(["nxc", "rdp", t.ip], outfile=d / "nxc_rdp.txt", timeout=60, tag="nxc-rdp")
    if 5985 in t.open_tcp or 5986 in t.open_tcp:
        hdr("WinRM (5985/5986)")
        if have("nxc"):
            run(["nxc", "winrm", t.ip], outfile=d / "winrm.txt", timeout=60, tag="nxc-winrm")
    if 623 in t.open_udp:
        hdr("IPMI (623/udp)")
        run(["nmap", "-sU", "-p", "623",
             "--script=ipmi-version,ipmi-cipher-zero,ipmi-brute", t.ip],
            outfile=d / "ipmi.txt", timeout=180, tag="nmap-ipmi")
    if 161 in t.open_udp:
        hdr("SNMP (161)")
        if have("onesixtyone"):
            comm = Path("/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt")
            if comm.is_file():
                run(["onesixtyone", "-c", str(comm), t.ip],
                    outfile=d / "snmp_community.txt", timeout=120, tag="onesixtyone")
            else:
                warn("seclists SNMP community file not found — using builtin fallback list")
                fallback = d / "_snmp_fallback_communities.txt"
                fallback.write_text("\n".join([
                    "public", "private", "community", "manager", "cisco",
                    "monitor", "secret", "admin", "default", "snmp",
                    "ILMI", "system", "openview", "security", "internal",
                ]) + "\n")
                run(["onesixtyone", "-c", str(fallback), t.ip],
                    outfile=d / "snmp_community.txt", timeout=120, tag="onesixtyone")
        if have("snmpwalk"):
            for c in ("public", "private", "community"):
                # Common OIDs: processes, software, users, network, system
                for oid, label in (
                    (".1.3.6.1.2.1.25.4.2.1.2",   "processes"),
                    (".1.3.6.1.2.1.25.6.3.1.2",   "software"),
                    (".1.3.6.1.4.1.77.1.2.25",    "users"),
                    (".1.3.6.1.2.1.6.13.1.3",     "tcp_ports"),
                    (".1.3.6.1.2.1.1",            "system"),
                ):
                    run(["snmpwalk", "-v2c", "-c", c, t.ip, oid],
                        outfile=d / f"snmp_{c}_{label}.txt", timeout=60,
                        tag=f"snmp-{c}-{label}")
    if 500 in t.open_udp:
        hdr("IKE (500/udp)")
        if shutil.which("ike-scan"):
            run(["ike-scan", "-M", t.ip], outfile=d / "ike.txt",
                timeout=120, tag="ike-scan")

# ---------------------------------------------------------------------------
# Service dispatcher
# ---------------------------------------------------------------------------
def phase2_services(t: Target, outdir: Path, threads: int,
                    web: bool, ad: bool, wordlist: Path | None) -> None:
    hdr("Phase 2 — Service enumeration")

    jobs: list = []
    pool = cf.ThreadPoolExecutor(max_workers=threads)

    if any(p in t.open_tcp for p in (139, 445)):
        jobs.append(pool.submit(enum_smb, t, outdir))
    if any(p in t.open_tcp for p in (389, 636, 3268, 3269)):
        jobs.append(pool.submit(enum_ldap, t, outdir))
    if 88 in t.open_tcp and ad:
        jobs.append(pool.submit(enum_kerberos, t, outdir, wordlist))
    if 53 in t.open_tcp or 53 in t.open_udp:
        jobs.append(pool.submit(enum_dns, t, outdir))

    if web:
        for p in (80, 8080, 8000, 8888):
            if p in t.open_tcp:
                jobs.append(pool.submit(enum_web, t, outdir, p, False, True))
        for p in (443, 8443):
            if p in t.open_tcp:
                jobs.append(pool.submit(enum_web, t, outdir, p, True, True))

    jobs.append(pool.submit(enum_other, t, outdir))

    for j in cf.as_completed(jobs):
        try:
            j.result()
        except Exception as e:
            err(f"task crashed: {e}")
    pool.shutdown(wait=True)

# ---------------------------------------------------------------------------
# Phase 3 — Summary
# ---------------------------------------------------------------------------
def write_summary(t: Target, outdir: Path, started: datetime) -> None:
    hdr("Phase 3 — Summary")
    s: list[str] = []
    s.append(f"# Recon Summary — {t.ip}")
    s.append("")
    s.append(f"- Started: `{started.isoformat(timespec='seconds')}`")
    s.append(f"- Finished: `{datetime.now().isoformat(timespec='seconds')}`")
    s.append(f"- Hostname: `{t.hostname or 'unknown'}`")
    s.append(f"- Domain: `{t.domain or 'unknown'}`")
    s.append(f"- FQDN: `{t.fqdn or 'unknown'}`")
    s.append("")
    s.append("## Open ports")
    s.append(f"- TCP ({len(t.open_tcp)}): `{','.join(str(p) for p in t.open_tcp) or '-'}`")
    s.append(f"- UDP ({len(t.open_udp)}): `{','.join(str(p) for p in t.open_udp) or '-'}`")
    s.append("")

    branches: list[str] = []
    if any(p in t.open_tcp for p in (88, 389, 636)):
        branches.append("**Active Directory** — see `active-directory-methodology.md` Phase 2 (Domain Enumeration)")
    if any(p in t.open_tcp for p in (139, 445)):
        branches.append("**SMB** — see `enumeration-methodology.md` Phase 3.8 + `windows-methodology.md` Phase 1.3")
    if any(p in t.open_tcp for p in (80, 443, 8080, 8443)):
        branches.append("**Web** — see `web-methodology.md` Phase 1 (Surface Mapping)")
    if 22 in t.open_tcp:
        branches.append("**SSH** → likely Linux — see `linux-methodology.md` Phase 1 (Initial Enumeration)")
    if 3389 in t.open_tcp:
        branches.append("**RDP** — see `enumeration-methodology.md` Phase 3.15 + `windows-methodology.md` Phase 1.13")
    if 5985 in t.open_tcp or 5986 in t.open_tcp:
        branches.append("**WinRM** — see `windows-methodology.md` Phase 1.7 (Remote Access)")
    if 1433 in t.open_tcp:
        branches.append("**MSSQL** — see `enumeration-methodology.md` Phase 3.13 + `windows-methodology.md` Phase 2.4")
    if 161 in t.open_udp:
        branches.append("**SNMP** — see `enumeration-methodology.md` Phase 3.11 (Community String / Walker)")

    s.append("## Branch decisions")
    s.extend(f"- {b}" for b in branches or ["- (no branches matched)"])
    s.append("")

    if t.users:
        s.append(f"## Users harvested ({len(t.users)})")
        s.append("```")
        s.extend(sorted(t.users))
        s.append("```")
        s.append("")

    s.append("## Suggested next commands")
    s.append("")
    cmds: list[str] = []
    has_smb = any(p in t.open_tcp for p in (139, 445))
    has_ad  = any(p in t.open_tcp for p in (88, 389, 636))
    has_web = any(p in t.open_tcp for p in (80, 443, 8080, 8443))
    has_kerb = 88 in t.open_tcp

    if has_ad and t.domain:
        cmds.append("# --- Active Directory branch ---")
        if t.users:
            cmds.append("# AS-REP roast harvested users (no creds needed)")
            cmds.append(f"impacket-GetNPUsers '{t.domain}/' -no-pass -usersfile users.txt -dc-ip {t.ip} -format hashcat -outputfile asrep.hash")
            cmds.append("")
            cmds.append("# Password spray (rotate per lockout policy in smb/pass_pol.txt)")
            cmds.append(f"nxc smb {t.ip} -u users.txt -p 'Spring2026!' --continue-on-success")
            cmds.append(f"nxc smb {t.ip} -u users.txt -p users.txt --no-bruteforce  # username == password")
            cmds.append("")
        cmds.append("# Once you have ANY valid creds:")
        cmds.append(f"nxc smb {t.ip} -u USER -p PASS --shares --users --pass-pol --groups --rid-brute 10000")
        cmds.append(f"nxc ldap {t.ip} -u USER -p PASS --kerberoasting kerb.hash --asreproast asrep2.hash --trusted-for-delegation --admin-count")
        cmds.append(f"impacket-GetUserSPNs '{t.domain}/USER:PASS' -dc-ip {t.ip} -request -outputfile kerberoast.hash")
        cmds.append(f"bloodhound-python -u USER -p PASS -d {t.domain} -dc {t.fqdn or t.ip} -ns {t.ip} -c All --zip")
        cmds.append("")
        if has_kerb:
            cmds.append("# Time skew \u2014 sync to DC before any Kerberos action")
            cmds.append(f"sudo ntpdate -u {t.ip} || sudo rdate -n {t.ip}")
            cmds.append("")
        cmds.append("# Certificate Services discovery (ESC1\u2013ESC15)")
        cmds.append(f"certipy-ad find -u USER@{t.domain} -p PASS -dc-ip {t.ip} -vulnerable -stdout")
    if has_smb and not has_ad:
        cmds.append("# --- Standalone SMB branch ---")
        cmds.append(f"smbclient -L //{t.ip}/ -N")
        cmds.append(f"smbmap -H {t.ip} -u guest -p ''")
        cmds.append(f"nxc smb {t.ip} -u '' -p '' --shares")
    if has_web:
        cmds.append("# --- Web branch ---")
        for p in (80, 443, 8080, 8443):
            if p in t.open_tcp:
                proto = "https" if p in (443, 8443) else "http"
                host = t.fqdn or t.ip
                cmds.append(f"feroxbuster -u {proto}://{host}:{p} -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,asp,aspx,jsp,html,txt -t 50")
                cmds.append(f"nuclei -u {proto}://{host}:{p} -severity medium,high,critical -o web/nuclei_{p}.txt")
    if 22 in t.open_tcp:
        cmds.append("# --- SSH branch ---")
        cmds.append(f"hydra -L users.txt -P /usr/share/wordlists/rockyou.txt -t 4 -f ssh://{t.ip}")
    if 3389 in t.open_tcp and t.domain:
        cmds.append("# --- RDP branch ---")
        cmds.append(f"nxc rdp {t.ip} -u users.txt -p 'Spring2026!' -d {t.domain} --continue-on-success")
    if 5985 in t.open_tcp or 5986 in t.open_tcp:
        cmds.append("# --- WinRM branch ---")
        cmds.append(f"evil-winrm -i {t.ip} -u USER -p PASS")

    if cmds:
        s.append("```bash")
        s.extend(cmds)
        s.append("```")
        s.append("")

    s.append("## Generated files")
    for p in sorted(outdir.rglob("*")):
        if p.is_file():
            rel = p.relative_to(outdir)
            sz = p.stat().st_size
            s.append(f"- `{rel}` ({sz}B)")

    (outdir / "summary.md").write_text("\n".join(s) + "\n")
    (outdir / "users.txt").write_text("\n".join(sorted(t.users)) + ("\n" if t.users else ""))
    ok(f"Summary → {outdir/'summary.md'}")
    ok(f"Users   → {outdir/'users.txt'}  ({len(t.users)} users)")

# ---------------------------------------------------------------------------
# HOST MODE — post-foothold on-target enumeration (Linux). Pure stdlib.
# ---------------------------------------------------------------------------
def host_mode(args) -> int:
    """Local enumeration on a Linux foothold. Read-only. Same output layout as recon.sh."""
    import socket
    started = datetime.now()
    host = socket.gethostname() or "unknown"
    out = Path(args.out) if args.out else Path(f"loot_{host}_{started.strftime('%Y%m%d_%H%M%S')}")
    try:
        out.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print(f"[!] cannot create {out}: {e}", file=sys.stderr); return 1

    findings: list[str] = []
    def hit(s: str)  -> None: findings.append(f"[+] {s}")
    def note_(s: str) -> None: findings.append(f"[i] {s}")
    def warn_(s: str) -> None: findings.append(f"[!] {s}")

    def cap(cmd: str, timeout: int = 30) -> str:
        """Run a shell command and capture combined output. Empty string on any failure."""
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                               timeout=timeout)
            return (r.stdout or "") + (r.stderr or "")
        except Exception:
            return ""

    def write_section(path: Path, blocks: list[tuple[str, str]]) -> None:
        with path.open("w") as fh:
            for title, body in blocks:
                fh.write(f"\n=== {title} ===\n{body or '(empty)'}\n")

    def read_text(p: str) -> str:
        try:
            return Path(p).read_text(errors="replace")
        except Exception:
            return ""

    def writable(p: str) -> bool:
        try: return os.access(p, os.W_OK)
        except Exception: return False

    # ── 1. system / identity ────────────────────────────────────────────────
    write_section(out / "system.txt", [
        ("uname / os-release", cap("uname -a") + read_text("/etc/os-release")),
        ("id / groups",        cap("id") + cap("groups")),
        ("UID-0 or login-shell users", cap(r"awk -F: '$3==0 || $7~/sh$/ {print}' /etc/passwd")),
        ("last logins",        cap("last -n 20")),
        ("currently logged in", cap("w")),
    ])

    # ── 2. privesc primitives ──────────────────────────────────────────────
    sudo_l = cap("sudo -n -l", timeout=10) or "(no cached sudo or password required)"
    sudo_v = cap("sudo --version | head -1")
    pkexec_v = cap("pkexec --version 2>&1 | head -1")
    pkexec_ls = cap("ls -la /usr/bin/pkexec")
    suid = cap("find / -perm -4000 -type f 2>/dev/null", timeout=120)
    sgid = cap("find / -perm -2000 -type f 2>/dev/null", timeout=120)
    caps_ = cap("getcap -r / 2>/dev/null", timeout=120)
    writable_sysfiles = []
    for f in ("/etc/passwd", "/etc/shadow", "/etc/sudoers"):
        if writable(f): writable_sysfiles.append(f"WRITABLE: {f}")

    write_section(out / "privesc.txt", [
        ("sudo -n -l", sudo_l),
        ("sudo version", sudo_v),
        ("SUID binaries", suid),
        ("SGID binaries", sgid),
        ("capabilities", caps_),
        ("writable system files", "\n".join(writable_sysfiles) or "(none)"),
        ("polkit / pkexec", pkexec_v + "\n" + pkexec_ls),
        ("kernel version", cap("uname -r")),
    ])

    if "NOPASSWD" in sudo_l:
        hit("sudo NOPASSWD entries — see privesc.txt + GTFOBins")
    if os.path.exists("/usr/bin/pkexec"):
        try:
            st = os.stat("/usr/bin/pkexec")
            if st.st_mode & 0o4000:
                hit(f"pkexec is SUID ({pkexec_v.strip()}) — PwnKit candidate (CVE-2021-4034) — linux-methodology.md §4.7")
        except Exception:
            pass
    m = re.search(r"\b([0-9]+\.[0-9]+\.[0-9]+[a-z0-9]*)\b", sudo_v)
    if m:
        warn_(f"sudo {m.group(1)} — verify against Baron Samedit (CVE-2021-3156, vuln 1.8.2-1.9.5p1)")
    for f in ("/etc/passwd", "/etc/shadow", "/etc/sudoers"):
        if writable(f):
            hit(f"{f} is WRITABLE — direct privesc")

    # ── 3. cron / timers / services ────────────────────────────────────────
    cron_blocks = [("/etc/crontab", read_text("/etc/crontab"))]
    for d in ("/etc/cron.hourly","/etc/cron.daily","/etc/cron.weekly","/etc/cron.monthly","/etc/cron.d"):
        if os.path.isdir(d):
            cron_blocks.append((d, cap(f"ls -la {d}")))
    user_crons = []
    for line in (read_text("/etc/passwd").splitlines()):
        parts = line.split(":")
        if len(parts) >= 7 and parts[6].endswith("sh"):
            f = f"/var/spool/cron/crontabs/{parts[0]}"
            t = read_text(f)
            if t: user_crons.append(f"--- {f} ---\n{t}") # pyright: ignore[reportUnknownMemberType]
    cron_blocks.append(("user crontabs (readable)", "\n".join(user_crons) or "(none)"))
    cron_blocks.append(("systemd timers", cap("systemctl list-timers --all --no-pager")))
    cron_blocks.append(("writable systemd unit files",
                        cap("find /etc/systemd /lib/systemd -name '*.service' -writable 2>/dev/null")))
    cron_blocks.append(("processes (top)", cap("ps auxf | head -60")))
    write_section(out / "services.txt", cron_blocks)

    if cap("find /etc/systemd -name '*.service' -writable 2>/dev/null").strip():
        hit("writable systemd unit files — service binary hijack candidate")

    # ── 4. credentials / config files ──────────────────────────────────────
    histories = []
    for f in ("~/.bash_history","~/.zsh_history","~/.history","/root/.bash_history"):
        path = os.path.expanduser(f)
        t = read_text(path)
        if t: histories.append(f"--- {path} ---\n{t}") # pyright: ignore[reportUnknownMemberType]
    cred_grep = cap(
        "grep -ErlI --include='*.conf' --include='*.cfg' --include='*.ini' --include='*.xml' "
        "--include='*.yml' --include='*.yaml' --include='*.env' --include='*.properties' "
        "-e 'password\\|secret\\|api[_-]?key\\|token' /etc /opt /var/www /home 2>/dev/null | head -50",
        timeout=60)
    ssh_keys = cap("find / \\( -name 'id_rsa*' -o -name 'id_ed25519*' -o -name 'id_ecdsa*' \\) "
                   "-readable 2>/dev/null | head -20", timeout=60)
    auth_keys = cap("find / -name authorized_keys -readable 2>/dev/null | head -10", timeout=60)
    db_hist = []
    for f in ("~/.mysql_history","~/.psql_history","/root/.mysql_history","/root/.psql_history"):
        path = os.path.expanduser(f)
        t = read_text(path)
        if t: db_hist.append(f"--- {path} ---\n{t}") # pyright: ignore[reportUnknownMemberType]
    cloud = cap("find / \\( -name credentials -path '*.aws/*' "
                "-o -name config -path '*gcloud*' -o -name azure.json \\) -readable 2>/dev/null",
                timeout=60)
    dotfiles = cap("find / \\( -name '.env' -o -name '.npmrc' -o -name '.pypirc' "
                   "-o \\( -name config -path '*/.git/*' \\) \\) -readable 2>/dev/null | head -30",
                   timeout=60)
    write_section(out / "creds.txt", [
        ("shell histories", "\n".join(histories) or "(none readable)"),
        ("config files mentioning password/secret/key (top 50 paths)", cred_grep),
        ("SSH private keys", ssh_keys),
        ("authorized_keys files", auth_keys),
        ("DB histories", "\n".join(db_hist) or "(none readable)"),
        ("cloud cred files (.aws / gcloud / azure)", cloud),
        (".env / .npmrc / .pypirc / .git/config", dotfiles),
    ])
    if ssh_keys.strip():
        hit("readable SSH private keys — see creds.txt for paths")

    # ── 5. network / pivot surface ─────────────────────────────────────────
    write_section(out / "network.txt", [
        ("interfaces",         cap("ip a")),
        ("routing v4",         cap("ip route")),
        ("routing v6",         cap("ip -6 route")),
        ("listening ports",    cap("ss -tulpn")),
        ("established conns",  cap("ss -tunp")),
        ("ARP / neighbors",    cap("ip neigh")),
        ("DNS",                read_text("/etc/resolv.conf")),
        ("/etc/hosts",         read_text("/etc/hosts")),
    ])
    nics = cap("ip -o link show 2>/dev/null | grep -v 'lo:' | wc -l").strip()
    try:
        if int(nics) > 1:
            hit(f"{nics} non-loopback NICs — pivot candidate (tunneling-pivoting.md)")
    except ValueError:
        pass
    if cap("ss -tlnp 2>/dev/null | grep -E '127\\.|\\[::1\\]'").strip():
        note_("internal-only services on 127.0.0.1 — port-forward candidate")

    # ── 6. containers / k8s ────────────────────────────────────────────────
    cont = []
    if os.path.exists("/.dockerenv"):         cont.append("Docker: /.dockerenv present")
    if os.path.isdir("/run/.containerenv"):   cont.append("Podman: /run/.containerenv present")
    cg = read_text("/proc/1/cgroup")
    if "docker" in cg:    cont.append("cgroup → docker")
    if "kubepods" in cg:  cont.append("cgroup → kubernetes pod")
    write_section(out / "containers.txt", [
        ("container indicators", "\n".join(cont) or "(no container indicators)"),
        ("process capabilities", cap("capsh --print 2>&1")),
        ("docker socket exposure", cap("ls -la /var/run/docker.sock 2>&1")),
        ("k8s SA token dir", cap("ls -la /var/run/secrets/kubernetes.io/serviceaccount/ 2>&1")),
    ])
    if os.path.exists("/.dockerenv"):
        hit("INSIDE Docker container — check escape paths")
    try:
        import stat as _stat
        st = os.stat("/var/run/docker.sock")
        if _stat.S_ISSOCK(st.st_mode):
            hit("/var/run/docker.sock present — escape via 'docker run --privileged --pid=host'")
    except FileNotFoundError:
        pass
    except Exception:
        pass
    if os.access("/var/run/secrets/kubernetes.io/serviceaccount/token", os.R_OK):
        hit("INSIDE Kubernetes pod with SA token — check kubeletctl / API access")

    # ── 7. NFS / shares ───────────────────────────────────────────────────
    exports = read_text("/etc/exports")
    write_section(out / "shares.txt", [
        ("/etc/exports", exports),
        ("showmount localhost", cap("showmount -e localhost 2>&1")),
        ("mounted shares", cap("mount | grep -E 'nfs|cifs|smb'")),
    ])
    if "no_root_squash" in exports:
        hit("/etc/exports has no_root_squash — NFS-to-SUID-root from another host")

    # ── 8. AD / domain enumeration ────────────────────────────────────────
    domain = ""
    krb_text = read_text("/etc/krb5.conf")
    m = re.search(r"^\s*default_realm\s*=\s*(\S+)", krb_text, re.MULTILINE)
    if m:
        domain = m.group(1).strip().lower()
    if not domain:
        rl = cap("realm list 2>&1")
        m2 = re.search(r"realm-name:\s*(\S+)", rl)
        if m2: domain = m2.group(1).lower()
    if not domain:
        domain = cap("hostname -d").strip().lower()

    dc_host = ""
    dc_ip = ""
    if domain:
        srv = cap(f"dig +short SRV _ldap._tcp.dc._msdcs.{domain}")
        for line in srv.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                dc_host = parts[3].rstrip("."); break
        if not dc_host:
            srv2 = cap(f"dig +short SRV _kerberos._tcp.{domain}")
            for line in srv2.splitlines():
                parts = line.split()
                if len(parts) >= 4:
                    dc_host = parts[3].rstrip("."); break
        if dc_host:
            dc_ip = cap(f"dig +short A {dc_host}").strip().splitlines()[0] if cap(f"dig +short A {dc_host}").strip() else ""

    write_section(out / "domain.txt", [
        ("domain join state", f"DOMAIN={domain}\nDC_HOST={dc_host}\nDC_IP={dc_ip}\n" + cap("realm list 2>&1") + cap("hostname -d")),
        ("Kerberos tickets (klist)", cap("klist 2>&1") + cap("klist -A 2>&1")),
        ("krb5.conf",      krb_text),
        ("sssd.conf",      read_text("/etc/sssd/sssd.conf")),
        ("sssd cached secrets dir", cap("ls -la /var/lib/sss/secrets 2>&1")),
        ("winbind",        cap("wbinfo --domain-info=. 2>&1") + cap("wbinfo -u 2>&1 | head -50") + cap("wbinfo -g 2>&1 | head -30") + cap("wbinfo -t 2>&1")),
        ("machine account hash material", cap("ls -la /etc/krb5.keytab /var/lib/samba/private/secrets.tdb 2>&1")),
        ("ccache locations", cap("ls -la /tmp/krb5cc_* 2>&1")),
    ])

    if domain and dc_ip:
        hit(f"host is DOMAIN-JOINED ({domain}, DC={dc_host}/{dc_ip}) — pivot to active-directory-methodology.md")

        base_dn = "DC=" + ",DC=".join(domain.split("."))
        ldap_blocks = [
            ("[ANON LDAP] rootDSE",
             cap(f"ldapsearch -x -H ldap://{dc_ip} -s base -b '' '(objectClass=*)' 2>&1 | head -80", timeout=30)),
            ("[ANON LDAP] naming contexts",
             cap(f"ldapsearch -x -H ldap://{dc_ip} -s base -b '' namingContexts 2>&1 | grep -i namingcontext", timeout=20)),
            ("[ANON LDAP] anonymous-bind users probe",
             cap(f"ldapsearch -x -H ldap://{dc_ip} -b '{base_dn}' '(objectClass=user)' sAMAccountName 2>&1 | head -40", timeout=30)),
            ("[ANON LDAP] computer-account count",
             cap(f"ldapsearch -x -H ldap://{dc_ip} -b '{base_dn}' '(objectCategory=computer)' sAMAccountName 2>&1 | grep -c sAMAccountName", timeout=30)),
            ("[NXC] SMB null/anon",
             cap(f"nxc smb {dc_ip} -u '' -p '' 2>&1 | head -30", timeout=30) +
             cap(f"nxc smb {dc_ip} -u 'guest' -p '' 2>&1 | head -10", timeout=30)),
            ("[NXC] LDAP no-auth",
             cap(f"nxc ldap {dc_ip} -u '' -p '' 2>&1 | head -30", timeout=30)),
            ("[NXC] BadSuccessor / dMSA scan",
             cap(f"nxc ldap {dc_ip} -u '' -p '' -M BadSuccessor 2>&1", timeout=30)),
            ("[NXC] timeroast (pre-Win2k computer accounts)",
             cap(f"nxc smb {dc_ip} -M timeroast 2>&1 | head -30", timeout=60)),
            ("[KERBRUTE] no-preauth user enum",
             cap(f"kerbrute userenum --dc {dc_ip} -d {domain} /usr/share/seclists/Usernames/jsmith.txt 2>&1 | head -50", timeout=120)
             if os.path.exists("/usr/share/seclists/Usernames/jsmith.txt") else "(kerbrute or seclists/Usernames/jsmith.txt missing)"),
            ("[DNS] domain SRV records",
             "\n".join(cap(f"dig +short SRV {srv}.{domain} @{dc_ip}") for srv in
                       ("_ldap._tcp","_kerberos._tcp","_kpasswd._tcp","_gc._tcp","_ldap._tcp.gc._msdcs"))),
            ("[DNS] AXFR attempt", cap(f"dig axfr {domain} @{dc_ip} 2>&1 | head -50", timeout=30)),
        ]
        write_section(out / "domain_enum.txt", ldap_blocks)

        # ── 8b. BloodHound auto-collect (always-on for domain-joined) ─────
        bh_dir = out / "bloodhound"
        bh_dir.mkdir(parents=True, exist_ok=True)
        bh_cmd = ""
        for c in ("bloodhound-ce-python", "bloodhound-python"):
            try:
                if subprocess.run(["which", c], capture_output=True).returncode == 0:
                    bh_cmd = c; break
            except Exception:
                pass
        # Auth context detection
        bh_auth = "none"
        if cap("klist -s 2>&1; echo $?").strip().endswith("0"):
            bh_auth = "kerberos"
        elif os.environ.get("BLOODHOUND_USER") and os.environ.get("BLOODHOUND_PASS"):
            bh_auth = "creds"

        log_lines = [f"DOMAIN={domain}  DC={dc_host}  AUTH={bh_auth}  TOOL={bh_cmd or 'NONE'}\n"]
        if not bh_cmd:
            log_lines.append("[!] No bloodhound collector installed.\n"
                             "    Install:  pipx install bloodhound-ce  (CE schema, recommended)\n"
                             f"    Manual:   {bh_cmd or 'bloodhound-ce-python'} -d {domain} -dc {dc_host} -c All --zip -ns {dc_ip}\n")
        elif bh_auth == "kerberos":
            log_lines.append("[+] Cached Kerberos ticket — running collector...\n")
            r = cap(f"cd '{bh_dir}' && KRB5CCNAME=${{KRB5CCNAME:-/tmp/krb5cc_$(id -u)}} "
                    f"{bh_cmd} -d '{domain}' -dc '{dc_host}' -c All --zip -ns {dc_ip} -k --no-pass 2>&1 | head -60",
                    timeout=600)
            log_lines.append(r)
        elif bh_auth == "creds":
            log_lines.append("[+] BLOODHOUND_USER / BLOODHOUND_PASS env vars present — running collector...\n")
            r = cap(f"cd '{bh_dir}' && {bh_cmd} -d '{domain}' -dc '{dc_host}' "
                    f"-u '{os.environ['BLOODHOUND_USER']}' -p '{os.environ['BLOODHOUND_PASS']}' "
                    f"-c All --zip -ns {dc_ip} 2>&1 | head -60",
                    timeout=600)
            log_lines.append(r)
        else:
            log_lines.append("[i] No Kerberos ticket cached and no BLOODHOUND_USER/BLOODHOUND_PASS set.\n"
                             f"    Manual:  {bh_cmd} -d {domain} -dc {dc_host} -u <USER> -p <PASS> -c All --zip -ns {dc_ip}\n")
        (bh_dir / "run.log").write_text("\n".join(log_lines))

        zips = list(bh_dir.glob("*.zip"))
        if zips:
            hit(f"BloodHound ZIP collected: {zips[0].name} — import into BloodHound CE UI")
        else:
            note_(f"BloodHound NOT collected — see {bh_dir}/run.log for the manual command")

    # ── findings summary ──────────────────────────────────────────────────
    (out / "findings.txt").write_text("\n".join(findings) + ("\n" if findings else ""))
    summary = [
        f"# Linux post-foothold loot — {host} @ {started.strftime('%Y%m%d_%H%M%S')}",
        "",
        "## Priority findings (read first)",
        "",
        "\n".join(findings) if findings else "(none flagged automatically — review files)",
        "",
        "## Files",
        cap(f"ls -la {out}"),
        "",
        "## Methodology cross-refs",
        "- privesc.txt    → linux-methodology.md §4 (Privilege Escalation)",
        "- creds.txt      → linux-methodology.md §3 (Credential Hunting)",
        "- services.txt   → linux-methodology.md §2 (Local Enumeration)",
        "- network.txt    → tunneling-pivoting.md (pivot opportunities)",
        "- containers.txt → linux-methodology.md (container escape)",
        "- shares.txt     → linux-methodology.md NFS/SMB sections",
        "- domain.txt     → active-directory-methodology.md (Linux-on-AD)",
    ]
    if (out / "domain_enum.txt").exists():
        summary.append("- domain_enum.txt → AD anon LDAP / kerbrute / nxc no-auth probes")
    if (out / "bloodhound").is_dir():
        summary.append("- bloodhound/    → BloodHound CE ZIP (import into UI) or manual cmd in run.log")
    (out / "summary.md").write_text("\n".join(summary))

    print(f"[+] loot dir: {out}")
    print("[+] priority findings:")
    if findings:
        for f in findings: print(f"    {f}")
    else:
        print("    (none flagged — review summary.md)")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(
        description="Automated CPTS recon orchestrator (defaults: everything on)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("ip", nargs="?",
                    help="Target IP address (required for --mode external; ignored for --mode host).")
    ap.add_argument("--mode", choices=("external", "host"), default="external",
                    help="external = scan a remote target (default); "
                         "host = post-foothold enum on THIS host (Linux only — pure stdlib).")
    ap.add_argument("--hostname", help="Short hostname (e.g. dc01)")
    ap.add_argument("--domain", help="Domain / realm (e.g. eighteen.htb)")
    ap.add_argument("--out", help="Output directory "
                                  "(external: ./recon_<IP>_<ts>; host: ./loot_<host>_<ts>)")
    # Scope toggles — ALL DEFAULT ON; flags exist to *disable*
    ap.add_argument("--fast", action="store_true",
                    help="Top-1000 TCP only (default: full -p-).")
    ap.add_argument("--no-udp", dest="udp", action="store_false",
                    help="Disable UDP scan (default on, root only).")
    ap.add_argument("--no-web",  dest="web", action="store_false",
                    help="Disable web enumeration (default on).")
    ap.add_argument("--no-ad",   dest="ad",  action="store_false",
                    help="Disable AD-specific enum (kerbrute) (default on).")
    ap.add_argument("--quiet",   action="store_true",
                    help="Disable live mirroring of tool output.")
    ap.add_argument("--threads", type=int, default=4,
                    help="Thread pool size (default 4 — keeps mirror readable).")
    ap.add_argument("--wordlist", type=Path, default=None,
                    help="Username wordlist for kerbrute.")
    ap.set_defaults(udp=True, web=True, ad=True)

    if len(sys.argv) == 1:
        ap.print_help()
        return 1
    args = ap.parse_args()

    # ── HOST MODE ── post-foothold on-host enumeration (no scanning, no IP needed)
    if args.mode == "host":
        return host_mode(args)

    # ── EXTERNAL MODE ── original behavior; requires a target
    if not args.ip:
        err("--mode external requires a target IP")
        return 2

    # Validate target: accept IPv4, IPv6, or resolvable hostname
    import ipaddress as _ipa
    try:
        _ipa.ip_address(args.ip)  # validates both v4 and v6
    except ValueError:
        # Not a bare IP — check if it looks like a hostname
        if not re.match(r"^[a-zA-Z0-9._-]+$", args.ip):
            err(f"invalid target (not an IP or hostname): {args.ip}")
            return 2
        warn(f"{args.ip} is not an IP address — treating as hostname")

    started = datetime.now()
    out = Path(args.out) if args.out else Path(
        f"recon_{args.ip}_{started.strftime('%Y%m%d_%H%M%S')}"
    )
    out.mkdir(parents=True, exist_ok=True)
    ok(f"Output dir → {out}")

    # Wire up master log + console mirroring
    global RUN_LOG, MIRROR
    RUN_LOG = out / "run.log"
    RUN_LOG.write_text(
        f"# recon.py run.log\n"
        f"# target: {args.ip}\n"
        f"# started: {started.isoformat(timespec='seconds')}\n"
        f"# argv: {' '.join(sys.argv)}\n"
        f"# uid: {os.geteuid()}\n\n"
    )
    MIRROR = not args.quiet
    if MIRROR:
        info("Live mirroring ON  — every tool's output streams here in real time.")
    else:
        info("Live mirroring OFF — see run.log + per-tool files for output.")

    if not is_root():
        warn("Not root — SYN/UDP scans fall back to connect; some scripts limited.")

    # Pre-flight tool check
    missing = [t for t in ("nmap","dig","curl") if not have(t)]
    if missing:
        err(f"missing core tools: {', '.join(missing)}")
        return 3

    fqdn = None
    if args.hostname and args.domain:
        fqdn = f"{args.hostname}.{args.domain}".lower()
    elif args.hostname and "." in args.hostname:
        fqdn = args.hostname.lower()

    t = Target(ip=args.ip, hostname=args.hostname, domain=args.domain, fqdn=fqdn)

    try:
        phase0_host(t, out)
        full_future = phase1_ports(t, out, full=not args.fast, udp=args.udp)
        if t.open_tcp:
            phase1_5_enrich(t, out)
            phase2_services(t, out, threads=args.threads,
                            web=args.web, ad=args.ad,
                            wordlist=args.wordlist)
        # Wait for background -p- sweep to finish before final summary
        if full_future is not None:
            if not full_future.done():
                info("Waiting for background -p- sweep to finish...")
            try:
                full_future.result(timeout=2400)
            except cf.TimeoutError:
                warn("Background -p- sweep still running at cap — captured output is partial.")
            except Exception as e:
                err(f"-p- sweep error: {e}")
            # If the full sweep found new ports AFTER Phase 2 ran, do a small follow-up
            unscanned = [p for p in t.open_tcp if p not in t.services]
            if unscanned:
                warn(f"Late-discovered ports not yet enumerated: {unscanned} — running follow-up enum.")
                # Re-run service dispatcher (idempotent — gates on open_tcp/open_udp)
                phase2_services(t, out, threads=args.threads,
                                web=args.web, ad=args.ad,
                                wordlist=args.wordlist)
        _purge_empty_files(out)
        write_summary(t, out, started)
    except KeyboardInterrupt:
        warn("Interrupted by user — writing partial summary.")
        _purge_empty_files(out)
        write_summary(t, out, started)
        return 130

    elapsed = (datetime.now() - started).total_seconds()
    ok(f"Done in {elapsed:.0f}s — review {out/'summary.md'}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
