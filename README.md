# iescan

**Internal Enterprise Security Assessment Network Scanner**

Authorized penetration testing tool for internal enterprise environments with AI-powered agentic reasoning. Covers Active Directory, Kerberos, network services, databases, file shares, ERP systems, and privilege escalation path mapping.

## Features

### Assessment Modules

| Module | Coverage |
|--------|----------|
| **AD Enumeration** | Users, groups, computers, unconstrained delegation, stale accounts, adminSDHolder |
| **Kerberos Assessment** | Kerberoasting, AS-REP Roasting, delegation abuse, encryption weakness, krbtgt review |
| **GPO Assessment** | GPP passwords (MS14-025), password policies, GPO permissions, unlinked GPOs |
| **Trust Assessment** | SID filtering, transitive chains, downlevel trusts, intra-forest RC4 |
| **Network Discovery** | Live host detection, port scanning, service identification, role detection |
| **Service Assessment** | Banner analysis, SMB signing, LLMNR, WinRM, version detection |
| **Share Enumeration** | SMB share access, admin shares, sensitive file detection, null sessions |
| **MSSQL Assessment** | Default credentials, xp_cmdshell, linked servers, TRUSTWORTHY DBs, sysadmin audit |
| **MySQL Assessment** | Anonymous users, passwordless accounts, wildcard hosts, SSL check |
| **PostgreSQL Assessment** | Trust authentication, superuser audit, SSL, default credentials |
| **ERP Assessment** | SAP system info disclosure, management consoles, exposed interfaces |
| **Privesc Pathfinder** | Kerberoast chains, delegation paths, nested groups, GPO abuse, ACL paths |

### AI-Powered Agentic Reasoning

The agentic reasoning engine uses LLM analysis to:
- **Decide next steps** — intelligently selects which module to run based on current findings
- **Correlate cross-module findings** — identifies compound risks that individual tools miss
- **Map attack chains** — builds realistic multi-step attack paths (e.g., Kerberoasting -> credential crack -> SQL linked server -> domain admin)
- **Generate attack narratives** — produces detailed exploitation walkthroughs for reports
- **Produce executive summaries** — CISO-ready risk assessments

Supports **Anthropic Claude**, **OpenAI**, and **local Ollama** models.

### MCP Server

Exposes all assessment tools via the **Model Context Protocol**, allowing AI agents to orchestrate security assessments through structured tool calls. Includes 17 MCP tools covering configuration, scanning, analysis, and reporting.

---

## Prerequisites

- **Python 3.10+**
- **pip** (Python package manager)
- **(Optional)** An LLM API key for agentic mode — Anthropic, OpenAI, or a local Ollama instance
- **(Optional)** Domain credentials for authenticated AD testing

---

## Step 1: Install

### Clone and install in editable mode

```bash
git clone https://github.com/sundi133/iescan.git
cd iescan
```

### Option A: Install with pip (recommended)

```bash
pip install -e .
```

### Option B: Install in a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate    # Linux/Mac
# .venv\Scripts\activate     # Windows
pip install -e .
```

### Option C: Install with dev dependencies (for contributors)

```bash
pip install -e ".[dev]"
```

### Verify installation

```bash
iescan --version
# iescan, version 0.1.0

iescan --help
```

Expected output:

```
Usage: iescan [OPTIONS] COMMAND [ARGS]...

  iescan - Internal Enterprise Security Assessment Scanner.
  Authorized penetration testing tool for internal enterprise environments.

Options:
  --version  Show the version and exit.
  --help     Show this message and exit.

Commands:
  ad-assess  Quick Active Directory assessment.
  agent      Run an AI-powered agentic assessment.
  discover   Quick network discovery scan.
  mcp        Start the MCP server for AI-assisted assessments.
  modules    List available assessment modules.
  scan       Run a security assessment scan.
```

---

## Step 2: Configure Your Engagement

Every config-driven scan requires an engagement YAML file. Copy the sample and edit it:

```bash
cp sample_config.yaml my_engagement.yaml
```

Edit `my_engagement.yaml`:

```yaml
# REQUIRED: Engagement authorization
engagement_id: "ENG-2026-001"
authorization_ref: "SOW-2026-001-signed.pdf"

# REQUIRED: Define your authorized scope
scope:
  networks:
    - "10.0.0.0/24"          # Subnets to scan
  domains:
    - "corp.local"            # AD domains
  hosts:
    - "10.0.0.1"              # Primary DC
    - "10.0.0.10"             # SQL Server
    - "10.0.0.20"             # File Server
  exclude_hosts:
    - "10.0.0.254"            # DO NOT TEST
  exclude_networks:
    - "10.0.1.0/24"           # OUT OF SCOPE

# Credentials for authenticated testing
credentials:
  username: "pentest_user"
  password: "your_password_here"
  domain: "corp.local"
  use_kerberos: false          # Set true for Kerberos auth
  # ntlm_hash: ""             # For pass-the-hash
  # kerberos_ticket: ""       # Path to .ccache file

# Which modules to run ("all" or list specific ones)
modules:
  - "all"

# Scan settings
threads: 10                    # Concurrent scan threads
timeout: 30                    # Connection timeout (seconds)
verbose: false                 # Debug logging
safe_mode: true                # Avoid destructive operations
output_dir: "./reports"        # Where reports are saved
```

### Configuration reference

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `engagement_id` | Yes | — | Unique engagement identifier |
| `authorization_ref` | Yes | — | Reference to signed authorization document |
| `scope.networks` | No | `[]` | CIDR ranges to scan |
| `scope.domains` | No | `[]` | AD domain names in scope |
| `scope.hosts` | No | `[]` | Individual IPs/hostnames |
| `scope.exclude_hosts` | No | `[]` | Hosts excluded from scope |
| `scope.exclude_networks` | No | `[]` | Networks excluded from scope |
| `credentials.username` | No | `""` | Domain username |
| `credentials.password` | No | `""` | Password |
| `credentials.domain` | No | `""` | AD domain for auth |
| `credentials.ntlm_hash` | No | `""` | NTLM hash (pass-the-hash) |
| `credentials.use_kerberos` | No | `false` | Use Kerberos authentication |
| `modules` | No | `["all"]` | Modules to run |
| `threads` | No | `10` | Concurrent scan threads |
| `timeout` | No | `30` | Connection timeout (seconds) |
| `verbose` | No | `false` | Debug logging |
| `safe_mode` | No | `true` | Avoid destructive operations |
| `output_dir` | No | `"./reports"` | Report output directory |

---

## Step 3: Run Scans

### 3a. List available modules

```bash
iescan modules
```

Shows all 12 assessment modules with descriptions and categories.

### 3b. Quick network discovery (no config file needed)

Discover live hosts and open ports on a subnet:

```bash
iescan discover -t 10.0.0.0/24
```

With custom timeout and thread count:

```bash
iescan discover -t 10.0.0.0/24 --timeout 10 --threads 50
```

### 3c. Quick AD assessment (no config file needed)

Run all AD modules against a domain controller with inline credentials:

```bash
iescan ad-assess \
  -t 10.0.0.1 \
  -u pentest_user \
  -p 'P@ssw0rd' \
  -d corp.local \
  -o ./reports
```

This runs 5 modules: AD Enumeration, Kerberos Assessment, GPO Assessment, Trust Assessment, and Privesc Pathfinder.

Reports saved to `./reports/ad_assessment.json` and `./reports/ad_assessment.html`.

### 3d. Full config-driven scan (all modules)

```bash
iescan scan -c my_engagement.yaml
```

Run specific modules only:

```bash
iescan scan -c my_engagement.yaml \
  -m network_discovery \
  -m service_assessment \
  -m ad_enumeration
```

Add extra targets from CLI:

```bash
iescan scan -c my_engagement.yaml -t 10.0.0.50 -t 10.0.0.51
```

Change output directory and report format:

```bash
iescan scan -c my_engagement.yaml \
  -o ./pentest_output \
  --format html           # json, html, or both (default: both)
```

Verbose mode (debug logging):

```bash
iescan scan -c my_engagement.yaml -v
```

### 3e. AI-powered agentic assessment

The agent autonomously decides which modules to run, correlates findings across modules, and generates attack narratives — all driven by LLM reasoning.

**Set your API key:**

```bash
# Anthropic (default provider)
export ANTHROPIC_API_KEY="sk-ant-..."

# Or OpenAI
export OPENAI_API_KEY="sk-..."
```

**Run with Anthropic Claude (default):**

```bash
iescan agent \
  -c my_engagement.yaml \
  -t 10.0.0.1 \
  -t 10.0.0.10 \
  --provider anthropic
```

**Run with OpenAI:**

```bash
iescan agent \
  -c my_engagement.yaml \
  -t 10.0.0.1 \
  --provider openai \
  --model gpt-4o \
  --api-key "$OPENAI_API_KEY"
```

**Run with local Ollama (fully offline, no API key):**

```bash
iescan agent \
  -c my_engagement.yaml \
  -t 10.0.0.1 \
  --provider ollama \
  --model llama3
```

**Limit agent iterations and set output:**

```bash
iescan agent \
  -c my_engagement.yaml \
  -t 10.0.0.1 \
  --max-steps 10 \
  -o ./agentic_reports \
  -v
```

**What the agent does at each step:**

1. Starts with **network discovery** to map the attack surface
2. Feeds results to the LLM, which **picks the next module and target**
3. Repeats: scan -> reason -> scan -> reason (up to `--max-steps`, default 20)
4. Runs **cross-module correlation** to find compound attack chains
5. Generates a **detailed attack narrative** for the pentest report
6. Produces a **CISO-ready executive summary**

---

## Step 4: Use the MCP Server

The MCP server exposes all 17 assessment tools for AI agent orchestration via stdio.

### Start the server

```bash
iescan mcp
```

### Configure in Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "iescan": {
      "command": "iescan",
      "args": ["mcp"]
    }
  }
}
```

### Configure in Claude Code

Add to `.mcp.json` in your project root:

```json
{
  "mcpServers": {
    "iescan": {
      "command": "iescan",
      "args": ["mcp"]
    }
  }
}
```

### MCP tool workflow

The AI agent uses the tools in this order:

**1. Configure the engagement (required first):**

```json
// Tool: configure_scan
{
  "engagement_id": "ENG-2026-001",
  "authorization_ref": "SOW-signed.pdf",
  "networks": ["10.0.0.0/24"],
  "domains": ["corp.local"],
  "hosts": ["10.0.0.1"],
  "username": "pentest_user",
  "password": "password",
  "domain": "corp.local"
}
```

**2. Run individual modules as needed:**

```
discover_network       { "target": "10.0.0.0/24" }
enumerate_ad           { "target": "10.0.0.1" }
assess_kerberos        { "target": "10.0.0.1" }
assess_gpo             { "target": "10.0.0.1" }
assess_trusts          { "target": "10.0.0.1" }
enumerate_shares       { "target": "10.0.0.20" }
assess_services        { "target": "10.0.0.10" }
assess_mssql           { "target": "10.0.0.10", "port": 1433 }
assess_mysql           { "target": "10.0.0.11", "port": 3306 }
assess_postgresql      { "target": "10.0.0.12", "port": 5432 }
assess_erp             { "target": "10.0.0.30" }
find_privesc_paths     { "target": "10.0.0.1" }
```

**3. Or run everything at once:**

```json
// Tool: full_internal_assessment
{ "targets": ["10.0.0.1", "10.0.0.10", "10.0.0.20"], "dc_target": "10.0.0.1" }
```

**4. Or let the AI agent drive autonomously:**

```json
// Tool: run_agentic_assessment
{
  "targets": ["10.0.0.1", "10.0.0.10"],
  "api_key": "sk-ant-...",
  "provider": "anthropic",
  "max_steps": 20
}
```

**5. Analyze findings with LLM reasoning (after running modules):**

```json
// Tool: analyze_findings
{ "api_key": "sk-ant-...", "provider": "anthropic" }
```

**6. Generate reports:**

```json
// Tool: generate_report
{ "format": "html", "output_path": "./reports/assessment.html" }
```

### All 17 MCP tools

| Tool | Description |
|------|-------------|
| `configure_scan` | Set engagement details, credentials, and scope |
| `discover_network` | Discover live hosts and open ports |
| `assess_services` | Check for vulnerable services and protocols |
| `enumerate_ad` | Enumerate AD objects and misconfigurations |
| `assess_kerberos` | Assess Kerberos security configuration |
| `assess_gpo` | Assess Group Policy Objects |
| `assess_trusts` | Assess AD trust relationships |
| `enumerate_shares` | Enumerate SMB shares and permissions |
| `assess_mssql` | Assess MSSQL security |
| `assess_mysql` | Assess MySQL security |
| `assess_postgresql` | Assess PostgreSQL security |
| `assess_erp` | Assess ERP systems (SAP, Oracle) |
| `find_privesc_paths` | Map privilege escalation paths |
| `full_internal_assessment` | Run all modules against targets |
| `analyze_findings` | LLM-powered finding correlation and analysis |
| `run_agentic_assessment` | Fully autonomous AI-driven assessment |
| `generate_report` | Generate JSON/HTML reports |

---

## Step 5: View Reports

Reports are saved to `./reports/` (or custom `output_dir`):

```
reports/
├── iescan_report_2026-03-02_14-30-00.json    # Machine-readable JSON
├── iescan_report_2026-03-02_14-30-00.html    # Browser-viewable HTML dashboard
├── ad_assessment.json                         # From ad-assess command
└── ad_assessment.html
```

- **JSON report** — structured findings with severity, evidence, and remediation. Ingest into SIEM, ticketing systems, or further analysis pipelines.
- **HTML report** — styled dashboard with severity breakdown chart, sortable findings table, and engagement metadata. Open in any browser.

---

## Module Names Reference

Use these names with the `-m` flag or in the config `modules:` list:

| Name | Category | Description |
|------|----------|-------------|
| `network_discovery` | Network | Host and port discovery |
| `service_assessment` | Network | Service vulnerability checks |
| `ad_enumeration` | Active Directory | AD object enumeration |
| `kerberos_assessment` | Active Directory | Kerberos security assessment |
| `gpo_assessment` | Active Directory | Group Policy assessment |
| `trust_assessment` | Active Directory | Trust relationship assessment |
| `share_enumeration` | File Shares | SMB share enumeration |
| `mssql_assessment` | Database | Microsoft SQL Server assessment |
| `mysql_assessment` | Database | MySQL/MariaDB assessment |
| `postgresql_assessment` | Database | PostgreSQL assessment |
| `erp_assessment` | ERP Systems | SAP/ERP assessment |
| `privesc_pathfinder` | Privilege Escalation | Escalation path mapping |

---

## CLI Quick Reference

```bash
iescan --help                   # Show all commands
iescan --version                # Show version
iescan modules                  # List all assessment modules

# Network discovery (no config file needed)
iescan discover -t 10.0.0.0/24
iescan discover -t 10.0.0.0/24 --timeout 10 --threads 50

# AD assessment (no config file needed)
iescan ad-assess -t DC_IP -u USER -p PASS -d DOMAIN
iescan ad-assess -t 10.0.0.1 -u admin -p 'P@ss' -d corp.local -o ./out

# Full config-driven scan
iescan scan -c config.yaml
iescan scan -c config.yaml -m ad_enumeration -m kerberos_assessment
iescan scan -c config.yaml -t EXTRA_TARGET --format json -o ./out -v

# Agentic AI assessment
iescan agent -c config.yaml -t TARGET --provider anthropic
iescan agent -c config.yaml -t TARGET --provider openai --model gpt-4o --api-key KEY
iescan agent -c config.yaml -t TARGET --provider ollama --model llama3
iescan agent -c config.yaml -t TARGET --max-steps 10 -o ./out -v

# MCP server
iescan mcp
```

---

## Architecture

```
src/iescan/
├── __init__.py                   # Package version
├── cli.py                        # CLI interface (click + rich)
├── config.py                     # YAML configuration management
├── core/
│   ├── scanner.py                # Scan engine, findings model, module base class
│   ├── reporter.py               # JSON + HTML report generation
│   ├── auth.py                   # Engagement authorization & scope enforcement
│   ├── reasoning.py              # LLM reasoning engine (Anthropic/OpenAI/Ollama)
│   └── agent.py                  # Agentic pentest orchestrator (autonomous loop)
├── modules/
│   ├── ad/
│   │   ├── enumeration.py        # AD user, group, computer, delegation enumeration
│   │   ├── kerberos.py           # Kerberos encryption, delegation, krbtgt assessment
│   │   ├── gpo.py                # GPO passwords, policies, permissions assessment
│   │   └── trusts.py             # Trust relationship security assessment
│   ├── network/
│   │   ├── discovery.py          # Live host and port discovery
│   │   ├── services.py           # Service banner analysis and vulnerability checks
│   │   └── shares.py             # SMB share enumeration and access testing
│   ├── database/
│   │   ├── mssql.py              # MSSQL security assessment
│   │   └── common.py             # MySQL + PostgreSQL assessment
│   ├── erp/
│   │   └── sap.py                # SAP/ERP interface assessment
│   └── privesc/
│       └── pathfinder.py         # Privilege escalation path mapping
├── mcp/
│   └── server.py                 # MCP server (17 tools, stdio transport)
└── utils/
    ├── network.py                # TCP scanning, host discovery, CIDR expansion
    └── ldap.py                   # LDAP connection management, search utilities
```

---

## Authorization

All scans require:
- **Engagement ID** — unique identifier for the pentest engagement
- **Authorization Reference** — reference to signed SOW/authorization document
- **Defined Scope** — explicit networks, hosts, and domains authorized for testing
- **Exclusion List** — systems explicitly out of scope

The tool validates authorization before executing any module and enforces scope boundaries at runtime. Targets outside the defined scope are automatically filtered and logged.

## License

MIT
