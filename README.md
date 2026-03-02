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
- **Map attack chains** — builds realistic multi-step attack paths (e.g., Kerberoasting → credential crack → SQL linked server → domain admin)
- **Generate attack narratives** — produces detailed exploitation walkthroughs for reports
- **Produce executive summaries** — CISO-ready risk assessments

Supports **Anthropic Claude**, **OpenAI**, and **local Ollama** models.

### MCP Server

Exposes all assessment tools via the **Model Context Protocol**, allowing AI agents to orchestrate security assessments through structured tool calls. Includes 17 MCP tools covering configuration, scanning, analysis, and reporting.

## Installation

```bash
pip install -e .
```

## Quick Start

### 1. Configure your engagement

```bash
cp sample_config.yaml my_engagement.yaml
# Edit with your engagement details, scope, and credentials
```

### 2. Run a full scan

```bash
iescan scan -c my_engagement.yaml
```

### 3. Quick network discovery

```bash
iescan discover -t 10.0.0.0/24
```

### 4. Quick AD assessment

```bash
iescan ad-assess -t 10.0.0.1 -u pentest_user -p 'password' -d corp.local
```

### 5. AI-powered agentic assessment

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
iescan agent -c my_engagement.yaml -t 10.0.0.1 -t 10.0.0.10 --provider anthropic
```

### 6. Start MCP server

```bash
iescan mcp
```

### 7. List available modules

```bash
iescan modules
```

## MCP Server Configuration

Add to your MCP client configuration:

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

### MCP Tools

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

## Architecture

```
src/iescan/
├── cli.py                    # CLI interface (click + rich)
├── config.py                 # YAML configuration management
├── core/
│   ├── scanner.py            # Scan engine, findings, module base
│   ├── reporter.py           # JSON + HTML report generation
│   ├── auth.py               # Engagement authorization & scope validation
│   ├── reasoning.py          # LLM-powered reasoning engine
│   └── agent.py              # Agentic pentest orchestrator
├── modules/
│   ├── ad/                   # Active Directory modules
│   │   ├── enumeration.py    # AD object enumeration
│   │   ├── kerberos.py       # Kerberos assessment
│   │   ├── gpo.py            # GPO assessment
│   │   └── trusts.py         # Trust relationship assessment
│   ├── network/              # Network modules
│   │   ├── discovery.py      # Host & port discovery
│   │   ├── services.py       # Service vulnerability checks
│   │   └── shares.py         # SMB share enumeration
│   ├── database/             # Database modules
│   │   ├── mssql.py          # MSSQL assessment
│   │   └── common.py         # MySQL + PostgreSQL assessment
│   ├── erp/
│   │   └── sap.py            # SAP/ERP assessment
│   └── privesc/
│       └── pathfinder.py     # Privilege escalation paths
├── mcp/
│   └── server.py             # MCP server (17 tools)
└── utils/
    ├── network.py            # TCP scanning, host discovery
    └── ldap.py               # LDAP/AD utilities
```

## Authorization

All scans require:
- **Engagement ID** — unique identifier for the pentest engagement
- **Authorization Reference** — reference to signed SOW/authorization document
- **Defined Scope** — explicit networks, hosts, and domains authorized for testing
- **Exclusion List** — systems explicitly out of scope

The tool validates authorization before executing any module and enforces scope boundaries.

## License

MIT
