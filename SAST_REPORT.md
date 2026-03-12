# SAST Security Scan Report - iescan

**Date:** 2026-03-12
**Tool:** Manual SAST Review
**Scope:** All Python source files in `src/iescan/`
**Total Files Analyzed:** 18
**Total Lines of Code:** ~2,151

---

## Summary

| Severity | Count |
|----------|-------|
| **CRITICAL** | 2 |
| **HIGH** | 5 |
| **MEDIUM** | 4 |
| **LOW** | 4 |
| **Total** | 15 |

---

## CRITICAL Findings

### SAST-001: Cross-Site Scripting (XSS) in HTML Report Generation

- **File:** `src/iescan/core/reporter.py:108-141`
- **CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)
- **OWASP:** A03:2021 - Injection

**Description:**
The Jinja2 `Template()` is instantiated without `autoescape=True`. Finding fields such as `finding.evidence`, `finding.description`, `finding.title`, and `finding.target` are rendered directly into the HTML report using `{{ ... }}` syntax without escaping. Since service banners, SMB share names, LDAP attributes, and SQL query results are inserted into findings as evidence, a malicious service banner or AD object name containing `<script>` tags would execute JavaScript when the HTML report is viewed in a browser.

**Affected Code:**
```python
# reporter.py:157-158
template = Template(HTML_TEMPLATE)  # No autoescape
html = template.render(result=result, ...)
```

Template contains unescaped outputs like:
```html
<div class="evidence">{{ finding.evidence }}</div>   <!-- line 126 -->
<p>{{ finding.description }}</p>                       <!-- line 124 -->
{{ finding.title }}                                    <!-- line 122 -->
```

**Remediation:**
```python
from jinja2 import Template, select_autoescape
template = Template(HTML_TEMPLATE, autoescape=True)
# Or use Environment with autoescape for HTML:
from jinja2 import Environment
env = Environment(autoescape=select_autoescape(['html']))
template = env.from_string(HTML_TEMPLATE)
```

---

### SAST-002: SSRF via Unvalidated `api_base` URL

- **File:** `src/iescan/core/reasoning.py:249, 273`
- **CWE:** CWE-918 (Server-Side Request Forgery)
- **OWASP:** A10:2021 - Server-Side Request Forgery

**Description:**
The `api_base` field in `ReasoningConfig` is used directly to construct HTTP request URLs without any validation or allowlisting. An attacker who can control the configuration (e.g., via the MCP server's `analyze_findings` or `run_agentic_assessment` tools) can direct the tool to make HTTP POST requests containing sensitive scan data (findings, credentials context) to arbitrary internal or external endpoints.

**Affected Code:**
```python
# reasoning.py:249-250
base = self.config.api_base or "https://api.openai.com/v1"
response = self._client.post(f"{base}/chat/completions", ...)

# reasoning.py:272-274
base = self.config.api_base or "http://localhost:11434"
response = self._client.post(f"{base}/api/generate", ...)
```

**Remediation:**
Validate `api_base` against an allowlist of known API endpoints. At minimum, restrict to HTTPS URLs and validate the URL scheme and host:
```python
from urllib.parse import urlparse

ALLOWED_HOSTS = {"api.openai.com", "api.anthropic.com", "localhost", "127.0.0.1"}

def _validate_api_base(self, url: str) -> str:
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError(f"Untrusted API base host: {parsed.hostname}")
    return url
```

---

## HIGH Findings

### SAST-003: SQL Injection Pattern in MSSQL Module

- **File:** `src/iescan/modules/database/mssql.py:195-198`
- **CWE:** CWE-89 (SQL Injection)
- **OWASP:** A03:2021 - Injection

**Description:**
The `_check_dangerous_procs` method constructs a SQL query by directly interpolating values into the query string using f-strings, rather than using parameterized queries. While the current values come from the hardcoded `DANGEROUS_PROCS` list (limiting exploitability), this is a dangerous pattern. If the list is ever made configurable or extended with user input, it becomes directly exploitable.

**Affected Code:**
```python
placeholders = ",".join(f"'{p}'" for p in DANGEROUS_PROCS)
cursor.execute(
    f"SELECT name FROM sys.objects WHERE name IN ({placeholders}) AND type = 'X'"
)
```

**Remediation:**
Use parameterized queries:
```python
placeholders = ",".join(["%s"] * len(DANGEROUS_PROCS))
cursor.execute(
    f"SELECT name FROM sys.objects WHERE name IN ({placeholders}) AND type = 'X'",
    tuple(DANGEROUS_PROCS),
)
```

---

### SAST-004: TLS Certificate Verification Disabled

- **File:** `src/iescan/modules/erp/sap.py:136-137, 223-224`
- **CWE:** CWE-295 (Improper Certificate Validation)
- **OWASP:** A07:2021 - Identification and Authentication Failures

**Description:**
HTTP requests to SAP and ERP management interfaces are made with `verify=False`, disabling TLS certificate validation. This makes the scanner itself vulnerable to man-in-the-middle attacks during assessment. An attacker on the network could intercept these requests and inject false responses, causing the tool to produce misleading results, or capture credentials if they are included in requests.

**Affected Code:**
```python
response = httpx.get(url, timeout=self.config.timeout, verify=False, follow_redirects=True)
```

**Remediation:**
Make TLS verification configurable with a secure default:
```python
verify = not self.config.safe_mode  # or a dedicated config flag
response = httpx.get(url, timeout=self.config.timeout, verify=verify, follow_redirects=False)
```
At minimum, log a warning when verification is disabled. Also disable `follow_redirects` to prevent open redirect abuse (see SAST-009).

---

### SAST-005: LDAP Filter Injection

- **File:** `src/iescan/modules/ad/gpo.py:182`, `src/iescan/modules/privesc/pathfinder.py:272, 305, 342`
- **CWE:** CWE-90 (LDAP Injection)
- **OWASP:** A03:2021 - Injection

**Description:**
Several LDAP search filters are constructed using f-string interpolation with values derived from configuration (primarily `base_dn`, which is built from the domain name). If the domain name in the config contains LDAP metacharacters (e.g., `)(`, `*`, `\`), it could alter the semantics of the LDAP filter.

**Affected Code:**
```python
# gpo.py:182
f"(distinguishedName={base_dn})"

# enumeration.py:104-105
f"(&(objectCategory=person)(objectClass=user)(memberOf=CN=Domain Admins,CN=Users,{base_dn}))"

# pathfinder.py:272
f"(&(objectCategory=group)(memberOf=CN=Domain Admins,CN=Users,{base_dn}))"
```

**Remediation:**
Escape LDAP special characters in user-supplied values before filter construction:
```python
from ldap3.utils.conv import escape_filter_chars

safe_base_dn = escape_filter_chars(base_dn)
search_filter = f"(distinguishedName={safe_base_dn})"
```

---

### SAST-006: Cleartext Credential Handling with No Memory Protection

- **File:** `src/iescan/config.py:25-34`, `src/iescan/cli.py:225-239`
- **CWE:** CWE-256 (Plaintext Storage of a Password)
- **OWASP:** A04:2021 - Insecure Design

**Description:**
Credentials (passwords, NTLM hashes, Kerberos tickets, API keys) are stored as plain Python strings in dataclass fields. They are loaded from YAML config files in plaintext, passed via CLI arguments (visible in process listing via `ps aux`), and remain in memory for the lifetime of the process. The `ad_assess` command accepts `--password` as a CLI argument which is visible in shell history and process listings.

**Affected Code:**
```python
# config.py:26-33
@dataclass
class Credentials:
    username: str = ""
    password: str = ""       # Plaintext
    ntlm_hash: str = ""      # Plaintext
    kerberos_ticket: str = "" # Plaintext

# cli.py:227
@click.option("-p", "--password", required=True, help="Password")
```

**Remediation:**
- Use `click.option("--password", prompt=True, hide_input=True)` for interactive password entry
- Support reading credentials from environment variables or credential files with restricted permissions
- Consider implementing a `SecureString` wrapper that zeros memory on deletion
- Add `__repr__` to `Credentials` that masks sensitive fields

---

### SAST-007: Hardcoded Default Credential Lists

- **File:** `src/iescan/modules/database/mssql.py:24-30`, `src/iescan/modules/database/common.py:23-36`
- **CWE:** CWE-798 (Use of Hard-coded Credentials)
- **OWASP:** A07:2021 - Identification and Authentication Failures

**Description:**
Default credential pairs for MSSQL, MySQL, and PostgreSQL are hardcoded in the source code. While intentional for security testing, these lists being in source code means they can't be easily updated, are visible to anyone with repo access, and could be inadvertently leaked. Additionally, the credential testing logic runs in a loop attempting logins, which could trigger account lockouts.

**Affected Code:**
```python
# mssql.py:24-30
DEFAULT_CREDS = [("sa", ""), ("sa", "sa"), ("sa", "password"), ...]

# common.py:23-36
MYSQL_DEFAULT_CREDS = [("root", ""), ("root", "root"), ...]
POSTGRES_DEFAULT_CREDS = [("postgres", ""), ("postgres", "postgres"), ...]
```

**Remediation:**
- Load credential lists from an external configuration file
- Add rate limiting between authentication attempts
- Check the account lockout policy before brute-forcing (already partially addressed by `safe_mode` check)
- Add a maximum attempt limit

---

## MEDIUM Findings

### SAST-008: Global Mutable State in MCP Server (Thread Safety)

- **File:** `src/iescan/mcp/server.py:36, 496, 501, 511`
- **CWE:** CWE-362 (Race Condition)
- **OWASP:** A04:2021 - Insecure Design

**Description:**
The MCP server uses global mutable variables `_config` and `_last_scan_result` to maintain state across tool calls. These are modified via `global` declarations within async handlers. If multiple concurrent requests are processed (which is possible with async), these shared globals could be read/written simultaneously, leading to race conditions where one client's scan results are served to another, or configuration is corrupted mid-scan.

**Remediation:**
Use a session-scoped state container or `contextvars` for request isolation:
```python
import contextvars
_session_config: contextvars.ContextVar[ScanConfig | None] = contextvars.ContextVar('config', default=None)
```

---

### SAST-009: Open Redirect via `follow_redirects=True`

- **File:** `src/iescan/modules/erp/sap.py:137, 224`
- **CWE:** CWE-601 (URL Redirection to Untrusted Site)

**Description:**
HTTP requests in the ERP module use `follow_redirects=True`. Combined with disabled TLS verification, a malicious server could redirect the scanner to an attacker-controlled endpoint, potentially causing the tool to disclose information about its scanning activity or trigger unintended actions against other hosts.

**Remediation:**
Set `follow_redirects=False` and explicitly handle redirects if needed, validating the redirect target is within scope.

---

### SAST-010: Socket Resource Leak in Port Scanner

- **File:** `src/iescan/utils/network.py:121-139`
- **CWE:** CWE-404 (Improper Resource Shutdown or Release)

**Description:**
In the `_scan_port` function, when a port is open (line 124, `result == 0`), the socket is passed to `grab_banner()` which closes it. However, if the port is closed, `sock.close()` is called. But if an exception other than `socket.timeout` or `OSError` is raised (e.g., `OverflowError` for invalid port, or `MemoryError`), the socket will leak. The function should use a `try/finally` or context manager.

**Remediation:**
```python
def _scan_port(port: int) -> PortResult:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        if result == 0:
            banner = grab_banner(sock, timeout)
            return PortResult(host=host, port=port, state="open", service=..., banner=banner)
        return PortResult(host=host, port=port, state="closed")
    except socket.timeout:
        return PortResult(host=host, port=port, state="filtered")
    except OSError:
        return PortResult(host=host, port=port, state="filtered")
    finally:
        try:
            sock.close()
        except OSError:
            pass
```

---

### SAST-011: Unvalidated Output Path (Path Traversal)

- **File:** `src/iescan/core/reporter.py:148-152, 162-165`, `src/iescan/mcp/server.py:559`
- **CWE:** CWE-22 (Path Traversal)

**Description:**
The report output path is user-controlled (via CLI `--output` or MCP `output_path` parameter) and is used directly with `Path.mkdir(parents=True)` and `open()`. There is no validation to prevent writing to arbitrary filesystem locations (e.g., `../../etc/cron.d/malicious`). Through the MCP server, an external AI agent could specify any output path.

**Remediation:**
Validate the output path is within an expected directory:
```python
def safe_output_path(output_path: str, base_dir: str = ".") -> Path:
    resolved = Path(output_path).resolve()
    base = Path(base_dir).resolve()
    if not str(resolved).startswith(str(base)):
        raise ValueError(f"Output path escapes base directory: {output_path}")
    return resolved
```

---

## LOW Findings

### SAST-012: Broad Exception Handling Hiding Errors

- **File:** Multiple files (shares.py:139, 173, 205, 257, 299; kerberos.py; gpo.py; etc.)
- **CWE:** CWE-396 (Declaration of Catch for Generic Exception)

**Description:**
Many modules use bare `except Exception: pass` blocks that silently swallow all errors. This can hide security-relevant failures such as authentication errors, network issues, or unexpected conditions, making debugging difficult and potentially causing the tool to report false negatives (missing findings that should have been reported).

---

### SAST-013: Sensitive Data in Log Messages

- **File:** `src/iescan/core/scanner.py:137`, `src/iescan/utils/ldap.py:87, 91`
- **CWE:** CWE-532 (Information Exposure Through Log Files)

**Description:**
Error messages logged via `logger.error()` include exception details via `str(e)` which may contain sensitive information such as connection strings, credentials, or internal network topology. These logs could be accessed by unauthorized parties if log files are not properly secured.

---

### SAST-014: Write Test File Left on Failure (shares.py)

- **File:** `src/iescan/modules/network/shares.py:178-184`
- **CWE:** CWE-459 (Incomplete Cleanup)

**Description:**
The write access test creates a file `__iescan_write_test__.tmp` on the target share and then deletes it. If the process crashes or is interrupted between `storeFile` and `deleteFiles`, the test file remains on the target share, leaving an artifact of the scan.

**Remediation:**
Wrap in try/finally or use a more unique filename with timestamp.

---

### SAST-015: Missing `HttpOnly`/`Secure` Considerations in HTML Report

- **File:** `src/iescan/core/reporter.py:17-142`
- **CWE:** CWE-1004 (Sensitive Cookie Without 'HttpOnly' Flag)

**Description:**
The HTML report is a standalone file with no CSP (Content Security Policy) headers or meta tags. Combined with SAST-001 (XSS), this means any injected script would have full access to the page content. The report could contain sensitive security findings, network topology, credentials, and evidence data.

**Remediation:**
Add a CSP meta tag to the HTML template:
```html
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
```

---

## Dependency Concerns

Based on `pyproject.toml` analysis:

| Dependency | Concern |
|-----------|---------|
| `impacket 0.11+` | Frequently targeted library; ensure pinned to secure version |
| `scapy 2.5+` | Requires root/admin for raw sockets; ensure privilege separation |
| `cx_Oracle 8.3+` | Oracle client dependency; verify no known CVEs in pinned version |
| `pyyaml 6.0+` | Using `safe_load` (good); verify no deserialization issues |
| `cryptography 41.0+` | Critical security library; keep updated to latest patch |

---

## Recommendations Summary

1. **Immediate (Critical):** Fix XSS in HTML reports by enabling Jinja2 autoescape. Validate `api_base` URLs.
2. **Short-term (High):** Use parameterized SQL queries. Fix LDAP filter injection. Implement secure credential handling. Add TLS verification controls.
3. **Medium-term:** Add thread-safe state management to MCP server. Fix socket leaks. Validate output paths. Disable follow_redirects.
4. **Long-term:** Implement proper error handling throughout. Add CSP to HTML reports. Externalize credential lists. Add logging sanitization.
