"""ERP system security assessment module.

Covers SAP and common enterprise application platforms.
Checks for default configurations, exposed management interfaces,
and known vulnerability patterns.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx

from iescan.config import ScanConfig
from iescan.core.scanner import (
    BaseModule,
    Finding,
    FindingCategory,
    ModuleResult,
    Severity,
)
from iescan.utils.network import PortResult, tcp_connect_scan

logger = logging.getLogger(__name__)

# Common SAP ports
SAP_PORTS = {
    3200: "SAP Dispatcher",
    3300: "SAP Gateway",
    8000: "SAP ICM HTTP",
    8001: "SAP ICM HTTPS",
    8080: "SAP Web Dispatcher",
    44300: "SAP ICM HTTPS",
    50000: "SAP Management Console",
    50013: "SAP Start Service",
    50014: "SAP Start Service HTTPS",
}

# SAP default URLs to check
SAP_CHECK_URLS = [
    ("/sap/public/info", "SAP System Information"),
    ("/sap/bc/gui/sap/its/webgui", "SAP Web GUI"),
    ("/sap/bc/webdynpro/sap/", "SAP WebDynpro"),
    ("/sap/hana/xs/formLogin/login.html", "SAP HANA XS Login"),
    ("/irj/portal", "SAP Enterprise Portal"),
    ("/webdynpro/dispatcher/sap.com/", "SAP WebDynpro Dispatcher"),
    ("/sap/bc/rest/", "SAP REST Services"),
]

# Known ERP management interfaces
ERP_MANAGEMENT_PATHS = [
    ("/console", "WebLogic Admin Console"),
    ("/em", "Oracle Enterprise Manager"),
    ("/apex", "Oracle APEX"),
    ("/manager/html", "Tomcat Manager"),
    ("/ibm/console", "IBM WebSphere Console"),
    ("/admin", "Admin Panel"),
    ("/administrator", "Admin Panel"),
]


class ERPAssessmentModule(BaseModule):
    """Assess ERP systems and enterprise applications for security issues."""

    name = "erp_assessment"
    description = "Assess ERP systems (SAP, Oracle) for misconfigurations and exposed interfaces"

    def run(self, target: str, **kwargs: Any) -> ModuleResult:
        result = self._make_result(target)

        # Scan for SAP ports
        sap_ports = list(SAP_PORTS.keys())
        open_ports = tcp_connect_scan(
            target,
            ports=sap_ports,
            timeout=self.config.timeout,
            threads=self.config.threads,
        )

        if open_ports:
            result.data["sap_ports"] = [
                {"port": p.port, "service": SAP_PORTS.get(p.port, p.service)}
                for p in open_ports
            ]
            result.findings.append(
                Finding(
                    title=f"SAP Services Detected on {target}",
                    severity=Severity.INFO,
                    category=FindingCategory.ERP,
                    description=(
                        f"Found {len(open_ports)} SAP-related ports open. "
                        "SAP systems contain critical business data and require "
                        "careful security configuration."
                    ),
                    target=target,
                    evidence="\n".join(
                        f"Port {p.port}: {SAP_PORTS.get(p.port, 'unknown')}"
                        for p in open_ports
                    ),
                )
            )

        # Check web interfaces
        web_ports_to_check = [
            p.port for p in open_ports if p.port in (8000, 8001, 8080, 44300, 50000)
        ]
        # Also check common web ports
        common_web = tcp_connect_scan(
            target, ports=[80, 443, 8080, 8443], timeout=self.config.timeout
        )
        web_ports_to_check.extend(p.port for p in common_web)

        for port in set(web_ports_to_check):
            self._check_web_interfaces(target, port, result)

        # Check for ERP management consoles
        for port in set(web_ports_to_check):
            self._check_management_consoles(target, port, result)

        return result

    def _check_web_interfaces(
        self, target: str, port: int, result: ModuleResult
    ) -> None:
        """Check for exposed SAP web interfaces."""
        scheme = "https" if port in (443, 8443, 8001, 44300, 50014) else "http"

        for path, desc in SAP_CHECK_URLS:
            url = f"{scheme}://{target}:{port}{path}"
            try:
                response = httpx.get(
                    url,
                    timeout=self.config.timeout,
                    verify=False,
                    follow_redirects=True,
                )

                if response.status_code == 200:
                    result.findings.append(
                        Finding(
                            title=f"{desc} Accessible on {target}:{port}",
                            severity=Severity.MEDIUM,
                            category=FindingCategory.ERP,
                            description=(
                                f"SAP interface '{desc}' is accessible at {url}. "
                                "Exposed SAP interfaces may reveal system information "
                                "or provide attack surface for authentication bypass."
                            ),
                            target=target,
                            evidence=f"URL: {url} (HTTP {response.status_code})",
                            remediation=(
                                "Restrict access to SAP web interfaces via firewall rules. "
                                "Ensure proper authentication is enforced. "
                                "Disable unnecessary services."
                            ),
                        )
                    )

                    # Check /sap/public/info specifically for information disclosure
                    if "/sap/public/info" in path:
                        self._parse_sap_info(response.text, target, result)

                elif response.status_code == 401 or response.status_code == 403:
                    # Service exists but requires auth
                    result.data.setdefault("authenticated_endpoints", []).append(
                        {"url": url, "desc": desc, "status": response.status_code}
                    )

            except Exception:
                continue

    def _parse_sap_info(self, body: str, target: str, result: ModuleResult) -> None:
        """Parse SAP system information from /sap/public/info."""
        info: dict[str, str] = {}

        # Extract key info fields
        patterns = {
            "system_id": r"<SAPSYSTEMNAME>([^<]+)</SAPSYSTEMNAME>",
            "instance": r"<SAPINSTANCE>([^<]+)</SAPINSTANCE>",
            "kernel_release": r"<KERNEL_RELEASE>([^<]+)</KERNEL_RELEASE>",
            "kernel_patch": r"<KERNEL_PATCHLEVEL>([^<]+)</KERNEL_PATCHLEVEL>",
            "database": r"<DATABASETYPE>([^<]+)</DATABASETYPE>",
            "os": r"<OPERATINGSYSTEM>([^<]+)</OPERATINGSYSTEM>",
        }

        for key, pattern in patterns.items():
            match = re.search(pattern, body)
            if match:
                info[key] = match.group(1)

        if info:
            result.data["sap_system_info"] = info
            result.findings.append(
                Finding(
                    title=f"SAP System Information Disclosed on {target}",
                    severity=Severity.HIGH,
                    category=FindingCategory.ERP,
                    description=(
                        "SAP /sap/public/info endpoint exposes detailed system information "
                        "including kernel version, database type, and OS. This information "
                        "aids attackers in identifying applicable exploits."
                    ),
                    target=target,
                    evidence="\n".join(f"{k}: {v}" for k, v in info.items()),
                    remediation=(
                        "Restrict access to /sap/public/info. "
                        "Configure ICM to block this URL for external access."
                    ),
                )
            )

    def _check_management_consoles(
        self, target: str, port: int, result: ModuleResult
    ) -> None:
        """Check for exposed ERP management consoles."""
        scheme = "https" if port in (443, 8443) else "http"

        for path, desc in ERP_MANAGEMENT_PATHS:
            url = f"{scheme}://{target}:{port}{path}"
            try:
                response = httpx.get(
                    url,
                    timeout=self.config.timeout,
                    verify=False,
                    follow_redirects=True,
                )

                if response.status_code == 200:
                    result.findings.append(
                        Finding(
                            title=f"Management Console Exposed: {desc} on {target}:{port}",
                            severity=Severity.HIGH,
                            category=FindingCategory.ERP,
                            description=(
                                f"Management console '{desc}' is accessible without "
                                f"authentication at {url}."
                            ),
                            target=target,
                            evidence=f"URL: {url} (HTTP {response.status_code})",
                            remediation=(
                                "Restrict management console access to admin networks only. "
                                "Implement strong authentication and access controls."
                            ),
                        )
                    )
            except Exception:
                continue
