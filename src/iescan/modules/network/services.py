"""Service identification and vulnerability assessment module.

Identifies running services and checks for known vulnerabilities
and misconfigurations.
"""

from __future__ import annotations

import logging
import re
import socket
from typing import Any

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

# Known vulnerable service patterns
VULNERABLE_BANNERS = [
    {
        "pattern": r"Microsoft-IIS/([0-9.]+)",
        "service": "IIS",
        "check": lambda v: v and tuple(int(x) for x in v.split(".")[:2]) < (10, 0),
        "severity": Severity.MEDIUM,
        "title": "Outdated IIS Version",
        "remediation": "Upgrade to the latest supported version of IIS.",
    },
    {
        "pattern": r"Apache/([0-9.]+)",
        "service": "Apache",
        "check": lambda v: v and tuple(int(x) for x in v.split(".")[:2]) < (2, 4),
        "severity": Severity.MEDIUM,
        "title": "Outdated Apache Version",
        "remediation": "Upgrade to the latest supported version of Apache.",
    },
    {
        "pattern": r"OpenSSH[_/]([0-9.]+)",
        "service": "OpenSSH",
        "check": lambda v: v and tuple(int(x) for x in v.split(".")[:2]) < (8, 0),
        "severity": Severity.MEDIUM,
        "title": "Outdated OpenSSH Version",
        "remediation": "Upgrade to the latest supported version of OpenSSH.",
    },
]


class ServiceAssessmentModule(BaseModule):
    """Identify services and check for known vulnerabilities."""

    name = "service_assessment"
    description = "Identify running services, check banners, and detect known vulnerabilities"

    def run(self, target: str, **kwargs: Any) -> ModuleResult:
        result = self._make_result(target)

        # Scan ports
        open_ports = tcp_connect_scan(
            target,
            timeout=self.config.timeout,
            threads=self.config.threads,
        )

        result.data["open_ports"] = [
            {"port": p.port, "service": p.service, "banner": p.banner}
            for p in open_ports
        ]

        # Analyze banners for version information
        for port_result in open_ports:
            self._analyze_banner(target, port_result, result)

        # Check for SMB signing
        if any(p.port == 445 for p in open_ports):
            self._check_smb_signing(target, result)

        # Check for LLMNR/NBT-NS (via open ports)
        if any(p.port == 5355 for p in open_ports):
            result.findings.append(
                Finding(
                    title=f"LLMNR Enabled on {target}",
                    severity=Severity.MEDIUM,
                    category=FindingCategory.PROTOCOL,
                    description=(
                        "Link-Local Multicast Name Resolution (LLMNR) is enabled. "
                        "LLMNR can be abused for credential relay attacks on the network."
                    ),
                    target=target,
                    remediation=(
                        "Disable LLMNR via Group Policy: Computer Configuration > "
                        "Administrative Templates > Network > DNS Client > "
                        "Turn off multicast name resolution = Enabled."
                    ),
                )
            )

        # Check WinRM
        if any(p.port in (5985, 5986) for p in open_ports):
            self._check_winrm(target, open_ports, result)

        return result

    def _analyze_banner(
        self, target: str, port_result: PortResult, result: ModuleResult
    ) -> None:
        """Analyze a service banner for version information and known issues."""
        if not port_result.banner:
            return

        for vuln_check in VULNERABLE_BANNERS:
            match = re.search(vuln_check["pattern"], port_result.banner)
            if match:
                version = match.group(1)
                if vuln_check["check"](version):
                    result.findings.append(
                        Finding(
                            title=f"{vuln_check['title']}: {vuln_check['service']}/{version} on {target}:{port_result.port}",
                            severity=vuln_check["severity"],
                            category=FindingCategory.NETWORK,
                            description=(
                                f"Detected {vuln_check['service']} version {version} which "
                                "may be outdated and contain known vulnerabilities."
                            ),
                            target=target,
                            evidence=f"Banner: {port_result.banner}",
                            remediation=vuln_check["remediation"],
                        )
                    )

    def _check_smb_signing(self, target: str, result: ModuleResult) -> None:
        """Check if SMB signing is required."""
        try:
            from impacket.smbconnection import SMBConnection

            smb = SMBConnection(target, target, timeout=self.config.timeout)
            smb.login("", "")  # Null session for signing check

            if not smb.isSigningRequired():
                result.findings.append(
                    Finding(
                        title=f"SMB Signing Not Required on {target}",
                        severity=Severity.HIGH,
                        category=FindingCategory.PROTOCOL,
                        description=(
                            "SMB signing is not required on this host. Without SMB signing, "
                            "an attacker can perform SMB relay attacks to authenticate as "
                            "other users and execute commands."
                        ),
                        target=target,
                        remediation=(
                            "Enable and require SMB signing via Group Policy: "
                            "Computer Configuration > Windows Settings > Security Settings > "
                            "Local Policies > Security Options > "
                            "Microsoft network server: Digitally sign communications (always) = Enabled."
                        ),
                    )
                )
            smb.close()

        except Exception as e:
            logger.debug("SMB signing check failed on %s: %s", target, e)

    def _check_winrm(
        self, target: str, ports: list[PortResult], result: ModuleResult
    ) -> None:
        """Check WinRM configuration."""
        has_http = any(p.port == 5985 for p in ports)
        has_https = any(p.port == 5986 for p in ports)

        if has_http and not has_https:
            result.findings.append(
                Finding(
                    title=f"WinRM Over HTTP (Unencrypted) on {target}",
                    severity=Severity.MEDIUM,
                    category=FindingCategory.PROTOCOL,
                    description=(
                        "WinRM is accessible over HTTP (port 5985) without HTTPS. "
                        "While WinRM encrypts payloads by default, using HTTPS provides "
                        "additional transport-layer encryption."
                    ),
                    target=target,
                    remediation=(
                        "Configure WinRM to use HTTPS (port 5986) with a valid certificate. "
                        "Disable HTTP listener if not required."
                    ),
                )
            )
