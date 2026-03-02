"""Network discovery and host enumeration module.

Discovers live hosts, identifies services, and maps the internal network.
"""

from __future__ import annotations

import logging
from typing import Any

from iescan.config import ScanConfig
from iescan.core.scanner import (
    BaseModule,
    Finding,
    FindingCategory,
    ModuleResult,
    Severity,
)
from iescan.utils.network import (
    AD_PORTS,
    DB_PORTS,
    WEB_PORTS,
    HostInfo,
    PortResult,
    discover_live_hosts,
    reverse_lookup,
    tcp_connect_scan,
)

logger = logging.getLogger(__name__)


class NetworkDiscoveryModule(BaseModule):
    """Discover live hosts and services on the internal network."""

    name = "network_discovery"
    description = "Discover live hosts, open ports, and running services"

    def run(self, target: str, **kwargs: Any) -> ModuleResult:
        result = self._make_result(target)

        # Discover live hosts
        logger.info("Discovering live hosts in %s", target)
        live_hosts = discover_live_hosts(
            [target],
            timeout=self.config.timeout,
            threads=self.config.threads,
        )

        result.data["live_hosts"] = live_hosts
        result.data["host_count"] = len(live_hosts)

        hosts_info: list[dict[str, Any]] = []

        for host_ip in live_hosts:
            logger.info("Scanning ports on %s", host_ip)
            hostname = reverse_lookup(host_ip) or ""

            open_ports = tcp_connect_scan(
                host_ip,
                timeout=self.config.timeout,
                threads=self.config.threads,
            )

            host_data: dict[str, Any] = {
                "ip": host_ip,
                "hostname": hostname,
                "open_ports": [
                    {
                        "port": p.port,
                        "service": p.service,
                        "banner": p.banner,
                        "state": p.state,
                    }
                    for p in open_ports
                ],
                "roles": self._identify_roles(open_ports),
            }
            hosts_info.append(host_data)

            # Check for security findings
            self._check_insecure_services(host_ip, hostname, open_ports, result)

        result.data["hosts"] = hosts_info
        return result

    def _identify_roles(self, ports: list[PortResult]) -> list[str]:
        """Identify probable server roles based on open ports."""
        open_port_nums = {p.port for p in ports}
        roles = []

        ad_overlap = open_port_nums & set(AD_PORTS)
        if len(ad_overlap) >= 3:
            roles.append("Domain Controller")

        if open_port_nums & set(DB_PORTS):
            db_services = []
            if 1433 in open_port_nums:
                db_services.append("MSSQL")
            if 1521 in open_port_nums:
                db_services.append("Oracle")
            if 3306 in open_port_nums:
                db_services.append("MySQL")
            if 5432 in open_port_nums:
                db_services.append("PostgreSQL")
            roles.append(f"Database ({', '.join(db_services)})")

        if open_port_nums & set(WEB_PORTS):
            roles.append("Web Server")

        if 445 in open_port_nums or 139 in open_port_nums:
            if "Domain Controller" not in roles:
                roles.append("File Server")

        if 3389 in open_port_nums:
            roles.append("RDP Enabled")

        if 5985 in open_port_nums or 5986 in open_port_nums:
            roles.append("WinRM Enabled")

        if 22 in open_port_nums:
            roles.append("SSH")

        return roles

    def _check_insecure_services(
        self,
        ip: str,
        hostname: str,
        ports: list[PortResult],
        result: ModuleResult,
    ) -> None:
        """Check for insecure services and protocols."""
        host_label = f"{ip} ({hostname})" if hostname else ip
        open_port_nums = {p.port for p in ports}

        # Check for Telnet
        if 23 in open_port_nums:
            result.findings.append(
                Finding(
                    title=f"Telnet Service Exposed on {host_label}",
                    severity=Severity.HIGH,
                    category=FindingCategory.PROTOCOL,
                    description=(
                        "Telnet transmits credentials and data in cleartext. "
                        "An attacker with network access can intercept authentication."
                    ),
                    target=ip,
                    remediation="Disable Telnet and use SSH instead.",
                )
            )

        # Check for FTP
        if 21 in open_port_nums:
            result.findings.append(
                Finding(
                    title=f"FTP Service Exposed on {host_label}",
                    severity=Severity.MEDIUM,
                    category=FindingCategory.PROTOCOL,
                    description=(
                        "FTP transmits credentials in cleartext. "
                        "Consider using SFTP or FTPS instead."
                    ),
                    target=ip,
                    remediation="Replace FTP with SFTP or FTPS. Disable anonymous access.",
                )
            )

        # Check for unencrypted LDAP
        if 389 in open_port_nums and 636 not in open_port_nums:
            result.findings.append(
                Finding(
                    title=f"Unencrypted LDAP Without LDAPS on {host_label}",
                    severity=Severity.MEDIUM,
                    category=FindingCategory.PROTOCOL,
                    description=(
                        "LDAP (port 389) is exposed without LDAPS (port 636). "
                        "LDAP simple bind sends credentials in cleartext."
                    ),
                    target=ip,
                    remediation=(
                        "Enable LDAPS and enforce channel binding. "
                        "Configure LDAP signing requirements."
                    ),
                )
            )

        # Check for RDP
        if 3389 in open_port_nums:
            result.findings.append(
                Finding(
                    title=f"RDP Service Exposed on {host_label}",
                    severity=Severity.INFO,
                    category=FindingCategory.NETWORK,
                    description=(
                        "Remote Desktop Protocol is accessible. Ensure NLA is enabled "
                        "and access is restricted to authorized users."
                    ),
                    target=ip,
                    remediation=(
                        "Enable Network Level Authentication (NLA). "
                        "Restrict RDP access via firewall rules and use a VPN or jump server."
                    ),
                )
            )
