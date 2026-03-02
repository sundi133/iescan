"""Microsoft SQL Server security assessment module.

Checks for misconfigurations, weak credentials, excessive privileges,
and dangerous stored procedures.
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

logger = logging.getLogger(__name__)

# Common default/weak MSSQL credentials
DEFAULT_CREDS = [
    ("sa", ""),
    ("sa", "sa"),
    ("sa", "password"),
    ("sa", "Password1"),
    ("sa", "1234"),
]

# Dangerous stored procedures
DANGEROUS_PROCS = [
    "xp_cmdshell",
    "xp_dirtree",
    "xp_fileexist",
    "xp_regread",
    "xp_regwrite",
    "xp_servicecontrol",
    "sp_OACreate",
    "sp_OAMethod",
]


class MSSQLAssessmentModule(BaseModule):
    """Assess Microsoft SQL Server for security misconfigurations."""

    name = "mssql_assessment"
    description = "Assess MSSQL for default credentials, dangerous procedures, and misconfigurations"

    def run(self, target: str, **kwargs: Any) -> ModuleResult:
        result = self._make_result(target)
        port = kwargs.get("port", 1433)

        try:
            import pymssql

            # Test provided credentials
            conn = self._connect(
                target,
                port,
                self.config.credentials.username,
                self.config.credentials.password,
            )

            if conn:
                self._assess_server(conn, target, result)
                conn.close()
            else:
                result.errors.append(
                    f"Could not connect to MSSQL on {target}:{port} with provided credentials"
                )

            # Check for default credentials
            if self.config.safe_mode:
                self._check_default_creds(target, port, result)

        except ImportError:
            result.errors.append("pymssql not available for MSSQL assessment")
            result.success = False

        return result

    def _connect(
        self, host: str, port: int, username: str, password: str
    ) -> Any | None:
        """Attempt MSSQL connection."""
        try:
            import pymssql

            conn = pymssql.connect(
                server=host,
                port=port,
                user=username,
                password=password,
                login_timeout=self.config.timeout,
            )
            return conn
        except Exception as e:
            logger.debug("MSSQL connection failed: %s", e)
            return None

    def _assess_server(self, conn: Any, target: str, result: ModuleResult) -> None:
        """Run security assessments on the MSSQL server."""
        cursor = conn.cursor()

        # Get server version
        self._check_version(cursor, target, result)

        # Check server configuration
        self._check_config(cursor, target, result)

        # Check dangerous stored procedures
        self._check_dangerous_procs(cursor, target, result)

        # Check for sysadmin users
        self._check_sysadmin_users(cursor, target, result)

        # Check linked servers
        self._check_linked_servers(cursor, target, result)

        # Check database permissions
        self._check_database_permissions(cursor, target, result)

        # Check for trustworthy databases
        self._check_trustworthy_dbs(cursor, target, result)

        cursor.close()

    def _check_version(self, cursor: Any, target: str, result: ModuleResult) -> None:
        """Check SQL Server version."""
        try:
            cursor.execute("SELECT @@VERSION")
            version = cursor.fetchone()[0]
            result.data["version"] = version

            result.findings.append(
                Finding(
                    title=f"SQL Server Version on {target}",
                    severity=Severity.INFO,
                    category=FindingCategory.DATABASE,
                    description=f"SQL Server version identified.",
                    target=target,
                    evidence=version,
                    remediation="Ensure this version is currently supported and patched.",
                )
            )
        except Exception as e:
            logger.debug("Version check failed: %s", e)

    def _check_config(self, cursor: Any, target: str, result: ModuleResult) -> None:
        """Check critical server configuration options."""
        try:
            cursor.execute(
                "SELECT name, CAST(value AS int) AS value, "
                "CAST(value_in_use AS int) AS value_in_use "
                "FROM sys.configurations "
                "WHERE name IN ("
                "'xp_cmdshell', 'Ole Automation Procedures', "
                "'clr enabled', 'cross db ownership chaining', "
                "'remote admin connections', 'Ad Hoc Distributed Queries')"
            )
            configs = cursor.fetchall()

            for name, value, value_in_use in configs:
                if value_in_use == 1:
                    severity = Severity.CRITICAL if name == "xp_cmdshell" else Severity.HIGH
                    result.findings.append(
                        Finding(
                            title=f"Dangerous Configuration Enabled: {name} on {target}",
                            severity=severity,
                            category=FindingCategory.DATABASE,
                            description=(
                                f"The '{name}' configuration option is enabled. "
                                "This can be abused for command execution or privilege escalation."
                            ),
                            target=target,
                            evidence=f"{name} = {value_in_use} (enabled)",
                            remediation=f"Disable '{name}' unless explicitly required: "
                            f"EXEC sp_configure '{name}', 0; RECONFIGURE;",
                        )
                    )

            result.data["configurations"] = [
                {"name": n, "value": v, "value_in_use": vu} for n, v, vu in configs
            ]
        except Exception as e:
            logger.debug("Config check failed: %s", e)

    def _check_dangerous_procs(
        self, cursor: Any, target: str, result: ModuleResult
    ) -> None:
        """Check for enabled dangerous stored procedures."""
        try:
            placeholders = ",".join(f"'{p}'" for p in DANGEROUS_PROCS)
            cursor.execute(
                f"SELECT name FROM sys.objects WHERE name IN ({placeholders}) AND type = 'X'"
            )
            procs = [row[0] for row in cursor.fetchall()]

            if procs:
                result.data["dangerous_procedures"] = procs
                result.findings.append(
                    Finding(
                        title=f"Dangerous Stored Procedures Available on {target}",
                        severity=Severity.HIGH,
                        category=FindingCategory.DATABASE,
                        description=(
                            f"Found {len(procs)} dangerous extended stored procedures "
                            "that could be used for OS command execution, file system "
                            "access, or registry manipulation."
                        ),
                        target=target,
                        evidence=f"Procedures: {', '.join(procs)}",
                        remediation=(
                            "Remove or restrict access to dangerous stored procedures. "
                            "Disable xp_cmdshell and Ole Automation Procedures."
                        ),
                    )
                )
        except Exception as e:
            logger.debug("Proc check failed: %s", e)

    def _check_sysadmin_users(
        self, cursor: Any, target: str, result: ModuleResult
    ) -> None:
        """Check for users with sysadmin privileges."""
        try:
            cursor.execute(
                "SELECT sp.name, sp.type_desc "
                "FROM sys.server_principals sp "
                "JOIN sys.server_role_members srm ON sp.principal_id = srm.member_principal_id "
                "JOIN sys.server_principals sr ON srm.role_principal_id = sr.principal_id "
                "WHERE sr.name = 'sysadmin' AND sp.name NOT IN ('sa', 'NT AUTHORITY\\SYSTEM')"
            )
            sysadmins = cursor.fetchall()

            if sysadmins:
                result.data["sysadmin_users"] = [
                    {"name": name, "type": type_desc} for name, type_desc in sysadmins
                ]
                result.findings.append(
                    Finding(
                        title=f"Multiple Sysadmin Accounts on {target}",
                        severity=Severity.MEDIUM,
                        category=FindingCategory.DATABASE,
                        description=(
                            f"Found {len(sysadmins)} non-default accounts with sysadmin privileges. "
                            "Excessive sysadmin access increases compromise risk."
                        ),
                        target=target,
                        evidence=(
                            "Sysadmin accounts: "
                            + ", ".join(f"{n} ({t})" for n, t in sysadmins)
                        ),
                        remediation=(
                            "Review sysadmin role membership. Use least-privilege principles "
                            "and grant specific permissions instead of sysadmin."
                        ),
                    )
                )
        except Exception as e:
            logger.debug("Sysadmin check failed: %s", e)

    def _check_linked_servers(
        self, cursor: Any, target: str, result: ModuleResult
    ) -> None:
        """Check for linked servers that could be used for lateral movement."""
        try:
            cursor.execute(
                "SELECT name, data_source, provider "
                "FROM sys.servers "
                "WHERE is_linked = 1"
            )
            linked = cursor.fetchall()

            if linked:
                result.data["linked_servers"] = [
                    {"name": n, "data_source": ds, "provider": p}
                    for n, ds, p in linked
                ]
                result.findings.append(
                    Finding(
                        title=f"Linked Servers Configured on {target}",
                        severity=Severity.HIGH,
                        category=FindingCategory.DATABASE,
                        description=(
                            f"Found {len(linked)} linked server(s). Linked servers can be "
                            "abused for lateral movement by executing queries on remote "
                            "servers using the linked server's credentials."
                        ),
                        target=target,
                        evidence="\n".join(
                            f"{n} -> {ds} ({p})" for n, ds, p in linked
                        ),
                        remediation=(
                            "Review linked server configurations and credentials. "
                            "Use least-privilege for linked server accounts. "
                            "Remove unused linked servers."
                        ),
                    )
                )
        except Exception as e:
            logger.debug("Linked server check failed: %s", e)

    def _check_database_permissions(
        self, cursor: Any, target: str, result: ModuleResult
    ) -> None:
        """Check for overly permissive database roles."""
        try:
            cursor.execute(
                "SELECT dp.name, dp.type_desc, drm.role_principal_id "
                "FROM sys.database_principals dp "
                "LEFT JOIN sys.database_role_members drm ON dp.principal_id = drm.member_principal_id "
                "WHERE dp.type IN ('S', 'U', 'G') "
                "AND dp.name NOT IN ('dbo', 'guest', 'INFORMATION_SCHEMA', 'sys')"
            )
            users = cursor.fetchall()
            result.data["database_users"] = len(users)
        except Exception as e:
            logger.debug("Permission check failed: %s", e)

    def _check_trustworthy_dbs(
        self, cursor: Any, target: str, result: ModuleResult
    ) -> None:
        """Check for databases with TRUSTWORTHY property enabled."""
        try:
            cursor.execute(
                "SELECT name FROM sys.databases "
                "WHERE is_trustworthy_on = 1 AND name != 'msdb'"
            )
            trustworthy = [row[0] for row in cursor.fetchall()]

            if trustworthy:
                result.findings.append(
                    Finding(
                        title=f"TRUSTWORTHY Databases Found on {target}",
                        severity=Severity.HIGH,
                        category=FindingCategory.DATABASE,
                        description=(
                            f"Found {len(trustworthy)} databases with TRUSTWORTHY enabled. "
                            "A db_owner of a TRUSTWORTHY database can escalate to sysadmin "
                            "privileges."
                        ),
                        target=target,
                        evidence=f"TRUSTWORTHY databases: {', '.join(trustworthy)}",
                        remediation=(
                            "Disable TRUSTWORTHY on databases unless explicitly required: "
                            "ALTER DATABASE [dbname] SET TRUSTWORTHY OFF;"
                        ),
                    )
                )
        except Exception as e:
            logger.debug("Trustworthy check failed: %s", e)

    def _check_default_creds(
        self, target: str, port: int, result: ModuleResult
    ) -> None:
        """Check for default/weak credentials (safe mode only)."""
        for username, password in DEFAULT_CREDS:
            conn = self._connect(target, port, username, password)
            if conn:
                severity = (
                    Severity.CRITICAL if not password else Severity.CRITICAL
                )
                result.findings.append(
                    Finding(
                        title=f"Default/Weak Credentials on MSSQL {target}",
                        severity=severity,
                        category=FindingCategory.DEFAULT_CRED,
                        description=(
                            f"Successfully authenticated to MSSQL with default/weak "
                            f"credentials ({username}/{('*' * len(password)) if password else 'blank'})."
                        ),
                        target=target,
                        remediation=(
                            "Change all default passwords immediately. "
                            "Disable the 'sa' account if not needed. "
                            "Implement a strong password policy."
                        ),
                    )
                )
                conn.close()
                break  # Stop after first success
