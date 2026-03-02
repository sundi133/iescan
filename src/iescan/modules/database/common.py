"""Common database security assessment utilities.

Shared assessment functions for MySQL, PostgreSQL, and other databases.
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

# Default credentials for various databases
MYSQL_DEFAULT_CREDS = [
    ("root", ""),
    ("root", "root"),
    ("root", "password"),
    ("root", "mysql"),
    ("admin", "admin"),
]

POSTGRES_DEFAULT_CREDS = [
    ("postgres", ""),
    ("postgres", "postgres"),
    ("postgres", "password"),
    ("admin", "admin"),
]


class MySQLAssessmentModule(BaseModule):
    """Assess MySQL/MariaDB for security misconfigurations."""

    name = "mysql_assessment"
    description = "Assess MySQL for default credentials, permissions, and misconfigurations"

    def run(self, target: str, **kwargs: Any) -> ModuleResult:
        result = self._make_result(target)
        port = kwargs.get("port", 3306)

        try:
            import pymysql

            # Test provided credentials
            conn = self._connect(
                target, port,
                self.config.credentials.username,
                self.config.credentials.password,
            )

            if conn:
                self._assess_server(conn, target, result)
                conn.close()

            # Check default credentials
            if self.config.safe_mode:
                self._check_default_creds(target, port, result)

        except ImportError:
            result.errors.append("pymysql not available for MySQL assessment")
            result.success = False

        return result

    def _connect(self, host: str, port: int, user: str, password: str) -> Any | None:
        try:
            import pymysql
            return pymysql.connect(
                host=host, port=port, user=user, password=password,
                connect_timeout=self.config.timeout,
            )
        except Exception:
            return None

    def _assess_server(self, conn: Any, target: str, result: ModuleResult) -> None:
        cursor = conn.cursor()

        # Check version
        try:
            cursor.execute("SELECT VERSION()")
            version = cursor.fetchone()[0]
            result.data["version"] = version
        except Exception:
            pass

        # Check for anonymous users
        try:
            cursor.execute("SELECT user, host FROM mysql.user WHERE user = ''")
            anon = cursor.fetchall()
            if anon:
                result.findings.append(
                    Finding(
                        title=f"Anonymous MySQL Users on {target}",
                        severity=Severity.HIGH,
                        category=FindingCategory.DATABASE,
                        description="Anonymous user accounts exist allowing unauthenticated access.",
                        target=target,
                        remediation="Remove anonymous users: DROP USER ''@'localhost';",
                    )
                )
        except Exception:
            pass

        # Check for users without passwords
        try:
            cursor.execute(
                "SELECT user, host FROM mysql.user "
                "WHERE authentication_string = '' OR authentication_string IS NULL"
            )
            no_pwd = cursor.fetchall()
            if no_pwd:
                result.findings.append(
                    Finding(
                        title=f"MySQL Users Without Passwords on {target}",
                        severity=Severity.CRITICAL,
                        category=FindingCategory.DEFAULT_CRED,
                        description=(
                            f"Found {len(no_pwd)} user(s) without passwords set."
                        ),
                        target=target,
                        evidence=", ".join(f"'{u}'@'{h}'" for u, h in no_pwd),
                        remediation="Set strong passwords for all MySQL users.",
                    )
                )
        except Exception:
            pass

        # Check for wildcard host grants
        try:
            cursor.execute(
                "SELECT user, host FROM mysql.user WHERE host = '%'"
            )
            wildcard = cursor.fetchall()
            if wildcard:
                result.findings.append(
                    Finding(
                        title=f"MySQL Users With Wildcard Host Access on {target}",
                        severity=Severity.MEDIUM,
                        category=FindingCategory.DATABASE,
                        description=(
                            f"Found {len(wildcard)} user(s) accessible from any host (%)."
                        ),
                        target=target,
                        evidence=", ".join(f"'{u}'@'%'" for u, h in wildcard),
                        remediation="Restrict host access to specific IPs or networks.",
                    )
                )
        except Exception:
            pass

        # Check SSL/TLS
        try:
            cursor.execute("SHOW VARIABLES LIKE 'have_ssl'")
            ssl_row = cursor.fetchone()
            if ssl_row and ssl_row[1].upper() == "DISABLED":
                result.findings.append(
                    Finding(
                        title=f"MySQL SSL Disabled on {target}",
                        severity=Severity.MEDIUM,
                        category=FindingCategory.DATABASE,
                        description="SSL/TLS is disabled. Database connections are unencrypted.",
                        target=target,
                        remediation="Enable SSL/TLS for MySQL connections.",
                    )
                )
        except Exception:
            pass

        cursor.close()

    def _check_default_creds(
        self, target: str, port: int, result: ModuleResult
    ) -> None:
        for user, pwd in MYSQL_DEFAULT_CREDS:
            conn = self._connect(target, port, user, pwd)
            if conn:
                result.findings.append(
                    Finding(
                        title=f"Default Credentials on MySQL {target}",
                        severity=Severity.CRITICAL,
                        category=FindingCategory.DEFAULT_CRED,
                        description=f"MySQL accessible with default credentials ({user}).",
                        target=target,
                        remediation="Change all default passwords immediately.",
                    )
                )
                conn.close()
                break


class PostgreSQLAssessmentModule(BaseModule):
    """Assess PostgreSQL for security misconfigurations."""

    name = "postgresql_assessment"
    description = "Assess PostgreSQL for default credentials, permissions, and misconfigurations"

    def run(self, target: str, **kwargs: Any) -> ModuleResult:
        result = self._make_result(target)
        port = kwargs.get("port", 5432)

        try:
            import psycopg2

            conn = self._connect(
                target, port,
                self.config.credentials.username,
                self.config.credentials.password,
            )

            if conn:
                self._assess_server(conn, target, result)
                conn.close()

            if self.config.safe_mode:
                self._check_default_creds(target, port, result)

        except ImportError:
            result.errors.append("psycopg2 not available for PostgreSQL assessment")
            result.success = False

        return result

    def _connect(self, host: str, port: int, user: str, password: str) -> Any | None:
        try:
            import psycopg2
            return psycopg2.connect(
                host=host, port=port, user=user, password=password,
                connect_timeout=self.config.timeout,
            )
        except Exception:
            return None

    def _assess_server(self, conn: Any, target: str, result: ModuleResult) -> None:
        conn.autocommit = True
        cursor = conn.cursor()

        # Check version
        try:
            cursor.execute("SELECT version()")
            version = cursor.fetchone()[0]
            result.data["version"] = version
        except Exception:
            pass

        # Check for superuser roles
        try:
            cursor.execute(
                "SELECT rolname FROM pg_roles WHERE rolsuper = true "
                "AND rolname NOT IN ('postgres')"
            )
            superusers = [row[0] for row in cursor.fetchall()]
            if superusers:
                result.findings.append(
                    Finding(
                        title=f"Non-Default Superuser Roles on PostgreSQL {target}",
                        severity=Severity.MEDIUM,
                        category=FindingCategory.DATABASE,
                        description=f"Found {len(superusers)} non-default superuser roles.",
                        target=target,
                        evidence=f"Superusers: {', '.join(superusers)}",
                        remediation="Review superuser privileges. Use least-privilege roles.",
                    )
                )
        except Exception:
            pass

        # Check pg_hba.conf trust entries (if accessible)
        try:
            cursor.execute(
                "SELECT type, database, user_name, address, auth_method "
                "FROM pg_hba_file_rules WHERE auth_method = 'trust'"
            )
            trust_entries = cursor.fetchall()
            if trust_entries:
                result.findings.append(
                    Finding(
                        title=f"PostgreSQL Trust Authentication Configured on {target}",
                        severity=Severity.CRITICAL,
                        category=FindingCategory.DATABASE,
                        description=(
                            "pg_hba.conf contains 'trust' authentication entries that "
                            "allow passwordless connections."
                        ),
                        target=target,
                        evidence="\n".join(str(e) for e in trust_entries),
                        remediation="Replace 'trust' with 'scram-sha-256' or 'md5'.",
                    )
                )
        except Exception:
            pass

        # Check SSL
        try:
            cursor.execute("SHOW ssl")
            ssl_status = cursor.fetchone()[0]
            if ssl_status.lower() == "off":
                result.findings.append(
                    Finding(
                        title=f"PostgreSQL SSL Disabled on {target}",
                        severity=Severity.MEDIUM,
                        category=FindingCategory.DATABASE,
                        description="SSL is disabled for PostgreSQL connections.",
                        target=target,
                        remediation="Enable ssl in postgresql.conf and configure certificates.",
                    )
                )
        except Exception:
            pass

        cursor.close()

    def _check_default_creds(
        self, target: str, port: int, result: ModuleResult
    ) -> None:
        for user, pwd in POSTGRES_DEFAULT_CREDS:
            conn = self._connect(target, port, user, pwd)
            if conn:
                result.findings.append(
                    Finding(
                        title=f"Default Credentials on PostgreSQL {target}",
                        severity=Severity.CRITICAL,
                        category=FindingCategory.DEFAULT_CRED,
                        description=f"PostgreSQL accessible with default credentials ({user}).",
                        target=target,
                        remediation="Change all default passwords immediately.",
                    )
                )
                conn.close()
                break
