"""Kerberos security assessment module.

Tests for Kerberoasting, AS-REP Roasting, delegation abuse,
and other Kerberos-related vulnerabilities.
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
from iescan.utils.ldap import LDAPConfig, build_base_dn, create_connection, ldap_search

logger = logging.getLogger(__name__)


class KerberosAssessmentModule(BaseModule):
    """Assess Kerberos configuration and identify attack vectors."""

    name = "kerberos_assessment"
    description = "Assess Kerberos configuration for Kerberoasting, delegation abuse, and misconfigurations"

    def run(self, target: str, **kwargs: Any) -> ModuleResult:
        result = self._make_result(target)

        ldap_config = LDAPConfig(
            server=target,
            domain=self.config.credentials.domain,
            username=self.config.credentials.username,
            password=self.config.credentials.password,
            base_dn=build_base_dn(self.config.credentials.domain),
        )

        conn = create_connection(ldap_config)
        if not conn:
            result.errors.append(f"Failed to connect to LDAP on {target}")
            result.success = False
            return result

        try:
            base_dn = ldap_config.base_dn

            # Check for weak Kerberos encryption types
            self._check_encryption_types(conn, base_dn, result)

            # Check for constrained delegation misconfigs
            self._check_constrained_delegation(conn, base_dn, result)

            # Check for resource-based constrained delegation
            self._check_rbcd(conn, base_dn, result)

            # Check for accounts with S4U delegation
            self._check_s4u_delegation(conn, base_dn, result)

            # Check for krbtgt account password age
            self._check_krbtgt(conn, base_dn, result)

        finally:
            conn.unbind()

        return result

    def _check_encryption_types(
        self, conn: Any, base_dn: str, result: ModuleResult
    ) -> None:
        """Check for accounts using weak Kerberos encryption (DES/RC4)."""
        # UAC flag 0x200000 = USE_DES_KEY_ONLY
        des_accounts = ldap_search(
            conn,
            base_dn,
            "(&(objectCategory=person)(objectClass=user)"
            "(userAccountControl:1.2.840.113556.1.4.803:=2097152))",
            ["sAMAccountName"],
        )

        if des_accounts:
            result.findings.append(
                Finding(
                    title="Accounts Using Weak DES Kerberos Encryption",
                    severity=Severity.HIGH,
                    category=FindingCategory.KERBEROS,
                    description=(
                        f"Found {len(des_accounts)} accounts configured to use DES encryption "
                        "for Kerberos. DES is cryptographically broken and can be cracked trivially."
                    ),
                    target=result.target,
                    evidence=(
                        "DES-only accounts: "
                        + ", ".join(
                            a.attributes.get("sAMAccountName", "") for a in des_accounts
                        )
                    ),
                    remediation=(
                        "Migrate all accounts to AES256 Kerberos encryption. "
                        "Remove the USE_DES_KEY_ONLY flag from all accounts."
                    ),
                )
            )

        # Check msDS-SupportedEncryptionTypes for RC4-only
        rc4_accounts = ldap_search(
            conn,
            base_dn,
            "(&(objectCategory=person)(objectClass=user)"
            "(msDS-SupportedEncryptionTypes=4))",  # RC4_HMAC_MD5 only
            ["sAMAccountName", "msDS-SupportedEncryptionTypes"],
        )

        if rc4_accounts:
            result.findings.append(
                Finding(
                    title="Accounts Limited to RC4 Kerberos Encryption",
                    severity=Severity.MEDIUM,
                    category=FindingCategory.KERBEROS,
                    description=(
                        f"Found {len(rc4_accounts)} accounts using only RC4 encryption for "
                        "Kerberos. RC4 tickets are easier to crack via Kerberoasting."
                    ),
                    target=result.target,
                    remediation=(
                        "Configure accounts to support AES256 encryption. "
                        "Update msDS-SupportedEncryptionTypes to include AES."
                    ),
                )
            )

    def _check_constrained_delegation(
        self, conn: Any, base_dn: str, result: ModuleResult
    ) -> None:
        """Check for constrained delegation configurations that could be abused."""
        constrained = ldap_search(
            conn,
            base_dn,
            "(&(objectClass=*)(msDS-AllowedToDelegateTo=*))",
            [
                "sAMAccountName",
                "objectClass",
                "msDS-AllowedToDelegateTo",
                "userAccountControl",
            ],
        )

        delegation_data = []
        for obj in constrained:
            targets = obj.attributes.get("msDS-AllowedToDelegateTo", [])
            if isinstance(targets, str):
                targets = [targets]
            delegation_data.append(
                {
                    "account": obj.attributes.get("sAMAccountName", ""),
                    "delegation_targets": targets,
                }
            )

        if delegation_data:
            # Check for sensitive delegation targets (LDAP, CIFS on DCs)
            sensitive_delegations = []
            for d in delegation_data:
                for svc_target in d["delegation_targets"]:
                    svc_lower = svc_target.lower()
                    if any(
                        svc in svc_lower
                        for svc in ["ldap/", "cifs/", "krbtgt/", "http/"]
                    ):
                        sensitive_delegations.append(d)
                        break

            if sensitive_delegations:
                result.findings.append(
                    Finding(
                        title="Constrained Delegation to Sensitive Services",
                        severity=Severity.HIGH,
                        category=FindingCategory.KERBEROS,
                        description=(
                            f"Found {len(sensitive_delegations)} accounts with constrained "
                            "delegation configured to sensitive services (LDAP, CIFS). "
                            "Compromising these accounts could allow lateral movement "
                            "or privilege escalation via S4U2Proxy."
                        ),
                        target=result.target,
                        evidence="\n".join(
                            f"{d['account']}: {', '.join(d['delegation_targets'])}"
                            for d in sensitive_delegations
                        ),
                        remediation=(
                            "Review constrained delegation configurations. "
                            "Minimize delegation targets and avoid delegating to sensitive "
                            "services on Domain Controllers."
                        ),
                    )
                )

        result.data["constrained_delegation"] = delegation_data

    def _check_rbcd(self, conn: Any, base_dn: str, result: ModuleResult) -> None:
        """Check for Resource-Based Constrained Delegation configurations."""
        rbcd = ldap_search(
            conn,
            base_dn,
            "(&(objectClass=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))",
            ["sAMAccountName", "msDS-AllowedToActOnBehalfOfOtherIdentity"],
        )

        if rbcd:
            result.findings.append(
                Finding(
                    title="Resource-Based Constrained Delegation Configured",
                    severity=Severity.INFO,
                    category=FindingCategory.KERBEROS,
                    description=(
                        f"Found {len(rbcd)} objects with Resource-Based Constrained Delegation "
                        "configured. While RBCD is a valid delegation mechanism, misconfigured "
                        "RBCD can be abused for privilege escalation."
                    ),
                    target=result.target,
                    evidence=(
                        "RBCD objects: "
                        + ", ".join(
                            r.attributes.get("sAMAccountName", "") for r in rbcd
                        )
                    ),
                    remediation=(
                        "Audit RBCD configurations regularly. Ensure only authorized "
                        "principals are listed in msDS-AllowedToActOnBehalfOfOtherIdentity."
                    ),
                )
            )

        result.data["rbcd_objects"] = len(rbcd)

    def _check_s4u_delegation(
        self, conn: Any, base_dn: str, result: ModuleResult
    ) -> None:
        """Check for accounts that can use S4U2Self (protocol transition)."""
        # TRUSTED_TO_AUTH_FOR_DELEGATION flag
        s4u = ldap_search(
            conn,
            base_dn,
            "(&(objectClass=*)"
            "(userAccountControl:1.2.840.113556.1.4.803:=16777216))",
            ["sAMAccountName", "msDS-AllowedToDelegateTo"],
        )

        if s4u:
            result.findings.append(
                Finding(
                    title="Accounts with Protocol Transition (S4U2Self) Enabled",
                    severity=Severity.HIGH,
                    category=FindingCategory.KERBEROS,
                    description=(
                        f"Found {len(s4u)} accounts with protocol transition enabled. "
                        "These accounts can obtain service tickets on behalf of any user "
                        "via S4U2Self, which combined with constrained delegation allows "
                        "impersonation of any user to the delegated services."
                    ),
                    target=result.target,
                    evidence=(
                        "Protocol transition accounts: "
                        + ", ".join(
                            a.attributes.get("sAMAccountName", "") for a in s4u
                        )
                    ),
                    remediation=(
                        "Review necessity of protocol transition. Consider using "
                        "Resource-Based Constrained Delegation as an alternative. "
                        "Mark sensitive accounts as 'Account is sensitive and cannot be delegated'."
                    ),
                )
            )

    def _check_krbtgt(self, conn: Any, base_dn: str, result: ModuleResult) -> None:
        """Check the krbtgt account password age."""
        krbtgt = ldap_search(
            conn,
            base_dn,
            "(&(objectClass=user)(sAMAccountName=krbtgt))",
            ["pwdLastSet", "whenChanged"],
        )

        if krbtgt:
            pwd_last_set = krbtgt[0].attributes.get("pwdLastSet", "")
            result.data["krbtgt_pwd_last_set"] = pwd_last_set

            result.findings.append(
                Finding(
                    title="KRBTGT Account Password Review",
                    severity=Severity.INFO,
                    category=FindingCategory.KERBEROS,
                    description=(
                        "The krbtgt account password should be rotated at least annually "
                        "and after any suspected compromise. Compromise of this account "
                        "allows Golden Ticket attacks."
                    ),
                    target=result.target,
                    evidence=f"krbtgt password last set: {pwd_last_set}",
                    remediation=(
                        "Rotate the krbtgt password twice (with a delay between rotations "
                        "to allow replication). Schedule regular krbtgt rotations."
                    ),
                )
            )
