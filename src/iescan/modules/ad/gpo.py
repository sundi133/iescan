"""Group Policy Object (GPO) security assessment module.

Identifies GPO misconfigurations, privilege escalation via GPO abuse,
and insecure policy settings.
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


class GPOAssessmentModule(BaseModule):
    """Assess Group Policy Objects for security misconfigurations and abuse vectors."""

    name = "gpo_assessment"
    description = "Assess GPO configurations for abuse vectors and insecure settings"

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

            # Enumerate all GPOs
            gpos = self._enumerate_gpos(conn, base_dn, result)
            result.data["gpo_count"] = len(gpos)

            # Check for GPOs with weak permissions
            self._check_gpo_permissions(conn, base_dn, gpos, result)

            # Check for GPOs with stored credentials (cpassword)
            self._check_gpo_credentials(conn, base_dn, result)

            # Check password policy GPOs
            self._check_password_policies(conn, base_dn, result)

            # Check for GPOs linked to privileged OUs
            self._check_privileged_ou_gpos(conn, base_dn, result)

            # Check for unlinked GPOs
            self._check_unlinked_gpos(conn, base_dn, gpos, result)

        finally:
            conn.unbind()

        return result

    def _enumerate_gpos(
        self, conn: Any, base_dn: str, result: ModuleResult
    ) -> list[dict[str, Any]]:
        """Enumerate all Group Policy Objects in the domain."""
        gpo_objects = ldap_search(
            conn,
            base_dn,
            "(objectClass=groupPolicyContainer)",
            [
                "displayName",
                "gPCFileSysPath",
                "flags",
                "whenCreated",
                "whenChanged",
                "versionNumber",
            ],
        )

        gpos = []
        for gpo in gpo_objects:
            gpos.append(
                {
                    "dn": gpo.dn,
                    "name": gpo.attributes.get("displayName", ""),
                    "path": gpo.attributes.get("gPCFileSysPath", ""),
                    "flags": gpo.attributes.get("flags", ""),
                    "created": gpo.attributes.get("whenCreated", ""),
                    "modified": gpo.attributes.get("whenChanged", ""),
                    "version": gpo.attributes.get("versionNumber", ""),
                }
            )

        return gpos

    def _check_gpo_permissions(
        self,
        conn: Any,
        base_dn: str,
        gpos: list[dict[str, Any]],
        result: ModuleResult,
    ) -> None:
        """Check for GPOs with overly permissive ACLs that allow modification by non-admins."""
        # This is a simplified check - full ACL analysis requires DACL parsing
        # We check if low-privilege groups can edit GPOs
        for gpo in gpos:
            gpo_dn = gpo["dn"]
            # Search for GPOs where 'Authenticated Users' or 'Domain Users' has
            # write access - requires nTSecurityDescriptor analysis
            # For now, flag GPOs for manual ACL review
            pass

        result.findings.append(
            Finding(
                title="GPO Permission Audit Required",
                severity=Severity.INFO,
                category=FindingCategory.GPO_ABUSE,
                description=(
                    f"Found {len(gpos)} GPOs in the domain. GPO permissions should be "
                    "reviewed to ensure that non-privileged users cannot modify policies "
                    "that apply to privileged users or computers."
                ),
                target=result.target,
                evidence=f"Total GPOs: {len(gpos)}",
                remediation=(
                    "Review GPO ACLs using tools like BloodHound or Get-GPPermission. "
                    "Ensure only authorized administrators can edit GPOs, especially those "
                    "linked to Domain Controllers or admin OUs."
                ),
            )
        )

    def _check_gpo_credentials(
        self, conn: Any, base_dn: str, result: ModuleResult
    ) -> None:
        """Check for GPO Preferences that may contain stored credentials (MS14-025)."""
        # GPP passwords are stored in cpassword fields in SYSVOL XML files
        # We flag this as a common finding to check
        result.findings.append(
            Finding(
                title="Check for Group Policy Preferences Passwords (MS14-025)",
                severity=Severity.HIGH,
                category=FindingCategory.GPO_ABUSE,
                description=(
                    "Group Policy Preferences (GPP) historically allowed storing encrypted "
                    "passwords in SYSVOL XML files. The encryption key was publicly disclosed "
                    "(MS14-025), making these passwords trivially recoverable. "
                    "SYSVOL should be checked for Groups.xml, Services.xml, DataSources.xml, "
                    "ScheduledTasks.xml, and Drives.xml containing cpassword fields."
                ),
                target=result.target,
                evidence="Requires SYSVOL file system access to verify",
                remediation=(
                    "Search SYSVOL for XML files containing 'cpassword'. "
                    "Remove any GPP with stored passwords. Rotate all affected credentials. "
                    "Apply KB2962486 to prevent future use."
                ),
                cve_ids=["CVE-2014-1812"],
            )
        )

    def _check_password_policies(
        self, conn: Any, base_dn: str, result: ModuleResult
    ) -> None:
        """Check domain password policy settings."""
        domain_policy = ldap_search(
            conn,
            base_dn,
            f"(distinguishedName={base_dn})",
            [
                "minPwdLength",
                "maxPwdAge",
                "minPwdAge",
                "pwdHistoryLength",
                "lockoutThreshold",
                "lockoutDuration",
                "lockOutObservationWindow",
                "pwdProperties",
            ],
        )

        if domain_policy:
            attrs = domain_policy[0].attributes
            min_pwd_len = int(attrs.get("minPwdLength", "0") or "0")
            lockout_threshold = int(attrs.get("lockoutThreshold", "0") or "0")
            pwd_history = int(attrs.get("pwdHistoryLength", "0") or "0")
            pwd_properties = int(attrs.get("pwdProperties", "0") or "0")

            policy_data = {
                "min_password_length": min_pwd_len,
                "lockout_threshold": lockout_threshold,
                "password_history": pwd_history,
                "complexity_enabled": bool(pwd_properties & 1),
            }
            result.data["password_policy"] = policy_data

            if min_pwd_len < 12:
                result.findings.append(
                    Finding(
                        title="Weak Minimum Password Length",
                        severity=Severity.HIGH,
                        category=FindingCategory.AD_MISCONFIG,
                        description=(
                            f"Domain minimum password length is {min_pwd_len} characters. "
                            "Passwords shorter than 12 characters are susceptible to "
                            "brute-force and dictionary attacks."
                        ),
                        target=result.target,
                        evidence=f"Minimum password length: {min_pwd_len}",
                        remediation=(
                            "Increase minimum password length to at least 14 characters. "
                            "Consider implementing a banned password list."
                        ),
                    )
                )

            if lockout_threshold == 0:
                result.findings.append(
                    Finding(
                        title="No Account Lockout Policy",
                        severity=Severity.HIGH,
                        category=FindingCategory.AD_MISCONFIG,
                        description=(
                            "No account lockout threshold is configured, allowing unlimited "
                            "password guessing attempts against domain accounts."
                        ),
                        target=result.target,
                        remediation=(
                            "Configure account lockout threshold (5-10 attempts recommended). "
                            "Also configure lockout duration and observation window."
                        ),
                    )
                )

            if not (pwd_properties & 1):
                result.findings.append(
                    Finding(
                        title="Password Complexity Not Enforced",
                        severity=Severity.MEDIUM,
                        category=FindingCategory.AD_MISCONFIG,
                        description=(
                            "Password complexity requirements are not enabled in the "
                            "domain password policy."
                        ),
                        target=result.target,
                        remediation=(
                            "Enable password complexity requirements. Consider using "
                            "fine-grained password policies for different user tiers."
                        ),
                    )
                )

    def _check_privileged_ou_gpos(
        self, conn: Any, base_dn: str, result: ModuleResult
    ) -> None:
        """Check for GPOs linked to OUs containing privileged accounts."""
        # Check Domain Controllers OU GPOs
        dc_ou = f"OU=Domain Controllers,{base_dn}"
        dc_ou_result = ldap_search(
            conn,
            dc_ou,
            "(objectClass=organizationalUnit)",
            ["gPLink", "gPOptions"],
        )

        if dc_ou_result:
            gp_link = dc_ou_result[0].attributes.get("gPLink", "")
            if gp_link:
                result.data["dc_ou_gpo_links"] = gp_link

    def _check_unlinked_gpos(
        self,
        conn: Any,
        base_dn: str,
        gpos: list[dict[str, Any]],
        result: ModuleResult,
    ) -> None:
        """Check for unlinked GPOs (disabled or not linked to any OU)."""
        unlinked = []
        for gpo in gpos:
            flags = str(gpo.get("flags", "0"))
            # GPO flags: 0=enabled, 1=user disabled, 2=computer disabled, 3=all disabled
            if flags == "3":
                unlinked.append(gpo)

        if unlinked:
            result.findings.append(
                Finding(
                    title="Disabled Group Policy Objects Found",
                    severity=Severity.LOW,
                    category=FindingCategory.GPO_ABUSE,
                    description=(
                        f"Found {len(unlinked)} disabled GPOs. Disabled GPOs may contain "
                        "outdated or insecure settings. If re-enabled accidentally, they "
                        "could weaken security posture."
                    ),
                    target=result.target,
                    evidence=(
                        "Disabled GPOs: "
                        + ", ".join(g["name"] for g in unlinked)
                    ),
                    remediation=(
                        "Review and delete GPOs that are no longer needed. "
                        "Document the purpose of disabled GPOs that must be retained."
                    ),
                )
            )

        result.data["disabled_gpos"] = len(unlinked)
