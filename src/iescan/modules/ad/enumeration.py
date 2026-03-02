"""Active Directory enumeration module.

Enumerates users, groups, computers, OUs, and domain configuration
to identify security weaknesses.
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
from iescan.utils.ldap import (
    ADObject,
    LDAPConfig,
    build_base_dn,
    create_connection,
    get_domain_info,
    ldap_search,
)

logger = logging.getLogger(__name__)


class ADEnumerationModule(BaseModule):
    """Enumerate Active Directory objects and identify misconfigurations."""

    name = "ad_enumeration"
    description = "Enumerate AD users, groups, computers, and identify misconfigurations"

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

            # Get domain info
            domain_info = get_domain_info(conn)
            result.data["domain_info"] = domain_info

            # Enumerate domain admins
            result.data["domain_admins"] = self._enum_domain_admins(conn, base_dn, result)

            # Find users with SPN (Kerberoastable)
            result.data["spn_users"] = self._enum_spn_users(conn, base_dn, result)

            # Find users that don't require pre-authentication (AS-REP roastable)
            result.data["asrep_users"] = self._enum_asrep_users(conn, base_dn, result)

            # Find users with password never expires
            result.data["pwd_never_expires"] = self._enum_pwd_never_expires(
                conn, base_dn, result
            )

            # Find disabled accounts with group memberships
            result.data["disabled_with_groups"] = self._enum_disabled_with_groups(
                conn, base_dn, result
            )

            # Find computers with unconstrained delegation
            result.data["unconstrained_delegation"] = self._enum_unconstrained_delegation(
                conn, base_dn, result
            )

            # Enumerate adminSDHolder protected accounts
            result.data["adminsdholder"] = self._enum_adminsdholder(conn, base_dn, result)

            # Find stale computer accounts
            result.data["stale_computers"] = self._enum_stale_computers(conn, base_dn, result)

        finally:
            conn.unbind()

        return result

    def _enum_domain_admins(
        self, conn: Any, base_dn: str, result: ModuleResult
    ) -> list[dict[str, Any]]:
        """Enumerate Domain Admins group members."""
        admins = ldap_search(
            conn,
            base_dn,
            "(&(objectCategory=person)(objectClass=user)(memberOf=CN=Domain Admins,CN=Users,"
            f"{base_dn}))",
            ["sAMAccountName", "displayName", "lastLogon", "whenCreated", "adminCount"],
        )
        admin_list = []
        for admin in admins:
            admin_list.append(
                {
                    "username": admin.attributes.get("sAMAccountName", ""),
                    "display_name": admin.attributes.get("displayName", ""),
                    "last_logon": admin.attributes.get("lastLogon", ""),
                    "created": admin.attributes.get("whenCreated", ""),
                }
            )

        if len(admin_list) > 10:
            result.findings.append(
                Finding(
                    title="Excessive Domain Admin Accounts",
                    severity=Severity.HIGH,
                    category=FindingCategory.AD_MISCONFIG,
                    description=(
                        f"Found {len(admin_list)} Domain Admin accounts. "
                        "Excessive privileged accounts increase the attack surface."
                    ),
                    target=result.target,
                    evidence=f"Domain Admin accounts: {', '.join(a['username'] for a in admin_list)}",
                    remediation=(
                        "Reduce Domain Admin membership to essential accounts only. "
                        "Use tiered administration model."
                    ),
                )
            )

        result.data["domain_admin_count"] = len(admin_list)
        return admin_list

    def _enum_spn_users(
        self, conn: Any, base_dn: str, result: ModuleResult
    ) -> list[dict[str, Any]]:
        """Find user accounts with Service Principal Names (Kerberoastable)."""
        spn_users = ldap_search(
            conn,
            base_dn,
            "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)"
            "(!(objectCategory=computer)))",
            ["sAMAccountName", "servicePrincipalName", "adminCount", "memberOf"],
        )
        spn_list = []
        for user in spn_users:
            spn_list.append(
                {
                    "username": user.attributes.get("sAMAccountName", ""),
                    "spns": user.attributes.get("servicePrincipalName", []),
                    "admin_count": user.attributes.get("adminCount", "0"),
                    "groups": user.attributes.get("memberOf", []),
                }
            )

        if spn_list:
            privileged_spn = [u for u in spn_list if str(u.get("admin_count")) == "1"]
            if privileged_spn:
                result.findings.append(
                    Finding(
                        title="Privileged Accounts Vulnerable to Kerberoasting",
                        severity=Severity.CRITICAL,
                        category=FindingCategory.KERBEROS,
                        description=(
                            f"Found {len(privileged_spn)} privileged user accounts with SPNs set. "
                            "These accounts are vulnerable to Kerberoasting attacks which can "
                            "extract their service tickets for offline cracking."
                        ),
                        target=result.target,
                        evidence=(
                            "Privileged Kerberoastable accounts: "
                            + ", ".join(u["username"] for u in privileged_spn)
                        ),
                        remediation=(
                            "Use Managed Service Accounts (MSA/gMSA) instead of user accounts "
                            "for services. If user accounts must be used, set strong (25+ char) "
                            "passwords and rotate them regularly."
                        ),
                    )
                )
            else:
                result.findings.append(
                    Finding(
                        title="User Accounts Vulnerable to Kerberoasting",
                        severity=Severity.HIGH,
                        category=FindingCategory.KERBEROS,
                        description=(
                            f"Found {len(spn_list)} user accounts with SPNs set. "
                            "These accounts are vulnerable to Kerberoasting attacks."
                        ),
                        target=result.target,
                        evidence=(
                            "Kerberoastable accounts: "
                            + ", ".join(u["username"] for u in spn_list)
                        ),
                        remediation=(
                            "Use Managed Service Accounts (MSA/gMSA). "
                            "Ensure strong passwords on service accounts."
                        ),
                    )
                )

        return spn_list

    def _enum_asrep_users(
        self, conn: Any, base_dn: str, result: ModuleResult
    ) -> list[dict[str, Any]]:
        """Find accounts that don't require Kerberos pre-authentication (AS-REP Roastable)."""
        # UAC flag 0x400000 = DONT_REQ_PREAUTH
        asrep = ldap_search(
            conn,
            base_dn,
            "(&(objectCategory=person)(objectClass=user)"
            "(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
            ["sAMAccountName", "memberOf"],
        )
        asrep_list = []
        for user in asrep:
            asrep_list.append(
                {
                    "username": user.attributes.get("sAMAccountName", ""),
                    "groups": user.attributes.get("memberOf", []),
                }
            )

        if asrep_list:
            result.findings.append(
                Finding(
                    title="Accounts Vulnerable to AS-REP Roasting",
                    severity=Severity.HIGH,
                    category=FindingCategory.KERBEROS,
                    description=(
                        f"Found {len(asrep_list)} accounts with Kerberos pre-authentication "
                        "disabled. Attackers can request AS-REP tickets for these accounts "
                        "and crack them offline without any authentication."
                    ),
                    target=result.target,
                    evidence=(
                        "AS-REP Roastable accounts: "
                        + ", ".join(u["username"] for u in asrep_list)
                    ),
                    remediation=(
                        "Enable Kerberos pre-authentication for all accounts. "
                        "Review why it was disabled and implement alternative controls."
                    ),
                )
            )

        return asrep_list

    def _enum_pwd_never_expires(
        self, conn: Any, base_dn: str, result: ModuleResult
    ) -> list[dict[str, Any]]:
        """Find accounts with password set to never expire."""
        # UAC flag 0x10000 = DONT_EXPIRE_PASSWORD
        pwd_users = ldap_search(
            conn,
            base_dn,
            "(&(objectCategory=person)(objectClass=user)"
            "(userAccountControl:1.2.840.113556.1.4.803:=65536))",
            ["sAMAccountName", "adminCount", "pwdLastSet"],
        )
        pwd_list = []
        for user in pwd_users:
            pwd_list.append(
                {
                    "username": user.attributes.get("sAMAccountName", ""),
                    "admin_count": user.attributes.get("adminCount", "0"),
                    "pwd_last_set": user.attributes.get("pwdLastSet", ""),
                }
            )

        if pwd_list:
            result.findings.append(
                Finding(
                    title="Accounts with Non-Expiring Passwords",
                    severity=Severity.MEDIUM,
                    category=FindingCategory.AD_MISCONFIG,
                    description=(
                        f"Found {len(pwd_list)} accounts with passwords set to never expire. "
                        "This increases the risk of credential compromise over time."
                    ),
                    target=result.target,
                    evidence=(
                        "Non-expiring password accounts: "
                        + ", ".join(u["username"] for u in pwd_list[:20])
                        + (f" (and {len(pwd_list) - 20} more)" if len(pwd_list) > 20 else "")
                    ),
                    remediation=(
                        "Implement password expiration policies. Consider using "
                        "fine-grained password policies for service accounts."
                    ),
                )
            )

        return pwd_list

    def _enum_disabled_with_groups(
        self, conn: Any, base_dn: str, result: ModuleResult
    ) -> list[dict[str, Any]]:
        """Find disabled accounts that still have privileged group memberships."""
        # UAC flag 0x2 = ACCOUNTDISABLE
        disabled = ldap_search(
            conn,
            base_dn,
            "(&(objectCategory=person)(objectClass=user)"
            "(userAccountControl:1.2.840.113556.1.4.803:=2)"
            "(adminCount=1))",
            ["sAMAccountName", "memberOf"],
        )
        disabled_list = []
        for user in disabled:
            disabled_list.append(
                {
                    "username": user.attributes.get("sAMAccountName", ""),
                    "groups": user.attributes.get("memberOf", []),
                }
            )

        if disabled_list:
            result.findings.append(
                Finding(
                    title="Disabled Accounts with Privileged Group Memberships",
                    severity=Severity.MEDIUM,
                    category=FindingCategory.AD_MISCONFIG,
                    description=(
                        f"Found {len(disabled_list)} disabled accounts that retain membership "
                        "in privileged groups. If re-enabled, these accounts would have "
                        "elevated privileges."
                    ),
                    target=result.target,
                    remediation=(
                        "Remove disabled accounts from privileged groups. "
                        "Implement account lifecycle management."
                    ),
                )
            )

        return disabled_list

    def _enum_unconstrained_delegation(
        self, conn: Any, base_dn: str, result: ModuleResult
    ) -> list[dict[str, Any]]:
        """Find computers with unconstrained delegation enabled."""
        # UAC flag 0x80000 = TRUSTED_FOR_DELEGATION
        delegation = ldap_search(
            conn,
            base_dn,
            "(&(objectCategory=computer)"
            "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            "(!(primaryGroupID=516)))",  # Exclude DCs
            ["sAMAccountName", "dNSHostName", "operatingSystem"],
        )
        delegation_list = []
        for comp in delegation:
            delegation_list.append(
                {
                    "hostname": comp.attributes.get("sAMAccountName", ""),
                    "dns_name": comp.attributes.get("dNSHostName", ""),
                    "os": comp.attributes.get("operatingSystem", ""),
                }
            )

        if delegation_list:
            result.findings.append(
                Finding(
                    title="Computers with Unconstrained Kerberos Delegation",
                    severity=Severity.CRITICAL,
                    category=FindingCategory.KERBEROS,
                    description=(
                        f"Found {len(delegation_list)} non-DC computers with unconstrained "
                        "delegation. Compromising these systems allows an attacker to "
                        "impersonate any user that authenticates to them, including Domain Admins."
                    ),
                    target=result.target,
                    evidence=(
                        "Unconstrained delegation systems: "
                        + ", ".join(c["hostname"] for c in delegation_list)
                    ),
                    remediation=(
                        "Replace unconstrained delegation with constrained delegation or "
                        "Resource-Based Constrained Delegation (RBCD). "
                        "Enable 'Account is sensitive and cannot be delegated' for privileged users."
                    ),
                )
            )

        return delegation_list

    def _enum_adminsdholder(
        self, conn: Any, base_dn: str, result: ModuleResult
    ) -> list[dict[str, Any]]:
        """Enumerate objects protected by adminSDHolder."""
        protected = ldap_search(
            conn,
            base_dn,
            "(&(objectCategory=person)(objectClass=user)(adminCount=1))",
            ["sAMAccountName", "memberOf", "whenChanged"],
        )
        protected_list = []
        for user in protected:
            protected_list.append(
                {
                    "username": user.attributes.get("sAMAccountName", ""),
                    "groups": user.attributes.get("memberOf", []),
                    "last_changed": user.attributes.get("whenChanged", ""),
                }
            )

        result.data["adminsdholder_count"] = len(protected_list)
        return protected_list

    def _enum_stale_computers(
        self, conn: Any, base_dn: str, result: ModuleResult
    ) -> list[dict[str, Any]]:
        """Find computer accounts that haven't logged in recently (90+ days)."""
        # Search for computers with old lastLogon
        stale = ldap_search(
            conn,
            base_dn,
            "(&(objectCategory=computer)(!(lastLogonTimestamp=*)))",
            ["sAMAccountName", "dNSHostName", "operatingSystem", "whenCreated"],
        )
        stale_list = []
        for comp in stale:
            stale_list.append(
                {
                    "hostname": comp.attributes.get("sAMAccountName", ""),
                    "dns_name": comp.attributes.get("dNSHostName", ""),
                    "os": comp.attributes.get("operatingSystem", ""),
                    "created": comp.attributes.get("whenCreated", ""),
                }
            )

        if stale_list:
            result.findings.append(
                Finding(
                    title="Stale Computer Accounts in Active Directory",
                    severity=Severity.LOW,
                    category=FindingCategory.AD_MISCONFIG,
                    description=(
                        f"Found {len(stale_list)} computer accounts that have never logged in "
                        "or have no recorded logon timestamp. These may represent decommissioned "
                        "systems whose accounts were not cleaned up."
                    ),
                    target=result.target,
                    remediation=(
                        "Review and disable or delete stale computer accounts. "
                        "Implement automated AD cleanup procedures."
                    ),
                )
            )

        return stale_list
