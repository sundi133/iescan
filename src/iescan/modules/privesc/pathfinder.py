"""Privilege escalation path discovery module.

Maps potential internal compromise paths from initial access
to domain admin, analyzing AD relationships, delegation chains,
group memberships, and trust relationships.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
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


@dataclass
class AttackNode:
    """A node in an attack path graph."""

    name: str
    node_type: str  # user, computer, group, gpo, trust
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackEdge:
    """An edge (relationship) in an attack path graph."""

    source: str
    target: str
    edge_type: str  # memberOf, adminTo, hasSession, canRDP, canPSRemote, etc.
    description: str = ""


@dataclass
class AttackPath:
    """A complete attack path from start to target."""

    start_node: str
    end_node: str
    edges: list[AttackEdge] = field(default_factory=list)
    risk_score: float = 0.0
    description: str = ""


class PrivescPathfinderModule(BaseModule):
    """Discover and map privilege escalation paths within the domain."""

    name = "privesc_pathfinder"
    description = "Map privilege escalation paths from initial access to domain admin"

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
            paths: list[dict[str, Any]] = []

            # 1. Kerberoasting -> password crack -> privileged access
            kerberoast_paths = self._find_kerberoast_paths(conn, base_dn, result)
            paths.extend(kerberoast_paths)

            # 2. Delegation abuse paths
            delegation_paths = self._find_delegation_paths(conn, base_dn, result)
            paths.extend(delegation_paths)

            # 3. Group nesting paths to DA
            nesting_paths = self._find_nested_group_paths(conn, base_dn, result)
            paths.extend(nesting_paths)

            # 4. GPO abuse paths
            gpo_paths = self._find_gpo_abuse_paths(conn, base_dn, result)
            paths.extend(gpo_paths)

            # 5. ACL abuse paths
            acl_paths = self._find_acl_abuse_paths(conn, base_dn, result)
            paths.extend(acl_paths)

            result.data["attack_paths"] = paths
            result.data["total_paths"] = len(paths)

            if paths:
                critical_paths = [p for p in paths if p.get("risk", "") == "critical"]
                high_paths = [p for p in paths if p.get("risk", "") == "high"]

                result.findings.append(
                    Finding(
                        title=f"Privilege Escalation Paths Identified ({len(paths)} total)",
                        severity=Severity.CRITICAL if critical_paths else Severity.HIGH,
                        category=FindingCategory.PRIVESC,
                        description=(
                            f"Identified {len(paths)} potential privilege escalation paths. "
                            f"{len(critical_paths)} critical, {len(high_paths)} high risk. "
                            "These paths represent chains of misconfigurations that could "
                            "allow an attacker to escalate from initial access to "
                            "Domain Admin privileges."
                        ),
                        target=target,
                        evidence="\n\n".join(
                            f"Path: {p['name']}\n"
                            f"  Risk: {p['risk']}\n"
                            f"  Chain: {' -> '.join(p.get('chain', []))}"
                            for p in paths[:10]
                        ),
                        remediation=(
                            "Address each attack path by fixing the weakest link. "
                            "Priority should be given to critical paths. "
                            "See individual findings for specific remediation steps."
                        ),
                    )
                )

        finally:
            conn.unbind()

        return result

    def _find_kerberoast_paths(
        self, conn: Any, base_dn: str, result: ModuleResult
    ) -> list[dict[str, Any]]:
        """Find paths: Kerberoastable account -> privileged group membership."""
        paths = []

        # Find Kerberoastable accounts in privileged groups
        spn_users = ldap_search(
            conn,
            base_dn,
            "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)"
            "(adminCount=1)(!(objectCategory=computer)))",
            ["sAMAccountName", "servicePrincipalName", "memberOf"],
        )

        for user in spn_users:
            username = user.attributes.get("sAMAccountName", "")
            groups = user.attributes.get("memberOf", [])
            if isinstance(groups, str):
                groups = [groups]

            # Check if member of high-value groups
            high_value_groups = [
                g for g in groups
                if any(
                    hv in g.lower()
                    for hv in [
                        "domain admins", "enterprise admins",
                        "schema admins", "administrators",
                        "account operators", "backup operators",
                    ]
                )
            ]

            if high_value_groups:
                paths.append({
                    "name": f"Kerberoast {username} -> Domain Admin",
                    "risk": "critical",
                    "technique": "Kerberoasting",
                    "chain": [
                        "Request TGS for SPN",
                        f"Crack {username} password offline",
                        "Authenticate as privileged user",
                        "Domain Admin access",
                    ],
                    "affected_account": username,
                    "target_groups": [g.split(",")[0] for g in high_value_groups],
                })

        return paths

    def _find_delegation_paths(
        self, conn: Any, base_dn: str, result: ModuleResult
    ) -> list[dict[str, Any]]:
        """Find paths via delegation abuse."""
        paths = []

        # Unconstrained delegation
        unconstrained = ldap_search(
            conn,
            base_dn,
            "(&(objectCategory=computer)"
            "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            "(!(primaryGroupID=516)))",
            ["sAMAccountName", "dNSHostName"],
        )

        for comp in unconstrained:
            hostname = comp.attributes.get("sAMAccountName", "")
            paths.append({
                "name": f"Unconstrained Delegation on {hostname}",
                "risk": "critical",
                "technique": "Unconstrained Delegation Abuse",
                "chain": [
                    f"Compromise {hostname}",
                    "Wait for/coerce privileged user authentication",
                    "Extract TGT from memory",
                    "Pass-the-Ticket as Domain Admin",
                ],
                "affected_host": hostname,
            })

        # Constrained delegation with protocol transition to sensitive services
        constrained = ldap_search(
            conn,
            base_dn,
            "(&(objectClass=*)(msDS-AllowedToDelegateTo=*)"
            "(userAccountControl:1.2.840.113556.1.4.803:=16777216))",
            ["sAMAccountName", "msDS-AllowedToDelegateTo"],
        )

        for obj in constrained:
            account = obj.attributes.get("sAMAccountName", "")
            targets = obj.attributes.get("msDS-AllowedToDelegateTo", [])
            if isinstance(targets, str):
                targets = [targets]

            sensitive_targets = [
                t for t in targets
                if any(s in t.lower() for s in ["ldap/", "cifs/", "host/"])
            ]

            if sensitive_targets:
                paths.append({
                    "name": f"Constrained Delegation via {account}",
                    "risk": "high",
                    "technique": "S4U2Self + S4U2Proxy",
                    "chain": [
                        f"Compromise {account}",
                        "Use S4U2Self to get ticket for any user",
                        f"Use S4U2Proxy to delegate to {sensitive_targets[0]}",
                        "Access target service as impersonated user",
                    ],
                    "affected_account": account,
                    "delegation_targets": sensitive_targets,
                })

        return paths

    def _find_nested_group_paths(
        self, conn: Any, base_dn: str, result: ModuleResult
    ) -> list[dict[str, Any]]:
        """Find privilege escalation via deeply nested group membership."""
        paths = []

        # Find groups that are members of Domain Admins (nested)
        da_members = ldap_search(
            conn,
            base_dn,
            f"(&(objectCategory=group)(memberOf=CN=Domain Admins,CN=Users,{base_dn}))",
            ["sAMAccountName", "member"],
        )

        for group in da_members:
            group_name = group.attributes.get("sAMAccountName", "")
            members = group.attributes.get("member", [])
            if isinstance(members, str):
                members = [members]

            if members:
                paths.append({
                    "name": f"Nested Group {group_name} -> Domain Admins",
                    "risk": "high",
                    "technique": "Nested Group Membership",
                    "chain": [
                        f"Compromise member of {group_name}",
                        f"{group_name} is member of Domain Admins",
                        "Inherit Domain Admin privileges",
                    ],
                    "affected_group": group_name,
                    "member_count": len(members),
                })

        return paths

    def _find_gpo_abuse_paths(
        self, conn: Any, base_dn: str, result: ModuleResult
    ) -> list[dict[str, Any]]:
        """Find privilege escalation via GPO abuse."""
        paths = []

        # Find GPOs linked to Domain Controllers OU
        dc_ou_dn = f"OU=Domain Controllers,{base_dn}"
        try:
            dc_ou = ldap_search(
                conn, dc_ou_dn,
                "(objectClass=organizationalUnit)",
                ["gPLink"],
            )

            if dc_ou:
                gp_link = dc_ou[0].attributes.get("gPLink", "")
                if gp_link:
                    paths.append({
                        "name": "GPO Linked to Domain Controllers OU",
                        "risk": "high",
                        "technique": "GPO Abuse",
                        "chain": [
                            "Gain write access to GPO",
                            "Modify GPO to deploy scheduled task or logon script",
                            "GPO applies to Domain Controllers",
                            "Code execution on Domain Controller",
                        ],
                        "gpo_link": gp_link,
                    })
        except Exception:
            pass

        return paths

    def _find_acl_abuse_paths(
        self, conn: Any, base_dn: str, result: ModuleResult
    ) -> list[dict[str, Any]]:
        """Find privilege escalation via ACL misconfigurations."""
        paths = []

        # Find users who can modify privileged groups
        # This is a simplified check - full ACL analysis requires DACL parsing
        # Check for users with write permissions on Domain Admins group
        da_dn = f"CN=Domain Admins,CN=Users,{base_dn}"

        # Check for users who own privileged objects
        privileged_objects = ldap_search(
            conn,
            base_dn,
            "(&(objectClass=user)(adminCount=1))",
            ["sAMAccountName", "nTSecurityDescriptor"],
        )

        # Check for accounts that can reset passwords
        # Look for accounts with "User-Force-Change-Password" extended right
        # This requires parsing nTSecurityDescriptor which is complex in LDAP

        # Check for DCSync-capable accounts (Replicating Directory Changes)
        # This would be found via ACL on the domain root
        result.data["acl_paths_note"] = (
            "Full ACL path analysis requires nTSecurityDescriptor parsing. "
            "Consider using BloodHound for comprehensive ACL path mapping."
        )

        return paths
