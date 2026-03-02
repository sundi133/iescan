"""Active Directory trust relationship assessment module.

Identifies trust misconfigurations, SID filtering issues,
and trust exploitation vectors.
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

# Trust direction constants
TRUST_DIRECTION = {
    "0": "Disabled",
    "1": "Inbound",
    "2": "Outbound",
    "3": "Bidirectional",
}

# Trust type constants
TRUST_TYPE = {
    "1": "Windows NT (downlevel)",
    "2": "Active Directory (uplevel)",
    "3": "MIT Kerberos realm",
    "4": "DCE realm",
}

# Trust attributes
TRUST_ATTR_NON_TRANSITIVE = 0x00000001
TRUST_ATTR_UPLEVEL_ONLY = 0x00000002
TRUST_ATTR_QUARANTINED = 0x00000004  # SID filtering enabled
TRUST_ATTR_FOREST_TRANSITIVE = 0x00000008
TRUST_ATTR_CROSS_ORG = 0x00000010
TRUST_ATTR_WITHIN_FOREST = 0x00000020
TRUST_ATTR_TREAT_AS_EXTERNAL = 0x00000040
TRUST_ATTR_RC4_ENCRYPTION = 0x00000080
TRUST_ATTR_CROSS_ORG_NO_TGT = 0x00000200
TRUST_ATTR_PIM_TRUST = 0x00000400


class TrustAssessmentModule(BaseModule):
    """Assess Active Directory trust relationships for security weaknesses."""

    name = "trust_assessment"
    description = "Assess AD trust relationships for SID filtering, transitivity, and abuse vectors"

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

            # Enumerate all trusts
            trusts = self._enumerate_trusts(conn, base_dn, result)
            result.data["trusts"] = trusts

            # Check for SID filtering issues
            self._check_sid_filtering(trusts, result)

            # Check for transitive trust chains
            self._check_transitivity(trusts, result)

            # Check for downlevel trusts
            self._check_downlevel_trusts(trusts, result)

            # Check for intra-forest trust issues
            self._check_intra_forest(trusts, result)

        finally:
            conn.unbind()

        return result

    def _enumerate_trusts(
        self, conn: Any, base_dn: str, result: ModuleResult
    ) -> list[dict[str, Any]]:
        """Enumerate all trust relationships."""
        trust_objects = ldap_search(
            conn,
            f"CN=System,{base_dn}",
            "(objectClass=trustedDomain)",
            [
                "trustPartner",
                "trustDirection",
                "trustType",
                "trustAttributes",
                "flatName",
                "securityIdentifier",
                "whenCreated",
                "whenChanged",
            ],
        )

        trusts = []
        for trust in trust_objects:
            attrs = trust.attributes
            trust_attr = int(attrs.get("trustAttributes", "0") or "0")
            trust_dir = str(attrs.get("trustDirection", "0"))
            trust_tp = str(attrs.get("trustType", "0"))

            trust_info = {
                "partner": attrs.get("trustPartner", ""),
                "flat_name": attrs.get("flatName", ""),
                "direction": TRUST_DIRECTION.get(trust_dir, f"Unknown ({trust_dir})"),
                "type": TRUST_TYPE.get(trust_tp, f"Unknown ({trust_tp})"),
                "attributes_raw": trust_attr,
                "sid_filtering": bool(trust_attr & TRUST_ATTR_QUARANTINED),
                "forest_transitive": bool(trust_attr & TRUST_ATTR_FOREST_TRANSITIVE),
                "within_forest": bool(trust_attr & TRUST_ATTR_WITHIN_FOREST),
                "non_transitive": bool(trust_attr & TRUST_ATTR_NON_TRANSITIVE),
                "rc4_encryption": bool(trust_attr & TRUST_ATTR_RC4_ENCRYPTION),
                "cross_org": bool(trust_attr & TRUST_ATTR_CROSS_ORG),
                "created": attrs.get("whenCreated", ""),
                "modified": attrs.get("whenChanged", ""),
            }
            trusts.append(trust_info)

        if trusts:
            result.findings.append(
                Finding(
                    title="Active Directory Trust Relationships Discovered",
                    severity=Severity.INFO,
                    category=FindingCategory.TRUST_ABUSE,
                    description=(
                        f"Found {len(trusts)} trust relationships. Trust relationships "
                        "extend the authentication boundary and must be carefully managed."
                    ),
                    target=result.target,
                    evidence="\n".join(
                        f"{t['partner']} ({t['direction']}, {t['type']})"
                        for t in trusts
                    ),
                )
            )

        return trusts

    def _check_sid_filtering(
        self, trusts: list[dict[str, Any]], result: ModuleResult
    ) -> None:
        """Check for trusts without SID filtering (quarantine)."""
        no_filtering = [
            t
            for t in trusts
            if not t["sid_filtering"] and not t["within_forest"]
        ]

        if no_filtering:
            result.findings.append(
                Finding(
                    title="External Trusts Without SID Filtering",
                    severity=Severity.CRITICAL,
                    category=FindingCategory.TRUST_ABUSE,
                    description=(
                        f"Found {len(no_filtering)} external trust(s) without SID filtering "
                        "enabled. Without SID filtering, a compromised trusted domain can "
                        "create tickets with arbitrary SIDs, including Enterprise Admins "
                        "and Domain Admins from the trusting domain (SID History attack)."
                    ),
                    target=result.target,
                    evidence="\n".join(
                        f"Trust: {t['partner']} - SID Filtering: DISABLED"
                        for t in no_filtering
                    ),
                    remediation=(
                        "Enable SID filtering on all external trusts using: "
                        "netdom trust <trusted_domain> /domain:<trusting_domain> /quarantine:yes\n"
                        "Note: This may break cross-domain access that relies on SID History."
                    ),
                )
            )

    def _check_transitivity(
        self, trusts: list[dict[str, Any]], result: ModuleResult
    ) -> None:
        """Check for potentially dangerous transitive trust chains."""
        transitive = [
            t for t in trusts if not t["non_transitive"] and not t["within_forest"]
        ]

        if len(transitive) > 1:
            result.findings.append(
                Finding(
                    title="Multiple Transitive External Trusts",
                    severity=Severity.HIGH,
                    category=FindingCategory.TRUST_ABUSE,
                    description=(
                        f"Found {len(transitive)} transitive external trusts. "
                        "Transitive trust chains can allow users from indirectly trusted "
                        "domains to access resources, potentially expanding the attack surface "
                        "beyond intended boundaries."
                    ),
                    target=result.target,
                    evidence="\n".join(
                        f"Transitive trust: {t['partner']} ({t['direction']})"
                        for t in transitive
                    ),
                    remediation=(
                        "Review trust transitivity requirements. Convert trusts to "
                        "non-transitive where full chain trust is not needed. "
                        "Implement selective authentication on trusts."
                    ),
                )
            )

    def _check_downlevel_trusts(
        self, trusts: list[dict[str, Any]], result: ModuleResult
    ) -> None:
        """Check for downlevel (NT4) trusts."""
        downlevel = [t for t in trusts if "downlevel" in t["type"].lower()]

        if downlevel:
            result.findings.append(
                Finding(
                    title="Legacy NT4-Style Trust Relationships",
                    severity=Severity.HIGH,
                    category=FindingCategory.TRUST_ABUSE,
                    description=(
                        f"Found {len(downlevel)} NT4-style (downlevel) trusts. "
                        "These trusts use older, weaker authentication mechanisms "
                        "and lack modern security features like SID filtering."
                    ),
                    target=result.target,
                    evidence="\n".join(
                        f"Downlevel trust: {t['partner']}" for t in downlevel
                    ),
                    remediation=(
                        "Upgrade or replace NT4-style trusts with Active Directory trusts. "
                        "If the trusted domain cannot be upgraded, consider removing the trust."
                    ),
                )
            )

    def _check_intra_forest(
        self, trusts: list[dict[str, Any]], result: ModuleResult
    ) -> None:
        """Check intra-forest trust configurations."""
        intra_forest = [t for t in trusts if t["within_forest"]]

        # Within-forest trusts do not have SID filtering by default, which is expected
        # but important to note
        if intra_forest:
            rc4_trusts = [t for t in intra_forest if t.get("rc4_encryption")]
            if rc4_trusts:
                result.findings.append(
                    Finding(
                        title="Intra-Forest Trusts Using RC4 Encryption",
                        severity=Severity.MEDIUM,
                        category=FindingCategory.TRUST_ABUSE,
                        description=(
                            f"Found {len(rc4_trusts)} intra-forest trusts using RC4 encryption. "
                            "RC4 is a weak cipher that should be replaced with AES."
                        ),
                        target=result.target,
                        remediation=(
                            "Upgrade trust encryption to AES. Ensure all Domain Controllers "
                            "support AES Kerberos encryption before making changes."
                        ),
                    )
                )
