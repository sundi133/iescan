"""Authorization and engagement validation for iescan.

Ensures that scans only run within authorized scope and with proper
engagement documentation.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass

from iescan.config import ScanConfig

logger = logging.getLogger(__name__)


@dataclass
class AuthorizationCheck:
    """Result of an authorization check."""

    authorized: bool
    reason: str


def validate_engagement(config: ScanConfig) -> AuthorizationCheck:
    """Validate that the scan has proper engagement authorization."""
    if not config.engagement_id:
        return AuthorizationCheck(
            authorized=False,
            reason="No engagement ID provided. All scans must have an engagement ID.",
        )

    if not config.authorization_ref:
        return AuthorizationCheck(
            authorized=False,
            reason="No authorization reference provided. Scans require documented authorization.",
        )

    if not config.scope.networks and not config.scope.hosts and not config.scope.domains:
        return AuthorizationCheck(
            authorized=False,
            reason="No targets defined in scope. At least one network, host, or domain is required.",
        )

    return AuthorizationCheck(authorized=True, reason="Engagement authorization validated.")


def is_target_in_scope(target: str, config: ScanConfig) -> bool:
    """Check if a target is within the authorized scope."""
    # Check exclusions first
    for excluded in config.scope.exclude_hosts:
        if target == excluded:
            logger.warning("Target %s is explicitly excluded from scope.", target)
            return False

    for excluded_net in config.scope.exclude_networks:
        try:
            network = ipaddress.ip_network(excluded_net, strict=False)
            if ipaddress.ip_address(target) in network:
                logger.warning("Target %s is in excluded network %s.", target, excluded_net)
                return False
        except ValueError:
            continue

    # Check if target is in scope
    if target in config.scope.hosts:
        return True

    for network_str in config.scope.networks:
        try:
            network = ipaddress.ip_network(network_str, strict=False)
            if ipaddress.ip_address(target) in network:
                return True
        except ValueError:
            continue

    # If target matches a domain
    for domain in config.scope.domains:
        if target.endswith(domain) or target == domain:
            return True

    logger.warning("Target %s is NOT in authorized scope.", target)
    return False


def filter_in_scope(targets: list[str], config: ScanConfig) -> list[str]:
    """Filter a list of targets to only those in scope."""
    return [t for t in targets if is_target_in_scope(t, config)]
