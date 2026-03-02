"""LDAP utility functions for Active Directory interaction."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from ldap3 import (
    ALL,
    AUTO_BIND_NO_TLS,
    NTLM,
    SASL,
    SIMPLE,
    SUBTREE,
    Connection,
    Server,
)

logger = logging.getLogger(__name__)


@dataclass
class LDAPConfig:
    """LDAP connection configuration."""

    server: str
    port: int = 389
    use_ssl: bool = False
    domain: str = ""
    username: str = ""
    password: str = ""
    ntlm_hash: str = ""
    base_dn: str = ""
    auth_method: str = "NTLM"  # NTLM, SIMPLE, SASL


@dataclass
class ADObject:
    """Represents an Active Directory object."""

    dn: str
    object_class: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)


def build_base_dn(domain: str) -> str:
    """Build a base DN from a domain name. e.g. corp.local -> DC=corp,DC=local"""
    parts = domain.split(".")
    return ",".join(f"DC={part}" for part in parts)


def create_connection(config: LDAPConfig) -> Connection | None:
    """Create an LDAP connection to an Active Directory server."""
    try:
        server = Server(
            config.server,
            port=config.port,
            use_ssl=config.use_ssl,
            get_info=ALL,
        )

        if config.auth_method == "NTLM":
            user = f"{config.domain}\\{config.username}"
            conn = Connection(
                server,
                user=user,
                password=config.password,
                authentication=NTLM,
                auto_bind=AUTO_BIND_NO_TLS,
            )
        elif config.auth_method == "SIMPLE":
            conn = Connection(
                server,
                user=config.username,
                password=config.password,
                authentication=SIMPLE,
                auto_bind=AUTO_BIND_NO_TLS,
            )
        else:
            conn = Connection(server, auto_bind=AUTO_BIND_NO_TLS)

        if conn.bound:
            logger.info("Successfully connected to %s", config.server)
            return conn
        else:
            logger.error("Failed to bind to %s: %s", config.server, conn.result)
            return None

    except Exception as e:
        logger.error("LDAP connection error: %s", e)
        return None


def ldap_search(
    conn: Connection,
    base_dn: str,
    search_filter: str,
    attributes: list[str] | None = None,
    scope: str = "SUBTREE",
) -> list[ADObject]:
    """Perform an LDAP search and return results as ADObject list."""
    if attributes is None:
        attributes = ["*"]

    search_scope = SUBTREE
    results: list[ADObject] = []

    try:
        conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=search_scope,
            attributes=attributes,
        )

        for entry in conn.entries:
            attrs = {}
            for attr_name in entry.entry_attributes:
                value = entry[attr_name].value
                if isinstance(value, list):
                    attrs[attr_name] = [str(v) for v in value]
                else:
                    attrs[attr_name] = str(value) if value is not None else ""

            results.append(
                ADObject(
                    dn=str(entry.entry_dn),
                    object_class=list(entry.entry_raw_attribute("objectClass")),
                    attributes=attrs,
                )
            )

    except Exception as e:
        logger.error("LDAP search error: %s", e)

    return results


def get_domain_info(conn: Connection) -> dict[str, Any]:
    """Get basic domain information from the RootDSE."""
    info: dict[str, Any] = {}
    if conn.server.info:
        server_info = conn.server.info
        info["naming_contexts"] = (
            list(server_info.naming_contexts) if server_info.naming_contexts else []
        )
        info["default_naming_context"] = str(
            server_info.other.get("defaultNamingContext", [""])[0]
            if server_info.other
            else ""
        )
        info["domain_functionality"] = str(
            server_info.other.get("domainFunctionality", [""])[0]
            if server_info.other
            else ""
        )
        info["forest_functionality"] = str(
            server_info.other.get("forestFunctionality", [""])[0]
            if server_info.other
            else ""
        )
        info["dns_host_name"] = str(
            server_info.other.get("dnsHostName", [""])[0]
            if server_info.other
            else ""
        )
    return info
