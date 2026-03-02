"""Configuration management for iescan."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class TargetScope:
    """Defines the authorized scope for a pentest engagement."""

    networks: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    exclude_hosts: list[str] = field(default_factory=list)
    exclude_networks: list[str] = field(default_factory=list)


@dataclass
class Credentials:
    """Credentials for authenticated testing."""

    username: str = ""
    password: str = ""
    domain: str = ""
    ntlm_hash: str = ""
    kerberos_ticket: str = ""
    use_kerberos: bool = False


@dataclass
class ScanConfig:
    """Main scan configuration."""

    engagement_id: str = ""
    authorization_ref: str = ""
    scope: TargetScope = field(default_factory=TargetScope)
    credentials: Credentials = field(default_factory=Credentials)
    output_dir: str = "./reports"
    modules: list[str] = field(default_factory=lambda: ["all"])
    threads: int = 10
    timeout: int = 30
    verbose: bool = False
    safe_mode: bool = True  # Avoid destructive operations


def load_config(config_path: str | Path) -> ScanConfig:
    """Load scan configuration from a YAML file."""
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(path) as f:
        raw: dict[str, Any] = yaml.safe_load(f)

    scope_data = raw.get("scope", {})
    scope = TargetScope(
        networks=scope_data.get("networks", []),
        domains=scope_data.get("domains", []),
        hosts=scope_data.get("hosts", []),
        exclude_hosts=scope_data.get("exclude_hosts", []),
        exclude_networks=scope_data.get("exclude_networks", []),
    )

    creds_data = raw.get("credentials", {})
    credentials = Credentials(
        username=creds_data.get("username", ""),
        password=creds_data.get("password", ""),
        domain=creds_data.get("domain", ""),
        ntlm_hash=creds_data.get("ntlm_hash", ""),
        kerberos_ticket=creds_data.get("kerberos_ticket", ""),
        use_kerberos=creds_data.get("use_kerberos", False),
    )

    return ScanConfig(
        engagement_id=raw.get("engagement_id", ""),
        authorization_ref=raw.get("authorization_ref", ""),
        scope=scope,
        credentials=credentials,
        output_dir=raw.get("output_dir", "./reports"),
        modules=raw.get("modules", ["all"]),
        threads=raw.get("threads", 10),
        timeout=raw.get("timeout", 30),
        verbose=raw.get("verbose", False),
        safe_mode=raw.get("safe_mode", True),
    )


def default_config() -> ScanConfig:
    """Return a default configuration."""
    return ScanConfig()
