"""Core scanning engine that orchestrates assessment modules."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from iescan.config import ScanConfig

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(str, Enum):
    AD_MISCONFIG = "Active Directory Misconfiguration"
    KERBEROS = "Kerberos Vulnerability"
    GPO_ABUSE = "GPO Abuse Vector"
    TRUST_ABUSE = "Trust Relationship Abuse"
    CREDENTIAL = "Credential Exposure"
    NETWORK = "Network Vulnerability"
    SMB_SHARE = "SMB Share Exposure"
    DATABASE = "Database Vulnerability"
    ERP = "ERP System Vulnerability"
    PRIVESC = "Privilege Escalation Path"
    DEFAULT_CRED = "Default Credentials"
    PROTOCOL = "Insecure Protocol"


@dataclass
class Finding:
    """A security finding discovered during assessment."""

    title: str
    severity: Severity
    category: FindingCategory
    description: str
    target: str
    evidence: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    cvss_score: float | None = None
    cve_ids: list[str] = field(default_factory=list)
    raw_data: dict[str, Any] = field(default_factory=dict)


@dataclass
class ModuleResult:
    """Result from running an assessment module."""

    module_name: str
    target: str
    findings: list[Finding] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    success: bool = True


@dataclass
class ScanResult:
    """Complete scan result across all modules."""

    engagement_id: str
    start_time: str = ""
    end_time: str = ""
    module_results: list[ModuleResult] = field(default_factory=list)
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    def compute_stats(self) -> None:
        """Compute finding statistics across all module results."""
        all_findings = []
        for mr in self.module_results:
            all_findings.extend(mr.findings)
        self.total_findings = len(all_findings)
        self.critical_count = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
        self.high_count = sum(1 for f in all_findings if f.severity == Severity.HIGH)
        self.medium_count = sum(1 for f in all_findings if f.severity == Severity.MEDIUM)
        self.low_count = sum(1 for f in all_findings if f.severity == Severity.LOW)
        self.info_count = sum(1 for f in all_findings if f.severity == Severity.INFO)


class BaseModule:
    """Base class for all assessment modules."""

    name: str = "base"
    description: str = ""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.logger = logging.getLogger(f"iescan.{self.name}")

    def run(self, target: str, **kwargs: Any) -> ModuleResult:
        """Run the assessment module against a target. Override in subclasses."""
        raise NotImplementedError

    def _make_result(self, target: str) -> ModuleResult:
        return ModuleResult(module_name=self.name, target=target)


class ScanEngine:
    """Orchestrates running assessment modules against targets."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.modules: list[BaseModule] = []
        self.results = ScanResult(engagement_id=config.engagement_id)

    def register_module(self, module: BaseModule) -> None:
        """Register an assessment module."""
        self.modules.append(module)
        logger.info("Registered module: %s", module.name)

    def run_module(self, module: BaseModule, target: str, **kwargs: Any) -> ModuleResult:
        """Run a single module against a target."""
        logger.info("Running %s against %s", module.name, target)
        start = time.time()
        try:
            result = module.run(target, **kwargs)
            result.duration_seconds = time.time() - start
            return result
        except Exception as e:
            logger.error("Module %s failed on %s: %s", module.name, target, e)
            result = ModuleResult(
                module_name=module.name,
                target=target,
                success=False,
                errors=[str(e)],
                duration_seconds=time.time() - start,
            )
            return result

    def run_all(self, targets: list[str], **kwargs: Any) -> ScanResult:
        """Run all registered modules against all targets."""
        self.results.start_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        for target in targets:
            for module in self.modules:
                should_run = (
                    "all" in self.config.modules or module.name in self.config.modules
                )
                if should_run:
                    result = self.run_module(module, target, **kwargs)
                    self.results.module_results.append(result)

        self.results.end_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.results.compute_stats()
        return self.results
