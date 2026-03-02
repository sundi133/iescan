"""MCP server for iescan - exposes assessment tools via Model Context Protocol.

Allows AI agents to orchestrate internal enterprise security assessments
through structured tool calls.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from iescan.config import Credentials, ScanConfig, TargetScope
from iescan.core.auth import filter_in_scope, validate_engagement
from iescan.core.reporter import generate_json_report
from iescan.core.scanner import ScanEngine
from iescan.modules.ad.enumeration import ADEnumerationModule
from iescan.modules.ad.gpo import GPOAssessmentModule
from iescan.modules.ad.kerberos import KerberosAssessmentModule
from iescan.modules.ad.trusts import TrustAssessmentModule
from iescan.modules.database.common import MySQLAssessmentModule, PostgreSQLAssessmentModule
from iescan.modules.database.mssql import MSSQLAssessmentModule
from iescan.modules.erp.sap import ERPAssessmentModule
from iescan.modules.network.discovery import NetworkDiscoveryModule
from iescan.modules.network.services import ServiceAssessmentModule
from iescan.modules.network.shares import ShareEnumerationModule
from iescan.modules.privesc.pathfinder import PrivescPathfinderModule

logger = logging.getLogger(__name__)

# Global config - set during initialization
_config: ScanConfig | None = None


def _build_config(params: dict[str, Any]) -> ScanConfig:
    """Build a ScanConfig from MCP tool parameters."""
    scope = TargetScope(
        networks=params.get("networks", []),
        domains=params.get("domains", []),
        hosts=params.get("hosts", []),
        exclude_hosts=params.get("exclude_hosts", []),
    )
    credentials = Credentials(
        username=params.get("username", ""),
        password=params.get("password", ""),
        domain=params.get("domain", ""),
    )
    return ScanConfig(
        engagement_id=params.get("engagement_id", "mcp-session"),
        authorization_ref=params.get("authorization_ref", "mcp-authorized"),
        scope=scope,
        credentials=credentials,
        output_dir=params.get("output_dir", "./reports"),
        modules=params.get("modules", ["all"]),
        threads=params.get("threads", 10),
        timeout=params.get("timeout", 30),
        safe_mode=params.get("safe_mode", True),
    )


def _run_module(module_class: type, config: ScanConfig, target: str, **kwargs: Any) -> dict:
    """Run a single assessment module and return results."""
    auth = validate_engagement(config)
    if not auth.authorized:
        return {"error": auth.reason}

    module = module_class(config)
    engine = ScanEngine(config)
    result = engine.run_module(module, target, **kwargs)

    return {
        "module": result.module_name,
        "target": result.target,
        "success": result.success,
        "duration_seconds": result.duration_seconds,
        "findings": [
            {
                "title": f.title,
                "severity": f.severity.value,
                "category": f.category.value,
                "description": f.description,
                "evidence": f.evidence,
                "remediation": f.remediation,
            }
            for f in result.findings
        ],
        "data": result.data,
        "errors": result.errors,
    }


TOOLS = [
    Tool(
        name="configure_scan",
        description=(
            "Configure the scan with engagement details, credentials, and scope. "
            "Must be called before running any assessment modules."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "engagement_id": {
                    "type": "string",
                    "description": "Unique engagement identifier",
                },
                "authorization_ref": {
                    "type": "string",
                    "description": "Authorization document reference (SOW, pentest agreement)",
                },
                "networks": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "CIDR networks in scope (e.g., ['10.0.0.0/24'])",
                },
                "domains": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "AD domains in scope (e.g., ['corp.local'])",
                },
                "hosts": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Individual hosts in scope",
                },
                "username": {
                    "type": "string",
                    "description": "Domain username for authenticated testing",
                },
                "password": {
                    "type": "string",
                    "description": "Password for authentication",
                },
                "domain": {
                    "type": "string",
                    "description": "AD domain name for authentication",
                },
            },
            "required": ["engagement_id", "authorization_ref"],
        },
    ),
    Tool(
        name="discover_network",
        description=(
            "Discover live hosts and open ports on a target network or host. "
            "Performs TCP connect scanning to identify services."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target IP, hostname, or CIDR range",
                },
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="assess_services",
        description=(
            "Identify running services and check for known vulnerabilities, "
            "insecure protocols, and misconfigurations on a target host."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target IP or hostname",
                },
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="enumerate_ad",
        description=(
            "Enumerate Active Directory objects including users, groups, computers, "
            "and identify misconfigurations like Kerberoastable accounts, "
            "unconstrained delegation, and stale objects."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Domain Controller IP or hostname",
                },
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="assess_kerberos",
        description=(
            "Assess Kerberos configuration for encryption weaknesses, "
            "delegation misconfigurations, and krbtgt password age."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Domain Controller IP or hostname",
                },
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="assess_gpo",
        description=(
            "Assess Group Policy Objects for security misconfigurations, "
            "stored credentials (GPP/cpassword), and abuse vectors."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Domain Controller IP or hostname",
                },
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="assess_trusts",
        description=(
            "Assess Active Directory trust relationships for SID filtering issues, "
            "transitive trust chains, and trust exploitation vectors."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Domain Controller IP or hostname",
                },
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="enumerate_shares",
        description=(
            "Enumerate and assess SMB file shares for access control issues, "
            "sensitive file exposure, and write permissions."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target host IP or hostname",
                },
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="assess_mssql",
        description=(
            "Assess Microsoft SQL Server for default credentials, dangerous "
            "stored procedures, linked servers, and privilege escalation vectors."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "MSSQL server IP or hostname",
                },
                "port": {
                    "type": "integer",
                    "description": "MSSQL port (default: 1433)",
                    "default": 1433,
                },
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="assess_mysql",
        description=(
            "Assess MySQL/MariaDB for default credentials, anonymous users, "
            "and security misconfigurations."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "MySQL server IP or hostname",
                },
                "port": {
                    "type": "integer",
                    "description": "MySQL port (default: 3306)",
                    "default": 3306,
                },
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="assess_postgresql",
        description=(
            "Assess PostgreSQL for default credentials, trust authentication, "
            "and security misconfigurations."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "PostgreSQL server IP or hostname",
                },
                "port": {
                    "type": "integer",
                    "description": "PostgreSQL port (default: 5432)",
                    "default": 5432,
                },
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="assess_erp",
        description=(
            "Assess ERP systems (SAP, Oracle) for exposed interfaces, "
            "default configurations, and management console access."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "ERP server IP or hostname",
                },
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="find_privesc_paths",
        description=(
            "Map privilege escalation paths from current access to Domain Admin. "
            "Analyzes Kerberoasting chains, delegation abuse, nested groups, "
            "GPO abuse, and ACL misconfigurations."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Domain Controller IP or hostname",
                },
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="full_internal_assessment",
        description=(
            "Run a comprehensive internal enterprise assessment covering "
            "network discovery, AD enumeration, Kerberos, GPO, trusts, "
            "shares, databases, and privilege escalation path mapping."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of targets (IPs, hostnames, or CIDR ranges)",
                },
                "dc_target": {
                    "type": "string",
                    "description": "Primary Domain Controller for AD assessments",
                },
            },
            "required": ["targets", "dc_target"],
        },
    ),
    Tool(
        name="generate_report",
        description=(
            "Generate a security assessment report from the latest scan results "
            "in JSON or HTML format."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "format": {
                    "type": "string",
                    "enum": ["json", "html"],
                    "description": "Report format",
                    "default": "json",
                },
                "output_path": {
                    "type": "string",
                    "description": "Output file path",
                },
            },
            "required": ["output_path"],
        },
    ),
    Tool(
        name="analyze_findings",
        description=(
            "Use LLM reasoning to analyze all scan findings, identify cross-module "
            "correlations, build attack chains, and generate an executive summary. "
            "Requires an LLM API key to be configured."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "provider": {
                    "type": "string",
                    "enum": ["anthropic", "openai", "ollama"],
                    "description": "LLM provider",
                    "default": "anthropic",
                },
                "api_key": {
                    "type": "string",
                    "description": "API key for the LLM provider",
                },
                "model": {
                    "type": "string",
                    "description": "Model name (default: claude-sonnet-4-5-20241022)",
                },
            },
            "required": ["api_key"],
        },
    ),
    Tool(
        name="run_agentic_assessment",
        description=(
            "Run a fully autonomous agentic assessment. The AI agent decides which "
            "modules to run, analyzes results, correlates findings, and generates "
            "attack narratives — all driven by LLM reasoning."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Target IPs/hostnames to assess",
                },
                "api_key": {
                    "type": "string",
                    "description": "API key for the LLM provider",
                },
                "provider": {
                    "type": "string",
                    "enum": ["anthropic", "openai", "ollama"],
                    "default": "anthropic",
                },
                "model": {
                    "type": "string",
                    "description": "Model name",
                },
                "max_steps": {
                    "type": "integer",
                    "description": "Maximum agent iterations (default: 20)",
                    "default": 20,
                },
            },
            "required": ["targets", "api_key"],
        },
    ),
]

# Map tool names to module classes
MODULE_MAP: dict[str, type] = {
    "discover_network": NetworkDiscoveryModule,
    "assess_services": ServiceAssessmentModule,
    "enumerate_ad": ADEnumerationModule,
    "assess_kerberos": KerberosAssessmentModule,
    "assess_gpo": GPOAssessmentModule,
    "assess_trusts": TrustAssessmentModule,
    "enumerate_shares": ShareEnumerationModule,
    "assess_mssql": MSSQLAssessmentModule,
    "assess_mysql": MySQLAssessmentModule,
    "assess_postgresql": PostgreSQLAssessmentModule,
    "assess_erp": ERPAssessmentModule,
    "find_privesc_paths": PrivescPathfinderModule,
}

# Store last scan result for report generation
_last_scan_result = None


async def serve() -> None:
    """Start the MCP server."""
    global _config, _last_scan_result

    server = Server("iescan")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return TOOLS

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        global _config, _last_scan_result

        # Handle configuration
        if name == "configure_scan":
            _config = _build_config(arguments)
            auth = validate_engagement(_config)
            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "configured": True,
                            "authorized": auth.authorized,
                            "message": auth.reason,
                            "engagement_id": _config.engagement_id,
                        },
                        indent=2,
                    ),
                )
            ]

        # All other tools require configuration
        if _config is None:
            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "error": "Scan not configured. Call configure_scan first "
                            "with engagement details and credentials."
                        }
                    ),
                )
            ]

        # Handle report generation
        if name == "generate_report":
            if _last_scan_result is None:
                return [
                    TextContent(
                        type="text",
                        text=json.dumps({"error": "No scan results available. Run an assessment first."}),
                    )
                ]

            from iescan.core.reporter import generate_html_report, generate_json_report

            fmt = arguments.get("format", "json")
            output = arguments["output_path"]

            if fmt == "html":
                path = generate_html_report(_last_scan_result, output)
            else:
                path = generate_json_report(_last_scan_result, output)

            return [
                TextContent(
                    type="text",
                    text=json.dumps({"report_generated": path, "format": fmt}),
                )
            ]

        # Handle full assessment
        if name == "full_internal_assessment":
            targets = arguments["targets"]
            dc_target = arguments["dc_target"]

            engine = ScanEngine(_config)

            # Register all modules
            all_modules = [
                NetworkDiscoveryModule(_config),
                ServiceAssessmentModule(_config),
                ADEnumerationModule(_config),
                KerberosAssessmentModule(_config),
                GPOAssessmentModule(_config),
                TrustAssessmentModule(_config),
                ShareEnumerationModule(_config),
                MSSQLAssessmentModule(_config),
                ERPAssessmentModule(_config),
                PrivescPathfinderModule(_config),
            ]
            for mod in all_modules:
                engine.register_module(mod)

            # Run network modules against all targets
            all_targets = targets + [dc_target] if dc_target not in targets else targets
            scan_result = engine.run_all(all_targets)
            _last_scan_result = scan_result

            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "completed": True,
                            "targets_scanned": len(all_targets),
                            "total_findings": scan_result.total_findings,
                            "critical": scan_result.critical_count,
                            "high": scan_result.high_count,
                            "medium": scan_result.medium_count,
                            "low": scan_result.low_count,
                            "info": scan_result.info_count,
                            "duration": f"{sum(mr.duration_seconds for mr in scan_result.module_results):.1f}s",
                        },
                        indent=2,
                    ),
                )
            ]

        # Handle agentic analysis of findings
        if name == "analyze_findings":
            if _last_scan_result is None:
                return [
                    TextContent(
                        type="text",
                        text=json.dumps({"error": "No scan results. Run an assessment first."}),
                    )
                ]

            from iescan.core.reasoning import ReasoningConfig, ReasoningEngine, ReasoningProvider

            provider_map = {
                "anthropic": ReasoningProvider.ANTHROPIC,
                "openai": ReasoningProvider.OPENAI,
                "ollama": ReasoningProvider.OLLAMA,
            }
            reasoning_config = ReasoningConfig(
                provider=provider_map.get(arguments.get("provider", "anthropic"), ReasoningProvider.ANTHROPIC),
                model=arguments.get("model", "claude-sonnet-4-5-20241022"),
                api_key=arguments.get("api_key", ""),
            )
            engine = ReasoningEngine(reasoning_config)

            try:
                analysis = engine.analyze_findings(_last_scan_result)
                correlations = engine.correlate_cross_module(_last_scan_result.module_results)
                narrative = engine.generate_attack_narrative(_last_scan_result)

                return [
                    TextContent(
                        type="text",
                        text=json.dumps(
                            {
                                "analysis": analysis.analysis,
                                "attack_chains": analysis.attack_chains,
                                "next_steps": analysis.next_steps,
                                "executive_summary": analysis.executive_summary,
                                "cross_correlations": correlations,
                                "attack_narrative": narrative,
                            },
                            indent=2,
                            default=str,
                        ),
                    )
                ]
            finally:
                engine.close()

        # Handle full agentic assessment
        if name == "run_agentic_assessment":
            from iescan.core.agent import PentestAgent
            from iescan.core.reasoning import ReasoningConfig, ReasoningProvider

            provider_map = {
                "anthropic": ReasoningProvider.ANTHROPIC,
                "openai": ReasoningProvider.OPENAI,
                "ollama": ReasoningProvider.OLLAMA,
            }
            reasoning_config = ReasoningConfig(
                provider=provider_map.get(arguments.get("provider", "anthropic"), ReasoningProvider.ANTHROPIC),
                model=arguments.get("model", "claude-sonnet-4-5-20241022"),
                api_key=arguments.get("api_key", ""),
            )

            agent = PentestAgent(_config, reasoning_config, arguments.get("max_steps", 20))
            agent.register_modules(MODULE_MAP)
            session = agent.run(arguments["targets"])

            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "completed": True,
                            "steps": [
                                {
                                    "step": s.step_number,
                                    "module": s.module_name,
                                    "target": s.target,
                                    "reasoning": s.reasoning,
                                    "findings": len(s.result.findings) if s.result else 0,
                                    "duration": f"{s.duration_seconds:.1f}s",
                                }
                                for s in session.steps
                            ],
                            "total_findings": session.total_findings,
                            "cross_correlations": session.cross_correlations[:10],
                            "executive_summary": session.executive_summary,
                            "attack_narrative": session.attack_narrative[:2000],
                        },
                        indent=2,
                        default=str,
                    ),
                )
            ]

        # Handle individual module execution
        if name in MODULE_MAP:
            target = arguments["target"]
            kwargs = {k: v for k, v in arguments.items() if k != "target"}
            result_data = _run_module(MODULE_MAP[name], _config, target, **kwargs)

            return [
                TextContent(
                    type="text",
                    text=json.dumps(result_data, indent=2, default=str),
                )
            ]

        return [
            TextContent(
                type="text",
                text=json.dumps({"error": f"Unknown tool: {name}"}),
            )
        ]

    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())
