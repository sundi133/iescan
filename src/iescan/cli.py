"""CLI interface for iescan - Internal Enterprise Security Assessment Scanner."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from iescan import __version__
from iescan.config import ScanConfig, load_config, default_config
from iescan.core.auth import validate_engagement, filter_in_scope
from iescan.core.reporter import generate_html_report, generate_json_report
from iescan.core.scanner import ScanEngine, Severity
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

console = Console()

BANNER = """
[bold purple]
  ██╗███████╗███████╗ ██████╗ █████╗ ███╗   ██╗
  ██║██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██║█████╗  ███████╗██║     ███████║██╔██╗ ██║
  ██║██╔══╝  ╚════██║██║     ██╔══██║██║╚██╗██║
  ██║███████╗███████║╚██████╗██║  ██║██║ ╚████║
  ╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
[/bold purple]
[dim]Internal Enterprise Security Assessment Scanner v{version}[/dim]
[dim]Authorized Penetration Testing Tool[/dim]
"""

ALL_MODULES = {
    "network_discovery": NetworkDiscoveryModule,
    "service_assessment": ServiceAssessmentModule,
    "ad_enumeration": ADEnumerationModule,
    "kerberos_assessment": KerberosAssessmentModule,
    "gpo_assessment": GPOAssessmentModule,
    "trust_assessment": TrustAssessmentModule,
    "share_enumeration": ShareEnumerationModule,
    "mssql_assessment": MSSQLAssessmentModule,
    "mysql_assessment": MySQLAssessmentModule,
    "postgresql_assessment": PostgreSQLAssessmentModule,
    "erp_assessment": ERPAssessmentModule,
    "privesc_pathfinder": PrivescPathfinderModule,
}


def setup_logging(verbose: bool) -> None:
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )


@click.group()
@click.version_option(version=__version__)
def main() -> None:
    """iescan - Internal Enterprise Security Assessment Scanner.

    Authorized penetration testing tool for internal enterprise environments.
    """
    pass


@main.command()
@click.option("-c", "--config", "config_path", required=True, help="Path to YAML config file")
@click.option("-t", "--target", multiple=True, help="Additional targets (IP/CIDR/hostname)")
@click.option("-m", "--module", multiple=True, help="Specific modules to run")
@click.option("-o", "--output", default="./reports", help="Output directory")
@click.option("--format", "report_format", type=click.Choice(["json", "html", "both"]),
              default="both", help="Report format")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
def scan(
    config_path: str,
    target: tuple[str, ...],
    module: tuple[str, ...],
    output: str,
    report_format: str,
    verbose: bool,
) -> None:
    """Run a security assessment scan."""
    setup_logging(verbose)
    console.print(BANNER.format(version=__version__))

    # Load config
    try:
        config = load_config(config_path)
    except FileNotFoundError:
        console.print(f"[red]Error: Config file not found: {config_path}[/red]")
        sys.exit(1)

    # Add CLI targets to scope
    if target:
        config.scope.hosts.extend(target)

    # Override modules if specified
    if module:
        config.modules = list(module)

    config.output_dir = output

    # Validate engagement
    auth = validate_engagement(config)
    if not auth.authorized:
        console.print(f"[red]Authorization failed: {auth.reason}[/red]")
        sys.exit(1)

    console.print(Panel(
        f"Engagement: [cyan]{config.engagement_id}[/cyan]\n"
        f"Authorization: [cyan]{config.authorization_ref}[/cyan]\n"
        f"Scope: [cyan]{len(config.scope.networks)} networks, "
        f"{len(config.scope.hosts)} hosts, "
        f"{len(config.scope.domains)} domains[/cyan]\n"
        f"Modules: [cyan]{', '.join(config.modules)}[/cyan]",
        title="[bold]Scan Configuration[/bold]",
        border_style="blue",
    ))

    # Build target list
    targets = list(config.scope.hosts)
    from iescan.utils.network import expand_targets
    targets.extend(expand_targets(config.scope.networks))
    # Deduplicate
    targets = list(dict.fromkeys(targets))

    if not targets:
        console.print("[red]No targets resolved. Check your scope configuration.[/red]")
        sys.exit(1)

    console.print(f"\n[bold]Targets:[/bold] {len(targets)} hosts")

    # Register modules
    engine = ScanEngine(config)
    modules_to_run = config.modules

    for mod_name, mod_class in ALL_MODULES.items():
        if "all" in modules_to_run or mod_name in modules_to_run:
            engine.register_module(mod_class(config))

    # Run scan
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Running assessment...", total=None)
        scan_result = engine.run_all(targets)
        progress.update(task, description="[green]Assessment complete!")

    # Display results summary
    _display_results(scan_result)

    # Generate reports
    Path(output).mkdir(parents=True, exist_ok=True)
    timestamp = scan_result.start_time.replace(":", "-").replace("T", "_").rstrip("Z")

    if report_format in ("json", "both"):
        json_path = generate_json_report(
            scan_result, f"{output}/iescan_report_{timestamp}.json"
        )
        console.print(f"[green]JSON report: {json_path}[/green]")

    if report_format in ("html", "both"):
        html_path = generate_html_report(
            scan_result, f"{output}/iescan_report_{timestamp}.html"
        )
        console.print(f"[green]HTML report: {html_path}[/green]")


@main.command()
@click.option("-t", "--target", required=True, help="Target IP/hostname/CIDR")
@click.option("--timeout", default=30, help="Connection timeout in seconds")
@click.option("--threads", default=20, help="Number of scanning threads")
def discover(target: str, timeout: int, threads: int) -> None:
    """Quick network discovery scan."""
    setup_logging(False)
    console.print(BANNER.format(version=__version__))

    from iescan.utils.network import discover_live_hosts, tcp_connect_scan

    console.print(f"[bold]Discovering hosts in {target}...[/bold]\n")

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
        task = progress.add_task("Scanning...", total=None)
        live_hosts = discover_live_hosts([target], timeout=timeout, threads=threads)
        progress.update(task, description=f"Found {len(live_hosts)} live hosts")

    table = Table(title="Live Hosts")
    table.add_column("IP Address", style="cyan")
    table.add_column("Open Ports", style="green")
    table.add_column("Services", style="yellow")

    for host in live_hosts:
        ports = tcp_connect_scan(host, timeout=timeout, threads=threads)
        port_str = ", ".join(str(p.port) for p in ports)
        svc_str = ", ".join(p.service for p in ports if p.service)
        table.add_row(host, port_str, svc_str)

    console.print(table)


@main.command()
@click.option("-t", "--target", required=True, help="Domain Controller IP/hostname")
@click.option("-u", "--username", required=True, help="Domain username")
@click.option("-p", "--password", required=True, help="Password")
@click.option("-d", "--domain", required=True, help="AD domain name")
@click.option("-o", "--output", default="./reports", help="Output directory")
def ad_assess(target: str, username: str, password: str, domain: str, output: str) -> None:
    """Quick Active Directory assessment."""
    setup_logging(False)
    console.print(BANNER.format(version=__version__))

    config = default_config()
    config.engagement_id = "quick-ad-assess"
    config.authorization_ref = "cli-authorized"
    config.credentials.username = username
    config.credentials.password = password
    config.credentials.domain = domain
    config.scope.hosts = [target]
    config.scope.domains = [domain]

    engine = ScanEngine(config)
    ad_modules = [
        ADEnumerationModule(config),
        KerberosAssessmentModule(config),
        GPOAssessmentModule(config),
        TrustAssessmentModule(config),
        PrivescPathfinderModule(config),
    ]
    for mod in ad_modules:
        engine.register_module(mod)

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
        task = progress.add_task("Running AD assessment...", total=None)
        result = engine.run_all([target])
        progress.update(task, description="[green]AD assessment complete!")

    _display_results(result)

    Path(output).mkdir(parents=True, exist_ok=True)
    json_path = generate_json_report(result, f"{output}/ad_assessment.json")
    html_path = generate_html_report(result, f"{output}/ad_assessment.html")
    console.print(f"\n[green]Reports saved to {output}/[/green]")


@main.command()
@click.option("-c", "--config", "config_path", required=True, help="Path to YAML config file")
@click.option("-t", "--target", multiple=True, required=True, help="Targets to assess")
@click.option("--provider", type=click.Choice(["anthropic", "openai", "ollama"]),
              default="anthropic", help="LLM provider for reasoning")
@click.option("--model", default="claude-sonnet-4-5-20241022", help="LLM model name")
@click.option("--api-key", envvar="ANTHROPIC_API_KEY", help="API key (or set env var)")
@click.option("--max-steps", default=20, help="Maximum agent iterations")
@click.option("-o", "--output", default="./reports", help="Output directory")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
def agent(
    config_path: str,
    target: tuple[str, ...],
    provider: str,
    model: str,
    api_key: str,
    max_steps: int,
    output: str,
    verbose: bool,
) -> None:
    """Run an AI-powered agentic assessment.

    The agent uses LLM reasoning to decide which modules to run,
    correlates findings across modules, and generates attack narratives.
    """
    setup_logging(verbose)
    console.print(BANNER.format(version=__version__))

    from iescan.core.agent import PentestAgent
    from iescan.core.reasoning import ReasoningConfig, ReasoningProvider

    # Load config
    try:
        config = load_config(config_path)
    except FileNotFoundError:
        console.print(f"[red]Error: Config file not found: {config_path}[/red]")
        sys.exit(1)

    config.scope.hosts.extend(target)
    config.output_dir = output

    # Validate engagement
    auth = validate_engagement(config)
    if not auth.authorized:
        console.print(f"[red]Authorization failed: {auth.reason}[/red]")
        sys.exit(1)

    # Setup reasoning
    provider_map = {
        "anthropic": ReasoningProvider.ANTHROPIC,
        "openai": ReasoningProvider.OPENAI,
        "ollama": ReasoningProvider.OLLAMA,
    }
    reasoning_config = ReasoningConfig(
        provider=provider_map[provider],
        model=model,
        api_key=api_key or "",
    )

    console.print(Panel(
        f"[cyan]Mode:[/cyan] Agentic Assessment\n"
        f"[cyan]LLM Provider:[/cyan] {provider} ({model})\n"
        f"[cyan]Max Steps:[/cyan] {max_steps}\n"
        f"[cyan]Targets:[/cyan] {', '.join(target)}",
        title="[bold purple]Agentic Assessment[/bold purple]",
        border_style="purple",
    ))

    # Run agentic assessment
    pentest_agent = PentestAgent(config, reasoning_config, max_steps)
    pentest_agent.register_modules(ALL_MODULES)

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
        task = progress.add_task("Running agentic assessment...", total=None)
        session = pentest_agent.run(list(target))
        progress.update(task, description="[green]Agentic assessment complete!")

    # Display agent steps
    steps_table = Table(title="\nAgent Execution Steps")
    steps_table.add_column("#", width=4)
    steps_table.add_column("Module", width=25)
    steps_table.add_column("Target", width=20)
    steps_table.add_column("Reasoning", width=50)
    steps_table.add_column("Findings", width=10)

    for step in session.steps:
        finding_count = len(step.result.findings) if step.result else 0
        steps_table.add_row(
            str(step.step_number),
            step.module_name,
            step.target,
            step.reasoning[:50] + "..." if len(step.reasoning) > 50 else step.reasoning,
            str(finding_count),
        )

    console.print(steps_table)

    # Display correlations
    if session.cross_correlations:
        console.print(Panel(
            "\n".join(
                f"[red]{c.get('compound_severity', 'unknown').upper()}[/red]: "
                f"{c.get('compound_risk', '')}\n"
                f"  Chain: {c.get('attack_scenario', '')}\n"
                for c in session.cross_correlations[:5]
            ),
            title="[bold red]Cross-Module Correlations[/bold red]",
            border_style="red",
        ))

    # Display executive summary
    if session.executive_summary:
        console.print(Panel(
            session.executive_summary,
            title="[bold]Executive Summary[/bold]",
            border_style="blue",
        ))

    console.print(f"\n[bold]Total Findings:[/bold] {session.total_findings}")
    console.print(f"[bold]Agent Steps:[/bold] {len(session.steps)}")


@main.command()
def mcp() -> None:
    """Start the MCP server for AI-assisted assessments."""
    from iescan.mcp.server import serve

    console.print("[bold purple]Starting iescan MCP server...[/bold purple]")
    console.print("[dim]Awaiting connections via stdio[/dim]")
    asyncio.run(serve())


@main.command()
def modules() -> None:
    """List available assessment modules."""
    console.print(BANNER.format(version=__version__))

    table = Table(title="Available Assessment Modules")
    table.add_column("Module", style="cyan")
    table.add_column("Description", style="white")
    table.add_column("Category", style="yellow")

    categories = {
        "network_discovery": "Network",
        "service_assessment": "Network",
        "ad_enumeration": "Active Directory",
        "kerberos_assessment": "Active Directory",
        "gpo_assessment": "Active Directory",
        "trust_assessment": "Active Directory",
        "share_enumeration": "File Shares",
        "mssql_assessment": "Database",
        "mysql_assessment": "Database",
        "postgresql_assessment": "Database",
        "erp_assessment": "ERP Systems",
        "privesc_pathfinder": "Privilege Escalation",
    }

    for name, mod_class in ALL_MODULES.items():
        mod = mod_class(default_config())
        table.add_row(name, mod.description, categories.get(name, "Other"))

    console.print(table)


def _display_results(scan_result: Any) -> None:
    """Display scan results in a formatted table."""
    console.print()

    # Summary
    severity_colors = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "green",
        "info": "blue",
    }

    summary = Table(title="Assessment Summary", show_header=False)
    summary.add_column("Metric", style="bold")
    summary.add_column("Value")
    summary.add_row("Total Findings", str(scan_result.total_findings))
    summary.add_row("Critical", f"[{severity_colors['critical']}]{scan_result.critical_count}[/]")
    summary.add_row("High", f"[{severity_colors['high']}]{scan_result.high_count}[/]")
    summary.add_row("Medium", f"[{severity_colors['medium']}]{scan_result.medium_count}[/]")
    summary.add_row("Low", f"[{severity_colors['low']}]{scan_result.low_count}[/]")
    summary.add_row("Info", f"[{severity_colors['info']}]{scan_result.info_count}[/]")
    console.print(summary)

    # Findings table
    if scan_result.total_findings > 0:
        findings_table = Table(title="\nFindings")
        findings_table.add_column("Severity", width=10)
        findings_table.add_column("Category", width=25)
        findings_table.add_column("Title", width=50)
        findings_table.add_column("Target", width=20)

        all_findings = []
        for mr in scan_result.module_results:
            all_findings.extend(mr.findings)

        # Sort by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        all_findings.sort(key=lambda f: severity_order.get(f.severity, 5))

        for finding in all_findings:
            color = severity_colors.get(finding.severity.value, "white")
            findings_table.add_row(
                f"[{color}]{finding.severity.value.upper()}[/]",
                finding.category.value,
                finding.title,
                finding.target,
            )

        console.print(findings_table)


if __name__ == "__main__":
    main()
