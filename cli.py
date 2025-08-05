#!/usr/bin/env python3
"""
AWS Security Suite CLI
Unified CLI for AWS security scanning and compliance checking.
"""

import asyncio
import logging
import re
import sys
from typing import List, Optional

import typer
from rich import print
from rich.console import Console
from rich.table import Table

from core.audit_context import AuditContext
from core.finding import Severity
from core.scanner import Scanner
from plugins.ec2 import register as ec2_register
from plugins.iam import register as iam_register
from plugins.lambda_func import register as lambda_register
from plugins.rds import register as rds_register
from plugins.s3 import register as s3_register

# Initialize rich console for beautiful output
console = Console()
app = typer.Typer(
    help="AWS Security Suite - Unified security scanning and compliance"
)

# SECURITY: Define allowed values for input validation
ALLOWED_SERVICES = {"s3", "ec2", "iam", "rds", "lambda"}
ALLOWED_REGIONS = {
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-central-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
    "ap-northeast-2",
}
ALLOWED_OUTPUT_FORMATS = {"table", "json", "csv"}
ALLOWED_SEVERITY_LEVELS = {"critical", "high", "medium", "low", "all"}
REGION_PATTERN = re.compile(r"^[a-z]{2}-[a-z]+-\d{1}$")


def setup_logging(verbose: bool = False):
    """Configure logging for the AWS Security Suite CLI."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


@app.command()
def scan(
    services: Optional[str] = typer.Option(
        None,
        "--services",
        help="Comma-separated list of services to scan (default: all)",
    ),
    regions: Optional[str] = typer.Option(
        None,
        "--regions",
        help="Comma-separated list of regions to scan (default: us-east-1)",
    ),
    profile: Optional[str] = typer.Option(
        None, "--profile", help="AWS profile to use"
    ),
    output_format: str = typer.Option(
        "table", "--format", help="Output format: table, json, csv"
    ),
    severity_filter: str = typer.Option(
        "all",
        "--severity",
        help="Filter by severity: critical, high, medium, low, all",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", help="Enable verbose logging"
    ),
):
    """Main CLI command to scan AWS services for security vulnerabilities."""
    setup_logging(verbose)

    # SECURITY: Validate and parse services and regions
    service_list = None
    if services:
        service_list = validate_services(services)

    region_list = ["us-east-1"]  # Default region
    if regions:
        region_list = validate_regions(regions)

    # SECURITY: Validate output format and severity filter
    if output_format not in ALLOWED_OUTPUT_FORMATS:
        console.print(
            f"[red]Invalid output format: {output_format}. "
            f"Allowed: {', '.join(ALLOWED_OUTPUT_FORMATS)}[/red]"
        )
        raise typer.Exit(1)

    if severity_filter not in ALLOWED_SEVERITY_LEVELS:
        console.print(
            f"[red]Invalid severity filter: {severity_filter}. "
            f"Allowed: {', '.join(ALLOWED_SEVERITY_LEVELS)}[/red]"
        )
        raise typer.Exit(1)

    # Create audit context
    context = AuditContext(
        profile_name=profile, regions=region_list, services=service_list or []
    )

    # Create scanner and register plugins
    scanner = Scanner(context)
    scanner.registry.register(s3_register())
    scanner.registry.register(iam_register())
    scanner.registry.register(ec2_register())
    scanner.registry.register(rds_register())
    scanner.registry.register(lambda_register())

    try:
        # Run scan
        console.print("[bold blue]Starting AWS Security Scan...[/bold blue]")
        console.print(f"Account: {context.account_id}")
        console.print(f"Regions: {', '.join(region_list)}")
        services_list = service_list or scanner.registry.list_services()
        console.print(f"Services: {', '.join(services_list)}")

        result = asyncio.run(scanner.scan_all_services(service_list))

        # Filter findings by severity
        findings = result.findings
        if severity_filter != "all":
            severity_enum = getattr(Severity, severity_filter.upper())
            findings = [f for f in findings if f.severity == severity_enum]

        # Display results
        if output_format == "table":
            display_table(findings)
        elif output_format == "json":
            display_json(findings)
        else:
            console.print(
                f"[red]Unsupported output format: {output_format}[/red]"
            )
            return

        # Display summary
        display_summary(result)

    except Exception as e:
        # SECURITY: Avoid information disclosure in error messages
        error_msg = "An error occurred during scanning"
        if verbose:
            error_msg = f"Scan failed: {str(e)}"
        console.print(f"[red]{error_msg}[/red]")
        if verbose:
            raise
        sys.exit(1)


def display_table(findings):
    """Display security findings in a formatted table using Rich library."""
    table = Table(title="AWS Security Findings")

    table.add_column("Service", style="cyan")
    table.add_column("Resource", style="blue")
    table.add_column("Check", style="magenta")
    table.add_column("Severity", style="red")
    table.add_column("Status", style="green")
    table.add_column("Region", style="yellow")

    for finding in findings:
        # Color code severity
        severity_color = {
            "CRITICAL": "[bold red]",
            "HIGH": "[red]",
            "MEDIUM": "[yellow]",
            "LOW": "[blue]",
            "INFO": "[dim]",
        }.get(finding.severity.value, "")

        status_color = {
            "FAIL": "[red]",
            "PASS": "[green]",
            "WARNING": "[yellow]",
        }.get(finding.status.value, "")

        table.add_row(
            finding.service,
            finding.resource_name,
            finding.check_title,
            f"{severity_color}{finding.severity.value}[/]",
            f"{status_color}{finding.status.value}[/]",
            finding.region,
        )

    console.print(table)


def display_json(findings):
    """Display security findings in JSON format for consumption."""
    import json

    data = [f.to_dict() for f in findings]
    print(json.dumps(data, indent=2, default=str))


def display_summary(result):
    """Display a comprehensive summary of the security scan results."""
    summary = result.get_summary()

    console.print("\n[bold]Scan Summary[/bold]")
    console.print(f"Total Findings: {summary['total_findings']}")
    console.print(
        f"Scan Duration: {summary['scan_duration_seconds']:.2f} seconds"
    )

    # Severity breakdown
    console.print("\n[bold]By Severity:[/bold]")
    for severity, count in summary["by_severity"].items():
        if count > 0:
            console.print(f"  {severity}: {count}")

    # Status breakdown
    console.print("\n[bold]By Status:[/bold]")
    for status, count in summary["by_status"].items():
        if count > 0:
            console.print(f"  {status}: {count}")


@app.command()
def list_services():
    """List all available AWS services that can be scanned."""
    # Create scanner to get registered services
    context = AuditContext()
    scanner = Scanner(context)
    scanner.registry.register(s3_register())
    scanner.registry.register(iam_register())
    scanner.registry.register(ec2_register())
    scanner.registry.register(rds_register())
    scanner.registry.register(lambda_register())

    console.print("[bold]Available Services:[/bold]")
    for service in scanner.registry.list_services():
        console.print(f"  - {service}")


@app.command()
def permissions(
    services: Optional[str] = typer.Option(
        None,
        "--services",
        help="Comma-separated list of services (default: all)",
    )
):
    """Show required AWS permissions for scanning."""
    context = AuditContext()
    scanner = Scanner(context)
    scanner.registry.register(s3_register())
    scanner.registry.register(iam_register())
    scanner.registry.register(ec2_register())
    scanner.registry.register(rds_register())
    scanner.registry.register(lambda_register())

    # SECURITY: Validate services before processing
    service_list = None
    if services:
        service_list = validate_services(services)
    perms = scanner.registry.get_required_permissions(service_list)

    console.print("[bold]Required AWS Permissions:[/bold]")
    for perm in perms:
        console.print(f"  - {perm}")


def validate_services(services_str: str) -> List[str]:
    """Validate and parse comma-separated service names."""
    if not services_str or not services_str.strip():
        return []

    services = [s.strip().lower() for s in services_str.split(",")]
    invalid_services = [s for s in services if s not in ALLOWED_SERVICES]

    if invalid_services:
        console.print(
            f"[red]Invalid services: {', '.join(invalid_services)}[/red]"
        )
        allowed_services = ", ".join(sorted(ALLOWED_SERVICES))
        console.print(f"[red]Allowed services: {allowed_services}[/red]")
        raise typer.Exit(1)

    return services


def validate_regions(regions_str: str) -> List[str]:
    """Validate and parse comma-separated region names."""
    if not regions_str or not regions_str.strip():
        return ["us-east-1"]

    regions = [r.strip().lower() for r in regions_str.split(",")]

    # Validate against known regions and pattern
    invalid_regions = []
    for region in regions:
        if region not in ALLOWED_REGIONS and not REGION_PATTERN.match(region):
            invalid_regions.append(region)

    if invalid_regions:
        console.print(
            f"[red]Invalid regions: {', '.join(invalid_regions)}[/red]"
        )
        console.print(
            "[red]Region format should match: xx-xxxxx-N "
            "(e.g., us-east-1)[/red]"
        )
        raise typer.Exit(1)

    return regions


if __name__ == "__main__":
    app()
