#!/usr/bin/env python3
"""
AWS Security Suite CLI
Unified CLI for AWS security scanning and compliance checking.
"""

import asyncio
import sys
import logging
import re
from typing import List, Optional
import typer
from rich.console import Console
from rich.table import Table
from rich import print

from core.audit_context import AuditContext
from core.scanner import Scanner
from core.finding import Severity, Status
from plugins.s3 import register as s3_register
from plugins.iam import register as iam_register
from plugins.ec2 import register as ec2_register
from plugins.rds import register as rds_register
from plugins.lambda_func import register as lambda_register

# Initialize rich console for beautiful output
console = Console()
app = typer.Typer(help="AWS Security Suite - Unified security scanning and compliance")

# SECURITY: Define allowed values for input validation
ALLOWED_SERVICES = {'s3', 'ec2', 'iam', 'rds', 'lambda'}
ALLOWED_REGIONS = {
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1',
    'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2'
}
ALLOWED_OUTPUT_FORMATS = {'table', 'json', 'csv'}
ALLOWED_SEVERITY_LEVELS = {'critical', 'high', 'medium', 'low', 'all'}
REGION_PATTERN = re.compile(r'^[a-z]{2}-[a-z]+-\d{1}$')


def setup_logging(verbose: bool = False):
    """
    Configure logging for the AWS Security Suite CLI.
    
    Args:
        verbose (bool): If True, enables DEBUG level logging. 
                       If False, uses INFO level logging.
    
    Time Complexity: O(1) - Simple configuration setup
    
    Note:
        This function configures the root logger with a standardized format
        that includes timestamp, logger name, level, and message.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


@app.command()
def scan(
    services: Optional[str] = typer.Option(
        None, 
        "--services", 
        help="Comma-separated list of services to scan (default: all)"
    ),
    regions: Optional[str] = typer.Option(
        None,
        "--regions", 
        help="Comma-separated list of regions to scan (default: us-east-1)"
    ),
    profile: Optional[str] = typer.Option(
        None,
        "--profile",
        help="AWS profile to use"
    ),
    output_format: str = typer.Option(
        "table",
        "--format",
        help="Output format: table, json, csv"
    ),
    severity_filter: str = typer.Option(
        "all",
        "--severity",
        help="Filter by severity: critical, high, medium, low, all"
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        help="Enable verbose logging"
    )
):
    """
    Main CLI command to scan AWS services for security vulnerabilities.
    
    This command orchestrates the entire security scanning process by:
    1. Setting up logging configuration
    2. Parsing command-line arguments
    3. Creating an audit context with AWS credentials
    4. Registering all available security plugins
    5. Running scans across specified services and regions
    6. Filtering and displaying results
    
    Args:
        services (Optional[str]): Comma-separated AWS services to scan.
                                 If None, scans all registered services.
        regions (Optional[str]): AWS regions to scan. Defaults to 'us-east-1'.
        profile (Optional[str]): AWS CLI profile to use for authentication.
        output_format (str): Output format - 'table', 'json', or 'csv'.
        severity_filter (str): Filter results by severity level.
        verbose (bool): Enable detailed logging output.
    
    Time Complexity: O(n*m*k) where:
        - n = number of services
        - m = number of regions  
        - k = average number of resources per service
    
    Raises:
        SystemExit: If scanning fails and verbose=False
        Exception: If scanning fails and verbose=True (for debugging)
    
    Call Flow:
        scan() -> setup_logging() -> AuditContext() -> Scanner() ->
        scanner.scan_all_services() -> display_*() functions -> display_summary()
    """
    setup_logging(verbose)
    
    # SECURITY: Validate and parse services and regions
    service_list = None
    if services:
        service_list = validate_services(services)
    
    region_list = ['us-east-1']  # Default region
    if regions:
        region_list = validate_regions(regions)
    
    # SECURITY: Validate output format and severity filter
    if output_format not in ALLOWED_OUTPUT_FORMATS:
        console.print(f"[red]Invalid output format: {output_format}. Allowed: {', '.join(ALLOWED_OUTPUT_FORMATS)}[/red]")
        raise typer.Exit(1)
    
    if severity_filter not in ALLOWED_SEVERITY_LEVELS:
        console.print(f"[red]Invalid severity filter: {severity_filter}. Allowed: {', '.join(ALLOWED_SEVERITY_LEVELS)}[/red]")
        raise typer.Exit(1)
    
    # Create audit context
    context = AuditContext(
        profile_name=profile,
        regions=region_list,
        services=service_list or []
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
        console.print(f"Services: {', '.join(service_list or scanner.registry.list_services())}")
        
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
            console.print(f"[red]Unsupported output format: {output_format}[/red]")
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
    """
    Display security findings in a formatted table using Rich library.
    
    Args:
        findings (List[Finding]): List of security findings to display.
    
    Time Complexity: O(n) where n is the number of findings
    
    Call Flow:
        Called by scan() -> Creates Rich Table -> Adds columns -> 
        Iterates findings -> Applies color coding -> Prints table
    
    Note:
        Uses color coding for severity levels:
        - CRITICAL: bold red
        - HIGH: red  
        - MEDIUM: yellow
        - LOW: blue
        - INFO: dim
    """
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
            "INFO": "[dim]"
        }.get(finding.severity.value, "")
        
        status_color = {
            "FAIL": "[red]",
            "PASS": "[green]",
            "WARNING": "[yellow]"
        }.get(finding.status.value, "")
        
        table.add_row(
            finding.service,
            finding.resource_name,
            finding.check_title,
            f"{severity_color}{finding.severity.value}[/]",
            f"{status_color}{finding.status.value}[/]",
            finding.region
        )
    
    console.print(table)


def display_json(findings):
    """
    Display security findings in JSON format for programmatic consumption.
    
    Args:
        findings (List[Finding]): List of security findings to serialize.
    
    Time Complexity: O(n) where n is the number of findings
    
    Call Flow:
        Called by scan() -> Converts findings to dict -> JSON serialization -> Print
    
    Note:
        Uses default=str to handle non-serializable objects like datetime.
    """
    import json
    data = [f.to_dict() for f in findings]
    print(json.dumps(data, indent=2, default=str))


def display_summary(result):
    """
    Display a comprehensive summary of the security scan results.
    
    Args:
        result (ScanResult): The scan result object containing findings and metadata.
    
    Time Complexity: O(n) where n is the number of findings (for summary calculation)
    
    Call Flow:
        Called by scan() -> result.get_summary() -> Console formatting -> Print summary
    
    Summary includes:
        - Total number of findings
        - Scan duration in seconds
        - Breakdown by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        - Breakdown by status (FAIL, PASS, WARNING)
    """
    summary = result.get_summary()
    
    console.print("\n[bold]Scan Summary[/bold]")
    console.print(f"Total Findings: {summary['total_findings']}")
    console.print(f"Scan Duration: {summary['scan_duration_seconds']:.2f} seconds")
    
    # Severity breakdown
    console.print("\n[bold]By Severity:[/bold]")
    for severity, count in summary['by_severity'].items():
        if count > 0:
            console.print(f"  {severity}: {count}")
    
    # Status breakdown
    console.print("\n[bold]By Status:[/bold]")
    for status, count in summary['by_status'].items():
        if count > 0:
            console.print(f"  {status}: {count}")


@app.command()
def list_services():
    """
    List all available AWS services that can be scanned by the security suite.
    
    Time Complexity: O(n) where n is the number of registered plugins
    
    Call Flow:
        list_services() -> Creates AuditContext() -> Scanner() -> 
        Registers all plugins -> scanner.registry.list_services() -> Print services
    
    Note:
        This command temporarily creates a scanner instance to enumerate
        all registered plugins without performing any actual scanning.
    """
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
        help="Comma-separated list of services (default: all)"
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
    """Validate and parse comma-separated service names.
    
    Args:
        services_str: Comma-separated string of service names
        
    Returns:
        List of validated service names
        
    Raises:
        typer.Exit: If any service name is invalid
    """
    if not services_str or not services_str.strip():
        return []
    
    services = [s.strip().lower() for s in services_str.split(',')]
    invalid_services = [s for s in services if s not in ALLOWED_SERVICES]
    
    if invalid_services:
        console.print(f"[red]Invalid services: {', '.join(invalid_services)}[/red]")
        console.print(f"[red]Allowed services: {', '.join(sorted(ALLOWED_SERVICES))}[/red]")
        raise typer.Exit(1)
    
    return services


def validate_regions(regions_str: str) -> List[str]:
    """Validate and parse comma-separated region names.
    
    Args:
        regions_str: Comma-separated string of region names
        
    Returns:
        List of validated region names
        
    Raises:
        typer.Exit: If any region name is invalid
    """
    if not regions_str or not regions_str.strip():
        return ['us-east-1']
    
    regions = [r.strip().lower() for r in regions_str.split(',')]
    
    # Validate against known regions and pattern
    invalid_regions = []
    for region in regions:
        if region not in ALLOWED_REGIONS and not REGION_PATTERN.match(region):
            invalid_regions.append(region)
    
    if invalid_regions:
        console.print(f"[red]Invalid regions: {', '.join(invalid_regions)}[/red]")
        console.print(f"[red]Region format should match: xx-xxxxx-N (e.g., us-east-1)[/red]")
        raise typer.Exit(1)
    
    return regions


if __name__ == "__main__":
    app()