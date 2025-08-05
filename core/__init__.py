"""AWS Security Suite Core Module

This module provides the foundational components for AWS security scanning,
including the audit context, scanner engine, plugin system, and finding models.
"""

__version__ = "0.1.0"
__author__ = "Security Engineering Team"

# Core module exports
from .audit_context import AuditContext
from .finding import Finding, Severity, Status
from .plugin import Plugin, PluginRegistry
from .scanner import Scanner

__all__ = [
    "AuditContext",
    "Scanner",
    "Finding",
    "Severity",
    "Status",
    "Plugin",
    "PluginRegistry",
]
