"""
Plugin system for AWS Security Suite.
Provides registry and interface for security scanning plugins.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .audit_context import AuditContext
from .finding import Finding


@dataclass
class Plugin:
    """
    Plugin definition for AWS service security scanners.

    Each plugin represents a security scanner for a specific AWS service
    and defines the interface for executing security checks.
    """

    service: str  # AWS service name (e.g., 's3', 'ec2')
    name: str  # Human-readable plugin name
    description: str  # Plugin description
    scan_function: Callable  # Async function that performs the scan
    required_permissions: List[str]  # AWS permissions needed for scanning
    compliance_frameworks: List[str] = field(
        default_factory=list
    )  # Supported frameworks
    version: str = "1.0.0"  # Plugin version

    def __post_init__(self):
        # Ensure lists are unique and sorted for consistency
        self.required_permissions = sorted(set(self.required_permissions))
        self.compliance_frameworks = sorted(set(self.compliance_frameworks))


class PluginRegistry:
    """
    Registry for managing and executing security scanning plugins.

    Provides centralized management of all available security plugins,
    handles plugin registration, and orchestrates plugin execution.
    """

    def __init__(self):
        self._plugins: Dict[str, Plugin] = {}
        self.logger = logging.getLogger(__name__)

    def register(self, plugin: Plugin) -> None:
        """
        Register a security scanning plugin.

        Args:
            plugin: Plugin instance to register

        Raises:
            ValueError: If plugin service is already registered
        """
        if plugin.service in self._plugins:
            self.logger.warning(
                f"Plugin for {plugin.service} already registered, overwriting"
            )

        self._plugins[plugin.service] = plugin
        self.logger.info(
            f"Registered plugin: {plugin.name} ({plugin.service})"
        )

    def get_plugin(self, service: str) -> Optional[Plugin]:
        """
        Get a registered plugin by service name.

        Args:
            service: AWS service name

        Returns:
            Plugin instance if found, None otherwise
        """
        return self._plugins.get(service)

    def list_services(self) -> List[str]:
        """
        Get list of all registered service names.

        Returns:
            List of AWS service names with registered plugins
        """
        return list(self._plugins.keys())

    def list_plugins(self) -> List[Plugin]:
        """
        Get list of all registered plugins.

        Returns:
            List of all registered Plugin instances
        """
        return list(self._plugins.values())

    def get_required_permissions(
        self, services: Optional[List[str]] = None
    ) -> List[str]:
        """
        Get all required AWS permissions for specified services.

        Args:
            services: List of service names. If None, returns for all services.

        Returns:
            Consolidated list of unique AWS permissions
        """
        permissions = set()

        target_services = services or self.list_services()

        for service in target_services:
            plugin = self.get_plugin(service)
            if plugin:
                permissions.update(plugin.required_permissions)

        return sorted(list(permissions))

    def get_compliance_frameworks(
        self, services: Optional[List[str]] = None
    ) -> List[str]:
        """
        Get all supported compliance frameworks for specified services.

        Args:
            services: List of service names. If None, returns for all services.

        Returns:
            Consolidated list of unique compliance frameworks
        """
        frameworks = set()

        target_services = services or self.list_services()

        for service in target_services:
            plugin = self.get_plugin(service)
            if plugin and plugin.compliance_frameworks:
                frameworks.update(plugin.compliance_frameworks)

        return sorted(list(frameworks))

    async def execute_plugin(
        self, service: str, context: AuditContext
    ) -> List[Finding]:
        """
        Execute a specific plugin's scan function.

        Args:
            service: AWS service name
            context: Audit context with AWS credentials and configuration

        Returns:
            List of security findings from the plugin

        Raises:
            ValueError: If plugin not found
            Exception: If plugin execution fails
        """
        plugin = self.get_plugin(service)
        if not plugin:
            raise ValueError(f"Plugin not found for service: {service}")

        try:
            self.logger.info(f"Executing plugin: {plugin.name}")

            # Execute the plugin's scan function
            if asyncio.iscoroutinefunction(plugin.scan_function):
                findings = await plugin.scan_function(context)
            else:
                # Wrap synchronous functions in async using modern approach
                import sys

                if sys.version_info >= (3, 9):
                    findings = await asyncio.to_thread(
                        plugin.scan_function, context
                    )
                else:
                    loop = asyncio.get_running_loop()
                    findings = await loop.run_in_executor(
                        None, plugin.scan_function, context
                    )

            self.logger.info(
                f"Plugin {plugin.name} completed with "
                f"{len(findings or [])} findings"
            )
            return findings or []

        except Exception as e:
            self.logger.error(f"Plugin {plugin.name} failed: {e}")
            return []

    def validate_plugins(self) -> Dict[str, List[str]]:
        """
        Validate all registered plugins for common issues.

        Returns:
            Dictionary mapping plugin services to lists of validation errors
        """
        validation_results = {}

        for service, plugin in self._plugins.items():
            errors = []

            # Check required fields
            if not plugin.name:
                errors.append("Plugin name is required")

            if not plugin.description:
                errors.append("Plugin description is required")

            if not plugin.scan_function:
                errors.append("Plugin scan_function is required")

            if not plugin.required_permissions:
                errors.append(
                    "Plugin required_permissions should not be empty"
                )

            # Check scan function signature
            if plugin.scan_function:
                import inspect

                sig = inspect.signature(plugin.scan_function)
                if len(sig.parameters) != 1:
                    errors.append(
                        "Scan function must accept exactly one parameter "
                        "(AuditContext)"
                    )

            if errors:
                validation_results[service] = errors

        return validation_results
