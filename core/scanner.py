"""
Main scanner orchestration engine.
"""

from __future__ import annotations

import asyncio
import time
from typing import List, Optional

from .audit_context import AuditContext
from .finding import Finding, ScanResult
from .logger import get_logger
from .plugin import PluginRegistry

__all__ = [
    "Scanner",
]


class Scanner:  # noqa: D101 – simple orchestration class
    def __init__(self, context: AuditContext) -> None:
        self.context: AuditContext = context
        self.registry: PluginRegistry = PluginRegistry()
        self.logger = get_logger(__name__)

    async def scan_all_services(
        self, services: Optional[List[str]] = None
    ) -> ScanResult:
        """Scan all or the provided *services*."""
        start_time = time.time()

        services = services or self.registry.list_services()

        result = ScanResult(
            account_id=self.context.account_id,
            regions_scanned=self.context.regions.copy(),
            services_scanned=services.copy(),
        )

        tasks = [
            self._scan_service(svc)
            for svc in services
            if svc in self.registry.list_services()
        ]

        if tasks:
            findings_lists = await asyncio.gather(
                *tasks, return_exceptions=True
            )
            for findings in findings_lists:
                if isinstance(findings, Exception):
                    self.logger.error("Service scan failed", exc_info=findings)
                    continue
                for finding in findings:  # type: ignore[arg-type]
                    result.add_finding(finding)

        result.scan_duration_seconds = time.time() - start_time
        return result

    async def _scan_service(self, service: str) -> List[Finding]:
        plugin = self.registry.get_plugin(service)
        if plugin is None:
            self.logger.warning("Plugin not found for service %s", service)
            return []

        tasks = [
            self._scan_service_region(plugin, region)
            for region in self.context.regions
        ]
        region_findings = await asyncio.gather(*tasks, return_exceptions=True)

        findings: List[Finding] = []
        for res in region_findings:
            if isinstance(res, Exception):
                self.logger.error(
                    "Region scan failed for %s", service, exc_info=res
                )
                continue
            findings.extend(res)  # type: ignore[arg-type]
        return findings

    async def _scan_service_region(
        self, plugin, region: str
    ) -> List[Finding]:  # noqa: ANN001, D401
        try:
            region_context = AuditContext(
                profile_name=self.context.profile_name,
                region=region,
                role_arn=self.context.role_arn,
                external_id=self.context.external_id,
                regions=[region],
                services=self.context.services,
            )
            findings = await plugin.scan_function(region_context)
            return findings or []
        except Exception as exc:  # noqa: BLE001 – broad but logged
            self.logger.error(
                "Failed to scan %s in %s", plugin.service, region, exc_info=exc
            )
            return []
