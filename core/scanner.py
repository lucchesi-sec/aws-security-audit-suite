"""
Main scanner orchestration engine.
"""

import asyncio
import time
from typing import List, Dict, Any
from .finding import Finding, ScanResult
from .audit_context import AuditContext
from .plugin import PluginRegistry
import logging


class Scanner:
    """Main scanner orchestration engine."""
    
    def __init__(self, context: AuditContext):
        self.context = context
        self.registry = PluginRegistry()
        self.logger = logging.getLogger(__name__)
    
    async def scan_all_services(self, services: List[str] = None) -> ScanResult:
        """Scan all or specified services."""
        start_time = time.time()
        
        if services is None:
            services = self.registry.list_services()
        
        result = ScanResult(
            account_id=self.context.account_id,
            regions_scanned=self.context.regions.copy(),
            services_scanned=services.copy()
        )
        
        # Run all service scans in parallel
        tasks = []
        for service in services:
            if service in self.registry.list_services():
                task = self._scan_service(service)
                tasks.append(task)
        
        if tasks:
            findings_lists = await asyncio.gather(*tasks, return_exceptions=True)
            
            for findings in findings_lists:
                if isinstance(findings, Exception):
                    self.logger.error(f"Service scan failed: {findings}")
                    continue
                
                for finding in findings:
                    result.add_finding(finding)
        
        result.scan_duration_seconds = time.time() - start_time
        return result
    
    async def _scan_service(self, service: str) -> List[Finding]:
        """Scan a single service across all regions."""
        plugin = self.registry.get_plugin(service)
        findings = []
        
        # Run service scan across all configured regions
        tasks = []
        for region in self.context.regions:
            task = self._scan_service_region(plugin, region)
            tasks.append(task)
        
        region_findings = await asyncio.gather(*tasks, return_exceptions=True)
        
        for region_result in region_findings:
            if isinstance(region_result, Exception):
                self.logger.error(f"Region scan failed for {service}: {region_result}")
                continue
            findings.extend(region_result)
        
        return findings
    
    async def _scan_service_region(self, plugin, region: str) -> List[Finding]:
        """Scan a service in a specific region."""
        try:
            # Create region-specific context
            region_context = AuditContext(
                profile_name=self.context.profile_name,
                region=region,
                role_arn=self.context.role_arn,
                external_id=self.context.external_id,
                regions=[region],
                services=self.context.services
            )
            
            # Call the plugin's scan function
            findings = await plugin.scan_function(region_context)
            return findings if findings else []
            
        except Exception as e:
            self.logger.error(f"Failed to scan {plugin.service} in {region}: {e}")
            return []