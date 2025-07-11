"""
Core Finding dataclass for unified AWS security scanning.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any
from datetime import datetime


class Severity(Enum):
    """Finding severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Status(Enum):
    """Finding status."""
    FAIL = "FAIL"
    PASS = "PASS"
    WARNING = "WARNING"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass
class Finding:
    """Unified finding structure for all AWS security scanners."""
    # Core identification
    service: str                    # "s3", "iam", "ec2"
    resource_id: str               # Resource ARN or unique identifier
    resource_name: str             # Human-readable resource name
    check_id: str                  # Unique check identifier
    check_title: str               # Human-readable check description
    
    # Assessment results
    status: Status
    severity: Severity
    
    # Context and evidence
    region: str
    account_id: str
    context: Dict[str, Any] = field(default_factory=dict)
    evidence: Dict[str, Any] = field(default_factory=dict)
    
    # Compliance mapping
    compliant_controls: List[str] = field(default_factory=list)
    
    # Remediation
    remediation: Dict[str, Any] = field(default_factory=dict)
    
    # Metadata
    timestamp: datetime = field(default_factory=datetime.utcnow)
    scanner_version: str = "1.0"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for serialization."""
        return {
            "service": self.service,
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "check_id": self.check_id,
            "check_title": self.check_title,
            "status": self.status.value,
            "severity": self.severity.value,
            "region": self.region,
            "account_id": self.account_id,
            "context": self.context,
            "evidence": self.evidence,
            "compliant_controls": self.compliant_controls,
            "remediation": self.remediation,
            "timestamp": self.timestamp.isoformat(),
            "scanner_version": self.scanner_version
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Finding':
        """Create finding from dictionary."""
        return cls(
            service=data["service"],
            resource_id=data["resource_id"],
            resource_name=data["resource_name"],
            check_id=data["check_id"],
            check_title=data["check_title"],
            status=Status(data["status"]),
            severity=Severity(data["severity"]),
            region=data["region"],
            account_id=data["account_id"],
            context=data.get("context", {}),
            evidence=data.get("evidence", {}),
            compliant_controls=data.get("compliant_controls", []),
            remediation=data.get("remediation", {}),
            timestamp=datetime.fromisoformat(data.get("timestamp", datetime.utcnow().isoformat())),
            scanner_version=data.get("scanner_version", "1.0")
        )


@dataclass
class ScanResult:
    """Container for scan results from all services."""
    account_id: str
    regions_scanned: List[str] = field(default_factory=list)
    services_scanned: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    scan_duration_seconds: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the results."""
        self.findings.append(finding)
    
    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        """Get all findings of a specific severity."""
        return [f for f in self.findings if f.severity == severity]
    
    def get_findings_by_service(self, service: str) -> List[Finding]:
        """Get all findings for a specific service."""
        return [f for f in self.findings if f.service == service]
    
    def get_findings_by_status(self, status: Status) -> List[Finding]:
        """Get all findings with a specific status."""
        return [f for f in self.findings if f.status == status]
    
    @property
    def total_findings(self) -> int:
        """Total number of findings."""
        return len(self.findings)
    
    @property
    def failed_findings(self) -> int:
        """Number of failed findings."""
        return len([f for f in self.findings if f.status == Status.FAIL])
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to dictionary."""
        return {
            "account_id": self.account_id,
            "regions_scanned": self.regions_scanned,
            "services_scanned": self.services_scanned,
            "findings": [f.to_dict() for f in self.findings],
            "scan_duration_seconds": self.scan_duration_seconds,
            "timestamp": self.timestamp.isoformat(),
            "summary": {
                "total_findings": self.total_findings,
                "failed_findings": self.failed_findings,
                "by_severity": {
                    severity.value: len(self.get_findings_by_severity(severity))
                    for severity in Severity
                },
                "by_status": {
                    status.value: len(self.get_findings_by_status(status))
                    for status in Status
                }
            }
        }
