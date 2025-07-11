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
    
    # Metadata
    timestamp: datetime = field(default_factory=datetime.utcnow)
    remediation_available: bool = False
    description: str = ""
    recommendation: str = ""
    
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
            "timestamp": self.timestamp.isoformat(),
            "remediation_available": self.remediation_available,
            "description": self.description,
            "recommendation": self.recommendation
        }
    
    def to_asff(self) -> Dict[str, Any]:
        """Convert finding to AWS Security Finding Format (ASFF) for Security Hub integration."""
        # Map severity to ASFF format
        severity_mapping = {
            Severity.CRITICAL: {"Label": "CRITICAL", "Normalized": 90},
            Severity.HIGH: {"Label": "HIGH", "Normalized": 70},
            Severity.MEDIUM: {"Label": "MEDIUM", "Normalized": 40},
            Severity.LOW: {"Label": "LOW", "Normalized": 30},
            Severity.INFO: {"Label": "INFORMATIONAL", "Normalized": 0}
        }
        
        # Map status to compliance status
        compliance_status = "PASSED" if self.status == Status.PASS else "FAILED"
        
        return {
            "SchemaVersion": "2018-10-08",
            "Id": f"{self.check_id}/{self.resource_id}",
            "ProductArn": f"arn:aws:securityhub:{self.region}:{self.account_id}:product/{self.account_id}/default",
            "GeneratorId": f"aws-security-suite/{self.service}",
            "AwsAccountId": self.account_id,
            "Types": [f"Sensitive Data Identifications/AWS/{self.service.upper()}"],
            "FirstObservedAt": self.timestamp.isoformat() + "Z",
            "LastObservedAt": self.timestamp.isoformat() + "Z",
            "CreatedAt": self.timestamp.isoformat() + "Z",
            "UpdatedAt": self.timestamp.isoformat() + "Z",
            "Severity": severity_mapping[self.severity],
            "Title": self.check_title,
            "Description": self.description,
            "Remediation": {
                "Recommendation": {
                    "Text": self.recommendation,
                    "Url": f"https://docs.aws.amazon.com/{self.service}/"
                }
            },
            "Resources": [
                {
                    "Id": self.resource_id,
                    "Type": f"AWS{self.service.upper()}",
                    "Region": self.region,
                    "Details": {
                        "Other": {
                            "resourceName": self.resource_name,
                            "checkId": self.check_id,
                            "remediationAvailable": str(self.remediation_available),
                            **self.context
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": compliance_status,
                "RelatedRequirements": self.compliant_controls
            },
            "RecordState": "ACTIVE",
            "WorkflowState": "NEW"
        }


@dataclass
class ScanResult:
    """Container for scan results from one or more services."""
    findings: List[Finding] = field(default_factory=list)
    scan_timestamp: datetime = field(default_factory=datetime.utcnow)
    account_id: str = ""
    regions_scanned: List[str] = field(default_factory=list)
    services_scanned: List[str] = field(default_factory=list)
    
    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the results."""
        self.findings.append(finding)
    
    def get_findings_by_service(self, service: str) -> List[Finding]:
        """Get all findings for a specific service."""
        return [f for f in self.findings if f.service == service]
    
    def get_critical_findings(self) -> List[Finding]:
        """Get all critical findings."""
        return [f for f in self.findings if f.severity == Severity.CRITICAL]
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of scan results."""
        from datetime import datetime
        
        # Calculate scan duration
        now = datetime.utcnow()
        duration = (now - self.scan_timestamp).total_seconds()
        
        # Count by severity
        severity_counts = {}
        for severity in Severity:
            severity_counts[severity.value] = len([f for f in self.findings if f.severity == severity])
        
        # Count by status  
        status_counts = {}
        for status in Status:
            status_counts[status.value] = len([f for f in self.findings if f.status == status])
        
        return {
            "total_findings": len(self.findings),
            "scan_duration_seconds": duration,
            "by_severity": severity_counts,
            "by_status": status_counts,
            "services_scanned": self.services_scanned,
            "regions_scanned": self.regions_scanned,
            "account_id": self.account_id,
            "scan_timestamp": self.scan_timestamp.isoformat()
        }