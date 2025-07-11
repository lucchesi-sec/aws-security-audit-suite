# AWS Security Audit Suite

A unified, extensible AWS security scanning and compliance suite that combines multiple security tools into a single, powerful platform.

## Features

- **Unified Plugin Architecture**: Extensible system for scanning multiple AWS services
- **Compliance Frameworks**: Built-in support for CIS, SOC2, and AWS Config Rules
- **Real-time Monitoring**: CloudWatch and EventBridge integration
- **Auto-Remediation**: Safe, controlled fixing of common misconfigurations
- **Policy as Code**: Generate Terraform and CDK templates from findings
- **Rich CLI**: Beautiful, interactive command-line interface

## Architecture

```
┌──────────────┐   plugin bus  ┌──────────────────┐
│  Scan Core   │◀─────────────▶│ Service Plugins  │   (S3, IAM, EC2, RDS, Lambda)
└────┬─────────┘               └──────────────────┘
     │              findings queue       
     ▼                                   
┌──────────────┐   pub/sub    ┌──────────────────┐
│ Compliance   │◀────────────▶│ Real-time Mon.   │  (CloudWatch/EventBridge)
│  Engine      │              └────────┬─────────┘
└────┬─────────┘                       │
     │  mapped controls                │
     ▼                                 │
┌──────────────┐    ▲     remediate    │
│ Report/Export│────┘                  │
│ + IaC Gen.   │                       │
└──────────────┘                       ▼
                                ┌──────────────┐
                                │ Remediation   │
                                │   Engine      │
                                └──────────────┘
```

## Quick Start

### Installation

```bash
pip install -e .
```

### Basic Usage

```bash
# Scan all services in default region
aws-security-suite scan

# Scan specific service
aws-security-suite scan --service s3

# Scan with compliance framework
aws-security-suite scan --compliance cis

# Generate report
aws-security-suite report --format json --output findings.json
```

### Configuration

Create `config.yaml`:
```yaml
aws:
  region: us-west-2
  profile: default
  
scanning:
  parallel_scans: 5
  rate_limit: 10
  
compliance:
  frameworks: ["cis", "soc2"]
  
reporting:
  format: json
  include_remediation: true
```

## Services Supported

### ✅ Currently Supported
- **S3**: Bucket security, encryption, access policies
- **IAM**: User permissions, role analysis, policy validation
- **EC2**: Security groups, instance configuration, AMI scanning
- **RDS**: Database security, encryption, backup policies
- **Lambda**: Function security, environment variables, permissions

### 🚧 Coming Soon
- VPC Security Groups
- CloudTrail Configuration
- KMS Key Management
- Route53 DNS Security
- ELB/ALB Configuration

## Development

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/lucchesi-sec/aws-security-audit-suite.git
cd aws-security-audit-suite

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run security checks
bandit -r .
safety check
```

### Creating a Plugin

```python
from core.plugin import Plugin, Finding
from core.finding import Severity

class CustomServicePlugin(Plugin):
    def __init__(self):
        super().__init__("custom-service", "Custom Service Scanner")
    
    async def scan(self, context):
        # Implement scanning logic
        findings = []
        # ... scanning code ...
        return findings

# Register plugin
register = lambda scanner: scanner.register_plugin(CustomServicePlugin())
```

## Security Features

- **Input Validation**: All user inputs are validated against allowlists
- **Secure Defaults**: Conservative settings and safe scanning practices
- **Rate Limiting**: Prevents API throttling and respects AWS limits
- **Credential Safety**: No credential logging or exposure
- **Audit Logging**: Comprehensive activity logging for compliance

## Compliance Frameworks

### CIS Benchmarks
- CIS AWS Foundations Benchmark v1.4.0
- Automated mapping of findings to controls
- Evidence collection for audits

### SOC2 Type II
- Security control validation
- Availability and confidentiality checks
- Processing integrity verification

### Custom Frameworks
- Define custom compliance rules
- Map findings to internal policies
- Generate compliance reports

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

## License

MIT License - see LICENSE file for details.
