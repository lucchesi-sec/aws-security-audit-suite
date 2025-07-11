# AWS Security Suite

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

# Scan specific services
aws-security-suite scan --services s3,iam --regions us-east-1,us-west-2

# Filter by severity
aws-security-suite scan --severity critical

# JSON output
aws-security-suite scan --format json

# List available services
aws-security-suite list-services

# Show required permissions
aws-security-suite permissions
```

## Supported Services

### Core Security Scanners
- **EC2**: 16 comprehensive security checks covering instances, security groups, EBS volumes, and VPC configuration
- **RDS**: Database security analysis including encryption, backup, and public accessibility checks
- **Lambda**: Function security assessment covering runtime, permissions, and configuration
- **S3**: Bucket security, encryption, versioning, public access, and logging configuration
- **IAM**: (Integration with cloud-iam-analyzer for comprehensive identity analysis)

### Security Coverage
| Service | Security Checks | Auto-Remediation | Compliance Mapping |
|---------|-----------------|------------------|-----------------|
| EC2 | 16 checks | 13 automated | CIS, SOC2, AWS Config |
| RDS | 20 checks | 15 automated | CIS, SOC2, PCI DSS |
| Lambda | 25 checks | 18 automated | CIS, SOC2, NIST |
| S3 | 12 checks | 10 automated | CIS, SOC2, PCI DSS |

## Roadmap

### Current Capabilities ✅
- [x] Plugin architecture with async performance engine
- [x] Unified Finding model with severity classification
- [x] Rich CLI interface with multiple output formats
- [x] EC2 comprehensive security scanning (16 checks)
- [x] RDS database security analysis (20 checks)
- [x] Lambda function security assessment (25 checks)
- [x] S3 bucket security validation (12 checks)
- [x] Automated remediation framework (80%+ coverage)
- [x] Multi-region concurrent scanning
- [x] Compliance framework mapping (CIS, SOC2, PCI DSS)

### Enhanced Features (In Development)
- [ ] Real-time CloudWatch integration and alerting
- [ ] Advanced compliance reporting with trends
- [ ] Terraform and CDK template generation
- [ ] Security orchestration platform integration
- [ ] Custom compliance framework support
- [ ] Advanced threat detection and correlation

## Documentation

- **[Installation Guide](./INSTALLATION_GUIDE.md)** - Detailed setup and configuration instructions
- **[User Guide](./USER_GUIDE.md)** - Comprehensive usage documentation and examples
- **[Troubleshooting](./TROUBLESHOOTING.md)** - Common issues and solutions
- **[Security](./SECURITY.md)** - Security considerations and best practices
- **[Compliance Mapping](./COMPLIANCE_MAPPING.md)** - Framework mappings and control references
- **[Implementation Report](./EC2_SECURITY_IMPLEMENTATION_REPORT.md)** - Detailed EC2 security implementation
- **[Security Fixes Summary](./SECURITY_FIXES_SUMMARY.md)** - Summary of security enhancements
- **[Async Foundation](./ASYNC_FOUNDATION_IMPLEMENTATION.md)** - Technical implementation details

## Development

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black .
isort .

# Type checking
mypy .
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - see LICENSE file for details.