# AWS Security Suite - Installation Guide

## Table of Contents
1. [System Requirements](#system-requirements)
2. [Quick Installation](#quick-installation)
3. [Development Installation](#development-installation)
4. [AWS Configuration](#aws-configuration)
5. [Verification](#verification)
6. [Docker Installation](#docker-installation)
7. [Enterprise Deployment](#enterprise-deployment)
8. [Troubleshooting Installation](#troubleshooting-installation)

## System Requirements

### Supported Operating Systems
- **Linux**: Ubuntu 18.04+, CentOS 7+, Amazon Linux 2
- **macOS**: 10.14+ (Mojave and later)
- **Windows**: Windows 10, Windows Server 2016+

### Python Requirements
- **Python**: 3.8 or higher (3.9+ recommended)
- **pip**: 21.0 or higher
- **virtualenv**: Recommended for isolation

### System Dependencies
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install python3 python3-pip python3-venv git

# CentOS/RHEL
sudo yum install python3 python3-pip git

# macOS (using Homebrew)
brew install python git

# Windows (using Chocolatey)
choco install python git
```

## Quick Installation

### Method 1: Git Clone (Recommended)
```bash
# Clone the repository
git clone https://github.com/lucchesi-sec/aws-security-audit-suite.git
cd aws-security-audit-suite

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install the package
pip install -e .
```

### Method 2: Direct Installation
```bash
# Install directly from GitHub
pip install git+https://github.com/lucchesi-sec/aws-security-audit-suite.git
```

## Development Installation

For contributors and developers who want to modify the code:

```bash
# Clone and setup development environment
git clone https://github.com/lucchesi-sec/aws-security-audit-suite.git
cd aws-security-audit-suite

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install in development mode with all dependencies
pip install -e ".[dev,security]"

# Install pre-commit hooks
pre-commit install
```

### Development Dependencies
The development installation includes:
- **Testing**: pytest, pytest-asyncio, pytest-cov, moto
- **Code Quality**: black, isort, flake8, mypy
- **Security**: bandit, safety, semgrep

## AWS Configuration

### Prerequisites
- AWS Account with appropriate permissions
- AWS CLI installed and configured
- Valid AWS credentials

### AWS CLI Setup
```bash
# Install AWS CLI
pip install awscli

# Configure AWS credentials
aws configure
# AWS Access Key ID: [Your Access Key]
# AWS Secret Access Key: [Your Secret Key]
# Default region name: us-east-1
# Default output format: json
```

### Alternative Authentication Methods

#### Environment Variables
```bash
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"
```

#### IAM Roles (Recommended for EC2)
```bash
# No additional configuration needed if running on EC2 with IAM role
aws-security-suite scan --profile default
```

#### Cross-Account Role Assumption
```bash
# For cross-account scanning
aws-security-suite scan --role-arn arn:aws:iam::123456789012:role/SecurityAuditRole
```

### Required AWS Permissions

Minimum permissions required for the security suite:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:Describe*",
                "s3:GetBucket*",
                "s3:GetObject*",
                "s3:ListBucket*",
                "iam:Get*",
                "iam:List*",
                "rds:Describe*",
                "lambda:Get*",
                "lambda:List*",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

To see the complete list of required permissions:
```bash
aws-security-suite permissions
```

## Verification

### Basic Functionality Test
```bash
# Test basic functionality
aws-security-suite list-services

# Expected output:
Available Services:
  - ec2
  - iam
  - lambda
  - rds
  - s3
```

### Quick Scan Test
```bash
# Run a quick scan on S3 only
aws-security-suite scan --services s3 --regions us-east-1
```

### Full Test Suite
```bash
# Run the complete test suite (development installation)
pytest tests/ -v
```

## Docker Installation

### Using Pre-built Image
```bash
# Pull the latest image
docker pull lucchesi-sec/aws-security-suite:latest

# Run with AWS credentials
docker run -e AWS_ACCESS_KEY_ID="your-key" \
           -e AWS_SECRET_ACCESS_KEY="your-secret" \
           -e AWS_DEFAULT_REGION="us-east-1" \
           lucchesi-sec/aws-security-suite:latest scan
```

### Building from Source
```bash
# Clone and build
git clone https://github.com/lucchesi-sec/aws-security-audit-suite.git
cd aws-security-audit-suite

# Build Docker image
docker build -t aws-security-suite .

# Run container
docker run --rm -v ~/.aws:/root/.aws aws-security-suite scan
```

### Docker Compose
```yaml
version: '3.8'
services:
  aws-security-suite:
    image: lucchesi-sec/aws-security-suite:latest
    environment:
      - AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
      - AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
      - AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-us-east-1}
    command: scan --format json
    volumes:
      - ./reports:/app/reports
```

## Enterprise Deployment

### Centralized Installation
```bash
# System-wide installation (requires sudo)
sudo pip install git+https://github.com/lucchesi-sec/aws-security-audit-suite.git

# Create system configuration
sudo mkdir -p /etc/aws-security-suite
sudo cat > /etc/aws-security-suite/config.yaml << EOF
default_regions:
  - us-east-1
  - us-west-2
  - eu-west-1

default_services:
  - ec2
  - s3
  - iam
  - rds
  - lambda

output_format: json
log_level: INFO
EOF
```

### Kubernetes Deployment
```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: aws-security-scan
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: aws-security-suite
            image: lucchesi-sec/aws-security-suite:latest
            command:
            - aws-security-suite
            - scan
            - --format
            - json
            env:
            - name: AWS_DEFAULT_REGION
              value: "us-east-1"
            volumeMounts:
            - name: aws-credentials
              mountPath: /root/.aws
              readOnly: true
          volumes:
          - name: aws-credentials
            secret:
              secretName: aws-credentials
          restartPolicy: OnFailure
```

## Troubleshooting Installation

### Common Issues

#### Python Version Conflicts
```bash
# Check Python version
python3 --version

# If using pyenv
pyenv install 3.9.16
pyenv global 3.9.16
```

#### Permission Errors
```bash
# Use virtual environment instead of system-wide installation
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

#### AWS Credential Issues
```bash
# Verify AWS credentials
aws sts get-caller-identity

# Check AWS configuration
aws configure list

# Test specific service access
aws s3 ls
aws ec2 describe-regions
```

#### Import Errors
```bash
# Ensure all dependencies are installed
pip install -r requirements.txt

# Reinstall in development mode
pip install -e .
```

### Getting Help

- **GitHub Issues**: https://github.com/lucchesi-sec/aws-security-audit-suite/issues
- **Documentation**: https://aws-security-suite.readthedocs.io
- **Troubleshooting Guide**: [TROUBLESHOOTING.md](./TROUBLESHOOTING.md)

### System Information Collection
```bash
# Collect system information for bug reports
python3 -c "
import sys, platform
print(f'Python: {sys.version}')
print(f'Platform: {platform.platform()}')
print(f'Architecture: {platform.architecture()}')
"

pip list | grep -E '(boto3|botocore|aws)'
aws --version
```