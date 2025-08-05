"""IAM Security Plugin"""

from core.plugin import Plugin


def scan_iam(context):
    """Scan for IAM security issues"""
    # This would be implemented as an async function
    pass


# Create plugin instance
iam_plugin = Plugin(
    service="iam",
    name="IAM Security Scanner",
    description=(
        "Scans for IAM security issues including users with "
        "passwords but no MFA, "
        "unused access keys, and overly permissive policies"
    ),
    scan_function=scan_iam,
    required_permissions=[
        "iam:ListUsers",
        "iam:GetLoginProfile",
        "iam:ListMFADevices",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "iam:ListPolicies",
        "iam:GetPolicyVersion",
    ],
    compliance_frameworks=["cis", "soc2"],
)


def register():
    """Register IAM security checks"""
    return iam_plugin
