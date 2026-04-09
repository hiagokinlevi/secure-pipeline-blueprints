# iac_scanner.py — IaC Security Scanner
# Part of Cyber Port · shared/analyzers
#
# Copyright 2024 Hiago Kin Levi
# Licensed under CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/
#
# Offline, production-quality scanner that evaluates normalized IaC resource
# dicts against a fixed catalogue of security checks.  No live API calls are
# made; the module is fully self-contained.

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Check catalogue — maps check_id → weight used in risk_score calculation
# ---------------------------------------------------------------------------
_CHECK_WEIGHTS: Dict[str, int] = {
    "IAC-001": 40,  # Public S3 bucket / public storage account
    "IAC-002": 35,  # Security group with open inbound
    "IAC-003": 25,  # Unencrypted storage / database
    "IAC-004": 40,  # Hardcoded credentials in template
    "IAC-005": 20,  # Admin/root access without MFA condition
    "IAC-006": 20,  # Overly permissive IAM role or firewall rule
    "IAC-007": 5,   # Missing required tags
}

# Severity assigned to each check
_CHECK_SEVERITY: Dict[str, str] = {
    "IAC-001": "CRITICAL",
    "IAC-002": "CRITICAL",
    "IAC-003": "HIGH",
    "IAC-004": "CRITICAL",
    "IAC-005": "HIGH",
    "IAC-006": "HIGH",
    "IAC-007": "LOW",
}

# Tags that every AWS resource must carry
_REQUIRED_TAGS = {"Environment", "Owner", "Project"}

# Config key names that indicate hardcoded secrets
_SECRET_KEYS = re.compile(
    r"^(password|secret|access_key|secret_key|api_key)$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class IaCResource:
    """Normalized representation of a single IaC resource."""

    resource_type: str  # e.g., "aws_s3_bucket", "aws_security_group"
    resource_name: str  # logical name within the template
    config: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "config": self.config,
        }


@dataclass
class IaCFinding:
    """A single security finding raised against an IaCResource."""

    check_id: str        # e.g., "IAC-001"
    severity: str        # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    resource_type: str
    resource_name: str
    message: str         # Human-readable description of the problem
    recommendation: str  # Actionable remediation guidance

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "check_id": self.check_id,
            "severity": self.severity,
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "message": self.message,
            "recommendation": self.recommendation,
        }


@dataclass
class IaCResult:
    """Aggregated result produced by IaCScanner.scan()."""

    findings: List[IaCFinding] = field(default_factory=list)
    risk_score: int = 0  # 0–100; sum of weights for fired checks, capped at 100

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """Return a one-line human-readable summary.

        Example: "IaCResult: 3 findings (CRITICAL:1 HIGH:1 LOW:1), risk_score=65"
        """
        by_sev = self.by_severity()
        # Build the severity breakdown string in a deterministic order
        _order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        parts = [
            f"{sev}:{len(by_sev[sev])}"
            for sev in _order
            if by_sev.get(sev)
        ]
        breakdown = " ".join(parts) if parts else "none"
        return (
            f"IaCResult: {len(self.findings)} findings "
            f"({breakdown}), risk_score={self.risk_score}"
        )

    def by_severity(self) -> Dict[str, List[IaCFinding]]:
        """Return findings grouped by severity level.

        Returns a dict with keys "CRITICAL", "HIGH", "MEDIUM", "LOW".
        Each value is a (possibly empty) list of IaCFinding objects.
        """
        groups: Dict[str, List[IaCFinding]] = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
        }
        for finding in self.findings:
            bucket = groups.setdefault(finding.severity, [])
            bucket.append(finding)
        return groups

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "findings": [f.to_dict() for f in self.findings],
            "risk_score": self.risk_score,
        }


# ---------------------------------------------------------------------------
# Internal check implementations
# ---------------------------------------------------------------------------

def _check_iac001(resource: IaCResource) -> Optional[IaCFinding]:
    """IAC-001: Public S3 bucket or public Azure storage account."""
    cfg = resource.config
    rtype = resource.resource_type

    triggered = False

    if rtype == "aws_s3_bucket":
        # ACL-based publicity
        if cfg.get("acl") in ("public-read", "public-read-write"):
            triggered = True
        # Block public access settings explicitly disabled
        if cfg.get("block_public_acls") is False:
            triggered = True
        if cfg.get("block_public_policy") is False:
            triggered = True

    elif rtype == "azurerm_storage_account":
        if cfg.get("allow_blob_public_access") is True:
            triggered = True

    if not triggered:
        return None

    return IaCFinding(
        check_id="IAC-001",
        severity=_CHECK_SEVERITY["IAC-001"],
        resource_type=rtype,
        resource_name=resource.resource_name,
        message=(
            f"Resource '{resource.resource_name}' ({rtype}) exposes storage "
            "data publicly.  Public read/write access or disabled block-public "
            "settings can lead to unauthorized data exposure."
        ),
        recommendation=(
            "Set acl to 'private', enable block_public_acls and "
            "block_public_policy for AWS S3 buckets, or set "
            "allow_blob_public_access=false for Azure storage accounts."
        ),
    )


def _check_iac002(resource: IaCResource) -> Optional[IaCFinding]:
    """IAC-002: Security group with open inbound (0.0.0.0/0 or ::/0)."""
    cfg = resource.config
    rtype = resource.resource_type

    if rtype == "aws_security_group":
        # ingress may be a list of rule dicts
        for rule in cfg.get("ingress", []):
            cidrs = rule.get("cidr_blocks", [])
            if "0.0.0.0/0" in cidrs or "::/0" in cidrs:
                return IaCFinding(
                    check_id="IAC-002",
                    severity=_CHECK_SEVERITY["IAC-002"],
                    resource_type=rtype,
                    resource_name=resource.resource_name,
                    message=(
                        f"Security group '{resource.resource_name}' allows "
                        "inbound traffic from the entire internet "
                        "(0.0.0.0/0 or ::/0)."
                    ),
                    recommendation=(
                        "Restrict ingress rules to known IP ranges or "
                        "security group IDs.  Never expose all ports to "
                        "0.0.0.0/0 in production environments."
                    ),
                )

    elif rtype == "google_compute_firewall":
        if cfg.get("direction") == "INGRESS":
            source_ranges = cfg.get("source_ranges", [])
            if "0.0.0.0/0" in source_ranges:
                return IaCFinding(
                    check_id="IAC-002",
                    severity=_CHECK_SEVERITY["IAC-002"],
                    resource_type=rtype,
                    resource_name=resource.resource_name,
                    message=(
                        f"GCP firewall rule '{resource.resource_name}' allows "
                        "inbound traffic from all IP addresses (0.0.0.0/0)."
                    ),
                    recommendation=(
                        "Replace 0.0.0.0/0 in source_ranges with specific "
                        "CIDR blocks or use service-account-based firewall "
                        "rules to limit exposure."
                    ),
                )

    return None


def _check_iac003(resource: IaCResource) -> Optional[IaCFinding]:
    """IAC-003: Unencrypted storage or database resource."""
    cfg = resource.config
    rtype = resource.resource_type

    triggered = False

    if rtype == "aws_s3_bucket":
        # Encryption is signalled by the presence of the configuration block
        if "server_side_encryption_configuration" not in cfg:
            triggered = True

    elif rtype == "aws_db_instance":
        # storage_encrypted must be explicitly True
        if not cfg.get("storage_encrypted", False):
            triggered = True

    elif rtype in ("aws_ebs_volume", "aws_instance"):
        if not cfg.get("encrypted", False):
            triggered = True

    elif rtype == "azurerm_storage_account":
        # HTTPS-only is treated as the encryption-in-transit requirement
        if cfg.get("enable_https_traffic_only") is False:
            triggered = True

    if not triggered:
        return None

    return IaCFinding(
        check_id="IAC-003",
        severity=_CHECK_SEVERITY["IAC-003"],
        resource_type=rtype,
        resource_name=resource.resource_name,
        message=(
            f"Resource '{resource.resource_name}' ({rtype}) does not have "
            "encryption enabled.  Data at rest may be exposed if the "
            "underlying storage is accessed directly."
        ),
        recommendation=(
            "Enable server-side encryption for S3 buckets, set "
            "storage_encrypted=true for RDS instances, encrypted=true for "
            "EBS volumes, and enable_https_traffic_only=true for Azure "
            "storage accounts."
        ),
    )


def _check_iac004(resource: IaCResource) -> Optional[IaCFinding]:
    """IAC-004: Hardcoded credentials detected in resource config."""
    cfg = resource.config

    for key, value in cfg.items():
        if _SECRET_KEYS.match(str(key)):
            # Only flag non-empty strings longer than 6 characters
            if isinstance(value, str) and len(value) > 6:
                return IaCFinding(
                    check_id="IAC-004",
                    severity=_CHECK_SEVERITY["IAC-004"],
                    resource_type=resource.resource_type,
                    resource_name=resource.resource_name,
                    message=(
                        f"Resource '{resource.resource_name}' "
                        f"({resource.resource_type}) contains a potentially "
                        f"hardcoded credential in config key '{key}'.  "
                        "Embedding secrets in IaC templates is a severe "
                        "security risk."
                    ),
                    recommendation=(
                        "Remove all plaintext credentials from IaC templates. "
                        "Use a secrets manager (e.g., AWS Secrets Manager, "
                        "HashiCorp Vault) and reference secrets dynamically "
                        "at deploy time."
                    ),
                )

    return None


def _check_iac005(resource: IaCResource) -> Optional[IaCFinding]:
    """IAC-005: Admin/root IAM policy without MFA condition."""
    cfg = resource.config
    rtype = resource.resource_type

    if rtype not in ("aws_iam_policy", "aws_iam_role_policy"):
        return None

    policy = cfg.get("policy")
    if not isinstance(policy, dict):
        return None

    statements = policy.get("Statement", [])
    if not isinstance(statements, list):
        return None

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue

        if stmt.get("Effect") != "Allow":
            continue

        # Collect all actions as a flat list
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        # Check for wildcard or iam:* action
        is_admin = any(
            a in ("*", "iam:*") for a in actions
        )
        if not is_admin:
            continue

        # Check whether a valid MFA condition is present
        condition = stmt.get("Condition", {})
        has_mfa = _has_mfa_condition(condition)
        if not has_mfa:
            return IaCFinding(
                check_id="IAC-005",
                severity=_CHECK_SEVERITY["IAC-005"],
                resource_type=rtype,
                resource_name=resource.resource_name,
                message=(
                    f"IAM policy '{resource.resource_name}' grants "
                    "administrator-level access (Action: '*' or 'iam:*') "
                    "without requiring MFA authentication."
                ),
                recommendation=(
                    "Add a Condition block that enforces MFA, e.g., "
                    "{'Bool': {'aws:MultiFactorAuthPresent': 'true'}}, "
                    "to all statements that grant broad administrative access."
                ),
            )

    return None


def _has_mfa_condition(condition: Any) -> bool:
    """Return True if the IAM condition block encodes an MFA requirement."""
    if not isinstance(condition, dict):
        return False
    for _operator, assertions in condition.items():
        if not isinstance(assertions, dict):
            continue
        for key in assertions:
            if "multifactorauthpresent" in key.lower():
                return True
    return False


def _check_iac006(resource: IaCResource) -> Optional[IaCFinding]:
    """IAC-006: Overly permissive IAM role or firewall rule."""
    cfg = resource.config
    rtype = resource.resource_type

    if rtype == "aws_iam_role":
        assume_policy = cfg.get("assume_role_policy", {})
        if isinstance(assume_policy, dict):
            statements = assume_policy.get("Statement", [])
            if not isinstance(statements, list):
                statements = []
            for stmt in statements:
                if not isinstance(stmt, dict):
                    continue
                principal = stmt.get("Principal", {})
                # Principal may be a string "*" or a dict {"AWS": "*"}
                if principal == "*":
                    return _make_iac006_role_finding(resource)
                if isinstance(principal, dict):
                    if principal.get("AWS") == "*" or principal.get("Service") == "*":
                        return _make_iac006_role_finding(resource)

    elif rtype == "google_compute_firewall":
        for allowed_rule in cfg.get("allowed", []):
            if not isinstance(allowed_rule, dict):
                continue
            ports = allowed_rule.get("ports")
            # Empty list OR missing key means all ports are permitted
            if ports is None or (isinstance(ports, list) and len(ports) == 0):
                return IaCFinding(
                    check_id="IAC-006",
                    severity=_CHECK_SEVERITY["IAC-006"],
                    resource_type=rtype,
                    resource_name=resource.resource_name,
                    message=(
                        f"GCP firewall rule '{resource.resource_name}' allows "
                        "traffic on ALL ports because the 'ports' field is "
                        "empty or absent in an allowed rule."
                    ),
                    recommendation=(
                        "Specify explicit port numbers in allowed[].ports "
                        "for every GCP firewall rule to enforce least-privilege "
                        "network access."
                    ),
                )

    return None


def _make_iac006_role_finding(resource: IaCResource) -> IaCFinding:
    """Helper: build the IAC-006 finding for an overly permissive IAM role."""
    return IaCFinding(
        check_id="IAC-006",
        severity=_CHECK_SEVERITY["IAC-006"],
        resource_type=resource.resource_type,
        resource_name=resource.resource_name,
        message=(
            f"IAM role '{resource.resource_name}' has an assume_role_policy "
            "that allows any principal ('*' or 'AWS: *') to assume it, "
            "granting unrestricted cross-account access."
        ),
        recommendation=(
            "Restrict the Principal in assume_role_policy to a specific AWS "
            "account ID, IAM user ARN, or service principal.  Never use "
            "Principal: '*' in production trust policies."
        ),
    )


def _check_iac007(resource: IaCResource) -> Optional[IaCFinding]:
    """IAC-007: Missing required tags on AWS resources."""
    if not resource.resource_type.startswith("aws_"):
        return None

    tags: Dict[str, Any] = resource.config.get("tags", {})
    if not isinstance(tags, dict):
        tags = {}

    missing = _REQUIRED_TAGS - set(tags.keys())
    if not missing:
        return None

    missing_str = ", ".join(sorted(missing))
    return IaCFinding(
        check_id="IAC-007",
        severity=_CHECK_SEVERITY["IAC-007"],
        resource_type=resource.resource_type,
        resource_name=resource.resource_name,
        message=(
            f"AWS resource '{resource.resource_name}' "
            f"({resource.resource_type}) is missing required tags: "
            f"{missing_str}."
        ),
        recommendation=(
            f"Add the missing tags ({missing_str}) to the resource "
            "configuration.  Required tags are: "
            + ", ".join(sorted(_REQUIRED_TAGS))
            + "."
        ),
    )


# Ordered list of check functions — executed in sequence for each resource
_CHECKS = [
    _check_iac001,
    _check_iac002,
    _check_iac003,
    _check_iac004,
    _check_iac005,
    _check_iac006,
    _check_iac007,
]


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class IaCScanner:
    """Offline IaC security scanner.

    Evaluates a list of IaCResource objects against the internal check
    catalogue and returns an IaCResult containing all findings plus a
    composite risk score.

    Usage::

        scanner = IaCScanner()
        result = scanner.scan([resource1, resource2, ...])
        print(result.summary())
    """

    def scan(self, resources: List[IaCResource]) -> IaCResult:
        """Scan a list of resources and return a consolidated IaCResult.

        The risk_score is calculated as::

            min(100, sum(_CHECK_WEIGHTS[check_id] for each unique fired check))

        A check that fires on multiple resources is counted once per resource
        but each firing contributes its full weight to the risk score.  The
        final score is capped at 100.

        Args:
            resources: List of IaCResource objects to evaluate.

        Returns:
            IaCResult with all findings and a calculated risk_score.
        """
        findings: List[IaCFinding] = []
        total_weight = 0

        for resource in resources:
            for check_fn in _CHECKS:
                finding = check_fn(resource)
                if finding is not None:
                    findings.append(finding)
                    total_weight += _CHECK_WEIGHTS[finding.check_id]

        risk_score = min(100, total_weight)
        return IaCResult(findings=findings, risk_score=risk_score)

    def scan_many(
        self,
        resource_lists: List[List[IaCResource]],
    ) -> List[IaCResult]:
        """Scan multiple independent resource lists.

        Each inner list is treated as a separate IaC template / environment
        and produces its own IaCResult.

        Args:
            resource_lists: A list of resource lists, one per template.

        Returns:
            A list of IaCResult objects, one per inner resource list.
        """
        return [self.scan(resources) for resources in resource_lists]
