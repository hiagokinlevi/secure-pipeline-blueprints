# container_registry_scanner.py
# Analyze container registry configurations for security misconfigurations.
#
# Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
#
# Part of the Cyber Port portfolio — github.com/hiagokinlevi
# Compatible with Python 3.9+

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Check weights — map from check ID -> weight value used in risk_score calc.
# risk_score = min(100, sum of weights for unique fired check IDs)
# ---------------------------------------------------------------------------
_CHECK_WEIGHTS: Dict[str, int] = {
    "CREG-001": 45,  # Public registry / repository visibility
    "CREG-002": 25,  # Vulnerability scanning not enabled
    "CREG-003": 20,  # Tag immutability not enabled
    "CREG-004": 20,  # Image signing / attestation not required
    "CREG-005": 15,  # No lifecycle / retention policy
    "CREG-006": 25,  # Encryption at rest not enabled
    "CREG-007": 25,  # Access policy allows external / untrusted principals
}

# Regex to extract the numeric account ID from an AWS IAM ARN.
# e.g. "arn:aws:iam::123456789012:root"  ->  group(1) == "123456789012"
_ARN_ACCOUNT_RE = re.compile(
    r"^arn:[^:]*:[^:]*:[^:]*:([0-9]{10,12}):"
)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class RegistryAccessPolicy:
    """Single policy statement attached to a container registry."""
    principal: str          # e.g. "arn:aws:iam::123456789012:root", "*", "public"
    actions: List[str]      # e.g. ["ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]
    effect: str             # "Allow" or "Deny"


@dataclass
class ContainerRegistry:
    """Complete configuration snapshot of a container registry."""
    registry_id: str
    name: str
    provider: str               # "ecr" | "acr" | "gcr" | "dockerhub" | "ghcr" | "generic"
    visibility: str             # "public" | "private"
    vulnerability_scanning: bool
    tag_immutability: bool
    image_signing_required: bool
    lifecycle_policy_enabled: bool
    encryption_enabled: bool
    account_id: str             # Owner account / org ID (used for cross-account policy checks)
    access_policies: List[RegistryAccessPolicy] = field(default_factory=list)


@dataclass
class CREGFinding:
    """A single security misconfiguration finding for a registry check."""
    check_id: str
    severity: str   # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str
    detail: str
    weight: int


@dataclass
class CREGResult:
    """Aggregated scan result for one container registry."""
    registry_name: str
    provider: str
    findings: List[CREGFinding]
    risk_score: int     # min(100, sum of weights for unique fired check IDs)
    compliant: bool     # True when risk_score == 0

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Return a plain dictionary representation of the result."""
        return {
            "registry_name": self.registry_name,
            "provider": self.provider,
            "risk_score": self.risk_score,
            "compliant": self.compliant,
            "findings": [
                {
                    "check_id": f.check_id,
                    "severity": f.severity,
                    "title": f.title,
                    "detail": f.detail,
                    "weight": f.weight,
                }
                for f in self.findings
            ],
        }

    def summary(self) -> str:
        """Return a single human-readable summary line."""
        status = "COMPLIANT" if self.compliant else "NON-COMPLIANT"
        finding_count = len(self.findings)
        return (
            f"[{status}] {self.registry_name} ({self.provider}) — "
            f"risk_score={self.risk_score}, findings={finding_count}"
        )

    def by_severity(self) -> Dict[str, List[CREGFinding]]:
        """Return findings grouped by severity label."""
        groups: Dict[str, List[CREGFinding]] = {}
        for finding in self.findings:
            groups.setdefault(finding.severity, []).append(finding)
        return groups


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_arn_account(principal: str) -> Optional[str]:
    """
    Extract the account ID from an AWS IAM ARN string.

    Returns None when the principal is not an ARN or does not contain
    a recognisable account ID segment.
    """
    match = _ARN_ACCOUNT_RE.match(principal)
    if match:
        return match.group(1)
    return None


def _is_external_principal(principal: str, account_id: str) -> bool:
    """
    Return True when a policy principal is considered external / untrusted.

    Rules (evaluated in order):
    1. Wildcard or literally "public" / "anonymous" -> external.
    2. ARN whose embedded account ID differs from account_id -> external.
    3. Principal that does not contain account_id AND is not a recognised
       safe internal token (e.g. the bare account ID string, "self",
       "internal") -> treated as external.
    """
    # Rule 1: explicit wildcard / public principals
    normalised = principal.strip().lower()
    if normalised in ("*", "public", "anonymous"):
        return True

    # Rule 2: ARN with a different account ID
    arn_account = _extract_arn_account(principal)
    if arn_account is not None:
        return arn_account != account_id

    # Rule 3: non-ARN string that does not contain the owner account ID
    # Safe internal tokens that do NOT need to carry the account ID.
    _SAFE_INTERNAL_TOKENS = {"self", "internal", "localhost"}
    if normalised in _SAFE_INTERNAL_TOKENS:
        return False

    # If the principal contains the account_id literally, treat as internal.
    if account_id and account_id in principal:
        return False

    # Anything else with no discernible link to the owner account is external.
    return True


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------

def _check_creg001(registry: ContainerRegistry) -> Optional[CREGFinding]:
    """CREG-001: Registry is publicly accessible."""
    if registry.visibility == "public":
        return CREGFinding(
            check_id="CREG-001",
            severity="CRITICAL",
            title="Registry is publicly accessible",
            detail=(
                f"Registry '{registry.name}' has visibility set to 'public'. "
                "Public registries expose all image layers and metadata to anyone "
                "on the internet, greatly increasing the attack surface."
            ),
            weight=_CHECK_WEIGHTS["CREG-001"],
        )
    return None


def _check_creg002(registry: ContainerRegistry) -> Optional[CREGFinding]:
    """CREG-002: Vulnerability scanning not enabled."""
    if not registry.vulnerability_scanning:
        return CREGFinding(
            check_id="CREG-002",
            severity="HIGH",
            title="Vulnerability scanning is not enabled",
            detail=(
                f"Registry '{registry.name}' does not have vulnerability scanning "
                "enabled. Without scanning, known CVEs in base images and installed "
                "packages will go undetected before deployment."
            ),
            weight=_CHECK_WEIGHTS["CREG-002"],
        )
    return None


def _check_creg003(registry: ContainerRegistry) -> Optional[CREGFinding]:
    """CREG-003: Tag immutability not enabled."""
    if not registry.tag_immutability:
        return CREGFinding(
            check_id="CREG-003",
            severity="HIGH",
            title="Tag immutability is not enabled",
            detail=(
                f"Registry '{registry.name}' allows image tags to be overwritten. "
                "Without tag immutability, a mutable tag (e.g. 'latest') can be "
                "silently replaced with a malicious or vulnerable image."
            ),
            weight=_CHECK_WEIGHTS["CREG-003"],
        )
    return None


def _check_creg004(registry: ContainerRegistry) -> Optional[CREGFinding]:
    """CREG-004: Image signing / attestation not required."""
    if not registry.image_signing_required:
        return CREGFinding(
            check_id="CREG-004",
            severity="HIGH",
            title="Image signing or attestation requirement is not configured",
            detail=(
                f"Registry '{registry.name}' does not require image signing or "
                "attestation. Without this control, unsigned or tampered images can "
                "be pulled and deployed without verification."
            ),
            weight=_CHECK_WEIGHTS["CREG-004"],
        )
    return None


def _check_creg005(registry: ContainerRegistry) -> Optional[CREGFinding]:
    """CREG-005: No lifecycle / retention policy."""
    if not registry.lifecycle_policy_enabled:
        return CREGFinding(
            check_id="CREG-005",
            severity="MEDIUM",
            title="No lifecycle or retention policy configured",
            detail=(
                f"Registry '{registry.name}' has no lifecycle or retention policy. "
                "Without automated cleanup, stale and potentially vulnerable images "
                "accumulate, increasing storage costs and the risk surface."
            ),
            weight=_CHECK_WEIGHTS["CREG-005"],
        )
    return None


def _check_creg006(registry: ContainerRegistry) -> Optional[CREGFinding]:
    """CREG-006: Encryption at rest not enabled."""
    if not registry.encryption_enabled:
        return CREGFinding(
            check_id="CREG-006",
            severity="HIGH",
            title="Encryption at rest is not enabled",
            detail=(
                f"Registry '{registry.name}' does not encrypt image layers at rest. "
                "Unencrypted storage leaves image data readable if the underlying "
                "storage medium is accessed directly."
            ),
            weight=_CHECK_WEIGHTS["CREG-006"],
        )
    return None


def _check_creg007(registry: ContainerRegistry) -> List[CREGFinding]:
    """
    CREG-007: Access policy allows external / untrusted principals.

    One finding is emitted per violating Allow-policy principal.
    However, the weight for CREG-007 is counted only once toward risk_score.
    """
    findings: List[CREGFinding] = []
    for policy in registry.access_policies:
        # Only Allow policies can grant unintended access.
        if policy.effect != "Allow":
            continue
        if _is_external_principal(policy.principal, registry.account_id):
            findings.append(
                CREGFinding(
                    check_id="CREG-007",
                    severity="HIGH",
                    title="Access policy allows an external or untrusted principal",
                    detail=(
                        f"Registry '{registry.name}' has an Allow policy for principal "
                        f"'{policy.principal}', which is outside the expected account / "
                        f"organisation (account_id='{registry.account_id}'). "
                        "Review and restrict registry access policies."
                    ),
                    weight=_CHECK_WEIGHTS["CREG-007"],
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan(registry: ContainerRegistry) -> CREGResult:
    """
    Scan a single container registry configuration for security issues.

    Parameters
    ----------
    registry:
        A fully-populated ContainerRegistry dataclass instance.

    Returns
    -------
    CREGResult
        Aggregated result containing all fired findings and a risk_score
        calculated as min(100, sum of weights for unique fired check IDs).
    """
    findings: List[CREGFinding] = []

    # Run single-finding checks (return None or one CREGFinding).
    for check_fn in (
        _check_creg001,
        _check_creg002,
        _check_creg003,
        _check_creg004,
        _check_creg005,
        _check_creg006,
    ):
        result = check_fn(registry)
        if result is not None:
            findings.append(result)

    # CREG-007 may produce multiple findings (one per violating principal).
    findings.extend(_check_creg007(registry))

    # risk_score: sum the weight for each *unique* check ID that fired.
    fired_check_ids = {f.check_id for f in findings}
    raw_score = sum(_CHECK_WEIGHTS[cid] for cid in fired_check_ids)
    risk_score = min(100, raw_score)

    return CREGResult(
        registry_name=registry.name,
        provider=registry.provider,
        findings=findings,
        risk_score=risk_score,
        compliant=(risk_score == 0),
    )


def scan_many(registries: List[ContainerRegistry]) -> List[CREGResult]:
    """
    Scan a list of container registry configurations.

    Parameters
    ----------
    registries:
        Iterable of ContainerRegistry instances.

    Returns
    -------
    List[CREGResult]
        One CREGResult per registry, in the same order as the input list.
    """
    return [scan(r) for r in registries]
