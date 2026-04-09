# supply_chain_risk_scorer.py
# Software supply chain risk scorer for package dependency analysis.
# Analyzes package metadata for supply chain attack vectors — offline, no registry API calls.
#
# © 2024 Cyber Port Contributors
# Licensed under the Creative Commons Attribution 4.0 International License (CC BY 4.0).
# See https://creativecommons.org/licenses/by/4.0/ for full license text.

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Severity constants
# ---------------------------------------------------------------------------
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

# ---------------------------------------------------------------------------
# Check weight registry — maps check ID → integer weight used in risk scoring.
# risk_score = min(100, sum of weights for unique fired check IDs).
# ---------------------------------------------------------------------------
_CHECK_WEIGHTS: Dict[str, int] = {
    "SCR-001": 15,  # Recently published package (MEDIUM)
    "SCR-002": 15,  # Very few maintainers (MEDIUM)
    "SCR-003": 5,   # Low community adoption (LOW)
    "SCR-004": 45,  # Name similarity to popular package — typosquatting (CRITICAL)
    "SCR-005": 20,  # No source repository URL (HIGH)
    "SCR-006": 20,  # Wildcard or unpinned version constraint (HIGH)
    "SCR-007": 15,  # Suspicious package scope or namespace (MEDIUM)
}

# ---------------------------------------------------------------------------
# Trusted npm scopes — packages under these scopes are NOT flagged by SCR-007.
# ---------------------------------------------------------------------------
_TRUSTED_NPM_SCOPES: List[str] = [
    "@angular",
    "@babel",
    "@types",
    "@vue",
    "@react",
    "@svelte",
    "@nestjs",
    "@aws-sdk",
    "@google-cloud",
    "@microsoft",
    "@azure",
    "@stripe",
    "@sentry",
    "@jest",
    "@testing-library",
    "@playwright",
    "@storybook",
    "@prisma",
    "@trpc",
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class PackageInfo:
    """Metadata for a single package version under analysis."""

    # Required identifiers
    name: str                              # e.g. "requests", "lodash", "@scope/package"
    version: str                           # e.g. "1.2.3"
    ecosystem: str                         # "npm" | "pypi" | "maven" | "nuget" | "rubygems" | "go"

    # Optional provenance & community signals
    published_at: Optional[float] = None   # Unix timestamp of THIS version's publish date
    author_count: Optional[int] = None     # Number of unique contributors / maintainers
    star_count: Optional[int] = None       # GitHub / GitLab star count
    source_repo_url: Optional[str] = None  # Link to upstream source repository

    # npm-specific
    scope: Optional[str] = None            # npm scope, e.g. "@company"; None for unscoped

    # Dependency constraint as written in the manifest
    version_constraint: Optional[str] = None  # e.g. "^1.2.3", ">=1.0", "*", "latest"

    # Pre-computed similarity to the nearest well-known package name (0.0–1.0)
    popular_package_similarity: Optional[float] = None

    def to_dict(self) -> Dict:
        """Serialize to a plain dictionary for JSON export or logging."""
        return {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "published_at": self.published_at,
            "author_count": self.author_count,
            "star_count": self.star_count,
            "source_repo_url": self.source_repo_url,
            "scope": self.scope,
            "version_constraint": self.version_constraint,
            "popular_package_similarity": self.popular_package_similarity,
        }


@dataclass
class SupplyChainFinding:
    """A single risk finding produced by one check against one package."""

    check_id: str          # e.g. "SCR-004"
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW
    package_name: str
    package_version: str
    ecosystem: str
    message: str           # Human-readable description of the detected issue
    recommendation: str    # Actionable remediation guidance

    def to_dict(self) -> Dict:
        """Serialize to a plain dictionary for JSON export or logging."""
        return {
            "check_id": self.check_id,
            "severity": self.severity,
            "package_name": self.package_name,
            "package_version": self.package_version,
            "ecosystem": self.ecosystem,
            "message": self.message,
            "recommendation": self.recommendation,
        }


@dataclass
class SupplyChainRiskResult:
    """Aggregated risk assessment for a single package."""

    package_name: str
    package_version: str
    ecosystem: str
    findings: List[SupplyChainFinding] = field(default_factory=list)
    risk_score: int = 0   # 0–100; higher = more risk

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """Return a one-line human-readable summary of the result."""
        if not self.findings:
            return (
                f"{self.package_name}@{self.package_version} [{self.ecosystem}] — "
                f"risk_score={self.risk_score} | No findings"
            )
        severity_counts: Dict[str, int] = {}
        for f in self.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        parts = ", ".join(
            f"{count} {sev}" for sev, count in sorted(severity_counts.items())
        )
        return (
            f"{self.package_name}@{self.package_version} [{self.ecosystem}] — "
            f"risk_score={self.risk_score} | {len(self.findings)} finding(s): {parts}"
        )

    def by_severity(self) -> Dict[str, List[SupplyChainFinding]]:
        """Return findings grouped by severity level.

        All four severity buckets are always present, even when empty,
        so callers can safely do ``result.by_severity()['CRITICAL']``.
        """
        buckets: Dict[str, List[SupplyChainFinding]] = {
            SEVERITY_CRITICAL: [],
            SEVERITY_HIGH: [],
            SEVERITY_MEDIUM: [],
            SEVERITY_LOW: [],
        }
        for finding in self.findings:
            if finding.severity in buckets:
                buckets[finding.severity].append(finding)
        return buckets

    def to_dict(self) -> Dict:
        """Serialize result (including all findings) to a plain dictionary."""
        return {
            "package_name": self.package_name,
            "package_version": self.package_version,
            "ecosystem": self.ecosystem,
            "risk_score": self.risk_score,
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Scorer
# ---------------------------------------------------------------------------

class SupplyChainRiskScorer:
    """Offline supply chain risk scorer for package dependencies.

    Parameters
    ----------
    max_new_package_days:
        Packages published within this many days are considered recently
        published (SCR-001).  Default: 30.
    min_stars:
        Packages with fewer stars than this threshold are flagged for low
        community adoption (SCR-003).  Default: 100.
    """

    def __init__(
        self,
        max_new_package_days: int = 30,
        min_stars: int = 100,
    ) -> None:
        self.max_new_package_days = max_new_package_days
        self.min_stars = min_stars

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score(self, package: PackageInfo) -> SupplyChainRiskResult:
        """Run all checks against *package* and return a ``SupplyChainRiskResult``."""
        findings: List[SupplyChainFinding] = []

        # Run each check; collect findings
        self._check_scr001(package, findings)
        self._check_scr002(package, findings)
        self._check_scr003(package, findings)
        self._check_scr004(package, findings)
        self._check_scr005(package, findings)
        self._check_scr006(package, findings)
        self._check_scr007(package, findings)

        # Compute risk score — accumulate weights for unique fired check IDs
        fired_ids = {f.check_id for f in findings}
        raw_score = sum(_CHECK_WEIGHTS[cid] for cid in fired_ids if cid in _CHECK_WEIGHTS)
        risk_score = min(100, raw_score)

        return SupplyChainRiskResult(
            package_name=package.name,
            package_version=package.version,
            ecosystem=package.ecosystem,
            findings=findings,
            risk_score=risk_score,
        )

    def score_many(self, packages: List[PackageInfo]) -> List[SupplyChainRiskResult]:
        """Score a list of packages and return a result per package, in order."""
        return [self.score(pkg) for pkg in packages]

    # ------------------------------------------------------------------
    # Individual checks (private)
    # ------------------------------------------------------------------

    def _check_scr001(
        self, pkg: PackageInfo, findings: List[SupplyChainFinding]
    ) -> None:
        """SCR-001 — Recently published package (MEDIUM, weight 15)."""
        if pkg.published_at is None:
            return
        age_seconds = time.time() - pkg.published_at
        if age_seconds < self.max_new_package_days * 86400:
            findings.append(
                SupplyChainFinding(
                    check_id="SCR-001",
                    severity=SEVERITY_MEDIUM,
                    package_name=pkg.name,
                    package_version=pkg.version,
                    ecosystem=pkg.ecosystem,
                    message=(
                        f"Package '{pkg.name}@{pkg.version}' was published less than "
                        f"{self.max_new_package_days} days ago and has not had sufficient "
                        "time for community security review."
                    ),
                    recommendation=(
                        "Prefer established packages with a longer track record. "
                        "If this package is required, review the source code manually "
                        "before deployment and monitor for any security advisories."
                    ),
                )
            )

    def _check_scr002(
        self, pkg: PackageInfo, findings: List[SupplyChainFinding]
    ) -> None:
        """SCR-002 — Very few maintainers (MEDIUM, weight 15)."""
        if pkg.author_count is None:
            return
        if pkg.author_count < 2:
            findings.append(
                SupplyChainFinding(
                    check_id="SCR-002",
                    severity=SEVERITY_MEDIUM,
                    package_name=pkg.name,
                    package_version=pkg.version,
                    ecosystem=pkg.ecosystem,
                    message=(
                        f"Package '{pkg.name}@{pkg.version}' has only "
                        f"{pkg.author_count} maintainer(s). Single-maintainer packages "
                        "carry elevated risk of abandonment or account takeover."
                    ),
                    recommendation=(
                        "Assess maintainer activity and responsiveness. Consider "
                        "forking the package or choosing an alternative with broader "
                        "maintainer coverage for critical dependencies."
                    ),
                )
            )

    def _check_scr003(
        self, pkg: PackageInfo, findings: List[SupplyChainFinding]
    ) -> None:
        """SCR-003 — Low community adoption (LOW, weight 5)."""
        if pkg.star_count is None:
            return
        if pkg.star_count < self.min_stars:
            findings.append(
                SupplyChainFinding(
                    check_id="SCR-003",
                    severity=SEVERITY_LOW,
                    package_name=pkg.name,
                    package_version=pkg.version,
                    ecosystem=pkg.ecosystem,
                    message=(
                        f"Package '{pkg.name}@{pkg.version}' has only "
                        f"{pkg.star_count} star(s) (threshold: {self.min_stars}). "
                        "Low adoption may indicate less community security vetting."
                    ),
                    recommendation=(
                        "Review the package's activity, issue tracker, and changelog. "
                        "Prefer widely adopted alternatives where possible."
                    ),
                )
            )

    def _check_scr004(
        self, pkg: PackageInfo, findings: List[SupplyChainFinding]
    ) -> None:
        """SCR-004 — Name similarity to popular package (typosquatting) (CRITICAL, weight 45)."""
        if pkg.popular_package_similarity is None:
            return
        if pkg.popular_package_similarity >= 0.85:
            findings.append(
                SupplyChainFinding(
                    check_id="SCR-004",
                    severity=SEVERITY_CRITICAL,
                    package_name=pkg.name,
                    package_version=pkg.version,
                    ecosystem=pkg.ecosystem,
                    message=(
                        f"Package '{pkg.name}@{pkg.version}' has a high name similarity "
                        f"score ({pkg.popular_package_similarity:.2f}) to a well-known "
                        "package. This is a strong typosquatting signal."
                    ),
                    recommendation=(
                        "Verify the exact package name against the official registry. "
                        "Do not install this package until provenance and intent are "
                        "confirmed. Report suspected typosquatting to the registry."
                    ),
                )
            )

    def _check_scr005(
        self, pkg: PackageInfo, findings: List[SupplyChainFinding]
    ) -> None:
        """SCR-005 — No source repository URL (HIGH, weight 20)."""
        if not pkg.source_repo_url:  # covers None and ""
            findings.append(
                SupplyChainFinding(
                    check_id="SCR-005",
                    severity=SEVERITY_HIGH,
                    package_name=pkg.name,
                    package_version=pkg.version,
                    ecosystem=pkg.ecosystem,
                    message=(
                        f"Package '{pkg.name}@{pkg.version}' does not publish a source "
                        "repository URL. Provenance cannot be independently verified."
                    ),
                    recommendation=(
                        "Require packages to link to a public source repository. "
                        "If no source is available, treat the package as untrusted and "
                        "perform binary analysis before adoption."
                    ),
                )
            )

    def _check_scr006(
        self, pkg: PackageInfo, findings: List[SupplyChainFinding]
    ) -> None:
        """SCR-006 — Wildcard or unpinned version constraint (HIGH, weight 20)."""
        if pkg.version_constraint is None:
            return

        constraint = pkg.version_constraint.strip()

        # Explicitly wildcard / floating constraints
        if constraint in ("*", "latest", ""):
            self._append_scr006(pkg, findings, constraint)
            return

        # Caret / tilde ranges (npm-style) allow automatic minor/patch updates
        if constraint.startswith("^") or constraint.startswith("~"):
            self._append_scr006(pkg, findings, constraint)
            return

        # ">=" without an upper bound — e.g. ">=1.0" but NOT ">=1.0,<2.0"
        if ">=" in constraint and "<" not in constraint:
            self._append_scr006(pkg, findings, constraint)
            return

    def _append_scr006(
        self,
        pkg: PackageInfo,
        findings: List[SupplyChainFinding],
        constraint: str,
    ) -> None:
        """Helper: append a SCR-006 finding."""
        findings.append(
            SupplyChainFinding(
                check_id="SCR-006",
                severity=SEVERITY_HIGH,
                package_name=pkg.name,
                package_version=pkg.version,
                ecosystem=pkg.ecosystem,
                message=(
                    f"Package '{pkg.name}@{pkg.version}' uses a wildcard or unpinned "
                    f"version constraint '{constraint}'. This allows arbitrary future "
                    "versions to be installed, enabling dependency confusion or "
                    "malicious update injection."
                ),
                recommendation=(
                    "Pin dependencies to exact versions (e.g., '1.2.3') or use "
                    "lock files to freeze the resolved dependency tree. Adopt "
                    "automated dependency update tooling (Dependabot, Renovate) with "
                    "mandatory code review for all updates."
                ),
            )
        )

    def _check_scr007(
        self, pkg: PackageInfo, findings: List[SupplyChainFinding]
    ) -> None:
        """SCR-007 — Suspicious npm package scope or namespace (MEDIUM, weight 15)."""
        # Only applies to npm packages that have a scope set
        if pkg.ecosystem != "npm":
            return
        if pkg.scope is None:
            return

        scope = pkg.scope  # e.g. "@company"

        # Must start with "@" to be a valid npm scope
        if not scope.startswith("@"):
            return

        # Trusted scopes are never flagged
        if scope in _TRUSTED_NPM_SCOPES:
            return

        # Short scope heuristic: 4 chars or fewer including "@" means 1–3 char name
        # e.g. "@x" (len=2), "@ab" (len=3), "@abc" (len=4)
        is_short_scope = len(scope) <= 4

        if is_short_scope or scope not in _TRUSTED_NPM_SCOPES:
            findings.append(
                SupplyChainFinding(
                    check_id="SCR-007",
                    severity=SEVERITY_MEDIUM,
                    package_name=pkg.name,
                    package_version=pkg.version,
                    ecosystem=pkg.ecosystem,
                    message=(
                        f"Package '{pkg.name}@{pkg.version}' uses the npm scope "
                        f"'{scope}' which is not in the list of trusted scopes and "
                        "may be used for namespace squatting."
                    ),
                    recommendation=(
                        "Verify the publisher identity of this scoped package. "
                        "Check for lookalike scopes impersonating trusted organizations. "
                        "Prefer packages from verified, well-known scopes."
                    ),
                )
            )
