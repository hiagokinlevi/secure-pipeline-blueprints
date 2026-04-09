# Copyright (c) 2024 Cyber Port — hiagokinlevi
# Licensed under the Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
#
# sbom_analyzer.py — Software Bill of Materials (SBOM) security analyzer.
# Works offline on SBOM component data dicts — no live API calls.

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Check weight registry
# Each key is a check ID; value is the integer risk weight added to the score
# when that check fires at least once in an analysis run.
# ---------------------------------------------------------------------------
_CHECK_WEIGHTS: Dict[str, int] = {
    "SBOM-001": 40,  # Direct component with critical CVE (CVSS >= 9.0)
    "SBOM-002": 20,  # Component missing version
    "SBOM-003": 15,  # Copyleft license (GPL / AGPL family)
    "SBOM-004": 15,  # Outdated component (exceeds max_age_days)
    "SBOM-005": 25,  # Component sourced from untrusted registry
    "SBOM-006":  5,  # Duplicate package name with different versions
    "SBOM-007": 25,  # Transitive dependency with critical CVE (CVSS >= 9.0)
}

# ---------------------------------------------------------------------------
# Default trusted registry prefixes
# ---------------------------------------------------------------------------
_DEFAULT_TRUSTED_REGISTRIES: List[str] = [
    "https://registry.npmjs.org",
    "https://pypi.org",
    "https://repo.maven.apache.org",
    "https://registry.hub.docker.com",
    "https://rubygems.org",
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class SBOMVulnerability:
    """A single known vulnerability associated with a component."""

    cve_id: str       # e.g. "CVE-2023-12345"
    cvss_score: float  # 0.0 – 10.0
    severity: str     # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"

    def to_dict(self) -> Dict:
        """Serialize to a plain dictionary (JSON-serialisable)."""
        return {
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
        }


@dataclass
class SBOMComponent:
    """A single software component entry inside an SBOM."""

    name: str
    version: Optional[str] = None        # None when version is unknown
    purl: Optional[str] = None           # Package URL, e.g. "pkg:npm/lodash@4.17.11"
    registry: Optional[str] = None       # Origin registry URL
    license: Optional[str] = None        # SPDX license identifier
    last_updated: Optional[float] = None  # Unix timestamp of package publish date
    vulnerabilities: List[SBOMVulnerability] = field(default_factory=list)
    is_transitive: bool = False          # True for indirect / transitive dependencies

    def to_dict(self) -> Dict:
        """Serialize to a plain dictionary (JSON-serialisable)."""
        return {
            "name": self.name,
            "version": self.version,
            "purl": self.purl,
            "registry": self.registry,
            "license": self.license,
            "last_updated": self.last_updated,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "is_transitive": self.is_transitive,
        }


@dataclass
class SBOMFinding:
    """A single policy finding raised by one of the SBOM checks."""

    check_id: str                          # e.g. "SBOM-001"
    severity: str                          # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    component_name: str
    component_version: Optional[str]       # None when version is unknown
    message: str                           # Human-readable description of the issue
    recommendation: str                    # Actionable remediation guidance
    cve_ids: List[str] = field(default_factory=list)  # Related CVE identifiers

    def to_dict(self) -> Dict:
        """Serialize to a plain dictionary (JSON-serialisable)."""
        return {
            "check_id": self.check_id,
            "severity": self.severity,
            "component_name": self.component_name,
            "component_version": self.component_version,
            "message": self.message,
            "recommendation": self.recommendation,
            "cve_ids": list(self.cve_ids),
        }


@dataclass
class SBOMResult:
    """Aggregated result of an SBOM analysis run."""

    findings: List[SBOMFinding] = field(default_factory=list)
    risk_score: int = 0  # 0 – 100; computed from unique check weights

    # ------------------------------------------------------------------
    # Reporting helpers
    # ------------------------------------------------------------------

    def by_severity(self) -> Dict[str, List[SBOMFinding]]:
        """Return findings grouped by severity label.

        Keys are always present for all four severity levels so callers
        can rely on a stable structure even when a level has no findings.
        """
        groups: Dict[str, List[SBOMFinding]] = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
        }
        for finding in self.findings:
            # Guard against unexpected severity strings
            if finding.severity in groups:
                groups[finding.severity].append(finding)
        return groups

    def summary(self) -> str:
        """Return a one-line human-readable summary.

        Example: "SBOMResult: 4 findings (CRITICAL:1 HIGH:2 MEDIUM:1), risk_score=65"
        """
        by_sev = self.by_severity()
        # Only include severity levels that have at least one finding
        sev_parts = [
            f"{label}:{len(items)}"
            for label in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
            if (items := by_sev[label])
        ]
        sev_str = " ".join(sev_parts) if sev_parts else "none"
        return (
            f"SBOMResult: {len(self.findings)} findings "
            f"({sev_str}), risk_score={self.risk_score}"
        )

    def to_dict(self) -> Dict:
        """Serialize to a plain dictionary (JSON-serialisable)."""
        return {
            "findings": [f.to_dict() for f in self.findings],
            "risk_score": self.risk_score,
            "summary": self.summary(),
        }


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class SBOMAnalyzer:
    """Offline SBOM security analyzer.

    Parameters
    ----------
    max_age_days:
        Number of days after which a component without a recent *last_updated*
        timestamp is flagged as outdated (SBOM-004). Defaults to 365.
    trusted_registries:
        List of registry URL prefixes considered trustworthy (SBOM-005).
        When *None* the module-level ``_DEFAULT_TRUSTED_REGISTRIES`` list is
        used.
    """

    def __init__(
        self,
        max_age_days: int = 365,
        trusted_registries: Optional[List[str]] = None,
    ) -> None:
        self.max_age_days = max_age_days
        # Use the default list when the caller passes None; copy to prevent
        # accidental mutation of the shared default.
        self.trusted_registries: List[str] = (
            list(trusted_registries)
            if trusted_registries is not None
            else list(_DEFAULT_TRUSTED_REGISTRIES)
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, components: List[SBOMComponent]) -> SBOMResult:
        """Analyze a single flat list of SBOM components.

        Runs all seven checks and returns a ``SBOMResult`` with the
        accumulated findings and a calculated risk score.
        """
        findings: List[SBOMFinding] = []

        # Run checks that operate on individual components
        findings.extend(self._check_001(components))
        findings.extend(self._check_002(components))
        findings.extend(self._check_003(components))
        findings.extend(self._check_004(components))
        findings.extend(self._check_005(components))
        findings.extend(self._check_007(components))

        # SBOM-006 requires a cross-component view
        findings.extend(self._check_006(components))

        # Compute risk score: sum weights for each unique check ID that fired
        fired_check_ids = {f.check_id for f in findings}
        risk_score = min(100, sum(_CHECK_WEIGHTS.get(cid, 0) for cid in fired_check_ids))

        return SBOMResult(findings=findings, risk_score=risk_score)

    def analyze_many(
        self,
        component_lists: List[List[SBOMComponent]],
    ) -> List[SBOMResult]:
        """Analyze multiple independent SBOM component lists.

        Each inner list is analyzed in isolation; returns one ``SBOMResult``
        per input list in the same order.
        """
        return [self.analyze(components) for components in component_lists]

    # ------------------------------------------------------------------
    # Individual check implementations
    # ------------------------------------------------------------------

    def _check_001(self, components: List[SBOMComponent]) -> List[SBOMFinding]:
        """SBOM-001: Direct component with a critical CVE (CVSS >= 9.0).

        One finding per unique component name; only non-transitive components
        are considered.
        """
        findings: List[SBOMFinding] = []
        seen_names: set = set()

        for comp in components:
            # Skip transitive dependencies — they are handled by SBOM-007
            if comp.is_transitive:
                continue
            if comp.name in seen_names:
                continue

            critical_vulns = [
                v for v in comp.vulnerabilities if v.cvss_score >= 9.0
            ]
            if not critical_vulns:
                continue

            seen_names.add(comp.name)
            cve_ids = [v.cve_id for v in critical_vulns]
            findings.append(
                SBOMFinding(
                    check_id="SBOM-001",
                    severity="CRITICAL",
                    component_name=comp.name,
                    component_version=comp.version,
                    message=(
                        f"Direct component '{comp.name}' has "
                        f"{len(critical_vulns)} critical CVE(s): "
                        f"{', '.join(cve_ids)}"
                    ),
                    recommendation=(
                        "Upgrade to a patched version immediately or replace "
                        "the dependency with a secure alternative."
                    ),
                    cve_ids=cve_ids,
                )
            )

        return findings

    def _check_002(self, components: List[SBOMComponent]) -> List[SBOMFinding]:
        """SBOM-002: Component with a missing or empty version string.

        Components without a known version cannot be patched reliably.
        """
        findings: List[SBOMFinding] = []

        for comp in components:
            if comp.version is None or comp.version == "":
                findings.append(
                    SBOMFinding(
                        check_id="SBOM-002",
                        severity="HIGH",
                        component_name=comp.name,
                        component_version=comp.version,
                        message=(
                            f"Component '{comp.name}' has no version specified; "
                            "cannot determine patch status."
                        ),
                        recommendation=(
                            "Pin an explicit version in the SBOM manifest to "
                            "enable vulnerability tracking and patching."
                        ),
                    )
                )

        return findings

    def _check_003(self, components: List[SBOMComponent]) -> List[SBOMFinding]:
        """SBOM-003: Component carrying a copyleft license (GPL / AGPL family).

        Any license identifier containing "GPL" or "AGPL" (case-insensitive)
        is flagged; this covers GPL-2.0, GPL-3.0, AGPL-3.0, LGPL-*, etc.
        """
        findings: List[SBOMFinding] = []

        for comp in components:
            if comp.license is None:
                continue
            license_upper = comp.license.upper()
            if "GPL" in license_upper or "AGPL" in license_upper:
                findings.append(
                    SBOMFinding(
                        check_id="SBOM-003",
                        severity="MEDIUM",
                        component_name=comp.name,
                        component_version=comp.version,
                        message=(
                            f"Component '{comp.name}' is licensed under "
                            f"'{comp.license}', which is a copyleft license."
                        ),
                        recommendation=(
                            "Review license compatibility with the project's "
                            "commercial distribution model; consider replacing "
                            "with a permissively-licensed alternative."
                        ),
                    )
                )

        return findings

    def _check_004(self, components: List[SBOMComponent]) -> List[SBOMFinding]:
        """SBOM-004: Outdated component (last_updated exceeds max_age_days).

        Reads the current wall-clock time via ``time.time()`` so tests can
        patch it with ``unittest.mock.patch``.
        """
        findings: List[SBOMFinding] = []
        # Capture current time once for consistency across the entire check
        now = time.time()
        max_age_seconds = self.max_age_days * 86400

        for comp in components:
            if comp.last_updated is None:
                continue  # Cannot determine age without a timestamp
            age_seconds = now - comp.last_updated
            if age_seconds > max_age_seconds:
                age_days = int(age_seconds // 86400)
                findings.append(
                    SBOMFinding(
                        check_id="SBOM-004",
                        severity="MEDIUM",
                        component_name=comp.name,
                        component_version=comp.version,
                        message=(
                            f"Component '{comp.name}' has not been updated for "
                            f"~{age_days} days (threshold: {self.max_age_days} days)."
                        ),
                        recommendation=(
                            "Check the upstream project for a newer release; "
                            "unmaintained packages accumulate security debt."
                        ),
                    )
                )

        return findings

    def _check_005(self, components: List[SBOMComponent]) -> List[SBOMFinding]:
        """SBOM-005: Component sourced from an untrusted registry.

        A registry is trusted when the component's ``registry`` value starts
        with at least one prefix in ``self.trusted_registries``.
        """
        findings: List[SBOMFinding] = []

        for comp in components:
            if comp.registry is None:
                continue  # No registry information — skip

            is_trusted = any(
                comp.registry.startswith(prefix)
                for prefix in self.trusted_registries
            )
            if not is_trusted:
                findings.append(
                    SBOMFinding(
                        check_id="SBOM-005",
                        severity="HIGH",
                        component_name=comp.name,
                        component_version=comp.version,
                        message=(
                            f"Component '{comp.name}' was sourced from an "
                            f"untrusted registry: '{comp.registry}'."
                        ),
                        recommendation=(
                            "Verify the integrity of this package; prefer "
                            "official registries or an internal artifact proxy "
                            "that mirrors approved sources."
                        ),
                    )
                )

        return findings

    def _check_006(self, components: List[SBOMComponent]) -> List[SBOMFinding]:
        """SBOM-006: Duplicate package name present with different versions.

        Collects all (name, version) pairs; flags any name that maps to more
        than one distinct version value.
        """
        findings: List[SBOMFinding] = []

        # Build a mapping from component name to the set of versions seen
        name_to_versions: Dict[str, set] = {}
        for comp in components:
            name_to_versions.setdefault(comp.name, set()).add(comp.version)

        for name, versions in name_to_versions.items():
            if len(versions) > 1:
                version_list = sorted(str(v) for v in versions)
                findings.append(
                    SBOMFinding(
                        check_id="SBOM-006",
                        severity="LOW",
                        component_name=name,
                        component_version=None,
                        message=(
                            f"Package '{name}' appears with multiple versions: "
                            f"{', '.join(version_list)}."
                        ),
                        recommendation=(
                            "Resolve version conflicts by aligning all "
                            "dependents to the same (latest patched) version."
                        ),
                    )
                )

        return findings

    def _check_007(self, components: List[SBOMComponent]) -> List[SBOMFinding]:
        """SBOM-007: Transitive dependency with a critical CVE (CVSS >= 9.0).

        Mirrors SBOM-001 but targets indirect / transitive components.
        One finding per unique component name.
        """
        findings: List[SBOMFinding] = []
        seen_names: set = set()

        for comp in components:
            # Only transitive components
            if not comp.is_transitive:
                continue
            if comp.name in seen_names:
                continue

            critical_vulns = [
                v for v in comp.vulnerabilities if v.cvss_score >= 9.0
            ]
            if not critical_vulns:
                continue

            seen_names.add(comp.name)
            cve_ids = [v.cve_id for v in critical_vulns]
            findings.append(
                SBOMFinding(
                    check_id="SBOM-007",
                    severity="HIGH",
                    component_name=comp.name,
                    component_version=comp.version,
                    message=(
                        f"Transitive dependency '{comp.name}' has "
                        f"{len(critical_vulns)} critical CVE(s): "
                        f"{', '.join(cve_ids)}"
                    ),
                    recommendation=(
                        "Update the direct dependency that pulls in this "
                        "transitive package, or force-resolve to a patched "
                        "version in your package manager lock file."
                    ),
                    cve_ids=cve_ids,
                )
            )

        return findings
