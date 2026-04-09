# Copyright (C) 2026 Cyber Port — hiagokinlevi
# Licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/)
#
# license_compliance_checker.py
# Analyze software dependency licenses for compliance risks: copyleft contamination,
# non-commercial restrictions, missing licenses, and policy violations.
#
# Python 3.9 compatible — uses typing.List / typing.Optional / typing.Dict.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# License classification constants
# ---------------------------------------------------------------------------

# LIC-001: strong copyleft — triggers for direct deps in proprietary projects
_STRONG_COPYLEFT: set = {
    "GPL-2.0",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "AGPL-3.0",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
}

# LIC-002: weak copyleft — triggers for any dep (direct or transitive)
_WEAK_COPYLEFT: set = {
    "LGPL-2.1",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "MPL-2.0",
    "EUPL-1.2",
}

# LIC-003: non-commercial restriction — triggers for any dep
_NON_COMMERCIAL: set = {
    "CC-BY-NC-4.0",
    "CC-BY-NC-SA-4.0",
    "Commons-Clause",
    "BUSL-1.1",
}

# LIC-005: deprecated / obsolete SPDX identifiers
_DEPRECATED: set = {
    "GPL-2.0-only",   # listed in deprecated set per spec (also in strong copyleft)
    "GPL-1.0",
    "Artistic-1.0",
    "LGPL-2.0",
    "LGPL-2.0-only",
    "MPL-1.0",
    "MPL-1.1",
}

# LIC-006: network copyleft — AGPL identifiers, triggers in SaaS context
_AGPL: set = {
    "AGPL-3.0",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
}

# Full set of known SPDX identifiers — anything outside this set triggers LIC-007
_KNOWN_SPDX: set = (
    _STRONG_COPYLEFT
    | _WEAK_COPYLEFT
    | _NON_COMMERCIAL
    | _DEPRECATED
    | {
        "MIT",
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "ISC",
        "0BSD",
        "CC0-1.0",
        "Unlicense",
        "CC-BY-4.0",
        "CC-BY-SA-4.0",
        "CDDL-1.0",
        "EPL-2.0",
        "PSF-2.0",
        "Python-2.0",
    }
)

# ---------------------------------------------------------------------------
# Check weights
# ---------------------------------------------------------------------------

_CHECK_WEIGHTS: Dict[str, int] = {
    "LIC-001": 45,  # strong copyleft in direct dep of proprietary project — CRITICAL
    "LIC-002": 15,  # weak copyleft in any dep — MEDIUM
    "LIC-003": 30,  # non-commercial restriction — HIGH
    "LIC-004": 20,  # no license information — HIGH
    "LIC-005": 15,  # deprecated/obsolete license — MEDIUM
    "LIC-006": 45,  # network copyleft (AGPL) in SaaS context — CRITICAL
    "LIC-007": 15,  # unparseable / unknown SPDX expression — MEDIUM
}

# Severity labels aligned to weights
_CHECK_SEVERITY: Dict[str, str] = {
    "LIC-001": "CRITICAL",
    "LIC-002": "MEDIUM",
    "LIC-003": "HIGH",
    "LIC-004": "HIGH",
    "LIC-005": "MEDIUM",
    "LIC-006": "CRITICAL",
    "LIC-007": "MEDIUM",
}

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Dependency:
    """Represents a single software dependency with its license metadata."""

    name: str          # Package name, e.g. "requests"
    version: str       # Version string, e.g. "2.28.0"
    license_id: Optional[str]  # SPDX identifier or None when unknown
    is_direct: bool    # True = direct dependency; False = transitive
    ecosystem: str     # Package ecosystem: "pypi", "npm", "maven", "go", etc.


@dataclass
class LICFinding:
    """A single compliance finding raised for a specific dependency."""

    check_id: str        # e.g. "LIC-001"
    severity: str        # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str           # Short human-readable title
    detail: str          # Full descriptive message
    weight: int          # Numeric risk contribution
    dependency_name: str # Name of the dependency that triggered this finding


@dataclass
class LICResult:
    """Aggregated result of a license compliance scan."""

    findings: List[LICFinding] = field(default_factory=list)
    risk_score: int = 0    # min(100, sum of weights for unique fired check IDs)
    compliant: bool = True  # True only when risk_score == 0

    # ------------------------------------------------------------------
    # Output helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Serialize the result to a plain dictionary (JSON-friendly)."""
        return {
            "risk_score": self.risk_score,
            "compliant": self.compliant,
            "findings": [
                {
                    "check_id": f.check_id,
                    "severity": f.severity,
                    "title": f.title,
                    "detail": f.detail,
                    "weight": f.weight,
                    "dependency_name": f.dependency_name,
                }
                for f in self.findings
            ],
        }

    def summary(self) -> str:
        """Return a single-line human-readable summary of the scan result."""
        status = "COMPLIANT" if self.compliant else "NON-COMPLIANT"
        return (
            f"License compliance scan: {status} | "
            f"risk_score={self.risk_score} | "
            f"findings={len(self.findings)}"
        )

    def by_severity(self) -> Dict[str, List[LICFinding]]:
        """Return findings grouped by severity level."""
        groups: Dict[str, List[LICFinding]] = {}
        for finding in self.findings:
            groups.setdefault(finding.severity, []).append(finding)
        return groups


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _make_finding(
    check_id: str,
    title: str,
    detail: str,
    dep_name: str,
) -> LICFinding:
    """Construct a LICFinding from check metadata + per-dep info."""
    return LICFinding(
        check_id=check_id,
        severity=_CHECK_SEVERITY[check_id],
        title=title,
        detail=detail,
        weight=_CHECK_WEIGHTS[check_id],
        dependency_name=dep_name,
    )


def _compute_risk_score(findings: List[LICFinding]) -> int:
    """Sum weights of unique fired check IDs, capped at 100."""
    fired: set = {f.check_id for f in findings}
    return min(100, sum(_CHECK_WEIGHTS[cid] for cid in fired))


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------


def _analyze_dependency(
    dep: Dependency,
    project_type: str,
    deployment_context: str,
) -> List[LICFinding]:
    """Return all findings for a single dependency."""
    findings: List[LICFinding] = []

    license_id = dep.license_id

    # Normalize empty string to None for uniform handling
    if license_id is not None and license_id.strip() == "":
        license_id = None

    # ---- LIC-004: missing license ----------------------------------------
    if license_id is None:
        findings.append(
            _make_finding(
                "LIC-004",
                title="Missing license information",
                detail=(
                    f"Dependency '{dep.name}' ({dep.version}) has no license "
                    "information. Unable to assess compliance risk."
                ),
                dep_name=dep.name,
            )
        )
        # LIC-007 must NOT fire when LIC-004 already fired for the same dep
        return findings

    # ---- LIC-007: unknown / unparseable SPDX expression ------------------
    # Checked before other content checks so that unknown identifiers are
    # flagged even if they happen to match no other category.
    if license_id not in _KNOWN_SPDX:
        findings.append(
            _make_finding(
                "LIC-007",
                title="Unknown or unparseable SPDX license identifier",
                detail=(
                    f"Dependency '{dep.name}' ({dep.version}) uses license "
                    f"'{license_id}', which is not a recognized SPDX identifier. "
                    "Manual review required."
                ),
                dep_name=dep.name,
            )
        )
        # Cannot classify further — return early
        return findings

    # ---- LIC-001: strong copyleft in direct dep of proprietary project ----
    if (
        license_id in _STRONG_COPYLEFT
        and dep.is_direct
        and project_type == "proprietary"
    ):
        findings.append(
            _make_finding(
                "LIC-001",
                title="Strong copyleft license in direct dependency",
                detail=(
                    f"Direct dependency '{dep.name}' ({dep.version}) uses "
                    f"'{license_id}', a strong copyleft license. This may require "
                    "the entire proprietary project to be released under the same "
                    "terms (copyleft contamination)."
                ),
                dep_name=dep.name,
            )
        )

    # ---- LIC-002: weak copyleft (direct or transitive) -------------------
    if license_id in _WEAK_COPYLEFT:
        dep_kind = "direct" if dep.is_direct else "transitive"
        findings.append(
            _make_finding(
                "LIC-002",
                title="Weak copyleft license in dependency",
                detail=(
                    f"{'Direct' if dep.is_direct else 'Transitive'} dependency "
                    f"'{dep.name}' ({dep.version}) uses '{license_id}', a weak "
                    "copyleft license. Modifications to this library may need to be "
                    f"shared under the same terms (found as {dep_kind} dependency)."
                ),
                dep_name=dep.name,
            )
        )

    # ---- LIC-003: non-commercial restriction -----------------------------
    if license_id in _NON_COMMERCIAL:
        findings.append(
            _make_finding(
                "LIC-003",
                title="Non-commercial license restriction",
                detail=(
                    f"Dependency '{dep.name}' ({dep.version}) uses '{license_id}', "
                    "which prohibits or restricts commercial use. This is incompatible "
                    "with commercial or revenue-generating projects."
                ),
                dep_name=dep.name,
            )
        )

    # ---- LIC-005: deprecated / obsolete license --------------------------
    if license_id in _DEPRECATED:
        findings.append(
            _make_finding(
                "LIC-005",
                title="Deprecated or obsolete license identifier",
                detail=(
                    f"Dependency '{dep.name}' ({dep.version}) uses '{license_id}', "
                    "which is marked as deprecated or obsolete by SPDX. "
                    "Consider updating to the current SPDX identifier or a newer license."
                ),
                dep_name=dep.name,
            )
        )

    # ---- LIC-006: network copyleft (AGPL) in SaaS context ----------------
    if license_id in _AGPL and deployment_context == "saas":
        findings.append(
            _make_finding(
                "LIC-006",
                title="Network copyleft (AGPL) license in SaaS deployment",
                detail=(
                    f"Dependency '{dep.name}' ({dep.version}) uses '{license_id}' "
                    "(AGPL). When deployed as a SaaS service, users who interact with "
                    "the software over a network are entitled to receive the source code, "
                    "including any modifications."
                ),
                dep_name=dep.name,
            )
        )

    return findings


def check(
    dependencies: List[Dependency],
    project_type: str = "proprietary",
    deployment_context: str = "on_premise",
) -> LICResult:
    """
    Analyze a list of dependencies for license compliance risks.

    Parameters
    ----------
    dependencies:
        List of Dependency objects to analyze.
    project_type:
        Nature of the project: "proprietary", "open_source", or "internal".
        Affects which checks apply (e.g., LIC-001 only fires for "proprietary").
    deployment_context:
        How the project is deployed: "on_premise", "saas", or "library".
        Affects LIC-006 (AGPL network copyleft).

    Returns
    -------
    LICResult with all findings, a capped risk score, and a compliance flag.
    """
    all_findings: List[LICFinding] = []

    for dep in dependencies:
        dep_findings = _analyze_dependency(dep, project_type, deployment_context)
        all_findings.extend(dep_findings)

    risk_score = _compute_risk_score(all_findings)
    return LICResult(
        findings=all_findings,
        risk_score=risk_score,
        compliant=(risk_score == 0),
    )


def check_many(
    dependency_lists: List[List[Dependency]],
    project_type: str = "proprietary",
    deployment_context: str = "on_premise",
) -> List[LICResult]:
    """
    Run license compliance checks against multiple independent dependency sets.

    Parameters
    ----------
    dependency_lists:
        Each inner list represents a distinct project's dependencies.
    project_type:
        Applied uniformly to all dependency lists.
    deployment_context:
        Applied uniformly to all dependency lists.

    Returns
    -------
    List of LICResult objects, one per input dependency list (same order).
    """
    return [
        check(deps, project_type=project_type, deployment_context=deployment_context)
        for deps in dependency_lists
    ]
