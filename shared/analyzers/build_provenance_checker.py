# CC BY 4.0 — Cyber Port Portfolio
# https://creativecommons.org/licenses/by/4.0/
# Module: build_provenance_checker.py
# Purpose: Verify build artifact provenance metadata for SLSA compliance,
#          reproducibility, and supply chain integrity — detecting missing
#          attestations, unpinned dependencies, unsigned outputs, and
#          missing build metadata.

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Check weights — single source of truth for scoring
# ---------------------------------------------------------------------------
_CHECK_WEIGHTS: Dict[str, int] = {
    "PROV-001": 25,  # No SLSA provenance attestation
    "PROV-002": 25,  # SLSA level below required minimum
    "PROV-003": 25,  # Source not pinned to a commit SHA
    "PROV-004": 20,  # Build environment is not hermetic
    "PROV-005": 20,  # Build output artifact is not signed
    "PROV-006": 15,  # Build timestamp is missing or zero
    "PROV-007": 15,  # Build materials contain unpinned references
}

# Regex for a full 40-character lowercase hex commit SHA
_SHA40_RE = re.compile(r"[0-9a-f]{40}")

# Regex for a strict semver pin like "1.2.3" (no leading v, no range chars)
_STRICT_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")

# Unpinned version-spec tokens
_UNPINNED_TOKENS = ("^", "~", "*", "latest")

# Branch-like name prefixes and exact names that are never a commit SHA
_BRANCH_LIKE_PREFIXES = ("refs/heads/",)
_BRANCH_LIKE_NAMES = {"main", "master", "develop", "HEAD"}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class BuildMaterial:
    """A single build dependency (source, library, tool, etc.)."""

    name: str
    version_spec: str  # e.g. "1.2.3", "^1.2.3", "main", "abc123def..."
    digest: Optional[str]  # SHA-256 or similar hash; None if not recorded


@dataclass
class BuildProvenance:
    """Full provenance record for a single build artifact."""

    artifact_id: str
    artifact_name: str
    slsa_level: Optional[int]       # 0, 1, 2, 3 or None if not attested
    source_ref: str                 # branch name, tag, or commit SHA
    builder_id: str                 # e.g. "github-actions/v1"
    build_timestamp: Optional[int]  # Unix epoch seconds; None if not recorded
    hermetic_build: bool            # False if network access was allowed
    output_digest: Optional[str]    # SHA-256 of output artifact
    output_signed: bool
    materials: List[BuildMaterial]


@dataclass
class PROVFinding:
    """A single provenance policy finding."""

    check_id: str
    severity: str   # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    weight: int


@dataclass
class PROVResult:
    """Aggregated provenance check result for one artifact."""

    artifact_id: str
    artifact_name: str
    findings: List[PROVFinding]
    risk_score: int         # min(100, sum of unique fired check weights)
    slsa_compliant: bool    # True if slsa_level >= required and risk_score < 50

    # ------------------------------------------------------------------
    # Convenience methods
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Return a plain-dict representation suitable for JSON serialisation."""
        return {
            "artifact_id": self.artifact_id,
            "artifact_name": self.artifact_name,
            "risk_score": self.risk_score,
            "slsa_compliant": self.slsa_compliant,
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
        """Return a one-line human-readable summary."""
        compliant_str = "COMPLIANT" if self.slsa_compliant else "NON-COMPLIANT"
        return (
            f"[{compliant_str}] {self.artifact_name} "
            f"(id={self.artifact_id}) — "
            f"risk_score={self.risk_score}, "
            f"findings={len(self.findings)}"
        )

    def by_severity(self) -> Dict[str, List[PROVFinding]]:
        """Return findings grouped by severity label."""
        groups: Dict[str, List[PROVFinding]] = {}
        for finding in self.findings:
            groups.setdefault(finding.severity, []).append(finding)
        return groups


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _is_full_sha(ref: str) -> bool:
    """Return True when *ref* is exactly a 40-char lowercase hex SHA."""
    return bool(_SHA40_RE.fullmatch(ref.lower()))


def _source_is_unpinned(source_ref: str) -> bool:
    """Return True when *source_ref* does not look like a pinned commit SHA."""
    # Explicit branch-like prefix check
    for prefix in _BRANCH_LIKE_PREFIXES:
        if source_ref.lower().startswith(prefix):
            return True
    # Exact well-known branch names
    if source_ref in _BRANCH_LIKE_NAMES:
        return True
    # Anything that is not a full 40-char hex SHA is considered unpinned
    return not _is_full_sha(source_ref)


def _material_is_unpinned(material: BuildMaterial) -> bool:
    """Return True when the material's version spec is not pinned.

    A material is considered pinned when ANY of the following hold (checked in
    this order of priority):
      - its digest is a full 40-char SHA (hash-pinned — overrides spec tokens)
      - its version_spec is a full 40-char SHA
      - its version_spec matches strict X.Y.Z (no range chars, no wildcards)

    A material is considered unpinned when:
      - it has no full-SHA digest AND version_spec contains ^, ~, *, or "latest"
      - OR its digest is None AND the spec is neither a full SHA nor strict X.Y.Z
    """
    spec = material.version_spec

    # A full-SHA digest provides cryptographic pinning regardless of the spec.
    # This check must come first so that hash-pinned materials are never flagged
    # even if the version_spec string happens to contain range tokens.
    if material.digest and _is_full_sha(material.digest):
        return False

    # No full-SHA digest: explicit unpinned tokens in the spec signal unpinned
    for token in _UNPINNED_TOKENS:
        if token in spec:
            return True

    # If the spec itself is a full SHA it is pinned
    if _is_full_sha(spec):
        return False

    # Strict X.Y.Z is an acceptable pin
    if _STRICT_VERSION_RE.match(spec):
        return False

    # Everything else (branch names, partial versions, tags, etc.) is unpinned
    return True


# ---------------------------------------------------------------------------
# Core check function
# ---------------------------------------------------------------------------


def check(
    provenance: BuildProvenance,
    required_slsa_level: int = 2,
) -> PROVResult:
    """Check build provenance for SLSA compliance and supply chain integrity.

    Parameters
    ----------
    provenance:
        The ``BuildProvenance`` record to evaluate.
    required_slsa_level:
        Minimum SLSA level that the artifact must satisfy (default: 2).

    Returns
    -------
    PROVResult
        Aggregated result containing all fired findings, a 0-100 risk score,
        and an overall SLSA compliance flag.
    """
    findings: List[PROVFinding] = []

    # ------------------------------------------------------------------
    # PROV-001: No SLSA provenance attestation present
    # ------------------------------------------------------------------
    prov001_fired = (
        provenance.slsa_level is None or provenance.slsa_level == 0
    )
    if prov001_fired:
        findings.append(
            PROVFinding(
                check_id="PROV-001",
                severity="HIGH",
                title="No SLSA provenance attestation present",
                detail=(
                    f"Artifact '{provenance.artifact_name}' has no SLSA "
                    f"attestation (slsa_level={provenance.slsa_level!r}). "
                    "Provenance cannot be verified."
                ),
                weight=_CHECK_WEIGHTS["PROV-001"],
            )
        )

    # ------------------------------------------------------------------
    # PROV-002: SLSA level below required minimum
    # Suppressed when PROV-001 already fired (no attestation at all).
    # ------------------------------------------------------------------
    if (
        not prov001_fired
        and provenance.slsa_level is not None
        and provenance.slsa_level < required_slsa_level
    ):
        findings.append(
            PROVFinding(
                check_id="PROV-002",
                severity="HIGH",
                title="SLSA level below required minimum",
                detail=(
                    f"Artifact '{provenance.artifact_name}' has SLSA level "
                    f"{provenance.slsa_level}, but the required minimum is "
                    f"{required_slsa_level}."
                ),
                weight=_CHECK_WEIGHTS["PROV-002"],
            )
        )

    # ------------------------------------------------------------------
    # PROV-003: Source ref is not pinned to a commit SHA
    # ------------------------------------------------------------------
    if _source_is_unpinned(provenance.source_ref):
        findings.append(
            PROVFinding(
                check_id="PROV-003",
                severity="HIGH",
                title="Build source not pinned to a commit SHA",
                detail=(
                    f"source_ref='{provenance.source_ref}' is not a 40-char "
                    "hex commit SHA. Branch names and tags are mutable and "
                    "can change after the build was recorded."
                ),
                weight=_CHECK_WEIGHTS["PROV-003"],
            )
        )

    # ------------------------------------------------------------------
    # PROV-004: Build environment is not hermetic
    # ------------------------------------------------------------------
    if not provenance.hermetic_build:
        findings.append(
            PROVFinding(
                check_id="PROV-004",
                severity="HIGH",
                title="Build environment is not hermetic",
                detail=(
                    f"Artifact '{provenance.artifact_name}' was built with "
                    "network access enabled or external fetches detected. "
                    "Non-hermetic builds are vulnerable to supply chain attacks."
                ),
                weight=_CHECK_WEIGHTS["PROV-004"],
            )
        )

    # ------------------------------------------------------------------
    # PROV-005: Build output is not signed / no digest present
    # ------------------------------------------------------------------
    if not provenance.output_signed or provenance.output_digest is None:
        findings.append(
            PROVFinding(
                check_id="PROV-005",
                severity="HIGH",
                title="Build output artifact is not signed",
                detail=(
                    f"Artifact '{provenance.artifact_name}': "
                    f"output_signed={provenance.output_signed}, "
                    f"output_digest={provenance.output_digest!r}. "
                    "Without a signature and digest the artifact cannot be "
                    "verified for integrity."
                ),
                weight=_CHECK_WEIGHTS["PROV-005"],
            )
        )

    # ------------------------------------------------------------------
    # PROV-006: Build timestamp is missing or zero
    # ------------------------------------------------------------------
    if provenance.build_timestamp is None or provenance.build_timestamp == 0:
        findings.append(
            PROVFinding(
                check_id="PROV-006",
                severity="MEDIUM",
                title="Build timestamp is missing or zero",
                detail=(
                    f"Artifact '{provenance.artifact_name}' has no recorded "
                    f"build timestamp (build_timestamp={provenance.build_timestamp!r}). "
                    "Timestamps are required for reproducibility and audit trails."
                ),
                weight=_CHECK_WEIGHTS["PROV-006"],
            )
        )

    # ------------------------------------------------------------------
    # PROV-007: Build materials contain unpinned references
    # Weight counted once even if multiple materials are unpinned.
    # ------------------------------------------------------------------
    unpinned_names: List[str] = [
        m.name for m in provenance.materials if _material_is_unpinned(m)
    ]
    if unpinned_names:
        findings.append(
            PROVFinding(
                check_id="PROV-007",
                severity="MEDIUM",
                title="Build materials contain unpinned references",
                detail=(
                    f"The following {len(unpinned_names)} material(s) are "
                    f"not pinned to an exact version or digest: "
                    f"{', '.join(unpinned_names)}. "
                    "Unpinned dependencies allow silent version drift and "
                    "supply chain substitution attacks."
                ),
                weight=_CHECK_WEIGHTS["PROV-007"],
            )
        )

    # ------------------------------------------------------------------
    # Scoring — weights summed once per unique fired check ID, capped at 100
    # ------------------------------------------------------------------
    fired_weights = [f.weight for f in findings]
    risk_score = min(100, sum(fired_weights))

    # SLSA compliance requires full attestation at or above required level
    # AND a risk score below 50.
    slsa_compliant = (
        provenance.slsa_level is not None
        and provenance.slsa_level >= required_slsa_level
        and risk_score < 50
    )

    return PROVResult(
        artifact_id=provenance.artifact_id,
        artifact_name=provenance.artifact_name,
        findings=findings,
        risk_score=risk_score,
        slsa_compliant=slsa_compliant,
    )


# ---------------------------------------------------------------------------
# Batch helper
# ---------------------------------------------------------------------------


def check_many(
    provenances: List[BuildProvenance],
    required_slsa_level: int = 2,
) -> List[PROVResult]:
    """Run ``check`` over a list of ``BuildProvenance`` records.

    Parameters
    ----------
    provenances:
        Sequence of provenance records to evaluate.
    required_slsa_level:
        Minimum SLSA level forwarded to each ``check`` call.

    Returns
    -------
    List[PROVResult]
        One result per input provenance, in the same order.
    """
    return [check(p, required_slsa_level=required_slsa_level) for p in provenances]
