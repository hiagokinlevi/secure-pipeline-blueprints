# artifact_integrity_checker.py
# Build artifact integrity checker — verifies software artifact provenance,
# signatures, and integrity properties. Works offline on artifact metadata.
#
# Copyright (C) 2024 Cyber Port
# Licensed under CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/
# SPDX-License-Identifier: CC-BY-4.0
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Risk weight registry — every check ID maps to its additive risk contribution.
# risk_score = min(100, sum of weights for each unique fired check ID).
# ---------------------------------------------------------------------------
_CHECK_WEIGHTS: Dict[str, int] = {
    "ART-001": 25,  # Missing checksum
    "ART-002": 20,  # Weak hash algorithm
    "ART-003": 20,  # Unverified source
    "ART-004": 15,  # SLSA provenance below minimum or unknown
    "ART-005": 20,  # Missing digital signature
    "ART-006": 15,  # Artifact age exceeds max_age_days
    "ART-007": 45,  # Checksum mismatch (critical — integrity failure)
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ArtifactMetadata:
    """Describes a software artifact to be evaluated for integrity properties.

    No file download is performed; all analysis works on metadata fields only.
    """

    # Human-readable artifact identifier, e.g. "myapp-1.0.0.jar"
    name: str

    # Artifact category: "docker-image" | "npm-package" | "python-wheel" |
    # "java-jar" | "binary" | "archive"
    artifact_type: str

    # URL the artifact was (or would be) fetched from; None if unknown
    source_url: Optional[str] = None

    # Hash algorithm used for checksum_value, e.g. "sha256", "sha512",
    # "sha1", "md5"; None when no checksum is provided at all
    checksum_algo: Optional[str] = None

    # Actual checksum value accompanying the artifact
    checksum_value: Optional[str] = None

    # Authoritative expected checksum to compare against (from a trusted
    # manifest or lockfile)
    expected_checksum: Optional[str] = None

    # True when the artifact ships with a digital signature (e.g. GPG, sigstore)
    has_digital_signature: bool = False

    # True when the signature has been cryptographically verified
    signature_verified: bool = False

    # SLSA provenance level (0–4); None means provenance is unknown
    slsa_level: Optional[int] = None

    # Unix timestamp (float) of publication; None if unknown
    published_at: Optional[float] = None

    # True when source_url resolves to a known, verified official registry
    source_is_verified: bool = False

    def to_dict(self) -> Dict:
        """Return a plain-dict representation suitable for serialisation."""
        return {
            "name": self.name,
            "artifact_type": self.artifact_type,
            "source_url": self.source_url,
            "checksum_algo": self.checksum_algo,
            "checksum_value": self.checksum_value,
            "expected_checksum": self.expected_checksum,
            "has_digital_signature": self.has_digital_signature,
            "signature_verified": self.signature_verified,
            "slsa_level": self.slsa_level,
            "published_at": self.published_at,
            "source_is_verified": self.source_is_verified,
        }


@dataclass
class IntegrityFinding:
    """A single integrity or provenance issue found in an artifact."""

    # Check identifier, e.g. "ART-001"
    check_id: str

    # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    severity: str

    # Artifact name from ArtifactMetadata.name
    artifact_name: str

    # Artifact type from ArtifactMetadata.artifact_type
    artifact_type: str

    # Human-readable description of the specific problem found
    message: str

    # Actionable remediation advice
    recommendation: str

    def to_dict(self) -> Dict:
        """Return a plain-dict representation suitable for serialisation."""
        return {
            "check_id": self.check_id,
            "severity": self.severity,
            "artifact_name": self.artifact_name,
            "artifact_type": self.artifact_type,
            "message": self.message,
            "recommendation": self.recommendation,
        }


@dataclass
class IntegrityCheckResult:
    """Aggregated result of running all integrity checks against one artifact."""

    # The artifact that was evaluated
    artifact: ArtifactMetadata

    # All findings raised during this evaluation (may be empty for a clean artifact)
    findings: List[IntegrityFinding] = field(default_factory=list)

    # Composite risk score 0–100 (higher = more risk)
    risk_score: int = 0

    # ------------------------------------------------------------------
    # Derived / query helpers
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """Return a one-line human-readable summary of this result."""
        count = len(self.findings)
        if count == 0:
            return (
                f"[{self.artifact.name}] No integrity issues found. "
                f"Risk score: {self.risk_score}/100."
            )
        sev_counts: Dict[str, int] = {}
        for f in self.findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        sev_summary = ", ".join(
            f"{v} {k}" for k, v in sorted(sev_counts.items())
        )
        return (
            f"[{self.artifact.name}] {count} finding(s) "
            f"({sev_summary}). Risk score: {self.risk_score}/100."
        )

    def by_severity(self) -> Dict[str, List[IntegrityFinding]]:
        """Return findings grouped by severity label.

        All five canonical severity keys are always present so callers can
        iterate predictably without key-existence checks.
        """
        groups: Dict[str, List[IntegrityFinding]] = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
            "INFO": [],
        }
        for finding in self.findings:
            bucket = finding.severity.upper()
            if bucket not in groups:
                groups[bucket] = []
            groups[bucket].append(finding)
        return groups

    def to_dict(self) -> Dict:
        """Return a plain-dict representation suitable for serialisation."""
        return {
            "artifact": self.artifact.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "risk_score": self.risk_score,
            "summary": self.summary(),
        }


# ---------------------------------------------------------------------------
# Checker
# ---------------------------------------------------------------------------

class ArtifactIntegrityChecker:
    """Evaluates ArtifactMetadata objects against a set of integrity checks.

    All checks operate purely on metadata — no network calls, no file I/O.

    Parameters
    ----------
    min_slsa_level:
        Minimum acceptable SLSA provenance level (0–4). Artifacts reporting a
        level below this threshold will trigger ART-004. Defaults to 2.
    max_age_days:
        Maximum acceptable artifact age in days. Artifacts older than this will
        trigger ART-006. Defaults to 365.
    weak_hash_algos:
        List of hash algorithm names (lowercase) considered cryptographically
        weak. Defaults to ["md5", "sha1"].
    """

    def __init__(
        self,
        min_slsa_level: int = 2,
        max_age_days: int = 365,
        weak_hash_algos: Optional[List[str]] = None,
    ) -> None:
        self.min_slsa_level = min_slsa_level
        self.max_age_days = max_age_days
        # Store as lowercase for case-insensitive comparison
        if weak_hash_algos is None:
            self.weak_hash_algos: List[str] = ["md5", "sha1"]
        else:
            self.weak_hash_algos = [a.lower() for a in weak_hash_algos]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self, artifact: ArtifactMetadata) -> IntegrityCheckResult:
        """Run all integrity checks against *artifact* and return a result."""
        findings: List[IntegrityFinding] = []

        # Run every check in definition order; each appends to *findings*
        # if the corresponding condition is met.
        self._check_art001(artifact, findings)
        self._check_art002(artifact, findings)
        self._check_art003(artifact, findings)
        self._check_art004(artifact, findings)
        self._check_art005(artifact, findings)
        self._check_art006(artifact, findings)
        self._check_art007(artifact, findings)

        # Compute risk score: sum weights of unique fired check IDs, cap at 100.
        fired_ids = {f.check_id for f in findings}
        raw_score = sum(_CHECK_WEIGHTS.get(cid, 0) for cid in fired_ids)
        risk_score = min(100, raw_score)

        return IntegrityCheckResult(
            artifact=artifact,
            findings=findings,
            risk_score=risk_score,
        )

    def check_many(
        self, artifacts: List[ArtifactMetadata]
    ) -> List[IntegrityCheckResult]:
        """Run :meth:`check` against every artifact in *artifacts* in order."""
        return [self.check(a) for a in artifacts]

    # ------------------------------------------------------------------
    # Individual check implementations (private)
    # ------------------------------------------------------------------

    def _check_art001(
        self,
        artifact: ArtifactMetadata,
        findings: List[IntegrityFinding],
    ) -> None:
        """ART-001 — Missing checksum (HIGH, weight 25)."""
        missing = (
            artifact.checksum_algo is None
            or artifact.checksum_value is None
            or artifact.checksum_value == ""
        )
        if missing:
            findings.append(
                IntegrityFinding(
                    check_id="ART-001",
                    severity="HIGH",
                    artifact_name=artifact.name,
                    artifact_type=artifact.artifact_type,
                    message=(
                        f"Artifact '{artifact.name}' has no checksum or an "
                        "empty checksum value. Integrity cannot be verified."
                    ),
                    recommendation=(
                        "Provide a checksum_algo (e.g. 'sha256') and a "
                        "non-empty checksum_value for every artifact. "
                        "Prefer SHA-256 or SHA-512."
                    ),
                )
            )

    def _check_art002(
        self,
        artifact: ArtifactMetadata,
        findings: List[IntegrityFinding],
    ) -> None:
        """ART-002 — Weak hash algorithm (HIGH, weight 20)."""
        if (
            artifact.checksum_algo is not None
            and artifact.checksum_algo.lower() in self.weak_hash_algos
        ):
            findings.append(
                IntegrityFinding(
                    check_id="ART-002",
                    severity="HIGH",
                    artifact_name=artifact.name,
                    artifact_type=artifact.artifact_type,
                    message=(
                        f"Artifact '{artifact.name}' uses the weak hash "
                        f"algorithm '{artifact.checksum_algo}'. "
                        "Collision attacks are feasible against this algorithm."
                    ),
                    recommendation=(
                        "Replace the checksum with one computed using SHA-256 "
                        "or SHA-512. Regenerate and redistribute the manifest."
                    ),
                )
            )

    def _check_art003(
        self,
        artifact: ArtifactMetadata,
        findings: List[IntegrityFinding],
    ) -> None:
        """ART-003 — Artifact from unverified source (HIGH, weight 20)."""
        if artifact.source_url is not None and not artifact.source_is_verified:
            findings.append(
                IntegrityFinding(
                    check_id="ART-003",
                    severity="HIGH",
                    artifact_name=artifact.name,
                    artifact_type=artifact.artifact_type,
                    message=(
                        f"Artifact '{artifact.name}' originates from "
                        f"'{artifact.source_url}', which is not a verified "
                        "official registry."
                    ),
                    recommendation=(
                        "Fetch artifacts exclusively from verified official "
                        "registries (e.g. PyPI, npm, Docker Hub official). "
                        "Set source_is_verified=True only after confirming "
                        "the registry URL against your organisation's approved list."
                    ),
                )
            )

    def _check_art004(
        self,
        artifact: ArtifactMetadata,
        findings: List[IntegrityFinding],
    ) -> None:
        """ART-004 — SLSA provenance level below minimum or unknown (MEDIUM, weight 15)."""
        slsa_insufficient = artifact.slsa_level is None or (
            artifact.slsa_level < self.min_slsa_level
        )
        if slsa_insufficient:
            level_desc = (
                "unknown" if artifact.slsa_level is None
                else str(artifact.slsa_level)
            )
            findings.append(
                IntegrityFinding(
                    check_id="ART-004",
                    severity="MEDIUM",
                    artifact_name=artifact.name,
                    artifact_type=artifact.artifact_type,
                    message=(
                        f"Artifact '{artifact.name}' has SLSA provenance level "
                        f"{level_desc}, below the required minimum of "
                        f"{self.min_slsa_level}."
                    ),
                    recommendation=(
                        f"Ensure the build pipeline generates SLSA level "
                        f"{self.min_slsa_level}+ provenance attestations. "
                        "See https://slsa.dev for guidance."
                    ),
                )
            )

    def _check_art005(
        self,
        artifact: ArtifactMetadata,
        findings: List[IntegrityFinding],
    ) -> None:
        """ART-005 — Missing digital signature (HIGH, weight 20)."""
        if not artifact.has_digital_signature:
            findings.append(
                IntegrityFinding(
                    check_id="ART-005",
                    severity="HIGH",
                    artifact_name=artifact.name,
                    artifact_type=artifact.artifact_type,
                    message=(
                        f"Artifact '{artifact.name}' has no digital signature. "
                        "Origin and authenticity cannot be cryptographically verified."
                    ),
                    recommendation=(
                        "Sign artifacts with a trusted key (GPG, sigstore/cosign). "
                        "Automate signing in the CI/CD pipeline and publish the "
                        "public key to a key server or transparency log."
                    ),
                )
            )

    def _check_art006(
        self,
        artifact: ArtifactMetadata,
        findings: List[IntegrityFinding],
    ) -> None:
        """ART-006 — Artifact age exceeds max_age_days (MEDIUM, weight 15)."""
        if artifact.published_at is not None:
            age_seconds = time.time() - artifact.published_at
            if age_seconds > self.max_age_days * 86400:
                age_days = int(age_seconds // 86400)
                findings.append(
                    IntegrityFinding(
                        check_id="ART-006",
                        severity="MEDIUM",
                        artifact_name=artifact.name,
                        artifact_type=artifact.artifact_type,
                        message=(
                            f"Artifact '{artifact.name}' is approximately "
                            f"{age_days} days old, exceeding the maximum "
                            f"allowed age of {self.max_age_days} days."
                        ),
                        recommendation=(
                            "Update to a newer artifact version. Stale "
                            "artifacts may contain unpatched vulnerabilities "
                            "and should be rotated regularly."
                        ),
                    )
                )

    def _check_art007(
        self,
        artifact: ArtifactMetadata,
        findings: List[IntegrityFinding],
    ) -> None:
        """ART-007 — Checksum mismatch (CRITICAL, weight 45)."""
        cv = artifact.checksum_value
        ec = artifact.expected_checksum

        # Both values must be non-empty strings to perform a meaningful comparison
        if (
            cv is not None and cv != ""
            and ec is not None and ec != ""
            and cv.lower().strip() != ec.lower().strip()
        ):
            findings.append(
                IntegrityFinding(
                    check_id="ART-007",
                    severity="CRITICAL",
                    artifact_name=artifact.name,
                    artifact_type=artifact.artifact_type,
                    message=(
                        f"Artifact '{artifact.name}' checksum mismatch: "
                        f"actual '{cv}' does not match expected '{ec}'. "
                        "The artifact may have been tampered with."
                    ),
                    recommendation=(
                        "Do NOT use this artifact. Re-download from the "
                        "official source and re-verify. Investigate whether "
                        "the supply chain has been compromised."
                    ),
                )
            )
