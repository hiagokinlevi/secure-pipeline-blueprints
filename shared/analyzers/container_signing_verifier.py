# container_signing_verifier.py
# Analyzes container image signing and OCI attestation security properties.
# Operates fully offline — no Docker daemon or registry connection required.
#
# Copyright (c) 2024 Cyber Port contributors
# Licensed under CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Check weight registry
# Each key is a check ID; the value is the integer weight added to risk_score
# when that check fires.  risk_score = min(100, sum of weights for fired IDs).
# ---------------------------------------------------------------------------
_CHECK_WEIGHTS: Dict[str, int] = {
    "SIGN-001": 25,  # No signatures attached to the image
    "SIGN-002": 25,  # Signature from a signer not in the trusted list
    "SIGN-003": 40,  # Signatures present but none passed cryptographic verification
    "SIGN-004": 15,  # SBOM attestation missing
    "SIGN-005": 15,  # Vulnerability-scan attestation missing
    "SIGN-006": 40,  # At least one signature has exceeded max_signature_age_days
    "SIGN-007": 20,  # Image referenced by mutable tag without a pinned digest
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ImageSignature:
    """Represents a single cryptographic signature attached to a container image."""

    signer_identity: str          # e.g. "cosign@mycompany.com", "github-actions@github.com"
    signature_algo: str           # e.g. "ecdsa-p256", "rsa-4096"
    signed_at: Optional[float]    # Unix timestamp of when the signature was created; None if unknown
    verified: bool = False        # True only when cryptographic verification succeeded

    def to_dict(self) -> Dict:
        """Serialize to a plain dictionary for JSON serialisation or logging."""
        return {
            "signer_identity": self.signer_identity,
            "signature_algo": self.signature_algo,
            "signed_at": self.signed_at,
            "verified": self.verified,
        }


@dataclass
class ImageAttestation:
    """Represents an OCI attestation (SBOM, vuln-scan, SLSA provenance, etc.)."""

    attestation_type: str   # "sbom", "vulnerability-scan", "slsa-provenance", "custom"
    predicate_type: str     # URI identifying the attestation schema (in-toto predicate type)
    verified: bool = False  # True when attestation signature was cryptographically verified

    def to_dict(self) -> Dict:
        """Serialize to a plain dictionary."""
        return {
            "attestation_type": self.attestation_type,
            "predicate_type": self.predicate_type,
            "verified": self.verified,
        }


@dataclass
class ContainerImage:
    """Full descriptor for a container image, including its signing state."""

    reference: str                            # Full image reference, e.g. "registry.io/org/image:1.0.0"
    digest: Optional[str] = None              # Immutable sha256 digest, e.g. "sha256:abc123..."
    tag: Optional[str] = None                 # Mutable tag, e.g. "1.0.0", "latest"; may be None
    signatures: List[ImageSignature] = field(default_factory=list)    # All signatures attached
    attestations: List[ImageAttestation] = field(default_factory=list) # All attestations attached
    registry: Optional[str] = None            # Registry hostname, e.g. "registry.io"

    def to_dict(self) -> Dict:
        """Serialize to a plain dictionary, including nested objects."""
        return {
            "reference": self.reference,
            "digest": self.digest,
            "tag": self.tag,
            "registry": self.registry,
            "signatures": [s.to_dict() for s in self.signatures],
            "attestations": [a.to_dict() for a in self.attestations],
        }


@dataclass
class SigningFinding:
    """A single security finding produced by one of the SIGN-* checks."""

    check_id: str          # e.g. "SIGN-001"
    severity: str          # "CRITICAL", "HIGH", or "MEDIUM"
    image_reference: str   # The image reference the finding applies to
    message: str           # Human-readable description of the problem
    recommendation: str    # Actionable remediation guidance

    def to_dict(self) -> Dict:
        """Serialize to a plain dictionary."""
        return {
            "check_id": self.check_id,
            "severity": self.severity,
            "image_reference": self.image_reference,
            "message": self.message,
            "recommendation": self.recommendation,
        }


@dataclass
class SigningVerifyResult:
    """Aggregated verification result for a single ContainerImage."""

    image_reference: str                # The image reference that was evaluated
    findings: List[SigningFinding] = field(default_factory=list)  # All fired findings
    risk_score: int = 0                 # Aggregate risk score in the range [0, 100]

    # ------------------------------------------------------------------
    # Computed helpers
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """Return a one-line human-readable summary of the verification result."""
        if not self.findings:
            return (
                f"[OK] {self.image_reference} — no signing issues detected "
                f"(risk_score={self.risk_score})"
            )
        # Tally severities for the summary line
        counts: Dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        parts = ", ".join(
            f"{sev}×{cnt}"
            for sev, cnt in sorted(counts.items())
        )
        return (
            f"[FINDINGS] {self.image_reference} — "
            f"{len(self.findings)} finding(s) [{parts}] "
            f"(risk_score={self.risk_score})"
        )

    def by_severity(self) -> Dict[str, List[SigningFinding]]:
        """Return findings grouped by severity label."""
        grouped: Dict[str, List[SigningFinding]] = {}
        for finding in self.findings:
            grouped.setdefault(finding.severity, []).append(finding)
        return grouped

    def to_dict(self) -> Dict:
        """Serialize the full result to a plain dictionary."""
        return {
            "image_reference": self.image_reference,
            "risk_score": self.risk_score,
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary(),
        }


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------

class ContainerSigningVerifier:
    """
    Analyses a ContainerImage for signing and attestation security issues.

    All checks are performed locally against the data already present in the
    ContainerImage object — no network calls or daemon connections are made.

    Parameters
    ----------
    trusted_signers:
        Optional allow-list of signer identities.  When None (default), the
        SIGN-002 check is skipped entirely — no trust-list is enforced.
        Pass an explicit list (even an empty one) to begin enforcement.
    max_signature_age_days:
        Number of days before a signature's ``signed_at`` timestamp is
        considered expired and SIGN-006 fires.  Defaults to 365 days.
    """

    def __init__(
        self,
        trusted_signers: Optional[List[str]] = None,
        max_signature_age_days: int = 365,
    ) -> None:
        # None means "trust-list not configured — skip SIGN-002"
        self.trusted_signers: Optional[List[str]] = trusted_signers
        self.max_signature_age_days: int = max_signature_age_days

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def verify(self, image: ContainerImage) -> SigningVerifyResult:
        """Run all SIGN-* checks against *image* and return a SigningVerifyResult."""
        findings: List[SigningFinding] = []

        findings.extend(self._check_sign_001(image))
        findings.extend(self._check_sign_002(image))
        findings.extend(self._check_sign_003(image))
        findings.extend(self._check_sign_004(image))
        findings.extend(self._check_sign_005(image))
        findings.extend(self._check_sign_006(image))
        findings.extend(self._check_sign_007(image))

        # Compute risk_score using unique fired check IDs only
        fired_ids = {f.check_id for f in findings}
        risk_score = min(100, sum(_CHECK_WEIGHTS[cid] for cid in fired_ids))

        return SigningVerifyResult(
            image_reference=image.reference,
            findings=findings,
            risk_score=risk_score,
        )

    def verify_many(self, images: List[ContainerImage]) -> List[SigningVerifyResult]:
        """Run verify() on each image and return the list of results in order."""
        return [self.verify(img) for img in images]

    # ------------------------------------------------------------------
    # Private per-check methods
    # ------------------------------------------------------------------

    def _check_sign_001(self, image: ContainerImage) -> List[SigningFinding]:
        """SIGN-001 — Image has no signatures (HIGH, weight 25)."""
        if len(image.signatures) == 0:
            return [SigningFinding(
                check_id="SIGN-001",
                severity="HIGH",
                image_reference=image.reference,
                message=(
                    f"Image '{image.reference}' has no cryptographic signatures attached."
                ),
                recommendation=(
                    "Sign the image with cosign or a compatible signing tool before "
                    "deploying to production.  Store the public key in your policy engine."
                ),
            )]
        return []

    def _check_sign_002(self, image: ContainerImage) -> List[SigningFinding]:
        """SIGN-002 — Signature from untrusted signer (HIGH, weight 25).

        Skipped entirely when trusted_signers is None (trust-list not configured).
        """
        # Skip when no trust list has been configured
        if self.trusted_signers is None:
            return []

        findings: List[SigningFinding] = []
        trusted_set = set(self.trusted_signers)
        for sig in image.signatures:
            if sig.signer_identity not in trusted_set:
                findings.append(SigningFinding(
                    check_id="SIGN-002",
                    severity="HIGH",
                    image_reference=image.reference,
                    message=(
                        f"Signature on '{image.reference}' is from signer "
                        f"'{sig.signer_identity}', which is not in the trusted-signers list."
                    ),
                    recommendation=(
                        "Only accept images signed by identities in your approved signer "
                        "allow-list.  Add the signer to trusted_signers if it is legitimate, "
                        "or reject the image."
                    ),
                ))
        return findings

    def _check_sign_003(self, image: ContainerImage) -> List[SigningFinding]:
        """SIGN-003 — Signatures present but none cryptographically verified (CRITICAL, weight 40)."""
        if len(image.signatures) == 0:
            # SIGN-001 already covers the no-signatures case; nothing to do here
            return []
        if not any(sig.verified for sig in image.signatures):
            return [SigningFinding(
                check_id="SIGN-003",
                severity="CRITICAL",
                image_reference=image.reference,
                message=(
                    f"Image '{image.reference}' has {len(image.signatures)} signature(s) "
                    "but none passed cryptographic verification."
                ),
                recommendation=(
                    "Verify signatures against the expected public key or keyless identity "
                    "using cosign verify.  Reject images whose signatures cannot be verified."
                ),
            )]
        return []

    def _check_sign_004(self, image: ContainerImage) -> List[SigningFinding]:
        """SIGN-004 — SBOM attestation missing (MEDIUM, weight 15)."""
        has_sbom = any(
            a.attestation_type == "sbom" for a in image.attestations
        )
        if not has_sbom:
            return [SigningFinding(
                check_id="SIGN-004",
                severity="MEDIUM",
                image_reference=image.reference,
                message=(
                    f"Image '{image.reference}' is missing an SBOM attestation."
                ),
                recommendation=(
                    "Generate an SBOM (e.g. with Syft or Trivy) and attach it as an "
                    "OCI attestation using cosign attest.  SBOMs are required for supply-chain "
                    "transparency and compliance."
                ),
            )]
        return []

    def _check_sign_005(self, image: ContainerImage) -> List[SigningFinding]:
        """SIGN-005 — Vulnerability-scan attestation missing (MEDIUM, weight 15)."""
        has_vuln_scan = any(
            a.attestation_type == "vulnerability-scan" for a in image.attestations
        )
        if not has_vuln_scan:
            return [SigningFinding(
                check_id="SIGN-005",
                severity="MEDIUM",
                image_reference=image.reference,
                message=(
                    f"Image '{image.reference}' is missing a vulnerability-scan attestation."
                ),
                recommendation=(
                    "Run a vulnerability scan (e.g. Grype, Trivy) and attach the results as "
                    "an OCI attestation before publishing.  Policy engines can then gate "
                    "deployments on acceptable CVE thresholds."
                ),
            )]
        return []

    def _check_sign_006(self, image: ContainerImage) -> List[SigningFinding]:
        """SIGN-006 — Signature age exceeds max_signature_age_days (CRITICAL, weight 40)."""
        threshold_seconds = self.max_signature_age_days * 86400
        now = time.time()
        findings: List[SigningFinding] = []
        for sig in image.signatures:
            if sig.signed_at is not None and (now - sig.signed_at) > threshold_seconds:
                findings.append(SigningFinding(
                    check_id="SIGN-006",
                    severity="CRITICAL",
                    image_reference=image.reference,
                    message=(
                        f"Signature by '{sig.signer_identity}' on '{image.reference}' was "
                        f"created more than {self.max_signature_age_days} day(s) ago and is "
                        "considered expired."
                    ),
                    recommendation=(
                        "Re-sign the image with a current timestamp and rotate keys if "
                        "necessary.  Enforce a signature-age policy in your admission controller."
                    ),
                ))
        return findings

    def _check_sign_007(self, image: ContainerImage) -> List[SigningFinding]:
        """SIGN-007 — Image referenced by mutable tag without a pinned digest (HIGH, weight 20).

        Fires when:
          • digest is absent AND a non-empty tag is present, OR
          • the tag is literally "latest" (regardless of digest, because latest is
            semantically unpinned and should be avoided in production).
        """
        # "latest" tag is always a red flag — explicitly check it first
        if image.tag == "latest":
            return [SigningFinding(
                check_id="SIGN-007",
                severity="HIGH",
                image_reference=image.reference,
                message=(
                    f"Image '{image.reference}' uses the mutable 'latest' tag.  "
                    "The 'latest' tag can be silently overwritten, breaking reproducibility."
                ),
                recommendation=(
                    "Pin the image by digest (sha256:...) or use an immutable, versioned tag "
                    "together with a digest.  Never use 'latest' in production manifests."
                ),
            )]

        # No digest AND a non-empty tag present
        if image.digest is None and image.tag is not None and image.tag != "":
            return [SigningFinding(
                check_id="SIGN-007",
                severity="HIGH",
                image_reference=image.reference,
                message=(
                    f"Image '{image.reference}' is referenced by the mutable tag "
                    f"'{image.tag}' without a pinned digest.  The tag can be overwritten "
                    "to point to a different image."
                ),
                recommendation=(
                    "Pin the image reference by adding a sha256 digest, for example: "
                    f"'{image.reference}@sha256:<digest>'.  Resolve digests at build time "
                    "and store them in version control."
                ),
            )]

        return []
