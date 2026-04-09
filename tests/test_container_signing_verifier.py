# test_container_signing_verifier.py
# Comprehensive test suite for ContainerSigningVerifier.
#
# Copyright (c) 2024 Cyber Port contributors
# Licensed under CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

# Allow running from the repo root without an installed package
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared" / "analyzers"))

from container_signing_verifier import (
    _CHECK_WEIGHTS,
    ContainerImage,
    ContainerSigningVerifier,
    ImageAttestation,
    ImageSignature,
    SigningFinding,
    SigningVerifyResult,
)


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

TRUSTED = ["cosign@company.com", "github-actions@github.com"]

NOW = time.time()
RECENT_TS = NOW - 86400          # 1 day ago — always fresh
OLD_TS = NOW - (400 * 86400)     # 400 days ago — always expired (default 365-day limit)


def _good_sig(
    identity: str = "cosign@company.com",
    signed_at: float = RECENT_TS,
    verified: bool = True,
) -> ImageSignature:
    """Return a fully compliant signature."""
    return ImageSignature(
        signer_identity=identity,
        signature_algo="ecdsa-p256",
        signed_at=signed_at,
        verified=verified,
    )


def _sbom_attestation(verified: bool = True) -> ImageAttestation:
    return ImageAttestation(
        attestation_type="sbom",
        predicate_type="https://spdx.dev/Document",
        verified=verified,
    )


def _vuln_attestation(verified: bool = True) -> ImageAttestation:
    return ImageAttestation(
        attestation_type="vulnerability-scan",
        predicate_type="https://cosign.sigstore.dev/attestation/vuln/v1",
        verified=verified,
    )


def _compliant_image(reference: str = "registry.io/org/app:1.0.0") -> ContainerImage:
    """Return an image that should pass all checks (no findings expected)."""
    return ContainerImage(
        reference=reference,
        digest="sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        tag="1.0.0",
        registry="registry.io",
        signatures=[_good_sig()],
        attestations=[_sbom_attestation(), _vuln_attestation()],
    )


def _verifier(trusted: list = None, max_age: int = 365) -> ContainerSigningVerifier:
    return ContainerSigningVerifier(trusted_signers=trusted, max_signature_age_days=max_age)


# ---------------------------------------------------------------------------
# 1. Fully compliant image — zero findings
# ---------------------------------------------------------------------------

class TestCompliantImage:
    def test_no_findings(self):
        result = _verifier().verify(_compliant_image())
        assert result.findings == []

    def test_risk_score_zero(self):
        result = _verifier().verify(_compliant_image())
        assert result.risk_score == 0

    def test_summary_ok_prefix(self):
        result = _verifier().verify(_compliant_image())
        assert result.summary().startswith("[OK]")

    def test_by_severity_empty(self):
        result = _verifier().verify(_compliant_image())
        assert result.by_severity() == {}

    def test_to_dict_no_findings(self):
        d = _verifier().verify(_compliant_image()).to_dict()
        assert d["findings"] == []
        assert d["risk_score"] == 0


# ---------------------------------------------------------------------------
# 2. SIGN-001 — no signatures
# ---------------------------------------------------------------------------

class TestSign001:
    def test_fires_when_no_signatures(self):
        img = _compliant_image()
        img.signatures = []
        findings = _verifier().verify(img).findings
        ids = [f.check_id for f in findings]
        assert "SIGN-001" in ids

    def test_does_not_fire_with_one_signature(self):
        img = _compliant_image()  # already has one signature
        findings = _verifier().verify(img).findings
        ids = [f.check_id for f in findings]
        assert "SIGN-001" not in ids

    def test_severity_is_high(self):
        img = _compliant_image()
        img.signatures = []
        finding = next(f for f in _verifier().verify(img).findings if f.check_id == "SIGN-001")
        assert finding.severity == "HIGH"

    def test_weight_contributes_to_score(self):
        img = _compliant_image()
        img.signatures = []
        score = _verifier().verify(img).risk_score
        assert score >= _CHECK_WEIGHTS["SIGN-001"]

    def test_image_reference_in_finding(self):
        ref = "registry.io/org/myapp:2.0.0"
        img = _compliant_image(reference=ref)
        img.signatures = []
        finding = next(f for f in _verifier().verify(img).findings if f.check_id == "SIGN-001")
        assert ref in finding.image_reference


# ---------------------------------------------------------------------------
# 3. SIGN-002 — untrusted signer
# ---------------------------------------------------------------------------

class TestSign002:
    def test_fires_when_signer_not_in_list(self):
        img = _compliant_image()
        img.signatures = [_good_sig(identity="unknown@evil.com")]
        v = _verifier(trusted=TRUSTED)
        findings = v.verify(img).findings
        ids = [f.check_id for f in findings]
        assert "SIGN-002" in ids

    def test_does_not_fire_when_signer_in_list(self):
        img = _compliant_image()
        img.signatures = [_good_sig(identity="cosign@company.com")]
        v = _verifier(trusted=TRUSTED)
        findings = v.verify(img).findings
        ids = [f.check_id for f in findings]
        assert "SIGN-002" not in ids

    def test_skipped_when_trusted_signers_none(self):
        img = _compliant_image()
        img.signatures = [_good_sig(identity="whoever@anywhere.com")]
        v = _verifier(trusted=None)
        findings = v.verify(img).findings
        ids = [f.check_id for f in findings]
        assert "SIGN-002" not in ids

    def test_skipped_when_no_signatures_and_trusted_signers_none(self):
        img = _compliant_image()
        img.signatures = []
        v = _verifier(trusted=None)
        findings = v.verify(img).findings
        ids = [f.check_id for f in findings]
        assert "SIGN-002" not in ids

    def test_fires_once_per_untrusted_signer(self):
        img = _compliant_image()
        img.signatures = [
            _good_sig(identity="bad1@evil.com"),
            _good_sig(identity="bad2@evil.com"),
        ]
        v = _verifier(trusted=TRUSTED)
        sign002_findings = [f for f in v.verify(img).findings if f.check_id == "SIGN-002"]
        assert len(sign002_findings) == 2

    def test_mixed_trusted_untrusted_fires_only_for_untrusted(self):
        img = _compliant_image()
        img.signatures = [
            _good_sig(identity="cosign@company.com"),
            _good_sig(identity="evil@hacker.com"),
        ]
        v = _verifier(trusted=TRUSTED)
        sign002_findings = [f for f in v.verify(img).findings if f.check_id == "SIGN-002"]
        assert len(sign002_findings) == 1
        assert "evil@hacker.com" in sign002_findings[0].message

    def test_severity_is_high(self):
        img = _compliant_image()
        img.signatures = [_good_sig(identity="bad@evil.com")]
        v = _verifier(trusted=TRUSTED)
        finding = next(f for f in v.verify(img).findings if f.check_id == "SIGN-002")
        assert finding.severity == "HIGH"

    def test_skipped_when_empty_trusted_list_but_not_none(self):
        # An empty list [] means the list IS configured — check IS enforced
        img = _compliant_image()
        img.signatures = [_good_sig(identity="anyone@anywhere.com")]
        v = _verifier(trusted=[])
        ids = [f.check_id for f in v.verify(img).findings]
        assert "SIGN-002" in ids

    def test_multiple_trusted_signers(self):
        trusted = ["alice@corp.com", "bob@corp.com", "ci@github.com"]
        img = _compliant_image()
        for identity in trusted:
            img_copy = _compliant_image()
            img_copy.signatures = [_good_sig(identity=identity)]
            v = _verifier(trusted=trusted)
            ids = [f.check_id for f in v.verify(img_copy).findings]
            assert "SIGN-002" not in ids


# ---------------------------------------------------------------------------
# 4. SIGN-003 — signatures present but none verified
# ---------------------------------------------------------------------------

class TestSign003:
    def test_fires_when_no_verified_sig(self):
        img = _compliant_image()
        img.signatures = [_good_sig(verified=False)]
        findings = _verifier().verify(img).findings
        ids = [f.check_id for f in findings]
        assert "SIGN-003" in ids

    def test_does_not_fire_when_one_sig_verified(self):
        img = _compliant_image()
        img.signatures = [_good_sig(verified=True)]
        findings = _verifier().verify(img).findings
        ids = [f.check_id for f in findings]
        assert "SIGN-003" not in ids

    def test_does_not_fire_with_mixed_verified_unverified(self):
        img = _compliant_image()
        img.signatures = [
            _good_sig(verified=False),
            _good_sig(verified=True),
        ]
        ids = [f.check_id for f in _verifier().verify(img).findings]
        assert "SIGN-003" not in ids

    def test_does_not_fire_when_no_signatures(self):
        # SIGN-001 handles that case; SIGN-003 must not double-fire
        img = _compliant_image()
        img.signatures = []
        ids = [f.check_id for f in _verifier().verify(img).findings]
        assert "SIGN-003" not in ids

    def test_severity_is_critical(self):
        img = _compliant_image()
        img.signatures = [_good_sig(verified=False)]
        finding = next(f for f in _verifier().verify(img).findings if f.check_id == "SIGN-003")
        assert finding.severity == "CRITICAL"

    def test_fires_once_regardless_of_signature_count(self):
        img = _compliant_image()
        img.signatures = [_good_sig(verified=False), _good_sig(verified=False)]
        sign003_findings = [f for f in _verifier().verify(img).findings if f.check_id == "SIGN-003"]
        assert len(sign003_findings) == 1


# ---------------------------------------------------------------------------
# 5. SIGN-004 — SBOM attestation missing
# ---------------------------------------------------------------------------

class TestSign004:
    def test_fires_when_no_sbom(self):
        img = _compliant_image()
        img.attestations = [_vuln_attestation()]  # only vuln scan, no sbom
        ids = [f.check_id for f in _verifier().verify(img).findings]
        assert "SIGN-004" in ids

    def test_does_not_fire_when_sbom_present(self):
        img = _compliant_image()  # already has sbom attestation
        ids = [f.check_id for f in _verifier().verify(img).findings]
        assert "SIGN-004" not in ids

    def test_fires_when_attestations_empty(self):
        img = _compliant_image()
        img.attestations = []
        ids = [f.check_id for f in _verifier().verify(img).findings]
        assert "SIGN-004" in ids

    def test_severity_is_medium(self):
        img = _compliant_image()
        img.attestations = [_vuln_attestation()]
        finding = next(f for f in _verifier().verify(img).findings if f.check_id == "SIGN-004")
        assert finding.severity == "MEDIUM"

    def test_custom_sbom_predicate_still_recognised(self):
        img = _compliant_image()
        img.attestations = [
            ImageAttestation(
                attestation_type="sbom",
                predicate_type="https://cyclonedx.org/bom",
                verified=True,
            ),
            _vuln_attestation(),
        ]
        ids = [f.check_id for f in _verifier().verify(img).findings]
        assert "SIGN-004" not in ids


# ---------------------------------------------------------------------------
# 6. SIGN-005 — vulnerability-scan attestation missing
# ---------------------------------------------------------------------------

class TestSign005:
    def test_fires_when_no_vuln_scan(self):
        img = _compliant_image()
        img.attestations = [_sbom_attestation()]  # only sbom, no vuln scan
        ids = [f.check_id for f in _verifier().verify(img).findings]
        assert "SIGN-005" in ids

    def test_does_not_fire_when_vuln_scan_present(self):
        img = _compliant_image()  # already has both
        ids = [f.check_id for f in _verifier().verify(img).findings]
        assert "SIGN-005" not in ids

    def test_fires_when_attestations_empty(self):
        img = _compliant_image()
        img.attestations = []
        ids = [f.check_id for f in _verifier().verify(img).findings]
        assert "SIGN-005" in ids

    def test_severity_is_medium(self):
        img = _compliant_image()
        img.attestations = [_sbom_attestation()]
        finding = next(f for f in _verifier().verify(img).findings if f.check_id == "SIGN-005")
        assert finding.severity == "MEDIUM"


# ---------------------------------------------------------------------------
# 7. SIGN-006 — expired signature
# ---------------------------------------------------------------------------

class TestSign006:
    def test_fires_when_signed_at_old(self):
        img = _compliant_image()
        img.signatures = [_good_sig(signed_at=OLD_TS)]
        ids = [f.check_id for f in _verifier().verify(img).findings]
        assert "SIGN-006" in ids

    def test_does_not_fire_when_signed_at_recent(self):
        img = _compliant_image()
        img.signatures = [_good_sig(signed_at=RECENT_TS)]
        ids = [f.check_id for f in _verifier().verify(img).findings]
        assert "SIGN-006" not in ids

    def test_does_not_fire_when_signed_at_none(self):
        img = _compliant_image()
        img.signatures = [_good_sig(signed_at=None)]
        ids = [f.check_id for f in _verifier().verify(img).findings]
        assert "SIGN-006" not in ids

    def test_custom_max_age_30_days_fires(self):
        # Signed 60 days ago; max_age=30 → should fire
        ts_60_days = NOW - (60 * 86400)
        img = _compliant_image()
        img.signatures = [_good_sig(signed_at=ts_60_days)]
        v = ContainerSigningVerifier(max_signature_age_days=30)
        ids = [f.check_id for f in v.verify(img).findings]
        assert "SIGN-006" in ids

    def test_custom_max_age_90_days_does_not_fire_for_60_day_sig(self):
        # Signed 60 days ago; max_age=90 → should NOT fire
        ts_60_days = NOW - (60 * 86400)
        img = _compliant_image()
        img.signatures = [_good_sig(signed_at=ts_60_days)]
        v = ContainerSigningVerifier(max_signature_age_days=90)
        ids = [f.check_id for f in v.verify(img).findings]
        assert "SIGN-006" not in ids

    def test_severity_is_critical(self):
        img = _compliant_image()
        img.signatures = [_good_sig(signed_at=OLD_TS)]
        finding = next(f for f in _verifier().verify(img).findings if f.check_id == "SIGN-006")
        assert finding.severity == "CRITICAL"

    def test_fires_once_per_expired_signature(self):
        img = _compliant_image()
        img.signatures = [
            _good_sig(signed_at=OLD_TS, identity="alice@corp.com"),
            _good_sig(signed_at=OLD_TS, identity="bob@corp.com"),
        ]
        sign006 = [f for f in _verifier().verify(img).findings if f.check_id == "SIGN-006"]
        assert len(sign006) == 2

    def test_only_expired_sig_fires_not_fresh_one(self):
        img = _compliant_image()
        img.signatures = [
            _good_sig(signed_at=OLD_TS, identity="old@corp.com"),
            _good_sig(signed_at=RECENT_TS, identity="new@corp.com"),
        ]
        sign006 = [f for f in _verifier().verify(img).findings if f.check_id == "SIGN-006"]
        assert len(sign006) == 1
        assert "old@corp.com" in sign006[0].message

    def test_exactly_at_boundary_does_not_fire(self):
        # Signed 1 second LESS than the limit ago — boundary is exclusive (>),
        # so a signature that is strictly younger than max_age_days must not fire.
        # We ask time.time() right now to avoid any race with module-load time.
        just_under_ts = time.time() - (365 * 86400) + 2  # 2 s buffer for test execution time
        img = _compliant_image()
        img.signatures = [_good_sig(signed_at=just_under_ts)]
        ids = [f.check_id for f in _verifier().verify(img).findings]
        assert "SIGN-006" not in ids


# ---------------------------------------------------------------------------
# 8. SIGN-007 — mutable tag without digest
# ---------------------------------------------------------------------------

class TestSign007:
    def test_fires_when_no_digest_and_tag_present(self):
        img = _compliant_image()
        img.digest = None
        img.tag = "1.0.0"
        ids = [f.check_id for f in _verifier().verify(img).findings]
        assert "SIGN-007" in ids

    def test_does_not_fire_when_digest_present(self):
        img = _compliant_image()  # digest is set
        ids = [f.check_id for f in _verifier().verify(img).findings]
        assert "SIGN-007" not in ids

    def test_fires_for_latest_tag(self):
        img = _compliant_image()
        img.tag = "latest"
        # Even with a digest present, "latest" should fire
        ids = [f.check_id for f in _verifier().verify(img).findings]
        assert "SIGN-007" in ids

    def test_fires_for_latest_tag_without_digest(self):
        img = _compliant_image()
        img.digest = None
        img.tag = "latest"
        ids = [f.check_id for f in _verifier().verify(img).findings]
        assert "SIGN-007" in ids

    def test_does_not_fire_when_tag_is_empty_string(self):
        img = _compliant_image()
        img.digest = None
        img.tag = ""
        ids = [f.check_id for f in _verifier().verify(img).findings]
        assert "SIGN-007" not in ids

    def test_does_not_fire_when_tag_and_digest_both_none(self):
        img = _compliant_image()
        img.digest = None
        img.tag = None
        ids = [f.check_id for f in _verifier().verify(img).findings]
        assert "SIGN-007" not in ids

    def test_severity_is_high(self):
        img = _compliant_image()
        img.digest = None
        img.tag = "v2.0.0"
        finding = next(f for f in _verifier().verify(img).findings if f.check_id == "SIGN-007")
        assert finding.severity == "HIGH"

    def test_fires_once_per_image(self):
        img = _compliant_image()
        img.digest = None
        img.tag = "stable"
        sign007 = [f for f in _verifier().verify(img).findings if f.check_id == "SIGN-007"]
        assert len(sign007) == 1


# ---------------------------------------------------------------------------
# 9. Multiple checks on the same image
# ---------------------------------------------------------------------------

class TestMultipleChecks:
    def test_no_sig_and_no_attestations_fires_001_004_005(self):
        img = ContainerImage(
            reference="registry.io/org/bare:latest",
            digest="sha256:abc123",
            tag="latest",
            signatures=[],
            attestations=[],
        )
        ids = {f.check_id for f in _verifier().verify(img).findings}
        # 001 because no sigs; 004, 005 because no attestations; 007 because "latest"
        assert "SIGN-001" in ids
        assert "SIGN-004" in ids
        assert "SIGN-005" in ids
        assert "SIGN-007" in ids

    def test_unverified_sig_plus_missing_attestations(self):
        img = ContainerImage(
            reference="registry.io/org/partial:1.0",
            digest="sha256:abc",
            tag="1.0",
            signatures=[_good_sig(verified=False)],
            attestations=[],
        )
        ids = {f.check_id for f in _verifier().verify(img).findings}
        assert "SIGN-003" in ids
        assert "SIGN-004" in ids
        assert "SIGN-005" in ids

    def test_risk_score_additive_across_checks(self):
        img = ContainerImage(
            reference="registry.io/org/risky:latest",
            digest=None,
            tag="latest",
            signatures=[],
            attestations=[],
        )
        result = _verifier().verify(img)
        fired_ids = {f.check_id for f in result.findings}
        expected = min(100, sum(_CHECK_WEIGHTS[cid] for cid in fired_ids))
        assert result.risk_score == expected


# ---------------------------------------------------------------------------
# 10. risk_score cap at 100
# ---------------------------------------------------------------------------

class TestRiskScoreCap:
    def test_score_capped_at_100(self):
        # Fire: 001(25) + 003(40) + 004(15) + 005(15) + 006(40) + 007(20) = 155 → capped 100
        img = ContainerImage(
            reference="registry.io/org/worst:latest",
            digest=None,
            tag="latest",
            signatures=[_good_sig(verified=False, signed_at=OLD_TS)],
            attestations=[],
        )
        result = _verifier().verify(img)
        assert result.risk_score == 100

    def test_score_never_exceeds_100(self):
        # Brute-force: make every possible check fire
        img = ContainerImage(
            reference="registry.io/org/all-bad:latest",
            digest=None,
            tag="latest",
            signatures=[
                ImageSignature(
                    signer_identity="evil@hacker.com",
                    signature_algo="rsa-1024",
                    signed_at=OLD_TS,
                    verified=False,
                )
            ],
            attestations=[],
        )
        v = ContainerSigningVerifier(trusted_signers=["good@company.com"], max_signature_age_days=365)
        result = v.verify(img)
        assert result.risk_score <= 100


# ---------------------------------------------------------------------------
# 11. by_severity()
# ---------------------------------------------------------------------------

class TestBySeverity:
    def test_returns_dict_with_correct_keys(self):
        img = _compliant_image()
        img.signatures = [_good_sig(verified=False)]  # SIGN-003 CRITICAL
        img.attestations = []                           # SIGN-004 + SIGN-005 MEDIUM
        grouped = _verifier().verify(img).by_severity()
        assert "CRITICAL" in grouped
        assert "MEDIUM" in grouped

    def test_findings_correctly_grouped(self):
        img = _compliant_image()
        img.signatures = []          # SIGN-001 HIGH
        img.attestations = []        # SIGN-004 MEDIUM, SIGN-005 MEDIUM
        grouped = _verifier().verify(img).by_severity()
        high = [f.check_id for f in grouped.get("HIGH", [])]
        medium = [f.check_id for f in grouped.get("MEDIUM", [])]
        assert "SIGN-001" in high
        assert "SIGN-004" in medium
        assert "SIGN-005" in medium

    def test_empty_image_returns_empty_dict(self):
        result = _verifier().verify(_compliant_image())
        assert result.by_severity() == {}

    def test_all_severities_possible(self):
        img = ContainerImage(
            reference="registry.io/org/multi:1",
            digest=None,
            tag="1",
            signatures=[_good_sig(verified=False, signed_at=OLD_TS)],  # SIGN-003 CRITICAL, SIGN-006 CRITICAL
            attestations=[],  # SIGN-004 MEDIUM, SIGN-005 MEDIUM
        )
        grouped = _verifier().verify(img).by_severity()
        # SIGN-007 HIGH (no digest + tag), SIGN-003/006 CRITICAL, SIGN-004/005 MEDIUM
        assert "CRITICAL" in grouped
        assert "MEDIUM" in grouped
        assert "HIGH" in grouped


# ---------------------------------------------------------------------------
# 12. summary() format
# ---------------------------------------------------------------------------

class TestSummary:
    def test_ok_prefix_when_no_findings(self):
        result = _verifier().verify(_compliant_image())
        assert result.summary().startswith("[OK]")

    def test_findings_prefix_when_findings_present(self):
        img = _compliant_image()
        img.signatures = []
        result = _verifier().verify(img)
        assert result.summary().startswith("[FINDINGS]")

    def test_summary_contains_image_reference(self):
        ref = "registry.io/myorg/myapp:3.0.0"
        result = _verifier().verify(_compliant_image(reference=ref))
        assert ref in result.summary()

    def test_summary_contains_risk_score(self):
        img = _compliant_image()
        img.signatures = []
        result = _verifier().verify(img)
        assert f"risk_score={result.risk_score}" in result.summary()

    def test_summary_contains_finding_count(self):
        img = _compliant_image()
        img.signatures = []
        img.attestations = []
        result = _verifier().verify(img)
        count = len(result.findings)
        assert str(count) in result.summary()


# ---------------------------------------------------------------------------
# 13. verify_many()
# ---------------------------------------------------------------------------

class TestVerifyMany:
    def test_returns_list(self):
        images = [_compliant_image("reg/a:1"), _compliant_image("reg/b:2")]
        results = _verifier().verify_many(images)
        assert isinstance(results, list)

    def test_length_matches_input(self):
        images = [_compliant_image(f"reg/app{i}:1") for i in range(5)]
        results = _verifier().verify_many(images)
        assert len(results) == 5

    def test_order_preserved(self):
        images = [_compliant_image(f"reg/app{i}:1") for i in range(3)]
        results = _verifier().verify_many(images)
        for i, result in enumerate(results):
            assert result.image_reference == images[i].reference

    def test_empty_list_returns_empty_list(self):
        results = _verifier().verify_many([])
        assert results == []

    def test_each_result_is_signing_verify_result(self):
        images = [_compliant_image("reg/a:1"), _compliant_image("reg/b:1")]
        for result in _verifier().verify_many(images):
            assert isinstance(result, SigningVerifyResult)

    def test_independent_results(self):
        bad = ContainerImage(reference="reg/bad:1", digest=None, tag="1", signatures=[], attestations=[])
        good = _compliant_image("reg/good:1")
        results = _verifier().verify_many([bad, good])
        bad_ids = {f.check_id for f in results[0].findings}
        good_ids = {f.check_id for f in results[1].findings}
        assert "SIGN-001" in bad_ids
        assert "SIGN-001" not in good_ids


# ---------------------------------------------------------------------------
# 14. to_dict() for all dataclasses
# ---------------------------------------------------------------------------

class TestToDict:
    def test_image_signature_to_dict_keys(self):
        sig = _good_sig()
        d = sig.to_dict()
        assert set(d.keys()) == {"signer_identity", "signature_algo", "signed_at", "verified"}

    def test_image_signature_to_dict_values(self):
        sig = ImageSignature(
            signer_identity="test@co.com",
            signature_algo="ecdsa-p256",
            signed_at=12345.0,
            verified=True,
        )
        d = sig.to_dict()
        assert d["signer_identity"] == "test@co.com"
        assert d["verified"] is True
        assert d["signed_at"] == 12345.0

    def test_image_attestation_to_dict_keys(self):
        att = _sbom_attestation()
        d = att.to_dict()
        assert set(d.keys()) == {"attestation_type", "predicate_type", "verified"}

    def test_image_attestation_to_dict_values(self):
        att = ImageAttestation(
            attestation_type="sbom",
            predicate_type="https://spdx.dev/Document",
            verified=True,
        )
        d = att.to_dict()
        assert d["attestation_type"] == "sbom"
        assert d["verified"] is True

    def test_container_image_to_dict_keys(self):
        img = _compliant_image()
        d = img.to_dict()
        assert set(d.keys()) == {"reference", "digest", "tag", "registry", "signatures", "attestations"}

    def test_container_image_to_dict_nested(self):
        img = _compliant_image()
        d = img.to_dict()
        assert isinstance(d["signatures"], list)
        assert isinstance(d["attestations"], list)
        # Nested objects are also dicts, not dataclass instances
        assert isinstance(d["signatures"][0], dict)
        assert isinstance(d["attestations"][0], dict)

    def test_signing_finding_to_dict_keys(self):
        img = _compliant_image()
        img.signatures = []
        finding = _verifier().verify(img).findings[0]
        d = finding.to_dict()
        assert set(d.keys()) == {"check_id", "severity", "image_reference", "message", "recommendation"}

    def test_signing_verify_result_to_dict_keys(self):
        result = _verifier().verify(_compliant_image())
        d = result.to_dict()
        assert set(d.keys()) == {"image_reference", "risk_score", "findings", "summary"}

    def test_signing_verify_result_to_dict_findings_are_dicts(self):
        img = _compliant_image()
        img.signatures = []
        result = _verifier().verify(img)
        d = result.to_dict()
        assert all(isinstance(f, dict) for f in d["findings"])

    def test_signing_verify_result_to_dict_risk_score_type(self):
        result = _verifier().verify(_compliant_image())
        d = result.to_dict()
        assert isinstance(d["risk_score"], int)


# ---------------------------------------------------------------------------
# 15. _CHECK_WEIGHTS structure
# ---------------------------------------------------------------------------

class TestCheckWeights:
    def test_all_seven_check_ids_present(self):
        expected = {"SIGN-001", "SIGN-002", "SIGN-003", "SIGN-004", "SIGN-005", "SIGN-006", "SIGN-007"}
        assert set(_CHECK_WEIGHTS.keys()) == expected

    def test_all_weights_are_positive_ints(self):
        for cid, w in _CHECK_WEIGHTS.items():
            assert isinstance(w, int) and w > 0, f"{cid} has invalid weight {w}"

    def test_specific_weights(self):
        assert _CHECK_WEIGHTS["SIGN-001"] == 25
        assert _CHECK_WEIGHTS["SIGN-002"] == 25
        assert _CHECK_WEIGHTS["SIGN-003"] == 40
        assert _CHECK_WEIGHTS["SIGN-004"] == 15
        assert _CHECK_WEIGHTS["SIGN-005"] == 15
        assert _CHECK_WEIGHTS["SIGN-006"] == 40
        assert _CHECK_WEIGHTS["SIGN-007"] == 20


# ---------------------------------------------------------------------------
# 16. Default constructor values
# ---------------------------------------------------------------------------

class TestDefaultConstructor:
    def test_default_trusted_signers_is_none(self):
        v = ContainerSigningVerifier()
        assert v.trusted_signers is None

    def test_default_max_signature_age_days(self):
        v = ContainerSigningVerifier()
        assert v.max_signature_age_days == 365

    def test_custom_trusted_signers_stored(self):
        v = ContainerSigningVerifier(trusted_signers=["a@b.com"])
        assert v.trusted_signers == ["a@b.com"]

    def test_custom_max_age_stored(self):
        v = ContainerSigningVerifier(max_signature_age_days=90)
        assert v.max_signature_age_days == 90


# ---------------------------------------------------------------------------
# 17. Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_image_with_only_digest_no_tag_no_007(self):
        img = ContainerImage(
            reference="registry.io/org/pinned@sha256:abc",
            digest="sha256:abc",
            tag=None,
            signatures=[_good_sig()],
            attestations=[_sbom_attestation(), _vuln_attestation()],
        )
        ids = {f.check_id for f in _verifier().verify(img).findings}
        assert "SIGN-007" not in ids

    def test_slsa_attestation_type_not_counted_as_sbom(self):
        img = _compliant_image()
        img.attestations = [
            ImageAttestation(
                attestation_type="slsa-provenance",
                predicate_type="https://slsa.dev/provenance/v0.2",
                verified=True,
            ),
            _vuln_attestation(),
        ]
        # No sbom → SIGN-004 should fire
        ids = {f.check_id for f in _verifier().verify(img).findings}
        assert "SIGN-004" in ids

    def test_custom_attestation_type_not_counted_as_vuln_scan(self):
        img = _compliant_image()
        img.attestations = [
            _sbom_attestation(),
            ImageAttestation(
                attestation_type="custom",
                predicate_type="https://example.com/custom",
                verified=True,
            ),
        ]
        # No vulnerability-scan → SIGN-005 should fire
        ids = {f.check_id for f in _verifier().verify(img).findings}
        assert "SIGN-005" in ids

    def test_finding_recommendation_not_empty(self):
        img = _compliant_image()
        img.signatures = []
        for finding in _verifier().verify(img).findings:
            assert finding.recommendation.strip() != ""

    def test_finding_message_not_empty(self):
        img = _compliant_image()
        img.signatures = []
        for finding in _verifier().verify(img).findings:
            assert finding.message.strip() != ""

    def test_image_reference_in_result(self):
        ref = "my.registry.io/prod/api:v3.1.0"
        result = _verifier().verify(_compliant_image(reference=ref))
        assert result.image_reference == ref

    def test_sign006_boundary_one_second_past(self):
        # One second past the limit should fire
        just_over_ts = NOW - (365 * 86400) - 1
        img = _compliant_image()
        img.signatures = [_good_sig(signed_at=just_over_ts)]
        ids = {f.check_id for f in _verifier().verify(img).findings}
        assert "SIGN-006" in ids
