# test_artifact_integrity_checker.py
# Comprehensive test suite for ArtifactIntegrityChecker.
#
# Copyright (C) 2024 Cyber Port
# Licensed under CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/
# SPDX-License-Identifier: CC-BY-4.0
from __future__ import annotations

import sys
import time
import os

# Make the shared/analyzers package importable without installing it
sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..", "shared", "analyzers"),
)

import pytest

from artifact_integrity_checker import (
    ArtifactIntegrityChecker,
    ArtifactMetadata,
    IntegrityCheckResult,
    IntegrityFinding,
    _CHECK_WEIGHTS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _perfect() -> ArtifactMetadata:
    """Return a metadata object that should pass ALL checks cleanly."""
    return ArtifactMetadata(
        name="myapp-1.0.0.jar",
        artifact_type="java-jar",
        source_url="https://repo.example.com/releases/myapp-1.0.0.jar",
        checksum_algo="sha256",
        checksum_value="abc123def456",
        expected_checksum="abc123def456",
        has_digital_signature=True,
        signature_verified=True,
        slsa_level=3,
        published_at=time.time() - 30 * 86400,  # 30 days ago
        source_is_verified=True,
    )


def _checker(**kwargs) -> ArtifactIntegrityChecker:
    return ArtifactIntegrityChecker(**kwargs)


def _ids(result: IntegrityCheckResult):
    return {f.check_id for f in result.findings}


# ---------------------------------------------------------------------------
# 1. Perfect artifact — no findings
# ---------------------------------------------------------------------------

class TestPerfectArtifact:
    def test_no_findings(self):
        result = _checker().check(_perfect())
        assert result.findings == []

    def test_risk_score_zero(self):
        result = _checker().check(_perfect())
        assert result.risk_score == 0

    def test_summary_no_issues(self):
        result = _checker().check(_perfect())
        assert "No integrity issues found" in result.summary()

    def test_summary_contains_artifact_name(self):
        result = _checker().check(_perfect())
        assert "myapp-1.0.0.jar" in result.summary()

    def test_summary_risk_score_zero(self):
        result = _checker().check(_perfect())
        assert "0/100" in result.summary()


# ---------------------------------------------------------------------------
# 2. ART-001 — Missing checksum
# ---------------------------------------------------------------------------

class TestART001:
    def test_checksum_algo_none_triggers(self):
        a = _perfect()
        a.checksum_algo = None
        result = _checker().check(a)
        assert "ART-001" in _ids(result)

    def test_checksum_value_none_triggers(self):
        a = _perfect()
        a.checksum_value = None
        result = _checker().check(a)
        assert "ART-001" in _ids(result)

    def test_checksum_value_empty_string_triggers(self):
        a = _perfect()
        a.checksum_value = ""
        # expected_checksum is also set; make sure ART-007 does NOT fire
        a.expected_checksum = None
        result = _checker().check(a)
        assert "ART-001" in _ids(result)

    def test_both_present_does_not_trigger(self):
        a = _perfect()
        result = _checker().check(a)
        assert "ART-001" not in _ids(result)

    def test_art001_severity_is_high(self):
        a = _perfect()
        a.checksum_algo = None
        result = _checker().check(a)
        finding = next(f for f in result.findings if f.check_id == "ART-001")
        assert finding.severity == "HIGH"

    def test_art001_weight(self):
        assert _CHECK_WEIGHTS["ART-001"] == 25

    def test_art001_message_contains_artifact_name(self):
        a = _perfect()
        a.checksum_algo = None
        result = _checker().check(a)
        finding = next(f for f in result.findings if f.check_id == "ART-001")
        assert a.name in finding.message

    def test_art001_finding_artifact_type(self):
        a = _perfect()
        a.checksum_algo = None
        result = _checker().check(a)
        finding = next(f for f in result.findings if f.check_id == "ART-001")
        assert finding.artifact_type == a.artifact_type

    def test_art001_recommendation_non_empty(self):
        a = _perfect()
        a.checksum_value = None
        result = _checker().check(a)
        finding = next(f for f in result.findings if f.check_id == "ART-001")
        assert finding.recommendation != ""


# ---------------------------------------------------------------------------
# 3. ART-002 — Weak hash algorithm
# ---------------------------------------------------------------------------

class TestART002:
    def test_md5_triggers(self):
        a = _perfect()
        a.checksum_algo = "md5"
        result = _checker().check(a)
        assert "ART-002" in _ids(result)

    def test_sha1_triggers(self):
        a = _perfect()
        a.checksum_algo = "sha1"
        result = _checker().check(a)
        assert "ART-002" in _ids(result)

    def test_sha256_does_not_trigger(self):
        a = _perfect()
        a.checksum_algo = "sha256"
        result = _checker().check(a)
        assert "ART-002" not in _ids(result)

    def test_sha512_does_not_trigger(self):
        a = _perfect()
        a.checksum_algo = "sha512"
        result = _checker().check(a)
        assert "ART-002" not in _ids(result)

    def test_uppercase_sha1_triggers_case_insensitive(self):
        a = _perfect()
        a.checksum_algo = "SHA1"
        result = _checker().check(a)
        assert "ART-002" in _ids(result)

    def test_uppercase_md5_triggers_case_insensitive(self):
        a = _perfect()
        a.checksum_algo = "MD5"
        result = _checker().check(a)
        assert "ART-002" in _ids(result)

    def test_mixed_case_triggers(self):
        a = _perfect()
        a.checksum_algo = "Md5"
        result = _checker().check(a)
        assert "ART-002" in _ids(result)

    def test_custom_weak_hash_algos_triggers(self):
        a = _perfect()
        a.checksum_algo = "sha256"
        result = _checker(weak_hash_algos=["sha256"]).check(a)
        assert "ART-002" in _ids(result)

    def test_custom_weak_hash_algos_does_not_trigger_for_unlisted(self):
        a = _perfect()
        a.checksum_algo = "sha256"
        # Only md5 is weak; sha256 is fine
        result = _checker(weak_hash_algos=["md5"]).check(a)
        assert "ART-002" not in _ids(result)

    def test_checksum_algo_none_does_not_trigger_art002(self):
        # When algo is None, ART-001 fires but ART-002 must NOT
        a = _perfect()
        a.checksum_algo = None
        result = _checker().check(a)
        assert "ART-002" not in _ids(result)

    def test_art002_severity_is_high(self):
        a = _perfect()
        a.checksum_algo = "md5"
        result = _checker().check(a)
        finding = next(f for f in result.findings if f.check_id == "ART-002")
        assert finding.severity == "HIGH"

    def test_art002_weight(self):
        assert _CHECK_WEIGHTS["ART-002"] == 20

    def test_custom_weak_algos_stored_lowercase(self):
        c = _checker(weak_hash_algos=["SHA256", "SHA512"])
        assert "sha256" in c.weak_hash_algos
        assert "sha512" in c.weak_hash_algos


# ---------------------------------------------------------------------------
# 4. ART-003 — Unverified source
# ---------------------------------------------------------------------------

class TestART003:
    def test_source_url_set_unverified_triggers(self):
        a = _perfect()
        a.source_is_verified = False
        result = _checker().check(a)
        assert "ART-003" in _ids(result)

    def test_source_url_set_verified_does_not_trigger(self):
        a = _perfect()
        a.source_is_verified = True
        result = _checker().check(a)
        assert "ART-003" not in _ids(result)

    def test_source_url_none_does_not_trigger(self):
        a = _perfect()
        a.source_url = None
        a.source_is_verified = False
        result = _checker().check(a)
        assert "ART-003" not in _ids(result)

    def test_art003_severity_is_high(self):
        a = _perfect()
        a.source_is_verified = False
        result = _checker().check(a)
        finding = next(f for f in result.findings if f.check_id == "ART-003")
        assert finding.severity == "HIGH"

    def test_art003_weight(self):
        assert _CHECK_WEIGHTS["ART-003"] == 20

    def test_art003_message_contains_source_url(self):
        a = _perfect()
        a.source_is_verified = False
        result = _checker().check(a)
        finding = next(f for f in result.findings if f.check_id == "ART-003")
        assert a.source_url in finding.message

    def test_art003_recommendation_non_empty(self):
        a = _perfect()
        a.source_is_verified = False
        result = _checker().check(a)
        finding = next(f for f in result.findings if f.check_id == "ART-003")
        assert finding.recommendation != ""


# ---------------------------------------------------------------------------
# 5. ART-004 — SLSA provenance level
# ---------------------------------------------------------------------------

class TestART004:
    def test_slsa_level_none_triggers(self):
        a = _perfect()
        a.slsa_level = None
        result = _checker().check(a)
        assert "ART-004" in _ids(result)

    def test_slsa_level_0_below_min2_triggers(self):
        a = _perfect()
        a.slsa_level = 0
        result = _checker(min_slsa_level=2).check(a)
        assert "ART-004" in _ids(result)

    def test_slsa_level_1_below_min2_triggers(self):
        a = _perfect()
        a.slsa_level = 1
        result = _checker(min_slsa_level=2).check(a)
        assert "ART-004" in _ids(result)

    def test_slsa_level_2_equals_min2_does_not_trigger(self):
        a = _perfect()
        a.slsa_level = 2
        result = _checker(min_slsa_level=2).check(a)
        assert "ART-004" not in _ids(result)

    def test_slsa_level_3_above_min2_does_not_trigger(self):
        a = _perfect()
        a.slsa_level = 3
        result = _checker(min_slsa_level=2).check(a)
        assert "ART-004" not in _ids(result)

    def test_slsa_level_4_does_not_trigger(self):
        a = _perfect()
        a.slsa_level = 4
        result = _checker(min_slsa_level=2).check(a)
        assert "ART-004" not in _ids(result)

    def test_custom_min_slsa_level(self):
        a = _perfect()
        a.slsa_level = 2
        result = _checker(min_slsa_level=3).check(a)
        assert "ART-004" in _ids(result)

    def test_art004_severity_is_medium(self):
        a = _perfect()
        a.slsa_level = None
        result = _checker().check(a)
        finding = next(f for f in result.findings if f.check_id == "ART-004")
        assert finding.severity == "MEDIUM"

    def test_art004_weight(self):
        assert _CHECK_WEIGHTS["ART-004"] == 15

    def test_art004_message_says_unknown_when_none(self):
        a = _perfect()
        a.slsa_level = None
        result = _checker().check(a)
        finding = next(f for f in result.findings if f.check_id == "ART-004")
        assert "unknown" in finding.message.lower()

    def test_art004_message_contains_level_number_when_set(self):
        a = _perfect()
        a.slsa_level = 1
        result = _checker(min_slsa_level=2).check(a)
        finding = next(f for f in result.findings if f.check_id == "ART-004")
        assert "1" in finding.message


# ---------------------------------------------------------------------------
# 6. ART-005 — Missing digital signature
# ---------------------------------------------------------------------------

class TestART005:
    def test_no_signature_triggers(self):
        a = _perfect()
        a.has_digital_signature = False
        result = _checker().check(a)
        assert "ART-005" in _ids(result)

    def test_signature_present_does_not_trigger(self):
        a = _perfect()
        a.has_digital_signature = True
        result = _checker().check(a)
        assert "ART-005" not in _ids(result)

    def test_art005_severity_is_high(self):
        a = _perfect()
        a.has_digital_signature = False
        result = _checker().check(a)
        finding = next(f for f in result.findings if f.check_id == "ART-005")
        assert finding.severity == "HIGH"

    def test_art005_weight(self):
        assert _CHECK_WEIGHTS["ART-005"] == 20

    def test_art005_message_contains_artifact_name(self):
        a = _perfect()
        a.has_digital_signature = False
        result = _checker().check(a)
        finding = next(f for f in result.findings if f.check_id == "ART-005")
        assert a.name in finding.message

    def test_art005_recommendation_non_empty(self):
        a = _perfect()
        a.has_digital_signature = False
        result = _checker().check(a)
        finding = next(f for f in result.findings if f.check_id == "ART-005")
        assert finding.recommendation != ""


# ---------------------------------------------------------------------------
# 7. ART-006 — Artifact age
# ---------------------------------------------------------------------------

class TestART006:
    def test_old_published_at_triggers(self):
        a = _perfect()
        a.published_at = time.time() - 400 * 86400  # 400 days ago
        result = _checker(max_age_days=365).check(a)
        assert "ART-006" in _ids(result)

    def test_recent_published_at_does_not_trigger(self):
        a = _perfect()
        a.published_at = time.time() - 10 * 86400  # 10 days ago
        result = _checker(max_age_days=365).check(a)
        assert "ART-006" not in _ids(result)

    def test_published_at_none_does_not_trigger(self):
        a = _perfect()
        a.published_at = None
        result = _checker().check(a)
        assert "ART-006" not in _ids(result)

    def test_custom_max_age_days_triggers(self):
        a = _perfect()
        a.published_at = time.time() - 100 * 86400  # 100 days ago
        result = _checker(max_age_days=30).check(a)
        assert "ART-006" in _ids(result)

    def test_custom_max_age_days_does_not_trigger_when_recent(self):
        a = _perfect()
        a.published_at = time.time() - 5 * 86400  # 5 days ago
        result = _checker(max_age_days=30).check(a)
        assert "ART-006" not in _ids(result)

    def test_exactly_at_limit_does_not_trigger(self):
        # Exactly at the boundary minus one second — should be fine
        a = _perfect()
        a.published_at = time.time() - 365 * 86400 + 60  # just under 365 days
        result = _checker(max_age_days=365).check(a)
        assert "ART-006" not in _ids(result)

    def test_art006_severity_is_medium(self):
        a = _perfect()
        a.published_at = time.time() - 400 * 86400
        result = _checker().check(a)
        finding = next(f for f in result.findings if f.check_id == "ART-006")
        assert finding.severity == "MEDIUM"

    def test_art006_weight(self):
        assert _CHECK_WEIGHTS["ART-006"] == 15

    def test_art006_message_contains_age_days(self):
        a = _perfect()
        a.published_at = time.time() - 400 * 86400
        result = _checker().check(a)
        finding = next(f for f in result.findings if f.check_id == "ART-006")
        # Message should mention "400" or "days"
        assert "400" in finding.message or "days" in finding.message

    def test_art006_recommendation_non_empty(self):
        a = _perfect()
        a.published_at = time.time() - 400 * 86400
        result = _checker().check(a)
        finding = next(f for f in result.findings if f.check_id == "ART-006")
        assert finding.recommendation != ""


# ---------------------------------------------------------------------------
# 8. ART-007 — Checksum mismatch
# ---------------------------------------------------------------------------

class TestART007:
    def test_mismatched_checksums_triggers(self):
        a = _perfect()
        a.checksum_value = "abc123"
        a.expected_checksum = "xyz789"
        result = _checker().check(a)
        assert "ART-007" in _ids(result)

    def test_matching_checksums_do_not_trigger(self):
        a = _perfect()
        a.checksum_value = "abc123"
        a.expected_checksum = "abc123"
        result = _checker().check(a)
        assert "ART-007" not in _ids(result)

    def test_case_insensitive_match_does_not_trigger(self):
        a = _perfect()
        a.checksum_value = "ABC123"
        a.expected_checksum = "abc123"
        result = _checker().check(a)
        assert "ART-007" not in _ids(result)

    def test_case_insensitive_mismatch_triggers(self):
        # "abc123" vs "ABC124" — different digits, still a mismatch
        a = _perfect()
        a.checksum_value = "abc123"
        a.expected_checksum = "ABC124"
        result = _checker().check(a)
        assert "ART-007" in _ids(result)

    def test_whitespace_stripped_match_does_not_trigger(self):
        a = _perfect()
        a.checksum_value = "  abc123  "
        a.expected_checksum = "abc123"
        result = _checker().check(a)
        assert "ART-007" not in _ids(result)

    def test_checksum_value_missing_does_not_trigger_art007(self):
        a = _perfect()
        a.checksum_value = None
        a.expected_checksum = "abc123"
        result = _checker().check(a)
        assert "ART-007" not in _ids(result)

    def test_expected_checksum_missing_does_not_trigger_art007(self):
        a = _perfect()
        a.checksum_value = "abc123"
        a.expected_checksum = None
        result = _checker().check(a)
        assert "ART-007" not in _ids(result)

    def test_both_missing_does_not_trigger_art007(self):
        a = _perfect()
        a.checksum_value = None
        a.expected_checksum = None
        result = _checker().check(a)
        assert "ART-007" not in _ids(result)

    def test_empty_checksum_value_does_not_trigger_art007(self):
        a = _perfect()
        a.checksum_value = ""
        a.expected_checksum = "abc123"
        result = _checker().check(a)
        assert "ART-007" not in _ids(result)

    def test_empty_expected_checksum_does_not_trigger_art007(self):
        a = _perfect()
        a.checksum_value = "abc123"
        a.expected_checksum = ""
        result = _checker().check(a)
        assert "ART-007" not in _ids(result)

    def test_art007_severity_is_critical(self):
        a = _perfect()
        a.checksum_value = "abc123"
        a.expected_checksum = "xyz789"
        result = _checker().check(a)
        finding = next(f for f in result.findings if f.check_id == "ART-007")
        assert finding.severity == "CRITICAL"

    def test_art007_weight(self):
        assert _CHECK_WEIGHTS["ART-007"] == 45

    def test_art007_message_mentions_mismatch(self):
        a = _perfect()
        a.checksum_value = "abc123"
        a.expected_checksum = "xyz789"
        result = _checker().check(a)
        finding = next(f for f in result.findings if f.check_id == "ART-007")
        assert "mismatch" in finding.message.lower() or "does not match" in finding.message.lower()

    def test_art007_recommendation_non_empty(self):
        a = _perfect()
        a.checksum_value = "bad"
        a.expected_checksum = "good"
        result = _checker().check(a)
        finding = next(f for f in result.findings if f.check_id == "ART-007")
        assert finding.recommendation != ""


# ---------------------------------------------------------------------------
# 9. Multiple checks firing on the same artifact
# ---------------------------------------------------------------------------

class TestMultipleChecks:
    def test_art001_and_art005_fire_together(self):
        a = _perfect()
        a.checksum_algo = None
        a.has_digital_signature = False
        result = _checker().check(a)
        ids = _ids(result)
        assert "ART-001" in ids
        assert "ART-005" in ids

    def test_all_checks_can_fire(self):
        a = ArtifactMetadata(
            name="bad-artifact.tar.gz",
            artifact_type="archive",
            source_url="https://untrusted.example.com/artifact.tar.gz",
            checksum_algo="md5",
            checksum_value="abc",
            expected_checksum="xyz",  # mismatch triggers ART-007
            has_digital_signature=False,
            signature_verified=False,
            slsa_level=None,
            published_at=time.time() - 400 * 86400,
            source_is_verified=False,
        )
        result = _checker(min_slsa_level=2, max_age_days=365).check(a)
        ids = _ids(result)
        # ART-001 does NOT fire because checksum_algo and checksum_value are set
        assert "ART-002" in ids  # md5 is weak
        assert "ART-003" in ids  # unverified source
        assert "ART-004" in ids  # slsa_level None
        assert "ART-005" in ids  # no signature
        assert "ART-006" in ids  # old artifact
        assert "ART-007" in ids  # checksum mismatch

    def test_risk_score_accumulates_multiple_checks(self):
        a = _perfect()
        a.checksum_algo = None  # ART-001 +25
        a.has_digital_signature = False  # ART-005 +20
        a.source_is_verified = False  # ART-003 +20
        result = _checker().check(a)
        # 25 + 20 + 20 = 65 (plus ART-004 from slsa not applicable since
        # slsa is set; but ART-004 should not fire since slsa_level=3 >= 2)
        assert result.risk_score == 65

    def test_findings_list_length_matches_fired_checks(self):
        a = _perfect()
        a.checksum_algo = None
        a.has_digital_signature = False
        result = _checker().check(a)
        assert len(result.findings) == 2


# ---------------------------------------------------------------------------
# 10. risk_score capped at 100
# ---------------------------------------------------------------------------

class TestRiskScoreCap:
    def test_risk_score_capped_at_100(self):
        # Trigger as many checks as possible to exceed 100
        a = ArtifactMetadata(
            name="worst-ever.bin",
            artifact_type="binary",
            source_url="http://sketchy.example.com/worst-ever.bin",
            checksum_algo="md5",       # ART-002: +20
            checksum_value="abc",
            expected_checksum="xyz",   # ART-007: +45
            has_digital_signature=False,  # ART-005: +20
            signature_verified=False,
            slsa_level=None,           # ART-004: +15
            published_at=time.time() - 400 * 86400,  # ART-006: +15
            source_is_verified=False,  # ART-003: +20
        )
        result = _checker().check(a)
        assert result.risk_score == 100

    def test_risk_score_not_negative(self):
        result = _checker().check(_perfect())
        assert result.risk_score >= 0

    def test_risk_score_within_bounds(self):
        a = ArtifactMetadata(
            name="something.bin",
            artifact_type="binary",
            source_url="http://x.example.com/a.bin",
            checksum_algo=None,
            has_digital_signature=False,
            source_is_verified=False,
        )
        result = _checker().check(a)
        assert 0 <= result.risk_score <= 100


# ---------------------------------------------------------------------------
# 11. by_severity() structure
# ---------------------------------------------------------------------------

class TestBySeverity:
    def test_by_severity_all_keys_present(self):
        result = _checker().check(_perfect())
        by_sev = result.by_severity()
        assert "CRITICAL" in by_sev
        assert "HIGH" in by_sev
        assert "MEDIUM" in by_sev
        assert "LOW" in by_sev
        assert "INFO" in by_sev

    def test_by_severity_empty_for_perfect_artifact(self):
        result = _checker().check(_perfect())
        by_sev = result.by_severity()
        assert by_sev["CRITICAL"] == []
        assert by_sev["HIGH"] == []
        assert by_sev["MEDIUM"] == []

    def test_by_severity_critical_contains_art007(self):
        a = _perfect()
        a.checksum_value = "bad"
        a.expected_checksum = "good"
        result = _checker().check(a)
        crits = result.by_severity()["CRITICAL"]
        assert any(f.check_id == "ART-007" for f in crits)

    def test_by_severity_high_contains_art001(self):
        a = _perfect()
        a.checksum_algo = None
        result = _checker().check(a)
        highs = result.by_severity()["HIGH"]
        assert any(f.check_id == "ART-001" for f in highs)

    def test_by_severity_medium_contains_art004(self):
        a = _perfect()
        a.slsa_level = None
        result = _checker().check(a)
        mediums = result.by_severity()["MEDIUM"]
        assert any(f.check_id == "ART-004" for f in mediums)

    def test_by_severity_values_are_lists(self):
        result = _checker().check(_perfect())
        for v in result.by_severity().values():
            assert isinstance(v, list)

    def test_by_severity_total_matches_findings(self):
        a = _perfect()
        a.checksum_algo = None
        a.has_digital_signature = False
        result = _checker().check(a)
        by_sev = result.by_severity()
        total = sum(len(v) for v in by_sev.values())
        assert total == len(result.findings)


# ---------------------------------------------------------------------------
# 12. summary() format
# ---------------------------------------------------------------------------

class TestSummary:
    def test_summary_is_string(self):
        result = _checker().check(_perfect())
        assert isinstance(result.summary(), str)

    def test_summary_contains_risk_score(self):
        a = _perfect()
        a.checksum_algo = None
        result = _checker().check(a)
        assert str(result.risk_score) in result.summary()

    def test_summary_contains_finding_count_when_issues(self):
        a = _perfect()
        a.checksum_algo = None
        a.has_digital_signature = False
        result = _checker().check(a)
        assert "2" in result.summary()

    def test_summary_contains_severity_info_when_issues(self):
        a = _perfect()
        a.checksum_algo = None  # HIGH
        result = _checker().check(a)
        assert "HIGH" in result.summary()

    def test_summary_no_issues_message_for_clean(self):
        result = _checker().check(_perfect())
        assert "No integrity issues found" in result.summary()


# ---------------------------------------------------------------------------
# 13. check_many() returns list
# ---------------------------------------------------------------------------

class TestCheckMany:
    def test_check_many_returns_list(self):
        artifacts = [_perfect(), _perfect()]
        results = _checker().check_many(artifacts)
        assert isinstance(results, list)

    def test_check_many_length_matches_input(self):
        artifacts = [_perfect() for _ in range(5)]
        results = _checker().check_many(artifacts)
        assert len(results) == 5

    def test_check_many_empty_list(self):
        results = _checker().check_many([])
        assert results == []

    def test_check_many_each_element_is_integrity_check_result(self):
        artifacts = [_perfect(), _perfect()]
        results = _checker().check_many(artifacts)
        for r in results:
            assert isinstance(r, IntegrityCheckResult)

    def test_check_many_independent_results(self):
        a1 = _perfect()
        a2 = _perfect()
        a2.checksum_algo = None
        results = _checker().check_many([a1, a2])
        assert results[0].risk_score == 0
        assert results[1].risk_score > 0


# ---------------------------------------------------------------------------
# 14. to_dict() — all dataclasses
# ---------------------------------------------------------------------------

class TestToDict:
    def test_artifact_metadata_to_dict_keys(self):
        a = _perfect()
        d = a.to_dict()
        expected_keys = {
            "name", "artifact_type", "source_url", "checksum_algo",
            "checksum_value", "expected_checksum", "has_digital_signature",
            "signature_verified", "slsa_level", "published_at",
            "source_is_verified",
        }
        assert set(d.keys()) == expected_keys

    def test_artifact_metadata_to_dict_values(self):
        a = _perfect()
        d = a.to_dict()
        assert d["name"] == a.name
        assert d["artifact_type"] == a.artifact_type
        assert d["slsa_level"] == a.slsa_level

    def test_integrity_finding_to_dict_keys(self):
        finding = IntegrityFinding(
            check_id="ART-001",
            severity="HIGH",
            artifact_name="test.jar",
            artifact_type="java-jar",
            message="test message",
            recommendation="test rec",
        )
        d = finding.to_dict()
        assert set(d.keys()) == {
            "check_id", "severity", "artifact_name", "artifact_type",
            "message", "recommendation",
        }

    def test_integrity_finding_to_dict_values(self):
        finding = IntegrityFinding(
            check_id="ART-007",
            severity="CRITICAL",
            artifact_name="bad.bin",
            artifact_type="binary",
            message="mismatch",
            recommendation="re-download",
        )
        d = finding.to_dict()
        assert d["check_id"] == "ART-007"
        assert d["severity"] == "CRITICAL"

    def test_integrity_check_result_to_dict_keys(self):
        result = _checker().check(_perfect())
        d = result.to_dict()
        assert "artifact" in d
        assert "findings" in d
        assert "risk_score" in d
        assert "summary" in d

    def test_integrity_check_result_to_dict_findings_are_dicts(self):
        a = _perfect()
        a.checksum_algo = None
        result = _checker().check(a)
        d = result.to_dict()
        for f in d["findings"]:
            assert isinstance(f, dict)

    def test_integrity_check_result_to_dict_artifact_is_dict(self):
        result = _checker().check(_perfect())
        d = result.to_dict()
        assert isinstance(d["artifact"], dict)

    def test_integrity_check_result_to_dict_risk_score_value(self):
        result = _checker().check(_perfect())
        d = result.to_dict()
        assert d["risk_score"] == 0

    def test_integrity_check_result_to_dict_summary_is_string(self):
        result = _checker().check(_perfect())
        d = result.to_dict()
        assert isinstance(d["summary"], str)


# ---------------------------------------------------------------------------
# 15. Default weak_hash_algos
# ---------------------------------------------------------------------------

class TestDefaultWeakHashAlgos:
    def test_default_contains_md5(self):
        c = ArtifactIntegrityChecker()
        assert "md5" in c.weak_hash_algos

    def test_default_contains_sha1(self):
        c = ArtifactIntegrityChecker()
        assert "sha1" in c.weak_hash_algos

    def test_default_does_not_contain_sha256(self):
        c = ArtifactIntegrityChecker()
        assert "sha256" not in c.weak_hash_algos

    def test_default_does_not_contain_sha512(self):
        c = ArtifactIntegrityChecker()
        assert "sha512" not in c.weak_hash_algos


# ---------------------------------------------------------------------------
# 16. Constructor parameter validation / defaults
# ---------------------------------------------------------------------------

class TestConstructorParameters:
    def test_default_min_slsa_level_is_2(self):
        c = ArtifactIntegrityChecker()
        assert c.min_slsa_level == 2

    def test_default_max_age_days_is_365(self):
        c = ArtifactIntegrityChecker()
        assert c.max_age_days == 365

    def test_custom_min_slsa_level_stored(self):
        c = ArtifactIntegrityChecker(min_slsa_level=3)
        assert c.min_slsa_level == 3

    def test_custom_max_age_days_stored(self):
        c = ArtifactIntegrityChecker(max_age_days=90)
        assert c.max_age_days == 90

    def test_custom_weak_hash_algos_stored(self):
        c = ArtifactIntegrityChecker(weak_hash_algos=["crc32"])
        assert "crc32" in c.weak_hash_algos

    def test_weak_hash_algos_none_gives_defaults(self):
        c = ArtifactIntegrityChecker(weak_hash_algos=None)
        assert "md5" in c.weak_hash_algos
        assert "sha1" in c.weak_hash_algos

    def test_check_weights_dict_has_all_seven_keys(self):
        expected = {"ART-001", "ART-002", "ART-003", "ART-004",
                    "ART-005", "ART-006", "ART-007"}
        assert set(_CHECK_WEIGHTS.keys()) == expected

    def test_risk_score_is_int(self):
        result = _checker().check(_perfect())
        assert isinstance(result.risk_score, int)

    def test_findings_attribute_is_list(self):
        result = _checker().check(_perfect())
        assert isinstance(result.findings, list)
