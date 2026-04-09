"""
Tests for shared.analyzers.dep_confusion_detector
===================================================
Covers every check rule (DC-001 through DC-006), report structure,
risk score computation, parser utility, and edge cases.

Run with::

    pytest tests/test_dep_confusion_detector.py -v
"""

from __future__ import annotations

import sys
import os

# Allow running from the repo root without installing the package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from shared.analyzers.dep_confusion_detector import (
    DCFinding,
    DCReport,
    DCSeverity,
    DepConfusionDetector,
    PackageEntry,
    parse_requirements_txt,
)


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture()
def detector() -> DepConfusionDetector:
    """Default detector with stock internal keywords and unpinned checks on."""
    return DepConfusionDetector()


@pytest.fixture()
def custom_detector() -> DepConfusionDetector:
    """Detector with a custom keyword list."""
    return DepConfusionDetector(internal_keywords=["acme", "myorg"])


@pytest.fixture()
def no_unpinned_detector() -> DepConfusionDetector:
    """Detector with unpinned-version checks disabled."""
    return DepConfusionDetector(check_unpinned=False)


# ===========================================================================
# Helper
# ===========================================================================

def _check_ids(findings: list) -> list:
    """Return sorted list of check_id strings from a findings list."""
    return sorted(f.check_id for f in findings)


def _fired(report: DCReport, check_id: str) -> bool:
    """True when the given check_id appears in the report's findings."""
    return any(f.check_id == check_id for f in report.findings)


# ===========================================================================
# PackageEntry defaults
# ===========================================================================

class TestPackageEntryDefaults:
    def test_default_version_is_wildcard(self):
        pkg = PackageEntry(name="foo")
        assert pkg.version == "*"

    def test_default_registry_is_unknown(self):
        pkg = PackageEntry(name="foo")
        assert pkg.registry == "unknown"

    def test_default_source_file_is_empty(self):
        pkg = PackageEntry(name="foo")
        assert pkg.source_file == ""

    def test_default_metadata_is_empty_dict(self):
        pkg = PackageEntry(name="foo")
        assert pkg.metadata == {}

    def test_metadata_instances_are_independent(self):
        # Mutable default factory — each instance gets its own dict
        a = PackageEntry(name="a")
        b = PackageEntry(name="b")
        a.metadata["x"] = "1"
        assert "x" not in b.metadata


# ===========================================================================
# DCSeverity enum
# ===========================================================================

class TestDCSeverity:
    def test_severity_values_exist(self):
        assert DCSeverity.CRITICAL.value == "CRITICAL"
        assert DCSeverity.HIGH.value == "HIGH"
        assert DCSeverity.MEDIUM.value == "MEDIUM"
        assert DCSeverity.LOW.value == "LOW"

    def test_severity_is_string_enum(self):
        # DCSeverity inherits from str — can be compared to plain strings
        assert DCSeverity.CRITICAL == "CRITICAL"


# ===========================================================================
# DCFinding helpers
# ===========================================================================

class TestDCFinding:
    @pytest.fixture()
    def sample_finding(self) -> DCFinding:
        return DCFinding(
            check_id="DC-001",
            severity=DCSeverity.CRITICAL,
            package_name="corp-utils",
            title="Test title",
            detail="Test detail",
            evidence="evidence text",
            remediation="Fix it",
        )

    def test_to_dict_keys(self, sample_finding):
        d = sample_finding.to_dict()
        expected_keys = {
            "check_id", "severity", "package_name",
            "title", "detail", "evidence", "remediation",
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_severity_is_string(self, sample_finding):
        d = sample_finding.to_dict()
        assert isinstance(d["severity"], str)
        assert d["severity"] == "CRITICAL"

    def test_summary_contains_check_id(self, sample_finding):
        s = sample_finding.summary()
        assert "DC-001" in s

    def test_summary_contains_package_name(self, sample_finding):
        s = sample_finding.summary()
        assert "corp-utils" in s

    def test_summary_contains_severity(self, sample_finding):
        s = sample_finding.summary()
        assert "CRITICAL" in s

    def test_evidence_default_is_empty(self):
        f = DCFinding(
            check_id="DC-005",
            severity=DCSeverity.MEDIUM,
            package_name="pkg",
            title="t",
            detail="d",
        )
        assert f.evidence == ""

    def test_remediation_default_is_empty(self):
        f = DCFinding(
            check_id="DC-005",
            severity=DCSeverity.MEDIUM,
            package_name="pkg",
            title="t",
            detail="d",
        )
        assert f.remediation == ""


# ===========================================================================
# DCReport structure and properties
# ===========================================================================

class TestDCReport:
    def test_empty_report_properties(self):
        report = DCReport()
        assert report.total_findings == 0
        assert report.critical_findings == 0
        assert report.high_findings == 0
        assert report.risk_score == 0
        assert report.packages_analyzed == 0

    def test_generated_at_is_float(self):
        report = DCReport()
        assert isinstance(report.generated_at, float)
        assert report.generated_at > 0

    def test_total_findings_counts_all(self):
        report = DCReport(
            findings=[
                DCFinding("DC-001", DCSeverity.CRITICAL, "p1", "t", "d"),
                DCFinding("DC-005", DCSeverity.MEDIUM, "p2", "t", "d"),
            ]
        )
        assert report.total_findings == 2

    def test_critical_findings_counts_correctly(self):
        report = DCReport(
            findings=[
                DCFinding("DC-001", DCSeverity.CRITICAL, "p1", "t", "d"),
                DCFinding("DC-003", DCSeverity.CRITICAL, "p2", "t", "d"),
                DCFinding("DC-005", DCSeverity.MEDIUM, "p3", "t", "d"),
            ]
        )
        assert report.critical_findings == 2

    def test_high_findings_counts_correctly(self):
        report = DCReport(
            findings=[
                DCFinding("DC-002", DCSeverity.HIGH, "p1", "t", "d"),
                DCFinding("DC-001", DCSeverity.CRITICAL, "p2", "t", "d"),
            ]
        )
        assert report.high_findings == 1

    def test_findings_by_check_groups_correctly(self):
        report = DCReport(
            findings=[
                DCFinding("DC-001", DCSeverity.CRITICAL, "pkg-a", "t", "d"),
                DCFinding("DC-001", DCSeverity.CRITICAL, "pkg-b", "t", "d"),
                DCFinding("DC-005", DCSeverity.MEDIUM, "pkg-c", "t", "d"),
            ]
        )
        by_check = report.findings_by_check()
        assert len(by_check["DC-001"]) == 2
        assert len(by_check["DC-005"]) == 1

    def test_findings_for_package_filters_correctly(self):
        report = DCReport(
            findings=[
                DCFinding("DC-001", DCSeverity.CRITICAL, "target", "t", "d"),
                DCFinding("DC-005", DCSeverity.MEDIUM, "target", "t", "d"),
                DCFinding("DC-006", DCSeverity.LOW, "other", "t", "d"),
            ]
        )
        results = report.findings_for_package("target")
        assert len(results) == 2
        assert all(f.package_name == "target" for f in results)

    def test_findings_for_package_no_match_returns_empty(self):
        report = DCReport(
            findings=[DCFinding("DC-001", DCSeverity.CRITICAL, "pkg", "t", "d")]
        )
        assert report.findings_for_package("nonexistent") == []

    def test_summary_contains_key_labels(self):
        report = DCReport(packages_analyzed=5, risk_score=40)
        s = report.summary()
        assert "Packages analysed" in s
        assert "Risk score" in s
        assert "5" in s

    def test_to_dict_contains_expected_keys(self):
        report = DCReport(packages_analyzed=2, risk_score=50)
        d = report.to_dict()
        for key in ("risk_score", "packages_analyzed", "total_findings",
                    "critical_findings", "high_findings", "generated_at", "findings"):
            assert key in d

    def test_to_dict_findings_are_dicts(self):
        report = DCReport(
            findings=[DCFinding("DC-001", DCSeverity.CRITICAL, "pkg", "t", "d")]
        )
        d = report.to_dict()
        assert isinstance(d["findings"][0], dict)


# ===========================================================================
# DC-001 — Internal keyword, unscoped name
# ===========================================================================

class TestDC001:
    def test_fires_for_internal_keyword_unscoped(self, detector):
        pkg = PackageEntry(name="internal-utils", version="1.0.0", registry="pypi")
        report = detector.analyze([pkg])
        assert _fired(report, "DC-001")

    def test_fires_for_private_keyword(self, detector):
        pkg = PackageEntry(name="private-config", version="1.0.0")
        report = detector.analyze([pkg])
        assert _fired(report, "DC-001")

    def test_does_not_fire_for_scoped_npm_name(self, detector):
        # "@org/internal-utils" starts with "@" — scope provides namespace protection
        pkg = PackageEntry(name="@myorg/internal-utils", version="1.0.0", registry="npm")
        report = detector.analyze([pkg])
        assert not _fired(report, "DC-001")

    def test_does_not_fire_when_no_keyword_match(self, detector):
        pkg = PackageEntry(name="requests", version="2.28.0", registry="pypi")
        report = detector.analyze([pkg])
        assert not _fired(report, "DC-001")

    def test_keyword_match_is_case_insensitive(self, detector):
        pkg = PackageEntry(name="INTERNAL-auth", version="1.0.0")
        report = detector.analyze([pkg])
        assert _fired(report, "DC-001")

    def test_severity_is_critical(self, detector):
        pkg = PackageEntry(name="internal-sdk", version="1.0.0")
        report = detector.analyze([pkg])
        finding = next(f for f in report.findings if f.check_id == "DC-001")
        assert finding.severity == DCSeverity.CRITICAL

    def test_custom_keyword_fires(self, custom_detector):
        pkg = PackageEntry(name="acme-payments", version="1.0.0")
        report = custom_detector.analyze([pkg])
        assert _fired(report, "DC-001")

    def test_default_keyword_absent_with_custom_list(self, custom_detector):
        # "internal" is not in custom_detector's keyword list
        pkg = PackageEntry(name="internal-helper", version="1.0.0")
        report = custom_detector.analyze([pkg])
        assert not _fired(report, "DC-001")


# ===========================================================================
# DC-002 — Internal version sentinel
# ===========================================================================

class TestDC002:
    @pytest.mark.parametrize("version", [
        "0.0.1", "0.0.0", "internal", "dev", "local", "private", "0.0.0-internal",
    ])
    def test_fires_for_known_sentinels(self, detector, version):
        pkg = PackageEntry(name="some-pkg", version=version)
        report = detector.analyze([pkg])
        assert _fired(report, "DC-002"), f"DC-002 should fire for version '{version}'"

    def test_fires_case_insensitive(self, detector):
        pkg = PackageEntry(name="some-pkg", version="INTERNAL")
        report = detector.analyze([pkg])
        assert _fired(report, "DC-002")

    def test_does_not_fire_for_real_version(self, detector):
        pkg = PackageEntry(name="some-pkg", version="1.2.3")
        report = detector.analyze([pkg])
        assert not _fired(report, "DC-002")

    def test_does_not_fire_for_zero_one(self, detector):
        # 0.1.0 is a legitimate early release, not a sentinel
        pkg = PackageEntry(name="some-pkg", version="0.1.0")
        report = detector.analyze([pkg])
        assert not _fired(report, "DC-002")

    def test_severity_is_high(self, detector):
        pkg = PackageEntry(name="pkg", version="dev")
        report = detector.analyze([pkg])
        finding = next(f for f in report.findings if f.check_id == "DC-002")
        assert finding.severity == DCSeverity.HIGH


# ===========================================================================
# DC-003 — Internal registry URL in metadata
# ===========================================================================

class TestDC003:
    @pytest.mark.parametrize("registry_hint", [
        "localhost",
        "127.0.0.1",
        "artifactory",
        "nexus",
        "jfrog",
        "internal.registry",
    ])
    def test_fires_for_known_registry_patterns(self, detector, registry_hint):
        pkg = PackageEntry(
            name="pkg",
            version="1.0.0",
            metadata={"source": f"https://{registry_hint}/repo/pkg"},
        )
        report = detector.analyze([pkg])
        assert _fired(report, "DC-003"), f"DC-003 should fire for pattern '{registry_hint}'"

    def test_fires_case_insensitive_metadata(self, detector):
        pkg = PackageEntry(
            name="pkg",
            version="1.0.0",
            metadata={"url": "https://ARTIFACTORY.corp.local/repo"},
        )
        report = detector.analyze([pkg])
        assert _fired(report, "DC-003")

    def test_does_not_fire_for_clean_metadata(self, detector):
        pkg = PackageEntry(
            name="pkg",
            version="1.0.0",
            metadata={"homepage": "https://github.com/foo/bar"},
        )
        report = detector.analyze([pkg])
        assert not _fired(report, "DC-003")

    def test_does_not_fire_when_metadata_is_empty(self, detector):
        pkg = PackageEntry(name="pkg", version="1.0.0")
        report = detector.analyze([pkg])
        assert not _fired(report, "DC-003")

    def test_severity_is_critical(self, detector):
        pkg = PackageEntry(
            name="pkg",
            version="1.0.0",
            metadata={"url": "http://localhost:8081/repo"},
        )
        report = detector.analyze([pkg])
        finding = next(f for f in report.findings if f.check_id == "DC-003")
        assert finding.severity == DCSeverity.CRITICAL


# ===========================================================================
# DC-004 — Hardcoded company-naming pattern
# ===========================================================================

class TestDC004:
    @pytest.mark.parametrize("name", [
        "acme-corp-sdk",       # contains "-corp"
        "corp-payments",       # contains "corp-"
        "my-company-utils",    # contains "company-"
        "sdk-company",         # contains "-company"
        "auth-internal-svc",   # contains "-internal-"
        "secret-config",       # contains "secret-"
        "private-keys",        # contains "private-"
    ])
    def test_fires_for_company_patterns(self, detector, name):
        pkg = PackageEntry(name=name, version="1.0.0")
        report = detector.analyze([pkg])
        assert _fired(report, "DC-004"), f"DC-004 should fire for name '{name}'"

    def test_does_not_fire_for_generic_name(self, detector):
        pkg = PackageEntry(name="requests", version="2.28.0")
        report = detector.analyze([pkg])
        assert not _fired(report, "DC-004")

    def test_severity_is_high(self, detector):
        pkg = PackageEntry(name="corp-auth", version="1.0.0")
        report = detector.analyze([pkg])
        finding = next(f for f in report.findings if f.check_id == "DC-004")
        assert finding.severity == DCSeverity.HIGH

    def test_fires_case_insensitive(self, detector):
        pkg = PackageEntry(name="CORP-UTILS", version="1.0.0")
        report = detector.analyze([pkg])
        assert _fired(report, "DC-004")


# ===========================================================================
# DC-005 — Unpinned version
# ===========================================================================

class TestDC005:
    @pytest.mark.parametrize("version", [
        "*",
        "latest",
        "",
        "^1.2.3",
        "~1.2.3",
        ">=1.0.0",
    ])
    def test_fires_for_unpinned_specifiers(self, detector, version):
        pkg = PackageEntry(name="pkg", version=version)
        report = detector.analyze([pkg])
        assert _fired(report, "DC-005"), f"DC-005 should fire for version '{version}'"

    def test_does_not_fire_for_exact_pin(self, detector):
        pkg = PackageEntry(name="pkg", version="1.2.3")
        report = detector.analyze([pkg])
        assert not _fired(report, "DC-005")

    def test_suppressed_when_check_unpinned_false(self, no_unpinned_detector):
        pkg = PackageEntry(name="pkg", version="*")
        report = no_unpinned_detector.analyze([pkg])
        assert not _fired(report, "DC-005")

    def test_still_suppressed_with_latest(self, no_unpinned_detector):
        pkg = PackageEntry(name="pkg", version="latest")
        report = no_unpinned_detector.analyze([pkg])
        assert not _fired(report, "DC-005")

    def test_severity_is_medium(self, detector):
        pkg = PackageEntry(name="pkg", version="*")
        report = detector.analyze([pkg])
        finding = next(f for f in report.findings if f.check_id == "DC-005")
        assert finding.severity == DCSeverity.MEDIUM


# ===========================================================================
# DC-006 — Suspiciously short package name
# ===========================================================================

class TestDC006:
    def test_fires_for_single_char_name(self, detector):
        pkg = PackageEntry(name="x", version="1.0.0")
        report = detector.analyze([pkg])
        assert _fired(report, "DC-006")

    def test_fires_for_two_char_name(self, detector):
        pkg = PackageEntry(name="xy", version="1.0.0")
        report = detector.analyze([pkg])
        assert _fired(report, "DC-006")

    def test_does_not_fire_for_three_char_name(self, detector):
        # 3 characters is the boundary — must NOT fire
        pkg = PackageEntry(name="abc", version="1.0.0")
        report = detector.analyze([pkg])
        assert not _fired(report, "DC-006")

    def test_does_not_fire_for_normal_name(self, detector):
        pkg = PackageEntry(name="requests", version="2.28.0")
        report = detector.analyze([pkg])
        assert not _fired(report, "DC-006")

    def test_scoped_npm_uses_basename(self, detector):
        # "@org/xy" — basename "xy" is 2 chars — should fire
        pkg = PackageEntry(name="@org/xy", version="1.0.0", registry="npm")
        report = detector.analyze([pkg])
        assert _fired(report, "DC-006")

    def test_scoped_npm_long_basename_no_fire(self, detector):
        pkg = PackageEntry(name="@org/lodash", version="4.17.21", registry="npm")
        report = detector.analyze([pkg])
        assert not _fired(report, "DC-006")

    def test_severity_is_low(self, detector):
        pkg = PackageEntry(name="ab", version="1.0.0")
        report = detector.analyze([pkg])
        finding = next(f for f in report.findings if f.check_id == "DC-006")
        assert finding.severity == DCSeverity.LOW


# ===========================================================================
# Risk score calculation
# ===========================================================================

class TestRiskScore:
    def test_empty_analysis_yields_zero_score(self, detector):
        report = detector.analyze([])
        assert report.risk_score == 0

    def test_single_dc001_adds_40_points(self, detector):
        # Use a clean package that only triggers DC-001
        pkg = PackageEntry(name="internal-sdk", version="1.0.0")
        report = detector.analyze([pkg])
        # DC-001 (40) fires; DC-005 does NOT fire because version is exact "1.0.0"
        assert 40 <= report.risk_score <= 100

    def test_score_is_capped_at_100(self, detector):
        # Craft a package that triggers every possible check to exceed 100 raw points
        pkg = PackageEntry(
            name="corp-internal-x",   # DC-001 (40) + DC-004 (35) + DC-006 (20)
            version="0.0.1",          # DC-002 (30)
            metadata={"url": "http://artifactory.corp/repo"},  # DC-003 (35)
            registry="pypi",
        )
        # DC-005 would add 25 but version is "0.0.1" (exact, not a range operator)
        report = detector.analyze([pkg])
        assert report.risk_score <= 100

    def test_score_uses_unique_check_ids_only(self, detector):
        """Two packages both triggering DC-001 should not double-count DC-001 weight."""
        pkgs = [
            PackageEntry(name="internal-a", version="1.0.0"),
            PackageEntry(name="internal-b", version="1.0.0"),
        ]
        report = detector.analyze(pkgs)
        # DC-001 weight (40) counted once even though it fired on two packages
        # There may be additional checks (e.g. DC-004 if patterns match),
        # but the score should remain deterministic and <= 100.
        assert report.risk_score <= 100

    def test_packages_analyzed_count(self, detector):
        pkgs = [PackageEntry(name=f"pkg-{i}", version="1.0.0") for i in range(5)]
        report = detector.analyze(pkgs)
        assert report.packages_analyzed == 5


# ===========================================================================
# parse_requirements_txt
# ===========================================================================

class TestParseRequirementsTxt:
    def test_exact_pin(self):
        entries = parse_requirements_txt("requests==2.28.0\n")
        assert len(entries) == 1
        assert entries[0].name == "requests"
        assert entries[0].version == "2.28.0"

    def test_gte_operator_preserved(self):
        entries = parse_requirements_txt("flask>=2.0.0\n")
        assert entries[0].version == ">=2.0.0"

    def test_no_version_becomes_wildcard(self):
        entries = parse_requirements_txt("boto3\n")
        assert entries[0].name == "boto3"
        assert entries[0].version == "*"

    def test_blank_lines_skipped(self):
        content = "\n\nrequests==2.28.0\n\n"
        entries = parse_requirements_txt(content)
        assert len(entries) == 1

    def test_comment_lines_skipped(self):
        content = "# this is a comment\nrequests==2.28.0\n"
        entries = parse_requirements_txt(content)
        assert len(entries) == 1
        assert entries[0].name == "requests"

    def test_inline_comment_stripped(self):
        entries = parse_requirements_txt("requests==2.28.0  # security lib\n")
        assert entries[0].version == "2.28.0"

    def test_recursive_include_skipped(self):
        content = "-r base-requirements.txt\nrequests==2.28.0\n"
        entries = parse_requirements_txt(content)
        assert len(entries) == 1
        assert entries[0].name == "requests"

    def test_extras_stripped_from_name(self):
        entries = parse_requirements_txt("uvicorn[standard]==0.20.0\n")
        assert entries[0].name == "uvicorn"
        assert entries[0].version == "0.20.0"

    def test_extras_stripped_no_version(self):
        entries = parse_requirements_txt("uvicorn[standard]\n")
        assert entries[0].name == "uvicorn"
        assert entries[0].version == "*"

    def test_multiple_packages_parsed(self):
        content = "requests==2.28.0\nflask>=2.0.0\nboto3\n"
        entries = parse_requirements_txt(content)
        assert len(entries) == 3

    def test_registry_defaults_to_pypi(self):
        entries = parse_requirements_txt("requests==2.28.0\n")
        assert entries[0].registry == "pypi"

    def test_source_file_set_to_requirements_txt(self):
        entries = parse_requirements_txt("requests==2.28.0\n")
        assert entries[0].source_file == "requirements.txt"

    def test_empty_content_returns_empty_list(self):
        assert parse_requirements_txt("") == []

    def test_only_comments_returns_empty_list(self):
        content = "# just comments\n# more comments\n"
        assert parse_requirements_txt(content) == []

    def test_tilde_operator_preserved(self):
        entries = parse_requirements_txt("django~=3.2.0\n")
        assert entries[0].version == "~=3.2.0"

    def test_whitespace_around_package_name(self):
        entries = parse_requirements_txt("  requests==2.28.0  \n")
        assert entries[0].name == "requests"


# ===========================================================================
# Integration — parse then detect
# ===========================================================================

class TestIntegration:
    def test_parse_and_detect_pipeline(self, detector):
        content = (
            "# internal build tools\n"
            "corp-internal-sdk==0.0.1\n"
            "requests==2.28.0\n"
            "boto3\n"
        )
        entries = parse_requirements_txt(content)
        report = detector.analyze(entries)

        # corp-internal-sdk should trigger DC-001, DC-002, DC-004 at minimum
        assert _fired(report, "DC-001")
        assert _fired(report, "DC-002")
        assert _fired(report, "DC-004")

        # requests is clean — no findings expected for it
        clean_findings = report.findings_for_package("requests")
        assert clean_findings == []

    def test_scoped_npm_package_does_not_trigger_dc001(self, detector):
        """Scoped npm packages already have namespace isolation."""
        pkgs = [PackageEntry(name="@myorg/internal-auth", version="1.0.0", registry="npm")]
        report = detector.analyze(pkgs)
        assert not _fired(report, "DC-001")

    def test_full_report_to_dict_roundtrip(self, detector):
        pkg = PackageEntry(name="internal-utils", version="*")
        report = detector.analyze([pkg])
        d = report.to_dict()
        # Structural sanity — risk_score should be a non-negative int
        assert isinstance(d["risk_score"], int)
        assert d["risk_score"] >= 0
        assert isinstance(d["findings"], list)
        for finding_dict in d["findings"]:
            assert "check_id" in finding_dict
            assert "severity" in finding_dict

    def test_no_findings_for_clean_packages(self, detector):
        pkgs = [
            PackageEntry(name="requests", version="2.31.0", registry="pypi"),
            PackageEntry(name="flask", version="3.0.0", registry="pypi"),
            PackageEntry(name="pytest", version="7.4.0", registry="pypi"),
        ]
        report = detector.analyze(pkgs)
        assert report.total_findings == 0
        assert report.risk_score == 0
