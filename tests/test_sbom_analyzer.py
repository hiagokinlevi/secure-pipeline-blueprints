# Copyright (c) 2024 Cyber Port — hiagokinlevi
# Licensed under the Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
#
# test_sbom_analyzer.py — pytest test suite for SBOMAnalyzer (90+ tests).

from __future__ import annotations

import sys
import time
import unittest.mock as mock
from typing import List

import pytest

# Allow the test file to be run from the repo root without an installed package
sys.path.insert(0, "/tmp/secure-pipeline-blueprints")

from shared.analyzers.sbom_analyzer import (
    _CHECK_WEIGHTS,
    _DEFAULT_TRUSTED_REGISTRIES,
    SBOMAnalyzer,
    SBOMComponent,
    SBOMFinding,
    SBOMResult,
    SBOMVulnerability,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_critical_vuln(cve_id: str = "CVE-2023-99999") -> SBOMVulnerability:
    return SBOMVulnerability(cve_id=cve_id, cvss_score=9.5, severity="CRITICAL")


def _make_high_vuln(cve_id: str = "CVE-2023-88888") -> SBOMVulnerability:
    return SBOMVulnerability(cve_id=cve_id, cvss_score=8.9, severity="HIGH")


def _findings_for(result: SBOMResult, check_id: str) -> List[SBOMFinding]:
    return [f for f in result.findings if f.check_id == check_id]


ANALYZER = SBOMAnalyzer()

# old timestamp: more than 365 days in the past
OLD_TIMESTAMP: float = time.time() - (366 * 86400)
# recent timestamp: 10 days ago
RECENT_TIMESTAMP: float = time.time() - (10 * 86400)


# ===========================================================================
# Section 1 — Empty input
# ===========================================================================

class TestEmptyInput:
    def test_empty_list_no_findings(self):
        result = ANALYZER.analyze([])
        assert result.findings == []

    def test_empty_list_risk_score_zero(self):
        result = ANALYZER.analyze([])
        assert result.risk_score == 0

    def test_empty_list_summary(self):
        result = ANALYZER.analyze([])
        assert "0 findings" in result.summary()
        assert "risk_score=0" in result.summary()

    def test_empty_list_by_severity_all_empty(self):
        result = ANALYZER.analyze([])
        bs = result.by_severity()
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            assert bs[level] == []


# ===========================================================================
# Section 2 — SBOM-001: Direct component with critical CVE
# ===========================================================================

class TestCheck001:
    def test_direct_critical_cve_triggers(self):
        comp = SBOMComponent(
            name="lodash", version="4.17.11",
            vulnerabilities=[_make_critical_vuln()],
            is_transitive=False,
        )
        result = ANALYZER.analyze([comp])
        assert len(_findings_for(result, "SBOM-001")) == 1

    def test_direct_critical_cve_severity_is_critical(self):
        comp = SBOMComponent(
            name="lodash", version="4.17.11",
            vulnerabilities=[_make_critical_vuln()],
        )
        result = ANALYZER.analyze([comp])
        f = _findings_for(result, "SBOM-001")[0]
        assert f.severity == "CRITICAL"

    def test_cvss_8_9_does_not_trigger_001(self):
        comp = SBOMComponent(
            name="lodash", version="4.17.11",
            vulnerabilities=[_make_high_vuln()],
        )
        result = ANALYZER.analyze([comp])
        assert _findings_for(result, "SBOM-001") == []

    def test_cvss_exactly_9_triggers_001(self):
        """Boundary: CVSS == 9.0 must trigger SBOM-001."""
        vuln = SBOMVulnerability(cve_id="CVE-2023-10000", cvss_score=9.0, severity="CRITICAL")
        comp = SBOMComponent(name="pkg-a", version="1.0", vulnerabilities=[vuln])
        result = ANALYZER.analyze([comp])
        assert len(_findings_for(result, "SBOM-001")) == 1

    def test_transitive_critical_does_not_trigger_001(self):
        comp = SBOMComponent(
            name="sub-dep", version="1.0",
            vulnerabilities=[_make_critical_vuln()],
            is_transitive=True,
        )
        result = ANALYZER.analyze([comp])
        assert _findings_for(result, "SBOM-001") == []

    def test_001_deduplicates_by_name(self):
        """Two entries with the same name produce only one SBOM-001 finding."""
        vuln = _make_critical_vuln()
        comp1 = SBOMComponent(name="lodash", version="4.17.11", vulnerabilities=[vuln])
        comp2 = SBOMComponent(name="lodash", version="4.17.12", vulnerabilities=[vuln])
        result = ANALYZER.analyze([comp1, comp2])
        assert len(_findings_for(result, "SBOM-001")) == 1

    def test_001_cve_ids_populated(self):
        cve = "CVE-2023-55555"
        comp = SBOMComponent(
            name="pkg", version="1.0",
            vulnerabilities=[SBOMVulnerability(cve_id=cve, cvss_score=9.8, severity="CRITICAL")],
        )
        result = ANALYZER.analyze([comp])
        f = _findings_for(result, "SBOM-001")[0]
        assert cve in f.cve_ids

    def test_001_multiple_critical_vulns_all_cves_listed(self):
        vulns = [
            SBOMVulnerability(cve_id="CVE-2023-00001", cvss_score=9.1, severity="CRITICAL"),
            SBOMVulnerability(cve_id="CVE-2023-00002", cvss_score=9.9, severity="CRITICAL"),
        ]
        comp = SBOMComponent(name="risky", version="2.0", vulnerabilities=vulns)
        result = ANALYZER.analyze([comp])
        f = _findings_for(result, "SBOM-001")[0]
        assert set(f.cve_ids) == {"CVE-2023-00001", "CVE-2023-00002"}

    def test_001_component_version_in_finding(self):
        comp = SBOMComponent(
            name="express", version="3.0.0",
            vulnerabilities=[_make_critical_vuln()],
        )
        result = ANALYZER.analyze([comp])
        f = _findings_for(result, "SBOM-001")[0]
        assert f.component_version == "3.0.0"

    def test_001_weight_in_risk_score(self):
        comp = SBOMComponent(
            name="pkg", version="1.0",
            vulnerabilities=[_make_critical_vuln()],
        )
        result = ANALYZER.analyze([comp])
        assert result.risk_score >= _CHECK_WEIGHTS["SBOM-001"]


# ===========================================================================
# Section 3 — SBOM-002: Missing version
# ===========================================================================

class TestCheck002:
    def test_version_none_triggers_002(self):
        comp = SBOMComponent(name="mystery-pkg", version=None)
        result = ANALYZER.analyze([comp])
        assert len(_findings_for(result, "SBOM-002")) == 1

    def test_version_empty_string_triggers_002(self):
        comp = SBOMComponent(name="mystery-pkg", version="")
        result = ANALYZER.analyze([comp])
        assert len(_findings_for(result, "SBOM-002")) == 1

    def test_version_set_does_not_trigger_002(self):
        comp = SBOMComponent(name="known-pkg", version="1.0.0")
        result = ANALYZER.analyze([comp])
        assert _findings_for(result, "SBOM-002") == []

    def test_002_severity_is_high(self):
        comp = SBOMComponent(name="mystery-pkg", version=None)
        result = ANALYZER.analyze([comp])
        f = _findings_for(result, "SBOM-002")[0]
        assert f.severity == "HIGH"

    def test_002_component_name_in_finding(self):
        comp = SBOMComponent(name="my-lib", version=None)
        result = ANALYZER.analyze([comp])
        f = _findings_for(result, "SBOM-002")[0]
        assert f.component_name == "my-lib"

    def test_002_finding_per_missing_version_component(self):
        comps = [
            SBOMComponent(name="a", version=None),
            SBOMComponent(name="b", version=""),
            SBOMComponent(name="c", version="2.0"),
        ]
        result = ANALYZER.analyze(comps)
        assert len(_findings_for(result, "SBOM-002")) == 2

    def test_002_weight_in_risk_score(self):
        comp = SBOMComponent(name="mystery-pkg", version=None)
        result = ANALYZER.analyze([comp])
        assert result.risk_score >= _CHECK_WEIGHTS["SBOM-002"]


# ===========================================================================
# Section 4 — SBOM-003: Copyleft license
# ===========================================================================

class TestCheck003:
    def test_gpl3_triggers_003(self):
        comp = SBOMComponent(name="gnu-tool", version="1.0", license="GPL-3.0")
        result = ANALYZER.analyze([comp])
        assert len(_findings_for(result, "SBOM-003")) == 1

    def test_agpl3_triggers_003(self):
        comp = SBOMComponent(name="agpl-tool", version="1.0", license="AGPL-3.0")
        result = ANALYZER.analyze([comp])
        assert len(_findings_for(result, "SBOM-003")) == 1

    def test_lgpl_triggers_003(self):
        comp = SBOMComponent(name="lgpl-lib", version="1.0", license="LGPL-2.1")
        result = ANALYZER.analyze([comp])
        assert len(_findings_for(result, "SBOM-003")) == 1

    def test_gpl2_triggers_003(self):
        comp = SBOMComponent(name="old-gnu", version="1.0", license="GPL-2.0")
        result = ANALYZER.analyze([comp])
        assert len(_findings_for(result, "SBOM-003")) == 1

    def test_mit_does_not_trigger_003(self):
        comp = SBOMComponent(name="open-pkg", version="1.0", license="MIT")
        result = ANALYZER.analyze([comp])
        assert _findings_for(result, "SBOM-003") == []

    def test_apache_does_not_trigger_003(self):
        comp = SBOMComponent(name="apache-pkg", version="1.0", license="Apache-2.0")
        result = ANALYZER.analyze([comp])
        assert _findings_for(result, "SBOM-003") == []

    def test_none_license_does_not_trigger_003(self):
        comp = SBOMComponent(name="unknown-lic", version="1.0", license=None)
        result = ANALYZER.analyze([comp])
        assert _findings_for(result, "SBOM-003") == []

    def test_003_case_insensitive(self):
        comp = SBOMComponent(name="lower-gpl", version="1.0", license="gpl-3.0")
        result = ANALYZER.analyze([comp])
        assert len(_findings_for(result, "SBOM-003")) == 1

    def test_003_severity_is_medium(self):
        comp = SBOMComponent(name="gnu-tool", version="1.0", license="GPL-3.0")
        result = ANALYZER.analyze([comp])
        f = _findings_for(result, "SBOM-003")[0]
        assert f.severity == "MEDIUM"

    def test_003_weight_in_risk_score(self):
        comp = SBOMComponent(name="gnu-tool", version="1.0", license="GPL-3.0")
        result = ANALYZER.analyze([comp])
        assert result.risk_score >= _CHECK_WEIGHTS["SBOM-003"]


# ===========================================================================
# Section 5 — SBOM-004: Outdated component
# ===========================================================================

class TestCheck004:
    def test_old_timestamp_triggers_004(self):
        comp = SBOMComponent(name="legacy", version="0.1", last_updated=OLD_TIMESTAMP)
        result = ANALYZER.analyze([comp])
        assert len(_findings_for(result, "SBOM-004")) == 1

    def test_recent_timestamp_does_not_trigger_004(self):
        comp = SBOMComponent(name="fresh", version="1.0", last_updated=RECENT_TIMESTAMP)
        result = ANALYZER.analyze([comp])
        assert _findings_for(result, "SBOM-004") == []

    def test_none_last_updated_does_not_trigger_004(self):
        comp = SBOMComponent(name="no-date", version="1.0", last_updated=None)
        result = ANALYZER.analyze([comp])
        assert _findings_for(result, "SBOM-004") == []

    def test_004_boundary_just_over_threshold(self):
        """Timestamp exactly one second beyond max_age_days should trigger."""
        threshold_ts = time.time() - (365 * 86400) - 1
        comp = SBOMComponent(name="borderline", version="1.0", last_updated=threshold_ts)
        result = ANALYZER.analyze([comp])
        assert len(_findings_for(result, "SBOM-004")) == 1

    def test_004_boundary_just_under_threshold(self):
        """Timestamp one second before the threshold should NOT trigger."""
        threshold_ts = time.time() - (365 * 86400) + 1
        comp = SBOMComponent(name="fresh-enough", version="1.0", last_updated=threshold_ts)
        result = ANALYZER.analyze([comp])
        assert _findings_for(result, "SBOM-004") == []

    def test_004_custom_max_age(self):
        """Custom max_age_days=30: a 31-day-old package should trigger."""
        analyzer = SBOMAnalyzer(max_age_days=30)
        ts_31_days_ago = time.time() - (31 * 86400)
        comp = SBOMComponent(name="somewhat-old", version="1.0", last_updated=ts_31_days_ago)
        result = analyzer.analyze([comp])
        assert len(_findings_for(result, "SBOM-004")) == 1

    def test_004_custom_max_age_not_triggered(self):
        analyzer = SBOMAnalyzer(max_age_days=30)
        ts_29_days_ago = time.time() - (29 * 86400)
        comp = SBOMComponent(name="fresh", version="1.0", last_updated=ts_29_days_ago)
        result = analyzer.analyze([comp])
        assert _findings_for(result, "SBOM-004") == []

    def test_004_severity_is_medium(self):
        comp = SBOMComponent(name="legacy", version="0.1", last_updated=OLD_TIMESTAMP)
        result = ANALYZER.analyze([comp])
        f = _findings_for(result, "SBOM-004")[0]
        assert f.severity == "MEDIUM"

    def test_004_weight_in_risk_score(self):
        comp = SBOMComponent(name="legacy", version="0.1", last_updated=OLD_TIMESTAMP)
        result = ANALYZER.analyze([comp])
        assert result.risk_score >= _CHECK_WEIGHTS["SBOM-004"]


# ===========================================================================
# Section 6 — SBOM-005: Untrusted registry
# ===========================================================================

class TestCheck005:
    def test_npm_trusted(self):
        comp = SBOMComponent(
            name="lodash", version="4.17.21",
            registry="https://registry.npmjs.org",
        )
        result = ANALYZER.analyze([comp])
        assert _findings_for(result, "SBOM-005") == []

    def test_pypi_trusted(self):
        comp = SBOMComponent(
            name="requests", version="2.28.0",
            registry="https://pypi.org",
        )
        result = ANALYZER.analyze([comp])
        assert _findings_for(result, "SBOM-005") == []

    def test_maven_trusted(self):
        comp = SBOMComponent(
            name="log4j-core", version="2.17.2",
            registry="https://repo.maven.apache.org",
        )
        result = ANALYZER.analyze([comp])
        assert _findings_for(result, "SBOM-005") == []

    def test_docker_hub_trusted(self):
        comp = SBOMComponent(
            name="nginx", version="1.25",
            registry="https://registry.hub.docker.com",
        )
        result = ANALYZER.analyze([comp])
        assert _findings_for(result, "SBOM-005") == []

    def test_rubygems_trusted(self):
        comp = SBOMComponent(
            name="rails", version="7.0.0",
            registry="https://rubygems.org",
        )
        result = ANALYZER.analyze([comp])
        assert _findings_for(result, "SBOM-005") == []

    def test_custom_registry_untrusted(self):
        comp = SBOMComponent(
            name="internal-lib", version="1.0",
            registry="https://my-private-nexus.example.com",
        )
        result = ANALYZER.analyze([comp])
        assert len(_findings_for(result, "SBOM-005")) == 1

    def test_none_registry_does_not_trigger_005(self):
        comp = SBOMComponent(name="no-registry", version="1.0", registry=None)
        result = ANALYZER.analyze([comp])
        assert _findings_for(result, "SBOM-005") == []

    def test_005_severity_is_high(self):
        comp = SBOMComponent(
            name="shady-pkg", version="0.0.1",
            registry="https://evil-registry.io",
        )
        result = ANALYZER.analyze([comp])
        f = _findings_for(result, "SBOM-005")[0]
        assert f.severity == "HIGH"

    def test_005_custom_trusted_registries(self):
        analyzer = SBOMAnalyzer(trusted_registries=["https://my-nexus.corp"])
        comp = SBOMComponent(
            name="corp-lib", version="1.0",
            registry="https://my-nexus.corp/repo",
        )
        result = analyzer.analyze([comp])
        assert _findings_for(result, "SBOM-005") == []

    def test_005_custom_trusted_registries_still_untrusted(self):
        """npm should be untrusted when a custom list is supplied without it."""
        analyzer = SBOMAnalyzer(trusted_registries=["https://my-nexus.corp"])
        comp = SBOMComponent(
            name="lodash", version="4.17.21",
            registry="https://registry.npmjs.org",
        )
        result = analyzer.analyze([comp])
        assert len(_findings_for(result, "SBOM-005")) == 1

    def test_005_weight_in_risk_score(self):
        comp = SBOMComponent(
            name="shady-pkg", version="1.0",
            registry="https://evil-registry.io",
        )
        result = ANALYZER.analyze([comp])
        assert result.risk_score >= _CHECK_WEIGHTS["SBOM-005"]


# ===========================================================================
# Section 7 — SBOM-006: Duplicate package name with different versions
# ===========================================================================

class TestCheck006:
    def test_same_name_different_versions_triggers_006(self):
        comps = [
            SBOMComponent(name="lodash", version="4.17.11"),
            SBOMComponent(name="lodash", version="4.17.21"),
        ]
        result = ANALYZER.analyze(comps)
        assert len(_findings_for(result, "SBOM-006")) == 1

    def test_same_name_same_version_does_not_trigger_006(self):
        comps = [
            SBOMComponent(name="lodash", version="4.17.21"),
            SBOMComponent(name="lodash", version="4.17.21"),
        ]
        result = ANALYZER.analyze(comps)
        assert _findings_for(result, "SBOM-006") == []

    def test_unique_names_do_not_trigger_006(self):
        comps = [
            SBOMComponent(name="express", version="4.18.0"),
            SBOMComponent(name="lodash", version="4.17.21"),
        ]
        result = ANALYZER.analyze(comps)
        assert _findings_for(result, "SBOM-006") == []

    def test_006_one_finding_per_duplicate_name(self):
        comps = [
            SBOMComponent(name="lodash", version="4.0.0"),
            SBOMComponent(name="lodash", version="4.1.0"),
            SBOMComponent(name="lodash", version="4.2.0"),
        ]
        result = ANALYZER.analyze(comps)
        assert len(_findings_for(result, "SBOM-006")) == 1

    def test_006_two_duplicate_packages_two_findings(self):
        comps = [
            SBOMComponent(name="lodash", version="4.0.0"),
            SBOMComponent(name="lodash", version="4.1.0"),
            SBOMComponent(name="moment", version="2.29.0"),
            SBOMComponent(name="moment", version="2.30.0"),
        ]
        result = ANALYZER.analyze(comps)
        assert len(_findings_for(result, "SBOM-006")) == 2

    def test_006_severity_is_low(self):
        comps = [
            SBOMComponent(name="react", version="17.0.0"),
            SBOMComponent(name="react", version="18.0.0"),
        ]
        result = ANALYZER.analyze(comps)
        f = _findings_for(result, "SBOM-006")[0]
        assert f.severity == "LOW"

    def test_006_component_name_in_finding(self):
        comps = [
            SBOMComponent(name="react", version="17.0.0"),
            SBOMComponent(name="react", version="18.0.0"),
        ]
        result = ANALYZER.analyze(comps)
        f = _findings_for(result, "SBOM-006")[0]
        assert f.component_name == "react"

    def test_006_weight_in_risk_score(self):
        comps = [
            SBOMComponent(name="react", version="17.0.0"),
            SBOMComponent(name="react", version="18.0.0"),
        ]
        result = ANALYZER.analyze(comps)
        assert result.risk_score >= _CHECK_WEIGHTS["SBOM-006"]


# ===========================================================================
# Section 8 — SBOM-007: Transitive dependency with critical CVE
# ===========================================================================

class TestCheck007:
    def test_transitive_critical_cve_triggers_007(self):
        comp = SBOMComponent(
            name="deep-dep", version="1.0",
            vulnerabilities=[_make_critical_vuln()],
            is_transitive=True,
        )
        result = ANALYZER.analyze([comp])
        assert len(_findings_for(result, "SBOM-007")) == 1

    def test_direct_critical_does_not_trigger_007(self):
        comp = SBOMComponent(
            name="direct-pkg", version="1.0",
            vulnerabilities=[_make_critical_vuln()],
            is_transitive=False,
        )
        result = ANALYZER.analyze([comp])
        assert _findings_for(result, "SBOM-007") == []

    def test_transitive_cvss_8_9_does_not_trigger_007(self):
        comp = SBOMComponent(
            name="deep-dep", version="1.0",
            vulnerabilities=[_make_high_vuln()],
            is_transitive=True,
        )
        result = ANALYZER.analyze([comp])
        assert _findings_for(result, "SBOM-007") == []

    def test_transitive_cvss_exactly_9_triggers_007(self):
        vuln = SBOMVulnerability(cve_id="CVE-2023-10001", cvss_score=9.0, severity="CRITICAL")
        comp = SBOMComponent(name="trans-pkg", version="1.0", vulnerabilities=[vuln], is_transitive=True)
        result = ANALYZER.analyze([comp])
        assert len(_findings_for(result, "SBOM-007")) == 1

    def test_007_deduplicates_by_name(self):
        vuln = _make_critical_vuln()
        comp1 = SBOMComponent(name="deep-dep", version="1.0", vulnerabilities=[vuln], is_transitive=True)
        comp2 = SBOMComponent(name="deep-dep", version="1.1", vulnerabilities=[vuln], is_transitive=True)
        result = ANALYZER.analyze([comp1, comp2])
        assert len(_findings_for(result, "SBOM-007")) == 1

    def test_007_severity_is_high(self):
        comp = SBOMComponent(
            name="deep-dep", version="1.0",
            vulnerabilities=[_make_critical_vuln()],
            is_transitive=True,
        )
        result = ANALYZER.analyze([comp])
        f = _findings_for(result, "SBOM-007")[0]
        assert f.severity == "HIGH"

    def test_007_cve_ids_populated(self):
        cve = "CVE-2023-77777"
        comp = SBOMComponent(
            name="trans-risky", version="1.0",
            vulnerabilities=[SBOMVulnerability(cve_id=cve, cvss_score=9.8, severity="CRITICAL")],
            is_transitive=True,
        )
        result = ANALYZER.analyze([comp])
        f = _findings_for(result, "SBOM-007")[0]
        assert cve in f.cve_ids

    def test_007_weight_in_risk_score(self):
        comp = SBOMComponent(
            name="deep-dep", version="1.0",
            vulnerabilities=[_make_critical_vuln()],
            is_transitive=True,
        )
        result = ANALYZER.analyze([comp])
        assert result.risk_score >= _CHECK_WEIGHTS["SBOM-007"]


# ===========================================================================
# Section 9 — Risk score behaviour
# ===========================================================================

class TestRiskScore:
    def test_risk_score_capped_at_100(self):
        """Fire all seven checks; accumulated weight > 100, must cap at 100."""
        comps = [
            # SBOM-001 (40) + SBOM-002 (20) + SBOM-003 (15) + SBOM-004 (15)
            # + SBOM-005 (25) + SBOM-006 (5) + SBOM-007 (25) = 145 -> capped
            SBOMComponent(
                name="bad-direct",
                version=None,                              # 002
                license="GPL-3.0",                        # 003
                last_updated=OLD_TIMESTAMP,               # 004
                registry="https://evil.io",               # 005
                vulnerabilities=[_make_critical_vuln()],  # 001
                is_transitive=False,
            ),
            SBOMComponent(
                name="bad-direct",
                version="0.0.2",                          # triggers 006 (dup name+diff version)
                registry="https://evil.io",
            ),
            SBOMComponent(
                name="bad-trans",
                version="1.0",
                vulnerabilities=[_make_critical_vuln()],  # 007
                is_transitive=True,
            ),
        ]
        result = ANALYZER.analyze(comps)
        assert result.risk_score == 100

    def test_risk_score_single_check_equals_weight(self):
        comp = SBOMComponent(name="mystery-pkg", version=None)
        result = ANALYZER.analyze([comp])
        # Only SBOM-002 should fire (weight=20)
        assert result.risk_score == _CHECK_WEIGHTS["SBOM-002"]

    def test_risk_score_is_int(self):
        comp = SBOMComponent(name="test", version=None)
        result = ANALYZER.analyze([comp])
        assert isinstance(result.risk_score, int)

    def test_multiple_firings_of_same_check_counted_once(self):
        """Ten missing-version components should not multiply the weight."""
        comps = [SBOMComponent(name=f"pkg-{i}", version=None) for i in range(10)]
        result = ANALYZER.analyze(comps)
        assert result.risk_score == _CHECK_WEIGHTS["SBOM-002"]

    def test_two_distinct_checks_sum_weights(self):
        """SBOM-002 (20) + SBOM-003 (15) = 35."""
        comp = SBOMComponent(name="dual-issue", version=None, license="GPL-3.0")
        result = ANALYZER.analyze([comp])
        expected = _CHECK_WEIGHTS["SBOM-002"] + _CHECK_WEIGHTS["SBOM-003"]
        assert result.risk_score == expected


# ===========================================================================
# Section 10 — Multiple checks on the same component
# ===========================================================================

class TestMultipleChecks:
    def test_component_triggers_multiple_checks(self):
        """One component that violates 001, 002, 003, 004, and 005."""
        comp = SBOMComponent(
            name="swiss-army-vuln",
            version=None,                              # 002
            license="GPL-3.0",                        # 003
            last_updated=OLD_TIMESTAMP,               # 004
            registry="https://evil.io",               # 005
            vulnerabilities=[_make_critical_vuln()],  # 001
        )
        result = ANALYZER.analyze([comp])
        fired = {f.check_id for f in result.findings}
        assert fired >= {"SBOM-001", "SBOM-002", "SBOM-003", "SBOM-004", "SBOM-005"}

    def test_both_001_and_007_can_fire_together(self):
        direct = SBOMComponent(
            name="pkg-direct", version="1.0",
            vulnerabilities=[_make_critical_vuln()],
            is_transitive=False,
        )
        trans = SBOMComponent(
            name="pkg-trans", version="1.0",
            vulnerabilities=[_make_critical_vuln()],
            is_transitive=True,
        )
        result = ANALYZER.analyze([direct, trans])
        assert len(_findings_for(result, "SBOM-001")) == 1
        assert len(_findings_for(result, "SBOM-007")) == 1


# ===========================================================================
# Section 11 — by_severity() structure
# ===========================================================================

class TestBySeverity:
    def test_by_severity_has_all_four_keys(self):
        result = ANALYZER.analyze([])
        bs = result.by_severity()
        assert set(bs.keys()) == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

    def test_by_severity_critical_finding(self):
        comp = SBOMComponent(
            name="pkg", version="1.0",
            vulnerabilities=[_make_critical_vuln()],
        )
        result = ANALYZER.analyze([comp])
        bs = result.by_severity()
        assert len(bs["CRITICAL"]) == 1

    def test_by_severity_high_finding(self):
        comp = SBOMComponent(name="pkg", version=None)  # SBOM-002 = HIGH
        result = ANALYZER.analyze([comp])
        bs = result.by_severity()
        assert len(bs["HIGH"]) >= 1

    def test_by_severity_medium_finding(self):
        comp = SBOMComponent(name="gpl-pkg", version="1.0", license="GPL-3.0")
        result = ANALYZER.analyze([comp])
        bs = result.by_severity()
        assert len(bs["MEDIUM"]) == 1

    def test_by_severity_low_finding(self):
        comps = [
            SBOMComponent(name="react", version="17.0.0"),
            SBOMComponent(name="react", version="18.0.0"),
        ]
        result = ANALYZER.analyze(comps)
        bs = result.by_severity()
        assert len(bs["LOW"]) >= 1

    def test_by_severity_returns_only_sbomfinding_objects(self):
        comp = SBOMComponent(name="pkg", version=None)
        result = ANALYZER.analyze([comp])
        for findings_list in result.by_severity().values():
            for item in findings_list:
                assert isinstance(item, SBOMFinding)


# ===========================================================================
# Section 12 — summary() format
# ===========================================================================

class TestSummary:
    def test_summary_contains_finding_count(self):
        comp = SBOMComponent(name="pkg", version=None)
        result = ANALYZER.analyze([comp])
        assert "1 findings" in result.summary()

    def test_summary_contains_risk_score(self):
        comp = SBOMComponent(name="pkg", version=None)
        result = ANALYZER.analyze([comp])
        assert f"risk_score={result.risk_score}" in result.summary()

    def test_summary_zero_findings(self):
        result = ANALYZER.analyze([])
        assert "0 findings" in result.summary()
        assert "risk_score=0" in result.summary()

    def test_summary_starts_with_sbomresult(self):
        result = ANALYZER.analyze([])
        assert result.summary().startswith("SBOMResult:")

    def test_summary_shows_critical_count(self):
        comp = SBOMComponent(
            name="crit-pkg", version="1.0",
            vulnerabilities=[_make_critical_vuln()],
        )
        result = ANALYZER.analyze([comp])
        assert "CRITICAL:1" in result.summary()

    def test_summary_shows_multiple_severities(self):
        comps = [
            SBOMComponent(
                name="crit-pkg", version="1.0",
                vulnerabilities=[_make_critical_vuln()],
            ),
            SBOMComponent(name="no-ver", version=None),  # HIGH
            SBOMComponent(name="gpl-pkg", version="1.0", license="GPL-3.0"),  # MEDIUM
        ]
        result = ANALYZER.analyze(comps)
        s = result.summary()
        assert "CRITICAL:1" in s
        assert "HIGH:" in s
        assert "MEDIUM:1" in s


# ===========================================================================
# Section 13 — analyze_many()
# ===========================================================================

class TestAnalyzeMany:
    def test_analyze_many_empty_outer_list(self):
        results = ANALYZER.analyze_many([])
        assert results == []

    def test_analyze_many_returns_list_of_sbomresult(self):
        results = ANALYZER.analyze_many([[], []])
        assert all(isinstance(r, SBOMResult) for r in results)

    def test_analyze_many_result_count_matches_input(self):
        lists = [[], [], []]
        results = ANALYZER.analyze_many(lists)
        assert len(results) == 3

    def test_analyze_many_each_result_is_independent(self):
        comp_a = SBOMComponent(name="pkg-a", version=None)   # fires SBOM-002
        comp_b = SBOMComponent(name="pkg-b", version="1.0")  # clean
        results = ANALYZER.analyze_many([[comp_a], [comp_b]])
        assert len(results[0].findings) > 0
        assert len(results[1].findings) == 0

    def test_analyze_many_risk_scores_independent(self):
        comp = SBOMComponent(name="pkg", version=None)
        results = ANALYZER.analyze_many([[comp], []])
        assert results[0].risk_score > 0
        assert results[1].risk_score == 0

    def test_analyze_many_preserves_order(self):
        comp1 = SBOMComponent(name="pkg-1", version=None)                          # SBOM-002
        comp2 = SBOMComponent(name="pkg-2", version="1.0", license="GPL-3.0")     # SBOM-003
        results = ANALYZER.analyze_many([[comp1], [comp2]])
        assert _findings_for(results[0], "SBOM-002") != []
        assert _findings_for(results[1], "SBOM-003") != []


# ===========================================================================
# Section 14 — to_dict() on all dataclasses
# ===========================================================================

class TestToDict:
    def test_sbom_vulnerability_to_dict_keys(self):
        v = SBOMVulnerability(cve_id="CVE-2023-1", cvss_score=9.5, severity="CRITICAL")
        d = v.to_dict()
        assert set(d.keys()) == {"cve_id", "cvss_score", "severity"}

    def test_sbom_vulnerability_to_dict_values(self):
        v = SBOMVulnerability(cve_id="CVE-2023-1", cvss_score=9.5, severity="CRITICAL")
        d = v.to_dict()
        assert d["cve_id"] == "CVE-2023-1"
        assert d["cvss_score"] == 9.5
        assert d["severity"] == "CRITICAL"

    def test_sbom_component_to_dict_keys(self):
        comp = SBOMComponent(name="lodash", version="4.17.21")
        d = comp.to_dict()
        expected_keys = {
            "name", "version", "purl", "registry", "license",
            "last_updated", "vulnerabilities", "is_transitive",
        }
        assert set(d.keys()) == expected_keys

    def test_sbom_component_to_dict_vulnerabilities_serialized(self):
        v = SBOMVulnerability(cve_id="CVE-2023-1", cvss_score=9.5, severity="CRITICAL")
        comp = SBOMComponent(name="lodash", version="4.17.21", vulnerabilities=[v])
        d = comp.to_dict()
        assert isinstance(d["vulnerabilities"], list)
        assert d["vulnerabilities"][0]["cve_id"] == "CVE-2023-1"

    def test_sbom_finding_to_dict_keys(self):
        f = SBOMFinding(
            check_id="SBOM-001", severity="CRITICAL",
            component_name="pkg", component_version="1.0",
            message="msg", recommendation="rec",
        )
        d = f.to_dict()
        expected_keys = {
            "check_id", "severity", "component_name", "component_version",
            "message", "recommendation", "cve_ids",
        }
        assert set(d.keys()) == expected_keys

    def test_sbom_finding_to_dict_cve_ids_is_list(self):
        f = SBOMFinding(
            check_id="SBOM-001", severity="CRITICAL",
            component_name="pkg", component_version="1.0",
            message="msg", recommendation="rec",
            cve_ids=["CVE-2023-1"],
        )
        d = f.to_dict()
        assert isinstance(d["cve_ids"], list)
        assert d["cve_ids"] == ["CVE-2023-1"]

    def test_sbom_result_to_dict_keys(self):
        result = ANALYZER.analyze([])
        d = result.to_dict()
        assert set(d.keys()) == {"findings", "risk_score", "summary"}

    def test_sbom_result_to_dict_findings_is_list(self):
        comp = SBOMComponent(name="pkg", version=None)
        result = ANALYZER.analyze([comp])
        d = result.to_dict()
        assert isinstance(d["findings"], list)

    def test_sbom_result_to_dict_summary_is_string(self):
        result = ANALYZER.analyze([])
        d = result.to_dict()
        assert isinstance(d["summary"], str)


# ===========================================================================
# Section 15 — Default trusted registries
# ===========================================================================

class TestDefaultTrustedRegistries:
    def test_default_list_has_five_entries(self):
        assert len(_DEFAULT_TRUSTED_REGISTRIES) == 5

    def test_default_list_contains_npmjs(self):
        assert "https://registry.npmjs.org" in _DEFAULT_TRUSTED_REGISTRIES

    def test_default_list_contains_pypi(self):
        assert "https://pypi.org" in _DEFAULT_TRUSTED_REGISTRIES

    def test_default_list_contains_maven(self):
        assert "https://repo.maven.apache.org" in _DEFAULT_TRUSTED_REGISTRIES

    def test_default_list_contains_docker_hub(self):
        assert "https://registry.hub.docker.com" in _DEFAULT_TRUSTED_REGISTRIES

    def test_default_list_contains_rubygems(self):
        assert "https://rubygems.org" in _DEFAULT_TRUSTED_REGISTRIES

    def test_analyzer_default_copies_list(self):
        """Mutating the analyzer's list must not affect the module-level default."""
        analyzer = SBOMAnalyzer()
        analyzer.trusted_registries.append("https://extra.io")
        assert "https://extra.io" not in _DEFAULT_TRUSTED_REGISTRIES

    def test_analyzer_uses_default_when_none_passed(self):
        analyzer = SBOMAnalyzer(trusted_registries=None)
        assert analyzer.trusted_registries == _DEFAULT_TRUSTED_REGISTRIES


# ===========================================================================
# Section 16 — SBOMAnalyzer constructor
# ===========================================================================

class TestAnalyzerConstructor:
    def test_default_max_age_days(self):
        analyzer = SBOMAnalyzer()
        assert analyzer.max_age_days == 365

    def test_custom_max_age_days_stored(self):
        analyzer = SBOMAnalyzer(max_age_days=90)
        assert analyzer.max_age_days == 90

    def test_custom_trusted_registries_stored(self):
        custom = ["https://internal.corp"]
        analyzer = SBOMAnalyzer(trusted_registries=custom)
        assert "https://internal.corp" in analyzer.trusted_registries

    def test_custom_trusted_registries_are_copied(self):
        """Original list mutation after construction must not affect analyzer."""
        original = ["https://internal.corp"]
        analyzer = SBOMAnalyzer(trusted_registries=original)
        original.append("https://evil.io")
        assert "https://evil.io" not in analyzer.trusted_registries


# ===========================================================================
# Section 17 — check_weights registry
# ===========================================================================

class TestCheckWeights:
    def test_all_seven_check_ids_present(self):
        for i in range(1, 8):
            cid = f"SBOM-{i:03d}"
            assert cid in _CHECK_WEIGHTS, f"{cid} missing from _CHECK_WEIGHTS"

    def test_001_weight_is_40(self):
        assert _CHECK_WEIGHTS["SBOM-001"] == 40

    def test_002_weight_is_20(self):
        assert _CHECK_WEIGHTS["SBOM-002"] == 20

    def test_003_weight_is_15(self):
        assert _CHECK_WEIGHTS["SBOM-003"] == 15

    def test_004_weight_is_15(self):
        assert _CHECK_WEIGHTS["SBOM-004"] == 15

    def test_005_weight_is_25(self):
        assert _CHECK_WEIGHTS["SBOM-005"] == 25

    def test_006_weight_is_5(self):
        assert _CHECK_WEIGHTS["SBOM-006"] == 5

    def test_007_weight_is_25(self):
        assert _CHECK_WEIGHTS["SBOM-007"] == 25


# ===========================================================================
# Section 18 — SBOMFinding cve_ids default empty
# ===========================================================================

class TestFindingDefaults:
    def test_finding_cve_ids_default_empty(self):
        f = SBOMFinding(
            check_id="SBOM-002", severity="HIGH",
            component_name="pkg", component_version=None,
            message="msg", recommendation="rec",
        )
        assert f.cve_ids == []

    def test_finding_cve_ids_not_shared_between_instances(self):
        """Each SBOMFinding must get its own cve_ids list (mutable default)."""
        f1 = SBOMFinding(
            check_id="SBOM-002", severity="HIGH",
            component_name="a", component_version=None,
            message="m", recommendation="r",
        )
        f2 = SBOMFinding(
            check_id="SBOM-002", severity="HIGH",
            component_name="b", component_version=None,
            message="m", recommendation="r",
        )
        f1.cve_ids.append("CVE-X")
        assert f2.cve_ids == []
