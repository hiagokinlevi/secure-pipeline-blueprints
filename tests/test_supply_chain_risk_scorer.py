# test_supply_chain_risk_scorer.py
# 90+ pytest tests for SupplyChainRiskScorer.
#
# © 2024 Cyber Port Contributors
# Licensed under the Creative Commons Attribution 4.0 International License (CC BY 4.0).
# See https://creativecommons.org/licenses/by/4.0/ for full license text.

from __future__ import annotations

import sys
import time

# Make the shared analyzers package importable when running from the repo root
# or from the tests/ directory.
import os

sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..", "shared", "analyzers"),
)

import pytest

from supply_chain_risk_scorer import (
    PackageInfo,
    SupplyChainFinding,
    SupplyChainRiskResult,
    SupplyChainRiskScorer,
    _CHECK_WEIGHTS,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
)

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

NOW = time.time()
ONE_YEAR_AGO = NOW - 365 * 86400
ONE_DAY_AGO = NOW - 86400          # < 30 days → triggers SCR-001
THIRTY_ONE_DAYS_AGO = NOW - 31 * 86400  # > 30 days → does NOT trigger SCR-001


def make_safe_pkg(**overrides) -> PackageInfo:
    """Return a baseline 'safe' package that triggers zero checks by default."""
    defaults = dict(
        name="requests",
        version="2.31.0",
        ecosystem="pypi",
        published_at=ONE_YEAR_AGO,    # old enough — no SCR-001
        author_count=10,              # ≥ 2 — no SCR-002
        star_count=50000,             # ≥ 100 — no SCR-003
        source_repo_url="https://github.com/psf/requests",  # set — no SCR-005
        scope=None,                   # no scope — no SCR-007
        version_constraint="2.31.0",  # exact pin — no SCR-006
        popular_package_similarity=0.0,  # no typosquatting — no SCR-004
    )
    defaults.update(overrides)
    return PackageInfo(**defaults)


def scorer() -> SupplyChainRiskScorer:
    return SupplyChainRiskScorer()


def check_ids(result: SupplyChainRiskResult):
    return {f.check_id for f in result.findings}


# ===========================================================================
# 1. Trusted / clean package — zero findings
# ===========================================================================

class TestCleanPackage:
    def test_no_findings(self):
        result = scorer().score(make_safe_pkg())
        assert result.findings == []

    def test_risk_score_zero(self):
        result = scorer().score(make_safe_pkg())
        assert result.risk_score == 0

    def test_summary_no_findings_text(self):
        result = scorer().score(make_safe_pkg())
        assert "No findings" in result.summary()

    def test_by_severity_all_empty(self):
        result = scorer().score(make_safe_pkg())
        by_sev = result.by_severity()
        assert by_sev[SEVERITY_CRITICAL] == []
        assert by_sev[SEVERITY_HIGH] == []
        assert by_sev[SEVERITY_MEDIUM] == []
        assert by_sev[SEVERITY_LOW] == []


# ===========================================================================
# 2. SCR-001 — Recently published package
# ===========================================================================

class TestSCR001:
    def test_recent_published_triggers(self):
        pkg = make_safe_pkg(published_at=ONE_DAY_AGO)
        result = scorer().score(pkg)
        assert "SCR-001" in check_ids(result)

    def test_recent_published_weight(self):
        pkg = make_safe_pkg(published_at=ONE_DAY_AGO)
        result = scorer().score(pkg)
        assert result.risk_score == _CHECK_WEIGHTS["SCR-001"]

    def test_recent_published_severity_medium(self):
        pkg = make_safe_pkg(published_at=ONE_DAY_AGO)
        result = scorer().score(pkg)
        finding = next(f for f in result.findings if f.check_id == "SCR-001")
        assert finding.severity == SEVERITY_MEDIUM

    def test_old_published_does_not_trigger(self):
        pkg = make_safe_pkg(published_at=THIRTY_ONE_DAYS_AGO)
        result = scorer().score(pkg)
        assert "SCR-001" not in check_ids(result)

    def test_none_published_at_does_not_trigger(self):
        pkg = make_safe_pkg(published_at=None)
        result = scorer().score(pkg)
        assert "SCR-001" not in check_ids(result)

    def test_custom_max_new_package_days_10_triggers(self):
        # Package published 15 days ago; default threshold 30 would trigger,
        # but with threshold=10 it should ALSO trigger (15 > 10 → should NOT).
        # Actually 15 days ago < 10 days threshold is False — so let's test
        # a package published 5 days ago with threshold=10.
        five_days_ago = NOW - 5 * 86400
        pkg = make_safe_pkg(published_at=five_days_ago)
        s = SupplyChainRiskScorer(max_new_package_days=10)
        result = s.score(pkg)
        assert "SCR-001" in check_ids(result)

    def test_custom_max_new_package_days_10_does_not_trigger_when_older(self):
        # 15 days ago with threshold=10: 15 > 10 so NOT triggered
        fifteen_days_ago = NOW - 15 * 86400
        pkg = make_safe_pkg(published_at=fifteen_days_ago)
        s = SupplyChainRiskScorer(max_new_package_days=10)
        result = s.score(pkg)
        assert "SCR-001" not in check_ids(result)

    def test_published_just_now_triggers(self):
        pkg = make_safe_pkg(published_at=NOW - 60)  # 1 minute ago
        result = scorer().score(pkg)
        assert "SCR-001" in check_ids(result)

    def test_published_exactly_30_days_ago_boundary(self):
        # Exactly 30 days ago is NOT less-than 30 days → should not trigger
        exactly_30_days = NOW - 30 * 86400
        pkg = make_safe_pkg(published_at=exactly_30_days)
        result = scorer().score(pkg)
        assert "SCR-001" not in check_ids(result)


# ===========================================================================
# 3. SCR-002 — Very few maintainers
# ===========================================================================

class TestSCR002:
    def test_author_count_1_triggers(self):
        pkg = make_safe_pkg(author_count=1)
        result = scorer().score(pkg)
        assert "SCR-002" in check_ids(result)

    def test_author_count_0_triggers(self):
        pkg = make_safe_pkg(author_count=0)
        result = scorer().score(pkg)
        assert "SCR-002" in check_ids(result)

    def test_author_count_2_does_not_trigger(self):
        pkg = make_safe_pkg(author_count=2)
        result = scorer().score(pkg)
        assert "SCR-002" not in check_ids(result)

    def test_author_count_10_does_not_trigger(self):
        pkg = make_safe_pkg(author_count=10)
        result = scorer().score(pkg)
        assert "SCR-002" not in check_ids(result)

    def test_author_count_none_does_not_trigger(self):
        pkg = make_safe_pkg(author_count=None)
        result = scorer().score(pkg)
        assert "SCR-002" not in check_ids(result)

    def test_author_count_1_severity_medium(self):
        pkg = make_safe_pkg(author_count=1)
        result = scorer().score(pkg)
        finding = next(f for f in result.findings if f.check_id == "SCR-002")
        assert finding.severity == SEVERITY_MEDIUM

    def test_author_count_1_weight(self):
        pkg = make_safe_pkg(author_count=1)
        result = scorer().score(pkg)
        assert result.risk_score == _CHECK_WEIGHTS["SCR-002"]


# ===========================================================================
# 4. SCR-003 — Low community adoption
# ===========================================================================

class TestSCR003:
    def test_star_count_50_triggers(self):
        pkg = make_safe_pkg(star_count=50)
        result = scorer().score(pkg)
        assert "SCR-003" in check_ids(result)

    def test_star_count_99_triggers(self):
        pkg = make_safe_pkg(star_count=99)
        result = scorer().score(pkg)
        assert "SCR-003" in check_ids(result)

    def test_star_count_0_triggers(self):
        pkg = make_safe_pkg(star_count=0)
        result = scorer().score(pkg)
        assert "SCR-003" in check_ids(result)

    def test_star_count_100_does_not_trigger(self):
        pkg = make_safe_pkg(star_count=100)
        result = scorer().score(pkg)
        assert "SCR-003" not in check_ids(result)

    def test_star_count_1000_does_not_trigger(self):
        pkg = make_safe_pkg(star_count=1000)
        result = scorer().score(pkg)
        assert "SCR-003" not in check_ids(result)

    def test_star_count_none_does_not_trigger(self):
        pkg = make_safe_pkg(star_count=None)
        result = scorer().score(pkg)
        assert "SCR-003" not in check_ids(result)

    def test_star_count_99_severity_low(self):
        pkg = make_safe_pkg(star_count=99)
        result = scorer().score(pkg)
        finding = next(f for f in result.findings if f.check_id == "SCR-003")
        assert finding.severity == SEVERITY_LOW

    def test_star_count_99_weight(self):
        pkg = make_safe_pkg(star_count=99)
        result = scorer().score(pkg)
        assert result.risk_score == _CHECK_WEIGHTS["SCR-003"]

    def test_custom_min_stars_triggers_at_200(self):
        pkg = make_safe_pkg(star_count=150)
        s = SupplyChainRiskScorer(min_stars=200)
        result = s.score(pkg)
        assert "SCR-003" in check_ids(result)

    def test_custom_min_stars_does_not_trigger_at_200(self):
        pkg = make_safe_pkg(star_count=250)
        s = SupplyChainRiskScorer(min_stars=200)
        result = s.score(pkg)
        assert "SCR-003" not in check_ids(result)


# ===========================================================================
# 5. SCR-004 — Typosquatting (name similarity)
# ===========================================================================

class TestSCR004:
    def test_similarity_0_90_triggers(self):
        pkg = make_safe_pkg(name="requets", popular_package_similarity=0.90)
        result = scorer().score(pkg)
        assert "SCR-004" in check_ids(result)

    def test_similarity_0_85_boundary_triggers(self):
        pkg = make_safe_pkg(name="requets", popular_package_similarity=0.85)
        result = scorer().score(pkg)
        assert "SCR-004" in check_ids(result)

    def test_similarity_0_84_does_not_trigger(self):
        pkg = make_safe_pkg(name="requets", popular_package_similarity=0.84)
        result = scorer().score(pkg)
        assert "SCR-004" not in check_ids(result)

    def test_similarity_0_0_does_not_trigger(self):
        pkg = make_safe_pkg(popular_package_similarity=0.0)
        result = scorer().score(pkg)
        assert "SCR-004" not in check_ids(result)

    def test_similarity_none_does_not_trigger(self):
        pkg = make_safe_pkg(popular_package_similarity=None)
        result = scorer().score(pkg)
        assert "SCR-004" not in check_ids(result)

    def test_similarity_0_90_severity_critical(self):
        pkg = make_safe_pkg(name="requets", popular_package_similarity=0.90)
        result = scorer().score(pkg)
        finding = next(f for f in result.findings if f.check_id == "SCR-004")
        assert finding.severity == SEVERITY_CRITICAL

    def test_similarity_0_90_weight(self):
        pkg = make_safe_pkg(name="requets", popular_package_similarity=0.90)
        result = scorer().score(pkg)
        assert result.risk_score == _CHECK_WEIGHTS["SCR-004"]

    def test_similarity_1_0_triggers(self):
        pkg = make_safe_pkg(name="requets", popular_package_similarity=1.0)
        result = scorer().score(pkg)
        assert "SCR-004" in check_ids(result)


# ===========================================================================
# 6. SCR-005 — No source repository URL
# ===========================================================================

class TestSCR005:
    def test_source_repo_none_triggers(self):
        pkg = make_safe_pkg(source_repo_url=None)
        result = scorer().score(pkg)
        assert "SCR-005" in check_ids(result)

    def test_source_repo_empty_string_triggers(self):
        pkg = make_safe_pkg(source_repo_url="")
        result = scorer().score(pkg)
        assert "SCR-005" in check_ids(result)

    def test_source_repo_set_does_not_trigger(self):
        pkg = make_safe_pkg(source_repo_url="https://github.com/psf/requests")
        result = scorer().score(pkg)
        assert "SCR-005" not in check_ids(result)

    def test_source_repo_none_severity_high(self):
        pkg = make_safe_pkg(source_repo_url=None)
        result = scorer().score(pkg)
        finding = next(f for f in result.findings if f.check_id == "SCR-005")
        assert finding.severity == SEVERITY_HIGH

    def test_source_repo_none_weight(self):
        pkg = make_safe_pkg(source_repo_url=None)
        result = scorer().score(pkg)
        assert result.risk_score == _CHECK_WEIGHTS["SCR-005"]


# ===========================================================================
# 7. SCR-006 — Wildcard / unpinned version constraint
# ===========================================================================

class TestSCR006:
    def test_wildcard_star_triggers(self):
        pkg = make_safe_pkg(version_constraint="*")
        result = scorer().score(pkg)
        assert "SCR-006" in check_ids(result)

    def test_latest_triggers(self):
        pkg = make_safe_pkg(version_constraint="latest")
        result = scorer().score(pkg)
        assert "SCR-006" in check_ids(result)

    def test_caret_triggers(self):
        pkg = make_safe_pkg(version_constraint="^1.2.3")
        result = scorer().score(pkg)
        assert "SCR-006" in check_ids(result)

    def test_tilde_triggers(self):
        pkg = make_safe_pkg(version_constraint="~1.2")
        result = scorer().score(pkg)
        assert "SCR-006" in check_ids(result)

    def test_gte_without_upper_bound_triggers(self):
        pkg = make_safe_pkg(version_constraint=">=1.0")
        result = scorer().score(pkg)
        assert "SCR-006" in check_ids(result)

    def test_gte_with_upper_bound_does_not_trigger(self):
        pkg = make_safe_pkg(version_constraint=">=1.0,<2.0")
        result = scorer().score(pkg)
        assert "SCR-006" not in check_ids(result)

    def test_exact_version_does_not_trigger(self):
        pkg = make_safe_pkg(version_constraint="1.2.3")
        result = scorer().score(pkg)
        assert "SCR-006" not in check_ids(result)

    def test_none_constraint_does_not_trigger(self):
        pkg = make_safe_pkg(version_constraint=None)
        result = scorer().score(pkg)
        assert "SCR-006" not in check_ids(result)

    def test_wildcard_severity_high(self):
        pkg = make_safe_pkg(version_constraint="*")
        result = scorer().score(pkg)
        finding = next(f for f in result.findings if f.check_id == "SCR-006")
        assert finding.severity == SEVERITY_HIGH

    def test_wildcard_weight(self):
        pkg = make_safe_pkg(version_constraint="*")
        result = scorer().score(pkg)
        assert result.risk_score == _CHECK_WEIGHTS["SCR-006"]

    def test_empty_string_constraint_triggers(self):
        pkg = make_safe_pkg(version_constraint="  ")  # whitespace-only strips to ""
        result = scorer().score(pkg)
        assert "SCR-006" in check_ids(result)

    def test_gte_lte_upper_bound_does_not_trigger(self):
        # ">=1.0,<=2.0" contains "<" (via "<=") — should NOT trigger
        pkg = make_safe_pkg(version_constraint=">=1.0,<=2.0")
        result = scorer().score(pkg)
        assert "SCR-006" not in check_ids(result)


# ===========================================================================
# 8. SCR-007 — Suspicious npm scope / namespace
# ===========================================================================

class TestSCR007:
    def test_npm_short_scope_single_char_triggers(self):
        # "@x" has len=2 ≤ 4
        pkg = make_safe_pkg(
            ecosystem="npm", scope="@x", name="@x/utils", version_constraint="1.0.0"
        )
        result = scorer().score(pkg)
        assert "SCR-007" in check_ids(result)

    def test_npm_short_scope_two_chars_triggers(self):
        # "@ab" has len=3 ≤ 4
        pkg = make_safe_pkg(
            ecosystem="npm", scope="@ab", name="@ab/lib", version_constraint="1.0.0"
        )
        result = scorer().score(pkg)
        assert "SCR-007" in check_ids(result)

    def test_npm_short_scope_three_chars_triggers(self):
        # "@abc" has len=4 ≤ 4
        pkg = make_safe_pkg(
            ecosystem="npm", scope="@abc", name="@abc/core", version_constraint="1.0.0"
        )
        result = scorer().score(pkg)
        assert "SCR-007" in check_ids(result)

    def test_npm_trusted_angular_does_not_trigger(self):
        pkg = make_safe_pkg(
            ecosystem="npm", scope="@angular", name="@angular/core", version_constraint="16.0.0"
        )
        result = scorer().score(pkg)
        assert "SCR-007" not in check_ids(result)

    def test_npm_trusted_babel_does_not_trigger(self):
        pkg = make_safe_pkg(
            ecosystem="npm", scope="@babel", name="@babel/core", version_constraint="7.0.0"
        )
        result = scorer().score(pkg)
        assert "SCR-007" not in check_ids(result)

    def test_npm_trusted_types_does_not_trigger(self):
        pkg = make_safe_pkg(
            ecosystem="npm", scope="@types", name="@types/node", version_constraint="18.0.0"
        )
        result = scorer().score(pkg)
        assert "SCR-007" not in check_ids(result)

    def test_npm_trusted_aws_sdk_does_not_trigger(self):
        pkg = make_safe_pkg(
            ecosystem="npm", scope="@aws-sdk", name="@aws-sdk/client-s3", version_constraint="3.0.0"
        )
        result = scorer().score(pkg)
        assert "SCR-007" not in check_ids(result)

    def test_non_npm_does_not_trigger(self):
        pkg = make_safe_pkg(
            ecosystem="pypi", scope="@company", name="company-utils", version_constraint="1.0.0"
        )
        result = scorer().score(pkg)
        assert "SCR-007" not in check_ids(result)

    def test_npm_scope_none_does_not_trigger(self):
        pkg = make_safe_pkg(
            ecosystem="npm", scope=None, name="lodash", version_constraint="4.17.21"
        )
        result = scorer().score(pkg)
        assert "SCR-007" not in check_ids(result)

    def test_npm_untrusted_long_scope_triggers(self):
        # "@mycompany" is long but NOT in trusted list → should trigger
        pkg = make_safe_pkg(
            ecosystem="npm", scope="@mycompany", name="@mycompany/tool", version_constraint="1.0.0"
        )
        result = scorer().score(pkg)
        assert "SCR-007" in check_ids(result)

    def test_npm_scr007_severity_medium(self):
        pkg = make_safe_pkg(
            ecosystem="npm", scope="@x", name="@x/utils", version_constraint="1.0.0"
        )
        result = scorer().score(pkg)
        finding = next(f for f in result.findings if f.check_id == "SCR-007")
        assert finding.severity == SEVERITY_MEDIUM


# ===========================================================================
# 9. Multiple checks firing on the same package
# ===========================================================================

class TestMultipleChecks:
    def test_scr002_and_scr005_together(self):
        pkg = make_safe_pkg(author_count=1, source_repo_url=None)
        result = scorer().score(pkg)
        ids = check_ids(result)
        assert "SCR-002" in ids
        assert "SCR-005" in ids

    def test_scr002_and_scr005_score_is_sum(self):
        pkg = make_safe_pkg(author_count=1, source_repo_url=None)
        result = scorer().score(pkg)
        expected = _CHECK_WEIGHTS["SCR-002"] + _CHECK_WEIGHTS["SCR-005"]
        assert result.risk_score == expected

    def test_all_seven_checks_fire(self):
        """Construct a package that triggers every single check."""
        pkg = PackageInfo(
            name="reqeusts",              # near "requests" — SCR-004
            version="0.0.1",
            ecosystem="npm",
            published_at=ONE_DAY_AGO,    # SCR-001
            author_count=1,              # SCR-002
            star_count=5,                # SCR-003
            source_repo_url=None,        # SCR-005
            scope="@xy",                 # SCR-007 (short, untrusted)
            version_constraint="*",      # SCR-006
            popular_package_similarity=0.95,  # SCR-004
        )
        result = scorer().score(pkg)
        ids = check_ids(result)
        for check in ["SCR-001", "SCR-002", "SCR-003", "SCR-004", "SCR-005", "SCR-006", "SCR-007"]:
            assert check in ids, f"{check} did not fire"

    def test_score_many_multiple_packages(self):
        pkgs = [
            make_safe_pkg(name="pkg-a"),
            make_safe_pkg(name="pkg-b", author_count=1),
        ]
        results = scorer().score_many(pkgs)
        assert len(results) == 2
        assert results[0].package_name == "pkg-a"
        assert results[1].package_name == "pkg-b"
        assert "SCR-002" in check_ids(results[1])

    def test_scr001_and_scr003_score_is_sum(self):
        pkg = make_safe_pkg(published_at=ONE_DAY_AGO, star_count=10)
        result = scorer().score(pkg)
        expected = _CHECK_WEIGHTS["SCR-001"] + _CHECK_WEIGHTS["SCR-003"]
        assert result.risk_score == expected


# ===========================================================================
# 10. Risk score cap at 100
# ===========================================================================

class TestRiskScoreCap:
    def test_score_capped_at_100(self):
        """All 7 checks firing: 15+15+5+45+20+20+15 = 135 → capped at 100."""
        pkg = PackageInfo(
            name="reqeusts",
            version="0.0.1",
            ecosystem="npm",
            published_at=ONE_DAY_AGO,
            author_count=1,
            star_count=5,
            source_repo_url=None,
            scope="@xy",
            version_constraint="*",
            popular_package_similarity=0.95,
        )
        result = scorer().score(pkg)
        assert result.risk_score == 100

    def test_score_never_exceeds_100(self):
        pkg = make_safe_pkg(
            published_at=ONE_DAY_AGO,
            author_count=1,
            star_count=5,
            source_repo_url=None,
            version_constraint="*",
            popular_package_similarity=0.95,
        )
        result = scorer().score(pkg)
        assert result.risk_score <= 100

    def test_score_min_zero(self):
        result = scorer().score(make_safe_pkg())
        assert result.risk_score >= 0


# ===========================================================================
# 11. by_severity() structure
# ===========================================================================

class TestBySeverity:
    def test_by_severity_has_all_keys(self):
        result = scorer().score(make_safe_pkg())
        by_sev = result.by_severity()
        assert set(by_sev.keys()) == {SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW}

    def test_by_severity_critical_populated(self):
        pkg = make_safe_pkg(name="reqeusts", popular_package_similarity=0.95)
        result = scorer().score(pkg)
        by_sev = result.by_severity()
        assert len(by_sev[SEVERITY_CRITICAL]) == 1
        assert by_sev[SEVERITY_CRITICAL][0].check_id == "SCR-004"

    def test_by_severity_high_populated(self):
        pkg = make_safe_pkg(source_repo_url=None)
        result = scorer().score(pkg)
        by_sev = result.by_severity()
        assert any(f.check_id == "SCR-005" for f in by_sev[SEVERITY_HIGH])

    def test_by_severity_medium_populated(self):
        pkg = make_safe_pkg(author_count=1)
        result = scorer().score(pkg)
        by_sev = result.by_severity()
        assert any(f.check_id == "SCR-002" for f in by_sev[SEVERITY_MEDIUM])

    def test_by_severity_low_populated(self):
        pkg = make_safe_pkg(star_count=5)
        result = scorer().score(pkg)
        by_sev = result.by_severity()
        assert any(f.check_id == "SCR-003" for f in by_sev[SEVERITY_LOW])

    def test_by_severity_empty_buckets_are_lists(self):
        result = scorer().score(make_safe_pkg(source_repo_url=None))
        by_sev = result.by_severity()
        assert isinstance(by_sev[SEVERITY_LOW], list)
        assert isinstance(by_sev[SEVERITY_CRITICAL], list)


# ===========================================================================
# 12. summary() format
# ===========================================================================

class TestSummary:
    def test_summary_contains_package_name(self):
        result = scorer().score(make_safe_pkg(name="mylib"))
        assert "mylib" in result.summary()

    def test_summary_contains_version(self):
        result = scorer().score(make_safe_pkg(version="9.9.9"))
        assert "9.9.9" in result.summary()

    def test_summary_contains_ecosystem(self):
        result = scorer().score(make_safe_pkg(ecosystem="npm"))
        assert "npm" in result.summary()

    def test_summary_contains_risk_score(self):
        result = scorer().score(make_safe_pkg())
        assert "risk_score=0" in result.summary()

    def test_summary_with_finding_mentions_count(self):
        pkg = make_safe_pkg(author_count=1)
        result = scorer().score(pkg)
        assert "1 finding" in result.summary()

    def test_summary_mentions_severity_when_findings_exist(self):
        pkg = make_safe_pkg(author_count=1)
        result = scorer().score(pkg)
        assert SEVERITY_MEDIUM in result.summary()

    def test_summary_no_findings_string(self):
        result = scorer().score(make_safe_pkg())
        assert "No findings" in result.summary()


# ===========================================================================
# 13. score_many()
# ===========================================================================

class TestScoreMany:
    def test_returns_list(self):
        results = scorer().score_many([make_safe_pkg()])
        assert isinstance(results, list)

    def test_returns_correct_count(self):
        pkgs = [make_safe_pkg(name=f"pkg-{i}") for i in range(5)]
        results = scorer().score_many(pkgs)
        assert len(results) == 5

    def test_empty_list_returns_empty(self):
        results = scorer().score_many([])
        assert results == []

    def test_preserves_order(self):
        pkgs = [make_safe_pkg(name=f"pkg-{i}") for i in range(3)]
        results = scorer().score_many(pkgs)
        names = [r.package_name for r in results]
        assert names == ["pkg-0", "pkg-1", "pkg-2"]

    def test_each_result_is_supply_chain_risk_result(self):
        results = scorer().score_many([make_safe_pkg()])
        assert isinstance(results[0], SupplyChainRiskResult)


# ===========================================================================
# 14. to_dict() — all dataclasses
# ===========================================================================

class TestToDict:
    # PackageInfo
    def test_package_info_to_dict_keys(self):
        pkg = make_safe_pkg()
        d = pkg.to_dict()
        expected_keys = {
            "name", "version", "ecosystem", "published_at", "author_count",
            "star_count", "source_repo_url", "scope", "version_constraint",
            "popular_package_similarity",
        }
        assert set(d.keys()) == expected_keys

    def test_package_info_to_dict_values(self):
        pkg = make_safe_pkg(name="lodash", version="4.17.21", ecosystem="npm")
        d = pkg.to_dict()
        assert d["name"] == "lodash"
        assert d["version"] == "4.17.21"
        assert d["ecosystem"] == "npm"

    def test_package_info_to_dict_none_fields(self):
        pkg = make_safe_pkg(published_at=None, scope=None)
        d = pkg.to_dict()
        assert d["published_at"] is None
        assert d["scope"] is None

    # SupplyChainFinding
    def test_finding_to_dict_keys(self):
        pkg = make_safe_pkg(author_count=1)
        result = scorer().score(pkg)
        finding = result.findings[0]
        d = finding.to_dict()
        expected_keys = {
            "check_id", "severity", "package_name", "package_version",
            "ecosystem", "message", "recommendation",
        }
        assert set(d.keys()) == expected_keys

    def test_finding_to_dict_values(self):
        pkg = make_safe_pkg(author_count=1, name="mypkg", version="1.0.0", ecosystem="pypi")
        result = scorer().score(pkg)
        finding = next(f for f in result.findings if f.check_id == "SCR-002")
        d = finding.to_dict()
        assert d["check_id"] == "SCR-002"
        assert d["package_name"] == "mypkg"
        assert d["package_version"] == "1.0.0"
        assert d["ecosystem"] == "pypi"
        assert d["severity"] == SEVERITY_MEDIUM

    # SupplyChainRiskResult
    def test_result_to_dict_keys(self):
        result = scorer().score(make_safe_pkg())
        d = result.to_dict()
        expected_keys = {
            "package_name", "package_version", "ecosystem",
            "risk_score", "findings",
        }
        assert set(d.keys()) == expected_keys

    def test_result_to_dict_findings_is_list(self):
        result = scorer().score(make_safe_pkg())
        d = result.to_dict()
        assert isinstance(d["findings"], list)

    def test_result_to_dict_findings_serialized(self):
        pkg = make_safe_pkg(author_count=1)
        result = scorer().score(pkg)
        d = result.to_dict()
        assert len(d["findings"]) == 1
        assert d["findings"][0]["check_id"] == "SCR-002"

    def test_result_to_dict_risk_score_int(self):
        result = scorer().score(make_safe_pkg())
        d = result.to_dict()
        assert isinstance(d["risk_score"], int)


# ===========================================================================
# 15. Edge cases and miscellaneous
# ===========================================================================

class TestEdgeCases:
    def test_check_weights_dict_has_all_seven_ids(self):
        for cid in ["SCR-001", "SCR-002", "SCR-003", "SCR-004", "SCR-005", "SCR-006", "SCR-007"]:
            assert cid in _CHECK_WEIGHTS

    def test_scorer_default_params(self):
        s = SupplyChainRiskScorer()
        assert s.max_new_package_days == 30
        assert s.min_stars == 100

    def test_scorer_custom_params(self):
        s = SupplyChainRiskScorer(max_new_package_days=7, min_stars=500)
        assert s.max_new_package_days == 7
        assert s.min_stars == 500

    def test_finding_fields_populated(self):
        pkg = make_safe_pkg(source_repo_url=None)
        result = scorer().score(pkg)
        f = next(x for x in result.findings if x.check_id == "SCR-005")
        assert f.package_name == pkg.name
        assert f.package_version == pkg.version
        assert f.ecosystem == pkg.ecosystem
        assert f.message != ""
        assert f.recommendation != ""

    def test_result_package_name_matches(self):
        pkg = make_safe_pkg(name="special-lib")
        result = scorer().score(pkg)
        assert result.package_name == "special-lib"

    def test_result_ecosystem_matches(self):
        pkg = make_safe_pkg(ecosystem="maven")
        result = scorer().score(pkg)
        assert result.ecosystem == "maven"

    def test_same_check_id_not_duplicated_in_findings(self):
        """A single check should produce at most one finding per package."""
        pkg = make_safe_pkg(version_constraint="*")
        result = scorer().score(pkg)
        scr006_findings = [f for f in result.findings if f.check_id == "SCR-006"]
        assert len(scr006_findings) == 1

    def test_score_many_single_element(self):
        results = scorer().score_many([make_safe_pkg()])
        assert len(results) == 1

    def test_findings_are_supply_chain_finding_instances(self):
        pkg = make_safe_pkg(author_count=1)
        result = scorer().score(pkg)
        for finding in result.findings:
            assert isinstance(finding, SupplyChainFinding)

    def test_scr006_caret_zero_version_triggers(self):
        pkg = make_safe_pkg(version_constraint="^0.0.1")
        result = scorer().score(pkg)
        assert "SCR-006" in check_ids(result)

    def test_scr001_and_scr006_together(self):
        pkg = make_safe_pkg(published_at=ONE_DAY_AGO, version_constraint="^1.0.0")
        result = scorer().score(pkg)
        ids = check_ids(result)
        assert "SCR-001" in ids
        assert "SCR-006" in ids

    def test_scr004_and_scr005_together_score(self):
        pkg = make_safe_pkg(
            name="reqeusts",
            popular_package_similarity=0.95,
            source_repo_url=None,
        )
        result = scorer().score(pkg)
        expected = min(100, _CHECK_WEIGHTS["SCR-004"] + _CHECK_WEIGHTS["SCR-005"])
        assert result.risk_score == expected
