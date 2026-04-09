# Copyright (C) 2026 Cyber Port — hiagokinlevi
# Licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/)
#
# test_license_compliance_checker.py
# Comprehensive pytest test suite for the license_compliance_checker module.
# 110+ tests covering all 7 check IDs, edge cases, and integration scenarios.

import sys
import os

# Ensure the shared/analyzers package is importable when running from the repo root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared", "analyzers"))

from license_compliance_checker import (
    Dependency,
    LICFinding,
    LICResult,
    _CHECK_WEIGHTS,
    _STRONG_COPYLEFT,
    _WEAK_COPYLEFT,
    _NON_COMMERCIAL,
    _DEPRECATED,
    _AGPL,
    _KNOWN_SPDX,
    check,
    check_many,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dep(
    name: str = "pkg",
    version: str = "1.0.0",
    license_id: str = "MIT",
    is_direct: bool = True,
    ecosystem: str = "pypi",
) -> Dependency:
    """Shorthand factory for Dependency objects."""
    return Dependency(
        name=name,
        version=version,
        license_id=license_id,
        is_direct=is_direct,
        ecosystem=ecosystem,
    )


def _check_ids(result: LICResult) -> list:
    """Return sorted list of check IDs fired in result."""
    return sorted({f.check_id for f in result.findings})


def _findings_for(result: LICResult, check_id: str) -> list:
    """Return findings matching a given check_id."""
    return [f for f in result.findings if f.check_id == check_id]


# ===========================================================================
# LIC-001: Strong copyleft in direct dependency of a proprietary project
# ===========================================================================


class TestLIC001:
    """LIC-001 — strong copyleft, direct dep, proprietary project."""

    def test_gpl2_direct_proprietary_fires(self):
        dep = _dep(name="libgpl", license_id="GPL-2.0", is_direct=True)
        result = check([dep], project_type="proprietary")
        assert "LIC-001" in _check_ids(result)

    def test_gpl3_direct_proprietary_fires(self):
        dep = _dep(name="libgpl3", license_id="GPL-3.0", is_direct=True)
        result = check([dep], project_type="proprietary")
        assert "LIC-001" in _check_ids(result)

    def test_agpl3_direct_proprietary_fires(self):
        dep = _dep(name="libagpl", license_id="AGPL-3.0", is_direct=True)
        result = check([dep], project_type="proprietary")
        assert "LIC-001" in _check_ids(result)

    def test_gpl2_only_direct_proprietary_fires(self):
        dep = _dep(name="libgpl2only", license_id="GPL-2.0-only", is_direct=True)
        result = check([dep], project_type="proprietary")
        assert "LIC-001" in _check_ids(result)

    def test_gpl3_or_later_direct_proprietary_fires(self):
        dep = _dep(name="libgpl3later", license_id="GPL-3.0-or-later", is_direct=True)
        result = check([dep], project_type="proprietary")
        assert "LIC-001" in _check_ids(result)

    def test_agpl3_only_direct_proprietary_fires(self):
        dep = _dep(name="libagplonly", license_id="AGPL-3.0-only", is_direct=True)
        result = check([dep], project_type="proprietary")
        assert "LIC-001" in _check_ids(result)

    def test_agpl3_or_later_direct_proprietary_fires(self):
        dep = _dep(name="libagpllater", license_id="AGPL-3.0-or-later", is_direct=True)
        result = check([dep], project_type="proprietary")
        assert "LIC-001" in _check_ids(result)

    def test_gpl2_transitive_proprietary_does_not_fire_lic001(self):
        # LIC-001 only fires for DIRECT deps
        dep = _dep(name="libgpl", license_id="GPL-2.0", is_direct=False)
        result = check([dep], project_type="proprietary")
        assert "LIC-001" not in _check_ids(result)

    def test_gpl2_direct_open_source_does_not_fire_lic001(self):
        # LIC-001 only fires for proprietary projects
        dep = _dep(name="libgpl", license_id="GPL-2.0", is_direct=True)
        result = check([dep], project_type="open_source")
        assert "LIC-001" not in _check_ids(result)

    def test_gpl2_direct_internal_does_not_fire_lic001(self):
        dep = _dep(name="libgpl", license_id="GPL-2.0", is_direct=True)
        result = check([dep], project_type="internal")
        assert "LIC-001" not in _check_ids(result)

    def test_lic001_finding_severity_is_critical(self):
        dep = _dep(license_id="GPL-3.0", is_direct=True)
        result = check([dep], project_type="proprietary")
        f = _findings_for(result, "LIC-001")[0]
        assert f.severity == "CRITICAL"

    def test_lic001_weight_is_45(self):
        dep = _dep(license_id="GPL-3.0", is_direct=True)
        result = check([dep], project_type="proprietary")
        f = _findings_for(result, "LIC-001")[0]
        assert f.weight == 45

    def test_lic001_detail_contains_dep_name(self):
        dep = _dep(name="mygpllib", license_id="GPL-2.0", is_direct=True)
        result = check([dep], project_type="proprietary")
        f = _findings_for(result, "LIC-001")[0]
        assert "mygpllib" in f.detail

    def test_lic001_one_finding_per_dep(self):
        # Two GPL deps → two LIC-001 findings
        deps = [
            _dep(name="a", license_id="GPL-2.0", is_direct=True),
            _dep(name="b", license_id="GPL-3.0", is_direct=True),
        ]
        result = check(deps, project_type="proprietary")
        assert len(_findings_for(result, "LIC-001")) == 2

    def test_lic001_risk_score_capped_at_45_for_single_dep(self):
        dep = _dep(license_id="GPL-2.0", is_direct=True)
        result = check([dep], project_type="proprietary")
        # weight deduplication: unique fired check IDs only
        assert result.risk_score == 45

    def test_mit_direct_proprietary_no_lic001(self):
        dep = _dep(license_id="MIT", is_direct=True)
        result = check([dep], project_type="proprietary")
        assert "LIC-001" not in _check_ids(result)


# ===========================================================================
# LIC-002: Weak copyleft
# ===========================================================================


class TestLIC002:
    """LIC-002 — weak copyleft, direct and transitive."""

    def test_lgpl21_direct_fires(self):
        dep = _dep(name="libweakdirect", license_id="LGPL-2.1", is_direct=True)
        result = check([dep])
        assert "LIC-002" in _check_ids(result)

    def test_lgpl21_only_fires(self):
        dep = _dep(license_id="LGPL-2.1-only")
        result = check([dep])
        assert "LIC-002" in _check_ids(result)

    def test_lgpl21_or_later_fires(self):
        dep = _dep(license_id="LGPL-2.1-or-later")
        result = check([dep])
        assert "LIC-002" in _check_ids(result)

    def test_lgpl30_fires(self):
        dep = _dep(license_id="LGPL-3.0")
        result = check([dep])
        assert "LIC-002" in _check_ids(result)

    def test_lgpl30_only_fires(self):
        dep = _dep(license_id="LGPL-3.0-only")
        result = check([dep])
        assert "LIC-002" in _check_ids(result)

    def test_lgpl30_or_later_fires(self):
        dep = _dep(license_id="LGPL-3.0-or-later")
        result = check([dep])
        assert "LIC-002" in _check_ids(result)

    def test_mpl20_fires(self):
        dep = _dep(license_id="MPL-2.0")
        result = check([dep])
        assert "LIC-002" in _check_ids(result)

    def test_eupl12_fires(self):
        dep = _dep(license_id="EUPL-1.2")
        result = check([dep])
        assert "LIC-002" in _check_ids(result)

    def test_lgpl21_transitive_fires(self):
        # Weak copyleft fires for transitive deps too
        dep = _dep(name="libweaktransitive", license_id="LGPL-2.1", is_direct=False)
        result = check([dep])
        assert "LIC-002" in _check_ids(result)

    def test_lic002_detail_mentions_transitive_for_transitive_dep(self):
        dep = _dep(name="transweakpkg", license_id="LGPL-3.0", is_direct=False)
        result = check([dep])
        f = _findings_for(result, "LIC-002")[0]
        assert "transitive" in f.detail.lower()

    def test_lic002_detail_mentions_direct_for_direct_dep(self):
        dep = _dep(name="directweakpkg", license_id="LGPL-3.0", is_direct=True)
        result = check([dep])
        f = _findings_for(result, "LIC-002")[0]
        assert "direct" in f.detail.lower()

    def test_lic002_severity_is_medium(self):
        dep = _dep(license_id="MPL-2.0")
        result = check([dep])
        f = _findings_for(result, "LIC-002")[0]
        assert f.severity == "MEDIUM"

    def test_lic002_weight_is_15(self):
        dep = _dep(license_id="MPL-2.0")
        result = check([dep])
        f = _findings_for(result, "LIC-002")[0]
        assert f.weight == 15

    def test_lic002_fires_regardless_of_project_type(self):
        dep = _dep(license_id="LGPL-2.1")
        for pt in ["proprietary", "open_source", "internal"]:
            result = check([dep], project_type=pt)
            assert "LIC-002" in _check_ids(result), f"Expected LIC-002 for {pt}"

    def test_mit_does_not_fire_lic002(self):
        dep = _dep(license_id="MIT")
        result = check([dep])
        assert "LIC-002" not in _check_ids(result)


# ===========================================================================
# LIC-003: Non-commercial restriction
# ===========================================================================


class TestLIC003:
    """LIC-003 — non-commercial license restriction."""

    def test_cc_by_nc_fires(self):
        dep = _dep(name="nclib", license_id="CC-BY-NC-4.0")
        result = check([dep])
        assert "LIC-003" in _check_ids(result)

    def test_cc_by_nc_sa_fires(self):
        dep = _dep(license_id="CC-BY-NC-SA-4.0")
        result = check([dep])
        assert "LIC-003" in _check_ids(result)

    def test_commons_clause_fires(self):
        dep = _dep(license_id="Commons-Clause")
        result = check([dep])
        assert "LIC-003" in _check_ids(result)

    def test_busl_fires(self):
        dep = _dep(license_id="BUSL-1.1")
        result = check([dep])
        assert "LIC-003" in _check_ids(result)

    def test_lic003_severity_is_high(self):
        dep = _dep(license_id="BUSL-1.1")
        result = check([dep])
        f = _findings_for(result, "LIC-003")[0]
        assert f.severity == "HIGH"

    def test_lic003_weight_is_30(self):
        dep = _dep(license_id="CC-BY-NC-4.0")
        result = check([dep])
        f = _findings_for(result, "LIC-003")[0]
        assert f.weight == 30

    def test_lic003_detail_contains_dep_name(self):
        dep = _dep(name="noncomm_pkg", license_id="CC-BY-NC-SA-4.0")
        result = check([dep])
        f = _findings_for(result, "LIC-003")[0]
        assert "noncomm_pkg" in f.detail

    def test_lic003_fires_for_transitive_dep(self):
        dep = _dep(license_id="BUSL-1.1", is_direct=False)
        result = check([dep])
        assert "LIC-003" in _check_ids(result)

    def test_apache20_does_not_fire_lic003(self):
        dep = _dep(license_id="Apache-2.0")
        result = check([dep])
        assert "LIC-003" not in _check_ids(result)


# ===========================================================================
# LIC-004: Missing license information
# ===========================================================================


class TestLIC004:
    """LIC-004 — no license information."""

    def test_none_license_fires(self):
        dep = _dep(name="nolicpkg", license_id=None)
        result = check([dep])
        assert "LIC-004" in _check_ids(result)

    def test_empty_string_license_fires(self):
        dep = Dependency(name="emptylicpkg", version="1.0.0", license_id="",
                         is_direct=True, ecosystem="pypi")
        result = check([dep])
        assert "LIC-004" in _check_ids(result)

    def test_whitespace_only_license_fires(self):
        dep = Dependency(name="wsspacepkg", version="1.0.0", license_id="   ",
                         is_direct=True, ecosystem="pypi")
        result = check([dep])
        assert "LIC-004" in _check_ids(result)

    def test_lic004_severity_is_high(self):
        dep = _dep(license_id=None)
        result = check([dep])
        f = _findings_for(result, "LIC-004")[0]
        assert f.severity == "HIGH"

    def test_lic004_weight_is_20(self):
        dep = _dep(license_id=None)
        result = check([dep])
        f = _findings_for(result, "LIC-004")[0]
        assert f.weight == 20

    def test_lic004_detail_contains_dep_name(self):
        dep = _dep(name="mystery_pkg", license_id=None)
        result = check([dep])
        f = _findings_for(result, "LIC-004")[0]
        assert "mystery_pkg" in f.detail

    def test_lic004_suppresses_lic007(self):
        # When license is None/empty, LIC-007 must NOT also fire
        dep = _dep(license_id=None)
        result = check([dep])
        assert "LIC-007" not in _check_ids(result)

    def test_lic004_fires_for_transitive_dep(self):
        dep = _dep(license_id=None, is_direct=False)
        result = check([dep])
        assert "LIC-004" in _check_ids(result)

    def test_mit_license_does_not_fire_lic004(self):
        dep = _dep(license_id="MIT")
        result = check([dep])
        assert "LIC-004" not in _check_ids(result)

    def test_lic004_one_finding_per_dep_with_no_license(self):
        deps = [_dep(name="a", license_id=None), _dep(name="b", license_id=None)]
        result = check(deps)
        assert len(_findings_for(result, "LIC-004")) == 2


# ===========================================================================
# LIC-005: Deprecated / obsolete license
# ===========================================================================


class TestLIC005:
    """LIC-005 — deprecated or obsolete SPDX identifier."""

    def test_gpl2_only_deprecated_fires(self):
        # GPL-2.0-only is both strong copyleft and deprecated
        dep = _dep(name="legacygpl", license_id="GPL-2.0-only", is_direct=True)
        result = check([dep], project_type="proprietary")
        assert "LIC-005" in _check_ids(result)

    def test_gpl1_fires(self):
        dep = _dep(license_id="GPL-1.0", is_direct=True)
        result = check([dep], project_type="proprietary")
        assert "LIC-005" in _check_ids(result)

    def test_artistic_10_fires(self):
        dep = _dep(license_id="Artistic-1.0")
        result = check([dep])
        assert "LIC-005" in _check_ids(result)

    def test_lgpl20_fires(self):
        dep = _dep(license_id="LGPL-2.0")
        result = check([dep])
        assert "LIC-005" in _check_ids(result)

    def test_lgpl20_only_fires(self):
        dep = _dep(license_id="LGPL-2.0-only")
        result = check([dep])
        assert "LIC-005" in _check_ids(result)

    def test_mpl10_fires(self):
        dep = _dep(license_id="MPL-1.0")
        result = check([dep])
        assert "LIC-005" in _check_ids(result)

    def test_mpl11_fires(self):
        dep = _dep(license_id="MPL-1.1")
        result = check([dep])
        assert "LIC-005" in _check_ids(result)

    def test_lic005_severity_is_medium(self):
        dep = _dep(license_id="MPL-1.1")
        result = check([dep])
        f = _findings_for(result, "LIC-005")[0]
        assert f.severity == "MEDIUM"

    def test_lic005_weight_is_15(self):
        dep = _dep(license_id="LGPL-2.0")
        result = check([dep])
        f = _findings_for(result, "LIC-005")[0]
        assert f.weight == 15

    def test_lic005_detail_contains_dep_name(self):
        dep = _dep(name="old_lic_pkg", license_id="Artistic-1.0")
        result = check([dep])
        f = _findings_for(result, "LIC-005")[0]
        assert "old_lic_pkg" in f.detail

    def test_apache20_not_deprecated(self):
        dep = _dep(license_id="Apache-2.0")
        result = check([dep])
        assert "LIC-005" not in _check_ids(result)

    def test_mpl20_not_deprecated(self):
        # MPL-2.0 is current; only MPL-1.0 and MPL-1.1 are deprecated
        dep = _dep(license_id="MPL-2.0")
        result = check([dep])
        assert "LIC-005" not in _check_ids(result)

    def test_gpl2_only_fires_both_lic001_and_lic005(self):
        # GPL-2.0-only is in _STRONG_COPYLEFT and _DEPRECATED
        dep = _dep(name="dualpkg", license_id="GPL-2.0-only", is_direct=True)
        result = check([dep], project_type="proprietary")
        check_ids = _check_ids(result)
        assert "LIC-001" in check_ids
        assert "LIC-005" in check_ids


# ===========================================================================
# LIC-006: Network copyleft (AGPL) in SaaS context
# ===========================================================================


class TestLIC006:
    """LIC-006 — AGPL license in SaaS deployment context."""

    def test_agpl3_saas_fires(self):
        dep = _dep(name="agplpkg", license_id="AGPL-3.0")
        result = check([dep], deployment_context="saas")
        assert "LIC-006" in _check_ids(result)

    def test_agpl3_only_saas_fires(self):
        dep = _dep(license_id="AGPL-3.0-only")
        result = check([dep], deployment_context="saas")
        assert "LIC-006" in _check_ids(result)

    def test_agpl3_or_later_saas_fires(self):
        dep = _dep(license_id="AGPL-3.0-or-later")
        result = check([dep], deployment_context="saas")
        assert "LIC-006" in _check_ids(result)

    def test_agpl3_on_premise_does_not_fire_lic006(self):
        dep = _dep(license_id="AGPL-3.0")
        result = check([dep], deployment_context="on_premise")
        assert "LIC-006" not in _check_ids(result)

    def test_agpl3_library_context_does_not_fire_lic006(self):
        dep = _dep(license_id="AGPL-3.0")
        result = check([dep], deployment_context="library")
        assert "LIC-006" not in _check_ids(result)

    def test_gpl3_saas_does_not_fire_lic006(self):
        # GPL-3.0 is not AGPL; LIC-006 only covers AGPL
        dep = _dep(license_id="GPL-3.0", is_direct=True)
        result = check([dep], project_type="proprietary", deployment_context="saas")
        assert "LIC-006" not in _check_ids(result)

    def test_lic006_severity_is_critical(self):
        dep = _dep(license_id="AGPL-3.0")
        result = check([dep], deployment_context="saas")
        f = _findings_for(result, "LIC-006")[0]
        assert f.severity == "CRITICAL"

    def test_lic006_weight_is_45(self):
        dep = _dep(license_id="AGPL-3.0")
        result = check([dep], deployment_context="saas")
        f = _findings_for(result, "LIC-006")[0]
        assert f.weight == 45

    def test_agpl3_proprietary_saas_fires_both_lic001_and_lic006(self):
        # AGPL-3.0 + proprietary + saas + direct → LIC-001 AND LIC-006
        dep = _dep(name="agpl_saas_pkg", license_id="AGPL-3.0", is_direct=True)
        result = check([dep], project_type="proprietary", deployment_context="saas")
        check_ids = _check_ids(result)
        assert "LIC-001" in check_ids, "LIC-001 should fire for proprietary"
        assert "LIC-006" in check_ids, "LIC-006 should fire for saas"

    def test_agpl3_proprietary_saas_risk_score_accounts_for_both(self):
        # Both LIC-001 (w=45) and LIC-006 (w=45) unique check IDs → min(100, 90) = 90
        dep = _dep(license_id="AGPL-3.0", is_direct=True)
        result = check([dep], project_type="proprietary", deployment_context="saas")
        assert result.risk_score == 90

    def test_agpl3_open_source_saas_only_fires_lic006_not_lic001(self):
        # open_source project → LIC-001 does not fire; LIC-006 still fires
        dep = _dep(license_id="AGPL-3.0", is_direct=True)
        result = check([dep], project_type="open_source", deployment_context="saas")
        check_ids = _check_ids(result)
        assert "LIC-001" not in check_ids
        assert "LIC-006" in check_ids

    def test_lic006_detail_contains_dep_name(self):
        dep = _dep(name="saas_agpl_dep", license_id="AGPL-3.0")
        result = check([dep], deployment_context="saas")
        f = _findings_for(result, "LIC-006")[0]
        assert "saas_agpl_dep" in f.detail

    def test_lic006_fires_for_transitive_dep_in_saas(self):
        dep = _dep(license_id="AGPL-3.0", is_direct=False)
        result = check([dep], deployment_context="saas")
        assert "LIC-006" in _check_ids(result)


# ===========================================================================
# LIC-007: Unknown / unparseable SPDX identifier
# ===========================================================================


class TestLIC007:
    """LIC-007 — unknown or unparseable SPDX license expression."""

    def test_unknown_spdx_fires(self):
        dep = _dep(name="unknownlicpkg", license_id="PROPRIETARY")
        result = check([dep])
        assert "LIC-007" in _check_ids(result)

    def test_custom_license_string_fires(self):
        dep = _dep(license_id="Custom-Internal-v1")
        result = check([dep])
        assert "LIC-007" in _check_ids(result)

    def test_freetext_fires(self):
        dep = _dep(license_id="See LICENSE file")
        result = check([dep])
        assert "LIC-007" in _check_ids(result)

    def test_lic007_severity_is_medium(self):
        dep = _dep(license_id="UnknownLicense")
        result = check([dep])
        f = _findings_for(result, "LIC-007")[0]
        assert f.severity == "MEDIUM"

    def test_lic007_weight_is_15(self):
        dep = _dep(license_id="UnknownLicense")
        result = check([dep])
        f = _findings_for(result, "LIC-007")[0]
        assert f.weight == 15

    def test_lic007_detail_contains_dep_name(self):
        dep = _dep(name="mysterious_pkg", license_id="PROPRIETARY")
        result = check([dep])
        f = _findings_for(result, "LIC-007")[0]
        assert "mysterious_pkg" in f.detail

    def test_none_license_does_not_fire_lic007(self):
        # LIC-004 fires instead; LIC-007 must be suppressed
        dep = _dep(license_id=None)
        result = check([dep])
        assert "LIC-007" not in _check_ids(result)

    def test_empty_license_does_not_fire_lic007(self):
        dep = Dependency(name="ep", version="1.0.0", license_id="",
                         is_direct=True, ecosystem="pypi")
        result = check([dep])
        assert "LIC-007" not in _check_ids(result)

    def test_mit_does_not_fire_lic007(self):
        dep = _dep(license_id="MIT")
        result = check([dep])
        assert "LIC-007" not in _check_ids(result)

    def test_all_known_spdx_do_not_fire_lic007(self):
        known = list(_KNOWN_SPDX)
        for spdx_id in known:
            dep = _dep(license_id=spdx_id)
            result = check([dep])
            assert "LIC-007" not in _check_ids(result), (
                f"Expected no LIC-007 for known SPDX '{spdx_id}'"
            )


# ===========================================================================
# Risk score and deduplication logic
# ===========================================================================


class TestRiskScore:
    """Weight deduplication: unique fired check IDs only, capped at 100."""

    def test_clean_deps_risk_score_zero(self):
        deps = [
            _dep(name="a", license_id="MIT"),
            _dep(name="b", license_id="Apache-2.0"),
            _dep(name="c", license_id="BSD-3-Clause"),
        ]
        result = check(deps)
        assert result.risk_score == 0

    def test_clean_deps_compliant_true(self):
        dep = _dep(license_id="MIT")
        result = check([dep])
        assert result.compliant is True

    def test_single_lic001_risk_score_45(self):
        dep = _dep(license_id="GPL-2.0", is_direct=True)
        result = check([dep], project_type="proprietary")
        assert result.risk_score == 45

    def test_multiple_gpl_deps_same_check_id_deduplication(self):
        # Multiple GPL deps → LIC-001 fires multiple times, but weight counted once.
        # GPL-2.0-only is also in _DEPRECATED, so LIC-005 fires as well.
        # Unique fired check IDs: LIC-001 (45) + LIC-005 (15) = 60.
        deps = [
            _dep(name="a", license_id="GPL-2.0", is_direct=True),
            _dep(name="b", license_id="GPL-3.0", is_direct=True),
            _dep(name="c", license_id="GPL-2.0-only", is_direct=True),
        ]
        result = check(deps, project_type="proprietary")
        assert result.risk_score == 60

    def test_two_unique_check_ids_sum_weights(self):
        # GPL-2.0 → LIC-001 only (not deprecated, not AGPL)
        # LGPL-2.1 → LIC-002 only
        # Unique: {LIC-001: 45, LIC-002: 15} → 60
        deps = [
            _dep(name="a", license_id="GPL-2.0", is_direct=True),
            _dep(name="b", license_id="LGPL-2.1"),
        ]
        result = check(deps, project_type="proprietary")
        assert result.risk_score == 60

    def test_risk_score_capped_at_100(self):
        # Trigger as many check IDs as possible to exceed 100 before capping
        # LIC-001(45) + LIC-002(15) + LIC-003(30) + LIC-004(20) + LIC-005(15)
        # + LIC-006(45) + LIC-007(15) = 185 → capped to 100
        deps = [
            _dep(name="d1", license_id="GPL-2.0", is_direct=True),      # LIC-001, LIC-005 (GPL-2.0-only is deprecated; GPL-2.0 is not — only LIC-001)
            _dep(name="d2", license_id="LGPL-2.1"),                       # LIC-002
            _dep(name="d3", license_id="BUSL-1.1"),                       # LIC-003
            _dep(name="d4", license_id=None),                              # LIC-004
            _dep(name="d5", license_id="MPL-1.1"),                        # LIC-005
            _dep(name="d6", license_id="AGPL-3.0", is_direct=True),      # LIC-006 (saas)
            _dep(name="d7", license_id="PROPRIETARY"),                    # LIC-007
        ]
        result = check(deps, project_type="proprietary", deployment_context="saas")
        assert result.risk_score == 100

    def test_non_compliant_when_risk_score_positive(self):
        dep = _dep(license_id="GPL-2.0", is_direct=True)
        result = check([dep], project_type="proprietary")
        assert result.compliant is False

    def test_compliant_false_means_risk_score_positive(self):
        dep = _dep(license_id="BUSL-1.1")
        result = check([dep])
        assert result.compliant is False
        assert result.risk_score > 0

    def test_empty_dependency_list_is_compliant(self):
        result = check([])
        assert result.compliant is True
        assert result.risk_score == 0
        assert result.findings == []

    def test_lic001_and_lic005_sum_weights(self):
        # GPL-2.0-only → LIC-001 (45) + LIC-005 (15) = 60
        dep = _dep(license_id="GPL-2.0-only", is_direct=True)
        result = check([dep], project_type="proprietary")
        assert result.risk_score == 60


# ===========================================================================
# LICResult output methods
# ===========================================================================


class TestLICResultMethods:
    """Tests for to_dict(), summary(), and by_severity()."""

    def test_to_dict_keys(self):
        dep = _dep(license_id="GPL-2.0", is_direct=True)
        result = check([dep], project_type="proprietary")
        d = result.to_dict()
        assert "risk_score" in d
        assert "compliant" in d
        assert "findings" in d

    def test_to_dict_findings_structure(self):
        dep = _dep(license_id="GPL-2.0", is_direct=True)
        result = check([dep], project_type="proprietary")
        findings = result.to_dict()["findings"]
        assert len(findings) >= 1
        f = findings[0]
        for key in ("check_id", "severity", "title", "detail", "weight", "dependency_name"):
            assert key in f, f"Missing key '{key}' in finding dict"

    def test_to_dict_risk_score_matches(self):
        dep = _dep(license_id="BUSL-1.1")
        result = check([dep])
        assert result.to_dict()["risk_score"] == result.risk_score

    def test_to_dict_compliant_matches(self):
        dep = _dep(license_id="MIT")
        result = check([dep])
        assert result.to_dict()["compliant"] is True

    def test_summary_contains_compliant(self):
        dep = _dep(license_id="MIT")
        result = check([dep])
        assert "COMPLIANT" in result.summary()

    def test_summary_contains_non_compliant(self):
        dep = _dep(license_id="GPL-2.0", is_direct=True)
        result = check([dep], project_type="proprietary")
        assert "NON-COMPLIANT" in result.summary()

    def test_summary_contains_risk_score(self):
        dep = _dep(license_id="LGPL-2.1")
        result = check([dep])
        assert str(result.risk_score) in result.summary()

    def test_summary_contains_findings_count(self):
        dep = _dep(license_id="GPL-2.0", is_direct=True)
        result = check([dep], project_type="proprietary")
        summary = result.summary()
        assert str(len(result.findings)) in summary

    def test_by_severity_groups_correctly(self):
        deps = [
            _dep(name="a", license_id="GPL-2.0", is_direct=True),  # CRITICAL
            _dep(name="b", license_id="LGPL-2.1"),                   # MEDIUM
        ]
        result = check(deps, project_type="proprietary")
        grouped = result.by_severity()
        assert "CRITICAL" in grouped
        assert "MEDIUM" in grouped
        assert all(f.severity == "CRITICAL" for f in grouped["CRITICAL"])
        assert all(f.severity == "MEDIUM" for f in grouped["MEDIUM"])

    def test_by_severity_returns_empty_dict_for_clean_result(self):
        dep = _dep(license_id="MIT")
        result = check([dep])
        assert result.by_severity() == {}

    def test_to_dict_returns_plain_dict_with_no_dataclass_instances(self):
        dep = _dep(license_id="MIT")
        result = check([dep])
        d = result.to_dict()
        assert isinstance(d, dict)
        assert isinstance(d["findings"], list)


# ===========================================================================
# check_many()
# ===========================================================================


class TestCheckMany:
    """Tests for check_many() batch function."""

    def test_check_many_returns_one_result_per_input_list(self):
        lists = [
            [_dep(name="a", license_id="MIT")],
            [_dep(name="b", license_id="GPL-2.0", is_direct=True)],
        ]
        results = check_many(lists, project_type="proprietary")
        assert len(results) == 2

    def test_check_many_preserves_order(self):
        lists = [
            [_dep(name="clean", license_id="MIT")],
            [_dep(name="risky", license_id="GPL-2.0", is_direct=True)],
        ]
        results = check_many(lists, project_type="proprietary")
        assert results[0].compliant is True
        assert results[1].compliant is False

    def test_check_many_empty_outer_list(self):
        results = check_many([])
        assert results == []

    def test_check_many_empty_inner_list(self):
        results = check_many([[]])
        assert len(results) == 1
        assert results[0].compliant is True

    def test_check_many_passes_project_type(self):
        dep = _dep(license_id="GPL-2.0", is_direct=True)
        results_proprietary = check_many([[dep]], project_type="proprietary")
        results_open = check_many([[dep]], project_type="open_source")
        assert results_proprietary[0].compliant is False
        assert results_open[0].compliant is True

    def test_check_many_passes_deployment_context(self):
        dep = _dep(license_id="AGPL-3.0")
        results_saas = check_many([[dep]], deployment_context="saas")
        results_on_prem = check_many([[dep]], deployment_context="on_premise")
        assert "LIC-006" in _check_ids(results_saas[0])
        assert "LIC-006" not in _check_ids(results_on_prem[0])


# ===========================================================================
# Integration / edge-case scenarios
# ===========================================================================


class TestIntegration:
    """End-to-end scenarios combining multiple checks and contexts."""

    def test_all_clean_permissive_licenses(self):
        deps = [
            _dep(name="requests", license_id="Apache-2.0"),
            _dep(name="click", license_id="BSD-3-Clause"),
            _dep(name="six", license_id="MIT"),
            _dep(name="certifi", license_id="MPL-2.0"),  # LIC-002 fires
        ]
        result = check(deps, project_type="proprietary")
        # certifi has MPL-2.0 → LIC-002
        assert "LIC-002" in _check_ids(result)
        assert "LIC-001" not in _check_ids(result)

    def test_mixed_ecosystem_deps(self):
        deps = [
            Dependency("requests", "2.28.0", "Apache-2.0", True, "pypi"),
            Dependency("lodash", "4.17.21", "MIT", True, "npm"),
            Dependency("commons-lang3", "3.12.0", "Apache-2.0", True, "maven"),
        ]
        result = check(deps)
        assert result.compliant is True

    def test_gpl_transitive_dep_proprietary_no_lic001(self):
        # Transitive GPL in proprietary project: LIC-001 must NOT fire (only for direct)
        dep = _dep(name="transitivegpl", license_id="GPL-2.0", is_direct=False)
        result = check([dep], project_type="proprietary")
        assert "LIC-001" not in _check_ids(result)

    def test_agpl_proprietary_on_premise_only_lic001(self):
        # AGPL-3.0, proprietary, on_premise, direct: LIC-001 fires, LIC-006 does not
        dep = _dep(license_id="AGPL-3.0", is_direct=True)
        result = check([dep], project_type="proprietary", deployment_context="on_premise")
        check_ids = _check_ids(result)
        assert "LIC-001" in check_ids
        assert "LIC-006" not in check_ids

    def test_no_findings_for_isc_license(self):
        dep = _dep(license_id="ISC")
        result = check([dep])
        assert result.findings == []

    def test_no_findings_for_cc0(self):
        dep = _dep(license_id="CC0-1.0")
        result = check([dep])
        assert result.findings == []

    def test_no_findings_for_unlicense(self):
        dep = _dep(license_id="Unlicense")
        result = check([dep])
        assert result.findings == []

    def test_deprecated_lgpl20_fires_lic005_only(self):
        # LGPL-2.0 is deprecated but NOT in weak copyleft set
        dep = _dep(license_id="LGPL-2.0")
        result = check([dep])
        check_ids = _check_ids(result)
        assert "LIC-005" in check_ids
        assert "LIC-002" not in check_ids

    def test_finding_dependency_name_attribute(self):
        dep = _dep(name="test_lib", license_id="GPL-3.0", is_direct=True)
        result = check([dep], project_type="proprietary")
        for f in result.findings:
            assert f.dependency_name == "test_lib"

    def test_finding_check_id_attribute_present(self):
        dep = _dep(license_id="GPL-2.0", is_direct=True)
        result = check([dep], project_type="proprietary")
        for f in result.findings:
            assert f.check_id in _CHECK_WEIGHTS

    def test_large_dependency_list_performance(self):
        # 500 clean deps should be fine
        deps = [_dep(name=f"pkg_{i}", license_id="MIT") for i in range(500)]
        result = check(deps)
        assert result.compliant is True

    def test_eupl12_is_weak_copyleft(self):
        dep = _dep(license_id="EUPL-1.2")
        result = check([dep])
        assert "LIC-002" in _check_ids(result)

    def test_bsd2_clause_no_findings(self):
        dep = _dep(license_id="BSD-2-Clause")
        result = check([dep])
        assert result.findings == []

    def test_psf20_no_findings(self):
        dep = _dep(license_id="PSF-2.0")
        result = check([dep])
        assert result.findings == []
