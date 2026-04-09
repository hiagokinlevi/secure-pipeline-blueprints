# CC BY 4.0 — Cyber Port Portfolio
# https://creativecommons.org/licenses/by/4.0/
# Test suite: test_build_provenance_checker.py
# Coverage: all 7 check IDs + edge cases + integration scenarios

from __future__ import annotations

import sys
import os

# Allow import without installing the package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared", "analyzers"))

from build_provenance_checker import (
    BuildMaterial,
    BuildProvenance,
    PROVFinding,
    PROVResult,
    _CHECK_WEIGHTS,
    _is_full_sha,
    _material_is_unpinned,
    _source_is_unpinned,
    check,
    check_many,
)

# ---------------------------------------------------------------------------
# Shared fixtures / factory helpers
# ---------------------------------------------------------------------------

GOOD_SHA = "a" * 40           # 40-char hex — valid commit SHA
GOOD_SHA2 = "b3f1c" + "0" * 35  # another valid 40-char hex SHA

def _pinned_material(name: str = "lib", version: str = "1.2.3") -> BuildMaterial:
    """Return a fully pinned material with a strict X.Y.Z version."""
    return BuildMaterial(name=name, version_spec=version, digest="sha256:" + "a" * 64)


def _clean_provenance(**overrides) -> BuildProvenance:
    """Return a fully compliant BuildProvenance; keyword args override defaults."""
    defaults = dict(
        artifact_id="art-001",
        artifact_name="my-service",
        slsa_level=2,
        source_ref=GOOD_SHA,
        builder_id="github-actions/v1",
        build_timestamp=1700000000,
        hermetic_build=True,
        output_digest="sha256:" + "b" * 64,
        output_signed=True,
        materials=[_pinned_material()],
    )
    defaults.update(overrides)
    return BuildProvenance(**defaults)


# ===========================================================================
# SECTION 1 — Helper unit tests: _is_full_sha
# ===========================================================================

# T001 — all-lowercase 40-char hex is a full SHA
def test_is_full_sha_valid_lowercase():
    assert _is_full_sha("a" * 40) is True

# T002 — 40-char hex with upper-case letters is also accepted (normalised)
def test_is_full_sha_valid_mixed_case():
    assert _is_full_sha("A" * 40) is True

# T003 — 39-char hex is not a full SHA
def test_is_full_sha_too_short():
    assert _is_full_sha("a" * 39) is False

# T004 — 41-char hex is not a full SHA
def test_is_full_sha_too_long():
    assert _is_full_sha("a" * 41) is False

# T005 — non-hex chars disqualify
def test_is_full_sha_non_hex():
    assert _is_full_sha("g" + "a" * 39) is False

# T006 — empty string is not a SHA
def test_is_full_sha_empty():
    assert _is_full_sha("") is False

# T007 — a realistic git SHA passes
def test_is_full_sha_realistic():
    assert _is_full_sha("d3adb33fd3adb33fd3adb33fd3adb33fd3adb33f") is True


# ===========================================================================
# SECTION 2 — Helper unit tests: _source_is_unpinned
# ===========================================================================

# T008 — full SHA is pinned
def test_source_pinned_full_sha():
    assert _source_is_unpinned(GOOD_SHA) is False

# T009 — "main" branch is unpinned
def test_source_unpinned_main():
    assert _source_is_unpinned("main") is True

# T010 — "master" is unpinned
def test_source_unpinned_master():
    assert _source_is_unpinned("master") is True

# T011 — "develop" is unpinned
def test_source_unpinned_develop():
    assert _source_is_unpinned("develop") is True

# T012 — "HEAD" is unpinned
def test_source_unpinned_HEAD():
    assert _source_is_unpinned("HEAD") is True

# T013 — refs/heads/ prefix is unpinned
def test_source_unpinned_refs_heads():
    assert _source_is_unpinned("refs/heads/feature/foo") is True

# T014 — a tag like "v1.2.3" is not a commit SHA (unpinned)
def test_source_unpinned_tag():
    assert _source_is_unpinned("v1.2.3") is True

# T015 — a short SHA (7 chars) is unpinned
def test_source_unpinned_short_sha():
    assert _source_is_unpinned("abc1234") is True

# T016 — uppercase refs/heads/ is also unpinned (case-insensitive prefix check)
def test_source_unpinned_refs_heads_upper():
    assert _source_is_unpinned("REFS/HEADS/main") is True


# ===========================================================================
# SECTION 3 — Helper unit tests: _material_is_unpinned
# ===========================================================================

# T017 — strict X.Y.Z without digest is pinned
def test_material_pinned_strict_version_no_digest():
    m = BuildMaterial(name="lib", version_spec="1.2.3", digest=None)
    assert _material_is_unpinned(m) is False

# T018 — strict X.Y.Z with digest is pinned
def test_material_pinned_strict_version_with_digest():
    m = BuildMaterial(name="lib", version_spec="2.0.0", digest="sha256:abc")
    assert _material_is_unpinned(m) is False

# T019 — full SHA version_spec is pinned even without digest
def test_material_pinned_sha_version_no_digest():
    m = BuildMaterial(name="lib", version_spec=GOOD_SHA, digest=None)
    assert _material_is_unpinned(m) is False

# T020 — full SHA digest pins regardless of spec
def test_material_pinned_by_sha_digest():
    m = BuildMaterial(name="lib", version_spec="latest", digest=GOOD_SHA)
    assert _material_is_unpinned(m) is False

# T021 — caret range is unpinned
def test_material_unpinned_caret():
    m = BuildMaterial(name="lib", version_spec="^1.2.3", digest=None)
    assert _material_is_unpinned(m) is True

# T022 — tilde range is unpinned
def test_material_unpinned_tilde():
    m = BuildMaterial(name="lib", version_spec="~1.2.3", digest=None)
    assert _material_is_unpinned(m) is True

# T023 — wildcard * is unpinned
def test_material_unpinned_wildcard():
    m = BuildMaterial(name="lib", version_spec="*", digest=None)
    assert _material_is_unpinned(m) is True

# T024 — "latest" keyword is unpinned
def test_material_unpinned_latest():
    m = BuildMaterial(name="lib", version_spec="latest", digest=None)
    assert _material_is_unpinned(m) is True

# T025 — branch name version_spec without digest is unpinned
def test_material_unpinned_branch_no_digest():
    m = BuildMaterial(name="lib", version_spec="main", digest=None)
    assert _material_is_unpinned(m) is True

# T026 — partial version "1.2" without digest is unpinned
def test_material_unpinned_partial_version():
    m = BuildMaterial(name="lib", version_spec="1.2", digest=None)
    assert _material_is_unpinned(m) is True

# T027 — "latest" with a short/non-SHA digest is still unpinned
#         (short digest does not provide cryptographic pinning)
def test_material_unpinned_latest_with_short_digest():
    m = BuildMaterial(name="lib", version_spec="latest", digest="sha256:abc")
    assert _material_is_unpinned(m) is True

# T028 — caret range WITH a full SHA digest is PINNED (hash-pin wins over token)
def test_material_pinned_caret_when_sha_digest_present():
    m = BuildMaterial(name="lib", version_spec="^1.0.0", digest=GOOD_SHA)
    assert _material_is_unpinned(m) is False


# ===========================================================================
# SECTION 4 — PROV-001: No SLSA attestation
# ===========================================================================

# T029 — slsa_level=None fires PROV-001
def test_prov001_fires_when_slsa_level_none():
    p = _clean_provenance(slsa_level=None)
    result = check(p)
    ids = [f.check_id for f in result.findings]
    assert "PROV-001" in ids

# T030 — slsa_level=0 fires PROV-001
def test_prov001_fires_when_slsa_level_zero():
    p = _clean_provenance(slsa_level=0)
    result = check(p)
    ids = [f.check_id for f in result.findings]
    assert "PROV-001" in ids

# T031 — slsa_level=1 does NOT fire PROV-001
def test_prov001_no_fire_when_slsa_level_one():
    p = _clean_provenance(slsa_level=1)
    result = check(p)
    ids = [f.check_id for f in result.findings]
    assert "PROV-001" not in ids

# T032 — slsa_level=2 does NOT fire PROV-001
def test_prov001_no_fire_when_slsa_level_two():
    p = _clean_provenance(slsa_level=2)
    result = check(p)
    ids = [f.check_id for f in result.findings]
    assert "PROV-001" not in ids

# T033 — PROV-001 weight is 25
def test_prov001_weight():
    p = _clean_provenance(slsa_level=None)
    result = check(p)
    finding = next(f for f in result.findings if f.check_id == "PROV-001")
    assert finding.weight == 25

# T034 — PROV-001 severity is HIGH
def test_prov001_severity():
    p = _clean_provenance(slsa_level=None)
    result = check(p)
    finding = next(f for f in result.findings if f.check_id == "PROV-001")
    assert finding.severity == "HIGH"


# ===========================================================================
# SECTION 5 — PROV-002: SLSA level below required
# ===========================================================================

# T035 — slsa_level=1 with required=2 fires PROV-002
def test_prov002_fires_level1_required2():
    p = _clean_provenance(slsa_level=1)
    result = check(p, required_slsa_level=2)
    ids = [f.check_id for f in result.findings]
    assert "PROV-002" in ids

# T036 — slsa_level=2 with required=2 does NOT fire PROV-002
def test_prov002_no_fire_exact_match():
    p = _clean_provenance(slsa_level=2)
    result = check(p, required_slsa_level=2)
    ids = [f.check_id for f in result.findings]
    assert "PROV-002" not in ids

# T037 — slsa_level=3 with required=2 does NOT fire PROV-002
def test_prov002_no_fire_exceeds_required():
    p = _clean_provenance(slsa_level=3)
    result = check(p, required_slsa_level=2)
    ids = [f.check_id for f in result.findings]
    assert "PROV-002" not in ids

# T038 — PROV-002 suppressed when PROV-001 fires (slsa_level=None)
def test_prov002_suppressed_when_prov001_fires_none():
    p = _clean_provenance(slsa_level=None)
    result = check(p, required_slsa_level=2)
    ids = [f.check_id for f in result.findings]
    assert "PROV-002" not in ids
    assert "PROV-001" in ids

# T039 — PROV-002 suppressed when slsa_level=0 (PROV-001 fires instead)
def test_prov002_suppressed_when_prov001_fires_zero():
    p = _clean_provenance(slsa_level=0)
    result = check(p, required_slsa_level=2)
    ids = [f.check_id for f in result.findings]
    assert "PROV-002" not in ids
    assert "PROV-001" in ids

# T040 — custom required_slsa_level=3: level=2 fires PROV-002
def test_prov002_fires_with_custom_required_level():
    p = _clean_provenance(slsa_level=2)
    result = check(p, required_slsa_level=3)
    ids = [f.check_id for f in result.findings]
    assert "PROV-002" in ids

# T041 — PROV-002 weight is 25
def test_prov002_weight():
    p = _clean_provenance(slsa_level=1)
    result = check(p, required_slsa_level=2)
    finding = next(f for f in result.findings if f.check_id == "PROV-002")
    assert finding.weight == 25

# T042 — required_slsa_level=1: level=1 satisfies, no PROV-002
def test_prov002_no_fire_required1_level1():
    p = _clean_provenance(slsa_level=1)
    result = check(p, required_slsa_level=1)
    ids = [f.check_id for f in result.findings]
    assert "PROV-002" not in ids


# ===========================================================================
# SECTION 6 — PROV-003: Source ref not pinned
# ===========================================================================

# T043 — full 40-char SHA does NOT fire PROV-003
def test_prov003_no_fire_full_sha():
    p = _clean_provenance(source_ref=GOOD_SHA)
    result = check(p)
    ids = [f.check_id for f in result.findings]
    assert "PROV-003" not in ids

# T044 — "main" fires PROV-003
def test_prov003_fires_main():
    p = _clean_provenance(source_ref="main")
    result = check(p)
    ids = [f.check_id for f in result.findings]
    assert "PROV-003" in ids

# T045 — "master" fires PROV-003
def test_prov003_fires_master():
    p = _clean_provenance(source_ref="master")
    result = check(p)
    ids = [f.check_id for f in result.findings]
    assert "PROV-003" in ids

# T046 — "develop" fires PROV-003
def test_prov003_fires_develop():
    p = _clean_provenance(source_ref="develop")
    result = check(p)
    ids = [f.check_id for f in result.findings]
    assert "PROV-003" in ids

# T047 — "HEAD" fires PROV-003
def test_prov003_fires_HEAD():
    p = _clean_provenance(source_ref="HEAD")
    result = check(p)
    ids = [f.check_id for f in result.findings]
    assert "PROV-003" in ids

# T048 — "refs/heads/feature/foo" fires PROV-003
def test_prov003_fires_refs_heads():
    p = _clean_provenance(source_ref="refs/heads/feature/foo")
    result = check(p)
    ids = [f.check_id for f in result.findings]
    assert "PROV-003" in ids

# T049 — tag "v2.1.0" fires PROV-003 (tag ≠ commit SHA)
def test_prov003_fires_tag():
    p = _clean_provenance(source_ref="v2.1.0")
    result = check(p)
    ids = [f.check_id for f in result.findings]
    assert "PROV-003" in ids

# T050 — short SHA "abc1234" fires PROV-003
def test_prov003_fires_short_sha():
    p = _clean_provenance(source_ref="abc1234")
    result = check(p)
    ids = [f.check_id for f in result.findings]
    assert "PROV-003" in ids

# T051 — PROV-003 weight is 25
def test_prov003_weight():
    p = _clean_provenance(source_ref="main")
    result = check(p)
    finding = next(f for f in result.findings if f.check_id == "PROV-003")
    assert finding.weight == 25

# T052 — PROV-003 severity is HIGH
def test_prov003_severity():
    p = _clean_provenance(source_ref="master")
    result = check(p)
    finding = next(f for f in result.findings if f.check_id == "PROV-003")
    assert finding.severity == "HIGH"

# T053 — uppercase REFS/HEADS/ fires PROV-003 (case-insensitive)
def test_prov003_fires_refs_heads_uppercase():
    p = _clean_provenance(source_ref="REFS/HEADS/main")
    result = check(p)
    ids = [f.check_id for f in result.findings]
    assert "PROV-003" in ids

# T054 — second valid 40-char SHA also does not fire PROV-003
def test_prov003_no_fire_second_sha():
    p = _clean_provenance(source_ref=GOOD_SHA2)
    result = check(p)
    ids = [f.check_id for f in result.findings]
    assert "PROV-003" not in ids


# ===========================================================================
# SECTION 7 — PROV-004: Non-hermetic build
# ===========================================================================

# T055 — hermetic_build=False fires PROV-004
def test_prov004_fires_non_hermetic():
    p = _clean_provenance(hermetic_build=False)
    result = check(p)
    ids = [f.check_id for f in result.findings]
    assert "PROV-004" in ids

# T056 — hermetic_build=True does NOT fire PROV-004
def test_prov004_no_fire_hermetic():
    p = _clean_provenance(hermetic_build=True)
    result = check(p)
    ids = [f.check_id for f in result.findings]
    assert "PROV-004" not in ids

# T057 — PROV-004 weight is 20
def test_prov004_weight():
    p = _clean_provenance(hermetic_build=False)
    result = check(p)
    finding = next(f for f in result.findings if f.check_id == "PROV-004")
    assert finding.weight == 20

# T058 — PROV-004 severity is HIGH
def test_prov004_severity():
    p = _clean_provenance(hermetic_build=False)
    result = check(p)
    finding = next(f for f in result.findings if f.check_id == "PROV-004")
    assert finding.severity == "HIGH"


# ===========================================================================
# SECTION 8 — PROV-005: Output not signed / no digest
# ===========================================================================

# T059 — output_signed=False fires PROV-005
def test_prov005_fires_not_signed():
    p = _clean_provenance(output_signed=False, output_digest="sha256:abc")
    result = check(p)
    ids = [f.check_id for f in result.findings]
    assert "PROV-005" in ids

# T060 — output_digest=None fires PROV-005
def test_prov005_fires_no_digest():
    p = _clean_provenance(output_signed=True, output_digest=None)
    result = check(p)
    ids = [f.check_id for f in result.findings]
    assert "PROV-005" in ids

# T061 — both False and None fires PROV-005 once
def test_prov005_fires_once_both_bad():
    p = _clean_provenance(output_signed=False, output_digest=None)
    result = check(p)
    prov005_findings = [f for f in result.findings if f.check_id == "PROV-005"]
    assert len(prov005_findings) == 1

# T062 — signed=True AND digest present does NOT fire PROV-005
def test_prov005_no_fire_signed_with_digest():
    p = _clean_provenance(output_signed=True, output_digest="sha256:" + "c" * 64)
    result = check(p)
    ids = [f.check_id for f in result.findings]
    assert "PROV-005" not in ids

# T063 — PROV-005 weight is 20
def test_prov005_weight():
    p = _clean_provenance(output_signed=False)
    result = check(p)
    finding = next(f for f in result.findings if f.check_id == "PROV-005")
    assert finding.weight == 20

# T064 — PROV-005 severity is HIGH
def test_prov005_severity():
    p = _clean_provenance(output_signed=False)
    result = check(p)
    finding = next(f for f in result.findings if f.check_id == "PROV-005")
    assert finding.severity == "HIGH"


# ===========================================================================
# SECTION 9 — PROV-006: Missing or zero timestamp
# ===========================================================================

# T065 — build_timestamp=None fires PROV-006
def test_prov006_fires_none_timestamp():
    p = _clean_provenance(build_timestamp=None)
    result = check(p)
    ids = [f.check_id for f in result.findings]
    assert "PROV-006" in ids

# T066 — build_timestamp=0 fires PROV-006
def test_prov006_fires_zero_timestamp():
    p = _clean_provenance(build_timestamp=0)
    result = check(p)
    ids = [f.check_id for f in result.findings]
    assert "PROV-006" in ids

# T067 — positive timestamp does NOT fire PROV-006
def test_prov006_no_fire_valid_timestamp():
    p = _clean_provenance(build_timestamp=1700000000)
    result = check(p)
    ids = [f.check_id for f in result.findings]
    assert "PROV-006" not in ids

# T068 — timestamp=1 (minimal positive) does NOT fire PROV-006
def test_prov006_no_fire_timestamp_one():
    p = _clean_provenance(build_timestamp=1)
    result = check(p)
    ids = [f.check_id for f in result.findings]
    assert "PROV-006" not in ids

# T069 — PROV-006 weight is 15
def test_prov006_weight():
    p = _clean_provenance(build_timestamp=None)
    result = check(p)
    finding = next(f for f in result.findings if f.check_id == "PROV-006")
    assert finding.weight == 15

# T070 — PROV-006 severity is MEDIUM
def test_prov006_severity():
    p = _clean_provenance(build_timestamp=None)
    result = check(p)
    finding = next(f for f in result.findings if f.check_id == "PROV-006")
    assert finding.severity == "MEDIUM"


# ===========================================================================
# SECTION 10 — PROV-007: Unpinned build materials
# ===========================================================================

# T071 — caret range material fires PROV-007
def test_prov007_fires_caret_range():
    p = _clean_provenance(materials=[BuildMaterial("lib", "^1.2.3", None)])
    result = check(p)
    ids = [f.check_id for f in result.findings]
    assert "PROV-007" in ids

# T072 — tilde range material fires PROV-007
def test_prov007_fires_tilde_range():
    p = _clean_provenance(materials=[BuildMaterial("lib", "~1.0.0", None)])
    result = check(p)
    ids = [f.check_id for f in result.findings]
    assert "PROV-007" in ids

# T073 — wildcard * material fires PROV-007
def test_prov007_fires_wildcard():
    p = _clean_provenance(materials=[BuildMaterial("lib", "1.*", None)])
    result = check(p)
    ids = [f.check_id for f in result.findings]
    assert "PROV-007" in ids

# T074 — "latest" material fires PROV-007
def test_prov007_fires_latest():
    p = _clean_provenance(materials=[BuildMaterial("docker-base", "latest", None)])
    result = check(p)
    ids = [f.check_id for f in result.findings]
    assert "PROV-007" in ids

# T075 — strict X.Y.Z material does NOT fire PROV-007
def test_prov007_no_fire_strict_version():
    p = _clean_provenance(materials=[BuildMaterial("lib", "3.1.4", None)])
    result = check(p)
    ids = [f.check_id for f in result.findings]
    assert "PROV-007" not in ids

# T076 — full-SHA version_spec material does NOT fire PROV-007
def test_prov007_no_fire_sha_version_spec():
    p = _clean_provenance(materials=[BuildMaterial("lib", GOOD_SHA, None)])
    result = check(p)
    ids = [f.check_id for f in result.findings]
    assert "PROV-007" not in ids

# T077 — material with full SHA digest does NOT fire PROV-007 (hash-pinned)
def test_prov007_no_fire_sha_digest_pins():
    p = _clean_provenance(materials=[BuildMaterial("lib", "latest", GOOD_SHA)])
    result = check(p)
    ids = [f.check_id for f in result.findings]
    assert "PROV-007" not in ids

# T078 — multiple unpinned materials produce exactly ONE PROV-007 finding
def test_prov007_one_finding_for_multiple_unpinned():
    mats = [
        BuildMaterial("a", "^1.0.0", None),
        BuildMaterial("b", "~2.0.0", None),
        BuildMaterial("c", "latest", None),
    ]
    p = _clean_provenance(materials=mats)
    result = check(p)
    prov007_findings = [f for f in result.findings if f.check_id == "PROV-007"]
    assert len(prov007_findings) == 1

# T079 — PROV-007 weight is 15
def test_prov007_weight():
    p = _clean_provenance(materials=[BuildMaterial("lib", "^1.0", None)])
    result = check(p)
    finding = next(f for f in result.findings if f.check_id == "PROV-007")
    assert finding.weight == 15

# T080 — PROV-007 severity is MEDIUM
def test_prov007_severity():
    p = _clean_provenance(materials=[BuildMaterial("lib", "latest", None)])
    result = check(p)
    finding = next(f for f in result.findings if f.check_id == "PROV-007")
    assert finding.severity == "MEDIUM"

# T081 — empty materials list does NOT fire PROV-007
def test_prov007_no_fire_empty_materials():
    p = _clean_provenance(materials=[])
    result = check(p)
    ids = [f.check_id for f in result.findings]
    assert "PROV-007" not in ids

# T082 — branch name version_spec without digest fires PROV-007
def test_prov007_fires_branch_version_no_digest():
    p = _clean_provenance(materials=[BuildMaterial("tool", "main", None)])
    result = check(p)
    ids = [f.check_id for f in result.findings]
    assert "PROV-007" in ids

# T083 — detail lists all unpinned material names
def test_prov007_detail_lists_all_unpinned_names():
    mats = [
        BuildMaterial("alpha", "^1.0.0", None),
        BuildMaterial("beta", "latest", None),
    ]
    p = _clean_provenance(materials=mats)
    result = check(p)
    finding = next(f for f in result.findings if f.check_id == "PROV-007")
    assert "alpha" in finding.detail
    assert "beta" in finding.detail


# ===========================================================================
# SECTION 11 — Risk score computation
# ===========================================================================

# T084 — fully clean provenance has risk_score=0
def test_risk_score_zero_for_clean():
    p = _clean_provenance()
    result = check(p)
    assert result.risk_score == 0

# T085 — only PROV-001 fires: risk_score = 25
def test_risk_score_prov001_only():
    p = _clean_provenance(
        slsa_level=None,
        source_ref=GOOD_SHA,
        hermetic_build=True,
        output_signed=True,
        output_digest="sha256:aaa",
        build_timestamp=1700000000,
        materials=[_pinned_material()],
    )
    result = check(p)
    assert result.risk_score == 25

# T086 — PROV-003 + PROV-004 sum to 45
def test_risk_score_prov003_prov004():
    p = _clean_provenance(source_ref="main", hermetic_build=False)
    result = check(p)
    # 25 (PROV-003) + 20 (PROV-004) = 45
    assert result.risk_score == 45

# T087 — all 7 checks fire: sum = 25+25+25+20+20+15+15 = 145 → capped at 100
def test_risk_score_all_checks_capped_at_100():
    p = _clean_provenance(
        slsa_level=None,          # PROV-001
        source_ref="main",        # PROV-003
        hermetic_build=False,     # PROV-004
        output_signed=False,      # PROV-005
        output_digest=None,       # PROV-005
        build_timestamp=None,     # PROV-006
        materials=[BuildMaterial("lib", "latest", None)],  # PROV-007
    )
    result = check(p)
    assert result.risk_score == 100

# T088 — risk_score never exceeds 100
def test_risk_score_never_exceeds_100():
    p = _clean_provenance(
        slsa_level=0,
        source_ref="master",
        hermetic_build=False,
        output_signed=False,
        output_digest=None,
        build_timestamp=0,
        materials=[BuildMaterial("a", "^1", None), BuildMaterial("b", "~2", None)],
    )
    result = check(p)
    assert result.risk_score <= 100


# ===========================================================================
# SECTION 12 — slsa_compliant flag
# ===========================================================================

# T089 — fully clean provenance with slsa_level=2 is compliant
def test_slsa_compliant_fully_clean():
    p = _clean_provenance(slsa_level=2)
    result = check(p)
    assert result.slsa_compliant is True

# T090 — slsa_level=3 with no findings is compliant
def test_slsa_compliant_slsa3():
    p = _clean_provenance(slsa_level=3)
    result = check(p, required_slsa_level=2)
    assert result.slsa_compliant is True

# T091 — slsa_level=None is not compliant
def test_slsa_not_compliant_no_attestation():
    p = _clean_provenance(slsa_level=None)
    result = check(p)
    assert result.slsa_compliant is False

# T092 — slsa_level=1 with required=2 is not compliant
def test_slsa_not_compliant_below_required():
    p = _clean_provenance(slsa_level=1)
    result = check(p, required_slsa_level=2)
    assert result.slsa_compliant is False

# T093 — risk_score >= 50 makes non-compliant even with good SLSA level
def test_slsa_not_compliant_high_risk_score():
    # PROV-003 (25) + PROV-004 (20) = 45, still compliant if level=2 is met
    # Add PROV-006 (+15) = 60 → not compliant
    p = _clean_provenance(
        slsa_level=2,
        source_ref="main",       # PROV-003 (+25)
        hermetic_build=False,    # PROV-004 (+20)
        build_timestamp=None,    # PROV-006 (+15)
    )
    result = check(p)
    assert result.risk_score == 60
    assert result.slsa_compliant is False

# T094 — risk_score=49 with compliant SLSA level IS compliant
def test_slsa_compliant_risk_49():
    # PROV-003 (25) + PROV-004 (20) = 45 < 50 → still compliant
    p = _clean_provenance(
        slsa_level=2,
        source_ref="main",
        hermetic_build=False,
    )
    result = check(p)
    assert result.risk_score == 45
    assert result.slsa_compliant is True

# T095 — risk_score=50 is NOT compliant (boundary)
def test_slsa_not_compliant_risk_50():
    # PROV-003 (25) + PROV-004 (20) + PROV-006 (15) = 60 → not compliant
    # Use PROV-005 (20) + PROV-007 (15) + PROV-006 (15) = 50 → not compliant
    p = _clean_provenance(
        slsa_level=2,
        output_signed=False,     # PROV-005 (+20)
        output_digest=None,
        build_timestamp=None,    # PROV-006 (+15)
        materials=[BuildMaterial("lib", "latest", None)],  # PROV-007 (+15)
    )
    result = check(p)
    assert result.risk_score == 50
    assert result.slsa_compliant is False


# ===========================================================================
# SECTION 13 — PROVResult methods
# ===========================================================================

# T096 — to_dict returns correct keys
def test_to_dict_keys():
    p = _clean_provenance(slsa_level=None)
    result = check(p)
    d = result.to_dict()
    assert set(d.keys()) == {"artifact_id", "artifact_name", "risk_score",
                              "slsa_compliant", "findings"}

# T097 — to_dict findings list length matches result.findings
def test_to_dict_findings_count():
    p = _clean_provenance(slsa_level=None, source_ref="main")
    result = check(p)
    d = result.to_dict()
    assert len(d["findings"]) == len(result.findings)

# T098 — to_dict finding dicts contain required fields
def test_to_dict_finding_fields():
    p = _clean_provenance(slsa_level=None)
    result = check(p)
    d = result.to_dict()
    for f in d["findings"]:
        assert "check_id" in f
        assert "severity" in f
        assert "title" in f
        assert "detail" in f
        assert "weight" in f

# T099 — summary contains artifact_name
def test_summary_contains_artifact_name():
    p = _clean_provenance(slsa_level=2)
    result = check(p)
    assert p.artifact_name in result.summary()

# T100 — summary of compliant result contains "COMPLIANT"
def test_summary_compliant_label():
    p = _clean_provenance(slsa_level=2)
    result = check(p)
    assert "COMPLIANT" in result.summary()

# T101 — summary of non-compliant result contains "NON-COMPLIANT"
def test_summary_non_compliant_label():
    p = _clean_provenance(slsa_level=None)
    result = check(p)
    assert "NON-COMPLIANT" in result.summary()

# T102 — by_severity groups correctly
def test_by_severity_groups():
    p = _clean_provenance(
        slsa_level=None,           # HIGH
        source_ref="main",         # HIGH
        build_timestamp=None,      # MEDIUM
    )
    result = check(p)
    grouped = result.by_severity()
    assert "HIGH" in grouped
    assert "MEDIUM" in grouped
    for finding in grouped["HIGH"]:
        assert finding.severity == "HIGH"
    for finding in grouped["MEDIUM"]:
        assert finding.severity == "MEDIUM"

# T103 — by_severity returns empty dict when no findings
def test_by_severity_empty_when_clean():
    p = _clean_provenance()
    result = check(p)
    assert result.by_severity() == {}

# T104 — to_dict risk_score matches result.risk_score
def test_to_dict_risk_score_matches():
    p = _clean_provenance(slsa_level=None)
    result = check(p)
    assert result.to_dict()["risk_score"] == result.risk_score


# ===========================================================================
# SECTION 14 — check_many
# ===========================================================================

# T105 — check_many with empty list returns empty list
def test_check_many_empty():
    assert check_many([]) == []

# T106 — check_many returns one result per input
def test_check_many_length():
    provenances = [_clean_provenance(artifact_id=str(i)) for i in range(5)]
    results = check_many(provenances)
    assert len(results) == 5

# T107 — check_many preserves order of inputs
def test_check_many_preserves_order():
    ids = ["art-A", "art-B", "art-C"]
    provenances = [_clean_provenance(artifact_id=i) for i in ids]
    results = check_many(provenances)
    assert [r.artifact_id for r in results] == ids

# T108 — check_many passes required_slsa_level to each check
def test_check_many_passes_required_slsa_level():
    p = _clean_provenance(slsa_level=2)
    results = check_many([p], required_slsa_level=3)
    assert "PROV-002" in [f.check_id for f in results[0].findings]

# T109 — check_many handles mixed compliant / non-compliant
def test_check_many_mixed():
    good = _clean_provenance(artifact_id="good")
    bad = _clean_provenance(artifact_id="bad", slsa_level=None)
    results = check_many([good, bad])
    assert results[0].slsa_compliant is True
    assert results[1].slsa_compliant is False


# ===========================================================================
# SECTION 15 — _CHECK_WEIGHTS dict
# ===========================================================================

# T110 — all 7 check IDs present in _CHECK_WEIGHTS
def test_check_weights_all_ids_present():
    expected = {"PROV-001", "PROV-002", "PROV-003", "PROV-004",
                "PROV-005", "PROV-006", "PROV-007"}
    assert set(_CHECK_WEIGHTS.keys()) == expected

# T111 — weight values match specification
def test_check_weights_values():
    assert _CHECK_WEIGHTS["PROV-001"] == 25
    assert _CHECK_WEIGHTS["PROV-002"] == 25
    assert _CHECK_WEIGHTS["PROV-003"] == 25
    assert _CHECK_WEIGHTS["PROV-004"] == 20
    assert _CHECK_WEIGHTS["PROV-005"] == 20
    assert _CHECK_WEIGHTS["PROV-006"] == 15
    assert _CHECK_WEIGHTS["PROV-007"] == 15


# ===========================================================================
# SECTION 16 — Integration / composite scenarios
# ===========================================================================

# T112 — perfect SLSA-3 artifact with all fields passes with zero findings
def test_integration_perfect_slsa3():
    p = BuildProvenance(
        artifact_id="int-001",
        artifact_name="trusted-binary",
        slsa_level=3,
        source_ref="d3adb33fd3adb33fd3adb33fd3adb33fd3adb33f",
        builder_id="github-actions/v3",
        build_timestamp=1700500000,
        hermetic_build=True,
        output_digest="sha256:" + "f" * 64,
        output_signed=True,
        materials=[
            BuildMaterial("openssl", "3.0.7", "sha256:" + "a" * 64),
            BuildMaterial("zlib", "1.2.13", "sha256:" + "b" * 64),
        ],
    )
    result = check(p, required_slsa_level=3)
    assert result.findings == []
    assert result.risk_score == 0
    assert result.slsa_compliant is True

# T113 — worst-case artifact fires all 7 distinct check IDs
def test_integration_all_checks_fire():
    p = BuildProvenance(
        artifact_id="int-002",
        artifact_name="sketchy-binary",
        slsa_level=None,          # PROV-001
        source_ref="main",        # PROV-003
        builder_id="local",
        build_timestamp=None,     # PROV-006
        hermetic_build=False,     # PROV-004
        output_digest=None,       # PROV-005
        output_signed=False,      # PROV-005
        materials=[               # PROV-007
            BuildMaterial("dep", "latest", None),
        ],
    )
    result = check(p)
    fired = {f.check_id for f in result.findings}
    # PROV-001 fires; PROV-002 is suppressed when PROV-001 fires
    assert "PROV-001" in fired
    assert "PROV-002" not in fired
    assert {"PROV-003", "PROV-004", "PROV-005", "PROV-006", "PROV-007"}.issubset(fired)
    assert result.risk_score == 100

# T114 — PROV-001 + PROV-002 cannot both fire for the same artifact
def test_integration_prov001_and_prov002_mutually_exclusive():
    for slsa in (None, 0):
        p = _clean_provenance(slsa_level=slsa)
        result = check(p, required_slsa_level=3)
        ids = [f.check_id for f in result.findings]
        assert not ("PROV-001" in ids and "PROV-002" in ids), (
            f"Both PROV-001 and PROV-002 fired for slsa_level={slsa}"
        )

# T115 — artifact_id and artifact_name round-trip through PROVResult
def test_integration_artifact_fields_roundtrip():
    p = _clean_provenance(artifact_id="xyz-999", artifact_name="cool-artifact")
    result = check(p)
    assert result.artifact_id == "xyz-999"
    assert result.artifact_name == "cool-artifact"
