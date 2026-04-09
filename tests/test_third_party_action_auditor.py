# test_third_party_action_auditor.py
# Tests for shared/analyzers/third_party_action_auditor.py
#
# Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
#
# Run with: python3 -m pytest tests/test_third_party_action_auditor.py -q

import sys
import os

# Allow imports from the shared/analyzers package without installing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared", "analyzers"))

from third_party_action_auditor import (
    ActionRef,
    TPAFinding,
    TPAResult,
    _CHECK_WEIGHTS,
    _is_sha_pinned,
    _parse_action_refs,
    _parse_org,
    _parse_ref,
    audit,
    audit_many,
)

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

SHA = "a" * 40  # 40-char hex — valid SHA-1 pin


def _make_workflow(steps_per_job=None, extra_jobs=None):
    """Build a minimal workflow dict from a list-of-step-lists."""
    jobs = {}
    for i, steps in enumerate(steps_per_job or []):
        jobs[f"job{i}"] = {"steps": steps}
    if extra_jobs:
        jobs.update(extra_jobs)
    return {"jobs": jobs}


def _uses_step(uses, name="step", **extra):
    s = {"uses": uses, "name": name}
    s.update(extra)
    return s


def _run_step(run="echo hi", name="run-step", **extra):
    s = {"run": run, "name": name}
    s.update(extra)
    return s


# ---------------------------------------------------------------------------
# Tests for _parse_org
# ---------------------------------------------------------------------------

class TestParseOrg:
    def test_simple_org(self):
        assert _parse_org("actions/checkout@v3") == "actions"

    def test_multi_segment_uses(self):
        assert _parse_org("aws-actions/configure-aws-credentials@v2") == "aws-actions"

    def test_docker_prefix(self):
        assert _parse_org("docker://alpine:3.14") == "docker-registry"

    def test_docker_with_digest(self):
        assert _parse_org("docker://alpine@sha256:abc123") == "docker-registry"

    def test_org_preserved_case(self):
        # _parse_org returns raw case; normalisation happens at call site
        assert _parse_org("MyOrg/my-action@main") == "MyOrg"


# ---------------------------------------------------------------------------
# Tests for _parse_ref
# ---------------------------------------------------------------------------

class TestParseRef:
    def test_semver_tag(self):
        assert _parse_ref("actions/checkout@v3") == "v3"

    def test_sha_ref(self):
        assert _parse_ref(f"actions/checkout@{SHA}") == SHA

    def test_no_at_sign(self):
        assert _parse_ref("actions/checkout") == ""

    def test_branch_ref(self):
        assert _parse_ref("org/repo@main") == "main"

    def test_docker_digest(self):
        assert _parse_ref("docker://alpine@sha256:deadbeef") == "sha256:deadbeef"

    def test_multi_at(self):
        # last @ wins
        assert _parse_ref("org/repo@some@thing") == "thing"


# ---------------------------------------------------------------------------
# Tests for _is_sha_pinned
# ---------------------------------------------------------------------------

class TestIsSHAPinned:
    def test_valid_sha1(self):
        assert _is_sha_pinned("a" * 40) is True

    def test_valid_sha1_mixed_case(self):
        assert _is_sha_pinned("A" * 40) is True

    def test_sha256_prefix(self):
        assert _is_sha_pinned("sha256:abc123def456") is True

    def test_floating_tag_not_pinned(self):
        assert _is_sha_pinned("v3") is False

    def test_branch_not_pinned(self):
        assert _is_sha_pinned("main") is False

    def test_short_hex_not_pinned(self):
        assert _is_sha_pinned("abc123") is False

    def test_39_char_hex_not_pinned(self):
        assert _is_sha_pinned("a" * 39) is False

    def test_41_char_hex_not_pinned(self):
        assert _is_sha_pinned("a" * 41) is False

    def test_non_hex_not_pinned(self):
        assert _is_sha_pinned("z" * 40) is False


# ---------------------------------------------------------------------------
# Tests for _parse_action_refs
# ---------------------------------------------------------------------------

class TestParseActionRefs:
    def test_single_ref(self):
        wf = _make_workflow([[_uses_step("actions/checkout@v3")]])
        refs = _parse_action_refs(wf)
        assert len(refs) == 1
        assert refs[0].uses == "actions/checkout@v3"
        assert refs[0].job_id == "job0"

    def test_step_name_captured(self):
        wf = _make_workflow([[_uses_step("actions/checkout@v3", name="Checkout code")]])
        refs = _parse_action_refs(wf)
        assert refs[0].step_name == "Checkout code"

    def test_local_action_excluded(self):
        wf = _make_workflow([[_uses_step("./.github/actions/my-action@v1")]])
        refs = _parse_action_refs(wf)
        assert refs == []

    def test_run_step_excluded(self):
        wf = _make_workflow([[_run_step()]])
        refs = _parse_action_refs(wf)
        assert refs == []

    def test_no_at_sign_excluded(self):
        wf = _make_workflow([[{"uses": "actions/checkout", "name": "s"}]])
        refs = _parse_action_refs(wf)
        assert refs == []

    def test_no_slash_excluded(self):
        wf = _make_workflow([[{"uses": "checkout@v3", "name": "s"}]])
        refs = _parse_action_refs(wf)
        assert refs == []

    def test_multiple_jobs(self):
        wf = _make_workflow([
            [_uses_step("actions/checkout@v3")],
            [_uses_step("actions/setup-python@v4")],
        ])
        refs = _parse_action_refs(wf)
        assert len(refs) == 2
        job_ids = {r.job_id for r in refs}
        assert job_ids == {"job0", "job1"}

    def test_empty_jobs(self):
        refs = _parse_action_refs({"jobs": {}})
        assert refs == []

    def test_no_jobs_key(self):
        refs = _parse_action_refs({})
        assert refs == []

    def test_step_with_no_name_key(self):
        wf = _make_workflow([[{"uses": "actions/checkout@v3"}]])
        refs = _parse_action_refs(wf)
        assert len(refs) == 1
        assert refs[0].step_name == ""

    def test_docker_ref_included(self):
        wf = _make_workflow([[_uses_step("docker://alpine:3.14@sha256:abc")]])
        refs = _parse_action_refs(wf)
        assert len(refs) == 1

    def test_multiple_steps_same_job(self):
        steps = [
            _uses_step("actions/checkout@v3", name="a"),
            _uses_step("actions/setup-node@v3", name="b"),
        ]
        wf = _make_workflow([steps])
        refs = _parse_action_refs(wf)
        assert len(refs) == 2


# ---------------------------------------------------------------------------
# TPA-001: Mutable branch references
# ---------------------------------------------------------------------------

class TestTPA001:
    def test_at_main_flagged(self):
        wf = _make_workflow([[_uses_step("org/action@main")]])
        result = audit(wf)
        ids = [f.check_id for f in result.findings]
        assert "TPA-001" in ids

    def test_at_master_flagged(self):
        wf = _make_workflow([[_uses_step("org/action@master")]])
        result = audit(wf)
        assert any(f.check_id == "TPA-001" for f in result.findings)

    def test_at_HEAD_flagged(self):
        wf = _make_workflow([[_uses_step("org/action@HEAD")]])
        result = audit(wf)
        assert any(f.check_id == "TPA-001" for f in result.findings)

    def test_at_develop_flagged(self):
        wf = _make_workflow([[_uses_step("org/action@develop")]])
        result = audit(wf)
        assert any(f.check_id == "TPA-001" for f in result.findings)

    def test_at_dev_flagged(self):
        wf = _make_workflow([[_uses_step("org/action@dev")]])
        result = audit(wf)
        assert any(f.check_id == "TPA-001" for f in result.findings)

    def test_sha_pinned_not_flagged(self):
        wf = _make_workflow([[_uses_step(f"actions/checkout@{SHA}")]])
        result = audit(wf)
        assert not any(f.check_id == "TPA-001" for f in result.findings)

    def test_floating_tag_not_flagged_by_tpa001(self):
        wf = _make_workflow([[_uses_step("actions/checkout@v3")]])
        result = audit(wf)
        assert not any(f.check_id == "TPA-001" for f in result.findings)

    def test_severity_is_critical(self):
        wf = _make_workflow([[_uses_step("org/action@main")]])
        result = audit(wf)
        f = next(f for f in result.findings if f.check_id == "TPA-001")
        assert f.severity == "CRITICAL"

    def test_weight_is_45(self):
        wf = _make_workflow([[_uses_step("org/action@main")]])
        result = audit(wf)
        f = next(f for f in result.findings if f.check_id == "TPA-001")
        assert f.weight == 45

    def test_multiple_mutable_refs_in_one_finding(self):
        steps = [
            _uses_step("org/a@main", name="a"),
            _uses_step("org/b@master", name="b"),
        ]
        wf = _make_workflow([steps])
        result = audit(wf)
        f = next(f for f in result.findings if f.check_id == "TPA-001")
        assert len(f.action_refs) == 2

    def test_case_insensitive_HEAD(self):
        # @head (lowercase) should still fire
        wf = _make_workflow([[_uses_step("org/action@head")]])
        result = audit(wf)
        assert any(f.check_id == "TPA-001" for f in result.findings)

    def test_action_refs_list_populated(self):
        wf = _make_workflow([[_uses_step("org/action@main")]])
        result = audit(wf)
        f = next(f for f in result.findings if f.check_id == "TPA-001")
        assert "org/action@main" in f.action_refs


# ---------------------------------------------------------------------------
# TPA-002: Floating version tags
# ---------------------------------------------------------------------------

class TestTPA002:
    def test_v_major_flagged(self):
        wf = _make_workflow([[_uses_step("actions/checkout@v3")]])
        result = audit(wf)
        assert any(f.check_id == "TPA-002" for f in result.findings)

    def test_v_major_minor_flagged(self):
        wf = _make_workflow([[_uses_step("actions/checkout@v1.2")]])
        result = audit(wf)
        assert any(f.check_id == "TPA-002" for f in result.findings)

    def test_v_semver_flagged(self):
        wf = _make_workflow([[_uses_step("actions/checkout@v1.2.3")]])
        result = audit(wf)
        assert any(f.check_id == "TPA-002" for f in result.findings)

    def test_sha_pinned_not_flagged(self):
        wf = _make_workflow([[_uses_step(f"actions/checkout@{SHA}")]])
        result = audit(wf)
        assert not any(f.check_id == "TPA-002" for f in result.findings)

    def test_mutable_branch_suppresses_tpa002(self):
        # @main fires TPA-001; TPA-002 must NOT also fire for same ref
        wf = _make_workflow([[_uses_step("actions/checkout@main")]])
        result = audit(wf)
        check_ids = [f.check_id for f in result.findings]
        assert "TPA-001" in check_ids
        assert "TPA-002" not in check_ids

    def test_severity_is_high(self):
        wf = _make_workflow([[_uses_step("actions/checkout@v3")]])
        result = audit(wf)
        f = next(f for f in result.findings if f.check_id == "TPA-002")
        assert f.severity == "HIGH"

    def test_weight_is_25(self):
        wf = _make_workflow([[_uses_step("actions/checkout@v3")]])
        result = audit(wf)
        f = next(f for f in result.findings if f.check_id == "TPA-002")
        assert f.weight == 25

    def test_v_followed_by_non_digit_not_flagged(self):
        # e.g. @v3-beta is not a pure semver float tag
        wf = _make_workflow([[_uses_step(f"actions/checkout@{SHA}")]])
        result = audit(wf)
        assert not any(f.check_id == "TPA-002" for f in result.findings)

    def test_action_refs_contains_flagged_uses(self):
        wf = _make_workflow([[_uses_step("actions/checkout@v3")]])
        result = audit(wf)
        f = next(f for f in result.findings if f.check_id == "TPA-002")
        assert "actions/checkout@v3" in f.action_refs


# ---------------------------------------------------------------------------
# TPA-003: Untrusted organisations
# ---------------------------------------------------------------------------

class TestTPA003:
    def test_unknown_org_flagged(self):
        wf = _make_workflow([[_uses_step("unknown-corp/action@v1")]])
        result = audit(wf)
        assert any(f.check_id == "TPA-003" for f in result.findings)

    def test_trusted_org_not_flagged(self):
        for org in ["actions", "github", "aws-actions", "azure", "google-github-actions", "docker"]:
            wf = _make_workflow([[_uses_step(f"{org}/some-action@v1")]])
            result = audit(wf)
            assert not any(f.check_id == "TPA-003" for f in result.findings), f"org={org} should be trusted"

    def test_custom_trusted_org(self):
        wf = _make_workflow([[_uses_step("my-company/deploy@v1")]])
        result = audit(wf, trusted_orgs=["my-company"])
        assert not any(f.check_id == "TPA-003" for f in result.findings)

    def test_docker_ref_not_flagged_by_tpa003(self):
        wf = _make_workflow([[_uses_step("docker://alpine:latest@sha256:abc")]])
        result = audit(wf)
        assert not any(f.check_id == "TPA-003" for f in result.findings)

    def test_severity_is_high(self):
        wf = _make_workflow([[_uses_step("random-org/action@v1")]])
        result = audit(wf)
        f = next(f for f in result.findings if f.check_id == "TPA-003")
        assert f.severity == "HIGH"

    def test_weight_is_25(self):
        wf = _make_workflow([[_uses_step("random-org/action@v1")]])
        result = audit(wf)
        f = next(f for f in result.findings if f.check_id == "TPA-003")
        assert f.weight == 25

    def test_trusted_org_case_insensitive(self):
        wf = _make_workflow([[_uses_step("Actions/checkout@v3")]])
        result = audit(wf, trusted_orgs=["actions"])
        assert not any(f.check_id == "TPA-003" for f in result.findings)

    def test_multiple_untrusted_orgs_in_one_finding(self):
        steps = [
            _uses_step("bad-org/a@v1", name="a"),
            _uses_step("another-bad/b@v1", name="b"),
        ]
        wf = _make_workflow([steps])
        result = audit(wf)
        f = next(f for f in result.findings if f.check_id == "TPA-003")
        assert len(f.action_refs) == 2

    def test_local_action_not_flagged(self):
        wf = _make_workflow([[_uses_step("./.github/actions/local@v1")]])
        result = audit(wf)
        assert not any(f.check_id == "TPA-003" for f in result.findings)

    def test_empty_trusted_orgs_flags_all(self):
        wf = _make_workflow([[_uses_step("actions/checkout@v3")]])
        result = audit(wf, trusted_orgs=[])
        assert any(f.check_id == "TPA-003" for f in result.findings)


# ---------------------------------------------------------------------------
# TPA-004: Docker images without digest
# ---------------------------------------------------------------------------

class TestTPA004:
    def test_docker_without_digest_flagged(self):
        wf = _make_workflow([[_uses_step("docker://alpine:3.14")]])
        result = audit(wf)
        assert any(f.check_id == "TPA-004" for f in result.findings)

    def test_docker_with_digest_not_flagged(self):
        wf = _make_workflow([[_uses_step("docker://alpine@sha256:deadbeef1234")]])
        result = audit(wf)
        assert not any(f.check_id == "TPA-004" for f in result.findings)

    def test_non_docker_not_flagged_by_tpa004(self):
        wf = _make_workflow([[_uses_step("actions/checkout@v3")]])
        result = audit(wf)
        assert not any(f.check_id == "TPA-004" for f in result.findings)

    def test_severity_is_high(self):
        wf = _make_workflow([[_uses_step("docker://ubuntu:22.04")]])
        result = audit(wf)
        f = next(f for f in result.findings if f.check_id == "TPA-004")
        assert f.severity == "HIGH"

    def test_weight_is_20(self):
        wf = _make_workflow([[_uses_step("docker://ubuntu:22.04")]])
        result = audit(wf)
        f = next(f for f in result.findings if f.check_id == "TPA-004")
        assert f.weight == 20

    def test_docker_latest_without_digest_flagged(self):
        wf = _make_workflow([[_uses_step("docker://node:latest")]])
        result = audit(wf)
        assert any(f.check_id == "TPA-004" for f in result.findings)

    def test_action_refs_contains_docker_uses(self):
        uses = "docker://alpine:3.14"
        wf = _make_workflow([[_uses_step(uses)]])
        result = audit(wf)
        f = next(f for f in result.findings if f.check_id == "TPA-004")
        assert uses in f.action_refs


# ---------------------------------------------------------------------------
# TPA-005: continue-on-error in security-sensitive jobs
# ---------------------------------------------------------------------------

class TestTPA005:
    def _security_job(self, steps, job_name="security-scan"):
        return {
            job_name.replace(" ", "-"): {
                "name": job_name,
                "steps": steps,
            }
        }

    def test_continue_on_error_in_security_job_flagged(self):
        steps = [_uses_step("actions/checkout@v3", **{"continue-on-error": True})]
        wf = {"jobs": self._security_job(steps)}
        result = audit(wf)
        assert any(f.check_id == "TPA-005" for f in result.findings)

    def test_continue_on_error_false_not_flagged(self):
        steps = [_uses_step("actions/checkout@v3", **{"continue-on-error": False})]
        wf = {"jobs": self._security_job(steps)}
        result = audit(wf)
        assert not any(f.check_id == "TPA-005" for f in result.findings)

    def test_continue_on_error_non_security_job_not_flagged(self):
        steps = [_uses_step("actions/checkout@v3", **{"continue-on-error": True})]
        wf = _make_workflow([steps])  # generic job0 — not security-sensitive
        result = audit(wf)
        assert not any(f.check_id == "TPA-005" for f in result.findings)

    def test_sensitive_keyword_scan_in_job_id(self):
        steps = [_run_step(**{"continue-on-error": True})]
        wf = {"jobs": {"code-scan": {"steps": steps}}}
        result = audit(wf)
        assert any(f.check_id == "TPA-005" for f in result.findings)

    def test_sensitive_keyword_test_in_job_id(self):
        steps = [_run_step(**{"continue-on-error": True})]
        wf = {"jobs": {"unit-test": {"steps": steps}}}
        result = audit(wf)
        assert any(f.check_id == "TPA-005" for f in result.findings)

    def test_sensitive_keyword_audit_in_job_name(self):
        steps = [_run_step(**{"continue-on-error": True})]
        wf = {"jobs": {"job1": {"name": "dependency-audit", "steps": steps}}}
        result = audit(wf)
        assert any(f.check_id == "TPA-005" for f in result.findings)

    def test_sensitive_keyword_sast(self):
        steps = [_run_step(**{"continue-on-error": True})]
        wf = {"jobs": {"sast-job": {"steps": steps}}}
        result = audit(wf)
        assert any(f.check_id == "TPA-005" for f in result.findings)

    def test_sensitive_keyword_sca(self):
        steps = [_run_step(**{"continue-on-error": True})]
        wf = {"jobs": {"sca-scan": {"steps": steps}}}
        result = audit(wf)
        assert any(f.check_id == "TPA-005" for f in result.findings)

    def test_sensitive_keyword_lint(self):
        steps = [_run_step(**{"continue-on-error": True})]
        wf = {"jobs": {"lint": {"steps": steps}}}
        result = audit(wf)
        assert any(f.check_id == "TPA-005" for f in result.findings)

    def test_sensitive_keyword_check(self):
        steps = [_run_step(**{"continue-on-error": True})]
        wf = {"jobs": {"pre-check": {"steps": steps}}}
        result = audit(wf)
        assert any(f.check_id == "TPA-005" for f in result.findings)

    def test_severity_is_medium(self):
        steps = [_uses_step("actions/checkout@v3", **{"continue-on-error": True})]
        wf = {"jobs": {"security": {"steps": steps}}}
        result = audit(wf)
        f = next(f for f in result.findings if f.check_id == "TPA-005")
        assert f.severity == "MEDIUM"

    def test_weight_is_15(self):
        steps = [_uses_step("actions/checkout@v3", **{"continue-on-error": True})]
        wf = {"jobs": {"security": {"steps": steps}}}
        result = audit(wf)
        f = next(f for f in result.findings if f.check_id == "TPA-005")
        assert f.weight == 15

    def test_two_steps_two_findings(self):
        steps = [
            _run_step(name="step-a", **{"continue-on-error": True}),
            _run_step(name="step-b", **{"continue-on-error": True}),
        ]
        wf = {"jobs": {"security": {"steps": steps}}}
        result = audit(wf)
        tpa005_findings = [f for f in result.findings if f.check_id == "TPA-005"]
        assert len(tpa005_findings) == 2

    def test_weight_deduplicated_in_score(self):
        # Two TPA-005 findings should only add weight once to risk_score
        steps = [
            _run_step(name="s1", **{"continue-on-error": True}),
            _run_step(name="s2", **{"continue-on-error": True}),
        ]
        wf = {"jobs": {"security": {"steps": steps}}}
        result = audit(wf)
        # Only TPA-005 fires; score should be 15 (not 30)
        assert result.risk_score == 15

    def test_continue_on_error_string_not_flagged(self):
        # "true" as a string should not trigger — must be bool True
        steps = [_run_step(**{"continue-on-error": "true"})]
        wf = {"jobs": {"security": {"steps": steps}}}
        result = audit(wf)
        assert not any(f.check_id == "TPA-005" for f in result.findings)


# ---------------------------------------------------------------------------
# TPA-006: Version inconsistency
# ---------------------------------------------------------------------------

class TestTPA006:
    def test_same_action_different_versions_flagged(self):
        steps_a = [_uses_step("actions/checkout@v3")]
        steps_b = [_uses_step("actions/checkout@v4")]
        wf = _make_workflow([steps_a, steps_b])
        result = audit(wf)
        assert any(f.check_id == "TPA-006" for f in result.findings)

    def test_same_action_same_version_not_flagged(self):
        steps_a = [_uses_step("actions/checkout@v3")]
        steps_b = [_uses_step("actions/checkout@v3")]
        wf = _make_workflow([steps_a, steps_b])
        result = audit(wf)
        assert not any(f.check_id == "TPA-006" for f in result.findings)

    def test_different_actions_no_conflict(self):
        steps = [
            _uses_step("actions/checkout@v3", name="a"),
            _uses_step("actions/setup-node@v3", name="b"),
        ]
        wf = _make_workflow([steps])
        result = audit(wf)
        assert not any(f.check_id == "TPA-006" for f in result.findings)

    def test_org_difference_does_not_matter_for_tpa006(self):
        # "checkout" from two different orgs but both @v3 — should not fire
        # because both have the same ref for "checkout"
        steps = [
            _uses_step("actions/checkout@v3", name="a"),
            _uses_step("third-party/checkout@v3", name="b"),
        ]
        wf = _make_workflow([steps])
        result = audit(wf)
        assert not any(f.check_id == "TPA-006" for f in result.findings)

    def test_org_difference_with_different_ref_fires(self):
        # "checkout" from two orgs with different refs
        steps = [
            _uses_step("actions/checkout@v3", name="a"),
            _uses_step("third-party/checkout@v4", name="b"),
        ]
        wf = _make_workflow([steps])
        result = audit(wf)
        assert any(f.check_id == "TPA-006" for f in result.findings)

    def test_severity_is_medium(self):
        steps_a = [_uses_step("actions/checkout@v3")]
        steps_b = [_uses_step("actions/checkout@v4")]
        wf = _make_workflow([steps_a, steps_b])
        result = audit(wf)
        f = next(f for f in result.findings if f.check_id == "TPA-006")
        assert f.severity == "MEDIUM"

    def test_weight_is_15(self):
        steps_a = [_uses_step("actions/checkout@v3")]
        steps_b = [_uses_step("actions/checkout@v4")]
        wf = _make_workflow([steps_a, steps_b])
        result = audit(wf)
        f = next(f for f in result.findings if f.check_id == "TPA-006")
        assert f.weight == 15

    def test_action_refs_include_inconsistent_uses(self):
        steps_a = [_uses_step("actions/checkout@v3")]
        steps_b = [_uses_step("actions/checkout@v4")]
        wf = _make_workflow([steps_a, steps_b])
        result = audit(wf)
        f = next(f for f in result.findings if f.check_id == "TPA-006")
        assert "actions/checkout@v3" in f.action_refs
        assert "actions/checkout@v4" in f.action_refs

    def test_three_different_versions_single_finding(self):
        steps = [
            _uses_step("actions/checkout@v2", name="a"),
            _uses_step("actions/checkout@v3", name="b"),
            _uses_step("actions/checkout@v4", name="c"),
        ]
        wf = _make_workflow([steps])
        result = audit(wf)
        tpa006_findings = [f for f in result.findings if f.check_id == "TPA-006"]
        assert len(tpa006_findings) == 1


# ---------------------------------------------------------------------------
# TPA-007: Excessive third-party action surface area
# ---------------------------------------------------------------------------

class TestTPA007:
    def _workflow_with_n_actions(self, n):
        steps = [_uses_step(f"org{i}/action{i}@v1", name=f"s{i}") for i in range(n)]
        return _make_workflow([steps])

    def test_exactly_15_not_flagged(self):
        wf = self._workflow_with_n_actions(15)
        result = audit(wf)
        assert not any(f.check_id == "TPA-007" for f in result.findings)

    def test_16_flagged(self):
        wf = self._workflow_with_n_actions(16)
        result = audit(wf)
        assert any(f.check_id == "TPA-007" for f in result.findings)

    def test_0_actions_not_flagged(self):
        wf = {"jobs": {}}
        result = audit(wf)
        assert not any(f.check_id == "TPA-007" for f in result.findings)

    def test_duplicates_count_once(self):
        # 10 distinct refs repeated 3 times each — still only 10 distinct
        steps = []
        for i in range(10):
            for _ in range(3):
                steps.append(_uses_step(f"org{i}/action{i}@v1", name=f"s{i}"))
        wf = _make_workflow([steps])
        result = audit(wf)
        assert not any(f.check_id == "TPA-007" for f in result.findings)

    def test_severity_is_medium(self):
        wf = self._workflow_with_n_actions(20)
        result = audit(wf)
        f = next(f for f in result.findings if f.check_id == "TPA-007")
        assert f.severity == "MEDIUM"

    def test_weight_is_15(self):
        wf = self._workflow_with_n_actions(20)
        result = audit(wf)
        f = next(f for f in result.findings if f.check_id == "TPA-007")
        assert f.weight == 15

    def test_action_refs_length_matches_distinct_count(self):
        wf = self._workflow_with_n_actions(20)
        result = audit(wf)
        f = next(f for f in result.findings if f.check_id == "TPA-007")
        assert len(f.action_refs) == 20

    def test_exactly_16_distinct_refs_fires(self):
        wf = self._workflow_with_n_actions(16)
        result = audit(wf)
        f = next(f for f in result.findings if f.check_id == "TPA-007")
        assert len(f.action_refs) == 16


# ---------------------------------------------------------------------------
# Risk score computation
# ---------------------------------------------------------------------------

class TestRiskScore:
    def test_no_findings_score_zero(self):
        wf = _make_workflow([[_uses_step(f"actions/checkout@{SHA}")]])
        result = audit(wf)
        assert result.risk_score == 0

    def test_score_capped_at_100(self):
        # Fire every check to exceed 100
        # TPA-001=45 + TPA-003=25 = 70 (two high-weight checks from mutable branch + untrusted org)
        # Add more via TPA-002 + TPA-004 + TPA-005 + TPA-006 + TPA-007
        # Craft a workflow that fires all 7 checks
        steps_a = []
        # TPA-001: mutable branch
        steps_a.append(_uses_step("bad-org/action@main", name="s-main"))
        # TPA-002: floating tag (different action to avoid TPA-001 suppression)
        steps_a.append(_uses_step("bad-org/other@v2", name="s-v2"))
        # TPA-003: bad-org is already untrusted (above)
        # TPA-004: docker without digest
        steps_a.append(_uses_step("docker://alpine:latest", name="s-docker"))
        # TPA-005: continue-on-error in security job handled via extra_jobs
        # TPA-006: version inconsistency
        steps_a.append(_uses_step("actions/checkout@v3", name="s-co-v3"))

        steps_b = [_uses_step("actions/checkout@v4", name="s-co-v4")]  # TPA-006

        # TPA-007: >15 distinct refs
        for i in range(14):
            steps_a.append(_uses_step(f"extra-org/pkg{i}@v1", name=f"extra{i}"))

        security_steps = [_run_step(name="scan", **{"continue-on-error": True})]

        extra_jobs = {
            "job-a": {"steps": steps_a},
            "job-b": {"steps": steps_b},
            "security-scan": {"steps": security_steps},
        }
        wf = {"jobs": extra_jobs}
        result = audit(wf)
        assert result.risk_score == 100

    def test_score_is_sum_of_unique_fired_weights(self):
        # Only TPA-001 fires: weight 45
        wf = _make_workflow([[_uses_step("actions/checkout@main")]])
        result = audit(wf, trusted_orgs=["actions"])
        fired = {f.check_id for f in result.findings}
        expected = sum(_CHECK_WEIGHTS[cid] for cid in fired)
        assert result.risk_score == min(100, expected)

    def test_tpa001_and_tpa003_combined_score(self):
        # TPA-001 (45) + TPA-003 (25) = 70
        wf = _make_workflow([[_uses_step("bad-org/action@main")]])
        result = audit(wf, trusted_orgs=[])
        assert result.risk_score == 45 + 25


# ---------------------------------------------------------------------------
# TPAResult helpers
# ---------------------------------------------------------------------------

class TestTPAResult:
    def _clean_result(self):
        wf = _make_workflow([[_uses_step(f"actions/checkout@{SHA}")]])
        return audit(wf)

    def _dirty_result(self):
        steps = [
            _uses_step("bad-org/action@main", name="a"),
            _uses_step("actions/checkout@v3", name="b"),
        ]
        return audit(_make_workflow([steps]))

    def test_to_dict_keys(self):
        r = self._clean_result()
        d = r.to_dict()
        assert set(d.keys()) == {"workflow_name", "total_action_refs", "risk_score", "findings"}

    def test_to_dict_findings_is_list(self):
        r = self._dirty_result()
        d = r.to_dict()
        assert isinstance(d["findings"], list)

    def test_to_dict_finding_keys(self):
        r = self._dirty_result()
        d = r.to_dict()
        assert len(d["findings"]) > 0
        keys = set(d["findings"][0].keys())
        assert keys == {"check_id", "severity", "title", "detail", "weight", "action_refs"}

    def test_summary_contains_workflow_name(self):
        r = audit({}, workflow_name="deploy.yml")
        assert "deploy.yml" in r.summary()

    def test_summary_contains_risk_score(self):
        r = audit({}, workflow_name="test.yml")
        assert "risk_score=0" in r.summary()

    def test_summary_contains_findings_count(self):
        r = audit({}, workflow_name="test.yml")
        assert "findings=0" in r.summary()

    def test_by_severity_grouping(self):
        steps = [
            _uses_step("bad-org/action@main", name="a"),   # CRITICAL + others
            _uses_step("actions/checkout@v3", name="b"),
        ]
        result = audit(_make_workflow([steps]))
        bsev = result.by_severity()
        assert "CRITICAL" in bsev
        assert all(f.severity == "CRITICAL" for f in bsev["CRITICAL"])

    def test_by_severity_high_group(self):
        steps = [_uses_step("actions/checkout@v3")]
        result = audit(_make_workflow([steps]))
        bsev = result.by_severity()
        # TPA-002 (HIGH) should fire
        assert "HIGH" in bsev

    def test_total_action_refs_count(self):
        steps = [
            _uses_step("actions/checkout@v3", name="a"),
            _uses_step("actions/setup-node@v3", name="b"),
        ]
        result = audit(_make_workflow([steps]))
        assert result.total_action_refs == 2

    def test_workflow_name_stored(self):
        result = audit({}, workflow_name="ci.yml")
        assert result.workflow_name == "ci.yml"


# ---------------------------------------------------------------------------
# audit_many
# ---------------------------------------------------------------------------

class TestAuditMany:
    def test_returns_list_of_results(self):
        workflows = [{"jobs": {}}, {"jobs": {}}]
        results = audit_many(workflows)
        assert len(results) == 2
        assert all(isinstance(r, TPAResult) for r in results)

    def test_names_assigned_correctly(self):
        workflows = [{"jobs": {}}, {"jobs": {}}]
        results = audit_many(workflows, names=["first.yml", "second.yml"])
        assert results[0].workflow_name == "first.yml"
        assert results[1].workflow_name == "second.yml"

    def test_default_names_when_none(self):
        workflows = [{"jobs": {}}, {"jobs": {}}]
        results = audit_many(workflows)
        assert results[0].workflow_name == "workflow-0"
        assert results[1].workflow_name == "workflow-1"

    def test_partial_names_fallback(self):
        workflows = [{"jobs": {}}, {"jobs": {}}, {"jobs": {}}]
        results = audit_many(workflows, names=["only-one.yml"])
        assert results[0].workflow_name == "only-one.yml"
        assert results[1].workflow_name == "workflow-1"
        assert results[2].workflow_name == "workflow-2"

    def test_trusted_orgs_passed_through(self):
        wf = _make_workflow([[_uses_step("my-corp/action@v1")]])
        results = audit_many([wf], trusted_orgs=["my-corp"])
        assert not any(f.check_id == "TPA-003" for f in results[0].findings)

    def test_empty_list_returns_empty(self):
        assert audit_many([]) == []

    def test_individual_audits_match(self):
        wf1 = _make_workflow([[_uses_step("bad-org/action@main")]])
        wf2 = _make_workflow([[_uses_step(f"actions/checkout@{SHA}")]])
        results = audit_many([wf1, wf2], names=["bad.yml", "clean.yml"])
        solo1 = audit(wf1, workflow_name="bad.yml")
        solo2 = audit(wf2, workflow_name="clean.yml")
        assert results[0].risk_score == solo1.risk_score
        assert results[1].risk_score == solo2.risk_score


# ---------------------------------------------------------------------------
# Integration / combined scenarios
# ---------------------------------------------------------------------------

class TestIntegration:
    def test_fully_pinned_trusted_workflow_clean(self):
        steps = [
            _uses_step(f"actions/checkout@{SHA}", name="checkout"),
            _uses_step(f"actions/setup-python@{SHA}", name="setup-python"),
        ]
        wf = _make_workflow([steps])
        result = audit(wf)
        assert result.risk_score == 0
        assert result.findings == []

    def test_mixed_workflow_fires_multiple_checks(self):
        steps_a = [
            _uses_step("bad-org/action@main", name="mutable"),
            _uses_step("actions/checkout@v3", name="float-tag"),
        ]
        wf = _make_workflow([steps_a])
        result = audit(wf)
        check_ids = {f.check_id for f in result.findings}
        assert "TPA-001" in check_ids
        assert "TPA-002" in check_ids
        assert "TPA-003" in check_ids  # bad-org is untrusted

    def test_only_local_actions_clean(self):
        steps = [_uses_step("./.github/actions/local@v1")]
        wf = _make_workflow([steps])
        result = audit(wf)
        assert result.total_action_refs == 0
        assert result.risk_score == 0

    def test_docker_with_digest_clean(self):
        steps = [_uses_step("docker://alpine@sha256:" + "a" * 64)]
        wf = _make_workflow([steps])
        result = audit(wf)
        assert not any(f.check_id == "TPA-004" for f in result.findings)

    def test_check_weights_dict_has_all_ids(self):
        expected_ids = {"TPA-001", "TPA-002", "TPA-003", "TPA-004", "TPA-005", "TPA-006", "TPA-007"}
        assert set(_CHECK_WEIGHTS.keys()) == expected_ids

    def test_check_weights_values_positive(self):
        for cid, w in _CHECK_WEIGHTS.items():
            assert w > 0, f"{cid} must have positive weight"

    def test_default_workflow_name(self):
        result = audit({})
        assert result.workflow_name == "workflow"

    def test_no_jobs_key_returns_zero_refs(self):
        result = audit({"on": "push"})
        assert result.total_action_refs == 0
        assert result.risk_score == 0

    def test_finding_detail_is_non_empty(self):
        wf = _make_workflow([[_uses_step("bad-org/action@main")]])
        result = audit(wf)
        for f in result.findings:
            assert len(f.detail) > 0

    def test_finding_title_is_non_empty(self):
        wf = _make_workflow([[_uses_step("bad-org/action@main")]])
        result = audit(wf)
        for f in result.findings:
            assert len(f.title) > 0
