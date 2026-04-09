# test_github_actions_permissions_auditor.py
# Tests for the GitHub Actions permissions auditor module.
#
# License: CC BY 4.0 — Creative Commons Attribution 4.0 International
# https://creativecommons.org/licenses/by/4.0/
#
# Part of the Cyber Port portfolio — github.com/hiagokinlevi
# Repository: k1N-Secure-Pipeline-Blueprints

import sys
import os

# Allow import from the shared/analyzers package without an installed package
sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..", "shared", "analyzers"),
)

from github_actions_permissions_auditor import (
    GHPFinding,
    GHPResult,
    WorkflowPermission,
    _CHECK_WEIGHTS,
    _collect_all_permissions,
    _has_pr_trigger,
    analyze,
    analyze_many,
)


# ---------------------------------------------------------------------------
# Fixtures / factory helpers
# ---------------------------------------------------------------------------

def _minimal_clean_workflow():
    """A minimal workflow that should produce zero findings."""
    return {
        "name": "CI",
        "on": {"push": {"branches": ["main"]}},
        "permissions": {"contents": "read"},
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [{"name": "checkout", "uses": "actions/checkout@v4"}],
            }
        },
    }


def _workflow_with_perms(perms):
    """Workflow dict with the given top-level permissions value."""
    return {
        "name": "test",
        "on": "push",
        "permissions": perms,
        "jobs": {},
    }


def _workflow_no_perms():
    """Workflow dict with no permissions key at all."""
    return {"name": "test", "on": "push", "jobs": {}}


def _workflow_pr_trigger(perms=None):
    """Workflow triggered by pull_request with optional permissions."""
    wf = {
        "name": "PR workflow",
        "on": "pull_request",
        "jobs": {},
    }
    if perms is not None:
        wf["permissions"] = perms
    return wf


def _workflow_with_step(step: dict, perms=None):
    """Workflow containing a single step in a single job."""
    wf = {
        "name": "test",
        "on": "push",
        "jobs": {
            "job1": {
                "runs-on": "ubuntu-latest",
                "steps": [step],
            }
        },
    }
    if perms is not None:
        wf["permissions"] = perms
    return wf


def _check_ids(result: GHPResult):
    """Return the set of check IDs that fired."""
    return {f.check_id for f in result.findings}


# ===========================================================================
# Section 1 — GHP-001: write-all at workflow level
# ===========================================================================

def test_ghp001_fires_on_write_all():
    wf = _workflow_with_perms("write-all")
    result = analyze(wf)
    assert "GHP-001" in _check_ids(result)


def test_ghp001_severity_is_critical():
    wf = _workflow_with_perms("write-all")
    result = analyze(wf)
    finding = next(f for f in result.findings if f.check_id == "GHP-001")
    assert finding.severity == "CRITICAL"


def test_ghp001_weight_is_45():
    wf = _workflow_with_perms("write-all")
    result = analyze(wf)
    finding = next(f for f in result.findings if f.check_id == "GHP-001")
    assert finding.weight == 45


def test_ghp001_does_not_fire_on_read_all():
    wf = _workflow_with_perms("read-all")
    result = analyze(wf)
    assert "GHP-001" not in _check_ids(result)


def test_ghp001_does_not_fire_on_dict_perms():
    wf = _workflow_with_perms({"contents": "write"})
    result = analyze(wf)
    assert "GHP-001" not in _check_ids(result)


def test_ghp001_does_not_fire_when_perms_missing():
    wf = _workflow_no_perms()
    result = analyze(wf)
    assert "GHP-001" not in _check_ids(result)


def test_ghp001_suppresses_ghp002():
    # When write-all fires, GHP-002 must NOT fire (permissions key IS present)
    wf = _workflow_with_perms("write-all")
    result = analyze(wf)
    assert "GHP-002" not in _check_ids(result)


def test_ghp001_risk_score_at_least_45():
    wf = _workflow_with_perms("write-all")
    result = analyze(wf)
    assert result.risk_score >= 45


def test_ghp001_finding_has_non_empty_detail():
    wf = _workflow_with_perms("write-all")
    result = analyze(wf)
    finding = next(f for f in result.findings if f.check_id == "GHP-001")
    assert len(finding.detail) > 0


def test_ghp001_finding_has_title():
    wf = _workflow_with_perms("write-all")
    result = analyze(wf)
    finding = next(f for f in result.findings if f.check_id == "GHP-001")
    assert len(finding.title) > 0


# ===========================================================================
# Section 2 — GHP-002: no top-level permissions block
# ===========================================================================

def test_ghp002_fires_when_permissions_key_absent():
    wf = _workflow_no_perms()
    result = analyze(wf)
    assert "GHP-002" in _check_ids(result)


def test_ghp002_severity_is_high():
    wf = _workflow_no_perms()
    result = analyze(wf)
    finding = next(f for f in result.findings if f.check_id == "GHP-002")
    assert finding.severity == "HIGH"


def test_ghp002_weight_is_25():
    wf = _workflow_no_perms()
    result = analyze(wf)
    finding = next(f for f in result.findings if f.check_id == "GHP-002")
    assert finding.weight == 25


def test_ghp002_does_not_fire_with_empty_dict_perms():
    wf = _workflow_with_perms({})
    result = analyze(wf)
    assert "GHP-002" not in _check_ids(result)


def test_ghp002_does_not_fire_with_read_all():
    wf = _workflow_with_perms("read-all")
    result = analyze(wf)
    assert "GHP-002" not in _check_ids(result)


def test_ghp002_does_not_fire_with_dict_perms():
    wf = _workflow_with_perms({"contents": "read"})
    result = analyze(wf)
    assert "GHP-002" not in _check_ids(result)


def test_ghp002_does_not_fire_on_write_all_because_ghp001_suppresses():
    wf = _workflow_with_perms("write-all")
    result = analyze(wf)
    assert "GHP-002" not in _check_ids(result)


def test_ghp002_risk_score_is_25_alone():
    wf = {"name": "t", "on": "push", "jobs": {}}
    result = analyze(wf)
    # Only GHP-002 should fire; others depend on specific perms / triggers
    assert result.risk_score == 25


def test_ghp002_detail_mentions_permissions():
    wf = _workflow_no_perms()
    result = analyze(wf)
    finding = next(f for f in result.findings if f.check_id == "GHP-002")
    assert "permissions" in finding.detail.lower()


def test_ghp002_no_findings_on_clean_workflow():
    wf = _minimal_clean_workflow()
    result = analyze(wf)
    assert "GHP-002" not in _check_ids(result)


# ===========================================================================
# Section 3 — GHP-003: contents:write on PR-triggered workflow
# ===========================================================================

def test_ghp003_fires_on_pull_request_trigger_with_contents_write():
    wf = _workflow_pr_trigger(perms={"contents": "write"})
    result = analyze(wf)
    assert "GHP-003" in _check_ids(result)


def test_ghp003_fires_on_pull_request_target_with_contents_write():
    wf = {
        "name": "t",
        "on": "pull_request_target",
        "permissions": {"contents": "write"},
        "jobs": {},
    }
    result = analyze(wf)
    assert "GHP-003" in _check_ids(result)


def test_ghp003_fires_when_trigger_is_list():
    wf = {
        "name": "t",
        "on": ["push", "pull_request"],
        "permissions": {"contents": "write"},
        "jobs": {},
    }
    result = analyze(wf)
    assert "GHP-003" in _check_ids(result)


def test_ghp003_fires_when_trigger_is_dict():
    wf = {
        "name": "t",
        "on": {"pull_request": {"branches": ["main"]}, "push": {}},
        "permissions": {"contents": "write"},
        "jobs": {},
    }
    result = analyze(wf)
    assert "GHP-003" in _check_ids(result)


def test_ghp003_does_not_fire_on_push_only():
    wf = _workflow_with_perms({"contents": "write"})
    wf["on"] = "push"
    result = analyze(wf)
    assert "GHP-003" not in _check_ids(result)


def test_ghp003_does_not_fire_with_contents_read():
    wf = _workflow_pr_trigger(perms={"contents": "read"})
    result = analyze(wf)
    assert "GHP-003" not in _check_ids(result)


def test_ghp003_severity_is_high():
    wf = _workflow_pr_trigger(perms={"contents": "write"})
    result = analyze(wf)
    finding = next(f for f in result.findings if f.check_id == "GHP-003")
    assert finding.severity == "HIGH"


def test_ghp003_weight_is_25():
    wf = _workflow_pr_trigger(perms={"contents": "write"})
    result = analyze(wf)
    finding = next(f for f in result.findings if f.check_id == "GHP-003")
    assert finding.weight == 25


def test_ghp003_does_not_fire_when_no_permissions_key():
    # No permissions key means GHP-002 fires, but GHP-003 needs an explicit perm
    wf = {"name": "t", "on": "pull_request", "jobs": {}}
    result = analyze(wf)
    assert "GHP-003" not in _check_ids(result)


def test_ghp003_fires_on_per_job_contents_write_with_pr_trigger():
    wf = {
        "name": "t",
        "on": "pull_request",
        "permissions": {},
        "jobs": {
            "deploy": {
                "runs-on": "ubuntu-latest",
                "permissions": {"contents": "write"},
                "steps": [],
            }
        },
    }
    result = analyze(wf)
    assert "GHP-003" in _check_ids(result)


def test_ghp003_detail_mentions_pull_request():
    wf = _workflow_pr_trigger(perms={"contents": "write"})
    result = analyze(wf)
    finding = next(f for f in result.findings if f.check_id == "GHP-003")
    assert "pull_request" in finding.detail.lower() or "pull request" in finding.detail.lower()


# ===========================================================================
# Section 4 — GHP-004: id-token:write present
# ===========================================================================

def test_ghp004_fires_on_workflow_level_id_token_write():
    wf = _workflow_with_perms({"id-token": "write"})
    result = analyze(wf)
    assert "GHP-004" in _check_ids(result)


def test_ghp004_fires_on_job_level_id_token_write():
    wf = {
        "name": "t",
        "on": "push",
        "permissions": {},
        "jobs": {
            "deploy": {
                "runs-on": "ubuntu-latest",
                "permissions": {"id-token": "write"},
                "steps": [],
            }
        },
    }
    result = analyze(wf)
    assert "GHP-004" in _check_ids(result)


def test_ghp004_does_not_fire_on_id_token_read():
    wf = _workflow_with_perms({"id-token": "read"})
    result = analyze(wf)
    assert "GHP-004" not in _check_ids(result)


def test_ghp004_does_not_fire_on_id_token_none():
    wf = _workflow_with_perms({"id-token": "none"})
    result = analyze(wf)
    assert "GHP-004" not in _check_ids(result)


def test_ghp004_severity_is_medium():
    wf = _workflow_with_perms({"id-token": "write"})
    result = analyze(wf)
    finding = next(f for f in result.findings if f.check_id == "GHP-004")
    assert finding.severity == "MEDIUM"


def test_ghp004_weight_is_15():
    wf = _workflow_with_perms({"id-token": "write"})
    result = analyze(wf)
    finding = next(f for f in result.findings if f.check_id == "GHP-004")
    assert finding.weight == 15


def test_ghp004_does_not_fire_on_clean_workflow():
    wf = _minimal_clean_workflow()
    result = analyze(wf)
    assert "GHP-004" not in _check_ids(result)


def test_ghp004_detail_mentions_oidc():
    wf = _workflow_with_perms({"id-token": "write"})
    result = analyze(wf)
    finding = next(f for f in result.findings if f.check_id == "GHP-004")
    assert "oidc" in finding.detail.lower() or "id-token" in finding.detail.lower()


def test_ghp004_fires_once_even_with_multiple_jobs():
    # Even if two jobs have id-token:write, only one finding should be emitted
    wf = {
        "name": "t",
        "on": "push",
        "permissions": {},
        "jobs": {
            "job1": {"runs-on": "ubuntu-latest", "permissions": {"id-token": "write"}, "steps": []},
            "job2": {"runs-on": "ubuntu-latest", "permissions": {"id-token": "write"}, "steps": []},
        },
    }
    result = analyze(wf)
    count = sum(1 for f in result.findings if f.check_id == "GHP-004")
    assert count == 1


# ===========================================================================
# Section 5 — GHP-005: secrets:inherit in uses: step
# ===========================================================================

def test_ghp005_fires_on_secrets_inherit_in_uses_step():
    step = {"uses": "org/repo/.github/workflows/deploy.yml@main", "with": {"secrets": "inherit"}}
    wf = _workflow_with_step(step, perms={"contents": "read"})
    result = analyze(wf)
    assert "GHP-005" in _check_ids(result)


def test_ghp005_does_not_fire_when_no_uses_key():
    # A run step with secrets:inherit in with should NOT fire (not a reusable workflow call)
    step = {"run": "echo hello", "with": {"secrets": "inherit"}}
    wf = _workflow_with_step(step, perms={"contents": "read"})
    result = analyze(wf)
    assert "GHP-005" not in _check_ids(result)


def test_ghp005_does_not_fire_on_uses_step_without_secrets_inherit():
    step = {"uses": "actions/checkout@v4", "with": {"ref": "main"}}
    wf = _workflow_with_step(step, perms={"contents": "read"})
    result = analyze(wf)
    assert "GHP-005" not in _check_ids(result)


def test_ghp005_does_not_fire_on_uses_step_with_no_with_block():
    step = {"uses": "actions/checkout@v4"}
    wf = _workflow_with_step(step, perms={"contents": "read"})
    result = analyze(wf)
    assert "GHP-005" not in _check_ids(result)


def test_ghp005_does_not_fire_when_secrets_value_is_not_inherit():
    step = {"uses": "org/repo/.github/workflows/ci.yml@main", "with": {"secrets": "MY_SECRET"}}
    wf = _workflow_with_step(step, perms={"contents": "read"})
    result = analyze(wf)
    assert "GHP-005" not in _check_ids(result)


def test_ghp005_severity_is_high():
    step = {"uses": "org/repo/.github/workflows/deploy.yml@main", "with": {"secrets": "inherit"}}
    wf = _workflow_with_step(step, perms={"contents": "read"})
    result = analyze(wf)
    finding = next(f for f in result.findings if f.check_id == "GHP-005")
    assert finding.severity == "HIGH"


def test_ghp005_weight_is_25():
    step = {"uses": "org/repo/.github/workflows/deploy.yml@main", "with": {"secrets": "inherit"}}
    wf = _workflow_with_step(step, perms={"contents": "read"})
    result = analyze(wf)
    finding = next(f for f in result.findings if f.check_id == "GHP-005")
    assert finding.weight == 25


def test_ghp005_fires_once_even_with_multiple_matching_steps():
    steps = [
        {"uses": "org/repo/.github/workflows/a.yml@main", "with": {"secrets": "inherit"}},
        {"uses": "org/repo/.github/workflows/b.yml@main", "with": {"secrets": "inherit"}},
    ]
    wf = {
        "name": "t",
        "on": "push",
        "permissions": {"contents": "read"},
        "jobs": {
            "job1": {"runs-on": "ubuntu-latest", "steps": steps}
        },
    }
    result = analyze(wf)
    count = sum(1 for f in result.findings if f.check_id == "GHP-005")
    assert count == 1


def test_ghp005_detail_mentions_secrets():
    step = {"uses": "org/repo/.github/workflows/deploy.yml@main", "with": {"secrets": "inherit"}}
    wf = _workflow_with_step(step, perms={"contents": "read"})
    result = analyze(wf)
    finding = next(f for f in result.findings if f.check_id == "GHP-005")
    assert "secrets" in finding.detail.lower()


def test_ghp005_fires_when_uses_step_has_named_step():
    step = {
        "name": "Call deploy workflow",
        "uses": "org/repo/.github/workflows/deploy.yml@main",
        "with": {"secrets": "inherit"},
    }
    wf = _workflow_with_step(step, perms={"contents": "read"})
    result = analyze(wf)
    assert "GHP-005" in _check_ids(result)


# ===========================================================================
# Section 6 — GHP-006: pull-requests:write
# ===========================================================================

def test_ghp006_fires_on_workflow_level_pull_requests_write():
    wf = _workflow_with_perms({"pull-requests": "write"})
    result = analyze(wf)
    assert "GHP-006" in _check_ids(result)


def test_ghp006_fires_on_job_level_pull_requests_write():
    wf = {
        "name": "t",
        "on": "push",
        "permissions": {},
        "jobs": {
            "pr-bot": {
                "runs-on": "ubuntu-latest",
                "permissions": {"pull-requests": "write"},
                "steps": [],
            }
        },
    }
    result = analyze(wf)
    assert "GHP-006" in _check_ids(result)


def test_ghp006_does_not_fire_on_pull_requests_read():
    wf = _workflow_with_perms({"pull-requests": "read"})
    result = analyze(wf)
    assert "GHP-006" not in _check_ids(result)


def test_ghp006_severity_is_high():
    wf = _workflow_with_perms({"pull-requests": "write"})
    result = analyze(wf)
    finding = next(f for f in result.findings if f.check_id == "GHP-006")
    assert finding.severity == "HIGH"


def test_ghp006_weight_is_20():
    wf = _workflow_with_perms({"pull-requests": "write"})
    result = analyze(wf)
    finding = next(f for f in result.findings if f.check_id == "GHP-006")
    assert finding.weight == 20


def test_ghp006_does_not_fire_on_clean_workflow():
    wf = _minimal_clean_workflow()
    result = analyze(wf)
    assert "GHP-006" not in _check_ids(result)


def test_ghp006_fires_once_even_with_multiple_jobs():
    wf = {
        "name": "t",
        "on": "push",
        "permissions": {},
        "jobs": {
            "job1": {"runs-on": "ubuntu-latest", "permissions": {"pull-requests": "write"}, "steps": []},
            "job2": {"runs-on": "ubuntu-latest", "permissions": {"pull-requests": "write"}, "steps": []},
        },
    }
    result = analyze(wf)
    count = sum(1 for f in result.findings if f.check_id == "GHP-006")
    assert count == 1


def test_ghp006_detail_mentions_pull_requests():
    wf = _workflow_with_perms({"pull-requests": "write"})
    result = analyze(wf)
    finding = next(f for f in result.findings if f.check_id == "GHP-006")
    assert "pull" in finding.detail.lower()


# ===========================================================================
# Section 7 — GHP-007: packages:write
# ===========================================================================

def test_ghp007_fires_on_workflow_level_packages_write():
    wf = _workflow_with_perms({"packages": "write"})
    result = analyze(wf)
    assert "GHP-007" in _check_ids(result)


def test_ghp007_fires_on_job_level_packages_write():
    wf = {
        "name": "t",
        "on": "push",
        "permissions": {},
        "jobs": {
            "publish": {
                "runs-on": "ubuntu-latest",
                "permissions": {"packages": "write"},
                "steps": [],
            }
        },
    }
    result = analyze(wf)
    assert "GHP-007" in _check_ids(result)


def test_ghp007_does_not_fire_on_packages_read():
    wf = _workflow_with_perms({"packages": "read"})
    result = analyze(wf)
    assert "GHP-007" not in _check_ids(result)


def test_ghp007_severity_is_medium():
    wf = _workflow_with_perms({"packages": "write"})
    result = analyze(wf)
    finding = next(f for f in result.findings if f.check_id == "GHP-007")
    assert finding.severity == "MEDIUM"


def test_ghp007_weight_is_15():
    wf = _workflow_with_perms({"packages": "write"})
    result = analyze(wf)
    finding = next(f for f in result.findings if f.check_id == "GHP-007")
    assert finding.weight == 15


def test_ghp007_does_not_fire_on_clean_workflow():
    wf = _minimal_clean_workflow()
    result = analyze(wf)
    assert "GHP-007" not in _check_ids(result)


def test_ghp007_fires_once_even_with_multiple_jobs():
    wf = {
        "name": "t",
        "on": "push",
        "permissions": {},
        "jobs": {
            "job1": {"runs-on": "ubuntu-latest", "permissions": {"packages": "write"}, "steps": []},
            "job2": {"runs-on": "ubuntu-latest", "permissions": {"packages": "write"}, "steps": []},
        },
    }
    result = analyze(wf)
    count = sum(1 for f in result.findings if f.check_id == "GHP-007")
    assert count == 1


def test_ghp007_detail_mentions_packages():
    wf = _workflow_with_perms({"packages": "write"})
    result = analyze(wf)
    finding = next(f for f in result.findings if f.check_id == "GHP-007")
    assert "packages" in finding.detail.lower()


# ===========================================================================
# Section 8 — Risk score and permissions score calculations
# ===========================================================================

def test_risk_score_is_zero_on_clean_workflow():
    wf = _minimal_clean_workflow()
    result = analyze(wf)
    assert result.risk_score == 0


def test_permissions_score_is_100_on_clean_workflow():
    wf = _minimal_clean_workflow()
    result = analyze(wf)
    assert result.permissions_score == 100


def test_risk_score_capped_at_100():
    # write-all(45) + id-token:write(15) + pull-requests:write(20) + packages:write(15)
    # + secrets:inherit(25) = 120 > 100 → should cap at 100
    step = {"uses": "org/repo/.github/workflows/a.yml@main", "with": {"secrets": "inherit"}}
    wf = {
        "name": "t",
        "on": "push",
        "permissions": "write-all",
        "jobs": {
            "job1": {
                "runs-on": "ubuntu-latest",
                "permissions": {
                    "id-token": "write",
                    "pull-requests": "write",
                    "packages": "write",
                },
                "steps": [step],
            }
        },
    }
    result = analyze(wf)
    assert result.risk_score == 100


def test_permissions_score_is_zero_when_risk_is_100():
    step = {"uses": "org/repo/.github/workflows/a.yml@main", "with": {"secrets": "inherit"}}
    wf = {
        "name": "t",
        "on": "push",
        "permissions": "write-all",
        "jobs": {
            "job1": {
                "runs-on": "ubuntu-latest",
                "permissions": {
                    "id-token": "write",
                    "pull-requests": "write",
                    "packages": "write",
                },
                "steps": [step],
            }
        },
    }
    result = analyze(wf)
    assert result.permissions_score == 0


def test_risk_score_equals_sum_of_weights_when_below_100():
    # GHP-006 (20) + GHP-007 (15) + GHP-002 fires? No — permissions key IS present.
    # Let's use GHP-006(20) + GHP-007(15) = 35
    wf = _workflow_with_perms({"pull-requests": "write", "packages": "write"})
    result = analyze(wf)
    assert result.risk_score == 35
    assert result.permissions_score == 65


def test_permissions_score_plus_risk_equals_100_or_less():
    wf = _workflow_with_perms({"id-token": "write", "packages": "write"})
    result = analyze(wf)
    assert result.risk_score + result.permissions_score == 100


def test_risk_score_ghp002_alone():
    wf = _workflow_no_perms()
    result = analyze(wf)
    assert result.risk_score == 25
    assert result.permissions_score == 75


def test_risk_score_ghp001_alone():
    # GHP-001 fires, GHP-002 suppressed
    wf = {"name": "t", "on": "push", "permissions": "write-all", "jobs": {}}
    result = analyze(wf)
    assert result.risk_score == 45
    assert result.permissions_score == 55


# ===========================================================================
# Section 9 — GHPResult helper methods
# ===========================================================================

def test_to_dict_contains_all_keys():
    wf = _minimal_clean_workflow()
    result = analyze(wf, workflow_name="ci.yml")
    d = result.to_dict()
    assert "workflow_name" in d
    assert "risk_score" in d
    assert "permissions_score" in d
    assert "findings" in d


def test_to_dict_findings_is_list():
    wf = _workflow_with_perms({"packages": "write"})
    result = analyze(wf, workflow_name="publish.yml")
    d = result.to_dict()
    assert isinstance(d["findings"], list)


def test_to_dict_finding_has_required_keys():
    wf = _workflow_with_perms({"packages": "write"})
    result = analyze(wf, workflow_name="publish.yml")
    d = result.to_dict()
    finding = d["findings"][0]
    for key in ("check_id", "severity", "title", "detail", "weight"):
        assert key in finding


def test_to_dict_zero_findings_on_clean():
    wf = _minimal_clean_workflow()
    d = analyze(wf).to_dict()
    assert d["findings"] == []


def test_summary_contains_workflow_name():
    wf = _minimal_clean_workflow()
    result = analyze(wf, workflow_name="my-workflow.yml")
    assert "my-workflow.yml" in result.summary()


def test_summary_contains_risk_score():
    wf = _minimal_clean_workflow()
    result = analyze(wf)
    assert "0" in result.summary()


def test_summary_contains_findings_count():
    wf = _workflow_with_perms({"packages": "write"})
    result = analyze(wf)
    assert "findings=1" in result.summary()


def test_by_severity_groups_correctly():
    wf = {
        "name": "t",
        "on": "push",
        "permissions": {"packages": "write", "pull-requests": "write"},
        "jobs": {},
    }
    result = analyze(wf)
    groups = result.by_severity()
    # Both are distinct severities in this case: GHP-006=HIGH, GHP-007=MEDIUM
    assert "HIGH" in groups
    assert "MEDIUM" in groups


def test_by_severity_returns_dict():
    wf = _minimal_clean_workflow()
    groups = analyze(wf).by_severity()
    assert isinstance(groups, dict)


def test_by_severity_empty_on_clean():
    wf = _minimal_clean_workflow()
    groups = analyze(wf).by_severity()
    assert groups == {}


def test_by_severity_critical_on_write_all():
    wf = _workflow_with_perms("write-all")
    groups = analyze(wf).by_severity()
    assert "CRITICAL" in groups
    assert any(f.check_id == "GHP-001" for f in groups["CRITICAL"])


def test_workflow_name_stored_correctly():
    wf = _minimal_clean_workflow()
    result = analyze(wf, workflow_name="special-name.yml")
    assert result.workflow_name == "special-name.yml"


def test_default_workflow_name():
    wf = _minimal_clean_workflow()
    result = analyze(wf)
    assert result.workflow_name == "workflow"


# ===========================================================================
# Section 10 — Helper functions: _has_pr_trigger and _collect_all_permissions
# ===========================================================================

def test_has_pr_trigger_string_pull_request():
    assert _has_pr_trigger({"on": "pull_request"}) is True


def test_has_pr_trigger_string_pull_request_target():
    assert _has_pr_trigger({"on": "pull_request_target"}) is True


def test_has_pr_trigger_string_push_false():
    assert _has_pr_trigger({"on": "push"}) is False


def test_has_pr_trigger_list_with_pull_request():
    assert _has_pr_trigger({"on": ["push", "pull_request"]}) is True


def test_has_pr_trigger_list_without_pr():
    assert _has_pr_trigger({"on": ["push", "workflow_dispatch"]}) is False


def test_has_pr_trigger_dict_with_pull_request_target():
    assert _has_pr_trigger({"on": {"pull_request_target": {}, "push": {}}}) is True


def test_has_pr_trigger_dict_without_pr():
    assert _has_pr_trigger({"on": {"push": {}, "schedule": []}}) is False


def test_has_pr_trigger_missing_on_key():
    assert _has_pr_trigger({}) is False


def test_collect_all_permissions_workflow_level():
    wf = _workflow_with_perms({"contents": "write", "packages": "read"})
    perms = _collect_all_permissions(wf)
    scopes = {p.scope for p in perms}
    assert "contents" in scopes
    assert "packages" in scopes


def test_collect_all_permissions_job_level():
    wf = {
        "name": "t",
        "on": "push",
        "permissions": {},
        "jobs": {
            "job1": {"runs-on": "ubuntu-latest", "permissions": {"id-token": "write"}, "steps": []},
        },
    }
    perms = _collect_all_permissions(wf)
    job_perms = [p for p in perms if p.location.startswith("job:")]
    assert len(job_perms) == 1
    assert job_perms[0].scope == "id-token"
    assert job_perms[0].level == "write"


def test_collect_all_permissions_returns_empty_on_string_perms():
    # "write-all" is a string, not a dict — no WorkflowPermission objects expected
    wf = _workflow_with_perms("write-all")
    perms = _collect_all_permissions(wf)
    assert perms == []


def test_collect_all_permissions_location_prefix_for_job():
    wf = {
        "name": "t",
        "on": "push",
        "permissions": {},
        "jobs": {
            "my-job": {"runs-on": "ubuntu-latest", "permissions": {"packages": "write"}, "steps": []},
        },
    }
    perms = _collect_all_permissions(wf)
    job_perm = next(p for p in perms if p.location.startswith("job:"))
    assert job_perm.location == "job:my-job"


def test_collect_all_permissions_workflow_location_label():
    wf = _workflow_with_perms({"contents": "read"})
    perms = _collect_all_permissions(wf)
    wf_perms = [p for p in perms if p.location == "workflow"]
    assert len(wf_perms) == 1


# ===========================================================================
# Section 11 — analyze_many
# ===========================================================================

def test_analyze_many_returns_list():
    results = analyze_many([_minimal_clean_workflow(), _workflow_no_perms()])
    assert isinstance(results, list)
    assert len(results) == 2


def test_analyze_many_uses_provided_names():
    results = analyze_many(
        [_minimal_clean_workflow(), _workflow_no_perms()],
        names=["clean.yml", "noперms.yml"],
    )
    assert results[0].workflow_name == "clean.yml"
    assert results[1].workflow_name == "noперms.yml"


def test_analyze_many_fallback_names():
    results = analyze_many([_minimal_clean_workflow(), _workflow_no_perms()])
    assert results[0].workflow_name == "workflow-0"
    assert results[1].workflow_name == "workflow-1"


def test_analyze_many_partial_names_list():
    # Only one name provided for two workflows — second should fall back
    results = analyze_many(
        [_minimal_clean_workflow(), _workflow_no_perms()],
        names=["first.yml"],
    )
    assert results[0].workflow_name == "first.yml"
    assert results[1].workflow_name == "workflow-1"


def test_analyze_many_empty_input():
    results = analyze_many([])
    assert results == []


def test_analyze_many_preserves_order():
    wf1 = _workflow_with_perms("write-all")
    wf2 = _minimal_clean_workflow()
    results = analyze_many([wf1, wf2], names=["a.yml", "b.yml"])
    assert "GHP-001" in _check_ids(results[0])
    assert "GHP-001" not in _check_ids(results[1])


def test_analyze_many_names_none_default():
    results = analyze_many([_minimal_clean_workflow()], names=None)
    assert results[0].workflow_name == "workflow-0"


# ===========================================================================
# Section 12 — Edge cases and combined scenarios
# ===========================================================================

def test_empty_workflow_dict():
    # Completely empty dict — should not raise; GHP-002 fires (no permissions key)
    result = analyze({})
    assert "GHP-002" in _check_ids(result)


def test_workflow_with_none_jobs():
    wf = {"name": "t", "on": "push", "permissions": {"contents": "read"}, "jobs": None}
    result = analyze(wf)
    assert result.risk_score == 0


def test_workflow_with_empty_jobs_dict():
    wf = {"name": "t", "on": "push", "permissions": {}, "jobs": {}}
    result = analyze(wf)
    assert result.risk_score == 0


def test_multiple_checks_fire_simultaneously():
    step = {"uses": "org/repo/.github/workflows/deploy.yml@main", "with": {"secrets": "inherit"}}
    wf = {
        "name": "t",
        "on": "pull_request",
        "permissions": {
            "contents": "write",
            "id-token": "write",
            "pull-requests": "write",
            "packages": "write",
        },
        "jobs": {
            "job1": {"runs-on": "ubuntu-latest", "steps": [step]},
        },
    }
    result = analyze(wf)
    ids = _check_ids(result)
    # GHP-003, GHP-004, GHP-005, GHP-006, GHP-007 must all fire
    assert "GHP-003" in ids
    assert "GHP-004" in ids
    assert "GHP-005" in ids
    assert "GHP-006" in ids
    assert "GHP-007" in ids


def test_ghp002_and_ghp005_can_fire_together():
    step = {"uses": "org/repo/.github/workflows/deploy.yml@main", "with": {"secrets": "inherit"}}
    wf = {
        "name": "t",
        "on": "push",
        "jobs": {
            "job1": {"runs-on": "ubuntu-latest", "steps": [step]},
        },
    }
    result = analyze(wf)
    ids = _check_ids(result)
    assert "GHP-002" in ids
    assert "GHP-005" in ids


def test_no_findings_on_fully_locked_down_workflow():
    wf = {
        "name": "CI",
        "on": {"push": {"branches": ["main"]}},
        "permissions": {
            "contents": "read",
            "id-token": "none",
            "pull-requests": "read",
            "packages": "read",
        },
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {"name": "checkout", "uses": "actions/checkout@v4"},
                    {"name": "build", "run": "make build"},
                ],
            }
        },
    }
    result = analyze(wf)
    assert result.findings == []
    assert result.risk_score == 0
    assert result.permissions_score == 100


def test_check_weights_dict_has_all_seven_checks():
    expected = {"GHP-001", "GHP-002", "GHP-003", "GHP-004", "GHP-005", "GHP-006", "GHP-007"}
    assert set(_CHECK_WEIGHTS.keys()) == expected


def test_dataclass_workflowpermission_fields():
    wp = WorkflowPermission(scope="contents", level="write", location="workflow")
    assert wp.scope == "contents"
    assert wp.level == "write"
    assert wp.location == "workflow"


def test_dataclass_ghpfinding_fields():
    f = GHPFinding(
        check_id="GHP-001",
        severity="CRITICAL",
        title="Test title",
        detail="Test detail",
        weight=45,
    )
    assert f.check_id == "GHP-001"
    assert f.severity == "CRITICAL"
    assert f.weight == 45


def test_ghpresult_dataclass_fields():
    result = GHPResult(
        workflow_name="test.yml",
        findings=[],
        risk_score=0,
        permissions_score=100,
    )
    assert result.workflow_name == "test.yml"
    assert result.findings == []
    assert result.risk_score == 0
    assert result.permissions_score == 100


def test_on_as_list_with_only_pr_target():
    wf = {
        "name": "t",
        "on": ["pull_request_target"],
        "permissions": {"contents": "write"},
        "jobs": {},
    }
    result = analyze(wf)
    assert "GHP-003" in _check_ids(result)


def test_job_with_no_steps_key():
    wf = {
        "name": "t",
        "on": "push",
        "permissions": {"contents": "read"},
        "jobs": {
            "job1": {"runs-on": "ubuntu-latest"},
        },
    }
    # Should not raise; no step-based checks fire
    result = analyze(wf)
    assert result.risk_score == 0


def test_step_with_no_with_key_does_not_raise():
    step = {"uses": "actions/checkout@v4"}
    wf = _workflow_with_step(step, perms={"contents": "read"})
    result = analyze(wf)
    assert "GHP-005" not in _check_ids(result)


def test_workflow_name_in_to_dict():
    result = analyze(_minimal_clean_workflow(), workflow_name="edge-case.yml")
    assert result.to_dict()["workflow_name"] == "edge-case.yml"
