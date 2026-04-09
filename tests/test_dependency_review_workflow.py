import sys
from pathlib import Path


REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT))

import yaml


WORKFLOW_PATH = REPO_ROOT / "github-actions" / "reusable" / "dependency_review.yml"


def _load_workflow() -> dict:
    with WORKFLOW_PATH.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def test_dependency_review_workflow_exists():
    assert WORKFLOW_PATH.exists()


def test_dependency_review_workflow_is_pr_gated():
    workflow = _load_workflow()
    triggers = workflow.get("on", {})
    assert "pull_request" in triggers
    assert "workflow_call" in triggers


def test_dependency_review_workflow_uses_least_privilege_permissions():
    workflow = _load_workflow()
    permissions = workflow.get("permissions", {})
    assert permissions == {"contents": "read", "pull-requests": "write"}


def test_dependency_review_workflow_has_review_step():
    workflow = _load_workflow()
    steps = workflow["jobs"]["dependency-review"]["steps"]
    uses_values = [step.get("uses", "") for step in steps]
    assert "actions/checkout@v4" in uses_values
    assert "actions/dependency-review-action@v4" in uses_values


def test_dependency_review_workflow_fails_on_high_by_default():
    workflow = _load_workflow()
    review_step = workflow["jobs"]["dependency-review"]["steps"][1]
    with_block = review_step.get("with", {})
    assert with_block["fail-on-severity"] == "${{ inputs.fail_on_severity || 'high' }}"
    assert with_block["comment-summary-in-pr"] == "${{ inputs.comment_summary_in_pr }}"
