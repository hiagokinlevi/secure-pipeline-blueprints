import sys
from pathlib import Path


REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT))

import yaml


WORKFLOW_PATH = REPO_ROOT / "github-actions" / "reusable" / "secret_scan.yml"


def _load_workflow() -> dict:
    with WORKFLOW_PATH.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def test_reusable_secret_scan_workflow_exists():
    assert WORKFLOW_PATH.exists()


def test_reusable_secret_scan_workflow_declares_inputs_and_required_github_token_secret():
    workflow = _load_workflow()
    workflow_call = workflow["on"]["workflow_call"]

    assert set(workflow_call["inputs"]) == {"fetch_depth", "config_path", "fail_on_leak"}
    assert workflow_call["secrets"] == {
        "GITHUB_TOKEN": {
            "description": "GitHub token required by Gitleaks action",
            "required": True,
        }
    }


def test_reusable_secret_scan_workflow_uses_least_privilege_permissions():
    workflow = _load_workflow()
    assert workflow.get("permissions") == {"contents": "read"}


def test_reusable_secret_scan_workflow_checkout_is_hardened():
    workflow = _load_workflow()
    checkout_step = workflow["jobs"]["gitleaks"]["steps"][0]

    assert checkout_step["uses"] == "actions/checkout@v4"
    assert checkout_step["with"]["fetch-depth"] == "${{ inputs.fetch_depth }}"
    assert checkout_step["with"]["persist-credentials"] is False


def test_reusable_secret_scan_workflow_uses_passed_github_token_only_in_scan_steps():
    workflow = _load_workflow()
    gitleaks_steps = [
        step
        for step in workflow["jobs"]["gitleaks"]["steps"]
        if step.get("id") in {"gitleaks-custom", "gitleaks-default"}
    ]

    assert len(gitleaks_steps) == 2
    for step in gitleaks_steps:
        assert step["env"]["GITHUB_TOKEN"] == "${{ secrets.GITHUB_TOKEN }}"


def test_reusable_secret_scan_workflow_fails_closed_by_default():
    workflow = _load_workflow()
    workflow_call = workflow["on"]["workflow_call"]
    fail_step = workflow["jobs"]["gitleaks"]["steps"][-1]

    assert workflow_call["inputs"]["fail_on_leak"]["default"] is True
    assert fail_step["name"] == "Fail job if secrets found and fail_on_leak is true"
    assert "inputs.fail_on_leak == true" in fail_step["if"]

