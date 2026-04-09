import sys
from pathlib import Path


REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT))

import yaml


WORKFLOW_PATH = REPO_ROOT / "github-actions" / "reusable" / "sast_semgrep.yml"


def _load_workflow() -> dict:
    with WORKFLOW_PATH.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def test_reusable_sast_workflow_exists():
    assert WORKFLOW_PATH.exists()


def test_reusable_sast_workflow_supports_pr_and_workflow_call():
    workflow = _load_workflow()
    triggers = workflow.get("on", {})
    assert "pull_request" in triggers
    assert "workflow_call" in triggers


def test_reusable_sast_workflow_uses_least_privilege_sarif_permissions():
    workflow = _load_workflow()
    assert workflow.get("permissions") == {
        "contents": "read",
        "security-events": "write",
    }


def test_reusable_sast_workflow_has_configurable_adoption_inputs():
    workflow = _load_workflow()
    inputs = workflow["on"]["workflow_call"]["inputs"]
    assert inputs["semgrep_config"]["default"] == "p/owasp-top-ten p/secrets"
    assert inputs["custom_config"]["default"] == ""
    assert inputs["fail_on_findings"]["default"] is True
    assert inputs["upload_sarif"]["default"] is True


def test_reusable_sast_workflow_runs_semgrep_and_uploads_sarif():
    workflow = _load_workflow()
    steps = workflow["jobs"]["semgrep"]["steps"]
    uses_values = [step.get("uses", "") for step in steps]
    assert "actions/checkout@v4" in uses_values
    assert "returntocorp/semgrep-action@v1" in uses_values
    assert "github/codeql-action/upload-sarif@v3" in uses_values

    semgrep_step = next(step for step in steps if step.get("id") == "semgrep")
    assert semgrep_step["continue-on-error"] == "${{ !inputs.fail_on_findings }}"
    assert semgrep_step["with"]["generateSarif"] == "1"
