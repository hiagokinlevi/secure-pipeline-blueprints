import sys
from pathlib import Path


REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT))

import yaml


WORKFLOW_PATH = REPO_ROOT / "github-actions" / "go" / "full_pipeline.yml"


def _load_workflow() -> dict:
    with WORKFLOW_PATH.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _steps_for(workflow: dict, job_name: str) -> list[dict]:
    return workflow["jobs"][job_name]["steps"]


def test_go_github_actions_blueprint_exists():
    assert WORKFLOW_PATH.exists()


def test_go_blueprint_uses_least_privilege_permissions():
    workflow = _load_workflow()
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["jobs"]["sast"]["permissions"] == {
        "contents": "read",
        "security-events": "write",
    }


def test_go_blueprint_has_test_race_and_coverage_gate():
    workflow = _load_workflow()
    test_steps = _steps_for(workflow, "test")
    step_text = "\n".join(str(step) for step in test_steps).lower()

    assert "actions/checkout@v4" in test_steps[0]["uses"]
    assert "actions/setup-go@v5" in step_text
    assert "go vet ./..." in step_text
    assert "go test -race -covermode=atomic -coverprofile=coverage.out ./..." in step_text
    assert "coverage_threshold" in step_text


def test_go_blueprint_has_sast_sca_and_secret_scanning():
    workflow = _load_workflow()
    jobs = workflow["jobs"]

    sast_text = "\n".join(str(step) for step in _steps_for(workflow, "sast")).lower()
    sca_text = "\n".join(str(step) for step in _steps_for(workflow, "sca")).lower()
    secret_text = "\n".join(str(step) for step in _steps_for(workflow, "secret-scan")).lower()

    assert set(jobs) == {"test", "sast", "sca", "secret-scan"}
    assert "returntocorp/semgrep-action@v1" in sast_text
    assert "p/golang" in sast_text
    assert "golang/govulncheck-action@v1" in sca_text
    assert "gitleaks/gitleaks-action@v2" in secret_text
    assert "fetch-depth" in secret_text
