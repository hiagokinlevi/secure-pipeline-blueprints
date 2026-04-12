import sys
from pathlib import Path


REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT))

import yaml


WORKFLOW_SPECS = {
    "python": {
        "path": REPO_ROOT / "github-actions" / "python" / "full_pipeline.yml",
        "top_permissions": {"contents": "read"},
        "job_permissions": {
            "sast": {"contents": "read", "security-events": "write"},
        },
    },
    "node": {
        "path": REPO_ROOT / "github-actions" / "node" / "full_pipeline.yml",
        "top_permissions": {"contents": "read"},
        "job_permissions": {
            "sast": {"contents": "read", "security-events": "write"},
        },
    },
    "go": {
        "path": REPO_ROOT / "github-actions" / "go" / "full_pipeline.yml",
        "top_permissions": {"contents": "read"},
        "job_permissions": {
            "sast": {"contents": "read", "security-events": "write"},
        },
    },
    "terraform": {
        "path": REPO_ROOT / "github-actions" / "iac" / "terraform_pipeline.yml",
        "top_permissions": {"contents": "read"},
        "job_permissions": {
            "checkov": {"contents": "read", "security-events": "write"},
            "tfsec": {"contents": "read", "security-events": "write"},
        },
    },
    "containers": {
        "path": REPO_ROOT / "github-actions" / "containers" / "container_scan.yml",
        "top_permissions": {"contents": "read"},
        "job_permissions": {
            "trivy-fs": {"contents": "read", "security-events": "write"},
            "build": {"contents": "read", "packages": "read"},
            "trivy-image": {
                "contents": "read",
                "packages": "read",
                "security-events": "write",
            },
        },
    },
}


def _load_workflow(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def test_blueprints_default_to_read_only_token_permissions():
    offenders = []

    for name, spec in WORKFLOW_SPECS.items():
        workflow = _load_workflow(spec["path"])
        if workflow.get("permissions") != spec["top_permissions"]:
            offenders.append(
                f"{name}={workflow.get('permissions')!r}"
            )

    assert not offenders, (
        "GitHub Actions blueprints should default to read-only workflow-level token scopes: "
        + ", ".join(offenders)
    )


def test_blueprints_scope_elevated_permissions_to_only_required_jobs():
    offenders = []

    for name, spec in WORKFLOW_SPECS.items():
        workflow = _load_workflow(spec["path"])
        jobs = workflow.get("jobs", {})
        for job_name, expected_permissions in spec["job_permissions"].items():
            actual_permissions = jobs.get(job_name, {}).get("permissions")
            if actual_permissions != expected_permissions:
                offenders.append(
                    f"{name}:{job_name}={actual_permissions!r}"
                )

    assert not offenders, (
        "Elevated token scopes must stay attached only to the jobs that need them: "
        + ", ".join(offenders)
    )
