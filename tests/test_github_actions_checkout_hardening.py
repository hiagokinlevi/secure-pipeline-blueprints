import sys
from pathlib import Path


REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT))

import yaml


WORKFLOW_ROOT = REPO_ROOT / "github-actions"


def _iter_checkout_steps():
    for workflow_path in sorted(WORKFLOW_ROOT.rglob("*.yml")):
        with workflow_path.open(encoding="utf-8") as handle:
            workflow = yaml.safe_load(handle)
        for job_name, job in workflow.get("jobs", {}).items():
            for index, step in enumerate(job.get("steps", []), start=1):
                if step.get("uses") == "actions/checkout@v4":
                    yield workflow_path, job_name, index, step


def test_github_actions_checkouts_disable_persisted_credentials():
    offenders = []
    for workflow_path, job_name, index, step in _iter_checkout_steps():
        with_block = step.get("with", {})
        if with_block.get("persist-credentials") is not False:
            offenders.append(
                f"{workflow_path.relative_to(REPO_ROOT)}::{job_name}::step-{index}"
            )

    assert not offenders, (
        "Each actions/checkout@v4 step must set with.persist-credentials to false: "
        + ", ".join(offenders)
    )
