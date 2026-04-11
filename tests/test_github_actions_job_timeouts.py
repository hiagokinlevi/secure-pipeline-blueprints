import sys
from pathlib import Path


REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT))

import yaml


WORKFLOW_ROOT = REPO_ROOT / "github-actions"


def test_github_actions_runner_jobs_define_timeout_minutes():
    offenders = []
    for workflow_path in sorted(WORKFLOW_ROOT.rglob("*.yml")):
        with workflow_path.open(encoding="utf-8") as handle:
            workflow = yaml.safe_load(handle)
        for job_name, job in workflow.get("jobs", {}).items():
            if not isinstance(job, dict) or "runs-on" not in job:
                continue
            if "timeout-minutes" not in job:
                offenders.append(f"{workflow_path.relative_to(REPO_ROOT)}::{job_name}")

    assert not offenders, (
        "Each GitHub Actions runner job must set timeout-minutes: "
        + ", ".join(offenders)
    )
