from pathlib import Path

import pytest

from yaml import load_yaml_file


REPO_ROOT = Path(__file__).resolve().parents[1]
REUSABLE_DIR = REPO_ROOT / "github-actions" / "reusable"


def _workflow_files():
    if not REUSABLE_DIR.exists():
        return []
    return sorted(
        p
        for p in REUSABLE_DIR.iterdir()
        if p.is_file() and p.suffix in {".yml", ".yaml"}
    )


def test_reusable_workflows_have_valid_workflow_call_contract():
    workflow_files = _workflow_files()
    assert workflow_files, "No reusable workflow files found under github-actions/reusable/"

    failures = []

    for wf_path in workflow_files:
        data = load_yaml_file(wf_path)
        if not isinstance(data, dict):
            failures.append(f"{wf_path}: workflow root must be a mapping")
            continue

        on_block = data.get("on")
        if not isinstance(on_block, dict):
            failures.append(f"{wf_path}: missing or invalid 'on' block")
            continue

        workflow_call = on_block.get("workflow_call")
        if not isinstance(workflow_call, dict):
            failures.append(f"{wf_path}: missing or invalid 'on.workflow_call' block")
            continue

        for key in ("inputs", "secrets"):
            if key not in workflow_call:
                failures.append(f"{wf_path}: 'on.workflow_call.{key}' key is required")
                continue
            if not isinstance(workflow_call[key], dict):
                failures.append(f"{wf_path}: 'on.workflow_call.{key}' must be a mapping")

        inputs = workflow_call.get("inputs", {})
        if isinstance(inputs, dict):
            for input_name, input_cfg in inputs.items():
                if not isinstance(input_cfg, dict):
                    failures.append(
                        f"{wf_path}: input '{input_name}' definition must be a mapping"
                    )
                    continue

                if "default" in input_cfg:
                    default_val = input_cfg["default"]
                    if isinstance(default_val, (dict, list, set, tuple)):
                        failures.append(
                            f"{wf_path}: input '{input_name}' has malformed default; "
                            "must be scalar/null"
                        )

    assert not failures, "\n" + "\n".join(failures)
