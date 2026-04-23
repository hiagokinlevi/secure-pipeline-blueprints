from __future__ import annotations

from pathlib import Path

import yaml


def _workflow_files() -> list[Path]:
    root = Path(__file__).resolve().parents[1]
    return sorted(root.glob("github-actions/**/*.yml")) + sorted(
        root.glob("github-actions/**/*.yaml")
    )


def _is_mapping(value: object) -> bool:
    return isinstance(value, dict)


def test_github_actions_workflows_require_explicit_least_privilege_permissions() -> None:
    failures: list[str] = []

    files = _workflow_files()
    assert files, "No GitHub Actions workflow files found under github-actions/**"

    for workflow_path in files:
        data = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
        if not _is_mapping(data):
            failures.append(f"{workflow_path}: invalid workflow YAML root")
            continue

        if "permissions" not in data:
            failures.append(
                f"{workflow_path}: missing explicit top-level permissions block"
            )
            continue

        permissions = data.get("permissions")

        if isinstance(permissions, str):
            normalized = permissions.strip().lower()
            if normalized in {"write-all", "read-all"}:
                failures.append(
                    f"{workflow_path}: top-level permissions must not use '{permissions}'"
                )
        elif _is_mapping(permissions):
            pass
        else:
            failures.append(
                f"{workflow_path}: top-level permissions must be a mapping or safe scalar"
            )

    assert not failures, "\n".join(failures)
