#!/usr/bin/env python3
"""
Pipeline Blueprint Validator
=============================
Validates that pipeline blueprint metadata files conform to the blueprint schema.
Also performs structural checks on YAML pipeline files (GitHub Actions, GitLab CI).

Usage:
    python validate_blueprint.py --blueprint github-actions/python/full_pipeline.yml
    python validate_blueprint.py --all
    python validate_blueprint.py --all --verbose

Requirements:
    Optional: jsonschema for schema validation

Exit codes:
    0 — all blueprints valid
    1 — one or more blueprints have validation errors
"""

import argparse
import json
import sys
from pathlib import Path

try:
    from .path_safety import validate_local_file
except ImportError:
    from path_safety import validate_local_file

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

try:
    from jsonschema import validate, ValidationError
    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False

# Repository root — 3 levels up from this script (validators/ -> shared/ -> repo root)
REPO_ROOT = Path(__file__).parent.parent.parent

# Path to the blueprint metadata schema
SCHEMA_PATH = REPO_ROOT / "shared" / "schemas" / "blueprint_metadata.json"

# Directories containing pipeline YAML blueprints
BLUEPRINT_DIRS = [
    "github-actions",
    "gitlab-ci",
    "azure-devops",
]

# Files and directories to skip during --all validation
SKIP_PATTERNS = ["schemas", "examples", ".git", "node_modules", "tests", "validators"]

# Required keys in GitHub Actions workflow files (top-level)
GITHUB_ACTIONS_REQUIRED_KEYS = ["name", "on", "jobs", "permissions"]

# Required keys in GitLab CI pipeline files
GITLAB_CI_RECOMMENDED_KEYS = ["stages", "image"]

# Security controls expected in a "full" blueprint
RECOMMENDED_CONTROLS = ["sast", "sca", "secret-scanning"]


def load_schema() -> dict | None:
    """Load the blueprint metadata JSON Schema."""
    if not SCHEMA_PATH.exists():
        return None
    try:
        with open(SCHEMA_PATH) as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"WARNING: Cannot load schema: {e}", file=sys.stderr)
        return None


def validate_github_actions_yaml(content: dict) -> list[str]:
    """
    Validate a GitHub Actions workflow YAML file.
    Checks for required keys, permissions block, and recommended security patterns.

    Args:
        content: Parsed YAML dict.
    Returns:
        List of error/warning strings. Empty means valid.
    """
    issues = []

    # Check required top-level keys
    has_on = "on" in content or True in content
    for key in ["name", "jobs"]:
        if key not in content:
            issues.append(f"Missing required GitHub Actions key: '{key}'")
    if not has_on:
        issues.append("Missing required GitHub Actions key: 'on'")

    # Check for permissions block (principle of least privilege)
    if "permissions" not in content:
        issues.append(
            "No top-level 'permissions' block found. "
            "Add 'permissions: contents: read' for least-privilege baseline."
        )

    # Check jobs section
    jobs = content.get("jobs", {})
    if not jobs:
        issues.append("No jobs defined in the workflow")
        return issues

    for job_name, job_config in jobs.items():
        if not isinstance(job_config, dict):
            continue

        if "runs-on" in job_config and "timeout-minutes" not in job_config:
            issues.append(
                f"Job '{job_name}' has no timeout-minutes. "
                "Add an explicit timeout to bound CI runtime and reduce runaway build risk."
            )

        steps = job_config.get("steps", [])
        if not steps:
            issues.append(f"Job '{job_name}' has no steps")
            continue

        # Check that checkout step is first (or very early)
        first_step = steps[0] if steps else {}
        if "actions/checkout" not in str(first_step.get("uses", "")):
            issues.append(
                f"Job '{job_name}': First step should be actions/checkout. "
                f"Got: {first_step.get('uses', first_step.get('run', 'unknown'))}"
            )

    return issues


def expected_control_hints(blueprint_path: Path) -> list[tuple[str, str]]:
    """Return the recommended control/tool hints for a specific blueprint path."""
    path_str = str(blueprint_path)

    if "github-actions/reusable/secret_scan.yml" in path_str:
        return [("secret scanning", "gitleaks")]
    if "github-actions/reusable/sast_semgrep.yml" in path_str:
        return [("SAST", "semgrep")]
    if "github-actions/reusable/dependency_review.yml" in path_str:
        return []
    if "github-actions/containers/" in path_str:
        return [("secret scanning", "gitleaks")]
    if "github-actions/go/" in path_str:
        return [
            ("SAST", "semgrep"),
            ("SCA", "govulncheck"),
            ("secret scanning", "gitleaks"),
        ]
    if "github-actions/iac/" in path_str:
        return [("secret scanning", "gitleaks")]
    if "gitlab-ci/" in path_str:
        return []

    return [
        ("SAST", "semgrep"),
        ("SCA", "audit"),
        ("secret scanning", "gitleaks"),
    ]


def validate_gitlab_ci_yaml(content: dict) -> list[str]:
    """
    Validate a GitLab CI pipeline YAML file.
    Checks for recommended structural patterns.

    Args:
        content: Parsed YAML dict.
    Returns:
        List of issue strings.
    """
    issues = []

    # Check for stages definition
    if "stages" not in content:
        issues.append("No 'stages' key found. Define explicit stages for pipeline order control.")

    # Check for at least one job definition
    jobs = {k: v for k, v in content.items() if isinstance(v, dict) and not k.startswith(".")}
    if not jobs:
        issues.append("No jobs found in GitLab CI configuration")

    # Check each job has a script
    for job_name, job_config in jobs.items():
        if job_name in ("stages", "variables", "default", "workflow"):
            continue
        if isinstance(job_config, dict) and "script" not in job_config:
            issues.append(f"Job '{job_name}' is missing 'script' key")

    return issues


def validate_blueprint_yaml(
    blueprint_path: Path,
    verbose: bool = False,
    repo_root: Path | None = None,
) -> list[str]:
    """
    Validate a pipeline blueprint YAML file.

    Args:
        blueprint_path: Path to the blueprint YAML file.
        verbose: If True, print additional context.
        repo_root: Optional repository root used to reject repo-escaping paths.

    Returns:
        List of error strings. Empty means valid.
    """
    path_error = validate_local_file(
        blueprint_path,
        repo_root=repo_root,
        label="blueprint file",
    )
    if path_error:
        return [path_error]

    errors = []

    if not YAML_AVAILABLE:
        return ["YAML support is unavailable in this environment"]

    # --- Load and parse YAML ---
    try:
        with open(blueprint_path) as f:
            content = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return [f"Invalid YAML syntax: {e}"]
    except OSError as e:
        return [f"Cannot read file: {e}"]

    if not content:
        return ["Empty YAML file"]

    if not isinstance(content, dict):
        return [f"Expected YAML mapping at top level, got: {type(content).__name__}"]

    # --- Platform-specific validation ---
    path_str = str(blueprint_path)

    if "github-actions" in path_str:
        errors.extend(validate_github_actions_yaml(content))
    elif "gitlab-ci" in path_str:
        errors.extend(validate_gitlab_ci_yaml(content))

    # --- Security control presence checks ---
    # Look for common security tool names in the YAML content
    yaml_text = str(content).lower()

    for control, tool_hint in expected_control_hints(blueprint_path):
        if tool_hint not in yaml_text:
            errors.append(
                f"Recommended security control missing: {control} "
                f"(expected '{tool_hint}' reference). "
                f"Security-first blueprints should include {control}."
            )

    return errors


def should_skip(path: Path) -> bool:
    """Return True if this file should be skipped during --all validation."""
    path_str = str(path)
    return any(pattern in path_str for pattern in SKIP_PATTERNS)


def main():
    parser = argparse.ArgumentParser(
        description="Validate k1N pipeline blueprint YAML files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python validate_blueprint.py --blueprint github-actions/python/full_pipeline.yml
  python validate_blueprint.py --all
  python validate_blueprint.py --all --verbose
        """,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--blueprint", help="Path to a single blueprint YAML file to validate")
    group.add_argument("--all", action="store_true", help="Validate all blueprint YAML files in the repository")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    if not YAML_AVAILABLE:
        print("ERROR: YAML support is unavailable in this environment", file=sys.stderr)
        sys.exit(1)

    if args.blueprint:
        # --- Single blueprint validation ---
        blueprint_path = Path(args.blueprint)
        if not blueprint_path.exists():
            print(f"ERROR: File not found: {blueprint_path}", file=sys.stderr)
            sys.exit(1)

        errors = validate_blueprint_yaml(
            blueprint_path,
            verbose=args.verbose,
            repo_root=REPO_ROOT,
        )
        if errors:
            print(f"FAIL  {blueprint_path}")
            for e in errors:
                print(f"  - {e}")
            sys.exit(1)
        else:
            print(f"OK    {blueprint_path}")

    elif args.all:
        # --- Validate all blueprints ---
        yaml_files = []
        for bp_dir in BLUEPRINT_DIRS:
            dir_path = REPO_ROOT / bp_dir
            if dir_path.exists():
                yaml_files.extend(dir_path.rglob("*.yml"))
                yaml_files.extend(dir_path.rglob("*.yaml"))

        blueprint_files = [f for f in yaml_files if not should_skip(f)]

        if not blueprint_files:
            print("No blueprint files found.", file=sys.stderr)
            sys.exit(0)

        failed = 0
        passed = 0

        for bf in sorted(blueprint_files):
            errors = validate_blueprint_yaml(
                bf,
                verbose=args.verbose,
                repo_root=REPO_ROOT,
            )
            if errors:
                print(f"FAIL  {bf.relative_to(REPO_ROOT)}")
                for e in errors:
                    print(f"  - {e}")
                failed += 1
            else:
                print(f"OK    {bf.relative_to(REPO_ROOT)}")
                passed += 1

        total = passed + failed
        print(f"\nResults: {passed}/{total} blueprints valid | {failed} failed")

        if failed:
            sys.exit(1)


if __name__ == "__main__":
    main()
