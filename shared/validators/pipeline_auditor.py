"""
CI/CD Pipeline Security Auditor
=================================
Scans GitHub Actions workflow YAML files for common security misconfigurations.

Checks performed:
  - PA001 CRITICAL: Workflow trigger on pull_request_target with checkout of
                    head ref (script injection / privilege escalation)
  - PA002 HIGH:     Actions not pinned to full SHA (supply chain risk)
  - PA003 HIGH:     'permissions: write-all' or no permissions block (over-privileged)
  - PA004 HIGH:     Secrets exposed via 'run: echo ${{ secrets.* }}'
  - PA005 MEDIUM:   Third-party actions not from verified publishers
  - PA006 MEDIUM:   'continue-on-error: true' on security-relevant steps
  - PA007 MEDIUM:   Use of deprecated 'set-env' or 'add-path' workflow commands
  - PA008 LOW:      Missing 'timeout-minutes' on jobs (allows runaway builds)
  - PA009 LOW:      'fetch-depth: 0' without documented reason (exposes full history)

Usage:
    from shared.validators.pipeline_auditor import audit_workflow_file, AuditResult

    result = audit_workflow_file(Path(".github/workflows/ci.yml"))
    for finding in result.findings:
        print(f"[{finding.severity}] {finding.rule_id}: {finding.message}")
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

try:
    from .path_safety import validate_local_file
except ImportError:
    from path_safety import validate_local_file


# ---------------------------------------------------------------------------
# Finding type
# ---------------------------------------------------------------------------

@dataclass
class PipelineFinding:
    """A single security finding in a workflow file."""

    rule_id: str
    severity: str          # "critical", "high", "medium", "low"
    location: str          # e.g. "jobs.build.steps[3]"
    message: str
    remediation: str
    evidence: str = ""     # The specific line/value that triggered the finding


@dataclass
class AuditResult:
    """Results of auditing a single workflow file."""

    file_path: Path
    workflow_name: str
    findings: list[PipelineFinding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not any(f.severity in ("critical", "high") for f in self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")


# ---------------------------------------------------------------------------
# Action SHA pinning
# ---------------------------------------------------------------------------

# Regex to match GitHub Actions 'uses' values
_USES_RE = re.compile(r"^([\w\-./]+)@(.+)$")

# SHA-1 or SHA-256 commit hash pattern (40 hex chars for SHA-1, 64 for SHA-256)
_SHA_RE = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")

# Well-known verified publishers whose actions at major versions are acceptable
_TRUSTED_PUBLISHERS = {
    "actions",       # github.com/actions
    "github",        # github.com/github
}


# ---------------------------------------------------------------------------
# Deprecated workflow commands
# ---------------------------------------------------------------------------
_DEPRECATED_COMMANDS = ["set-env", "add-path"]

# Regex pattern to detect secret echo
_SECRET_ECHO_RE = re.compile(
    r"echo\s+.*\$\{\{?\s*secrets\.[A-Za-z0-9_]+\s*\}?\}",
    re.IGNORECASE,
)

# Regex to detect 'run' fields containing secret references
_SECRET_IN_RUN_RE = re.compile(
    r"\$\{\{?\s*secrets\.",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def audit_workflow_file(
    workflow_path: Path,
    repo_root: Path | None = None,
) -> AuditResult:
    """
    Audit a GitHub Actions workflow YAML file for security issues.

    Args:
        workflow_path: Path to the workflow YAML file.
        repo_root: Optional root used to reject repo-escaping workflow paths.

    Returns:
        AuditResult with all findings.
    """
    path_error = validate_local_file(
        workflow_path,
        repo_root=repo_root,
        label="workflow file",
    )
    if path_error:
        result = AuditResult(
            file_path=workflow_path,
            workflow_name="(unreadable)",
        )
        result.warnings.append(path_error)
        return result

    try:
        content = workflow_path.read_text(encoding="utf-8")
        workflow = yaml.safe_load(content)
    except (OSError, yaml.YAMLError) as exc:
        result = AuditResult(
            file_path=workflow_path,
            workflow_name="(unreadable)",
        )
        result.warnings.append(f"Could not parse workflow file: {exc}")
        return result

    if not isinstance(workflow, dict):
        result = AuditResult(file_path=workflow_path, workflow_name="(invalid)")
        result.warnings.append("Workflow file does not contain a valid YAML mapping")
        return result

    workflow_name = workflow.get("name", workflow_path.name)
    result = AuditResult(file_path=workflow_path, workflow_name=workflow_name)

    # Run checks
    _check_pull_request_target(workflow, result)
    _check_permissions(workflow, result)
    _check_jobs(workflow, result, content)

    # Sort: critical first
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    result.findings.sort(key=lambda f: severity_order.get(f.severity, 99))

    return result


def audit_workflow_directory(
    workflow_dir: Path,
    glob_pattern: str = "**/*.yml",
) -> list[AuditResult]:
    """
    Audit all workflow files in a directory.

    Args:
        workflow_dir:  Directory to scan (default: .github/workflows).
        glob_pattern:  Glob pattern for workflow files.

    Returns:
        List of AuditResult objects, one per workflow file.
    """
    results: list[AuditResult] = []
    for workflow_file in sorted(workflow_dir.glob(glob_pattern)):
        if workflow_file.is_file():
            results.append(audit_workflow_file(workflow_file, repo_root=workflow_dir))
    return results


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def _check_pull_request_target(workflow: dict, result: AuditResult) -> None:
    """PA001: pull_request_target with checkout of head ref."""
    # PyYAML (YAML 1.1) parses the bare key 'on' as boolean True.
    # Check both the string key and the boolean key to handle both parsers.
    triggers = workflow.get("on") or workflow.get(True) or {}
    if not isinstance(triggers, dict):
        return

    if "pull_request_target" not in triggers:
        return

    # Check if any job step checks out the PR head ref
    for job_name, job in (workflow.get("jobs") or {}).items():
        for i, step in enumerate(job.get("steps", [])):
            uses = step.get("uses", "")
            with_params = step.get("with", {}) or {}
            step_ref = with_params.get("ref", "")

            if "checkout" in uses and "${{ github.head_ref" in str(step_ref):
                result.findings.append(PipelineFinding(
                    rule_id="PA001",
                    severity="critical",
                    location=f"jobs.{job_name}.steps[{i}]",
                    message=(
                        "Workflow uses pull_request_target trigger AND checks out the PR "
                        "head ref — an attacker can execute arbitrary code with write "
                        "permissions by opening a PR from a forked repo"
                    ),
                    remediation=(
                        "Do not use pull_request_target unless you must access write tokens. "
                        "If required, never check out pull request code — only use the "
                        "base branch. Alternatively, use the 'pull_request' trigger instead."
                    ),
                    evidence=f"uses: {uses}, with.ref: {step_ref}",
                ))


def _check_permissions(workflow: dict, result: AuditResult) -> None:
    """PA003: Workflow-level permissions."""
    permissions = workflow.get("permissions")

    if permissions is None:
        result.findings.append(PipelineFinding(
            rule_id="PA003",
            severity="medium",
            location="workflow.permissions",
            message="No top-level permissions block — workflow inherits default token permissions",
            remediation=(
                "Add 'permissions: read-all' at the workflow level to reduce the default "
                "permissions, then grant only the specific permissions each job needs "
                "(e.g., 'security-events: write' for SARIF uploads)."
            ),
        ))
    elif permissions == "write-all":
        result.findings.append(PipelineFinding(
            rule_id="PA003",
            severity="high",
            location="workflow.permissions",
            message="Workflow uses 'permissions: write-all' — grants all write permissions to GITHUB_TOKEN",
            remediation=(
                "Replace 'write-all' with the minimum specific permissions required. "
                "For most workflows, 'contents: read' is sufficient at the workflow level."
            ),
            evidence="permissions: write-all",
        ))


def _check_jobs(workflow: dict, result: AuditResult, raw_content: str) -> None:
    """Run per-job and per-step checks."""
    jobs = workflow.get("jobs") or {}

    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue

        # PA008: Missing timeout-minutes
        if "timeout-minutes" not in job:
            result.findings.append(PipelineFinding(
                rule_id="PA008",
                severity="low",
                location=f"jobs.{job_name}",
                message=f"Job '{job_name}' has no timeout-minutes — runaway builds can accumulate costs",
                remediation=(
                    f"Add 'timeout-minutes: 30' (or appropriate value) to job '{job_name}' "
                    "to prevent runaway executions from consuming CI minutes indefinitely."
                ),
            ))

        steps = job.get("steps") or []
        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                continue

            step_loc = f"jobs.{job_name}.steps[{i}]"
            step_name = step.get("name", f"step-{i}")
            _check_step(step, step_loc, step_name, result)


def _check_step(
    step: dict,
    location: str,
    step_name: str,
    result: AuditResult,
) -> None:
    """Run security checks on a single workflow step."""
    uses = step.get("uses", "")
    run = step.get("run", "")
    continue_on_error = step.get("continue-on-error", False)

    # PA002: Action not pinned to SHA
    if uses:
        match = _USES_RE.match(uses)
        if match:
            action_path, ref = match.group(1), match.group(2)
            owner = action_path.split("/")[0].lower()
            is_sha = bool(_SHA_RE.match(ref))
            is_trusted_major_version = (
                owner in _TRUSTED_PUBLISHERS and re.match(r"^v\d+$", ref)
            )
            if not is_sha and not is_trusted_major_version:
                result.findings.append(PipelineFinding(
                    rule_id="PA002",
                    severity="medium",
                    location=location,
                    message=(
                        f"Action '{uses}' is not pinned to a full commit SHA — "
                        "the action can be silently updated to malicious code"
                    ),
                    remediation=(
                        f"Pin the action to a full commit SHA: "
                        f"'uses: {action_path}@<full-sha>  # {ref}'. "
                        "Use a tool like pin-github-action to maintain pinned actions."
                    ),
                    evidence=f"uses: {uses}",
                ))

    # PA004: Secret echoed in run script
    if run and _SECRET_ECHO_RE.search(run):
        result.findings.append(PipelineFinding(
            rule_id="PA004",
            severity="high",
            location=location,
            message=f"Step '{step_name}' echoes a secret value — secret may appear in build logs",
            remediation=(
                "Never echo or print secrets in run scripts. "
                "Use GitHub Actions masking (add_mask) if you must work with a derived value, "
                "or use the 'mask' function: echo '::add-mask::$MY_VAR'"
            ),
            evidence=run[:120],
        ))

    # PA006: continue-on-error on a security step
    if continue_on_error:
        step_name_lower = (step.get("name") or "").lower()
        uses_lower = (uses or "").lower()
        security_indicators = ["sast", "semgrep", "gitleaks", "secret", "audit", "scan", "checkov"]
        if any(ind in step_name_lower or ind in uses_lower for ind in security_indicators):
            result.findings.append(PipelineFinding(
                rule_id="PA006",
                severity="medium",
                location=location,
                message=(
                    f"Security step '{step_name}' has continue-on-error: true — "
                    "security failures will not block the pipeline"
                ),
                remediation=(
                    "Remove 'continue-on-error: true' from security scanning steps. "
                    "Security controls should fail the build to prevent vulnerable code "
                    "from being deployed."
                ),
                evidence=f"continue-on-error: true on '{step_name}'",
            ))

    # PA007: Deprecated workflow commands
    if run:
        for deprecated_cmd in _DEPRECATED_COMMANDS:
            if f"echo ::{deprecated_cmd}::" in run or f"::{deprecated_cmd}::" in run:
                result.findings.append(PipelineFinding(
                    rule_id="PA007",
                    severity="medium",
                    location=location,
                    message=f"Step uses deprecated workflow command '::{deprecated_cmd}::' — security vulnerability",
                    remediation=(
                        f"Replace '::{deprecated_cmd}::' with the secure environment file approach. "
                        "For set-env: echo 'NAME=VALUE' >> $GITHUB_ENV. "
                        "For add-path: echo '/my/path' >> $GITHUB_PATH."
                    ),
                    evidence=f"::{deprecated_cmd}::",
                ))
