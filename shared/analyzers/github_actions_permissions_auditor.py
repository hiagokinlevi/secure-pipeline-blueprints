# github_actions_permissions_auditor.py
# Analyze GitHub Actions workflow YAML for over-privileged GITHUB_TOKEN permission configs.
#
# License: CC BY 4.0 — Creative Commons Attribution 4.0 International
# https://creativecommons.org/licenses/by/4.0/
#
# Part of the Cyber Port portfolio — github.com/hiagokinlevi
# Repository: k1N-Secure-Pipeline-Blueprints

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Check IDs and their weights used for risk scoring
# ---------------------------------------------------------------------------
_CHECK_WEIGHTS: Dict[str, int] = {
    "GHP-001": 45,  # permissions: write-all at workflow level — CRITICAL
    "GHP-002": 25,  # No top-level permissions block (legacy permissive default) — HIGH
    "GHP-003": 25,  # contents: write on a PR-triggered workflow — HIGH
    "GHP-004": 15,  # id-token: write present (unnecessary for most workflows) — MEDIUM
    "GHP-005": 25,  # secrets: inherit in a uses: workflow_call step — HIGH
    "GHP-006": 20,  # pull-requests: write permission — HIGH
    "GHP-007": 15,  # packages: write permission — MEDIUM
}

# Human-readable titles for each check
_CHECK_TITLES: Dict[str, str] = {
    "GHP-001": "Workflow-level write-all permissions",
    "GHP-002": "Missing top-level permissions block",
    "GHP-003": "contents:write on a pull_request-triggered workflow",
    "GHP-004": "id-token:write permission present",
    "GHP-005": "secrets:inherit in reusable workflow call step",
    "GHP-006": "pull-requests:write permission present",
    "GHP-007": "packages:write permission present",
}

# Severity label per check
_CHECK_SEVERITY: Dict[str, str] = {
    "GHP-001": "CRITICAL",
    "GHP-002": "HIGH",
    "GHP-003": "HIGH",
    "GHP-004": "MEDIUM",
    "GHP-005": "HIGH",
    "GHP-006": "HIGH",
    "GHP-007": "MEDIUM",
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class WorkflowPermission:
    """Represents a single permission scope discovered in a workflow or job."""

    scope: str      # e.g. "contents", "id-token"
    level: str      # "read", "write", or "none"
    location: str   # "workflow" or "job:<job_id>"


@dataclass
class GHPFinding:
    """A single fired check result."""

    check_id: str
    severity: str   # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    weight: int


@dataclass
class GHPResult:
    """Aggregated result for one workflow file."""

    workflow_name: str
    findings: List[GHPFinding]
    risk_score: int         # min(100, sum of weights for fired checks)
    permissions_score: int  # max(0, 100 - risk_score)

    # ------------------------------------------------------------------
    # Convenience methods
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Serialize the result to a plain dictionary (JSON-safe)."""
        return {
            "workflow_name": self.workflow_name,
            "risk_score": self.risk_score,
            "permissions_score": self.permissions_score,
            "findings": [
                {
                    "check_id": f.check_id,
                    "severity": f.severity,
                    "title": f.title,
                    "detail": f.detail,
                    "weight": f.weight,
                }
                for f in self.findings
            ],
        }

    def summary(self) -> str:
        """Return a one-line human-readable summary of the result."""
        count = len(self.findings)
        severities = [f.severity for f in self.findings]
        # Highest severity label for the summary line
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        top = "NONE"
        for level in order:
            if level in severities:
                top = level
                break
        return (
            f"[{self.workflow_name}] findings={count} "
            f"top_severity={top} "
            f"risk={self.risk_score}/100 "
            f"score={self.permissions_score}/100"
        )

    def by_severity(self) -> Dict[str, List[GHPFinding]]:
        """Return findings grouped by severity label."""
        groups: Dict[str, List[GHPFinding]] = {}
        for finding in self.findings:
            groups.setdefault(finding.severity, []).append(finding)
        return groups


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _collect_all_permissions(workflow: dict) -> List[WorkflowPermission]:
    """Extract every WorkflowPermission from workflow-level and per-job blocks."""
    result: List[WorkflowPermission] = []

    # Workflow-level permissions
    wf_perms = workflow.get("permissions")
    if isinstance(wf_perms, dict):
        for scope, level in wf_perms.items():
            result.append(WorkflowPermission(
                scope=str(scope),
                level=str(level),
                location="workflow",
            ))

    # Per-job permissions
    jobs = workflow.get("jobs") or {}
    if isinstance(jobs, dict):
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            job_perms = job.get("permissions")
            if isinstance(job_perms, dict):
                for scope, level in job_perms.items():
                    result.append(WorkflowPermission(
                        scope=str(scope),
                        level=str(level),
                        location=f"job:{job_id}",
                    ))

    return result


def _has_pr_trigger(workflow: dict) -> bool:
    """Return True if the workflow is triggered by pull_request or pull_request_target."""
    pr_events = {"pull_request", "pull_request_target"}
    on_value = workflow.get("on")

    # on: push  (plain string)
    if isinstance(on_value, str):
        return on_value in pr_events

    # on: [push, pull_request]  (list)
    if isinstance(on_value, list):
        return any(e in pr_events for e in on_value)

    # on: {pull_request: ..., push: ...}  (dict)
    if isinstance(on_value, dict):
        return bool(pr_events.intersection(on_value.keys()))

    return False


def _iter_all_steps(workflow: dict):
    """Yield every step dict from every job in the workflow."""
    jobs = workflow.get("jobs") or {}
    if not isinstance(jobs, dict):
        return
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps") or []
        if not isinstance(steps, list):
            continue
        for step in steps:
            if isinstance(step, dict):
                yield step


# ---------------------------------------------------------------------------
# Individual check functions — each returns an Optional[GHPFinding]
# ---------------------------------------------------------------------------

def _check_ghp001(workflow: dict) -> Optional[GHPFinding]:
    """GHP-001: permissions: write-all at workflow level."""
    if workflow.get("permissions") == "write-all":
        return GHPFinding(
            check_id="GHP-001",
            severity=_CHECK_SEVERITY["GHP-001"],
            title=_CHECK_TITLES["GHP-001"],
            detail=(
                "The top-level 'permissions' key is set to 'write-all', granting "
                "write access across every GITHUB_TOKEN scope. Restrict permissions "
                "to only the scopes actually required by each job."
            ),
            weight=_CHECK_WEIGHTS["GHP-001"],
        )
    return None


def _check_ghp002(workflow: dict, ghp001_fired: bool) -> Optional[GHPFinding]:
    """GHP-002: No top-level permissions block (only when GHP-001 did not fire)."""
    if ghp001_fired:
        return None
    if "permissions" not in workflow:
        return GHPFinding(
            check_id="GHP-002",
            severity=_CHECK_SEVERITY["GHP-002"],
            title=_CHECK_TITLES["GHP-002"],
            detail=(
                "No top-level 'permissions' block was found. Without an explicit "
                "permissions declaration, GitHub falls back to the repository's "
                "default token permissions, which may be broadly permissive. "
                "Add 'permissions: {}' or declare the minimum required scopes."
            ),
            weight=_CHECK_WEIGHTS["GHP-002"],
        )
    return None


def _check_ghp003(workflow: dict, all_perms: List[WorkflowPermission]) -> Optional[GHPFinding]:
    """GHP-003: contents:write when PR trigger is present."""
    has_pr = _has_pr_trigger(workflow)
    if not has_pr:
        return None
    for perm in all_perms:
        if perm.scope == "contents" and perm.level == "write":
            return GHPFinding(
                check_id="GHP-003",
                severity=_CHECK_SEVERITY["GHP-003"],
                title=_CHECK_TITLES["GHP-003"],
                detail=(
                    f"'contents: write' was found at location '{perm.location}' and "
                    "the workflow is triggered by pull_request or pull_request_target. "
                    "This combination can allow a forked PR to modify repository contents. "
                    "Reduce to 'contents: read' or remove the permission entirely."
                ),
                weight=_CHECK_WEIGHTS["GHP-003"],
            )
    return None


def _check_ghp004(all_perms: List[WorkflowPermission]) -> Optional[GHPFinding]:
    """GHP-004: id-token:write present anywhere in the workflow."""
    for perm in all_perms:
        if perm.scope == "id-token" and perm.level == "write":
            return GHPFinding(
                check_id="GHP-004",
                severity=_CHECK_SEVERITY["GHP-004"],
                title=_CHECK_TITLES["GHP-004"],
                detail=(
                    f"'id-token: write' was found at location '{perm.location}'. "
                    "This permission is required only for OIDC-based cloud authentication. "
                    "Remove it from workflows that do not perform OIDC federation."
                ),
                weight=_CHECK_WEIGHTS["GHP-004"],
            )
    return None


def _check_ghp005(workflow: dict) -> Optional[GHPFinding]:
    """GHP-005: secrets:inherit in a uses: step."""
    for step in _iter_all_steps(workflow):
        # Only applies to reusable workflow call steps (uses: key present)
        if "uses" not in step:
            continue
        with_block = step.get("with")
        if isinstance(with_block, dict):
            if with_block.get("secrets") == "inherit":
                return GHPFinding(
                    check_id="GHP-005",
                    severity=_CHECK_SEVERITY["GHP-005"],
                    title=_CHECK_TITLES["GHP-005"],
                    detail=(
                        f"Step '{step.get('name', step.get('uses', 'unknown'))}' passes "
                        "'secrets: inherit' to a reusable workflow call. This forwards "
                        "all parent secrets to the child workflow. Pass only the specific "
                        "secrets the called workflow requires."
                    ),
                    weight=_CHECK_WEIGHTS["GHP-005"],
                )
    return None


def _check_ghp006(all_perms: List[WorkflowPermission]) -> Optional[GHPFinding]:
    """GHP-006: pull-requests:write present anywhere."""
    for perm in all_perms:
        if perm.scope == "pull-requests" and perm.level == "write":
            return GHPFinding(
                check_id="GHP-006",
                severity=_CHECK_SEVERITY["GHP-006"],
                title=_CHECK_TITLES["GHP-006"],
                detail=(
                    f"'pull-requests: write' was found at location '{perm.location}'. "
                    "This scope allows the token to create, update, and close pull requests. "
                    "Verify this level of access is strictly necessary."
                ),
                weight=_CHECK_WEIGHTS["GHP-006"],
            )
    return None


def _check_ghp007(all_perms: List[WorkflowPermission]) -> Optional[GHPFinding]:
    """GHP-007: packages:write present anywhere."""
    for perm in all_perms:
        if perm.scope == "packages" and perm.level == "write":
            return GHPFinding(
                check_id="GHP-007",
                severity=_CHECK_SEVERITY["GHP-007"],
                title=_CHECK_TITLES["GHP-007"],
                detail=(
                    f"'packages: write' was found at location '{perm.location}'. "
                    "This scope allows publishing packages to GitHub Packages. "
                    "Scope it to the jobs that actually publish to avoid unnecessary exposure."
                ),
                weight=_CHECK_WEIGHTS["GHP-007"],
            )
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze(workflow: dict, workflow_name: str = "workflow") -> GHPResult:
    """Analyze a parsed GitHub Actions workflow dict for permission issues.

    Parameters
    ----------
    workflow:
        A Python dict that mirrors the deserialized GitHub Actions YAML structure.
    workflow_name:
        A human-readable label for the workflow (e.g. the filename).

    Returns
    -------
    GHPResult
        Aggregated findings, risk score, and permissions score.
    """
    findings: List[GHPFinding] = []

    # Pre-compute shared state used by multiple checks
    all_perms = _collect_all_permissions(workflow)

    # --- GHP-001 ---
    finding_001 = _check_ghp001(workflow)
    if finding_001:
        findings.append(finding_001)

    # --- GHP-002 (only when GHP-001 did not fire) ---
    finding_002 = _check_ghp002(workflow, ghp001_fired=finding_001 is not None)
    if finding_002:
        findings.append(finding_002)

    # --- GHP-003 ---
    finding_003 = _check_ghp003(workflow, all_perms)
    if finding_003:
        findings.append(finding_003)

    # --- GHP-004 ---
    finding_004 = _check_ghp004(all_perms)
    if finding_004:
        findings.append(finding_004)

    # --- GHP-005 ---
    finding_005 = _check_ghp005(workflow)
    if finding_005:
        findings.append(finding_005)

    # --- GHP-006 ---
    finding_006 = _check_ghp006(all_perms)
    if finding_006:
        findings.append(finding_006)

    # --- GHP-007 ---
    finding_007 = _check_ghp007(all_perms)
    if finding_007:
        findings.append(finding_007)

    # Compute scores
    total_weight = sum(f.weight for f in findings)
    risk_score = min(100, total_weight)
    permissions_score = max(0, 100 - risk_score)

    return GHPResult(
        workflow_name=workflow_name,
        findings=findings,
        risk_score=risk_score,
        permissions_score=permissions_score,
    )


def analyze_many(
    workflows: List[dict],
    names: Optional[List[str]] = None,
) -> List[GHPResult]:
    """Analyze a collection of workflow dicts and return one GHPResult per workflow.

    Parameters
    ----------
    workflows:
        List of parsed workflow dicts.
    names:
        Optional list of names that align with *workflows* by index.
        Falls back to "workflow-<index>" if not provided or too short.

    Returns
    -------
    List[GHPResult]
        One result per input workflow, in the same order.
    """
    results: List[GHPResult] = []
    for idx, wf in enumerate(workflows):
        # Determine a label for this workflow
        if names and idx < len(names):
            name = names[idx]
        else:
            name = f"workflow-{idx}"
        results.append(analyze(wf, workflow_name=name))
    return results
