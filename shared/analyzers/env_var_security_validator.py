# CC BY 4.0 — Cyber Port Portfolio
# Module: env_var_security_validator
# Purpose: Validate GitHub Actions workflow environment variables for security risks.
# License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#          https://creativecommons.org/licenses/by/4.0/

"""
GitHub Actions workflow env-var security validator.

Checks performed
----------------
ENV-001  Hardcoded secret value          CRITICAL  w=45
ENV-002  URL with embedded credentials   HIGH      w=25
ENV-003  User-controlled input in secret HIGH      w=25
ENV-004  Broad GitHub token exposure     MEDIUM    w=15
ENV-005  Secret name at workflow scope   MEDIUM    w=15
ENV-006  Same env var, conflicting vals  MEDIUM    w=15
ENV-007  Embedded private key / cert     CRITICAL  w=45
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SECRET_NAME_KEYWORDS = {
    "PASSWORD", "SECRET", "KEY", "TOKEN", "API_KEY", "CREDENTIAL", "PRIVATE"
}

_CHECK_WEIGHTS: Dict[str, int] = {
    "ENV-001": 45,
    "ENV-002": 25,
    "ENV-003": 25,
    "ENV-004": 15,
    "ENV-005": 15,
    "ENV-006": 15,
    "ENV-007": 45,
}

_CHECK_SEVERITIES: Dict[str, str] = {
    "ENV-001": "CRITICAL",
    "ENV-002": "HIGH",
    "ENV-003": "HIGH",
    "ENV-004": "MEDIUM",
    "ENV-005": "MEDIUM",
    "ENV-006": "MEDIUM",
    "ENV-007": "CRITICAL",
}

# Matches scheme://user:pass@host patterns (credentials embedded in URL)
_URL_WITH_CREDS_RE = re.compile(
    r"[a-zA-Z][a-zA-Z0-9+\-.]*://[^@\s]{1,100}@[^\s/]+"
)

# Matches ${{ secrets.<name> }} (the canonical safe reference)
_SECRET_REF_RE = re.compile(r"\$\{\{\s*secrets\.\w+\s*\}\}")

# Matches any expression starting with ${{
_EXPRESSION_RE = re.compile(r"^\s*\$\{\{")

# Matches github.token or secrets.GITHUB_TOKEN references
_GITHUB_TOKEN_RE = re.compile(
    r"\$\{\{\s*(?:github\.token|secrets\.GITHUB_TOKEN)\s*\}\}"
)

# Markers for embedded private keys / certificates in multi-line values
_PRIVATE_KEY_MARKERS = ("-----BEGIN ", "BEGIN CERTIFICATE", "BEGIN RSA PRIVATE KEY")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class EnvVar:
    """A single environment variable entry with its CI/CD scope."""

    name: str
    value: str          # Raw value string (may be expression like "${{ secrets.X }}")
    scope: str          # "workflow", "job:<job_id>", "step:<job_id>:<step_name>"
    is_secret_ref: bool # True when value matches the ${{ secrets.* }} pattern


@dataclass
class ENVFinding:
    """A single security finding for an environment variable check."""

    check_id: str
    severity: str       # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    weight: int
    env_var_name: str


@dataclass
class ENVResult:
    """Aggregated validation result for a set of environment variables."""

    findings: List[ENVFinding] = field(default_factory=list)
    risk_score: int = 0

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Serialise result to a plain dict (JSON-friendly)."""
        return {
            "risk_score": self.risk_score,
            "findings": [
                {
                    "check_id": f.check_id,
                    "severity": f.severity,
                    "title": f.title,
                    "detail": f.detail,
                    "weight": f.weight,
                    "env_var_name": f.env_var_name,
                }
                for f in self.findings
            ],
        }

    def summary(self) -> str:
        """Return a one-line human-readable summary."""
        n = len(self.findings)
        if n == 0:
            return f"risk_score={self.risk_score} — no findings"
        ids = ", ".join(sorted({f.check_id for f in self.findings}))
        return f"risk_score={self.risk_score} — {n} finding(s): {ids}"

    def by_severity(self) -> Dict[str, List[ENVFinding]]:
        """Group findings by severity label."""
        groups: Dict[str, List[ENVFinding]] = {}
        for f in self.findings:
            groups.setdefault(f.severity, []).append(f)
        return groups


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _has_secret_name(name: str) -> bool:
    """Return True if the variable name contains any secret-related keyword."""
    upper = name.upper()
    return any(kw in upper for kw in _SECRET_NAME_KEYWORDS)


def _redact(value: str, keep: int = 4) -> str:
    """Show only the first *keep* characters then mask the rest."""
    if not value:
        return ""
    prefix = value[:keep]
    return f"{prefix}****"


def _make_finding(
    check_id: str,
    env_var_name: str,
    detail: str,
) -> ENVFinding:
    """Construct an ENVFinding from a check ID and contextual detail."""
    titles: Dict[str, str] = {
        "ENV-001": "Hardcoded secret value",
        "ENV-002": "URL with embedded credentials",
        "ENV-003": "User-controlled input assigned to secret context",
        "ENV-004": "Broad GitHub token exposure at workflow scope",
        "ENV-005": "Secret-named env var exposed at workflow scope",
        "ENV-006": "Conflicting values for the same env var across scopes",
        "ENV-007": "Private key or certificate embedded in env var value",
    }
    return ENVFinding(
        check_id=check_id,
        severity=_CHECK_SEVERITIES[check_id],
        title=titles[check_id],
        detail=detail,
        weight=_CHECK_WEIGHTS[check_id],
        env_var_name=env_var_name,
    )


# ---------------------------------------------------------------------------
# Per-check predicates
# ---------------------------------------------------------------------------


def _check_env_001(var: EnvVar) -> Optional[ENVFinding]:
    """ENV-001: Secret name with a hardcoded (non-expression) value."""
    if not _has_secret_name(var.name):
        return None
    if var.is_secret_ref:
        return None
    if not var.value:
        return None
    if _EXPRESSION_RE.match(var.value):
        return None
    return _make_finding(
        "ENV-001",
        var.name,
        f"Variable '{var.name}' in scope '{var.scope}' appears to hold a "
        f"hardcoded secret (value is not a secrets reference).",
    )


def _check_env_002(var: EnvVar) -> Optional[ENVFinding]:
    """ENV-002: URL containing embedded user:pass credentials."""
    if _URL_WITH_CREDS_RE.search(var.value):
        return _make_finding(
            "ENV-002",
            var.name,
            f"Variable '{var.name}' in scope '{var.scope}' contains a URL "
            f"with embedded credentials (user:pass@host pattern).",
        )
    return None


def _check_env_003(var: EnvVar) -> Optional[ENVFinding]:
    """ENV-003: Secret name referencing user-controlled context."""
    if not _has_secret_name(var.name):
        return None
    if "${{ github.event." in var.value or "${{ inputs." in var.value:
        return _make_finding(
            "ENV-003",
            var.name,
            f"Variable '{var.name}' in scope '{var.scope}' references a "
            f"user-controlled input context, enabling potential secret injection.",
        )
    return None


def _check_env_004(var: EnvVar) -> Optional[ENVFinding]:
    """ENV-004: Secret name set to github.token / GITHUB_TOKEN at workflow scope."""
    if not _has_secret_name(var.name):
        return None
    if var.scope != "workflow":
        return None
    if _GITHUB_TOKEN_RE.search(var.value):
        return _make_finding(
            "ENV-004",
            var.name,
            f"Variable '{var.name}' is set to the GitHub token at workflow scope, "
            f"exposing the token to all jobs and steps.",
        )
    return None


def _check_env_005(var: EnvVar, env_004_fired_names: set) -> Optional[ENVFinding]:
    """ENV-005: Secret name exposed at workflow scope (suppressed when ENV-004 fires)."""
    if not _has_secret_name(var.name):
        return None
    if var.scope != "workflow":
        return None
    # Suppress if ENV-004 already fired for the same variable name
    if var.name in env_004_fired_names:
        return None
    return _make_finding(
        "ENV-005",
        var.name,
        f"Variable '{var.name}' has a sensitive name and is defined at workflow "
        f"scope, making it accessible to all jobs.",
    )


def _check_env_007(var: EnvVar) -> Optional[ENVFinding]:
    """ENV-007: Private key or certificate material embedded in the value."""
    for marker in _PRIVATE_KEY_MARKERS:
        if marker in var.value:
            return _make_finding(
                "ENV-007",
                var.name,
                f"Variable '{var.name}' in scope '{var.scope}' appears to contain "
                f"private key or certificate material (marker: '{marker}').",
            )
    return None


# ---------------------------------------------------------------------------
# Core validation function
# ---------------------------------------------------------------------------


def validate(env_vars: List[EnvVar]) -> ENVResult:
    """Validate a list of CI/CD environment variables for security risks."""
    findings: List[ENVFinding] = []

    # --- ENV-004 pass: collect names where ENV-004 fires (for ENV-005 suppression)
    env_004_fired_names: set = set()
    for var in env_vars:
        f4 = _check_env_004(var)
        if f4:
            env_004_fired_names.add(var.name)

    # --- Per-variable checks (001, 002, 003, 004, 005, 007)
    for var in env_vars:
        for checker in (
            _check_env_001,
            _check_env_002,
            _check_env_003,
            _check_env_007,
        ):
            result = checker(var)
            if result:
                findings.append(result)

        f4 = _check_env_004(var)
        if f4:
            findings.append(f4)

        f5 = _check_env_005(var, env_004_fired_names)
        if f5:
            findings.append(f5)

    # --- ENV-006: conflicting values across scopes (group by normalised name)
    name_groups: Dict[str, List[EnvVar]] = {}
    for var in env_vars:
        key = var.name.upper()
        name_groups.setdefault(key, []).append(var)

    for canonical_name, group in name_groups.items():
        # Only entries with a non-empty value participate in conflict detection
        non_empty = [v for v in group if v.value]
        if len(non_empty) < 2:
            continue
        # Check whether at least two entries have different values
        unique_values = {v.value for v in non_empty}
        if len(unique_values) < 2:
            continue
        # Fire one finding listing all conflicting scopes
        scope_summary = "; ".join(
            f"{v.scope}={_redact(v.value)}" for v in non_empty
        )
        findings.append(
            _make_finding(
                "ENV-006",
                non_empty[0].name,
                f"Variable '{non_empty[0].name}' has conflicting values across "
                f"scopes: {scope_summary}",
            )
        )

    # --- Compute risk score: sum weights for unique fired check IDs, capped at 100
    fired_ids = {f.check_id for f in findings}
    risk_score = min(100, sum(_CHECK_WEIGHTS[cid] for cid in fired_ids))

    return ENVResult(findings=findings, risk_score=risk_score)


# ---------------------------------------------------------------------------
# Workflow extraction helper
# ---------------------------------------------------------------------------


def extract_env_vars(workflow: dict) -> List[EnvVar]:
    """Extract all env vars from a GitHub Actions workflow dict with their scopes.

    Traversal order:
      1. workflow-level ``env`` block  → scope ``"workflow"``
      2. per-job ``env`` blocks        → scope ``"job:<job_id>"``
      3. per-step ``env`` blocks       → scope ``"step:<job_id>:<step_name_or_index>"``
    """
    result: List[EnvVar] = []

    def _build(name: str, value: str, scope: str) -> EnvVar:
        raw = str(value)
        is_secret_ref = bool(_SECRET_REF_RE.match(raw))
        return EnvVar(name=name, value=raw, scope=scope, is_secret_ref=is_secret_ref)

    # Workflow-level env vars
    for name, value in workflow.get("env", {}).items():
        result.append(_build(name, value, "workflow"))

    # Job-level and step-level env vars
    for job_id, job in workflow.get("jobs", {}).items():
        job_scope = f"job:{job_id}"

        for name, value in job.get("env", {}).items():
            result.append(_build(name, value, job_scope))

        for idx, step in enumerate(job.get("steps", [])):
            # Use the step name when available, otherwise fall back to the index
            step_label = step.get("name") or str(idx)
            step_scope = f"step:{job_id}:{step_label}"

            for name, value in step.get("env", {}).items():
                result.append(_build(name, value, step_scope))

    return result
