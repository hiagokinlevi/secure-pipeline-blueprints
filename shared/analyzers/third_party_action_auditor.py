# third_party_action_auditor.py
# Part of the Cyber Port portfolio — github.com/hiagokinlevi
#
# Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
#
# Audit GitHub Actions workflows for third-party action supply chain risks:
# unpinned branch references, floating version tags, untrusted organisations,
# unsigned Docker images, error suppression in security jobs, version
# inconsistency, and excessive action surface area.

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

# ---------------------------------------------------------------------------
# Check weights — used to compute risk_score = min(100, sum of fired weights)
# ---------------------------------------------------------------------------
_CHECK_WEIGHTS: Dict[str, int] = {
    "TPA-001": 45,  # mutable branch reference — CRITICAL
    "TPA-002": 25,  # floating version tag — HIGH
    "TPA-003": 25,  # untrusted organisation — HIGH
    "TPA-004": 20,  # Docker image without digest — HIGH
    "TPA-005": 15,  # continue-on-error in security-sensitive job — MEDIUM
    "TPA-006": 15,  # same action referenced with different versions — MEDIUM
    "TPA-007": 15,  # more than 15 distinct third-party uses references — MEDIUM
}

# Branch names that represent mutable (non-pinned) references
_MUTABLE_BRANCHES: Set[str] = {"main", "master", "head", "develop", "dev"}

# Trusted organisations shipped as the default allowlist
_DEFAULT_TRUSTED_ORGS: List[str] = [
    "actions",
    "github",
    "aws-actions",
    "azure",
    "google-github-actions",
    "docker",
]

# Keywords that mark a job as security-sensitive (case-insensitive substring)
_SENSITIVE_KEYWORDS: List[str] = [
    "security",
    "scan",
    "lint",
    "test",
    "audit",
    "sast",
    "sca",
    "check",
]

# Regex for a floating SemVer-style tag: v1, v1.2, v1.2.3, …
_FLOATING_TAG_RE = re.compile(r"^v\d+(\.\d+)*$")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ActionRef:
    """A single `uses:` reference parsed from a workflow step."""

    job_id: str
    step_name: str
    uses: str  # raw uses value, e.g. "actions/checkout@v3" or "actions/checkout@abc123"


@dataclass
class TPAFinding:
    """One supply-chain risk finding for a single check ID."""

    check_id: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    weight: int
    action_refs: List[str]  # the uses strings that triggered this finding


@dataclass
class TPAResult:
    """Aggregated audit result for a single workflow file."""

    workflow_name: str
    total_action_refs: int
    findings: List[TPAFinding]
    risk_score: int  # min(100, sum of weights for unique fired check IDs)

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Serialise the result to a plain dictionary (JSON-safe)."""
        return {
            "workflow_name": self.workflow_name,
            "total_action_refs": self.total_action_refs,
            "risk_score": self.risk_score,
            "findings": [
                {
                    "check_id": f.check_id,
                    "severity": f.severity,
                    "title": f.title,
                    "detail": f.detail,
                    "weight": f.weight,
                    "action_refs": f.action_refs,
                }
                for f in self.findings
            ],
        }

    def summary(self) -> str:
        """Return a human-readable one-line summary."""
        finding_count = len(self.findings)
        return (
            f"[{self.workflow_name}] risk_score={self.risk_score}/100 "
            f"findings={finding_count} refs={self.total_action_refs}"
        )

    def by_severity(self) -> Dict[str, List[TPAFinding]]:
        """Group findings by their severity label."""
        result: Dict[str, List[TPAFinding]] = {}
        for f in self.findings:
            result.setdefault(f.severity, []).append(f)
        return result


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def _parse_action_refs(workflow: dict) -> List[ActionRef]:
    """
    Walk all jobs and steps in *workflow* and collect every third-party
    `uses:` reference.

    Rules:
    - The step must have a `uses` key.
    - The `uses` value must contain both `/` and `@` (looks like an action ref).
    - Steps whose `uses` starts with `./.` are local actions and are excluded.
    """
    refs: List[ActionRef] = []
    jobs: dict = workflow.get("jobs", {})

    for job_id, job in jobs.items():
        steps = job.get("steps", []) if isinstance(job, dict) else []
        for step in steps:
            if not isinstance(step, dict):
                continue
            uses: Optional[str] = step.get("uses")
            if not uses or not isinstance(uses, str):
                continue
            # Exclude local actions
            if uses.startswith("./."):
                continue
            # Determine whether this is a valid reference to include:
            # - docker:// prefixed refs are always valid (digest/@ is optional)
            # - standard action refs must contain both '/' and '@'
            is_docker = uses.startswith("docker://")
            if not is_docker and ("/" not in uses or "@" not in uses):
                continue
            sname = step.get("name", "") or ""
            refs.append(ActionRef(job_id=job_id, step_name=sname, uses=uses))

    return refs


def _parse_org(uses: str) -> str:
    """
    Extract the organisation (owner) from a `uses` string.

    - ``docker://image/path@sha256:abc`` → ``"docker-registry"``
    - ``actions/checkout@v3``           → ``"actions"``
    """
    if uses.startswith("docker://"):
        return "docker-registry"
    return uses.split("/")[0]


def _parse_ref(uses: str) -> str:
    """
    Extract the ref portion from a `uses` string (everything after the last ``@``).

    Returns an empty string when no ``@`` is present.
    """
    if "@" not in uses:
        return ""
    return uses.rsplit("@", 1)[1]


def _is_sha_pinned(ref: str) -> bool:
    """
    Return True when *ref* is a cryptographic pin:
    - a 40-character lowercase hexadecimal string (SHA-1 commit hash), or
    - a string that starts with ``sha256:`` (Docker content-addressed digest).
    """
    if ref.startswith("sha256:"):
        return True
    # SHA-1: exactly 40 hex characters
    return bool(re.fullmatch(r"[0-9a-fA-F]{40}", ref))


# ---------------------------------------------------------------------------
# Individual check implementations
# ---------------------------------------------------------------------------


def _check_tpa001(refs: List[ActionRef]) -> Optional[TPAFinding]:
    """TPA-001: Action pinned to a mutable branch reference."""
    flagged: List[str] = []
    for r in refs:
        ref = _parse_ref(r.uses).lower()
        if ref in _MUTABLE_BRANCHES:
            flagged.append(r.uses)
    if not flagged:
        return None
    return TPAFinding(
        check_id="TPA-001",
        severity="CRITICAL",
        title="Action pinned to mutable branch reference",
        detail=(
            f"{len(flagged)} action(s) use a mutable branch ref "
            f"(@main, @master, @HEAD, @develop, @dev). "
            "An attacker who pushes to that branch can inject malicious code."
        ),
        weight=_CHECK_WEIGHTS["TPA-001"],
        action_refs=flagged,
    )


def _check_tpa002(refs: List[ActionRef], tpa001_uses: Set[str]) -> Optional[TPAFinding]:
    """TPA-002: Action uses a floating version tag without SHA pinning."""
    flagged: List[str] = []
    for r in refs:
        # Suppress if TPA-001 already fired for this exact uses string
        if r.uses in tpa001_uses:
            continue
        ref = _parse_ref(r.uses)
        if _FLOATING_TAG_RE.match(ref):
            flagged.append(r.uses)
    if not flagged:
        return None
    return TPAFinding(
        check_id="TPA-002",
        severity="HIGH",
        title="Action uses floating version tag without SHA pinning",
        detail=(
            f"{len(flagged)} action(s) reference a mutable version tag (e.g. @v2). "
            "Pin to a full commit SHA to guarantee reproducible, tamper-proof builds."
        ),
        weight=_CHECK_WEIGHTS["TPA-002"],
        action_refs=flagged,
    )


def _check_tpa003(
    refs: List[ActionRef],
    trusted_orgs_lower: Set[str],
) -> Optional[TPAFinding]:
    """TPA-003: Action org not in the trusted-orgs allowlist."""
    flagged: List[str] = []
    for r in refs:
        # docker:// images are handled by TPA-004
        if r.uses.startswith("docker://"):
            continue
        org = _parse_org(r.uses).lower()
        if org not in trusted_orgs_lower:
            flagged.append(r.uses)
    if not flagged:
        return None
    return TPAFinding(
        check_id="TPA-003",
        severity="HIGH",
        title="Action from untrusted organisation",
        detail=(
            f"{len(flagged)} action(s) originate from organisations outside the "
            "trusted-orgs allowlist. Review each action carefully before use."
        ),
        weight=_CHECK_WEIGHTS["TPA-003"],
        action_refs=flagged,
    )


def _check_tpa004(refs: List[ActionRef]) -> Optional[TPAFinding]:
    """TPA-004: Docker registry image used without a content-addressed digest."""
    flagged: List[str] = []
    for r in refs:
        if r.uses.startswith("docker://") and "@sha256:" not in r.uses:
            flagged.append(r.uses)
    if not flagged:
        return None
    return TPAFinding(
        check_id="TPA-004",
        severity="HIGH",
        title="Docker image used without content-addressed digest",
        detail=(
            f"{len(flagged)} step(s) pull a Docker image without a @sha256: digest. "
            "Without a digest the pulled image can change at any time."
        ),
        weight=_CHECK_WEIGHTS["TPA-004"],
        action_refs=flagged,
    )


def _check_tpa005(workflow: dict) -> List[TPAFinding]:
    """
    TPA-005: ``continue-on-error: true`` in a security-sensitive job step.

    Returns a list because each offending step produces its own finding,
    but the weight is deduplicated at the score level (only one TPA-005 weight
    is added regardless of how many individual findings exist).
    """
    findings: List[TPAFinding] = []
    jobs: dict = workflow.get("jobs", {})

    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue

        # Determine whether this job is security-sensitive
        job_name: str = (job.get("name") or "").lower()
        job_id_lower: str = job_id.lower()
        is_sensitive = any(
            kw in job_id_lower or kw in job_name for kw in _SENSITIVE_KEYWORDS
        )
        if not is_sensitive:
            continue

        steps = job.get("steps", []) or []
        for step in steps:
            if not isinstance(step, dict):
                continue
            if step.get("continue-on-error") is True:
                step_name = step.get("name") or step.get("uses") or "(unnamed step)"
                flagged_ref = step.get("uses") or step.get("run") or step_name
                findings.append(
                    TPAFinding(
                        check_id="TPA-005",
                        severity="MEDIUM",
                        title="Error suppression in security-sensitive job step",
                        detail=(
                            f"Step '{step_name}' in job '{job_id}' has "
                            "`continue-on-error: true`. Failures in security "
                            "checks will be silently ignored."
                        ),
                        weight=_CHECK_WEIGHTS["TPA-005"],
                        action_refs=[str(flagged_ref)],
                    )
                )

    return findings


def _check_tpa006(refs: List[ActionRef]) -> Optional[TPAFinding]:
    """TPA-006: Same action (by repo name) referenced with inconsistent versions."""
    # Map bare repo name → set of ref strings seen
    repo_to_refs: Dict[str, Set[str]] = {}
    repo_to_uses: Dict[str, List[str]] = {}

    for r in refs:
        uses = r.uses
        # Skip docker images — no repo name concept
        if uses.startswith("docker://"):
            continue
        # Extract the repo name: part between the first `/` and the `@`
        # e.g. "actions/checkout@v3" → "checkout"
        try:
            after_slash = uses.split("/", 1)[1]  # "checkout@v3"
            repo_name = after_slash.rsplit("@", 1)[0]  # "checkout"
        except IndexError:
            continue
        ref = _parse_ref(uses)
        repo_to_refs.setdefault(repo_name, set()).add(ref)
        repo_to_uses.setdefault(repo_name, []).append(uses)

    inconsistent_uses: List[str] = []
    detail_parts: List[str] = []
    for repo_name, ref_set in repo_to_refs.items():
        if len(ref_set) > 1:
            all_uses = list(dict.fromkeys(repo_to_uses[repo_name]))  # deduplicate, preserve order
            inconsistent_uses.extend(all_uses)
            detail_parts.append(f"'{repo_name}' used with refs: {sorted(ref_set)}")

    if not inconsistent_uses:
        return None
    return TPAFinding(
        check_id="TPA-006",
        severity="MEDIUM",
        title="Same action referenced with inconsistent versions",
        detail=(
            "Version inconsistency detected — the same action is pinned to "
            "different refs in different jobs: " + "; ".join(detail_parts)
        ),
        weight=_CHECK_WEIGHTS["TPA-006"],
        action_refs=inconsistent_uses,
    )


def _check_tpa007(refs: List[ActionRef]) -> Optional[TPAFinding]:
    """TPA-007: More than 15 distinct third-party uses references in the workflow."""
    distinct_uses: Set[str] = {r.uses for r in refs}
    count = len(distinct_uses)
    if count <= 15:
        return None
    return TPAFinding(
        check_id="TPA-007",
        severity="MEDIUM",
        title="Excessive third-party action surface area",
        detail=(
            f"{count} distinct third-party action references found (threshold: 15). "
            "A large number of external dependencies increases supply-chain exposure."
        ),
        weight=_CHECK_WEIGHTS["TPA-007"],
        action_refs=sorted(distinct_uses),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def audit(
    workflow: dict,
    workflow_name: str = "workflow",
    trusted_orgs: Optional[List[str]] = None,
) -> TPAResult:
    """
    Audit a GitHub Actions workflow dict for third-party action supply chain risks.

    Parameters
    ----------
    workflow:
        Parsed YAML/JSON content of the workflow file (as a plain dict).
    workflow_name:
        Friendly name used in the result (typically the filename).
    trusted_orgs:
        List of organisation names considered trustworthy.  Defaults to the
        k1N standard allowlist when *None*.

    Returns
    -------
    TPAResult
        Aggregated findings and risk score.
    """
    if trusted_orgs is None:
        trusted_orgs = _DEFAULT_TRUSTED_ORGS

    trusted_orgs_lower: Set[str] = {o.lower() for o in trusted_orgs}

    # Parse all third-party action references from the workflow
    refs: List[ActionRef] = _parse_action_refs(workflow)

    findings: List[TPAFinding] = []

    # --- TPA-001 -----------------------------------------------------------
    f001 = _check_tpa001(refs)
    tpa001_uses: Set[str] = set(f001.action_refs) if f001 else set()
    if f001:
        findings.append(f001)

    # --- TPA-002 -----------------------------------------------------------
    f002 = _check_tpa002(refs, tpa001_uses)
    if f002:
        findings.append(f002)

    # --- TPA-003 -----------------------------------------------------------
    f003 = _check_tpa003(refs, trusted_orgs_lower)
    if f003:
        findings.append(f003)

    # --- TPA-004 -----------------------------------------------------------
    f004 = _check_tpa004(refs)
    if f004:
        findings.append(f004)

    # --- TPA-005 -----------------------------------------------------------
    findings.extend(_check_tpa005(workflow))

    # --- TPA-006 -----------------------------------------------------------
    f006 = _check_tpa006(refs)
    if f006:
        findings.append(f006)

    # --- TPA-007 -----------------------------------------------------------
    f007 = _check_tpa007(refs)
    if f007:
        findings.append(f007)

    # Deduplicate by check_id when summing weights for the score
    fired_check_ids: Set[str] = {f.check_id for f in findings}
    risk_score: int = min(100, sum(_CHECK_WEIGHTS[cid] for cid in fired_check_ids))

    return TPAResult(
        workflow_name=workflow_name,
        total_action_refs=len(refs),
        findings=findings,
        risk_score=risk_score,
    )


def audit_many(
    workflows: List[dict],
    names: Optional[List[str]] = None,
    trusted_orgs: Optional[List[str]] = None,
) -> List[TPAResult]:
    """
    Audit multiple workflow dicts in one call.

    Parameters
    ----------
    workflows:
        Sequence of parsed workflow dicts.
    names:
        Optional parallel sequence of workflow names.  Falls back to
        ``"workflow-{i}"`` when *None* or shorter than *workflows*.
    trusted_orgs:
        Passed through to every :func:`audit` call unchanged.

    Returns
    -------
    List[TPAResult]
        One result per workflow, in input order.
    """
    results: List[TPAResult] = []
    for i, wf in enumerate(workflows):
        name = (names[i] if names and i < len(names) else f"workflow-{i}")
        results.append(audit(wf, workflow_name=name, trusted_orgs=trusted_orgs))
    return results
