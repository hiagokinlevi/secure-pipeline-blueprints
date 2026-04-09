# SAST Findings Aggregator — Cyber Port Portfolio
# Copyright 2024 hiagokinlevi. Licensed under CC BY 4.0.
# https://creativecommons.org/licenses/by/4.0/
#
# Aggregate and analyze SAST findings from multiple tools, normalize them,
# detect quality and coverage gaps, and determine if a pipeline should fail.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Check ID weights — used to compute risk_score (unique check IDs that fired).
# ---------------------------------------------------------------------------
_CHECK_WEIGHTS: Dict[str, int] = {
    "SAST-001": 15,  # Finding has no CWE mapping
    "SAST-002": 45,  # Critical/High finding open > 30 days
    "SAST-003": 20,  # Same CWE reported with different severities across tools
    "SAST-004": 20,  # Suppressed finding without expiry_date
    "SAST-005": 25,  # Total CRITICAL/HIGH count exceeds threshold
    "SAST-006": 25,  # Security-sensitive file path with severity below HIGH
    "SAST-007": 5,   # Duplicate finding (same file+line+rule) across tools
}

# Keywords that indicate a security-sensitive file path (case-insensitive).
_SENSITIVE_PATH_KEYWORDS: Tuple[str, ...] = (
    "crypto",
    "auth",
    "secret",
    "password",
    "token",
    "login",
    "session",
    "jwt",
    "key",
    "cert",
)

# Severities considered critical or high.
_CRITICAL_HIGH: Set[str] = {"CRITICAL", "HIGH"}

# Severities below HIGH (SAST-006 trigger set).
_BELOW_HIGH: Set[str] = {"MEDIUM", "LOW", "INFO"}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class SASTFinding:
    """Represents a single finding emitted by a SAST tool."""

    finding_id: str          # unique ID (tool + rule_id + file_path + line_number)
    tool: str                # e.g. "semgrep", "bandit", "sonarqube", "codeql"
    rule_id: str
    file_path: str
    line_number: int
    severity: str            # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    cwe: Optional[str]       # e.g. "CWE-89" or None
    age_days: int            # days since the finding was first detected
    suppressed: bool         # True if manually suppressed / ignored
    expiry_date: Optional[str]  # ISO date string when suppressed with an expiry


@dataclass
class SASTAggFinding:
    """A meta-issue produced by the aggregator describing a pipeline quality gap."""

    check_id: str
    severity: str
    title: str
    detail: str
    weight: int
    affected_finding_ids: List[str] = field(default_factory=list)


@dataclass
class SASTAggResult:
    """The complete output of an aggregation run."""

    total_input_findings: int
    critical_count: int
    high_count: int
    findings: List[SASTAggFinding]      # meta-issues found by the aggregator
    risk_score: int                      # min(100, sum of weights for unique fired checks)
    pipeline_fail: bool                  # True when risk_score >= 50

    # ------------------------------------------------------------------
    # Convenience methods
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Return a JSON-serialisable dictionary representation."""
        return {
            "total_input_findings": self.total_input_findings,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "risk_score": self.risk_score,
            "pipeline_fail": self.pipeline_fail,
            "findings": [
                {
                    "check_id": f.check_id,
                    "severity": f.severity,
                    "title": f.title,
                    "detail": f.detail,
                    "weight": f.weight,
                    "affected_finding_ids": f.affected_finding_ids,
                }
                for f in self.findings
            ],
        }

    def summary(self) -> str:
        """Return a one-line human-readable summary of the result."""
        status = "FAIL" if self.pipeline_fail else "PASS"
        return (
            f"Pipeline: {status} | risk_score={self.risk_score} | "
            f"meta_findings={len(self.findings)} | "
            f"input_findings={self.total_input_findings} "
            f"(CRITICAL={self.critical_count}, HIGH={self.high_count})"
        )

    def by_severity(self) -> Dict[str, List[SASTAggFinding]]:
        """Group aggregator findings by their severity label."""
        groups: Dict[str, List[SASTAggFinding]] = {}
        for agg_finding in self.findings:
            groups.setdefault(agg_finding.severity, []).append(agg_finding)
        return groups


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_sensitive_path(file_path: str) -> bool:
    """Return True if *file_path* contains any security-sensitive keyword."""
    lower = file_path.lower()
    return any(kw in lower for kw in _SENSITIVE_PATH_KEYWORDS)


def _normalise_cwe(cwe: Optional[str]) -> Optional[str]:
    """Strip whitespace; return None for empty/None CWE values."""
    if cwe is None:
        return None
    stripped = cwe.strip()
    return stripped if stripped else None


# ---------------------------------------------------------------------------
# Core aggregation logic
# ---------------------------------------------------------------------------

def aggregate(
    findings: List[SASTFinding],
    critical_high_threshold: int = 10,
) -> SASTAggResult:
    """Aggregate SAST findings and check for pipeline quality/security issues.

    Parameters
    ----------
    findings:
        Raw SAST findings emitted by one or more tools.
    critical_high_threshold:
        Maximum allowed count of CRITICAL or HIGH findings before SAST-005
        fires.  Defaults to 10.

    Returns
    -------
    SASTAggResult
        Aggregated result including meta-findings, risk score, and pipeline
        gate decision.
    """
    agg_findings: List[SASTAggFinding] = []
    fired_check_ids: Set[str] = set()

    # Pre-compute counts used across multiple checks.
    critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in findings if f.severity == "HIGH")

    # ------------------------------------------------------------------
    # SAST-001 — Finding has no CWE mapping.
    # ------------------------------------------------------------------
    for f in findings:
        if _normalise_cwe(f.cwe) is None:
            agg_findings.append(
                SASTAggFinding(
                    check_id="SAST-001",
                    severity="MEDIUM",
                    title="Finding lacks CWE mapping",
                    detail=(
                        f"Finding '{f.finding_id}' (rule '{f.rule_id}' from tool "
                        f"'{f.tool}') has no CWE identifier, making triage and "
                        "remediation tracking harder."
                    ),
                    weight=_CHECK_WEIGHTS["SAST-001"],
                    affected_finding_ids=[f.finding_id],
                )
            )
            fired_check_ids.add("SAST-001")

    # ------------------------------------------------------------------
    # SAST-002 — Critical/High finding open for more than 30 days.
    # ------------------------------------------------------------------
    for f in findings:
        if f.severity in _CRITICAL_HIGH and f.age_days > 30:
            agg_findings.append(
                SASTAggFinding(
                    check_id="SAST-002",
                    severity="CRITICAL",
                    title="Stale critical/high finding exceeds 30-day SLA",
                    detail=(
                        f"Finding '{f.finding_id}' (severity={f.severity}) has been "
                        f"open for {f.age_days} days, exceeding the 30-day remediation "
                        "SLA for critical and high severity issues."
                    ),
                    weight=_CHECK_WEIGHTS["SAST-002"],
                    affected_finding_ids=[f.finding_id],
                )
            )
            fired_check_ids.add("SAST-002")

    # ------------------------------------------------------------------
    # SAST-003 — Same CWE reported with different severities across tools.
    # ------------------------------------------------------------------
    # Map: normalised CWE -> set of (tool, severity) pairs; track finding IDs.
    cwe_severity_map: Dict[str, Set[str]] = {}
    cwe_finding_ids: Dict[str, List[str]] = {}

    for f in findings:
        norm_cwe = _normalise_cwe(f.cwe)
        if norm_cwe is None:
            continue  # Skip unmapped CWEs — covered by SAST-001.
        cwe_severity_map.setdefault(norm_cwe, set()).add(f.severity)
        cwe_finding_ids.setdefault(norm_cwe, []).append(f.finding_id)

    for cwe, severities in cwe_severity_map.items():
        if len(severities) > 1:
            agg_findings.append(
                SASTAggFinding(
                    check_id="SAST-003",
                    severity="HIGH",
                    title="Severity disagreement across tools for the same CWE",
                    detail=(
                        f"CWE '{cwe}' is reported with conflicting severities "
                        f"{sorted(severities)} by different tools. Manual review "
                        "is required to establish the canonical severity."
                    ),
                    weight=_CHECK_WEIGHTS["SAST-003"],
                    affected_finding_ids=list(cwe_finding_ids[cwe]),
                )
            )
            fired_check_ids.add("SAST-003")

    # ------------------------------------------------------------------
    # SAST-004 — Suppressed finding without expiry_date.
    # ------------------------------------------------------------------
    for f in findings:
        if f.suppressed and f.expiry_date is None:
            agg_findings.append(
                SASTAggFinding(
                    check_id="SAST-004",
                    severity="HIGH",
                    title="Suppressed finding has no expiry date",
                    detail=(
                        f"Finding '{f.finding_id}' is suppressed/ignored but has no "
                        "expiry_date set. Indefinite suppressions may hide real "
                        "vulnerabilities and should include a review deadline."
                    ),
                    weight=_CHECK_WEIGHTS["SAST-004"],
                    affected_finding_ids=[f.finding_id],
                )
            )
            fired_check_ids.add("SAST-004")

    # ------------------------------------------------------------------
    # SAST-005 — Total CRITICAL/HIGH count exceeds configured threshold.
    # ------------------------------------------------------------------
    total_critical_high = critical_count + high_count
    if total_critical_high > critical_high_threshold:
        agg_findings.append(
            SASTAggFinding(
                check_id="SAST-005",
                severity="HIGH",
                title="CRITICAL/HIGH finding count exceeds threshold",
                detail=(
                    f"Found {total_critical_high} CRITICAL/HIGH findings "
                    f"({critical_count} CRITICAL, {high_count} HIGH), which exceeds "
                    f"the configured threshold of {critical_high_threshold}."
                ),
                weight=_CHECK_WEIGHTS["SAST-005"],
                affected_finding_ids=[
                    f.finding_id
                    for f in findings
                    if f.severity in _CRITICAL_HIGH
                ],
            )
        )
        fired_check_ids.add("SAST-005")

    # ------------------------------------------------------------------
    # SAST-006 — Security-sensitive file with severity below HIGH.
    # ------------------------------------------------------------------
    for f in findings:
        if _is_sensitive_path(f.file_path) and f.severity in _BELOW_HIGH:
            agg_findings.append(
                SASTAggFinding(
                    check_id="SAST-006",
                    severity="HIGH",
                    title="Low-severity finding in security-sensitive file",
                    detail=(
                        f"Finding '{f.finding_id}' (severity={f.severity}) is located "
                        f"in '{f.file_path}', which matches a security-sensitive path "
                        "keyword. Low/medium findings in sensitive files warrant "
                        "elevated scrutiny."
                    ),
                    weight=_CHECK_WEIGHTS["SAST-006"],
                    affected_finding_ids=[f.finding_id],
                )
            )
            fired_check_ids.add("SAST-006")

    # ------------------------------------------------------------------
    # SAST-007 — Duplicate finding (same file+line+rule) across tools.
    # ------------------------------------------------------------------
    # Dedup key -> set of tools that reported it, and list of finding IDs.
    dedup_tools: Dict[Tuple[str, int, str], Set[str]] = {}
    dedup_ids: Dict[Tuple[str, int, str], List[str]] = {}

    for f in findings:
        key: Tuple[str, int, str] = (f.file_path, f.line_number, f.rule_id)
        dedup_tools.setdefault(key, set()).add(f.tool)
        dedup_ids.setdefault(key, []).append(f.finding_id)

    for key, tools in dedup_tools.items():
        if len(tools) > 1:
            file_path, line_number, rule_id = key
            agg_findings.append(
                SASTAggFinding(
                    check_id="SAST-007",
                    severity="LOW",
                    title="Duplicate finding reported by multiple tools",
                    detail=(
                        f"Rule '{rule_id}' at '{file_path}:{line_number}' was "
                        f"reported by {len(tools)} tools ({sorted(tools)}). "
                        "Deduplicate tool configurations to reduce noise."
                    ),
                    weight=_CHECK_WEIGHTS["SAST-007"],
                    affected_finding_ids=list(dedup_ids[key]),
                )
            )
            fired_check_ids.add("SAST-007")

    # ------------------------------------------------------------------
    # Compute risk_score using unique fired check IDs only.
    # ------------------------------------------------------------------
    risk_score = min(100, sum(_CHECK_WEIGHTS[cid] for cid in fired_check_ids))
    pipeline_fail = risk_score >= 50

    return SASTAggResult(
        total_input_findings=len(findings),
        critical_count=critical_count,
        high_count=high_count,
        findings=agg_findings,
        risk_score=risk_score,
        pipeline_fail=pipeline_fail,
    )


def aggregate_many(
    finding_sets: List[List[SASTFinding]],
    critical_high_threshold: int = 10,
) -> List[SASTAggResult]:
    """Aggregate multiple independent sets of SAST findings.

    Parameters
    ----------
    finding_sets:
        A list of finding lists, each representing a separate scan run or
        target scope.
    critical_high_threshold:
        Passed through to each ``aggregate`` call unchanged.

    Returns
    -------
    List[SASTAggResult]
        One result per input finding set, in the same order.
    """
    return [
        aggregate(fs, critical_high_threshold=critical_high_threshold)
        for fs in finding_sets
    ]
