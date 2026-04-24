#!/usr/bin/env python3
"""Branch-aware severity gate for SCA scanner JSON outputs.

Usage:
  python shared/severity_gate.py --input scanner.json [--threshold low|medium|high|critical] [--branch BRANCH]

Policy:
- Default threshold is branch-aware:
  - main/master/release/* => high (strict)
  - others => critical (relaxed)
- Any finding with severity >= threshold fails the gate (exit code 1)

Supported JSON styles (minimal, tool-agnostic):
- Top-level list of findings
- Dict with findings-like arrays under keys such as vulnerabilities/results/issues/findings/alerts
- Nested dict/list structures (best-effort recursive extraction)

A finding severity can be provided in keys like severity, level, or cvss_severity.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Iterable

SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class GateConfigError(ValueError):
    pass


def normalize_severity(value: Any) -> str | None:
    if value is None:
        return None
    s = str(value).strip().lower()
    aliases = {
        "info": "low",
        "informational": "low",
        "moderate": "medium",
        "sev_low": "low",
        "sev_medium": "medium",
        "sev_high": "high",
        "sev_critical": "critical",
    }
    s = aliases.get(s, s)
    return s if s in SEVERITY_ORDER else None


def branch_default_threshold(branch: str | None) -> str:
    b = (branch or "").strip().lower()
    if b in {"main", "master"} or b.startswith("release/"):
        return "high"
    return "critical"


def resolve_threshold(explicit: str | None, branch: str | None) -> str:
    if explicit:
        sev = normalize_severity(explicit)
        if not sev:
            raise GateConfigError("threshold must be one of: low|medium|high|critical")
        return sev
    return branch_default_threshold(branch)


def iter_findings(node: Any) -> Iterable[dict[str, Any]]:
    if isinstance(node, list):
        for item in node:
            if isinstance(item, dict):
                yield item
            else:
                yield from iter_findings(item)
        return

    if isinstance(node, dict):
        findings_keys = {"vulnerabilities", "results", "issues", "findings", "alerts"}
        for key, value in node.items():
            if key.lower() in findings_keys and isinstance(value, (list, dict)):
                yield from iter_findings(value)

        # Heuristic: if this dict itself looks like a finding, emit it.
        if any(k in node for k in ("severity", "level", "cvss_severity")):
            yield node

        # Recursive fallback for nested structures.
        for value in node.values():
            if isinstance(value, (dict, list)):
                yield from iter_findings(value)


def finding_severity(finding: dict[str, Any]) -> str | None:
    for key in ("severity", "level", "cvss_severity"):
        sev = normalize_severity(finding.get(key))
        if sev:
            return sev
    return None


def evaluate_gate(data: Any, threshold: str) -> tuple[int, list[str]]:
    threshold_rank = SEVERITY_ORDER[threshold]
    violations: list[str] = []
    total = 0

    for f in iter_findings(data):
        sev = finding_severity(f)
        if not sev:
            continue
        total += 1
        if SEVERITY_ORDER[sev] >= threshold_rank:
            pkg = f.get("package") or f.get("name") or f.get("id") or "unknown"
            violations.append(f"{sev}:{pkg}")

    return total, violations


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Enforce severity policy on scanner JSON output")
    parser.add_argument("--input", required=True, help="Path to scanner JSON output")
    parser.add_argument("--threshold", help="Severity threshold: low|medium|high|critical")
    parser.add_argument(
        "--branch",
        default=os.getenv("GITHUB_REF_NAME") or os.getenv("CI_COMMIT_REF_NAME") or "",
        help="Branch name used for branch-aware default threshold",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])

    try:
        threshold = resolve_threshold(args.threshold, args.branch)
    except GateConfigError as exc:
        print(f"[severity-gate] configuration error: {exc}", file=sys.stderr)
        return 2

    try:
        with open(args.input, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"[severity-gate] input file not found: {args.input}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"[severity-gate] invalid JSON: {exc}", file=sys.stderr)
        return 2

    total, violations = evaluate_gate(data, threshold)
    print(f"[severity-gate] branch={args.branch or '-'} threshold={threshold} findings={total} violations={len(violations)}")

    if violations:
        for v in violations[:20]:
            print(f"[severity-gate] violation: {v}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
