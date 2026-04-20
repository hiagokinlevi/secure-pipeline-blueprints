#!/usr/bin/env python3
"""Pipeline Misconfiguration Linter

Scans CI configuration files for insecure patterns across:
- GitHub Actions workflows (.github/workflows/*.yml, *.yaml)
- GitLab CI (.gitlab-ci.yml, *.gitlab-ci*.yml)
- Jenkinsfiles (Jenkinsfile, *.jenkinsfile)

Checks include:
- Unpinned GitHub Actions uses references (not pinned to commit SHA)
- Overly broad GitHub token permissions (write-all)
- Potential secret exposure in env/variables values
- Unpinned container images in GitHub Actions / GitLab CI
- Jenkins shell steps that may echo/print secrets

Exit codes:
- 0: no findings
- 1: findings detected
- 2: execution error
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Iterable

import yaml


SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"

SECRET_KEY_RE = re.compile(r"(?i)(secret|token|password|passwd|apikey|api_key|private[_-]?key)")
SENSITIVE_VALUE_RE = re.compile(
    r"(?i)(ghp_[a-z0-9]{20,}|github_pat_[a-z0-9_]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----)"
)
SHA_PIN_RE = re.compile(r"^[a-f0-9]{40}$")
IMAGE_PIN_RE = re.compile(r".+@sha256:[a-f0-9]{64}$")


@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str
    file: str
    line: int | None = None


def iter_files(root: Path, explicit: list[str] | None = None) -> Iterable[Path]:
    if explicit:
        for item in explicit:
            p = (root / item).resolve() if not Path(item).is_absolute() else Path(item)
            if p.exists() and p.is_file():
                yield p
        return

    for p in root.rglob("*"):
        if not p.is_file():
            continue
        name = p.name
        s = str(p)
        if "/.git/" in s or "\\.git\\" in s:
            continue

        if ".github/workflows" in s and name.endswith((".yml", ".yaml")):
            yield p
            continue
        if name in {".gitlab-ci.yml", ".gitlab-ci.yaml"} or "gitlab-ci" in name and name.endswith((".yml", ".yaml")):
            yield p
            continue
        if name == "Jenkinsfile" or name.lower().endswith(".jenkinsfile"):
            yield p


def load_yaml_file(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def is_github_workflow(path: Path) -> bool:
    return ".github/workflows" in str(path) and path.suffix in {".yml", ".yaml"}


def is_gitlab_ci(path: Path) -> bool:
    n = path.name
    return n in {".gitlab-ci.yml", ".gitlab-ci.yaml"} or ("gitlab-ci" in n and path.suffix in {".yml", ".yaml"})


def is_jenkinsfile(path: Path) -> bool:
    return path.name == "Jenkinsfile" or path.name.lower().endswith(".jenkinsfile")


def find_line(text: str, needle: str) -> int | None:
    for i, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return i
    return None


def lint_github(path: Path, findings: list[Finding]) -> None:
    raw = path.read_text(encoding="utf-8", errors="ignore")
    doc = load_yaml_file(path)
    if not isinstance(doc, dict):
        return

    # permissions: write-all
    perms = doc.get("permissions")
    if isinstance(perms, str) and perms.strip().lower() == "write-all":
        findings.append(
            Finding(
                rule_id="GH001",
                severity=SEVERITY_HIGH,
                message="Top-level permissions set to write-all; use least privilege.",
                file=str(path),
                line=find_line(raw, "permissions:"),
            )
        )

    # unpinned actions
    jobs = doc.get("jobs", {})
    if isinstance(jobs, dict):
        for _, job in jobs.items():
            if not isinstance(job, dict):
                continue
            job_perms = job.get("permissions")
            if isinstance(job_perms, str) and job_perms.strip().lower() == "write-all":
                findings.append(
                    Finding(
                        rule_id="GH002",
                        severity=SEVERITY_HIGH,
                        message="Job-level permissions set to write-all; scope down permissions.",
                        file=str(path),
                        line=find_line(raw, "permissions:"),
                    )
                )

            container = job.get("container")
            if isinstance(container, str) and ":" in container and not IMAGE_PIN_RE.match(container):
                findings.append(
                    Finding(
                        rule_id="GH003",
                        severity=SEVERITY_MEDIUM,
                        message=f"Container image '{container}' is not pinned by digest.",
                        file=str(path),
                        line=find_line(raw, str(container)),
                    )
                )

            steps = job.get("steps", [])
            if not isinstance(steps, list):
                continue
            for step in steps:
                if not isinstance(step, dict):
                    continue
                uses = step.get("uses")
                if isinstance(uses, str) and "@" in uses:
                    ref = uses.rsplit("@", 1)[-1]
                    if not SHA_PIN_RE.match(ref):
                        findings.append(
                            Finding(
                                rule_id="GH004",
                                severity=SEVERITY_MEDIUM,
                                message=f"Action '{uses}' is not pinned to a commit SHA.",
                                file=str(path),
                                line=find_line(raw, uses),
                            )
                        )

                env = step.get("env")
                if isinstance(env, dict):
                    for k, v in env.items():
                        v_str = "" if v is None else str(v)
                        if SECRET_KEY_RE.search(str(k)) and "${{" not in v_str and "secrets." not in v_str:
                            findings.append(
                                Finding(
                                    rule_id="GH005",
                                    severity=SEVERITY_HIGH,
                                    message=f"Potential hardcoded secret in env '{k}'.",
                                    file=str(path),
                                    line=find_line(raw, str(k)),
                                )
                            )
                        elif SENSITIVE_VALUE_RE.search(v_str):
                            findings.append(
                                Finding(
                                    rule_id="GH006",
                                    severity=SEVERITY_HIGH,
                                    message=f"Sensitive token-like value detected in env '{k}'.",
                                    file=str(path),
                                    line=find_line(raw, v_str[:12]),
                                )
                            )


def lint_gitlab(path: Path, findings: list[Finding]) -> None:
    raw = path.read_text(encoding="utf-8", errors="ignore")
    doc = load_yaml_file(path)
    if not isinstance(doc, dict):
        return

    # variables section
    variables = doc.get("variables")
    if isinstance(variables, dict):
        for k, v in variables.items():
            v_str = "" if v is None else str(v)
            if SECRET_KEY_RE.search(str(k)) and "$" not in v_str:
                findings.append(
                    Finding(
                        rule_id="GL001",
                        severity=SEVERITY_HIGH,
                        message=f"Potential hardcoded secret in variables '{k}'.",
                        file=str(path),
                        line=find_line(raw, str(k)),
                    )
                )
            elif SENSITIVE_VALUE_RE.search(v_str):
                findings.append(
                    Finding(
                        rule_id="GL002",
                        severity=SEVERITY_HIGH,
                        message=f"Sensitive token-like value detected in variables '{k}'.",
                        file=str(path),
                        line=find_line(raw, v_str[:12]),
                    )
                )

    # image pinning at top-level and per-job
    top_image = doc.get("image")
    if isinstance(top_image, str) and ":" in top_image and not IMAGE_PIN_RE.match(top_image):
        findings.append(
            Finding(
                rule_id="GL003",
                severity=SEVERITY_MEDIUM,
                message=f"Top-level image '{top_image}' is not pinned by digest.",
                file=str(path),
                line=find_line(raw, "image:"),
            )
        )

    for job_name, cfg in doc.items():
        if not isinstance(cfg, dict):
            continue
        image = cfg.get("image")
        if isinstance(image, str) and ":" in image and not IMAGE_PIN_RE.match(image):
            findings.append(
                Finding(
                    rule_id="GL004",
                    severity=SEVERITY_MEDIUM,
                    message=f"Job '{job_name}' image '{image}' is not pinned by digest.",
                    file=str(path),
                    line=find_line(raw, str(image)),
                )
            )


def lint_jenkins(path: Path, findings: list[Finding]) -> None:
    raw = path.read_text(encoding="utf-8", errors="ignore")
    lines = raw.splitlines()
    for idx, line in enumerate(lines, start=1):
        low = line.lower()
        if ("echo " in low or "printenv" in low or "env |" in low) and (
            "secret" in low or "token" in low or "password" in low
        ):
            findings.append(
                Finding(
                    rule_id="JK001",
                    severity=SEVERITY_HIGH,
                    message="Potential secret exposure in Jenkins shell/log command.",
                    file=str(path),
                    line=idx,
                )
            )


def format_text(findings: list[Finding]) -> str:
    if not findings:
        return "No misconfigurations detected."
    out = []
    for f in findings:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        out.append(f"[{f.severity}] {f.rule_id} {loc} - {f.message}")
    out.append(f"Total findings: {len(findings)}")
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description="Lint CI configs for security misconfigurations.")
    parser.add_argument("--path", default=".", help="Repository root path (default: current directory)")
    parser.add_argument("--files", nargs="*", help="Optional explicit files to scan")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    args = parser.parse_args()

    root = Path(args.path).resolve()
    if not root.exists():
        print("Path does not exist", file=sys.stderr)
        return 2

    findings: list[Finding] = []

    for path in iter_files(root, args.files):
        try:
            if is_github_workflow(path):
                lint_github(path, findings)
            elif is_gitlab_ci(path):
                lint_gitlab(path, findings)
            elif is_jenkinsfile(path):
                lint_jenkins(path, findings)
        except Exception as exc:
            findings.append(
                Finding(
                    rule_id="LINTERR",
                    severity=SEVERITY_LOW,
                    message=f"Failed to fully parse file: {exc}",
                    file=str(path),
                    line=None,
                )
            )

    if args.format == "json":
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        print(format_text(findings))

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
