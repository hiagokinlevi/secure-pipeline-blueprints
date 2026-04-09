"""
GitLab CI Pipeline Security Auditor
======================================
Scans .gitlab-ci.yml files for common security misconfigurations,
following the same interface pattern as pipeline_auditor.py.

Checks performed:
  - GL-001 HIGH:     CI credentials or tokens echoed in script blocks
                     (echo $CI_REGISTRY_PASSWORD, $DEPLOY_TOKEN, etc.)
  - GL-002 HIGH:     Jobs missing a 'timeout' directive (runaway build risk)
  - GL-003 HIGH:     Docker image using ':latest' tag or no tag at all
                     (supply chain / reproducibility risk)
  - GL-004 MEDIUM:   'allow_failure: true' on security-relevant stages or jobs
                     (sast, sca, secrets, scan, security, audit)
  - GL-005 MEDIUM:   Deploy-stage jobs with no 'rules' or 'only' restriction
                     (unprotected deployment trigger)
  - GL-006 MEDIUM:   GIT_DEPTH: "0" or 0 in variables block
                     (exposes full git history when unnecessary)
  - GL-007 MEDIUM:   Docker-in-Docker (docker:dind) service used without
                     DOCKER_TLS_CERTDIR set (insecure DinD config)
  - GL-008 LOW:      Artifacts defined without an 'expire_in' directive
                     (artifacts stored indefinitely, wasting storage and
                     potentially exposing build artefacts)

Usage:
    from shared.validators.gitlab_ci_auditor import (
        audit_gitlab_ci_file,
        GitLabAuditResult,
        GitLabFinding,
    )

    result = audit_gitlab_ci_file(Path(".gitlab-ci.yml"))
    for f in result.findings:
        print(f"[{f.severity.upper()}] {f.rule_id} @ {f.location}: {f.message}")

    if not result.passed:
        print("Pipeline has HIGH or CRITICAL findings — review before merging.")
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class GitLabFinding:
    """A single security finding from a .gitlab-ci.yml audit."""

    rule_id: str
    severity: str        # "critical", "high", "medium", "low"
    location: str        # e.g. "jobs.build_job.script[2]"
    message: str
    remediation: str
    evidence: str = ""   # The specific value or line that triggered the finding


@dataclass
class GitLabAuditResult:
    """Results of auditing a single .gitlab-ci.yml file."""

    file_path: Path
    pipeline_name: str
    findings: list[GitLabFinding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """True if no critical or high findings are present."""
        return not any(f.severity in ("critical", "high") for f in self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "medium")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "low")

    def findings_by_rule(self, rule_id: str) -> list[GitLabFinding]:
        return [f for f in self.findings if f.rule_id == rule_id]

    def summary(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        return (
            f"[{status}] {self.pipeline_name} — "
            f"CRITICAL={self.critical_count} "
            f"HIGH={self.high_count} "
            f"MEDIUM={self.medium_count} "
            f"LOW={self.low_count}"
        )


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Regex for detecting secret/credential variable echoes in script lines
_SECRET_ECHO_RE = re.compile(
    r"echo\s+['\"]?.*\$(?:CI_REGISTRY_(?:USER|PASSWORD)|CI_JOB_TOKEN|"
    r"CI_DEPLOY_(?:USER|PASSWORD)|CI_PIPELINE_TRIGGERED|"
    r"(?:[A-Z][A-Z0-9_]*(?:TOKEN|PASSWORD|SECRET|KEY|CREDENTIAL)[A-Z0-9_]*))",
    re.IGNORECASE,
)

# Broad "looks like a secret variable" pattern for echo detection
_SECRET_VAR_RE = re.compile(
    r"echo\s+['\"]?.*\$(?:[A-Z_]*(?:TOKEN|PASSWORD|SECRET|KEY|CREDENTIAL)[A-Z_0-9]*)",
    re.IGNORECASE,
)

# Stage names that are security-related — allow_failure on these is risky
_SECURITY_STAGES = {
    "sast", "sca", "secrets", "secret", "scan", "security",
    "audit", "lint-security", "security-test", "security_test",
}

# Docker-in-Docker image pattern
_DIND_IMAGE_RE = re.compile(r"docker:\S*dind\S*", re.IGNORECASE)

# Image tag patterns:
#   - Ends with :latest
#   - Has no : at all (implicit latest)
_LATEST_TAG_RE = re.compile(r"^[a-zA-Z0-9\-._/]+:latest$")
_NO_TAG_RE = re.compile(r"^[a-zA-Z0-9\-._/]+$")

# Built-in GitLab images / service images that don't need a tag check
_BUILTIN_IMAGE_PREFIXES = (
    "alpine",
    "busybox",
    "scratch",
)


# ---------------------------------------------------------------------------
# Internal checkers
# ---------------------------------------------------------------------------

def _is_job_key(key: str, pipeline: dict[str, Any]) -> bool:
    """Return True if 'key' is a job definition, not a top-level keyword."""
    _TOP_LEVEL_KEYS = {
        "image", "services", "before_script", "after_script", "stages",
        "variables", "cache", "include", "workflow", "default", "pages",
    }
    if key.startswith("."):  # Template/hidden job
        return False
    if key in _TOP_LEVEL_KEYS:
        return False
    val = pipeline.get(key)
    return isinstance(val, dict)


def _iter_jobs(pipeline: dict[str, Any]):
    """Yield (job_name, job_dict) for every concrete job in the pipeline."""
    for key, val in pipeline.items():
        if _is_job_key(key, pipeline):
            yield key, val


def _script_lines(job: dict[str, Any]) -> list[tuple[str, str]]:
    """
    Yield (phase, line) tuples for all script lines in before_script,
    script, and after_script blocks of a job.
    """
    for phase in ("before_script", "script", "after_script"):
        block = job.get(phase, [])
        if isinstance(block, list):
            for line in block:
                if isinstance(line, str):
                    yield phase, line


def _get_image_name(image_val: Any) -> Optional[str]:
    """Extract the image name string from a job.image value (string or dict)."""
    if isinstance(image_val, str):
        return image_val
    if isinstance(image_val, dict):
        return image_val.get("name")
    return None


def _check_gl001_secret_echo(
    job_name: str,
    job: dict[str, Any],
    result: GitLabAuditResult,
) -> None:
    """GL-001: CI secret/token echoed in script block."""
    for i, (phase, line) in enumerate(script_lines := list(_script_lines(job))):
        stripped = line.strip()
        if _SECRET_VAR_RE.search(stripped) or _SECRET_ECHO_RE.search(stripped):
            result.findings.append(
                GitLabFinding(
                    rule_id="GL-001",
                    severity="high",
                    location=f"jobs.{job_name}.{phase}[{i}]",
                    message=(
                        f"Job '{job_name}' echoes a secret or credential variable "
                        f"in the '{phase}' block. Secrets in logs are visible to "
                        "all project members with log access."
                    ),
                    remediation=(
                        "Remove the echo statement, or mask the variable via "
                        "Settings → CI/CD → Variables → Masked. Never print "
                        "secrets to CI logs."
                    ),
                    evidence=stripped[:120],
                )
            )


def _check_gl002_missing_timeout(
    job_name: str,
    job: dict[str, Any],
    result: GitLabAuditResult,
) -> None:
    """GL-002: Job missing a 'timeout' directive."""
    if "timeout" not in job:
        result.findings.append(
            GitLabFinding(
                rule_id="GL-002",
                severity="high",
                location=f"jobs.{job_name}",
                message=(
                    f"Job '{job_name}' has no 'timeout' directive. Without a "
                    "timeout, a hung job consumes runner resources indefinitely "
                    "and can mask supply-chain or denial-of-service attacks."
                ),
                remediation=(
                    "Add 'timeout: 30 minutes' (or an appropriate value) to the "
                    "job definition. GitLab default is 1 hour."
                ),
                evidence="",
            )
        )


def _check_gl003_unpinned_image(
    job_name: str,
    job: dict[str, Any],
    result: GitLabAuditResult,
) -> None:
    """GL-003: Docker image using ':latest' tag or no tag at all."""
    image_val = job.get("image")
    if image_val is None:
        return  # Job inherits global image — checked separately

    name = _get_image_name(image_val)
    if not name:
        return

    # Ignore images with a digest pin (contains @sha256:)
    if "@sha256:" in name:
        return
    # Ignore local/built images (start with .)
    if name.startswith("."):
        return

    is_latest = _LATEST_TAG_RE.match(name) is not None
    is_no_tag = _NO_TAG_RE.match(name) is not None and ":" not in name

    if is_latest or is_no_tag:
        reason = "uses ':latest' tag" if is_latest else "has no version tag (implicit 'latest')"
        result.findings.append(
            GitLabFinding(
                rule_id="GL-003",
                severity="high",
                location=f"jobs.{job_name}.image",
                message=(
                    f"Job '{job_name}' {reason}. Unpinned images are rebuilt "
                    "at any time, creating supply-chain risk and breaking "
                    "reproducibility."
                ),
                remediation=(
                    "Pin the image to a specific version tag (e.g. 'python:3.12-slim') "
                    "or a digest hash (e.g. 'python:3.12@sha256:abc123...')."
                ),
                evidence=name,
            )
        )


def _check_gl004_allow_failure_security(
    job_name: str,
    job: dict[str, Any],
    result: GitLabAuditResult,
) -> None:
    """GL-004: allow_failure: true on a security-relevant stage or job."""
    if not job.get("allow_failure", False):
        return

    stage = str(job.get("stage", "")).lower()
    job_lower = job_name.lower()

    is_security_stage = stage in _SECURITY_STAGES
    is_security_job = any(kw in job_lower for kw in _SECURITY_STAGES)

    if is_security_stage or is_security_job:
        result.findings.append(
            GitLabFinding(
                rule_id="GL-004",
                severity="medium",
                location=f"jobs.{job_name}.allow_failure",
                message=(
                    f"Job '{job_name}' (stage: '{stage}') has 'allow_failure: true'. "
                    "Security jobs that are allowed to fail silently defeat the purpose "
                    "of the security gate — failures will not block the pipeline."
                ),
                remediation=(
                    "Remove 'allow_failure: true' from security-related jobs so that "
                    "findings block the pipeline. If you need a non-blocking scan, "
                    "separate it into a dedicated reporting stage."
                ),
                evidence=f"allow_failure: true on stage '{stage}'",
            )
        )


def _check_gl005_deploy_no_rules(
    job_name: str,
    job: dict[str, Any],
    result: GitLabAuditResult,
) -> None:
    """GL-005: Deploy-stage job with no 'rules' or 'only' restriction."""
    stage = str(job.get("stage", "")).lower()
    if stage not in ("deploy", "release", "publish", "production", "prod"):
        return

    has_rules = "rules" in job
    has_only = "only" in job

    if not has_rules and not has_only:
        result.findings.append(
            GitLabFinding(
                rule_id="GL-005",
                severity="medium",
                location=f"jobs.{job_name}",
                message=(
                    f"Deploy job '{job_name}' (stage: '{stage}') has no 'rules' "
                    "or 'only' restriction. It will trigger on every pipeline run, "
                    "including feature branches and merge requests."
                ),
                remediation=(
                    "Add a 'rules' block restricting deployment to protected "
                    "branches (e.g. main/master) or specific pipeline sources:\n"
                    "  rules:\n"
                    "    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH"
                ),
                evidence=f"stage: {stage}",
            )
        )


def _check_gl006_git_depth_zero(
    pipeline: dict[str, Any],
    result: GitLabAuditResult,
) -> None:
    """GL-006: GIT_DEPTH: 0 in top-level or default variables block."""
    # Top-level variables
    variables = pipeline.get("variables", {})
    if isinstance(variables, dict):
        depth_val = variables.get("GIT_DEPTH")
        if str(depth_val) == "0":
            result.findings.append(
                GitLabFinding(
                    rule_id="GL-006",
                    severity="medium",
                    location="variables.GIT_DEPTH",
                    message=(
                        "GIT_DEPTH is set to 0, which clones the full git history. "
                        "Full history exposes deleted secrets and sensitive commit "
                        "messages to every runner that processes this pipeline."
                    ),
                    remediation=(
                        "Use a shallow clone depth (e.g. GIT_DEPTH: '20') unless "
                        "a specific job requires the full history. Annotate the "
                        "exception with a comment explaining the requirement."
                    ),
                    evidence="GIT_DEPTH: 0",
                )
            )

    # Per-job variables
    for job_name, job in _iter_jobs(pipeline):
        job_vars = job.get("variables", {})
        if isinstance(job_vars, dict):
            depth_val = job_vars.get("GIT_DEPTH")
            if str(depth_val) == "0":
                result.findings.append(
                    GitLabFinding(
                        rule_id="GL-006",
                        severity="medium",
                        location=f"jobs.{job_name}.variables.GIT_DEPTH",
                        message=(
                            f"Job '{job_name}' sets GIT_DEPTH: 0 (full git history). "
                            "Expose the full history only when explicitly required."
                        ),
                        remediation=(
                            "Use a shallow clone (e.g. GIT_DEPTH: '20') and document "
                            "why the full history is needed if it truly is."
                        ),
                        evidence=f"GIT_DEPTH: 0 in job '{job_name}'",
                    )
                )


def _check_gl007_dind_no_tls(
    pipeline: dict[str, Any],
    result: GitLabAuditResult,
) -> None:
    """GL-007: docker:dind service used without DOCKER_TLS_CERTDIR set."""
    uses_dind = False

    # Global services
    global_services = pipeline.get("services", [])
    for svc in (global_services if isinstance(global_services, list) else []):
        name = svc if isinstance(svc, str) else svc.get("name", "")
        if _DIND_IMAGE_RE.search(str(name)):
            uses_dind = True
            break

    # Per-job services
    for _job_name, job in _iter_jobs(pipeline):
        for svc in (job.get("services", []) or []):
            name = svc if isinstance(svc, str) else svc.get("name", "")
            if _DIND_IMAGE_RE.search(str(name)):
                uses_dind = True
                break

    if not uses_dind:
        return

    # Check that DOCKER_TLS_CERTDIR is set somewhere
    global_vars = pipeline.get("variables", {})
    tls_set = "DOCKER_TLS_CERTDIR" in (global_vars or {})

    if not tls_set:
        # Also check default.variables if present
        default = pipeline.get("default", {})
        default_vars = default.get("variables", {}) if isinstance(default, dict) else {}
        tls_set = "DOCKER_TLS_CERTDIR" in default_vars

    if not tls_set:
        result.findings.append(
            GitLabFinding(
                rule_id="GL-007",
                severity="medium",
                location="services",
                message=(
                    "Docker-in-Docker (docker:dind) is used but DOCKER_TLS_CERTDIR "
                    "is not set in the variables block. Without TLS, the Docker "
                    "daemon is accessible over an unencrypted socket, allowing "
                    "container breakout on shared runners."
                ),
                remediation=(
                    "Add to the variables block:\n"
                    "  variables:\n"
                    "    DOCKER_TLS_CERTDIR: '/certs'\n"
                    "And update the Docker client to use TLS_VERIFY."
                ),
                evidence="docker:dind without DOCKER_TLS_CERTDIR",
            )
        )


def _check_gl008_artifacts_no_expiry(
    job_name: str,
    job: dict[str, Any],
    result: GitLabAuditResult,
) -> None:
    """GL-008: Artifacts block missing 'expire_in' directive."""
    artifacts = job.get("artifacts")
    if not isinstance(artifacts, dict):
        return

    # Reports-only artifacts are exempt (they're small and managed by GitLab)
    if set(artifacts.keys()) == {"reports"}:
        return

    if "expire_in" not in artifacts:
        result.findings.append(
            GitLabFinding(
                rule_id="GL-008",
                severity="low",
                location=f"jobs.{job_name}.artifacts",
                message=(
                    f"Job '{job_name}' uploads artifacts without setting 'expire_in'. "
                    "Artifacts stored indefinitely accumulate storage costs and may "
                    "expose build outputs (compiled binaries, reports) beyond their "
                    "useful lifespan."
                ),
                remediation=(
                    "Add 'expire_in' to the artifacts block, e.g.:\n"
                    "  artifacts:\n"
                    "    expire_in: 7 days"
                ),
                evidence="artifacts: { expire_in: <missing> }",
            )
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def audit_gitlab_ci_file(pipeline_path: Path) -> GitLabAuditResult:
    """
    Audit a single .gitlab-ci.yml file for security misconfigurations.

    Args:
        pipeline_path:  Path to the .gitlab-ci.yml file to audit.

    Returns:
        GitLabAuditResult containing all findings and warnings.

    Raises:
        FileNotFoundError: If pipeline_path does not exist.
        yaml.YAMLError:     If the file is not valid YAML.
    """
    raw = pipeline_path.read_text(encoding="utf-8")

    try:
        pipeline: dict[str, Any] = yaml.safe_load(raw) or {}
    except yaml.YAMLError as exc:
        result = GitLabAuditResult(
            file_path=pipeline_path,
            pipeline_name=pipeline_path.name,
        )
        result.warnings.append(f"YAML parse error: {exc}")
        return result

    pipeline_name = pipeline_path.stem or pipeline_path.name
    result = GitLabAuditResult(
        file_path=pipeline_path,
        pipeline_name=pipeline_name,
    )

    # --- Global checks ---
    _check_gl006_git_depth_zero(pipeline, result)
    _check_gl007_dind_no_tls(pipeline, result)

    # --- Per-job checks ---
    for job_name, job in _iter_jobs(pipeline):
        _check_gl001_secret_echo(job_name, job, result)
        _check_gl002_missing_timeout(job_name, job, result)
        _check_gl003_unpinned_image(job_name, job, result)
        _check_gl004_allow_failure_security(job_name, job, result)
        _check_gl005_deploy_no_rules(job_name, job, result)
        _check_gl008_artifacts_no_expiry(job_name, job, result)

    return result


def audit_gitlab_ci_directory(
    directory: Path,
    pattern: str = "*.yml",
) -> list[GitLabAuditResult]:
    """
    Audit all .gitlab-ci.yml files matching pattern in a directory.

    Args:
        directory:  Directory to search in.
        pattern:    Glob pattern for pipeline files (default "*.yml").

    Returns:
        List of GitLabAuditResult objects, one per matched file.
    """
    results: list[GitLabAuditResult] = []
    for path in sorted(directory.glob(pattern)):
        try:
            results.append(audit_gitlab_ci_file(path))
        except Exception as exc:
            r = GitLabAuditResult(
                file_path=path,
                pipeline_name=path.name,
            )
            r.warnings.append(f"Failed to audit {path.name}: {exc}")
            results.append(r)
    return results
