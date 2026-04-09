# pipeline_secret_scanner.py
# CI/CD Pipeline Secret Scanner — scans pipeline log content and environment
# variable configs for exposed secrets.  Works fully offline on text data;
# no live API calls are made.
#
# Copyright (c) 2024 Cyber Port contributors
# Licensed under the Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
#
# SPDX-License-Identifier: CC-BY-4.0

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Check weight registry
# Each key is a check ID; the value is the integer weight added to risk_score
# when that check fires.  Duplicate findings for the same check ID within a
# single scan do NOT increase the score a second time.
# ---------------------------------------------------------------------------
_CHECK_WEIGHTS: Dict[str, int] = {
    "PIPE-001": 40,  # AWS credential exposed in log        — CRITICAL
    "PIPE-002": 40,  # GitHub / GitLab token in log         — CRITICAL
    "PIPE-003": 25,  # Base64-encoded secret in log         — HIGH
    "PIPE-004": 40,  # Secret in curl / wget command        — CRITICAL
    "PIPE-005": 25,  # Secret variable not masked           — HIGH
    "PIPE-006": 25,  # Plaintext Docker registry credential — HIGH
    "PIPE-007": 40,  # SSH private key in log or env var    — CRITICAL
}

# Severity label mapped from weight (critical ≥ 40, high ≥ 25, else medium)
_SEVERITY: Dict[str, str] = {
    "PIPE-001": "CRITICAL",
    "PIPE-002": "CRITICAL",
    "PIPE-003": "HIGH",
    "PIPE-004": "CRITICAL",
    "PIPE-005": "HIGH",
    "PIPE-006": "HIGH",
    "PIPE-007": "CRITICAL",
}

# Precompiled patterns — kept at module level to avoid repeated compilation
_RE_AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
_RE_AWS_SECRET_LINE = re.compile(
    r"aws_secret_access_key\s*=\s*\S{16,}", re.IGNORECASE
)
_RE_GITHUB_TOKEN = re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")
_RE_GITLAB_PAT = re.compile(r"glpat-[A-Za-z0-9_\-]{20,}")
_RE_BASE64_CANDIDATE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_RE_CURL_BEARER = re.compile(
    r'(?:curl|wget).*?-H\s+["\']Authorization:\s+Bearer\s+([^\s"\']{21,})',
    re.DOTALL,
)
_RE_CURL_USERPWD = re.compile(
    r'(?:curl|wget).*?-u\s+\S+:(\S{9,})', re.DOTALL
)
_RE_CURL_TOKEN = re.compile(r'--token=(\S{11,})')
# Docker config detection: all three substrings must be present in the text
# but order is not guaranteed (e.g. the path may appear before or after the
# JSON payload in a shell echo-redirect command).
_DOCKER_CONFIG_TOKENS = (r'\.docker/config\.json', r'auths', r'auth')
_RE_DOCKER_CONFIG_PARTS = [re.compile(t, re.DOTALL) for t in _DOCKER_CONFIG_TOKENS]
_RE_DOCKER_LOGIN_P = re.compile(
    r'docker\s+login.*?(?:-p|--password)\s+\S+', re.DOTALL
)
_SSH_KEY_HEADERS = (
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class PipelineEnvVar:
    """Represents a single environment variable configured for a pipeline step."""

    name: str   # Variable name, e.g. "AWS_SECRET_ACCESS_KEY"
    value: str  # Variable value
    is_masked: bool = False  # True when the CI system marks this as a secret

    def to_dict(self) -> Dict:
        """Return a plain dictionary representation of this instance."""
        return {
            "name": self.name,
            "value": self.value,
            "is_masked": self.is_masked,
        }


@dataclass
class PipelineStep:
    """Represents one step/job in a CI/CD pipeline."""

    name: str                          # Human-readable step name
    log_content: str                   # Text output produced by this step
    env_vars: List[PipelineEnvVar] = field(default_factory=list)
    script: Optional[str] = None       # The shell script / commands for this step

    def to_dict(self) -> Dict:
        """Return a plain dictionary representation of this instance."""
        return {
            "name": self.name,
            "log_content": self.log_content,
            "env_vars": [ev.to_dict() for ev in self.env_vars],
            "script": self.script,
        }


@dataclass
class PipelineFinding:
    """A single security finding produced by one of the pipeline checks."""

    check_id: str         # e.g. "PIPE-001"
    severity: str         # "CRITICAL" | "HIGH" | "MEDIUM"
    step_name: str        # Name of the step where the issue was found
    location: str         # "log" | "env" | "script"
    message: str          # Human-readable description of the finding
    recommendation: str   # Actionable remediation advice
    masked_evidence: Optional[str] = None  # First 8 chars of evidence + "****"

    def to_dict(self) -> Dict:
        """Return a plain dictionary representation of this instance."""
        return {
            "check_id": self.check_id,
            "severity": self.severity,
            "step_name": self.step_name,
            "location": self.location,
            "message": self.message,
            "recommendation": self.recommendation,
            "masked_evidence": self.masked_evidence,
        }


@dataclass
class PipelineScanResult:
    """Aggregated result of scanning one or more pipeline steps."""

    findings: List[PipelineFinding] = field(default_factory=list)
    risk_score: int = 0  # Integer 0–100 derived from fired check weights

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """Return a one-line human-readable summary of the scan result."""
        total = len(self.findings)
        by_sev = self.by_severity()
        critical = by_sev.get("CRITICAL", 0)
        high = by_sev.get("HIGH", 0)
        medium = by_sev.get("MEDIUM", 0)
        return (
            f"PipelineScanResult: {total} finding(s) "
            f"[CRITICAL={critical}, HIGH={high}, MEDIUM={medium}] "
            f"risk_score={self.risk_score}"
        )

    def by_severity(self) -> Dict[str, int]:
        """Return a dict mapping severity label to count of findings."""
        counts: Dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def to_dict(self) -> Dict:
        """Return a plain dictionary representation of this instance."""
        return {
            "findings": [f.to_dict() for f in self.findings],
            "risk_score": self.risk_score,
        }


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class PipelineSecretScanner:
    """
    Scans CI/CD pipeline artefacts — log output, environment variables, and
    inline scripts — for accidentally exposed secrets.

    All analysis is performed entirely offline on the supplied text; no
    network requests are made.
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_log(
        self, log_content: str, step_name: str = "unknown"
    ) -> PipelineScanResult:
        """
        Scan a single log string for exposed secrets.

        Parameters
        ----------
        log_content:
            The raw text output captured from a pipeline step.
        step_name:
            Optional label identifying the step this log belongs to.

        Returns
        -------
        PipelineScanResult
        """
        findings: List[PipelineFinding] = []
        self._check_pipe001_log(log_content, step_name, findings)
        self._check_pipe002_log(log_content, step_name, findings)
        self._check_pipe003_log(log_content, step_name, findings)
        self._check_pipe004_text(log_content, step_name, "log", findings)
        self._check_pipe006_text(log_content, step_name, "log", findings)
        self._check_pipe007_text(log_content, step_name, "log", findings)
        return self._build_result(findings)

    def scan_env_vars(
        self, env_vars: List[PipelineEnvVar], step_name: str = "unknown"
    ) -> PipelineScanResult:
        """
        Scan a list of environment variables for secret-exposure issues.

        Parameters
        ----------
        env_vars:
            The environment variables configured for a pipeline step.
        step_name:
            Optional label identifying the step these vars belong to.

        Returns
        -------
        PipelineScanResult
        """
        findings: List[PipelineFinding] = []
        self._check_pipe005_env(env_vars, step_name, findings)
        self._check_pipe007_env(env_vars, step_name, findings)
        return self._build_result(findings)

    def scan_pipeline(self, steps: List[PipelineStep]) -> PipelineScanResult:
        """
        Scan every step in a pipeline — combining log, env-var, and script
        analysis into a single aggregated result.

        Parameters
        ----------
        steps:
            All pipeline steps to inspect.

        Returns
        -------
        PipelineScanResult with deduplicated risk_score capped at 100.
        """
        all_findings: List[PipelineFinding] = []
        for step in steps:
            # Log checks
            self._check_pipe001_log(step.log_content, step.name, all_findings)
            self._check_pipe002_log(step.log_content, step.name, all_findings)
            self._check_pipe003_log(step.log_content, step.name, all_findings)
            self._check_pipe004_text(
                step.log_content, step.name, "log", all_findings
            )
            self._check_pipe006_text(
                step.log_content, step.name, "log", all_findings
            )
            self._check_pipe007_text(
                step.log_content, step.name, "log", all_findings
            )
            # Script checks
            if step.script:
                self._check_pipe004_text(
                    step.script, step.name, "script", all_findings
                )
                self._check_pipe006_text(
                    step.script, step.name, "script", all_findings
                )
                self._check_pipe007_text(
                    step.script, step.name, "script", all_findings
                )
            # Env var checks
            self._check_pipe005_env(step.env_vars, step.name, all_findings)
            self._check_pipe007_env(step.env_vars, step.name, all_findings)

        return self._build_result(all_findings)

    # ------------------------------------------------------------------
    # Private helpers — check implementations
    # ------------------------------------------------------------------

    @staticmethod
    def _mask(evidence: str) -> str:
        """Return the first 8 characters of *evidence* followed by '****'."""
        return evidence[:8] + "****"

    @staticmethod
    def _build_result(findings: List[PipelineFinding]) -> PipelineScanResult:
        """
        Compute the risk_score from the *unique* set of check IDs that fired,
        cap it at 100, and return a PipelineScanResult.
        """
        fired_ids = {f.check_id for f in findings}
        raw_score = sum(_CHECK_WEIGHTS.get(cid, 0) for cid in fired_ids)
        return PipelineScanResult(
            findings=findings,
            risk_score=min(100, raw_score),
        )

    # --- PIPE-001 -------------------------------------------------------

    def _check_pipe001_log(
        self,
        text: str,
        step_name: str,
        findings: List[PipelineFinding],
    ) -> None:
        """AWS credential exposed in log output."""
        # Pattern 1 — bare AWS access key ID
        for match in _RE_AWS_KEY.finditer(text):
            findings.append(PipelineFinding(
                check_id="PIPE-001",
                severity=_SEVERITY["PIPE-001"],
                step_name=step_name,
                location="log",
                message=(
                    "AWS access key ID pattern detected in log output "
                    f"(match: {self._mask(match.group())})"
                ),
                recommendation=(
                    "Rotate the exposed AWS key immediately.  Store AWS "
                    "credentials as masked CI/CD secrets and never echo them "
                    "to the log."
                ),
                masked_evidence=self._mask(match.group()),
            ))

        # Pattern 2 — aws_secret_access_key assignment on a single line
        for match in _RE_AWS_SECRET_LINE.finditer(text):
            findings.append(PipelineFinding(
                check_id="PIPE-001",
                severity=_SEVERITY["PIPE-001"],
                step_name=step_name,
                location="log",
                message=(
                    "AWS secret access key assignment detected in log output."
                ),
                recommendation=(
                    "Rotate the exposed AWS key immediately.  Store AWS "
                    "credentials as masked CI/CD secrets and never echo them "
                    "to the log."
                ),
                masked_evidence=self._mask(match.group()),
            ))

    # --- PIPE-002 -------------------------------------------------------

    def _check_pipe002_log(
        self,
        text: str,
        step_name: str,
        findings: List[PipelineFinding],
    ) -> None:
        """GitHub / GitLab personal-access token in log output."""
        for match in _RE_GITHUB_TOKEN.finditer(text):
            findings.append(PipelineFinding(
                check_id="PIPE-002",
                severity=_SEVERITY["PIPE-002"],
                step_name=step_name,
                location="log",
                message=(
                    "GitHub personal-access token detected in log output."
                ),
                recommendation=(
                    "Revoke the token immediately via GitHub settings.  "
                    "Store GitHub tokens as masked CI/CD secrets."
                ),
                masked_evidence=self._mask(match.group()),
            ))

        for match in _RE_GITLAB_PAT.finditer(text):
            findings.append(PipelineFinding(
                check_id="PIPE-002",
                severity=_SEVERITY["PIPE-002"],
                step_name=step_name,
                location="log",
                message=(
                    "GitLab personal-access token (glpat-) detected in log "
                    "output."
                ),
                recommendation=(
                    "Revoke the token immediately via GitLab settings.  "
                    "Store GitLab tokens as masked CI/CD secrets."
                ),
                masked_evidence=self._mask(match.group()),
            ))

    # --- PIPE-003 -------------------------------------------------------

    def _check_pipe003_log(
        self,
        text: str,
        step_name: str,
        findings: List[PipelineFinding],
    ) -> None:
        """Base64-encoded binary/encrypted data blob in log output."""
        seen: set = set()  # avoid duplicate findings for identical strings
        for match in _RE_BASE64_CANDIDATE.finditer(text):
            candidate = match.group()
            # Only consider strings strictly longer than 40 characters
            if len(candidate) <= 40:
                continue
            if candidate in seen:
                continue
            # Attempt decoding; skip if the string is not valid base64
            try:
                decoded = base64.b64decode(candidate + "==")
            except Exception:
                continue
            # Heuristic: more than 30 % of decoded bytes are non-printable
            non_printable = sum(
                1 for b in decoded if b < 0x20 or b > 0x7E
            )
            if len(decoded) == 0:
                continue
            if non_printable / len(decoded) > 0.30:
                seen.add(candidate)
                findings.append(PipelineFinding(
                    check_id="PIPE-003",
                    severity=_SEVERITY["PIPE-003"],
                    step_name=step_name,
                    location="log",
                    message=(
                        "Possible base64-encoded binary/encrypted secret "
                        "detected in log output."
                    ),
                    recommendation=(
                        "Investigate the source of this blob.  Do not log "
                        "encryption keys, certificates, or binary tokens."
                    ),
                    masked_evidence=self._mask(candidate),
                ))

    # --- PIPE-004 -------------------------------------------------------

    def _check_pipe004_text(
        self,
        text: str,
        step_name: str,
        location: str,
        findings: List[PipelineFinding],
    ) -> None:
        """Secret exposed inside a curl / wget command."""
        # Bearer token in -H "Authorization: Bearer ..."
        for match in _RE_CURL_BEARER.finditer(text):
            token = match.group(1)
            findings.append(PipelineFinding(
                check_id="PIPE-004",
                severity=_SEVERITY["PIPE-004"],
                step_name=step_name,
                location=location,
                message=(
                    "Bearer token exposed in a curl/wget Authorization "
                    "header."
                ),
                recommendation=(
                    "Pass the token via an environment variable and reference "
                    "it with $VAR_NAME rather than hardcoding the value."
                ),
                masked_evidence=self._mask(token),
            ))

        # Basic-auth credentials via -u user:password
        for match in _RE_CURL_USERPWD.finditer(text):
            pwd = match.group(1)
            findings.append(PipelineFinding(
                check_id="PIPE-004",
                severity=_SEVERITY["PIPE-004"],
                step_name=step_name,
                location=location,
                message=(
                    "Plaintext password exposed in a curl/wget -u "
                    "user:password argument."
                ),
                recommendation=(
                    "Store the password as a masked CI/CD secret and supply "
                    "it via an environment variable."
                ),
                masked_evidence=self._mask(pwd),
            ))

        # --token= flag
        for match in _RE_CURL_TOKEN.finditer(text):
            token = match.group(1)
            findings.append(PipelineFinding(
                check_id="PIPE-004",
                severity=_SEVERITY["PIPE-004"],
                step_name=step_name,
                location=location,
                message=(
                    "Token exposed via --token= flag in command."
                ),
                recommendation=(
                    "Replace the hardcoded token with a masked CI/CD secret "
                    "referenced through an environment variable."
                ),
                masked_evidence=self._mask(token),
            ))

    # --- PIPE-005 -------------------------------------------------------

    @staticmethod
    def _is_secret_var_name(name: str) -> bool:
        """Return True when *name* contains a known sensitive keyword."""
        keywords = (
            "SECRET", "KEY", "TOKEN", "PASSWORD",
            "CREDENTIAL", "PWD", "PASSWD",
        )
        upper = name.upper()
        return any(kw in upper for kw in keywords)

    def _check_pipe005_env(
        self,
        env_vars: List[PipelineEnvVar],
        step_name: str,
        findings: List[PipelineFinding],
    ) -> None:
        """Secret-looking variable that is not marked as masked."""
        for var in env_vars:
            if (
                not var.is_masked
                and self._is_secret_var_name(var.name)
                and len(var.value) > 8
            ):
                findings.append(PipelineFinding(
                    check_id="PIPE-005",
                    severity=_SEVERITY["PIPE-005"],
                    step_name=step_name,
                    location="env",
                    message=(
                        f"Environment variable '{var.name}' appears to "
                        "contain a secret but is not masked in the CI "
                        "configuration."
                    ),
                    recommendation=(
                        f"Mark '{var.name}' as a masked/protected variable "
                        "in the CI/CD settings to prevent it from appearing "
                        "in logs."
                    ),
                    masked_evidence=self._mask(var.value),
                ))

    # --- PIPE-006 -------------------------------------------------------

    def _check_pipe006_text(
        self,
        text: str,
        step_name: str,
        location: str,
        findings: List[PipelineFinding],
    ) -> None:
        """Plaintext Docker registry credentials."""
        if all(pat.search(text) for pat in _RE_DOCKER_CONFIG_PARTS):
            findings.append(PipelineFinding(
                check_id="PIPE-006",
                severity=_SEVERITY["PIPE-006"],
                step_name=step_name,
                location=location,
                message=(
                    "Docker registry credentials appear to be written to "
                    ".docker/config.json with a base64-encoded auth field."
                ),
                recommendation=(
                    "Use a credential helper (e.g. docker-credential-pass) "
                    "or a CI/CD masked secret instead of storing credentials "
                    "in config.json."
                ),
                masked_evidence=None,
            ))

        for match in _RE_DOCKER_LOGIN_P.finditer(text):
            findings.append(PipelineFinding(
                check_id="PIPE-006",
                severity=_SEVERITY["PIPE-006"],
                step_name=step_name,
                location=location,
                message=(
                    "Plaintext password passed to 'docker login' via -p / "
                    "--password flag."
                ),
                recommendation=(
                    "Pass the Docker password via STDIN "
                    "('echo $PASS | docker login --password-stdin') or use a "
                    "masked CI/CD secret."
                ),
                masked_evidence=self._mask(match.group()),
            ))

    # --- PIPE-007 -------------------------------------------------------

    def _check_pipe007_text(
        self,
        text: str,
        step_name: str,
        location: str,
        findings: List[PipelineFinding],
    ) -> None:
        """SSH private key header detected in text (log or script)."""
        for header in _SSH_KEY_HEADERS:
            if header in text:
                findings.append(PipelineFinding(
                    check_id="PIPE-007",
                    severity=_SEVERITY["PIPE-007"],
                    step_name=step_name,
                    location=location,
                    message=(
                        f"SSH private key header '{header}' detected in "
                        f"{location} output."
                    ),
                    recommendation=(
                        "Remove the private key from the pipeline immediately."
                        "  Store SSH keys as masked CI/CD secrets and inject "
                        "them into the agent via an SSH agent socket, never "
                        "as plaintext."
                    ),
                    masked_evidence=self._mask(header),
                ))

    def _check_pipe007_env(
        self,
        env_vars: List[PipelineEnvVar],
        step_name: str,
        findings: List[PipelineFinding],
    ) -> None:
        """SSH private key header detected in an environment variable value."""
        for var in env_vars:
            for header in _SSH_KEY_HEADERS:
                if header in var.value:
                    findings.append(PipelineFinding(
                        check_id="PIPE-007",
                        severity=_SEVERITY["PIPE-007"],
                        step_name=step_name,
                        location="env",
                        message=(
                            f"SSH private key header '{header}' detected in "
                            f"environment variable '{var.name}'."
                        ),
                        recommendation=(
                            "Remove the private key from the environment "
                            "variable.  Use an SSH agent socket or a "
                            "dedicated secrets manager integration instead."
                        ),
                        masked_evidence=self._mask(var.value),
                    ))
