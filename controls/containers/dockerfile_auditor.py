"""
Dockerfile Security Auditor
==============================
Parses Dockerfile content and checks for common security anti-patterns
that introduce risk into container images used in CI/CD pipelines.

Checks Performed
-----------------
DF-001  Running as root (no USER directive or USER root/0)
        Containers that run as root grant any process inside full host
        privilege if a container escape occurs.

DF-002  Latest tag or unpinned base image
        ``FROM ubuntu:latest`` or ``FROM ubuntu`` makes builds
        non-reproducible and susceptible to supply-chain attacks via
        silently updated base images.

DF-003  Secrets baked into image (ARG/ENV with secret-like names)
        Build arguments and environment variables with names like
        PASSWORD, SECRET, TOKEN, or KEY may embed credentials into image
        layers visible via ``docker history``.

DF-004  ADD used instead of COPY
        ``ADD`` with a URL fetches remote content at build time without
        checksum verification, enabling supply-chain substitution.

DF-005  apt-get / apk without pinned versions
        Installing packages without version pinning (``apt-get install
        curl``) means the package version can change between builds,
        introducing unvetted software.

DF-006  curl | bash — remote code execution at build time
        Piping remote scripts directly into a shell during build executes
        unverified code and cannot be audited.

DF-007  HEALTHCHECK missing
        Without a HEALTHCHECK, orchestrators cannot detect unhealthy
        containers and route traffic away from them, reducing resilience.

DF-008  Privileged capabilities added (--cap-add)
        Adding Linux capabilities (--cap-add SYS_ADMIN, --cap-add ALL)
        in a RUN or ENTRYPOINT instruction unnecessarily expands the
        attack surface.

DF-009  COPY --chown not used for application files
        Application files copied without ``--chown`` default to root
        ownership, requiring unnecessary privilege for file access.

DF-010  No content trust / image digest pinning
        Using a tag instead of a digest (``image@sha256:…``) means the
        exact image bytes are not guaranteed across builds.

Usage::

    from controls.containers.dockerfile_auditor import (
        DockerfileAuditor,
        AuditReport,
    )

    with open("Dockerfile") as fh:
        content = fh.read()

    auditor = DockerfileAuditor()
    report = auditor.audit(content)
    print(report.summary())
    for finding in report.findings:
        print(finding.summary())
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class DockerSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------

_CHECK_META: dict[str, tuple[DockerSeverity, str]] = {
    "DF-001": (DockerSeverity.HIGH,     "Container runs as root"),
    "DF-002": (DockerSeverity.HIGH,     "Unpinned base image tag"),
    "DF-003": (DockerSeverity.CRITICAL, "Secret-like variable in image layer"),
    "DF-004": (DockerSeverity.MEDIUM,   "ADD with URL — no checksum verification"),
    "DF-005": (DockerSeverity.MEDIUM,   "Package installed without version pinning"),
    "DF-006": (DockerSeverity.CRITICAL, "Remote script piped to shell"),
    "DF-007": (DockerSeverity.LOW,      "HEALTHCHECK directive missing"),
    "DF-008": (DockerSeverity.HIGH,     "Dangerous capability added"),
    "DF-009": (DockerSeverity.LOW,      "COPY without --chown"),
    "DF-010": (DockerSeverity.MEDIUM,   "Image referenced by tag, not digest"),
}

_CHECK_WEIGHTS: dict[str, int] = {
    "DF-001": 20,
    "DF-002": 15,
    "DF-003": 35,
    "DF-004": 10,
    "DF-005": 10,
    "DF-006": 35,
    "DF-007": 5,
    "DF-008": 20,
    "DF-009": 5,
    "DF-010": 10,
}


@dataclass
class DockerFinding:
    """
    A single Dockerfile security finding.

    Attributes:
        check_id:    Check identifier (DF-001 … DF-010).
        severity:    Finding severity.
        title:       Short description.
        detail:      Detailed explanation.
        remediation: Step to fix the issue.
        line_number: Line in the Dockerfile (1-based, 0 if unknown).
        line_content: The offending Dockerfile line (truncated).
    """
    check_id:     str
    severity:     DockerSeverity
    title:        str
    detail:       str
    remediation:  str
    line_number:  int = 0
    line_content: str = ""

    def summary(self) -> str:
        loc = f"line {self.line_number}" if self.line_number else "global"
        return f"[{self.severity.value}] {self.check_id} ({loc}): {self.title}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id":     self.check_id,
            "severity":     self.severity.value,
            "title":        self.title,
            "detail":       self.detail,
            "remediation":  self.remediation,
            "line_number":  self.line_number,
            "line_content": self.line_content,
        }


# ---------------------------------------------------------------------------
# Audit report
# ---------------------------------------------------------------------------

@dataclass
class AuditReport:
    """
    Aggregated Dockerfile audit report.

    Attributes:
        findings:       All findings from the audit.
        risk_score:     Aggregate 0–100 risk score.
        pass_count:     Number of checks that passed (fired no finding).
        dockerfile_path: Path to the Dockerfile analyzed (informational).
    """
    findings:        list[DockerFinding] = field(default_factory=list)
    risk_score:      int = 0
    pass_count:      int = 0
    dockerfile_path: str = ""

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_findings(self) -> list[DockerFinding]:
        return [f for f in self.findings if f.severity == DockerSeverity.CRITICAL]

    @property
    def high_findings(self) -> list[DockerFinding]:
        return [f for f in self.findings if f.severity == DockerSeverity.HIGH]

    def findings_by_check(self, check_id: str) -> list[DockerFinding]:
        return [f for f in self.findings if f.check_id == check_id]

    def summary(self) -> str:
        path_str = f" ({self.dockerfile_path})" if self.dockerfile_path else ""
        return (
            f"DockerfileAudit{path_str}: risk={self.risk_score} | "
            f"{self.total_findings} finding(s) "
            f"[CRITICAL={len(self.critical_findings)} HIGH={len(self.high_findings)}] "
            f"pass={self.pass_count}"
        )


# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

# Secret-like ENV/ARG variable name patterns
_SECRET_VAR_RE = re.compile(
    r"\b(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|CERT|CREDENTIAL|"
    r"AUTH|ACCESS_KEY|AWS_SECRET|DATABASE_URL|DB_PASS)\b",
    re.IGNORECASE,
)

# ADD with a URL (http or ftp)
_ADD_URL_RE = re.compile(r"^ADD\s+(https?://|ftp://)", re.IGNORECASE)

# apt-get install without version pin (=)
_APT_NO_PIN_RE = re.compile(
    r"apt-get\s+install\b[^=\n]*$",
    re.IGNORECASE | re.MULTILINE,
)

# apk add without version pin (=)
_APK_NO_PIN_RE = re.compile(
    r"apk\s+add\b[^=\n]*$",
    re.IGNORECASE | re.MULTILINE,
)

# curl/wget piped to a shell
_CURL_BASH_RE = re.compile(
    r"(curl|wget)\s+[^\n|]+\|\s*(ba)?sh\b",
    re.IGNORECASE,
)

# Dangerous capability patterns
_CAP_ADD_RE = re.compile(
    r"--cap-add\s+(ALL|SYS_ADMIN|SYS_PTRACE|NET_ADMIN|SYS_MODULE|DAC_OVERRIDE)",
    re.IGNORECASE,
)

# FROM line: image reference without digest
_FROM_RE = re.compile(r"^FROM\s+(?!scratch)([^\s#]+)", re.IGNORECASE)


# ---------------------------------------------------------------------------
# DockerfileAuditor
# ---------------------------------------------------------------------------

class DockerfileAuditor:
    """
    Audits a Dockerfile string for security anti-patterns.

    Args:
        check_chown:  If True, flag COPY directives without --chown (DF-009).
                      Default True.
        require_healthcheck: If True, flag missing HEALTHCHECK (DF-007).
                             Default True.
    """

    def __init__(
        self,
        check_chown: bool = True,
        require_healthcheck: bool = True,
    ) -> None:
        self._check_chown = check_chown
        self._require_healthcheck = require_healthcheck

    def audit(
        self,
        content: str,
        dockerfile_path: str = "",
    ) -> AuditReport:
        """
        Parse and audit Dockerfile content.

        Args:
            content:         Full Dockerfile text.
            dockerfile_path: Optional path label for the report.

        Returns an AuditReport.
        """
        lines = content.splitlines()
        findings: list[DockerFinding] = []
        checks_fired: set[str] = set()

        # Per-line checks
        has_user_directive = False
        has_healthcheck = False

        for lineno, raw_line in enumerate(lines, start=1):
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            instruction = stripped.split()[0].upper() if stripped.split() else ""

            # DF-001: USER check — track presence
            if instruction == "USER":
                user_val = stripped.split(None, 1)[1].strip() if len(stripped.split(None, 1)) > 1 else ""
                # USER root / USER 0 / USER 0:0 are still root
                if user_val.lower() not in ("root", "0", "0:0"):
                    has_user_directive = True

            # DF-002: Unpinned base image
            if instruction == "FROM":
                m = _FROM_RE.match(stripped)
                if m:
                    image_ref = m.group(1)
                    if not _is_pinned(image_ref):
                        finding = self._make_finding(
                            "DF-002", lineno, raw_line.strip(),
                            detail=(
                                f"Base image '{image_ref}' uses a mutable tag "
                                "(or no tag, defaulting to :latest). The image "
                                "can change silently between builds."
                            ),
                            remediation=(
                                "Pin to a specific digest: "
                                "``FROM ubuntu@sha256:<digest>`` or at minimum "
                                "a versioned tag: ``FROM ubuntu:22.04``"
                            ),
                        )
                        findings.append(finding)
                        checks_fired.add("DF-002")

                    # DF-010: Tag instead of digest
                    if not _has_digest(image_ref) and image_ref != "scratch":
                        finding = self._make_finding(
                            "DF-010", lineno, raw_line.strip(),
                            detail=(
                                f"Base image '{image_ref}' is referenced by "
                                "tag rather than an immutable SHA-256 digest. "
                                "Tag reassignment can silently alter the image."
                            ),
                            remediation=(
                                "Use a digest reference: "
                                "``FROM image@sha256:<hash>``"
                            ),
                        )
                        findings.append(finding)
                        checks_fired.add("DF-010")

            # DF-003: Secret-like variable names in ENV/ARG
            if instruction in ("ENV", "ARG"):
                m = _SECRET_VAR_RE.search(stripped)
                if m:
                    finding = self._make_finding(
                        "DF-003", lineno, raw_line.strip(),
                        detail=(
                            f"The variable '{m.group(0)}' in a {instruction} "
                            "directive may embed a secret into the image layer. "
                            "Image layers are permanently stored and visible via "
                            "``docker history``."
                        ),
                        remediation=(
                            "Pass secrets at runtime via ``--env`` or "
                            "``--secret`` (BuildKit) instead of baking them "
                            "into the image."
                        ),
                    )
                    findings.append(finding)
                    checks_fired.add("DF-003")

            # DF-004: ADD with URL
            if instruction == "ADD" and _ADD_URL_RE.match(stripped):
                finding = self._make_finding(
                    "DF-004", lineno, raw_line.strip(),
                    detail=(
                        "ADD with a URL fetches remote content at build time "
                        "without SHA checksum verification. A compromised "
                        "remote resource can inject malicious content."
                    ),
                    remediation=(
                        "Use RUN with curl/wget and verify a checksum, or "
                        "pre-download and use COPY."
                    ),
                )
                findings.append(finding)
                checks_fired.add("DF-004")

            # DF-006: curl/wget piped to shell
            if instruction in ("RUN",):
                if _CURL_BASH_RE.search(stripped):
                    finding = self._make_finding(
                        "DF-006", lineno, raw_line.strip(),
                        detail=(
                            "A remote script is fetched and executed directly "
                            "in a shell. The content of the remote script is "
                            "not verified and can be replaced by an attacker."
                        ),
                        remediation=(
                            "Download the script separately, verify its "
                            "SHA-256 checksum, then execute."
                        ),
                    )
                    findings.append(finding)
                    checks_fired.add("DF-006")

                # DF-005: Unversioned apt-get/apk install
                if _APT_NO_PIN_RE.search(stripped) and "apt-get install" in stripped.lower():
                    if not _has_version_pin(stripped):
                        finding = self._make_finding(
                            "DF-005", lineno, raw_line.strip(),
                            detail=(
                                "apt-get install is used without version pinning. "
                                "Package versions can change between builds, "
                                "introducing unvetted software."
                            ),
                            remediation=(
                                "Pin package versions: "
                                "``apt-get install -y curl=7.88.1-10``"
                            ),
                        )
                        findings.append(finding)
                        checks_fired.add("DF-005")
                elif _APK_NO_PIN_RE.search(stripped) and "apk add" in stripped.lower():
                    if not _has_version_pin(stripped):
                        finding = self._make_finding(
                            "DF-005", lineno, raw_line.strip(),
                            detail=(
                                "apk add is used without version pinning. "
                                "Package versions can change between builds."
                            ),
                            remediation=(
                                "Pin package versions: "
                                "``apk add --no-cache curl=7.88.1-r0``"
                            ),
                        )
                        findings.append(finding)
                        checks_fired.add("DF-005")

                # DF-008: Dangerous capability
                m = _CAP_ADD_RE.search(stripped)
                if m:
                    finding = self._make_finding(
                        "DF-008", lineno, raw_line.strip(),
                        detail=(
                            f"The capability '{m.group(1)}' is added via "
                            "--cap-add. Broad capabilities significantly "
                            "expand the container attack surface."
                        ),
                        remediation=(
                            "Remove unnecessary capabilities. If required, "
                            "scope them as narrowly as possible and document "
                            "the business justification."
                        ),
                    )
                    findings.append(finding)
                    checks_fired.add("DF-008")

            # DF-009: COPY without --chown
            if instruction == "COPY" and self._check_chown:
                if "--chown" not in stripped:
                    finding = self._make_finding(
                        "DF-009", lineno, raw_line.strip(),
                        detail=(
                            "COPY without --chown leaves files owned by root. "
                            "The application process may need unnecessary "
                            "privilege to read or write these files."
                        ),
                        remediation=(
                            "Add ownership: ``COPY --chown=appuser:appgroup "
                            "src/ /app/``"
                        ),
                    )
                    findings.append(finding)
                    checks_fired.add("DF-009")

            # DF-007: HEALTHCHECK present
            if instruction == "HEALTHCHECK":
                has_healthcheck = True

        # End-of-file checks

        # DF-001: No USER directive (or only root USER)
        if not has_user_directive:
            finding = self._make_finding(
                "DF-001", 0, "",
                detail=(
                    "No USER directive sets a non-root user. The container "
                    "process runs as root (uid 0) by default, granting "
                    "elevated privileges inside the container."
                ),
                remediation=(
                    "Add ``RUN useradd -m appuser`` and "
                    "``USER appuser`` before the final CMD/ENTRYPOINT."
                ),
            )
            findings.append(finding)
            checks_fired.add("DF-001")

        # DF-007: No HEALTHCHECK
        if not has_healthcheck and self._require_healthcheck:
            finding = self._make_finding(
                "DF-007", 0, "",
                detail=(
                    "No HEALTHCHECK directive is defined. Orchestrators "
                    "cannot detect an unhealthy container and will continue "
                    "routing traffic to it."
                ),
                remediation=(
                    "Add: ``HEALTHCHECK --interval=30s --timeout=5s "
                    "CMD curl -f http://localhost/health || exit 1``"
                ),
            )
            findings.append(finding)
            checks_fired.add("DF-007")

        total_checks = len(_CHECK_META)
        pass_count   = total_checks - len(checks_fired)

        risk_score = min(100, sum(
            _CHECK_WEIGHTS.get(f.check_id, 5) for f in findings
        ))

        return AuditReport(
            findings=findings,
            risk_score=risk_score,
            pass_count=max(0, pass_count),
            dockerfile_path=dockerfile_path,
        )

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------

    @staticmethod
    def _make_finding(
        check_id: str,
        line_number: int,
        line_content: str,
        detail: str,
        remediation: str,
    ) -> DockerFinding:
        severity, title = _CHECK_META[check_id]
        return DockerFinding(
            check_id=check_id,
            severity=severity,
            title=title,
            detail=detail,
            remediation=remediation,
            line_number=line_number,
            line_content=line_content[:200],
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_pinned(image_ref: str) -> bool:
    """Return True if image_ref has a versioned tag (not :latest or no tag)."""
    if "@sha256:" in image_ref:
        return True
    if ":" in image_ref:
        tag = image_ref.split(":")[-1]
        return tag.lower() not in ("latest", "")
    return False  # bare image name with no tag — defaults to :latest


def _has_digest(image_ref: str) -> bool:
    return "@sha256:" in image_ref


def _has_version_pin(run_line: str) -> bool:
    """Heuristic: presence of '=' after a package name suggests pinning."""
    return bool(re.search(r"\w+=[\d.~+:-]", run_line))
