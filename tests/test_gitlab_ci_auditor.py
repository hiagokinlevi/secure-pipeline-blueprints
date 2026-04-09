"""
Tests for shared/validators/gitlab_ci_auditor.py

Validates:
  - GitLabFinding dataclass fields
  - GitLabAuditResult.passed, counts, summary(), findings_by_rule()
  - GL-001: secret echo detected in script/before_script/after_script
  - GL-001: non-secret echo not flagged
  - GL-001: multiple secret echoes produce multiple findings
  - GL-002: job without timeout flagged
  - GL-002: job with timeout not flagged
  - GL-002: template jobs (starting with .) not flagged
  - GL-003: image with :latest tag flagged
  - GL-003: image with no tag (implicit latest) flagged
  - GL-003: image with specific version tag not flagged
  - GL-003: image with digest sha256 pin not flagged
  - GL-003: job with no image (inherits global) not flagged
  - GL-004: allow_failure on sast stage flagged
  - GL-004: allow_failure on non-security stage not flagged
  - GL-004: allow_failure: false not flagged
  - GL-004: security keyword in job name triggers rule
  - GL-005: deploy job without rules or only flagged
  - GL-005: deploy job with rules not flagged
  - GL-005: deploy job with only not flagged
  - GL-005: non-deploy stage not flagged
  - GL-006: GIT_DEPTH: 0 in top-level variables flagged
  - GL-006: GIT_DEPTH: 20 not flagged
  - GL-006: GIT_DEPTH: 0 in per-job variables flagged
  - GL-007: docker:dind without DOCKER_TLS_CERTDIR flagged
  - GL-007: docker:dind with DOCKER_TLS_CERTDIR not flagged
  - GL-007: no docker:dind usage not flagged
  - GL-008: artifacts without expire_in flagged
  - GL-008: artifacts with expire_in not flagged
  - GL-008: reports-only artifacts not flagged
  - audit_gitlab_ci_file: YAML parse error produces warning
  - audit_gitlab_ci_file: clean pipeline returns passed=True
  - audit_gitlab_ci_directory: scans multiple files
"""
from __future__ import annotations

import sys
import tempfile
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "shared" / "validators"))

from gitlab_ci_auditor import (
    GitLabAuditResult,
    GitLabFinding,
    audit_gitlab_ci_directory,
    audit_gitlab_ci_file,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_yaml(content: str, suffix: str = ".yml") -> Path:
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=suffix, delete=False, encoding="utf-8"
    )
    tmp.write(textwrap.dedent(content))
    tmp.flush()
    tmp.close()
    return Path(tmp.name)


def _findings_for(result: GitLabAuditResult, rule_id: str) -> list[GitLabFinding]:
    return [f for f in result.findings if f.rule_id == rule_id]


# ---------------------------------------------------------------------------
# GitLabAuditResult
# ---------------------------------------------------------------------------

class TestGitLabAuditResult:

    def test_passed_true_when_no_high_or_critical(self):
        r = GitLabAuditResult(file_path=Path("x.yml"), pipeline_name="x")
        r.findings.append(
            GitLabFinding("GL-008", "low", "jobs.build.artifacts", "msg", "fix")
        )
        assert r.passed is True

    def test_passed_false_when_high_present(self):
        r = GitLabAuditResult(file_path=Path("x.yml"), pipeline_name="x")
        r.findings.append(
            GitLabFinding("GL-002", "high", "jobs.build", "msg", "fix")
        )
        assert r.passed is False

    def test_passed_false_when_critical_present(self):
        r = GitLabAuditResult(file_path=Path("x.yml"), pipeline_name="x")
        r.findings.append(
            GitLabFinding("GL-001", "critical", "jobs.build.script[0]", "msg", "fix")
        )
        assert r.passed is False

    def test_count_properties(self):
        r = GitLabAuditResult(file_path=Path("x.yml"), pipeline_name="x")
        r.findings = [
            GitLabFinding("GL-001", "high", "", "", ""),
            GitLabFinding("GL-004", "medium", "", "", ""),
            GitLabFinding("GL-008", "low", "", "", ""),
        ]
        assert r.high_count == 1
        assert r.medium_count == 1
        assert r.low_count == 1

    def test_summary_pass(self):
        r = GitLabAuditResult(file_path=Path("x.yml"), pipeline_name="my-pipeline")
        assert "PASS" in r.summary()
        assert "my-pipeline" in r.summary()

    def test_summary_fail(self):
        r = GitLabAuditResult(file_path=Path("x.yml"), pipeline_name="broken")
        r.findings.append(GitLabFinding("GL-002", "high", "", "", ""))
        assert "FAIL" in r.summary()

    def test_findings_by_rule_filters(self):
        r = GitLabAuditResult(file_path=Path("x.yml"), pipeline_name="x")
        r.findings = [
            GitLabFinding("GL-001", "high", "", "", ""),
            GitLabFinding("GL-002", "high", "", "", ""),
            GitLabFinding("GL-001", "high", "", "", ""),
        ]
        assert len(r.findings_by_rule("GL-001")) == 2
        assert len(r.findings_by_rule("GL-002")) == 1
        assert len(r.findings_by_rule("GL-999")) == 0


# ---------------------------------------------------------------------------
# GL-001: secret echo
# ---------------------------------------------------------------------------

class TestGL001SecretEcho:

    def test_registry_password_echo_flagged(self):
        path = _write_yaml("""\
            stages: [build]
            build-job:
              stage: build
              timeout: 10 minutes
              image: python:3.12-slim
              script:
                - echo $CI_REGISTRY_PASSWORD
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-001")
        assert len(findings) >= 1

    def test_custom_token_echo_flagged(self):
        path = _write_yaml("""\
            stages: [build]
            build-job:
              stage: build
              timeout: 10 minutes
              image: python:3.12-slim
              script:
                - echo $DEPLOY_TOKEN
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-001")
        assert len(findings) >= 1

    def test_non_secret_echo_not_flagged(self):
        path = _write_yaml("""\
            stages: [build]
            build-job:
              stage: build
              timeout: 10 minutes
              image: python:3.12-slim
              script:
                - echo "Build started"
                - echo $CI_COMMIT_SHA
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-001")
        assert len(findings) == 0

    def test_before_script_echo_flagged(self):
        path = _write_yaml("""\
            stages: [test]
            test-job:
              stage: test
              timeout: 10 minutes
              image: python:3.12-slim
              before_script:
                - echo $API_SECRET_KEY
              script:
                - pytest
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-001")
        assert len(findings) >= 1

    def test_multiple_secret_echoes_produce_multiple_findings(self):
        path = _write_yaml("""\
            stages: [test]
            test-job:
              stage: test
              timeout: 10 minutes
              image: python:3.12-slim
              script:
                - echo $REGISTRY_PASSWORD
                - echo $DEPLOY_TOKEN
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-001")
        assert len(findings) >= 2


# ---------------------------------------------------------------------------
# GL-002: missing timeout
# ---------------------------------------------------------------------------

class TestGL002MissingTimeout:

    def test_job_without_timeout_flagged(self):
        path = _write_yaml("""\
            stages: [build]
            build-job:
              stage: build
              image: python:3.12-slim
              script:
                - echo hello
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-002")
        assert len(findings) >= 1

    def test_job_with_timeout_not_flagged(self):
        path = _write_yaml("""\
            stages: [build]
            build-job:
              stage: build
              timeout: 30 minutes
              image: python:3.12-slim
              script:
                - echo hello
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-002")
        assert len(findings) == 0

    def test_multiple_jobs_without_timeout_produce_multiple_findings(self):
        path = _write_yaml("""\
            stages: [build, test]
            build-job:
              stage: build
              image: python:3.12-slim
              script:
                - make build
            test-job:
              stage: test
              image: python:3.12-slim
              script:
                - pytest
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-002")
        assert len(findings) == 2

    def test_template_job_dot_prefix_not_flagged(self):
        path = _write_yaml("""\
            stages: [build]
            .base-job:
              image: python:3.12-slim
              script:
                - echo template
            build-job:
              extends: .base-job
              stage: build
              timeout: 10 minutes
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-002")
        assert len(findings) == 0   # build-job has timeout; .base-job is skipped


# ---------------------------------------------------------------------------
# GL-003: unpinned image
# ---------------------------------------------------------------------------

class TestGL003UnpinnedImage:

    def test_latest_tag_flagged(self):
        path = _write_yaml("""\
            stages: [build]
            build-job:
              stage: build
              timeout: 10 minutes
              image: python:latest
              script:
                - echo hello
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-003")
        assert len(findings) >= 1

    def test_no_tag_flagged(self):
        path = _write_yaml("""\
            stages: [build]
            build-job:
              stage: build
              timeout: 10 minutes
              image: python
              script:
                - echo hello
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-003")
        assert len(findings) >= 1

    def test_versioned_tag_not_flagged(self):
        path = _write_yaml("""\
            stages: [build]
            build-job:
              stage: build
              timeout: 10 minutes
              image: python:3.12-slim
              script:
                - echo hello
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-003")
        assert len(findings) == 0

    def test_digest_pin_not_flagged(self):
        path = _write_yaml("""\
            stages: [build]
            build-job:
              stage: build
              timeout: 10 minutes
              image: python@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
              script:
                - echo hello
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-003")
        assert len(findings) == 0

    def test_no_image_key_not_flagged(self):
        """Jobs with no image key inherit the global image — GL-003 skips them."""
        path = _write_yaml("""\
            image: python:3.12-slim
            stages: [build]
            build-job:
              stage: build
              timeout: 10 minutes
              script:
                - echo hello
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-003")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# GL-004: allow_failure on security stage
# ---------------------------------------------------------------------------

class TestGL004AllowFailure:

    def test_allow_failure_on_sast_stage_flagged(self):
        path = _write_yaml("""\
            stages: [sast]
            sast-scan:
              stage: sast
              timeout: 10 minutes
              image: python:3.12-slim
              allow_failure: true
              script:
                - semgrep --config=auto .
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-004")
        assert len(findings) >= 1

    def test_allow_failure_on_secrets_stage_flagged(self):
        path = _write_yaml("""\
            stages: [secrets]
            secret-scan:
              stage: secrets
              timeout: 10 minutes
              image: python:3.12-slim
              allow_failure: true
              script:
                - gitleaks detect
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-004")
        assert len(findings) >= 1

    def test_allow_failure_on_non_security_stage_not_flagged(self):
        path = _write_yaml("""\
            stages: [build]
            build-job:
              stage: build
              timeout: 10 minutes
              image: python:3.12-slim
              allow_failure: true
              script:
                - make build
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-004")
        assert len(findings) == 0

    def test_allow_failure_false_not_flagged(self):
        path = _write_yaml("""\
            stages: [sast]
            sast-scan:
              stage: sast
              timeout: 10 minutes
              image: python:3.12-slim
              allow_failure: false
              script:
                - semgrep .
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-004")
        assert len(findings) == 0

    def test_security_keyword_in_job_name_triggers_rule(self):
        path = _write_yaml("""\
            stages: [ci]
            security-scan:
              stage: ci
              timeout: 10 minutes
              image: python:3.12-slim
              allow_failure: true
              script:
                - ./run-security-checks.sh
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-004")
        assert len(findings) >= 1


# ---------------------------------------------------------------------------
# GL-005: deploy without rules/only
# ---------------------------------------------------------------------------

class TestGL005DeployNoRules:

    def test_deploy_job_without_rules_flagged(self):
        path = _write_yaml("""\
            stages: [deploy]
            deploy-prod:
              stage: deploy
              timeout: 10 minutes
              image: python:3.12-slim
              script:
                - ./deploy.sh
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-005")
        assert len(findings) >= 1

    def test_deploy_job_with_rules_not_flagged(self):
        path = _write_yaml("""\
            stages: [deploy]
            deploy-prod:
              stage: deploy
              timeout: 10 minutes
              image: python:3.12-slim
              rules:
                - if: $CI_COMMIT_BRANCH == "main"
              script:
                - ./deploy.sh
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-005")
        assert len(findings) == 0

    def test_deploy_job_with_only_not_flagged(self):
        path = _write_yaml("""\
            stages: [deploy]
            deploy-prod:
              stage: deploy
              timeout: 10 minutes
              image: python:3.12-slim
              only:
                - main
              script:
                - ./deploy.sh
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-005")
        assert len(findings) == 0

    def test_non_deploy_stage_not_flagged(self):
        path = _write_yaml("""\
            stages: [build]
            build-job:
              stage: build
              timeout: 10 minutes
              image: python:3.12-slim
              script:
                - make build
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-005")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# GL-006: GIT_DEPTH 0
# ---------------------------------------------------------------------------

class TestGL006GitDepthZero:

    def test_git_depth_zero_string_flagged(self):
        path = _write_yaml("""\
            variables:
              GIT_DEPTH: "0"
            stages: [build]
            build-job:
              stage: build
              timeout: 10 minutes
              image: python:3.12-slim
              script:
                - echo hello
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-006")
        assert len(findings) >= 1

    def test_git_depth_zero_int_flagged(self):
        path = _write_yaml("""\
            variables:
              GIT_DEPTH: 0
            stages: [build]
            build-job:
              stage: build
              timeout: 10 minutes
              image: python:3.12-slim
              script:
                - echo hello
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-006")
        assert len(findings) >= 1

    def test_git_depth_nonzero_not_flagged(self):
        path = _write_yaml("""\
            variables:
              GIT_DEPTH: "20"
            stages: [build]
            build-job:
              stage: build
              timeout: 10 minutes
              image: python:3.12-slim
              script:
                - echo hello
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-006")
        assert len(findings) == 0

    def test_git_depth_zero_per_job_flagged(self):
        path = _write_yaml("""\
            stages: [secrets]
            secret-scan:
              stage: secrets
              timeout: 10 minutes
              image: python:3.12-slim
              variables:
                GIT_DEPTH: "0"
              script:
                - gitleaks detect
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-006")
        assert len(findings) >= 1


# ---------------------------------------------------------------------------
# GL-007: Docker-in-Docker without TLS
# ---------------------------------------------------------------------------

class TestGL007DinDNoTLS:

    def test_dind_without_tls_certdir_flagged(self):
        path = _write_yaml("""\
            image: docker:24
            stages: [build]
            services:
              - docker:dind
            build-job:
              stage: build
              timeout: 10 minutes
              script:
                - docker build .
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-007")
        assert len(findings) >= 1

    def test_dind_with_tls_certdir_not_flagged(self):
        path = _write_yaml("""\
            image: docker:24
            stages: [build]
            variables:
              DOCKER_TLS_CERTDIR: /certs
            services:
              - docker:dind
            build-job:
              stage: build
              timeout: 10 minutes
              script:
                - docker build .
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-007")
        assert len(findings) == 0

    def test_no_dind_not_flagged(self):
        path = _write_yaml("""\
            stages: [build]
            build-job:
              stage: build
              timeout: 10 minutes
              image: python:3.12-slim
              script:
                - echo hello
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-007")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# GL-008: artifacts without expire_in
# ---------------------------------------------------------------------------

class TestGL008ArtifactsNoExpiry:

    def test_artifacts_without_expire_in_flagged(self):
        path = _write_yaml("""\
            stages: [build]
            build-job:
              stage: build
              timeout: 10 minutes
              image: python:3.12-slim
              script:
                - make dist
              artifacts:
                paths:
                  - dist/
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-008")
        assert len(findings) >= 1

    def test_artifacts_with_expire_in_not_flagged(self):
        path = _write_yaml("""\
            stages: [build]
            build-job:
              stage: build
              timeout: 10 minutes
              image: python:3.12-slim
              script:
                - make dist
              artifacts:
                paths:
                  - dist/
                expire_in: 7 days
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-008")
        assert len(findings) == 0

    def test_reports_only_artifacts_not_flagged(self):
        """Artifacts that only contain 'reports' are managed by GitLab — exempt."""
        path = _write_yaml("""\
            stages: [sast]
            sast-scan:
              stage: sast
              timeout: 10 minutes
              image: python:3.12-slim
              script:
                - semgrep --sarif -o report.sarif .
              artifacts:
                reports:
                  sast: report.sarif
        """)
        result = audit_gitlab_ci_file(path)
        findings = _findings_for(result, "GL-008")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Integration: clean pipeline passes
# ---------------------------------------------------------------------------

class TestCleanPipeline:

    def test_clean_pipeline_passes(self):
        path = _write_yaml("""\
            image: python:3.12-slim

            stages:
              - lint
              - test
              - sast
              - deploy

            variables:
              GIT_DEPTH: "20"
              DOCKER_TLS_CERTDIR: /certs

            lint-job:
              stage: lint
              timeout: 10 minutes
              script:
                - ruff check .

            test-job:
              stage: test
              timeout: 15 minutes
              script:
                - pytest --cov=src --cov-fail-under=70
              artifacts:
                reports:
                  coverage_report:
                    coverage_format: cobertura
                    path: coverage.xml

            sast-scan:
              stage: sast
              timeout: 20 minutes
              script:
                - semgrep --config=auto --error .
              allow_failure: false
              artifacts:
                paths:
                  - semgrep-report.sarif
                expire_in: 7 days

            deploy-prod:
              stage: deploy
              timeout: 15 minutes
              rules:
                - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
              script:
                - ./deploy.sh
        """)
        result = audit_gitlab_ci_file(path)
        assert result.passed is True
        assert len([f for f in result.findings if f.severity in ("critical", "high")]) == 0

    def test_yaml_parse_error_produces_warning(self):
        path = _write_yaml("{\n  invalid yaml [[[")
        result = audit_gitlab_ci_file(path)
        assert len(result.warnings) > 0
        assert result.findings == []


# ---------------------------------------------------------------------------
# audit_gitlab_ci_directory
# ---------------------------------------------------------------------------

class TestAuditDirectory:

    def test_scans_multiple_files(self, tmp_path):
        for i in range(3):
            (tmp_path / f"pipeline{i}.yml").write_text(
                textwrap.dedent(f"""\
                    stages: [build]
                    build-job-{i}:
                      stage: build
                      image: python:3.12-slim
                      script:
                        - echo hello
                """)
            )
        results = audit_gitlab_ci_directory(tmp_path)
        assert len(results) == 3

    def test_empty_directory_returns_empty_list(self, tmp_path):
        results = audit_gitlab_ci_directory(tmp_path)
        assert results == []
