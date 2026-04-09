# test_pipeline_secret_scanner.py
# Pytest test-suite for pipeline_secret_scanner.py
#
# Copyright (c) 2024 Cyber Port contributors
# Licensed under the Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
#
# SPDX-License-Identifier: CC-BY-4.0

from __future__ import annotations

import sys
import os
import pytest

# ---------------------------------------------------------------------------
# Make the shared package importable regardless of CWD
# ---------------------------------------------------------------------------
sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..", "shared", "analyzers"),
)

from pipeline_secret_scanner import (  # noqa: E402
    PipelineEnvVar,
    PipelineFinding,
    PipelineStep,
    PipelineScanResult,
    PipelineSecretScanner,
    _CHECK_WEIGHTS,
)

# ---------------------------------------------------------------------------
# Dynamically constructed test values — avoids triggering GitHub push protection
# ---------------------------------------------------------------------------
_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"           # 20-char AWS access key ID
_GHP_TOKEN = "ghp_" + "x" * 40                    # GitHub PAT (ghp_)
_GHO_TOKEN = "gho_" + "y" * 36                    # GitHub OAuth token (gho_)
_GLPAT = "glpat-" + "abcdefghijklmnopqrstu"       # GitLab PAT (21 chars after dash)
_RSA_HEADER = "-----BEGIN RSA PRIVATE KEY-----"
_OPENSSH_HEADER = "-----BEGIN OPENSSH PRIVATE KEY-----"
_EC_HEADER = "-----BEGIN EC PRIVATE KEY-----"

# A base64 string that decodes to clearly binary/non-printable data.
# We build it from raw bytes so > 30 % are outside 0x20–0x7E.
import base64 as _b64
_BINARY_BYTES = bytes(range(0, 100))               # bytes 0x00–0x63, mostly non-printable
_BINARY_B64 = _b64.b64encode(_BINARY_BYTES).decode()  # well over 40 chars

# A base64 string that decodes to fully printable ASCII — should NOT fire.
_PRINTABLE_B64 = _b64.b64encode(b"Hello World this is normal ASCII text and it is long enough to exceed the minimum").decode()

SCANNER = PipelineSecretScanner()


# ===========================================================================
# Helpers
# ===========================================================================

def findings_for_check(result: PipelineScanResult, check_id: str) -> list:
    """Return all findings with the given check_id."""
    return [f for f in result.findings if f.check_id == check_id]


# ===========================================================================
# 1. Clean-log baseline
# ===========================================================================

class TestCleanLog:
    def test_empty_log_no_findings(self):
        result = SCANNER.scan_log("")
        assert result.findings == []

    def test_benign_log_no_findings(self):
        log = "Build started\nCompiling source files...\nBuild successful."
        result = SCANNER.scan_log(log)
        assert result.findings == []

    def test_clean_log_risk_score_zero(self):
        result = SCANNER.scan_log("All checks passed.")
        assert result.risk_score == 0

    def test_clean_log_summary_no_findings(self):
        result = SCANNER.scan_log("OK")
        assert "0 finding" in result.summary()

    def test_clean_log_by_severity_empty(self):
        result = SCANNER.scan_log("OK")
        assert result.by_severity() == {}


# ===========================================================================
# 2. PIPE-001 — AWS credential in log
# ===========================================================================

class TestPipe001:
    def test_aws_key_id_triggers(self):
        result = SCANNER.scan_log(f"Setting up credentials: {_AWS_KEY}")
        hits = findings_for_check(result, "PIPE-001")
        assert len(hits) >= 1

    def test_aws_key_id_severity_critical(self):
        result = SCANNER.scan_log(f"key={_AWS_KEY}")
        assert findings_for_check(result, "PIPE-001")[0].severity == "CRITICAL"

    def test_aws_key_id_location_log(self):
        result = SCANNER.scan_log(f"key={_AWS_KEY}")
        assert findings_for_check(result, "PIPE-001")[0].location == "log"

    def test_aws_secret_key_line_triggers(self):
        log = "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        result = SCANNER.scan_log(log)
        assert len(findings_for_check(result, "PIPE-001")) >= 1

    def test_aws_secret_key_case_insensitive(self):
        log = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        result = SCANNER.scan_log(log)
        assert len(findings_for_check(result, "PIPE-001")) >= 1

    def test_aws_secret_key_short_value_no_trigger(self):
        # Value only 8 chars — below the ≥16 threshold
        log = "aws_secret_access_key=shortval"
        result = SCANNER.scan_log(log)
        assert findings_for_check(result, "PIPE-001") == []

    def test_non_matching_akia_prefix_no_trigger(self):
        # AKIB instead of AKIA — should not match
        log = "AKIBIOSFODNN7EXAMPLETEST"
        result = SCANNER.scan_log(log)
        assert findings_for_check(result, "PIPE-001") == []

    def test_aws_finding_has_masked_evidence(self):
        result = SCANNER.scan_log(f"{_AWS_KEY} in log")
        finding = findings_for_check(result, "PIPE-001")[0]
        assert finding.masked_evidence is not None
        assert finding.masked_evidence.endswith("****")

    def test_aws_risk_score_includes_weight(self):
        result = SCANNER.scan_log(f"{_AWS_KEY}")
        assert result.risk_score >= _CHECK_WEIGHTS["PIPE-001"]


# ===========================================================================
# 3. PIPE-002 — GitHub / GitLab token in log
# ===========================================================================

class TestPipe002:
    def test_ghp_token_triggers(self):
        result = SCANNER.scan_log(f"Token: {_GHP_TOKEN}")
        assert len(findings_for_check(result, "PIPE-002")) >= 1

    def test_gho_token_triggers(self):
        result = SCANNER.scan_log(f"Using {_GHO_TOKEN} for auth")
        assert len(findings_for_check(result, "PIPE-002")) >= 1

    def test_ghs_token_triggers(self):
        token = "ghs_" + "z" * 36
        result = SCANNER.scan_log(f"token={token}")
        assert len(findings_for_check(result, "PIPE-002")) >= 1

    def test_ghr_token_triggers(self):
        token = "ghr_" + "a" * 36
        result = SCANNER.scan_log(token)
        assert len(findings_for_check(result, "PIPE-002")) >= 1

    def test_ghu_token_triggers(self):
        token = "ghu_" + "b" * 36
        result = SCANNER.scan_log(token)
        assert len(findings_for_check(result, "PIPE-002")) >= 1

    def test_gitlab_pat_triggers(self):
        result = SCANNER.scan_log(f"pat={_GLPAT}")
        assert len(findings_for_check(result, "PIPE-002")) >= 1

    def test_gitlab_pat_severity_critical(self):
        result = SCANNER.scan_log(_GLPAT)
        assert findings_for_check(result, "PIPE-002")[0].severity == "CRITICAL"

    def test_random_string_no_trigger(self):
        result = SCANNER.scan_log("some_random_string_without_prefix_1234")
        assert findings_for_check(result, "PIPE-002") == []

    def test_short_github_token_no_trigger(self):
        # Only 10 chars after prefix — below the ≥36 threshold
        result = SCANNER.scan_log("ghp_" + "x" * 10)
        assert findings_for_check(result, "PIPE-002") == []

    def test_github_finding_masked_evidence(self):
        result = SCANNER.scan_log(_GHP_TOKEN)
        finding = findings_for_check(result, "PIPE-002")[0]
        assert finding.masked_evidence.endswith("****")
        assert finding.masked_evidence[:4] == "ghp_"

    def test_gitlab_finding_location_log(self):
        result = SCANNER.scan_log(_GLPAT)
        assert findings_for_check(result, "PIPE-002")[0].location == "log"


# ===========================================================================
# 4. PIPE-003 — Base64-encoded binary secret in log
# ===========================================================================

class TestPipe003:
    def test_binary_base64_triggers(self):
        result = SCANNER.scan_log(f"data: {_BINARY_B64}")
        assert len(findings_for_check(result, "PIPE-003")) >= 1

    def test_binary_base64_severity_high(self):
        result = SCANNER.scan_log(_BINARY_B64)
        assert findings_for_check(result, "PIPE-003")[0].severity == "HIGH"

    def test_short_base64_no_trigger(self):
        # Exactly 40 chars — equal to threshold so must NOT fire (strictly > 40)
        short = _b64.b64encode(bytes(range(30))).decode()[:40]
        result = SCANNER.scan_log(short)
        assert findings_for_check(result, "PIPE-003") == []

    def test_printable_base64_no_trigger(self):
        result = SCANNER.scan_log(_PRINTABLE_B64)
        assert findings_for_check(result, "PIPE-003") == []

    def test_duplicate_base64_fired_once(self):
        # Same blob repeated twice — should still fire only once per unique string
        log = f"{_BINARY_B64} some text {_BINARY_B64}"
        result = SCANNER.scan_log(log)
        hits = findings_for_check(result, "PIPE-003")
        assert len(hits) == 1

    def test_binary_base64_location_log(self):
        result = SCANNER.scan_log(_BINARY_B64)
        assert findings_for_check(result, "PIPE-003")[0].location == "log"

    def test_binary_base64_has_masked_evidence(self):
        result = SCANNER.scan_log(_BINARY_B64)
        finding = findings_for_check(result, "PIPE-003")[0]
        assert finding.masked_evidence is not None
        assert finding.masked_evidence.endswith("****")


# ===========================================================================
# 5. PIPE-004 — Secret in curl / wget command
# ===========================================================================

class TestPipe004:
    def test_curl_bearer_long_token_triggers(self):
        log = 'curl -H "Authorization: Bearer supersecrettoken12345678" https://api.example.com'
        result = SCANNER.scan_log(log)
        assert len(findings_for_check(result, "PIPE-004")) >= 1

    def test_curl_bearer_location_log(self):
        log = 'curl -H "Authorization: Bearer supersecrettoken12345678" https://api.example.com'
        result = SCANNER.scan_log(log)
        assert findings_for_check(result, "PIPE-004")[0].location == "log"

    def test_curl_bearer_severity_critical(self):
        log = 'curl -H "Authorization: Bearer supersecrettoken12345678" https://api.example.com'
        result = SCANNER.scan_log(log)
        assert findings_for_check(result, "PIPE-004")[0].severity == "CRITICAL"

    def test_curl_userpwd_long_password_triggers(self):
        log = "curl -u admin:verylongpassword123 https://api.example.com/endpoint"
        result = SCANNER.scan_log(log)
        assert len(findings_for_check(result, "PIPE-004")) >= 1

    def test_curl_userpwd_short_password_no_trigger(self):
        # Password is only 4 chars — below the ≥9 threshold (value group >8)
        log = "curl -u admin:pass https://api.example.com"
        result = SCANNER.scan_log(log)
        assert findings_for_check(result, "PIPE-004") == []

    def test_curl_token_flag_triggers(self):
        log = "curl --token=myverysecrettoken123 https://api.example.com"
        result = SCANNER.scan_log(log)
        assert len(findings_for_check(result, "PIPE-004")) >= 1

    def test_curl_token_short_no_trigger(self):
        # Only 5 chars after = — below the ≥11 threshold
        log = "curl --token=short https://api.example.com"
        result = SCANNER.scan_log(log)
        assert findings_for_check(result, "PIPE-004") == []

    def test_wget_bearer_triggers(self):
        log = 'wget -H "Authorization: Bearer anotherverylongbearertoken9876" https://api.example.com'
        result = SCANNER.scan_log(log)
        assert len(findings_for_check(result, "PIPE-004")) >= 1

    def test_pipe004_in_script_location(self):
        step = PipelineStep(
            name="deploy",
            log_content="",
            script='curl -H "Authorization: Bearer supersecrettoken12345678" https://api.example.com',
        )
        result = SCANNER.scan_pipeline([step])
        hits = findings_for_check(result, "PIPE-004")
        assert any(h.location == "script" for h in hits)

    def test_pipe004_masked_evidence_set(self):
        log = 'curl -H "Authorization: Bearer supersecrettoken12345678" https://api.example.com'
        result = SCANNER.scan_log(log)
        finding = findings_for_check(result, "PIPE-004")[0]
        assert finding.masked_evidence is not None
        assert finding.masked_evidence.endswith("****")


# ===========================================================================
# 6. PIPE-005 — Secret variable not masked
# ===========================================================================

class TestPipe005:
    def test_secret_var_not_masked_long_value_triggers(self):
        var = PipelineEnvVar(name="MY_SECRET_KEY", value="supersecretvalue123", is_masked=False)
        result = SCANNER.scan_env_vars([var])
        assert len(findings_for_check(result, "PIPE-005")) >= 1

    def test_secret_var_masked_no_trigger(self):
        var = PipelineEnvVar(name="MY_SECRET_KEY", value="supersecretvalue123", is_masked=True)
        result = SCANNER.scan_env_vars([var])
        assert findings_for_check(result, "PIPE-005") == []

    def test_secret_var_short_value_no_trigger(self):
        # Value is exactly 8 chars — boundary condition (must be > 8 to trigger)
        var = PipelineEnvVar(name="MY_SECRET_KEY", value="12345678", is_masked=False)
        result = SCANNER.scan_env_vars([var])
        assert findings_for_check(result, "PIPE-005") == []

    def test_non_secret_name_no_trigger(self):
        var = PipelineEnvVar(name="BUILD_VERSION", value="supersecretvalue123", is_masked=False)
        result = SCANNER.scan_env_vars([var])
        assert findings_for_check(result, "PIPE-005") == []

    def test_password_keyword_triggers(self):
        var = PipelineEnvVar(name="DB_PASSWORD", value="mydbpassword123", is_masked=False)
        result = SCANNER.scan_env_vars([var])
        assert len(findings_for_check(result, "PIPE-005")) >= 1

    def test_token_keyword_triggers(self):
        var = PipelineEnvVar(name="API_TOKEN", value="myapitoken1234567", is_masked=False)
        result = SCANNER.scan_env_vars([var])
        assert len(findings_for_check(result, "PIPE-005")) >= 1

    def test_credential_keyword_triggers(self):
        var = PipelineEnvVar(name="DEPLOY_CREDENTIAL", value="cred_value_12345", is_masked=False)
        result = SCANNER.scan_env_vars([var])
        assert len(findings_for_check(result, "PIPE-005")) >= 1

    def test_pwd_keyword_triggers(self):
        var = PipelineEnvVar(name="DB_PWD", value="somepwd_value_123", is_masked=False)
        result = SCANNER.scan_env_vars([var])
        assert len(findings_for_check(result, "PIPE-005")) >= 1

    def test_passwd_keyword_triggers(self):
        var = PipelineEnvVar(name="ROOT_PASSWD", value="rootpasswd_123456", is_masked=False)
        result = SCANNER.scan_env_vars([var])
        assert len(findings_for_check(result, "PIPE-005")) >= 1

    def test_pipe005_severity_high(self):
        var = PipelineEnvVar(name="APP_SECRET", value="secretvalue_12345", is_masked=False)
        result = SCANNER.scan_env_vars([var])
        assert findings_for_check(result, "PIPE-005")[0].severity == "HIGH"

    def test_pipe005_location_env(self):
        var = PipelineEnvVar(name="APP_SECRET", value="secretvalue_12345", is_masked=False)
        result = SCANNER.scan_env_vars([var])
        assert findings_for_check(result, "PIPE-005")[0].location == "env"

    def test_pipe005_masked_evidence(self):
        var = PipelineEnvVar(name="APP_SECRET", value="secretvalue_12345", is_masked=False)
        result = SCANNER.scan_env_vars([var])
        finding = findings_for_check(result, "PIPE-005")[0]
        assert finding.masked_evidence is not None
        assert finding.masked_evidence.endswith("****")
        assert finding.masked_evidence[:8] == "secretva"

    def test_key_keyword_case_insensitive(self):
        var = PipelineEnvVar(name="my_api_key", value="supersecret_12345", is_masked=False)
        result = SCANNER.scan_env_vars([var])
        assert len(findings_for_check(result, "PIPE-005")) >= 1


# ===========================================================================
# 7. PIPE-006 — Plaintext Docker registry credentials
# ===========================================================================

class TestPipe006:
    def test_docker_login_p_triggers(self):
        log = "docker login -p myregistrypassword registry.example.com"
        result = SCANNER.scan_log(log)
        assert len(findings_for_check(result, "PIPE-006")) >= 1

    def test_docker_login_password_long_form_triggers(self):
        log = "docker login --password myregistrypassword registry.example.com"
        result = SCANNER.scan_log(log)
        assert len(findings_for_check(result, "PIPE-006")) >= 1

    def test_docker_config_json_auths_triggers(self):
        log = (
            'Writing .docker/config.json: {"auths": {"registry": {"auth": '
            '"dXNlcjpwYXNzd29yZA=="}}}'
        )
        result = SCANNER.scan_log(log)
        assert len(findings_for_check(result, "PIPE-006")) >= 1

    def test_docker_config_json_in_script_triggers(self):
        script = (
            'echo \'{"auths":{"registry":{"auth":"dXNlcjpwYXNz"}}}\' '
            '> .docker/config.json'
        )
        step = PipelineStep(name="push", log_content="", script=script)
        result = SCANNER.scan_pipeline([step])
        assert len(findings_for_check(result, "PIPE-006")) >= 1

    def test_docker_login_severity_high(self):
        log = "docker login -p myregistrypassword registry.example.com"
        result = SCANNER.scan_log(log)
        assert findings_for_check(result, "PIPE-006")[0].severity == "HIGH"

    def test_plain_docker_pull_no_trigger(self):
        log = "docker pull ubuntu:22.04"
        result = SCANNER.scan_log(log)
        assert findings_for_check(result, "PIPE-006") == []

    def test_docker_login_stdin_no_trigger(self):
        # Using --password-stdin is the secure pattern — should NOT fire
        log = "echo $PASS | docker login --password-stdin registry.example.com"
        result = SCANNER.scan_log(log)
        assert findings_for_check(result, "PIPE-006") == []


# ===========================================================================
# 8. PIPE-007 — SSH private key
# ===========================================================================

class TestPipe007:
    def test_rsa_key_in_log_triggers(self):
        log = f"Deploying\n{_RSA_HEADER}\nMIIEowIBAAKCAQEA...\n"
        result = SCANNER.scan_log(log)
        assert len(findings_for_check(result, "PIPE-007")) >= 1

    def test_openssh_key_in_log_triggers(self):
        log = f"SSH key:\n{_OPENSSH_HEADER}\nb3BlbnNzaC1rZXktdjEAAAA=\n"
        result = SCANNER.scan_log(log)
        assert len(findings_for_check(result, "PIPE-007")) >= 1

    def test_ec_key_in_log_triggers(self):
        log = f"EC key loaded\n{_EC_HEADER}\nMHQCAQEEIBkg...\n"
        result = SCANNER.scan_log(log)
        assert len(findings_for_check(result, "PIPE-007")) >= 1

    def test_rsa_key_in_env_var_triggers(self):
        var = PipelineEnvVar(
            name="SSH_PRIVATE_KEY",
            value=f"{_RSA_HEADER}\nMIIEowIBAAKCAQEA...",
            is_masked=False,
        )
        result = SCANNER.scan_env_vars([var])
        assert len(findings_for_check(result, "PIPE-007")) >= 1

    def test_openssh_key_in_env_var_triggers(self):
        var = PipelineEnvVar(
            name="DEPLOY_KEY",
            value=f"{_OPENSSH_HEADER}\nb3BlbnNzaC1rZXktdjEAAAA=",
            is_masked=False,
        )
        result = SCANNER.scan_env_vars([var])
        assert len(findings_for_check(result, "PIPE-007")) >= 1

    def test_ec_key_in_env_var_triggers(self):
        var = PipelineEnvVar(
            name="TLS_KEY",
            value=f"{_EC_HEADER}\nMHQCAQEEIBkg",
            is_masked=False,
        )
        result = SCANNER.scan_env_vars([var])
        assert len(findings_for_check(result, "PIPE-007")) >= 1

    def test_pipe007_severity_critical(self):
        result = SCANNER.scan_log(f"key: {_RSA_HEADER}")
        assert findings_for_check(result, "PIPE-007")[0].severity == "CRITICAL"

    def test_pipe007_location_log(self):
        result = SCANNER.scan_log(f"{_RSA_HEADER}")
        assert findings_for_check(result, "PIPE-007")[0].location == "log"

    def test_pipe007_env_location(self):
        var = PipelineEnvVar(name="KEY", value=f"{_RSA_HEADER}", is_masked=False)
        result = SCANNER.scan_env_vars([var])
        assert findings_for_check(result, "PIPE-007")[0].location == "env"

    def test_pipe007_masked_evidence_set(self):
        result = SCANNER.scan_log(f"{_RSA_HEADER}")
        finding = findings_for_check(result, "PIPE-007")[0]
        assert finding.masked_evidence is not None
        assert finding.masked_evidence.endswith("****")

    def test_public_key_no_trigger(self):
        log = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0B...\n-----END PUBLIC KEY-----"
        result = SCANNER.scan_log(log)
        assert findings_for_check(result, "PIPE-007") == []

    def test_rsa_key_in_script_triggers(self):
        step = PipelineStep(
            name="setup-ssh",
            log_content="",
            script=f"echo '{_RSA_HEADER}' > id_rsa",
        )
        result = SCANNER.scan_pipeline([step])
        hits = findings_for_check(result, "PIPE-007")
        assert any(h.location == "script" for h in hits)


# ===========================================================================
# 9. scan_env_vars — only env-related checks fire
# ===========================================================================

class TestScanEnvVars:
    def test_env_scan_does_not_fire_log_checks(self):
        # Even if the env var value looks like an AWS key, log-only checks
        # should not fire from scan_env_vars — only PIPE-005 and PIPE-007
        # are relevant to env vars.
        var = PipelineEnvVar(name="BUILD_ID", value=_AWS_KEY, is_masked=False)
        result = SCANNER.scan_env_vars([var])
        # PIPE-001 should NOT fire (it's a log check)
        assert findings_for_check(result, "PIPE-001") == []

    def test_env_scan_fires_pipe005(self):
        var = PipelineEnvVar(name="DB_PASSWORD", value="longpassword123", is_masked=False)
        result = SCANNER.scan_env_vars([var])
        assert len(findings_for_check(result, "PIPE-005")) >= 1

    def test_env_scan_fires_pipe007(self):
        var = PipelineEnvVar(name="DEPLOY_KEY", value=_RSA_HEADER, is_masked=False)
        result = SCANNER.scan_env_vars([var])
        assert len(findings_for_check(result, "PIPE-007")) >= 1

    def test_env_scan_empty_list_no_findings(self):
        result = SCANNER.scan_env_vars([])
        assert result.findings == []
        assert result.risk_score == 0

    def test_env_scan_accepts_step_name(self):
        var = PipelineEnvVar(name="DB_PASSWORD", value="longpassword123", is_masked=False)
        result = SCANNER.scan_env_vars([var], step_name="build-step")
        assert findings_for_check(result, "PIPE-005")[0].step_name == "build-step"


# ===========================================================================
# 10. scan_pipeline — combines log + env
# ===========================================================================

class TestScanPipeline:
    def test_pipeline_scan_combines_log_and_env(self):
        var = PipelineEnvVar(name="API_SECRET", value="supersecretvalue99", is_masked=False)
        step = PipelineStep(
            name="test",
            log_content=f"Token found: {_GHP_TOKEN}",
            env_vars=[var],
        )
        result = SCANNER.scan_pipeline([step])
        pipe002_hits = findings_for_check(result, "PIPE-002")
        pipe005_hits = findings_for_check(result, "PIPE-005")
        assert len(pipe002_hits) >= 1
        assert len(pipe005_hits) >= 1

    def test_pipeline_scan_uses_step_name(self):
        step = PipelineStep(
            name="deploy",
            log_content=f"{_AWS_KEY}",
            env_vars=[],
        )
        result = SCANNER.scan_pipeline([step])
        assert findings_for_check(result, "PIPE-001")[0].step_name == "deploy"

    def test_pipeline_scan_empty_steps_no_findings(self):
        result = SCANNER.scan_pipeline([])
        assert result.findings == []
        assert result.risk_score == 0

    def test_pipeline_scan_multiple_steps(self):
        steps = [
            PipelineStep(name="step1", log_content=f"{_AWS_KEY}", env_vars=[]),
            PipelineStep(name="step2", log_content=f"{_GHP_TOKEN}", env_vars=[]),
        ]
        result = SCANNER.scan_pipeline(steps)
        assert len(findings_for_check(result, "PIPE-001")) >= 1
        assert len(findings_for_check(result, "PIPE-002")) >= 1

    def test_pipeline_scan_includes_script_checks(self):
        step = PipelineStep(
            name="curl-step",
            log_content="",
            script='curl -H "Authorization: Bearer supersecrettoken12345678" https://api.example.com',
        )
        result = SCANNER.scan_pipeline([step])
        assert len(findings_for_check(result, "PIPE-004")) >= 1

    def test_pipeline_scan_no_script_no_crash(self):
        step = PipelineStep(name="test", log_content="clean log", env_vars=[])
        result = SCANNER.scan_pipeline([step])
        assert isinstance(result, PipelineScanResult)


# ===========================================================================
# 11. Risk score behaviour
# ===========================================================================

class TestRiskScore:
    def test_risk_score_capped_at_100(self):
        # Trigger multiple CRITICAL checks — combined weights > 100
        var = PipelineEnvVar(name="SSH_KEY", value=_RSA_HEADER, is_masked=False)
        log = (
            f"{_AWS_KEY} "
            f"{_GHP_TOKEN} "
            f'{_RSA_HEADER} '
            'curl -H "Authorization: Bearer supersecrettoken12345678" https://api.example.com'
        )
        step = PipelineStep(name="step", log_content=log, env_vars=[var])
        result = SCANNER.scan_pipeline([step])
        assert result.risk_score <= 100

    def test_risk_score_increases_per_unique_check(self):
        result1 = SCANNER.scan_log(f"{_AWS_KEY}")
        result2 = SCANNER.scan_log(f"{_AWS_KEY} {_GHP_TOKEN}")
        assert result2.risk_score >= result1.risk_score

    def test_same_check_fired_twice_counted_once(self):
        # Two AWS keys in the same log — PIPE-001 fires twice but weight added once
        log = f"{_AWS_KEY} and another {_AWS_KEY}"
        result = SCANNER.scan_log(log)
        assert result.risk_score == _CHECK_WEIGHTS["PIPE-001"]

    def test_no_findings_risk_score_zero(self):
        result = SCANNER.scan_log("clean output")
        assert result.risk_score == 0

    def test_risk_score_single_check_equals_weight(self):
        result = SCANNER.scan_log(f"{_GHP_TOKEN}")
        assert result.risk_score == _CHECK_WEIGHTS["PIPE-002"]

    def test_two_different_checks_score_sum(self):
        log = f"{_AWS_KEY} {_GHP_TOKEN}"
        result = SCANNER.scan_log(log)
        expected = _CHECK_WEIGHTS["PIPE-001"] + _CHECK_WEIGHTS["PIPE-002"]
        assert result.risk_score == min(100, expected)


# ===========================================================================
# 12. by_severity() structure
# ===========================================================================

class TestBySeverity:
    def test_by_severity_returns_dict(self):
        result = SCANNER.scan_log(_GHP_TOKEN)
        assert isinstance(result.by_severity(), dict)

    def test_by_severity_critical_key_present(self):
        result = SCANNER.scan_log(_GHP_TOKEN)
        assert "CRITICAL" in result.by_severity()

    def test_by_severity_counts_correctly(self):
        # Two CRITICAL findings: PIPE-001 + PIPE-002
        log = f"{_AWS_KEY} {_GHP_TOKEN}"
        result = SCANNER.scan_log(log)
        sev = result.by_severity()
        assert sev.get("CRITICAL", 0) >= 2

    def test_by_severity_high_key_present_for_high_finding(self):
        var = PipelineEnvVar(name="DB_SECRET", value="mysecretvalue123", is_masked=False)
        result = SCANNER.scan_env_vars([var])
        assert "HIGH" in result.by_severity()

    def test_by_severity_empty_for_no_findings(self):
        result = SCANNER.scan_log("OK")
        assert result.by_severity() == {}

    def test_by_severity_mixed(self):
        var = PipelineEnvVar(name="DB_SECRET", value="mysecretvalue123", is_masked=False)
        step = PipelineStep(
            name="s", log_content=_GHP_TOKEN, env_vars=[var]
        )
        result = SCANNER.scan_pipeline([step])
        sev = result.by_severity()
        assert sev.get("CRITICAL", 0) >= 1
        assert sev.get("HIGH", 0) >= 1


# ===========================================================================
# 13. summary() format
# ===========================================================================

class TestSummary:
    def test_summary_returns_string(self):
        result = SCANNER.scan_log("clean")
        assert isinstance(result.summary(), str)

    def test_summary_contains_finding_count(self):
        result = SCANNER.scan_log(_GHP_TOKEN)
        assert str(len(result.findings)) in result.summary() or "finding" in result.summary()

    def test_summary_contains_risk_score(self):
        result = SCANNER.scan_log(_GHP_TOKEN)
        assert str(result.risk_score) in result.summary()

    def test_summary_zero_findings(self):
        result = SCANNER.scan_log("OK")
        assert "0 finding" in result.summary()

    def test_summary_contains_critical(self):
        result = SCANNER.scan_log(_GHP_TOKEN)
        assert "CRITICAL" in result.summary()

    def test_summary_contains_high(self):
        var = PipelineEnvVar(name="DB_SECRET", value="mysecretvalue123", is_masked=False)
        result = SCANNER.scan_env_vars([var])
        assert "HIGH" in result.summary()


# ===========================================================================
# 14. to_dict() — all dataclasses
# ===========================================================================

class TestToDict:
    def test_pipeline_env_var_to_dict(self):
        var = PipelineEnvVar(name="API_KEY", value="v4lue", is_masked=True)
        d = var.to_dict()
        assert d["name"] == "API_KEY"
        assert d["value"] == "v4lue"
        assert d["is_masked"] is True

    def test_pipeline_step_to_dict(self):
        step = PipelineStep(
            name="build",
            log_content="log line",
            env_vars=[PipelineEnvVar(name="X", value="y")],
            script="echo hi",
        )
        d = step.to_dict()
        assert d["name"] == "build"
        assert d["log_content"] == "log line"
        assert d["script"] == "echo hi"
        assert isinstance(d["env_vars"], list)
        assert d["env_vars"][0]["name"] == "X"

    def test_pipeline_finding_to_dict(self):
        finding = PipelineFinding(
            check_id="PIPE-001",
            severity="CRITICAL",
            step_name="test",
            location="log",
            message="AWS key found",
            recommendation="Rotate it",
            masked_evidence="AKIAIOSD****",
        )
        d = finding.to_dict()
        assert d["check_id"] == "PIPE-001"
        assert d["severity"] == "CRITICAL"
        assert d["masked_evidence"] == "AKIAIOSD****"

    def test_pipeline_scan_result_to_dict(self):
        result = SCANNER.scan_log(_GHP_TOKEN)
        d = result.to_dict()
        assert "findings" in d
        assert "risk_score" in d
        assert isinstance(d["findings"], list)
        assert isinstance(d["risk_score"], int)

    def test_scan_result_to_dict_findings_are_dicts(self):
        result = SCANNER.scan_log(_GHP_TOKEN)
        d = result.to_dict()
        for item in d["findings"]:
            assert isinstance(item, dict)
            assert "check_id" in item

    def test_pipeline_step_to_dict_no_script(self):
        step = PipelineStep(name="test", log_content="output")
        d = step.to_dict()
        assert d["script"] is None

    def test_empty_result_to_dict(self):
        result = SCANNER.scan_log("clean")
        d = result.to_dict()
        assert d["findings"] == []
        assert d["risk_score"] == 0


# ===========================================================================
# 15. masked_evidence truncation
# ===========================================================================

class TestMaskedEvidence:
    def test_masked_evidence_format(self):
        result = SCANNER.scan_log(f"{_AWS_KEY}")
        finding = findings_for_check(result, "PIPE-001")[0]
        assert finding.masked_evidence is not None
        # Must be exactly 8 real chars + 4 asterisks
        assert len(finding.masked_evidence) == 12
        assert finding.masked_evidence[8:] == "****"

    def test_masked_evidence_first_eight_chars_of_aws_key(self):
        result = SCANNER.scan_log(f"{_AWS_KEY}")
        finding = findings_for_check(result, "PIPE-001")[0]
        # First 8 chars of the AWS key
        assert finding.masked_evidence[:8] == _AWS_KEY[:8]

    def test_masked_evidence_none_when_no_evidence(self):
        # PIPE-006 docker config match has masked_evidence=None
        log = (
            'Writing .docker/config.json: {"auths": {"registry": {"auth": '
            '"dXNlcjpwYXNzd29yZA=="}}}'
        )
        result = SCANNER.scan_log(log)
        config_hits = [
            f for f in findings_for_check(result, "PIPE-006")
            if f.masked_evidence is None
        ]
        assert len(config_hits) >= 1

    def test_masked_evidence_github_token(self):
        result = SCANNER.scan_log(_GHP_TOKEN)
        finding = findings_for_check(result, "PIPE-002")[0]
        assert finding.masked_evidence == _GHP_TOKEN[:8] + "****"

    def test_masked_evidence_env_var_value(self):
        var = PipelineEnvVar(name="DB_PASSWORD", value="longpassword123", is_masked=False)
        result = SCANNER.scan_env_vars([var])
        finding = findings_for_check(result, "PIPE-005")[0]
        assert finding.masked_evidence == "longpass****"
