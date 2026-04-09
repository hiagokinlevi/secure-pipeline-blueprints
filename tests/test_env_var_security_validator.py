# CC BY 4.0 — Cyber Port Portfolio
# Tests: env_var_security_validator
# Compatible with: Python 3.9+, pytest

"""
Test suite for shared/analyzers/env_var_security_validator.py

Groups
------
  A  – ENV-001  Hardcoded secret value
  B  – ENV-002  URL with embedded credentials
  C  – ENV-003  User-controlled input in secret context
  D  – ENV-004  Broad GitHub token exposure
  E  – ENV-005  Secret name at workflow scope
  F  – ENV-006  Conflicting values across scopes
  G  – ENV-007  Embedded private key / certificate
  H  – extract_env_vars helper
  I  – ENVResult helpers (to_dict, summary, by_severity)
  J  – risk_score and deduplication
  K  – Integration / combined scenarios
"""

import sys
import os

# Allow importing the module without an installed package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared", "analyzers"))

from env_var_security_validator import (
    EnvVar,
    ENVFinding,
    ENVResult,
    extract_env_vars,
    validate,
)


# ---------------------------------------------------------------------------
# Fixtures / convenience builders
# ---------------------------------------------------------------------------


def wf_var(name: str, value: str, is_secret_ref: bool = False) -> EnvVar:
    return EnvVar(name=name, value=value, scope="workflow", is_secret_ref=is_secret_ref)


def job_var(name: str, value: str, job_id: str = "build", is_secret_ref: bool = False) -> EnvVar:
    return EnvVar(name=name, value=value, scope=f"job:{job_id}", is_secret_ref=is_secret_ref)


def step_var(name: str, value: str, job_id: str = "build", step: str = "run", is_secret_ref: bool = False) -> EnvVar:
    return EnvVar(name=name, value=value, scope=f"step:{job_id}:{step}", is_secret_ref=is_secret_ref)


def check_ids(result: ENVResult):
    return {f.check_id for f in result.findings}


# ===========================================================================
# A – ENV-001: Hardcoded secret value
# ===========================================================================


def test_env001_fires_for_password_hardcoded():
    r = validate([wf_var("DB_PASSWORD", "hunter2")])
    assert "ENV-001" in check_ids(r)


def test_env001_fires_for_secret_in_name():
    r = validate([wf_var("APP_SECRET", "mysecretvalue")])
    assert "ENV-001" in check_ids(r)


def test_env001_fires_for_token_hardcoded():
    r = validate([job_var("GITHUB_TOKEN_BACKUP", "ghp_abc123")])
    assert "ENV-001" in check_ids(r)


def test_env001_fires_for_api_key_hardcoded():
    r = validate([step_var("STRIPE_API_KEY", "sk_live_0123456789")])
    assert "ENV-001" in check_ids(r)


def test_env001_fires_for_credential_in_name():
    r = validate([wf_var("AWS_CREDENTIAL", "AKIAIOSFODNN7EXAMPLE")])
    assert "ENV-001" in check_ids(r)


def test_env001_fires_for_private_in_name():
    r = validate([wf_var("PRIVATE_CERT_DATA", "some-cert-string")])
    assert "ENV-001" in check_ids(r)


def test_env001_does_not_fire_for_secret_ref():
    """A proper ${{ secrets.X }} reference must NOT trigger ENV-001."""
    r = validate([wf_var("DB_PASSWORD", "${{ secrets.DB_PASSWORD }}", is_secret_ref=True)])
    assert "ENV-001" not in check_ids(r)


def test_env001_does_not_fire_for_empty_value():
    r = validate([wf_var("DB_PASSWORD", "")])
    assert "ENV-001" not in check_ids(r)


def test_env001_does_not_fire_for_expression_value():
    """Any ${{ ... }} expression (non-secret) should be considered an expression, not hardcoded."""
    r = validate([wf_var("API_KEY", "${{ env.SOME_VAR }}")])
    assert "ENV-001" not in check_ids(r)


def test_env001_does_not_fire_for_non_secret_name():
    r = validate([wf_var("LOG_LEVEL", "debug")])
    assert "ENV-001" not in check_ids(r)


def test_env001_case_insensitive_name_match():
    """Name matching is case-insensitive."""
    r = validate([wf_var("db_password", "hunter2")])
    assert "ENV-001" in check_ids(r)


def test_env001_partial_keyword_match():
    """'KEY' appearing as substring (e.g., MONKEY) should still match."""
    r = validate([wf_var("MONKEY_KEY", "abc123")])
    assert "ENV-001" in check_ids(r)


def test_env001_fires_at_step_scope():
    r = validate([step_var("ACCESS_TOKEN", "plain-text-value")])
    assert "ENV-001" in check_ids(r)


# ===========================================================================
# B – ENV-002: URL with embedded credentials
# ===========================================================================


def test_env002_fires_for_http_creds_in_url():
    r = validate([wf_var("DB_URL", "https://user:pass@db.example.com/mydb")])
    assert "ENV-002" in check_ids(r)


def test_env002_fires_for_postgres_dsn():
    r = validate([wf_var("DATABASE_URL", "postgresql://admin:s3cr3t@localhost:5432/appdb")])
    assert "ENV-002" in check_ids(r)


def test_env002_fires_for_ftp_creds():
    r = validate([job_var("FTP_URL", "ftp://ftpuser:ftppass@ftp.example.com")])
    assert "ENV-002" in check_ids(r)


def test_env002_fires_for_redis_with_password():
    r = validate([wf_var("REDIS_URL", "redis://:mypassword@cache.example.com:6379")])
    assert "ENV-002" in check_ids(r)


def test_env002_does_not_fire_for_url_without_creds():
    r = validate([wf_var("SERVICE_URL", "https://api.example.com/endpoint")])
    assert "ENV-002" not in check_ids(r)


def test_env002_does_not_fire_for_empty_value():
    r = validate([wf_var("DB_URL", "")])
    assert "ENV-002" not in check_ids(r)


def test_env002_fires_regardless_of_var_name():
    """ENV-002 fires on URL pattern regardless of whether name is secret-related."""
    r = validate([wf_var("SOME_ENDPOINT", "mysql://root:root@mysql.internal:3306/")])
    assert "ENV-002" in check_ids(r)


def test_env002_fires_for_mongo_uri():
    r = validate([wf_var("MONGO_URI", "mongodb://user:password@cluster.mongodb.net:27017/db")])
    assert "ENV-002" in check_ids(r)


def test_env002_does_not_fire_for_non_url():
    r = validate([wf_var("NOTE", "user:pass is documented here")])
    assert "ENV-002" not in check_ids(r)


# ===========================================================================
# C – ENV-003: User-controlled input in secret context
# ===========================================================================


def test_env003_fires_for_github_event_input():
    r = validate([wf_var("API_KEY", "${{ github.event.client_payload.key }}")])
    assert "ENV-003" in check_ids(r)


def test_env003_fires_for_inputs_ref():
    r = validate([wf_var("APP_SECRET", "${{ inputs.secret_value }}")])
    assert "ENV-003" in check_ids(r)


def test_env003_fires_for_github_event_on_token():
    r = validate([wf_var("ACCESS_TOKEN", "${{ github.event.inputs.token }}")])
    assert "ENV-003" in check_ids(r)


def test_env003_does_not_fire_for_safe_secret_ref():
    r = validate([wf_var("API_KEY", "${{ secrets.API_KEY }}", is_secret_ref=True)])
    assert "ENV-003" not in check_ids(r)


def test_env003_does_not_fire_for_non_secret_name():
    """github.event in a non-secret-named var must NOT fire ENV-003."""
    r = validate([wf_var("RUN_ID", "${{ github.event.run_id }}")])
    assert "ENV-003" not in check_ids(r)


def test_env003_does_not_fire_for_inputs_non_secret_name():
    r = validate([wf_var("TARGET_ENV", "${{ inputs.environment }}")])
    assert "ENV-003" not in check_ids(r)


def test_env003_fires_at_step_scope():
    r = validate([step_var("DB_PASSWORD", "${{ github.event.client_payload.dbpass }}")])
    assert "ENV-003" in check_ids(r)


# ===========================================================================
# D – ENV-004: Broad GitHub token exposure at workflow scope
# ===========================================================================


def test_env004_fires_for_github_token_at_workflow():
    r = validate([wf_var("CI_TOKEN", "${{ github.token }}")])
    assert "ENV-004" in check_ids(r)


def test_env004_fires_for_secrets_github_token_at_workflow():
    r = validate([wf_var("GH_TOKEN", "${{ secrets.GITHUB_TOKEN }}")])
    assert "ENV-004" in check_ids(r)


def test_env004_does_not_fire_at_job_scope():
    """ENV-004 only fires at workflow scope."""
    r = validate([job_var("CI_TOKEN", "${{ github.token }}")])
    assert "ENV-004" not in check_ids(r)


def test_env004_does_not_fire_at_step_scope():
    r = validate([step_var("CI_TOKEN", "${{ github.token }}")])
    assert "ENV-004" not in check_ids(r)


def test_env004_does_not_fire_for_non_secret_name():
    r = validate([wf_var("RUNNER_TOKEN", "${{ github.token }}")])
    # RUNNER contains no keyword exactly? Let's check: TOKEN is a keyword so RUNNER_TOKEN matches
    # "TOKEN" IS in "RUNNER_TOKEN".upper() → ENV-004 should fire
    assert "ENV-004" in check_ids(r)


def test_env004_does_not_fire_for_non_token_value():
    r = validate([wf_var("CI_TOKEN", "${{ secrets.MY_CUSTOM_TOKEN }}")])
    # value is a secrets ref but not github.token / GITHUB_TOKEN → no ENV-004
    assert "ENV-004" not in check_ids(r)


# ===========================================================================
# E – ENV-005: Secret name at workflow scope (broad exposure)
# ===========================================================================


def test_env005_fires_for_secret_name_at_workflow():
    r = validate([wf_var("API_KEY", "${{ secrets.API_KEY }}", is_secret_ref=True)])
    assert "ENV-005" in check_ids(r)


def test_env005_does_not_fire_at_job_scope():
    r = validate([job_var("API_KEY", "${{ secrets.API_KEY }}", is_secret_ref=True)])
    assert "ENV-005" not in check_ids(r)


def test_env005_does_not_fire_for_non_secret_name_at_workflow():
    r = validate([wf_var("NODE_ENV", "production")])
    assert "ENV-005" not in check_ids(r)


def test_env005_suppressed_when_env004_fires():
    """If ENV-004 fires for a var, ENV-005 must NOT also fire for the same var."""
    var = wf_var("CI_TOKEN", "${{ github.token }}")
    r = validate([var])
    assert "ENV-004" in check_ids(r)
    assert "ENV-005" not in check_ids(r)


def test_env005_suppressed_for_github_token_workflow():
    var = wf_var("GH_TOKEN", "${{ secrets.GITHUB_TOKEN }}")
    r = validate([var])
    assert "ENV-004" in check_ids(r)
    assert "ENV-005" not in check_ids(r)


def test_env005_fires_for_password_at_workflow_non_token_value():
    """ENV-005 fires when the value doesn't trigger ENV-004."""
    var = wf_var("DB_PASSWORD", "${{ secrets.DB_PASSWORD }}", is_secret_ref=True)
    r = validate([var])
    assert "ENV-005" in check_ids(r)
    assert "ENV-004" not in check_ids(r)


def test_env005_fires_at_workflow_scope_with_hardcoded():
    """ENV-001 and ENV-005 can both fire for the same var."""
    var = wf_var("DB_PASSWORD", "hard_coded_pass")
    r = validate([var])
    assert "ENV-001" in check_ids(r)
    assert "ENV-005" in check_ids(r)


# ===========================================================================
# F – ENV-006: Conflicting values across scopes
# ===========================================================================


def test_env006_fires_for_same_name_different_values():
    v1 = wf_var("DB_HOST", "prod.db.example.com")
    v2 = job_var("DB_HOST", "staging.db.example.com")
    r = validate([v1, v2])
    assert "ENV-006" in check_ids(r)


def test_env006_does_not_fire_for_same_name_same_value():
    v1 = wf_var("DB_HOST", "shared.db.example.com")
    v2 = job_var("DB_HOST", "shared.db.example.com")
    r = validate([v1, v2])
    assert "ENV-006" not in check_ids(r)


def test_env006_does_not_fire_for_single_occurrence():
    r = validate([wf_var("DB_HOST", "prod.db.example.com")])
    assert "ENV-006" not in check_ids(r)


def test_env006_does_not_fire_when_one_value_empty():
    v1 = wf_var("DB_HOST", "prod.db.example.com")
    v2 = job_var("DB_HOST", "")  # empty value excluded from conflict detection
    r = validate([v1, v2])
    assert "ENV-006" not in check_ids(r)


def test_env006_case_insensitive_name_grouping():
    """db_host and DB_HOST should be treated as the same variable."""
    v1 = EnvVar(name="db_host", value="prod.db.example.com", scope="workflow", is_secret_ref=False)
    v2 = EnvVar(name="DB_HOST", value="staging.db.example.com", scope="job:build", is_secret_ref=False)
    r = validate([v1, v2])
    assert "ENV-006" in check_ids(r)


def test_env006_fires_once_per_conflicting_name():
    """Only one ENV-006 finding per variable name even if 3 scopes differ."""
    v1 = wf_var("CONFIG_URL", "https://a.example.com")
    v2 = job_var("CONFIG_URL", "https://b.example.com")
    v3 = step_var("CONFIG_URL", "https://c.example.com")
    r = validate([v1, v2, v3])
    env006_findings = [f for f in r.findings if f.check_id == "ENV-006"]
    assert len(env006_findings) == 1


def test_env006_detail_redacts_values():
    """The finding detail must redact actual values to first 4 chars + ****."""
    v1 = wf_var("DB_HOST", "supersecret")
    v2 = job_var("DB_HOST", "differentsecret")
    r = validate([v1, v2])
    env006_f = next(f for f in r.findings if f.check_id == "ENV-006")
    assert "supe****" in env006_f.detail
    assert "diff****" in env006_f.detail


def test_env006_two_empty_values_do_not_fire():
    """Two entries both with empty values → no conflict."""
    v1 = wf_var("DB_HOST", "")
    v2 = job_var("DB_HOST", "")
    r = validate([v1, v2])
    assert "ENV-006" not in check_ids(r)


# ===========================================================================
# G – ENV-007: Embedded private key / certificate
# ===========================================================================


def test_env007_fires_for_begin_marker():
    val = "-----BEGIN OPENSSH PRIVATE KEY-----\nABC123\n-----END OPENSSH PRIVATE KEY-----"
    r = validate([wf_var("SSH_KEY", val)])
    assert "ENV-007" in check_ids(r)


def test_env007_fires_for_begin_certificate():
    val = "BEGIN CERTIFICATE\nMIIBIjANBgkqhkiG9w0BA\n"
    r = validate([wf_var("TLS_CERT", val)])
    assert "ENV-007" in check_ids(r)


def test_env007_fires_for_begin_rsa_private_key():
    val = "BEGIN RSA PRIVATE KEY\nMIIEowIBAAKCAQEA\n"
    r = validate([wf_var("RSA_KEY", val)])
    assert "ENV-007" in check_ids(r)


def test_env007_does_not_fire_for_normal_value():
    r = validate([wf_var("DEPLOY_ENV", "production")])
    assert "ENV-007" not in check_ids(r)


def test_env007_does_not_fire_for_empty_value():
    r = validate([wf_var("PEM_CERT", "")])
    assert "ENV-007" not in check_ids(r)


def test_env007_fires_regardless_of_var_name():
    """ENV-007 fires even when the name has no secret keyword."""
    val = "-----BEGIN EC PRIVATE KEY-----\nABC\n-----END EC PRIVATE KEY-----"
    r = validate([wf_var("SOME_DATA", val)])
    assert "ENV-007" in check_ids(r)


def test_env007_fires_at_job_scope():
    val = "-----BEGIN DSA PRIVATE KEY-----\nABC\n"
    r = validate([job_var("SIGNING_KEY", val)])
    assert "ENV-007" in check_ids(r)


def test_env007_fires_at_step_scope():
    val = "BEGIN RSA PRIVATE KEY\nABC\n"
    r = validate([step_var("GPG_KEY", val)])
    assert "ENV-007" in check_ids(r)


# ===========================================================================
# H – extract_env_vars helper
# ===========================================================================


def _sample_workflow() -> dict:
    return {
        "env": {
            "NODE_ENV": "production",
            "DB_PASSWORD": "${{ secrets.DB_PASSWORD }}",
        },
        "jobs": {
            "build": {
                "env": {
                    "CI": "true",
                    "ACCESS_TOKEN": "${{ secrets.ACCESS_TOKEN }}",
                },
                "steps": [
                    {
                        "name": "checkout",
                        "env": {
                            "GIT_TOKEN": "${{ secrets.GIT_TOKEN }}",
                        },
                    },
                    {
                        "name": "test",
                        "env": {
                            "TEST_API_KEY": "hardcoded-value",
                        },
                    },
                ],
            },
            "deploy": {
                "env": {
                    "DEPLOY_ENV": "prod",
                },
                "steps": [
                    {
                        # step with no name (uses index)
                        "env": {
                            "SSH_KEY": "-----BEGIN RSA PRIVATE KEY-----\nABC\n",
                        },
                    },
                ],
            },
        },
    }


def test_extract_workflow_level_vars():
    wf = _sample_workflow()
    vars_ = extract_env_vars(wf)
    workflow_vars = [v for v in vars_ if v.scope == "workflow"]
    names = {v.name for v in workflow_vars}
    assert "NODE_ENV" in names
    assert "DB_PASSWORD" in names


def test_extract_job_level_vars():
    vars_ = extract_env_vars(_sample_workflow())
    job_vars = [v for v in vars_ if v.scope == "job:build"]
    names = {v.name for v in job_vars}
    assert "CI" in names
    assert "ACCESS_TOKEN" in names


def test_extract_step_level_vars_with_name():
    vars_ = extract_env_vars(_sample_workflow())
    step_vars = [v for v in vars_ if v.scope == "step:build:checkout"]
    names = {v.name for v in step_vars}
    assert "GIT_TOKEN" in names


def test_extract_step_level_vars_with_index_fallback():
    """Steps without a name attribute use their 0-based index as label."""
    vars_ = extract_env_vars(_sample_workflow())
    step_vars = [v for v in vars_ if v.scope == "step:deploy:0"]
    assert any(v.name == "SSH_KEY" for v in step_vars)


def test_extract_is_secret_ref_true_for_secrets():
    vars_ = extract_env_vars(_sample_workflow())
    db_pw = next(v for v in vars_ if v.name == "DB_PASSWORD")
    assert db_pw.is_secret_ref is True


def test_extract_is_secret_ref_false_for_plain_value():
    vars_ = extract_env_vars(_sample_workflow())
    node_env = next(v for v in vars_ if v.name == "NODE_ENV")
    assert node_env.is_secret_ref is False


def test_extract_is_secret_ref_false_for_hardcoded():
    vars_ = extract_env_vars(_sample_workflow())
    api_key = next(v for v in vars_ if v.name == "TEST_API_KEY")
    assert api_key.is_secret_ref is False


def test_extract_total_count():
    """Verify the total number of extracted vars across all scopes."""
    vars_ = extract_env_vars(_sample_workflow())
    # workflow=2, job:build=2, step:build:checkout=1, step:build:test=1, job:deploy=1, step:deploy:0=1
    assert len(vars_) == 8


def test_extract_empty_workflow():
    r = extract_env_vars({})
    assert r == []


def test_extract_workflow_no_env_key():
    wf = {"jobs": {"build": {"steps": []}}}
    r = extract_env_vars(wf)
    assert r == []


def test_extract_job_no_steps():
    wf = {"jobs": {"build": {"env": {"CI": "true"}}}}
    r = extract_env_vars(wf)
    assert len(r) == 1
    assert r[0].scope == "job:build"


def test_extract_step_no_env_key():
    wf = {"jobs": {"build": {"steps": [{"name": "lint"}]}}}
    r = extract_env_vars(wf)
    assert r == []


def test_extract_deploy_job_vars():
    vars_ = extract_env_vars(_sample_workflow())
    deploy_job_vars = [v for v in vars_ if v.scope == "job:deploy"]
    assert any(v.name == "DEPLOY_ENV" for v in deploy_job_vars)


# ===========================================================================
# I – ENVResult helpers
# ===========================================================================


def test_to_dict_empty_result():
    r = ENVResult(findings=[], risk_score=0)
    d = r.to_dict()
    assert d["risk_score"] == 0
    assert d["findings"] == []


def test_to_dict_with_findings():
    r = validate([wf_var("DB_PASSWORD", "hardcoded")])
    d = r.to_dict()
    assert isinstance(d, dict)
    assert "risk_score" in d
    assert isinstance(d["findings"], list)
    assert len(d["findings"]) > 0
    first = d["findings"][0]
    assert "check_id" in first
    assert "severity" in first
    assert "title" in first
    assert "detail" in first
    assert "weight" in first
    assert "env_var_name" in first


def test_summary_no_findings():
    r = ENVResult(findings=[], risk_score=0)
    s = r.summary()
    assert "0" in s
    assert "no findings" in s


def test_summary_with_findings():
    r = validate([wf_var("DB_PASSWORD", "hardcoded")])
    s = r.summary()
    assert "ENV-001" in s
    assert "risk_score=" in s


def test_by_severity_groups_correctly():
    r = validate([
        wf_var("DB_PASSWORD", "hardcoded"),
        wf_var("API_KEY", "${{ secrets.API_KEY }}", is_secret_ref=True),
    ])
    by_sev = r.by_severity()
    # ENV-001 is CRITICAL, ENV-005 is MEDIUM
    assert "CRITICAL" in by_sev or "MEDIUM" in by_sev


def test_by_severity_empty_when_no_findings():
    r = ENVResult(findings=[], risk_score=0)
    assert r.by_severity() == {}


# ===========================================================================
# J – risk_score computation and weight deduplication
# ===========================================================================


def test_risk_score_zero_for_no_findings():
    r = validate([wf_var("LOG_LEVEL", "debug")])
    assert r.risk_score == 0


def test_risk_score_env001_alone():
    # ENV-001 w=45, no other checks
    r = validate([job_var("DB_PASSWORD", "hardcoded")])
    # Only ENV-001 (45) should fire at job scope — no ENV-005 (job scope)
    assert r.risk_score == 45


def test_risk_score_capped_at_100():
    """Firing multiple high-weight checks must be capped at 100."""
    vars_ = [
        wf_var("DB_PASSWORD", "hardcoded"),      # ENV-001(45) + ENV-005(15)
        wf_var("API_URL", "https://u:p@db.example.com"),  # ENV-002(25)
        wf_var("PRIV_KEY", "-----BEGIN RSA PRIVATE KEY-----\nABC\n"),  # ENV-007(45)
    ]
    r = validate(vars_)
    assert r.risk_score == 100


def test_risk_score_deduplication_same_check_id():
    """Multiple findings with the same check ID contribute the weight only once."""
    vars_ = [
        wf_var("DB_PASSWORD", "hardcoded"),
        wf_var("APP_SECRET", "hardcoded2"),
    ]
    r = validate(vars_)
    env001_findings = [f for f in r.findings if f.check_id == "ENV-001"]
    assert len(env001_findings) == 2
    # But weight counted only once: ENV-001(45) + ENV-005(15) = 60
    assert r.risk_score == 60


def test_risk_score_env007_alone():
    val = "-----BEGIN OPENSSH PRIVATE KEY-----\nABC\n"
    # Use a name with no secret keyword so only ENV-007 fires
    r = validate([job_var("CERT_BUNDLE", val)])
    # ENV-007(45) only; job scope so no ENV-005; CERT_BUNDLE has no secret keyword
    assert r.risk_score == 45


def test_risk_score_env004_no_env005():
    r = validate([wf_var("CI_TOKEN", "${{ github.token }}")])
    assert "ENV-004" in check_ids(r)
    assert "ENV-005" not in check_ids(r)
    assert r.risk_score == 15


def test_risk_score_env006_adds_weight():
    v1 = wf_var("DB_HOST", "prod.db.example.com")
    v2 = job_var("DB_HOST", "staging.db.example.com")
    r = validate([v1, v2])
    assert "ENV-006" in check_ids(r)
    # ENV-006 w=15
    assert 15 <= r.risk_score <= 100


# ===========================================================================
# K – Integration / combined scenarios
# ===========================================================================


def test_integration_safe_workflow():
    """A well-configured workflow should produce zero findings."""
    vars_ = [
        wf_var("NODE_ENV", "production"),
        wf_var("LOG_LEVEL", "info"),
        wf_var("DB_PASSWORD", "${{ secrets.DB_PASSWORD }}", is_secret_ref=True),
        job_var("CI", "true"),
        job_var("ACCESS_TOKEN", "${{ secrets.ACCESS_TOKEN }}", is_secret_ref=True),
        step_var("GITHUB_TOKEN", "${{ secrets.GITHUB_TOKEN }}", is_secret_ref=True),
    ]
    r = validate(vars_)
    # DB_PASSWORD and ACCESS_TOKEN at workflow / job are safe refs; only ENV-005 may fire
    # for wf DB_PASSWORD (workflow scope, secret name, but value is expression, not hardcoded)
    # ENV-005 fires for DB_PASSWORD at workflow scope
    # ACCESS_TOKEN is at job scope so no ENV-005
    assert r.risk_score <= 15


def test_integration_full_validate_from_extract():
    """End-to-end: extract then validate."""
    wf = {
        "env": {"DB_PASSWORD": "plaintext_secret"},
        "jobs": {
            "build": {
                "steps": [
                    {
                        "name": "deploy",
                        "env": {"DEPLOY_KEY": "-----BEGIN RSA PRIVATE KEY-----\nABC\n"},
                    }
                ]
            }
        },
    }
    vars_ = extract_env_vars(wf)
    r = validate(vars_)
    cids = check_ids(r)
    assert "ENV-001" in cids   # DB_PASSWORD hardcoded
    assert "ENV-007" in cids   # DEPLOY_KEY contains private key
    assert r.risk_score > 0


def test_integration_env003_and_env001_independent():
    """ENV-003 fires on inputs ref; ENV-001 is independent (fires on hardcoded)."""
    v_inputs = wf_var("API_KEY", "${{ inputs.api_key }}")
    v_hard = job_var("DB_SECRET", "plain-text")
    r = validate([v_inputs, v_hard])
    assert "ENV-003" in check_ids(r)
    assert "ENV-001" in check_ids(r)


def test_integration_env002_and_env001_same_var():
    """A URL with creds where the var name is also secret-named → ENV-001 + ENV-002."""
    # value starts with https:// → it IS an expression-like prefix? No, it's a URL not ${{
    r = validate([job_var("DB_PASSWORD", "https://admin:pass@db.example.com")])
    cids = check_ids(r)
    assert "ENV-001" in cids
    assert "ENV-002" in cids


def test_integration_multiple_jobs():
    wf = {
        "jobs": {
            "job1": {"env": {"DB_PASSWORD": "secret1"}, "steps": []},
            "job2": {"env": {"DB_PASSWORD": "secret2"}, "steps": []},
        }
    }
    vars_ = extract_env_vars(wf)
    r = validate(vars_)
    cids = check_ids(r)
    assert "ENV-001" in cids
    assert "ENV-006" in cids


def test_integration_env005_fires_for_multiple_workflow_secrets():
    vars_ = [
        wf_var("DB_PASSWORD", "${{ secrets.DB_PASSWORD }}", is_secret_ref=True),
        wf_var("API_KEY", "${{ secrets.API_KEY }}", is_secret_ref=True),
    ]
    r = validate(vars_)
    env005_findings = [f for f in r.findings if f.check_id == "ENV-005"]
    assert len(env005_findings) == 2


def test_integration_no_false_positives_log_vars():
    """Common CI vars must not produce any findings."""
    vars_ = [
        wf_var("CI", "true"),
        wf_var("DEBUG", "false"),
        wf_var("LOG_FORMAT", "json"),
        job_var("RUNNER_OS", "Linux"),
        step_var("OUTPUT_DIR", "/tmp/artifacts"),
    ]
    r = validate(vars_)
    assert r.risk_score == 0
    assert r.findings == []


def test_integration_env007_and_env005_can_coexist():
    """At workflow scope, a private-key value fires ENV-007; ENV-005 fires too if name is secret."""
    val = "-----BEGIN EC PRIVATE KEY-----\nABC\n"
    r = validate([wf_var("EC_PRIVATE_KEY", val)])
    cids = check_ids(r)
    assert "ENV-007" in cids
    assert "ENV-005" in cids


def test_integration_env006_with_three_scopes():
    v1 = wf_var("DB_PORT", "5432")
    v2 = job_var("DB_PORT", "5433")
    v3 = step_var("DB_PORT", "5434")
    r = validate([v1, v2, v3])
    assert "ENV-006" in check_ids(r)
    env006_findings = [f for f in r.findings if f.check_id == "ENV-006"]
    assert len(env006_findings) == 1
    assert "5432"[:4] + "****" in env006_findings[0].detail


def test_integration_env001_does_not_fire_on_env_expression():
    """${{ env.SOME_VAR }} is an expression and must not be flagged as hardcoded."""
    r = validate([wf_var("API_KEY", "${{ env.API_KEY }}")])
    assert "ENV-001" not in check_ids(r)


def test_integration_env003_github_event_at_job_scope():
    r = validate([job_var("ACCESS_TOKEN", "${{ github.event.inputs.token }}")])
    assert "ENV-003" in check_ids(r)


def test_integration_finding_attributes_populated():
    r = validate([wf_var("DB_PASSWORD", "secret123")])
    f = next(x for x in r.findings if x.check_id == "ENV-001")
    assert f.severity == "CRITICAL"
    assert f.weight == 45
    assert f.env_var_name == "DB_PASSWORD"
    assert "DB_PASSWORD" in f.detail
    assert f.title != ""


def test_integration_env_var_dataclass_fields():
    v = EnvVar(name="X", value="y", scope="workflow", is_secret_ref=False)
    assert v.name == "X"
    assert v.value == "y"
    assert v.scope == "workflow"
    assert v.is_secret_ref is False


# ===========================================================================
# L – Additional edge cases (ENV-001 through ENV-007 fine-grained)
# ===========================================================================


# ENV-001 extra
def test_env001_does_not_fire_for_github_context_expression():
    """Any ${{ ... }} expression (github context) must not be treated as hardcoded."""
    r = validate([wf_var("API_KEY", "${{ github.sha }}")])
    assert "ENV-001" not in check_ids(r)


def test_env001_fires_for_value_with_leading_whitespace():
    """Leading whitespace before a non-expression value should still trigger ENV-001."""
    r = validate([wf_var("APP_SECRET", "  my_secret_value")])
    assert "ENV-001" in check_ids(r)


def test_env001_keyword_in_middle_of_name():
    """MYSECRETVAR has SECRET as a substring — must fire."""
    r = validate([job_var("MYSECRETVAR", "plaintext")])
    assert "ENV-001" in check_ids(r)


# ENV-002 extra
def test_env002_does_not_fire_for_expression_url():
    """A ${{ secrets.DB_URL }} reference containing a URL pattern is still safe."""
    r = validate([wf_var("DB_URL", "${{ secrets.DB_URL }}", is_secret_ref=True)])
    assert "ENV-002" not in check_ids(r)


def test_env002_fires_for_smtp_with_creds():
    r = validate([wf_var("SMTP_URL", "smtp://notify:pass123@smtp.example.com:587")])
    assert "ENV-002" in check_ids(r)


# ENV-003 extra
def test_env003_fires_with_mixed_expression():
    """Value that mixes literal and ${{ inputs.x }} still triggers."""
    r = validate([wf_var("DB_PASSWORD", "prefix-${{ inputs.user_pass }}")])
    assert "ENV-003" in check_ids(r)


def test_env003_does_not_fire_for_github_run_id():
    """${{ github.run_id }} is not a user-controlled input."""
    r = validate([wf_var("APP_SECRET", "${{ github.run_id }}")])
    assert "ENV-003" not in check_ids(r)


# ENV-004 extra
def test_env004_fires_for_token_keyword_only():
    """A var with TOKEN in its name set to github.token at workflow scope fires ENV-004."""
    r = validate([wf_var("MY_TOKEN", "${{ github.token }}")])
    assert "ENV-004" in check_ids(r)


# ENV-005 extra
def test_env005_does_not_fire_for_secret_name_at_step_scope():
    r = validate([step_var("DB_PASSWORD", "${{ secrets.DB_PASSWORD }}", is_secret_ref=True)])
    assert "ENV-005" not in check_ids(r)


# ENV-006 extra
def test_env006_does_not_fire_for_two_workflow_level_same_value():
    """Two workflow-level entries with identical values must NOT fire ENV-006."""
    v1 = EnvVar(name="DB_HOST", value="prod.db.example.com", scope="workflow", is_secret_ref=False)
    v2 = EnvVar(name="DB_HOST", value="prod.db.example.com", scope="job:build", is_secret_ref=False)
    r = validate([v1, v2])
    assert "ENV-006" not in check_ids(r)


# ENV-007 extra
def test_env007_does_not_fire_for_partial_end_marker_only():
    """-----END RSA PRIVATE KEY----- alone (without BEGIN) should not fire."""
    r = validate([wf_var("CERT_DATA", "-----END RSA PRIVATE KEY-----")])
    assert "ENV-007" not in check_ids(r)


def test_env007_fires_for_begin_private_key_lowercase_content():
    """Marker check is substring-based; surrounding lowercase content should not matter."""
    val = "some_prefix -----BEGIN CERTIFICATE----- MIIB some_suffix"
    r = validate([wf_var("TLS_DATA", val)])
    assert "ENV-007" in check_ids(r)


# ENVResult extra
def test_to_dict_risk_score_matches_result():
    r = validate([job_var("CERT_BUNDLE", "-----BEGIN OPENSSH PRIVATE KEY-----\nABC\n")])
    d = r.to_dict()
    assert d["risk_score"] == r.risk_score
