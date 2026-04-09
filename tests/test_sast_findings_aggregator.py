# Tests for sast_findings_aggregator.py — Cyber Port Portfolio
# Copyright 2024 hiagokinlevi. Licensed under CC BY 4.0.
# https://creativecommons.org/licenses/by/4.0/
#
# Run with:  python -m pytest tests/test_sast_findings_aggregator.py -q

import sys
import os

# Allow imports from the project root without installing the package.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shared.analyzers.sast_findings_aggregator import (
    SASTFinding,
    SASTAggFinding,
    SASTAggResult,
    aggregate,
    aggregate_many,
    _CHECK_WEIGHTS,
    _is_sensitive_path,
)


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def make_finding(
    finding_id: str = "f1",
    tool: str = "semgrep",
    rule_id: str = "RULE-001",
    file_path: str = "src/main.py",
    line_number: int = 10,
    severity: str = "MEDIUM",
    title: str = "Test finding",
    cwe: str = "CWE-89",
    age_days: int = 5,
    suppressed: bool = False,
    expiry_date: str = None,
) -> SASTFinding:
    """Factory with sensible defaults that satisfy no checks."""
    return SASTFinding(
        finding_id=finding_id,
        tool=tool,
        rule_id=rule_id,
        file_path=file_path,
        line_number=line_number,
        severity=severity,
        title=title,
        cwe=cwe,
        age_days=age_days,
        suppressed=suppressed,
        expiry_date=expiry_date,
    )


# ===========================================================================
# EMPTY / BASELINE TESTS
# ===========================================================================

def test_empty_findings_no_meta_issues():
    result = aggregate([])
    assert result.total_input_findings == 0
    assert result.critical_count == 0
    assert result.high_count == 0
    assert result.findings == []
    assert result.risk_score == 0
    assert result.pipeline_fail is False


def test_empty_findings_summary_contains_pass():
    result = aggregate([])
    assert "PASS" in result.summary()


def test_empty_findings_to_dict_structure():
    result = aggregate([])
    d = result.to_dict()
    assert d["total_input_findings"] == 0
    assert d["findings"] == []
    assert d["pipeline_fail"] is False


def test_single_clean_finding_no_meta_issues():
    f = make_finding()
    result = aggregate([f])
    assert result.total_input_findings == 1
    assert result.findings == []
    assert result.risk_score == 0


def test_by_severity_empty():
    result = aggregate([])
    assert result.by_severity() == {}


# ===========================================================================
# SAST-001 — Finding has no CWE mapping
# ===========================================================================

def test_sast001_none_cwe_fires():
    f = make_finding(finding_id="f1", cwe=None)
    result = aggregate([f])
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-001" in check_ids


def test_sast001_empty_string_cwe_fires():
    f = make_finding(finding_id="f1", cwe="")
    result = aggregate([f])
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-001" in check_ids


def test_sast001_whitespace_only_cwe_fires():
    f = make_finding(finding_id="f1", cwe="   ")
    result = aggregate([f])
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-001" in check_ids


def test_sast001_valid_cwe_does_not_fire():
    f = make_finding(finding_id="f1", cwe="CWE-89")
    result = aggregate([f])
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-001" not in check_ids


def test_sast001_emits_one_per_missing_cwe():
    findings = [
        make_finding(finding_id="f1", cwe=None),
        make_finding(finding_id="f2", cwe=None),
        make_finding(finding_id="f3", cwe="CWE-79"),
    ]
    result = aggregate(findings)
    sast001 = [af for af in result.findings if af.check_id == "SAST-001"]
    assert len(sast001) == 2


def test_sast001_affected_finding_id_correct():
    f = make_finding(finding_id="f-no-cwe", cwe=None)
    result = aggregate([f])
    sast001 = [af for af in result.findings if af.check_id == "SAST-001"]
    assert sast001[0].affected_finding_ids == ["f-no-cwe"]


def test_sast001_severity_is_medium():
    f = make_finding(cwe=None)
    result = aggregate([f])
    sast001 = [af for af in result.findings if af.check_id == "SAST-001"]
    assert sast001[0].severity == "MEDIUM"


def test_sast001_weight():
    f = make_finding(cwe=None)
    result = aggregate([f])
    sast001 = [af for af in result.findings if af.check_id == "SAST-001"]
    assert sast001[0].weight == 15


def test_sast001_risk_score_contribution_unique():
    # Even with 3 findings triggering SAST-001, the weight is counted once.
    findings = [make_finding(finding_id=f"f{i}", cwe=None) for i in range(3)]
    result = aggregate(findings)
    assert result.risk_score == _CHECK_WEIGHTS["SAST-001"]


# ===========================================================================
# SAST-002 — Critical/High open more than 30 days
# ===========================================================================

def test_sast002_critical_over_30_days_fires():
    f = make_finding(finding_id="f1", severity="CRITICAL", age_days=31)
    result = aggregate([f])
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-002" in check_ids


def test_sast002_high_over_30_days_fires():
    f = make_finding(finding_id="f1", severity="HIGH", age_days=31)
    result = aggregate([f])
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-002" in check_ids


def test_sast002_exactly_30_days_does_not_fire():
    f = make_finding(finding_id="f1", severity="CRITICAL", age_days=30)
    result = aggregate([f])
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-002" not in check_ids


def test_sast002_medium_over_30_days_does_not_fire():
    f = make_finding(finding_id="f1", severity="MEDIUM", age_days=31)
    result = aggregate([f])
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-002" not in check_ids


def test_sast002_low_over_30_days_does_not_fire():
    f = make_finding(finding_id="f1", severity="LOW", age_days=60)
    result = aggregate([f])
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-002" not in check_ids


def test_sast002_emits_one_per_stale_finding():
    findings = [
        make_finding(finding_id="f1", severity="CRITICAL", age_days=31),
        make_finding(finding_id="f2", severity="HIGH", age_days=90),
        make_finding(finding_id="f3", severity="MEDIUM", age_days=100),
    ]
    result = aggregate(findings)
    sast002 = [af for af in result.findings if af.check_id == "SAST-002"]
    assert len(sast002) == 2


def test_sast002_severity_is_critical():
    f = make_finding(severity="HIGH", age_days=31)
    result = aggregate([f])
    sast002 = [af for af in result.findings if af.check_id == "SAST-002"]
    assert sast002[0].severity == "CRITICAL"


def test_sast002_weight():
    f = make_finding(severity="CRITICAL", age_days=31)
    result = aggregate([f])
    sast002 = [af for af in result.findings if af.check_id == "SAST-002"]
    assert sast002[0].weight == 45


def test_sast002_affected_finding_id():
    f = make_finding(finding_id="stale-crit", severity="CRITICAL", age_days=31)
    result = aggregate([f])
    sast002 = [af for af in result.findings if af.check_id == "SAST-002"]
    assert sast002[0].affected_finding_ids == ["stale-crit"]


def test_sast002_risk_score_contribution_unique():
    # Use distinct CWEs so SAST-003 (severity disagreement) cannot fire.
    findings = [
        make_finding(finding_id="f1", severity="CRITICAL", age_days=31, cwe="CWE-A"),
        make_finding(finding_id="f2", severity="HIGH",     age_days=50, cwe="CWE-B"),
    ]
    result = aggregate(findings)
    # Only SAST-002 fires; weight counted once even though two findings trigger it.
    assert result.risk_score == _CHECK_WEIGHTS["SAST-002"]


def test_sast002_29_days_does_not_fire():
    f = make_finding(severity="CRITICAL", age_days=29)
    result = aggregate([f])
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-002" not in check_ids


# ===========================================================================
# SAST-003 — Same CWE with different severities across tools
# ===========================================================================

def test_sast003_different_severities_same_cwe_fires():
    findings = [
        make_finding(finding_id="f1", tool="semgrep", cwe="CWE-89", severity="HIGH"),
        make_finding(finding_id="f2", tool="bandit",  cwe="CWE-89", severity="MEDIUM"),
    ]
    result = aggregate(findings)
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-003" in check_ids


def test_sast003_same_severity_same_cwe_does_not_fire():
    findings = [
        make_finding(finding_id="f1", tool="semgrep", cwe="CWE-89", severity="HIGH"),
        make_finding(finding_id="f2", tool="bandit",  cwe="CWE-89", severity="HIGH"),
    ]
    result = aggregate(findings)
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-003" not in check_ids


def test_sast003_none_cwe_is_skipped():
    findings = [
        make_finding(finding_id="f1", tool="semgrep", cwe=None, severity="HIGH"),
        make_finding(finding_id="f2", tool="bandit",  cwe=None, severity="MEDIUM"),
    ]
    result = aggregate(findings)
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-003" not in check_ids


def test_sast003_emits_one_per_conflicting_cwe():
    findings = [
        make_finding(finding_id="f1", tool="semgrep", cwe="CWE-89", severity="HIGH"),
        make_finding(finding_id="f2", tool="bandit",  cwe="CWE-89", severity="LOW"),
        make_finding(finding_id="f3", tool="semgrep", cwe="CWE-79", severity="CRITICAL"),
        make_finding(finding_id="f4", tool="codeql",  cwe="CWE-79", severity="MEDIUM"),
    ]
    result = aggregate(findings)
    sast003 = [af for af in result.findings if af.check_id == "SAST-003"]
    assert len(sast003) == 2


def test_sast003_affected_finding_ids_includes_all_for_cwe():
    findings = [
        make_finding(finding_id="f1", tool="semgrep", cwe="CWE-22", severity="HIGH"),
        make_finding(finding_id="f2", tool="bandit",  cwe="CWE-22", severity="MEDIUM"),
    ]
    result = aggregate(findings)
    sast003 = [af for af in result.findings if af.check_id == "SAST-003"]
    assert set(sast003[0].affected_finding_ids) == {"f1", "f2"}


def test_sast003_severity_is_high():
    findings = [
        make_finding(finding_id="f1", tool="a", cwe="CWE-1", severity="HIGH"),
        make_finding(finding_id="f2", tool="b", cwe="CWE-1", severity="LOW"),
    ]
    result = aggregate(findings)
    sast003 = [af for af in result.findings if af.check_id == "SAST-003"]
    assert sast003[0].severity == "HIGH"


def test_sast003_weight():
    findings = [
        make_finding(finding_id="f1", tool="a", cwe="CWE-1", severity="HIGH"),
        make_finding(finding_id="f2", tool="b", cwe="CWE-1", severity="LOW"),
    ]
    result = aggregate(findings)
    sast003 = [af for af in result.findings if af.check_id == "SAST-003"]
    assert sast003[0].weight == 20


def test_sast003_single_tool_multiple_severities_fires():
    # Same CWE, same tool but different severities — SAST-003 is about CWE
    # severity sets, not tool counts, so this should still fire.
    findings = [
        make_finding(finding_id="f1", tool="semgrep", cwe="CWE-89", severity="HIGH",
                     rule_id="R1", file_path="a.py", line_number=1),
        make_finding(finding_id="f2", tool="semgrep", cwe="CWE-89", severity="LOW",
                     rule_id="R2", file_path="b.py", line_number=2),
    ]
    result = aggregate(findings)
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-003" in check_ids


def test_sast003_three_tools_same_severity_does_not_fire():
    findings = [
        make_finding(finding_id=f"f{i}", tool=f"tool{i}", cwe="CWE-78",
                     severity="HIGH")
        for i in range(3)
    ]
    result = aggregate(findings)
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-003" not in check_ids


# ===========================================================================
# SAST-004 — Suppressed finding with no expiry_date
# ===========================================================================

def test_sast004_suppressed_no_expiry_fires():
    f = make_finding(suppressed=True, expiry_date=None)
    result = aggregate([f])
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-004" in check_ids


def test_sast004_suppressed_with_expiry_does_not_fire():
    f = make_finding(suppressed=True, expiry_date="2025-12-31")
    result = aggregate([f])
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-004" not in check_ids


def test_sast004_not_suppressed_no_expiry_does_not_fire():
    f = make_finding(suppressed=False, expiry_date=None)
    result = aggregate([f])
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-004" not in check_ids


def test_sast004_emits_one_per_suppressed_finding():
    findings = [
        make_finding(finding_id="f1", suppressed=True, expiry_date=None),
        make_finding(finding_id="f2", suppressed=True, expiry_date=None),
        make_finding(finding_id="f3", suppressed=True, expiry_date="2025-01-01"),
        make_finding(finding_id="f4", suppressed=False, expiry_date=None),
    ]
    result = aggregate(findings)
    sast004 = [af for af in result.findings if af.check_id == "SAST-004"]
    assert len(sast004) == 2


def test_sast004_severity_is_high():
    f = make_finding(suppressed=True, expiry_date=None)
    result = aggregate([f])
    sast004 = [af for af in result.findings if af.check_id == "SAST-004"]
    assert sast004[0].severity == "HIGH"


def test_sast004_weight():
    f = make_finding(suppressed=True, expiry_date=None)
    result = aggregate([f])
    sast004 = [af for af in result.findings if af.check_id == "SAST-004"]
    assert sast004[0].weight == 20


def test_sast004_affected_finding_id():
    f = make_finding(finding_id="sup-f1", suppressed=True, expiry_date=None)
    result = aggregate([f])
    sast004 = [af for af in result.findings if af.check_id == "SAST-004"]
    assert sast004[0].affected_finding_ids == ["sup-f1"]


def test_sast004_risk_score_unique():
    findings = [make_finding(finding_id=f"f{i}", suppressed=True, expiry_date=None)
                for i in range(5)]
    result = aggregate(findings)
    assert result.risk_score == _CHECK_WEIGHTS["SAST-004"]


# ===========================================================================
# SAST-005 — Total CRITICAL/HIGH count exceeds threshold
# ===========================================================================

def test_sast005_count_equals_threshold_does_not_fire():
    findings = [
        make_finding(finding_id=f"f{i}", severity="HIGH")
        for i in range(10)
    ]
    result = aggregate(findings, critical_high_threshold=10)
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-005" not in check_ids


def test_sast005_count_exceeds_threshold_fires():
    findings = [
        make_finding(finding_id=f"f{i}", severity="HIGH")
        for i in range(11)
    ]
    result = aggregate(findings, critical_high_threshold=10)
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-005" in check_ids


def test_sast005_count_below_threshold_does_not_fire():
    findings = [
        make_finding(finding_id=f"f{i}", severity="CRITICAL")
        for i in range(9)
    ]
    result = aggregate(findings, critical_high_threshold=10)
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-005" not in check_ids


def test_sast005_mixed_critical_high_combined():
    findings = (
        [make_finding(finding_id=f"c{i}", severity="CRITICAL") for i in range(6)]
        + [make_finding(finding_id=f"h{i}", severity="HIGH") for i in range(5)]
    )
    result = aggregate(findings, critical_high_threshold=10)
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-005" in check_ids


def test_sast005_medium_not_counted():
    findings = [
        make_finding(finding_id=f"m{i}", severity="MEDIUM")
        for i in range(100)
    ]
    result = aggregate(findings, critical_high_threshold=10)
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-005" not in check_ids


def test_sast005_emits_exactly_one():
    findings = [
        make_finding(finding_id=f"f{i}", severity="CRITICAL")
        for i in range(20)
    ]
    result = aggregate(findings, critical_high_threshold=10)
    sast005 = [af for af in result.findings if af.check_id == "SAST-005"]
    assert len(sast005) == 1


def test_sast005_detail_contains_count_and_threshold():
    findings = [
        make_finding(finding_id=f"f{i}", severity="HIGH")
        for i in range(12)
    ]
    result = aggregate(findings, critical_high_threshold=10)
    sast005 = [af for af in result.findings if af.check_id == "SAST-005"]
    assert "12" in sast005[0].detail
    assert "10" in sast005[0].detail


def test_sast005_affected_finding_ids_all_critical_high():
    findings = [
        make_finding(finding_id="c1", severity="CRITICAL"),
        make_finding(finding_id="h1", severity="HIGH"),
        make_finding(finding_id="m1", severity="MEDIUM"),
    ]
    result = aggregate(findings, critical_high_threshold=1)
    sast005 = [af for af in result.findings if af.check_id == "SAST-005"]
    assert set(sast005[0].affected_finding_ids) == {"c1", "h1"}


def test_sast005_severity_is_high():
    findings = [make_finding(finding_id=f"f{i}", severity="HIGH") for i in range(11)]
    result = aggregate(findings, critical_high_threshold=10)
    sast005 = [af for af in result.findings if af.check_id == "SAST-005"]
    assert sast005[0].severity == "HIGH"


def test_sast005_weight():
    findings = [make_finding(finding_id=f"f{i}", severity="HIGH") for i in range(11)]
    result = aggregate(findings, critical_high_threshold=10)
    sast005 = [af for af in result.findings if af.check_id == "SAST-005"]
    assert sast005[0].weight == 25


def test_sast005_custom_threshold_zero_fires_with_any_critical():
    f = make_finding(severity="CRITICAL")
    result = aggregate([f], critical_high_threshold=0)
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-005" in check_ids


# ===========================================================================
# SAST-006 — Security-sensitive file with severity below HIGH
# ===========================================================================

def test_sast006_crypto_medium_fires():
    f = make_finding(file_path="src/crypto/cipher.py", severity="MEDIUM")
    result = aggregate([f])
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-006" in check_ids


def test_sast006_auth_low_fires():
    f = make_finding(file_path="src/auth/handler.go", severity="LOW")
    result = aggregate([f])
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-006" in check_ids


def test_sast006_secret_info_fires():
    f = make_finding(file_path="config/secret_store.py", severity="INFO")
    result = aggregate([f])
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-006" in check_ids


def test_sast006_sensitive_path_high_does_not_fire():
    f = make_finding(file_path="src/auth/login.py", severity="HIGH")
    result = aggregate([f])
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-006" not in check_ids


def test_sast006_sensitive_path_critical_does_not_fire():
    f = make_finding(file_path="src/jwt/validator.py", severity="CRITICAL")
    result = aggregate([f])
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-006" not in check_ids


def test_sast006_nonsensitive_path_medium_does_not_fire():
    f = make_finding(file_path="src/utils/helpers.py", severity="MEDIUM")
    result = aggregate([f])
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-006" not in check_ids


def test_sast006_password_in_path_fires():
    f = make_finding(file_path="lib/password_manager.py", severity="LOW")
    result = aggregate([f])
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-006" in check_ids


def test_sast006_token_in_path_fires():
    f = make_finding(file_path="services/token_refresh.ts", severity="MEDIUM")
    result = aggregate([f])
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-006" in check_ids


def test_sast006_cert_in_path_fires():
    f = make_finding(file_path="infra/cert_manager.py", severity="MEDIUM")
    result = aggregate([f])
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-006" in check_ids


def test_sast006_case_insensitive_keyword():
    f = make_finding(file_path="src/AUTH/handler.py", severity="LOW")
    result = aggregate([f])
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-006" in check_ids


def test_sast006_emits_one_per_sensitive_finding():
    findings = [
        make_finding(finding_id="f1", file_path="crypto/util.py", severity="MEDIUM"),
        make_finding(finding_id="f2", file_path="crypto/enc.py",  severity="LOW"),
        make_finding(finding_id="f3", file_path="main.py",        severity="MEDIUM"),
    ]
    result = aggregate(findings)
    sast006 = [af for af in result.findings if af.check_id == "SAST-006"]
    assert len(sast006) == 2


def test_sast006_severity_is_high():
    f = make_finding(file_path="src/session/store.py", severity="LOW")
    result = aggregate([f])
    sast006 = [af for af in result.findings if af.check_id == "SAST-006"]
    assert sast006[0].severity == "HIGH"


def test_sast006_weight():
    f = make_finding(file_path="src/key/storage.py", severity="MEDIUM")
    result = aggregate([f])
    sast006 = [af for af in result.findings if af.check_id == "SAST-006"]
    assert sast006[0].weight == 25


def test_sast006_affected_finding_id():
    f = make_finding(finding_id="sens-001", file_path="auth/login.py", severity="LOW")
    result = aggregate([f])
    sast006 = [af for af in result.findings if af.check_id == "SAST-006"]
    assert sast006[0].affected_finding_ids == ["sens-001"]


def test_sast006_login_path_fires():
    f = make_finding(file_path="views/login_view.py", severity="MEDIUM")
    result = aggregate([f])
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-006" in check_ids


def test_sast006_key_in_path_fires():
    f = make_finding(file_path="utils/key_derivation.py", severity="INFO")
    result = aggregate([f])
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-006" in check_ids


def test_sast006_session_path_fires():
    f = make_finding(file_path="middleware/session_handler.js", severity="LOW")
    result = aggregate([f])
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-006" in check_ids


# ===========================================================================
# SAST-007 — Duplicate finding across tools
# ===========================================================================

def test_sast007_duplicate_across_tools_fires():
    findings = [
        make_finding(finding_id="f1", tool="semgrep", file_path="a.py",
                     line_number=10, rule_id="SQL-INJ"),
        make_finding(finding_id="f2", tool="bandit",  file_path="a.py",
                     line_number=10, rule_id="SQL-INJ"),
    ]
    result = aggregate(findings)
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-007" in check_ids


def test_sast007_same_tool_same_rule_does_not_fire():
    findings = [
        make_finding(finding_id="f1", tool="semgrep", file_path="a.py",
                     line_number=10, rule_id="SQL-INJ"),
        make_finding(finding_id="f2", tool="semgrep", file_path="a.py",
                     line_number=10, rule_id="SQL-INJ"),
    ]
    result = aggregate(findings)
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-007" not in check_ids


def test_sast007_different_line_does_not_fire():
    findings = [
        make_finding(finding_id="f1", tool="semgrep", file_path="a.py",
                     line_number=10, rule_id="SQL-INJ"),
        make_finding(finding_id="f2", tool="bandit",  file_path="a.py",
                     line_number=11, rule_id="SQL-INJ"),
    ]
    result = aggregate(findings)
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-007" not in check_ids


def test_sast007_different_file_does_not_fire():
    findings = [
        make_finding(finding_id="f1", tool="semgrep", file_path="a.py",
                     line_number=10, rule_id="SQL-INJ"),
        make_finding(finding_id="f2", tool="bandit",  file_path="b.py",
                     line_number=10, rule_id="SQL-INJ"),
    ]
    result = aggregate(findings)
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-007" not in check_ids


def test_sast007_different_rule_does_not_fire():
    findings = [
        make_finding(finding_id="f1", tool="semgrep", file_path="a.py",
                     line_number=10, rule_id="SQL-INJ"),
        make_finding(finding_id="f2", tool="bandit",  file_path="a.py",
                     line_number=10, rule_id="XSS"),
    ]
    result = aggregate(findings)
    check_ids = [af.check_id for af in result.findings]
    assert "SAST-007" not in check_ids


def test_sast007_emits_one_per_duplicate_group():
    findings = [
        # Group 1
        make_finding(finding_id="f1", tool="semgrep", file_path="a.py",
                     line_number=10, rule_id="R1"),
        make_finding(finding_id="f2", tool="bandit",  file_path="a.py",
                     line_number=10, rule_id="R1"),
        # Group 2
        make_finding(finding_id="f3", tool="codeql",  file_path="b.py",
                     line_number=20, rule_id="R2"),
        make_finding(finding_id="f4", tool="sonar",   file_path="b.py",
                     line_number=20, rule_id="R2"),
    ]
    result = aggregate(findings)
    sast007 = [af for af in result.findings if af.check_id == "SAST-007"]
    assert len(sast007) == 2


def test_sast007_three_tools_same_location_one_finding():
    findings = [
        make_finding(finding_id=f"f{i}", tool=f"tool{i}", file_path="c.py",
                     line_number=5, rule_id="XSS")
        for i in range(3)
    ]
    result = aggregate(findings)
    sast007 = [af for af in result.findings if af.check_id == "SAST-007"]
    assert len(sast007) == 1


def test_sast007_affected_finding_ids_includes_all_duplicates():
    findings = [
        make_finding(finding_id="dup1", tool="a", file_path="x.py",
                     line_number=1, rule_id="R"),
        make_finding(finding_id="dup2", tool="b", file_path="x.py",
                     line_number=1, rule_id="R"),
    ]
    result = aggregate(findings)
    sast007 = [af for af in result.findings if af.check_id == "SAST-007"]
    assert set(sast007[0].affected_finding_ids) == {"dup1", "dup2"}


def test_sast007_severity_is_low():
    findings = [
        make_finding(finding_id="f1", tool="a", file_path="x.py",
                     line_number=1, rule_id="R"),
        make_finding(finding_id="f2", tool="b", file_path="x.py",
                     line_number=1, rule_id="R"),
    ]
    result = aggregate(findings)
    sast007 = [af for af in result.findings if af.check_id == "SAST-007"]
    assert sast007[0].severity == "LOW"


def test_sast007_weight():
    findings = [
        make_finding(finding_id="f1", tool="a", file_path="x.py",
                     line_number=1, rule_id="R"),
        make_finding(finding_id="f2", tool="b", file_path="x.py",
                     line_number=1, rule_id="R"),
    ]
    result = aggregate(findings)
    sast007 = [af for af in result.findings if af.check_id == "SAST-007"]
    assert sast007[0].weight == 5


# ===========================================================================
# RISK SCORE and PIPELINE_FAIL
# ===========================================================================

def test_risk_score_capped_at_100():
    # Fire all 7 checks: total would be 15+45+20+20+25+25+5 = 155 -> capped at 100.
    findings = [
        # SAST-001: no CWE
        make_finding(finding_id="f1", cwe=None, severity="MEDIUM",
                     file_path="main.py", tool="semgrep"),
        # SAST-002: critical, stale
        make_finding(finding_id="f2", cwe="CWE-X", severity="CRITICAL",
                     age_days=31, file_path="main.py", tool="semgrep"),
        # SAST-003 + SAST-005: same CWE different severity, and HIGH count
        make_finding(finding_id="f3", cwe="CWE-89", severity="HIGH",
                     file_path="main.py", tool="toolA"),
        make_finding(finding_id="f4", cwe="CWE-89", severity="MEDIUM",
                     file_path="main.py", tool="toolB"),
        # SAST-004: suppressed, no expiry
        make_finding(finding_id="f5", cwe="CWE-Y", suppressed=True,
                     expiry_date=None, file_path="main.py", tool="semgrep"),
        # SAST-006: sensitive path + below HIGH
        make_finding(finding_id="f6", cwe="CWE-Z", severity="MEDIUM",
                     file_path="auth/handler.py", tool="semgrep"),
        # SAST-007: duplicate
        make_finding(finding_id="f7", tool="toolC", file_path="dup.py",
                     line_number=1, rule_id="DUP", cwe="CWE-D", severity="LOW"),
        make_finding(finding_id="f8", tool="toolD", file_path="dup.py",
                     line_number=1, rule_id="DUP", cwe="CWE-D", severity="LOW"),
    ]
    # Ensure SAST-005 fires: there are CRITICAL(f2) + HIGH(f3) = 2, below default 10;
    # so lower the threshold.
    result = aggregate(findings, critical_high_threshold=1)
    assert result.risk_score == 100


def test_pipeline_fail_true_when_risk_score_gte_50():
    # SAST-002 alone = weight 45; add SAST-001 = +15 -> total 60 >= 50.
    findings = [
        make_finding(finding_id="f1", cwe=None, severity="MEDIUM",
                     age_days=5, file_path="main.py"),
        make_finding(finding_id="f2", cwe="CWE-X", severity="CRITICAL",
                     age_days=31, file_path="main.py"),
    ]
    result = aggregate(findings)
    assert result.pipeline_fail is True


def test_pipeline_fail_false_when_risk_score_below_50():
    # Only SAST-001 fires (weight=15) — well below 50.
    f = make_finding(cwe=None, severity="LOW", age_days=5, file_path="main.py")
    result = aggregate([f])
    assert result.pipeline_fail is False


def test_pipeline_fail_boundary_exactly_50():
    # SAST-003 (20) + SAST-004 (20) + SAST-001 (15) = 55 -> fail
    # Simpler: fire SAST-002 (45) + SAST-007 (5) = 50 -> fail exactly.
    findings = [
        make_finding(finding_id="f1", cwe="CWE-A", severity="CRITICAL",
                     age_days=31, tool="a", file_path="dup.py",
                     line_number=99, rule_id="R-DUP"),
        make_finding(finding_id="f2", cwe="CWE-B", severity="LOW",
                     age_days=1, tool="b", file_path="dup.py",
                     line_number=99, rule_id="R-DUP"),
    ]
    result = aggregate(findings)
    # SAST-002 (f1) = 45, SAST-007 = 5 -> score 50
    assert result.risk_score == 50
    assert result.pipeline_fail is True


def test_pipeline_fail_score_49_is_pass():
    # SAST-001 (15) + SAST-007 (5) + SAST-004 (20) = 40 -> PASS.
    # Or: just SAST-004 (20) + SAST-006 (25) = 45 -> PASS.
    findings = [
        make_finding(finding_id="f1", suppressed=True, expiry_date=None,
                     severity="LOW", file_path="auth/x.py"),
    ]
    result = aggregate(findings)
    # SAST-004 (20) + SAST-006 (25) = 45 < 50
    assert result.risk_score == 45
    assert result.pipeline_fail is False


def test_risk_score_uses_unique_check_ids():
    # 5 findings all missing CWE — SAST-001 fires 5 times but weight counted once.
    findings = [make_finding(finding_id=f"f{i}", cwe=None) for i in range(5)]
    result = aggregate(findings)
    assert result.risk_score == _CHECK_WEIGHTS["SAST-001"]
    assert result.risk_score == 15


# ===========================================================================
# to_dict / summary / by_severity
# ===========================================================================

def test_to_dict_keys_present():
    result = aggregate([make_finding(cwe=None)])
    d = result.to_dict()
    for key in ("total_input_findings", "critical_count", "high_count",
                "risk_score", "pipeline_fail", "findings"):
        assert key in d


def test_to_dict_findings_have_required_keys():
    result = aggregate([make_finding(cwe=None)])
    d = result.to_dict()
    for f in d["findings"]:
        for key in ("check_id", "severity", "title", "detail",
                    "weight", "affected_finding_ids"):
            assert key in f


def test_summary_contains_risk_score():
    result = aggregate([make_finding(cwe=None)])
    assert str(result.risk_score) in result.summary()


def test_summary_contains_pipeline_status():
    result = aggregate([make_finding(cwe=None)])
    assert "PASS" in result.summary() or "FAIL" in result.summary()


def test_by_severity_groups_correctly():
    findings = [
        make_finding(finding_id="f1", cwe=None),  # SAST-001 -> MEDIUM
        make_finding(finding_id="f2", severity="CRITICAL", age_days=31,
                     cwe="CWE-X"),  # SAST-002 -> CRITICAL
    ]
    result = aggregate(findings)
    groups = result.by_severity()
    assert "MEDIUM" in groups
    assert "CRITICAL" in groups
    assert all(af.severity == "MEDIUM" for af in groups["MEDIUM"])
    assert all(af.severity == "CRITICAL" for af in groups["CRITICAL"])


def test_counts_correct():
    findings = [
        make_finding(finding_id="c1", severity="CRITICAL", cwe="CWE-1"),
        make_finding(finding_id="c2", severity="CRITICAL", cwe="CWE-2"),
        make_finding(finding_id="h1", severity="HIGH",     cwe="CWE-3"),
        make_finding(finding_id="m1", severity="MEDIUM",   cwe="CWE-4"),
    ]
    result = aggregate(findings)
    assert result.critical_count == 2
    assert result.high_count == 1
    assert result.total_input_findings == 4


# ===========================================================================
# aggregate_many
# ===========================================================================

def test_aggregate_many_empty_list():
    results = aggregate_many([])
    assert results == []


def test_aggregate_many_returns_correct_count():
    sets = [[make_finding()], [make_finding(cwe=None)], []]
    results = aggregate_many(sets)
    assert len(results) == 3


def test_aggregate_many_independent_results():
    sets = [
        [make_finding(finding_id="f1", cwe=None)],
        [make_finding(finding_id="f2", cwe="CWE-89")],
    ]
    results = aggregate_many(sets)
    assert results[0].risk_score == _CHECK_WEIGHTS["SAST-001"]
    assert results[1].risk_score == 0


def test_aggregate_many_threshold_applied_per_set():
    sets = [
        [make_finding(finding_id=f"f{i}", severity="HIGH") for i in range(11)],
        [make_finding(finding_id=f"g{i}", severity="HIGH") for i in range(5)],
    ]
    results = aggregate_many(sets, critical_high_threshold=10)
    # First set exceeds threshold; second does not.
    check_ids_0 = [af.check_id for af in results[0].findings]
    check_ids_1 = [af.check_id for af in results[1].findings]
    assert "SAST-005" in check_ids_0
    assert "SAST-005" not in check_ids_1


def test_aggregate_many_with_all_empty_sets():
    results = aggregate_many([[], [], []])
    assert all(r.risk_score == 0 for r in results)


# ===========================================================================
# _is_sensitive_path helper
# ===========================================================================

def test_is_sensitive_path_crypto():
    assert _is_sensitive_path("src/crypto/util.py") is True


def test_is_sensitive_path_no_keyword():
    assert _is_sensitive_path("src/utils/helper.py") is False


def test_is_sensitive_path_case_insensitive():
    assert _is_sensitive_path("SRC/AUTH/LOGIN.PY") is True


def test_is_sensitive_path_partial_match():
    # "key" should match "monkey" — this tests current behaviour.
    assert _is_sensitive_path("utils/monkey_patch.py") is True


def test_is_sensitive_path_all_keywords():
    keywords = ["crypto", "auth", "secret", "password", "token",
                "login", "session", "jwt", "key", "cert"]
    for kw in keywords:
        assert _is_sensitive_path(f"src/{kw}/file.py") is True


# ===========================================================================
# _CHECK_WEIGHTS integrity
# ===========================================================================

def test_check_weights_all_ids_present():
    expected = {"SAST-001", "SAST-002", "SAST-003", "SAST-004",
                "SAST-005", "SAST-006", "SAST-007"}
    assert set(_CHECK_WEIGHTS.keys()) == expected


def test_check_weights_values():
    assert _CHECK_WEIGHTS["SAST-001"] == 15
    assert _CHECK_WEIGHTS["SAST-002"] == 45
    assert _CHECK_WEIGHTS["SAST-003"] == 20
    assert _CHECK_WEIGHTS["SAST-004"] == 20
    assert _CHECK_WEIGHTS["SAST-005"] == 25
    assert _CHECK_WEIGHTS["SAST-006"] == 25
    assert _CHECK_WEIGHTS["SAST-007"] == 5
