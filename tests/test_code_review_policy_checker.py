# Copyright 2024 Cyber Port Contributors
#
# Licensed under the Creative Commons Attribution 4.0 International License
# (CC BY 4.0). You may obtain a copy of the License at:
# https://creativecommons.org/licenses/by/4.0/

"""test_code_review_policy_checker.py

90+ tests for CodeReviewPolicyChecker, covering every check rule, edge
cases, data-model contracts, and helper methods.
"""

from __future__ import annotations

import sys
import os

# Ensure the shared/analyzers package is importable without installation.
sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..", "shared", "analyzers"),
)

import pytest

from code_review_policy_checker import (
    BranchProtectionPolicy,
    CodeReviewPolicyChecker,
    ReviewPolicyFinding,
    ReviewPolicyResult,
    StatusCheck,
    _CHECK_WEIGHTS,
    CRITICAL,
    HIGH,
    MEDIUM,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ideal_policy(branch_name: str = "main", repository: str = "acme/repo") -> BranchProtectionPolicy:
    """Return a policy that satisfies every security requirement."""
    return BranchProtectionPolicy(
        branch_name=branch_name,
        repository=repository,
        is_protected=True,
        required_review_count=2,
        dismiss_stale_reviews=True,
        require_code_owner_review=True,
        allow_self_approval=False,
        allow_force_push=False,
        allow_deletions=False,
        require_status_checks=True,
        status_checks=[
            StatusCheck(context="ci/tests"),
            StatusCheck(context="security/scan"),
        ],
        require_linear_history=True,
        lock_branch=False,
    )


def _checker() -> CodeReviewPolicyChecker:
    return CodeReviewPolicyChecker()


def _find(result: ReviewPolicyResult, check_id: str) -> ReviewPolicyFinding | None:
    return next((f for f in result.findings if f.check_id == check_id), None)


def _ids(result: ReviewPolicyResult) -> set:
    return {f.check_id for f in result.findings}


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def checker() -> CodeReviewPolicyChecker:
    return CodeReviewPolicyChecker()


# ===========================================================================
# Section 1 — Ideal policy: zero findings
# ===========================================================================


class TestIdealPolicy:
    def test_ideal_main_no_findings(self, checker):
        result = checker.check(_ideal_policy("main"))
        assert result.findings == []

    def test_ideal_master_no_findings(self, checker):
        result = checker.check(_ideal_policy("master"))
        assert result.findings == []

    def test_ideal_develop_no_findings(self, checker):
        result = checker.check(_ideal_policy("develop"))
        assert result.findings == []

    def test_ideal_risk_score_zero(self, checker):
        result = checker.check(_ideal_policy())
        assert result.risk_score == 0

    def test_ideal_summary_no_findings(self, checker):
        result = checker.check(_ideal_policy())
        assert "No findings" in result.summary()
        assert "0/100" in result.summary()

    def test_ideal_by_severity_all_empty(self, checker):
        sev = checker.check(_ideal_policy()).by_severity()
        assert sev[CRITICAL] == []
        assert sev[HIGH] == []
        assert sev[MEDIUM] == []

    def test_ideal_to_dict_keys(self, checker):
        d = checker.check(_ideal_policy()).to_dict()
        assert "findings" in d
        assert "risk_score" in d
        assert "summary" in d
        assert "by_severity" in d


# ===========================================================================
# Section 2 — CRP-001: No required reviewers
# ===========================================================================


class TestCRP001:
    def test_triggers_on_zero_count(self, checker):
        policy = _ideal_policy()
        policy.required_review_count = 0
        result = checker.check(policy)
        assert "CRP-001" in _ids(result)

    def test_not_triggered_on_count_one(self, checker):
        """count=1 triggers CRP-006 but not CRP-001."""
        policy = _ideal_policy()
        policy.required_review_count = 1
        result = checker.check(policy)
        assert "CRP-001" not in _ids(result)

    def test_not_triggered_on_count_two(self, checker):
        policy = _ideal_policy()
        policy.required_review_count = 2
        result = checker.check(policy)
        assert "CRP-001" not in _ids(result)

    def test_not_triggered_on_count_five(self, checker):
        policy = _ideal_policy()
        policy.required_review_count = 5
        result = checker.check(policy)
        assert "CRP-001" not in _ids(result)

    def test_severity_is_high(self, checker):
        policy = _ideal_policy()
        policy.required_review_count = 0
        finding = _find(checker.check(policy), "CRP-001")
        assert finding is not None
        assert finding.severity == HIGH

    def test_finding_carries_branch_name(self, checker):
        policy = _ideal_policy("main")
        policy.required_review_count = 0
        finding = _find(checker.check(policy), "CRP-001")
        assert finding.branch_name == "main"

    def test_finding_carries_repository(self, checker):
        policy = _ideal_policy(repository="org/backend")
        policy.required_review_count = 0
        finding = _find(checker.check(policy), "CRP-001")
        assert finding.repository == "org/backend"

    def test_weight_contributes_to_risk_score(self, checker):
        policy = _ideal_policy()
        policy.required_review_count = 0
        result = checker.check(policy)
        assert result.risk_score >= _CHECK_WEIGHTS["CRP-001"]


# ===========================================================================
# Section 3 — CRP-002: Self-approval allowed
# ===========================================================================


class TestCRP002:
    def test_triggers_when_self_approval_true(self, checker):
        policy = _ideal_policy()
        policy.allow_self_approval = True
        assert "CRP-002" in _ids(checker.check(policy))

    def test_not_triggered_when_false(self, checker):
        policy = _ideal_policy()
        policy.allow_self_approval = False
        assert "CRP-002" not in _ids(checker.check(policy))

    def test_severity_is_critical(self, checker):
        policy = _ideal_policy()
        policy.allow_self_approval = True
        finding = _find(checker.check(policy), "CRP-002")
        assert finding.severity == CRITICAL

    def test_message_mentions_self_approval(self, checker):
        policy = _ideal_policy()
        policy.allow_self_approval = True
        finding = _find(checker.check(policy), "CRP-002")
        assert "self" in finding.message.lower() or "approv" in finding.message.lower()

    def test_recommendation_non_empty(self, checker):
        policy = _ideal_policy()
        policy.allow_self_approval = True
        finding = _find(checker.check(policy), "CRP-002")
        assert finding.recommendation != ""

    def test_weight_in_risk_score(self, checker):
        policy = _ideal_policy()
        policy.allow_self_approval = True
        result = checker.check(policy)
        assert result.risk_score >= _CHECK_WEIGHTS["CRP-002"]


# ===========================================================================
# Section 4 — CRP-003: Force push allowed
# ===========================================================================


class TestCRP003:
    def test_triggers_when_force_push_true(self, checker):
        policy = _ideal_policy()
        policy.allow_force_push = True
        assert "CRP-003" in _ids(checker.check(policy))

    def test_not_triggered_when_false(self, checker):
        policy = _ideal_policy()
        policy.allow_force_push = False
        assert "CRP-003" not in _ids(checker.check(policy))

    def test_severity_is_high(self, checker):
        policy = _ideal_policy()
        policy.allow_force_push = True
        finding = _find(checker.check(policy), "CRP-003")
        assert finding.severity == HIGH

    def test_message_mentions_force_push(self, checker):
        policy = _ideal_policy()
        policy.allow_force_push = True
        finding = _find(checker.check(policy), "CRP-003")
        assert "force" in finding.message.lower()

    def test_weight_in_risk_score(self, checker):
        policy = _ideal_policy()
        policy.allow_force_push = True
        result = checker.check(policy)
        assert result.risk_score >= _CHECK_WEIGHTS["CRP-003"]


# ===========================================================================
# Section 5 — CRP-004: Stale review dismissal not enabled
# ===========================================================================


class TestCRP004:
    def test_triggers_when_stale_false_and_reviews_positive(self, checker):
        policy = _ideal_policy()
        policy.dismiss_stale_reviews = False
        policy.required_review_count = 2
        assert "CRP-004" in _ids(checker.check(policy))

    def test_not_triggered_when_stale_true(self, checker):
        policy = _ideal_policy()
        policy.dismiss_stale_reviews = True
        policy.required_review_count = 2
        assert "CRP-004" not in _ids(checker.check(policy))

    def test_not_triggered_when_reviews_zero(self, checker):
        """reviews=0 means CRP-001 fires, not CRP-004."""
        policy = _ideal_policy()
        policy.dismiss_stale_reviews = False
        policy.required_review_count = 0
        assert "CRP-004" not in _ids(checker.check(policy))

    def test_severity_is_medium(self, checker):
        policy = _ideal_policy()
        policy.dismiss_stale_reviews = False
        policy.required_review_count = 2
        finding = _find(checker.check(policy), "CRP-004")
        assert finding.severity == MEDIUM

    def test_triggers_with_review_count_one(self, checker):
        policy = _ideal_policy()
        policy.dismiss_stale_reviews = False
        policy.required_review_count = 1
        assert "CRP-004" in _ids(checker.check(policy))

    def test_weight_in_risk_score(self, checker):
        policy = _ideal_policy()
        policy.dismiss_stale_reviews = False
        policy.required_review_count = 2
        result = checker.check(policy)
        assert result.risk_score >= _CHECK_WEIGHTS["CRP-004"]


# ===========================================================================
# Section 6 — CRP-005: No required CI/CD status checks
# ===========================================================================


class TestCRP005:
    def test_triggers_when_require_status_checks_false(self, checker):
        policy = _ideal_policy()
        policy.require_status_checks = False
        policy.status_checks = []
        assert "CRP-005" in _ids(checker.check(policy))

    def test_triggers_when_true_but_empty_list(self, checker):
        policy = _ideal_policy()
        policy.require_status_checks = True
        policy.status_checks = []
        assert "CRP-005" in _ids(checker.check(policy))

    def test_not_triggered_when_true_and_non_empty(self, checker):
        policy = _ideal_policy()
        policy.require_status_checks = True
        policy.status_checks = [StatusCheck(context="ci/tests")]
        assert "CRP-005" not in _ids(checker.check(policy))

    def test_not_triggered_on_ideal(self, checker):
        assert "CRP-005" not in _ids(checker.check(_ideal_policy()))

    def test_severity_is_high(self, checker):
        policy = _ideal_policy()
        policy.require_status_checks = False
        finding = _find(checker.check(policy), "CRP-005")
        assert finding.severity == HIGH

    def test_triggers_when_require_false_even_with_checks_listed(self, checker):
        """require_status_checks=False is sufficient to fire CRP-005."""
        policy = _ideal_policy()
        policy.require_status_checks = False
        policy.status_checks = [StatusCheck(context="ci/tests")]
        assert "CRP-005" in _ids(checker.check(policy))

    def test_weight_in_risk_score(self, checker):
        policy = _ideal_policy()
        policy.require_status_checks = False
        policy.status_checks = []
        result = checker.check(policy)
        assert result.risk_score >= _CHECK_WEIGHTS["CRP-005"]


# ===========================================================================
# Section 7 — CRP-006: Insufficient minimum reviewer count
# ===========================================================================


class TestCRP006:
    def test_triggers_on_count_one(self, checker):
        policy = _ideal_policy()
        policy.required_review_count = 1
        assert "CRP-006" in _ids(checker.check(policy))

    def test_not_triggered_on_count_zero(self, checker):
        """count=0 triggers CRP-001 instead."""
        policy = _ideal_policy()
        policy.required_review_count = 0
        assert "CRP-006" not in _ids(checker.check(policy))

    def test_not_triggered_on_count_two(self, checker):
        policy = _ideal_policy()
        policy.required_review_count = 2
        assert "CRP-006" not in _ids(checker.check(policy))

    def test_not_triggered_on_count_three(self, checker):
        policy = _ideal_policy()
        policy.required_review_count = 3
        assert "CRP-006" not in _ids(checker.check(policy))

    def test_severity_is_high(self, checker):
        policy = _ideal_policy()
        policy.required_review_count = 1
        finding = _find(checker.check(policy), "CRP-006")
        assert finding.severity == HIGH

    def test_crp001_not_triggered_on_count_one(self, checker):
        """Verify mutual exclusion: count=1 triggers 006 not 001."""
        policy = _ideal_policy()
        policy.required_review_count = 1
        ids = _ids(checker.check(policy))
        assert "CRP-001" not in ids
        assert "CRP-006" in ids

    def test_weight_in_risk_score(self, checker):
        policy = _ideal_policy()
        policy.required_review_count = 1
        result = checker.check(policy)
        assert result.risk_score >= _CHECK_WEIGHTS["CRP-006"]


# ===========================================================================
# Section 8 — CRP-007: Branch not protected
# ===========================================================================


class TestCRP007:
    @pytest.mark.parametrize("branch", ["main", "master", "develop", "release", "production"])
    def test_triggers_critical_on_critical_branches(self, checker, branch):
        policy = _ideal_policy(branch_name=branch)
        policy.is_protected = False
        finding = _find(checker.check(policy), "CRP-007")
        assert finding is not None
        assert finding.severity == CRITICAL

    def test_triggers_medium_on_feature_branch(self, checker):
        policy = _ideal_policy(branch_name="feature/xyz")
        policy.is_protected = False
        finding = _find(checker.check(policy), "CRP-007")
        assert finding is not None
        assert finding.severity == MEDIUM

    def test_triggers_medium_on_hotfix_branch(self, checker):
        policy = _ideal_policy(branch_name="hotfix/fix-login")
        policy.is_protected = False
        finding = _find(checker.check(policy), "CRP-007")
        assert finding is not None
        assert finding.severity == MEDIUM

    def test_not_triggered_when_protected(self, checker):
        policy = _ideal_policy(branch_name="main")
        policy.is_protected = True
        assert "CRP-007" not in _ids(checker.check(policy))

    def test_not_triggered_on_protected_feature_branch(self, checker):
        policy = _ideal_policy(branch_name="feature/abc")
        policy.is_protected = True
        assert "CRP-007" not in _ids(checker.check(policy))

    def test_weight_in_risk_score_critical_branch(self, checker):
        policy = _ideal_policy(branch_name="main")
        policy.is_protected = False
        result = checker.check(policy)
        assert result.risk_score >= _CHECK_WEIGHTS["CRP-007"]

    def test_finding_carries_correct_branch_name(self, checker):
        policy = _ideal_policy(branch_name="master")
        policy.is_protected = False
        finding = _find(checker.check(policy), "CRP-007")
        assert finding.branch_name == "master"

    def test_triggers_on_arbitrary_non_critical_branch(self, checker):
        policy = _ideal_policy(branch_name="chore/cleanup")
        policy.is_protected = False
        assert "CRP-007" in _ids(checker.check(policy))


# ===========================================================================
# Section 9 — Multiple findings on the same policy
# ===========================================================================


class TestMultipleFindings:
    def test_unprotected_branch_all_defaults_fires_multiple(self, checker):
        """Default BranchProtectionPolicy (mostly permissive) fires several checks."""
        policy = BranchProtectionPolicy(
            branch_name="main",
            is_protected=False,   # CRP-007 CRITICAL
            required_review_count=0,  # CRP-001
            allow_self_approval=True,  # CRP-002
            allow_force_push=True,     # CRP-003
            require_status_checks=False,  # CRP-005
        )
        result = checker.check(policy)
        ids = _ids(result)
        assert "CRP-001" in ids
        assert "CRP-002" in ids
        assert "CRP-003" in ids
        assert "CRP-005" in ids
        assert "CRP-007" in ids

    def test_crp001_and_crp002_together(self, checker):
        policy = _ideal_policy()
        policy.required_review_count = 0
        policy.allow_self_approval = True
        ids = _ids(checker.check(policy))
        assert "CRP-001" in ids
        assert "CRP-002" in ids

    def test_crp002_and_crp003_together(self, checker):
        policy = _ideal_policy()
        policy.allow_self_approval = True
        policy.allow_force_push = True
        ids = _ids(checker.check(policy))
        assert "CRP-002" in ids
        assert "CRP-003" in ids

    def test_crp004_and_crp006_together(self, checker):
        """dismiss_stale=False + review_count=1 fires both CRP-004 and CRP-006."""
        policy = _ideal_policy()
        policy.dismiss_stale_reviews = False
        policy.required_review_count = 1
        ids = _ids(checker.check(policy))
        assert "CRP-004" in ids
        assert "CRP-006" in ids

    def test_crp005_and_crp003_together(self, checker):
        policy = _ideal_policy()
        policy.allow_force_push = True
        policy.require_status_checks = False
        policy.status_checks = []
        ids = _ids(checker.check(policy))
        assert "CRP-003" in ids
        assert "CRP-005" in ids

    def test_findings_count_matches_unique_ids(self, checker):
        policy = BranchProtectionPolicy(
            branch_name="main",
            is_protected=False,
            required_review_count=0,
            allow_self_approval=True,
            allow_force_push=True,
            require_status_checks=False,
        )
        result = checker.check(policy)
        assert len(result.findings) == len(_ids(result))


# ===========================================================================
# Section 10 — Risk score arithmetic and cap
# ===========================================================================


class TestRiskScore:
    def test_risk_score_zero_for_ideal(self, checker):
        assert checker.check(_ideal_policy()).risk_score == 0

    def test_risk_score_matches_single_check_weight(self, checker):
        """Only CRP-002 fires; risk score must equal CRP-002 weight."""
        policy = _ideal_policy()
        policy.allow_self_approval = True
        result = checker.check(policy)
        assert result.risk_score == _CHECK_WEIGHTS["CRP-002"]

    def test_risk_score_capped_at_100(self, checker):
        """Deliberately trigger checks whose weights sum > 100."""
        policy = BranchProtectionPolicy(
            branch_name="main",
            is_protected=False,      # 45
            required_review_count=0, # 25
            allow_self_approval=True, # 40
            allow_force_push=True,   # 25
            require_status_checks=False,  # 20
        )
        # 45 + 25 + 40 + 25 + 20 = 155 → must be capped at 100
        result = checker.check(policy)
        assert result.risk_score == 100

    def test_risk_score_does_not_double_count_same_id(self, checker):
        """Each unique check ID contributes its weight exactly once."""
        policy = _ideal_policy()
        policy.allow_force_push = True  # CRP-003 weight = 25
        policy.allow_self_approval = True  # CRP-002 weight = 40
        result = checker.check(policy)
        expected = _CHECK_WEIGHTS["CRP-002"] + _CHECK_WEIGHTS["CRP-003"]
        assert result.risk_score == expected

    def test_risk_score_is_integer(self, checker):
        result = checker.check(_ideal_policy())
        assert isinstance(result.risk_score, int)

    def test_risk_score_non_negative(self, checker):
        result = checker.check(_ideal_policy())
        assert result.risk_score >= 0

    def test_risk_score_crp001_only(self, checker):
        policy = _ideal_policy()
        policy.required_review_count = 0
        result = checker.check(policy)
        assert result.risk_score == _CHECK_WEIGHTS["CRP-001"]

    def test_risk_score_crp006_only(self, checker):
        policy = _ideal_policy()
        policy.required_review_count = 1
        result = checker.check(policy)
        assert result.risk_score == _CHECK_WEIGHTS["CRP-006"]


# ===========================================================================
# Section 11 — summary() method
# ===========================================================================


class TestSummary:
    def test_summary_zero_findings(self, checker):
        s = checker.check(_ideal_policy()).summary()
        assert "No findings" in s

    def test_summary_contains_risk_score(self, checker):
        result = checker.check(_ideal_policy())
        assert "0/100" in result.summary()

    def test_summary_mentions_finding_count(self, checker):
        policy = _ideal_policy()
        policy.allow_self_approval = True
        s = checker.check(policy).summary()
        assert "1" in s

    def test_summary_mentions_critical_when_present(self, checker):
        policy = _ideal_policy()
        policy.allow_self_approval = True  # CRP-002 is CRITICAL
        s = checker.check(policy).summary()
        assert CRITICAL in s

    def test_summary_mentions_high_when_present(self, checker):
        policy = _ideal_policy()
        policy.allow_force_push = True  # CRP-003 is HIGH
        s = checker.check(policy).summary()
        assert HIGH in s

    def test_summary_mentions_medium_when_present(self, checker):
        policy = _ideal_policy()
        policy.dismiss_stale_reviews = False
        # required_review_count stays 2 from ideal so CRP-004 (MEDIUM) fires
        s = checker.check(policy).summary()
        assert MEDIUM in s

    def test_summary_returns_string(self, checker):
        assert isinstance(checker.check(_ideal_policy()).summary(), str)

    def test_summary_non_empty(self, checker):
        assert checker.check(_ideal_policy()).summary() != ""


# ===========================================================================
# Section 12 — by_severity() method
# ===========================================================================


class TestBySeverity:
    def test_by_severity_returns_dict(self, checker):
        assert isinstance(checker.check(_ideal_policy()).by_severity(), dict)

    def test_by_severity_has_all_keys(self, checker):
        sev = checker.check(_ideal_policy()).by_severity()
        assert CRITICAL in sev
        assert HIGH in sev
        assert MEDIUM in sev

    def test_by_severity_critical_contains_crp002(self, checker):
        policy = _ideal_policy()
        policy.allow_self_approval = True
        sev = checker.check(policy).by_severity()
        ids = [f.check_id for f in sev[CRITICAL]]
        assert "CRP-002" in ids

    def test_by_severity_high_contains_crp003(self, checker):
        policy = _ideal_policy()
        policy.allow_force_push = True
        sev = checker.check(policy).by_severity()
        ids = [f.check_id for f in sev[HIGH]]
        assert "CRP-003" in ids

    def test_by_severity_medium_contains_crp004(self, checker):
        policy = _ideal_policy()
        policy.dismiss_stale_reviews = False
        sev = checker.check(policy).by_severity()
        ids = [f.check_id for f in sev[MEDIUM]]
        assert "CRP-004" in ids

    def test_by_severity_empty_buckets_are_lists(self, checker):
        sev = checker.check(_ideal_policy()).by_severity()
        assert isinstance(sev[CRITICAL], list)
        assert isinstance(sev[HIGH], list)
        assert isinstance(sev[MEDIUM], list)

    def test_by_severity_total_matches_findings(self, checker):
        policy = _ideal_policy()
        policy.allow_self_approval = True
        policy.allow_force_push = True
        result = checker.check(policy)
        sev = result.by_severity()
        total = sum(len(v) for v in sev.values())
        assert total == len(result.findings)


# ===========================================================================
# Section 13 — check_many()
# ===========================================================================


class TestCheckMany:
    def test_returns_list(self, checker):
        result = checker.check_many([_ideal_policy()])
        assert isinstance(result, list)

    def test_returns_empty_list_for_empty_input(self, checker):
        assert checker.check_many([]) == []

    def test_length_matches_input(self, checker):
        policies = [_ideal_policy("main"), _ideal_policy("master"), _ideal_policy("develop")]
        results = checker.check_many(policies)
        assert len(results) == 3

    def test_each_element_is_review_policy_result(self, checker):
        results = checker.check_many([_ideal_policy(), _ideal_policy("master")])
        for r in results:
            assert isinstance(r, ReviewPolicyResult)

    def test_independent_results_per_policy(self, checker):
        p1 = _ideal_policy("main")
        p1.allow_self_approval = True  # fires CRP-002

        p2 = _ideal_policy("master")   # no issues

        results = checker.check_many([p1, p2])
        assert "CRP-002" in _ids(results[0])
        assert "CRP-002" not in _ids(results[1])

    def test_single_policy_same_as_check(self, checker):
        policy = _ideal_policy()
        policy.allow_force_push = True
        result_single = checker.check(policy)
        result_many = checker.check_many([policy])[0]
        assert result_single.risk_score == result_many.risk_score
        assert _ids(result_single) == _ids(result_many)


# ===========================================================================
# Section 14 — to_dict() on all data models
# ===========================================================================


class TestToDict:
    def test_status_check_to_dict_keys(self):
        sc = StatusCheck(context="ci/tests", is_required=True)
        d = sc.to_dict()
        assert "context" in d
        assert "is_required" in d

    def test_status_check_to_dict_values(self):
        sc = StatusCheck(context="security/scan", is_required=False)
        d = sc.to_dict()
        assert d["context"] == "security/scan"
        assert d["is_required"] is False

    def test_branch_protection_policy_to_dict_keys(self):
        d = _ideal_policy().to_dict()
        expected_keys = {
            "branch_name", "repository", "is_protected",
            "required_review_count", "dismiss_stale_reviews",
            "require_code_owner_review", "allow_self_approval",
            "allow_force_push", "allow_deletions",
            "require_status_checks", "status_checks",
            "require_linear_history", "lock_branch",
        }
        assert expected_keys.issubset(d.keys())

    def test_branch_protection_policy_status_checks_serialised(self):
        d = _ideal_policy().to_dict()
        assert isinstance(d["status_checks"], list)
        assert all(isinstance(sc, dict) for sc in d["status_checks"])

    def test_review_policy_finding_to_dict_keys(self):
        f = ReviewPolicyFinding(
            check_id="CRP-001",
            severity=HIGH,
            branch_name="main",
            repository="org/repo",
            message="test message",
            recommendation="test rec",
        )
        d = f.to_dict()
        assert {"check_id", "severity", "branch_name", "repository", "message", "recommendation"}.issubset(d.keys())

    def test_review_policy_finding_to_dict_values(self):
        f = ReviewPolicyFinding(
            check_id="CRP-002",
            severity=CRITICAL,
            branch_name="main",
            repository="acme/app",
            message="msg",
            recommendation="rec",
        )
        d = f.to_dict()
        assert d["check_id"] == "CRP-002"
        assert d["severity"] == CRITICAL
        assert d["branch_name"] == "main"
        assert d["repository"] == "acme/app"

    def test_review_policy_result_to_dict_keys(self, checker):
        d = checker.check(_ideal_policy()).to_dict()
        assert {"findings", "risk_score", "summary", "by_severity"}.issubset(d.keys())

    def test_review_policy_result_to_dict_findings_is_list(self, checker):
        d = checker.check(_ideal_policy()).to_dict()
        assert isinstance(d["findings"], list)

    def test_review_policy_result_to_dict_risk_score_is_int(self, checker):
        d = checker.check(_ideal_policy()).to_dict()
        assert isinstance(d["risk_score"], int)

    def test_review_policy_result_to_dict_by_severity_is_dict(self, checker):
        d = checker.check(_ideal_policy()).to_dict()
        assert isinstance(d["by_severity"], dict)

    def test_review_policy_result_to_dict_with_findings(self, checker):
        policy = _ideal_policy()
        policy.allow_self_approval = True
        d = checker.check(policy).to_dict()
        assert len(d["findings"]) == 1
        assert d["findings"][0]["check_id"] == "CRP-002"

    def test_branch_protection_policy_to_dict_round_trip_values(self):
        policy = _ideal_policy("release", "k1n/pipeline")
        d = policy.to_dict()
        assert d["branch_name"] == "release"
        assert d["repository"] == "k1n/pipeline"
        assert d["is_protected"] is True
        assert d["required_review_count"] == 2


# ===========================================================================
# Section 15 — _CHECK_WEIGHTS registry
# ===========================================================================


class TestCheckWeights:
    def test_all_check_ids_present(self):
        for cid in ("CRP-001", "CRP-002", "CRP-003", "CRP-004", "CRP-005", "CRP-006", "CRP-007"):
            assert cid in _CHECK_WEIGHTS

    def test_all_weights_positive(self):
        for cid, w in _CHECK_WEIGHTS.items():
            assert w > 0, f"{cid} has non-positive weight {w}"

    def test_crp007_highest_weight(self):
        assert _CHECK_WEIGHTS["CRP-007"] == max(_CHECK_WEIGHTS.values())

    def test_crp004_lowest_weight(self):
        assert _CHECK_WEIGHTS["CRP-004"] == min(_CHECK_WEIGHTS.values())
