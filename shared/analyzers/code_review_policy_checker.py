# Copyright 2024 Cyber Port Contributors
#
# Licensed under the Creative Commons Attribution 4.0 International License
# (CC BY 4.0). You may obtain a copy of the License at:
# https://creativecommons.org/licenses/by/4.0/
#
# Unless required by applicable law or agreed to in writing, software
# distributed under this License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""code_review_policy_checker.py

Validates branch protection and code review policies against security
requirements.  Works entirely offline on policy metadata — no live API calls.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Severity constants
# ---------------------------------------------------------------------------

CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"


# ---------------------------------------------------------------------------
# Check weight registry
# Keys are check IDs; values are the integer risk-score contribution.
# ---------------------------------------------------------------------------

_CHECK_WEIGHTS: Dict[str, int] = {
    "CRP-001": 25,  # No required reviewers configured
    "CRP-002": 40,  # Self-approval allowed
    "CRP-003": 25,  # Force push allowed to protected branch
    "CRP-004": 15,  # Stale review dismissal not enabled
    "CRP-005": 20,  # No required CI/CD status checks
    "CRP-006": 20,  # Insufficient minimum reviewer count
    "CRP-007": 45,  # Branch is not protected
}

# Branch names that are considered "critical" for the CRP-007 severity override.
_CRITICAL_BRANCHES = frozenset({"main", "master", "develop", "release", "production"})


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class StatusCheck:
    """Represents a single CI/CD status check requirement on a branch."""

    context: str  # e.g. "ci/tests", "security/scan"
    is_required: bool = True

    def to_dict(self) -> Dict:
        """Serialise to a plain dictionary."""
        return {
            "context": self.context,
            "is_required": self.is_required,
        }


@dataclass
class BranchProtectionPolicy:
    """Full branch protection and code-review policy for one branch."""

    branch_name: str                       # e.g. "main", "master", "develop"
    repository: str = "unknown"
    is_protected: bool = True
    required_review_count: int = 0         # minimum approvals required
    dismiss_stale_reviews: bool = False    # dismiss reviews on new commits
    require_code_owner_review: bool = False
    allow_self_approval: bool = True       # PR author can approve their own PR
    allow_force_push: bool = False
    allow_deletions: bool = False
    require_status_checks: bool = False
    status_checks: List[StatusCheck] = field(default_factory=list)
    require_linear_history: bool = False
    lock_branch: bool = False

    def to_dict(self) -> Dict:
        """Serialise to a plain dictionary."""
        return {
            "branch_name": self.branch_name,
            "repository": self.repository,
            "is_protected": self.is_protected,
            "required_review_count": self.required_review_count,
            "dismiss_stale_reviews": self.dismiss_stale_reviews,
            "require_code_owner_review": self.require_code_owner_review,
            "allow_self_approval": self.allow_self_approval,
            "allow_force_push": self.allow_force_push,
            "allow_deletions": self.allow_deletions,
            "require_status_checks": self.require_status_checks,
            "status_checks": [sc.to_dict() for sc in self.status_checks],
            "require_linear_history": self.require_linear_history,
            "lock_branch": self.lock_branch,
        }


@dataclass
class ReviewPolicyFinding:
    """A single security finding produced by a policy check."""

    check_id: str          # e.g. "CRP-001"
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW
    branch_name: str
    repository: str
    message: str           # human-readable description of the issue
    recommendation: str    # actionable remediation guidance

    def to_dict(self) -> Dict:
        """Serialise to a plain dictionary."""
        return {
            "check_id": self.check_id,
            "severity": self.severity,
            "branch_name": self.branch_name,
            "repository": self.repository,
            "message": self.message,
            "recommendation": self.recommendation,
        }


@dataclass
class ReviewPolicyResult:
    """Aggregated result of running all checks against one policy."""

    findings: List[ReviewPolicyFinding] = field(default_factory=list)
    risk_score: int = 0   # 0–100; higher is riskier

    # ------------------------------------------------------------------ #
    # Derived helpers                                                      #
    # ------------------------------------------------------------------ #

    def summary(self) -> str:
        """Return a one-line human-readable summary of the result."""
        total = len(self.findings)
        if total == 0:
            return f"No findings — risk score {self.risk_score}/100."
        severities = self.by_severity()
        parts = []
        for sev in (CRITICAL, HIGH, MEDIUM, LOW):
            count = len(severities.get(sev, []))
            if count:
                parts.append(f"{count} {sev}")
        return (
            f"{total} finding(s) [{', '.join(parts)}] — "
            f"risk score {self.risk_score}/100."
        )

    def by_severity(self) -> Dict[str, List[ReviewPolicyFinding]]:
        """Return findings grouped by severity label."""
        result: Dict[str, List[ReviewPolicyFinding]] = {
            CRITICAL: [],
            HIGH: [],
            MEDIUM: [],
            LOW: [],
        }
        for finding in self.findings:
            bucket = result.get(finding.severity)
            if bucket is not None:
                bucket.append(finding)
            else:
                # Unknown severity — add a bucket on the fly.
                result[finding.severity] = [finding]
        return result

    def to_dict(self) -> Dict:
        """Serialise to a plain dictionary."""
        return {
            "findings": [f.to_dict() for f in self.findings],
            "risk_score": self.risk_score,
            "summary": self.summary(),
            "by_severity": {
                sev: [f.to_dict() for f in findings]
                for sev, findings in self.by_severity().items()
            },
        }


# ---------------------------------------------------------------------------
# Checker
# ---------------------------------------------------------------------------


class CodeReviewPolicyChecker:
    """Validates a :class:`BranchProtectionPolicy` against security rules.

    All checks are pure functions of the policy metadata; no network I/O.
    """

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def check(self, policy: BranchProtectionPolicy) -> ReviewPolicyResult:
        """Run all checks against *policy* and return a :class:`ReviewPolicyResult`."""
        findings: List[ReviewPolicyFinding] = []

        # Run each check; collect findings.
        for check_fn in (
            self._check_crp001,
            self._check_crp002,
            self._check_crp003,
            self._check_crp004,
            self._check_crp005,
            self._check_crp006,
            self._check_crp007,
        ):
            result: Optional[ReviewPolicyFinding] = check_fn(policy)
            if result is not None:
                findings.append(result)

        # Deduplicate by check_id (defensive — each helper fires at most once).
        seen_ids: set = set()
        unique_findings: List[ReviewPolicyFinding] = []
        for finding in findings:
            if finding.check_id not in seen_ids:
                seen_ids.add(finding.check_id)
                unique_findings.append(finding)

        # Compute risk score from unique fired check IDs, capped at 100.
        risk_score = min(
            100,
            sum(_CHECK_WEIGHTS.get(f.check_id, 0) for f in unique_findings),
        )

        return ReviewPolicyResult(findings=unique_findings, risk_score=risk_score)

    def check_many(
        self, policies: List[BranchProtectionPolicy]
    ) -> List[ReviewPolicyResult]:
        """Run checks on each policy in *policies* and return a list of results."""
        return [self.check(p) for p in policies]

    # ------------------------------------------------------------------ #
    # Individual checks (private)                                         #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _check_crp001(
        policy: BranchProtectionPolicy,
    ) -> Optional[ReviewPolicyFinding]:
        """CRP-001 — No required reviewers configured (HIGH, weight 25)."""
        if policy.required_review_count != 0:
            return None
        return ReviewPolicyFinding(
            check_id="CRP-001",
            severity=HIGH,
            branch_name=policy.branch_name,
            repository=policy.repository,
            message=(
                f"Branch '{policy.branch_name}' in '{policy.repository}' has no "
                "required reviewers configured. Any PR can be merged without peer review."
            ),
            recommendation=(
                "Set required_review_count to at least 2 for critical branches "
                "to enforce mandatory peer review before merging."
            ),
        )

    @staticmethod
    def _check_crp002(
        policy: BranchProtectionPolicy,
    ) -> Optional[ReviewPolicyFinding]:
        """CRP-002 — Self-approval allowed (CRITICAL, weight 40)."""
        if not policy.allow_self_approval:
            return None
        return ReviewPolicyFinding(
            check_id="CRP-002",
            severity=CRITICAL,
            branch_name=policy.branch_name,
            repository=policy.repository,
            message=(
                f"Branch '{policy.branch_name}' in '{policy.repository}' allows "
                "PR authors to approve their own changes."
            ),
            recommendation=(
                "Disable self-approval (allow_self_approval=False) so that every "
                "merge requires sign-off from a different developer."
            ),
        )

    @staticmethod
    def _check_crp003(
        policy: BranchProtectionPolicy,
    ) -> Optional[ReviewPolicyFinding]:
        """CRP-003 — Force push allowed to protected branch (HIGH, weight 25)."""
        if not policy.allow_force_push:
            return None
        return ReviewPolicyFinding(
            check_id="CRP-003",
            severity=HIGH,
            branch_name=policy.branch_name,
            repository=policy.repository,
            message=(
                f"Branch '{policy.branch_name}' in '{policy.repository}' permits "
                "force pushes, which can silently rewrite history on a protected branch."
            ),
            recommendation=(
                "Set allow_force_push=False to prevent history rewrites and "
                "preserve the audit trail on protected branches."
            ),
        )

    @staticmethod
    def _check_crp004(
        policy: BranchProtectionPolicy,
    ) -> Optional[ReviewPolicyFinding]:
        """CRP-004 — Stale review dismissal not enabled (MEDIUM, weight 15).

        Only fires when at least one reviewer is required; if no reviewers are
        required, CRP-001 already covers the gap.
        """
        if policy.dismiss_stale_reviews or policy.required_review_count == 0:
            return None
        return ReviewPolicyFinding(
            check_id="CRP-004",
            severity=MEDIUM,
            branch_name=policy.branch_name,
            repository=policy.repository,
            message=(
                f"Branch '{policy.branch_name}' in '{policy.repository}' does not "
                "dismiss stale reviews when new commits are pushed. An approval "
                "granted before a new commit is pushed remains valid, creating an "
                "approval-bypass risk."
            ),
            recommendation=(
                "Enable dismiss_stale_reviews=True so that existing approvals are "
                "invalidated whenever new commits are added to a PR."
            ),
        )

    @staticmethod
    def _check_crp005(
        policy: BranchProtectionPolicy,
    ) -> Optional[ReviewPolicyFinding]:
        """CRP-005 — No required CI/CD status checks (HIGH, weight 20)."""
        if policy.require_status_checks and len(policy.status_checks) > 0:
            return None
        return ReviewPolicyFinding(
            check_id="CRP-005",
            severity=HIGH,
            branch_name=policy.branch_name,
            repository=policy.repository,
            message=(
                f"Branch '{policy.branch_name}' in '{policy.repository}' does not "
                "require passing CI/CD status checks before merging. Code can be "
                "merged without running automated tests or security scans."
            ),
            recommendation=(
                "Set require_status_checks=True and populate status_checks with "
                "at least the CI test suite and a security scanning job."
            ),
        )

    @staticmethod
    def _check_crp006(
        policy: BranchProtectionPolicy,
    ) -> Optional[ReviewPolicyFinding]:
        """CRP-006 — Insufficient minimum reviewer count (HIGH, weight 20).

        Only fires when some reviewers are required but the count is below 2.
        If the count is 0, CRP-001 already fires instead.
        """
        if policy.required_review_count == 0 or policy.required_review_count >= 2:
            return None
        return ReviewPolicyFinding(
            check_id="CRP-006",
            severity=HIGH,
            branch_name=policy.branch_name,
            repository=policy.repository,
            message=(
                f"Branch '{policy.branch_name}' in '{policy.repository}' requires "
                f"only {policy.required_review_count} reviewer(s). A single reviewer "
                "is insufficient for critical branches — collusion or error risk is high."
            ),
            recommendation=(
                "Increase required_review_count to at least 2 to ensure independent "
                "oversight for every merge."
            ),
        )

    @staticmethod
    def _check_crp007(
        policy: BranchProtectionPolicy,
    ) -> Optional[ReviewPolicyFinding]:
        """CRP-007 — Branch is not protected (CRITICAL for critical branches, MEDIUM otherwise).

        Critical branches: main, master, develop, release, production.
        All other branch names receive MEDIUM severity.
        """
        if policy.is_protected:
            return None

        is_critical = policy.branch_name in _CRITICAL_BRANCHES
        severity = CRITICAL if is_critical else MEDIUM

        return ReviewPolicyFinding(
            check_id="CRP-007",
            severity=severity,
            branch_name=policy.branch_name,
            repository=policy.repository,
            message=(
                f"Branch '{policy.branch_name}' in '{policy.repository}' has no "
                "branch protection rules applied. Without protection, any contributor "
                "can push directly, force-push, or delete the branch."
            ),
            recommendation=(
                "Enable branch protection on this branch and configure at minimum: "
                "required reviewers, status checks, and disabled force pushes."
            ),
        )
