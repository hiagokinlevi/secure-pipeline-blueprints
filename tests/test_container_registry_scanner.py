# test_container_registry_scanner.py
# Tests for container_registry_scanner.py — Cyber Port portfolio.
#
# Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
#
# Run with:  python -m pytest tests/test_container_registry_scanner.py -q

import sys
import os

# Allow imports from the shared/analyzers package without installing it.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared", "analyzers"))

from container_registry_scanner import (
    ContainerRegistry,
    CREGFinding,
    CREGResult,
    RegistryAccessPolicy,
    _CHECK_WEIGHTS,
    _extract_arn_account,
    _is_external_principal,
    scan,
    scan_many,
)

# ---------------------------------------------------------------------------
# Shared fixture helpers
# ---------------------------------------------------------------------------

OWNER_ACCOUNT = "111122223333"


def _make_registry(**overrides) -> ContainerRegistry:
    """
    Return a fully-compliant (all-good) registry with optional field overrides.
    Baseline: private, scanning on, immutable tags, signing required,
    lifecycle policy enabled, encrypted, same-account policy only.
    """
    defaults = dict(
        registry_id="reg-001",
        name="my-ecr-repo",
        provider="ecr",
        visibility="private",
        vulnerability_scanning=True,
        tag_immutability=True,
        image_signing_required=True,
        lifecycle_policy_enabled=True,
        encryption_enabled=True,
        account_id=OWNER_ACCOUNT,
        access_policies=[
            RegistryAccessPolicy(
                principal=f"arn:aws:iam::{OWNER_ACCOUNT}:root",
                actions=["ecr:GetDownloadUrlForLayer"],
                effect="Allow",
            )
        ],
    )
    defaults.update(overrides)
    return ContainerRegistry(**defaults)


def _finding_ids(result: CREGResult):
    """Return a set of check_ids from all findings in a CREGResult."""
    return {f.check_id for f in result.findings}


# ===========================================================================
# CREG-001  — Public visibility
# ===========================================================================

class TestCREG001:
    """Tests for CREG-001: registry visibility == 'public'."""

    def test_public_registry_fires(self):
        result = scan(_make_registry(visibility="public"))
        assert "CREG-001" in _finding_ids(result)

    def test_public_registry_severity_is_critical(self):
        result = scan(_make_registry(visibility="public"))
        finding = next(f for f in result.findings if f.check_id == "CREG-001")
        assert finding.severity == "CRITICAL"

    def test_public_registry_weight_is_45(self):
        result = scan(_make_registry(visibility="public"))
        finding = next(f for f in result.findings if f.check_id == "CREG-001")
        assert finding.weight == 45

    def test_private_registry_does_not_fire(self):
        result = scan(_make_registry(visibility="private"))
        assert "CREG-001" not in _finding_ids(result)

    def test_public_registry_is_non_compliant(self):
        result = scan(_make_registry(visibility="public", access_policies=[]))
        assert not result.compliant

    def test_public_registry_risk_score_includes_creg001_weight(self):
        # Only CREG-001 fires when everything else is fine and no policies.
        result = scan(_make_registry(visibility="public", access_policies=[]))
        assert result.risk_score >= _CHECK_WEIGHTS["CREG-001"]

    def test_fully_compliant_registry_no_creg001(self):
        result = scan(_make_registry())
        assert "CREG-001" not in _finding_ids(result)

    def test_public_visibility_string_exact_match(self):
        # "Public" with capital P should NOT fire — case-sensitive check.
        result = scan(_make_registry(visibility="Public", access_policies=[]))
        assert "CREG-001" not in _finding_ids(result)

    def test_empty_visibility_does_not_fire(self):
        result = scan(_make_registry(visibility="", access_policies=[]))
        assert "CREG-001" not in _finding_ids(result)


# ===========================================================================
# CREG-002  — Vulnerability scanning
# ===========================================================================

class TestCREG002:
    """Tests for CREG-002: vulnerability_scanning == False."""

    def test_scanning_disabled_fires(self):
        result = scan(_make_registry(vulnerability_scanning=False))
        assert "CREG-002" in _finding_ids(result)

    def test_scanning_disabled_severity_is_high(self):
        result = scan(_make_registry(vulnerability_scanning=False))
        finding = next(f for f in result.findings if f.check_id == "CREG-002")
        assert finding.severity == "HIGH"

    def test_scanning_disabled_weight_is_25(self):
        result = scan(_make_registry(vulnerability_scanning=False))
        finding = next(f for f in result.findings if f.check_id == "CREG-002")
        assert finding.weight == 25

    def test_scanning_enabled_does_not_fire(self):
        result = scan(_make_registry(vulnerability_scanning=True))
        assert "CREG-002" not in _finding_ids(result)

    def test_scanning_disabled_is_non_compliant(self):
        result = scan(_make_registry(vulnerability_scanning=False, access_policies=[]))
        assert not result.compliant

    def test_scanning_enabled_contributes_zero_to_risk(self):
        # Fully compliant registry — risk score must be 0.
        result = scan(_make_registry())
        assert result.risk_score == 0

    def test_scanning_disabled_finding_has_title(self):
        result = scan(_make_registry(vulnerability_scanning=False))
        finding = next(f for f in result.findings if f.check_id == "CREG-002")
        assert "scanning" in finding.title.lower() or "vulnerability" in finding.title.lower()

    def test_scanning_disabled_finding_has_detail(self):
        result = scan(_make_registry(vulnerability_scanning=False))
        finding = next(f for f in result.findings if f.check_id == "CREG-002")
        assert len(finding.detail) > 10


# ===========================================================================
# CREG-003  — Tag immutability
# ===========================================================================

class TestCREG003:
    """Tests for CREG-003: tag_immutability == False."""

    def test_mutable_tags_fires(self):
        result = scan(_make_registry(tag_immutability=False))
        assert "CREG-003" in _finding_ids(result)

    def test_mutable_tags_severity_is_high(self):
        result = scan(_make_registry(tag_immutability=False))
        finding = next(f for f in result.findings if f.check_id == "CREG-003")
        assert finding.severity == "HIGH"

    def test_mutable_tags_weight_is_20(self):
        result = scan(_make_registry(tag_immutability=False))
        finding = next(f for f in result.findings if f.check_id == "CREG-003")
        assert finding.weight == 20

    def test_immutable_tags_does_not_fire(self):
        result = scan(_make_registry(tag_immutability=True))
        assert "CREG-003" not in _finding_ids(result)

    def test_mutable_tags_non_compliant(self):
        result = scan(_make_registry(tag_immutability=False, access_policies=[]))
        assert not result.compliant

    def test_mutable_tags_finding_mentions_tag(self):
        result = scan(_make_registry(tag_immutability=False))
        finding = next(f for f in result.findings if f.check_id == "CREG-003")
        assert "tag" in finding.title.lower() or "immutab" in finding.title.lower()

    def test_immutable_tags_contributes_zero_risk(self):
        result = scan(_make_registry())
        assert result.risk_score == 0


# ===========================================================================
# CREG-004  — Image signing
# ===========================================================================

class TestCREG004:
    """Tests for CREG-004: image_signing_required == False."""

    def test_signing_not_required_fires(self):
        result = scan(_make_registry(image_signing_required=False))
        assert "CREG-004" in _finding_ids(result)

    def test_signing_not_required_severity_is_high(self):
        result = scan(_make_registry(image_signing_required=False))
        finding = next(f for f in result.findings if f.check_id == "CREG-004")
        assert finding.severity == "HIGH"

    def test_signing_not_required_weight_is_20(self):
        result = scan(_make_registry(image_signing_required=False))
        finding = next(f for f in result.findings if f.check_id == "CREG-004")
        assert finding.weight == 20

    def test_signing_required_does_not_fire(self):
        result = scan(_make_registry(image_signing_required=True))
        assert "CREG-004" not in _finding_ids(result)

    def test_signing_not_required_non_compliant(self):
        result = scan(_make_registry(image_signing_required=False, access_policies=[]))
        assert not result.compliant

    def test_signing_not_required_finding_has_detail(self):
        result = scan(_make_registry(image_signing_required=False))
        finding = next(f for f in result.findings if f.check_id == "CREG-004")
        assert "sign" in finding.detail.lower() or "attest" in finding.detail.lower()

    def test_signing_required_contributes_zero_risk(self):
        result = scan(_make_registry())
        assert result.risk_score == 0


# ===========================================================================
# CREG-005  — Lifecycle / retention policy
# ===========================================================================

class TestCREG005:
    """Tests for CREG-005: lifecycle_policy_enabled == False."""

    def test_no_lifecycle_policy_fires(self):
        result = scan(_make_registry(lifecycle_policy_enabled=False))
        assert "CREG-005" in _finding_ids(result)

    def test_no_lifecycle_policy_severity_is_medium(self):
        result = scan(_make_registry(lifecycle_policy_enabled=False))
        finding = next(f for f in result.findings if f.check_id == "CREG-005")
        assert finding.severity == "MEDIUM"

    def test_no_lifecycle_policy_weight_is_15(self):
        result = scan(_make_registry(lifecycle_policy_enabled=False))
        finding = next(f for f in result.findings if f.check_id == "CREG-005")
        assert finding.weight == 15

    def test_lifecycle_policy_enabled_does_not_fire(self):
        result = scan(_make_registry(lifecycle_policy_enabled=True))
        assert "CREG-005" not in _finding_ids(result)

    def test_no_lifecycle_policy_non_compliant(self):
        result = scan(_make_registry(lifecycle_policy_enabled=False, access_policies=[]))
        assert not result.compliant

    def test_no_lifecycle_policy_finding_mentions_lifecycle(self):
        result = scan(_make_registry(lifecycle_policy_enabled=False))
        finding = next(f for f in result.findings if f.check_id == "CREG-005")
        assert "lifecycle" in finding.title.lower() or "retention" in finding.title.lower()

    def test_lifecycle_policy_enabled_zero_risk_contribution(self):
        result = scan(_make_registry())
        assert result.risk_score == 0


# ===========================================================================
# CREG-006  — Encryption at rest
# ===========================================================================

class TestCREG006:
    """Tests for CREG-006: encryption_enabled == False."""

    def test_encryption_disabled_fires(self):
        result = scan(_make_registry(encryption_enabled=False))
        assert "CREG-006" in _finding_ids(result)

    def test_encryption_disabled_severity_is_high(self):
        result = scan(_make_registry(encryption_enabled=False))
        finding = next(f for f in result.findings if f.check_id == "CREG-006")
        assert finding.severity == "HIGH"

    def test_encryption_disabled_weight_is_25(self):
        result = scan(_make_registry(encryption_enabled=False))
        finding = next(f for f in result.findings if f.check_id == "CREG-006")
        assert finding.weight == 25

    def test_encryption_enabled_does_not_fire(self):
        result = scan(_make_registry(encryption_enabled=True))
        assert "CREG-006" not in _finding_ids(result)

    def test_encryption_disabled_non_compliant(self):
        result = scan(_make_registry(encryption_enabled=False, access_policies=[]))
        assert not result.compliant

    def test_encryption_disabled_finding_mentions_encryption(self):
        result = scan(_make_registry(encryption_enabled=False))
        finding = next(f for f in result.findings if f.check_id == "CREG-006")
        assert "encrypt" in finding.title.lower() or "encrypt" in finding.detail.lower()

    def test_encryption_enabled_zero_risk_contribution(self):
        result = scan(_make_registry())
        assert result.risk_score == 0


# ===========================================================================
# CREG-007  — Access policy: external / untrusted principals
# ===========================================================================

class TestCREG007:
    """Tests for CREG-007: Allow policy with external or untrusted principals."""

    # --- wildcard principal ---

    def test_wildcard_principal_fires(self):
        policy = RegistryAccessPolicy(principal="*", actions=["ecr:*"], effect="Allow")
        result = scan(_make_registry(access_policies=[policy]))
        assert "CREG-007" in _finding_ids(result)

    def test_wildcard_principal_severity_is_high(self):
        policy = RegistryAccessPolicy(principal="*", actions=["ecr:*"], effect="Allow")
        result = scan(_make_registry(access_policies=[policy]))
        finding = next(f for f in result.findings if f.check_id == "CREG-007")
        assert finding.severity == "HIGH"

    def test_wildcard_principal_weight_is_25(self):
        policy = RegistryAccessPolicy(principal="*", actions=["ecr:*"], effect="Allow")
        result = scan(_make_registry(access_policies=[policy]))
        finding = next(f for f in result.findings if f.check_id == "CREG-007")
        assert finding.weight == 25

    # --- "public" and "anonymous" principals ---

    def test_public_principal_fires(self):
        policy = RegistryAccessPolicy(principal="public", actions=["ecr:Pull"], effect="Allow")
        result = scan(_make_registry(access_policies=[policy]))
        assert "CREG-007" in _finding_ids(result)

    def test_anonymous_principal_fires(self):
        policy = RegistryAccessPolicy(principal="anonymous", actions=["ecr:Pull"], effect="Allow")
        result = scan(_make_registry(access_policies=[policy]))
        assert "CREG-007" in _finding_ids(result)

    def test_uppercase_anonymous_principal_fires(self):
        policy = RegistryAccessPolicy(principal="Anonymous", actions=["ecr:Pull"], effect="Allow")
        result = scan(_make_registry(access_policies=[policy]))
        assert "CREG-007" in _finding_ids(result)

    # --- cross-account ARN principals ---

    def test_cross_account_arn_fires(self):
        other_account = "999988887777"
        policy = RegistryAccessPolicy(
            principal=f"arn:aws:iam::{other_account}:root",
            actions=["ecr:GetDownloadUrlForLayer"],
            effect="Allow",
        )
        result = scan(_make_registry(access_policies=[policy]))
        assert "CREG-007" in _finding_ids(result)

    def test_same_account_arn_does_not_fire(self):
        policy = RegistryAccessPolicy(
            principal=f"arn:aws:iam::{OWNER_ACCOUNT}:root",
            actions=["ecr:GetDownloadUrlForLayer"],
            effect="Allow",
        )
        result = scan(_make_registry(access_policies=[policy]))
        assert "CREG-007" not in _finding_ids(result)

    def test_same_account_role_arn_does_not_fire(self):
        policy = RegistryAccessPolicy(
            principal=f"arn:aws:iam::{OWNER_ACCOUNT}:role/my-deploy-role",
            actions=["ecr:BatchGetImage"],
            effect="Allow",
        )
        result = scan(_make_registry(access_policies=[policy]))
        assert "CREG-007" not in _finding_ids(result)

    def test_cross_account_role_arn_fires(self):
        policy = RegistryAccessPolicy(
            principal="arn:aws:iam::000011112222:role/external-ci",
            actions=["ecr:BatchGetImage"],
            effect="Allow",
        )
        result = scan(_make_registry(access_policies=[policy]))
        assert "CREG-007" in _finding_ids(result)

    # --- Deny policies must NOT fire ---

    def test_wildcard_deny_policy_does_not_fire(self):
        policy = RegistryAccessPolicy(principal="*", actions=["ecr:*"], effect="Deny")
        result = scan(_make_registry(access_policies=[policy]))
        assert "CREG-007" not in _finding_ids(result)

    def test_cross_account_deny_policy_does_not_fire(self):
        policy = RegistryAccessPolicy(
            principal="arn:aws:iam::999988887777:root",
            actions=["ecr:*"],
            effect="Deny",
        )
        result = scan(_make_registry(access_policies=[policy]))
        assert "CREG-007" not in _finding_ids(result)

    # --- Multiple violating principals: multiple findings, weight counted once ---

    def test_two_violating_principals_produce_two_findings(self):
        policies = [
            RegistryAccessPolicy(principal="*", actions=["ecr:Pull"], effect="Allow"),
            RegistryAccessPolicy(
                principal="arn:aws:iam::999988887777:root",
                actions=["ecr:Push"],
                effect="Allow",
            ),
        ]
        result = scan(_make_registry(access_policies=policies))
        creg007_findings = [f for f in result.findings if f.check_id == "CREG-007"]
        assert len(creg007_findings) == 2

    def test_two_violating_principals_weight_counted_once(self):
        policies = [
            RegistryAccessPolicy(principal="*", actions=["ecr:Pull"], effect="Allow"),
            RegistryAccessPolicy(
                principal="arn:aws:iam::999988887777:root",
                actions=["ecr:Push"],
                effect="Allow",
            ),
        ]
        # All other checks pass — only CREG-007 should contribute weight.
        result = scan(
            _make_registry(
                access_policies=policies,
                visibility="private",
                vulnerability_scanning=True,
                tag_immutability=True,
                image_signing_required=True,
                lifecycle_policy_enabled=True,
                encryption_enabled=True,
            )
        )
        # Risk score must equal CREG-007 weight (25), not 50.
        assert result.risk_score == _CHECK_WEIGHTS["CREG-007"]

    def test_no_access_policies_does_not_fire(self):
        result = scan(_make_registry(access_policies=[]))
        assert "CREG-007" not in _finding_ids(result)

    def test_only_allow_same_account_does_not_fire(self):
        policies = [
            RegistryAccessPolicy(
                principal=f"arn:aws:iam::{OWNER_ACCOUNT}:role/ci",
                actions=["ecr:Push"],
                effect="Allow",
            ),
            RegistryAccessPolicy(
                principal=f"arn:aws:iam::{OWNER_ACCOUNT}:role/deploy",
                actions=["ecr:Pull"],
                effect="Allow",
            ),
        ]
        result = scan(_make_registry(access_policies=policies))
        assert "CREG-007" not in _finding_ids(result)

    def test_principal_detail_contains_violating_principal(self):
        other_account = "999988887777"
        policy = RegistryAccessPolicy(
            principal=f"arn:aws:iam::{other_account}:root",
            actions=["ecr:*"],
            effect="Allow",
        )
        result = scan(_make_registry(access_policies=[policy]))
        finding = next(f for f in result.findings if f.check_id == "CREG-007")
        assert other_account in finding.detail

    def test_public_principal_upper_does_not_bypass(self):
        policy = RegistryAccessPolicy(principal="PUBLIC", actions=["ecr:Pull"], effect="Allow")
        result = scan(_make_registry(access_policies=[policy]))
        assert "CREG-007" in _finding_ids(result)


# ===========================================================================
# Risk score calculation
# ===========================================================================

class TestRiskScore:
    """Tests for risk_score computation."""

    def test_fully_compliant_score_is_zero(self):
        result = scan(_make_registry())
        assert result.risk_score == 0

    def test_compliant_flag_true_when_score_zero(self):
        result = scan(_make_registry())
        assert result.compliant is True

    def test_compliant_flag_false_when_score_nonzero(self):
        result = scan(_make_registry(visibility="public", access_policies=[]))
        assert result.compliant is False

    def test_all_checks_fire_score_capped_at_100(self):
        """
        Fire CREG-001 (45) + CREG-002 (25) + CREG-003 (20) + CREG-004 (20)
        + CREG-005 (15) + CREG-006 (25) + CREG-007 (25) = 175 -> capped at 100.
        """
        bad_policy = RegistryAccessPolicy(principal="*", actions=["ecr:*"], effect="Allow")
        registry = _make_registry(
            visibility="public",
            vulnerability_scanning=False,
            tag_immutability=False,
            image_signing_required=False,
            lifecycle_policy_enabled=False,
            encryption_enabled=False,
            access_policies=[bad_policy],
        )
        result = scan(registry)
        assert result.risk_score == 100

    def test_single_check_creg001_score(self):
        result = scan(_make_registry(visibility="public", access_policies=[]))
        assert result.risk_score == _CHECK_WEIGHTS["CREG-001"]

    def test_single_check_creg002_score(self):
        result = scan(_make_registry(vulnerability_scanning=False, access_policies=[]))
        assert result.risk_score == _CHECK_WEIGHTS["CREG-002"]

    def test_single_check_creg003_score(self):
        result = scan(_make_registry(tag_immutability=False, access_policies=[]))
        assert result.risk_score == _CHECK_WEIGHTS["CREG-003"]

    def test_single_check_creg004_score(self):
        result = scan(_make_registry(image_signing_required=False, access_policies=[]))
        assert result.risk_score == _CHECK_WEIGHTS["CREG-004"]

    def test_single_check_creg005_score(self):
        result = scan(_make_registry(lifecycle_policy_enabled=False, access_policies=[]))
        assert result.risk_score == _CHECK_WEIGHTS["CREG-005"]

    def test_single_check_creg006_score(self):
        result = scan(_make_registry(encryption_enabled=False, access_policies=[]))
        assert result.risk_score == _CHECK_WEIGHTS["CREG-006"]

    def test_single_check_creg007_score(self):
        bad_policy = RegistryAccessPolicy(principal="*", actions=["ecr:*"], effect="Allow")
        result = scan(
            _make_registry(
                access_policies=[bad_policy],
                visibility="private",
                vulnerability_scanning=True,
                tag_immutability=True,
                image_signing_required=True,
                lifecycle_policy_enabled=True,
                encryption_enabled=True,
            )
        )
        assert result.risk_score == _CHECK_WEIGHTS["CREG-007"]

    def test_two_checks_score_is_additive(self):
        result = scan(
            _make_registry(
                vulnerability_scanning=False,
                tag_immutability=False,
                access_policies=[],
            )
        )
        expected = _CHECK_WEIGHTS["CREG-002"] + _CHECK_WEIGHTS["CREG-003"]
        assert result.risk_score == expected

    def test_score_never_exceeds_100(self):
        # CREG-001 (45) + CREG-002 (25) + CREG-006 (25) = 95; adding CREG-003 (20) = 115 -> 100.
        result = scan(
            _make_registry(
                visibility="public",
                vulnerability_scanning=False,
                tag_immutability=False,
                encryption_enabled=False,
                access_policies=[],
            )
        )
        assert result.risk_score <= 100


# ===========================================================================
# CREGResult helpers: to_dict, summary, by_severity
# ===========================================================================

class TestCREGResultHelpers:
    """Tests for CREGResult.to_dict(), .summary(), and .by_severity()."""

    def test_to_dict_contains_registry_name(self):
        result = scan(_make_registry())
        d = result.to_dict()
        assert d["registry_name"] == "my-ecr-repo"

    def test_to_dict_contains_provider(self):
        result = scan(_make_registry())
        d = result.to_dict()
        assert d["provider"] == "ecr"

    def test_to_dict_contains_risk_score(self):
        result = scan(_make_registry())
        d = result.to_dict()
        assert "risk_score" in d

    def test_to_dict_contains_compliant(self):
        result = scan(_make_registry())
        d = result.to_dict()
        assert "compliant" in d

    def test_to_dict_findings_is_list(self):
        result = scan(_make_registry(vulnerability_scanning=False))
        d = result.to_dict()
        assert isinstance(d["findings"], list)

    def test_to_dict_finding_has_check_id(self):
        result = scan(_make_registry(vulnerability_scanning=False))
        d = result.to_dict()
        finding_ids = [f["check_id"] for f in d["findings"]]
        assert "CREG-002" in finding_ids

    def test_to_dict_finding_has_severity(self):
        result = scan(_make_registry(vulnerability_scanning=False))
        d = result.to_dict()
        creg002 = next(f for f in d["findings"] if f["check_id"] == "CREG-002")
        assert creg002["severity"] == "HIGH"

    def test_to_dict_finding_has_weight(self):
        result = scan(_make_registry(vulnerability_scanning=False))
        d = result.to_dict()
        creg002 = next(f for f in d["findings"] if f["check_id"] == "CREG-002")
        assert creg002["weight"] == 25

    def test_to_dict_compliant_true_for_clean_registry(self):
        result = scan(_make_registry())
        assert result.to_dict()["compliant"] is True

    def test_summary_contains_registry_name(self):
        result = scan(_make_registry())
        assert "my-ecr-repo" in result.summary()

    def test_summary_contains_provider(self):
        result = scan(_make_registry())
        assert "ecr" in result.summary()

    def test_summary_contains_risk_score(self):
        result = scan(_make_registry())
        assert "risk_score" in result.summary() or "0" in result.summary()

    def test_summary_compliant_label(self):
        result = scan(_make_registry())
        assert "COMPLIANT" in result.summary()

    def test_summary_non_compliant_label(self):
        result = scan(_make_registry(vulnerability_scanning=False, access_policies=[]))
        assert "NON-COMPLIANT" in result.summary()

    def test_by_severity_returns_dict(self):
        result = scan(_make_registry(vulnerability_scanning=False))
        assert isinstance(result.by_severity(), dict)

    def test_by_severity_groups_findings_correctly(self):
        result = scan(
            _make_registry(
                vulnerability_scanning=False,   # HIGH
                lifecycle_policy_enabled=False,  # MEDIUM
                access_policies=[],
            )
        )
        groups = result.by_severity()
        assert "HIGH" in groups
        assert "MEDIUM" in groups
        assert any(f.check_id == "CREG-002" for f in groups["HIGH"])
        assert any(f.check_id == "CREG-005" for f in groups["MEDIUM"])

    def test_by_severity_empty_on_compliant_registry(self):
        result = scan(_make_registry())
        groups = result.by_severity()
        assert groups == {}

    def test_by_severity_critical_label(self):
        result = scan(_make_registry(visibility="public", access_policies=[]))
        groups = result.by_severity()
        assert "CRITICAL" in groups


# ===========================================================================
# scan_many
# ===========================================================================

class TestScanMany:
    """Tests for the scan_many() bulk scanning function."""

    def test_scan_many_returns_list(self):
        results = scan_many([_make_registry(), _make_registry(name="repo-2")])
        assert isinstance(results, list)

    def test_scan_many_length_matches_input(self):
        registries = [_make_registry(name=f"repo-{i}") for i in range(5)]
        results = scan_many(registries)
        assert len(results) == 5

    def test_scan_many_empty_input(self):
        results = scan_many([])
        assert results == []

    def test_scan_many_preserves_order(self):
        registries = [
            _make_registry(name="alpha", vulnerability_scanning=False),
            _make_registry(name="beta"),
        ]
        results = scan_many(registries)
        assert results[0].registry_name == "alpha"
        assert results[1].registry_name == "beta"

    def test_scan_many_first_has_finding(self):
        registries = [
            _make_registry(name="bad", vulnerability_scanning=False),
            _make_registry(name="good"),
        ]
        results = scan_many(registries)
        assert "CREG-002" in _finding_ids(results[0])
        assert "CREG-002" not in _finding_ids(results[1])

    def test_scan_many_all_compliant(self):
        registries = [_make_registry(name=f"clean-{i}") for i in range(3)]
        results = scan_many(registries)
        assert all(r.compliant for r in results)

    def test_scan_many_none_compliant(self):
        registries = [
            _make_registry(name=f"bad-{i}", vulnerability_scanning=False, access_policies=[])
            for i in range(3)
        ]
        results = scan_many(registries)
        assert all(not r.compliant for r in results)


# ===========================================================================
# Internal helpers: _extract_arn_account, _is_external_principal
# ===========================================================================

class TestExtractArnAccount:
    """Tests for the _extract_arn_account internal helper."""

    def test_valid_iam_arn_root(self):
        assert _extract_arn_account(f"arn:aws:iam::{OWNER_ACCOUNT}:root") == OWNER_ACCOUNT

    def test_valid_iam_arn_role(self):
        assert _extract_arn_account(f"arn:aws:iam::{OWNER_ACCOUNT}:role/my-role") == OWNER_ACCOUNT

    def test_valid_iam_arn_user(self):
        assert _extract_arn_account(f"arn:aws:iam::{OWNER_ACCOUNT}:user/alice") == OWNER_ACCOUNT

    def test_wildcard_returns_none(self):
        assert _extract_arn_account("*") is None

    def test_public_returns_none(self):
        assert _extract_arn_account("public") is None

    def test_plain_account_id_returns_none(self):
        assert _extract_arn_account(OWNER_ACCOUNT) is None

    def test_partial_arn_returns_none(self):
        assert _extract_arn_account("arn:aws:iam::") is None

    def test_different_account_extracted(self):
        assert _extract_arn_account("arn:aws:iam::999988887777:root") == "999988887777"


class TestIsExternalPrincipal:
    """Tests for the _is_external_principal internal helper."""

    def test_wildcard_is_external(self):
        assert _is_external_principal("*", OWNER_ACCOUNT) is True

    def test_public_is_external(self):
        assert _is_external_principal("public", OWNER_ACCOUNT) is True

    def test_anonymous_is_external(self):
        assert _is_external_principal("anonymous", OWNER_ACCOUNT) is True

    def test_uppercase_anonymous_is_external(self):
        assert _is_external_principal("Anonymous", OWNER_ACCOUNT) is True

    def test_same_account_arn_is_not_external(self):
        assert _is_external_principal(f"arn:aws:iam::{OWNER_ACCOUNT}:root", OWNER_ACCOUNT) is False

    def test_different_account_arn_is_external(self):
        assert _is_external_principal("arn:aws:iam::999988887777:root", OWNER_ACCOUNT) is True

    def test_plain_account_id_matching_owner_is_not_external(self):
        assert _is_external_principal(OWNER_ACCOUNT, OWNER_ACCOUNT) is False

    def test_self_token_is_not_external(self):
        assert _is_external_principal("self", OWNER_ACCOUNT) is False

    def test_internal_token_is_not_external(self):
        assert _is_external_principal("internal", OWNER_ACCOUNT) is False

    def test_unrelated_string_is_external(self):
        assert _is_external_principal("some-random-service", OWNER_ACCOUNT) is True


# ===========================================================================
# Edge cases and provider variety
# ===========================================================================

class TestEdgeCases:
    """Miscellaneous edge-case and provider-variety tests."""

    def test_ghcr_provider_public_fires(self):
        result = scan(_make_registry(provider="ghcr", visibility="public", access_policies=[]))
        assert "CREG-001" in _finding_ids(result)

    def test_dockerhub_provider_all_bad_fires_all_checks(self):
        bad_policy = RegistryAccessPolicy(principal="*", actions=["pull"], effect="Allow")
        registry = _make_registry(
            provider="dockerhub",
            visibility="public",
            vulnerability_scanning=False,
            tag_immutability=False,
            image_signing_required=False,
            lifecycle_policy_enabled=False,
            encryption_enabled=False,
            access_policies=[bad_policy],
        )
        result = scan(registry)
        fired = _finding_ids(result)
        for check_id in _CHECK_WEIGHTS:
            assert check_id in fired, f"{check_id} did not fire"

    def test_gcr_provider_clean(self):
        result = scan(_make_registry(provider="gcr"))
        assert result.compliant is True

    def test_acr_provider_clean(self):
        result = scan(_make_registry(provider="acr"))
        assert result.compliant is True

    def test_generic_provider_clean(self):
        result = scan(_make_registry(provider="generic"))
        assert result.compliant is True

    def test_registry_name_in_result(self):
        result = scan(_make_registry(name="my-special-repo"))
        assert result.registry_name == "my-special-repo"

    def test_provider_in_result(self):
        result = scan(_make_registry(provider="ghcr"))
        assert result.provider == "ghcr"

    def test_findings_are_creg_finding_instances(self):
        result = scan(_make_registry(vulnerability_scanning=False))
        for finding in result.findings:
            assert isinstance(finding, CREGFinding)

    def test_multiple_checks_finding_count(self):
        result = scan(
            _make_registry(
                vulnerability_scanning=False,
                tag_immutability=False,
                lifecycle_policy_enabled=False,
                access_policies=[],
            )
        )
        # Exactly 3 checks fire.
        assert len(result.findings) == 3

    def test_check_weights_dict_has_all_seven_ids(self):
        for i in range(1, 8):
            check_id = f"CREG-{i:03d}"
            assert check_id in _CHECK_WEIGHTS

    def test_no_findings_list_is_empty(self):
        result = scan(_make_registry())
        assert result.findings == []

    def test_creg007_deny_mixed_with_allow_external(self):
        """Deny for external + Allow for external -> CREG-007 fires once for Allow."""
        policies = [
            RegistryAccessPolicy(principal="*", actions=["ecr:Push"], effect="Deny"),
            RegistryAccessPolicy(principal="*", actions=["ecr:Pull"], effect="Allow"),
        ]
        result = scan(_make_registry(access_policies=policies))
        creg007_findings = [f for f in result.findings if f.check_id == "CREG-007"]
        # Only the Allow policy fires.
        assert len(creg007_findings) == 1

    def test_creg007_allow_same_and_cross_account(self):
        """One same-account Allow + one cross-account Allow -> exactly one CREG-007 finding."""
        policies = [
            RegistryAccessPolicy(
                principal=f"arn:aws:iam::{OWNER_ACCOUNT}:role/ci",
                actions=["ecr:Push"],
                effect="Allow",
            ),
            RegistryAccessPolicy(
                principal="arn:aws:iam::999988887777:role/external",
                actions=["ecr:Pull"],
                effect="Allow",
            ),
        ]
        result = scan(_make_registry(access_policies=policies))
        creg007_findings = [f for f in result.findings if f.check_id == "CREG-007"]
        assert len(creg007_findings) == 1

    def test_scan_result_is_creg_result_instance(self):
        assert isinstance(scan(_make_registry()), CREGResult)
