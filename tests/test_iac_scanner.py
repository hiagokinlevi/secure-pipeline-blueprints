# test_iac_scanner.py — Comprehensive test suite for IaCScanner
# Part of Cyber Port · tests/
#
# Copyright 2024 Hiago Kin Levi
# Licensed under CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/
#
# Run with:
#   python3 -m pytest tests/test_iac_scanner.py --override-ini="addopts=" -q

from __future__ import annotations

import sys
import os

# Ensure the package root is on the path so we can import from shared/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from shared.analyzers.iac_scanner import (
    IaCFinding,
    IaCResource,
    IaCResult,
    IaCScanner,
    _CHECK_WEIGHTS,
)

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

SCANNER = IaCScanner()


def _make_s3(name: str, config: dict) -> IaCResource:
    return IaCResource(resource_type="aws_s3_bucket", resource_name=name, config=config)


def _make_sg(name: str, config: dict) -> IaCResource:
    return IaCResource(resource_type="aws_security_group", resource_name=name, config=config)


def _make_gcp_fw(name: str, config: dict) -> IaCResource:
    return IaCResource(resource_type="google_compute_firewall", resource_name=name, config=config)


def _make_azure_storage(name: str, config: dict) -> IaCResource:
    return IaCResource(
        resource_type="azurerm_storage_account", resource_name=name, config=config
    )


def _make_db(name: str, config: dict) -> IaCResource:
    return IaCResource(resource_type="aws_db_instance", resource_name=name, config=config)


def _make_ebs(name: str, config: dict) -> IaCResource:
    return IaCResource(resource_type="aws_ebs_volume", resource_name=name, config=config)


def _make_ec2(name: str, config: dict) -> IaCResource:
    return IaCResource(resource_type="aws_instance", resource_name=name, config=config)


def _make_iam_policy(name: str, config: dict) -> IaCResource:
    return IaCResource(resource_type="aws_iam_policy", resource_name=name, config=config)


def _make_iam_role_policy(name: str, config: dict) -> IaCResource:
    return IaCResource(resource_type="aws_iam_role_policy", resource_name=name, config=config)


def _make_iam_role(name: str, config: dict) -> IaCResource:
    return IaCResource(resource_type="aws_iam_role", resource_name=name, config=config)


def _full_tags() -> dict:
    """Minimal tag set that satisfies IAC-007."""
    return {"Environment": "prod", "Owner": "security", "Project": "k1n"}


# ---------------------------------------------------------------------------
# 1. Clean resources — no findings, risk_score = 0
# ---------------------------------------------------------------------------

class TestCleanResources:
    def test_secure_s3_bucket_no_findings(self):
        r = _make_s3("secure-bucket", {
            "acl": "private",
            "block_public_acls": True,
            "block_public_policy": True,
            "server_side_encryption_configuration": {"rule": {}},
            "tags": _full_tags(),
        })
        result = SCANNER.scan([r])
        assert result.findings == []
        assert result.risk_score == 0

    def test_secure_sg_no_findings(self):
        r = _make_sg("restricted-sg", {
            "ingress": [{"cidr_blocks": ["10.0.0.0/8"], "from_port": 443, "to_port": 443}],
            "tags": _full_tags(),
        })
        result = SCANNER.scan([r])
        assert result.findings == []
        assert result.risk_score == 0

    def test_secure_db_no_findings(self):
        r = _make_db("prod-db", {
            "storage_encrypted": True,
            "tags": _full_tags(),
        })
        result = SCANNER.scan([r])
        assert result.findings == []
        assert result.risk_score == 0

    def test_empty_resource_list(self):
        result = SCANNER.scan([])
        assert result.findings == []
        assert result.risk_score == 0

    def test_non_aws_resource_no_tag_check(self):
        # azurerm resources are not subject to IAC-007
        r = _make_azure_storage("az-store", {
            "allow_blob_public_access": False,
            "enable_https_traffic_only": True,
        })
        result = SCANNER.scan([r])
        assert result.findings == []
        assert result.risk_score == 0

    def test_clean_gcp_firewall_egress(self):
        # EGRESS direction should not trigger IAC-002
        r = _make_gcp_fw("egress-fw", {
            "direction": "EGRESS",
            "source_ranges": ["0.0.0.0/0"],
            "allowed": [{"protocol": "tcp", "ports": ["443"]}],
        })
        result = SCANNER.scan([r])
        # IAC-006 should not fire because ports list is non-empty
        iac002 = [f for f in result.findings if f.check_id == "IAC-002"]
        assert iac002 == []


# ---------------------------------------------------------------------------
# 2. IAC-001 — Public storage
# ---------------------------------------------------------------------------

class TestIAC001:
    def test_s3_public_read_acl_triggers(self):
        r = _make_s3("pub-bucket", {"acl": "public-read", "tags": _full_tags()})
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-001" in ids

    def test_s3_public_read_write_acl_triggers(self):
        r = _make_s3("pub-bucket-rw", {"acl": "public-read-write", "tags": _full_tags()})
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-001" in ids

    def test_s3_block_public_acls_false_triggers(self):
        r = _make_s3("bpa-off", {"block_public_acls": False, "tags": _full_tags()})
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-001" in ids

    def test_s3_block_public_policy_false_triggers(self):
        r = _make_s3("bpp-off", {"block_public_policy": False, "tags": _full_tags()})
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-001" in ids

    def test_s3_private_acl_no_trigger(self):
        r = _make_s3("private-bucket", {
            "acl": "private",
            "block_public_acls": True,
            "block_public_policy": True,
            "server_side_encryption_configuration": {},
            "tags": _full_tags(),
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-001" not in ids

    def test_s3_no_acl_key_no_trigger_for_iac001(self):
        # No acl key at all, blocks set to True — should not trigger IAC-001
        r = _make_s3("no-acl", {
            "block_public_acls": True,
            "block_public_policy": True,
            "server_side_encryption_configuration": {},
            "tags": _full_tags(),
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-001" not in ids

    def test_azure_allow_blob_public_access_true_triggers(self):
        r = _make_azure_storage("az-pub", {"allow_blob_public_access": True})
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-001" in ids

    def test_azure_allow_blob_public_access_false_no_trigger(self):
        r = _make_azure_storage("az-priv", {
            "allow_blob_public_access": False,
            "enable_https_traffic_only": True,
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-001" not in ids

    def test_finding_severity_is_critical(self):
        r = _make_s3("crit-bucket", {"acl": "public-read", "tags": _full_tags()})
        result = SCANNER.scan([r])
        finding = next(f for f in result.findings if f.check_id == "IAC-001")
        assert finding.severity == "CRITICAL"

    def test_finding_resource_fields_populated(self):
        r = _make_s3("field-test", {"acl": "public-read", "tags": _full_tags()})
        result = SCANNER.scan([r])
        finding = next(f for f in result.findings if f.check_id == "IAC-001")
        assert finding.resource_type == "aws_s3_bucket"
        assert finding.resource_name == "field-test"
        assert len(finding.message) > 0
        assert len(finding.recommendation) > 0


# ---------------------------------------------------------------------------
# 3. IAC-002 — Open inbound
# ---------------------------------------------------------------------------

class TestIAC002:
    def test_sg_ingress_ipv4_any_triggers(self):
        r = _make_sg("open-sg", {
            "ingress": [{"cidr_blocks": ["0.0.0.0/0"], "from_port": 0, "to_port": 65535}],
            "tags": _full_tags(),
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-002" in ids

    def test_sg_ingress_ipv6_any_triggers(self):
        r = _make_sg("ipv6-open-sg", {
            "ingress": [{"cidr_blocks": ["::/0"], "from_port": 22, "to_port": 22}],
            "tags": _full_tags(),
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-002" in ids

    def test_sg_ingress_restricted_no_trigger(self):
        r = _make_sg("restrict-sg", {
            "ingress": [{"cidr_blocks": ["10.0.0.0/8"], "from_port": 443, "to_port": 443}],
            "tags": _full_tags(),
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-002" not in ids

    def test_sg_no_ingress_key_no_trigger(self):
        r = _make_sg("no-ingress-sg", {"egress": [], "tags": _full_tags()})
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-002" not in ids

    def test_gcp_fw_ingress_any_triggers(self):
        r = _make_gcp_fw("open-fw", {
            "direction": "INGRESS",
            "source_ranges": ["0.0.0.0/0"],
            "allowed": [{"protocol": "tcp", "ports": ["22"]}],
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-002" in ids

    def test_gcp_fw_ingress_restricted_no_trigger(self):
        r = _make_gcp_fw("safe-fw", {
            "direction": "INGRESS",
            "source_ranges": ["192.168.1.0/24"],
            "allowed": [{"protocol": "tcp", "ports": ["443"]}],
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-002" not in ids

    def test_gcp_fw_egress_with_any_no_trigger(self):
        # EGRESS direction should NOT trigger IAC-002 even with 0.0.0.0/0
        r = _make_gcp_fw("egress-any", {
            "direction": "EGRESS",
            "source_ranges": ["0.0.0.0/0"],
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-002" not in ids

    def test_sg_multiple_ingress_one_open_triggers(self):
        r = _make_sg("mixed-sg", {
            "ingress": [
                {"cidr_blocks": ["10.0.0.0/8"], "from_port": 443, "to_port": 443},
                {"cidr_blocks": ["0.0.0.0/0"], "from_port": 80, "to_port": 80},
            ],
            "tags": _full_tags(),
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-002" in ids

    def test_finding_severity_is_critical(self):
        r = _make_sg("sev-sg", {
            "ingress": [{"cidr_blocks": ["0.0.0.0/0"]}],
            "tags": _full_tags(),
        })
        result = SCANNER.scan([r])
        finding = next(f for f in result.findings if f.check_id == "IAC-002")
        assert finding.severity == "CRITICAL"


# ---------------------------------------------------------------------------
# 4. IAC-003 — Unencrypted storage / database
# ---------------------------------------------------------------------------

class TestIAC003:
    def test_s3_no_sse_config_triggers(self):
        r = _make_s3("unencrypted-s3", {"tags": _full_tags()})
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-003" in ids

    def test_s3_with_sse_config_no_trigger(self):
        r = _make_s3("encrypted-s3", {
            "server_side_encryption_configuration": {"rule": {"apply_server_side_encryption_by_default": {}}},
            "tags": _full_tags(),
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-003" not in ids

    def test_db_storage_encrypted_false_triggers(self):
        r = _make_db("unenc-db", {"storage_encrypted": False, "tags": _full_tags()})
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-003" in ids

    def test_db_storage_encrypted_absent_triggers(self):
        r = _make_db("missing-enc-db", {"tags": _full_tags()})
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-003" in ids

    def test_db_storage_encrypted_true_no_trigger(self):
        r = _make_db("enc-db", {"storage_encrypted": True, "tags": _full_tags()})
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-003" not in ids

    def test_ebs_encrypted_false_triggers(self):
        r = _make_ebs("unenc-ebs", {"encrypted": False, "tags": _full_tags()})
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-003" in ids

    def test_ebs_encrypted_absent_triggers(self):
        r = _make_ebs("no-enc-flag-ebs", {"tags": _full_tags()})
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-003" in ids

    def test_ebs_encrypted_true_no_trigger(self):
        r = _make_ebs("enc-ebs", {"encrypted": True, "tags": _full_tags()})
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-003" not in ids

    def test_ec2_instance_encrypted_false_triggers(self):
        r = _make_ec2("unenc-ec2", {"encrypted": False, "tags": _full_tags()})
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-003" in ids

    def test_ec2_instance_encrypted_absent_triggers(self):
        r = _make_ec2("no-enc-ec2", {"tags": _full_tags()})
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-003" in ids

    def test_ec2_instance_encrypted_true_no_trigger(self):
        r = _make_ec2("enc-ec2", {"encrypted": True, "tags": _full_tags()})
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-003" not in ids

    def test_azure_https_only_false_triggers(self):
        r = _make_azure_storage("az-http", {
            "allow_blob_public_access": False,
            "enable_https_traffic_only": False,
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-003" in ids

    def test_azure_https_only_true_no_trigger(self):
        r = _make_azure_storage("az-https", {
            "allow_blob_public_access": False,
            "enable_https_traffic_only": True,
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-003" not in ids

    def test_finding_severity_is_high(self):
        r = _make_db("sev-db", {"storage_encrypted": False, "tags": _full_tags()})
        result = SCANNER.scan([r])
        finding = next(f for f in result.findings if f.check_id == "IAC-003")
        assert finding.severity == "HIGH"


# ---------------------------------------------------------------------------
# 5. IAC-004 — Hardcoded credentials
# ---------------------------------------------------------------------------

class TestIAC004:
    def test_password_key_long_value_triggers(self):
        r = IaCResource(
            resource_type="aws_db_instance",
            resource_name="cred-db",
            config={"password": "SuperSecret123!", "tags": _full_tags()},
        )
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-004" in ids

    def test_secret_key_long_value_triggers(self):
        r = IaCResource(
            resource_type="aws_lambda_function",
            resource_name="fn",
            config={"secret": "MySuperLongSecret", "tags": _full_tags()},
        )
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-004" in ids

    def test_access_key_long_value_triggers(self):
        r = IaCResource(
            resource_type="aws_iam_user",
            resource_name="user",
            config={"access_key": "AKIAIOSFODNN7EXAMPLE", "tags": _full_tags()},
        )
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-004" in ids

    def test_secret_key_name_long_value_triggers(self):
        r = IaCResource(
            resource_type="aws_iam_user",
            resource_name="user2",
            config={"secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "tags": _full_tags()},
        )
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-004" in ids

    def test_api_key_long_value_triggers(self):
        r = IaCResource(
            resource_type="aws_api_gateway_api_key",
            resource_name="api-key-res",
            config={"api_key": "very-long-api-key-value-here", "tags": _full_tags()},
        )
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-004" in ids

    def test_short_value_6_chars_no_trigger(self):
        # Value of exactly 6 chars should NOT trigger
        r = IaCResource(
            resource_type="aws_db_instance",
            resource_name="short-pw",
            config={"password": "abc123", "tags": _full_tags()},
        )
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-004" not in ids

    def test_short_value_under_6_chars_no_trigger(self):
        r = IaCResource(
            resource_type="aws_db_instance",
            resource_name="empty-pw",
            config={"password": "abc", "tags": _full_tags()},
        )
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-004" not in ids

    def test_empty_string_value_no_trigger(self):
        r = IaCResource(
            resource_type="aws_db_instance",
            resource_name="blank-pw",
            config={"password": "", "tags": _full_tags()},
        )
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-004" not in ids

    def test_non_string_value_no_trigger(self):
        r = IaCResource(
            resource_type="aws_db_instance",
            resource_name="int-pw",
            config={"password": 12345678, "tags": _full_tags()},
        )
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-004" not in ids

    def test_no_secret_keys_no_trigger(self):
        r = IaCResource(
            resource_type="aws_db_instance",
            resource_name="clean-db",
            config={"engine": "mysql", "tags": _full_tags()},
        )
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-004" not in ids

    def test_finding_severity_is_critical(self):
        r = IaCResource(
            resource_type="aws_db_instance",
            resource_name="sev-cred",
            config={"password": "ExposedPassword99!", "tags": _full_tags()},
        )
        result = SCANNER.scan([r])
        finding = next(f for f in result.findings if f.check_id == "IAC-004")
        assert finding.severity == "CRITICAL"

    def test_finding_message_contains_key_name(self):
        r = IaCResource(
            resource_type="aws_db_instance",
            resource_name="key-in-msg",
            config={"api_key": "supersecretapikey9999", "tags": _full_tags()},
        )
        result = SCANNER.scan([r])
        finding = next(f for f in result.findings if f.check_id == "IAC-004")
        assert "api_key" in finding.message


# ---------------------------------------------------------------------------
# 6. IAC-005 — Admin access without MFA
# ---------------------------------------------------------------------------

class TestIAC005:
    def _admin_policy_no_mfa(self) -> dict:
        return {
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["*"],
                        "Resource": "*",
                    }
                ],
            }
        }

    def _admin_policy_with_mfa(self) -> dict:
        return {
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["*"],
                        "Resource": "*",
                        "Condition": {
                            "Bool": {"aws:MultiFactorAuthPresent": "true"}
                        },
                    }
                ],
            }
        }

    def test_iam_policy_wildcard_no_mfa_triggers(self):
        r = _make_iam_policy("admin-policy", self._admin_policy_no_mfa())
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-005" in ids

    def test_iam_role_policy_wildcard_no_mfa_triggers(self):
        r = _make_iam_role_policy("admin-role-policy", self._admin_policy_no_mfa())
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-005" in ids

    def test_iam_policy_iam_star_no_mfa_triggers(self):
        r = _make_iam_policy("iam-star-policy", {
            "policy": {
                "Statement": [{"Effect": "Allow", "Action": ["iam:*"], "Resource": "*"}]
            }
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-005" in ids

    def test_iam_policy_with_mfa_condition_no_trigger(self):
        r = _make_iam_policy("mfa-policy", self._admin_policy_with_mfa())
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-005" not in ids

    def test_iam_policy_deny_effect_no_trigger(self):
        r = _make_iam_policy("deny-policy", {
            "policy": {
                "Statement": [{"Effect": "Deny", "Action": ["*"], "Resource": "*"}]
            }
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-005" not in ids

    def test_iam_policy_non_admin_action_no_trigger(self):
        r = _make_iam_policy("s3-policy", {
            "policy": {
                "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}]
            }
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-005" not in ids

    def test_non_iam_resource_type_not_checked(self):
        r = _make_s3("s3-with-policy-key", {
            "policy": {
                "Statement": [{"Effect": "Allow", "Action": ["*"], "Resource": "*"}]
            },
            "server_side_encryption_configuration": {},
            "block_public_acls": True,
            "block_public_policy": True,
            "tags": _full_tags(),
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-005" not in ids

    def test_iam_policy_action_as_string_star_triggers(self):
        r = _make_iam_policy("str-action-policy", {
            "policy": {
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
            }
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-005" in ids

    def test_finding_severity_is_high(self):
        r = _make_iam_policy("sev-policy", self._admin_policy_no_mfa())
        result = SCANNER.scan([r])
        finding = next(f for f in result.findings if f.check_id == "IAC-005")
        assert finding.severity == "HIGH"


# ---------------------------------------------------------------------------
# 7. IAC-006 — Overly permissive IAM role or firewall
# ---------------------------------------------------------------------------

class TestIAC006:
    def test_iam_role_principal_star_triggers(self):
        r = _make_iam_role("public-role", {
            "assume_role_policy": {
                "Statement": [
                    {"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}
                ]
            },
            "tags": _full_tags(),
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-006" in ids

    def test_iam_role_principal_aws_star_triggers(self):
        r = _make_iam_role("aws-star-role", {
            "assume_role_policy": {
                "Statement": [
                    {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}
                ]
            },
            "tags": _full_tags(),
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-006" in ids

    def test_iam_role_restricted_principal_no_trigger(self):
        r = _make_iam_role("safe-role", {
            "assume_role_policy": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                        "Action": "sts:AssumeRole",
                    }
                ]
            },
            "tags": _full_tags(),
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-006" not in ids

    def test_iam_role_no_assume_policy_no_trigger(self):
        r = _make_iam_role("no-assume-role", {"tags": _full_tags()})
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-006" not in ids

    def test_gcp_fw_empty_ports_list_triggers(self):
        r = _make_gcp_fw("all-ports-fw", {
            "direction": "INGRESS",
            "source_ranges": ["10.0.0.0/8"],
            "allowed": [{"protocol": "tcp", "ports": []}],
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-006" in ids

    def test_gcp_fw_no_ports_key_triggers(self):
        r = _make_gcp_fw("no-ports-key-fw", {
            "direction": "INGRESS",
            "source_ranges": ["10.0.0.0/8"],
            "allowed": [{"protocol": "tcp"}],  # ports key absent
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-006" in ids

    def test_gcp_fw_specific_ports_no_trigger(self):
        r = _make_gcp_fw("specific-ports-fw", {
            "direction": "INGRESS",
            "source_ranges": ["10.0.0.0/8"],
            "allowed": [{"protocol": "tcp", "ports": ["443", "8080"]}],
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-006" not in ids

    def test_gcp_fw_no_allowed_block_no_trigger(self):
        r = _make_gcp_fw("no-allowed-fw", {
            "direction": "INGRESS",
            "source_ranges": ["10.0.0.0/8"],
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-006" not in ids

    def test_finding_severity_is_high(self):
        r = _make_iam_role("sev-role", {
            "assume_role_policy": {
                "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]
            },
            "tags": _full_tags(),
        })
        result = SCANNER.scan([r])
        finding = next(f for f in result.findings if f.check_id == "IAC-006")
        assert finding.severity == "HIGH"


# ---------------------------------------------------------------------------
# 8. IAC-007 — Missing required tags
# ---------------------------------------------------------------------------

class TestIAC007:
    def test_aws_resource_no_tags_triggers(self):
        r = _make_s3("no-tag-bucket", {
            "server_side_encryption_configuration": {},
            "block_public_acls": True,
            "block_public_policy": True,
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-007" in ids

    def test_aws_resource_missing_one_tag_triggers(self):
        r = _make_s3("partial-tag-bucket", {
            "server_side_encryption_configuration": {},
            "block_public_acls": True,
            "block_public_policy": True,
            "tags": {"Environment": "prod", "Owner": "team"},  # missing Project
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-007" in ids

    def test_aws_resource_all_required_tags_no_trigger(self):
        r = _make_s3("full-tag-bucket", {
            "server_side_encryption_configuration": {},
            "block_public_acls": True,
            "block_public_policy": True,
            "tags": _full_tags(),
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-007" not in ids

    def test_aws_resource_extra_tags_plus_required_no_trigger(self):
        tags = {**_full_tags(), "CostCenter": "123", "Team": "platform"}
        r = _make_s3("extra-tags-bucket", {
            "server_side_encryption_configuration": {},
            "block_public_acls": True,
            "block_public_policy": True,
            "tags": tags,
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-007" not in ids

    def test_non_aws_resource_no_trigger(self):
        r = _make_azure_storage("az-no-tag", {
            "allow_blob_public_access": False,
            "enable_https_traffic_only": True,
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-007" not in ids

    def test_gcp_resource_no_trigger(self):
        r = _make_gcp_fw("gcp-no-tag", {
            "direction": "INGRESS",
            "source_ranges": ["10.0.0.0/8"],
            "allowed": [{"protocol": "tcp", "ports": ["443"]}],
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-007" not in ids

    def test_aws_db_missing_tags_triggers(self):
        r = _make_db("no-tag-db", {"storage_encrypted": True})
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-007" in ids

    def test_missing_tags_listed_in_message(self):
        r = _make_s3("msg-tag-bucket", {
            "server_side_encryption_configuration": {},
            "block_public_acls": True,
            "block_public_policy": True,
        })
        result = SCANNER.scan([r])
        finding = next(f for f in result.findings if f.check_id == "IAC-007")
        # At least one required tag name should appear in the message
        assert any(tag in finding.message for tag in ["Environment", "Owner", "Project"])

    def test_finding_severity_is_low(self):
        r = _make_s3("low-sev-bucket", {
            "server_side_encryption_configuration": {},
            "block_public_acls": True,
            "block_public_policy": True,
        })
        result = SCANNER.scan([r])
        finding = next(f for f in result.findings if f.check_id == "IAC-007")
        assert finding.severity == "LOW"

    def test_aws_ebs_missing_tags_triggers(self):
        r = _make_ebs("no-tag-ebs", {"encrypted": True})
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-007" in ids


# ---------------------------------------------------------------------------
# 9. risk_score computation
# ---------------------------------------------------------------------------

class TestRiskScore:
    def test_no_findings_score_zero(self):
        result = SCANNER.scan([])
        assert result.risk_score == 0

    def test_single_iac007_score_equals_weight(self):
        r = _make_s3("score-test", {
            "server_side_encryption_configuration": {},
            "block_public_acls": True,
            "block_public_policy": True,
        })
        result = SCANNER.scan([r])
        # IAC-007 fires (missing tags); IAC-003 does not (SSE present); IAC-001 does not
        iac007 = [f for f in result.findings if f.check_id == "IAC-007"]
        assert len(iac007) == 1
        assert result.risk_score == _CHECK_WEIGHTS["IAC-007"]

    def test_multiple_checks_score_sums(self):
        # IAC-001 (40) + IAC-003 (25) + IAC-007 (5) = 70
        r = _make_s3("multi-check", {
            "acl": "public-read",                 # IAC-001
            # no server_side_encryption_configuration → IAC-003
            # no tags → IAC-007
        })
        result = SCANNER.scan([r])
        expected = _CHECK_WEIGHTS["IAC-001"] + _CHECK_WEIGHTS["IAC-003"] + _CHECK_WEIGHTS["IAC-007"]
        assert result.risk_score == expected

    def test_score_capped_at_100(self):
        # Stack several CRITICAL resources to exceed 100
        resources = [
            # IAC-001: 40
            _make_s3("pub-s3", {"acl": "public-read"}),
            # IAC-002: 35
            _make_sg("open-sg", {
                "ingress": [{"cidr_blocks": ["0.0.0.0/0"]}],
            }),
            # IAC-004: 40 (would push over 100 when combined with others)
            IaCResource(
                resource_type="aws_db_instance",
                resource_name="cred-db",
                config={"password": "HardcodedPassXYZ"},
            ),
        ]
        result = SCANNER.scan(resources)
        assert result.risk_score <= 100

    def test_two_critical_checks_score_correct_or_capped(self):
        # IAC-001=40 (public read, full tags, SSE present so IAC-003 silent)
        # IAC-004=40 (hardcoded password, storage_encrypted=True, full tags so IAC-007 silent)
        # Combined = 80, below the cap of 100
        r1 = _make_s3("pub-s3-b", {
            "acl": "public-read",
            "server_side_encryption_configuration": {"rule": {}},  # silence IAC-003
            "block_public_acls": True,       # only acl triggers IAC-001
            "block_public_policy": True,
            "tags": _full_tags(),             # silence IAC-007
        })
        r2 = IaCResource(
            resource_type="aws_db_instance",
            resource_name="cred-db-b",
            config={
                "password": "HardcodedPassXYZ123",
                "storage_encrypted": True,   # silence IAC-003
                "tags": _full_tags(),         # silence IAC-007
            },
        )
        result = SCANNER.scan([r1, r2])
        # IAC-001 fires (40) + IAC-004 fires (40) = 80
        assert result.risk_score == _CHECK_WEIGHTS["IAC-001"] + _CHECK_WEIGHTS["IAC-004"]

    def test_same_check_multiple_resources_accumulates(self):
        # IAC-007 fires for each resource: 3 resources × weight 5 = 15
        resources = [
            _make_s3(f"no-tag-s3-{i}", {
                "server_side_encryption_configuration": {},
                "block_public_acls": True,
                "block_public_policy": True,
            })
            for i in range(3)
        ]
        result = SCANNER.scan(resources)
        assert result.risk_score == _CHECK_WEIGHTS["IAC-007"] * 3

    def test_risk_score_never_negative(self):
        result = SCANNER.scan([])
        assert result.risk_score >= 0

    def test_risk_score_never_exceeds_100(self):
        # Spam the same finding type many times
        resources = [
            IaCResource(
                resource_type="aws_db_instance",
                resource_name=f"cred-db-{i}",
                config={"password": "HardcodedPassXYZ123"},
            )
            for i in range(10)
        ]
        result = SCANNER.scan(resources)
        assert result.risk_score <= 100


# ---------------------------------------------------------------------------
# 10. by_severity() grouping
# ---------------------------------------------------------------------------

class TestBySeverity:
    def test_empty_findings_all_buckets_empty(self):
        result = IaCResult(findings=[], risk_score=0)
        by_sev = result.by_severity()
        assert by_sev["CRITICAL"] == []
        assert by_sev["HIGH"] == []
        assert by_sev["MEDIUM"] == []
        assert by_sev["LOW"] == []

    def test_critical_finding_in_correct_bucket(self):
        finding = IaCFinding(
            check_id="IAC-001",
            severity="CRITICAL",
            resource_type="aws_s3_bucket",
            resource_name="x",
            message="msg",
            recommendation="rec",
        )
        result = IaCResult(findings=[finding], risk_score=40)
        by_sev = result.by_severity()
        assert finding in by_sev["CRITICAL"]
        assert finding not in by_sev["HIGH"]

    def test_high_finding_in_correct_bucket(self):
        finding = IaCFinding(
            check_id="IAC-003",
            severity="HIGH",
            resource_type="aws_db_instance",
            resource_name="y",
            message="msg",
            recommendation="rec",
        )
        result = IaCResult(findings=[finding], risk_score=25)
        by_sev = result.by_severity()
        assert finding in by_sev["HIGH"]
        assert finding not in by_sev["CRITICAL"]

    def test_low_finding_in_correct_bucket(self):
        finding = IaCFinding(
            check_id="IAC-007",
            severity="LOW",
            resource_type="aws_s3_bucket",
            resource_name="z",
            message="msg",
            recommendation="rec",
        )
        result = IaCResult(findings=[finding], risk_score=5)
        by_sev = result.by_severity()
        assert finding in by_sev["LOW"]
        assert finding not in by_sev["HIGH"]

    def test_mixed_severities_each_in_right_bucket(self):
        f_crit = IaCFinding("IAC-001", "CRITICAL", "aws_s3_bucket", "a", "m", "r")
        f_high = IaCFinding("IAC-003", "HIGH", "aws_db_instance", "b", "m", "r")
        f_low = IaCFinding("IAC-007", "LOW", "aws_s3_bucket", "c", "m", "r")
        result = IaCResult(findings=[f_crit, f_high, f_low], risk_score=70)
        by_sev = result.by_severity()
        assert f_crit in by_sev["CRITICAL"]
        assert f_high in by_sev["HIGH"]
        assert f_low in by_sev["LOW"]
        assert by_sev["MEDIUM"] == []

    def test_by_severity_returns_all_four_keys(self):
        result = IaCResult(findings=[], risk_score=0)
        by_sev = result.by_severity()
        for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            assert key in by_sev

    def test_by_severity_scan_result(self):
        r = _make_s3("pub-enc-notag", {"acl": "public-read"})
        result = SCANNER.scan([r])
        by_sev = result.by_severity()
        # IAC-001 is CRITICAL
        crit_ids = [f.check_id for f in by_sev["CRITICAL"]]
        assert "IAC-001" in crit_ids


# ---------------------------------------------------------------------------
# 11. summary() format
# ---------------------------------------------------------------------------

class TestSummary:
    def test_summary_no_findings(self):
        result = IaCResult(findings=[], risk_score=0)
        s = result.summary()
        assert s == "IaCResult: 0 findings (none), risk_score=0"

    def test_summary_single_critical(self):
        finding = IaCFinding("IAC-001", "CRITICAL", "aws_s3_bucket", "x", "m", "r")
        result = IaCResult(findings=[finding], risk_score=40)
        s = result.summary()
        assert "1 findings" in s
        assert "CRITICAL:1" in s
        assert "risk_score=40" in s

    def test_summary_mixed_severities(self):
        findings = [
            IaCFinding("IAC-001", "CRITICAL", "aws_s3_bucket", "a", "m", "r"),
            IaCFinding("IAC-003", "HIGH", "aws_db_instance", "b", "m", "r"),
            IaCFinding("IAC-007", "LOW", "aws_s3_bucket", "c", "m", "r"),
        ]
        result = IaCResult(findings=findings, risk_score=70)
        s = result.summary()
        assert "3 findings" in s
        assert "CRITICAL:1" in s
        assert "HIGH:1" in s
        assert "LOW:1" in s
        assert "risk_score=70" in s

    def test_summary_starts_with_iaresult(self):
        result = IaCResult(findings=[], risk_score=0)
        assert result.summary().startswith("IaCResult:")

    def test_summary_correct_finding_count(self):
        findings = [
            IaCFinding("IAC-007", "LOW", "aws_s3_bucket", f"r{i}", "m", "r")
            for i in range(5)
        ]
        result = IaCResult(findings=findings, risk_score=25)
        assert "5 findings" in result.summary()

    def test_summary_risk_score_capped_reflects_in_output(self):
        findings = [
            IaCFinding("IAC-001", "CRITICAL", "aws_s3_bucket", "x", "m", "r")
        ]
        result = IaCResult(findings=findings, risk_score=100)
        assert "risk_score=100" in result.summary()


# ---------------------------------------------------------------------------
# 12. scan_many()
# ---------------------------------------------------------------------------

class TestScanMany:
    def test_returns_list(self):
        results = SCANNER.scan_many([[]])
        assert isinstance(results, list)

    def test_empty_list_returns_empty(self):
        results = SCANNER.scan_many([])
        assert results == []

    def test_one_list_returns_one_result(self):
        results = SCANNER.scan_many([[]])
        assert len(results) == 1

    def test_two_lists_returns_two_results(self):
        r1 = _make_s3("s3-a", {
            "acl": "private",
            "block_public_acls": True,
            "block_public_policy": True,
            "server_side_encryption_configuration": {},
            "tags": _full_tags(),
        })
        r2 = _make_s3("s3-b", {"acl": "public-read"})
        results = SCANNER.scan_many([[r1], [r2]])
        assert len(results) == 2

    def test_clean_template_has_zero_score(self):
        r = _make_s3("clean-s3", {
            "acl": "private",
            "block_public_acls": True,
            "block_public_policy": True,
            "server_side_encryption_configuration": {},
            "tags": _full_tags(),
        })
        results = SCANNER.scan_many([[r]])
        assert results[0].risk_score == 0

    def test_dirty_template_has_nonzero_score(self):
        r = _make_s3("pub-s3-c", {"acl": "public-read"})
        results = SCANNER.scan_many([[r]])
        assert results[0].risk_score > 0

    def test_results_are_independent(self):
        r1 = _make_s3("pub-s3-d", {"acl": "public-read"})
        r2 = _make_s3("clean-s3-e", {
            "acl": "private",
            "block_public_acls": True,
            "block_public_policy": True,
            "server_side_encryption_configuration": {},
            "tags": _full_tags(),
        })
        results = SCANNER.scan_many([[r1], [r2]])
        ids_0 = [f.check_id for f in results[0].findings]
        ids_1 = [f.check_id for f in results[1].findings]
        assert "IAC-001" in ids_0
        assert "IAC-001" not in ids_1

    def test_each_result_is_iac_result_instance(self):
        results = SCANNER.scan_many([[], []])
        for r in results:
            assert isinstance(r, IaCResult)


# ---------------------------------------------------------------------------
# 13. to_dict() — IaCFinding and IaCResult serialization
# ---------------------------------------------------------------------------

class TestToDict:
    def test_iac_resource_to_dict_keys(self):
        r = IaCResource(
            resource_type="aws_s3_bucket",
            resource_name="bucket-a",
            config={"acl": "private"},
        )
        d = r.to_dict()
        assert d["resource_type"] == "aws_s3_bucket"
        assert d["resource_name"] == "bucket-a"
        assert d["config"] == {"acl": "private"}

    def test_iac_finding_to_dict_all_keys_present(self):
        f = IaCFinding(
            check_id="IAC-001",
            severity="CRITICAL",
            resource_type="aws_s3_bucket",
            resource_name="my-bucket",
            message="Test message",
            recommendation="Fix it",
        )
        d = f.to_dict()
        for key in ("check_id", "severity", "resource_type", "resource_name", "message", "recommendation"):
            assert key in d

    def test_iac_finding_to_dict_values_correct(self):
        f = IaCFinding(
            check_id="IAC-002",
            severity="CRITICAL",
            resource_type="aws_security_group",
            resource_name="sg-1",
            message="Open inbound",
            recommendation="Restrict CIDRs",
        )
        d = f.to_dict()
        assert d["check_id"] == "IAC-002"
        assert d["severity"] == "CRITICAL"
        assert d["resource_type"] == "aws_security_group"
        assert d["resource_name"] == "sg-1"
        assert d["message"] == "Open inbound"
        assert d["recommendation"] == "Restrict CIDRs"

    def test_iac_result_to_dict_keys(self):
        result = IaCResult(findings=[], risk_score=0)
        d = result.to_dict()
        assert "findings" in d
        assert "risk_score" in d

    def test_iac_result_to_dict_findings_serialized(self):
        f = IaCFinding("IAC-007", "LOW", "aws_s3_bucket", "x", "m", "r")
        result = IaCResult(findings=[f], risk_score=5)
        d = result.to_dict()
        assert isinstance(d["findings"], list)
        assert len(d["findings"]) == 1
        assert d["findings"][0]["check_id"] == "IAC-007"

    def test_iac_result_to_dict_risk_score_value(self):
        result = IaCResult(findings=[], risk_score=42)
        d = result.to_dict()
        assert d["risk_score"] == 42

    def test_to_dict_scan_result(self):
        r = _make_s3("dict-bucket", {"acl": "public-read"})
        result = SCANNER.scan([r])
        d = result.to_dict()
        assert isinstance(d, dict)
        assert "findings" in d
        assert isinstance(d["findings"], list)
        assert "risk_score" in d

    def test_to_dict_nested_finding_has_all_keys(self):
        r = _make_s3("nested-dict-bucket", {"acl": "public-read", "tags": _full_tags()})
        result = SCANNER.scan([r])
        d = result.to_dict()
        for finding_dict in d["findings"]:
            for key in ("check_id", "severity", "resource_type", "resource_name", "message", "recommendation"):
                assert key in finding_dict


# ---------------------------------------------------------------------------
# 14. Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_config_dict_s3(self):
        r = IaCResource(resource_type="aws_s3_bucket", resource_name="empty", config={})
        # Should not raise; should detect IAC-003 and IAC-007 at minimum
        result = SCANNER.scan([r])
        assert result is not None
        ids = [f.check_id for f in result.findings]
        assert "IAC-003" in ids  # no SSE config
        assert "IAC-007" in ids  # no tags

    def test_empty_config_dict_sg(self):
        r = IaCResource(resource_type="aws_security_group", resource_name="empty-sg", config={})
        result = SCANNER.scan([r])
        assert result is not None

    def test_empty_config_dict_iam_role(self):
        r = IaCResource(resource_type="aws_iam_role", resource_name="empty-role", config={})
        result = SCANNER.scan([r])
        assert result is not None

    def test_config_with_none_tags_value(self):
        r = _make_s3("null-tags", {
            "server_side_encryption_configuration": {},
            "block_public_acls": True,
            "block_public_policy": True,
            "tags": None,  # explicitly None
        })
        # Should not raise; tags=None treated as empty
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-007" in ids

    def test_ingress_rule_without_cidr_blocks_key(self):
        r = _make_sg("no-cidr-sg", {
            "ingress": [{"from_port": 22, "to_port": 22}],  # no cidr_blocks key
            "tags": _full_tags(),
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-002" not in ids

    def test_iam_policy_no_policy_key_no_trigger(self):
        r = _make_iam_policy("empty-policy", {})
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-005" not in ids

    def test_iam_role_assume_policy_not_dict_no_trigger(self):
        r = _make_iam_role("str-assume-role", {
            "assume_role_policy": "not-a-dict",
            "tags": _full_tags(),
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-006" not in ids

    def test_gcp_fw_ingress_no_source_ranges_no_trigger(self):
        r = _make_gcp_fw("no-src-fw", {
            "direction": "INGRESS",
            "allowed": [{"protocol": "tcp", "ports": ["443"]}],
        })
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-002" not in ids

    def test_resource_type_not_checked_by_any_rule(self):
        r = IaCResource(
            resource_type="aws_lambda_function",
            resource_name="fn",
            config={"handler": "index.handler", "tags": _full_tags()},
        )
        # Only IAC-004 (credentials) is universal; no creds here, so no findings
        result = SCANNER.scan([r])
        ids = [f.check_id for f in result.findings]
        assert "IAC-001" not in ids
        assert "IAC-002" not in ids

    def test_check_weights_dict_complete(self):
        for check_id in ("IAC-001", "IAC-002", "IAC-003", "IAC-004", "IAC-005", "IAC-006", "IAC-007"):
            assert check_id in _CHECK_WEIGHTS
            assert isinstance(_CHECK_WEIGHTS[check_id], int)
            assert _CHECK_WEIGHTS[check_id] > 0

    def test_iac_result_default_values(self):
        result = IaCResult()
        assert result.findings == []
        assert result.risk_score == 0

    def test_iac_resource_default_config(self):
        r = IaCResource(resource_type="aws_s3_bucket", resource_name="defaults")
        assert r.config == {}

    def test_multiple_resources_no_cross_contamination(self):
        clean = _make_s3("clean", {
            "acl": "private",
            "block_public_acls": True,
            "block_public_policy": True,
            "server_side_encryption_configuration": {},
            "tags": _full_tags(),
        })
        dirty = _make_s3("dirty", {"acl": "public-read"})
        result = SCANNER.scan([clean, dirty])
        # Findings should reference "dirty", not "clean" for IAC-001
        iac001_names = [f.resource_name for f in result.findings if f.check_id == "IAC-001"]
        assert "dirty" in iac001_names
        assert "clean" not in iac001_names
