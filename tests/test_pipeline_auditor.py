#!/usr/bin/env python3
"""
Unit tests for shared/validators/pipeline_auditor.py

Run with:
    python -m pytest tests/test_pipeline_auditor.py -v

Or:
    python tests/test_pipeline_auditor.py

Requirements:
    pip install pyyaml pytest
"""

import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

# Add validators directory to path
REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "shared" / "validators"))

from pipeline_auditor import (
    AuditResult,
    PipelineFinding,
    audit_workflow_directory,
    audit_workflow_file,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_workflow(content: str) -> Path:
    """Write YAML content to a temporary file and return its path."""
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yml", delete=False, encoding="utf-8"
    )
    tmp.write(textwrap.dedent(content))
    tmp.flush()
    tmp.close()
    return Path(tmp.name)


def _findings_by_rule(result: AuditResult, rule_id: str) -> list[PipelineFinding]:
    return [f for f in result.findings if f.rule_id == rule_id]


# ---------------------------------------------------------------------------
# PA001: pull_request_target + checkout head ref
# ---------------------------------------------------------------------------


class TestPA001PullRequestTarget(unittest.TestCase):
    """PA001: pull_request_target trigger with checkout of PR head ref."""

    def test_pa001_triggered_when_head_ref_checked_out(self):
        path = _write_workflow("""
            name: Dangerous Workflow
            on:
              pull_request_target:
                branches: [main]
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                timeout-minutes: 30
                steps:
                  - name: Checkout PR head
                    uses: actions/checkout@v4
                    with:
                      ref: ${{ github.head_ref }}
        """)
        result = audit_workflow_file(path)
        pa001 = _findings_by_rule(result, "PA001")
        self.assertTrue(pa001, "Expected PA001 finding for head_ref checkout")
        self.assertEqual(pa001[0].severity, "critical")

    def test_pa001_not_triggered_for_pull_request_trigger(self):
        """Regular pull_request trigger (not target) should not fire PA001."""
        path = _write_workflow("""
            name: Safe Workflow
            on:
              pull_request:
                branches: [main]
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                timeout-minutes: 30
                steps:
                  - name: Checkout
                    uses: actions/checkout@v4
        """)
        result = audit_workflow_file(path)
        self.assertFalse(_findings_by_rule(result, "PA001"))

    def test_pa001_not_triggered_when_no_head_ref(self):
        """pull_request_target without head_ref checkout should not fire PA001."""
        path = _write_workflow("""
            name: Managed Workflow
            on:
              pull_request_target:
                branches: [main]
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                timeout-minutes: 30
                steps:
                  - name: Checkout base
                    uses: actions/checkout@v4
        """)
        result = audit_workflow_file(path)
        self.assertFalse(_findings_by_rule(result, "PA001"))

    def test_pa001_location_points_to_step(self):
        """PA001 location should reference the specific step index."""
        path = _write_workflow("""
            name: Dangerous
            on:
              pull_request_target:
            permissions:
              contents: read
            jobs:
              deploy:
                runs-on: ubuntu-latest
                timeout-minutes: 15
                steps:
                  - name: Prepare
                    run: echo "prep"
                  - name: Checkout head
                    uses: actions/checkout@v4
                    with:
                      ref: ${{ github.head_ref }}
        """)
        result = audit_workflow_file(path)
        pa001 = _findings_by_rule(result, "PA001")
        self.assertTrue(pa001)
        # Step index 1 (0-based second step)
        self.assertIn("steps[1]", pa001[0].location)


# ---------------------------------------------------------------------------
# PA002: Actions not pinned to SHA
# ---------------------------------------------------------------------------


class TestPA002ActionPinning(unittest.TestCase):
    """PA002: Actions should be pinned to full commit SHAs."""

    def test_pa002_fires_for_branch_ref(self):
        """An action pinned to a branch name should trigger PA002."""
        path = _write_workflow("""
            name: Unpinned Workflow
            on:
              push:
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                timeout-minutes: 30
                steps:
                  - name: Third-party action on branch
                    uses: some-org/some-action@main
        """)
        result = audit_workflow_file(path)
        pa002 = _findings_by_rule(result, "PA002")
        self.assertTrue(pa002)
        self.assertIn("some-org/some-action@main", pa002[0].evidence)

    def test_pa002_fires_for_semver_tag(self):
        """An action pinned to a semver tag (not SHA) should trigger PA002."""
        path = _write_workflow("""
            name: Tag Pinned
            on:
              push:
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                timeout-minutes: 30
                steps:
                  - uses: third-party/action@v1.2.3
        """)
        result = audit_workflow_file(path)
        self.assertTrue(_findings_by_rule(result, "PA002"))

    def test_pa002_not_fired_for_full_sha(self):
        """An action pinned to a full 40-char SHA should NOT trigger PA002."""
        path = _write_workflow("""
            name: SHA Pinned
            on:
              push:
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                timeout-minutes: 30
                steps:
                  - uses: third-party/action@a81bbbf8298c0fa03ea29cdc473d45769f953675
        """)
        result = audit_workflow_file(path)
        self.assertFalse(_findings_by_rule(result, "PA002"))

    def test_pa002_not_fired_for_trusted_major_version(self):
        """actions/checkout@v4 (trusted publisher + major version) should not trigger PA002."""
        path = _write_workflow("""
            name: Trusted Major Version
            on:
              push:
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                timeout-minutes: 30
                steps:
                  - uses: actions/checkout@v4
                  - uses: actions/setup-python@v5
                  - uses: github/codeql-action/upload-sarif@v3
        """)
        result = audit_workflow_file(path)
        self.assertFalse(_findings_by_rule(result, "PA002"))

    def test_pa002_fires_for_untrusted_major_version(self):
        """An untrusted publisher using major version should trigger PA002."""
        path = _write_workflow("""
            name: Untrusted Major
            on:
              push:
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                timeout-minutes: 30
                steps:
                  - uses: returntocorp/semgrep-action@v1
        """)
        result = audit_workflow_file(path)
        self.assertTrue(_findings_by_rule(result, "PA002"))


# ---------------------------------------------------------------------------
# PA003: Permissions misconfigurations
# ---------------------------------------------------------------------------


class TestPA003Permissions(unittest.TestCase):
    """PA003: Workflow-level permissions checks."""

    def test_pa003_high_for_write_all(self):
        """permissions: write-all should trigger PA003 HIGH."""
        path = _write_workflow("""
            name: Write All
            on:
              push:
            permissions: write-all
            jobs:
              build:
                runs-on: ubuntu-latest
                timeout-minutes: 30
                steps:
                  - uses: actions/checkout@v4
        """)
        result = audit_workflow_file(path)
        pa003 = _findings_by_rule(result, "PA003")
        self.assertTrue(pa003)
        self.assertEqual(pa003[0].severity, "high")

    def test_pa003_medium_for_missing_permissions(self):
        """Missing permissions block should trigger PA003 MEDIUM."""
        path = _write_workflow("""
            name: No Permissions
            on:
              push:
            jobs:
              build:
                runs-on: ubuntu-latest
                timeout-minutes: 30
                steps:
                  - uses: actions/checkout@v4
        """)
        result = audit_workflow_file(path)
        pa003 = _findings_by_rule(result, "PA003")
        self.assertTrue(pa003)
        self.assertEqual(pa003[0].severity, "medium")

    def test_pa003_not_fired_for_scoped_permissions(self):
        """A scoped permissions block should not trigger PA003."""
        path = _write_workflow("""
            name: Scoped Permissions
            on:
              push:
            permissions:
              contents: read
              security-events: write
            jobs:
              build:
                runs-on: ubuntu-latest
                timeout-minutes: 30
                steps:
                  - uses: actions/checkout@v4
        """)
        result = audit_workflow_file(path)
        self.assertFalse(_findings_by_rule(result, "PA003"))

    def test_pa003_not_fired_for_read_all(self):
        """permissions: read-all should not trigger PA003."""
        path = _write_workflow("""
            name: Read All
            on:
              push:
            permissions: read-all
            jobs:
              build:
                runs-on: ubuntu-latest
                timeout-minutes: 30
                steps:
                  - uses: actions/checkout@v4
        """)
        result = audit_workflow_file(path)
        self.assertFalse(_findings_by_rule(result, "PA003"))


# ---------------------------------------------------------------------------
# PA004: Secret echoed in run scripts
# ---------------------------------------------------------------------------


class TestPA004SecretEcho(unittest.TestCase):
    """PA004: Secrets should not be echoed in run scripts."""

    def test_pa004_fires_for_echo_secret(self):
        """echo ${{ secrets.* }} in run script should trigger PA004."""
        path = _write_workflow("""
            name: Echo Secret
            on:
              push:
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                timeout-minutes: 30
                steps:
                  - name: Leak secret
                    run: echo ${{ secrets.MY_API_KEY }}
        """)
        result = audit_workflow_file(path)
        pa004 = _findings_by_rule(result, "PA004")
        self.assertTrue(pa004)
        self.assertEqual(pa004[0].severity, "high")

    def test_pa004_fires_for_echo_with_quotes(self):
        """Quoted echo of a secret should also trigger PA004."""
        path = _write_workflow("""
            name: Quoted Echo
            on:
              push:
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                timeout-minutes: 30
                steps:
                  - name: Print token
                    run: echo "${{ secrets.GITHUB_TOKEN }}"
        """)
        result = audit_workflow_file(path)
        self.assertTrue(_findings_by_rule(result, "PA004"))

    def test_pa004_not_fired_for_env_var_usage(self):
        """Using a secret as an environment variable (not echoed) should not fire PA004."""
        path = _write_workflow("""
            name: Safe Secret Use
            on:
              push:
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                timeout-minutes: 30
                steps:
                  - name: Use secret safely
                    env:
                      TOKEN: ${{ secrets.MY_TOKEN }}
                    run: curl -H "Authorization: Bearer $TOKEN" https://api.example.com/data
        """)
        result = audit_workflow_file(path)
        self.assertFalse(_findings_by_rule(result, "PA004"))


# ---------------------------------------------------------------------------
# PA006: continue-on-error on security-relevant steps
# ---------------------------------------------------------------------------


class TestPA006ContinueOnError(unittest.TestCase):
    """PA006: Security steps should not have continue-on-error: true."""

    def test_pa006_fires_for_semgrep_step(self):
        """Semgrep step with continue-on-error: true should trigger PA006."""
        path = _write_workflow("""
            name: Soft SAST
            on:
              push:
            permissions:
              contents: read
            jobs:
              sast:
                runs-on: ubuntu-latest
                timeout-minutes: 30
                steps:
                  - name: Run semgrep scan
                    uses: returntocorp/semgrep-action@v1
                    continue-on-error: true
        """)
        result = audit_workflow_file(path)
        pa006 = _findings_by_rule(result, "PA006")
        self.assertTrue(pa006)
        self.assertEqual(pa006[0].severity, "medium")

    def test_pa006_fires_for_gitleaks_step(self):
        """Gitleaks step with continue-on-error: true should trigger PA006."""
        path = _write_workflow("""
            name: Soft Secret Scan
            on:
              push:
            permissions:
              contents: read
            jobs:
              scan:
                runs-on: ubuntu-latest
                timeout-minutes: 30
                steps:
                  - name: Run gitleaks secret scan
                    uses: gitleaks/gitleaks-action@v2
                    continue-on-error: true
        """)
        result = audit_workflow_file(path)
        self.assertTrue(_findings_by_rule(result, "PA006"))

    def test_pa006_not_fired_for_non_security_step(self):
        """A non-security step with continue-on-error: true should NOT trigger PA006."""
        path = _write_workflow("""
            name: Soft Build
            on:
              push:
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                timeout-minutes: 30
                steps:
                  - name: Run integration tests
                    run: pytest tests/integration/
                    continue-on-error: true
        """)
        result = audit_workflow_file(path)
        self.assertFalse(_findings_by_rule(result, "PA006"))

    def test_pa006_fires_when_audit_in_step_name(self):
        """A step named 'pip audit' with continue-on-error should trigger PA006."""
        path = _write_workflow("""
            name: Soft Audit
            on:
              push:
            permissions:
              contents: read
            jobs:
              sca:
                runs-on: ubuntu-latest
                timeout-minutes: 30
                steps:
                  - name: Run pip audit
                    run: pip-audit -r requirements.txt
                    continue-on-error: true
        """)
        result = audit_workflow_file(path)
        self.assertTrue(_findings_by_rule(result, "PA006"))


# ---------------------------------------------------------------------------
# PA007: Deprecated workflow commands
# ---------------------------------------------------------------------------


class TestPA007DeprecatedCommands(unittest.TestCase):
    """PA007: Deprecated ::set-env:: and ::add-path:: workflow commands."""

    def test_pa007_fires_for_set_env(self):
        """::set-env:: command in run script should trigger PA007."""
        path = _write_workflow("""
            name: Set Env Legacy
            on:
              push:
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                timeout-minutes: 30
                steps:
                  - name: Export variable
                    run: echo "::set-env::MY_VAR=some_value"
        """)
        result = audit_workflow_file(path)
        pa007 = _findings_by_rule(result, "PA007")
        self.assertTrue(pa007)
        self.assertEqual(pa007[0].severity, "medium")

    def test_pa007_fires_for_add_path(self):
        """::add-path:: usage should trigger PA007."""
        path = _write_workflow("""
            name: Add Path Legacy
            on:
              push:
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                timeout-minutes: 30
                steps:
                  - name: Add to PATH
                    run: echo ::add-path::/usr/local/custom/bin
        """)
        result = audit_workflow_file(path)
        self.assertTrue(_findings_by_rule(result, "PA007"))

    def test_pa007_not_fired_for_modern_env_file(self):
        """Modern $GITHUB_ENV approach should not trigger PA007."""
        path = _write_workflow("""
            name: Modern Env
            on:
              push:
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                timeout-minutes: 30
                steps:
                  - name: Export variable
                    run: echo "MY_VAR=some_value" >> $GITHUB_ENV
        """)
        result = audit_workflow_file(path)
        self.assertFalse(_findings_by_rule(result, "PA007"))


# ---------------------------------------------------------------------------
# PA008: Missing timeout-minutes
# ---------------------------------------------------------------------------


class TestPA008TimeoutMinutes(unittest.TestCase):
    """PA008: Jobs without timeout-minutes can cause runaway builds."""

    def test_pa008_fires_when_timeout_missing(self):
        """A job without timeout-minutes should trigger PA008."""
        path = _write_workflow("""
            name: No Timeout
            on:
              push:
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
        """)
        result = audit_workflow_file(path)
        pa008 = _findings_by_rule(result, "PA008")
        self.assertTrue(pa008)
        self.assertEqual(pa008[0].severity, "low")

    def test_pa008_not_fired_when_timeout_present(self):
        """A job with timeout-minutes set should NOT trigger PA008."""
        path = _write_workflow("""
            name: With Timeout
            on:
              push:
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                timeout-minutes: 30
                steps:
                  - uses: actions/checkout@v4
        """)
        result = audit_workflow_file(path)
        self.assertFalse(_findings_by_rule(result, "PA008"))

    def test_pa008_fires_per_job(self):
        """PA008 should fire separately for each job missing the timeout."""
        path = _write_workflow("""
            name: Multi Job No Timeout
            on:
              push:
            permissions:
              contents: read
            jobs:
              job_a:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
              job_b:
                runs-on: ubuntu-latest
                steps:
                  - run: echo "hello"
        """)
        result = audit_workflow_file(path)
        pa008 = _findings_by_rule(result, "PA008")
        self.assertEqual(len(pa008), 2)

    def test_pa008_partial_with_one_job_missing(self):
        """Only the job missing timeout-minutes should be flagged."""
        path = _write_workflow("""
            name: Partial Timeout
            on:
              push:
            permissions:
              contents: read
            jobs:
              guarded:
                runs-on: ubuntu-latest
                timeout-minutes: 20
                steps:
                  - uses: actions/checkout@v4
              unguarded:
                runs-on: ubuntu-latest
                steps:
                  - run: echo "build"
        """)
        result = audit_workflow_file(path)
        pa008 = _findings_by_rule(result, "PA008")
        self.assertEqual(len(pa008), 1)
        self.assertIn("unguarded", pa008[0].location)


# ---------------------------------------------------------------------------
# AuditResult properties
# ---------------------------------------------------------------------------


class TestAuditResultProperties(unittest.TestCase):
    """Tests for AuditResult.passed, .critical_count, .high_count."""

    def test_passed_true_when_no_critical_or_high(self):
        """passed should be True when there are only medium/low findings."""
        path = _write_workflow("""
            name: Low Risk Workflow
            on:
              push:
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
        """)
        result = audit_workflow_file(path)
        # PA008 (low) and PA002 (medium for unpinned) may fire but not high/critical
        high_or_critical = [
            f for f in result.findings if f.severity in ("critical", "high")
        ]
        if not high_or_critical:
            self.assertTrue(result.passed)

    def test_passed_false_when_high_finding_present(self):
        """passed should be False when there is at least one HIGH finding."""
        path = _write_workflow("""
            name: High Risk
            on:
              push:
            permissions: write-all
            jobs:
              build:
                runs-on: ubuntu-latest
                timeout-minutes: 30
                steps:
                  - uses: actions/checkout@v4
        """)
        result = audit_workflow_file(path)
        self.assertFalse(result.passed)

    def test_critical_count_correct(self):
        """critical_count should accurately reflect the number of CRITICAL findings."""
        path = _write_workflow("""
            name: Critical Workflow
            on:
              pull_request_target:
            permissions:
              contents: read
            jobs:
              deploy:
                runs-on: ubuntu-latest
                timeout-minutes: 10
                steps:
                  - name: Checkout PR
                    uses: actions/checkout@v4
                    with:
                      ref: ${{ github.head_ref }}
        """)
        result = audit_workflow_file(path)
        self.assertEqual(result.critical_count, 1)

    def test_findings_sorted_critical_first(self):
        """Findings should be sorted with critical severity before high/medium/low."""
        path = _write_workflow("""
            name: Mixed Severity
            on:
              pull_request_target:
            jobs:
              deploy:
                runs-on: ubuntu-latest
                steps:
                  - name: Checkout PR head
                    uses: actions/checkout@v4
                    with:
                      ref: ${{ github.head_ref }}
        """)
        result = audit_workflow_file(path)
        if len(result.findings) >= 2:
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            severities = [severity_order[f.severity] for f in result.findings]
            self.assertEqual(severities, sorted(severities))


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestErrorHandling(unittest.TestCase):
    """Tests for error conditions in audit_workflow_file."""

    def test_nonexistent_file_returns_warning(self):
        """Auditing a non-existent file should return a result with a warning."""
        result = audit_workflow_file(Path("/tmp/does_not_exist_12345.yml"))
        self.assertTrue(result.warnings)
        self.assertEqual(result.workflow_name, "(unreadable)")

    def test_invalid_yaml_returns_warning(self):
        """Auditing a file with invalid YAML should return a result with a warning."""
        path = _write_workflow("{ invalid: yaml: broken:")
        result = audit_workflow_file(path)
        self.assertTrue(result.warnings)

    def test_non_mapping_yaml_returns_warning(self):
        """Auditing a YAML file that is a list (not a mapping) should warn."""
        path = _write_workflow("- item1\n- item2\n")
        result = audit_workflow_file(path)
        self.assertTrue(result.warnings)
        self.assertEqual(result.workflow_name, "(invalid)")


# ---------------------------------------------------------------------------
# audit_workflow_directory
# ---------------------------------------------------------------------------


class TestAuditWorkflowDirectory(unittest.TestCase):
    """Tests for audit_workflow_directory()."""

    def setUp(self):
        import tempfile as _tf
        self._tmpdir_obj = _tf.TemporaryDirectory()
        self.tmpdir = Path(self._tmpdir_obj.name)

    def tearDown(self):
        self._tmpdir_obj.cleanup()

    def _write(self, name: str, content: str) -> Path:
        path = self.tmpdir / name
        path.write_text(textwrap.dedent(content), encoding="utf-8")
        return path

    def test_scans_all_yml_files(self):
        """audit_workflow_directory should return one result per YAML file."""
        self._write("workflow_a.yml", """
            name: A
            on: push
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                timeout-minutes: 10
                steps:
                  - uses: actions/checkout@v4
        """)
        self._write("workflow_b.yml", """
            name: B
            on: push
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                timeout-minutes: 10
                steps:
                  - uses: actions/checkout@v4
        """)
        results = audit_workflow_directory(self.tmpdir)
        self.assertEqual(len(results), 2)

    def test_empty_directory_returns_empty_list(self):
        """An empty directory should return an empty list."""
        results = audit_workflow_directory(self.tmpdir)
        self.assertEqual(results, [])

    def test_returns_correct_workflow_names(self):
        """Each AuditResult should reflect the workflow's name field."""
        self._write("named_workflow.yml", """
            name: My Named Workflow
            on: push
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                timeout-minutes: 10
                steps:
                  - uses: actions/checkout@v4
        """)
        results = audit_workflow_directory(self.tmpdir)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].workflow_name, "My Named Workflow")


# ---------------------------------------------------------------------------
# Real blueprint audit
# ---------------------------------------------------------------------------


class TestRealPipelineBlueprintAudit(unittest.TestCase):
    """Audit the real blueprint files included in the repository."""

    def test_python_blueprint_passes(self):
        """The Python blueprint should have no critical or high findings."""
        blueprint = REPO_ROOT / "github-actions" / "python" / "full_pipeline.yml"
        if not blueprint.exists():
            self.skipTest("Python blueprint not found")
        result = audit_workflow_file(blueprint)
        high_or_critical = [
            f for f in result.findings if f.severity in ("critical", "high")
        ]
        self.assertEqual(
            high_or_critical,
            [],
            f"Python blueprint has critical/high findings: {[f.rule_id for f in high_or_critical]}",
        )

    def test_python_blueprint_has_permissions_block(self):
        """Python blueprint should define a permissions block (no PA003 missing)."""
        blueprint = REPO_ROOT / "github-actions" / "python" / "full_pipeline.yml"
        if not blueprint.exists():
            self.skipTest("Python blueprint not found")
        result = audit_workflow_file(blueprint)
        pa003_missing = [
            f for f in result.findings
            if f.rule_id == "PA003" and "No top-level" in f.message
        ]
        self.assertFalse(
            pa003_missing,
            "Python blueprint is missing a permissions block",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
