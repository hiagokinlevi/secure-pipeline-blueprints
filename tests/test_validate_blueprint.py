#!/usr/bin/env python3
"""
Unit tests for shared/validators/validate_blueprint.py

Run with:
    python -m pytest tests/test_validate_blueprint.py -v

Or:
    python tests/test_validate_blueprint.py

Requirements:
    pip install pyyaml pytest
"""

import sys
import tempfile
import unittest
from pathlib import Path

# Add validators directory to path
REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "shared" / "validators"))

import validate_blueprint
from validate_blueprint import (
    validate_github_actions_yaml,
    validate_gitlab_ci_yaml,
    validate_blueprint_yaml,
    should_skip,
)


class TestValidateGitHubActionsYAML(unittest.TestCase):
    """Tests for validate_github_actions_yaml()."""

    def _valid_workflow(self) -> dict:
        """Return a minimal valid GitHub Actions workflow dict."""
        return {
            "name": "Test Workflow",
            "on": {"push": {"branches": ["main"]}},
            "permissions": {"contents": "read", "security-events": "write"},
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {"name": "Checkout", "uses": "actions/checkout@v4"},
                        {"name": "Run tests", "run": "pytest tests/"},
                        {"name": "Run gitleaks", "run": "gitleaks detect ."},
                        {"name": "Run semgrep", "uses": "returntocorp/semgrep-action@v1"},
                        {"name": "Run audit", "run": "pip-audit -r requirements.txt"},
                    ],
                }
            },
        }

    def test_valid_workflow_returns_no_issues(self):
        """A fully valid workflow should return no issues."""
        workflow = self._valid_workflow()
        issues = validate_github_actions_yaml(workflow)
        self.assertEqual(issues, [], f"Expected no issues, got: {issues}")

    def test_missing_name_returns_issue(self):
        """Workflow missing 'name' should return an issue."""
        workflow = self._valid_workflow()
        del workflow["name"]
        issues = validate_github_actions_yaml(workflow)
        self.assertTrue(any("name" in i.lower() for i in issues))

    def test_missing_on_returns_issue(self):
        """Workflow missing 'on' trigger should return an issue."""
        workflow = self._valid_workflow()
        del workflow["on"]
        issues = validate_github_actions_yaml(workflow)
        self.assertTrue(any("on" in i.lower() for i in issues) or len(issues) > 0)

    def test_missing_jobs_returns_issue(self):
        """Workflow missing 'jobs' should return an issue."""
        workflow = self._valid_workflow()
        del workflow["jobs"]
        issues = validate_github_actions_yaml(workflow)
        self.assertTrue(any("jobs" in i.lower() for i in issues))

    def test_missing_permissions_returns_issue(self):
        """Workflow without 'permissions' block should warn."""
        workflow = self._valid_workflow()
        del workflow["permissions"]
        issues = validate_github_actions_yaml(workflow)
        self.assertTrue(
            any("permissions" in i.lower() for i in issues),
            f"Expected permissions warning, got: {issues}",
        )

    def test_empty_jobs_returns_issue(self):
        """Workflow with empty jobs dict should return an issue."""
        workflow = self._valid_workflow()
        workflow["jobs"] = {}
        issues = validate_github_actions_yaml(workflow)
        self.assertTrue(any("jobs" in i.lower() for i in issues))

    def test_checkout_not_first_step_returns_issue(self):
        """Job where checkout is not the first step should warn."""
        workflow = self._valid_workflow()
        # Reorder steps so checkout is second
        workflow["jobs"]["test"]["steps"] = [
            {"name": "Something else", "run": "echo hello"},
            {"name": "Checkout", "uses": "actions/checkout@v4"},
        ]
        issues = validate_github_actions_yaml(workflow)
        self.assertTrue(
            any("checkout" in i.lower() for i in issues),
            f"Expected checkout warning, got: {issues}",
        )

    def test_job_with_no_steps_returns_issue(self):
        """A job with no steps should return an issue."""
        workflow = self._valid_workflow()
        workflow["jobs"]["test"]["steps"] = []
        issues = validate_github_actions_yaml(workflow)
        self.assertTrue(any("steps" in i.lower() for i in issues))


class TestValidateGitLabCIYAML(unittest.TestCase):
    """Tests for validate_gitlab_ci_yaml()."""

    def _valid_gitlab_ci(self) -> dict:
        """Return a minimal valid GitLab CI dict."""
        return {
            "stages": ["lint", "test", "sast"],
            "image": "python:3.12-slim",
            "lint": {
                "stage": "lint",
                "script": ["ruff check ."],
            },
            "test": {
                "stage": "test",
                "script": ["pytest tests/"],
            },
        }

    def test_valid_gitlab_ci_returns_no_issues(self):
        """Valid GitLab CI config should return no issues."""
        config = self._valid_gitlab_ci()
        issues = validate_gitlab_ci_yaml(config)
        self.assertEqual(issues, [], f"Expected no issues, got: {issues}")

    def test_missing_stages_returns_issue(self):
        """GitLab CI without 'stages' should warn."""
        config = self._valid_gitlab_ci()
        del config["stages"]
        issues = validate_gitlab_ci_yaml(config)
        self.assertTrue(any("stages" in i.lower() for i in issues))

    def test_job_without_script_returns_issue(self):
        """A job without 'script' key should return an issue."""
        config = self._valid_gitlab_ci()
        config["lint"] = {"stage": "lint"}  # No 'script' key
        issues = validate_gitlab_ci_yaml(config)
        self.assertTrue(any("script" in i.lower() for i in issues))


class TestValidateBlueprintYAML(unittest.TestCase):
    """Tests for validate_blueprint_yaml() — integration with file system."""

    def setUp(self):
        """Create a temporary directory for test files."""
        import tempfile as _tempfile
        self.temp_dir_obj = _tempfile.TemporaryDirectory()
        self.temp_dir = Path(self.temp_dir_obj.name)

    def tearDown(self):
        self.temp_dir_obj.cleanup()

    def _write_yaml(self, content: str, subdir: str = "github-actions") -> Path:
        """Write YAML content to a temp file in the appropriate subdirectory."""
        path = self.temp_dir / subdir / "test_pipeline.yml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def test_invalid_yaml_syntax_returns_error(self):
        """A file with invalid YAML should return a syntax error."""
        path = self._write_yaml("{ invalid: yaml: content: }")
        errors = validate_blueprint_yaml(path)
        self.assertTrue(
            len(errors) > 0,
            "Invalid YAML should produce errors"
        )

    def test_empty_yaml_file_returns_error(self):
        """An empty YAML file should return an error."""
        path = self._write_yaml("")
        errors = validate_blueprint_yaml(path)
        self.assertTrue(len(errors) > 0, "Empty YAML should produce errors")

    def test_nonexistent_file_returns_error(self):
        """A path to a non-existent file should return an error."""
        path = self.temp_dir / "github-actions" / "does_not_exist.yml"
        errors = validate_blueprint_yaml(path)
        self.assertTrue(len(errors) > 0, "Non-existent file should produce errors")


class TestShouldSkip(unittest.TestCase):
    """Tests for the should_skip() function."""

    def test_should_skip_schemas(self):
        """Files in 'schemas' directories should be skipped."""
        self.assertTrue(should_skip(Path("/repo/shared/schemas/blueprint.json")))

    def test_should_skip_tests(self):
        """Files in 'tests' directories should be skipped."""
        self.assertTrue(should_skip(Path("/repo/tests/test_something.yml")))

    def test_should_not_skip_github_actions(self):
        """GitHub Actions YAML files should NOT be skipped."""
        self.assertFalse(should_skip(Path("/repo/github-actions/python/full_pipeline.yml")))

    def test_should_not_skip_gitlab_ci(self):
        """GitLab CI YAML files should NOT be skipped."""
        self.assertFalse(should_skip(Path("/repo/gitlab-ci/python/secure_pipeline.yml")))


class TestRealBlueprints(unittest.TestCase):
    """Integration tests that validate the actual blueprint files in the repository."""

    def test_python_github_actions_blueprint_exists(self):
        """The Python GitHub Actions blueprint file should exist."""
        blueprint_path = REPO_ROOT / "github-actions" / "python" / "full_pipeline.yml"
        self.assertTrue(blueprint_path.exists(), f"Blueprint not found: {blueprint_path}")

    def test_node_github_actions_blueprint_exists(self):
        """The Node.js GitHub Actions blueprint file should exist."""
        blueprint_path = REPO_ROOT / "github-actions" / "node" / "full_pipeline.yml"
        self.assertTrue(blueprint_path.exists(), f"Blueprint not found: {blueprint_path}")

    def test_terraform_blueprint_exists(self):
        """The Terraform GitHub Actions blueprint file should exist."""
        blueprint_path = REPO_ROOT / "github-actions" / "iac" / "terraform_pipeline.yml"
        self.assertTrue(blueprint_path.exists(), f"Blueprint not found: {blueprint_path}")

    def test_gitlab_python_blueprint_exists(self):
        """The GitLab CI Python blueprint file should exist."""
        blueprint_path = REPO_ROOT / "gitlab-ci" / "python" / "secure_pipeline.yml"
        self.assertTrue(blueprint_path.exists(), f"Blueprint not found: {blueprint_path}")

    def test_gitleaks_config_exists(self):
        """The Gitleaks configuration file should exist."""
        config_path = REPO_ROOT / "controls" / "secrets" / "gitleaks_config.toml"
        self.assertTrue(config_path.exists(), f"Config not found: {config_path}")

    def test_semgrep_config_exists(self):
        """The Semgrep configuration file should exist."""
        config_path = REPO_ROOT / "controls" / "sast" / "semgrep_config.yaml"
        self.assertTrue(config_path.exists(), f"Config not found: {config_path}")

    def test_dependency_review_workflow_exists(self):
        """The reusable dependency review workflow file should exist."""
        workflow_path = REPO_ROOT / "github-actions" / "reusable" / "dependency_review.yml"
        self.assertTrue(workflow_path.exists(), f"Workflow not found: {workflow_path}")

    def test_checkov_config_exists(self):
        """The Checkov configuration file should exist."""
        config_path = REPO_ROOT / "controls" / "iac" / "checkov_config.yaml"
        self.assertTrue(config_path.exists(), f"Config not found: {config_path}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
