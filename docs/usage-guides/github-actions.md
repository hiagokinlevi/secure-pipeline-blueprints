# GitHub Actions Usage Guide

This guide covers how to adopt secure-pipeline-blueprints in a GitHub Actions project.

## Prerequisites

- GitHub repository (public or private)
- Repository admin access (to configure secrets and branch protection rules)
- The appropriate stack files:
  - Python: `requirements.txt` with hashes, `tests/` directory, `src/` directory
  - Node.js: `package.json` with jest, `package-lock.json`
  - Go: `go.mod`, `go.sum`, and packages under `./...`
  - Terraform: `.tf` files

## Adopting a Blueprint

### Step 1: Copy the Blueprint

```bash
# Example: Python blueprint
mkdir -p .github/workflows
cp github-actions/python/full_pipeline.yml .github/workflows/secure-python.yml
```

### Step 2: Review and Customize

Open the copied file and adjust:

1. **python-version**: Match your project's Python version
2. **Coverage threshold**: Start at your current coverage (use `pytest --cov=src --cov-report=term` to check)
3. **Branch triggers**: Adjust `branches: [main, develop]` to match your branch model

### Step 3: Add Required Secrets

Navigate to your repository > Settings > Secrets and variables > Actions:

| Secret | Required | Description |
|---|---|---|
| `SEMGREP_APP_TOKEN` | Optional | Enables Semgrep Cloud integration for centralized findings management |
| `GITHUB_TOKEN` | Automatic | Provided by GitHub automatically — no setup needed |

### Step 4: Enable Branch Protection

To enforce security gates on pull requests:

1. Go to repository Settings > Branches
2. Add a branch protection rule for `main`
3. Enable "Require status checks to pass before merging"
4. Select the required status checks:
   - `Lint & Test (Coverage Gate)`
   - `SAST (Semgrep)`
   - `SCA (pip-audit)`
   - `Secret Scanning (Gitleaks)`

### Step 5: Review Initial Run

Push to a feature branch and create a PR. Review:
- The Actions tab for pipeline results
- The Security tab for SARIF findings
- PR annotations for inline findings

---

## Using Reusable Workflows

For organizations with multiple repositories, use the reusable secret scanning workflow:

```yaml
# In your project's .github/workflows/security.yml
name: Security

on: [push, pull_request]

jobs:
  secret-scan:
    uses: hiagokinlevi/secure-pipeline-blueprints/.github/workflows/reusable/secret_scan.yml@main
    secrets: inherit
    with:
      fetch_depth: 0        # Full git history (recommended)
      fail_on_leak: true    # Fail the job if secrets are found
```

Use the reusable SAST workflow when a repository needs Semgrep coverage without a full stack blueprint:

```yaml
jobs:
  sast:
    uses: hiagokinlevi/secure-pipeline-blueprints/.github/workflows/sast_semgrep.yml@main
    permissions:
      contents: read
      security-events: write
    with:
      semgrep_config: "p/owasp-top-ten p/secrets"
      custom_config: ".semgrep/"
      fail_on_findings: true
```

---

## Customizing Semgrep Rules

To add custom Semgrep rules for your organization's security patterns:

1. Copy `controls/sast/semgrep_config.yaml` to your project
2. Add your custom rules to the file
3. Update the GitHub Actions workflow to reference your config:

```yaml
- name: Run Semgrep SAST
  uses: returntocorp/semgrep-action@v1
  with:
    config: >-
      p/python
      p/owasp-top-ten
      .semgrep/  # Your custom rules directory
```

---

## Troubleshooting

### Coverage Gate Failing at 70%

If your project's current coverage is below 70%, start at your actual coverage:

```bash
# Check current coverage
pytest --cov=src --cov-report=term-missing tests/
# Note the TOTAL % and use that as your starting threshold
```

Update the workflow:
```yaml
- name: Run tests with coverage gate
  run: pytest --cov=src --cov-fail-under=55 tests/  # Start at your baseline
```

Then increase quarterly until you reach 70%+.

### Semgrep Finding False Positives

Add an inline suppression comment on the offending line:
```python
result = some_function()  # nosemgrep: rule-id
```

Or add a `.semgrepignore` file to exclude entire directories:
```
# .semgrepignore
tests/
migrations/
```

### Gitleaks Blocking on Test Fixtures

Add the test file pattern to `gitleaks_config.toml`:
```toml
[allowlist]
paths = [
    '''^tests?/fixtures/.*''',
]
```

Or add an inline suppression:
```python
TEST_API_KEY = "fake-key-for-unit-tests"  # gitleaks:allow
```
