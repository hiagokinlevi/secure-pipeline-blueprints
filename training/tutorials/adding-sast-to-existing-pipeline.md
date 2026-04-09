# Tutorial: Adding SAST to an Existing CI Pipeline

This tutorial walks through adding Semgrep SAST to a pipeline that already has unit tests but no security scanning. It follows the gradual adoption approach: audit mode first, then gated mode.

## Prerequisites

- Existing GitHub Actions pipeline with unit tests
- Python or Node.js project
- About 30 minutes

---

## Part 1: Understand What You Are Adding

Semgrep is a static analysis tool that scans source code for vulnerability patterns. When added to a pipeline it will:

1. Check out your code
2. Run configured rule sets against all source files
3. Report findings with severity, file location, and remediation guidance
4. Optionally fail the build if HIGH/CRITICAL findings are found

In this tutorial, we start in **audit mode** (no build failure) so you can see what Semgrep finds without immediately breaking your pipeline.

---

## Part 2: Add Semgrep in Audit Mode

Open your existing `.github/workflows/ci.yml` and add a new job:

```yaml
# Add this job to your existing workflow file
# This runs Semgrep in report-only mode — does NOT fail the build
sast-audit:
  name: SAST Audit (Semgrep — Report Only)
  runs-on: ubuntu-latest
  # Only run on PRs to avoid cluttering push builds during initial audit
  if: github.event_name == 'pull_request'
  permissions:
    contents: read
    security-events: write  # Required for SARIF upload

  steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Run Semgrep (audit mode — no failures)
      uses: returntocorp/semgrep-action@v1
      with:
        # Start with the language-specific and OWASP Top 10 rules
        config: >-
          p/python
          p/owasp-top-ten
        # Generate SARIF so findings appear in GitHub Security tab
        generateSarif: "1"
        # audit mode: do not fail on findings (auditOn: none)
        # This is the default when SEMGREP_APP_TOKEN is not set
      # Do NOT add 'continue-on-error: false' here — we want audit mode

    - name: Upload findings to GitHub Security tab
      uses: github/codeql-action/upload-sarif@v3
      if: always()
      with:
        sarif_file: semgrep.sarif
        category: semgrep-audit
```

Commit and push to a branch. Open a PR. The SAST audit job will run.

---

## Part 3: Review the First Findings

After the first run, go to your repository's **Security** tab > **Code scanning alerts**.

For each finding, determine:

1. **Is it a true positive?** Does the code actually have the vulnerability described?
   - Example: `python.lang.security.audit.subprocess-shell-true` — your code uses `subprocess.run(cmd, shell=True)` where `cmd` comes from user input. That's a real command injection vulnerability.

2. **Is it a false positive?** The rule triggered but the code is actually safe.
   - Example: `python.lang.security.audit.dangerous-eval` — your code does `eval("1 + 1")` which is a string literal, not user input. That's a false positive.

For each true positive finding, create a GitHub issue to track the remediation.

For false positives, add inline suppression comments:
```python
result = eval("1 + 1")  # nosemgrep: python.lang.security.audit.dangerous-eval
# This is a string literal, not user input — false positive
```

---

## Part 4: Remediate True Positives

Work through the true positive findings before enabling the gate. Common remediations:

### Command Injection (subprocess)
```python
# Before (vulnerable)
import subprocess
subprocess.run(f"git clone {repo_url}", shell=True)

# After (safe)
import subprocess
subprocess.run(["git", "clone", repo_url], shell=False)
```

### SQL Injection (string formatting)
```python
# Before (vulnerable)
cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")

# After (safe — parameterized query)
cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
```

### Hardcoded Secrets
```python
# Before (vulnerable)
API_KEY = "sk-prod-abc123def456"

# After (safe)
import os
API_KEY = os.environ["API_KEY"]  # Set via GitHub Actions secret
```

---

## Part 5: Enable SAST as a Build Gate

After resolving all true positives and suppressing false positives, switch from audit mode to gated mode.

Replace the `sast-audit` job with:

```yaml
# SAST gate — fails the build if HIGH/CRITICAL findings are found
sast:
  name: SAST (Semgrep — Gated)
  runs-on: ubuntu-latest
  needs: test  # Only run SAST if unit tests pass
  permissions:
    contents: read
    security-events: write

  steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Run Semgrep SAST
      uses: returntocorp/semgrep-action@v1
      with:
        config: >-
          p/python
          p/owasp-top-ten
          p/secrets
        generateSarif: "1"
      # No continue-on-error — Semgrep will fail the job on findings

    - name: Upload SARIF to GitHub Security tab
      uses: github/codeql-action/upload-sarif@v3
      if: always()
      with:
        sarif_file: semgrep.sarif
        category: semgrep-python
```

Add the `SAST (Semgrep — Gated)` check to your branch protection rules.

---

## Summary

You have:
1. Added Semgrep in audit mode to see findings without breaking the pipeline
2. Triaged all findings (true positives vs false positives)
3. Remediated true positive security vulnerabilities
4. Suppressed false positives with documented reasons
5. Enabled SAST as a mandatory build gate

Future PRs that introduce new security vulnerabilities will now fail the build automatically.

**Next step**: Add SCA (pip-audit) using the same gradual approach. See `docs/controls/sca.md`.
