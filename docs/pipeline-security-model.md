# Pipeline Security Model

## DevSecOps and Shift-Left Security

The secure-pipeline-blueprints implement a shift-left security model where security controls are integrated at the earliest stage of the software delivery lifecycle — the developer's pull request.

```
Developer PR → CI Security Gates → Code Review → Merge → Deploy
                    |
                    ├── Secret Scanning (Gitleaks)
                    ├── SAST (Semgrep)
                    ├── SCA (pip-audit / npm audit)
                    ├── IaC Scanning (Checkov / tfsec)
                    ├── Container Scanning (Trivy)
                    └── Coverage Gate (pytest-cov / jest)
```

## Threat Model

### What These Pipelines Protect Against

| Threat | Control | Mitigation |
|---|---|---|
| Developer commits credentials | Secret scanning (Gitleaks) | Detects secrets before merge |
| Vulnerable dependencies (known CVEs) | SCA (pip-audit / npm audit) | Fails build on HIGH/CRITICAL with fix |
| Code vulnerabilities (OWASP Top 10) | SAST (Semgrep) | Detects patterns associated with injection, auth issues, etc. |
| Misconfigured cloud infrastructure | IaC scanning (Checkov / tfsec) | Catches S3 public access, unencrypted data, missing MFA |
| Vulnerable OS packages in containers | Container scanning (Trivy) | Scans image layers before deployment |
| Test coverage regression | Coverage gate | Prevents silently removing test coverage |

### What These Pipelines Do NOT Protect Against

- **Logic vulnerabilities**: SAST cannot detect business logic flaws
- **Runtime vulnerabilities**: DAST (Dynamic Application Security Testing) is not included in this bootstrap phase
- **Zero-day vulnerabilities**: SCA only catches known CVEs from public databases
- **Social engineering**: Pipeline security cannot protect against compromised developer accounts
- **Supply chain attacks on CI actions**: Actions are pinned to major versions but not SHA digests in this baseline

## Pipeline Permissions Model

Every GitHub Actions workflow uses the minimum necessary permissions:

```yaml
permissions:
  contents: read           # Read repository code
  security-events: write   # Upload SARIF to GitHub Security tab
  pull-requests: read      # Read PR metadata (if needed)
```

Do not grant `write` access to `contents`, `packages`, or `id-token` unless specifically required (e.g., for deployments). Do not use `permissions: write-all`.

## SARIF and Security Tab Integration

All SAST, SCA, and container scanning tools produce SARIF output that is uploaded to the GitHub Security tab via the `github/codeql-action/upload-sarif` action. This provides:

- A centralized view of security findings across all repositories
- Finding lifetime tracking (open, fixed, dismissed)
- Integration with GitHub code scanning alerts
- PR annotations showing findings inline in the diff

## Handling Findings

### Triage Policy

1. **CRITICAL**: Block merge. Fix before any code from the affected PR is merged.
2. **HIGH**: Block merge unless a documented exception is approved.
3. **MEDIUM**: Do not block merge, but create a tracked issue with a 30-day SLA.
4. **LOW / INFORMATIONAL**: Optional — create issues for backlog.

### False Positive Management

For SAST false positives, use Semgrep's inline suppression:
```python
result = eval(safe_expression)  # nosemgrep: k1n-python-eval-usage
```

For Gitleaks false positives, use inline suppression:
```python
API_KEY = "example-key-for-docs"  # gitleaks:allow
```

Or add allowlist entries to `controls/secrets/gitleaks_config.toml`.

## Compliance Mapping

These pipeline controls map to the following compliance requirements:

| Control | SOC 2 | ISO 27001 | PCI DSS | NIST CSF |
|---|---|---|---|---|
| SAST | CC7.1 | A.12.6.1 | 6.3.2 | DE.CM-8 |
| SCA | CC7.1 | A.12.6.1 | 6.3.2 | DE.CM-8 |
| Secret Scanning | CC6.7 | A.9.4.3 | 6.4 | PR.AC-1 |
| IaC Scanning | CC6.1 | A.12.1.1 | 6.3 | PR.IP-1 |
| Coverage Gate | CC7.2 | A.12.1.1 | 6.3.3 | DE.CM-8 |
