# Reusable Trivy Container Scan Workflow

Use `github-actions/reusable/trivy_scan.yml` to standardize container vulnerability scanning across repositories.

## Example caller workflow

```yaml
name: Container Security Scan

on:
  pull_request:
  push:
    branches: [main]

jobs:
  trivy:
    uses: your-org/secure-pipeline-blueprints/.github/workflows/trivy_scan.yml@main
    with:
      image: ghcr.io/your-org/your-app:${{ github.sha }}
      severity_threshold: CRITICAL,HIGH
      fail_on_severity: true
```

## Inputs

- `image` (required): Container image reference to scan.
- `severity_threshold` (optional, default `CRITICAL,HIGH`): Severities included in the scan gate.
- `fail_on_severity` (optional, default `true`): Fail the job if matching vulnerabilities are found.
