# GitLab CI SARIF Upload to GitHub Security

This repository includes a focused workflow at:

- `.github/workflows/gitlab-sarif-upload.yml`

## What it does

On pull requests, the workflow uploads SARIF reports into the GitHub Security tab using `github/codeql-action/upload-sarif`.

## Expected artifact location

For compatibility with existing blueprints, place GitLab-generated SARIF files at:

- `artifacts/security/*.sarif`

Examples:

- `artifacts/security/semgrep.sarif`
- `artifacts/security/gitleaks.sarif`
- `artifacts/security/checkov.sarif`

The workflow fails fast if no SARIF files are found at this path.
