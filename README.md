# secure-pipeline-blueprints

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status: Bootstrap](https://img.shields.io/badge/Status-Bootstrap-blue.svg)]()
[![Platforms: 3](https://img.shields.io/badge/Platforms-GitHub_Actions_%7C_GitLab_CI_%7C_Azure_DevOps-green.svg)]()
[![Security Controls: SAST%2C_SCA%2C_Secrets%2C_IaC](https://img.shields.io/badge/Controls-SAST%2C_SCA%2C_Secrets%2C_IaC-orange.svg)]()

> Reusable, security-first CI/CD pipeline blueprints for GitHub Actions, GitLab CI, and Azure DevOps. Each blueprint ships with SAST, SCA, secrets scanning, and IaC validation built-in.

---

## What Is This?

`secure-pipeline-blueprints` is a curated collection of secure CI/CD pipeline templates that embed security controls directly into your build pipeline. Rather than adding security as an afterthought, these blueprints make security checks a first-class part of every pull request and merge.

Each blueprint includes:

- **SAST** (Static Application Security Testing): Semgrep for code-level vulnerability detection
- **SCA** (Software Composition Analysis): Dependency vulnerability scanning (pip-audit, npm audit, govulncheck)
- **Secret Scanning**: Gitleaks to prevent credential commits
- **IaC Validation**: Checkov/tfsec for Terraform and other IaC
- **Container Scanning**: Trivy for Docker image vulnerabilities
- **Coverage Gates**: Test coverage enforcement to prevent regressions
- **SARIF Upload**: Integration with GitHub Security tab for centralized findings

---

## Supported Platforms

| Platform | Status |
|---|---|
| **GitHub Actions** | Available |
| **GitLab CI** | Available |
| **Azure DevOps** | Planned |

---

## Supported Stacks

| Stack | Blueprint | Key Controls |
|---|---|---|
| **Python** | `github-actions/python/full_pipeline.yml` | Semgrep, pip-audit, Gitleaks, ruff, pytest coverage |
| **Node.js** | `github-actions/node/full_pipeline.yml` | Semgrep, npm audit, Gitleaks, ESLint security, jest coverage |
| **Go** | `github-actions/go/full_pipeline.yml` | Semgrep, govulncheck, Gitleaks, go vet, race detector, coverage |
| **Terraform / IaC** | `github-actions/iac/terraform_pipeline.yml` | tflint, checkov, terraform validate, tfsec |
| **Containers** | `github-actions/containers/container_scan.yml` | Trivy, Hadolint, Gitleaks |
| **Dependency Review** | `github-actions/reusable/dependency_review.yml` | GitHub dependency review, PR summary, severity gate |
| **Reusable SAST** | `github-actions/reusable/

## Reusable SARIF Upload (GitHub Actions)

Use `.github/workflows/reusable_sarif_upload.yml` to upload Semgrep/Trivy/Checkov SARIF artifacts to the GitHub Security tab and enforce a high/critical severity gate.

**Required permission:** `security-events: write`

Example blueprint/job usage:

```yaml
jobs:
  sarif-upload:
    permissions:
      security-events: write
      contents: read
      actions: read
    uses: ./.github/workflows/reusable_sarif_upload.yml
    with:
      semgrep_sarif: reports/semgrep.sarif
      trivy_sarif: reports/trivy.sarif
      checkov_sarif: reports/checkov.sarif
      high_critical_threshold: 0
```
