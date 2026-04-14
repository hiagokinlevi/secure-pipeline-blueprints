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
| **Reusable SAST** | `github-actions/reusable/sast_semgrep.yml` | Semgrep, optional custom rules, SARIF upload, audit-only rollout |

---

## Security Controls per Blueprint

### Python Pipeline (`github-actions/python/full_pipeline.yml`)

| Control | Tool | Gate |
|---|---|---|
| Lint | ruff | Fail on lint errors |
| Unit tests | pytest | Required to pass |
| Coverage gate | pytest-cov | Minimum 70% |
| SAST | Semgrep (python + owasp-top-ten + secrets) | Fail on findings |
| SCA | pip-audit | Fail on HIGH/CRITICAL with fix available |
| Secret scanning | Gitleaks | Fail on any finding |
| SARIF upload | GitHub Security tab | Always upload |

### Node.js Pipeline (`github-actions/node/full_pipeline.yml`)

| Control | Tool | Gate |
|---|---|---|
| Lint | ESLint + eslint-plugin-security | Fail on security findings |
| Unit tests | jest | Required to pass |
| Coverage gate | jest --coverage | Minimum 70% |
| SAST | Semgrep (javascript + owasp-top-ten) | Fail on findings |
| SCA | npm audit | Fail on HIGH/CRITICAL |
| Secret scanning | Gitleaks | Fail on any finding |

### Go Pipeline (`github-actions/go/full_pipeline.yml`)

| Control | Tool | Gate |
|---|---|---|
| Static checks | go vet | Fail on vet findings |
| Unit tests | go test -race | Required to pass |
| Coverage gate | go tool cover | Minimum 70% |
| SAST | Semgrep (Go + OWASP Top Ten + secrets) | Fail on findings |
| SCA | govulncheck | Fail on reachable vulnerabilities |
| Secret scanning | Gitleaks | Fail on any finding |

### Terraform / IaC Pipeline (`github-actions/iac/terraform_pipeline.yml`)

| Control | Tool | Gate |
|---|---|---|
| Lint | tflint | Fail on errors |
| Format check | terraform fmt | Fail if not formatted |
| Validation | terraform validate | Fail on invalid config |
| IaC security | checkov | Fail on CRITICAL findings |
| IaC security | tfsec | Fail on HIGH/CRITICAL |
| Secret scanning | Gitleaks | Fail on any finding |

---

## Quick Start

### GitHub Actions — Python

1. Copy the blueprint to your project:

```bash
mkdir -p .github/workflows
cp github-actions/python/full_pipeline.yml .github/workflows/secure-python.yml
```

2. Ensure your project has a `requirements.txt` with hashes:

```bash
pip install pip-tools
pip-compile --generate-hashes requirements.in
```

3. Push to a branch — the pipeline will run automatically on PR to `main`.

4. Check the **Security** tab in your GitHub repo for SARIF findings.

### GitHub Actions — Terraform

```bash
mkdir -p .github/workflows
cp github-actions/iac/terraform_pipeline.yml .github/workflows/terraform-security.yml
```

### GitHub Actions — Go

```bash
mkdir -p .github/workflows
cp github-actions/go/full_pipeline.yml .github/workflows/secure-go.yml
```

---

## How to Adopt in Your Team

### Gradual Adoption Approach

For teams new to security-first pipelines, a gradual approach reduces friction:

1. **Week 1**: Add secret scanning only (Gitleaks). Zero false positives, high value.
2. **Week 2**: Add SCA (pip-audit / npm audit). Minimal false positives, clear remediation.
3. **Week 3**: Add SAST in report-only mode (no pipeline gate). Review findings.
4. **Week 4**: Enable SAST as a pipeline gate. Fix all HIGH/CRITICAL findings.
5. **Month 2**: Add coverage gate. Start at your current baseline and increase quarterly.

### Reusable Workflows

For organizations with multiple repositories, use the reusable workflows in `github-actions/reusable/`:

```yaml
# In your project's .github/workflows/security.yml
jobs:
  secret-scan:
    uses: hiagokinlevi/secure-pipeline-blueprints/.github/workflows/secret_scan.yml@main
    secrets:
      GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

For PR-time dependency change blocking, use the reusable dependency review workflow:

```yaml
jobs:
  dependency-review:
    uses: hiagokinlevi/secure-pipeline-blueprints/.github/workflows/dependency_review.yml@main
    permissions:
      contents: read
      pull-requests: write
```

For organization-wide SAST coverage, use the reusable Semgrep workflow:

```yaml
jobs:
  sast:
    uses: hiagokinlevi/secure-pipeline-blueprints/.github/workflows/sast_semgrep.yml@main
    permissions:
      contents: read
      security-events: write
    with:
      semgrep_config: "p/owasp-top-ten p/secrets"
      fail_on_findings: true
```

---

## Repository Structure

```
secure-pipeline-blueprints/
├── github-actions/
│   ├── python/               # Python secure pipeline blueprint
│   ├── node/                 # Node.js secure pipeline blueprint
│   ├── go/                   # Go secure pipeline blueprint
│   ├── iac/                  # Terraform/IaC security pipeline
│   ├── containers/           # Container scanning pipeline
│   └── reusable/             # Reusable workflow components (secret scan, dependency review, SAST)
├── gitlab-ci/
│   └── python/               # GitLab CI Python blueprint
├── controls/
│   ├── sast/                 # SAST tool configurations (Semgrep rules)
│   ├── secrets/              # Secret scanning configurations (Gitleaks)
│   └── iac/                  # IaC scanning configurations (Checkov)
├── shared/
│   ├── schemas/              # JSON Schema for blueprint metadata
│   └── validators/           # Blueprint validation scripts
├── docs/
│   ├── overview.md
│   ├── pipeline-security-model.md
│   ├── usage-guides/
│   └── controls/
└── training/
    ├── tutorials/
    ├── labs/
    └── exercises/
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## License

[CC BY 4.0](LICENSE).
