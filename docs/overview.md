# Overview

## What Is secure-pipeline-blueprints?

`secure-pipeline-blueprints` is a collection of CI/CD pipeline templates that embed security controls directly into the build process. The goal is to make DevSecOps accessible — a developer should be able to copy a blueprint into their project and immediately have SAST, SCA, secrets scanning, and more running on every pull request.

## Why Security in the Pipeline?

Traditional security approaches test applications after they are built and deployed. This is expensive: finding a vulnerability in production requires coordinating incident response, hotfixes, and sometimes emergency deployments.

Shift-left security moves security testing into the earliest possible stage — the pull request. Key benefits:

- **Faster feedback**: Developers get security findings before code is merged, when the fix context is fresh
- **Lower cost**: Fixing a vulnerability in a PR is orders of magnitude cheaper than in production
- **Continuous coverage**: Security checks run on every commit, not once per quarter
- **Automated consistency**: No human error in remembering to run a security scan

## Design Principles

### 1. Security Controls Are Not Optional

Every blueprint includes mandatory security gates — not just informational scans. If a HIGH severity vulnerability is found in a dependency, the build fails. This creates accountability without manual overhead.

### 2. SARIF Integration

All SAST and SCA tools output SARIF (Static Analysis Results Interchange Format), which is uploaded to the GitHub Security tab. This gives security teams a central dashboard of all findings across all repositories.

### 3. Least Privilege

Every GitHub Actions workflow has a `permissions:` block with the minimum required scopes. This limits the blast radius if a workflow is compromised via a supply chain attack on a third-party action.

### 4. Pinned Tool Versions

All tool versions are pinned (e.g., `actions/checkout@v4`, `python-version: "3.12"`). This ensures reproducible builds and prevents silent updates from introducing new behavior.

### 5. Graduated Adoption

New teams should not be expected to enforce all security controls on day one. The documentation includes a graduated adoption guide that introduces controls incrementally, reducing friction and giving teams time to remediate existing findings.

## Architecture

```
secure-pipeline-blueprints/
├── github-actions/          # GitHub Actions blueprints
│   ├── python/              # Python full pipeline
│   ├── node/                # Node.js full pipeline
│   ├── iac/                 # Terraform/IaC security pipeline
│   ├── containers/          # Container scanning pipeline
│   └── reusable/            # Reusable workflow components
├── gitlab-ci/               # GitLab CI blueprints
├── controls/                # Tool configurations
│   ├── sast/                # Semgrep custom rules
│   ├── secrets/             # Gitleaks configuration
│   └── iac/                 # Checkov configuration
├── shared/
│   ├── schemas/             # Blueprint metadata JSON Schema
│   └── validators/          # Blueprint validation scripts
└── docs/                    # This documentation
```

## Security Control Categories

| Category | Purpose | Tools |
|---|---|---|
| SAST | Detect vulnerabilities in source code | Semgrep |
| SCA | Detect vulnerable dependencies | pip-audit, npm audit, govulncheck |
| Secrets | Prevent credentials being committed | Gitleaks |
| IaC | Detect cloud misconfigurations | Checkov, tfsec, tflint |
| Containers | Detect vulnerabilities in images | Trivy, Hadolint |
| Coverage | Prevent test coverage regression | pytest-cov, jest --coverage |

Reusable workflows also include PR-time dependency review so manifest and lockfile changes are gated before merge, not only after the full SCA stage runs.
