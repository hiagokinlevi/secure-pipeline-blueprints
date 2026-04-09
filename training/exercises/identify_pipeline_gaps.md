# Exercise: Identify Pipeline Security Gaps

**Type**: Analysis exercise
**Difficulty**: Intermediate
**Time**: 30-45 minutes

---

## Objective

Review the following example CI/CD pipeline configurations and identify security gaps. For each gap, describe the risk it creates and how it would be addressed using secure-pipeline-blueprints.

---

## Pipeline A: Basic Python CI

```yaml
name: Python CI

on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@latest
      - uses: actions/setup-python@latest
        with:
          python-version: "3.x"
      - run: pip install -r requirements.txt
      - run: pytest tests/
```

### Questions for Pipeline A

1. List all security controls that are **missing** from this pipeline.
2. What supply chain attack surface does `actions/checkout@latest` create? How would you mitigate it?
3. What risk does `pip install -r requirements.txt` without `--require-hashes` create?
4. What would a malicious actor be able to do if `requirements.txt` was tampered with?
5. How would you prioritize adding security controls to this pipeline? List in order of impact.

**Model Answer** (read after completing):
- Missing: SAST, SCA, secrets scanning, permissions block, coverage gate
- `@latest` floats to the newest version — a compromised action release could inject malicious steps; pin to `@v4`
- Without hashes, a compromised PyPI package could install a different version; use `--require-hashes`
- An attacker could inject a package that exfiltrates environment variables (including `GITHUB_TOKEN`) to an external server
- Priority: (1) Secrets scanning — zero code changes needed, (2) SCA — catches known CVEs immediately, (3) SAST — after test suite is green

---

## Pipeline B: Node.js with Some Security

```yaml
name: Node CI

on:
  push:
    branches: [main]
  pull_request:

permissions: write-all

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "latest"
      - run: npm install
      - run: npm test
      - run: npm audit --audit-level=critical
      - name: Deploy to staging
        run: npm run deploy:staging
        env:
          DEPLOY_KEY: "ssh-rsa AAAAB3Nza... (actual key)"
```

### Questions for Pipeline B

1. What critical security error is visible in this pipeline?
2. What is wrong with `permissions: write-all`?
3. What is the risk of running `npm install` vs `npm ci`?
4. The developer added `npm audit --audit-level=critical` — is this sufficient? What would you improve?
5. What concern does deploying from a PR pipeline raise (the `on: pull_request` + deploy combination)?

**Model Answer**:
- The `DEPLOY_KEY` value in the env block is a hardcoded SSH private key — a critical secret exposure
- `write-all` grants maximum GitHub token permissions; an attacker could write to the repository, publish packages, etc. Use least-privilege: `contents: read`
- `npm install` can install different versions than `package-lock.json`; `npm ci` enforces the lockfile
- `--audit-level=critical` only fails on CRITICAL; HIGH severity vulnerabilities are ignored — should be `--audit-level=high`
- Pull request pipelines from forks can access secrets; never deploy from pull_request events, only from push to main

---

## Pipeline C: Terraform with No Security

```yaml
name: Terraform

on:
  pull_request:
  push:
    branches: [main]

jobs:
  terraform:
    runs-on: ubuntu-latest
    env:
      AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
      AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - run: terraform init
      - run: terraform validate
      - run: terraform plan
      - if: github.ref == 'refs/heads/main'
        run: terraform apply -auto-approve
```

### Questions for Pipeline C

1. What IaC security controls are completely absent from this pipeline?
2. What is the risk of running `terraform apply -auto-approve` directly from the pipeline?
3. How should the plan/apply split be handled more securely?
4. Is there any secret scanning in this pipeline? What could happen without it?
5. What changes would you make to align this with the `github-actions/iac/terraform_pipeline.yml` blueprint?

**Model Answer**:
- Missing: Checkov (IaC security scanning), tfsec, tflint, Gitleaks, SARIF upload
- Auto-approve bypasses human review of the plan; a malicious PR could add `aws_s3_bucket_public_access_block { block_public_acls = false }` that would be applied automatically
- Use "plan on PR, apply on merge" pattern with a required plan review step; consider Terraform Cloud run tasks for plan approvals
- Without secrets scanning, a developer could accidentally commit an AWS key in a .tfvars file — it would be applied as Terraform environment context, and the key would be in git history
- Add: terraform fmt -check, tflint, checkov scan, tfsec scan, Gitleaks, separate plan-only step on PR, apply-only step on merge to main

---

## Scoring

| Gap Identified | Points |
|---|---|
| Missing security control (per control) | 1 |
| Security control present but misconfigured | 2 |
| Critical security error (hardcoded secret, write-all, etc.) | 3 |
| Correct remediation with tool name | 1 bonus |

Score yourself after completing all three pipelines. A score of 15+ indicates a strong understanding of pipeline security fundamentals.
