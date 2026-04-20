# GitHub Actions OIDC-Based Cloud Authentication (AWS, Azure, GCP)

This guide shows how to authenticate CI/CD jobs to cloud providers **without long-lived secrets** by using GitHub Actions OIDC federation.

## Why OIDC instead of static credentials

- No stored cloud access keys in GitHub secrets
- Short-lived credentials minted per workflow run
- Fine-grained trust based on repository, branch/tag, and workflow context
- Easier key rotation posture (nothing persistent to rotate)

---

## 1) GitHub Actions requirements

In any workflow that needs federation:

```yaml
permissions:
  id-token: write
  contents: read
```

- `id-token: write` is required for GitHub to issue an OIDC JWT.
- Keep token scope minimal by using job-level permissions where possible.

Recommended hardening:
- Restrict deployments to protected branches/environments.
- Use environment protection rules for production.
- Pin action versions to immutable tags/SHAs where practical.

---

## 2) AWS setup (IAM role + trust policy)

### A. Create IAM OIDC identity provider
Provider URL:
- `https://token.actions.githubusercontent.com`

Audience:
- `sts.amazonaws.com`

### B. Create IAM role trusted by GitHub OIDC

Example trust policy (replace `ORG`, `REPO`, and branch):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:ORG/REPO:ref:refs/heads/main"
        }
      }
    }
  ]
}
```

Notes:
- Prefer exact `sub` matches over wildcards.
- For environment-based deployments, use subject patterns aligned to environment refs.

### C. Attach least-privilege permissions
Attach a narrow IAM policy to the role (example: only specific S3 bucket/path, specific ECR repo, etc.).

### D. Workflow usage

```yaml
name: deploy-aws-oidc
on:
  push:
    branches: [main]

permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials from OIDC
      uses: aws-actions/configure-aws-credentials@v4
      with:
        role-to-assume: arn:aws:iam::<ACCOUNT_ID>:role/github-actions-deploy-role
        aws-region: us-east-1

      - name: Verify caller
        run: aws sts get-caller-identity
```

---

## 3) Azure setup (Entra ID federated credential)

### A. Create app registration / service principal
Create an Entra ID application (service principal) used by GitHub Actions.

### B. Add federated credential
In the app registration, add a federated credential with:
- **Issuer**: `https://token.actions.githubusercontent.com`
- **Audience**: `api://AzureADTokenExchange`
- **Subject**: e.g. `repo:ORG/REPO:ref:refs/heads/main`

Use exact subject constraints where possible.

### C. Assign least-privilege Azure RBAC
Grant the service principal minimal role assignments at minimal scope (resource group > subscription).

### D. Workflow usage

```yaml
name: deploy-azure-oidc
on:
  push:
    branches: [main]

permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Azure login (OIDC)
      uses: azure/login@v2
      with:
        client-id: ${{ secrets.AZURE_CLIENT_ID }}
        tenant-id: ${{ secrets.AZURE_TENANT_ID }}
        subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

      - name: Verify identity
        run: az account show
```

Notes:
- These IDs are identifiers, not secrets, but storing in repo/org variables or secrets is common operationally.
- No client secret is required when using OIDC federation.

---

## 4) GCP setup (Workload Identity Federation)

### A. Create Workload Identity Pool + Provider
Provider config:
- Issuer: `https://token.actions.githubusercontent.com`
- Map claims (example):
  - `google.subject=assertion.sub`
  - `attribute.repository=assertion.repository`
  - `attribute.ref=assertion.ref`

### B. Allow principal to impersonate service account
Grant `roles/iam.workloadIdentityUser` on target service account to principal set constrained by attributes.

Example principal selector pattern:
- `principalSet://iam.googleapis.com/projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/<POOL_ID>/attribute.repository/ORG/REPO`

Optionally add `attribute.ref` condition for `refs/heads/main`.

### C. Grant least-privilege roles to service account
Assign only required roles for deployment target.

### D. Workflow usage

```yaml
name: deploy-gcp-oidc
on:
  push:
    branches: [main]

permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Authenticate to GCP via OIDC
      uses: google-github-actions/auth@v2
      with:
        workload_identity_provider: projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/<POOL_ID>/providers/<PROVIDER_ID>
        service_account: deploy-sa@<PROJECT_ID>.iam.gserviceaccount.com

      - name: Setup gcloud
      uses: google-github-actions/setup-gcloud@v2

      - name: Verify identity
        run: gcloud auth list
```

---

## 5) Security policy baseline (all clouds)

Enforce these minimums for production:

1. **OIDC only** for CI/CD cloud auth (no static keys).
2. **Exact subject matching** (repo + protected ref/environment).
3. **Least privilege** cloud role assignments.
4. **Protected deployment path** (protected branches/tags/environments).
5. **Auditability** enabled (CloudTrail / Azure Activity Logs / GCP Audit Logs).
6. **Session duration minimized** and defaults reviewed.

---

## 6) Troubleshooting quick checks

- Missing `id-token: write` permission in workflow/job.
- Subject (`sub`) mismatch between cloud trust config and workflow ref.
- Wrong audience (`aud`) value for provider.
- Role assignment missing on assumed/impersonated identity.
- Attempting from untrusted branch/PR when trust only allows `main`.

---

## Minimal reusable workflow snippet

Use this pattern in reusable workflows that need cloud federation:

```yaml
on:
  workflow_call:

jobs:
  secure-deploy:
    permissions:
      id-token: write
      contents: read
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # cloud-specific auth step here (AWS/Azure/GCP)
```
