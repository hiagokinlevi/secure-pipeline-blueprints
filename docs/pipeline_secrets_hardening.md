# Pipeline Secrets Hardening Blueprint

This blueprint provides practical guidance and examples for securely managing secrets in CI/CD pipelines using GitHub Actions.

Goals:
- Prevent plaintext secrets in repositories
- Limit exposure of credentials during pipelines
- Enforce approval and environment protection for sensitive deployments
- Encourage regular secret rotation

---

## 1. Store Secrets Using GitHub Secrets

Never hardcode credentials in workflows or source code. Store them in GitHub **Repository Secrets** or **Environment Secrets**.

Example secrets:
- AWS_ACCESS_KEY_ID
- AWS_SECRET_ACCESS_KEY
- DOCKERHUB_TOKEN
- PYPI_API_TOKEN

Example workflow usage:

name: deploy

on:
  push:
    branches: [ main ]

jobs:
  deploy:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Docker login
        run: echo "${{ secrets.DOCKERHUB_TOKEN }}" | docker login -u myuser --password-stdin

      - name: Deploy
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        run: ./deploy.sh

Key rules:
- Never commit credentials
- Avoid printing secrets to logs
- Limit secrets to the jobs that require them

---

## 2. Use GitHub Environments for Production Secrets

GitHub Environments allow additional controls for sensitive stages.

Create environment:
Repository → Settings → Environments → production

Recommended protections:
- Required reviewers
- Restricted branches
- Wait timers
- Environment-scoped secrets

Example workflow using environment protection:

jobs:
  deploy:
    runs-on: ubuntu-latest

    environment:
      name: production

    steps:
      - uses: actions/checkout@v4

      - name: Production deploy
        env:
          API_KEY: ${{ secrets.PROD_API_KEY }}
        run: ./deploy.sh

Benefits:
- Prevents automatic production deployments
- Limits which workflows can access sensitive secrets
- Adds manual approval gates

---

## 3. Prefer OIDC Over Long‑Lived Cloud Credentials

Instead of storing cloud keys, use GitHub's OpenID Connect integration to obtain short‑lived credentials.

Example AWS configuration:

permissions:
  id-token: write
  contents: read

steps:
  - name: Configure AWS credentials
    uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: arn:aws:iam::123456789012:role/github-deploy
      aws-region: us-east-1

Advantages:
- Eliminates stored AWS secrets
- Credentials expire automatically
- Access is bound to the workflow identity

---

## 4. Secret Rotation Guidance

Secrets should be rotated regularly to reduce the blast radius of credential exposure.

Suggested rotation intervals:
- Cloud credentials: 30–90 days
- API tokens: 60–90 days
- Registry tokens: 60 days

Recommended rotation process:

1. Generate a new credential
2. Add the new value to GitHub Secrets
3. Deploy using the new credential
4. Revoke the old credential

Optional scheduled workflow trigger for rotation checks:

on:
  schedule:
    - cron: "0 3 1 * *"

---

## 5. Detect Plaintext Secrets in Workflow Files

Workflow YAML files are a common place for accidental leaks. Add automated checks to detect suspicious patterns.

Example lightweight detection script:

#!/usr/bin/env python3
import pathlib
import re
import sys

PATTERNS = [
    r"aws_secret_access_key",
    r"api[_-]?key",
    r"secret[_-]?key",
    r"password\s*:",
    r"token\s*:",
    r"AKIA[0-9A-Z]{16}",
]

workflow_dir = pathlib.Path(".github/workflows")
violations = []

for path in workflow_dir.rglob("*.yml"):
    text = path.read_text(errors="ignore")
    for pattern in PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            violations.append((path, pattern))

if violations:
    print("Potential plaintext secrets detected:")
    for path, pattern in violations:
        print(f"- {path} matched pattern: {pattern}")
    sys.exit(1)

print("No obvious plaintext secrets detected.")

Example pipeline step:

- name: Check workflows for plaintext secrets
  run: python scripts/detect_plaintext_secrets.py

Note: For production environments, pair this with dedicated tools such as:
- Gitleaks
- GitHub Secret Scanning
- TruffleHog

---

## 6. Recommended Defense-in-Depth

Combine multiple controls:

- GitHub Secrets for credential storage
- Environment protection rules
- OIDC short‑lived credentials
- Secret scanning (Gitleaks)
- Workflow plaintext detection

Together these controls significantly reduce the likelihood of secret exposure in CI/CD pipelines.
