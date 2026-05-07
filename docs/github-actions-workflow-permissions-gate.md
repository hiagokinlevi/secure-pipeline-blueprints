# GitHub Actions Workflow Permissions Gate

Use this reusable workflow to enforce a minimum `permissions:` policy on changed workflow files in pull requests.

## What it enforces

For changed files under `.github/workflows/*.yml` or `.yaml`:

- Requires a **top-level** `permissions:` block.
- Fails if broad default `write-all` is used.
- Allows explicit write scopes only from a small allowlist:
  - `security-events: write` (for SARIF upload use cases)

## Example usage in PR validation

Create `.github/workflows/policy-workflow-permissions.yml` in your repository:

```yaml
name: Policy - Workflow Permissions

on:
  pull_request:
    paths:
      - '.github/workflows/*.yml'
      - '.github/workflows/*.yaml'

jobs:
  enforce:
    uses: secure-pipeline-blueprints/secure-pipeline-blueprints/.github/workflows/enforce_workflow_permissions.yml@main
```

If your org/vendor mirrors reusable workflows under `github-actions/reusable/`, reference that published path/ref according to your distribution setup.
