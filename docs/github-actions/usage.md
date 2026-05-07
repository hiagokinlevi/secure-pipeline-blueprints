# GitHub Actions Usage

## Enforce root `permissions: {}` policy in PRs

Add a PR validation workflow in your repository (for example, `.github/workflows/policy_permissions.yml`) that calls the reusable policy workflow:

```yaml
name: Policy - Root Permissions Baseline

on:
  pull_request:

permissions: {}

jobs:
  enforce:
    uses: secure-pipeline-blueprints/secure-pipeline-blueprints/.github/workflows/enforce_root_permissions.yml@main
```

This check fails when any workflow under `.github/workflows/` is missing a root-level `permissions` block set to deny-all (`{}` or explicit `none` values), forcing explicit job-level permission grants.
