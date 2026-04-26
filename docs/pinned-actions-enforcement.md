# Enforce pinned GitHub Actions references

Use the reusable workflow to enforce that external `uses:` action references are pinned to a full commit SHA.

```yaml
jobs:
  pinned-actions:
    uses: ./.github/workflows/enforce_pinned_actions.yml
```

This check scans workflow YAML files in:

- `github-actions/**`
- `.github/workflows/**`

## Expected patterns

### Pass

```yaml
uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608
```

```yaml
uses: ./github-actions/reusable/my-local-action
```

```yaml
uses: docker://alpine:3.20
```

### Fail

```yaml
uses: actions/checkout@v4
```

```yaml
uses: aquasecurity/trivy-action@master
```
