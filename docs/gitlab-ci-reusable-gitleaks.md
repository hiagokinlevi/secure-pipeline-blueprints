# Reusable GitLab CI Gitleaks Template

Use the reusable template to run secret scanning with your repository's existing `.gitleaks.toml` config and emit a JSON report artifact.

```yaml
include:
  - project: your-group/secure-pipeline-blueprints
    ref: main
    file: /gitlab-ci/reusable/gitleaks.yml

stages:
  - security

gitleaks_scan:
  extends: gitleaks_scan
```

## Behavior

- Uses `.gitleaks.toml` from the target project repo.
- Writes `gitleaks-report.json` as a job artifact (`when: always`).
- Fails the job (and pipeline stage) when leaks are detected.
