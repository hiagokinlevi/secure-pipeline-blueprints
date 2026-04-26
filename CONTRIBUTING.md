# Contributing

Thanks for helping improve **secure-pipeline-blueprints**.

## Local pre-commit checks (recommended)

This repo includes lightweight local checks to catch broken security config updates before push (Gitleaks + Semgrep config sanity).

```bash
python -m pip install pre-commit
pre-commit install
pre-commit run --all-files
```

What runs locally:
- `gitleaks.toml` TOML validation + targeted regex sanity check
- Semgrep YAML/rule config validation + basic rule-id sanity check

If a hook fails, fix the config and re-run:

```bash
pre-commit run --all-files
```
