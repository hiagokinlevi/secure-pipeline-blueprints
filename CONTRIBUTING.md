# Contributing to secure-pipeline-blueprints

Thank you for contributing. This project grows by practitioners sharing battle-tested, well-documented secure pipeline blueprints.

## Ways to Contribute

- **Add a new blueprint**: A new stack (Go, Java, Ruby, .NET) or platform (Azure DevOps)
- **Improve an existing blueprint**: Better gate logic, updated tool versions, more thorough comments
- **Add a new security control**: A control not yet covered (DAST, fuzzing, license scanning)
- **Add a reusable workflow**: Factor out a control so other repos can reuse it
- **Improve documentation**: Usage guides, tutorials, labs
- **Report issues**: Broken pipelines, incorrect tool configurations, outdated versions

## Before You Start

1. Check existing issues and pull requests to avoid duplicates.
2. For new platforms or major architectural changes, open a discussion issue first.
3. All blueprints must follow the **security-first** principle: security controls are mandatory, not optional.

## Blueprint Quality Bar

Every blueprint must:

1. **Include a header comment block** explaining what the blueprint does, which security controls it includes, and how to use it.
2. **Comment every non-obvious step** — especially security-relevant decisions (e.g., why `--require-hashes`, why `fetch-depth: 0`).
3. **Use least-privilege permissions** (`permissions:` block with minimum necessary scopes).
4. **Pin action versions** to a major version tag (e.g., `@v4`, not `@latest`).
5. **Fail on security findings** — security controls must be gates, not just informational.
6. **Upload SARIF** to GitHub Security tab where supported.
7. **Document required secrets** in the header comment.

## Development Setup

Blueprints are YAML/HCL/TOML files. To validate them locally:

```bash
# Validate blueprint metadata
pip install jsonschema pyyaml
python shared/validators/validate_blueprint.py --all

# For GitHub Actions YAML validation (optional)
pip install yamllint
yamllint github-actions/python/full_pipeline.yml
```

## Pull Request Process

1. Fork the repository and create a feature branch: `feat/add-golang-blueprint`
2. Run the validator to confirm your blueprint metadata is valid.
3. Test the pipeline in your own GitHub repository before submitting.
4. Open a PR with:
   - What language/platform/stack does this blueprint cover?
   - Which security controls are included?
   - How was it tested?
   - Known limitations or gotchas?

## Commit Style

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add Go secure pipeline blueprint for GitHub Actions
fix: pin Semgrep action to v1 to prevent version drift
docs: add Azure DevOps usage guide
chore: update pip-audit to v2.7.0
```

## Code of Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
