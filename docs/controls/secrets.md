# Secret Scanning

## What Is Secret Scanning?

Secret scanning detects credentials, API keys, tokens, and other sensitive values accidentally committed to a git repository. Once a secret is committed, it may be visible in git history forever — even after deletion from the current HEAD.

## Tool: Gitleaks

All blueprints use **Gitleaks** for secret scanning. Gitleaks:

- Scans the **full git history** (`fetch-depth: 0`), not just the current working tree
- Uses regex-based rules for hundreds of known secret patterns
- Provides configurable allowlists for false positive suppression
- Integrates with GitHub Actions and GitLab CI natively

## Custom Configuration

The `controls/secrets/gitleaks_config.toml` extends Gitleaks' built-in rules with additional patterns for:

- Cloudflare API tokens and global API keys
- Semgrep App tokens
- JWT tokens hardcoded in source
- Terraform Cloud API tokens
- PEM private key blocks
- Database connection strings (PostgreSQL, MySQL)
- Slack webhook URLs

## What To Do When Gitleaks Finds a Secret

**If the secret was committed in this PR (has not been merged to main):**

1. Immediately revoke the secret at the service provider (rotate the API key, invalidate the token)
2. Remove the secret from the code and use an environment variable or secrets manager instead
3. Amend or squash the commits so the secret is not in the PR history
4. Re-run the pipeline to confirm clean

**If the secret is in a historical commit (already in main):**

1. Immediately revoke the secret — assume it has been exposed
2. Use `git filter-repo` or the GitHub Secret Scanning API to remove from history
3. Force-push to main (requires temporarily disabling branch protection — coordinate with team)
4. Audit logs for any use of the exposed credential

**The secret is already revoked and you need to silence the scan:**

Add an inline suppression to the line where the (now-invalid) value appears:
```python
OLD_REVOKED_KEY = "..."  # gitleaks:allow — revoked 2026-01-15, ticket #1234
```

## Common False Positives

| Pattern | Reason | Fix |
|---|---|---|
| Test fixture API keys | Fake keys in test files | Add test directory to allowlist in `gitleaks_config.toml` |
| Example documentation keys | Placeholder values in README | Use clearly fake values like `YOUR_API_KEY_HERE` |
| Encoded/encrypted values | Base64 or encrypted data matching key entropy | Use `--no-git` or add to allowlist |
| Internal test certificates | Self-signed certs in test fixtures | Add test path to allowlist |

## Preventing Future Leaks

1. **Pre-commit hook**: Install Gitleaks as a pre-commit hook so developers get feedback before committing:
   ```bash
   # Install gitleaks
   brew install gitleaks
   # Or: go install github.com/gitleaks/gitleaks/v8@latest

   # Add to .git/hooks/pre-commit
   gitleaks protect --staged --config controls/secrets/gitleaks_config.toml
   ```

2. **Developer education**: Add secret management guidelines to your onboarding docs

3. **Secrets manager adoption**: Migrate all secrets to a secrets manager (AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager) and eliminate hardcoded values entirely

4. **GitHub's native secret scanning**: Enable GitHub's built-in secret scanning (Settings > Security > Secret scanning) as a complementary layer
