# SAST: Static Application Security Testing

## What Is SAST?

Static Application Security Testing (SAST) analyzes source code without executing it to find security vulnerabilities. It examines code patterns, data flows, and API usage to detect issues before the application is deployed.

## Tool: Semgrep

All blueprints in this repository use **Semgrep** for SAST. Semgrep is:

- **Fast**: Analyzes large codebases in seconds
- **Rule-based**: Uses simple, readable pattern matching rules
- **Multi-language**: Supports Python, JavaScript/TypeScript, Go, Java, and more
- **Open source**: Free to use; Semgrep Cloud adds centralized management

### Rule Sets Used

| Rule Set | Coverage |
|---|---|
| `p/python` | Python-specific security patterns (SQLi, command injection, insecure deserialization) |
| `p/javascript` | JavaScript/TypeScript security patterns (prototype pollution, eval, XSS sinks) |
| `p/nodejs` | Node.js-specific patterns (path traversal, command injection, insecure dependencies) |
| `p/owasp-top-ten` | OWASP Top 10 2021 patterns across all languages |
| `p/secrets` | Hardcoded credentials, API keys, and tokens |

### Custom Rules

Custom rules are defined in `controls/sast/semgrep_config.yaml`. Current custom rules cover:

- Hardcoded AWS Access Key IDs
- Hardcoded JWT secrets
- Unsafe pickle deserialization
- eval() with dynamic input
- Node.js exec() with dynamic commands
- Weak hash algorithms (MD5, SHA-1)
- SQL query construction via string formatting

## SARIF Integration

Semgrep outputs SARIF, which is uploaded to the GitHub Security tab. This allows:

- Viewing all findings across all repositories in one place
- Tracking finding lifecycle (open, fixed, dismissed)
- PR annotations with findings inline in the diff
- Alerting when new findings are introduced

## Reusable Workflow

Use `github-actions/reusable/sast_semgrep.yml` when multiple repositories should share the same SAST gate without copying a full pipeline file. The workflow runs Semgrep with `p/owasp-top-ten` and `p/secrets` by default, accepts a repository-local `custom_config` such as `.semgrep/`, and uploads `semgrep.sarif` when `upload_sarif` is enabled.

Minimal caller:

```yaml
jobs:
  sast:
    uses: hiagokinlevi/secure-pipeline-blueprints/.github/workflows/sast_semgrep.yml@main
    permissions:
      contents: read
      security-events: write
```

For burn-in, set `fail_on_findings: false` for a time-boxed rollout window, review findings in the Security tab, then return to the default blocking mode.

## Handling Findings

### True Positive

A true positive finding must be remediated before the PR is merged. The fix approach depends on the finding type:

- **SQL injection via string formatting**: Use parameterized queries
- **Hardcoded credentials**: Move to environment variables or secrets manager
- **Command injection**: Use `subprocess.run(["cmd", arg])` instead of `shell=True`
- **Insecure deserialization**: Replace pickle with JSON or a safe alternative

### False Positive

To suppress a false positive, add an inline comment:

```python
# Python
result = eval(safe_expression)  # nosemgrep: k1n-python-eval-usage

# Or with multiple rules
data = pickle.loads(internal_data)  # nosemgrep: k1n-python-pickle-deserialization
```

For TypeScript/JavaScript:
```typescript
exec(hardcoded_command)  // nosemgrep: k1n-node-child-process-exec
```

Always document *why* the finding is a false positive in the comment:
```python
data = pickle.loads(internal_data)  # nosemgrep: k1n-python-pickle-deserialization
# data is loaded from our internal Redis cache, never from user input
```

## SAST Limitations

SAST cannot detect:
- **Business logic vulnerabilities**: SAST doesn't understand your application's domain
- **Runtime-only vulnerabilities**: Issues that only manifest with specific input combinations
- **Missing security controls**: SAST finds bad patterns, not absent good ones (e.g., missing authentication)
- **Configuration issues**: Use IaC scanning for cloud misconfiguration

SAST is one layer in a defense-in-depth strategy, not a complete security solution.
