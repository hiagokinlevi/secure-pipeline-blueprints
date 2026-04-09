# SCA: Software Composition Analysis

## What Is SCA?

Software Composition Analysis (SCA) scans your application's third-party dependencies for known security vulnerabilities (CVEs). Modern applications typically include hundreds of open source libraries, and any of them may have vulnerabilities.

## Tools by Stack

| Stack | Tool | Database |
|---|---|---|
| Python | pip-audit | OSV (Open Source Vulnerabilities) |
| Node.js | npm audit | npm advisory database + OSV |
| Go | govulncheck | Go vulnerability database |
| Java | Dependency-Check (planned) | NVD |
| Containers | Trivy (in container blueprint) | OSV + NVD + GitHub Advisories |

## Python: pip-audit

`pip-audit` scans Python requirements against the OSV database.

### Gate Logic

The blueprint fails the build when:
- A vulnerability exists in an installed package AND
- A fixed version is available in the same major version line

Unfixable vulnerabilities (no upstream fix) are reported but do not fail the build. This prevents situations where the build is permanently broken by a vulnerability that has no remediation.

### Remediation

When pip-audit finds a fixable vulnerability:

```bash
# Check what needs updating
pip-audit --requirement requirements.txt

# Update the specific package
pip install --upgrade affected-package==fixed.version

# Regenerate requirements.txt with hashes
pip-compile --generate-hashes --upgrade-package affected-package requirements.in
```

## Node.js: npm audit

`npm audit` checks installed packages against the npm advisory database.

### Gate Logic

The blueprint uses `--audit-level=high`, which fails on HIGH and CRITICAL severity vulnerabilities. MODERATE and LOW findings are reported but do not fail the build.

### Remediation

```bash
# Show all vulnerabilities
npm audit

# Auto-fix compatible updates (does not break semver)
npm audit fix

# Fix including breaking changes (review carefully)
npm audit fix --force
```

## Go: govulncheck

`govulncheck` scans Go modules and call graphs against the Go vulnerability database. The Go blueprint runs it against `./...` so CI fails when a reachable vulnerable dependency or standard-library issue is present.

### Remediation

```bash
# Review reachable vulnerabilities locally
govulncheck ./...

# Upgrade the affected module, then refresh module metadata
go get example.com/affected/module@fixed.version
go mod tidy
```

## Managing Accepted Risks

Sometimes you cannot immediately fix a vulnerability (e.g., no fix available, breaking changes in the fix version, or the vulnerable code path is not exercised in your application). In these cases:

1. **Document the accepted risk**: Create a GitHub issue with the CVE ID, severity, affected package, and reason for not fixing.
2. **Set a review date**: Re-evaluate when a fix becomes available.
3. **Suppress in CI**: If the vulnerability truly does not apply to your usage, configure an exemption.

For pip-audit exemptions, use `pip-audit --ignore-vuln CVE-YYYY-XXXXX` with a documented reason in your CI workflow.

## PR Dependency Review

For GitHub pull requests, use `github-actions/reusable/dependency_review.yml` to block dependency changes before merge. This catches newly introduced vulnerable packages even when the main branch is currently clean.

Recommended baseline:

- Trigger on `pull_request`
- Set `permissions.contents=read`
- Set `permissions.pull-requests=write`
- Fail on `high` or stricter severity
- Enable PR summaries so reviewers see the exact dependency deltas

## SCA Limitations

- SCA only catches **known** vulnerabilities (in public CVE/OSV databases)
- Zero-day vulnerabilities in dependencies are not detected
- SCA does not analyze how a vulnerable function is used — a dependency may be vulnerable but the vulnerable code path not reachable in your application
- SCA for transitive dependencies (dependencies of dependencies) can produce findings outside your direct control
