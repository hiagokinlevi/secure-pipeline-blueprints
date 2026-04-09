# Pipeline Security Review Prompts

Prompts for using AI assistants to help review and improve CI/CD pipeline security.

---

## 1. Pipeline Security Audit

Use when you want a comprehensive review of an existing pipeline.

```
Please review this CI/CD pipeline configuration for security issues:

Platform: [GitHub Actions / GitLab CI / Azure DevOps]
Stack: [Python / Node.js / Terraform / etc.]

[PASTE THE PIPELINE YAML/HCL]

Please evaluate:
1. What security controls are present? (SAST, SCA, secrets scanning, IaC scanning, etc.)
2. What security controls are missing for this stack?
3. Are there any permissions that are overly broad?
4. Are action/image versions pinned?
5. Are there any supply chain risk concerns?
6. Are secrets handled securely (referenced via ${{ secrets.X }} not hardcoded)?
7. What is the minimum viable improvement to add if you could only change one thing?

Compare against the secure-pipeline-blueprints standards for this stack.
```

---

## 2. Semgrep Finding Triage

Use when Semgrep reports a finding and you need help understanding it.

```
Semgrep reported the following finding in my code:

Rule ID: [e.g., python.lang.security.audit.dangerous-eval]
Severity: [HIGH/MEDIUM/LOW]
File: [filename and line number]

Code at the finding location:
[PASTE THE CODE SNIPPET]

Context:
- This function receives input from: [describe the input source]
- This function is called from: [describe the callers]
- The application type is: [web API / CLI tool / etc.]

Please tell me:
1. Is this a true positive or false positive? Explain why.
2. If true positive, what is the attack scenario?
3. What is the recommended remediation?
4. If false positive, how should I suppress it with proper justification?
```

---

## 3. pip-audit / npm audit Finding Triage

Use when SCA finds a vulnerable dependency.

```
pip-audit / npm audit found the following vulnerability:

Package: [name]==[version]
CVE: [CVE-YYYY-XXXXX]
Severity: [CRITICAL/HIGH/MEDIUM/LOW]
Description: [paste the CVE description]
Fixed in: [version]

Our application:
- Uses this package for: [describe what you use it for]
- This specific package version is: [a direct dependency / transitive dependency]
- The vulnerable function/method is: [describe if known]

Please help me:
1. Does this vulnerability affect our usage pattern?
2. Is upgrading to [fixed version] likely to be a breaking change?
3. Are there any workarounds if upgrading is not immediately feasible?
4. What is the risk of not fixing this immediately?
```

---

## 4. Coverage Gate Calibration

Use when setting up a coverage gate for the first time.

```
I am setting up a test coverage gate for a [Python/Node.js/Go] project.

Current state:
- Current coverage: [X%]
- Number of test files: [N]
- Lines of code: [approximately N]
- Project type: [web API / data pipeline / CLI tool / library]
- Team size: [N developers]
- Test maturity: [new tests / existing suite / legacy code with few tests]

Please help me:
1. What is a realistic starting coverage threshold for this project?
2. What is an appropriate quarterly progression plan to reach 80%?
3. Which types of code should be excluded from coverage requirements? (migrations, generated code, etc.)
4. How should I handle a large legacy codebase with < 30% coverage?
```

---

## 5. Pipeline Migration

Use when migrating from an existing CI system to a more secure one.

```
I need to migrate a CI/CD pipeline from [current platform] to [target platform].

Current pipeline (simplified):
[PASTE OR DESCRIBE CURRENT PIPELINE]

Technology stack: [Python / Node.js / Terraform / etc.]
Current security controls: [list what you have, e.g., "only unit tests, no security scanning"]
Target: [describe what you want, e.g., "match the secure-pipeline-blueprints standard"]

Constraints:
- [e.g., must maintain the same deployment triggers]
- [e.g., cannot use paid services]
- [e.g., team is new to the target platform]

Please help me:
1. Recommend which secure-pipeline-blueprints blueprint to start with
2. Map the existing pipeline steps to the new platform
3. Identify what new security controls need to be added
4. Suggest a migration plan that minimizes disruption to the team
```

---

## 6. Secret Remediation

Use when Gitleaks finds a secret in the repository history.

```
Gitleaks found a potential secret in our repository:

Finding:
- Rule ID: [e.g., k1n-cloudflare-api-token]
- File: [filename]
- Commit: [commit hash]
- Line: [the line content, redact the actual secret value]

Questions:
1. Is this likely a real secret or a false positive based on the pattern?
2. What is the blast radius if this secret is real and has been exposed?
3. What service/system does this type of credential typically access?
4. What are the steps to revoke and rotate this type of credential?
5. How do we remove this from the git history permanently?
6. How do we prevent this type of secret from being committed again?
```
