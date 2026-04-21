# Roadmap

## Phase 1 — Bootstrap (Current)

**Goal**: Establish foundation with high-quality blueprints for the most common stacks on GitHub Actions.

- [x] Python secure pipeline blueprint (GitHub Actions)
- [x] Node.js secure pipeline blueprint (GitHub Actions)
- [x] Terraform/IaC security pipeline (GitHub Actions)
- [x] Container scanning pipeline (GitHub Actions)
- [x] Reusable secret scanning workflow (GitHub Actions)
- [x] GitLab CI Python blueprint
- [x] Semgrep custom rules configuration
- [x] Gitleaks custom configuration
- [x] Checkov configuration for Terraform
- [x] Blueprint metadata schema and validator
- [x] Documentation: overview, pipeline security model, usage guides

---

## Phase 2 — Platform and Stack Expansion

**Goal**: Cover Go, Java, and Azure DevOps.

- [x] Go secure pipeline blueprint (GitHub Actions)
- [ ] Java/Maven secure pipeline blueprint (GitHub Actions)
- [ ] Java/Gradle secure pipeline blueprint (GitHub Actions)
- [ ] Azure DevOps Python blueprint
- [ ] Azure DevOps Node.js blueprint
- [ ] Azure DevOps Terraform blueprint
- [ ] GitLab CI Node.js blueprint
- [ ] GitLab CI Terraform blueprint
- [ ] .NET/C# pipeline blueprint

---

## Phase 3 — Advanced Controls

**Goal**: Add DAST, fuzzing, and dependency review controls.

- [ ] DAST integration: OWASP ZAP API scan as a pipeline stage
- [x] GitHub Dependency Review Action for PR-level SCA
- [ ] Fuzzing: Go fuzzing integration
- [ ] License scanning: FOSSA or licensee integration
- [x] Reusable SAST workflow (callable from any repo)
- [ ] Reusable SCA workflow (callable from any repo)
- [ ] SBOM generation: syft + cosign attestation

---

## Phase 4 — Policy as Code

**Goal**: Define security requirements as code, enforce them automatically.

- [ ] OPA policy: minimum security controls p

## Automated Completions
- [x] GitHub Actions SHA Pinning Linter Workflow (cycle 25)
