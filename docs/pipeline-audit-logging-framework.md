# Pipeline Audit Logging Framework

This guide provides **production-ready examples** to export CI/CD pipeline logs to centralized systems for auditability and incident investigation.

Targets covered:

- **ELK** (Elasticsearch via HTTP ingest endpoint / Logstash HTTP input)
- **Loki** (Grafana Loki `/loki/api/v1/push`)

Platforms covered:

- GitHub Actions
- GitLab CI
- Azure DevOps

---

## 1) Audit Logging Design Requirements

For useful investigations, include these fields in every exported event:

- `platform` (github-actions, gitlab-ci, azure-devops)
- `pipeline_id` / `run_id`
- `job_id` / `job_name`
- `repo` / `project`
- `branch` / `ref`
- `commit_sha`
- `actor` / `triggered_by`
- `status`
- `timestamp`
- `log_type` (console, security-scan, artifact)

Security requirements:

- Send logs over TLS (`https`).
- Store tokens in platform secret stores only.
- Never echo secrets in job output.
- Apply retention + immutable storage policy in your SIEM/log platform.

---

## 2) GitHub Actions Example (ELK + Loki)

Create `.github/workflows/audit-log-export.yml`:

```yaml
name: Audit Log Export

on:
  workflow_run:
    workflows: ["CI", "Secure Pipeline", "Python Secure Pipeline"]
    types: [completed]

jobs:
  export-logs:
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
    steps:
      - name: Export workflow metadata + logs to ELK and Loki
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          ELK_INGEST_URL: ${{ secrets.ELK_INGEST_URL }}
          ELK_API_KEY: ${{ secrets.ELK_API_KEY }}
          LOKI_URL: ${{ secrets.LOKI_URL }}
          LOKI_USER: ${{ secrets.LOKI_USER }}
          LOKI_TOKEN: ${{ secrets.LOKI_TOKEN }}
          REPO: ${{ github.repository }}
          RUN_ID: ${{ github.event.workflow_run.id }}
        run: |
          set -euo pipefail

          sudo apt-get update -y >/dev/null
          sudo apt-get install -y jq >/dev/null

          meta=$(gh api \
            repos/${REPO}/actions/runs/${RUN_ID} \
            --jq '{platform:"github-actions", pipeline_id:.id, workflow:.name, status:.conclusion, actor:.actor.login, branch:.head_branch, commit_sha:.head_sha, timestamp:.updated_at, repo:.repository.full_name}')

          logs_url=$(gh api repos/${REPO}/actions/runs/${RUN_ID} --jq '.logs_url')
          curl -sSL -H "Authorization: Bearer ${GH_TOKEN}" -o run_logs.zip "${logs_url}"

          # ELK ingest (JSON event)
          curl -sS -X POST "${ELK_INGEST_URL}" \
            -H "Authorization: ApiKey ${ELK_API_KEY}" \
            -H "Content-Type: application/json" \
            -d "${meta}"

          # Loki ingest (labels + log line)
          ts_ns=$(date +%s%N)
          loki_payload=$(jq -cn \
            --arg ts "$ts_ns" \
            --arg repo "$REPO" \
            --argjson meta "$meta" \
            '{streams:[{stream:{platform:"github-actions",repo:$repo,log_type:"pipeline-meta"},values:[[$ts,($meta|tostring)]]}]}' )

          curl -sS -u "${LOKI_USER}:${LOKI_TOKEN}" \
            -H "Content-Type: application/json" \
            -X POST "${LOKI_URL}/loki/api/v1/push" \
            -d "${loki_payload}"
```

Required GitHub secrets:

- `ELK_INGEST_URL`
- `ELK_API_KEY`
- `LOKI_URL`
- `LOKI_USER`
- `LOKI_TOKEN`

---

## 3) GitLab CI Example (ELK + Loki)

Add to `.gitlab-ci.yml`:

```yaml
stages:
  - build
  - test
  - audit_export

audit_log_export:
  stage: audit_export
  image: alpine:3.20
  rules:
    - if: '$CI_PIPELINE_SOURCE'
  before_script:
    - apk add --no-cache curl jq
  script:
    - |
      set -euo pipefail

      META=$(jq -cn \
        --arg platform "gitlab-ci" \
        --arg pipeline_id "$CI_PIPELINE_ID" \
        --arg job_id "$CI_JOB_ID" \
        --arg project "$CI_PROJECT_PATH" \
        --arg branch "$CI_COMMIT_REF_NAME" \
        --arg commit_sha "$CI_COMMIT_SHA" \
        --arg actor "$GITLAB_USER_LOGIN" \
        --arg status "$CI_JOB_STATUS" \
        --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{platform:$platform,pipeline_id:$pipeline_id,job_id:$job_id,project:$project,branch:$branch,commit_sha:$commit_sha,actor:$actor,status:$status,timestamp:$timestamp,log_type:"pipeline-meta"}')

      curl -sS -X POST "$ELK_INGEST_URL" \
        -H "Authorization: Bearer $ELK_TOKEN" \
        -H "Content-Type: application/json" \
        -d "$META"

      TS_NS=$(date +%s%N)
      LOKI_PAYLOAD=$(jq -cn \
        --arg ts "$TS_NS" \
        --arg project "$CI_PROJECT_PATH" \
        --arg line "$META" \
        '{streams:[{stream:{platform:"gitlab-ci",project:$project,log_type:"pipeline-meta"},values:[[$ts,$line]]}]}' )

      curl -sS -u "$LOKI_USER:$LOKI_TOKEN" \
        -H "Content-Type: application/json" \
        -X POST "$LOKI_URL/loki/api/v1/push" \
        -d "$LOKI_PAYLOAD"
```

Set GitLab CI/CD variables (masked/protected):

- `ELK_INGEST_URL`
- `ELK_TOKEN`
- `LOKI_URL`
- `LOKI_USER`
- `LOKI_TOKEN`

---

## 4) Azure DevOps Example (ELK + Loki)

Add stage/job to `azure-pipelines.yml`:

```yaml
stages:
- stage: AuditExport
  displayName: Export Pipeline Audit Logs
  jobs:
  - job: ExportLogs
    pool:
      vmImage: ubuntu-latest
    steps:
    - bash: |
        set -euo pipefail

        META=$(jq -cn \
          --arg platform "azure-devops" \
          --arg pipeline_id "$(Build.BuildId)" \
          --arg job_name "$(Agent.JobName)" \
          --arg project "$(System.TeamProject)" \
          --arg repo "$(Build.Repository.Name)" \
          --arg branch "$(Build.SourceBranch)" \
          --arg commit_sha "$(Build.SourceVersion)" \
          --arg actor "$(Build.RequestedFor)" \
          --arg status "$(Agent.JobStatus)" \
          --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
          '{platform:$platform,pipeline_id:$pipeline_id,job_name:$job_name,project:$project,repo:$repo,branch:$branch,commit_sha:$commit_sha,actor:$actor,status:$status,timestamp:$timestamp,log_type:"pipeline-meta"}')

        curl -sS -X POST "$(ELK_INGEST_URL)" \
          -H "Authorization: ApiKey $(ELK_API_KEY)" \
          -H "Content-Type: application/json" \
          -d "$META"

        TS_NS=$(date +%s%N)
        LOKI_PAYLOAD=$(jq -cn \
          --arg ts "$TS_NS" \
          --arg repo "$(Build.Repository.Name)" \
          --arg line "$META" \
          '{streams:[{stream:{platform:"azure-devops",repo:$repo,log_type:"pipeline-meta"},values:[[$ts,$line]]}]}' )

        curl -sS -u "$(LOKI_USER):$(LOKI_TOKEN)" \
          -H "Content-Type: application/json" \
          -X POST "$(LOKI_URL)/loki/api/v1/push" \
          -d "$LOKI_PAYLOAD"
      displayName: Send metadata to ELK and Loki
```

Store secrets in Azure Pipeline variable groups or Key Vault-backed variables:

- `ELK_INGEST_URL`
- `ELK_API_KEY`
- `LOKI_URL`
- `LOKI_USER`
- `LOKI_TOKEN`

---

## 5) Operational Hardening Checklist

- Configure ingestion endpoints behind auth + IP allow-list where possible.
- Add schema validation in ingest pipeline (reject malformed events).
- Tag events with environment (`dev`, `staging`, `prod`).
- Enable retention policies (e.g., 90–365 days based on compliance).
- Add correlation IDs to security scan outputs so findings map to exact pipeline run.

This framework provides the minimum reliable pattern to centralize CI/CD audit events across supported platforms.
