# pull_request_target checkout guard

This repository provides a reusable workflow guard: `.github/workflows/reusable-prtarget-guard.yml`.

## Why this exists

`pull_request_target` runs in the context of the base repository and can access privileged tokens/secrets depending on configuration. If such a workflow checks out **fork PR head code** (for example `${{ github.event.pull_request.head.sha }}` or `refs/pull/<n>/head`) and then executes it, an attacker can modify that code to:

- exfiltrate secrets or tokens
- execute injected commands with elevated repository permissions

## Guard behavior

The guard scans changed workflow files and fails if it finds a `pull_request_target` workflow using `actions/checkout` with fork-head refs/SHAs.

## Safe baseline

For untrusted PR contexts, only use trusted refs (default checkout behavior, base branch, or base SHA). If you need to run untrusted PR code, do it in a `pull_request` workflow with least privileges and without secrets.
