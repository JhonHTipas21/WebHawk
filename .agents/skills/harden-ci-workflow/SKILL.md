---
name: harden-ci-workflow
description: Guidelines and best practices for hardening GitHub Actions workflows against supply chain attacks, ensuring least-privilege permissions, and performing security scans.
---

# GitHub Actions Workflow Hardening Guide

This skill details how to design, secure, and maintain GitHub Actions workflows to protect the repository from dependency hijacking and malicious executions.

## Supply Chain Defense

### Pinning Third-Party Actions to Commit SHAs
Do not use mutable version tags (e.g., `@v4`, `@v2.3.4`) for third-party actions, as tags can be updated or hijacked. Always pin third-party actions to their immutable 40-character commit SHAs. Add comments to indicate the user-friendly version tag.

```yaml
# Correct pattern:
- name: Checkout Code
  uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1 pinned SHA
```

### Avoiding pull_request_target Triggers for Untrusted Code
Never use the `pull_request_target` trigger unless absolutely necessary and securely configured. Unlike `pull_request`, `pull_request_target` runs in the context of the base branch and has write permissions and access to repository secrets, which allows malicious PRs to execute arbitrary code with privileges.

## Least-Privilege Permissions

Explicitly configure permissions for the workflow or individual jobs to block arbitrary write access. If a permission is not needed, set it to `read` or omit it.

```yaml
# Correct pattern:
permissions:
  contents: read
  security-events: write # Required for CodeQL
  pull-requests: read
```

## Mandatory CI Security Scans

### Secret Scanning (Gitleaks)
Integrate secret scanning to prevent developers from committing credentials, API tokens, or webhook secrets.

```yaml
- name: Run Gitleaks
  uses: gitleaks/gitleaks-action@v2 # Managed Org Action
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Static Application Security Testing (SAST)
Use static analysis tools like GitHub CodeQL to inspect the codebase for security flaws (e.g., injection, insecure comparisons) on every push and PR.

### Workflow Linting (actionlint)
Lint GitHub Actions files using `actionlint` to enforce syntax correctness and security constraints before merging PRs.
