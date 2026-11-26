---
phase: 07-release-1-0-certification
plan: 19
subsystem: conformance / certification
tags: [conformance, openid-certification, OIDC-23, ci]
requires: ["07-13"]
provides:
  - "docs/CERTIFICATION.md owner runbook with a Status section for 07-24"
  - "tests/conformance/setup.sh --public (hosted-suite provisioning)"
  - "conformance.yml on v* tags, 90-day artifact retention for tag runs"
affects: ["07-22 (docs/SUMMARY.md entry)", "07-23 (gate run)", "07-24 (owner checkpoint)"]
tech-stack:
  added: []
  patterns: ["retention-days expression: tag ? 90 : 0 (0 = repository default)"]
key-files:
  created:
    - docs/CERTIFICATION.md
  modified:
    - tests/conformance/setup.sh
    - tests/conformance/README.md
    - .github/workflows/conformance.yml
decisions:
  - "Public mode also retargets the client callbacks to SUITE_URL (default https://www.certification.openid.net), because the hosted suite's callbacks differ from the local suite's. SUITE_ALIAS can be overridden in both modes, and a non-default alias is written into the rendered configs"
  - "Non-tag conformance runs keep the repository default artifact retention (retention-days 0). Only tag runs are raised to 90 days"
  - "Teardown in the runbook means destroying the data directory (KEK and signing keys), not just deleting clients, because OIDF publishes the logs"
metrics:
  duration: "~35 min"
  completed: 2026-11-26
---

# Phase 7 Plan 19: Certification package Summary

This plan adds an owner runbook for OpenID certification (hosted suite, five plans, evidence ZIPs, submission checklist, then revoke and tear down). It also adds a `setup.sh --public` mode that provisions a publicly reachable deployment for the hosted suite, and a conformance workflow that also runs on `v*` tags and keeps the tag runs' evidence for 90 days.

## Conformance result (local, Docker available)

I ran `tests/conformance/run.sh all` locally on HEAD `c291637`. The code tree was clean apart from the new setup.sh, so the default local mode of the modified script was exercised. The run used suite `release-v5.3.5` and the committed expected files, which are unchanged. `run-test-plan.py` exited with 0.

| Plan | Modules | Conditions |
|------|---------|------------|
| Basic OP | 36 | 0 failures, 0 warnings |
| Config OP | 2 | 0 failures, 0 warnings |
| Form Post OP | 36 | 0 failures, 0 warnings |
| RP-Initiated Logout OP | 12 | 0 failures, 0 warnings |
| Back-Channel Logout OP | 3 | 0 failures, 0 warnings |

Config OP stays free of warnings with the two RFC 9126 discovery names from 07-13 (`pushed_authorization_request_endpoint`, `require_pushed_authorization_requests`). The expected skip was used by Basic and Form Post as before, with no new skips. CI on the gate commit (07-23) is still the authoritative run.

## setup.sh change

- `setup.sh [--public] <setup-url> <out-config> <out-backchannel-config>`. Existing callers that pass three arguments behave exactly as before.
- Public mode:
  - The setup URL must be https.
  - curl runs without `--resolve` and without `-k`.
  - The callbacks, post-logout redirect and back-channel URIs use `SUITE_URL`, which defaults to `https://www.certification.openid.net` in public mode and stays `https://localhost.emobix.co.uk:8443` in local mode.
- `SUITE_ALIAS` (default `anvilid`) is validated against `[A-Za-z0-9._-]+`. When it differs from the template, it is written into the rendered configs' `alias` field. The default alias keeps the template's formatting byte for byte.
- Checks run:
  - `bash -n` passes.
  - Negative paths: http URL with `--public` gives rc 2, wrong argument count gives rc 2, a bad alias gives rc 2.
  - Public mode against an unresolvable host makes curl do a real DNS lookup (no loopback pinning).
  - `shellcheck` is not installed here.

## Workflow change

- `on.push.tags: ["v*"]`.
- `retention-days: ${{ startsWith(github.ref, 'refs/tags/') && 90 || 0 }}` on the `conformance-results` upload. 0 is upload-artifact's "repository default", so other runs are unchanged.
- The YAML parses. `actionlint` is not installed.

## Runbook (docs/CERTIFICATION.md)

The runbook covers:

- self-hosted CI versus the hosted suite
- the five plans with exact variant strings
- owner decisions (payment or waiver, membership, hostname, deployment name and version, signer), with fees and criteria linked to openid.net rather than restated
- a throwaway deployment with a fresh data directory, the login quota raised as in CI, and no outbound overrides needed
- `setup.sh --public`
- running the plans in the UI, or with `run-test-plan.py` plus `CONFORMANCE_TOKEN` (checked in the suite script)
- checking results: FINISHED, REVIEW screenshots, and why `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported` is SKIPPED
- "Publish for certification" ZIPs
- the submission checklist, with no personal data
- revocation and teardown
- the relation between the rc and 1.0.0
- a `## Status` section for 07-24

## Deviations from Plan

1. **[Rule 2] Public mode also retargets the suite callbacks.** Without this, clients provisioned for the hosted suite would carry `localhost.emobix.co.uk` callbacks and every module would fail. I added the `SUITE_URL` and `SUITE_ALIAS` environment overrides for this. The local defaults are unchanged and CI proves the local mode. Files: tests/conformance/setup.sh.
2. **Links to repository files outside `docs/` use GitHub URLs** in docs/CERTIFICATION.md. A relative `../tests/...` link would fail `scripts/check-docs-site.sh` (broken internal links) once 07-22 adds the page to the site. Commit 7f9e883.

## Notes for other plans

- 07-22: docs/SUMMARY.md has no entry for CERTIFICATION.md yet (not owned here). docs/THREAT-MODEL.md and docs/SECURITY-REVIEW-SCOPE.md link `../SECURITY.md`, which would fail the docs-site link check if those pages are added to SUMMARY.md.
- The working tree had other plans' in-progress changes (Cargo.toml/lock, anvil-web admin files) after my run. My run built a clean HEAD, so it was not affected.

## Commits

- e9fe91d docs(07-19): OpenID certification runbook for the owner
- 7f9e883 docs(07-19): link the conformance README by repository URL in the runbook
- 4c559c3 feat(07-19): setup.sh --public mode, conformance on v* tags with 90-day evidence retention

## Self-Check: PASSED

- docs/CERTIFICATION.md, tests/conformance/setup.sh, README and workflow present. Commits e9fe91d, 7f9e883 and 4c559c3 are in the log.
- Both plan verify commands pass. `scripts/check-release-graph.sh` passes. I touched no Rust, so fmt, clippy and deps do not apply.
