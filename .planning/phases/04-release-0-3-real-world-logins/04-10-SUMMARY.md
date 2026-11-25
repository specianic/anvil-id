---
phase: 04-release-0-3-real-world-logins
plan: 10
subsystem: conformance
tags: [openid-conformance, rp-initiated-logout, backchannel-logout, ssrf, tls, harness]
requires:
  - phase: 04-02
    provides: ANVILID_OUTBOUND_CA_FILE and ANVILID_OUTBOUND_ALLOW_CIDRS operator settings (SSRF-guarded outbound client)
  - phase: 03-28
    provides: run.sh [basic|config|formpost|all], empty skip list pattern, login quota
provides:
  - "run.sh selections logout (LOGOUT_PLAN) and backchannel (BACKCHANNEL_PLAN), env-overridable, not in all"
  - "gen_callback_cert: per-run P-256 CA + RSA-2048 leaf for localhost.emobix.co.uk, mounted read-only into the suite's nginx"
  - "anvilid started with ANVILID_OUTBOUND_CA_FILE=<callback CA> and ANVILID_OUTBOUND_ALLOW_CIDRS=127.0.0.1/32 for every selection"
  - "config.template.json /logout* browser block and overrides for the 8 placeholder logout modules"
affects: [04-13, 04-23]
tech-stack:
  added: []
  patterns:
    - "Reach the suite's callback through real operator settings (extra CA + CIDR allow-list) instead of disabling the SSRF guard or TLS verification"
key-files:
  created: []
  modified:
    - tests/conformance/run.sh
    - tests/conformance/compose.override.yml
    - tests/conformance/config.template.json
    - tests/conformance/README.md
key-decisions:
  - "04-10: The callback leaf is RSA-2048 (CA is P-256). One listener in the suite's nginx.conf (release-v5.3.5) allows only ECDHE-RSA ciphers, so an EC leaf would change suite behaviour there"
  - "04-10: logout/backchannel runs use the generated empty skip list (the reviewed skip is Basic/Form Post only and run-test-plan.py fails on unused entries)"
  - "04-10: Logout browser contract is URL-based: confirmation page under /ui/logout*, signed-out page NOT under /ui/logout*, error pages under the tenant base URL; 04-13 must honour it or 04-23 adjusts the template"
  - "04-10: compose.override.yml uses long-syntax bind mounts with create_host_path: false and /nonexistent defaults, so `docker compose config` works without run.sh but `up` never creates stray directories"
requirements-completed: []
duration: 25min
completed: 2026-11-25
---

# Phase 4 Plan 10: Conformance harness for the logout plans Summary

**`run.sh logout|backchannel` selections, a per-run CA + leaf mounted into the suite's nginx so anvilid can deliver back-channel logout tokens with TLS verification and the SSRF guard on (ANVILID_OUTBOUND_CA_FILE + ANVILID_OUTBOUND_ALLOW_CIDRS=127.0.0.1/32), and browser tasks for the logout confirmation, signed-out and error pages.**

## Tasks

| Task | Name | Commit |
|------|------|--------|
| 1 | Plan selections, callback certificate, outbound settings | c313dd8 |
| 2 | Browser tasks for logout pages + README | 21d6918, f5b61ba |

## What changed

- **run.sh**
  - `LOGOUT_PLAN` and `BACKCHANNEL_PLAN` have the plan's default variant strings and can be overridden from the environment.
  - New selections `logout` and `backchannel`, with updated usage and error text. `all` is still basic + config + formpost.
  - `gen_callback_cert()` is self-contained (it can be sourced on its own) and writes four files to `$TMP_DIR`:
    - `callback-ca.pem` / `.key`: P-256, 1 day, `CA:TRUE` critical, keyCertSign.
    - `callback-leaf.pem` / `.key`: RSA-2048, SAN `DNS:localhost.emobix.co.uk`, `serverAuth`, `CA:FALSE`, signed by the CA.
    - All four are chmod 600. The function runs `openssl verify -purpose sslserver -verify_hostname` before returning.
    - It runs after the cleanup trap is registered and before `compose up`, so the existing teardown deletes the files.
  - anvilid now starts with `ANVILID_OUTBOUND_CA_FILE` (absolute path) and `ANVILID_OUTBOUND_ALLOW_CIDRS=127.0.0.1/32` for every selection.
- **compose.override.yml:** the nginx service gets the leaf and its key mounted read-only over `/etc/ssl/certs/nginx-selfsigned.crt` and `/etc/ssl/private/nginx-selfsigned.key`. I checked these paths in `nginx/Dockerfile` and `nginx.conf` at release-v5.3.5.
- **config.template.json**
  - Default `/logout*` block: an optional "Confirm sign-out" task that clicks `#logout-confirm-submit` on `/ui/logout*`, then "Verify Complete", which waits for `submission_complete` on `*/test/*/post_logout_redirect*` (the suite's `resultCaptured` page).
  - Overrides that repeat the `/authorize*` block, because an override replaces the whole browser list. I checked the module names against the suite sources:
    - 5 error modules wait for the exact error sentence and capture it with `update-image-placeholder`.
    - no-params, no-post-logout-redirect-uri and only-state confirm if asked, then wait for "You have been signed out." and capture it.
- **README:** documents the selections, the env overrides, the callback CA/leaf design and why it is needed, the URL contract for the logout pages, the empty skip list, and that the plans join `all` in 04-23.

## Verification

- `bash -n` passes on run.sh. shellcheck 0.11.0 is not installed on the machine, so I ran it from a scratch venv (`shellcheck-py`): clean.
- The plan's standalone check passes with Homebrew OpenSSL and with the system OpenSSL 3.0.2 (the CI-like version): source `gen_callback_cert`, then `openssl verify -CAfile ca leaf` returns OK. I also checked the extensions with `openssl x509 -text`.
- `run.sh foo` and `run.sh a b` fail with the new usage and error text.
- The template parses as JSON, and so does compose.override.yml as YAML.
- **Not run:** Docker is down and there is no docker CLI. Not tested: `docker compose config`, any suite run, the basic/config/formpost regression run, and whether nginx accepts the mounted leaf. CI is authoritative; 04-23 makes the logout plans green.

## Deviations from Plan

- **[Rule 3 - Blocking] Empty skip list for `logout`/`backchannel`.** run-test-plan.py fails on unused skip entries, and the reviewed skip belongs to Basic/Form Post. Without this, the logout selections would always fail. Part of c313dd8.
- **[Rule 3 - Blocking] `# shellcheck disable=SC2329` on `cleanup()`.** shellcheck 0.11 flags the trap-invoked function (info level, already present before this plan). The plan's verification needs a clean shellcheck run.
- **Leaf key type RSA instead of EC** (the plan only specified P-256 for the CA). See key decisions.
- **Extra docs commit f5b61ba:** the README's TLS section said "no CA is installed anywhere", which is no longer accurate.

## Notes for 04-13 / 04-23

- 04-23 must add `post_logout_redirect_uris` (`…/test/a/anvilid/post_logout_redirect`), `backchannel_logout_uri` (`…/test/a/anvilid/backchannel_logout`) and `backchannel_logout_session_required` to `setup.sh`, confirm the plan variant strings, and add both selections to `all` and to CI.
- URL contract the browser relies on:
  - The confirmation page is under `/ui/logout*`.
  - The signed-out page is not under `/ui/logout*`. Otherwise the optional confirm task matches it and fails to find the button.
  - The error and signed-out pages are under `@BASE_URL@/`.

## Self-Check: PASSED

- FOUND: tests/conformance/run.sh (contains oidcc-backchannel-rp-initiated-logout-certification-test-plan), tests/conformance/config.template.json (contains logout-confirm-submit), tests/conformance/compose.override.yml, tests/conformance/README.md
- FOUND: c313dd8, 21d6918, f5b61ba
