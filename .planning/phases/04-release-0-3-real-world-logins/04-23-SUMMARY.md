---
phase: 04-release-0-3-real-world-logins
plan: 23
subsystem: conformance
tags: [openid-conformance, rp-initiated-logout, backchannel-logout, harness, ci]
requires:
  - phase: 04-10
    provides: run.sh logout/backchannel selections, callback CA + nginx mount, outbound CA/allow-list settings, logout browser tasks
  - phase: 04-11
    provides: admin API client fields post_logout_redirect_uris, backchannel_logout_uri, backchannel_logout_session_required
  - phase: 04-13
    provides: /logout endpoint, /ui/logout confirmation contract, error/signed-out sentences
  - phase: 04-17
    provides: back-channel logout delivery worker
provides:
  - "run.sh all = basic, config, formpost, logout, backchannel (one suite, one anvilid); CI runs it unchanged"
  - "setup.sh registers post_logout_redirect_uris on `client` and a dedicated back-channel client (post-logout URI + backchannel_logout_uri + session_required)"
  - "Second rendered suite config (anvilid-oidcc-backchannel.json) used only by the Back-Channel plan"
  - "Plan variant strings confirmed against the suite source at release-v5.3.5"
affects: [04-32]
tech-stack:
  added: []
  patterns:
    - "Per-plan suite config when a client's metadata would make the OP call into modules that do not expect it"
key-files:
  created: []
  modified:
    - tests/conformance/setup.sh
    - tests/conformance/run.sh
    - tests/conformance/config.template.json
    - tests/conformance/README.md
    - .github/workflows/conformance.yml
key-decisions:
  - "04-23: backchannel_logout_uri lives on a dedicated 4th client used only by the Back-Channel plan (own rendered config). A suite module reports any HTTP request it does not handle as a FAILURE (AbstractTestModule.unexpectedHttpRequest), so a back-channel logout token sent during an RP-Initiated Logout or Basic module would fail it"
  - "04-23: Logout plan variants are [response_type=code][client_registration=static_client]. Confirmed in suite source at release-v5.3.5: both plans fix server_metadata, client_auth_type, response_mode; AbstractOIDCCServerTest's remaining @VariantParameters are response_type and client_registration (the suite's own CI uses the same two keys)"
  - "04-23: The post_logout_redirect 'Verify Complete' task only checks the URL. The suite's resultCaptured.html has no submission_complete element (only implicitCallback.html adds it), and the suite's own logout config uses a command-less task there"
patterns-established:
  - "Verify harness assumptions against the pinned suite source (plan classes, templates, BrowserControl) before relying on them"
requirements-completed: []
duration: 30min
completed: 2026-11-25
---

# Phase 4 Plan 23: Logout conformance plans in `all` and CI Summary

**`run.sh all` now runs Basic, Config, Form Post, RP-Initiated Logout and Back-Channel Logout. The suite's `client` has a registered `post_logout_redirect_uri`, and a dedicated back-channel client (its own rendered config) has the back-channel URI with `session_required`. The plan variant strings are confirmed from the suite source at release-v5.3.5. A browser-config bug that would have failed every successful-redirect logout module is fixed. No OP code changed, and expected-failures/skips are unchanged. The suite run itself still has to happen in CI.**

`requirements-completed` is empty on purpose. OIDC-12 is proven by a green conformance run, which could not run here (no Docker). Per the shared rules, no checkbox was ticked.

## Performance

- **Duration:** about 30 min
- **Completed:** 2026-11-25
- **Tasks:** 2
- **Files modified:** 5

## Final plan strings

| Selection | Plan | Config |
|---|---|---|
| `logout` | `oidcc-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]` | `anvilid-oidcc.json` |
| `backchannel` | `oidcc-backchannel-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]` | `anvilid-oidcc-backchannel.json` |

How the strings were checked (in `./suite`, release-v5.3.5, `git show HEAD:`):
- `OIDCCRpInitiatedLogoutTestPlan` and `OIDCCBackchannelRpInitiatedLogoutTestPlan` set `ServerMetadata=discovery`, `ClientAuthType=client_secret_basic` and `ResponseMode=default` per module list.
- `AbstractOIDCCServerTest` declares `@VariantParameters` for ServerMetadata, ClientAuthType, ResponseType, ResponseMode and ClientRegistration. That leaves `response_type` and `client_registration`.
- The parameter names come from the `@VariantParameter(name=…)` annotations. The values are `code` and `static_client`.
- The suite's `.gitlab-ci/run-tests.sh` runs the same plans with `[response_type=…][client_registration=…]`.

## What changed

- **setup.sh**
  - `client` gets `post_logout_redirect_uris: [".../test/a/anvilid/post_logout_redirect"]`.
  - A new client, "conformance back-channel logout client", gets the same settings plus that URI, `backchannel_logout_uri: ".../test/a/anvilid/backchannel_logout"` and `backchannel_logout_session_required: true`.
  - The URIs follow the suite's `CreatePostLogoutRedirectUri` and `CreateBackchannelLogoutUri` (`base_url` + suffix).
  - It now takes a third argument and renders the template twice. The second config has `client` = the back-channel client.
  - It dies if any client creation returned nothing.
- **run.sh**
  - `all` now has five plans.
  - The Back-Channel plan is paired with `$CFG_BACKCHANNEL`, every other plan with `$CFG`.
  - The comment now records why the variant strings are what they are.
  - The skip-file logic is unchanged: `all` uses `expected-skips.json`, whose entry is used by Basic/Form Post, and the back-channel config name does not match its `*anvilid-oidcc.json` pattern.
- **config.template.json:** the default `/logout*` block's "Verify Complete" (`*/test/*/post_logout_redirect*`) no longer waits for `#submission_complete`, and a comment explains why.
- **conformance.yml:** the job and step names and the header comment list the five plans. The step still runs `tests/conformance/run.sh all`. The timeout stays at 60 min (recent runs took about 6 min, and the logout plans add 13 short modules).
- **README:** covers the five plans, how the variant strings were confirmed, the back-channel client design, the two rendered configs and the URL-only post-logout check. The "not in `all` yet" notes are removed.
- **expected-failures.json** is still `[]`, and **expected-skips.json** is unchanged (no new skips).

## Verification

- `bash -n` passes on run.sh and setup.sh.
- shellcheck 0.11.0 (`shellcheck-py` in a scratch venv, since deleted) is clean on both.
- config.template.json and the expected-* files parse as JSON. The template still round-trips with `json.dumps(indent=2)`.
- conformance.yml parses as YAML, and its only run step is `tests/conformance/run.sh all`.
- **setup.sh against a real anvilid:**
  - Setup: `cargo build --locked -p anvilid`, then the binary on its TLS listener with a temporary data dir in the scratchpad (since deleted).
  - setup.sh exited 0 and wrote both configs (mode 600).
  - The `client` table shows `client` with only the post-logout URI, client2 and client_secret_post with none, and the back-channel client with the post-logout URI, the back-channel URI and `session_required = 1`.
  - Config contents: `client` in the back-channel config is the back-channel client, and the other sections are identical in both configs.
- I sourced the `case` and pairing loop from run.sh: `all` gives five plans, and only the back-channel plan is paired with `anvilid-oidcc-backchannel.json`.
- `cargo test -p anvil-web --test logout --test security_logout --test backchannel`: 12 + 14 + 8 passed.

## Not run (needs CI)

- `tests/conformance/run.sh logout`, `backchannel` and `all`, because Docker is not running here.
- So these are unproven until the conformance workflow runs:
  - that the variant strings are accepted at run time (they were checked only in the source),
  - that the 13 logout modules pass or reach REVIEW,
  - that the back-channel POST through the callback CA and the 127.0.0.1/32 allow-list reaches nginx,
  - that Basic/Config/Form Post still pass in the combined run.
- No run ids yet. The orchestrator pushes and watches CI, and 04-32 is the gate.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Back-channel URI on a dedicated client instead of on `client`**
- **Found during:** Task 1, reading the suite source.
- **Issue:** The plan put `backchannel_logout_uri` on the shared `client`. Every successful sign-out in the RP-Initiated plan (rp-initiated-logout, no-state, no-params, no-post-logout-redirect-uri, only-state) would then POST a logout token to `/test/a/anvilid/backchannel_logout` while a module that does not serve that path is running. `AbstractTestModule.unexpectedHttpRequest` reports that as a FAILURE.
- **Fix:** A fourth client with the back-channel metadata and a second rendered config, used only by the Back-Channel plan. The must-have "static client registered with post_logout_redirect_uris and backchannel_logout_uri (session required)" holds for the client the Back-Channel plan uses.
- **Files modified:** tests/conformance/setup.sh, tests/conformance/run.sh
- **Commit:** ebe10a8

**2. [Rule 1 - Bug] Post-logout "Verify Complete" waited for an element that never appears**
- **Found during:** Task 1.
- **Issue:** The 04-10 default `/logout*` block waited 10 s for `#submission_complete` on the suite's post_logout_redirect page. At release-v5.3.5 that page is `resultCaptured.html`, which only has `#complete`. BrowserControl throws `TestFailureException("Timed out waiting…")`, so rp-initiated-logout, no-state and backchannel-rp-initiated-logout would fail.
- **Fix:** A command-less task that only checks the URL, the same as the suite's own `.gitlab-ci/local-provider-oidcc-conformance-config.json`.
- **Files modified:** tests/conformance/config.template.json
- **Commit:** ebe10a8

### Notes

- No OP-side fix was needed from the offline review, so none of the listed Rust/theme logout files changed. The suite checks I reviewed in source match the 04-13/04-17 behaviour:
  - logout token claims and `events`,
  - iss = discovery issuer for the default tenant,
  - sub/sid match the ID token,
  - only `logout_token` in the body,
  - TLS 1.3 (nginx 8443 allows it),
  - exact `state` only in the redirect, and no state when none was sent.
- run.sh is committed entirely in the Task 1 commit (pairing and `all` in one file, without interactive hunk staging). The Task 2 commit has README and the workflow.
- Another plan's in-progress files (flow/*, discovery.rs, select_account) were in the tree. They are not part of these commits.

## Commits

- ebe10a8 feat(04-23): register logout metadata and wire the logout plans into the harness
- a8c57c8 docs(04-23): conformance CI and README cover the five plans

## Self-Check: PASSED

- FOUND: tests/conformance/run.sh (contains BACKCHANNEL_PLAN, five-plan `all`)
- FOUND: tests/conformance/setup.sh (contains backchannel_logout_uri)
- FOUND: .github/workflows/conformance.yml (contains `run.sh all`)
- FOUND: ebe10a8, a8c57c8
