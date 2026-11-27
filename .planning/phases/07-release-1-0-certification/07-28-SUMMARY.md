---
phase: 07-release-1-0-certification
plan: 28
subsystem: testing
status: complete
tags: [saml, interop, keycloak, simplesamlphp, shibboleth, playwright, ci]
requires: ["07-23"]
provides:
  - "tests/saml-interop/ harness: three pinned IdP containers, per-run secrets, non-interactive provisioning"
  - "tests/e2e/specs/saml-interop.spec.ts: real-IdP sign-in, refusals, rollover, MFA, JIT rule, audit"
  - ".github/workflows/saml-interop.yml (PRs touching code, main, v* tags, manual)"
  - "just saml-interop / saml-interop-clean"
  - "docs/SAML.md 'Automated interop (CI)' section"
affects: ["07-26 owner decision on the SAML experimental label (evidence, not the decision)"]
tech-stack:
  added:
    - "quay.io/keycloak/keycloak:26.8.2 (test container)"
    - "cirrusid/simplesamlphp:v2.5.3.1.20261023T014150 (test container)"
    - "i2incommon/shib-idp:5.2.3_20261117_rocky9_multiarch (test container)"
  patterns:
    - "per-run mode-700 dir with every key/password generated; templates with @@NAME@@ placeholders rendered by node from R_* env vars"
    - "compose.yml as the single source of image references (run.sh reads them via docker compose config)"
key-files:
  created:
    - tests/saml-interop/README.md
    - tests/saml-interop/run.sh
    - tests/saml-interop/compose.yml
    - tests/saml-interop/keycloak/interop-realm.json.tmpl
    - tests/saml-interop/simplesamlphp/config-override.php.tmpl
    - tests/saml-interop/simplesamlphp/authsources.php.tmpl
    - tests/saml-interop/simplesamlphp/saml20-idp-hosted.php.tmpl
    - tests/saml-interop/simplesamlphp/saml20-sp-remote.php.tmpl
    - tests/saml-interop/shibboleth/conf/idp.properties.tmpl
    - tests/saml-interop/shibboleth/conf/secrets.properties.tmpl
    - tests/saml-interop/shibboleth/conf/relying-party.xml.tmpl
    - tests/saml-interop/shibboleth/conf/metadata-providers.xml
    - tests/saml-interop/shibboleth/conf/attribute-resolver.xml.tmpl
    - tests/saml-interop/shibboleth/conf/attribute-filter.xml.tmpl
    - tests/saml-interop/shibboleth/conf/saml-nameid.xml
    - tests/saml-interop/shibboleth/conf/authn/password-authn-config.xml
    - tests/saml-interop/shibboleth/metadata/idp-metadata.xml.tmpl
    - tests/saml-interop/shibboleth/metadata/anvil-sp.xml.tmpl
    - tests/e2e/specs/saml-interop.spec.ts
    - tests/e2e/lib/saml-interop.ts
    - .github/workflows/saml-interop.yml
  modified:
    - tests/e2e/lib/org.ts
    - tests/e2e/lib/code-flow.ts
    - tests/e2e/run.sh
    - justfile
    - .gitignore
    - docs/SAML.md
    - scripts/check-security-tests.sh
decisions:
  - "Keycloak keeps NameID format persistent: it stayed stable across sign-ins (row 7 green), so no switch to username/unspecified"
  - "Shibboleth TLS: Tomcat's server.xml reads PEM /opt/certs/idp-default.{crt,key}; the run leaf is mounted there, no nginx front needed"
  - "Shibboleth sealer generated per run with the image's own seckeygen.sh (run as the calling user); back-channel p12 also per run (its password lives in secrets.properties, which is replaced)"
  - "saml-interop run raises only the admin rate budget (ANVILID_RATE_LIMIT_ADMIN_PER_SECOND=200, exported by run.sh and inherited by tests/e2e/run.sh); the set-up burst of ~12 connections hit the 20/s default"
  - "Compose password variables use ${VAR:-} (not :?) so the plan's verify `SAML_INTEROP_RUN_DIR=/nonexistent docker compose config -q` passes; run.sh always sets them"
  - "Replay (row 10) observes relay_state on all three IdPs: scenario 1's flow is finished; the assertion-id replay guard stays covered by saml_login.rs (documented)"
metrics:
  duration: "~62 min"
  completed: 2026-11-27
  tasks: 3
  files: 28
---

# Phase 7 Plan 28: Automated real-IdP SAML interop Summary

AnvilID now signs in through real Keycloak 26.8.2, SimpleSAMLphp 2.5.3.1 and Shibboleth IdP 5.2.3
containers on every CI run that touches code. The IdPs start from images pinned by digest and are
provisioned from committed templates, with every key and password generated per run. Locally,
`just saml-interop sqlite` passed 27/27 scenarios across all three IdPs. No AnvilID bug was found,
and no production code changed.

## Image references used (tests/saml-interop/compose.yml)

- `quay.io/keycloak/keycloak:26.8.2@sha256:7e66a96e4739239070aeaf72e4c5decf0f7f682cfc725b9f7ea2b336eaba38b3`
- `cirrusid/simplesamlphp:v2.5.3.1.20261023T014150@sha256:ae33d1faa5ce1ca0171ffb30916261bdb90bc4e734154db254c9735de8696240`
- `i2incommon/shib-idp:5.2.3_20261117_rocky9_multiarch@sha256:2dacee78da07113856e6ccf5d8acdf7f00db4f8fdf4d3a617265fc38fb50d3c6`

All three digests resolved on pull (2026-11-27). The nginx fallback was not needed, so it is not
in compose.yml.

## IdP settings that were needed

- **Keycloak:** client signature required off, assertion signing on, NameID `persistent`
  (forced), exclusive C14N, user-property mappers email/firstName/lastName to
  email/given_name/family_name. The realm keys are generated at import, so no Keycloak key is ever
  committed. The re-authentication page (ForceAuthn with an IdP session) shows the user name
  read-only, so the login driver fills the user name only when the field is editable.
- **SimpleSAMLphp:** `saml:PersistentNameID` on `uid`, needed because the default NameID is transient.
  The `exampleauth` module is enabled. With no explicit settings it signs both the Response and the
  assertion (observed).
- **Shibboleth:** `signAssertions=true` for `shib-ok`, needed because the default signs only the
  Response (observed on `shib-default`, refused with `signature_profile`). Also: encryption off,
  the persistent generator enabled (salt per run), the HTPasswd validator (`openssl passwd -apr1`
  is accepted by the IdP 5 validator), Template attributes released by FriendlyName, and the
  image's baked keys and sealer replaced. `TIER_BEACON_OPT_OUT=True` and
  `ENABLE_SEALER_KEY_ROTATION=False` are set. How the image is wired is recorded in
  tests/saml-interop/README.md.

## Scenario x IdP results (local run, results.json)

| Scenario | Rows | Keycloak | SimpleSAMLphp | Shibboleth |
|---|---|---|---|---|
| metadata import by https URL, SP metadata matches template | 2 | pass (6 connections) | pass (4) | pass (2) |
| 1 SP-initiated JIT sign-in | 1,3-6,16 | pass: assertion signed, rsa-sha256/sha256, persistent | pass: Response + assertion signed, rsa-sha256/sha256, persistent | pass: Response + assertion signed, rsa-sha256/sha256, persistent |
| 2 second sign-in, same sub | 7 | pass | pass | pass |
| 3 prompt=login -> ForceAuthn, IdP asks again | 8 | pass | pass | pass |
| 4 other accepted signing setup | 3 | pass (kc-both: Response + assertion) | pass (ssp-assert-only) | n/a (shib-ok already signs both) |
| 5 IdP-initiated refused | 9,16 | pass (relay_state) | pass (relay_state) | pass (relay_state) |
| 6 replay refused | 10,16 | pass (relay_state) | pass (relay_state) | pass (relay_state) |
| 7 response-only signing | 14 | pass (signature_profile) | pass (signature_profile) | pass (shib-default, signature_profile) |
| 7 encrypted assertion | 13 | pass (encrypted) | pass (encrypted) | n/a |
| 7 nothing signed | 3 | pass (signature_profile) | n/a | n/a |
| 7 RSA-SHA1 | 3 | pass (algorithm) | n/a | n/a |
| 8 JIT refused for an address outside verified domains (closed registration) | 6,16 | pass (upstream_login_failed no_account; saml_login_succeeded first) | n/a | n/a |
| 9 org MFA policy after SAML sign-in | 15 | pass (enrolment forced; amr fed, otp, mfa) | n/a | n/a |
| 10 rollover, then only the retired key pinned | 12 | pass (refused: untrusted_key) | n/a | n/a |

**Checklist rows automated:** Keycloak 1-10, 12-16; SimpleSAMLphp 1-10, 13, 14, 16; Shibboleth
1-10, 14, 16. **Left manual:** row 11 (clock skew: no image can shift its clock), and every row
for Entra ID, Okta and Google Workspace (cloud services). Wrong audience/recipient, expired
assertions and XSW stay with security_saml.rs and the mock-IdP saml.spec.ts.

## Interop bugs found

None. Every refusal reason matched what security_saml.rs asserts for that shape: response-only
and unsigned give `signature_profile`, SHA-1 gives `algorithm`, encryption gives `encrypted`, and
a retired key gives `untrusted_key`. No Rust regression test or security-map entry was needed.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Admin rate limit during the set-up burst**
- **Found during:** Task 2 (first run)
- **Issue:** creating 6 connections with verified, routed domains in a burst hit the 20/s admin
  budget (HTTP 429 on PATCH domain).
- **Fix:** tests/saml-interop/run.sh exports `ANVILID_RATE_LIMIT_ADMIN_PER_SECOND=200` before it
  calls tests/e2e/run.sh. That script starts anvilid with the caller's environment, so it stays
  unchanged apart from the planned exclusion. Rate limiting stays on, in the same way e2e raises
  only its auth budget.
- **Commit:** 3eb4fa9

**2. [Rule 1 - Bug] Login driver hung on Keycloak's re-authentication page**
- **Found during:** Task 2, scenario 3
- **Issue:** with ForceAuthn and an existing IdP session, Keycloak shows the user name read-only
  and asks only for the password. `fill('#username')` waited forever.
- **Fix:** the driver fills the user name only when it is editable. A `screenshot:
  'only-on-failure'` option on the spec keeps this kind of failure diagnosable in CI.
- **Commit:** ab555f3

**3. [Rule 3 - Blocking] Shibboleth secrets.properties location and back-channel keystore**
- secrets.properties renders from conf/ (where the plan puts the template) and is moved into
  credentials/, where the IdP reads it. Replacing secrets.properties drops the image's
  back-channel keystore password, so a per-run idp-backchannel.p12/crt is generated and mounted
  as well.
- **Commit:** 3eb4fa9

**4. Compose password interpolation:** the variables use `${VAR:-}` so the plan's own verify
command (`SAML_INTEROP_RUN_DIR=/nonexistent docker compose ... config -q`) passes. run.sh always
sets them.

**5. justfile:** `just saml-interop-clean images=1` passes the literal `images=1` positionally
in just, so the recipe accepts `1`, `images` or `images=1`.

No forced extra files: every file changed is in the plan's files_modified.

## Verification

- `just saml-interop sqlite` (all three IdPs): 27 passed, results.json lists all three IdPs. No
  container labelled `dev.anvilid.test=saml-interop` was left after the runs.
- `tests/saml-interop/run.sh --provision-only sqlite keycloak simplesamlphp shibboleth`: all
  three ready in about 25 s, no container left.
- Plan verify blocks for Tasks 1-3 (static parts): OK. `cd tests/e2e && npx tsc --noEmit -p .`:
  OK. saml.spec.ts unchanged. The spec has 10 `test(` occurrences and no skip, fixme or only.
- scripts/check-release-graph.sh, scripts/check-deps.sh, scripts/check-security-tests.sh (1115
  pairs) and its --self-test: OK.
- Docs site: scratch mdBook 0.5.4 build of a research-free copy of docs/, then
  scripts/check-docs-site.sh: OK; the `#automated-interop-ci` anchor exists. The scratch binary
  and copy are deleted.
- `git grep -nE 'BEGIN .*PRIVATE KEY|BEGIN CERTIFICATE' tests/saml-interop`: nothing.
- Disk: pulled IdP images removed (`just saml-interop-clean images=1`), `just
  clean-test-containers` run, local result dirs deleted.

## Not run / pending

- The saml-interop workflow has not run in CI yet. The orchestrator has not pushed, so there is no
  CI run id. Postgres was not exercised (by design: one backend; SAML replay on Postgres is
  covered by saml_login.rs).
- The experimental flag, its default and the manual checklist template are unchanged. Graduation
  remains the owner's decision (07-26).

## Self-Check: PASSED

- FOUND: tests/saml-interop/run.sh, compose.yml, README.md, all templates; tests/e2e/specs/saml-interop.spec.ts; tests/e2e/lib/saml-interop.ts; .github/workflows/saml-interop.yml
- FOUND commits: 3eb4fa9, ab555f3, 2c3f147
