---
phase: 03-release-0-2-secure-by-default
plan: 09
subsystem: auth
tags: [webauthn, passkeys, webauthn-rs, totp, qr, svg, csp]
requires:
  - phase: 03-01
    provides: webauthn-rs 0.6.2 (danger-allow-state-serialisation, conditional-ui), qrcodegen
  - phase: 03-02
    provides: anvil_core::ports::PasskeyCeremonies, RelyingParty, Challenge, PasskeyError
provides:
  - anvil_web::adapters::WebauthnPasskeys (PasskeyCeremonies over webauthn-rs)
  - anvil_web::adapters::relying_party(tenant, issuer)
  - anvil_web::adapters::qr_svg(data) (otpauth URI -> inline SVG)
  - themes/default/static/webauthn.js (served at /assets/webauthn.js)
affects: [03-12, 03-14, 03-20, 03-26]
tech-stack:
  added: []
  patterns:
    - "Software P-256 authenticator in test code (hand-encoded CBOR, none attestation) for WebAuthn round trips without a browser"
    - "Library enum not re-exported (ResidentKeyRequirement) named through serde inference instead of adding a direct dependency"
key-files:
  created:
    - crates/anvil-web/src/adapters/passkey.rs
    - crates/anvil-web/src/adapters/qr.rs
    - crates/anvil-web/tests/passkey_adapter.rs
    - themes/default/static/webauthn.js
  modified:
    - crates/anvil-web/src/adapters/mod.rs
key-decisions:
  - "relying_party returns Result<RelyingParty, CoreError>: issuers with IP-literal hosts or non-http(s) schemes cannot be WebAuthn RPs and fail with Internal instead of panicking"
  - "finish_discoverable also checks the response credential id equals the stored passkey's before calling webauthn-rs (Invalid otherwise)"
  - "Registration counter/backup_eligible read from the Passkey's own serde JSON (cred.counter, cred.backup_eligible); Credential internals stay behind danger-credential-internals"
  - "webauthn.js DOM contract: form[data-webauthn=register|authenticate], hidden input name=response, [data-webauthn-trigger] (hidden until WebAuthn is available), [data-webauthn-status] aria-live, optional data-options-url and data-webauthn-msg-{cancelled,failed}"
patterns-established:
  - "WebAuthn security checks proven in Rust with a soft authenticator; browser path left to Playwright CDP virtual authenticator (03-26)"
requirements-completed: []
duration: 15min
completed: 2026-11-25
---

# Phase 3 Plan 09: WebAuthn adapter, SVG QR and webauthn.js Summary

**webauthn-rs 0.6.2 implementation of PasskeyCeremonies (discoverable, UV required, finish_discoverable_authentication_v2, clone detection), a qrcodegen SVG renderer for otpauth URIs and a CSP-safe self-hosted browser ceremony helper**

## Performance

- **Duration:** ~15 min
- **Completed:** 2026-11-25
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments

- `WebauthnPasskeys` builds a `Webauthn` per call from the tenant `RelyingParty`; ceremony state is JSON for server-side storage only.
- `relying_party(tenant, issuer)`: `https://op.test/t/acme` gives `rp_id=op.test`, `origin=https://op.test`; `http://localhost:8080` gives `rp_id=localhost`, `origin=http://localhost:8080`; name is the tenant display name.
- Error mapping: `CredentialPossibleCompromise` becomes `PossibleClone`, every other library or parse error becomes `Invalid` (logged at debug level by variant only). Nothing panics.
- 24 integration tests + 3 unit tests. A software P-256 authenticator in the test file runs full registration and sign-in round trips, and the tests show these are rejected: wrong challenge state (registration and assertion), wrong origin, wrong rp id hash, missing UV (registration and assertion), a forged signature from another key, an assertion checked against another stored passkey, a counter that does not advance (equal and lower, both `PossibleClone`), garbage in every input, and a missing or non-UUID user handle.
- `qr_svg`: ECC at least medium, 4-module quiet zone, one `<path fill="currentColor">`, `role="img"` + aria-label, deterministic, rejects empty or >1 KiB input. 5 unit tests.
- `webauthn.js`: classic script with no inline handlers. Checked with `node --check` and a vm smoke test (no-op when unsupported, triggers revealed and bound when supported).

## Options JSON shape (as produced by the adapter)

Registration (`Challenge.options_json`, sent to the browser as is):

```json
{"publicKey": {
  "rp": {"id": "op.test", "name": "Acme"},
  "user": {"id": "<b64url(user UUID 16 bytes)>", "name": "...", "displayName": "..."},
  "challenge": "<b64url>",
  "pubKeyCredParams": [...],
  "timeout": 300000,
  "excludeCredentials": [{"type": "public-key", "id": "<b64url>"}],   // omitted when none
  "authenticatorSelection": {"residentKey": "required", "requireResidentKey": true,
                             "userVerification": "required"},
  "attestation": "none",
  "extensions": {"credentialProtectionPolicy": ..., "uvm": true, "credProps": true}
}}
```

Discoverable sign-in: `{"publicKey": {"challenge", "timeout", "rpId": "op.test", "allowCredentials": [], "userVerification": "required", "extensions": {...}}}`, with **no** `mediation` key (the library's forced `conditional` is cleared).

The flow keeps `state_json` and consumes it once (03-02 single-use flow state). `finish_registration` returns `RegisteredPasskey { credential_id, passkey_json, counter, backup_eligible }`. `finish_discoverable` returns `VerifiedAssertion`, and `updated_passkey_json` is `Some` when the counter or backup state changed and the passkey must be saved (`CredentialRepo::update_passkey`).

## webauthn.js DOM contract

Include `<script src="/assets/webauthn.js" defer></script>` (embedded via rust-embed from `themes/default/static/`).

```html
<form method="post" action="..." data-webauthn="register|authenticate"
      data-options-url="..."                  (optional)
      data-webauthn-msg-cancelled="..."       (optional localized text)
      data-webauthn-msg-failed="...">
  <input type="hidden" name="csrf_token" value="...">
  <input type="hidden" name="response" value="">
  <script type="application/json" data-webauthn-options>{"publicKey":{...}}</script>
  <button type="button" data-webauthn-trigger hidden>Use a passkey</button>
  <p data-webauthn-status aria-live="polite"></p>
</form>
```

- Where options come from, in order: `data-options-url` (POST, form-encoded `csrf_token`, `Accept: application/json`, same-origin credentials; the answer is the options JSON), then a form-scoped `script[type=application/json][data-webauthn-options]`, then the page-level `#webauthn-options`.
- Conversion uses `PublicKeyCredential.parseCreationOptionsFromJSON` / `parseRequestOptionsFromJSON` when available. Otherwise a base64url fallback decodes the challenge, `user.id` and `exclude/allowCredentials[].id`.
- Serialisation uses `credential.toJSON()`, or a fallback that produces the same shape (`id`, `rawId`, `type`, `response.{clientDataJSON, attestationObject, transports}` or `{authenticatorData, clientDataJSON, signature, userHandle}`, `clientExtensionResults`). The result goes into `input[name=response]` and the form is submitted via `HTMLFormElement.prototype.submit` (so a control named `submit` cannot shadow it).
- On `NotAllowedError`/`AbortError` the cancelled message goes into `[data-webauthn-status]`; any other error shows the failed message. The trigger is re-enabled and focused.
- Without WebAuthn the script does nothing. Triggers keep their `hidden` attribute, so the password path stays the only visible option and no-JS pages are unaffected.

## Task Commits

1. **Task 1: webauthn-rs adapter and relying-party derivation**: `b0c9f1b` (feat; tests were written with the implementation and passed on the first run)
2. **Task 2: SVG QR renderer and webauthn.js**: `df97aa7` (feat)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Correctness] relying_party returns Result**
- **Found during:** Task 1
- **Issue:** The plan signature `-> RelyingParty` cannot handle IP-literal hosts (WebAuthn forbids them; webauthn-rs rejects them with Configuration) or unparsable issuers without panicking.
- **Fix:** `relying_party(tenant, issuer) -> Result<RelyingParty, CoreError>` returns `Internal` for those cases. Consumers (03-12/03-14) must propagate it.
- **Commit:** b0c9f1b

**2. [Rule 3 - Blocking] ResidentKeyRequirement not reachable**
- **Found during:** Task 1
- **Issue:** webauthn-rs does not re-export the proto `ResidentKeyRequirement`, and adding webauthn-rs-proto would mean changing Cargo.toml, which is outside this plan's files.
- **Fix:** Kept the typed field assignment and produced the value through serde inference (`serde_json::from_str("\"required\"")`).
- **Commit:** b0c9f1b

**3. [Rule 2 - Security tests] Positive round trips and more rejection tests in Rust**
- **Found during:** Task 1
- **Issue:** The plan deferred positive round trips to Playwright. Without a positive path, the rejection tests would only prove that malformed JSON fails, not that the security checks work.
- **Fix:** Added a P-256 software authenticator to the test file (test code only) and tests for challenge, origin, rp id, UV, signature, credential binding and counter regression.
- **Commit:** b0c9f1b

---

**Total deviations:** 3 auto-fixed. No scope creep: all changes are in the plan's files.

## Issues Encountered

- Uncommitted work from parallel plans (sqlx offline cache for new SQLite queries) broke the anvil-web dev-dependency build in the main tree, so verification ran in a temporary worktree (`target/wt-03-09`, removed afterwards).
- Already failing, out of scope: `cargo test -p anvil-web --test security_csp` (`every_ui_page_has_the_strict_headers_and_no_external_references`) fails at HEAD 280534f even without this plan's files. It is not caused by webauthn.js. It should be looked at by whichever plan owns the setup or CSP pages.

## Next Phase Readiness

- 03-12/03-14 can wire `WebauthnPasskeys` behind `Arc<dyn PasskeyCeremonies>`. They should store `state_json` in the flow state, call `identify` and then look up the passkey with `find_passkey`, then call `finish_discoverable`, and save `updated_passkey_json`. They should treat `PossibleClone` as a security event.
- 03-20 renders `qr_svg(otpauth_uri)` inline (mark it as safe in the template) and styles it with `color`/`background` in anvil.css.
- 03-26 runs webauthn.js end to end with the CDP virtual authenticator.

## Self-Check: PASSED

- FOUND: crates/anvil-web/src/adapters/passkey.rs, qr.rs, tests/passkey_adapter.rs, themes/default/static/webauthn.js
- FOUND: b0c9f1b, df97aa7
