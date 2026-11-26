---
phase: 07-release-1-0-certification
plan: 13
subsystem: protocol
tags: [par, rfc9126, rfc10070, oauth, authorize, discovery, OIDC-18]
requires:
  - "07-03: model::par, Client.require_pushed_authorization_requests, TenantSettings.par"
  - "07-04: oauth::par / service::par / protocol::par skeletons, /par rate-limit class Token"
  - "07-08: GrantRepo::{create_pushed_request, consume_pushed_request}, purge in purge_expired"
provides:
  - "POST {issuer}/par (RFC 9126): 201 {request_uri, expires_in: 60}, JSON errors, no CORS"
  - "oauth::par: REQUEST_URI_PREFIX, LIFETIME, REQUEST_URI_RANDOM_CHARS, FRONT_CHANNEL_PARAMETERS, CLIENT_AUTH_PARAMETERS, new_request_uri, parse_request_uri, is_pushed_request_uri, push_error, recheck_client_policy"
  - "service::par::ParService {push, consume} + PushedAuthorization, PushedRequestRefused"
  - "AuthorizeService::resume_pushed_request(tenant, issuer, client_id, request_uri) -> Result<Result<ResumedPushedRequest, AuthorizeOutcome>, CoreError> (the single resume path, for 07-18)"
  - "Per-client and per-tenant PAR enforcement on plain /authorize"
  - "Discovery: pushed_authorization_request_endpoint, require_pushed_authorization_requests"
  - "docs/PAR.md"
affects: [07-18 (native start calls resume_pushed_request), 07-19 (Config OP re-check with the two new metadata fields), 07-23 (ticks OIDC-18)]
tech-stack:
  added: []
  patterns:
    - "Pushed params stored as validated AuthorizationParams JSON; policy re-checked at use by a pure function instead of re-running validate"
    - "PAR resume = consume + client match + recheck + store_request, then the existing continue_request(Stage::AfterLogin)"
key-files:
  created:
    - crates/anvil-web/tests/par_support/mod.rs
    - crates/anvil-web/tests/par.rs
    - crates/anvil-web/tests/security_par.rs
    - docs/PAR.md
  modified:
    - crates/anvil-core/src/oauth/par.rs
    - crates/anvil-core/src/service/par.rs
    - crates/anvil-core/src/oauth/authorize_request.rs
    - crates/anvil-core/src/service/authorize.rs
    - crates/anvil-web/src/protocol/par.rs
    - crates/anvil-web/src/protocol/authorize.rs
    - crates/anvil-web/src/protocol/discovery.rs
    - crates/anvil-web/tests/discovery.rs
    - crates/anvil-web/tests/skeleton_v10.rs
key-decisions:
  - "id_token_hint in a pushed body is invalid_request: AuthorizationParams (the stored form, per research) has no hint, and silently dropping it would change prompt=none semantics"
  - "A client_id mismatch at /authorize still consumes the pushed request (a leaked request_uri cannot be retried)"
  - "The RFC 9126 §7.4 re-check is a pure function (recheck_client_policy): redirect URI still registered (else error page), code grant, PKCE requirement, scopes narrowed to the client's current list (openid required), resources, organization policy, prompt=create vs registration mode"
  - "After resume, the request continues through continue_request(Stage::AfterLogin); prompt=create answers Register like a plain request"
  - "The two RFC 9126 metadata names were added to the discovery test's ALLOWED_METADATA list (registered AS metadata); 07-19 must confirm the Config OP plan stays warning-free"
  - "No per-client /par limiter: only the per-IP Token class from 07-04 (claimed_client_id lives in token.rs, which this plan does not own)"
metrics:
  duration: ~75min
  completed: 2026-11-26
---

# Phase 7 Plan 13: Pushed authorization requests (RFC 9126) Summary

Clients can push their authorization parameters to `POST /par` and use the returned single-use,
60-second `request_uri` at `/authorize`. Client authentication is the token endpoint's own. PAR
can be required per client or per tenant, and discovery advertises it.

## Endpoint behaviour

- `POST {issuer}/par`, form body. Client credentials (`Authorization: Basic`, `client_secret`,
  `client_assertion_type`, `client_assertion`) are split off; the rest is the authorization request.
  Authentication goes through `ClientAuthenticator` (the `/token` implementation, shared jti
  replay store). After that: `request_uri` gives `invalid_request`, `request` gives
  `request_not_supported`, `id_token_hint` gives `invalid_request`, and a body `client_id`
  that contradicts the credentials gives `invalid_client`. Then `authorize_request::validate`
  runs with the authenticated client. Page-type errors become `invalid_request`, redirect-type
  errors return their own code.
- Success: `201`, `{"request_uri":"urn:ietf:params:oauth:request_uri:<43 b64url>","expires_in":60}`,
  `Cache-Control: no-store`. Only `SHA-256(request_uri)` is stored.
- `/authorize` (GET or POST) with a `request_uri` carrying the PAR prefix takes the PAR branch
  before any validation. Only `client_id` and `request_uri` are read. Then
  `resume_pushed_request` runs: an unusable or mismatched URI shows the error page
  (`invalid_request`), a missing client shows `unknown_client`, and a policy re-check failure is a
  page or a redirect. Next comes `store_request`, then `continue_request`. Any other
  `request_uri` value still gets `request_uri_not_supported`.
- A plain `/authorize` from a client with `require_pushed_authorization_requests`, or in a
  tenant with `par.require_pushed_authorization_requests`, is refused with `invalid_request`
  through the redirect once the redirect URI is trusted. Before that point it gets the error page.

## Discovery diff

```diff
+  "pushed_authorization_request_endpoint": "{issuer}/par",
+  "require_pushed_authorization_requests": false,   // tenant par.require_pushed_authorization_requests
   "request_uri_parameter_supported": false,          // unchanged
```

## Tests

- Core unit tests (`oauth::par`): `new_request_uri_has_the_prefix_43_chars_and_its_hash`,
  `parse_request_uri_rejects_malformed_values`, `push_errors_are_json_errors_never_pages`,
  `recheck_accepts_an_unchanged_client`, `recheck_refuses_a_removed_redirect_uri_with_an_error_page`,
  `recheck_follows_policy_changes`. Web unit tests (`protocol::par`): credential splitting and
  repeated-credential refusal. Discovery unit test extended.
- `par.rs` (12): one happy path per method (basic, post, private_key_jwt, public PKCE), each
  with the ID-token nonce checked: push, authorize, code, token. Also:
  `par_basic_client_may_repeat_its_client_id_in_the_body`, `par_front_channel_parameters_are_ignored`,
  `par_without_session_goes_through_login_and_continue`,
  `par_pushed_prompt_none_without_session_answers_at_the_redirect_uri`,
  `par_post_authorize_accepts_a_request_uri`, `par_path_tenant_endpoint_is_served`,
  `par_expired_rows_are_purged`, `par_response_carries_no_redirect`.
- `security_par.rs` (20). All 16 named tests: `par_request_uri_single_use`,
  `par_request_uri_concurrent_single_winner` (8 parallel tasks, multi-thread runtime, exactly
  (1, 7)), `par_request_uri_expires` (59 s works, 60 s refused), `par_request_uri_bound_to_client`,
  `par_non_urn_request_uri_refused`, `par_unknown_request_uri_no_redirect`,
  `par_confidential_client_requires_auth`, `par_wrong_secret_refused`, `par_request_uri_in_body_refused`,
  `par_request_object_not_supported`, `par_client_assertion_aud_par_endpoint_refused` (PAR and token
  URLs both refused, issuer accepted), `par_jti_replay_shared_with_token` (both directions),
  `par_redirect_uri_must_match_registered`, `par_required_client_plain_authorize_refused`,
  `par_tenant_required_plain_authorize_refused`, `par_no_interaction_errors`. Four extras:
  `par_policy_rechecked_at_use` (scopes changed, client deleted), `par_id_token_hint_refused`,
  `par_body_client_id_must_match_credentials`, `par_requires_form_body`.
- `discovery.rs`: `par_metadata_is_published` (both well-known forms, tenant flag on),
  `par_metadata_follows_the_path_tenant_issuer`.

## Mutation results

1. I disabled the `client_id` comparison in `ParService::consume` (`if false && ...`).
   `par_request_uri_bound_to_client` **failed** (303 with a code instead of the 400 page). Reverted.
2. Non-atomic read-then-delete consume: **not applied.** The consume is a single sqlx
   `query!` UPDATE ... RETURNING in `anvil-storage-sqlite/src/grants.rs`. That file is owned by
   07-08, and changing the query breaks the offline `.sqlx` cache. The service has no read-only
   accessor that could emulate the race. Atomicity is proven at the storage layer by the 07-08
   contract case `par_consume_single_winner_under_concurrency` (8 tasks x 10 rounds). Over HTTP,
   `par_request_uri_concurrent_single_winner` pins exactly one winner.

## Verification

- `cargo test -p anvil-core --lib -- oauth::par service::par oauth::authorize_request service::authorize`: 55 passed.
- `cargo test -p anvil-web --test par --test security_par --test discovery --test skeleton_v10 --test security_private_key_jwt --test security_client_auth`: 12 + 20 + 16 + 1 + 16 + 9 passed.
- `cargo test -p anvil-web --locked --no-fail-fast`: 1577 passed, 0 failed (125 test binaries). An earlier
  run had failed only in `export_redaction` (07-15's work in progress); it was fixed by the time of the
  final run.
- `cargo clippy -p anvil-core -p anvil-web --all-targets`: no warnings in this plan's files.
- `scripts/check-release-graph.sh`: OK.
- Not run: Postgres (no Docker; the Postgres PAR methods come from 07-11) and the conformance Config
  OP plan (CI, 07-19).

## Deviations from Plan

1. **[Rule 2] `id_token_hint` refused at `/par`.** The stored form (validated `AuthorizationParams`)
   cannot carry it, and dropping it silently would change what `prompt=none` means. It is
   documented in docs/PAR.md.
2. **`resume_pushed_request` signature.** It takes `issuer` (redirect-delivered re-check errors
   need `iss`) and returns `Result<Result<ResumedPushedRequest, AuthorizeOutcome>, CoreError>`
   instead of a bare id. `ResumedPushedRequest` carries `request_id`, the current `client` (so 07-18
   can check `headless_native`) and the re-checked `params`. `now` comes from the service clock.
3. **Discovery allow-list.** `tests/discovery.rs` keeps a list of the metadata names the
   conformance suite knows, so I added the two RFC 9126 names there.
4. ClientAuthService is implemented by `ClientAuthenticator` in the code. The docs name both.

## Issues seen in other plans' files

- `crates/anvil-web/tests/export_redaction.rs` (07-15): `export_dto_contains_no_secrets` and
  `gdpr_export_redacts_other_actors` failed during an intermediate run ("admin email leaked":
  `actor_client_id` carried `admin-person@example.test`). They passed in the final full run.
- During Task 1 the core build was briefly broken by 07-12's in-progress `service/config.rs`
  (missing new `ClientOptions` fields and `dev_mode`). It resolved on its own.
- docs/ARCHITECTURE.md line 236 says `authorization_request` is "also used for PAR". 07-08 gave
  PAR its own `pushed_authorization_request` table, so the doc should be updated (not owned here).
- docs/SUMMARY.md (docs site index) may need a `PAR.md` entry (not owned here).

## Self-Check: PASSED

Commits 5463046 and b3c1225 exist. docs/PAR.md, tests/par.rs, tests/security_par.rs and
tests/par_support/mod.rs exist. service/par.rs has more than 120 lines.
