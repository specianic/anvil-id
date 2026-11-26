#!/usr/bin/env bash
# scripts/check-security-tests.sh: QUAL-01, every security control has a named negative test.
#
#   scripts/check-security-tests.sh              check the map, exit non-zero if any test is missing
#   scripts/check-security-tests.sh --self-test  prove the gate rejects a renamed test function and a
#                                                mapped function that is not a registered test, and
#                                                accepts the unmodified map
#
# The map below ties each in-scope control (ARCHITECTURE.md §11, the RFC 9700 / OAuth 2.1 checklist
# of phase 2 research) to `file::test_fn`. Two checks run:
#
#   1. Source: `fn <test_fn>` exists in the named file.
#   2. Registration: the test binary that owns the file lists `<test_fn>` under `--list`, so a
#      function that lost its #[test]/#[tokio::test] attribute (or a contract case that was never
#      instantiated) is caught. Listing compiles but does not run the tests (no Docker needed).
#
# Owning binary per file:
#   crates/<c>/tests/<t>.rs              -> integration test <t> of crate <c>
#   crates/anvil-storage/src/contract/*  -> the `contract` test of anvil-storage-sqlite (the suite
#                                           is instantiated there by storage_contract_tests!)
#   crates/anvil-cache/src/limiter/contract.rs
#                                        -> the `limiter_contract` test of anvil-cache (included
#                                           with #[path], instantiated per backend by
#                                           limiter_contract_tests!)
#   crates/<c>/src/**                    -> unit tests of crate <c>
#
# Release 0.2 adds the Phase 3 controls: passkeys, TOTP and recovery codes, introspection and
# revocation, consent, session revocation, rate limiting and brute-force protection, CAPTCHA,
# trusted proxies, form_post, the destructive-migration guard, Postgres composite tenant keys and
# the new admin routes.
#
# Release 0.3 adds the Phase 4 controls: the outbound SSRF guard, upstream sign-in (state, binding
# cookie, nonce, iss, ID token alg/aud/exp, require_verified_email), account linking and the atomic
# unlink guard, sealed write-only connection secrets, RP-Initiated Logout (hint, redirect URI,
# confirmation, CSRF exemption scope), Back-Channel Logout (token claims, per-session iss, response
# classification, worker wake), resource indicators, email code and magic link (single use,
# attempt cap, POST-only link, per-toggle enforcement, login_code template check), MFA policy and
# step-up, session switch, email change, theme validation, cookie names, per-route body limits and
# the admin scope of the new routes.
#
# Release 0.4 adds the Phase 5 controls: dynamic client registration (policy, 404 when disabled,
# system tenant, initial and registration access tokens, redirect allow-list, software_statement,
# admin scope, max clients, rate limit), Client ID Metadata Documents (policy and allow-list
# before any fetch, private destinations, redirects, 5 KiB cap, client_id match, no shared
# secrets, no jwks_uri, http refused in production, errors not cached, never redirects, fetch
# budget), resource-aware consent, webhooks (signature, SSRF at create and send, redirects,
# write-only sealed secrets, no personal data, exactly-once claims and leases), custom attribute
# schemas, claim mapping, RBAC (isolation, admin-scope bounding, escalation, last administrator),
# the shared Redis limiter (contract equivalence with the in-process limiter, fail-closed outage,
# hashed keys), declarative tenant configuration, backup/restore guards, local admin recovery,
# the loopback-only healthcheck, passkey enrolment and passkey second factor challenges, the
# config body limit, the 0.4 admin routes and telemetry redaction.
#
# Controls deliberately not mapped here:
#   - "Test code" (SEC-06): enforced by scripts/check-release-graph.sh, not by a unit test.
#   - Released-migration immutability: enforced by scripts/check-migrations.sh (and its
#     --self-test), which `just ci` runs as migrations-check.
#   - Browser-level behaviour (passkey ceremony, consent, sessions, a11y, and for 0.3 the
#     upstream sign-in and linking journeys, RP-Initiated and Back-Channel Logout, email code and
#     magic link, MFA policy and step-up, theme preview, i18n; for 0.4 the multi-tenant console
#     pages, the MCP authorization journey and in-flow passkey enrolment): Playwright specs under
#     tests/e2e/specs, run by the e2e workflow, plus the OpenID conformance plans (conformance
#     workflow).
#   - JIT sign-up racing a concurrent registration of the same email cannot be produced over HTTP;
#     its atomicity is the create_user_with_link_* contract tests mapped above.
#
# Every finding prints one `SECURITY TEST MISSING:` line.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=${CHECK_SECURITY_TESTS_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}

W=crates/anvil-web/tests
# control | file | test function
MAP=$(
  cat <<EOF
redirect: exact match, error page, no redirect|$W/security_redirect.rs|modified_redirect_uris_render_the_error_page
redirect: exact match, error page, no redirect|$W/security_redirect.rs|unknown_client_renders_the_error_page
redirect: exact match, error page, no redirect|$W/security_redirect.rs|post_with_bad_redirect_uri_renders_the_error_page
redirect: validated before any other error|$W/security_redirect.rs|bad_redirect_uri_wins_over_a_bad_response_type
redirect: port flexibility only for native loopback IPs|$W/security_redirect.rs|web_client_port_change_is_rejected
redirect: port flexibility only for native loopback IPs|$W/security_redirect.rs|native_localhost_port_change_is_rejected
pkce: required by default, S256 only|$W/security_pkce.rs|pkce_violations_are_invalid_request
pkce: public clients always need PKCE|$W/security_pkce.rs|public_native_client_always_needs_pkce
pkce: require_pkce client refused even with nonce|$W/security_pkce.rs|pkce_required_client_without_pkce_is_rejected_even_with_nonce
pkce: wrong verifier|$W/security_code.rs|wrong_verifier_is_rejected
pkce: downgrade (challenge without verifier)|$W/security_code.rs|challenge_without_verifier_is_rejected
pkce: downgrade (verifier without challenge)|$W/security_code.rs|verifier_without_challenge_is_rejected
pkce: require_pkce=false only for confidential clients|$W/admin_api.rs|client_registration_rules_are_enforced
pkce: require_pkce=false only for confidential clients|crates/anvil-core/src/service/client.rs|public_client_may_not_disable_pkce
code: single use, reuse revokes the family|$W/security_code.rs|code_reuse_is_rejected_and_revokes_the_family
code: expiry|$W/security_code.rs|expired_code_is_rejected
code: bound to the client|$W/security_code.rs|code_issued_to_another_client_is_rejected
code: bound to the redirect_uri|$W/security_code.rs|mismatched_redirect_uri_is_rejected
code: bound to the redirect_uri|$W/security_code.rs|missing_redirect_uri_is_rejected
code: one winner under concurrency|crates/anvil-storage/src/contract/grants.rs|consume_code_concurrent_single_winner
refresh: reuse revokes the family|$W/security_refresh.rs|reuse_revokes_the_whole_family
refresh: other client rejected without revocation|$W/security_refresh.rs|another_clients_refresh_token_is_rejected_without_revocation
refresh: scope widening|$W/security_refresh.rs|scope_widening_is_rejected
refresh: idle expiry|$W/security_refresh.rs|idle_expired_refresh_token_is_rejected
refresh: one winner under concurrency|crates/anvil-storage/src/contract/grants.rs|rotate_refresh_concurrent
no implicit / hybrid response types|$W/security_pkce.rs|implicit_and_hybrid_response_types_are_unsupported
no ROPC / unknown grants|$W/token_client_credentials.rs|unsupported_and_missing_grant_types
client auth: wrong secret|$W/security_client_auth.rs|wrong_secret_with_basic_is_401_with_challenge
client auth: unknown client indistinguishable|$W/security_client_auth.rs|unknown_client_is_indistinguishable_from_a_wrong_secret
client auth: two methods|$W/security_client_auth.rs|basic_and_body_secret_together_are_rejected
client auth: registered method only|$W/security_client_auth.rs|wrong_method_for_the_client_is_rejected
client auth: missing credentials|$W/security_client_auth.rs|confidential_client_without_credentials_is_rejected
client auth: public client with a secret|$W/security_client_auth.rs|public_client_presenting_a_secret_is_rejected
client auth: malformed basic header|$W/security_client_auth.rs|malformed_basic_headers_are_rejected
client credentials: public clients refused|$W/token_client_credentials.rs|public_client_is_unauthorized
client credentials: openid scope refused|$W/token_client_credentials.rs|openid_scope_is_rejected
private_key_jwt: token endpoint audience|$W/security_private_key_jwt.rs|token_endpoint_audience_is_rejected
private_key_jwt: multi-valued audience|$W/security_private_key_jwt.rs|multi_valued_audience_is_rejected
private_key_jwt: replay|$W/security_private_key_jwt.rs|replayed_assertion_is_rejected
private_key_jwt: reused jti|$W/security_private_key_jwt.rs|reused_jti_in_a_new_assertion_is_rejected
private_key_jwt: jti one winner under concurrency|crates/anvil-storage/src/contract/grants.rs|record_jti_concurrent_single_winner
private_key_jwt: exp more than 5 min ahead|$W/security_private_key_jwt.rs|far_future_exp_is_rejected
private_key_jwt: expired|$W/security_private_key_jwt.rs|expired_assertion_is_rejected
private_key_jwt: missing jti or exp|$W/security_private_key_jwt.rs|missing_jti_or_exp_is_rejected
private_key_jwt: iss differs from sub|$W/security_private_key_jwt.rs|iss_different_from_sub_is_rejected
private_key_jwt: HS256 and none|$W/security_private_key_jwt.rs|hs256_and_none_are_rejected
private_key_jwt: unknown kid|$W/security_private_key_jwt.rs|unknown_kid_is_rejected
private_key_jwt: unregistered key|$W/security_private_key_jwt.rs|unregistered_key_under_the_registered_kid_is_rejected
private_key_jwt: wrong client method|$W/security_private_key_jwt.rs|assertion_for_a_secret_client_is_rejected
jws: HS256 algorithm confusion|crates/anvil-jose/src/jws.rs|hs256_alg_confusion_rejected
jws: alg none|crates/anvil-jose/src/jws.rs|alg_none_rejected
jws: alg outside the allow-list|crates/anvil-jose/src/jws.rs|alg_not_in_allow_list_rejected
jws: token type confusion (typ)|crates/anvil-jose/src/op_token.rs|wrong_or_missing_typ_rejected
iss in authorization responses (RFC 9207)|$W/security_iss.rs|success_redirect_has_iss
iss in authorization responses (RFC 9207)|$W/security_iss.rs|login_required_redirect_has_iss
iss in authorization responses (RFC 9207)|$W/security_iss.rs|invalid_request_redirect_has_iss
iss in authorization responses (RFC 9207)|$W/security_iss.rs|iss_is_added_even_if_the_client_sends_one
id token claims|crates/anvil-core/src/service/claims.rs|id_token_has_all_protocol_claims_with_types
id token at_hash|crates/anvil-jose/src/encoding.rs|at_hash_vector
bearer: no token in the query|$W/security_userinfo.rs|token_in_the_query_is_refused
bearer: ID token is not an access token|$W/security_userinfo.rs|id_token_is_not_an_access_token
bearer: revoked family refused|$W/security_userinfo.rs|token_of_a_revoked_family_is_refused
bearer: expired or tampered tokens refused|$W/security_userinfo.rs|expired_token_is_refused
bearer: expired or tampered tokens refused|$W/security_userinfo.rs|malformed_and_tampered_bearers_are_refused
303 after a credential POST|$W/flow_login.rs|valid_credentials_redirect_303_to_the_authorize_continuation_and_rotate_the_session
303 after a credential POST|$W/flow_registration.rs|open_registration_creates_the_user_signs_in_and_sends_a_verification_link
headers: CSP, frame-ancestors, Referrer-Policy, no external assets|$W/security_csp.rs|every_ui_page_has_the_strict_headers_and_no_external_references
headers: HSTS only over HTTPS|crates/anvil-web/src/layers/security_headers.rs|headers_with_and_without_hsts
csrf: synchronizer token|$W/security_csrf.rs|missing_csrf_token_is_403
csrf: synchronizer token|$W/security_csrf.rs|wrong_csrf_token_is_403
csrf: synchronizer token|$W/security_csrf.rs|csrf_token_of_another_flow_is_403
csrf: synchronizer token|$W/security_csrf.rs|missing_flow_cookie_is_403
csrf: synchronizer token|$W/security_csrf.rs|every_form_page_rejects_a_missing_token
csrf: Sec-Fetch-Site and Origin|$W/security_csrf.rs|cross_site_fetch_metadata_is_403
csrf: Sec-Fetch-Site and Origin|crates/anvil-web/src/layers/csrf.rs|origin_rules
csrf: Sec-Fetch-Site and Origin|crates/anvil-web/src/layers/csrf.rs|without_allowed_origins_any_origin_is_rejected
cookies: __Host-, Secure, HttpOnly, SameSite|$W/security_cookies.rs|production_cookies_are_host_prefixed_secure_and_strict
cookies: dev mode relaxation|$W/security_cookies.rs|development_cookies_have_no_prefix_and_no_secure
secrets hashed at rest (SQLite)|crates/anvil-storage-sqlite/tests/plaintext.rs|secrets_never_stored_plaintext
secrets hashed at rest (Postgres)|crates/anvil-storage-postgres/tests/plaintext.rs|secrets_never_stored_plaintext
secret hygiene: no secrets in Debug output|crates/anvil-core/src/service/client_auth.rs|debug_redacts_secrets
secret hygiene: no secrets in Debug output|crates/anvil-core/src/model/key.rs|debug_redacts_private_key
secret hygiene: config show redacts secrets|crates/anvilid/src/config.rs|show_lists_sources_and_redacts_secrets
tenant isolation: clients|$W/security_tenant.rs|client_of_another_tenant_is_unknown
tenant isolation: clients|$W/security_client_auth.rs|client_of_another_tenant_is_unknown_here
tenant isolation: sessions|$W/security_tenant.rs|session_of_another_tenant_is_not_used
tenant isolation: access tokens|$W/security_userinfo.rs|other_tenants_token_is_refused
tenant isolation: admin tokens|$W/security_admin.rs|access_token_of_another_tenant_is_401
tenant isolation: admin API installation level only|$W/security_admin.rs|admin_api_is_installation_level_only
enumeration: recovery|$W/security_enumeration.rs|recovery_for_an_existing_and_an_unknown_email_is_identical
enumeration: login (dummy hash)|$W/security_enumeration.rs|unknown_user_and_wrong_password_are_identical_and_both_run_argon2
brute force: dummy hash for unknown users|crates/anvil-web/src/adapters/argon2.rs|missing_user_runs_the_dummy_hash
brute force: bounded Argon2 pool never bypasses|crates/anvil-web/src/adapters/argon2.rs|saturation_is_overloaded_never_a_bypass
setup: no default credentials|$W/security_setup.rs|fresh_install_has_no_users_and_no_default_credentials
setup: invalid token refused|$W/security_setup.rs|valid_token_shows_the_form_invalid_token_is_403_without_a_form
setup: expired token refused|$W/security_setup.rs|expired_token_is_refused
setup: single use|$W/security_setup.rs|setup_creates_the_admin_and_a_working_management_client_once
setup: single use under concurrency|$W/security_setup.rs|concurrent_submissions_complete_setup_exactly_once
admin: missing or malformed bearer|$W/security_admin.rs|missing_or_malformed_authorization_is_401
admin: tampered or expired token|$W/security_admin.rs|tampered_token_is_401
admin: tampered or expired token|$W/security_admin.rs|expired_token_is_401
admin: ID token as bearer|$W/security_admin.rs|id_token_as_bearer_is_401
admin: deleted client|$W/security_admin.rs|token_of_a_deleted_client_is_401
admin: scopes|$W/security_admin.rs|read_scope_cannot_write
admin: scopes|$W/security_admin.rs|resource_scopes_are_confined_to_their_resource
admin: scopes|$W/security_admin.rs|system_clients_need_full_admin
cache: OAuth responses are no-store|crates/anvil-web/src/errors.rs|every_oauth_response_is_no_store
passkey: challenge single use|$W/flow_login_factors.rs|passkey_challenge_is_single_use
passkey: challenge single use|$W/flow_passkey.rs|passkey_signs_in_and_a_consumed_challenge_cannot_be_replayed
passkey: enrolment challenge single use, duplicates conflict|$W/account_security.rs|passkey_challenge_is_single_use_even_concurrently_and_duplicates_conflict
passkey: garbage or unrequested responses store nothing|$W/account_security.rs|garbage_or_unrequested_passkey_responses_store_nothing
passkey: garbage assertion refused|$W/flow_passkey.rs|a_garbage_assertion_is_the_login_form_with_passkey_failed
passkey: another user's or tenant's credential refused|$W/flow_login_factors.rs|passkey_of_another_user_or_tenant_is_rejected
passkey: clone detection / stale counter|$W/flow_login_factors.rs|possible_clone_or_stale_counter_fails_and_is_audited
passkey: counter never moves backwards|crates/anvil-storage/src/contract/credentials.rs|passkey_concurrent_updates_never_move_counter_backwards
passkey: credential id unique|crates/anvil-storage/src/contract/credentials.rs|passkey_duplicate_credential_id_conflicts
passkey: invalid relying-party issuers refused|$W/passkey_adapter.rs|relying_party_rejects_ip_and_garbage_issuers
totp: replay rejected|$W/flow_login_factors.rs|totp_code_signs_in_once_and_a_replay_is_rejected
totp: replay rejected|$W/flow_mfa.rs|totp_signs_in_with_mfa_amr_and_the_same_code_is_rejected_later
totp: step one winner under concurrency|crates/anvil-storage/src/contract/credentials.rs|totp_step_concurrent_single_winner
second factor: no factor without a verified password|$W/flow_login_factors.rs|second_factor_inputs_without_a_verified_password_are_refused
second factor: binding token required|$W/flow_mfa.rs|a_second_factor_post_without_a_valid_binding_token_restarts_the_sign_in
second factor: code on the password route is not a factor|$W/flow_mfa.rs|a_code_posted_to_the_password_route_is_not_a_second_factor
second factor: csrf|$W/flow_mfa.rs|second_factor_form_without_csrf_or_flow_is_rejected
recovery code: single use|$W/flow_login_factors.rs|recovery_code_is_single_use_and_enqueues_a_sealed_notice
recovery code: one winner under concurrency|crates/anvil-storage/src/contract/credentials.rs|recovery_code_concurrent_single_winner
credentials: tenant isolation|crates/anvil-storage/src/contract/credentials.rs|credentials_isolated_by_tenant
credentials: removal only by the owner|$W/account_security.rs|removing_a_passkey_works_without_javascript_and_only_for_its_owner
account: csrf, binding and cross-site posts|$W/account_security.rs|posts_without_csrf_with_a_wrong_token_or_cross_site_are_rejected
account: settings flow owner and kind|$W/account_security.rs|binding_owner_and_kind_are_enforced
account: re-authentication for changes|$W/account_security.rs|a_stale_session_must_sign_in_again_and_changes_nothing
account: session required|$W/account_security.rs|without_a_session_every_route_sends_the_user_to_sign_in
introspection: confidential client authentication only|$W/security_introspect_revoke.rs|introspect_requires_confidential_client_authentication
introspection: request shape|$W/security_introspect_revoke.rs|introspect_request_shape_is_enforced
introspection: other clients' tokens need can_introspect|$W/security_introspect_revoke.rs|other_clients_token_needs_can_introspect
introspection: garbage, expired, other tenant inactive|$W/security_introspect_revoke.rs|garbage_expired_and_other_tenant_tokens_are_inactive
introspection: consumed refresh token inactive|$W/security_introspect_revoke.rs|consumed_refresh_token_is_inactive
introspection: opaque tokens tenant-bound|$W/access_token_format.rs|opaque_token_of_one_tenant_is_unknown_in_another
revocation: client authentication and POST|$W/security_introspect_revoke.rs|revoke_requires_client_authentication_and_post
revocation: unknown token no oracle|$W/security_introspect_revoke.rs|unknown_token_is_200_without_effect
revocation: unsupported hint|$W/security_introspect_revoke.rs|unsupported_hint_is_rejected
revocation: refresh token revokes the family|$W/security_introspect_revoke.rs|revoking_a_refresh_token_revokes_the_family
revocation: access token revokes the family|$W/security_introspect_revoke.rs|revoking_a_jwt_access_token_revokes_its_family
revocation: access token revokes the family|$W/security_introspect_revoke.rs|revoking_an_opaque_access_token_revokes_it_and_its_family
revocation: another client's token unchanged|$W/security_introspect_revoke.rs|another_clients_token_is_not_revoked
revocation: JWT client-credentials token unsupported|$W/security_introspect_revoke.rs|jwt_client_credentials_token_cannot_be_revoked
revocation: reuse is audited|$W/security_introspect_revoke.rs|refresh_and_code_reuse_are_audited
consent: csrf and binding|$W/consent.rs|submissions_without_a_valid_binding_are_rejected
consent: deny is access_denied with state and iss|$W/consent.rs|deny_returns_access_denied_with_state_and_iss
consent: prompt=none needs a grant|$W/consent.rs|prompt_none_when_consent_is_needed_is_consent_required
consent: double submission issues one code|$W/consent.rs|a_double_submission_issues_one_code
consent: session required|$W/consent.rs|the_consent_page_needs_a_session
consent: id_token_hint algorithm gated by the tenant|$W/consent.rs|an_es256_hint_is_rejected_when_the_tenant_does_not_enable_es256
consent: revocation changes nothing without a binding|$W/account_apps.rs|revocations_without_a_valid_binding_change_nothing
consent: revocation only that client's tokens|crates/anvil-storage/src/contract/consent.rs|consent_revoke_revokes_only_that_clients_families
consent: tenant isolation|crates/anvil-storage/src/contract/consent.rs|consent_isolated_by_tenant
sessions: another user's or unknown session cannot be revoked|$W/sessions.rs|another_users_or_unknown_session_cannot_be_revoked
sessions: csrf, binding and cross-site posts|$W/sessions.rs|posts_without_csrf_with_a_wrong_binding_or_cross_site_are_rejected
sessions: revocation revokes the session's tokens|$W/sessions.rs|revoking_another_session_signs_it_out_and_revokes_its_tokens
sessions: idle timeout|$W/sessions.rs|idle_timeout_signs_out
sessions: absolute limit|$W/sessions.rs|hourly_activity_keeps_the_session_until_the_absolute_limit
sessions: revocation only its own families|crates/anvil-storage/src/contract/sessions.rs|session_revoke_with_families_only_its_own
rate limit: auth class per IP, themed 429|$W/security_ratelimit.rs|auth_class_is_limited_per_ip_with_a_themed_429
rate limit: token endpoint per IP|$W/security_ratelimit.rs|token_flood_from_one_ip_gets_oauth_json_429
rate limit: token endpoint per client|$W/security_ratelimit.rs|token_endpoint_limits_per_claimed_client_id
rate limit: admin API|$W/security_ratelimit.rs|admin_api_flood_gets_problem_json_429
rate limit: path tenants classified|$W/security_ratelimit.rs|path_tenant_auth_routes_are_classified_tenant_relative
rate limit: spoofed X-Forwarded-For does not bypass|$W/security_ratelimit.rs|varying_x_forwarded_for_from_an_untrusted_peer_does_not_bypass
rate limit: no peer address is not waved through|$W/security_ratelimit.rs|request_without_peer_address_is_not_waved_through
rate limit: route classes independent|crates/anvil-cache/tests/limiter.rs|gcra_route_classes_are_independent
brute force: progressive lock, success resets|$W/security_bruteforce.rs|failed_passwords_lock_progressively_and_success_resets
brute force: lock per identifier and IP|$W/security_bruteforce.rs|the_lock_is_per_identifier_and_ip
brute force: enumeration-safe answers|$W/security_bruteforce.rs|unknown_identifiers_get_byte_identical_answers
brute force: identifier tier across many IPs|$W/security_bruteforce.rs|the_identifier_tier_delays_attempts_from_many_ips_without_captcha
brute force: CAPTCHA before the password|$W/security_bruteforce.rs|with_captcha_the_identifier_tier_requires_a_verified_captcha_before_the_password
brute force: second factor throttled per user|$W/security_bruteforce.rs|second_factor_attempts_are_throttled_per_user_and_reset_on_success
brute force: passkey failures throttled per IP|$W/security_bruteforce.rs|passkey_failures_are_throttled_per_ip
brute force: known and unknown identifiers identical|crates/anvil-cache/tests/limiter.rs|gate_known_and_unknown_identifiers_behave_identically
brute force: lock capped, doubling|crates/anvil-cache/tests/limiter.rs|backoff_free_attempts_then_doubling_lock_capped_at_fifteen_minutes
captcha: unreachable provider fails closed|$W/security_bruteforce.rs|an_unreachable_captcha_provider_fails_closed
captcha: success false rejected|$W/captcha.rs|success_false_is_rejected
captcha: http error fails closed|$W/captcha.rs|http_error_fails_closed
captcha: timeout fails closed|$W/captcha.rs|timeout_fails_closed
captcha: malformed json fails closed|$W/captcha.rs|malformed_json_fails_closed
captcha: oversized body fails closed|$W/captcha.rs|oversized_body_fails_closed
captcha: redirects not followed|$W/captcha.rs|redirects_are_not_followed
captcha: non-https endpoints refused|$W/captcha.rs|non_https_endpoints_are_refused
trusted proxies: untrusted peer ignores X-Forwarded-For|$W/client_ip.rs|client_ip_untrusted_peer_ignores_spoofed_xff
trusted proxies: no trusted proxies ignores headers|$W/client_ip.rs|client_ip_no_trusted_proxies_ignores_headers
trusted proxies: right-to-left walk, never leftmost|$W/client_ip.rs|client_ip_walks_right_to_left_never_leftmost
trusted proxies: unparsable entry stops the walk|$W/client_ip.rs|client_ip_unparsable_entry_stops_the_walk
trusted proxies: header modes do not mix|$W/client_ip.rs|client_ip_header_modes_do_not_mix
trusted proxies: spoofed prefix never chosen (property)|$W/client_ip.rs|client_ip_never_comes_from_spoofed_prefix
trusted proxies: spoofed prefix never chosen (property)|$W/client_ip.rs|client_ip_never_comes_from_spoofed_forwarded_prefix
trusted proxies: forwarded proto/host do not change issuer or cookies|$W/client_ip.rs|client_ip_forwarded_proto_and_host_do_not_change_issuer_or_cookies
form_post: escaping of reflected values|$W/response_mode.rs|form_post_escapes_reflected_state
form_post: CSP form-action only the redirect origin|$W/response_mode.rs|form_post_success_posts_code_state_and_iss
form_post: invalid redirect is an error page without a form|$W/response_mode.rs|invalid_redirect_with_form_post_is_an_error_page_without_a_form
form_post: unsupported response_mode via query|$W/response_mode.rs|unsupported_response_mode_is_invalid_request_via_query
request objects: rejected, delivered with their mode|$W/response_mode.rs|rejected_request_object_is_delivered_with_its_form_post_mode
request objects: unusable mode falls back to query|$W/response_mode.rs|rejected_request_object_with_unusable_mode_falls_back_to_query
request objects: invalid redirect is an error page|$W/response_mode.rs|request_object_with_invalid_redirect_is_an_error_page
id token alg: not enabled for the tenant refused|$W/id_token_alg.rs|alg_not_enabled_for_the_tenant_is_a_server_error
key rotation: algorithm must be enabled|$W/jwks_rotation.rs|rotate_now_rejects_an_alg_the_tenant_has_not_enabled
key rotation: one promotion under concurrency|$W/jwks_rotation.rs|concurrent_runs_promote_exactly_once
key rotation: immediate rotation drops the old key|$W/jwks_rotation.rs|immediate_rotation_drops_the_old_key_from_jwks_at_once
jobs: lease single holder|crates/anvilid/tests/jobs.rs|two_runners_never_run_the_same_job_concurrently
jobs: lease single holder under concurrency|crates/anvil-storage/src/contract/jobs.rs|job_lease_concurrent_single_holder
migrations: destructive guard refuses and changes nothing (SQLite)|crates/anvil-storage-sqlite/src/migrate.rs|migrate_refuses_pending_destructive_migration_and_changes_nothing
migrations: destructive guard refuses and changes nothing (Postgres)|crates/anvil-storage-postgres/src/migrate.rs|migrate_refuses_pending_destructive_migration_and_changes_nothing
migrations: embedded migrations are not destructive (SQLite)|crates/anvil-storage-sqlite/src/migrate.rs|migrate_embedded_migrations_are_not_destructive
migrations: embedded migrations are not destructive (Postgres)|crates/anvil-storage-postgres/src/migrate.rs|migrate_embedded_migrations_are_not_destructive
migrations: destructive refusal names the flag|crates/anvilid/src/storage.rs|destructive_refusal_names_the_migrations_and_the_flag
tenant isolation: Postgres composite tenant foreign keys|crates/anvil-storage-postgres/src/lib.rs|composite_tenant_foreign_keys_reject_cross_tenant_rows
admin v0.2: new routes need a token|$W/security_admin_v02.rs|every_new_route_rejects_a_missing_token
admin v0.2: new routes reject other tenants' tokens|$W/security_admin_v02.rs|every_new_route_rejects_tokens_of_another_tenant
admin v0.2: new routes require their scope|$W/security_admin_v02.rs|every_new_route_requires_its_scope
admin v0.2: tenant signing/captcha need tenants write|$W/security_admin_v02.rs|tenant_signing_and_captcha_settings_need_the_tenants_write_scope
admin v0.2: write-only secrets never disclosed|$W/security_admin_v02.rs|captcha_secret_and_smtp_password_are_never_disclosed
admin v0.2: write-only secrets never disclosed|$W/admin_api_v02.rs|captcha_secret_is_write_only
admin v0.2: disabling an algorithm in use refused|$W/admin_api_v02.rs|disabling_a_signing_algorithm_in_use_is_refused_with_the_client_ids
admin audit: failed actions record nothing|$W/admin_audit.rs|failed_admin_actions_record_nothing
admin audit: signing algs gate client id token alg|$W/admin_audit.rs|signing_algs_enable_keys_and_gate_client_id_token_alg
console: default tenant clients cannot get admin scopes|$W/console_client.rs|default_tenant_clients_cannot_obtain_admin_scopes
console: system tenant registration disabled|$W/console_client.rs|system_tenant_registration_is_disabled_on_install_and_enforced_later
console: traversal and missing files are 404|$W/console.rs|missing_files_and_traversal_are_404
mail templates: no includes, runaway loops bounded|crates/anvil-mail/tests/templates.rs|includes_are_not_possible
mail templates: no includes, runaway loops bounded|crates/anvil-mail/tests/templates.rs|runaway_loops_fail_quickly
mail templates: render errors do not leak payload|crates/anvil-mail/tests/templates.rs|override_render_errors_do_not_leak_payload_values
smtp test: errors never include credentials|crates/anvil-mail/tests/smtp_test.rs|auth_rejection_reports_535_without_credentials
ssrf: blocked address classes refused without connecting|$W/security_ssrf.rs|blocked_ip_literals_are_refused_without_connecting
ssrf: blocked address classes refused without connecting|crates/anvil-web/src/adapters/outbound.rs|blocked_table
ssrf: blocked address classes refused without connecting|crates/anvil-web/src/adapters/outbound.rs|any_address_in_a_blocked_v4_net_is_blocked
ssrf: blocked address classes refused without connecting|crates/anvil-web/src/adapters/outbound.rs|any_address_in_a_blocked_v6_net_is_blocked
ssrf: DNS answers checked, allow-list explicit|$W/security_ssrf.rs|host_name_resolving_to_loopback_is_blocked_unless_allow_listed
ssrf: DNS answers checked, allow-list explicit|crates/anvil-web/src/adapters/outbound.rs|allow_list_overrides_and_dev_default
ssrf: redirects never followed|$W/security_ssrf.rs|redirects_are_never_followed
ssrf: userinfo and non-https schemes rejected|$W/security_ssrf.rs|userinfo_and_non_https_schemes_are_rejected
ssrf: userinfo and non-https schemes rejected|crates/anvil-web/src/adapters/outbound.rs|check_url_rules
ssrf: body size and time bounded|$W/security_ssrf.rs|oversized_body_is_too_large
ssrf: body size and time bounded|$W/security_ssrf.rs|slow_server_times_out
ssrf: errors do not echo the destination|$W/security_ssrf.rs|errors_do_not_echo_the_destination
ssrf: errors do not echo the destination|crates/anvil-web/src/adapters/outbound.rs|errors_never_echo_details
ssrf: proxy environment ignored, extra CA only when configured|$W/security_ssrf.rs|proxy_environment_is_ignored
ssrf: proxy environment ignored, extra CA only when configured|$W/security_ssrf.rs|extra_ca_is_trusted_only_when_configured
ssrf: upstream discovery endpoints obey the outbound policy|$W/upstream_adapter.rs|discovery_rejects_endpoints_the_outbound_policy_refuses
ssrf: upstream discovery endpoints obey the outbound policy|$W/upstream_adapter.rs|production_policy_blocks_loopback_upstreams
ssrf: back-channel to a blocked destination gives up without a request|$W/backchannel.rs|blocked_destination_gives_up_without_a_request
upstream: discovery issuer must match|$W/upstream_adapter.rs|discovery_issuer_mismatch_is_rejected
upstream: JWKS failures fail closed, private keys refused|$W/upstream_adapter.rs|jwks_fetch_failures_fail_closed
upstream: JWKS failures fail closed, private keys refused|$W/upstream_adapter.rs|jwks_with_private_members_is_rejected
upstream: errors never echo bodies or URLs|$W/upstream_adapter.rs|upstream_errors_never_echo_bodies_or_urls
upstream: state bound to the flow|$W/security_linking.rs|tampered_or_foreign_state_is_rejected
upstream: state bound to the flow|$W/security_linking.rs|a_replayed_callback_is_rejected
upstream: binding cookie required|$W/security_linking.rs|callback_without_the_binding_cookie_is_rejected_and_keeps_the_flow
upstream: binding cookie required|$W/security_linking.rs|callback_with_another_binding_cookie_is_rejected
upstream: binding cookie cleared only on a state match|$W/security_linking.rs|forged_callback_does_not_cancel_pending_sign_in
upstream: binding cookie cleared only on a state match|$W/security_linking.rs|matching_callback_clears_the_binding_cookie_even_when_it_fails_later
upstream: sealed flow values bound to flow and tenant|crates/anvil-core/src/service/upstream.rs|sealed_values_open_only_in_their_flow_and_tenant
upstream: nonce|$W/security_linking.rs|an_id_token_for_another_nonce_is_rejected
upstream: nonce|crates/anvil-core/src/upstream/claims.rs|nonce_rules
upstream: RFC 9207 iss on the callback|$W/security_linking.rs|rfc9207_iss_must_match_when_the_provider_advertises_it
upstream: ID token issuer|crates/anvil-core/src/upstream/claims.rs|google_rule_rejects_other_issuers
upstream: ID token issuer|crates/anvil-core/src/upstream/claims.rs|microsoft_single_tenant_still_checks_tid
upstream: ID token alg (none, HS confusion, allow-list, signature)|crates/anvil-core/src/upstream/claims.rs|alg_none_rejected
upstream: ID token alg (none, HS confusion, allow-list, signature)|crates/anvil-core/src/upstream/claims.rs|hs256_with_public_key_bytes_rejected
upstream: ID token alg (none, HS confusion, allow-list, signature)|crates/anvil-core/src/upstream/claims.rs|alg_outside_allow_list_rejected
upstream: ID token alg (none, HS confusion, allow-list, signature)|crates/anvil-core/src/upstream/claims.rs|unknown_kid_and_bad_signature_rejected
upstream: ID token audience|crates/anvil-core/src/upstream/claims.rs|audience_rules
upstream: ID token exp/iat|crates/anvil-core/src/upstream/claims.rs|time_rules
upstream: ID token check order|crates/anvil-core/src/upstream/claims.rs|check_order_signature_before_issuer_before_audience
upstream: UserInfo of another subject refused|$W/security_linking.rs|userinfo_fallback_rejects_another_subject
upstream: provider error not echoed|$W/security_linking.rs|provider_error_is_a_generic_error_without_echoing_it
upstream: start needs csrf and the flow cookie|$W/security_linking.rs|start_requires_the_csrf_token_and_the_flow_cookie
upstream: only the callback accepts a cross-site post|$W/security_linking.rs|only_the_callback_accepts_a_cross_site_post
upstream: untrusted emails never verified|crates/anvil-core/src/upstream/claims.rs|untrusted_never_verified
upstream: untrusted emails never verified|crates/anvil-core/src/upstream/claims.rs|microsoft_email_never_verified_and_ids_kept
upstream: require_verified_email applies to upstream accounts|$W/security_linking.rs|untrusted_jit_account_must_verify_before_sign_in
upstream: require_verified_email applies to upstream accounts|$W/security_linking.rs|linked_unverified_account_is_refused_under_require_verified_email
linking: unverified upstream email never auto-links|$W/security_linking.rs|unverified_upstream_email_never_auto_links_and_hides_the_account
linking: unverified upstream email never auto-links|crates/anvil-core/src/upstream/linking.rs|unverified_upstream_email_never_links_and_hides_candidate
linking: unverified local account never auto-linked|$W/security_linking.rs|unverified_local_account_is_never_auto_linked
linking: unverified local account never auto-linked|crates/anvil-core/src/upstream/linking.rs|unverified_local_email_refuses_auto_link
linking: untrusted connection needs confirmation|$W/security_linking.rs|untrusted_connection_with_a_verified_email_needs_confirmation
linking: confirmation page does not enumerate accounts|$W/security_linking.rs|confirmation_page_does_not_tell_whether_an_untrusted_email_has_an_account
linking: Microsoft never auto-links|$W/security_linking.rs|microsoft_email_never_auto_links_even_when_trusted
linking: Microsoft never auto-links|crates/anvil-core/src/upstream/linking.rs|microsoft_never_auto_links
linking: inactive link refused|crates/anvil-core/src/upstream/linking.rs|existing_inactive_link_refused
linking: one identity, one user|$W/security_linking.rs|an_identity_linked_to_one_user_cannot_be_linked_to_another
linking: one identity, one user|$W/account_linked.rs|connect_refuses_an_identity_linked_to_another_user
linking: account-page link needs the owner, re-auth and the binding|$W/security_linking.rs|link_from_the_account_page_needs_the_owner_signed_in
linking: account-page link needs the owner, re-auth and the binding|$W/account_linked.rs|connect_needs_a_recent_sign_in_and_the_binding
linking: unlink keeps a sign-in method|$W/account_linked.rs|unlink_of_the_only_sign_in_method_is_refused
linking: unlink keeps a sign-in method|crates/anvil-storage/src/contract/connections.rs|delete_link_keeps_a_sign_in_method
linking: unlink guard atomic under concurrency|crates/anvil-storage/src/contract/connections.rs|delete_link_concurrent_never_removes_the_last_method
linking: unverified email is not a remaining sign-in method|$W/account_linked.rs|unverified_email_is_not_a_remaining_sign_in_method
linking: unlink only own links, csrf, re-auth|$W/account_linked.rs|unlink_of_another_users_link_is_not_found
linking: unlink only own links, csrf, re-auth|$W/account_linked.rs|unlink_without_csrf_or_flow_cookie_is_forbidden
linking: unlink only own links, csrf, re-auth|$W/account_linked.rs|unlink_needs_a_recent_sign_in
linking: unlink only own links, csrf, re-auth|crates/anvil-storage/src/contract/connections.rs|identity_link_delete_only_own
linking: JIT user and link created atomically|crates/anvil-storage/src/contract/connections.rs|create_user_with_link_is_atomic
linking: JIT user and link created atomically|crates/anvil-storage/src/contract/connections.rs|create_user_with_link_stores_verification_atomically
linking: tenant isolation|crates/anvil-storage/src/contract/connections.rs|connections_isolated_by_tenant
connections: secret sealed with tenant and connection AAD|crates/anvil-core/src/service/connection.rs|secret_is_sealed_with_tenant_and_connection_aad
connections: secret sealed at rest (SQLite)|crates/anvil-storage-sqlite/tests/plaintext.rs|connection_secret_sealed_at_rest
connections: secret sealed at rest (Postgres)|crates/anvil-storage-postgres/tests/plaintext.rs|connection_secret_sealed_and_bound_to_tenant_and_connection
connections: write-only secret, never echoed|$W/admin_connections.rs|crud_round_trip_with_write_only_secret
connections: write-only secret, never echoed|$W/security_admin_v03.rs|the_secret_is_never_echoed_in_validation_errors
connections: write-only secret, never echoed|crates/anvil-core/src/service/connection.rs|debug_of_inputs_hides_the_secret
connections: issuer and endpoints https only|crates/anvil-core/src/service/connection.rs|oidc_issuer_must_be_https_or_loopback_http
connections: issuer and endpoints https only|crates/anvil-core/src/service/connection.rs|endpoint_overrides_and_oauth2_endpoints_are_checked
connections: Microsoft email trust needs the risk flag|$W/admin_connections.rs|microsoft_email_trust_needs_the_risk_flag_and_is_audited
connections: Microsoft email trust needs the risk flag|crates/anvil-core/src/service/connection.rs|email_trust_defaults_per_kind_and_microsoft_needs_the_flag
admin v0.3: connection routes need a token|$W/security_admin_v03.rs|every_connection_route_rejects_a_missing_token
admin v0.3: connection routes require the settings scope|$W/security_admin_v03.rs|every_connection_route_requires_the_settings_scope
admin v0.3: another tenant's connection not found|$W/security_admin_v03.rs|another_tenants_connection_is_not_found
admin v0.3: system tenant connections need admin write|$W/security_admin_v03.rs|system_tenant_connections_need_admin_write
admin v0.3: branding routes enforce the admin scope|$W/security_theme.rs|every_branding_route_enforces_the_admin_scope
logout: id_token_hint alg none rejected|$W/security_logout.rs|alg_none_hint_is_rejected
logout: id_token_hint signature, tenant and type checked|$W/security_logout.rs|a_hint_signed_by_a_foreign_key_is_rejected
logout: id_token_hint signature, tenant and type checked|$W/security_logout.rs|a_hint_from_another_tenant_is_rejected
logout: id_token_hint signature, tenant and type checked|$W/security_logout.rs|a_tampered_payload_is_rejected
logout: id_token_hint signature, tenant and type checked|$W/security_logout.rs|a_token_that_is_not_an_id_token_is_rejected
logout: id_token_hint signature, tenant and type checked|$W/security_logout.rs|a_hint_for_an_unknown_client_is_rejected
logout: post_logout_redirect_uri exact and registered|$W/security_logout.rs|unregistered_or_modified_redirect_uris_are_rejected
logout: post_logout_redirect_uri exact and registered|$W/security_logout.rs|a_uri_without_hint_or_client_id_is_rejected
logout: client_id must match the hint|$W/security_logout.rs|client_id_must_match_the_hint
logout: client_id must match the hint|$W/security_logout.rs|an_unknown_client_id_is_rejected
logout: repeated parameters invalid|$W/security_logout.rs|repeated_parameters_and_non_form_posts_are_invalid_requests
logout: repeated parameters invalid|crates/anvil-core/src/service/logout.rs|from_pairs_rejects_every_repeated_known_parameter
logout: hint for another session does not redirect|$W/logout.rs|a_hint_for_another_session_asks_and_does_not_redirect
logout: confirmation needs the flow cookie and csrf|$W/security_logout.rs|confirmation_requires_flow_cookie_and_csrf
logout: CSRF/fetch-metadata exemption only for end_session|$W/security_logout.rs|confirmation_post_is_behind_fetch_metadata_but_end_session_post_is_not
logout: CSRF/fetch-metadata exemption only for end_session|$W/security_logout.rs|a_cross_site_post_without_a_valid_hint_never_logs_out
back-channel: logout token has exactly the spec claims|crates/anvil-core/src/service/logout.rs|logout_token_has_typ_and_exactly_the_spec_claims
back-channel: logout token has exactly the spec claims|$W/backchannel.rs|logout_delivers_only_a_spec_logout_token_and_204_marks_delivered
back-channel: signed with the client's id token alg|$W/backchannel.rs|token_is_signed_with_the_clients_id_token_alg
back-channel: iss is the issuer of the RP session|$W/backchannel.rs|logout_token_iss_is_the_issuer_the_rp_signed_in_with
back-channel: iss is the issuer of the RP session|crates/anvil-core/src/service/logout.rs|logout_token_uses_the_delivery_issuer_before_the_canonical_one
back-channel: iss is the issuer of the RP session|crates/anvil-storage/src/contract/logout.rs|rp_session_records_issuer_and_deliveries_copy_it
back-channel: response classification (4xx give up, 5xx retry, removed URI)|$W/backchannel.rs|status_400_gives_up_after_one_attempt_and_is_audited_without_token
back-channel: response classification (4xx give up, 5xx retry, removed URI)|$W/backchannel.rs|status_500_retries_with_backoff_and_gives_up_at_the_deadline
back-channel: response classification (4xx give up, 5xx retry, removed URI)|$W/backchannel.rs|removed_uri_gives_up
back-channel: response classification (4xx give up, 5xx retry, removed URI)|crates/anvil-web/src/adapters/backchannel.rs|outbound_results_map_to_delivery_outcomes
back-channel: every revocation enqueues|crates/anvil-storage/src/contract/logout.rs|revoke_with_families_enqueues_backchannel_delivery
back-channel: every revocation enqueues|crates/anvil-storage/src/contract/logout.rs|revoke_all_for_user_enqueues_backchannel_delivery
back-channel: every revocation enqueues|crates/anvil-storage/src/contract/logout.rs|complete_recovery_enqueues_backchannel_delivery
back-channel: every revocation enqueues|crates/anvil-storage/src/contract/logout.rs|user_delete_enqueues_backchannel_delivery
back-channel: each delivery claimed once under concurrency|crates/anvil-storage/src/contract/logout.rs|delivery_claim_concurrent_each_row_once
back-channel: every revocation path wakes the worker|$W/backchannel_wake.rs|account_session_revocation_wakes_and_the_page_read_does_not
back-channel: every revocation path wakes the worker|$W/backchannel_wake.rs|admin_session_and_user_deletion_wake_the_worker
back-channel: every revocation path wakes the worker|$W/backchannel_wake.rs|session_switch_delivers_the_old_users_logout_without_waiting_for_the_poll
resources: unlisted or malformed resource is invalid_target|$W/resource_indicators.rs|unlisted_or_malformed_resources_redirect_invalid_target
resources: unlisted or malformed resource is invalid_target|$W/resource_indicators.rs|malformed_resources_at_token_are_invalid_target_before_the_code_is_used
resources: bad resource with an untrusted redirect is an error page|$W/resource_indicators.rs|a_bad_resource_with_an_untrusted_redirect_is_an_error_page
resources: downscope only within the grant|$W/resource_indicators.rs|code_exchange_outside_the_grant_is_invalid_target_and_burns_the_code
resources: downscope only within the grant|$W/resource_indicators.rs|refresh_downscopes_and_the_refresh_token_keeps_the_full_grant
resources: downscope only within the grant|crates/anvil-core/src/service/token.rs|refresh_resources_downscope_within_the_family_grant
resources: client_credentials only allowed resources|$W/resource_indicators.rs|client_credentials_accepts_allowed_resources_only
resources: client_credentials only allowed resources|crates/anvil-core/src/service/token.rs|client_credentials_resources_must_be_allowed
resources: UserInfo refuses tokens for other audiences|$W/resource_indicators.rs|userinfo_refuses_tokens_bound_only_to_other_resources
email code: unknown, unverified and blocked addresses look the same|$W/security_email_code.rs|unknown_unverified_and_blocked_addresses_look_the_same_and_get_nothing
email code: unknown, unverified and blocked addresses look the same|$W/security_email_code.rs|an_address_unverified_after_the_send_cannot_use_its_code_or_link
email code: single use|$W/security_email_code.rs|a_code_works_once
email code: single use|$W/security_email_code.rs|concurrent_submits_of_one_code_sign_in_once
email code: single use|crates/anvil-core/src/flow/email_code.rs|right_code_is_accepted_once_and_clears_code_and_link
email code: attempt cap and per-user lock|$W/security_email_code.rs|five_wrong_codes_invalidate_the_code_and_the_link
email code: attempt cap and per-user lock|$W/security_email_code.rs|code_attempts_are_locked_per_user_across_new_codes
email code: attempt cap and per-user lock|crates/anvil-core/src/flow/email_code.rs|five_wrong_codes_invalidate_code_and_link
email code: expiry|$W/security_email_code.rs|expired_code_and_link_are_refused
email code: send limits|$W/security_email_code.rs|a_flow_sends_at_most_three_emails
email code: send limits|$W/security_email_code.rs|sends_per_address_escalate_across_peers
email code: a new code replaces the previous one|$W/security_email_code.rs|a_new_code_replaces_the_previous_one
email code: link GET consumes nothing, POST once|$W/security_email_code.rs|link_get_consumes_nothing_and_the_post_works_once
email code: link from another browser consumes nothing|$W/security_email_code.rs|link_from_another_browser_consumes_nothing
email code: csrf, rejected posts consume nothing|$W/security_email_code.rs|posts_without_or_with_a_wrong_csrf_token_are_403
email code: csrf, rejected posts consume nothing|$W/security_email_code.rs|rejected_posts_consume_nothing
email code: code and link token not stored in clear|$W/security_email_code.rs|the_code_and_the_link_token_are_not_stored_in_clear
email code: code and link token not stored in clear|crates/anvil-core/src/flow/email_code.rs|state_json_holds_no_code_or_token
email code: never claims MFA|$W/security_email_code.rs|email_sign_in_never_claims_mfa
email code: per-toggle enforcement (code / link)|$W/security_email_code.rs|code_only_tenant_refuses_the_link_routes
email code: per-toggle enforcement (code / link)|$W/security_email_code.rs|link_only_tenant_refuses_the_code_route
email code: per-toggle enforcement (code / link)|$W/security_email_code.rs|a_method_switched_off_after_the_send_is_refused
email code: per-toggle enforcement (code / link)|$W/security_email_code.rs|core_refuses_a_code_the_email_did_not_carry
email code: per-toggle enforcement (code / link)|$W/security_email_code.rs|core_refuses_a_link_the_email_did_not_carry
email code: login_code template must guard optional code/link|crates/anvil-mail/tests/templates.rs|login_code_unguarded_code_is_rejected
email code: login_code template must guard optional code/link|crates/anvil-mail/tests/templates.rs|login_code_unguarded_link_is_rejected
email code: login_code template must guard optional code/link|crates/anvil-mail/tests/templates.rs|login_code_bare_if_is_rejected_because_rendering_is_strict
email code: login_code template must guard optional code/link|$W/admin_api_v02.rs|email_templates_default_override_validation_and_reset
mfa policy: strictest wins, client never relaxes the tenant|crates/anvil-core/src/policy/mfa.rs|effective_policy_never_weakens_tenant
mfa policy: strictest wins, client never relaxes the tenant|$W/flow_mfa_policy.rs|client_off_cannot_relax_tenant_required
mfa policy: required enrols a factor before the session|$W/flow_mfa_policy.rs|required_without_a_factor_enrols_then_signs_in_with_mfa
mfa policy: required applies after upstream sign-in|$W/upstream_login.rs|required_mfa_policy_asks_for_the_second_factor_after_an_upstream_sign_in
mfa policy: enrolment csrf|$W/flow_mfa_policy.rs|enrolment_post_without_csrf_or_with_a_wrong_one_is_forbidden
step-up: refused once the session is gone|$W/authorize_step_up.rs|step_up_is_refused_once_the_session_is_gone
step-up: essential acr not met is unmet_authentication_requirements|$W/authorize_step_up.rs|essential_acr_a_user_cannot_meet_is_unmet_authentication_requirements
step-up: voluntary acr not met issues the lower acr|$W/authorize_step_up.rs|voluntary_acr_a_user_cannot_meet_issues_the_lower_acr
step-up: prompt=none never shows a step-up page|$W/authorize_step_up.rs|prompt_none_never_shows_a_step_up_page
step-up: acr request classification|crates/anvil-core/src/policy/mfa.rs|acr_request_classification
session switch: signing in as another user revokes the previous session|$W/authorize_step_up.rs|signing_in_as_another_user_revokes_the_previous_users_session
session switch: signing in as another user revokes the previous session|$W/authorize_prompt.rs|use_another_account_signs_in_bob_and_logs_alice_out
session switch: never answers with the old session|$W/authorize_prompt.rs|use_another_account_without_signing_in_never_answers_with_the_old_session
session switch: chooser binding and ownership|$W/authorize_prompt.rs|chooser_submissions_without_a_valid_binding_are_rejected
session switch: chooser binding and ownership|$W/authorize_prompt.rs|another_users_chooser_flow_is_refused
login hint: only an email, escaped|$W/authorize_step_up.rs|login_hint_prefills_only_an_email_and_is_escaped
email change: needs a recent sign-in|$W/account_profile.rs|email_change_needs_a_recent_sign_in
email change: confirmed by POST only, single use|$W/account_profile.rs|email_change_is_confirmed_by_post_only_switches_and_notifies_the_old_address
email change: confirmed by POST only, single use|crates/anvil-storage/src/contract/users.rs|email_change_rejects_invalid_tokens
email change: confirmed by POST only, single use|crates/anvil-storage/src/contract/users.rs|email_change_concurrent_single_winner
email change: tampered, expired or missing links rejected|$W/account_profile.rs|tampered_expired_or_missing_links_are_rejected
email change: tampered, expired or missing links rejected|crates/anvil-core/src/service/account.rs|email_change_link_aad_binds_tenant_and_token
email change: conflict keeps the token|$W/account_profile.rs|address_taken_at_confirmation_keeps_the_token_until_it_is_free
email change: conflict keeps the token|crates/anvil-storage/src/contract/users.rs|email_change_conflict_keeps_token
account pages: csrf and flow cookie|$W/account_profile.rs|posts_without_csrf_wrong_token_or_flow_cookie_are_forbidden_and_change_nothing
account pages: password change needs a recent sign-in|$W/account_profile.rs|password_change_needs_a_recent_sign_in
theme: custom CSS validator|crates/anvil-core/src/policy/branding.rs|css_forbidden_constructs_report_their_line
theme: custom CSS validator|crates/anvil-core/src/policy/branding.rs|url_in_any_casing_is_rejected
theme: custom CSS validator|crates/anvil-core/src/policy/branding.rs|css_control_characters_refused
theme: custom CSS validator|crates/anvil-core/src/policy/branding.rs|accepted_css_never_escapes_its_context
theme: custom CSS validator|$W/security_theme.rs|dangerous_custom_css_is_refused_by_the_api
theme: logos sniffed and size limited|crates/anvil-core/src/policy/branding.rs|logo_sniffing
theme: logos sniffed and size limited|$W/security_theme.rs|logos_are_sniffed_and_size_limited
theme: cross-tenant theme, logo and preview|$W/security_theme.rs|tenants_cannot_read_each_others_theme_logo_or_preview
theme: cross-tenant theme, logo and preview|$W/security_theme.rs|expired_or_unknown_preview_tokens_are_not_found
theme: cross-tenant theme, logo and preview|crates/anvil-storage/src/contract/branding.rs|branding_isolated_by_tenant
theme: frame-ancestors only for the preview page|$W/security_theme.rs|only_the_preview_page_may_be_framed_by_self
cookies: names unique per tenant|crates/anvil-web/src/cookies.rs|tenants_created_in_the_same_millisecond_get_distinct_cookie_names
body limit: 413 per route family, 400 KiB only for logos|$W/security_body_limit.rs|protocol_and_page_routes_answer_413_above_64_kib
body limit: 413 per route family, 400 KiB only for logos|$W/security_body_limit.rs|admin_json_routes_answer_413_above_64_kib
body limit: 413 per route family, 400 KiB only for logos|$W/security_body_limit.rs|logo_uploads_accept_up_to_400_kib_and_no_more
dcr: disabled policy is 404|$W/security_registration.rs|dcr_disabled_returns_404
dcr: system tenant always disabled|$W/security_registration.rs|dcr_system_tenant_always_disabled
dcr: system tenant always disabled|$W/security_admin_v04.rs|system_tenant_registration_policies_forced_disabled
dcr: system tenant always disabled|$W/security_admin_config.rs|system_document_keeps_registration_disabled_and_the_console_client_out
dcr: allow-listed policy requires an initial access token|$W/security_registration.rs|dcr_allow_listed_requires_initial_access_token
dcr: allow-listed policy requires an initial access token|crates/anvil-core/src/service/registration.rs|dcr_allow_listed_requires_initial_access_token
dcr: initial access token single use|$W/security_registration.rs|dcr_initial_access_token_single_use
dcr: initial access token single use|$W/security_registration.rs|dcr_rejected_metadata_keeps_the_single_use_token
dcr: initial access token single use|crates/anvil-core/src/service/registration.rs|dcr_initial_access_token_single_use
dcr: initial access token single use under concurrency|crates/anvil-storage/src/contract/registration.rs|iat_single_use_concurrent_single_winner
dcr: initial access token expiry and revocation|$W/security_registration.rs|dcr_expired_initial_access_token_refused
dcr: initial access token expiry and revocation|$W/security_registration.rs|dcr_revoked_initial_access_token_refused
dcr: initial access token expiry and revocation|crates/anvil-core/src/service/registration.rs|dcr_expired_initial_access_token_refused
dcr: initial access token expiry and revocation|crates/anvil-core/src/service/registration.rs|dcr_revoked_initial_access_token_refused
dcr: initial access token expiry and revocation|crates/anvil-storage/src/contract/registration.rs|iat_expired_or_revoked_not_consumed
dcr: initial access token hashed at rest, shown once|$W/security_registration.rs|dcr_initial_access_token_hashed_at_rest
dcr: initial access token hashed at rest, shown once|$W/security_admin_v04.rs|initial_access_token_shown_once
dcr: initial and registration access tokens hashed at rest (SQLite)|crates/anvil-storage-sqlite/tests/plaintext.rs|secrets_never_stored_plaintext
dcr: initial and registration access tokens hashed at rest (Postgres)|crates/anvil-storage-postgres/tests/plaintext.rs|secrets_never_stored_plaintext
dcr: registration access token required (RFC 7592)|$W/security_registration.rs|dcr_registration_access_token_required
dcr: registration access token required (RFC 7592)|$W/security_registration.rs|dcr_wrong_registration_access_token_401
dcr: registration access token required (RFC 7592)|crates/anvil-core/src/service/registration.rs|dcr_registration_access_token_required
dcr: registration access token required (RFC 7592)|crates/anvil-core/src/service/registration.rs|dcr_wrong_registration_access_token_refused
dcr: static clients not manageable through RFC 7592|$W/security_registration.rs|dcr_static_client_not_manageable
dcr: update constraints|$W/security_registration.rs|dcr_update_constraints_rejected
dcr: redirect host allow-list|$W/security_registration.rs|dcr_redirect_host_allow_list_enforced
dcr: redirect host allow-list|crates/anvil-core/src/oauth/registration.rs|dcr_redirect_host_allow_list_enforced
dcr: redirect URI rules|crates/anvil-core/src/oauth/registration.rs|dcr_redirect_uri_rules_rejected
dcr: redirect URI rules|crates/anvil-core/src/oauth/registration.rs|dcr_web_client_loopback_http_rejected
dcr: redirect URI rules|crates/anvil-core/src/oauth/registration.rs|dcr_native_client_redirect_rules_rejected
dcr: software_statement rejected|$W/security_registration.rs|dcr_software_statement_rejected
dcr: software_statement rejected|crates/anvil-core/src/oauth/registration.rs|dcr_software_statement_rejected
dcr: admin scope never registrable|$W/security_registration.rs|dcr_admin_scope_never_registrable
dcr: admin scope never registrable|crates/anvil-core/src/oauth/registration.rs|dcr_admin_scope_never_registrable
dcr: scopes and resources only from the tenant policy|crates/anvil-core/src/oauth/registration.rs|dcr_scope_outside_allowed_scopes_rejected
dcr: scopes and resources only from the tenant policy|crates/anvil-core/src/oauth/registration.rs|dcr_resource_outside_allowed_resources_rejected
dcr: metadata and request shape|$W/security_registration.rs|dcr_metadata_and_request_shape_rejected
dcr: metadata and request shape|crates/anvil-core/src/oauth/registration.rs|dcr_public_client_credentials_rejected
dcr: metadata and request shape|crates/anvil-core/src/oauth/registration.rs|dcr_client_credentials_without_allow_rejected
dcr: jwks_uri rejected, private_key_jwt needs inline jwks|crates/anvil-core/src/oauth/registration.rs|dcr_jwks_uri_rejected
dcr: jwks_uri rejected, private_key_jwt needs inline jwks|crates/anvil-core/src/oauth/registration.rs|dcr_private_key_jwt_requires_inline_jwks
dcr: max clients|$W/security_registration.rs|dcr_max_clients_enforced
dcr: max clients|crates/anvil-core/src/service/registration.rs|dcr_max_clients_enforced
dcr: rate limited|$W/security_registration.rs|dcr_rate_limited
cimd: policy checked before any fetch|$W/security_cimd.rs|cimd_policy_checked_before_fetch
cimd: policy checked before any fetch|crates/anvil-core/src/oauth/cimd.rs|cimd_url_checked_before_document
cimd: host allow-list checked before any fetch|$W/security_cimd.rs|cimd_allow_list_checked_before_fetch
cimd: private destinations blocked|$W/security_cimd.rs|cimd_private_destination_blocked
cimd: redirects not followed|$W/security_cimd.rs|cimd_redirect_not_followed
cimd: document size capped at 5 KiB|$W/security_cimd.rs|cimd_document_over_5k_rejected
cimd: document size capped at 5 KiB|crates/anvil-core/src/oauth/cimd.rs|cimd_document_over_5k_rejected
cimd: client_id must match the document URL|$W/security_cimd.rs|cimd_client_id_mismatch_rejected
cimd: client_id must match the document URL|crates/anvil-core/src/oauth/cimd.rs|cimd_client_id_mismatch_rejected
cimd: shared-secret methods rejected|$W/security_cimd.rs|cimd_shared_secret_method_rejected
cimd: shared-secret methods rejected|crates/anvil-core/src/oauth/cimd.rs|cimd_shared_secret_method_rejected
cimd: shared-secret methods rejected|crates/anvil-core/src/oauth/cimd.rs|cimd_client_secret_rejected
cimd: jwks_uri rejected, private_key_jwt needs inline jwks|$W/security_cimd.rs|cimd_jwks_uri_document_rejected
cimd: jwks_uri rejected, private_key_jwt needs inline jwks|crates/anvil-core/src/oauth/cimd.rs|cimd_jwks_uri_rejected
cimd: jwks_uri rejected, private_key_jwt needs inline jwks|crates/anvil-core/src/oauth/cimd.rs|cimd_private_key_jwt_requires_inline_jwks
cimd: http client_id rejected in production (loopback too)|$W/security_cimd.rs|cimd_http_client_id_rejected_in_production
cimd: http client_id rejected in production (loopback too)|crates/anvil-core/src/oauth/cimd.rs|cimd_http_rejected_in_production_including_loopback
cimd: admin scope never granted|crates/anvil-core/src/oauth/cimd.rs|cimd_admin_scope_rejected
cimd: fetch errors are not cached|$W/security_cimd.rs|cimd_fetch_error_not_cached
cimd: refused documents not stored|$W/cimd.rs|resolver_refused_documents_are_invalid_client_and_not_stored
cimd: disabled policy never fetches|$W/cimd.rs|resolver_disabled_policy_never_fetches_and_hides_cimd_rows
cimd: failure never redirects to the client|$W/security_cimd.rs|cimd_failure_never_redirects
cimd: fetch rate limited|$W/security_cimd.rs|cimd_fetch_rate_limited
cimd: consent names the host, unverified name, no remote logo|$W/consent.rs|a_cimd_client_is_named_by_its_host_with_an_unverified_name_and_no_remote_logo
mcp: CIMD client token only for its resource|$W/resource_indicators.rs|a_cimd_client_gets_a_token_for_the_mcp_server_and_no_other_resource
consent: a new resource asks again|$W/consent.rs|remembered_consent_covers_resources_and_a_new_resource_asks_again
consent: a new resource asks again|$W/consent.rs|a_grant_without_resources_asks_once_for_a_resource
consent: a new resource asks again|crates/anvil-core/src/flow/consent.rs|a_new_resource_requires_consent
consent: deny does not add the resource|$W/consent.rs|deny_does_not_add_the_resource
consent: revocation clears resources|$W/consent.rs|revoking_consent_revokes_families_and_clears_resources
webhook: signature verifies, tampering fails|$W/security_webhooks.rs|webhook_signature_verifies_and_tampered_body_fails
webhook: signature verifies, tampering fails|crates/anvil-jose/src/webhook.rs|signature_matches_spec_test_vector
webhook: signature verifies, tampering fails|crates/anvil-jose/src/webhook.rs|signature_changes_with_every_input
webhook: signature verifies, tampering fails|crates/anvil-jose/src/webhook.rs|parse_rejects_bad_secrets
webhook: both secrets sign during rotation only|$W/webhooks.rs|worker_signs_with_both_secrets_during_rotation_window
webhook: SSRF refused at create|$W/security_webhooks.rs|webhook_url_private_ip_refused_at_create
webhook: SSRF refused at create|$W/webhooks.rs|service_refuses_loopback_and_plain_http_in_production
webhook: SSRF refused at send|$W/security_webhooks.rs|webhook_send_blocked_for_private_destination
webhook: redirects not followed|$W/security_webhooks.rs|webhook_redirect_not_followed
webhook: redirects not followed|$W/webhooks.rs|worker_redirect_is_a_failure_and_retried
webhook: secret write-only|$W/security_webhooks.rs|webhook_secret_never_returned_after_create
webhook: secret write-only|$W/security_admin_v04.rs|webhook_secret_write_only_in_api
webhook: secret sealed at rest (SQLite)|crates/anvil-storage-sqlite/tests/plaintext.rs|secrets_never_stored_plaintext
webhook: secret sealed at rest (Postgres)|crates/anvil-storage-postgres/tests/plaintext.rs|secrets_never_stored_plaintext
webhook: payloads carry no personal data|$W/security_webhooks.rs|webhook_payload_has_no_pii
webhook: payloads carry no personal data|crates/anvil-core/src/policy/webhook_event.rs|payloads_never_carry_personal_data
webhook: failed actions emit nothing|crates/anvil-core/src/policy/webhook_event.rs|failures_never_emit
webhook: each delivery claimed once under concurrency|crates/anvil-storage/src/contract/webhooks.rs|webhook_claim_concurrent_each_row_once
webhook: each delivery claimed once under concurrency|crates/anvilid/tests/webhook_worker.rs|two_workers_deliver_each_row_exactly_once
webhook: lease outlives the request timeout|crates/anvilid/tests/webhook_worker.rs|lease_holds_in_flight_rows_past_the_request_timeout
webhook: shutdown waits for an in-flight request|crates/anvilid/src/main.rs|jobs_shutdown_timeout_covers_a_webhook_request
webhook: tenant isolation|crates/anvil-storage/src/contract/webhooks.rs|webhooks_isolated_by_tenant
attributes: remote schema references refused without network|$W/security_attributes.rs|attribute_schema_remote_ref_refused
attributes: remote schema references refused without network|crates/anvil-web/src/adapters/attribute_schema.rs|remote_ref_is_refused_without_network
attributes: schema size and depth capped|$W/security_attributes.rs|attribute_schema_size_capped
attributes: schema size and depth capped|crates/anvil-web/src/adapters/attribute_schema.rs|oversized_schema_is_refused
attributes: schema size and depth capped|crates/anvil-web/src/adapters/attribute_schema.rs|deeply_nested_schema_is_refused
attributes: patterns run in linear time|$W/security_attributes.rs|attribute_pattern_is_linear_time
attributes: patterns run in linear time|crates/anvil-web/src/adapters/attribute_schema.rs|redos_pattern_runs_in_linear_time
attributes: patterns run in linear time|crates/anvil-web/src/adapters/attribute_schema.rs|backtracking_only_patterns_are_refused
attributes: values validated on every write|$W/security_attributes.rs|attribute_values_validated_on_write
attributes: values validated on every write|$W/account_attributes.rs|invalid_values_are_refused_with_field_errors
attributes: validation errors never echo values|crates/anvil-web/src/adapters/attribute_schema.rs|errors_never_echo_instance_values
attributes: cross-tenant refused|$W/security_attributes.rs|attribute_other_tenant_user_refused
attributes: cross-tenant refused|$W/admin_attributes.rs|attributes_of_another_tenant_are_404
attributes: cross-tenant refused|crates/anvil-storage/src/contract/attributes.rs|attributes_isolated_by_tenant
attributes: non-editable attributes refused on the account page|$W/account_attributes.rs|non_editable_attributes_are_refused
claims: mapping never overrides reserved claims|$W/security_rbac.rs|claim_mapping_collision_rejected
claims: mapping never overrides reserved claims|crates/anvil-core/src/policy/claims_mapping.rs|validate_mapping_rejects_reserved_claims
claims: mapping never overrides reserved claims|crates/anvil-core/src/policy/claims_mapping.rs|mapping_never_overrides_reserved_or_earlier_claims_at_runtime
claims: mapping never overrides reserved claims|crates/anvil-core/src/policy/claims_mapping.rs|output_never_contains_protocol_claims
claims: mapping never overrides reserved claims|crates/anvil-core/src/service/claims.rs|access_token_extras_never_override_or_add_reserved_claims
claims: mapping never overrides reserved claims|crates/anvil-core/src/service/claims.rs|id_token_extras_never_set_reserved_protocol_claims
rbac: tenant isolation|$W/security_rbac.rs|assigning_another_tenants_role_is_refused
rbac: tenant isolation|$W/security_rbac.rs|assigning_to_another_tenants_user_is_refused
rbac: tenant isolation|crates/anvil-storage/src/contract/roles.rs|role_assign_refuses_foreign_tenant
rbac: tenant isolation|crates/anvil-storage/src/contract/roles.rs|roles_isolated_by_tenant
rbac: admin scopes bounded by role permissions|$W/security_rbac.rs|admin_scope_requires_role_permission
rbac: admin scopes bounded by role permissions|$W/security_rbac.rs|user_without_roles_gets_no_admin_scope
rbac: admin scopes bounded by role permissions|crates/anvil-core/src/service/role.rs|bound_admin_scope_intersects_with_roles
rbac: non-system tenant roles never grant admin scopes|$W/security_rbac.rs|non_system_tenant_role_never_grants_admin_scopes
rbac: non-system tenant roles never grant admin scopes|crates/anvil-core/src/service/role.rs|non_system_roles_never_grant_admin_scopes
rbac: no escalation beyond the caller's scopes|$W/security_rbac.rs|role_assignment_beyond_caller_scopes_is_refused
rbac: no escalation beyond the caller's scopes|crates/anvil-core/src/service/role.rs|escalation_is_refused_beyond_the_callers_scopes
rbac: last administrator kept (unassign, role delete, user delete, disable)|$W/security_rbac.rs|last_administrator_cannot_be_unassigned
rbac: last administrator kept (unassign, role delete, user delete, disable)|$W/security_rbac.rs|last_administrator_role_cannot_be_deleted
rbac: last administrator kept (unassign, role delete, user delete, disable)|$W/security_rbac.rs|last_administrator_cannot_be_deleted
rbac: last administrator kept (unassign, role delete, user delete, disable)|$W/security_rbac.rs|last_administrator_cannot_be_disabled
rbac: role routes require their scopes|$W/security_rbac.rs|role_routes_require_scopes
static clients: admin scopes refused outside the system tenant|$W/security_admin_v04.rs|static_client_admin_scope_refused_outside_system_tenant
static clients: admin scopes refused outside the system tenant|$W/security_admin.rs|system_clients_need_full_admin
static clients: admin scopes refused outside the system tenant|$W/security_admin_config.rs|config_apply_refuses_admin_scope_on_non_system_client
static clients: system tenant keeps admin scopes, legacy rows stay editable|$W/security_admin_v04.rs|system_tenant_static_client_may_hold_admin_scopes
static clients: system tenant keeps admin scopes, legacy rows stay editable|$W/security_admin_v04.rs|legacy_admin_scope_client_stays_editable
limiter: shared backend has the in-process semantics (contract)|crates/anvil-cache/src/limiter/contract.rs|gcra_burst_is_exact_then_denied_for_one_interval
limiter: shared backend has the in-process semantics (contract)|crates/anvil-cache/src/limiter/contract.rs|gcra_denial_does_not_consume_quota
limiter: shared backend has the in-process semantics (contract)|crates/anvil-cache/src/limiter/contract.rs|gcra_keys_are_isolated
limiter: shared backend has the in-process semantics (contract)|crates/anvil-cache/src/limiter/contract.rs|backoff_free_attempts_then_doubling_lock_capped
limiter: shared backend has the in-process semantics (contract)|crates/anvil-cache/src/limiter/contract.rs|backoff_keys_are_isolated_by_tier_and_tenant
limiter: shared backend has the in-process semantics (contract)|crates/anvil-cache/src/limiter/contract.rs|gate_denies_while_the_strict_key_is_locked
limiter: shared backend has the in-process semantics (contract)|crates/anvil-cache/src/limiter/contract.rs|gate_strict_lock_takes_precedence_over_captcha
limiter: Redis outage fails closed for auth and the gate|crates/anvil-cache/tests/limiter_contract.rs|redis_outage_auth_and_gate_fail_closed_breaker_skips_then_recovers
limiter: Redis outage fails closed for auth and the gate|crates/anvilid/tests/limiter_redis.rs|redis_outage_login_fails_closed_or_local_token_keeps_issuing_then_recovers
limiter: Redis outage local mode is explicit|crates/anvil-cache/tests/limiter_contract.rs|redis_outage_local_mode_uses_the_in_process_limiter
limiter: unreachable Redis fails startup|crates/anvil-cache/tests/limiter_contract.rs|redis_connect_fails_fast_when_unreachable
limiter: unreachable Redis fails startup|crates/anvilid/tests/config_phase5.rs|redis_url_unreachable_fails_startup_explicitly
limiter: nodes share one budget|crates/anvil-cache/tests/limiter_contract.rs|redis_instances_share_one_budget
limiter: nodes share one budget|crates/anvilid/tests/limiter_redis.rs|redis_two_nodes_share_one_client_token_budget
limiter: Redis keys are hashed (no IPs or identifiers in clear)|crates/anvil-cache/tests/limiter_contract.rs|redis_key_names_are_hashed
limiter: Redis keys are hashed (no IPs or identifiers in clear)|crates/anvilid/src/limiter.rs|key_hasher_is_hmac_under_the_derived_ratelimit_key
secret hygiene: Redis and OTLP URL credentials redacted|crates/anvilid/tests/config_phase5.rs|credentials_in_redis_and_otel_urls_are_redacted
config: apply never reads server environment or files|$W/security_admin_config.rs|config_apply_never_reads_server_env_or_files
config: export contains no secrets or hashes|$W/security_admin_config.rs|config_export_contains_no_secrets_or_hashes
config: plans never print inline secrets|crates/anvil-core/src/service/config.rs|inline_secret_uses_the_supplied_equality_and_never_prints_it
config: invalid document changes nothing|$W/security_admin_config.rs|config_apply_invalid_document_changes_nothing
config: invalid document changes nothing|crates/anvilid/tests/tenant_config.rs|invalid_documents_are_reported_by_path
config: apply requires admin write|$W/security_admin_config.rs|config_apply_requires_admin_write
config: apply cannot lock out system admins|$W/security_admin_config.rs|config_apply_cannot_lock_out_system_admins
config: system tenant rules|crates/anvil-core/src/service/config.rs|system_tenant_rules
config: CLI deletions need --prune, non-terminal apply needs --yes|crates/anvilid/tests/tenant_config.rs|deletions_need_prune
config: CLI deletions need --prune, non-terminal apply needs --yes|crates/anvilid/tests/tenant_config.rs|apply_without_yes_on_a_non_terminal_refuses
backup: restore refuses while the server runs (serve.lock)|crates/anvilid/tests/backup.rs|backup_restore_refuses_while_the_server_runs
backup: restore refuses corrupt and foreign files|crates/anvilid/tests/backup.rs|backup_restore_refuses_corrupt_and_foreign_files
backup: restore refuses corrupt and foreign files|crates/anvil-storage-sqlite/src/backup.rs|inspect_rejects_truncated_and_foreign_files
backup: restore refuses a backup from a newer binary|crates/anvil-storage-sqlite/src/backup.rs|restore_inspection_refuses_a_backup_from_a_newer_binary
backup: restore refuses a wrong KEK and overwrites only with --yes|crates/anvilid/tests/backup.rs|backup_restore_refuses_a_wrong_kek_and_an_existing_database_without_yes
backup: never creates a missing source|crates/anvil-storage-sqlite/src/backup.rs|backup_never_creates_a_missing_source
admin recover: local only, no HTTP route|crates/anvilid/tests/admin_recover.rs|admin_recovery_has_no_http_route
admin recover: unknown, other-tenant and blocked accounts refused|crates/anvilid/tests/admin_recover.rs|admin_recover_refuses_unknown_and_other_tenant_emails
admin recover: unknown, other-tenant and blocked accounts refused|crates/anvilid/tests/admin_recover.rs|admin_recover_refuses_blocked_accounts
admin recover: recovery URL expires|crates/anvilid/tests/admin_recover.rs|admin_recover_token_expires_after_one_hour
admin recover: fresh admin only after a lockout|crates/anvilid/tests/admin_recover.rs|admin_recover_creates_fresh_admin_when_locked_out
admin recover: fresh admin only after a lockout|crates/anvilid/tests/admin_recover.rs|admin_recover_without_email_refused_when_admin_exists
healthcheck: non-loopback hosts refused without connecting|crates/anvilid/tests/healthcheck.rs|healthcheck_refuses_other_hosts_without_connecting
healthcheck: non-loopback hosts refused without connecting|crates/anvilid/src/healthcheck.rs|other_hosts_schemes_and_credentials_are_refused
healthcheck: not ready or draining fails|crates/anvilid/tests/healthcheck.rs|healthcheck_fails_when_not_ready_or_unreachable
healthcheck: not ready or draining fails|crates/anvilid/tests/healthcheck.rs|healthcheck_fails_while_the_server_drains
passkey enrolment: challenge single use|$W/flow_mfa_policy.rs|a_replayed_passkey_enrolment_challenge_is_refused
passkey enrolment: challenge single use|$W/flow_mfa_policy.rs|a_successful_passkey_enrolment_cannot_be_replayed
passkey enrolment: challenge single use|crates/anvil-core/src/flow/login.rs|passkey_enrolment_challenge_is_taken_out_once
passkey enrolment: challenge bound to its flow and step|$W/flow_mfa_policy.rs|a_passkey_enrolment_challenge_from_another_flow_is_refused
passkey enrolment: challenge bound to its flow and step|$W/flow_mfa_policy.rs|a_passkey_finish_without_a_pending_challenge_is_refused
passkey enrolment: challenge bound to its flow and step|$W/flow_mfa_policy.rs|an_abandoned_passkey_enrolment_challenge_is_refused
passkey enrolment: challenge bound to its flow and step|$W/flow_mfa_policy.rs|passkey_enrolment_routes_are_bound_to_the_flow_and_its_enrolment_step
passkey second factor: passkey-only user gets the passkey step|$W/flow_mfa_policy.rs|passkey_only_user_gets_the_passkey_second_factor_not_enrolment
passkey second factor: bound to the step user|$W/flow_mfa_policy.rs|second_factor_passkey_of_another_user_is_refused
passkey second factor: bound to the step user|$W/flow_mfa_policy.rs|second_factor_passkey_unknown_credential_is_refused
passkey second factor: challenge single use|$W/flow_mfa_policy.rs|second_factor_passkey_challenge_cannot_be_replayed
passkey second factor: challenge single use|crates/anvil-core/src/flow/login.rs|second_factor_passkey_challenge_is_taken_out_once_and_only_in_its_step
passkey second factor: challenge bound to the flow and step|$W/flow_mfa_policy.rs|second_factor_passkey_cross_flow_challenge_is_refused
passkey second factor: challenge bound to the flow and step|$W/flow_mfa_policy.rs|identify_step_passkey_challenge_is_not_accepted_at_second_factor
passkey second factor: challenge bound to the flow and step|$W/flow_mfa_policy.rs|second_factor_passkey_finish_without_challenge_is_refused
passkey second factor: challenge bound to the flow and step|$W/flow_mfa_policy.rs|second_factor_passkey_options_refused_outside_the_second_factor_step
passkey second factor: a code is not a passkey|crates/anvil-core/src/flow/login.rs|a_totp_code_at_a_passkey_only_step_is_invalid_input
body limit: config routes 1 MiB and no more|$W/security_body_limit.rs|config_routes_accept_up_to_1_mib_and_no_more
admin v0.4: new routes require their scopes|$W/security_admin_v04.rs|v04_admin_routes_require_scopes
admin v0.4: new routes isolate tenants|$W/security_admin_v04.rs|v04_admin_routes_isolate_tenants
telemetry: no personal data, secrets or client IPs in logs, spans or metrics|crates/anvilid/tests/telemetry_redaction.rs|telemetry_carries_no_personal_data_secrets_or_client_ips
EOF
)

violation() {
  echo "SECURITY TEST MISSING: $*"
}

# owner <file> -> "<crate>|<binary key>" where the key is `tests/<t>.rs` or `src`.
owner() {
  local f=$1 crate rest
  if [[ $f == crates/anvil-storage/src/contract/* ]]; then
    echo "anvil-storage-sqlite|tests/contract.rs"
    return
  fi
  if [[ $f == crates/anvil-cache/src/limiter/contract.rs ]]; then
    echo "anvil-cache|tests/limiter_contract.rs"
    return
  fi
  crate=${f#crates/}
  crate=${crate%%/*}
  rest=${f#crates/"$crate"/}
  if [[ $rest == tests/*.rs && $rest != tests/*/* ]]; then
    echo "$crate|$rest"
  else
    echo "$crate|src"
  fi
}

# check_source <root> <map>: every mapped function is defined in its file.
check_source() {
  local root=$1 map=$2 fail=0 control file fn
  while IFS='|' read -r control file fn; do
    [[ -z $file ]] && continue
    if [[ ! -f $root/$file ]]; then
      violation "$control: $file does not exist (expected fn $fn)"
      fail=1
    elif ! grep -Eq "^[[:space:]]*(pub(\([a-z]+\))? )?(async )?fn ${fn}[[:space:]]*[(<]" "$root/$file"; then
      violation "$control: no fn $fn in $file"
      fail=1
    fi
  done <<<"$map"
  return $fail
}

# list_tests: `<crate>|<binary key>|<test path>` for every registered test in the workspace.
# The crate comes from the binary path (target/.../build/<crate>/... on current cargo) or, on the
# older target/debug/deps layout, from the last `unittests` binary (cargo lists a crate's lib/main
# unit tests before its integration tests).
list_tests() {
  (cd "$ROOT" && cargo test --workspace --locked --color never -- --list 2>&1) | awk '
    /^[[:space:]]+Running / {
      key = $2
      bin = $NF; gsub(/[()]/, "", bin)
      crate = ""
      if (match(bin, /\/build\/[^\/]+\/[0-9a-f]+\/out\/[^\/]+$/)) {
        crate = substr(bin, RSTART + 7)
        sub(/\/.*/, "", crate)
      } else if ($2 == "unittests") {
        key = "src"; n = split(bin, parts, "/"); crate = parts[n]
        sub(/-[0-9a-f]+$/, "", crate); gsub(/_/, "-", crate)
      } else {
        crate = last
      }
      if ($2 == "unittests") { key = "src"; last = crate }
      next
    }
    /^[[:space:]]+Doc-tests / { crate = ""; next }
    /: test$/ && crate != "" { sub(/: test$/, ""); print crate "|" key "|" $0 }
  '
}

# check_registered <map> <listing>: every mapped function is a registered test of its owner.
check_registered() {
  local map=$1 listing=$2 fail=0 control file fn own
  while IFS='|' read -r control file fn; do
    [[ -z $file ]] && continue
    own=$(owner "$file")
    if ! grep -Eq "^${own//|/\\|}\\|(.*::)?${fn}\$" <<<"$listing"; then
      violation "$control: $file::$fn is not a registered test of ${own%%|*} (${own#*|})"
      fail=1
    fi
  done <<<"$map"
  return $fail
}

run_check() {
  local fail=0 listing count
  check_source "$ROOT" "$MAP" || fail=1
  if ! listing=$(list_tests); then
    echo "SECURITY TEST MISSING: cargo test --list failed" >&2
    exit 1
  fi
  if [[ -z $listing ]]; then
    violation "cargo test --list returned no tests"
    exit 1
  fi
  check_registered "$MAP" "$listing" || fail=1
  count=$(grep -c '|' <<<"$MAP")
  if [[ $fail -ne 0 ]]; then
    echo "check-security-tests: FAILED"
    exit 1
  fi
  echo "check-security-tests: OK ($count control/test pairs, all present and registered)"
}

self_test() {
  local out first_file first_fn listing helper_map
  SELF_TEST_TMP=$(mktemp -d)
  local tmp=$SELF_TEST_TMP
  trap 'rm -rf "$SELF_TEST_TMP"' EXIT

  # Copy every mapped file into a scratch tree.
  while IFS='|' read -r _ file _; do
    [[ -z $file ]] && continue
    mkdir -p "$tmp/$(dirname "$file")"
    cp "$ROOT/$file" "$tmp/$file"
  done <<<"$MAP"

  # 1. Unmodified copy passes the source check.
  if ! out=$(check_source "$tmp" "$MAP"); then
    echo "self-test FAILED: unmodified map rejected:"
    echo "$out"
    exit 1
  fi

  # 2. Renaming one mapped test function must be detected.
  IFS='|' read -r _ first_file first_fn <<<"$(head -n1 <<<"$MAP")"
  sed -i -E "s/fn ${first_fn}\(/fn ${first_fn}_renamed(/" "$tmp/$first_file"
  if out=$(check_source "$tmp" "$MAP"); then
    echo "self-test FAILED: renamed fn $first_fn in $first_file was not detected"
    exit 1
  fi
  if ! grep -q "SECURITY TEST MISSING: .*no fn $first_fn in $first_file" <<<"$out"; then
    echo "self-test FAILED: unexpected output for the renamed fn:"
    echo "$out"
    exit 1
  fi

  # 3. A function that exists but is not a test (a helper) must fail the registration check.
  listing=$(list_tests)
  helper_map="helper is not a test|$W/security_code.rs|exchange_with"
  if ! check_source "$ROOT" "$helper_map" >/dev/null; then
    echo "self-test FAILED: helper exchange_with not found in security_code.rs (update the self-test)"
    exit 1
  fi
  if out=$(check_registered "$helper_map" "$listing"); then
    echo "self-test FAILED: helper fn exchange_with accepted as a registered test"
    exit 1
  fi

  # 4. The real map is fully registered.
  if ! out=$(check_registered "$MAP" "$listing"); then
    echo "self-test FAILED: unmodified map not registered:"
    echo "$out"
    exit 1
  fi

  echo "check-security-tests self-test: OK (renamed fn and non-test helper rejected, real map accepted)"
}

case "${1:-}" in
  --self-test) self_test ;;
  "") run_check ;;
  *)
    echo "usage: $0 [--self-test]" >&2
    exit 2
    ;;
esac
