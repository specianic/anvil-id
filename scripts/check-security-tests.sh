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
#   crates/<c>/src/**                    -> unit tests of crate <c>
#
# Release 0.2 adds the Phase 3 controls: passkeys, TOTP and recovery codes, introspection and
# revocation, consent, session revocation, rate limiting and brute-force protection, CAPTCHA,
# trusted proxies, form_post, the destructive-migration guard, Postgres composite tenant keys and
# the new admin routes.
#
# Controls deliberately not mapped here:
#   - SSRF guard: the server fetches no client-supplied URL (jwks_uri and request_uri are not
#     fetched). The CAPTCHA verifier only calls operator-configured https endpoints (mapped above).
#   - "Test code" (SEC-06): enforced by scripts/check-release-graph.sh, not by a unit test.
#   - Released-migration immutability: enforced by scripts/check-migrations.sh (and its
#     --self-test), which `just ci` runs as migrations-check.
#   - Browser-level behaviour (passkey ceremony, consent, sessions, a11y): Playwright specs under
#     tests/e2e/specs, run by the e2e workflow.
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
    elif ! grep -Eq "^[[:space:]]*(pub(\([a-z]+\))? )?(async )?fn ${fn}[[:space:]]*\(" "$root/$file"; then
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
