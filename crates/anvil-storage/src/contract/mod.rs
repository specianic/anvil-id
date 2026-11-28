//! Storage contract suite (feature `contract`).
//!
//! Every backend instantiates [`storage_contract_tests!`](crate::storage_contract_tests) with a
//! factory returning a fresh [`TestStorage`]. The list of contract tests lives in one place (the
//! macro), so a backend cannot silently skip one. The tests are split per aggregate (one module
//! per port) and re-exported here.
//!
//! All timestamps are truncated to whole milliseconds: the storage contract is millisecond
//! precision (see `anvil_core::model::truncate_to_ms`).
//!
//! # Secrets at rest
//!
//! "Secrets are never stored in plaintext" cannot be tested generically: behind the port only
//! hashes ever reach storage, and the suite cannot inspect rows. Each backend therefore has its own
//! row-inspection test (`secrets_never_stored_plaintext`) that reads the raw columns holding
//! hashes, PHC strings and sealed keys and checks that only the values passed in are stored.

use std::any::Any;
use std::sync::Arc;

use anvil_core::ports::Storage;

mod access_tokens;
mod attributes;
mod audit;
mod branding;
mod clients;
mod connections;
mod consent;
mod credentials;
pub mod fixtures;
mod flows;
mod grants;
mod jobs;
mod keys;
mod logout;
mod mail_settings;
mod org_domains;
mod org_invitations;
mod orgs;
mod outbox;
mod par;
mod password_profiles;
mod registration;
mod roles;
mod sessions;
mod setup;
mod tenants;
mod users;
mod webhooks;

pub use access_tokens::*;
pub use attributes::*;
pub use audit::*;
pub use branding::*;
pub use clients::*;
pub use connections::*;
pub use consent::*;
pub use credentials::*;
pub use fixtures::*;
pub use flows::*;
pub use grants::*;
pub use jobs::*;
pub use keys::*;
pub use logout::*;
pub use mail_settings::*;
pub use org_domains::*;
pub use org_invitations::*;
pub use orgs::*;
pub use outbox::*;
pub use par::*;
pub use password_profiles::*;
pub use registration::*;
pub use roles::*;
pub use sessions::*;
pub use setup::*;
pub use tenants::*;
pub use users::*;
pub use webhooks::*;

/// A storage backend under test.
pub struct TestStorage {
    pub storage: Arc<dyn Storage>,
    /// Keeps backend resources (temp dir, test database handle, ...) alive for the test.
    pub _guard: Box<dyn Any + Send + Sync>,
}

/// Expands one `#[tokio::test]` per contract test, each calling `$factory().await` for a fresh
/// [`TestStorage`](crate::contract::TestStorage).
///
/// The callers need `tokio` (with `macros` and `rt-multi-thread`) as a dev-dependency.
#[macro_export]
macro_rules! storage_contract_tests {
    ($factory:path) => {
        $crate::storage_contract_tests!(@each $factory;
            // tenants
            tenant_create_and_get,
            tenant_slug_conflict,
            tenant_get_by_host,
            tenant_host_conflict,
            tenant_list_pagination,
            tenant_update_settings_round_trip,
            tenant_delete_cascades,
            // users
            user_create_round_trip_all_fields,
            user_email_conflict_persists_nothing,
            user_username_conflict,
            user_get_by_email,
            user_list_pagination,
            user_update_and_conflict,
            user_password_set_and_get,
            user_record_login,
            user_delete_cascades_sessions_and_revokes_families,
            user_isolated_by_tenant,
            // self-service tokens
            verification_completes_once,
            verification_rejects_changed_email,
            verification_expired_none,
            recovery_sets_password_verifies_email_revokes_sessions_and_families_and_enqueues_notice,
            recovery_token_single_use_concurrent,
            // clients
            client_create_get_round_trip,
            client_id_conflict,
            client_update,
            client_set_secret_hash,
            client_delete_revokes_families,
            client_list_pagination,
            // keys
            key_insert_and_active,
            key_second_active_conflict,
            key_published_excludes_expired,
            // sessions
            session_get_active_by_hash,
            session_expired_or_idle_not_returned,
            session_touch_extends_idle,
            session_revoke,
            // flows
            flow_create_get_update_delete,
            flow_expired_not_returned,
            flow_isolated_by_tenant,
            // grants: authorization requests
            auth_request_round_trip_with_claims_request,
            auth_request_expired_none,
            // grants: codes and families
            create_code_creates_family,
            consume_code_once,
            consume_code_expired,
            consume_code_unknown,
            consume_code_wrong_tenant,
            create_code_duplicate_conflict,
            consume_code_concurrent_single_winner,
            code_reuse_reports_family_id,
            revoke_family_idempotent_keeps_first_reason,
            // grants: refresh tokens
            refresh_create_find,
            rotate_refresh_success_inserts_child,
            rotate_refresh_reuse_revokes_family,
            rotate_refresh_expired_not_found,
            rotate_refresh_absolute_expiry,
            rotate_refresh_concurrent,
            // grants: replay guards
            record_jti_once_then_replayed,
            record_jti_expired_can_be_reused,
            record_jti_concurrent_single_winner,
            // setup
            install_creates_tenants_keys_token_once,
            peek_setup_token,
            complete_setup_once,
            complete_setup_expired_invalid,
            // outbox
            outbox_enqueue_claim_mark_sent,
            outbox_claim_lease_skips_claimed,
            outbox_mark_failed_reschedules,
            outbox_expired_not_claimed,
            // purge
            purge_expired_removes_only_expired_rows,
            purge_expired_removes_expired_token_families,
            // ---- Phase 3 (plan 03-02); backends implement them in 03-05 / 03-06 ----
            // clients and sessions: new columns
            client_phase3_fields_round_trip,
            session_request_context_round_trip,
            // users: recovery notice addressed by storage
            recovery_notice_not_enqueued_for_invalid_token,
            // credentials
            passkey_create_list_find,
            passkey_duplicate_credential_id_conflicts,
            passkey_update_counter_compare_and_swap,
            passkey_concurrent_updates_never_move_counter_backwards,
            totp_create_get_and_conflict,
            totp_step_accepted_once,
            totp_step_concurrent_single_winner,
            recovery_code_consumed_once,
            recovery_code_concurrent_single_winner,
            recovery_code_notice_enqueued_only_on_success,
            delete_totp_removes_recovery_codes,
            delete_credential_only_own_and_never_password,
            list_credentials_summarises_every_kind,
            credentials_isolated_by_tenant,
            // consent
            consent_upsert_unions_scopes,
            consent_revoked_is_ignored_and_reactivated,
            consent_revoke_revokes_only_that_clients_families,
            consent_isolated_by_tenant,
            // access tokens and families without a code
            access_token_create_find_with_and_without_family,
            access_token_found_in_any_state,
            access_token_revoke,
            create_family_without_code,
            // keys
            key_list_returns_every_state,
            key_promote_retires_then_activates,
            key_promote_stale_ids_change_nothing,
            key_delete_expired_removes_only_expired_retired,
            // sessions
            session_get_in_any_state,
            session_list_for_user_active_newest_first,
            session_list_tenant_wide_paging,
            session_revoke_with_families_only_its_own,
            session_revoke_all_for_user_keeps_except,
            // flows
            flow_swap_state_compare_and_swap,
            flow_swap_state_concurrent_single_winner,
            // audit
            audit_append_and_query_newest_first,
            audit_query_filters,
            audit_cursor_pages_without_gaps,
            audit_isolated_by_tenant,
            audit_purge_before_deletes_only_older,
            // mail settings
            mail_template_put_get_list_delete,
            mail_smtp_put_get_delete,
            mail_settings_isolated_by_tenant,
            // job leases
            job_lease_exclusive_renew_and_release,
            job_expired_lease_taken_over,
            job_lease_concurrent_single_holder,
            // ---- Phase 4 (plan 04-01): client fields, step-up, email change, connections,
            // branding and back-channel logout ----
            // clients, grants, access tokens: new fields
            client_phase4_fields_round_trip,
            // Phase 5 (plan 05-01): persisted faithfully or refused, never dropped
            client_phase5_fields_never_dropped,
            code_and_family_resource_round_trip,
            access_token_resource_round_trip,
            // flows
            flow_logout_kind_round_trip,
            // sessions: step-up
            session_upgrade_auth,
            // users: email change
            email_change_completes_and_notifies_old_address,
            email_change_rejects_invalid_tokens,
            email_change_conflict_keeps_token,
            email_change_concurrent_single_winner,
            // connections and identity links
            connection_create_get_list_update,
            connection_slug_conflict_per_tenant,
            connection_set_secret_round_trip,
            connection_delete_cascades_links,
            identity_link_create_find_and_conflict,
            identity_link_delete_only_own,
            delete_link_keeps_a_sign_in_method,
            delete_link_concurrent_never_removes_the_last_method,
            create_user_with_link_is_atomic,
            create_user_with_link_stores_verification_atomically,
            connections_isolated_by_tenant,
            // branding
            branding_put_get_scopes,
            branding_logo_keep_clear_set,
            branding_draft_replace_and_preview,
            branding_delete,
            branding_isolated_by_tenant,
            purge_expired_removes_unreferenced_logos,
            client_delete_removes_its_branding,
            // back-channel logout: RP sessions, enqueue on every revoking intent, delivery queue
            create_code_records_rp_session_once,
            rp_session_records_issuer_and_deliveries_copy_it,
            revoke_enqueues_backchannel_delivery,
            revoke_with_families_enqueues_backchannel_delivery,
            revoke_all_for_user_enqueues_backchannel_delivery,
            complete_recovery_enqueues_backchannel_delivery,
            user_delete_enqueues_backchannel_delivery,
            revoke_noop_enqueues_nothing,
            delivery_claim_leases_due_rows,
            delivery_claim_concurrent_each_row_once,
            delivery_complete_semantics,
            // ---- Phase 5 (plan 05-02): roles, custom attributes, webhooks, dynamic client
            // registration, consent resources and the setup administrator ----
            // roles
            role_create_get_update_delete,
            role_list_in_name_order,
            role_name_conflict_per_tenant,
            role_assign_idempotent_and_unassign,
            role_assign_refuses_foreign_tenant,
            role_delete_cascades_assignments,
            role_users_with_role_paginates,
            role_holders_of_permission_counts_active_users,
            roles_isolated_by_tenant,
            // custom attributes
            attribute_upsert_list_get_delete,
            attribute_user_values_round_trip,
            attribute_delete_keeps_user_values,
            attributes_isolated_by_tenant,
            // webhooks: endpoints, enqueue in append, leased delivery queue
            webhook_endpoint_crud_and_name_conflict,
            webhook_rotate_secret_keeps_previous_with_expiry,
            webhook_disable_and_reenable_endpoint,
            webhook_append_enqueues_subscribed_endpoints,
            webhook_claim_leases_due_rows,
            webhook_claim_concurrent_each_row_once,
            webhook_complete_semantics,
            webhook_deliveries_listing_newest_first,
            webhook_redeliver_and_enqueue_test,
            webhook_delete_endpoint_cascades_deliveries,
            webhooks_isolated_by_tenant,
            audit_append_without_webhook_enqueues_nothing,
            // dynamic client registration and CIMD clients
            iat_create_list_revoke,
            iat_consume_decrements_and_stops_at_zero,
            iat_expired_or_revoked_not_consumed,
            iat_single_use_concurrent_single_winner,
            count_clients_by_source,
            client_upsert_cimd_inserts_then_replaces,
            client_upsert_cimd_never_overwrites_registered_clients,
            client_registration_token_lookup_and_rotation,
            // consent resources
            consent_resources_round_trip_and_merge,
            // setup: the system administrator role
            install_creates_system_administrator_role,
            complete_setup_assigns_administrator_role,
            // ---- Phase 6 (plan 06-04): organizations, invitations, domains, org roles, org SSO
            // and org-bound grants ----
            // organizations and members
            org_create_get_update_delete,
            org_slug_conflict_per_tenant,
            org_list_pagination,
            orgs_isolated_by_tenant,
            org_add_member_idempotent_with_roles,
            org_add_member_refuses_unknown_or_foreign,
            org_remove_member_revokes_only_that_orgs_families,
            org_delete_cascades_and_revokes_families,
            org_memberships_of_user,
            org_list_members_paginates,
            // invitations
            invitation_create_list_revoke,
            invitation_by_hash_and_unique_hash,
            invitation_accept_adds_membership_and_roles,
            invitation_accept_wrong_email_writes_nothing,
            invitation_accept_concurrent_single_winner,
            invitation_closed_tokens_are_invalid,
            invitation_existing_member_keeps_token,
            invitation_accept_with_new_user_is_atomic,
            invitations_isolated_by_tenant,
            // domains
            domain_create_list_get_delete,
            domain_create_refuses_foreign_routing_connection,
            domain_mark_verified_one_org_per_domain,
            domain_mark_verified_concurrent_single_winner,
            domain_update_routing_connection_same_org_only,
            domain_routed_domain_requires_verified_routing_enabled_connection,
            domain_record_check_failure_streak,
            domain_unverify_stops_routing,
            domain_due_for_recheck_across_tenants,
            domain_verified_domains_of_org,
            domains_isolated_by_tenant,
            // org roles
            role_org_owned_name_unique_per_org,
            role_list_excludes_org_roles,
            role_assign_in_org_requires_membership,
            role_org_owned_role_only_in_its_org,
            role_tenant_role_in_org_scoped_to_that_org,
            role_holders_of_permission_ignores_org_assignments,
            role_org_holders_of_permission_counts_in_org_members,
            // org connections, SAML configs, links, JIT membership
            connection_org_and_saml_round_trip,
            connection_has_links,
            create_user_with_link_with_membership,
            // org-bound grants, SAML replay, mail, branding, client policy
            code_and_family_org_round_trip,
            record_jti_saml_assertion_id_replay,
            mail_template_org_invitation_round_trip,
            branding_org_scope_independent,
            client_organization_policy_round_trip,
            // ---- Phase 7 (plan 07-08): PAR, password hash profiles, password compare-and-swap,
            // the new client fields and the export reads ----
            // clients
            client_new_fields_round_trip,
            // pushed authorization requests
            par_create_and_consume_round_trip,
            par_create_duplicate_hash_conflict,
            par_consume_twice_is_none,
            par_consume_expired_is_none,
            par_consume_single_winner_under_concurrency,
            par_tenant_isolation,
            par_purged_after_expiry,
            par_deleted_with_client,
            // password hash profiles
            password_profile_create_get_list_delete,
            password_profile_name_unique_per_tenant,
            password_profile_tenant_isolation,
            password_profile_count_references,
            // users: password compare-and-swap, export reads
            password_replace_if_swaps_only_matching,
            password_replace_if_wrong_expected_is_noop,
            password_replace_if_concurrent_single_winner,
            pending_self_service_tokens_existence_only,
            // grants: export read
            families_for_user_every_state_oldest_first,
            // ---- Phase 7.1 (plan 07.1-04): client home URLs, read-only self-service token peek ----
            client_home_urls_round_trip,
            peek_self_service_token_reports_usable_tokens_only,
            peek_self_service_token_never_consumes,
        );
    };
    (@each $factory:path; $($name:ident),+ $(,)?) => {
        $(
            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            async fn $name() {
                let s = $factory().await;
                $crate::contract::$name(&s).await;
            }
        )+
    };
}
