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

mod clients;
pub mod fixtures;
mod flows;
mod grants;
mod keys;
mod outbox;
mod sessions;
mod setup;
mod tenants;
mod users;

pub use clients::*;
pub use fixtures::*;
pub use flows::*;
pub use grants::*;
pub use keys::*;
pub use outbox::*;
pub use sessions::*;
pub use setup::*;
pub use tenants::*;
pub use users::*;

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
