//! Ports: storage repositories (implemented by the `anvil-storage-*` crates) and non-storage
//! services (clock, password hashing, breach checking). Protocol logic and handlers use them
//! only through these traits.
//!
//! # Design: intent methods, not generic transactions
//!
//! There is no `begin() -> Box<dyn Tx>`. Every multi-row change that must be atomic is one
//! repository method (`GrantRepo::create_code`, `UserRepo::create`, `UserRepo::complete_recovery`,
//! `SetupRepo::complete_setup`, `SetupRepo::install`, ...). This keeps the traits dyn-compatible,
//! makes a forgotten commit impossible, and lets the contract suite test each atomic unit.
//!
//! # Conventions
//!
//! - Every method that touches tenant data takes a [`TenantId`] and only ever sees rows of that
//!   tenant; a row of another tenant behaves exactly like a missing row. The exceptions are
//!   tenant resolution (`TenantRepo::get_by_slug` / `get_by_host` / `list`), [`SetupRepo`]
//!   (installation-wide) and the outbox worker methods (`claim_due`, `mark_sent`, `mark_failed`).
//! - Uniqueness is enforced by unique indexes and reported as [`StorageError::Conflict`]; never
//!   check-then-insert.
//! - Timestamps are passed in by callers (millisecond precision, see
//!   [`crate::model::truncate_to_ms`]); "expired" means `expires_at <= now`.
//! - Secrets are only ever stored and looked up by [`SecretHash`].

use std::time::Duration;

use time::OffsetDateTime;

pub use crate::clock::{Clock, SystemClock};
use crate::error::CoreError;
use crate::model::{
    AuthRequestId, AuthorizationCode, AuthorizationRequest, BrowserSession, Client, ClientUpdate,
    CodeHash, Flow, FlowId, InstallPlan, NewAuthorizationCode, NewAuthorizationRequest,
    NewBrowserSession, NewClient, NewEmail, NewFlow, NewPasswordCredential, NewRefreshToken,
    NewSelfServiceToken, NewSetupToken, NewSigningKey, NewTenant, NewTokenFamily, NewUser,
    OutboxEmail, OutboxId, Page, PageRequest, PasswordCredential, RefreshToken, ReplayKind,
    RevokeReason, SecretHash, SessionId, SigningKey, Tenant, TenantId, TenantUpdate, TokenFamily,
    TokenFamilyId, User, UserId, UserUpdate,
};

/// Entry point to all repositories of one storage backend.
#[async_trait::async_trait]
pub trait Storage: Send + Sync + 'static {
    fn tenants(&self) -> &dyn TenantRepo;
    fn users(&self) -> &dyn UserRepo;
    fn clients(&self) -> &dyn ClientRepo;
    fn keys(&self) -> &dyn KeyRepo;
    fn sessions(&self) -> &dyn SessionRepo;
    fn flows(&self) -> &dyn FlowRepo;
    fn grants(&self) -> &dyn GrantRepo;
    fn setup(&self) -> &dyn SetupRepo;
    fn outbox(&self) -> &dyn OutboxRepo;

    /// Batch-deletes expired rows across all tenants: authorization codes, authorization
    /// requests, flows, browser sessions, refresh tokens, replay guards, self-service tokens and
    /// setup tokens with `expires_at <= now`, plus sent or expired outbox emails. Never deletes a
    /// row that is still usable at `now`. Consumed codes and refresh tokens are kept until they
    /// expire, so code and refresh-token reuse detection keeps working. Returns the number of
    /// rows deleted.
    async fn purge_expired(&self, now: OffsetDateTime) -> Result<u64, StorageError>;
}

/// Tenant persistence.
#[async_trait::async_trait]
pub trait TenantRepo: Send + Sync {
    /// Persists a tenant. `Conflict` on a duplicate slug or host (unique indexes).
    async fn create(&self, tenant: &NewTenant) -> Result<Tenant, StorageError>;

    async fn get(&self, id: TenantId) -> Result<Option<Tenant>, StorageError>;

    /// Tenant resolution by slug (path-based tenants).
    async fn get_by_slug(&self, slug: &str) -> Result<Option<Tenant>, StorageError>;

    /// Tenant resolution by custom host (host-based tenants).
    async fn get_by_host(&self, host: &str) -> Result<Option<Tenant>, StorageError>;

    /// Installation-wide list in id order (keyset pagination).
    async fn list(&self, page: PageRequest) -> Result<Page<Tenant>, StorageError>;

    /// Applies a partial update. `None` if the tenant does not exist; `Conflict` on a duplicate
    /// host.
    async fn update(
        &self,
        id: TenantId,
        update: &TenantUpdate,
    ) -> Result<Option<Tenant>, StorageError>;

    /// Deletes the tenant and, by cascade, every row that belongs to it. `false` if it did not
    /// exist.
    async fn delete(&self, id: TenantId) -> Result<bool, StorageError>;
}

/// User, credential and self-service token persistence.
#[async_trait::async_trait]
pub trait UserRepo: Send + Sync {
    /// Creates a user with an optional password, self-service token (e.g. verification) and
    /// email, in **one transaction**. `Conflict` on a duplicate (tenant, email) or (tenant,
    /// username); on conflict nothing at all is persisted.
    async fn create(
        &self,
        tenant: TenantId,
        user: &NewUser,
        password: Option<&NewPasswordCredential>,
        token: Option<&NewSelfServiceToken>,
        email: Option<&NewEmail>,
    ) -> Result<User, StorageError>;

    async fn get(&self, tenant: TenantId, id: UserId) -> Result<Option<User>, StorageError>;

    /// Lookup by normalised email (callers normalise; storage compares exactly).
    async fn get_by_email(
        &self,
        tenant: TenantId,
        email: &str,
    ) -> Result<Option<User>, StorageError>;

    /// Users of one tenant in id order (keyset pagination).
    async fn list(&self, tenant: TenantId, page: PageRequest) -> Result<Page<User>, StorageError>;

    /// Applies a partial update and sets `updated_at = now`. `None` if the user does not exist;
    /// `Conflict` on a duplicate email or username (nothing changed).
    async fn update(
        &self,
        tenant: TenantId,
        id: UserId,
        update: &UserUpdate,
        now: OffsetDateTime,
    ) -> Result<Option<User>, StorageError>;

    /// Deletes the user with its credentials, sessions and self-service tokens, and revokes
    /// every token family of the user (reason `UserDeleted`), in one transaction. `false` if the
    /// user did not exist.
    async fn delete(&self, tenant: TenantId, id: UserId) -> Result<bool, StorageError>;

    /// The user's password credential, if any.
    async fn password(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Option<PasswordCredential>, StorageError>;

    /// Upserts the password (PHC string): inserts with `created_at = updated_at = now` or
    /// replaces `phc` and sets `updated_at = now`. `false` if the user does not exist.
    async fn set_password(
        &self,
        tenant: TenantId,
        user: UserId,
        phc: &str,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError>;

    /// Sets `last_login_at = now`. A missing user is not an error.
    async fn record_login(
        &self,
        tenant: TenantId,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<(), StorageError>;

    /// Stores a self-service token and optionally enqueues its email, in one transaction.
    /// `Conflict` on a duplicate token hash.
    async fn issue_self_service_token(
        &self,
        tenant: TenantId,
        token: &NewSelfServiceToken,
        email: Option<&NewEmail>,
    ) -> Result<(), StorageError>;

    /// Atomically consumes a `Verification` token (single `UPDATE ... WHERE consumed_at IS NULL
    /// AND expires_at > now`) and sets `email_verified = true` only if the user's current email
    /// equals the token's email. `None` if the token is unknown, of another kind, consumed,
    /// expired, or the email changed since it was issued. Exactly one concurrent caller can get
    /// `Some`.
    async fn complete_verification(
        &self,
        tenant: TenantId,
        token_hash: &SecretHash,
        now: OffsetDateTime,
    ) -> Result<Option<User>, StorageError>;

    /// In one transaction: atomically consumes a `Recovery` or `Invitation` token, upserts the
    /// password to `new_phc`, sets `email_verified = true`, revokes every browser session and
    /// every token family of the user (reason `UserRecovery`), and enqueues `notice` if given.
    /// `None` (and nothing changed) if the token is unknown, of another kind, consumed or
    /// expired. Exactly one concurrent caller can get `Some`.
    async fn complete_recovery(
        &self,
        tenant: TenantId,
        token_hash: &SecretHash,
        new_phc: &str,
        now: OffsetDateTime,
        notice: Option<&NewEmail>,
    ) -> Result<Option<User>, StorageError>;
}

/// Client persistence.
#[async_trait::async_trait]
pub trait ClientRepo: Send + Sync {
    /// `Conflict` on a duplicate (tenant, client_id).
    async fn create(&self, tenant: TenantId, client: &NewClient) -> Result<Client, StorageError>;

    /// Lookup by OAuth `client_id`.
    async fn get(&self, tenant: TenantId, client_id: &str) -> Result<Option<Client>, StorageError>;

    /// Clients of one tenant in row-id order (keyset pagination).
    async fn list(&self, tenant: TenantId, page: PageRequest)
    -> Result<Page<Client>, StorageError>;

    /// Applies a partial update and sets `updated_at = now`. `None` if the client does not exist.
    async fn update(
        &self,
        tenant: TenantId,
        client_id: &str,
        update: &ClientUpdate,
        now: OffsetDateTime,
    ) -> Result<Option<Client>, StorageError>;

    /// Replaces (or clears) the secret digest and sets `updated_at = now`. `false` if the client
    /// does not exist.
    async fn set_secret_hash(
        &self,
        tenant: TenantId,
        client_id: &str,
        secret_hash: Option<SecretHash>,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError>;

    /// Deletes the client and revokes all its token families (reason `ClientDeleted`) in one
    /// transaction. `false` if it did not exist.
    async fn delete(&self, tenant: TenantId, client_id: &str) -> Result<bool, StorageError>;
}

/// Signing key persistence.
#[async_trait::async_trait]
pub trait KeyRepo: Send + Sync {
    /// Stores a key. `Conflict` on a duplicate kid, or if the key is `Active` and another
    /// `Active` key exists for the same (tenant, alg) (partial unique index).
    async fn insert(&self, tenant: TenantId, key: &NewSigningKey) -> Result<(), StorageError>;

    /// The single `Active` key for `alg`, if any.
    async fn active(&self, tenant: TenantId, alg: &str)
    -> Result<Option<SigningKey>, StorageError>;

    /// Keys to publish in the JWKS: any state, with `expires_at` null or `> now`, in id order.
    async fn published(
        &self,
        tenant: TenantId,
        now: OffsetDateTime,
    ) -> Result<Vec<SigningKey>, StorageError>;
}

/// Browser session persistence.
#[async_trait::async_trait]
pub trait SessionRepo: Send + Sync {
    /// `Conflict` on a duplicate id or token hash.
    async fn create(
        &self,
        tenant: TenantId,
        session: &NewBrowserSession,
    ) -> Result<(), StorageError>;

    /// The session for a cookie hash if it is not revoked, `expires_at > now` and
    /// `idle_expires_at > now`.
    async fn get_active(
        &self,
        tenant: TenantId,
        token_hash: &SecretHash,
        now: OffsetDateTime,
    ) -> Result<Option<BrowserSession>, StorageError>;

    /// Sets `last_seen_at = now` and `idle_expires_at` on a session that is still active.
    /// `false` otherwise.
    async fn touch(
        &self,
        tenant: TenantId,
        id: SessionId,
        now: OffsetDateTime,
        idle_expires_at: OffsetDateTime,
    ) -> Result<bool, StorageError>;

    /// Sets `revoked_at = now` if not yet revoked. `false` if unknown or already revoked.
    async fn revoke(
        &self,
        tenant: TenantId,
        id: SessionId,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError>;
}

/// Self-service flow persistence.
#[async_trait::async_trait]
pub trait FlowRepo: Send + Sync {
    async fn create(&self, tenant: TenantId, flow: &NewFlow) -> Result<(), StorageError>;

    /// The flow if `expires_at > now`.
    async fn get(
        &self,
        tenant: TenantId,
        id: FlowId,
        now: OffsetDateTime,
    ) -> Result<Option<Flow>, StorageError>;

    /// Replaces the opaque state of an unexpired flow. `false` if missing or expired.
    async fn update_state(
        &self,
        tenant: TenantId,
        id: FlowId,
        state: &str,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError>;

    async fn delete(&self, tenant: TenantId, id: FlowId) -> Result<bool, StorageError>;
}

/// Authorization requests, codes, token families, refresh tokens and replay guards.
#[async_trait::async_trait]
pub trait GrantRepo: Send + Sync {
    async fn create_authorization_request(
        &self,
        tenant: TenantId,
        request: &NewAuthorizationRequest,
    ) -> Result<(), StorageError>;

    /// The request if `expires_at > now`.
    async fn get_authorization_request(
        &self,
        tenant: TenantId,
        id: AuthRequestId,
        now: OffsetDateTime,
    ) -> Result<Option<AuthorizationRequest>, StorageError>;

    async fn delete_authorization_request(
        &self,
        tenant: TenantId,
        id: AuthRequestId,
    ) -> Result<bool, StorageError>;

    /// Stores the token family and the code in **one transaction**. The family exists from the
    /// moment the code does, so a code replay racing the exchange still revokes it. Callers set
    /// `code.token_family_id == family.id`; a mismatch is rejected with `Conflict` and nothing is
    /// stored. `Conflict` on a duplicate code hash or family id.
    async fn create_code(
        &self,
        tenant: TenantId,
        code: &NewAuthorizationCode,
        family: &NewTokenFamily,
    ) -> Result<(), StorageError>;

    /// Atomically consumes a code: a single
    /// `UPDATE ... WHERE consumed_at IS NULL AND expires_at > now RETURNING ...`.
    /// Exactly one concurrent caller can receive [`ConsumeOutcome::Consumed`].
    async fn consume_code(
        &self,
        tenant: TenantId,
        code_hash: &CodeHash,
        now: OffsetDateTime,
    ) -> Result<ConsumeOutcome, StorageError>;

    async fn get_family(
        &self,
        tenant: TenantId,
        id: TokenFamilyId,
    ) -> Result<Option<TokenFamily>, StorageError>;

    /// Sets `revoked_at = now` and `revoked_reason` if not yet revoked. Idempotent: a second call
    /// keeps the first time and reason. Returns `true` if the family exists (revoked by this call
    /// or before), `false` if unknown.
    async fn revoke_family(
        &self,
        tenant: TenantId,
        id: TokenFamilyId,
        reason: RevokeReason,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError>;

    /// Stores a refresh token. `Conflict` on a duplicate hash.
    async fn create_refresh_token(
        &self,
        tenant: TenantId,
        token: &NewRefreshToken,
    ) -> Result<(), StorageError>;

    /// Read-only lookup in any state (consumed, expired, revoked family); used by revocation and
    /// introspection.
    async fn find_refresh_token(
        &self,
        tenant: TenantId,
        token_hash: &SecretHash,
    ) -> Result<Option<(RefreshToken, TokenFamily)>, StorageError>;

    /// Refresh rotation in **one transaction**:
    /// - presented token unconsumed, `expires_at > now`, family not revoked and
    ///   `absolute_expires_at > now` → mark it consumed, insert `child`, return
    ///   [`RotateOutcome::Rotated`] with the family;
    /// - presented token exists but was already consumed → revoke the family (reason
    ///   `RefreshReuse`) and return [`RotateOutcome::ReuseDetected`];
    /// - otherwise (unknown, expired, revoked or expired family, other tenant) →
    ///   [`RotateOutcome::NotFound`].
    ///
    /// Exactly one concurrent caller presenting the same token can get `Rotated`.
    async fn rotate_refresh(
        &self,
        tenant: TenantId,
        presented: &SecretHash,
        child: &NewRefreshToken,
        now: OffsetDateTime,
    ) -> Result<RotateOutcome, StorageError>;

    /// Insert-or-fail replay guard: records `hash` for `kind` until `expires_at`. Returns
    /// `Replayed` if an unexpired entry exists; an expired entry may be replaced. Exactly one
    /// concurrent caller can get `Recorded`.
    async fn record_jti(
        &self,
        tenant: TenantId,
        kind: ReplayKind,
        hash: &SecretHash,
        expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<JtiOutcome, StorageError>;
}

/// First-start installation and setup (installation-wide; no tenant parameter).
#[async_trait::async_trait]
pub trait SetupRepo: Send + Sync {
    /// Whether the system tenant exists.
    async fn is_installed(&self) -> Result<bool, StorageError>;

    /// Writes the tenants, keys and setup token of the plan in **one transaction**, unless the
    /// installation already exists (then nothing is written). Concurrent installers: exactly one
    /// gets `Installed`.
    async fn install(&self, plan: &InstallPlan) -> Result<InstallOutcome, StorageError>;

    /// Stores an additional setup token (e.g. a regenerated one). `Conflict` on duplicate hash.
    async fn create_setup_token(&self, token: &NewSetupToken) -> Result<(), StorageError>;

    /// Whether an unconsumed setup token with `expires_at > now` exists for `hash`. Read-only.
    async fn peek_setup_token(
        &self,
        hash: &SecretHash,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError>;

    /// In **one transaction**: atomically consumes the setup token, creates the first
    /// administrator (with password) in `admin_tenant` and the admin client in `client_tenant`.
    /// `InvalidToken` (nothing written) if the token is unknown, consumed or expired. Exactly one
    /// concurrent caller can get `Completed`. A user/client conflict rolls back everything,
    /// including the token consumption, and returns `Conflict`.
    #[expect(
        clippy::too_many_arguments,
        reason = "one atomic intent method; see module docs"
    )]
    async fn complete_setup(
        &self,
        hash: &SecretHash,
        now: OffsetDateTime,
        admin_tenant: TenantId,
        admin: &NewUser,
        password: &NewPasswordCredential,
        client_tenant: TenantId,
        client: &NewClient,
    ) -> Result<SetupOutcome, StorageError>;
}

/// Transactional email outbox.
#[async_trait::async_trait]
pub trait OutboxRepo: Send + Sync {
    /// Enqueues an email (`attempts = 0`, `next_attempt_at = created_at`).
    async fn enqueue(&self, tenant: TenantId, email: &NewEmail) -> Result<(), StorageError>;

    /// Claims up to `limit` due emails (unsent, `next_attempt_at <= now`, `expires_at > now`)
    /// across tenants, oldest first. Claiming sets `next_attempt_at = now + lease` and increments
    /// `attempts`, so a concurrent claimer skips them; a claimed email is never returned twice
    /// within its lease.
    async fn claim_due(
        &self,
        now: OffsetDateTime,
        limit: u32,
        lease: Duration,
    ) -> Result<Vec<OutboxEmail>, StorageError>;

    /// Sets `sent_at = now`. `false` if unknown.
    async fn mark_sent(&self, id: OutboxId, now: OffsetDateTime) -> Result<bool, StorageError>;

    /// Records the error and reschedules at `next_attempt_at`. `false` if unknown.
    async fn mark_failed(
        &self,
        id: OutboxId,
        error: &str,
        next_attempt_at: OffsetDateTime,
    ) -> Result<bool, StorageError>;
}

/// Result of [`GrantRepo::consume_code`].
#[expect(
    clippy::large_enum_variant,
    reason = "returned by value once per token request; boxing would only add an allocation"
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsumeOutcome {
    /// This call consumed the code.
    Consumed(AuthorizationCode),
    /// The code had already been consumed (replay). Carries the token family so callers can
    /// revoke tokens issued from it.
    AlreadyConsumed { family_id: Option<TokenFamilyId> },
    /// Unknown, expired, or belongs to another tenant. Callers map all of these to `invalid_grant`.
    NotFound,
}

/// Result of [`GrantRepo::rotate_refresh`].
#[expect(
    clippy::large_enum_variant,
    reason = "returned by value once per refresh; boxing would only add an allocation"
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotateOutcome {
    /// The presented token was consumed and the child stored.
    Rotated(TokenFamily),
    /// The presented token had already been consumed; the family is now revoked.
    ReuseDetected { family_id: TokenFamilyId },
    /// Unknown, expired, revoked/expired family, or another tenant.
    NotFound,
}

/// Result of [`GrantRepo::record_jti`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JtiOutcome {
    Recorded,
    Replayed,
}

/// Result of [`SetupRepo::install`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallOutcome {
    Installed,
    AlreadyInstalled,
}

/// Result of [`SetupRepo::complete_setup`].
#[expect(
    clippy::large_enum_variant,
    reason = "returned once per installation; boxing would only add an allocation"
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupOutcome {
    Completed { user: User, client: Client },
    InvalidToken,
}

/// Errors returned by storage backends.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// A uniqueness constraint was violated.
    #[error("conflict: {0}")]
    Conflict(String),
    /// Stored data could not be decoded into the domain model.
    #[error("corrupt stored data: {0}")]
    Corrupt(String),
    /// Any other backend failure (connection, I/O, driver error).
    #[error("storage backend error: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The backend does not implement this operation (yet). Never a success.
    #[error("unsupported storage operation: {0}")]
    Unsupported(&'static str),
}

/// Result of a password verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordCheck {
    pub valid: bool,
    /// The stored hash uses outdated parameters; callers re-hash and store on success.
    pub needs_rehash: bool,
}

/// Password hashing (Argon2id, run off the async executor with bounded concurrency).
#[async_trait::async_trait]
pub trait PasswordHasher: Send + Sync {
    /// Hashes a password into a PHC string. `Overloaded` when the hashing queue is full.
    async fn hash(&self, password: &str) -> Result<String, CoreError>;

    /// Verifies `password` against `phc`. With `phc = None` (unknown user, no password) it
    /// verifies against a dummy hash so timing does not reveal account existence, and returns
    /// `valid = false`.
    async fn verify(&self, phc: Option<&str>, password: &str) -> Result<PasswordCheck, CoreError>;
}

/// Checks a password against a breached-password corpus.
#[async_trait::async_trait]
pub trait BreachChecker: Send + Sync {
    async fn is_breached(&self, password: &str) -> Result<bool, CoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ports are used as trait objects (`&dyn TenantRepo`, `Arc<dyn Storage>`), so they must
    /// stay dyn-compatible. This fails to compile if a change breaks that.
    #[test]
    fn ports_are_dyn_compatible_and_thread_safe() {
        fn assert_send_sync<T: ?Sized + Send + Sync>() {}
        assert_send_sync::<dyn Storage>();
        assert_send_sync::<dyn TenantRepo>();
        assert_send_sync::<dyn UserRepo>();
        assert_send_sync::<dyn ClientRepo>();
        assert_send_sync::<dyn KeyRepo>();
        assert_send_sync::<dyn SessionRepo>();
        assert_send_sync::<dyn FlowRepo>();
        assert_send_sync::<dyn GrantRepo>();
        assert_send_sync::<dyn SetupRepo>();
        assert_send_sync::<dyn OutboxRepo>();
        assert_send_sync::<dyn Clock>();
        assert_send_sync::<dyn PasswordHasher>();
        assert_send_sync::<dyn BreachChecker>();
        assert_send_sync::<StorageError>();
    }

    #[test]
    fn storage_error_keeps_backend_source() {
        let err = StorageError::Backend("connection reset".into());
        assert_eq!(err.to_string(), "storage backend error: connection reset");
        assert!(std::error::Error::source(&err).is_some());
    }
}
