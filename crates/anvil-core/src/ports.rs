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
//!   tenant resolution (`TenantRepo::get_by_slug` / `get_by_host` / `list`), [`SetupRepo`] and
//!   [`JobRepo`] (installation-wide), the outbox worker methods (`claim_due`, `mark_sent`,
//!   `mark_failed`), the logout delivery worker methods ([`LogoutRepo::claim_due_deliveries`],
//!   [`LogoutRepo::complete_delivery`]) and audit retention ([`AuditRepo::purge_before`]).
//! - Uniqueness is enforced by unique indexes and reported as [`StorageError::Conflict`]; never
//!   check-then-insert.
//! - Timestamps are passed in by callers (millisecond precision, see
//!   [`crate::model::truncate_to_ms`]); "expired" means `expires_at <= now`.
//! - Secrets are only ever stored and looked up by [`SecretHash`] (or stored KEK-sealed, like
//!   connection secrets).
//!
//! # Back-channel logout enqueueing
//!
//! Every intent that revokes browser sessions ([`SessionRepo::revoke`],
//! [`SessionRepo::revoke_with_families`], [`SessionRepo::revoke_all_for_user`],
//! [`UserRepo::complete_recovery`], [`UserRepo::delete`]) inserts, **in the same transaction**,
//! one logout delivery per (session revoked by that call x `rp_session` row of that session whose
//! client has a `backchannel_logout_uri`): `uri` copied from the client, `sub` = the user id,
//! `sid` = the session id, `next_attempt_at = now`, `give_up_at = now + 24h`
//! ([`crate::model::LOGOUT_DELIVERY_TTL`]), `attempts = 0`. A call that revokes nothing enqueues
//! nothing. `rp_session` rows are written by [`GrantRepo::create_code`]. Methods without a `now`
//! parameter (`UserRepo::delete`) use the storage clock.

use std::time::Duration;

use anvil_jose::Jwks;
use secrecy::SecretString;
use time::OffsetDateTime;

pub use crate::clock::{Clock, SystemClock};
use crate::error::CoreError;
use crate::model::{
    AccessTokenRecord, AuditEvent, AuditQuery, AuthRequestId, AuthorizationCode,
    AuthorizationRequest, Branding, BrandingDraft, BrandingUpdate, BrowserSession, Client,
    ClientUpdate, CodeHash, Connection, ConnectionId, ConnectionUpdate, ConsentGrant,
    CounterOutcome, CredentialId, CredentialSummary, DeliveryResult, EmailKind, EmailTemplate,
    Flow, FlowId, IdentityLink, IdentityLinkId, InstallPlan, Logo, LogoutDelivery,
    LogoutDeliveryId, NewAccessToken, NewAuditEvent, NewAuthorizationCode, NewAuthorizationRequest,
    NewBrowserSession, NewClient, NewConnection, NewConsent, NewEmail, NewFlow, NewIdentityLink,
    NewPasskey, NewPasswordCredential, NewRefreshToken, NewSelfServiceToken, NewSetupToken,
    NewSigningKey, NewTenant, NewTokenFamily, NewTotp, NewUser, OutboxEmail, OutboxId, Page,
    PageRequest, PasskeyCredential, PasswordCredential, RecoveryCodeHash, RecoveryNotice,
    RefreshToken, ReplayKind, RevokeReason, RpSession, SecretHash, SessionId, SigningKey,
    SigningKeyId, SmtpSettings, SmtpTls, Tenant, TenantId, TenantUpdate, TokenFamily,
    TokenFamilyId, TotpCredential, User, UserId, UserUpdate,
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
    fn audit(&self) -> &dyn AuditRepo;
    fn mail_settings(&self) -> &dyn MailSettingsRepo;
    fn jobs(&self) -> &dyn JobRepo;
    fn connections(&self) -> &dyn ConnectionRepo;
    fn branding(&self) -> &dyn BrandingRepo;
    fn logout(&self) -> &dyn LogoutRepo;

    /// Batch-deletes expired rows across all tenants: authorization codes, authorization
    /// requests, flows, browser sessions, refresh tokens, opaque access tokens, replay guards,
    /// self-service tokens and setup tokens with `expires_at <= now`, plus sent or expired outbox
    /// emails. Never deletes a
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

    /// Deletes the user with its credentials, sessions, identity links and self-service tokens,
    /// and revokes every token family of the user (reason `UserDeleted`), in one transaction.
    /// Enqueues back-channel logout deliveries for the user's unrevoked sessions in the same
    /// transaction (module docs; storage clock). `false` if the user did not exist.
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
    /// every token family of the user (reason `UserRecovery`), and, if given, enqueues `notice`
    /// addressed to the consumed token's `email` ([`RecoveryNotice::to_email`]). Enqueues
    /// back-channel logout deliveries for every session it revoked (module docs). `None` (and
    /// nothing changed, no email or delivery enqueued) if the token is unknown, of another kind,
    /// consumed or expired. Exactly one concurrent caller can get `Some`.
    async fn complete_recovery(
        &self,
        tenant: TenantId,
        token_hash: &SecretHash,
        new_phc: &str,
        now: OffsetDateTime,
        notice: Option<&RecoveryNotice>,
    ) -> Result<Option<User>, StorageError>;

    /// In one transaction: atomically consumes an `EmailChange` self-service token (single
    /// conditional `UPDATE ... WHERE consumed_at IS NULL AND expires_at > now`), sets the user's
    /// `email = token.email` and `email_verified = true`, and, if given, enqueues `notice`
    /// addressed to the user's email **before** the change ([`RecoveryNotice::to_email`]).
    /// `None` (nothing changed) if the token is unknown, of another kind, consumed or expired.
    /// `Conflict` (nothing changed, the token stays unconsumed) if another user of the tenant
    /// holds the new email. Exactly one concurrent caller can get `Some`.
    async fn complete_email_change(
        &self,
        tenant: TenantId,
        token_hash: &SecretHash,
        now: OffsetDateTime,
        notice: Option<&RecoveryNotice>,
    ) -> Result<Option<User>, StorageError>;

    /// Every credential of the user (password, passkeys, TOTP) as summaries, oldest first.
    async fn list_credentials(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Vec<CredentialSummary>, StorageError>;

    /// Stores a passkey for `user`. `Conflict` if `passkey.credential_id` is already registered
    /// anywhere in the tenant (to this or another user): a WebAuthn credential id must never be
    /// bound to two accounts. Conflict on the row id as well.
    async fn create_passkey(
        &self,
        tenant: TenantId,
        user: UserId,
        passkey: &NewPasskey,
    ) -> Result<(), StorageError>;

    /// The user's passkeys, oldest first.
    async fn passkeys(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Vec<PasskeyCredential>, StorageError>;

    /// Lookup by WebAuthn credential id (discoverable sign-in: the user is not known yet).
    async fn find_passkey(
        &self,
        tenant: TenantId,
        credential_id: &[u8],
    ) -> Result<Option<PasskeyCredential>, StorageError>;

    /// Records a successful assertion with a **single conditional UPDATE**: stores
    /// `passkey_json`, `counter` and `last_used_at = now` iff `counter > stored counter`, or
    /// `counter == 0` and the stored counter is 0 (authenticators without a counter).
    /// Otherwise (counter went backwards or repeated: possible clone; or unknown id) nothing
    /// changes and `Stale` is returned. Concurrent updates never move the counter backwards.
    async fn update_passkey(
        &self,
        tenant: TenantId,
        id: CredentialId,
        passkey_json: &str,
        counter: u32,
        now: OffsetDateTime,
    ) -> Result<CounterOutcome, StorageError>;

    /// The user's TOTP credential, if enrolled.
    async fn totp(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Option<TotpCredential>, StorageError>;

    /// In **one transaction**: inserts the TOTP credential (`Conflict` if the user already has
    /// one; then nothing changes) and replaces the user's recovery-code set with `codes`.
    async fn create_totp(
        &self,
        tenant: TenantId,
        user: UserId,
        totp: &NewTotp,
        codes: &[RecoveryCodeHash],
        now: OffsetDateTime,
    ) -> Result<(), StorageError>;

    /// Accepts TOTP time step `step` with a **single conditional UPDATE**
    /// (`... WHERE last_step IS NULL OR last_step < step`), also setting `last_used_at = now`.
    /// `Stale` if the step (or a later one) was already accepted or the user has no TOTP, so a
    /// code is accepted at most once even under concurrency.
    async fn advance_totp_step(
        &self,
        tenant: TenantId,
        user: UserId,
        step: u64,
        now: OffsetDateTime,
    ) -> Result<CounterOutcome, StorageError>;

    /// Deletes one passkey or TOTP credential of `user`. Deleting the TOTP credential also
    /// deletes the user's recovery codes in the same transaction. Passwords cannot be deleted
    /// through this method. `false` if no such credential of this user exists.
    async fn delete_credential(
        &self,
        tenant: TenantId,
        user: UserId,
        id: CredentialId,
    ) -> Result<bool, StorageError>;

    /// Replaces the user's recovery-code set (old codes stop working) in **one transaction**.
    async fn replace_recovery_codes(
        &self,
        tenant: TenantId,
        user: UserId,
        codes: &[RecoveryCodeHash],
        now: OffsetDateTime,
    ) -> Result<(), StorageError>;

    /// Consumes one recovery code with a **single conditional UPDATE**
    /// (`SET used_at = now WHERE ... AND used_at IS NULL`) and, only if that succeeded, enqueues
    /// `notice` in the same transaction. Exactly one concurrent caller presenting the same code
    /// gets `true`.
    async fn consume_recovery_code(
        &self,
        tenant: TenantId,
        user: UserId,
        hash: &RecoveryCodeHash,
        now: OffsetDateTime,
        notice: Option<&NewEmail>,
    ) -> Result<bool, StorageError>;

    /// Number of unused recovery codes of the user.
    async fn recovery_codes_remaining(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<u32, StorageError>;
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

    /// Every key of the tenant in any state (including expired retired keys), in id order.
    async fn list(&self, tenant: TenantId) -> Result<Vec<SigningKey>, StorageError>;

    /// Key promotion in **one transaction** of two statements, in this order (never one swapping
    /// UPDATE, which the partial unique index on active keys would reject):
    /// 1. if `retire = Some((id, expires_at))`: the `Active` key `id` becomes `Retired` with
    ///    `retired_at = now` and `expires_at`;
    /// 2. the `Next` key `activate` becomes `Active` with `activated_at = now`.
    ///
    /// `false` and nothing changed if `retire` is not an `Active` key or `activate` is not a
    /// `Next` key of the tenant (stale or unknown ids). `Conflict` (nothing changed) if another
    /// key of the same alg is still active after step 1.
    async fn promote(
        &self,
        tenant: TenantId,
        retire: Option<(SigningKeyId, OffsetDateTime)>,
        activate: SigningKeyId,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError>;

    /// Deletes `Retired` keys with `expires_at <= now`. Returns the number deleted.
    async fn delete_expired(
        &self,
        tenant: TenantId,
        now: OffsetDateTime,
    ) -> Result<u64, StorageError>;
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

    /// Sets `revoked_at = now` if not yet revoked and enqueues back-channel logout deliveries for
    /// the session in the same transaction (module docs). `false` (nothing enqueued) if unknown
    /// or already revoked.
    async fn revoke(
        &self,
        tenant: TenantId,
        id: SessionId,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError>;

    /// The session by id in any state (revoked or expired included); callers check the state.
    async fn get(
        &self,
        tenant: TenantId,
        id: SessionId,
    ) -> Result<Option<BrowserSession>, StorageError>;

    /// The user's active sessions (not revoked, both expiries `> now`), newest first.
    async fn list_for_user(
        &self,
        tenant: TenantId,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<Vec<BrowserSession>, StorageError>;

    /// Active sessions of the whole tenant (admin view), keyset-paginated in id order.
    async fn list(
        &self,
        tenant: TenantId,
        now: OffsetDateTime,
        page: PageRequest,
    ) -> Result<Page<BrowserSession>, StorageError>;

    /// In **one transaction**: revokes the session (as [`SessionRepo::revoke`]) and every token
    /// family with `session_id = id` (reason `SessionRevoked`; already revoked families keep
    /// their first reason), and enqueues back-channel logout deliveries for the session (module
    /// docs). `false` (nothing changed) if the session is unknown or already revoked.
    async fn revoke_with_families(
        &self,
        tenant: TenantId,
        id: SessionId,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError>;

    /// In **one transaction**: revokes every unrevoked session of `user` except `except`, and the
    /// token families of those sessions (reason `SessionRevoked`), and enqueues back-channel
    /// logout deliveries for each session it revoked (module docs). Returns the number of
    /// sessions revoked.
    async fn revoke_all_for_user(
        &self,
        tenant: TenantId,
        user: UserId,
        except: Option<SessionId>,
        now: OffsetDateTime,
    ) -> Result<u64, StorageError>;

    /// Step-up: sets `acr`, `amr` and `auth_time` of an **active** session (not revoked, both
    /// expiries `> now`) in a single UPDATE. `false` if the session is unknown, revoked or
    /// expired.
    async fn upgrade_auth(
        &self,
        tenant: TenantId,
        id: SessionId,
        acr: &str,
        amr: &[String],
        auth_time: OffsetDateTime,
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

    /// Compare-and-swap of the opaque state: a single `UPDATE ... SET state = new WHERE state =
    /// expected AND expires_at > now`. `false` if the flow is missing, expired or its state is no
    /// longer `expected`. Makes WebAuthn challenges and TOTP enrolment single-use: of concurrent
    /// callers with the same `expected`, exactly one gets `true`.
    async fn swap_state(
        &self,
        tenant: TenantId,
        id: FlowId,
        expected: &str,
        new: &str,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError>;
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
    /// stored. `Conflict` on a duplicate code hash or family id. In the same transaction it
    /// records the RP session `(tenant, code.session_id, code.client_id)` (ignoring an existing
    /// row), which back-channel logout uses ([`LogoutRepo`]).
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

    /// Stores a token family without a code (client credentials). `Conflict` on a duplicate id.
    async fn create_family(
        &self,
        tenant: TenantId,
        family: &NewTokenFamily,
    ) -> Result<(), StorageError>;

    /// Stores an opaque access token. `Conflict` on a duplicate hash.
    async fn create_access_token(
        &self,
        tenant: TenantId,
        token: &NewAccessToken,
    ) -> Result<(), StorageError>;

    /// Read-only lookup in any state (expired, revoked, revoked family) with its family if it
    /// has one; callers decide validity (introspection, revocation, UserInfo).
    async fn find_access_token(
        &self,
        tenant: TenantId,
        token_hash: &SecretHash,
    ) -> Result<Option<(AccessTokenRecord, Option<TokenFamily>)>, StorageError>;

    /// Sets `revoked_at = now` on an unrevoked access token. `false` if unknown or already
    /// revoked.
    async fn revoke_access_token(
        &self,
        tenant: TenantId,
        token_hash: &SecretHash,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError>;

    /// The active (unrevoked) consent of `user` for `client_id`.
    async fn consent(
        &self,
        tenant: TenantId,
        user: UserId,
        client_id: &str,
    ) -> Result<Option<ConsentGrant>, StorageError>;

    /// The user's active consents, in client id order.
    async fn list_consents(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Vec<ConsentGrant>, StorageError>;

    /// Grants `consent.scopes` to (user, client) in one statement or transaction: creates the
    /// grant (with `consent.id`), or merges the scopes into the existing one (union, sorted) and
    /// sets `updated_at = now`. A revoked grant is re-activated with exactly the new scopes.
    /// Returns the stored grant.
    async fn upsert_consent(
        &self,
        tenant: TenantId,
        consent: &NewConsent,
        now: OffsetDateTime,
    ) -> Result<ConsentGrant, StorageError>;

    /// In **one transaction**: revokes the active consent of (user, client) and every unrevoked
    /// token family of that user and client (reason `ConsentRevoked`). `false` (nothing
    /// changed) if there is no active consent.
    async fn revoke_consent(
        &self,
        tenant: TenantId,
        user: UserId,
        client_id: &str,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError>;
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

/// Append-only audit log.
#[async_trait::async_trait]
pub trait AuditRepo: Send + Sync {
    /// Appends an event. `Conflict` on a duplicate id. Events are never updated.
    async fn append(&self, tenant: TenantId, event: &NewAuditEvent) -> Result<(), StorageError>;

    /// Events of one tenant matching every set filter of `query`, newest first (id descending),
    /// at most `query.limit` items (callers normalise the limit). `query.before` is the cursor:
    /// only events with a smaller id. `next_cursor` is the id of the last item iff more follow.
    async fn query(
        &self,
        tenant: TenantId,
        query: &AuditQuery,
    ) -> Result<Page<AuditEvent>, StorageError>;

    /// Retention, installation-wide: deletes every event with `at < cutoff`. Returns the number
    /// deleted.
    async fn purge_before(&self, cutoff: OffsetDateTime) -> Result<u64, StorageError>;
}

/// Per-tenant email template overrides and SMTP settings.
#[async_trait::async_trait]
pub trait MailSettingsRepo: Send + Sync {
    /// The tenant's override for `kind`, if any.
    async fn template(
        &self,
        tenant: TenantId,
        kind: EmailKind,
    ) -> Result<Option<EmailTemplate>, StorageError>;

    /// Every override of the tenant, in kind-name order.
    async fn list_templates(&self, tenant: TenantId) -> Result<Vec<EmailTemplate>, StorageError>;

    /// Inserts or replaces the override for `template.kind`.
    async fn put_template(
        &self,
        tenant: TenantId,
        template: &EmailTemplate,
    ) -> Result<(), StorageError>;

    /// Removes the override (back to the theme default). `false` if there was none.
    async fn delete_template(
        &self,
        tenant: TenantId,
        kind: EmailKind,
    ) -> Result<bool, StorageError>;

    /// The tenant's SMTP settings, if any.
    async fn smtp(&self, tenant: TenantId) -> Result<Option<SmtpSettings>, StorageError>;

    /// Inserts or replaces the tenant's SMTP settings.
    async fn put_smtp(&self, tenant: TenantId, settings: &SmtpSettings)
    -> Result<(), StorageError>;

    /// Removes the tenant's SMTP settings (back to the installation SMTP). `false` if none.
    async fn delete_smtp(&self, tenant: TenantId) -> Result<bool, StorageError>;
}

/// Installation-wide leases for background jobs, so one node runs a job at a time.
#[async_trait::async_trait]
pub trait JobRepo: Send + Sync {
    /// Takes or renews the lease of job `name` for `owner` until `until`, in one statement:
    /// succeeds if no lease exists, the existing lease expired (`until <= now`) or `owner`
    /// already holds it. `false` while another owner holds an unexpired lease. Of concurrent
    /// callers for a free job, exactly one gets `true`.
    async fn try_lease(
        &self,
        name: &str,
        owner: &str,
        until: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError>;

    /// Releases the lease if `owner` holds it. `false` otherwise.
    async fn release(&self, name: &str, owner: &str) -> Result<bool, StorageError>;
}

/// Upstream identity-provider connections and identity links (AUTH-07, AUTH-11).
#[async_trait::async_trait]
pub trait ConnectionRepo: Send + Sync {
    /// `Conflict` on a duplicate (tenant, slug).
    async fn create(
        &self,
        tenant: TenantId,
        connection: &NewConnection,
    ) -> Result<Connection, StorageError>;

    async fn get(
        &self,
        tenant: TenantId,
        id: ConnectionId,
    ) -> Result<Option<Connection>, StorageError>;

    async fn get_by_slug(
        &self,
        tenant: TenantId,
        slug: &str,
    ) -> Result<Option<Connection>, StorageError>;

    /// Every connection of the tenant in slug order.
    async fn list(&self, tenant: TenantId) -> Result<Vec<Connection>, StorageError>;

    /// Applies a partial update and sets `updated_at = now`. `None` if the connection does not
    /// exist.
    async fn update(
        &self,
        tenant: TenantId,
        id: ConnectionId,
        update: &ConnectionUpdate,
        now: OffsetDateTime,
    ) -> Result<Option<Connection>, StorageError>;

    /// Replaces (`Some`) or clears (`None`) the sealed secret exactly as given and sets
    /// `updated_at = now`. `false` if the connection does not exist.
    async fn set_secret(
        &self,
        tenant: TenantId,
        id: ConnectionId,
        secret_enc: Option<&[u8]>,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError>;

    /// Deletes the connection and, in the same transaction (cascade), its identity links.
    /// `false` if it did not exist.
    async fn delete(&self, tenant: TenantId, id: ConnectionId) -> Result<bool, StorageError>;

    /// The link of upstream `subject` at `connection_id` (exact match).
    async fn find_link(
        &self,
        tenant: TenantId,
        connection_id: ConnectionId,
        subject: &str,
    ) -> Result<Option<IdentityLink>, StorageError>;

    /// `Conflict` if (tenant, connection, subject) is already linked (to any user), on a
    /// duplicate id, or if the user or connection does not exist in the tenant.
    async fn create_link(
        &self,
        tenant: TenantId,
        link: &NewIdentityLink,
    ) -> Result<IdentityLink, StorageError>;

    /// The user's links, oldest first.
    async fn links_for_user(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Vec<IdentityLink>, StorageError>;

    /// Sets `last_used_at = now`. `false` if the link does not exist.
    async fn touch_link(
        &self,
        tenant: TenantId,
        id: IdentityLinkId,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError>;

    /// Deletes one link of `user`. `false` if there is no such link of this user (another user's
    /// link is never deleted).
    async fn delete_link(
        &self,
        tenant: TenantId,
        user: UserId,
        id: IdentityLinkId,
    ) -> Result<bool, StorageError>;

    /// Creates the user (no password) and the link in **one transaction** (sign-up through an
    /// upstream). `Conflict` on a duplicate email/username or link; on conflict nothing at all
    /// is persisted.
    async fn create_user_with_link(
        &self,
        tenant: TenantId,
        user: &NewUser,
        link: &NewIdentityLink,
    ) -> Result<User, StorageError>;
}

/// Theming per tenant and client (UI-03). `scope_key` is [`crate::model::BrandingScope::scope_key`].
#[async_trait::async_trait]
pub trait BrandingRepo: Send + Sync {
    async fn get(
        &self,
        tenant: TenantId,
        scope_key: &str,
    ) -> Result<Option<Branding>, StorageError>;

    /// Upsert of the scope's tokens and custom CSS (`updated_at = now`) in one transaction.
    /// `LogoChange::Keep` keeps the current logo, `Clear` removes the reference, `Set` stores the
    /// logo bytes keyed by their sha256 (idempotent) and references it. Returns the stored
    /// record.
    async fn put(
        &self,
        tenant: TenantId,
        scope_key: &str,
        update: &BrandingUpdate,
        now: OffsetDateTime,
    ) -> Result<Branding, StorageError>;

    /// Removes the scope's branding (back to the inherited one). `false` if there was none.
    async fn delete(&self, tenant: TenantId, scope_key: &str) -> Result<bool, StorageError>;

    /// A stored logo of the tenant by lowercase hex sha256.
    async fn logo(&self, tenant: TenantId, sha256: &str) -> Result<Option<Logo>, StorageError>;

    /// Stores the preview draft of a scope, replacing that scope's previous draft.
    async fn put_draft(
        &self,
        tenant: TenantId,
        scope_key: &str,
        draft: &BrandingDraft,
        now: OffsetDateTime,
    ) -> Result<(), StorageError>;

    /// The unexpired (`preview_expires_at > now`) draft of this tenant with this preview token
    /// hash, with its scope key.
    async fn draft_by_preview(
        &self,
        tenant: TenantId,
        preview_token_hash: &SecretHash,
        now: OffsetDateTime,
    ) -> Result<Option<(String, BrandingDraft)>, StorageError>;
}

/// RP sessions and back-channel logout deliveries (OIDC-12). Deliveries are enqueued by the
/// revoking intents (module docs, "Back-channel logout enqueueing"); this trait reads them and
/// drives the delivery worker.
#[async_trait::async_trait]
pub trait LogoutRepo: Send + Sync {
    /// RP sessions of a browser session, in client id order.
    async fn rp_sessions(
        &self,
        tenant: TenantId,
        session_id: SessionId,
    ) -> Result<Vec<RpSession>, StorageError>;

    /// Installation-wide, like the outbox: claims up to `limit` rows with
    /// `delivered_at IS NULL AND next_attempt_at <= now AND give_up_at > now`, oldest first, and
    /// leases them by setting `next_attempt_at = owner_lease_until`. Concurrent claimers never
    /// get the same row (Postgres: `FOR UPDATE SKIP LOCKED`; SQLite: the single writer).
    async fn claim_due_deliveries(
        &self,
        owner_lease_until: OffsetDateTime,
        now: OffsetDateTime,
        limit: u32,
    ) -> Result<Vec<LogoutDelivery>, StorageError>;

    /// Records an attempt: `Delivered` sets `delivered_at = now`; `Retry` increments
    /// `attempts`, sets `next_attempt_at` and `last_error`; `GiveUp` increments `attempts`, sets
    /// `give_up_at = now` and `last_error`. `false` if unknown.
    async fn complete_delivery(
        &self,
        id: LogoutDeliveryId,
        result: &DeliveryResult,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError>;

    /// Every delivery of a client in any state, oldest first (admin and test visibility).
    async fn deliveries_for_client(
        &self,
        tenant: TenantId,
        client_id: &str,
    ) -> Result<Vec<LogoutDelivery>, StorageError>;
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

/// Receives every recorded audit event as one JSON line (the stdout mirror). Installed once per
/// process with [`crate::service::audit::install_mirror`]; the binary's implementation emits
/// `tracing::info!(target: "audit", event = %json)` (the core has no logging dependency).
pub trait AuditMirror: Send + Sync {
    fn emit(&self, event_json: &str);
}

/// WebAuthn relying party of a tenant (computed by the web layer from the issuer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelyingParty {
    pub rp_id: String,
    pub origin: String,
    pub name: String,
}

/// The user a passkey is registered for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyUser {
    pub id: UserId,
    pub name: String,
    pub display_name: String,
}

/// A WebAuthn ceremony challenge. `options_json` goes to the browser; `state_json` stays on the
/// server (in the flow state) and is consumed exactly once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub options_json: String,
    pub state_json: String,
}

/// Result of a verified registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredPasskey {
    pub credential_id: Vec<u8>,
    pub passkey_json: String,
    pub counter: u32,
    pub backup_eligible: bool,
}

/// Who a discoverable assertion claims to be (before verification).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionIdentity {
    pub user_id: UserId,
    pub credential_id: Vec<u8>,
}

/// Result of a verified assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAssertion {
    pub counter: u32,
    pub user_verified: bool,
    pub backup_eligible: bool,
    /// Present when the stored passkey changed (counter, backup state) and must be saved.
    pub updated_passkey_json: Option<String>,
}

/// Why a WebAuthn response was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PasskeyError {
    /// Malformed, wrong challenge/origin, bad signature, unknown credential.
    #[error("invalid passkey response")]
    Invalid,
    /// The signature counter went backwards: the authenticator may have been cloned.
    #[error("possible cloned authenticator")]
    PossibleClone,
}

/// WebAuthn ceremonies (implemented with webauthn-rs in the web layer). Synchronous: pure
/// cryptography, no I/O.
pub trait PasskeyCeremonies: Send + Sync {
    /// Registration options for `user`, excluding the already registered credential ids.
    fn start_registration(
        &self,
        rp: &RelyingParty,
        user: &PasskeyUser,
        exclude: &[Vec<u8>],
    ) -> Result<Challenge, CoreError>;

    /// Verifies a registration response against the server-side state.
    fn finish_registration(
        &self,
        rp: &RelyingParty,
        response_json: &str,
        state_json: &str,
    ) -> Result<RegisteredPasskey, PasskeyError>;

    /// Options for a discoverable (usernameless) assertion.
    fn start_discoverable(&self, rp: &RelyingParty) -> Result<Challenge, CoreError>;

    /// Extracts the claimed user handle and credential id from an assertion response, without
    /// verifying it.
    fn identify(&self, response_json: &str) -> Result<AssertionIdentity, PasskeyError>;

    /// Verifies a discoverable assertion against the server-side state and the stored passkey.
    fn finish_discoverable(
        &self,
        rp: &RelyingParty,
        response_json: &str,
        state_json: &str,
        stored_passkey_json: &str,
    ) -> Result<VerifiedAssertion, PasskeyError>;
}

/// A template problem, reported to the administrator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateIssue {
    pub line: Option<u32>,
    pub message: String,
}

/// Compiles an email template override (with sample variables) before it is stored.
pub trait EmailTemplateCheck: Send + Sync {
    fn check(
        &self,
        kind: EmailKind,
        subject: &str,
        html: &str,
        text: &str,
    ) -> Result<(), TemplateIssue>;
}

/// Connection parameters for an SMTP test send, with the password opened.
#[derive(Debug, Clone)]
pub struct SmtpConnection {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<SecretString>,
    pub from: String,
    pub tls: SmtpTls,
}

/// Sends a test email with given SMTP settings (admin "send test email").
#[async_trait::async_trait]
pub trait SmtpTester: Send + Sync {
    /// `Err` carries a message safe to show to the administrator (never the password).
    async fn send_test(&self, conn: &SmtpConnection, to: &str) -> Result<(), String>;
}

/// OpenID Provider metadata of an upstream (the subset AnvilID uses).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: String,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub authorization_response_iss_parameter_supported: bool,
    pub code_challenge_methods_supported: Vec<String>,
}

/// How the client authenticates at the upstream token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenEndpointAuth {
    /// `client_secret_basic`.
    Basic,
    /// `client_secret_post`.
    Post,
}

/// An authorization-code exchange at an upstream token endpoint.
#[derive(Debug, Clone)]
pub struct CodeExchange {
    pub token_endpoint: String,
    pub client_id: String,
    pub client_secret: Option<SecretString>,
    pub auth: TokenEndpointAuth,
    pub code: SecretString,
    pub redirect_uri: String,
    pub code_verifier: Option<SecretString>,
}

/// The upstream token response.
#[derive(Debug, Clone)]
pub struct TokenSet {
    pub access_token: SecretString,
    /// Validated by the caller (signature, iss, aud, exp, nonce) before use.
    pub id_token: Option<String>,
    pub token_type: String,
    pub scope: Option<String>,
}

/// Request profile for [`UpstreamClient::get_json`] (headers some APIs require).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiProfile {
    /// `Accept: application/json`.
    Standard,
    /// GitHub REST API: `Accept: application/vnd.github+json`, `X-GitHub-Api-Version`, and a
    /// `User-Agent`.
    Github,
}

/// Why an upstream call failed. `Display` never echoes URLs, IP addresses or response bodies.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UpstreamError {
    /// The destination is not allowed (SSRF guard: private address, scheme, port).
    #[error("upstream destination blocked")]
    Blocked,
    #[error("upstream network error")]
    Network,
    #[error("upstream timeout")]
    Timeout,
    /// Unexpected HTTP status.
    #[error("upstream returned status {0}")]
    Status(u16),
    /// The response exceeded the size limit.
    #[error("upstream response too large")]
    TooLarge,
    /// The response could not be parsed or failed validation (fixed, code-defined reason).
    #[error("invalid upstream response: {0}")]
    InvalidResponse(&'static str),
}

/// Outbound calls to upstream identity providers (implemented in the web layer on the
/// SSRF-guarded HTTP client with timeouts and size limits; discovery and JWKS cached).
#[async_trait::async_trait]
pub trait UpstreamClient: Send + Sync {
    /// OIDC discovery at `{issuer}/.well-known/openid-configuration`. The adapter checks that the
    /// document's `issuer` equals `issuer` exactly (`InvalidResponse` otherwise).
    async fn metadata(&self, issuer: &str) -> Result<ProviderMetadata, UpstreamError>;

    /// The JWK Set at `jwks_uri`; `force_refresh` bypasses the cache (unknown `kid`).
    async fn jwks(&self, jwks_uri: &str, force_refresh: bool) -> Result<Jwks, UpstreamError>;

    /// Exchanges an authorization code (RFC 6749 §4.1.3).
    async fn exchange_code(&self, exchange: &CodeExchange) -> Result<TokenSet, UpstreamError>;

    /// GET `url` with `Authorization: Bearer` and the profile's headers; a JSON body.
    async fn get_json(
        &self,
        url: &str,
        bearer: &SecretString,
        profile: ApiProfile,
    ) -> Result<serde_json::Value, UpstreamError>;
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
        assert_send_sync::<dyn AuditRepo>();
        assert_send_sync::<dyn MailSettingsRepo>();
        assert_send_sync::<dyn JobRepo>();
        assert_send_sync::<dyn ConnectionRepo>();
        assert_send_sync::<dyn BrandingRepo>();
        assert_send_sync::<dyn LogoutRepo>();
        assert_send_sync::<dyn UpstreamClient>();
        assert_send_sync::<UpstreamError>();
        assert_send_sync::<dyn AuditMirror>();
        assert_send_sync::<dyn PasskeyCeremonies>();
        assert_send_sync::<dyn EmailTemplateCheck>();
        assert_send_sync::<dyn SmtpTester>();
        assert_send_sync::<dyn Clock>();
        assert_send_sync::<dyn PasswordHasher>();
        assert_send_sync::<dyn BreachChecker>();
        assert_send_sync::<StorageError>();
    }

    #[test]
    fn upstream_error_display_is_fixed_text() {
        for (e, want) in [
            (UpstreamError::Blocked, "upstream destination blocked"),
            (UpstreamError::Network, "upstream network error"),
            (UpstreamError::Timeout, "upstream timeout"),
            (UpstreamError::Status(502), "upstream returned status 502"),
            (UpstreamError::TooLarge, "upstream response too large"),
            (
                UpstreamError::InvalidResponse("issuer mismatch"),
                "invalid upstream response: issuer mismatch",
            ),
        ] {
            assert_eq!(e.to_string(), want);
        }
    }

    #[test]
    fn storage_error_keeps_backend_source() {
        let err = StorageError::Backend("connection reset".into());
        assert_eq!(err.to_string(), "storage backend error: connection reset");
        assert!(std::error::Error::source(&err).is_some());
    }
}
