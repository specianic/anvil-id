//! Account self-service for credentials (AUTH-04, AUTH-05, ADM-04): passkey registration, TOTP
//! enrolment with recovery codes, recovery-code regeneration and credential removal, plus the
//! administrator's list/remove used by the management API. Profile editing, email change with
//! re-verification and password change/set (AUTH-13) use the same settings-flow binding.
//!
//! # Binding and re-authentication
//!
//! Every self-service change runs inside a settings flow ([`crate::flow::settings`]): the
//! submission must present the flow cookie and the CSRF token ([`check_binding`]), the flow must
//! belong to the signed-in user, and the session must have authenticated within
//! [`REAUTH_WINDOW`](crate::flow::settings::REAUTH_WINDOW) (15 minutes). Otherwise nothing changes: a wrong binding is
//! `CoreError::Forbidden`, a stale session is [`AccountFailure::ReauthRequired`].
//!
//! # Single use
//!
//! A pending WebAuthn challenge or TOTP secret is consumed with `FlowRepo::swap_state` before it
//! is used, so of two concurrent submissions exactly one proceeds. The TOTP step that confirmed
//! the enrolment is recorded right after the credential is created, so the same code cannot be
//! used again to sign in.
//!
//! # Secrets
//!
//! The pending TOTP secret is sealed with the KEK under the flow's AAD; the enrolled seed is
//! sealed again under the credential's AAD. Recovery codes are HMAC'd with the KEK-derived pepper
//! and their plaintext is returned exactly once.

use std::collections::BTreeMap;
use std::sync::Arc;

use anvil_jose::Kek;
use anvil_jose::encoding::{b64url, b64url_decode, random_token, secret_hash};
use anvil_jose::otp::{TotpSecret, check_code, otpauth_uri};
use anvil_jose::recovery_code::{
    generate_recovery_codes, normalize_recovery_code, recovery_code_hash,
};
use secrecy::{ExposeSecret as _, SecretString};
use time::Duration;

use super::audit::AuditService;
use super::flow::{BindingError, FLOW_LIFETIME, NOTICE_EMAIL_TTL, check_binding};
use crate::error::CoreError;
use crate::flow::settings::{
    SETTINGS_TOTP_PURPOSE, SettingsState, is_recent_auth, normalize_label, settings_totp_aad,
};
use crate::model::{
    AuditAction, AuditActor, AuditDetails, AuditOutcome, BrowserSession, CredentialId,
    CredentialKind, CredentialSummary, EmailKind, Flow, FlowId, FlowKind, NewEmail, NewFlow,
    NewPasskey, NewSelfServiceToken, NewTotp, OutboxId, RecoveryCodeHash, RecoveryNotice,
    RequestContext, SecretHash, SelfServiceKind, TOTP_SEED_PURPOSE, Tenant, TenantId, User, UserId,
    UserUpdate, credential_aad, normalize_email, seal_payload,
};
use crate::policy::{PasswordPolicy, check_password};
use crate::ports::{
    BreachChecker, Clock, PasskeyCeremonies, PasskeyUser, PasswordHasher, RelyingParty, Storage,
    StorageError,
};

/// Number of recovery codes in a set.
pub const RECOVERY_CODE_COUNT: usize = 10;

/// Why a self-service change was refused. Each has a stable message key for the page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccountFailure {
    /// The session is older than [`REAUTH_WINDOW`](crate::flow::settings::REAUTH_WINDOW): sign in again first.
    ReauthRequired,
    /// The settings flow expired (or does not exist): reload the page.
    FlowExpired,
    /// Passkey label too long or with control characters.
    InvalidLabel,
    /// No pending challenge, a consumed challenge, or an invalid WebAuthn response.
    PasskeyFailed,
    /// The credential id is already registered in this tenant.
    PasskeyExists,
    /// The user already has a TOTP credential.
    TotpExists,
    /// No TOTP enrolment is pending in this flow.
    TotpNotPending,
    /// The confirmation code is wrong (the pending secret is kept).
    TotpInvalidCode,
    /// Recovery codes need an enrolled TOTP credential.
    TotpRequired,
    /// No such passkey or TOTP credential of this user.
    CredentialNotFound,
    /// A concurrent change of the same flow won.
    Concurrent,
    /// A name field is longer than [`PROFILE_FIELD_MAX`] characters or has control characters.
    InvalidName,
    /// The locale is not a language tag like `en` or `pt-BR`.
    InvalidLocale,
    /// The new email address is malformed.
    InvalidEmail,
    /// The new email address is the current one.
    EmailUnchanged,
    /// Another account holds the new address (at confirmation; the token stays usable).
    EmailTaken,
    /// The email-change link is unknown, used, expired or malformed.
    EmailTokenInvalid,
    /// The new password is shorter than the policy minimum.
    PasswordTooShort,
    /// The new password is longer than the policy maximum.
    PasswordTooLong,
    /// The new password appears in the breach corpus.
    PasswordBreached,
    /// Hashing or the breach check is overloaded: try again shortly.
    Overloaded,
}

impl AccountFailure {
    /// Every failure (for tests and documentation).
    pub const ALL: &'static [Self] = &[
        Self::ReauthRequired,
        Self::FlowExpired,
        Self::InvalidLabel,
        Self::PasskeyFailed,
        Self::PasskeyExists,
        Self::TotpExists,
        Self::TotpNotPending,
        Self::TotpInvalidCode,
        Self::TotpRequired,
        Self::CredentialNotFound,
        Self::Concurrent,
        Self::InvalidName,
        Self::InvalidLocale,
        Self::InvalidEmail,
        Self::EmailUnchanged,
        Self::EmailTaken,
        Self::EmailTokenInvalid,
        Self::PasswordTooShort,
        Self::PasswordTooLong,
        Self::PasswordBreached,
        Self::Overloaded,
    ];

    /// The stable message key.
    pub fn key(self) -> &'static str {
        match self {
            Self::ReauthRequired => "account.reauth_required",
            Self::FlowExpired => "account.flow_expired",
            Self::InvalidLabel => "account.invalid_label",
            Self::PasskeyFailed => "account.passkey_failed",
            Self::PasskeyExists => "account.passkey_exists",
            Self::TotpExists => "account.totp_exists",
            Self::TotpNotPending => "account.totp_not_pending",
            Self::TotpInvalidCode => "account.totp_invalid_code",
            Self::TotpRequired => "account.totp_required",
            Self::CredentialNotFound => "account.credential_not_found",
            Self::Concurrent => "account.try_again",
            Self::InvalidName => "account.invalid_name",
            Self::InvalidLocale => "account.invalid_locale",
            Self::InvalidEmail => "account.invalid_email",
            Self::EmailUnchanged => "account.email_unchanged",
            Self::EmailTaken => "account.email_taken",
            Self::EmailTokenInvalid => "account.email_token_invalid",
            Self::PasswordTooShort => "account.password_too_short",
            Self::PasswordTooLong => "account.password_too_long",
            Self::PasswordBreached => "account.password_breached",
            Self::Overloaded => "account.overloaded",
        }
    }
}

/// Error of a self-service change: a refusal shown on the page, or a core error (`Forbidden`
/// for a broken binding, storage and internal failures).
#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    #[error("account change refused: {}", .0.key())]
    Failure(AccountFailure),
    #[error(transparent)]
    Core(#[from] CoreError),
}

impl From<AccountFailure> for AccountError {
    fn from(f: AccountFailure) -> Self {
        Self::Failure(f)
    }
}

impl From<StorageError> for AccountError {
    fn from(e: StorageError) -> Self {
        Self::Core(e.into())
    }
}

/// The submission's binding to its settings flow.
#[derive(Debug, Clone, Copy)]
pub struct SettingsBinding<'a> {
    pub flow_id: FlowId,
    pub cookie_token: Option<&'a str>,
    pub csrf_token: &'a str,
}

/// A newly created settings flow: the cookie and the CSRF token go to the browser.
#[derive(Debug)]
pub struct StartedSettings {
    pub flow_id: FlowId,
    pub cookie_token: SecretString,
    pub csrf_token: SecretString,
}

/// What the account security page lists. No secret material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountOverview {
    pub passkeys: Vec<CredentialSummary>,
    pub totp: Option<CredentialSummary>,
    pub recovery_codes_remaining: u32,
    /// The session may change credentials now (signed in within [`REAUTH_WINDOW`](crate::flow::settings::REAUTH_WINDOW)).
    pub recent_auth: bool,
}

/// A pending TOTP enrolment for display: the `otpauth://` URI (QR code) and the base32 secret
/// for manual entry.
#[derive(Debug)]
pub struct TotpEnrolment {
    pub otpauth_uri: SecretString,
    pub secret_base32: SecretString,
}

/// Credential self-service and administration.
pub struct AccountService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
    pub kek: Arc<Kek>,
    pub passkeys: Arc<dyn PasskeyCeremonies>,
}

/// A settings flow opened for a submission.
struct Opened {
    flow: Flow,
    state: SettingsState,
}

impl AccountService {
    fn audit(&self) -> AuditService {
        AuditService {
            storage: self.storage.clone(),
            clock: self.clock.clone(),
        }
    }

    /// Creates a settings flow for the session's user.
    pub async fn start(
        &self,
        tenant: TenantId,
        session: &BrowserSession,
    ) -> Result<StartedSettings, CoreError> {
        let now = self.clock.now();
        let cookie = random_token();
        let csrf = random_token();
        let new = NewFlow {
            id: FlowId::new_v7(),
            kind: FlowKind::Settings,
            state: SettingsState::new(session.user_id).to_json(),
            csrf_hash: SecretHash(secret_hash(&csrf)),
            cookie_hash: SecretHash(secret_hash(&cookie)),
            auth_request_id: None,
            created_at: now,
            expires_at: now + FLOW_LIFETIME,
        };
        self.storage.flows().create(tenant, &new).await?;
        Ok(StartedSettings {
            flow_id: new.id,
            cookie_token: SecretString::from(cookie),
            csrf_token: SecretString::from(csrf),
        })
    }

    /// The credentials of the session's user.
    pub async fn overview(
        &self,
        tenant: TenantId,
        session: &BrowserSession,
    ) -> Result<AccountOverview, CoreError> {
        let users = self.storage.users();
        let all = users.list_credentials(tenant, session.user_id).await?;
        let passkeys = all
            .iter()
            .filter(|c| c.kind == CredentialKind::Webauthn)
            .cloned()
            .collect();
        let totp = all.into_iter().find(|c| c.kind == CredentialKind::Totp);
        let recovery_codes_remaining = users
            .recovery_codes_remaining(tenant, session.user_id)
            .await?;
        Ok(AccountOverview {
            passkeys,
            totp,
            recovery_codes_remaining,
            recent_auth: is_recent_auth(session.auth_time, self.clock.now()),
        })
    }

    /// Checks the binding, the flow owner and the recent authentication. Changes nothing.
    async fn open(
        &self,
        tenant: TenantId,
        session: &BrowserSession,
        binding: &SettingsBinding<'_>,
    ) -> Result<Opened, AccountError> {
        self.open_with(tenant, session, binding, true).await
    }

    /// [`Self::open`], with the recent-authentication check only when `reauth` is set (profile
    /// edits need the binding but not a fresh sign-in).
    async fn open_with(
        &self,
        tenant: TenantId,
        session: &BrowserSession,
        binding: &SettingsBinding<'_>,
        reauth: bool,
    ) -> Result<Opened, AccountError> {
        let now = self.clock.now();
        let Some(flow) = self
            .storage
            .flows()
            .get(tenant, binding.flow_id, now)
            .await?
        else {
            return Err(AccountFailure::FlowExpired.into());
        };
        if flow.kind != FlowKind::Settings {
            return Err(CoreError::Forbidden.into());
        }
        match check_binding(&flow, binding.cookie_token, binding.csrf_token, now) {
            Ok(()) => {}
            Err(BindingError::Expired) => return Err(AccountFailure::FlowExpired.into()),
            Err(BindingError::Forbidden) => return Err(CoreError::Forbidden.into()),
        }
        let state = SettingsState::from_json(&flow.state)
            .map_err(|e| CoreError::Internal(e.to_string()))?;
        if state.user != session.user_id || session.tenant_id != tenant {
            return Err(CoreError::Forbidden.into());
        }
        if reauth && !is_recent_auth(session.auth_time, now) {
            return Err(AccountFailure::ReauthRequired.into());
        }
        Ok(Opened { flow, state })
    }

    /// The settings flow of a submission, checked like every account change: flow cookie and
    /// CSRF token, owned by the session's user, session authenticated within
    /// [`REAUTH_WINDOW`](crate::flow::settings::REAUTH_WINDOW). Changes nothing. Used by the
    /// upstream service to link a provider identity from the account page.
    pub(crate) async fn settings_flow_for(
        &self,
        tenant: TenantId,
        binding: &SettingsBinding<'_>,
        session: &BrowserSession,
    ) -> Result<(Flow, SettingsState), AccountError> {
        let opened = self.open(tenant, session, binding).await?;
        Ok((opened.flow, opened.state))
    }

    /// Persists `next` iff the flow still holds the state it was opened with.
    async fn swap(
        &self,
        tenant: TenantId,
        opened: &Opened,
        next: &SettingsState,
    ) -> Result<bool, CoreError> {
        Ok(self
            .storage
            .flows()
            .swap_state(
                tenant,
                opened.flow.id,
                &opened.flow.state,
                &next.to_json(),
                self.clock.now(),
            )
            .await?)
    }

    async fn user(&self, tenant: TenantId, id: UserId) -> Result<User, CoreError> {
        self.storage
            .users()
            .get(tenant, id)
            .await?
            .ok_or(CoreError::Forbidden)
    }

    /// Starts a passkey registration: options for the browser (discoverable credential, user
    /// verification required, the user's existing credentials excluded). The server-side state
    /// is kept in the flow.
    pub async fn begin_passkey(
        &self,
        tenant: &Tenant,
        session: &BrowserSession,
        binding: &SettingsBinding<'_>,
        rp: &RelyingParty,
    ) -> Result<String, AccountError> {
        let opened = self.open(tenant.id, session, binding).await?;
        let user = self.user(tenant.id, session.user_id).await?;
        let exclude: Vec<Vec<u8>> = self
            .storage
            .users()
            .passkeys(tenant.id, user.id)
            .await?
            .into_iter()
            .map(|p| p.credential_id)
            .collect();
        let passkey_user = PasskeyUser {
            id: user.id,
            name: user.email.clone(),
            display_name: user
                .claims
                .name
                .clone()
                .filter(|n| !n.trim().is_empty())
                .unwrap_or_else(|| user.email.clone()),
        };
        let challenge = self
            .passkeys
            .start_registration(rp, &passkey_user, &exclude)?;
        let next = opened
            .state
            .clone()
            .with_passkey_challenge(challenge.state_json);
        if !self.swap(tenant.id, &opened, &next).await? {
            return Err(AccountFailure::Concurrent.into());
        }
        Ok(challenge.options_json)
    }

    /// Completes a passkey registration. The pending challenge is consumed before the response
    /// is verified, so it can be used once.
    #[expect(
        clippy::too_many_arguments,
        reason = "one call per submission; every argument is part of it"
    )]
    pub async fn finish_passkey(
        &self,
        tenant: &Tenant,
        session: &BrowserSession,
        binding: &SettingsBinding<'_>,
        rp: &RelyingParty,
        response_json: &str,
        label: &str,
        ctx: &RequestContext,
    ) -> Result<CredentialId, AccountError> {
        let opened = self.open(tenant.id, session, binding).await?;
        let label = normalize_label(label).ok_or(AccountFailure::InvalidLabel)?;
        let (next, pending) = opened.state.clone().take_passkey();
        let Some(state_json) = pending else {
            return Err(AccountFailure::PasskeyFailed.into());
        };
        if !self.swap(tenant.id, &opened, &next).await? {
            return Err(AccountFailure::PasskeyFailed.into());
        }
        let registered = self
            .passkeys
            .finish_registration(rp, response_json, &state_json)
            .map_err(|_| AccountFailure::PasskeyFailed)?;
        let now = self.clock.now();
        let new = NewPasskey {
            id: CredentialId::new_v7(),
            credential_id: registered.credential_id,
            passkey_json: registered.passkey_json,
            counter: registered.counter,
            backup_eligible: registered.backup_eligible,
            label,
            created_at: now,
        };
        match self
            .storage
            .users()
            .create_passkey(tenant.id, session.user_id, &new)
            .await
        {
            Ok(()) => {}
            Err(StorageError::Conflict(_)) => return Err(AccountFailure::PasskeyExists.into()),
            Err(e) => return Err(e.into()),
        }
        self.audit()
            .record(
                tenant.id,
                AuditActor::user(session.user_id),
                AuditAction::PasskeyRegistered,
                Some(new.id.to_string()),
                AuditOutcome::Success,
                ctx,
                AuditDetails::credential(CredentialKind::Webauthn),
            )
            .await?;
        Ok(new.id)
    }

    /// Starts a TOTP enrolment: a fresh secret, sealed into the flow (purpose
    /// [`SETTINGS_TOTP_PURPOSE`], AAD = flow id). Nothing is stored as a credential until
    /// [`Self::confirm_totp`].
    pub async fn begin_totp(
        &self,
        tenant: &Tenant,
        session: &BrowserSession,
        binding: &SettingsBinding<'_>,
    ) -> Result<TotpEnrolment, AccountError> {
        let opened = self.open(tenant.id, session, binding).await?;
        if self
            .storage
            .users()
            .totp(tenant.id, session.user_id)
            .await?
            .is_some()
        {
            return Err(AccountFailure::TotpExists.into());
        }
        let user = self.user(tenant.id, session.user_id).await?;
        let secret = TotpSecret::generate();
        let sealed = seal_pending_totp(&self.kek, opened.flow.id, &secret)?;
        let enrolment = enrolment(tenant, &user, &secret)?;
        let next = opened.state.clone().with_totp_secret(sealed);
        if !self.swap(tenant.id, &opened, &next).await? {
            return Err(AccountFailure::Concurrent.into());
        }
        Ok(enrolment)
    }

    /// The pending TOTP enrolment of the flow (to show the QR code again after a wrong code).
    pub async fn pending_totp(
        &self,
        tenant: &Tenant,
        session: &BrowserSession,
        binding: &SettingsBinding<'_>,
    ) -> Result<TotpEnrolment, AccountError> {
        let opened = self.open(tenant.id, session, binding).await?;
        let Some(sealed) = opened.state.pending_totp.as_deref() else {
            return Err(AccountFailure::TotpNotPending.into());
        };
        let secret = self.open_pending(opened.flow.id, sealed)?;
        let user = self.user(tenant.id, session.user_id).await?;
        Ok(enrolment(tenant, &user, &secret)?)
    }

    fn open_pending(&self, flow: FlowId, sealed_b64: &str) -> Result<TotpSecret, CoreError> {
        open_pending_totp(&self.kek, flow, sealed_b64)
    }

    /// Confirms the pending TOTP enrolment with a code from the authenticator app. A wrong code
    /// keeps the pending secret. The right code creates the credential (seed sealed under the
    /// credential AAD) and a fresh set of recovery codes in one storage call, records the code's
    /// step as used and returns the recovery codes (shown once).
    pub async fn confirm_totp(
        &self,
        tenant: &Tenant,
        session: &BrowserSession,
        binding: &SettingsBinding<'_>,
        code: &str,
        ctx: &RequestContext,
    ) -> Result<Vec<SecretString>, AccountError> {
        let opened = self.open(tenant.id, session, binding).await?;
        let Some(sealed) = opened.state.pending_totp.clone() else {
            return Err(AccountFailure::TotpNotPending.into());
        };
        let secret = self.open_pending(opened.flow.id, &sealed)?;
        let now = self.clock.now();
        let Some(step) = pending_totp_step(&secret, code, now) else {
            return Err(AccountFailure::TotpInvalidCode.into());
        };
        let (next, _) = opened.state.clone().take_totp();
        if !self.swap(tenant.id, &opened, &next).await? {
            return Err(AccountFailure::TotpNotPending.into());
        }
        create_confirmed_totp(
            self.storage.as_ref(),
            &self.kek,
            &self.audit(),
            tenant.id,
            session.user_id,
            &secret,
            step,
            now,
            ctx,
        )
        .await?
        .ok_or_else(|| AccountFailure::TotpExists.into())
    }

    /// Replaces the user's recovery codes (the old set stops working) and returns the new codes
    /// (shown once). Requires an enrolled TOTP credential.
    pub async fn regenerate_recovery_codes(
        &self,
        tenant: &Tenant,
        session: &BrowserSession,
        binding: &SettingsBinding<'_>,
        ctx: &RequestContext,
    ) -> Result<Vec<SecretString>, AccountError> {
        self.open(tenant.id, session, binding).await?;
        let users = self.storage.users();
        if users.totp(tenant.id, session.user_id).await?.is_none() {
            return Err(AccountFailure::TotpRequired.into());
        }
        let (codes, hashes) = new_recovery_codes(&self.kek)?;
        users
            .replace_recovery_codes(tenant.id, session.user_id, &hashes, self.clock.now())
            .await?;
        self.audit()
            .record(
                tenant.id,
                AuditActor::user(session.user_id),
                AuditAction::RecoveryCodesRegenerated,
                None,
                AuditOutcome::Success,
                ctx,
                AuditDetails::count("codes", RECOVERY_CODE_COUNT as u64),
            )
            .await?;
        Ok(codes)
    }

    /// Removes one of the user's passkeys or the TOTP credential (with its recovery codes).
    pub async fn remove_credential(
        &self,
        tenant: &Tenant,
        session: &BrowserSession,
        binding: &SettingsBinding<'_>,
        id: CredentialId,
        ctx: &RequestContext,
    ) -> Result<CredentialKind, AccountError> {
        self.open(tenant.id, session, binding).await?;
        self.remove(
            tenant.id,
            session.user_id,
            id,
            AuditActor::user(session.user_id),
            ctx,
        )
        .await?
        .ok_or_else(|| AccountFailure::CredentialNotFound.into())
    }

    /// Admin view: every credential of `user` (password, passkeys, TOTP) without secrets.
    /// `NotFound` if the user does not exist in the tenant.
    pub async fn admin_list(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Vec<CredentialSummary>, CoreError> {
        let users = self.storage.users();
        if users.get(tenant, user).await?.is_none() {
            return Err(CoreError::NotFound);
        }
        Ok(users.list_credentials(tenant, user).await?)
    }

    /// Admin removal of a passkey or TOTP credential of `user`, audited with the administrator
    /// as actor. `NotFound` for an unknown credential, a credential of another user or a
    /// password.
    pub async fn admin_remove(
        &self,
        tenant: TenantId,
        user: UserId,
        id: CredentialId,
        admin: &str,
        ctx: &RequestContext,
    ) -> Result<CredentialKind, CoreError> {
        self.remove(tenant, user, id, AuditActor::admin(admin), ctx)
            .await?
            .ok_or(CoreError::NotFound)
    }

    /// Deletes a passkey or TOTP credential of `user` and audits it. `None` if there is no such
    /// removable credential.
    async fn remove(
        &self,
        tenant: TenantId,
        user: UserId,
        id: CredentialId,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<Option<CredentialKind>, CoreError> {
        let users = self.storage.users();
        let Some(kind) = users
            .list_credentials(tenant, user)
            .await?
            .into_iter()
            .find(|c| c.id == id && c.kind != CredentialKind::Password)
            .map(|c| c.kind)
        else {
            return Ok(None);
        };
        if !users.delete_credential(tenant, user, id).await? {
            return Ok(None);
        }
        let action = match kind {
            CredentialKind::Totp => AuditAction::TotpRemoved,
            _ => AuditAction::PasskeyRemoved,
        };
        self.audit()
            .record(
                tenant,
                actor,
                action,
                Some(id.to_string()),
                AuditOutcome::Success,
                ctx,
                AuditDetails::credential(kind),
            )
            .await?;
        Ok(Some(kind))
    }
}

// ---------------------------------------------------------------------------------------------
// Profile, email change and password change (AUTH-13)
// ---------------------------------------------------------------------------------------------

/// Maximum length (characters) of `name`, `given_name` and `family_name`.
pub const PROFILE_FIELD_MAX: usize = 200;

/// Lifetime of an email-change link.
pub const EMAIL_CHANGE_TOKEN_TTL: Duration = Duration::hours(24);

/// KEK purpose of the new address sealed into an email-change link (see
/// [`AccountService::request_email_change`]).
pub const EMAIL_CHANGE_LINK_PURPOSE: &str = "anvilid/email-change-link/v1";

/// The editable profile claims as submitted. Surrounding whitespace is trimmed; an empty value
/// clears the claim.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProfileInput<'a> {
    pub name: &'a str,
    pub given_name: &'a str,
    pub family_name: &'a str,
    pub locale: &'a str,
}

/// What a password change needs besides storage: the hasher, the breach corpus and the policy
/// (the same ones the sign-up and recovery flows use).
#[derive(Clone, Copy)]
pub struct PasswordDeps<'a> {
    pub hasher: &'a dyn PasswordHasher,
    pub breach: &'a dyn BreachChecker,
    pub policy: PasswordPolicy,
}

/// The account profile page data. No secret material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountProfile {
    pub email: String,
    pub email_verified: bool,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub locale: Option<String>,
    /// The user has a password (social-only users can set one).
    pub has_password: bool,
    /// The session may change email or password now.
    pub recent_auth: bool,
}

impl AccountService {
    /// The profile of the session's user.
    pub async fn profile(
        &self,
        tenant: TenantId,
        session: &BrowserSession,
    ) -> Result<AccountProfile, CoreError> {
        let user = self.user(tenant, session.user_id).await?;
        let has_password = self
            .storage
            .users()
            .password(tenant, user.id)
            .await?
            .is_some();
        Ok(AccountProfile {
            email: user.email,
            email_verified: user.email_verified,
            name: user.claims.name,
            given_name: user.claims.given_name,
            family_name: user.claims.family_name,
            locale: user.claims.locale,
            has_password,
            recent_auth: is_recent_auth(session.auth_time, self.clock.now()),
        })
    }

    /// Updates `name`, `given_name`, `family_name` and `locale` of the session's user (settings
    /// flow binding; no recent sign-in needed). Audited `profile_updated` with the names of the
    /// changed fields; a submission that changes nothing is not audited.
    pub async fn update_profile(
        &self,
        tenant: TenantId,
        session: &BrowserSession,
        binding: &SettingsBinding<'_>,
        input: &ProfileInput<'_>,
        ctx: &RequestContext,
    ) -> Result<User, AccountError> {
        self.open_with(tenant, session, binding, false).await?;
        let name = profile_field(input.name)?;
        let given_name = profile_field(input.given_name)?;
        let family_name = profile_field(input.family_name)?;
        let locale = locale_field(input.locale)?;
        let user = self.user(tenant, session.user_id).await?;
        let mut claims = user.claims.clone();
        let mut changed: Vec<&'static str> = Vec::new();
        for (field, slot, value) in [
            ("name", &mut claims.name, name),
            ("given_name", &mut claims.given_name, given_name),
            ("family_name", &mut claims.family_name, family_name),
            ("locale", &mut claims.locale, locale),
        ] {
            if *slot != value {
                *slot = value;
                changed.push(field);
            }
        }
        if changed.is_empty() {
            return Ok(user);
        }
        let update = UserUpdate {
            claims: Some(claims),
            ..UserUpdate::default()
        };
        let updated = self
            .storage
            .users()
            .update(tenant, user.id, &update, self.clock.now())
            .await?
            .ok_or(CoreError::Forbidden)?;
        self.audit()
            .record(
                tenant,
                AuditActor::user(user.id),
                AuditAction::ProfileUpdated,
                Some(user.id.to_string()),
                AuditOutcome::Success,
                ctx,
                AuditDetails::fields(&changed),
            )
            .await?;
        Ok(updated)
    }

    /// Starts an email change (recent sign-in required): issues an `EmailChange` token for the
    /// normalised `new_email` (TTL [`EMAIL_CHANGE_TOKEN_TTL`], 256-bit, SHA-256 at rest) and, in
    /// the same storage call, the sealed `email_change` email to the new address with the link
    /// `{confirm_url}?token=…`.
    ///
    /// The link token is `{token}.{sealed}`: `sealed` is the new address sealed with the KEK
    /// (purpose [`EMAIL_CHANGE_LINK_PURPOSE`], AAD = tenant id + token hash), so the confirmation
    /// can address the `email_changed` notice (which names the new address) before the token
    /// is consumed. Only `token` is hashed and stored.
    ///
    /// An address that another account of the tenant already uses gets the same `Ok(())` as a
    /// free one, so the page does not reveal which addresses are registered; nothing is sent
    /// and the attempt is audited as a failure (`email_taken`).
    pub async fn request_email_change(
        &self,
        tenant: &Tenant,
        session: &BrowserSession,
        binding: &SettingsBinding<'_>,
        new_email: &str,
        confirm_url: &str,
        ctx: &RequestContext,
    ) -> Result<(), AccountError> {
        self.open(tenant.id, session, binding).await?;
        let new_email = normalize_email(new_email).map_err(|_| AccountFailure::InvalidEmail)?;
        let user = self.user(tenant.id, session.user_id).await?;
        if new_email == user.email {
            return Err(AccountFailure::EmailUnchanged.into());
        }
        let users = self.storage.users();
        if users.get_by_email(tenant.id, &new_email).await?.is_some() {
            self.audit()
                .record(
                    tenant.id,
                    AuditActor::user(user.id),
                    AuditAction::EmailChangeRequested,
                    Some(user.id.to_string()),
                    AuditOutcome::Failure,
                    ctx,
                    AuditDetails::reason("email_taken"),
                )
                .await?;
            return Ok(());
        }
        let now = self.clock.now();
        let token = random_token();
        let hash = secret_hash(&token);
        let sealed = self
            .kek
            .seal(
                EMAIL_CHANGE_LINK_PURPOSE,
                &email_change_link_aad(tenant.id, &hash),
                new_email.as_bytes(),
            )
            .map_err(|_| CoreError::Internal("sealing the email-change address failed".into()))?;
        let expires_at = now + EMAIL_CHANGE_TOKEN_TTL;
        let record = NewSelfServiceToken {
            token_hash: SecretHash(hash),
            kind: SelfServiceKind::EmailChange,
            user_id: user.id,
            email: new_email.clone(),
            created_at: now,
            expires_at,
        };
        let mut payload = BTreeMap::new();
        payload.insert("tenant_name".to_owned(), tenant.display_name.clone());
        payload.insert(
            "link".to_owned(),
            format!("{confirm_url}?token={token}.{}", b64url(&sealed)),
        );
        payload.insert("new_email".to_owned(), new_email.clone());
        payload.insert(
            "expires_minutes".to_owned(),
            EMAIL_CHANGE_TOKEN_TTL.whole_minutes().to_string(),
        );
        let mail = NewEmail {
            id: OutboxId::new_v7(),
            to: new_email,
            template: EmailKind::EmailChange.as_str().to_owned(),
            payload: seal_payload(&self.kek, tenant.id, &payload)?,
            created_at: now,
            expires_at,
        };
        users
            .issue_self_service_token(tenant.id, &record, Some(&mail))
            .await?;
        self.audit()
            .record(
                tenant.id,
                AuditActor::user(user.id),
                AuditAction::EmailChangeRequested,
                Some(user.id.to_string()),
                AuditOutcome::Success,
                ctx,
                AuditDetails::empty(),
            )
            .await?;
        Ok(())
    }

    /// Completes an email change from the link token (POST only; no session needed: the token
    /// proves control of the new address and was issued to a recently signed-in user).
    /// Atomically consumes the token, switches the email (verified) and enqueues the
    /// `email_changed` notice to the old address (`UserRepo::complete_email_change`). Another
    /// account holding the address meanwhile is [`AccountFailure::EmailTaken`] and leaves the
    /// token usable. Audited `email_changed`.
    pub async fn complete_email_change(
        &self,
        tenant: &Tenant,
        link_token: &str,
        ctx: &RequestContext,
    ) -> Result<User, AccountError> {
        let invalid = || AccountError::from(AccountFailure::EmailTokenInvalid);
        let (token, sealed) = link_token.trim().split_once('.').ok_or_else(invalid)?;
        if token.is_empty() || token.len() > 128 || sealed.len() > 2048 {
            return Err(invalid());
        }
        let hash = secret_hash(token);
        let sealed = b64url_decode(sealed).map_err(|_| invalid())?;
        let new_email = self
            .kek
            .open(
                EMAIL_CHANGE_LINK_PURPOSE,
                &email_change_link_aad(tenant.id, &hash),
                &sealed,
            )
            .ok()
            .and_then(|raw| String::from_utf8(raw.to_vec()).ok())
            .ok_or_else(invalid)?;
        let now = self.clock.now();
        let mut payload = BTreeMap::new();
        payload.insert("tenant_name".to_owned(), tenant.display_name.clone());
        payload.insert("new_email".to_owned(), new_email);
        let notice = RecoveryNotice {
            id: OutboxId::new_v7(),
            template: EmailKind::EmailChanged.as_str().to_owned(),
            payload: seal_payload(&self.kek, tenant.id, &payload)?,
            created_at: now,
            expires_at: now + NOTICE_EMAIL_TTL,
        };
        let user = match self
            .storage
            .users()
            .complete_email_change(tenant.id, &SecretHash(hash), now, Some(&notice))
            .await
        {
            Ok(Some(user)) => user,
            Ok(None) => return Err(invalid()),
            Err(StorageError::Conflict(_)) => return Err(AccountFailure::EmailTaken.into()),
            Err(e) => return Err(e.into()),
        };
        self.audit()
            .record(
                tenant.id,
                AuditActor::user(user.id),
                AuditAction::EmailChanged,
                Some(user.id.to_string()),
                AuditOutcome::Success,
                ctx,
                AuditDetails::empty(),
            )
            .await?;
        Ok(user)
    }

    /// Sets a new password for the session's user (recent sign-in required; users without a
    /// password set their first one this way). Enforces the policy and the breach check,
    /// stores the hash, revokes every other session when `revoke_others` (through
    /// `SessionRepo::revoke_all_for_user`, which enqueues their back-channel logout deliveries;
    /// the current session stays), enqueues the `password_changed` notice and audits
    /// `password_changed`. Returns the number of sessions revoked.
    #[expect(
        clippy::too_many_arguments,
        reason = "one call per submission; every argument is part of it"
    )]
    pub async fn change_password(
        &self,
        tenant: &Tenant,
        session: &BrowserSession,
        binding: &SettingsBinding<'_>,
        new_password: &SecretString,
        revoke_others: bool,
        deps: &PasswordDeps<'_>,
        ctx: &RequestContext,
    ) -> Result<u64, AccountError> {
        self.open(tenant.id, session, binding).await?;
        let password = new_password.expose_secret();
        if check_password(&deps.policy, password).is_err() {
            let short = password.chars().count() < deps.policy.min_len;
            return Err(if short {
                AccountFailure::PasswordTooShort
            } else {
                AccountFailure::PasswordTooLong
            }
            .into());
        }
        match deps.breach.is_breached(password).await {
            Ok(false) => {}
            Ok(true) => return Err(AccountFailure::PasswordBreached.into()),
            Err(CoreError::Overloaded) => return Err(AccountFailure::Overloaded.into()),
            Err(e) => return Err(e.into()),
        }
        let phc = match deps.hasher.hash(password).await {
            Ok(phc) => phc,
            Err(CoreError::Overloaded) => return Err(AccountFailure::Overloaded.into()),
            Err(e) => return Err(e.into()),
        };
        let user = self.user(tenant.id, session.user_id).await?;
        let users = self.storage.users();
        let had_password = users.password(tenant.id, user.id).await?.is_some();
        let now = self.clock.now();
        if !users.set_password(tenant.id, user.id, &phc, now).await? {
            return Err(CoreError::Forbidden.into());
        }
        let revoked = if revoke_others {
            self.storage
                .sessions()
                .revoke_all_for_user(tenant.id, user.id, Some(session.id), now)
                .await?
        } else {
            0
        };
        let mut payload = BTreeMap::new();
        payload.insert("tenant_name".to_owned(), tenant.display_name.clone());
        payload.insert("email".to_owned(), user.email.clone());
        let notice = NewEmail {
            id: OutboxId::new_v7(),
            to: user.email.clone(),
            template: EmailKind::PasswordChanged.as_str().to_owned(),
            payload: seal_payload(&self.kek, tenant.id, &payload)?,
            created_at: now,
            expires_at: now + NOTICE_EMAIL_TTL,
        };
        self.storage.outbox().enqueue(tenant.id, &notice).await?;
        let reason = if had_password {
            "account_change"
        } else {
            "account_set"
        };
        self.audit()
            .record(
                tenant.id,
                AuditActor::user(user.id),
                AuditAction::PasswordChanged,
                Some(user.id.to_string()),
                AuditOutcome::Success,
                ctx,
                AuditDetails::reason(reason).with(AuditDetails::count("sessions_revoked", revoked)),
            )
            .await?;
        Ok(revoked)
    }
}

/// AAD of the address sealed into an email-change link: tenant id bytes followed by the token
/// hash.
fn email_change_link_aad(tenant: TenantId, token_hash: &[u8; 32]) -> Vec<u8> {
    let mut aad = tenant.0.as_bytes().to_vec();
    aad.extend_from_slice(token_hash);
    aad
}

/// A trimmed name claim: `None` when empty; at most [`PROFILE_FIELD_MAX`] characters and no
/// control characters.
fn profile_field(raw: &str) -> Result<Option<String>, AccountFailure> {
    let value = raw.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.chars().count() > PROFILE_FIELD_MAX || value.chars().any(char::is_control) {
        return Err(AccountFailure::InvalidName);
    }
    Ok(Some(value.to_owned()))
}

/// A trimmed locale claim: `None` when empty, otherwise `^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$`
/// (at most [`PROFILE_FIELD_MAX`] characters).
fn locale_field(raw: &str) -> Result<Option<String>, AccountFailure> {
    let value = raw.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > PROFILE_FIELD_MAX || !is_locale_tag(value) {
        return Err(AccountFailure::InvalidLocale);
    }
    Ok(Some(value.to_owned()))
}

/// `^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$`.
fn is_locale_tag(value: &str) -> bool {
    let mut parts = value.split('-');
    let Some(language) = parts.next() else {
        return false;
    };
    (2..=3).contains(&language.len())
        && language.bytes().all(|b| b.is_ascii_alphabetic())
        && parts.all(|p| (2..=8).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// Seals a pending TOTP secret into flow state (purpose [`SETTINGS_TOTP_PURPOSE`], AAD = the
/// flow id, base64url). Used by the settings flow and by in-flow enrolment at sign-in; the AAD
/// binds it to the one flow.
pub(crate) fn seal_pending_totp(
    kek: &Kek,
    flow: FlowId,
    secret: &TotpSecret,
) -> Result<String, CoreError> {
    kek.seal(
        SETTINGS_TOTP_PURPOSE,
        &settings_totp_aad(flow),
        secret.as_bytes(),
    )
    .map(|sealed| b64url(&sealed))
    .map_err(|_| CoreError::Internal("sealing the pending TOTP secret failed".into()))
}

/// Opens a pending TOTP secret sealed by [`seal_pending_totp`] for `flow`.
pub(crate) fn open_pending_totp(
    kek: &Kek,
    flow: FlowId,
    sealed_b64: &str,
) -> Result<TotpSecret, CoreError> {
    let corrupt = || CoreError::Internal("pending TOTP secret does not open".into());
    let sealed = b64url_decode(sealed_b64).map_err(|_| corrupt())?;
    let raw = kek
        .open(SETTINGS_TOTP_PURPOSE, &settings_totp_aad(flow), &sealed)
        .map_err(|_| corrupt())?;
    TotpSecret::from_bytes(&raw).map_err(|_| corrupt())
}

/// The time step a confirming `code` (whitespace ignored) matches for a pending secret at `now`.
pub(crate) fn pending_totp_step(
    secret: &TotpSecret,
    code: &str,
    now: time::OffsetDateTime,
) -> Option<u64> {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    let unix = u64::try_from(now.unix_timestamp()).ok()?;
    check_code(secret, &code, unix)
}

/// Stores a confirmed TOTP enrolment: the credential (seed sealed under the credential AAD) and a
/// fresh recovery-code set in one storage call, then records the confirming `step` as used (the
/// code cannot sign in later) and audits `totp_enrolled`. Returns the recovery codes (shown
/// once), or `None` if the user already has a TOTP credential.
#[expect(
    clippy::too_many_arguments,
    reason = "shared by the settings flow and the sign-in enrolment; every argument is needed"
)]
pub(crate) async fn create_confirmed_totp(
    storage: &dyn Storage,
    kek: &Kek,
    audit: &AuditService,
    tenant: TenantId,
    user: UserId,
    secret: &TotpSecret,
    step: u64,
    now: time::OffsetDateTime,
    ctx: &RequestContext,
) -> Result<Option<Vec<SecretString>>, CoreError> {
    let id = CredentialId::new_v7();
    let secret_enc = kek
        .seal(TOTP_SEED_PURPOSE, &credential_aad(id), secret.as_bytes())
        .map_err(|_| CoreError::Internal("sealing the TOTP seed failed".into()))?;
    let (codes, hashes) = new_recovery_codes(kek)?;
    let users = storage.users();
    match users
        .create_totp(
            tenant,
            user,
            &NewTotp {
                id,
                secret_enc,
                created_at: now,
            },
            &hashes,
            now,
        )
        .await
    {
        Ok(()) => {}
        Err(StorageError::Conflict(_)) => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    // The confirming code must not also sign the user in later.
    users.advance_totp_step(tenant, user, step, now).await?;
    audit
        .record(
            tenant,
            AuditActor::user(user),
            AuditAction::TotpEnrolled,
            Some(id.to_string()),
            AuditOutcome::Success,
            ctx,
            AuditDetails::credential(CredentialKind::Totp),
        )
        .await?;
    Ok(Some(codes))
}

/// Display data of a TOTP secret: issuer = tenant display name, account = user email.
pub(crate) fn enrolment(
    tenant: &Tenant,
    user: &User,
    secret: &TotpSecret,
) -> Result<TotpEnrolment, CoreError> {
    let issuer = if tenant.display_name.trim().is_empty() {
        tenant.slug.as_str()
    } else {
        tenant.display_name.as_str()
    };
    let uri = otpauth_uri(secret, issuer, &user.email)
        .map_err(|_| CoreError::Internal("building the otpauth URI failed".into()))?;
    Ok(TotpEnrolment {
        otpauth_uri: SecretString::from(uri),
        secret_base32: SecretString::from(secret.to_base32().as_str().to_owned()),
    })
}

/// A fresh recovery-code set: the plaintext codes (shown once) and their peppered hashes.
pub fn new_recovery_codes(
    kek: &Kek,
) -> Result<(Vec<SecretString>, Vec<RecoveryCodeHash>), CoreError> {
    let generated = generate_recovery_codes(RECOVERY_CODE_COUNT)
        .map_err(|_| CoreError::Internal("generating recovery codes failed".into()))?;
    let mut codes = Vec::with_capacity(generated.len());
    let mut hashes = Vec::with_capacity(generated.len());
    for code in &generated {
        let normalized = normalize_recovery_code(code)
            .map_err(|_| CoreError::Internal("generated recovery code is malformed".into()))?;
        hashes.push(RecoveryCodeHash(recovery_code_hash(kek, &normalized)));
        codes.push(SecretString::from(code.as_str().to_owned()));
    }
    Ok((codes, hashes))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn failure_keys_are_unique_and_namespaced() {
        let keys: HashSet<&str> = AccountFailure::ALL.iter().map(|f| f.key()).collect();
        assert_eq!(keys.len(), AccountFailure::ALL.len());
        for f in AccountFailure::ALL {
            assert!(f.key().starts_with("account."), "{f:?}");
        }
        assert_eq!(
            AccountFailure::ReauthRequired.key(),
            "account.reauth_required"
        );
    }

    #[test]
    fn locale_tags_follow_the_pattern() {
        for ok in [
            "en",
            "de",
            "pt-BR",
            "zh-Hant-TW",
            "sr-Latn",
            "es-419",
            "fil",
        ] {
            assert_eq!(locale_field(ok).unwrap().as_deref(), Some(ok), "{ok}");
        }
        assert_eq!(locale_field("  ").unwrap(), None);
        assert_eq!(locale_field(" en ").unwrap().as_deref(), Some("en"));
        for bad in [
            "e",
            "engl",
            "en_US",
            "en-",
            "-en",
            "en-x",
            "en-abcdefghi",
            "12",
            "en US",
            "en-<b>",
            "énglish",
        ] {
            assert_eq!(
                locale_field(bad),
                Err(AccountFailure::InvalidLocale),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn profile_fields_are_trimmed_bounded_and_printable() {
        assert_eq!(profile_field("  Ada  ").unwrap().as_deref(), Some("Ada"));
        assert_eq!(profile_field("").unwrap(), None);
        let max = "é".repeat(PROFILE_FIELD_MAX);
        assert_eq!(profile_field(&max).unwrap().as_deref(), Some(max.as_str()));
        let long = "a".repeat(PROFILE_FIELD_MAX + 1);
        assert_eq!(profile_field(&long), Err(AccountFailure::InvalidName));
        assert_eq!(profile_field("a\u{0}b"), Err(AccountFailure::InvalidName));
        assert_eq!(profile_field("a\nb"), Err(AccountFailure::InvalidName));
    }

    #[test]
    fn email_change_link_aad_binds_tenant_and_token() {
        let kek = Kek::generate();
        let t = TenantId::new_v7();
        let h = secret_hash("token");
        let sealed = kek
            .seal(
                EMAIL_CHANGE_LINK_PURPOSE,
                &email_change_link_aad(t, &h),
                b"new@example.com",
            )
            .unwrap();
        let other_hash = secret_hash("other");
        assert!(
            kek.open(
                EMAIL_CHANGE_LINK_PURPOSE,
                &email_change_link_aad(t, &other_hash),
                &sealed
            )
            .is_err()
        );
        assert!(
            kek.open(
                EMAIL_CHANGE_LINK_PURPOSE,
                &email_change_link_aad(TenantId::new_v7(), &h),
                &sealed
            )
            .is_err()
        );
        assert_eq!(
            kek.open(
                EMAIL_CHANGE_LINK_PURPOSE,
                &email_change_link_aad(t, &h),
                &sealed
            )
            .unwrap()
            .as_slice(),
            b"new@example.com"
        );
    }

    #[test]
    fn recovery_codes_are_ten_distinct_and_hashed_with_the_pepper() {
        let kek = Kek::generate();
        let (codes, hashes) = new_recovery_codes(&kek).unwrap();
        assert_eq!(codes.len(), RECOVERY_CODE_COUNT);
        assert_eq!(hashes.len(), RECOVERY_CODE_COUNT);
        let distinct: HashSet<String> =
            codes.iter().map(|c| c.expose_secret().to_owned()).collect();
        assert_eq!(distinct.len(), RECOVERY_CODE_COUNT);
        for (code, hash) in codes.iter().zip(&hashes) {
            let normalized = normalize_recovery_code(code.expose_secret()).unwrap();
            assert_eq!(hash.0, recovery_code_hash(&kek, &normalized));
            // The hash is not a plain digest of the code: another KEK gives another hash.
            assert_ne!(hash.0, recovery_code_hash(&Kek::generate(), &normalized));
        }
    }

    #[test]
    fn enrolment_uses_tenant_name_and_email() {
        let tenant = Tenant {
            id: TenantId::new_v7(),
            slug: "acme".into(),
            display_name: "Acme".into(),
            host: None,
            settings: crate::model::TenantSettings::default(),
            created_at: time::OffsetDateTime::UNIX_EPOCH,
        };
        let user = User {
            id: UserId::new_v7(),
            tenant_id: tenant.id,
            email: "alice@example.com".into(),
            email_verified: true,
            username: None,
            claims: crate::model::StandardClaims::default(),
            status: crate::model::UserStatus::Active,
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
            last_login_at: None,
        };
        let secret = TotpSecret::generate();
        let e = enrolment(&tenant, &user, &secret).unwrap();
        let uri = e.otpauth_uri.expose_secret();
        assert!(
            uri.starts_with("otpauth://totp/Acme:alice%40example.com?"),
            "{uri}"
        );
        assert!(uri.contains(&format!("secret={}", e.secret_base32.expose_secret())));
        assert_eq!(e.secret_base32.expose_secret(), secret.to_base32().as_str());
        // Debug never shows the secret.
        assert!(!format!("{e:?}").contains(e.secret_base32.expose_secret()));
    }

    #[test]
    fn pending_secret_seal_is_bound_to_the_flow() {
        let kek = Kek::generate();
        let flow = FlowId::new_v7();
        let secret = TotpSecret::generate();
        let sealed = kek
            .seal(
                SETTINGS_TOTP_PURPOSE,
                &settings_totp_aad(flow),
                secret.as_bytes(),
            )
            .unwrap();
        assert!(
            kek.open(
                SETTINGS_TOTP_PURPOSE,
                &settings_totp_aad(FlowId::new_v7()),
                &sealed
            )
            .is_err()
        );
        assert!(
            kek.open(TOTP_SEED_PURPOSE, &settings_totp_aad(flow), &sealed)
                .is_err()
        );
        let state = SettingsState::new(UserId::new_v7()).with_totp_secret(b64url(&sealed));
        let json = state.to_json();
        assert!(!json.contains(secret.to_base32().as_str()));
        assert!(!json.contains(&b64url(secret.as_bytes())));
    }
}
