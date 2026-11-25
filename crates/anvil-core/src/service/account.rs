//! Account self-service for credentials (AUTH-04, AUTH-05, ADM-04): passkey registration, TOTP
//! enrolment with recovery codes, recovery-code regeneration and credential removal, plus the
//! administrator's list/remove used by the management API.
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

use std::sync::Arc;

use anvil_jose::Kek;
use anvil_jose::encoding::{b64url, b64url_decode, random_token, secret_hash};
use anvil_jose::otp::{TotpSecret, check_code, otpauth_uri};
use anvil_jose::recovery_code::{
    generate_recovery_codes, normalize_recovery_code, recovery_code_hash,
};
use secrecy::SecretString;

use super::audit::AuditService;
use super::flow::{BindingError, FLOW_LIFETIME, check_binding};
use crate::error::CoreError;
use crate::flow::settings::{
    SETTINGS_TOTP_PURPOSE, SettingsState, is_recent_auth, normalize_label, settings_totp_aad,
};
use crate::model::{
    AuditAction, AuditActor, AuditDetails, AuditOutcome, BrowserSession, CredentialId,
    CredentialKind, CredentialSummary, Flow, FlowId, FlowKind, NewFlow, NewPasskey, NewTotp,
    RecoveryCodeHash, RequestContext, SecretHash, TOTP_SEED_PURPOSE, Tenant, TenantId, User,
    UserId, credential_aad,
};
use crate::ports::{Clock, PasskeyCeremonies, PasskeyUser, RelyingParty, Storage, StorageError};

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
        }
    }
}

/// Text of an account message key (failures and confirmations). Unknown keys get a generic text.
pub fn message_text(key: &str) -> &'static str {
    match key {
        "account.reauth_required" => {
            "For your security, sign in again before changing how you sign in."
        }
        "account.flow_expired" => "This page expired. Please try again.",
        "account.invalid_label" => "Use a name of at most 64 characters.",
        "account.passkey_failed" => "The passkey could not be registered. Please try again.",
        "account.passkey_exists" => "This passkey is already registered.",
        "account.totp_exists" => "An authenticator app is already set up.",
        "account.totp_not_pending" => "Start the authenticator app setup again.",
        "account.totp_invalid_code" => {
            "That code is not valid. Check the time on your device and try again."
        }
        "account.totp_required" => "Set up an authenticator app first.",
        "account.credential_not_found" => "That sign-in method no longer exists.",
        "account.try_again" => "Another change happened at the same time. Please try again.",
        "account.passkey_registered" => "Passkey added.",
        "account.passkey_removed" => "Passkey removed.",
        "account.totp_removed" => "Authenticator app removed. Your recovery codes were deleted.",
        "account.totp_enrolled" => "Authenticator app set up.",
        "account.recovery_codes_regenerated" => {
            "New recovery codes created. The old codes no longer work."
        }
        _ => "Something went wrong.",
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
        if !is_recent_auth(session.auth_time, now) {
            return Err(AccountFailure::ReauthRequired.into());
        }
        Ok(Opened { flow, state })
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
        let sealed = self
            .kek
            .seal(
                SETTINGS_TOTP_PURPOSE,
                &settings_totp_aad(opened.flow.id),
                secret.as_bytes(),
            )
            .map_err(|_| CoreError::Internal("sealing the pending TOTP secret failed".into()))?;
        let enrolment = enrolment(tenant, &user, &secret)?;
        let next = opened.state.clone().with_totp_secret(b64url(&sealed));
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
        let corrupt = || CoreError::Internal("pending TOTP secret does not open".into());
        let sealed = b64url_decode(sealed_b64).map_err(|_| corrupt())?;
        let raw = self
            .kek
            .open(SETTINGS_TOTP_PURPOSE, &settings_totp_aad(flow), &sealed)
            .map_err(|_| corrupt())?;
        TotpSecret::from_bytes(&raw).map_err(|_| corrupt())
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
        let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        let unix = u64::try_from(now.unix_timestamp()).unwrap_or(0);
        let Some(step) = check_code(&secret, &code, unix) else {
            return Err(AccountFailure::TotpInvalidCode.into());
        };
        let (next, _) = opened.state.clone().take_totp();
        if !self.swap(tenant.id, &opened, &next).await? {
            return Err(AccountFailure::TotpNotPending.into());
        }
        let id = CredentialId::new_v7();
        let secret_enc = self
            .kek
            .seal(TOTP_SEED_PURPOSE, &credential_aad(id), secret.as_bytes())
            .map_err(|_| CoreError::Internal("sealing the TOTP seed failed".into()))?;
        let (codes, hashes) = new_recovery_codes(&self.kek)?;
        let users = self.storage.users();
        match users
            .create_totp(
                tenant.id,
                session.user_id,
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
            Err(StorageError::Conflict(_)) => return Err(AccountFailure::TotpExists.into()),
            Err(e) => return Err(e.into()),
        }
        // The confirming code must not also sign the user in later.
        users
            .advance_totp_step(tenant.id, session.user_id, step, now)
            .await?;
        self.audit()
            .record(
                tenant.id,
                AuditActor::user(session.user_id),
                AuditAction::TotpEnrolled,
                Some(id.to_string()),
                AuditOutcome::Success,
                ctx,
                AuditDetails::credential(CredentialKind::Totp),
            )
            .await?;
        Ok(codes)
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

/// Display data of a TOTP secret: issuer = tenant display name, account = user email.
fn enrolment(
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

    use secrecy::ExposeSecret as _;

    use super::*;

    #[test]
    fn failure_keys_are_unique_and_have_text() {
        let keys: HashSet<&str> = AccountFailure::ALL.iter().map(|f| f.key()).collect();
        assert_eq!(keys.len(), AccountFailure::ALL.len());
        for f in AccountFailure::ALL {
            assert!(f.key().starts_with("account."));
            assert_ne!(message_text(f.key()), "Something went wrong.", "{f:?}");
        }
        assert_eq!(
            AccountFailure::ReauthRequired.key(),
            "account.reauth_required"
        );
        assert_eq!(message_text("nope"), "Something went wrong.");
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
