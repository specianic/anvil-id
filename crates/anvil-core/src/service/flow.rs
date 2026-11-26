//! Flow service: starts self-service flows and executes the effects planned by the pure flow
//! engine (`flow::engine`) through the ports.
//!
//! # Binding
//!
//! Every flow is bound to two independent random tokens: the flow cookie and the CSRF token
//! (hidden form field). The flow row stores only their SHA-256 hashes. Every submission must
//! present both; they are compared in constant time ([`check_binding`]). A mismatch is
//! [`CoreError::Forbidden`]. Flows expire after [`FLOW_LIFETIME`] (15 minutes); submitting to an
//! expired or unknown flow starts a fresh flow of the same kind that shows `flow.expired`
//! ([`FlowOutcome::Restarted`]).
//!
//! # Enumeration safety
//!
//! - Login: unknown users, blocked users and users without a password run
//!   `PasswordHasher::verify(None, …)` (the dummy hash) and produce the same failure as a wrong
//!   password ([`password_login_result`]).
//! - Recovery request: the response is `recovery.sent` whether or not an account exists; the
//!   request does the same lookup either way and issues a token only for an active user.
//!
//! `CoreError::Overloaded` from the hasher or breach checker renders the form with
//! `service.overloaded`; it is never a bypass.
//!
//! # Passkeys and second factors
//!
//! - A WebAuthn challenge lives in the login flow state ([`FlowService::passkey_options`]) and
//!   is single-use: before an assertion is verified, the state is swapped (compare-and-swap) to
//!   the state without the challenge; a replayed or concurrent finish loses the swap and fails.
//!   The passkey is looked up tenant-scoped by credential id and must belong to the asserted
//!   user handle; its counter advances with a compare-and-swap. A possible clone (counter not
//!   advancing) records `passkey_clone_suspected`. Every passkey failure is the same
//!   [`Failure::PasskeyInvalid`].
//! - A TOTP code is accepted only if its time step is newer than the last accepted one
//!   (`UserRepo::advance_totp_step`). A recovery code is consumed atomically together with its
//!   sealed `recovery_code_used` notification email.
//! - Throttling of attempts is the web layer's job: every [`SubmitResult`] carries the
//!   [`AuthAttempt`] it represents.
//!
//! # MFA policy, enrolment and step-up (AUTH-08)
//!
//! After a correct password, [`Effect::CheckSecondFactor`] reads the flow's authorization
//! request (if it still exists) for the client's MFA policy and the requested `acr`, and applies
//! `flow::login::after_primary_auth` with the tenant's policy (strictest wins). `Required` without
//! a factor moves the login to the enrolment step: a fresh TOTP secret is sealed into the flow
//! state under the flow id (the account page's sealing, `service::account`) and the page shows it
//! ([`FlowOutcome::Enroll`]). The confirming code takes the secret out with a compare-and-swap,
//! creates the credential and recovery codes (shown once on the next page) and signs in with
//! `[pwd, otp, mfa]`. The same step offers a passkey instead
//! ([`FlowService::passkey_enrolment_options`] / [`FlowService::passkey_enrolment_finish`]): the
//! registration state is stored in the flow with a compare-and-swap and taken out with one before
//! the response is verified (abandoned, replayed and cross-flow responses fail); the stored
//! passkey signs in as a passkey sign-in, `[hwk|swk, user, mfa]`.
//!
//! A passkey counts as a second factor (`service::authorize::second_factor_methods`, the one
//! answer for this engine, the step-up path and the authorization decision). At the
//! second-factor step ([`FlowService::passkey_second_factor_options`] /
//! [`FlowService::passkey_second_factor_finish`]) a discoverable challenge is stored in its own
//! field of the flow state and taken out with a compare-and-swap before the assertion is
//! verified; the assertion must come from one of the step user's own passkeys (user handle and
//! credential id checked before any signature check, through the same verification path as the
//! sign-in page's passkey). Success signs in as a passkey sign-in or upgrades the step-up
//! session.
//!
//! [`FlowService::start_login`] starts a step-up flow when the stored request decides
//! `StepUp` for the caller's session: the flow begins at the second-factor (or enrolment) step
//! for the session's user and ends with `SessionRepo::upgrade_auth` on that same session (amr
//! union plus `mfa`, `acr` from it, `auth_time` now), audited `step_up_completed`. The upgrade
//! is refused unless the submitting browser still holds that session and its user is the
//! verified one.
//!
//! # Session switch
//!
//! Signing in rotates the caller's current session. When the current session belongs to
//! another user, it is revoked with `SessionRepo::revoke_with_families` (its token families
//! too; the intent enqueues back-channel logout deliveries) before the new user's session is
//! created, and `session_revoked` is audited with reason `session_switch`.
//!
//! # Upstream sign-in (AUTH-07, AUTH-11)
//!
//! `service::upstream` runs the provider round trip and then hands the established user to
//! `FlowService::upstream_primary`: the same MFA policy applies, a single-factor upstream
//! sign-in gets `[fed]` and a second factor after it `[fed, otp, mfa]`. The provider's return
//! carries neither the flow cookie nor the CSRF token, so a login that needs another form
//! continues in a fresh flow (`FlowService::continue_login`). A login flow holding a pending
//! link (`flow::upstream::PendingLink`) links the waiting identity to the account signed in to
//! there, right before the session is created (`service::upstream::confirm_link`).
//!
//! # Email code and magic link (AUTH-06)
//!
//! [`Effect::SendEmailCode`] does the same work for every address (lookup, a fresh code and link
//! token, their hashes stored in the flow with a compare-and-swap) and enqueues the sealed
//! `login_code` email only for an active user with a verified address (an unverified address is
//! treated like an unknown one); the page is the same either way.
//! [`Effect::VerifyEmailCode`] checks the code against the stored HMAC and stores the verdict with
//! a compare-and-swap (a right code clears the code and the link, so it works once; the fifth
//! wrong code invalidates both). The magic link goes through [`FlowService::email_link`]: bound to
//! the browser by the flow cookie (a POST without it consumes nothing), consumed like a code, and
//! continued like an upstream sign-in (a second factor or enrolment goes on in a fresh flow). Email
//! sign-in is `[otp]` with the pwd `acr`; the effective MFA policy then applies.
//!
//! The tenant settings are independent: `email_otp` puts the code in the email, `magic_link` the
//! link ([`email_code_enabled`] is true when either is on, so email sign-in is offered). The send
//! does the same work in every configuration; the state records what the email carried, and a
//! code is verified only while `email_otp` is on and the email carried one (a link likewise with
//! `magic_link`). Otherwise verify answers `NotFound` before any attempt is counted and the link
//! is rejected without consuming anything.
//!
//! # Audit
//!
//! `login_succeeded`, `login_failed`, `second_factor_failed`, `passkey_clone_suspected`,
//! `recovery_code_used`, `password_changed`, `user_registered` and `email_verified` are
//! recorded right after the corresponding state change. Identifiers are never written to the
//! audit log: a failed login targets the user id when the account exists, otherwise nothing.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use anvil_jose::Kek;
use anvil_jose::email_code::generate_email_code;
use anvil_jose::encoding::{b64url, b64url_decode, ct_eq, random_token, secret_hash};
use anvil_jose::otp::{TotpSecret, check_code};
use anvil_jose::recovery_code::{normalize_recovery_code, recovery_code_hash};
use secrecy::{ExposeSecret as _, SecretString};
use time::{Duration, OffsetDateTime};

use super::account::SettingsBinding;
use super::account::{
    TotpEnrolment, create_confirmed_totp, enrolment, open_pending_totp, pending_totp_step,
    seal_pending_totp,
};
use super::audit::AuditService;
use super::authorize::{mfa_context, second_factor_methods};
use super::saml::SamlService;
use super::session::{NewSessionCookie, SessionService};
use super::upstream::{StartResult, UpstreamService, confirm_link};
use crate::error::CoreError;
use crate::flow::email_code::{self, Check, EmailCodeState};
use crate::flow::engine::{
    AfterPrimary, Effect, EmailKind, Failure, FlowEnv, FlowInput, FlowState, LoginState, LoginStep,
    SecondFactorMethods, SessionAuth, after_primary_auth, enroll_required, on_failure,
    second_factor_required, session_acr_amr, step_up, transition, upgraded_acr_amr,
};
use crate::flow::form::{FormDescription, FormMessage, MessageLevel};
use crate::flow::login::{
    HrdRoute, Identified, IdentifyInput, IdentifyStep, USE_SSO, email_first, form_with,
    identify_input, passkey_enrolment_failed,
    passkey_enrolment_finish as login_passkey_enrolment_finish, passkey_enrolment_user, routed,
    second_factor_passkey_failed, second_factor_passkey_user, take_passkey_enrolment,
    take_second_factor_passkey, with_passkey_enrolment, with_second_factor_passkey,
};
use crate::flow::settings::DEFAULT_PASSKEY_LABEL;
use crate::flow::upstream::upstream_aad;
use crate::model::{
    ActorKind, AuditAction, AuditActor, AuditDetails, AuditOutcome, AuthRequestId, BrowserSession,
    Connection, ConnectionKind, CounterOutcome, CredentialId, CredentialKind, Flow, FlowId,
    FlowKind, NewEmail, NewFlow, NewPasskey, NewPasswordCredential, NewSelfServiceToken, NewUser,
    OrgId, OutboxId, PasskeyCredential, RecoveryCodeHash, RecoveryNotice, RequestContext,
    SecretHash, SelfServiceKind, SessionId, StandardClaims, TOTP_SEED_PURPOSE, Tenant, TenantId,
    TotpCredential, User, UserId, UserStatus, credential_aad, normalize_email, seal_payload,
};
use crate::oauth::decision::{SessionDecision, decide};
use crate::policy::PasswordPolicy;
use crate::policy::home_realm::{self, Route, RoutedDomain};
use crate::policy::mfa::{AcrRequest, MfaRequirement, mfa_requirement};
use crate::policy::return_to::{ReturnTarget, parse_return_target};
use crate::ports::{
    AssertionIdentity, BreachChecker, Clock, PasskeyCeremonies, PasskeyError, PasskeyUser,
    PasswordCheck, PasswordHasher, RelyingParty, Storage, StorageError, VerifiedAssertion,
};
use anvil_jose::otp::TotpSecret as PendingSecret;

/// Lifetime of a self-service flow.
pub const FLOW_LIFETIME: Duration = Duration::minutes(15);
/// Lifetime of an email verification token.
pub const VERIFICATION_TOKEN_TTL: Duration = Duration::hours(24);
/// Lifetime of a recovery token.
pub const RECOVERY_TOKEN_TTL: Duration = Duration::hours(1);
/// How long an informational email (password changed, recovery code used) stays deliverable in
/// the outbox.
pub const NOTICE_EMAIL_TTL: Duration = Duration::hours(24);

/// Per-request context: the resolved tenant, its URLs, its WebAuthn relying party and the
/// request context recorded on sessions and audit events.
#[derive(Debug, Clone, Copy)]
pub struct FlowContext<'a> {
    pub tenant: &'a Tenant,
    pub issuer: &'a str,
    /// `issuer + "/ui"`: base of the self-service pages and of the emailed links.
    pub ui_base: &'a str,
    /// The tenant's relying party (`adapters::passkey::relying_party`). An issuer that cannot
    /// be a relying party (IP-literal host) is an error that only passkey effects propagate;
    /// password sign-in keeps working.
    pub rp: &'a Result<RelyingParty, CoreError>,
    /// Client IP, user agent and request id of the submission.
    pub ctx: &'a RequestContext,
}

impl FlowContext<'_> {
    fn relying_party(&self) -> Result<&RelyingParty, CoreError> {
        self.rp
            .as_ref()
            .map_err(|e| CoreError::Internal(format!("passkeys unavailable: {e}")))
    }
}

/// A newly created flow. `cookie_token` goes into the flow cookie; the form carries the CSRF
/// token.
#[derive(Debug)]
pub struct StartedFlow {
    pub flow_id: FlowId,
    pub cookie_token: SecretString,
    pub form: FormDescription,
    /// A step-up flow: the user of the second-factor or enrolment step it starts at.
    pub factor_user: Option<UserId>,
    /// A step-up flow that starts at enrolment: the pending secret to show.
    pub totp: Option<TotpEnrolment>,
}

/// Result of a submission.
#[derive(Debug)]
pub enum FlowOutcome {
    /// Render the form again. HTTP 400 if it carries an error message, 200 otherwise.
    Render(FormDescription),
    /// Render the enrolment form (form id `mfa-enroll`) with the pending authenticator-app secret.
    Enroll {
        form: FormDescription,
        totp: TotpEnrolment,
    },
    /// The user signed in: set the session cookie and continue (the authorization request, the
    /// login's return target, or the default page when `None`; see [`Continue`]).
    /// `recovery_codes` is non-empty when a second factor was enrolled in this flow: show them
    /// once before continuing.
    SignedIn {
        cookie: NewSessionCookie,
        continue_to: Option<Continue>,
        recovery_codes: Vec<SecretString>,
    },
    /// Step-up completed: the caller's session was upgraded in place (no new cookie). Continue
    /// as for `SignedIn`.
    SteppedUp {
        continue_to: Option<Continue>,
        recovery_codes: Vec<SecretString>,
    },
    /// Show a message page. The flow is finished.
    Message { key: &'static str },
    /// Validated setup input. The caller completes setup with `BootstrapService`.
    SetupSubmitted {
        email: String,
        password: SecretString,
    },
    /// The flow had expired or did not exist: a fresh flow of the same kind was started (set its
    /// cookie) and its form shows `flow.expired`.
    Restarted(StartedFlow),
}

/// An authentication attempt a submission represents, for rate limiting by the web layer.
/// `ident_hash` is the SHA-256 of the normalised identifier ([`identifier_hash`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthAttempt {
    /// Wrong password, unknown, blocked or password-less account (indistinguishable).
    PasswordFailed {
        ident_hash: [u8; 32],
    },
    /// The password was correct (a second factor may still be required).
    PasswordSucceeded {
        ident_hash: [u8; 32],
        user: UserId,
    },
    /// Wrong, replayed or malformed TOTP or recovery code.
    SecondFactorFailed {
        user: UserId,
    },
    SecondFactorSucceeded {
        user: UserId,
    },
    /// Any rejected passkey assertion.
    PasskeyFailed,
    PasskeySucceeded {
        user: UserId,
    },
    /// A sign-in email was requested (sent, or for an unknown address pretended). `subject` is the
    /// rate-limit subject of its code (`flow::email_code::limit_subject`): the user, or a keyed
    /// pseudo id for an address without an account.
    EmailCodeSent {
        subject: UserId,
    },
    /// A wrong email code.
    EmailCodeFailed {
        subject: UserId,
    },
    /// A right email code (`subject` is the user).
    EmailCodeSucceeded {
        subject: UserId,
    },
}

/// SHA-256 of a normalised login identifier (the rate-limit key; never stored or logged).
pub fn identifier_hash(normalized: &str) -> [u8; 32] {
    secret_hash(normalized)
}

/// Outcome of a submission plus the authentication attempt it represents (`None` for
/// submissions that are not an authentication attempt, e.g. registration, invalid input or an
/// overloaded hasher).
#[derive(Debug)]
pub struct SubmitResult {
    pub outcome: FlowOutcome,
    pub attempt: Option<AuthAttempt>,
}

impl SubmitResult {
    fn plain(outcome: FlowOutcome) -> Self {
        Self {
            outcome,
            attempt: None,
        }
    }
}

/// Where a finished sign-in continues (`FlowService::continuation`: the authorization request
/// bound to the flow always wins over a return target).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Continue {
    /// Continue the authorization request (`{issuer}/authorize/continue?request=`).
    Authorize(AuthRequestId),
    /// Return to this allowlisted tenant-relative page (the invitation page).
    Return(ReturnTarget),
}

/// KEK purpose of the login's sealed return target ([`LoginState::return_to_sealed`]; AAD: the
/// tenant and flow ids, as for the other values sealed into flow state).
pub const RETURN_TO_PURPOSE: &str = "anvilid/login-return-to/v1";

/// Seals `target` into the login flow `flow` of `tenant` (base64url).
fn seal_return_target(
    kek: &Kek,
    tenant: TenantId,
    flow: FlowId,
    target: &ReturnTarget,
) -> Result<String, CoreError> {
    kek.seal(
        RETURN_TO_PURPOSE,
        &upstream_aad(tenant, flow),
        target.as_path().as_bytes(),
    )
    .map(|s| b64url(&s))
    .map_err(|_| CoreError::Internal("sealing the return target failed".into()))
}

/// The return target sealed into the stored login flow `flow` of `tenant`. `None` if there is
/// none, or it does not open (another flow or tenant, tampered) or is no longer allowlisted: the
/// sign-in then ends on the signed-in page. The value is never logged.
fn return_target_of(kek: &Kek, tenant: TenantId, flow: &Flow) -> Option<ReturnTarget> {
    let Ok(FlowState::Login(state)) = serde_json::from_str::<FlowState>(&flow.state) else {
        return None;
    };
    let raw = b64url_decode(state.return_to_sealed.as_deref()?).ok()?;
    let plain = kek
        .open(RETURN_TO_PURPOSE, &upstream_aad(tenant, flow.id), &raw)
        .ok()?;
    parse_return_target(std::str::from_utf8(&plain).ok()?)
}

/// Where a sign-in finishing in the stored flow `flow` continues: its authorization request
/// first, otherwise its return target (see [`return_target_of`]).
fn continuation_of(kek: &Kek, tenant: TenantId, flow: &Flow) -> Option<Continue> {
    if let Some(request) = flow.auth_request_id {
        return Some(Continue::Authorize(request));
    }
    return_target_of(kek, tenant, flow).map(Continue::Return)
}

/// Result of [`FlowService::upstream_primary`].
#[derive(Debug)]
pub(crate) enum UpstreamPrimary {
    /// Signed in: set the session cookie and continue.
    SignedIn {
        cookie: NewSessionCookie,
        continue_to: Option<Continue>,
    },
    /// A second factor or enrolment is needed: set the new flow's cookie and render its form.
    Continue(StartedFlow),
}

/// Result of [`FlowService::email_link`].
#[derive(Debug)]
pub enum EmailLinkOutcome {
    /// Signed in (`FlowOutcome::SignedIn`), or the flow had expired (`FlowOutcome::Restarted`).
    Done(FlowOutcome),
    /// A second factor or enrolment is needed: set the new flow's cookie and render its form.
    /// `factor_user` and `totp` are set as for a step-up start.
    Continue(StartedFlow),
    /// The POST came without this flow's cookie (another browser): nothing was consumed.
    OtherBrowser,
    /// The link is used, expired, invalidated or wrong: nothing changed. Message key.
    Rejected(&'static str),
}

/// An org identity provider to start a sign-in at (home-realm discovery). The caller dispatches
/// with [`start_idp`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdpStart {
    /// The connection's slug (the start routes are keyed by slug).
    pub slug: String,
    /// A SAML connection ([`SamlService::start`]); otherwise OIDC ([`UpstreamService::start`]).
    pub saml: bool,
}

impl IdpStart {
    fn of(conn: &Connection) -> Self {
        Self {
            slug: conn.slug.clone(),
            saml: conn.kind() == ConnectionKind::Saml,
        }
    }
}

/// Result of [`FlowService::start_login`].
#[derive(Debug)]
pub enum LoginStart {
    /// Set the flow cookie and render the form.
    Form(StartedFlow),
    /// Set the flow cookie and start the sign-in at `idp` right away (bound to `started`): the
    /// request's `login_hint` routed to an org IdP, or its `organization` names an org with
    /// exactly one enabled enterprise connection.
    Idp { started: StartedFlow, idp: IdpStart },
}

/// Result of [`FlowService::identify`].
#[derive(Debug)]
pub enum IdentifyOutcome {
    /// Render (or restart) as for a submission.
    Done(Box<FlowOutcome>),
    /// Start the sign-in at the org's IdP with the same flow binding ([`start_idp`]).
    StartIdp(IdpStart),
}

/// Starts a sign-in at an org IdP chosen by home-realm discovery: SAML connections through
/// [`SamlService::start`] (which refuses while `saml_experimental` is off), every other kind
/// through [`UpstreamService::start`]. The one dispatch by connection kind.
pub async fn start_idp(
    idp: &IdpStart,
    upstream: &UpstreamService<'_>,
    saml: &SamlService<'_>,
    cx: &FlowContext<'_>,
    binding: &SettingsBinding<'_>,
    current: Option<&BrowserSession>,
) -> Result<StartResult, CoreError> {
    if idp.saml {
        saml.start(cx, binding, &idp.slug).await
    } else {
        upstream.start(cx, binding, &idp.slug, current).await
    }
}

/// Why a submission does not match its flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingError {
    /// Missing or wrong flow cookie, or wrong CSRF token.
    Forbidden,
    /// The flow has expired.
    Expired,
}

/// Checks that a submission belongs to `flow`: unexpired, with the flow cookie and the CSRF
/// token whose hashes the flow stores. Both hashes are compared in constant time and both are
/// always compared.
pub fn check_binding(
    flow: &Flow,
    cookie_token: Option<&str>,
    csrf_token: &str,
    now: OffsetDateTime,
) -> Result<(), BindingError> {
    if flow.expires_at <= now {
        return Err(BindingError::Expired);
    }
    let Some(cookie) = cookie_token else {
        return Err(BindingError::Forbidden);
    };
    let cookie_ok = ct_eq(&secret_hash(cookie), flow.cookie_hash.as_bytes());
    let csrf_ok = ct_eq(&secret_hash(csrf_token), flow.csrf_hash.as_bytes());
    if cookie_ok & csrf_ok {
        Ok(())
    } else {
        Err(BindingError::Forbidden)
    }
}

/// Maps a password check to the login result. Every credential failure (no such user, blocked,
/// no password, wrong password) is the same [`Failure::InvalidCredentials`]. A `valid` check
/// without a stored password is never accepted.
pub fn password_login_result(
    user: Option<User>,
    had_password: bool,
    check: PasswordCheck,
    require_verified_email: bool,
) -> Result<User, Failure> {
    match user {
        Some(u) if had_password && check.valid && u.status == UserStatus::Active => {
            if require_verified_email && !u.email_verified {
                Err(Failure::EmailNotVerified)
            } else {
                Ok(u)
            }
        }
        _ => Err(Failure::InvalidCredentials),
    }
}

/// The stored passkey a discoverable assertion may be verified against: it must exist in the
/// tenant (the lookup is tenant-scoped) and belong to the asserted user handle. `None` → the
/// assertion is rejected before any signature check.
pub fn bound_passkey(
    identity: &AssertionIdentity,
    found: Option<PasskeyCredential>,
) -> Option<PasskeyCredential> {
    found.filter(|pk| pk.user_id == identity.user_id && pk.credential_id == identity.credential_id)
}

/// Request options (`navigator.credentials.get` JSON) with `publicKey.allowCredentials` set to
/// `passkeys` (base64url credential ids), replacing whatever list the options carried. Used at the
/// second-factor step, where the user is known: it narrows the browser's passkey picker and is not
/// a security check (the finish verifies ownership). `Internal` if the options are not an object
/// with a `publicKey` object.
fn with_allow_credentials(
    options_json: &str,
    passkeys: &[PasskeyCredential],
) -> Result<String, CoreError> {
    let malformed = || CoreError::Internal("passkey request options are malformed".into());
    let mut options: serde_json::Value =
        serde_json::from_str(options_json).map_err(|_| malformed())?;
    let public_key = options
        .get_mut("publicKey")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(malformed)?;
    let allow = passkeys
        .iter()
        .map(|pk| serde_json::json!({ "type": "public-key", "id": b64url(&pk.credential_id) }))
        .collect();
    public_key.insert("allowCredentials".into(), serde_json::Value::Array(allow));
    serde_json::to_string(&options).map_err(|_| malformed())
}

/// The time step a TOTP `code` matches for the sealed credential at `now`, if any. Whitespace in
/// the code is ignored. Replay protection (step newer than the last accepted) is done by the
/// caller with `UserRepo::advance_totp_step`.
pub fn totp_step(
    kek: &Kek,
    totp: &TotpCredential,
    code: &str,
    now: OffsetDateTime,
) -> Result<Option<u64>, CoreError> {
    let seed = kek
        .open(
            TOTP_SEED_PURPOSE,
            &credential_aad(totp.id),
            &totp.secret_enc,
        )
        .map_err(|_| CoreError::Internal("TOTP seed could not be opened".into()))?;
    let secret = TotpSecret::from_bytes(&seed)
        .map_err(|_| CoreError::Internal("stored TOTP seed is invalid".into()))?;
    let Ok(unix) = u64::try_from(now.unix_timestamp()) else {
        return Ok(None);
    };
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    Ok(check_code(&secret, &code, unix))
}

/// The stored hash of a recovery code as typed by the user; `None` if it cannot be a recovery
/// code.
pub fn recovery_code_lookup(kek: &Kek, input: &str) -> Option<RecoveryCodeHash> {
    let normalized = normalize_recovery_code(input).ok()?;
    Some(RecoveryCodeHash(recovery_code_hash(kek, &normalized)))
}

/// Binds an engine form to a flow: absolute action URL and the real CSRF token.
pub fn bind_form(
    mut form: FormDescription,
    cx: &FlowContext<'_>,
    flow_id: FlowId,
    csrf_token: &str,
) -> FormDescription {
    form.action = format!("{}/{}?flow={}", cx.ui_base, form.action, flow_id);
    form.csrf_token = csrf_token.to_owned();
    form
}

/// Executes self-service flows.
pub struct FlowService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
    pub hasher: Arc<dyn PasswordHasher>,
    pub breach: Arc<dyn BreachChecker>,
    pub policy: PasswordPolicy,
    /// Seals outbox email payloads (verification and recovery links carry single-use tokens)
    /// and opens TOTP seeds.
    pub kek: Arc<Kek>,
    /// WebAuthn ceremonies (webauthn-rs adapter in the web layer).
    pub passkeys: Arc<dyn PasskeyCeremonies>,
    /// The operator flag `saml_experimental`: while off, a domain routed to a SAML connection is
    /// treated as not routed (local sign-in).
    pub saml_enabled: bool,
}

enum Step {
    Continue,
    Fail(Failure),
    Done(Box<FlowOutcome>),
    /// The established user must present a second factor.
    SecondFactor(SecondFactorMethods),
    /// The established user must enrol a second factor.
    Enroll,
}

/// Per-submission execution state threaded through the effect runner.
struct Exec<'a> {
    flow: &'a Flow,
    /// The flow state after the transition, encoded (the swap target of `FinishPasskey`).
    state_json: &'a str,
    current_session: Option<SessionId>,
    /// The user established by the last successful effect.
    subject: Option<User>,
    attempt: Option<AuthAttempt>,
    /// Login method for the audit log (`password`, `totp`, `recovery_code`, `passkey`).
    method: &'static str,
    passkey_backup_eligible: bool,
    /// Recovery codes of a second factor enrolled in this submission.
    recovery_codes: Vec<SecretString>,
    /// The submitted CSRF token (binds forms an effect renders itself).
    csrf_token: &'a str,
}

enum Loaded {
    Flow(Flow, FlowState),
    Restarted(FlowOutcome),
}

impl FlowService {
    fn env(&self, cx: &FlowContext<'_>) -> FlowEnv {
        FlowEnv {
            registration: cx.tenant.settings.registration,
            require_verified_email: cx.tenant.settings.require_verified_email,
            policy: self.policy,
            email_code: email_code_enabled(cx.tenant),
        }
    }

    fn sessions(&self) -> SessionService {
        SessionService {
            storage: self.storage.clone(),
            clock: self.clock.clone(),
        }
    }

    fn audit(&self) -> AuditService {
        AuditService {
            storage: self.storage.clone(),
            clock: self.clock.clone(),
        }
    }

    /// Records an event about `user` (actor and target) with the submission's request context.
    async fn audit_user(
        &self,
        cx: &FlowContext<'_>,
        action: AuditAction,
        user: UserId,
        outcome: AuditOutcome,
        details: AuditDetails,
    ) -> Result<(), CoreError> {
        self.audit()
            .record(
                cx.tenant.id,
                AuditActor::user(user),
                action,
                Some(user.to_string()),
                outcome,
                cx.ctx,
                details,
            )
            .await
    }

    /// `login_failed`: anonymous actor (the caller is not authenticated); the target is the
    /// account when it exists.
    async fn audit_login_failed(
        &self,
        cx: &FlowContext<'_>,
        target: Option<UserId>,
        details: AuditDetails,
    ) -> Result<(), CoreError> {
        self.audit()
            .record(
                cx.tenant.id,
                AuditActor::anonymous(ActorKind::User),
                AuditAction::LoginFailed,
                target.map(|u| u.to_string()),
                AuditOutcome::Failure,
                cx.ctx,
                details,
            )
            .await
    }

    /// Starts a flow. For verification and recovery, `token` (from the emailed link) is placed
    /// in a hidden field unvalidated; it is only consumed when the form is submitted.
    pub async fn start(
        &self,
        cx: &FlowContext<'_>,
        kind: FlowKind,
        auth_request: Option<AuthRequestId>,
        token: Option<String>,
    ) -> Result<StartedFlow, CoreError> {
        let (state, form) = self.initial(cx, kind, token).await?;
        self.create_flow(cx, &state, form, auth_request).await
    }

    /// The initial state and form of a flow of `kind`. A login of a tenant with a routable
    /// domain ([`Self::email_first_enabled`]) starts at the email-first page; every other login
    /// keeps the combined form.
    async fn initial(
        &self,
        cx: &FlowContext<'_>,
        kind: FlowKind,
        token: Option<String>,
    ) -> Result<(FlowState, FormDescription), CoreError> {
        if kind == FlowKind::Login && self.email_first_enabled(cx.tenant.id).await? {
            let (state, form) = email_first();
            return Ok((FlowState::Login(state), form));
        }
        FlowState::initial(kind, token, &self.env(cx))
    }

    /// The form a new login of this tenant starts with (the same decision [`Self::start`] makes:
    /// email-first in a tenant with a routable domain, the combined form otherwise). No flow is
    /// created; the web layer renders it on pages answered before the flow runs (brute-force
    /// lock, CAPTCHA demand), so it never decides email-first itself.
    pub async fn initial_login_form(
        &self,
        cx: &FlowContext<'_>,
    ) -> Result<FormDescription, CoreError> {
        let (_, form) = self.initial(cx, FlowKind::Login, None).await?;
        Ok(form)
    }

    /// Whether the tenant's sign-in asks for the email first: at least one candidate routing
    /// connection ([`OrgRepo::routing_connections`](crate::ports::OrgRepo::routing_connections))
    /// can route by the same flag-aware rule as home-realm routing ([`Self::idp_routable`]). A
    /// tenant whose only route is a SAML connection while `saml_experimental` is off keeps the
    /// combined form.
    async fn email_first_enabled(&self, tenant: TenantId) -> Result<bool, CoreError> {
        Ok(self
            .storage
            .organizations()
            .routing_connections(tenant)
            .await?
            .iter()
            .any(|c| self.idp_routable(c)))
    }

    /// Whether an org connection can be a home-realm target: enabled, owned by an org, OIDC (or
    /// SAML while `saml_experimental` is on).
    fn idp_routable(&self, conn: &Connection) -> bool {
        conn.enabled
            && conn.org_id.is_some()
            && match conn.kind() {
                ConnectionKind::Oidc => true,
                ConnectionKind::Saml => self.saml_enabled,
                _ => false,
            }
    }

    /// Routes `email` by its domain only ([`home_realm::route`] over
    /// [`OrgRepo::routed_domain`](crate::ports::OrgRepo::routed_domain)); no account is looked
    /// up, so the answer is the same for every address of a domain. The IdP to start comes along
    /// for a routed domain.
    async fn hrd_route(
        &self,
        tenant: TenantId,
        email: &str,
    ) -> Result<(HrdRoute, Option<IdpStart>), CoreError> {
        let Some(domain) = home_realm::email_domain(email) else {
            return Ok((HrdRoute::Local, None));
        };
        let Some((claim, conn)) = self
            .storage
            .organizations()
            .routed_domain(tenant, &domain)
            .await?
        else {
            return Ok((HrdRoute::Local, None));
        };
        if !self.idp_routable(&conn) || conn.org_id != Some(claim.org_id) {
            return Ok((HrdRoute::Local, None));
        }
        let routed: Vec<RoutedDomain> = RoutedDomain::from_org_domain(&claim).into_iter().collect();
        match home_realm::route(email, &routed) {
            Route::Sso(target) if target.connection_id == conn.id => Ok((
                HrdRoute::Sso {
                    connection_id: conn.id,
                    allow_local_password: claim.allow_local_password,
                },
                Some(IdpStart::of(&conn)),
            )),
            _ => Ok((HrdRoute::Local, None)),
        }
    }

    /// Whether local sign-in (password, email code, magic link) is refused for `email`: its
    /// domain routes to an org IdP and the org turned local passwords off (decision Q6/Q7).
    /// Decided from the domain only. Passkeys are not affected (account-bound and
    /// phishing-resistant).
    async fn local_sign_in_refused(
        &self,
        tenant: TenantId,
        email: &str,
    ) -> Result<bool, CoreError> {
        Ok(matches!(
            self.hrd_route(tenant, email).await?.0,
            HrdRoute::Sso {
                allow_local_password: false,
                ..
            }
        ))
    }

    /// The refusal of a local sign-in for a domain that forces SSO: the current step's form with
    /// [`USE_SSO`], audited `login_failed` (reason `sso_required`, no target: no account was
    /// looked up).
    async fn refuse_local(
        &self,
        cx: &FlowContext<'_>,
        exec: &Exec<'_>,
        state: &FlowState,
        method: &'static str,
    ) -> Result<Step, CoreError> {
        let FlowState::Login(s) = state else {
            return Err(CoreError::Internal("local sign-in outside a login".into()));
        };
        self.audit_login_failed(
            cx,
            None,
            AuditDetails::login(method).with(AuditDetails::reason("sso_required")),
        )
        .await?;
        let form = form_with(s, vec![FormMessage::error(USE_SSO)]);
        let outcome = self
            .render(cx, exec.flow, exec.csrf_token, state, form)
            .await?;
        Ok(Step::Done(Box::new(outcome)))
    }

    /// The single enabled, routable connection of the org named by an `organization` request
    /// parameter (canonical id first, then the exact slug). `None` for an unknown org, or none or
    /// several connections.
    async fn org_single_connection(
        &self,
        tenant: TenantId,
        requested: &str,
    ) -> Result<Option<Connection>, CoreError> {
        let orgs = self.storage.organizations();
        let org = match uuid::Uuid::parse_str(requested) {
            Ok(id) if id.hyphenated().to_string() == requested => {
                orgs.get(tenant, OrgId(id)).await?
            }
            _ => orgs.get_by_slug(tenant, requested).await?,
        };
        let Some(org) = org else {
            return Ok(None);
        };
        let mut usable: Vec<Connection> = self
            .storage
            .connections()
            .list_for_org(tenant, org.id)
            .await?
            .into_iter()
            .filter(|c| self.idp_routable(c))
            .collect();
        Ok(match usable.len() {
            1 => usable.pop(),
            _ => None,
        })
    }

    /// The email-first page or the single-sign-on choice was submitted (`POST
    /// /ui/login/identify?flow=`). Routing uses the email's domain only. Errors: `Forbidden`
    /// (binding), `InvalidRequest` (not a login flow).
    pub async fn identify(
        &self,
        cx: &FlowContext<'_>,
        flow_id: FlowId,
        cookie_token: Option<&str>,
        csrf_token: &str,
        input: IdentifyInput,
    ) -> Result<IdentifyOutcome, CoreError> {
        let (flow, state) = match self
            .load(cx, flow_id, cookie_token, csrf_token, FlowKind::Login)
            .await?
        {
            Loaded::Flow(f, s) => (f, s),
            Loaded::Restarted(outcome) => return Ok(IdentifyOutcome::Done(Box::new(outcome))),
        };
        let FlowState::Login(state) = state else {
            return Err(CoreError::InvalidRequest("not a sign-in flow".into()));
        };
        let (state, route, idp, chose_sso) = match identify_input(state, input) {
            IdentifyStep::Render(state, form) => {
                let outcome = self
                    .render(cx, &flow, csrf_token, &FlowState::Login(state), form)
                    .await?;
                return Ok(IdentifyOutcome::Done(Box::new(outcome)));
            }
            IdentifyStep::Route {
                state,
                email,
                chose_sso,
            } => {
                let (route, idp) = self.hrd_route(cx.tenant.id, &email).await?;
                (state, route, idp, chose_sso)
            }
        };
        match (routed(state, route, chose_sso), idp) {
            (Identified::Render(b), _) => {
                let (state, form) = *b;
                let outcome = self
                    .render(cx, &flow, csrf_token, &FlowState::Login(state), form)
                    .await?;
                Ok(IdentifyOutcome::Done(Box::new(outcome)))
            }
            (Identified::StartIdp(_), Some(idp)) => Ok(IdentifyOutcome::StartIdp(idp)),
            (Identified::StartIdp(_), None) => Err(CoreError::Internal(
                "home-realm route without a connection".into(),
            )),
        }
    }

    async fn create_flow(
        &self,
        cx: &FlowContext<'_>,
        state: &FlowState,
        form: FormDescription,
        auth_request: Option<AuthRequestId>,
    ) -> Result<StartedFlow, CoreError> {
        self.create_flow_with_id(cx, FlowId::new_v7(), state, form, auth_request)
            .await
    }

    /// [`Self::create_flow`] with a chosen id (a pending enrolment secret is sealed under it
    /// before the flow is stored).
    pub(crate) async fn create_flow_with_id(
        &self,
        cx: &FlowContext<'_>,
        id: FlowId,
        state: &FlowState,
        form: FormDescription,
        auth_request: Option<AuthRequestId>,
    ) -> Result<StartedFlow, CoreError> {
        let now = self.clock.now();
        let cookie = random_token();
        let csrf = random_token();
        let new = NewFlow {
            id,
            kind: state.kind(),
            state: encode_state(state)?,
            csrf_hash: SecretHash(secret_hash(&csrf)),
            cookie_hash: SecretHash(secret_hash(&cookie)),
            auth_request_id: auth_request,
            created_at: now,
            expires_at: now + FLOW_LIFETIME,
        };
        self.storage.flows().create(cx.tenant.id, &new).await?;
        Ok(StartedFlow {
            flow_id: new.id,
            cookie_token: SecretString::from(cookie),
            form: bind_form(form, cx, new.id, &csrf),
            factor_user: None,
            totp: None,
        })
    }

    async fn restart(
        &self,
        cx: &FlowContext<'_>,
        kind: FlowKind,
        auth_request: Option<AuthRequestId>,
    ) -> Result<FlowOutcome, CoreError> {
        let (state, mut form) = self.initial(cx, kind, None).await?;
        form.messages
            .insert(0, FormMessage::new(MessageLevel::Error, "flow.expired"));
        let started = self.create_flow(cx, &state, form, auth_request).await?;
        Ok(FlowOutcome::Restarted(started))
    }

    /// Loads a flow for a submission and checks its binding. An unknown or expired flow is
    /// restarted (kind of the input, or of the expired flow).
    async fn load(
        &self,
        cx: &FlowContext<'_>,
        flow_id: FlowId,
        cookie_token: Option<&str>,
        csrf_token: &str,
        kind: FlowKind,
    ) -> Result<Loaded, CoreError> {
        let now = self.clock.now();
        let Some(flow) = self.storage.flows().get(cx.tenant.id, flow_id, now).await? else {
            return Ok(Loaded::Restarted(self.restart(cx, kind, None).await?));
        };
        // A flow this engine does not run (settings, consent: another service owns their
        // state) is treated like an unknown flow, never decoded.
        if !engine_kind(flow.kind) {
            return Ok(Loaded::Restarted(self.restart(cx, kind, None).await?));
        }
        match check_binding(&flow, cookie_token, csrf_token, now) {
            Ok(()) => {}
            Err(BindingError::Expired) => {
                let outcome = self.restart(cx, flow.kind, flow.auth_request_id).await?;
                return Ok(Loaded::Restarted(outcome));
            }
            Err(BindingError::Forbidden) => return Err(CoreError::Forbidden),
        }
        let state: FlowState = serde_json::from_str(&flow.state)
            .map_err(|e| CoreError::Internal(format!("corrupt flow state: {e}")))?;
        if state.kind() != flow.kind {
            return Err(CoreError::Internal("flow state kind mismatch".into()));
        }
        Ok(Loaded::Flow(flow, state))
    }

    /// Creates a discoverable passkey challenge for a login flow and returns the options JSON
    /// for `navigator.credentials.get`. The challenge's server-side state replaces any earlier
    /// one in the flow state (compare-and-swap). Errors: `Forbidden` (binding),
    /// `InvalidRequest` (expired or unknown flow, not a login flow in its identify step, or a
    /// concurrent change of the flow), `Internal` (the issuer cannot be a relying party).
    pub async fn passkey_options(
        &self,
        cx: &FlowContext<'_>,
        flow_id: FlowId,
        cookie_token: Option<&str>,
        csrf_token: &str,
    ) -> Result<String, CoreError> {
        let (flow, state) = match self
            .load(cx, flow_id, cookie_token, csrf_token, FlowKind::Login)
            .await?
        {
            Loaded::Flow(f, s) => (f, s),
            Loaded::Restarted(_) => {
                return Err(CoreError::InvalidRequest("the sign-in flow expired".into()));
            }
        };
        let (state, effects) = transition(state, FlowInput::PasskeyOptions, &self.env(cx));
        match (state, effects.as_slice()) {
            (FlowState::Login(mut s), [Effect::StartPasskey]) => {
                let challenge = self.passkeys.start_discoverable(cx.relying_party()?)?;
                s.passkey_challenge = Some(challenge.state_json);
                let json = encode_state(&FlowState::Login(s))?;
                let swapped = self
                    .storage
                    .flows()
                    .swap_state(cx.tenant.id, flow.id, &flow.state, &json, self.clock.now())
                    .await?;
                if !swapped {
                    return Err(CoreError::InvalidRequest(
                        "the sign-in flow changed concurrently".into(),
                    ));
                }
                Ok(challenge.options_json)
            }
            _ => Err(CoreError::InvalidRequest(
                "passkey sign-in is not available in this step".into(),
            )),
        }
    }

    /// Creates passkey registration options for the user of a login flow in its enrolment step
    /// (MFA policy `required`, no second factor yet) and returns the creation options JSON for
    /// `navigator.credentials.create`. The registration state replaces any earlier one in the
    /// flow state (compare-and-swap). The user's existing passkeys are excluded. Errors:
    /// `Forbidden` (binding), `InvalidRequest` (expired or unknown flow, not in the enrolment
    /// step, inactive user, or a concurrent change of the flow), `Internal` (the issuer cannot
    /// be a relying party).
    pub async fn passkey_enrolment_options(
        &self,
        cx: &FlowContext<'_>,
        flow_id: FlowId,
        cookie_token: Option<&str>,
        csrf_token: &str,
    ) -> Result<String, CoreError> {
        let unavailable =
            || CoreError::InvalidRequest("passkey enrolment is not available in this step".into());
        let (flow, state) = match self
            .load(cx, flow_id, cookie_token, csrf_token, FlowKind::Login)
            .await?
        {
            Loaded::Flow(f, FlowState::Login(s)) => (f, s),
            Loaded::Flow(..) => return Err(unavailable()),
            Loaded::Restarted(_) => {
                return Err(CoreError::InvalidRequest("the sign-in flow expired".into()));
            }
        };
        let tenant = cx.tenant.id;
        let Some(user_id) = passkey_enrolment_user(&state) else {
            return Err(unavailable());
        };
        let Some(user) = self.second_factor_user(tenant, user_id).await? else {
            return Err(unavailable());
        };
        let exclude: Vec<Vec<u8>> = self
            .storage
            .users()
            .passkeys(tenant, user.id)
            .await?
            .into_iter()
            .map(|p| p.credential_id)
            .collect();
        let challenge = self.passkeys.start_registration(
            cx.relying_party()?,
            &passkey_user(&user),
            &exclude,
        )?;
        let next = with_passkey_enrolment(state, challenge.state_json);
        let json = encode_state(&FlowState::Login(next))?;
        if !self
            .storage
            .flows()
            .swap_state(tenant, flow.id, &flow.state, &json, self.clock.now())
            .await?
        {
            return Err(CoreError::InvalidRequest(
                "the sign-in flow changed concurrently".into(),
            ));
        }
        Ok(challenge.options_json)
    }

    /// Completes an in-flow passkey enrolment with the registration response from
    /// `navigator.credentials.create`. The pending registration state is taken out of the flow
    /// with a compare-and-swap before the response is verified, so it is used once: an
    /// abandoned (superseded), replayed, cross-flow or invalid response, or one with no pending
    /// registration (the user went the authenticator-app way), renders the enrolment form with
    /// `mfa_enroll.passkey_failed` and stores nothing. A verified passkey is stored for the
    /// step's user (audited `passkey_registered`) and the user is signed in like a passkey
    /// sign-in (`[hwk|swk, user, mfa]`, MFA `acr`), or the step-up session is upgraded.
    /// `current_session` is handled as in [`Self::submit`].
    pub async fn passkey_enrolment_finish(
        &self,
        cx: &FlowContext<'_>,
        flow_id: FlowId,
        cookie_token: Option<&str>,
        csrf_token: &str,
        response_json: &str,
        current_session: Option<SessionId>,
    ) -> Result<SubmitResult, CoreError> {
        let (flow, state) = match self
            .load(cx, flow_id, cookie_token, csrf_token, FlowKind::Login)
            .await?
        {
            Loaded::Flow(f, FlowState::Login(s)) => (f, s),
            Loaded::Flow(f, other) => {
                // Not a login flow: the current form of that flow, unchanged.
                let form = crate::flow::engine::current_form(
                    &other,
                    vec![FormMessage::error("flow.invalid_input")],
                    &self.env(cx),
                );
                let form = bind_form(form, cx, f.id, csrf_token);
                return Ok(SubmitResult::plain(FlowOutcome::Render(form)));
            }
            Loaded::Restarted(outcome) => return Ok(SubmitResult::plain(outcome)),
        };
        let tenant = cx.tenant.id;
        let now = self.clock.now();
        let mut next = state;
        let Some((user_id, registration)) = take_passkey_enrolment(&mut next) else {
            return self
                .passkey_enrolment_refused(cx, &flow, csrf_token, &next, None)
                .await;
        };
        let next_json = encode_state(&FlowState::Login(next.clone()))?;
        // Single use: whoever swaps the challenge out first verifies it; a replayed or
        // concurrent finish loses the swap.
        if !self
            .storage
            .flows()
            .swap_state(tenant, flow.id, &flow.state, &next_json, now)
            .await?
        {
            return self
                .passkey_enrolment_refused(cx, &flow, csrf_token, &next, None)
                .await;
        }
        let Some(user) = self.second_factor_user(tenant, user_id).await? else {
            return self
                .passkey_enrolment_refused(cx, &flow, csrf_token, &next, Some(user_id))
                .await;
        };
        let Ok(registered) =
            self.passkeys
                .finish_registration(cx.relying_party()?, response_json, &registration)
        else {
            return self
                .passkey_enrolment_refused(cx, &flow, csrf_token, &next, Some(user_id))
                .await;
        };
        let new = NewPasskey {
            id: CredentialId::new_v7(),
            credential_id: registered.credential_id,
            passkey_json: registered.passkey_json,
            counter: registered.counter,
            backup_eligible: registered.backup_eligible,
            label: DEFAULT_PASSKEY_LABEL.to_owned(),
            created_at: now,
        };
        match self
            .storage
            .users()
            .create_passkey(tenant, user.id, &new)
            .await
        {
            Ok(()) => {}
            // The credential is already registered (to this or another account).
            Err(StorageError::Conflict(_)) => {
                return self
                    .passkey_enrolment_refused(cx, &flow, csrf_token, &next, Some(user_id))
                    .await;
            }
            Err(e) => return Err(e.into()),
        }
        self.audit()
            .record(
                tenant,
                AuditActor::user(user.id),
                AuditAction::PasskeyRegistered,
                Some(new.id.to_string()),
                AuditOutcome::Success,
                cx.ctx,
                AuditDetails::credential(CredentialKind::Webauthn),
            )
            .await?;
        let env = self.env(cx);
        let mut queue = VecDeque::new();
        let mut exec = Exec {
            flow: &flow,
            state_json: &next_json,
            current_session,
            subject: Some(user),
            attempt: Some(AuthAttempt::PasskeySucceeded { user: user_id }),
            method: "passkey",
            passkey_backup_eligible: registered.backup_eligible,
            recovery_codes: Vec::new(),
            csrf_token,
        };
        let terminal = login_passkey_enrolment_finish(&next);
        match self.run(cx, &terminal, &mut queue, &mut exec, &env).await? {
            Step::Done(outcome) => Ok(SubmitResult {
                outcome: *outcome,
                attempt: exec.attempt,
            }),
            _ => Err(CoreError::Internal(
                "passkey enrolment ended without a session".into(),
            )),
        }
    }

    /// The enrolment form with `mfa_enroll.passkey_failed` (and the pending authenticator-app
    /// secret). Nothing is written: the challenge was already taken out (or never pending), and
    /// a lost swap must not overwrite the winner's state. `user` is audited `login_failed`
    /// (method `passkey_enrolment`) when a registration response was actually checked.
    async fn passkey_enrolment_refused(
        &self,
        cx: &FlowContext<'_>,
        flow: &Flow,
        csrf_token: &str,
        state: &LoginState,
        user: Option<UserId>,
    ) -> Result<SubmitResult, CoreError> {
        if let Some(user) = user {
            self.audit_login_failed(cx, Some(user), AuditDetails::login("passkey_enrolment"))
                .await?;
        }
        let state = FlowState::Login(state.clone());
        let form = match &state {
            FlowState::Login(s) if passkey_enrolment_user(s).is_some() => {
                passkey_enrolment_failed()
            }
            _ => crate::flow::engine::current_form(
                &state,
                vec![FormMessage::error("flow.invalid_input")],
                &self.env(cx),
            ),
        };
        let form = bind_form(form, cx, flow.id, csrf_token);
        let outcome = match self.pending_enrolment(cx, flow.id, &state).await? {
            Some(totp) => FlowOutcome::Enroll { form, totp },
            None => FlowOutcome::Render(form),
        };
        Ok(SubmitResult::plain(outcome))
    }

    /// Creates a discoverable passkey challenge for the second-factor step of a login flow and
    /// returns the options JSON for `navigator.credentials.get`. Only offered when the step's user
    /// is active and has a passkey. The challenge is stored in its own field of the flow state
    /// (`LoginState::second_factor_passkey`, replacing an earlier one, compare-and-swap), never
    /// in the identify step's challenge. Errors: `Forbidden` (binding), `InvalidRequest` (expired
    /// or unknown flow, not in a second-factor step with a passkey, inactive user or no passkey,
    /// or a concurrent change of the flow), `Internal` (the issuer cannot be a relying party).
    ///
    /// The options list the step user's passkeys in `publicKey.allowCredentials`, so the browser
    /// offers only that user's passkeys. The list narrows the picker only: ownership is enforced
    /// when the assertion is finished ([`Self::passkey_second_factor_finish`]).
    pub async fn passkey_second_factor_options(
        &self,
        cx: &FlowContext<'_>,
        flow_id: FlowId,
        cookie_token: Option<&str>,
        csrf_token: &str,
    ) -> Result<String, CoreError> {
        let unavailable =
            || CoreError::InvalidRequest("passkey is not available in this step".into());
        let (flow, state) = match self
            .load(cx, flow_id, cookie_token, csrf_token, FlowKind::Login)
            .await?
        {
            Loaded::Flow(f, FlowState::Login(s)) => (f, s),
            Loaded::Flow(..) => return Err(unavailable()),
            Loaded::Restarted(_) => {
                return Err(CoreError::InvalidRequest("the sign-in flow expired".into()));
            }
        };
        let tenant = cx.tenant.id;
        let Some(user_id) = second_factor_passkey_user(&state) else {
            return Err(unavailable());
        };
        let Some(user) = self.second_factor_user(tenant, user_id).await? else {
            return Err(unavailable());
        };
        let passkeys = self.storage.users().passkeys(tenant, user.id).await?;
        if passkeys.is_empty() {
            return Err(unavailable());
        }
        let challenge = self.passkeys.start_discoverable(cx.relying_party()?)?;
        let options_json = with_allow_credentials(&challenge.options_json, &passkeys)?;
        let next =
            with_second_factor_passkey(state, challenge.state_json).ok_or_else(unavailable)?;
        let json = encode_state(&FlowState::Login(next))?;
        if !self
            .storage
            .flows()
            .swap_state(tenant, flow.id, &flow.state, &json, self.clock.now())
            .await?
        {
            return Err(CoreError::InvalidRequest(
                "the sign-in flow changed concurrently".into(),
            ));
        }
        Ok(options_json)
    }

    /// Completes the second-factor step with a passkey assertion from
    /// `navigator.credentials.get`. The pending second-factor challenge is taken out of the flow
    /// with a compare-and-swap before the assertion is verified, so it is used once. The
    /// assertion must name the step user (user handle) and one of that user's stored passkeys;
    /// another user's passkey, an unknown credential, an invalid assertion, a replayed or
    /// cross-flow challenge, a challenge of the identify step, or no pending challenge renders the
    /// second-factor form with `second_factor.passkey_failed`, with no session and no flow-state
    /// change besides the consumed challenge. Success signs in like a passkey sign-in
    /// (`[hwk|swk, user, mfa]`, MFA `acr`) or upgrades the step-up session in place.
    /// `current_session` is handled as in [`Self::submit`].
    pub async fn passkey_second_factor_finish(
        &self,
        cx: &FlowContext<'_>,
        flow_id: FlowId,
        cookie_token: Option<&str>,
        csrf_token: &str,
        response_json: &str,
        current_session: Option<SessionId>,
    ) -> Result<SubmitResult, CoreError> {
        let (flow, state) = match self
            .load(cx, flow_id, cookie_token, csrf_token, FlowKind::Login)
            .await?
        {
            Loaded::Flow(f, FlowState::Login(s)) => (f, s),
            Loaded::Flow(f, other) => {
                let form = crate::flow::engine::current_form(
                    &other,
                    vec![FormMessage::error("flow.invalid_input")],
                    &self.env(cx),
                );
                let form = bind_form(form, cx, f.id, csrf_token);
                return Ok(SubmitResult::plain(FlowOutcome::Render(form)));
            }
            Loaded::Restarted(outcome) => return Ok(SubmitResult::plain(outcome)),
        };
        let tenant = cx.tenant.id;
        let now = self.clock.now();
        let mut next = state;
        let Some((user_id, challenge)) = take_second_factor_passkey(&mut next) else {
            return self
                .passkey_second_factor_refused(cx, &flow, csrf_token, &next, None)
                .await;
        };
        let next_json = encode_state(&FlowState::Login(next.clone()))?;
        // Single use: whoever swaps the challenge out first verifies it; a replayed or
        // concurrent finish loses the swap.
        if !self
            .storage
            .flows()
            .swap_state(tenant, flow.id, &flow.state, &next_json, now)
            .await?
        {
            return self
                .passkey_second_factor_refused(cx, &flow, csrf_token, &next, None)
                .await;
        }
        let refused = Some(user_id);
        let Some(user) = self.second_factor_user(tenant, user_id).await? else {
            return self
                .passkey_second_factor_refused(cx, &flow, csrf_token, &next, refused)
                .await;
        };
        let verified = match self
            .check_assertion(cx, response_json, &challenge, Some(user.id))
            .await?
        {
            AssertionCheck::Verified { passkey, verified }
                if self.record_assertion(cx, &passkey, &verified).await? =>
            {
                verified
            }
            _ => {
                return self
                    .passkey_second_factor_refused(cx, &flow, csrf_token, &next, refused)
                    .await;
            }
        };
        let env = self.env(cx);
        let mut queue = VecDeque::new();
        let mut exec = Exec {
            flow: &flow,
            state_json: &next_json,
            current_session,
            subject: Some(user),
            attempt: Some(AuthAttempt::PasskeySucceeded { user: user_id }),
            method: "passkey",
            passkey_backup_eligible: verified.backup_eligible,
            recovery_codes: Vec::new(),
            csrf_token,
        };
        let terminal = login_passkey_enrolment_finish(&next);
        match self.run(cx, &terminal, &mut queue, &mut exec, &env).await? {
            Step::Done(outcome) => Ok(SubmitResult {
                outcome: *outcome,
                attempt: exec.attempt,
            }),
            _ => Err(CoreError::Internal(
                "second-factor passkey ended without a session".into(),
            )),
        }
    }

    /// The second-factor form with `second_factor.passkey_failed` (another step's form with
    /// `flow.invalid_input`). Nothing is written: the challenge was already taken out (or never
    /// pending), and a lost swap must not overwrite the winner's state. `user` is audited
    /// `login_failed` (method `passkey_second_factor`) when an assertion was actually checked.
    async fn passkey_second_factor_refused(
        &self,
        cx: &FlowContext<'_>,
        flow: &Flow,
        csrf_token: &str,
        state: &LoginState,
        user: Option<UserId>,
    ) -> Result<SubmitResult, CoreError> {
        if let Some(user) = user {
            self.audit_login_failed(cx, Some(user), AuditDetails::login("passkey_second_factor"))
                .await?;
        }
        let form = match state.step {
            LoginStep::SecondFactor { methods, .. } => second_factor_passkey_failed(methods),
            _ => crate::flow::engine::current_form(
                &FlowState::Login(state.clone()),
                vec![FormMessage::error("flow.invalid_input")],
                &self.env(cx),
            ),
        };
        let form = bind_form(form, cx, flow.id, csrf_token);
        let state = FlowState::Login(state.clone());
        let outcome = match self.pending_enrolment(cx, flow.id, &state).await? {
            Some(totp) => FlowOutcome::Enroll { form, totp },
            None => FlowOutcome::Render(form),
        };
        Ok(SubmitResult::plain(outcome))
    }

    /// Submits user input to a flow. `current_session` (the caller's existing session, if any)
    /// is revoked when the user signs in. Passkey options are requested with
    /// [`FlowService::passkey_options`], not here.
    pub async fn submit(
        &self,
        cx: &FlowContext<'_>,
        flow_id: FlowId,
        cookie_token: Option<&str>,
        csrf_token: &str,
        input: FlowInput,
        current_session: Option<SessionId>,
    ) -> Result<SubmitResult, CoreError> {
        if matches!(input, FlowInput::PasskeyOptions) {
            return Err(CoreError::InvalidRequest(
                "passkey options are requested separately".into(),
            ));
        }
        let (flow, state) = match self
            .load(cx, flow_id, cookie_token, csrf_token, input.kind())
            .await?
        {
            Loaded::Flow(f, s) => (f, s),
            Loaded::Restarted(outcome) => return Ok(SubmitResult::plain(outcome)),
        };
        let tenant = cx.tenant.id;
        let env = self.env(cx);
        let (state, effects) = transition(state, input, &env);
        let state_json = encode_state(&state)?;
        let mut queue: VecDeque<Effect> = effects.into();
        let mut exec = Exec {
            flow: &flow,
            state_json: &state_json,
            current_session,
            subject: None,
            attempt: None,
            method: "password",
            passkey_backup_eligible: false,
            recovery_codes: Vec::new(),
            csrf_token,
        };

        while let Some(effect) = queue.pop_front() {
            let outcome = match effect {
                Effect::Render(form) => self.render(cx, &flow, csrf_token, &state, form).await?,
                Effect::Message(key) => {
                    self.storage.flows().delete(tenant, flow.id).await?;
                    FlowOutcome::Message { key }
                }
                effect => match self.run(cx, &effect, &mut queue, &mut exec, &env).await? {
                    Step::Continue => continue,
                    Step::Done(outcome) => *outcome,
                    Step::Fail(failure) => {
                        let mut pending = Vec::with_capacity(queue.len() + 1);
                        pending.push(effect);
                        pending.extend(queue.drain(..));
                        let (state, form) = on_failure(state, &pending, failure, &env);
                        self.render(cx, &flow, csrf_token, &state, form).await?
                    }
                    Step::SecondFactor(methods) => {
                        let (FlowState::Login(mut s), Some(user)) = (state, exec.subject.take())
                        else {
                            return Err(CoreError::Internal(
                                "second factor outside a login with an established user".into(),
                            ));
                        };
                        email_primary(&mut s, exec.method);
                        let (state, form) = second_factor_required(s, user.id, methods);
                        self.render(cx, &flow, csrf_token, &state, form).await?
                    }
                    Step::Enroll => {
                        let (FlowState::Login(mut s), Some(user)) = (state, exec.subject.take())
                        else {
                            return Err(CoreError::Internal(
                                "enrolment outside a login with an established user".into(),
                            ));
                        };
                        email_primary(&mut s, exec.method);
                        let pending =
                            seal_pending_totp(&self.kek, flow.id, &PendingSecret::generate())?;
                        let (state, form) = enroll_required(s, user.id, pending);
                        self.render(cx, &flow, csrf_token, &state, form).await?
                    }
                },
            };
            return Ok(SubmitResult {
                outcome,
                attempt: exec.attempt,
            });
        }
        Err(CoreError::Internal(
            "flow effects ended without a terminal effect".into(),
        ))
    }

    async fn render(
        &self,
        cx: &FlowContext<'_>,
        flow: &Flow,
        csrf_token: &str,
        state: &FlowState,
        form: FormDescription,
    ) -> Result<FlowOutcome, CoreError> {
        let json = encode_state(state)?;
        if json != flow.state {
            self.storage
                .flows()
                .update_state(cx.tenant.id, flow.id, &json, self.clock.now())
                .await?;
        }
        let form = bind_form(form, cx, flow.id, csrf_token);
        match self.pending_enrolment(cx, flow.id, state).await? {
            Some(totp) => Ok(FlowOutcome::Enroll { form, totp }),
            None => Ok(FlowOutcome::Render(form)),
        }
    }

    /// The display data of the pending enrolment of a login in its enrolment step.
    async fn pending_enrolment(
        &self,
        cx: &FlowContext<'_>,
        flow: FlowId,
        state: &FlowState,
    ) -> Result<Option<TotpEnrolment>, CoreError> {
        let FlowState::Login(s) = state else {
            return Ok(None);
        };
        let (LoginStep::Enroll { user_id }, Some(sealed)) = (s.step, s.pending_totp.as_deref())
        else {
            return Ok(None);
        };
        let Some(user) = self.second_factor_user(cx.tenant.id, user_id).await? else {
            return Err(CoreError::Forbidden);
        };
        let secret = open_pending_totp(&self.kek, flow, sealed)?;
        Ok(Some(enrolment(cx.tenant, &user, &secret)?))
    }

    /// Starts a login flow. With an authorization request and a signed-in `current` session
    /// for which the request decides step-up (`oauth::decision::decide`), the flow starts at the
    /// second-factor or enrolment step for the session's user and later upgrades that session
    /// (module docs); otherwise it is a plain [`FlowService::start`] of a login.
    ///
    /// Home-realm discovery (module docs of `flow::login`): an `organization` parameter naming an
    /// org with exactly one enabled enterprise connection starts at that IdP
    /// ([`LoginStart::Idp`]). In a tenant with a routed domain, a `login_hint` that is an email
    /// skips the email page and is routed at once (to the IdP, the single-sign-on choice or the
    /// password step).
    ///
    /// `return_to` (an allowlisted [`ReturnTarget`], the invitation page) is kept only for a login
    /// without an authorization request (the request always wins): it is sealed into the flow
    /// state ([`LoginState::return_to_sealed`]) and every sign-in that finishes the login returns
    /// there ([`Continue::Return`]). A flow restarted after it expired starts without it.
    pub async fn start_login(
        &self,
        cx: &FlowContext<'_>,
        auth_request: Option<AuthRequestId>,
        current: Option<&BrowserSession>,
        return_to: Option<ReturnTarget>,
    ) -> Result<LoginStart, CoreError> {
        let return_to = return_to.filter(|_| auth_request.is_none());
        let return_to = return_to.as_ref();
        if let (Some(request_id), Some(session)) = (auth_request, current)
            && let Some(started) = self.start_step_up(cx, request_id, session).await?
        {
            return Ok(LoginStart::Form(started));
        }
        let tenant = cx.tenant.id;
        let request = match auth_request {
            Some(id) => {
                self.storage
                    .grants()
                    .get_authorization_request(tenant, id, self.clock.now())
                    .await?
            }
            None => None,
        };
        let params = request.as_ref().map(|r| &r.params);
        if let Some(requested) = params.and_then(|p| p.organization.as_deref())
            && let Some(conn) = self.org_single_connection(tenant, requested).await?
        {
            let started = self.start(cx, FlowKind::Login, auth_request, None).await?;
            return Ok(LoginStart::Idp {
                started,
                idp: IdpStart::of(&conn),
            });
        }
        if !self.email_first_enabled(tenant).await? {
            let (state, form) = FlowState::initial(FlowKind::Login, None, &self.env(cx))?;
            let started = self
                .create_login_flow(cx, state, form, auth_request, return_to)
                .await?;
            return Ok(LoginStart::Form(started));
        }
        let (mut state, form) = email_first();
        let hint = params
            .and_then(|p| p.login_hint.as_deref())
            .and_then(|h| normalize_email(h.trim()).ok());
        let Some(email) = hint else {
            let started = self
                .create_login_flow(cx, FlowState::Login(state), form, auth_request, return_to)
                .await?;
            return Ok(LoginStart::Form(started));
        };
        state.identifier = Some(email.clone());
        let (route, idp) = self.hrd_route(tenant, &email).await?;
        Ok(match (routed(state.clone(), route, false), idp) {
            (Identified::Render(b), _) => LoginStart::Form(
                self.create_login_flow(cx, FlowState::Login(b.0), b.1, auth_request, return_to)
                    .await?,
            ),
            (Identified::StartIdp(_), Some(idp)) => LoginStart::Idp {
                started: self
                    .create_login_flow(cx, FlowState::Login(state), form, auth_request, return_to)
                    .await?,
                idp,
            },
            (Identified::StartIdp(_), None) => {
                return Err(CoreError::Internal(
                    "home-realm route without a connection".into(),
                ));
            }
        })
    }

    /// [`Self::create_flow`] for a fresh login: with `return_to` (only without an authorization
    /// request and outside a step-up), the target is sealed under the new flow id first.
    async fn create_login_flow(
        &self,
        cx: &FlowContext<'_>,
        state: FlowState,
        form: FormDescription,
        auth_request: Option<AuthRequestId>,
        return_to: Option<&ReturnTarget>,
    ) -> Result<StartedFlow, CoreError> {
        let id = FlowId::new_v7();
        let state = match (state, return_to) {
            (FlowState::Login(mut s), Some(target))
                if auth_request.is_none() && s.step_up_session.is_none() =>
            {
                s.return_to_sealed = Some(seal_return_target(&self.kek, cx.tenant.id, id, target)?);
                FlowState::Login(s)
            }
            (state, _) => state,
        };
        self.create_flow_with_id(cx, id, &state, form, auth_request)
            .await
    }

    /// Where a sign-in finishing in the stored flow `flow` continues: the authorization request
    /// bound to the flow, else the login's sealed return target, else `None` (the signed-in
    /// page). The one place every sign-in and step-up outcome takes its `continue_to` from.
    fn continuation(&self, cx: &FlowContext<'_>, flow: &Flow) -> Option<Continue> {
        continuation_of(&self.kek, cx.tenant.id, flow)
    }

    async fn start_step_up(
        &self,
        cx: &FlowContext<'_>,
        request_id: AuthRequestId,
        session: &BrowserSession,
    ) -> Result<Option<StartedFlow>, CoreError> {
        let tenant = cx.tenant.id;
        let now = self.clock.now();
        if session.tenant_id != tenant || session.revoked_at.is_some() {
            return Ok(None);
        }
        let Some(user) = self.second_factor_user(tenant, session.user_id).await? else {
            return Ok(None);
        };
        let Some(request) = self
            .storage
            .grants()
            .get_authorization_request(tenant, request_id, now)
            .await?
        else {
            return Ok(None);
        };
        let client = self
            .storage
            .clients()
            .get(tenant, &request.client_id)
            .await?;
        let mfa = mfa_context(
            self.storage.as_ref(),
            cx.tenant,
            client.as_ref(),
            &request.params,
            Some(session),
        )
        .await?;
        let p = &request.params;
        if !matches!(
            decide(
                &p.prompt,
                p.max_age,
                Some(session),
                None,
                request.created_at,
                now,
                mfa
            ),
            SessionDecision::StepUp
        ) {
            return Ok(None);
        }
        let flow_id = FlowId::new_v7();
        let (state, form, totp) =
            match mfa_requirement(mfa.policy, mfa.acr, false, mfa.user_has_factor) {
                MfaRequirement::SecondFactor => {
                    let methods = self.second_factor_methods(tenant, user.id).await?;
                    let (state, form) = step_up(session.id, user.id, methods, None);
                    (state, form, None)
                }
                MfaRequirement::Enroll => {
                    let secret = PendingSecret::generate();
                    let display = enrolment(cx.tenant, &user, &secret)?;
                    let sealed = seal_pending_totp(&self.kek, flow_id, &secret)?;
                    let (state, form) = step_up(
                        session.id,
                        user.id,
                        SecondFactorMethods::default(),
                        Some(sealed),
                    );
                    (state, form, Some(display))
                }
                MfaRequirement::None | MfaRequirement::Unmet => return Ok(None),
            };
        let mut started = self
            .create_flow_with_id(cx, flow_id, &state, form, Some(request_id))
            .await?;
        started.factor_user = Some(user.id);
        started.totp = totp;
        Ok(Some(started))
    }

    /// Continues a login in a fresh flow `id` (new flow cookie and CSRF token) holding `state`,
    /// bound to the old flow's authorization request and carrying its return target (resealed
    /// under `id`); the old flow is deleted. Used after an
    /// upstream callback, which arrives without the flow cookie and the CSRF token.
    pub(crate) async fn continue_login(
        &self,
        cx: &FlowContext<'_>,
        old: Option<&Flow>,
        id: FlowId,
        state: &FlowState,
        form: FormDescription,
    ) -> Result<StartedFlow, CoreError> {
        let auth_request = old.and_then(|f| f.auth_request_id);
        // A login's return target moves with it: opened under the old flow, sealed under the new.
        let carried;
        let state = match (old, state) {
            (Some(old), FlowState::Login(s)) => {
                let mut s = s.clone();
                s.return_to_sealed = match return_target_of(&self.kek, cx.tenant.id, old) {
                    Some(target) => Some(seal_return_target(&self.kek, cx.tenant.id, id, &target)?),
                    None => None,
                };
                carried = FlowState::Login(s);
                &carried
            }
            _ => state,
        };
        let started = self
            .create_flow_with_id(cx, id, state, form, auth_request)
            .await?;
        if let Some(old) = old {
            self.storage.flows().delete(cx.tenant.id, old.id).await?;
        }
        Ok(started)
    }

    /// A fresh login flow whose sign-in form shows the error `key` (bound to the old flow's
    /// authorization request, which is deleted).
    pub(crate) async fn restart_login_with(
        &self,
        cx: &FlowContext<'_>,
        old: Option<&Flow>,
        key: &str,
    ) -> Result<StartedFlow, CoreError> {
        self.restart_login_with_message(cx, old, FormMessage::error(key))
            .await
    }

    /// A fresh login flow whose sign-in form shows `message` first (bound to the old flow's
    /// authorization request, which is deleted).
    pub(crate) async fn restart_login_with_message(
        &self,
        cx: &FlowContext<'_>,
        old: Option<&Flow>,
        message: FormMessage,
    ) -> Result<StartedFlow, CoreError> {
        let (state, mut form) = self.initial(cx, FlowKind::Login, None).await?;
        form.messages.insert(0, message);
        self.continue_login(cx, old, FlowId::new_v7(), &state, form)
            .await
    }

    /// After an upstream sign-in established `user` (`flow::upstream`): applies the MFA policy of
    /// the flow's authorization request ([`after_primary_auth`]) and signs in with `[fed]`, or
    /// continues in a fresh flow at the second-factor or enrolment step (whose second factor
    /// then signs in with `[fed, otp, mfa]`). `state` is the login state without its pending
    /// upstream authorization.
    pub(crate) async fn upstream_primary(
        &self,
        cx: &FlowContext<'_>,
        flow: &Flow,
        state: LoginState,
        user: &User,
        current_session: Option<SessionId>,
    ) -> Result<UpstreamPrimary, CoreError> {
        let state = LoginState {
            federated: true,
            upstream: None,
            pending_link: None,
            step_up_session: None,
            passkey_challenge: None,
            ..state
        };
        self.primary_without_form(
            cx,
            flow,
            state,
            user,
            current_session,
            SessionAuth::Federated,
            "upstream",
        )
        .await
    }

    /// After a primary authentication that arrived without the flow's CSRF token (upstream
    /// callback, magic link): applies the MFA policy of the flow's authorization request and signs
    /// in with `auth`, or continues in a fresh flow at the second-factor or enrolment step. `state`
    /// already carries the primary-method flag the second factor's session auth follows.
    #[expect(
        clippy::too_many_arguments,
        reason = "the primary method's session auth and audit name travel with the flow"
    )]
    async fn primary_without_form(
        &self,
        cx: &FlowContext<'_>,
        flow: &Flow,
        state: LoginState,
        user: &User,
        current_session: Option<SessionId>,
        auth: SessionAuth,
        method: &'static str,
    ) -> Result<UpstreamPrimary, CoreError> {
        let tenant = cx.tenant.id;
        let methods = self.second_factor_methods(tenant, user.id).await?;
        let (policy, acr) = self.flow_mfa(cx, flow).await?;
        match after_primary_auth(policy, acr, methods) {
            AfterPrimary::SignIn => {
                let cookie = self
                    .create_signed_in_session(cx, user.id, auth, false, current_session, method)
                    .await?;
                self.storage.flows().delete(tenant, flow.id).await?;
                Ok(UpstreamPrimary::SignedIn {
                    cookie,
                    continue_to: self.continuation(cx, flow),
                })
            }
            AfterPrimary::SecondFactor(methods) => {
                let (next, form) = second_factor_required(state, user.id, methods);
                let mut started = self
                    .continue_login(cx, Some(flow), FlowId::new_v7(), &next, form)
                    .await?;
                started.factor_user = Some(user.id);
                Ok(UpstreamPrimary::Continue(started))
            }
            AfterPrimary::Enroll => {
                let id = FlowId::new_v7();
                let secret = PendingSecret::generate();
                let display = enrolment(cx.tenant, user, &secret)?;
                let sealed = seal_pending_totp(&self.kek, id, &secret)?;
                let (next, form) = enroll_required(state, user.id, sealed);
                let mut started = self.continue_login(cx, Some(flow), id, &next, form).await?;
                started.factor_user = Some(user.id);
                started.totp = Some(display);
                Ok(UpstreamPrimary::Continue(started))
            }
        }
    }

    /// The magic link of a sign-in email was posted (`POST /ui/login/email-link?flow=`, module
    /// docs). `cookie_token` is the flow cookie (absent in another browser), `csrf_token` the link
    /// page's token (`flow::email_code::link_csrf`). Errors: `Forbidden` (the flow cookie matches
    /// but the CSRF token does not).
    pub async fn email_link(
        &self,
        cx: &FlowContext<'_>,
        flow_id: FlowId,
        cookie_token: Option<&str>,
        csrf_token: &str,
        token: &str,
        current_session: Option<SessionId>,
    ) -> Result<EmailLinkOutcome, CoreError> {
        let tenant = cx.tenant.id;
        let now = self.clock.now();
        let Some(flow) = self.storage.flows().get(tenant, flow_id, now).await? else {
            let outcome = self.restart(cx, FlowKind::Login, None).await?;
            return Ok(EmailLinkOutcome::Done(outcome));
        };
        if flow.kind != FlowKind::Login {
            return Ok(EmailLinkOutcome::Rejected(email_code::LINK_INVALID));
        }
        if flow.expires_at <= now {
            let outcome = self
                .restart(cx, FlowKind::Login, flow.auth_request_id)
                .await?;
            return Ok(EmailLinkOutcome::Done(outcome));
        }
        // Same browser: the flow cookie (SameSite=Strict, sent on the page's own POST).
        let same_browser =
            cookie_token.is_some_and(|c| ct_eq(&secret_hash(c), flow.cookie_hash.as_bytes()));
        if !same_browser {
            return Ok(EmailLinkOutcome::OtherBrowser);
        }
        let expected = email_code::link_csrf(&self.kek, flow.id, token);
        if !ct_eq(expected.as_bytes(), csrf_token.as_bytes()) {
            return Err(CoreError::Forbidden);
        }
        if !cx.tenant.settings.magic_link {
            return Ok(EmailLinkOutcome::Rejected(email_code::LINK_INVALID));
        }
        let state: FlowState = serde_json::from_str(&flow.state)
            .map_err(|e| CoreError::Internal(format!("corrupt flow state: {e}")))?;
        let (state, effects) = transition(
            state,
            FlowInput::EmailLink {
                token: token.to_owned(),
            },
            &self.env(cx),
        );
        let (FlowState::Login(s), Some(Effect::ConsumeEmailLink { .. })) = (state, effects.first())
        else {
            return Ok(EmailLinkOutcome::Rejected(email_code::LINK_INVALID));
        };
        let Some(ec) = s.email_code.as_deref().filter(|ec| ec.link) else {
            return Ok(EmailLinkOutcome::Rejected(email_code::LINK_INVALID));
        };
        // The domain forces SSO now (a link sent before the org turned passwords off): nothing
        // is consumed.
        if self.local_sign_in_refused(tenant, &ec.email).await? {
            self.audit_login_failed(
                cx,
                None,
                AuditDetails::login("magic_link").with(AuditDetails::reason("sso_required")),
            )
            .await?;
            return Ok(EmailLinkOutcome::Rejected(USE_SSO));
        }
        let (check, next) = email_code::check_link(ec, email_code::link_hash(token), now);
        if check != Check::Accepted {
            return Ok(EmailLinkOutcome::Rejected(email_code::LINK_INVALID));
        }
        let mut consumed = s.clone();
        consumed.email_code = Some(Box::new(next));
        if !self
            .storage
            .flows()
            .swap_state(
                tenant,
                flow.id,
                &flow.state,
                &encode_state(&FlowState::Login(consumed))?,
                now,
            )
            .await?
        {
            return Ok(EmailLinkOutcome::Rejected(email_code::LINK_INVALID));
        }
        let user = match ec.user_id {
            Some(u) => self
                .second_factor_user(tenant, u)
                .await?
                .filter(email_code_recipient),
            None => None,
        };
        let Some(user) = user else {
            self.audit_login_failed(cx, ec.user_id, AuditDetails::login("magic_link"))
                .await?;
            return Ok(EmailLinkOutcome::Rejected(email_code::LINK_INVALID));
        };
        let state = LoginState {
            email_primary: true,
            email_code: None,
            passkey_challenge: None,
            ..s
        };
        Ok(
            match self
                .primary_without_form(
                    cx,
                    &flow,
                    state,
                    &user,
                    current_session,
                    SessionAuth::EmailCode,
                    "magic_link",
                )
                .await?
            {
                UpstreamPrimary::SignedIn {
                    cookie,
                    continue_to,
                } => EmailLinkOutcome::Done(FlowOutcome::SignedIn {
                    cookie,
                    continue_to,
                    recovery_codes: Vec::new(),
                }),
                UpstreamPrimary::Continue(started) => EmailLinkOutcome::Continue(started),
            },
        )
    }

    /// [`Effect::SendEmailCode`]: see the module docs.
    async fn send_email_code(
        &self,
        cx: &FlowContext<'_>,
        exec: &mut Exec<'_>,
        email: &str,
    ) -> Result<Step, CoreError> {
        let tenant = cx.tenant.id;
        let now = self.clock.now();
        let flow = exec.flow;
        let FlowState::Login(mut s) = decode_state(exec.state_json)? else {
            return Err(CoreError::Internal("email code outside a login".into()));
        };
        // A domain that forces SSO: refused before any account lookup (nothing is sent).
        if self.local_sign_in_refused(tenant, email).await? {
            let state = FlowState::Login(s);
            return self.refuse_local(cx, exec, &state, "email_code").await;
        }
        // The same work for every address: lookup, code, link token, both hashes. Only an active
        // account with a verified address gets the email: an unverified address may not belong to
        // the account holder, so it is treated exactly like an unknown one.
        let user = self
            .storage
            .users()
            .get_by_email(tenant, email)
            .await?
            .filter(email_code_recipient);
        let code = generate_email_code();
        let token = random_token();
        let code_hash = email_code::code_hash(&self.kek, flow.id, &code)
            .ok_or_else(|| CoreError::Internal("generated email code is malformed".into()))?;
        let (with_code, with_link) = (cx.tenant.settings.email_otp, cx.tenant.settings.magic_link);
        let next = EmailCodeState::issue(
            s.email_code.as_deref(),
            email,
            user.as_ref().map(|u| u.id),
            code_hash,
            email_code::link_hash(&token),
            now,
        )
        .with_methods(with_code, with_link);
        let sent = email_code::sent_form(&next);
        let lost =
            email_code::form_for(Some(&next), vec![FormMessage::error("flow.invalid_input")]);
        s.step = LoginStep::EmailCode;
        s.passkey_challenge = None;
        s.email_code = Some(Box::new(next));
        let json = encode_state(&FlowState::Login(s))?;
        if !self
            .storage
            .flows()
            .swap_state(tenant, flow.id, &flow.state, &json, now)
            .await?
        {
            return Ok(Step::Done(Box::new(FlowOutcome::Render(bind_form(
                lost,
                cx,
                flow.id,
                exec.csrf_token,
            )))));
        }
        if let Some(user) = &user {
            let mail = login_code_email(
                &self.kek,
                cx,
                flow.id,
                &user.email,
                with_code.then_some(code.as_str()),
                with_link.then_some(token.as_str()),
                now,
            )?;
            self.storage.outbox().enqueue(tenant, &mail).await?;
            self.audit_user(
                cx,
                AuditAction::EmailCodeSent,
                user.id,
                AuditOutcome::Success,
                AuditDetails::empty(),
            )
            .await?;
        }
        exec.attempt = Some(AuthAttempt::EmailCodeSent {
            subject: email_code::limit_subject(
                &self.kek,
                tenant,
                email,
                user.as_ref().map(|u| u.id),
            ),
        });
        Ok(Step::Done(Box::new(FlowOutcome::Render(bind_form(
            sent,
            cx,
            flow.id,
            exec.csrf_token,
        )))))
    }

    /// [`Effect::VerifyEmailCode`]: see the module docs.
    async fn verify_email_code(
        &self,
        cx: &FlowContext<'_>,
        exec: &mut Exec<'_>,
        code: &SecretString,
    ) -> Result<Step, CoreError> {
        let tenant = cx.tenant.id;
        let now = self.clock.now();
        let flow = exec.flow;
        let FlowState::Login(s) = decode_state(&flow.state)? else {
            return Err(CoreError::Internal("email code outside a login".into()));
        };
        let Some(ec) = s.email_code.as_deref() else {
            return Err(CoreError::Internal("email code step without a code".into()));
        };
        // The code method is off (now, or for the email that was sent): not found, no attempt.
        if !cx.tenant.settings.email_otp || !ec.code {
            return Err(CoreError::NotFound);
        }
        // The domain forces SSO now (a code sent before the org turned passwords off).
        if self.local_sign_in_refused(tenant, &ec.email).await? {
            return self
                .refuse_local(cx, exec, &FlowState::Login(s.clone()), "email_code")
                .await;
        }
        let subject = email_code::limit_subject(&self.kek, tenant, &ec.email, ec.user_id);
        let presented = email_code::code_hash(&self.kek, flow.id, code.expose_secret());
        let (check, next) = email_code::check_code(ec, presented, now);
        let mut stored = s.clone();
        stored.email_code = Some(Box::new(next));
        let changed = matches!(check, Check::Accepted | Check::Wrong { .. });
        let won = changed
            && self
                .storage
                .flows()
                .swap_state(
                    tenant,
                    flow.id,
                    &flow.state,
                    &encode_state(&FlowState::Login(stored))?,
                    now,
                )
                .await?;
        let user = match (check, won, ec.user_id) {
            (Check::Accepted, true, Some(u)) => self
                .second_factor_user(tenant, u)
                .await?
                .filter(email_code_recipient),
            _ => None,
        };
        if let Some(user) = user {
            exec.attempt = Some(AuthAttempt::EmailCodeSucceeded { subject: user.id });
            exec.method = "email_code";
            exec.subject = Some(user);
            return Ok(Step::Continue);
        }
        // Not signed in: a wrong code (or one that lost the race) counts as a failed attempt.
        let key = match check {
            Check::Accepted => email_code::INVALIDATED,
            other => email_code::failure_key(other),
        };
        if matches!(check, Check::Wrong { .. } | Check::Accepted) {
            exec.attempt = Some(AuthAttempt::EmailCodeFailed { subject });
            self.audit_login_failed(cx, ec.user_id, AuditDetails::login("email_code"))
                .await?;
        }
        let f = email_code::form_for(Some(ec), vec![FormMessage::error(key)]);
        Ok(Step::Done(Box::new(FlowOutcome::Render(bind_form(
            f,
            cx,
            flow.id,
            exec.csrf_token,
        )))))
    }

    /// The second factors `user` can use at the second-factor step.
    async fn second_factor_methods(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<SecondFactorMethods, CoreError> {
        second_factor_methods(self.storage.as_ref(), tenant, user).await
    }

    /// The effective MFA policy and `acr` request of the flow's authorization request; the
    /// tenant's policy and no request when the flow has none (or it expired).
    async fn flow_mfa(
        &self,
        cx: &FlowContext<'_>,
        flow: &Flow,
    ) -> Result<(crate::model::MfaPolicy, AcrRequest), CoreError> {
        let tenant = cx.tenant.id;
        let request = match flow.auth_request_id {
            Some(id) => {
                self.storage
                    .grants()
                    .get_authorization_request(tenant, id, self.clock.now())
                    .await?
            }
            None => None,
        };
        let Some(request) = request else {
            return Ok((cx.tenant.settings.mfa_policy, AcrRequest::None));
        };
        let client = self
            .storage
            .clients()
            .get(tenant, &request.client_id)
            .await?;
        let mfa = mfa_context(
            self.storage.as_ref(),
            cx.tenant,
            client.as_ref(),
            &request.params,
            None,
        )
        .await?;
        Ok((mfa.policy, mfa.acr))
    }

    async fn run(
        &self,
        cx: &FlowContext<'_>,
        effect: &Effect,
        queue: &mut VecDeque<Effect>,
        exec: &mut Exec<'_>,
        env: &FlowEnv,
    ) -> Result<Step, CoreError> {
        let tenant = cx.tenant.id;
        let users = self.storage.users();
        match effect {
            Effect::VerifyPassword { email, password } => {
                // A domain that forces SSO: refused before any account lookup.
                if self.local_sign_in_refused(tenant, email).await? {
                    let state = decode_state(exec.state_json)?;
                    return self.refuse_local(cx, exec, &state, "password").await;
                }
                let ident_hash = identifier_hash(email);
                let user = users.get_by_email(tenant, email).await?;
                let target = user.as_ref().map(|u| u.id);
                // Blocked users and users without a password take the dummy-hash path.
                let phc = match &user {
                    Some(u) if u.status == UserStatus::Active => {
                        users.password(tenant, u.id).await?.map(|c| c.phc)
                    }
                    _ => None,
                };
                // No hash profile yet: imported legacy hashes and their profiles land in 07-14.
                let check = match self
                    .hasher
                    .verify(phc.as_deref(), password.expose_secret(), None)
                    .await
                {
                    Ok(c) => c,
                    Err(CoreError::Overloaded) => return Ok(Step::Fail(Failure::Overloaded)),
                    Err(e) => return Err(e),
                };
                match password_login_result(user, phc.is_some(), check, env.require_verified_email)
                {
                    Ok(u) => {
                        if check.needs_rehash {
                            self.rehash(tenant, u.id, password).await?;
                        }
                        exec.attempt = Some(AuthAttempt::PasswordSucceeded {
                            ident_hash,
                            user: u.id,
                        });
                        exec.method = "password";
                        exec.subject = Some(u);
                        Ok(Step::Continue)
                    }
                    Err(Failure::EmailNotVerified) => {
                        self.audit_login_failed(
                            cx,
                            target,
                            AuditDetails::login("password")
                                .with(AuditDetails::reason("email_not_verified")),
                        )
                        .await?;
                        Ok(Step::Fail(Failure::EmailNotVerified))
                    }
                    Err(f) => {
                        exec.attempt = Some(AuthAttempt::PasswordFailed { ident_hash });
                        self.audit_login_failed(cx, target, AuditDetails::login("password"))
                            .await?;
                        Ok(Step::Fail(f))
                    }
                }
            }
            Effect::CheckSecondFactor => {
                let Some(user) = exec.subject.as_ref() else {
                    return Err(CoreError::Internal(
                        "CheckSecondFactor without an established user".into(),
                    ));
                };
                let user = user.id;
                let methods = self.second_factor_methods(tenant, user).await?;
                let (policy, acr) = self.flow_mfa(cx, exec.flow).await?;
                Ok(match after_primary_auth(policy, acr, methods) {
                    AfterPrimary::SignIn => Step::Continue,
                    AfterPrimary::SecondFactor(methods) => Step::SecondFactor(methods),
                    AfterPrimary::Enroll => Step::Enroll,
                })
            }
            Effect::StartPasskey => Err(CoreError::Internal(
                "StartPasskey runs only through passkey_options".into(),
            )),
            Effect::FinishPasskey {
                response_json,
                challenge,
            } => {
                self.finish_passkey(cx, exec, env, response_json, challenge)
                    .await
            }
            Effect::VerifyTotp { user_id, code } => {
                let now = self.clock.now();
                let accepted = match self.second_factor_user(tenant, *user_id).await? {
                    Some(user) => match users.totp(tenant, user.id).await? {
                        Some(totp) => match totp_step(&self.kek, &totp, code.expose_secret(), now)?
                        {
                            Some(step) => {
                                users.advance_totp_step(tenant, user.id, step, now).await?
                                    == CounterOutcome::Advanced
                            }
                            None => false,
                        },
                        None => false,
                    }
                    .then_some(user),
                    None => None,
                };
                self.second_factor_result(cx, exec, *user_id, accepted, "totp")
                    .await
            }
            Effect::ConsumeRecoveryCode { user_id, code } => {
                let now = self.clock.now();
                let mut accepted = None;
                if let Some(user) = self.second_factor_user(tenant, *user_id).await?
                    && let Some(hash) = recovery_code_lookup(&self.kek, code.expose_secret())
                {
                    let remaining = users
                        .recovery_codes_remaining(tenant, user.id)
                        .await?
                        .saturating_sub(1);
                    let notice =
                        recovery_code_used_email(&self.kek, cx, &user.email, remaining, now)?;
                    if users
                        .consume_recovery_code(tenant, user.id, &hash, now, Some(&notice))
                        .await?
                    {
                        self.audit_user(
                            cx,
                            AuditAction::RecoveryCodeUsed,
                            user.id,
                            AuditOutcome::Success,
                            AuditDetails::count("remaining", u64::from(remaining)),
                        )
                        .await?;
                        accepted = Some(user);
                    }
                }
                self.second_factor_result(cx, exec, *user_id, accepted, "recovery_code")
                    .await
            }
            Effect::ConfirmTotpEnrolment {
                user_id,
                pending,
                code,
            } => {
                self.confirm_enrolment(cx, exec, *user_id, pending, code)
                    .await
            }
            Effect::UpgradeSession { session, auth } => {
                self.upgrade_session(cx, exec, *session, *auth).await
            }
            Effect::CheckBreach { password } => {
                match self.breach.is_breached(password.expose_secret()).await {
                    Ok(true) => Ok(Step::Fail(Failure::Breached)),
                    Ok(false) => Ok(Step::Continue),
                    Err(CoreError::Overloaded) => Ok(Step::Fail(Failure::Overloaded)),
                    Err(e) => Err(e),
                }
            }
            Effect::CreateUser {
                email,
                name,
                password,
            } => {
                let phc = match self.hasher.hash(password.expose_secret()).await {
                    Ok(p) => p,
                    Err(CoreError::Overloaded) => return Ok(Step::Fail(Failure::Overloaded)),
                    Err(e) => return Err(e),
                };
                let now = self.clock.now();
                let new_user = NewUser {
                    id: UserId::new_v7(),
                    email: email.clone(),
                    email_verified: false,
                    username: None,
                    claims: StandardClaims {
                        name: name.clone(),
                        ..StandardClaims::default()
                    },
                    status: UserStatus::Active,
                    created_at: now,
                };
                let credential = NewPasswordCredential {
                    phc,
                    created_at: now,
                };
                // A verification email directly after CreateUser is stored in the same
                // transaction as the user.
                let verification = if matches!(
                    queue.front(),
                    Some(Effect::EnqueueEmail(EmailKind::Verification))
                ) {
                    queue.pop_front();
                    Some(self_service_email(
                        &self.kek,
                        cx,
                        SelfServiceKind::Verification,
                        new_user.id,
                        email,
                        now,
                    )?)
                } else {
                    None
                };
                let result = users
                    .create(
                        tenant,
                        &new_user,
                        Some(&credential),
                        verification.as_ref().map(|(t, _)| t),
                        verification.as_ref().map(|(_, e)| e),
                    )
                    .await;
                match result {
                    Ok(u) => {
                        self.audit_user(
                            cx,
                            AuditAction::UserRegistered,
                            u.id,
                            AuditOutcome::Success,
                            AuditDetails::empty(),
                        )
                        .await?;
                        exec.method = "password";
                        exec.subject = Some(u);
                        Ok(Step::Continue)
                    }
                    Err(StorageError::Conflict(_)) => Ok(Step::Fail(Failure::EmailTaken)),
                    Err(e) => Err(e.into()),
                }
            }
            Effect::EnqueueEmail(kind) => Err(CoreError::Internal(format!(
                "EnqueueEmail({kind:?}) is only valid directly after CreateUser"
            ))),
            Effect::CreateSession(auth) => {
                let Some(user) = exec.subject.take() else {
                    return Err(CoreError::Internal(
                        "CreateSession without an established user".into(),
                    ));
                };
                // Link confirmation (AUTH-11): the account just proved gets the waiting
                // upstream identity.
                if let Ok(FlowState::Login(s)) = serde_json::from_str::<FlowState>(exec.state_json)
                    && let Some(link) = &s.pending_link
                {
                    confirm_link(
                        self.storage.as_ref(),
                        &self.kek,
                        &self.audit(),
                        cx,
                        exec.flow.id,
                        link,
                        user.id,
                    )
                    .await?;
                }
                let cookie = self
                    .create_signed_in_session(
                        cx,
                        user.id,
                        *auth,
                        exec.passkey_backup_eligible,
                        exec.current_session,
                        exec.method,
                    )
                    .await?;
                self.storage.flows().delete(tenant, exec.flow.id).await?;
                Ok(Step::Done(Box::new(FlowOutcome::SignedIn {
                    cookie,
                    continue_to: self.continuation(cx, exec.flow),
                    recovery_codes: std::mem::take(&mut exec.recovery_codes),
                })))
            }
            Effect::SendEmailCode { email } => self.send_email_code(cx, exec, email).await,
            Effect::VerifyEmailCode { code } => self.verify_email_code(cx, exec, code).await,
            Effect::ConsumeEmailLink { .. } => Err(CoreError::Internal(
                "ConsumeEmailLink runs only through email_link".into(),
            )),
            Effect::IssueRecovery { email } => {
                // Same lookup whether or not the account exists; the caller always shows
                // `recovery.sent`.
                if let Some(user) = users.get_by_email(tenant, email).await?
                    && user.status == UserStatus::Active
                {
                    let (token, mail) = self_service_email(
                        &self.kek,
                        cx,
                        SelfServiceKind::Recovery,
                        user.id,
                        &user.email,
                        self.clock.now(),
                    )?;
                    users
                        .issue_self_service_token(tenant, &token, Some(&mail))
                        .await?;
                }
                Ok(Step::Continue)
            }
            Effect::CompleteVerification { token } => {
                let hash = SecretHash(secret_hash(token.expose_secret()));
                match users
                    .complete_verification(tenant, &hash, self.clock.now())
                    .await?
                {
                    Some(user) => {
                        self.audit_user(
                            cx,
                            AuditAction::EmailVerified,
                            user.id,
                            AuditOutcome::Success,
                            AuditDetails::empty(),
                        )
                        .await?;
                        Ok(Step::Continue)
                    }
                    None => Ok(Step::Fail(Failure::InvalidToken)),
                }
            }
            Effect::CompleteRecovery { token, password } => {
                let phc = match self.hasher.hash(password.expose_secret()).await {
                    Ok(p) => p,
                    Err(CoreError::Overloaded) => return Ok(Step::Fail(Failure::Overloaded)),
                    Err(e) => return Err(e),
                };
                let hash = SecretHash(secret_hash(token.expose_secret()));
                let now = self.clock.now();
                // The notice is enqueued in the recovery transaction, addressed to the consumed
                // token's email. Its sealed payload has no `email` (the address is unknown until
                // the token is consumed); the outbox worker fills it from the recipient.
                let notice = password_changed_notice(&self.kek, cx, now)?;
                let Some(user) = users
                    .complete_recovery(tenant, &hash, &phc, now, Some(&notice))
                    .await?
                else {
                    return Ok(Step::Fail(Failure::InvalidToken));
                };
                self.audit_user(
                    cx,
                    AuditAction::PasswordChanged,
                    user.id,
                    AuditOutcome::Success,
                    AuditDetails::reason("recovery"),
                )
                .await?;
                Ok(Step::Continue)
            }
            Effect::SubmitSetup { email, password } => {
                Ok(Step::Done(Box::new(FlowOutcome::SetupSubmitted {
                    email: email.clone(),
                    password: SecretString::from(password.expose_secret().to_owned()),
                })))
            }
            Effect::Render(_) | Effect::Message(_) => Err(CoreError::Internal(
                "terminal effect reached the effect runner".into(),
            )),
        }
    }

    /// Session switch (module docs): the session `CreateSession` should rotate. A current session
    /// of the same user is returned (rotated by `SessionService::create`); one of another user
    /// is revoked here with its token families (back-channel deliveries enqueued) and audited.
    /// The one way a sign-in creates its browser session: replaces another user's session in this
    /// browser ([`Self::switch_session`]), creates the session with the acr/amr of `auth`, records
    /// the login and audits `login_succeeded` with `method`. The caller deletes its flow.
    async fn create_signed_in_session(
        &self,
        cx: &FlowContext<'_>,
        user: UserId,
        auth: SessionAuth,
        passkey_backup_eligible: bool,
        current_session: Option<SessionId>,
        method: &'static str,
    ) -> Result<NewSessionCookie, CoreError> {
        let tenant = cx.tenant.id;
        let (acr, amr) = session_acr_amr(auth, passkey_backup_eligible);
        let replaces = self.switch_session(cx, current_session, user).await?;
        let cookie = self
            .sessions()
            .create(tenant, user, acr, &amr, replaces, cx.ctx)
            .await?;
        self.storage
            .users()
            .record_login(tenant, user, self.clock.now())
            .await?;
        self.audit_user(
            cx,
            AuditAction::LoginSucceeded,
            user,
            AuditOutcome::Success,
            AuditDetails::login(method),
        )
        .await?;
        Ok(cookie)
    }

    /// Signs in `user`, just created through an organization invitation
    /// (`OrgInvitationService::accept_with_registration`, which checked the password): a session
    /// as after a password sign-in (`acr`/`amr` of [`SessionAuth::Password`]), through the same
    /// code as every flow sign-in, so another user's session in this browser (`current`) is
    /// replaced and `login_succeeded` is audited (method `invitation_registration`). There is no
    /// flow. Refused (`InvalidRequest`) unless the user exists in this tenant, is active and has
    /// a verified email.
    pub async fn sign_in_registered_user(
        &self,
        cx: &FlowContext<'_>,
        user: UserId,
        current: Option<&BrowserSession>,
    ) -> Result<NewSessionCookie, CoreError> {
        let tenant = cx.tenant.id;
        match self.storage.users().get(tenant, user).await? {
            Some(u) if u.status == UserStatus::Active && u.email_verified => {}
            _ => {
                return Err(CoreError::InvalidRequest(
                    "the user cannot be signed in".into(),
                ));
            }
        }
        let current = current
            .filter(|s| s.tenant_id == tenant && s.revoked_at.is_none())
            .map(|s| s.id);
        self.create_signed_in_session(
            cx,
            user,
            SessionAuth::Password,
            false,
            current,
            "invitation_registration",
        )
        .await
    }

    async fn switch_session(
        &self,
        cx: &FlowContext<'_>,
        current: Option<SessionId>,
        user: UserId,
    ) -> Result<Option<SessionId>, CoreError> {
        let Some(id) = current else {
            return Ok(None);
        };
        let tenant = cx.tenant.id;
        let Some(old) = self.storage.sessions().get(tenant, id).await? else {
            return Ok(None);
        };
        if old.user_id == user {
            return Ok(Some(id));
        }
        if self
            .storage
            .sessions()
            .revoke_with_families(tenant, id, self.clock.now())
            .await?
        {
            self.audit()
                .record(
                    tenant,
                    AuditActor::user(old.user_id),
                    AuditAction::SessionRevoked,
                    Some(id.to_string()),
                    AuditOutcome::Success,
                    cx.ctx,
                    AuditDetails::reason("session_switch"),
                )
                .await?;
        }
        Ok(None)
    }

    /// Confirms an in-flow TOTP enrolment (see [`Effect::ConfirmTotpEnrolment`]).
    async fn confirm_enrolment(
        &self,
        cx: &FlowContext<'_>,
        exec: &mut Exec<'_>,
        user_id: UserId,
        pending: &str,
        code: &SecretString,
    ) -> Result<Step, CoreError> {
        let tenant = cx.tenant.id;
        let now = self.clock.now();
        let Some(user) = self.second_factor_user(tenant, user_id).await? else {
            return self
                .second_factor_result(cx, exec, user_id, None, "totp")
                .await;
        };
        let secret = open_pending_totp(&self.kek, exec.flow.id, pending)?;
        let Some(step) = pending_totp_step(&secret, code.expose_secret(), now) else {
            return self
                .second_factor_result(cx, exec, user_id, None, "totp")
                .await;
        };
        // Single use: the state without the pending secret replaces the stored one; a replayed
        // or concurrent confirmation loses the swap.
        let mut next: FlowState = serde_json::from_str(exec.state_json)
            .map_err(|e| CoreError::Internal(format!("corrupt flow state: {e}")))?;
        if let FlowState::Login(s) = &mut next {
            s.pending_totp = None;
        }
        let next = encode_state(&next)?;
        if !self
            .storage
            .flows()
            .swap_state(tenant, exec.flow.id, &exec.flow.state, &next, now)
            .await?
        {
            return self
                .second_factor_result(cx, exec, user_id, None, "totp")
                .await;
        }
        let Some(codes) = create_confirmed_totp(
            self.storage.as_ref(),
            &self.kek,
            &self.audit(),
            tenant,
            user.id,
            &secret,
            step,
            now,
            cx.ctx,
        )
        .await?
        else {
            // Enrolled concurrently elsewhere: the user signs in with that factor instead.
            return self
                .second_factor_result(cx, exec, user_id, None, "totp")
                .await;
        };
        exec.recovery_codes = codes;
        self.second_factor_result(cx, exec, user_id, Some(user), "totp")
            .await
    }

    /// Completes a step-up (see [`Effect::UpgradeSession`]).
    async fn upgrade_session(
        &self,
        cx: &FlowContext<'_>,
        exec: &mut Exec<'_>,
        session_id: SessionId,
        auth: crate::flow::engine::SessionAuth,
    ) -> Result<Step, CoreError> {
        let tenant = cx.tenant.id;
        let now = self.clock.now();
        let Some(user) = exec.subject.take() else {
            return Err(CoreError::Internal(
                "UpgradeSession without an established user".into(),
            ));
        };
        // The browser must still present the session being upgraded, and it must be the
        // verified user's.
        if exec.current_session != Some(session_id) {
            return Err(CoreError::Forbidden);
        }
        let session = match self.storage.sessions().get(tenant, session_id).await? {
            Some(s) if s.user_id == user.id => s,
            _ => return Err(CoreError::Forbidden),
        };
        let (acr, amr) = upgraded_acr_amr(&session.amr, auth, exec.passkey_backup_eligible);
        if !self
            .storage
            .sessions()
            .upgrade_auth(tenant, session_id, acr, &amr, now, now)
            .await?
        {
            return Err(CoreError::Forbidden);
        }
        self.storage.flows().delete(tenant, exec.flow.id).await?;
        self.audit_user(
            cx,
            AuditAction::StepUpCompleted,
            user.id,
            AuditOutcome::Success,
            AuditDetails::login(exec.method),
        )
        .await?;
        Ok(Step::Done(Box::new(FlowOutcome::SteppedUp {
            continue_to: self.continuation(cx, exec.flow),
            recovery_codes: std::mem::take(&mut exec.recovery_codes),
        })))
    }

    /// The user a second-factor step is for, if still active.
    async fn second_factor_user(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Option<User>, CoreError> {
        Ok(self
            .storage
            .users()
            .get(tenant, user)
            .await?
            .filter(|u| u.status == UserStatus::Active))
    }

    /// Records the result of a TOTP or recovery-code check.
    async fn second_factor_result(
        &self,
        cx: &FlowContext<'_>,
        exec: &mut Exec<'_>,
        user_id: UserId,
        accepted: Option<User>,
        method: &'static str,
    ) -> Result<Step, CoreError> {
        match accepted {
            Some(user) => {
                exec.attempt = Some(AuthAttempt::SecondFactorSucceeded { user: user.id });
                exec.method = method;
                exec.subject = Some(user);
                Ok(Step::Continue)
            }
            None => {
                exec.attempt = Some(AuthAttempt::SecondFactorFailed { user: user_id });
                self.audit_user(
                    cx,
                    AuditAction::SecondFactorFailed,
                    user_id,
                    AuditOutcome::Failure,
                    AuditDetails::login(method),
                )
                .await?;
                Ok(Step::Fail(Failure::SecondFactorInvalid))
            }
        }
    }

    /// Verifies a passkey assertion (see the module docs). The challenge is taken out of the
    /// stored flow state before anything else.
    async fn finish_passkey(
        &self,
        cx: &FlowContext<'_>,
        exec: &mut Exec<'_>,
        env: &FlowEnv,
        response_json: &str,
        challenge: &str,
    ) -> Result<Step, CoreError> {
        let tenant = cx.tenant.id;
        let users = self.storage.users();
        let now = self.clock.now();
        exec.attempt = Some(AuthAttempt::PasskeyFailed);
        let rejected = Ok(Step::Fail(Failure::PasskeyInvalid));

        // Single use: of concurrent or replayed finishes with the same challenge, at most one
        // wins this swap.
        if !self
            .storage
            .flows()
            .swap_state(tenant, exec.flow.id, &exec.flow.state, exec.state_json, now)
            .await?
        {
            return rejected;
        }
        let (passkey, verified) = match self
            .check_assertion(cx, response_json, challenge, None)
            .await?
        {
            AssertionCheck::Verified { passkey, verified } => (passkey, verified),
            AssertionCheck::Unbound => {
                self.audit_login_failed(cx, None, AuditDetails::login("passkey"))
                    .await?;
                return rejected;
            }
            AssertionCheck::Invalid(user) => {
                self.audit_login_failed(cx, Some(user), AuditDetails::login("passkey"))
                    .await?;
                return rejected;
            }
            AssertionCheck::CloneSuspected => return rejected,
        };
        let user = match users.get(tenant, passkey.user_id).await? {
            Some(u) if u.status == UserStatus::Active => u,
            _ => {
                self.audit_login_failed(cx, Some(passkey.user_id), AuditDetails::login("passkey"))
                    .await?;
                return rejected;
            }
        };
        if !self.record_assertion(cx, &passkey, &verified).await? {
            return rejected;
        }
        if env.require_verified_email && !user.email_verified {
            exec.attempt = None;
            self.audit_login_failed(
                cx,
                Some(user.id),
                AuditDetails::login("passkey").with(AuditDetails::reason("email_not_verified")),
            )
            .await?;
            return Ok(Step::Fail(Failure::EmailNotVerified));
        }
        exec.attempt = Some(AuthAttempt::PasskeySucceeded { user: user.id });
        exec.method = "passkey";
        exec.passkey_backup_eligible = verified.backup_eligible;
        exec.subject = Some(user);
        Ok(Step::Continue)
    }

    /// Checks a discoverable assertion against the stored passkeys (the one verification path of
    /// the sign-in page's passkey and the second-factor passkey): the response names a credential
    /// id and a user handle; the tenant-scoped stored passkey must exist and belong to that user
    /// handle ([`bound_passkey`]) and, with `expected_user`, to that user, before any signature
    /// check. The assertion must verify against `challenge` with user verification. A possible
    /// clone records `passkey_clone_suspected`. Nothing is written for a verified assertion: the
    /// caller records it with [`Self::record_assertion`].
    async fn check_assertion(
        &self,
        cx: &FlowContext<'_>,
        response_json: &str,
        challenge: &str,
        expected_user: Option<UserId>,
    ) -> Result<AssertionCheck, CoreError> {
        let rp = cx.relying_party()?;
        let Ok(identity) = self.passkeys.identify(response_json) else {
            return Ok(AssertionCheck::Unbound);
        };
        if expected_user.is_some_and(|u| u != identity.user_id) {
            return Ok(AssertionCheck::Unbound);
        }
        let found = self
            .storage
            .users()
            .find_passkey(cx.tenant.id, &identity.credential_id)
            .await?;
        let Some(passkey) = bound_passkey(&identity, found) else {
            return Ok(AssertionCheck::Unbound);
        };
        match self
            .passkeys
            .finish_discoverable(rp, response_json, challenge, &passkey.passkey_json)
        {
            Ok(verified) if verified.user_verified => {
                Ok(AssertionCheck::Verified { passkey, verified })
            }
            Ok(_) | Err(PasskeyError::Invalid) => Ok(AssertionCheck::Invalid(passkey.user_id)),
            Err(PasskeyError::PossibleClone) => {
                self.clone_suspected(cx, &passkey).await?;
                Ok(AssertionCheck::CloneSuspected)
            }
        }
    }

    /// Stores the verified assertion's counter (and changed passkey) with a compare-and-swap.
    /// `false`: the counter did not advance, `passkey_clone_suspected` was recorded and the
    /// assertion must be refused.
    async fn record_assertion(
        &self,
        cx: &FlowContext<'_>,
        passkey: &PasskeyCredential,
        verified: &VerifiedAssertion,
    ) -> Result<bool, CoreError> {
        let json = verified
            .updated_passkey_json
            .as_deref()
            .unwrap_or(&passkey.passkey_json);
        if self
            .storage
            .users()
            .update_passkey(
                cx.tenant.id,
                passkey.id,
                json,
                verified.counter,
                self.clock.now(),
            )
            .await?
            == CounterOutcome::Stale
        {
            self.clone_suspected(cx, passkey).await?;
            return Ok(false);
        }
        Ok(true)
    }

    /// `passkey_clone_suspected` for the passkey's user (the sign-in itself fails generically).
    async fn clone_suspected(
        &self,
        cx: &FlowContext<'_>,
        passkey: &PasskeyCredential,
    ) -> Result<(), CoreError> {
        self.audit()
            .record(
                cx.tenant.id,
                AuditActor::anonymous(ActorKind::User),
                AuditAction::PasskeyCloneSuspected,
                Some(passkey.user_id.to_string()),
                AuditOutcome::Failure,
                cx.ctx,
                AuditDetails::credential(CredentialKind::Webauthn),
            )
            .await
    }

    /// Re-hashes a password with the current parameters after a successful login. Skipped
    /// (retried at the next login) when the hasher is overloaded.
    async fn rehash(
        &self,
        tenant: TenantId,
        user: UserId,
        password: &SecretString,
    ) -> Result<(), CoreError> {
        match self.hasher.hash(password.expose_secret()).await {
            Ok(phc) => {
                self.storage
                    .users()
                    .set_password(tenant, user, &phc, self.clock.now())
                    .await?;
                Ok(())
            }
            Err(CoreError::Overloaded) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// A new self-service token for `user` and the email carrying its link. The payload is sealed
/// with the KEK because the link carries the token. Also used by just-in-time upstream
/// registration (`service::upstream`).
pub(crate) fn self_service_email(
    kek: &Kek,
    cx: &FlowContext<'_>,
    kind: SelfServiceKind,
    user: UserId,
    email: &str,
    now: OffsetDateTime,
) -> Result<(NewSelfServiceToken, NewEmail), CoreError> {
    let token = random_token();
    let (ttl, page, template, expires_in) = match kind {
        SelfServiceKind::Verification => (
            VERIFICATION_TOKEN_TTL,
            "verification",
            "verification",
            "24 hours",
        ),
        SelfServiceKind::Recovery => (RECOVERY_TOKEN_TTL, "recovery", "recovery", "1 hour"),
        SelfServiceKind::Invitation => (Duration::days(7), "recovery", "invitation", "7 days"),
        SelfServiceKind::EmailChange => {
            return Err(CoreError::Internal(
                "email change tokens are issued by AccountService".to_owned(),
            ));
        }
    };
    let expires_at = now + ttl;
    let record = NewSelfServiceToken {
        token_hash: SecretHash(secret_hash(&token)),
        kind,
        user_id: user,
        email: email.to_owned(),
        created_at: now,
        expires_at,
    };
    let mut payload = BTreeMap::new();
    payload.insert("tenant_name".to_owned(), cx.tenant.display_name.clone());
    payload.insert("email".to_owned(), email.to_owned());
    payload.insert(
        "link".to_owned(),
        format!("{}/{}?token={}", cx.ui_base, page, token),
    );
    payload.insert("expires_in".to_owned(), expires_in.to_owned());
    let mail = NewEmail {
        id: OutboxId::new_v7(),
        to: email.to_owned(),
        template: template.to_owned(),
        payload: seal_payload(kek, cx.tenant.id, &payload)?,
        created_at: now,
        expires_at,
    };
    Ok((record, mail))
}

/// The `password_changed` notice of a recovery (payload `tenant_name`, sealed). It carries no
/// `email`: the recipient is the consumed token's address, which the outbox worker supplies as
/// the `email` template variable.
fn password_changed_notice(
    kek: &Kek,
    cx: &FlowContext<'_>,
    now: OffsetDateTime,
) -> Result<RecoveryNotice, CoreError> {
    let mut payload = BTreeMap::new();
    payload.insert("tenant_name".to_owned(), cx.tenant.display_name.clone());
    Ok(RecoveryNotice {
        id: OutboxId::new_v7(),
        template: "password_changed".to_owned(),
        payload: seal_payload(kek, cx.tenant.id, &payload)?,
        created_at: now,
        expires_at: now + NOTICE_EMAIL_TTL,
    })
}

/// The `recovery_code_used` notice (payload `tenant_name` and `remaining`, sealed).
fn recovery_code_used_email(
    kek: &Kek,
    cx: &FlowContext<'_>,
    to: &str,
    remaining: u32,
    now: OffsetDateTime,
) -> Result<NewEmail, CoreError> {
    let mut payload = BTreeMap::new();
    payload.insert("tenant_name".to_owned(), cx.tenant.display_name.clone());
    payload.insert("remaining".to_owned(), remaining.to_string());
    Ok(NewEmail {
        id: OutboxId::new_v7(),
        to: to.to_owned(),
        template: "recovery_code_used".to_owned(),
        payload: seal_payload(kek, cx.tenant.id, &payload)?,
        created_at: now,
        expires_at: now + NOTICE_EMAIL_TTL,
    })
}

/// Whether email sign-in is offered for the tenant: either setting. Each method is then enforced
/// on its own (`email_otp`: the code, `magic_link`: the link; module docs).
pub fn email_code_enabled(tenant: &Tenant) -> bool {
    tenant.settings.email_otp || tenant.settings.magic_link
}

/// Whether `user` may sign in by email code or link: active, with a verified address (checked when
/// the code is sent and again when it is used).
fn email_code_recipient(user: &User) -> bool {
    user.status == UserStatus::Active && user.email_verified
}

/// Marks a login whose primary authentication was an email code or link (its second factor then
/// ends in `[otp, mfa]`) and drops the used code.
fn email_primary(state: &mut LoginState, method: &str) {
    if method == "email_code" || method == "magic_link" {
        state.email_primary = true;
        state.email_code = None;
    }
}

/// The `login_code` email (payload `tenant_name`, `code` when `code` is given, `link` when `token`
/// is given, `expires_minutes`; sealed: it carries the code and/or the link token).
fn login_code_email(
    kek: &Kek,
    cx: &FlowContext<'_>,
    flow: FlowId,
    to: &str,
    code: Option<&str>,
    token: Option<&str>,
    now: OffsetDateTime,
) -> Result<NewEmail, CoreError> {
    let mut payload = BTreeMap::new();
    payload.insert("tenant_name".to_owned(), cx.tenant.display_name.clone());
    if let Some(code) = code {
        payload.insert("code".to_owned(), code.to_owned());
    }
    if let Some(token) = token {
        payload.insert(
            "link".to_owned(),
            format!("{}/login/email-link?flow={flow}&token={token}", cx.ui_base),
        );
    }
    payload.insert(
        "expires_minutes".to_owned(),
        email_code::EMAIL_CODE_TTL.whole_minutes().to_string(),
    );
    Ok(NewEmail {
        id: OutboxId::new_v7(),
        to: to.to_owned(),
        template: "login_code".to_owned(),
        payload: seal_payload(kek, cx.tenant.id, &payload)?,
        created_at: now,
        expires_at: now + email_code::EMAIL_CODE_TTL,
    })
}

fn decode_state(json: &str) -> Result<FlowState, CoreError> {
    serde_json::from_str(json).map_err(|e| CoreError::Internal(format!("corrupt flow state: {e}")))
}

/// Flow kinds whose state is a [`FlowState`] run by this service.
fn engine_kind(kind: FlowKind) -> bool {
    match kind {
        FlowKind::Login
        | FlowKind::Registration
        | FlowKind::Verification
        | FlowKind::Recovery
        | FlowKind::Setup => true,
        FlowKind::Settings | FlowKind::Consent | FlowKind::Logout => false,
    }
}

/// Result of [`FlowService::check_assertion`].
enum AssertionCheck {
    /// The response names no stored passkey of the tenant bound to its user handle (or to the
    /// expected user), or cannot be parsed. No signature was checked.
    Unbound,
    /// The stored passkey of this user did not verify (signature, challenge, origin, or no user
    /// verification).
    Invalid(UserId),
    /// The authenticator may be cloned; `passkey_clone_suspected` was recorded.
    CloneSuspected,
    Verified {
        passkey: PasskeyCredential,
        verified: VerifiedAssertion,
    },
}

/// The WebAuthn user of a passkey registration: the email as name, the display name (or the
/// email) as display name, like the account page.
fn passkey_user(user: &User) -> PasskeyUser {
    PasskeyUser {
        id: user.id,
        name: user.email.clone(),
        display_name: user
            .claims
            .name
            .clone()
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| user.email.clone()),
    }
}

fn encode_state(state: &FlowState) -> Result<String, CoreError> {
    serde_json::to_string(state)
        .map_err(|e| CoreError::Internal(format!("flow state serialisation: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::engine::LoginState;
    use crate::model::{CredentialId, SEALED_PAYLOAD_KEY, TenantSettings, open_payload};
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-11-25 12:00 UTC);

    fn flow(cookie: &str, csrf: &str, expires_at: OffsetDateTime) -> Flow {
        Flow {
            id: FlowId::new_v7(),
            tenant_id: TenantId::new_v7(),
            kind: FlowKind::Login,
            state: "{}".into(),
            csrf_hash: SecretHash(secret_hash(csrf)),
            cookie_hash: SecretHash(secret_hash(cookie)),
            auth_request_id: None,
            created_at: NOW,
            expires_at,
        }
    }

    fn user(status: UserStatus, verified: bool) -> User {
        User {
            id: UserId::new_v7(),
            tenant_id: TenantId::new_v7(),
            email: "alice@example.com".into(),
            email_verified: verified,
            username: None,
            claims: StandardClaims::default(),
            status,
            created_at: NOW,
            updated_at: NOW,
            last_login_at: None,
        }
    }

    const INVALID: PasswordCheck = PasswordCheck {
        valid: false,
        needs_rehash: false,
    };
    const VALID: PasswordCheck = PasswordCheck {
        valid: true,
        needs_rehash: false,
    };

    #[test]
    fn binding_accepts_matching_tokens() {
        let f = flow("cookie", "csrf", NOW + FLOW_LIFETIME);
        assert_eq!(check_binding(&f, Some("cookie"), "csrf", NOW), Ok(()));
    }

    #[test]
    fn binding_rejects_missing_or_wrong_tokens() {
        let f = flow("cookie", "csrf", NOW + FLOW_LIFETIME);
        for (cookie, csrf) in [
            (None, "csrf"),
            (Some("other"), "csrf"),
            (Some("cookie"), "other"),
            (Some("cookie"), ""),
            (Some(""), "csrf"),
            // The tokens are not interchangeable.
            (Some("csrf"), "cookie"),
        ] {
            assert_eq!(
                check_binding(&f, cookie, csrf, NOW),
                Err(BindingError::Forbidden),
                "{cookie:?} {csrf:?}"
            );
        }
    }

    #[test]
    fn binding_rejects_expired_flow() {
        let f = flow("cookie", "csrf", NOW);
        assert_eq!(
            check_binding(&f, Some("cookie"), "csrf", NOW),
            Err(BindingError::Expired)
        );
        let f = flow("cookie", "csrf", NOW - Duration::seconds(1));
        assert_eq!(
            check_binding(&f, None, "x", NOW),
            Err(BindingError::Expired)
        );
    }

    #[test]
    fn login_failures_are_indistinguishable() {
        let env = FlowEnv::default();
        let cases = [
            password_login_result(None, false, INVALID, false),
            password_login_result(Some(user(UserStatus::Active, true)), true, INVALID, false),
            password_login_result(Some(user(UserStatus::Active, true)), false, INVALID, false),
            // A valid check never rescues a blocked user or a user without a password.
            password_login_result(Some(user(UserStatus::Blocked, true)), true, VALID, false),
            password_login_result(Some(user(UserStatus::Active, true)), false, VALID, false),
        ];
        let state = FlowState::Login(LoginState {
            identifier: Some("alice@example.com".into()),
            ..LoginState::default()
        });
        let mut forms = Vec::new();
        for r in cases {
            let failure = r.expect_err("must fail");
            assert_eq!(failure, Failure::InvalidCredentials);
            let (_, form) = on_failure(
                state.clone(),
                &[Effect::CreateSession(
                    crate::flow::engine::SessionAuth::Password,
                )],
                failure,
                &env,
            );
            forms.push(form);
        }
        assert!(forms.windows(2).all(|w| w[0] == w[1]));
        let keys: Vec<_> = forms[0].messages.iter().map(|m| m.key.as_str()).collect();
        assert_eq!(keys, vec!["login.invalid_credentials"]);
    }

    #[test]
    fn login_success_and_verified_email_requirement() {
        let u = user(UserStatus::Active, false);
        assert_eq!(
            password_login_result(Some(u.clone()), true, VALID, false).map(|x| x.id),
            Ok(u.id)
        );
        assert_eq!(
            password_login_result(Some(u), true, VALID, true).map(|x| x.id),
            Err(Failure::EmailNotVerified)
        );
    }

    #[test]
    fn bind_form_sets_action_and_csrf() {
        let tenant = Tenant {
            id: TenantId::new_v7(),
            slug: "acme".into(),
            display_name: "Acme".into(),
            host: None,
            settings: TenantSettings::default(),
            created_at: NOW,
        };
        let cx = cx(&tenant);
        let (_, form) = FlowState::initial(FlowKind::Login, None, &FlowEnv::default()).unwrap();
        let id = FlowId::new_v7();
        let bound = bind_form(form, &cx, id, "csrf-tok");
        assert_eq!(
            bound.action,
            format!("https://id.example.test/t/acme/ui/login?flow={id}")
        );
        assert_eq!(bound.csrf_token, "csrf-tok");
    }

    fn acme() -> Tenant {
        Tenant {
            id: TenantId::new_v7(),
            slug: "acme".into(),
            display_name: "Acme".into(),
            host: None,
            settings: TenantSettings::default(),
            created_at: NOW,
        }
    }

    fn cx(tenant: &Tenant) -> FlowContext<'_> {
        FlowContext {
            tenant,
            issuer: "https://id.example.test/t/acme",
            ui_base: "https://id.example.test/t/acme/ui",
            rp: rp(),
            ctx: Box::leak(Box::new(RequestContext::default())),
        }
    }

    fn rp() -> &'static Result<RelyingParty, CoreError> {
        Box::leak(Box::new(Ok(RelyingParty {
            rp_id: "id.example.test".into(),
            origin: "https://id.example.test".into(),
            name: "Acme".into(),
        })))
    }

    #[test]
    fn self_service_emails_are_sealed() {
        let kek = Kek::generate();
        let tenant = acme();
        let cx = cx(&tenant);
        for (kind, page, template, expires_in) in [
            (
                SelfServiceKind::Verification,
                "verification",
                "verification",
                "24 hours",
            ),
            (SelfServiceKind::Recovery, "recovery", "recovery", "1 hour"),
        ] {
            let user = UserId::new_v7();
            let (record, mail) =
                self_service_email(&kek, &cx, kind, user, "alice@example.com", NOW).unwrap();
            assert_eq!(mail.template, template);
            assert_eq!(mail.payload.len(), 1, "{template}: one sealed entry");
            assert!(mail.payload.contains_key(SEALED_PAYLOAD_KEY));
            assert!(!mail.payload[SEALED_PAYLOAD_KEY].contains("token="));
            assert!(open_payload(&kek, TenantId::new_v7(), &mail.payload).is_err());
            let payload = open_payload(&kek, tenant.id, &mail.payload).unwrap();
            let token = payload["link"]
                .strip_prefix(&format!("https://id.example.test/t/acme/ui/{page}?token="))
                .expect("link format");
            assert_eq!(record.token_hash, SecretHash(secret_hash(token)));
            assert!(!mail.payload[SEALED_PAYLOAD_KEY].contains(token));
            assert_eq!(payload["email"], "alice@example.com");
            assert_eq!(payload["tenant_name"], "Acme");
            assert_eq!(payload["expires_in"], expires_in);
        }
    }

    #[test]
    fn password_changed_notice_is_sealed_and_addressed_by_the_recovery() {
        let kek = Kek::generate();
        let tenant = acme();
        let notice = password_changed_notice(&kek, &cx(&tenant), NOW).unwrap();
        assert_eq!(notice.template, "password_changed");
        assert_eq!(notice.payload.len(), 1);
        assert!(notice.payload.contains_key(SEALED_PAYLOAD_KEY));
        let payload = open_payload(&kek, tenant.id, &notice.payload).unwrap();
        assert_eq!(payload["tenant_name"], "Acme");
        // The address is only known once the token is consumed; the worker fills `email`.
        assert!(!payload.contains_key("email"));
        let mail = notice.to_email("alice@example.com");
        assert_eq!(mail.to, "alice@example.com");
        assert_eq!(mail.payload, notice.payload);
    }

    #[test]
    fn identifier_hash_is_sha256_of_the_normalised_identifier() {
        assert_eq!(
            identifier_hash("alice@example.com"),
            secret_hash("alice@example.com")
        );
        assert_ne!(
            identifier_hash("alice@example.com"),
            identifier_hash("bob@example.com")
        );
    }

    fn passkey(user: UserId, credential_id: &[u8]) -> PasskeyCredential {
        PasskeyCredential {
            id: CredentialId::new_v7(),
            user_id: user,
            credential_id: credential_id.to_vec(),
            passkey_json: "{}".into(),
            counter: 0,
            backup_eligible: false,
            label: "Key".into(),
            created_at: NOW,
            last_used_at: None,
        }
    }

    #[test]
    fn passkey_must_belong_to_the_asserted_user_handle() {
        let alice = UserId::new_v7();
        let mallory = UserId::new_v7();
        let identity = AssertionIdentity {
            user_id: alice,
            credential_id: vec![1, 2, 3],
        };
        // Unknown credential (also: another tenant's credential, the lookup is tenant-scoped).
        assert_eq!(bound_passkey(&identity, None), None);
        // A credential of another user presented with alice's user handle.
        assert_eq!(
            bound_passkey(&identity, Some(passkey(mallory, &[1, 2, 3]))),
            None
        );
        // A row for another credential id.
        assert_eq!(bound_passkey(&identity, Some(passkey(alice, &[9]))), None);
        let ok = passkey(alice, &[1, 2, 3]);
        assert_eq!(bound_passkey(&identity, Some(ok.clone())), Some(ok));
    }

    #[test]
    fn allow_credentials_list_exactly_the_given_passkeys() {
        let alice = UserId::new_v7();
        let options = r#"{"publicKey":{"challenge":"abc","allowCredentials":[{"type":"public-key","id":"AA"}],"userVerification":"required"},"mediation":"optional"}"#;
        let out = with_allow_credentials(
            options,
            &[passkey(alice, &[1, 2, 3]), passkey(alice, &[0xfb, 0xff])],
        )
        .expect("options");
        let v: serde_json::Value = serde_json::from_str(&out).expect("json");
        assert_eq!(
            v["publicKey"]["allowCredentials"],
            serde_json::json!([
                { "type": "public-key", "id": "AQID" },
                { "type": "public-key", "id": "-_8" },
            ])
        );
        // Everything else is untouched.
        assert_eq!(v["publicKey"]["challenge"], "abc");
        assert_eq!(v["publicKey"]["userVerification"], "required");
        assert_eq!(v["mediation"], "optional");
    }

    #[test]
    fn allow_credentials_refuse_malformed_options() {
        let pk = passkey(UserId::new_v7(), &[1]);
        for bad in [
            "not json",
            "[]",
            r#"{"publicKey":[]}"#,
            r#"{"challenge":"abc"}"#,
        ] {
            assert!(
                matches!(
                    with_allow_credentials(bad, std::slice::from_ref(&pk)),
                    Err(CoreError::Internal(_))
                ),
                "{bad}"
            );
        }
    }

    fn sealed_totp(kek: &Kek, secret: &TotpSecret) -> TotpCredential {
        let id = CredentialId::new_v7();
        TotpCredential {
            id,
            user_id: UserId::new_v7(),
            secret_enc: kek
                .seal(TOTP_SEED_PURPOSE, &credential_aad(id), secret.as_bytes())
                .unwrap(),
            last_step: None,
            created_at: NOW,
            last_used_at: None,
        }
    }

    /// RFC 6238 Appendix B SHA-1 seed; at T=1111111109 the 6-digit code is 081804 (step
    /// 37037036) and at T=59 it is 287082 (step 1).
    fn rfc_secret() -> TotpSecret {
        TotpSecret::from_bytes(b"12345678901234567890").unwrap()
    }

    fn at(unix: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(unix).unwrap()
    }

    #[test]
    fn totp_step_opens_the_sealed_seed_and_matches_codes() {
        let kek = Kek::generate();
        let totp = sealed_totp(&kek, &rfc_secret());
        let t = at(1_111_111_109);
        assert_eq!(
            totp_step(&kek, &totp, "081804", t).unwrap(),
            Some(37_037_036)
        );
        assert_eq!(
            totp_step(&kek, &totp, " 081 804 ", t).unwrap(),
            Some(37_037_036)
        );
        assert_eq!(totp_step(&kek, &totp, "287082", at(59)).unwrap(), Some(1));
        // The T=59 code is far outside the window at T=1111111109.
        assert_eq!(totp_step(&kek, &totp, "287082", t).unwrap(), None);
        for bad in ["", "08180", "0818045", "abcdef"] {
            assert_eq!(totp_step(&kek, &totp, bad, t).unwrap(), None, "{bad:?}");
        }
    }

    #[test]
    fn totp_seed_is_bound_to_its_credential_id_and_kek() {
        let kek = Kek::generate();
        let mut totp = sealed_totp(&kek, &rfc_secret());
        let t = at(1_111_111_109);
        assert!(totp_step(&Kek::generate(), &totp, "081804", t).is_err());
        totp.id = CredentialId::new_v7();
        assert!(totp_step(&kek, &totp, "081804", t).is_err());
    }

    #[test]
    fn recovery_code_lookup_normalises_and_rejects_garbage() {
        let kek = Kek::generate();
        let a = recovery_code_lookup(&kek, "ABCD-EFGH-IJKL-MNOP").unwrap();
        let b = recovery_code_lookup(&kek, " abcd efgh ijkl mnop ").unwrap();
        assert_eq!(a, b);
        assert_ne!(
            Some(a),
            recovery_code_lookup(&Kek::generate(), "ABCD-EFGH-IJKL-MNOP")
        );
        for bad in ["", "ABCD", "ABCD-EFGH-IJKL-MNO1", &"A".repeat(100)] {
            assert_eq!(recovery_code_lookup(&kek, bad), None, "{bad:?}");
        }
    }

    #[test]
    fn recovery_code_used_email_is_sealed_with_tenant_name_and_remaining_only() {
        let kek = Kek::generate();
        let tenant = acme();
        let mail =
            recovery_code_used_email(&kek, &cx(&tenant), "alice@example.com", 7, NOW).unwrap();
        assert_eq!(mail.template, "recovery_code_used");
        assert_eq!(mail.to, "alice@example.com");
        assert_eq!(mail.expires_at, NOW + NOTICE_EMAIL_TTL);
        assert_eq!(mail.payload.len(), 1);
        assert!(mail.payload.contains_key(SEALED_PAYLOAD_KEY));
        let payload = open_payload(&kek, tenant.id, &mail.payload).unwrap();
        let keys: Vec<_> = payload.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["remaining", "tenant_name"]);
        assert_eq!(payload["remaining"], "7");
        assert_eq!(payload["tenant_name"], "Acme");
    }

    #[test]
    fn unavailable_relying_party_is_an_error_only_when_used() {
        let tenant = acme();
        let err: &'static Result<RelyingParty, CoreError> =
            Box::leak(Box::new(Err(CoreError::Internal("ip literal".into()))));
        let mut c = cx(&tenant);
        c.rp = err;
        assert!(matches!(c.relying_party(), Err(CoreError::Internal(_))));
        assert!(cx(&tenant).relying_party().is_ok());
    }

    fn login_flow(tenant: TenantId, state: &LoginState) -> Flow {
        let mut f = flow("cookie", "csrf", NOW + FLOW_LIFETIME);
        f.tenant_id = tenant;
        f.state = encode_state(&FlowState::Login(state.clone())).unwrap();
        f
    }

    const TOKEN: &str = "invitation-token-AbCdEfGhIjKlMnOpQrStUvWxYz0";

    fn target() -> ReturnTarget {
        parse_return_target(&format!("/ui/invitation?token={TOKEN}")).unwrap()
    }

    /// A login flow holding `target` sealed for itself.
    fn flow_with_target(kek: &Kek, tenant: TenantId) -> Flow {
        let mut f = login_flow(tenant, &LoginState::default());
        let sealed = seal_return_target(kek, tenant, f.id, &target()).unwrap();
        f.state = encode_state(&FlowState::Login(LoginState {
            return_to_sealed: Some(sealed),
            ..LoginState::default()
        }))
        .unwrap();
        f
    }

    #[test]
    fn continuation_prefers_the_authorization_request() {
        let kek = Kek::generate();
        let tenant = TenantId::new_v7();
        let mut f = flow_with_target(&kek, tenant);
        assert_eq!(
            continuation_of(&kek, tenant, &f),
            Some(Continue::Return(target()))
        );
        let request = AuthRequestId::new_v7();
        f.auth_request_id = Some(request);
        assert_eq!(
            continuation_of(&kek, tenant, &f),
            Some(Continue::Authorize(request))
        );
        // No target, no request: the signed-in page.
        let plain = login_flow(tenant, &LoginState::default());
        assert_eq!(continuation_of(&kek, tenant, &plain), None);
    }

    #[test]
    fn return_target_is_sealed_never_plaintext() {
        let kek = Kek::generate();
        let f = flow_with_target(&kek, TenantId::new_v7());
        assert!(f.state.contains("return_to_sealed"));
        assert!(!f.state.contains(TOKEN), "{}", f.state);
        assert!(!f.state.contains("/ui/invitation"), "{}", f.state);
    }

    #[test]
    fn return_target_does_not_open_elsewhere_or_tampered() {
        let kek = Kek::generate();
        let tenant = TenantId::new_v7();
        let f = flow_with_target(&kek, tenant);
        // Moved to another flow id (another flow's row), another tenant or another KEK.
        let mut moved = f.clone();
        moved.id = FlowId::new_v7();
        assert_eq!(continuation_of(&kek, tenant, &moved), None);
        assert_eq!(continuation_of(&kek, TenantId::new_v7(), &f), None);
        assert_eq!(continuation_of(&Kek::generate(), tenant, &f), None);
        // A tampered or garbage sealed value.
        let FlowState::Login(s) = serde_json::from_str::<FlowState>(&f.state).unwrap() else {
            panic!("login state");
        };
        let sealed = s.return_to_sealed.clone().unwrap();
        let mut raw = b64url_decode(&sealed).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        for bad in [b64url(&raw), "not base64 !".into(), String::new()] {
            let tampered = login_flow(
                tenant,
                &LoginState {
                    return_to_sealed: Some(bad.clone()),
                    ..s.clone()
                },
            );
            let tampered = Flow {
                id: f.id,
                ..tampered
            };
            assert_eq!(continuation_of(&kek, tenant, &tampered), None, "{bad:?}");
        }
        // A sealed value that is not an allowlisted target (defence in depth on open).
        let evil = kek
            .seal(
                RETURN_TO_PURPOSE,
                &upstream_aad(tenant, f.id),
                b"https://evil.example/ui/invitation?token=a",
            )
            .unwrap();
        let evil_flow = Flow {
            id: f.id,
            ..login_flow(
                tenant,
                &LoginState {
                    return_to_sealed: Some(b64url(&evil)),
                    ..LoginState::default()
                },
            )
        };
        assert_eq!(continuation_of(&kek, tenant, &evil_flow), None);
        // Not a login flow.
        let mut other = f.clone();
        other.state = "{}".into();
        assert_eq!(continuation_of(&kek, tenant, &other), None);
    }

    #[test]
    fn only_engine_flow_kinds_are_decoded() {
        for kind in FlowKind::ALL {
            let decodable = FlowState::initial(*kind, None, &FlowEnv::default()).is_ok();
            assert_eq!(engine_kind(*kind), decodable, "{kind:?}");
        }
    }
}
