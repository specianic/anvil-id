//! Flow engine: typed flow state, user inputs, effects and the pure transition dispatcher.
//!
//! # Execution style: plan effects, then fail over
//!
//! Every flow uses the same two-step style:
//!
//! 1. [`transition`] takes the stored state and a user input and returns the new state plus an
//!    ordered list of [`Effect`]s. It does no I/O. Input validation (password policy, email
//!    syntax, registration mode) happens here.
//! 2. The service (`service::flow::FlowService`) executes the effects in order through the
//!    ports. Effects that can fail for a user-visible reason (wrong password, breached password,
//!    email taken, invalid token, hasher overloaded) report a [`Failure`]. The first failure stops
//!    the list. The service then calls [`on_failure`] with the failed effect and the effects that
//!    did not run yet, and renders the form it returns. A failure never triggers further I/O.
//!
//! The last effect of every list is terminal: [`Effect::Render`], [`Effect::Message`],
//! [`Effect::CreateSession`], [`Effect::UpgradeSession`], [`Effect::SubmitSetup`] or (only
//! through `FlowService::passkey_options`) [`Effect::StartPasskey`].
//! [`Effect::CheckSecondFactor`] can end a list early by moving the login to its second-factor
//! step ([`second_factor_required`]) or its enrolment step ([`enroll_required`]).
//!
//! # Forms
//!
//! Forms produced here are not yet bound to a flow. `action` holds the page path below the UI
//! base (`login`, `registration`, `verification`, `recovery`, `setup`) and `csrf_token` holds
//! [`CSRF_PLACEHOLDER`]. The service replaces both before rendering.
//!
//! Passwords are never written into a form. Non-secret values (email, name, identifier) are
//! echoed back after a validation error.

use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use super::form::{FieldKind, FormDescription, FormField, FormMessage, MessageLevel};
pub use super::login::{
    AfterPrimary, LoginState, LoginStep, SecondFactorMethods, after_primary_auth, enroll_required,
    second_factor_required, step_up,
};
pub use super::recovery::RecoveryState;
pub use super::registration::RegistrationState;
pub use super::setup::SetupState;
pub use super::verification::VerificationState;
use super::{email_code, login, recovery, registration, setup, verification};
use crate::error::CoreError;
use crate::model::{
    ACR_MFA, ACR_PWD, AMR_FED, AMR_HWK, AMR_MFA, AMR_OTP, AMR_PWD, AMR_SWK, AMR_USER, FlowKind,
    RegistrationMode, SessionId, UserId, normalize_email,
};
use crate::policy::mfa::acr_for;
use crate::policy::{PasswordPolicy, check_password};

/// Placeholder for the CSRF token in forms produced by the engine. The service replaces it with
/// the flow's real token.
pub const CSRF_PLACEHOLDER: &str = "__csrf__";

/// Tenant settings and policy the transitions depend on. Built by the service per request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowEnv {
    pub registration: RegistrationMode,
    pub require_verified_email: bool,
    pub policy: PasswordPolicy,
    /// Email code / magic-link sign-in is enabled (tenant `email_otp` or `magic_link`).
    pub email_code: bool,
}

impl Default for FlowEnv {
    fn default() -> Self {
        Self {
            registration: RegistrationMode::Open,
            require_verified_email: false,
            policy: PasswordPolicy::default(),
            email_code: false,
        }
    }
}

/// Typed flow state, stored as JSON in `Flow.state`. Holds no secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FlowState {
    Login(LoginState),
    Registration(RegistrationState),
    Verification(VerificationState),
    Recovery(RecoveryState),
    Setup(SetupState),
}

impl FlowState {
    /// The flow kind of this state.
    pub fn kind(&self) -> FlowKind {
        match self {
            Self::Login(_) => FlowKind::Login,
            Self::Registration(_) => FlowKind::Registration,
            Self::Verification(_) => FlowKind::Verification,
            Self::Recovery(_) => FlowKind::Recovery,
            Self::Setup(_) => FlowKind::Setup,
        }
    }

    /// The initial state and form of a new flow. For verification and recovery, `token` (from
    /// the emailed link) goes into a hidden field unvalidated; it is only consumed on POST.
    ///
    /// `Settings`, `Consent` and `Logout` flows have their own state machines (`flow::settings`,
    /// driven by `service::account`, `flow::consent`, driven by `service::consent`, and
    /// `flow::logout`, driven by `service::logout`) and are never started here: asking this
    /// engine for one is an explicit error.
    pub fn initial(
        kind: FlowKind,
        token: Option<String>,
        env: &FlowEnv,
    ) -> Result<(FlowState, FormDescription), CoreError> {
        Ok(match kind {
            FlowKind::Login => {
                let s = LoginState::default();
                let f = login::form(&s, Vec::new());
                (Self::Login(s), f)
            }
            FlowKind::Registration => registration::initial(env),
            FlowKind::Verification => verification::initial(token),
            FlowKind::Recovery => recovery::initial(token),
            FlowKind::Setup => {
                let s = SetupState::default();
                let f = setup::form(&s, Vec::new(), Vec::new(), Vec::new());
                (Self::Setup(s), f)
            }
            FlowKind::Settings | FlowKind::Consent | FlowKind::Logout => {
                return Err(CoreError::Internal(format!(
                    "the {} flow is not started by the flow engine",
                    kind.as_str()
                )));
            }
        })
    }
}

/// A user input to a flow.
pub enum FlowInput {
    Login {
        identifier: String,
        password: String,
    },
    Register {
        email: String,
        password: String,
        name: Option<String>,
    },
    ConfirmVerification {
        token: String,
    },
    RequestRecovery {
        email: String,
    },
    ResetPassword {
        token: String,
        password: String,
    },
    Setup {
        email: String,
        password: String,
    },
    /// Request options for a usernameless passkey sign-in (login, identify step).
    PasskeyOptions,
    /// A WebAuthn assertion response (`PublicKeyCredential.toJSON()`) for the stored challenge.
    PasskeyAssertion {
        response_json: String,
    },
    /// A TOTP code (login, second-factor step).
    Totp {
        code: String,
    },
    /// A recovery code (login, second-factor step).
    RecoveryCode {
        code: String,
    },
    /// Send a sign-in email (login, identify step) to `email`; `None` sends a new code to the
    /// address of the current one (email step).
    EmailCodeRequest {
        email: Option<String>,
    },
    /// The code from the sign-in email (login, email step).
    EmailCode {
        code: String,
    },
    /// The token of the magic link (login, email step; through `FlowService::email_link`).
    EmailLink {
        token: String,
    },
}

impl FlowInput {
    /// The flow kind this input belongs to.
    pub fn kind(&self) -> FlowKind {
        match self {
            Self::Login { .. }
            | Self::PasskeyOptions
            | Self::PasskeyAssertion { .. }
            | Self::Totp { .. }
            | Self::RecoveryCode { .. }
            | Self::EmailCodeRequest { .. }
            | Self::EmailCode { .. }
            | Self::EmailLink { .. } => FlowKind::Login,
            Self::Register { .. } => FlowKind::Registration,
            Self::ConfirmVerification { .. } => FlowKind::Verification,
            Self::RequestRecovery { .. } | Self::ResetPassword { .. } => FlowKind::Recovery,
            Self::Setup { .. } => FlowKind::Setup,
        }
    }
}

const REDACTED: &str = "<redacted>";

impl std::fmt::Debug for FlowInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Login { identifier, .. } => f
                .debug_struct("Login")
                .field("identifier", identifier)
                .field("password", &REDACTED)
                .finish(),
            Self::Register { email, name, .. } => f
                .debug_struct("Register")
                .field("email", email)
                .field("password", &REDACTED)
                .field("name", name)
                .finish(),
            Self::ConfirmVerification { .. } => f
                .debug_struct("ConfirmVerification")
                .field("token", &REDACTED)
                .finish(),
            Self::RequestRecovery { email } => f
                .debug_struct("RequestRecovery")
                .field("email", email)
                .finish(),
            Self::ResetPassword { .. } => f
                .debug_struct("ResetPassword")
                .field("token", &REDACTED)
                .field("password", &REDACTED)
                .finish(),
            Self::Setup { email, .. } => f
                .debug_struct("Setup")
                .field("email", email)
                .field("password", &REDACTED)
                .finish(),
            Self::PasskeyOptions => f.write_str("PasskeyOptions"),
            Self::PasskeyAssertion { response_json } => f
                .debug_struct("PasskeyAssertion")
                .field("response_len", &response_json.len())
                .finish(),
            Self::Totp { .. } => f.debug_struct("Totp").field("code", &REDACTED).finish(),
            Self::RecoveryCode { .. } => f
                .debug_struct("RecoveryCode")
                .field("code", &REDACTED)
                .finish(),
            Self::EmailCodeRequest { email } => f
                .debug_struct("EmailCodeRequest")
                .field("email", email)
                .finish(),
            Self::EmailCode { .. } => f
                .debug_struct("EmailCode")
                .field("code", &REDACTED)
                .finish(),
            Self::EmailLink { .. } => f
                .debug_struct("EmailLink")
                .field("token", &REDACTED)
                .finish(),
        }
    }
}

/// How the user of a [`Effect::CreateSession`] authenticated; determines the session's `acr`
/// and `amr` ([`session_acr_amr`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAuth {
    /// Password only (also the sign-in right after self-registration).
    Password,
    /// Password, then a TOTP code or a recovery code.
    SecondFactor,
    /// A user-verified passkey (counts as multi-factor).
    Passkey,
    /// An upstream identity provider (social, OIDC, OAuth2): single factor (`flow::upstream`).
    Federated,
    /// An upstream identity provider, then a TOTP code or a recovery code.
    FederatedSecondFactor,
    /// An emailed one-time code or magic link (`flow::email_code`): single factor.
    EmailCode,
    /// An emailed code or link, then a TOTP code or a recovery code.
    EmailCodeSecondFactor,
}

/// `(acr, amr)` of a session: password `[pwd]` + pwd ACR; password plus TOTP or recovery code
/// `[pwd, otp, mfa]` + MFA ACR; passkey `[hwk|swk, user, mfa]` + MFA ACR, `swk` when the
/// passkey is backup eligible (synced), `hwk` otherwise; upstream provider `[fed]` + pwd ACR
/// (single factor), plus a second factor `[fed, otp, mfa]` + MFA ACR; emailed code or link `[otp]`
/// + pwd ACR (single factor, RFC 8176 `otp`), plus a second factor `[otp, mfa]` + MFA ACR.
pub fn session_acr_amr(
    auth: SessionAuth,
    passkey_backup_eligible: bool,
) -> (&'static str, Vec<String>) {
    let v = |xs: &[&str]| xs.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
    match auth {
        SessionAuth::Password => (ACR_PWD, v(&[AMR_PWD])),
        SessionAuth::SecondFactor => (ACR_MFA, v(&[AMR_PWD, AMR_OTP, AMR_MFA])),
        SessionAuth::Passkey => {
            let key = if passkey_backup_eligible {
                AMR_SWK
            } else {
                AMR_HWK
            };
            (ACR_MFA, v(&[key, AMR_USER, AMR_MFA]))
        }
        SessionAuth::Federated => (ACR_PWD, v(&[AMR_FED])),
        SessionAuth::FederatedSecondFactor => (ACR_MFA, v(&[AMR_FED, AMR_OTP, AMR_MFA])),
        SessionAuth::EmailCode => (ACR_PWD, v(&[AMR_OTP])),
        SessionAuth::EmailCodeSecondFactor => (ACR_MFA, v(&[AMR_OTP, AMR_MFA])),
    }
}

/// `(acr, amr)` of a session upgraded by a step-up with `auth`: the session's `amr` followed by
/// the values `auth` adds that it does not have yet (always including `mfa` for a second
/// factor); `acr` follows from the result ([`acr_for`]).
pub fn upgraded_acr_amr(
    existing: &[String],
    auth: SessionAuth,
    passkey_backup_eligible: bool,
) -> (&'static str, Vec<String>) {
    let (_, added) = session_acr_amr(auth, passkey_backup_eligible);
    let mut amr = existing.to_vec();
    for a in added {
        // A step-up proves the second factor only: it never adds the primary method (`pwd`
        // stays once after a password sign-in and is not claimed for an upstream sign-in).
        if a == AMR_PWD || a == AMR_FED {
            continue;
        }
        if !amr.contains(&a) {
            amr.push(a);
        }
    }
    (acr_for(&amr), amr)
}

/// Emails an effect list can request next to a domain change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailKind {
    /// Email verification link. Only valid directly after [`Effect::CreateUser`]; the service
    /// stores it in the same transaction as the user.
    Verification,
}

/// Work the service performs through the ports. `Debug` redacts passwords and tokens.
pub enum Effect {
    /// Look up the user by (normalised) email and verify the password. Unknown users, blocked
    /// users and users without a password run the dummy-hash path. Establishes the user that a
    /// following [`Effect::CreateSession`] signs in. Fails with `InvalidCredentials`,
    /// `EmailNotVerified` or `Overloaded`.
    VerifyPassword {
        email: String,
        password: SecretString,
    },
    /// Check the password against the breach corpus. Fails with `Breached`.
    CheckBreach { password: SecretString },
    /// Hash the password and create the user. Establishes the user for
    /// [`Effect::CreateSession`]. Fails with `EmailTaken` or `Overloaded`.
    CreateUser {
        email: String,
        name: Option<String>,
        password: SecretString,
    },
    /// Enqueue an email (see [`EmailKind`] for where each kind is valid).
    EnqueueEmail(EmailKind),
    /// After a successful [`Effect::VerifyPassword`]: applies the MFA policy
    /// ([`after_primary_auth`]): the login moves to its second-factor step
    /// ([`second_factor_required`]) or its enrolment step ([`enroll_required`]) and the remaining
    /// effects are dropped; or nothing happens (sign in single-factor).
    CheckSecondFactor,
    /// Terminal for `FlowService::passkey_options`: create a discoverable WebAuthn challenge and
    /// store its server-side state in [`LoginState::passkey_challenge`].
    StartPasskey,
    /// Take the challenge out of the stored flow state (compare-and-swap, so it is single-use),
    /// then verify the assertion against the tenant-scoped passkey of the asserted user handle
    /// and advance its counter. Establishes the user. Fails with `PasskeyInvalid` (or
    /// `EmailNotVerified`).
    FinishPasskey {
        response_json: String,
        challenge: String,
    },
    /// Verify a TOTP code of `user_id` and accept its time step at most once. Establishes the
    /// user. Fails with `SecondFactorInvalid`.
    VerifyTotp { user_id: UserId, code: SecretString },
    /// Consume a recovery code of `user_id` (atomically, with the notification email).
    /// Establishes the user. Fails with `SecondFactorInvalid`.
    ConsumeRecoveryCode { user_id: UserId, code: SecretString },
    /// Confirm the enrolment of the sealed `pending` TOTP secret with `code`; the secret is taken
    /// out of the flow state (compare-and-swap, single use) only when the code is right. Creates
    /// the credential and a recovery-code set and establishes the user. Fails with
    /// `SecondFactorInvalid`.
    ConfirmTotpEnrolment {
        user_id: UserId,
        pending: String,
        code: SecretString,
    },
    /// Terminal: sign the established user in (rotating any current session of the same user;
    /// revoking, with its token families, a session of another user) and finish the flow.
    CreateSession(SessionAuth),
    /// Terminal (step-up): upgrade the request's own `session` in place (`amr` union, `acr` from
    /// it, `auth_time` now) for the established user, who must be the session's user, and finish
    /// the flow.
    UpgradeSession {
        session: SessionId,
        auth: SessionAuth,
    },
    /// Terminal (`flow::email_code`): look the address up, generate a code and a link token, store
    /// their hashes in the login state (compare-and-swap; the login moves to the email step) and,
    /// only for an active user, enqueue the sealed `login_code` email. Renders the same "check your
    /// email" form either way.
    SendEmailCode { email: String },
    /// Terminal (`flow::email_code`), link confirmation whose matching account may not be
    /// revealed: like [`Effect::SendEmailCode`] for the pending link's upstream address, but the
    /// email goes only to the sealed matching account, and only when it is active with that
    /// verified address. Same work and the same "check your email" form either way.
    SendLinkEmailCode,
    /// Check the code against the stored hash (compare-and-swap: a right code clears the code and
    /// the link, a wrong one counts an attempt). Establishes the user. A code that does not sign in
    /// answers the email form with its message itself (no [`Failure`]).
    VerifyEmailCode { code: SecretString },
    /// Check the magic-link token like [`Effect::VerifyEmailCode`] (no attempt counting).
    ConsumeEmailLink { token: SecretString },
    /// Look the address up; if an active user has it, issue a recovery token and email it.
    /// Never fails visibly: the outcome is the same whether or not the account exists.
    IssueRecovery { email: String },
    /// Consume a verification token. Fails with `InvalidToken`.
    CompleteVerification { token: SecretString },
    /// Hash the password and consume a recovery token, setting the password and revoking all
    /// sessions and token families. Fails with `InvalidToken` or `Overloaded`.
    CompleteRecovery {
        token: SecretString,
        password: SecretString,
    },
    /// Terminal: hand validated setup input to the caller (bootstrap is not run by the flow
    /// service).
    SubmitSetup {
        email: String,
        password: SecretString,
    },
    /// Terminal: render a form.
    Render(FormDescription),
    /// Terminal: show a message page with this key and finish the flow.
    Message(&'static str),
}

impl std::fmt::Debug for Effect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VerifyPassword { email, .. } => f
                .debug_struct("VerifyPassword")
                .field("email", email)
                .field("password", &REDACTED)
                .finish(),
            Self::CheckBreach { .. } => f
                .debug_struct("CheckBreach")
                .field("password", &REDACTED)
                .finish(),
            Self::CreateUser { email, name, .. } => f
                .debug_struct("CreateUser")
                .field("email", email)
                .field("name", name)
                .field("password", &REDACTED)
                .finish(),
            Self::EnqueueEmail(k) => f.debug_tuple("EnqueueEmail").field(k).finish(),
            Self::CheckSecondFactor => f.write_str("CheckSecondFactor"),
            Self::StartPasskey => f.write_str("StartPasskey"),
            Self::FinishPasskey { response_json, .. } => f
                .debug_struct("FinishPasskey")
                .field("response_len", &response_json.len())
                .finish_non_exhaustive(),
            Self::VerifyTotp { user_id, .. } => f
                .debug_struct("VerifyTotp")
                .field("user_id", user_id)
                .field("code", &REDACTED)
                .finish(),
            Self::ConsumeRecoveryCode { user_id, .. } => f
                .debug_struct("ConsumeRecoveryCode")
                .field("user_id", user_id)
                .field("code", &REDACTED)
                .finish(),
            Self::ConfirmTotpEnrolment { user_id, .. } => f
                .debug_struct("ConfirmTotpEnrolment")
                .field("user_id", user_id)
                .field("pending", &REDACTED)
                .field("code", &REDACTED)
                .finish(),
            Self::CreateSession(auth) => f.debug_tuple("CreateSession").field(auth).finish(),
            Self::UpgradeSession { session, auth } => f
                .debug_struct("UpgradeSession")
                .field("session", session)
                .field("auth", auth)
                .finish(),
            Self::SendEmailCode { email } => f
                .debug_struct("SendEmailCode")
                .field("email", email)
                .finish(),
            Self::SendLinkEmailCode => f.write_str("SendLinkEmailCode"),
            Self::VerifyEmailCode { .. } => f
                .debug_struct("VerifyEmailCode")
                .field("code", &REDACTED)
                .finish(),
            Self::ConsumeEmailLink { .. } => f
                .debug_struct("ConsumeEmailLink")
                .field("token", &REDACTED)
                .finish(),
            Self::IssueRecovery { email } => f
                .debug_struct("IssueRecovery")
                .field("email", email)
                .finish(),
            Self::CompleteVerification { .. } => f
                .debug_struct("CompleteVerification")
                .field("token", &REDACTED)
                .finish(),
            Self::CompleteRecovery { .. } => f
                .debug_struct("CompleteRecovery")
                .field("token", &REDACTED)
                .field("password", &REDACTED)
                .finish(),
            Self::SubmitSetup { email, .. } => f
                .debug_struct("SubmitSetup")
                .field("email", email)
                .field("password", &REDACTED)
                .finish(),
            Self::Render(form) => f.debug_tuple("Render").field(&form.id).finish(),
            Self::Message(key) => f.debug_tuple("Message").field(key).finish(),
        }
    }
}

/// A user-visible reason an effect did not succeed. Storage and internal errors are not
/// failures; they abort the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    InvalidCredentials,
    EmailNotVerified,
    Breached,
    EmailTaken,
    InvalidToken,
    Overloaded,
    /// Wrong, replayed or malformed TOTP or recovery code.
    SecondFactorInvalid,
    /// Rejected passkey assertion (any reason; one generic failure).
    PasskeyInvalid,
}

/// The pure transition: plans the effects of `input` on `state`. An input of another flow kind
/// re-renders the current form with `flow.invalid_input`.
pub fn transition(state: FlowState, input: FlowInput, env: &FlowEnv) -> (FlowState, Vec<Effect>) {
    match (state, input) {
        (
            FlowState::Login(s),
            FlowInput::Login {
                identifier,
                password,
            },
        ) => login::transition(s, identifier, password, env),
        (FlowState::Login(s), FlowInput::PasskeyOptions) => login::passkey_options(s),
        (FlowState::Login(s), FlowInput::PasskeyAssertion { response_json }) => {
            login::passkey_assertion(s, response_json)
        }
        (FlowState::Login(s), FlowInput::Totp { code }) => login::totp(s, code),
        (FlowState::Login(s), FlowInput::RecoveryCode { code }) => login::recovery_code(s, code),
        (FlowState::Login(s), FlowInput::EmailCodeRequest { email }) => {
            email_code::request(s, email, env)
        }
        (FlowState::Login(s), FlowInput::EmailCode { code }) => email_code::verify(s, code),
        (FlowState::Login(s), FlowInput::EmailLink { token }) => email_code::link(s, token),
        (
            FlowState::Registration(s),
            FlowInput::Register {
                email,
                password,
                name,
            },
        ) => registration::transition(s, email, password, name, env),
        (FlowState::Verification(s), FlowInput::ConfirmVerification { token }) => {
            verification::transition(s, token)
        }
        (FlowState::Recovery(s), FlowInput::RequestRecovery { email }) => {
            recovery::request(s, email)
        }
        (FlowState::Recovery(s), FlowInput::ResetPassword { token, password }) => {
            recovery::reset(s, token, password, env)
        }
        (FlowState::Setup(s), FlowInput::Setup { email, password }) => {
            setup::transition(s, email, password, env)
        }
        (state, _) => {
            let form = current_form(&state, vec![error("flow.invalid_input")], env);
            (state, vec![Effect::Render(form)])
        }
    }
}

/// The form to render after `pending[0]` reported `failure`. `pending` is the failed effect
/// followed by the effects that did not run. Pure; never plans further I/O.
pub fn on_failure(
    state: FlowState,
    pending: &[Effect],
    failure: Failure,
    env: &FlowEnv,
) -> (FlowState, FormDescription) {
    match state {
        FlowState::Login(s) => {
            let f = login::on_failure(&s, failure);
            (FlowState::Login(s), f)
        }
        FlowState::Registration(s) => {
            let f = registration::on_failure(&s, failure, env);
            (FlowState::Registration(s), f)
        }
        FlowState::Verification(s) => {
            let f = verification::on_failure(failure);
            (FlowState::Verification(s), f)
        }
        FlowState::Recovery(s) => recovery::on_failure(s, pending, failure),
        FlowState::Setup(s) => {
            let f = setup::on_failure(&s, failure);
            (FlowState::Setup(s), f)
        }
    }
}

/// The current form of `state` with form-level `messages` (no field values beyond the state).
pub fn current_form(
    state: &FlowState,
    messages: Vec<FormMessage>,
    env: &FlowEnv,
) -> FormDescription {
    match state {
        FlowState::Login(s) => login::current_form(s, messages),
        FlowState::Registration(s) => registration::form(s, messages, Vec::new(), Vec::new(), env),
        FlowState::Verification(_) => verification::form(None, messages),
        FlowState::Recovery(s) => recovery::current_form(s, messages),
        FlowState::Setup(s) => setup::form(s, messages, Vec::new(), Vec::new()),
    }
}

// ---- form helpers shared by the flow modules ----

pub(super) fn error(key: &str) -> FormMessage {
    message(MessageLevel::Error, key)
}

pub(super) fn message(level: MessageLevel, key: &str) -> FormMessage {
    FormMessage::new(level, key)
}

pub(super) fn field(
    name: &str,
    kind: FieldKind,
    label_key: &str,
    value: Option<String>,
    required: bool,
    autocomplete: Option<&str>,
    messages: Vec<FormMessage>,
) -> FormField {
    FormField {
        name: name.to_owned(),
        kind,
        label_key: label_key.to_owned(),
        label: String::new(),
        // Password values are never echoed.
        value: if kind == FieldKind::Password {
            None
        } else {
            value
        },
        required,
        autocomplete: autocomplete.map(str::to_owned),
        messages,
    }
}

pub(super) fn password_field(autocomplete: &str, messages: Vec<FormMessage>) -> FormField {
    field(
        "password",
        FieldKind::Password,
        "field.password",
        None,
        true,
        Some(autocomplete),
        messages,
    )
}

pub(super) fn form(
    id: &str,
    action: &str,
    fields: Vec<FormField>,
    messages: Vec<FormMessage>,
) -> FormDescription {
    FormDescription {
        id: id.to_owned(),
        action: action.to_owned(),
        method: "post",
        fields,
        messages,
        csrf_token: CSRF_PLACEHOLDER.to_owned(),
    }
}

/// The message key for a password policy violation, if any.
pub(super) fn password_error(policy: &PasswordPolicy, password: &str) -> Option<&'static str> {
    match check_password(policy, password) {
        Ok(()) => None,
        Err(_) if password.chars().count() < policy.min_len => Some("password.too_short"),
        Err(_) => Some("password.too_long"),
    }
}

/// Validates email and password together. Returns the normalised email or the field messages.
pub(super) fn validate_credentials(
    raw_email: &str,
    password: &str,
    policy: &PasswordPolicy,
) -> Result<String, (Vec<FormMessage>, Vec<FormMessage>)> {
    let email = normalize_email(raw_email);
    let pw = password_error(policy, password);
    match (email, pw) {
        (Ok(email), None) => Ok(email),
        (email, pw) => Err((
            if email.is_err() {
                vec![error("email.invalid")]
            } else {
                Vec::new()
            },
            pw.map(error).into_iter().collect(),
        )),
    }
}

pub(super) fn secret(s: String) -> SecretString {
    SecretString::from(s)
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::super::form::{FieldKind, FormDescription};

    pub const IDS: [&str; 9] = [
        "login",
        "email-code",
        "second-factor",
        "mfa-enroll",
        "registration",
        "verification",
        "recovery",
        "recovery-reset",
        "setup",
    ];

    /// Invariants every engine form satisfies.
    pub fn assert_form_invariants(form: &FormDescription, secrets: &[&str]) {
        assert!(IDS.contains(&form.id.as_str()), "form id {}", form.id);
        assert!(!form.csrf_token.is_empty());
        assert_eq!(form.method, "post");
        for f in &form.fields {
            if f.kind == FieldKind::Password {
                assert!(f.value.is_none(), "password echoed in {}", form.id);
            }
            for s in secrets {
                assert_ne!(f.value.as_deref(), Some(*s), "secret echoed in {}", f.name);
            }
        }
    }

    pub fn all_keys(form: &FormDescription) -> Vec<String> {
        let mut keys: Vec<String> = form.messages.iter().map(|m| m.key.clone()).collect();
        for f in &form.fields {
            keys.extend(f.messages.iter().map(|m| m.key.clone()));
        }
        keys
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    #[test]
    fn flow_state_round_trips_through_json() {
        let env = FlowEnv::default();
        for kind in FlowKind::ALL {
            for token in [None, Some("tok".to_owned())] {
                let Ok((state, _)) = FlowState::initial(*kind, token, &env) else {
                    assert!(matches!(
                        kind,
                        FlowKind::Settings | FlowKind::Consent | FlowKind::Logout
                    ));
                    continue;
                };
                let json = serde_json::to_string(&state).unwrap();
                let back: FlowState = serde_json::from_str(&json).unwrap();
                assert_eq!(back, state);
                assert_eq!(back.kind(), *kind);
                assert!(
                    !json.contains("tok"),
                    "state must not hold the token: {json}"
                );
            }
        }
        let s = FlowState::Registration(RegistrationState {
            email: Some("a@b.c".into()),
            name: Some("A".into()),
        });
        let back: FlowState = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn flow_input_debug_redacts_secrets() {
        let inputs = [
            FlowInput::Login {
                identifier: "a@b.c".into(),
                password: "hunter2-secret".into(),
            },
            FlowInput::Register {
                email: "a@b.c".into(),
                password: "hunter2-secret".into(),
                name: None,
            },
            FlowInput::ConfirmVerification {
                token: "tok-secret".into(),
            },
            FlowInput::RequestRecovery {
                email: "a@b.c".into(),
            },
            FlowInput::ResetPassword {
                token: "tok-secret".into(),
                password: "hunter2-secret".into(),
            },
            FlowInput::Setup {
                email: "a@b.c".into(),
                password: "hunter2-secret".into(),
            },
            FlowInput::Totp {
                code: "secret-123456".into(),
            },
            FlowInput::RecoveryCode {
                code: "secret-code".into(),
            },
            FlowInput::PasskeyAssertion {
                response_json: "{\"secret\":1}".into(),
            },
            FlowInput::EmailCode {
                code: "secret-123456".into(),
            },
            FlowInput::EmailLink {
                token: "secret-token".into(),
            },
        ];
        for i in &inputs {
            let d = format!("{i:?}");
            assert!(!d.contains("secret"), "{d}");
        }
    }

    #[test]
    fn effect_debug_redacts_secrets() {
        let effects = [
            Effect::VerifyPassword {
                email: "a@b.c".into(),
                password: secret("pw-secret".into()),
            },
            Effect::CheckBreach {
                password: secret("pw-secret".into()),
            },
            Effect::CreateUser {
                email: "a@b.c".into(),
                name: None,
                password: secret("pw-secret".into()),
            },
            Effect::CompleteVerification {
                token: secret("tok-secret".into()),
            },
            Effect::CompleteRecovery {
                token: secret("tok-secret".into()),
                password: secret("pw-secret".into()),
            },
            Effect::SubmitSetup {
                email: "a@b.c".into(),
                password: secret("pw-secret".into()),
            },
            Effect::VerifyTotp {
                user_id: UserId::new_v7(),
                code: secret("secret-123456".into()),
            },
            Effect::ConsumeRecoveryCode {
                user_id: UserId::new_v7(),
                code: secret("secret-code".into()),
            },
            Effect::FinishPasskey {
                response_json: "{\"secret\":1}".into(),
                challenge: "challenge-secret".into(),
            },
            Effect::VerifyEmailCode {
                code: secret("secret-123456".into()),
            },
            Effect::ConsumeEmailLink {
                token: secret("secret-token".into()),
            },
        ];
        for e in &effects {
            let d = format!("{e:?}");
            assert!(!d.contains("secret"), "{d}");
        }
    }

    #[test]
    fn initial_forms_satisfy_invariants() {
        let env = FlowEnv::default();
        for kind in FlowKind::ALL {
            for token in [None, Some("tok".to_owned())] {
                let Ok((_, form)) = FlowState::initial(*kind, token, &env) else {
                    assert!(matches!(
                        kind,
                        FlowKind::Settings | FlowKind::Consent | FlowKind::Logout
                    ));
                    continue;
                };
                assert_form_invariants(&form, &[]);
                assert_eq!(form.csrf_token, CSRF_PLACEHOLDER);
            }
        }
    }

    #[test]
    fn mismatched_input_rerenders_without_effects() {
        let env = FlowEnv::default();
        let (state, _) = FlowState::initial(FlowKind::Login, None, &env).unwrap();
        let (next, effects) = transition(
            state.clone(),
            FlowInput::ConfirmVerification { token: "x".into() },
            &env,
        );
        assert_eq!(next, state);
        assert_eq!(effects.len(), 1);
        match &effects[0] {
            Effect::Render(f) => {
                assert_eq!(f.id, "login");
                assert_eq!(all_keys(f), vec!["flow.invalid_input"]);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn core_messages_and_fields_carry_keys_not_text() {
        let m = error("login.invalid_credentials");
        assert_eq!(m.key, "login.invalid_credentials");
        assert_eq!(m.level, MessageLevel::Error);
        assert!(
            m.text.is_empty(),
            "text is filled by the presentation layer"
        );
        assert!(m.args.is_empty());
        let f = password_field("current-password", Vec::new());
        assert_eq!(f.label_key, "field.password");
        assert!(
            f.label.is_empty(),
            "labels are filled by the presentation layer"
        );
    }

    #[test]
    fn step_up_amr_is_the_union_plus_mfa() {
        let pwd = vec![AMR_PWD.to_owned()];
        let (acr, amr) = upgraded_acr_amr(&pwd, SessionAuth::SecondFactor, false);
        assert_eq!(acr, ACR_MFA);
        assert_eq!(amr, vec![AMR_PWD, AMR_OTP, AMR_MFA]);
        // Nothing is duplicated when the session already had some of the values.
        let had = vec![AMR_PWD.to_owned(), AMR_OTP.to_owned()];
        let (_, amr) = upgraded_acr_amr(&had, SessionAuth::SecondFactor, false);
        assert_eq!(amr, vec![AMR_PWD, AMR_OTP, AMR_MFA]);
        // An upstream session stepped up does not claim a password.
        let fed = vec![AMR_FED.to_owned()];
        let (acr, amr) = upgraded_acr_amr(&fed, SessionAuth::SecondFactor, false);
        assert_eq!(acr, ACR_MFA);
        assert_eq!(amr, vec![AMR_FED, AMR_OTP, AMR_MFA]);
        // An email-code session stepped up gains mfa only.
        let otp = vec![AMR_OTP.to_owned()];
        let (acr, amr) = upgraded_acr_amr(&otp, SessionAuth::SecondFactor, false);
        assert_eq!(acr, ACR_MFA);
        assert_eq!(amr, vec![AMR_OTP, AMR_MFA]);
    }

    #[test]
    fn session_acr_amr_per_method() {
        let s = |xs: &[&str]| xs.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            session_acr_amr(SessionAuth::Password, true),
            (ACR_PWD, s(&["pwd"]))
        );
        assert_eq!(
            session_acr_amr(SessionAuth::SecondFactor, false),
            (ACR_MFA, s(&["pwd", "otp", "mfa"]))
        );
        assert_eq!(
            session_acr_amr(SessionAuth::Passkey, false),
            (ACR_MFA, s(&["hwk", "user", "mfa"]))
        );
        assert_eq!(
            session_acr_amr(SessionAuth::Passkey, true),
            (ACR_MFA, s(&["swk", "user", "mfa"]))
        );
        assert_eq!(
            session_acr_amr(SessionAuth::Federated, false),
            (ACR_PWD, s(&["fed"]))
        );
        assert_eq!(
            session_acr_amr(SessionAuth::FederatedSecondFactor, false),
            (ACR_MFA, s(&["fed", "otp", "mfa"]))
        );
        // Email sign-in is single factor and never claims mfa.
        assert_eq!(
            session_acr_amr(SessionAuth::EmailCode, false),
            (ACR_PWD, s(&["otp"]))
        );
        assert_eq!(
            session_acr_amr(SessionAuth::EmailCodeSecondFactor, false),
            (ACR_MFA, s(&["otp", "mfa"]))
        );
    }

    #[test]
    fn password_error_keys() {
        let p = PasswordPolicy::default();
        assert_eq!(password_error(&p, "1234567"), Some("password.too_short"));
        assert_eq!(
            password_error(&p, &"a".repeat(1025)),
            Some("password.too_long")
        );
        assert_eq!(password_error(&p, "12345678"), None);
    }
}
