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
//! [`Effect::CreateSession`] or [`Effect::SubmitSetup`].
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
pub use super::login::LoginState;
pub use super::recovery::RecoveryState;
pub use super::registration::RegistrationState;
pub use super::setup::SetupState;
pub use super::verification::VerificationState;
use super::{login, recovery, registration, setup, verification};
use crate::error::CoreError;
use crate::model::{FlowKind, RegistrationMode, normalize_email};
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
}

impl Default for FlowEnv {
    fn default() -> Self {
        Self {
            registration: RegistrationMode::Open,
            require_verified_email: false,
            policy: PasswordPolicy::default(),
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
    /// `Settings` and `Consent` flows are declared in the model (plan 03-02) but not implemented
    /// by this engine yet: starting one is an explicit error.
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
            FlowKind::Settings | FlowKind::Consent => {
                return Err(CoreError::Internal(format!(
                    "the {} flow is not implemented",
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
}

impl FlowInput {
    /// The flow kind this input belongs to.
    pub fn kind(&self) -> FlowKind {
        match self {
            Self::Login { .. } => FlowKind::Login,
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
        }
    }
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
    /// Terminal: sign the established user in (rotating any current session) and finish the
    /// flow.
    CreateSession,
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
            Self::CreateSession => f.write_str("CreateSession"),
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
        FlowState::Login(s) => login::form(s, messages),
        FlowState::Registration(s) => registration::form(s, messages, Vec::new(), Vec::new(), env),
        FlowState::Verification(_) => verification::form(None, messages),
        FlowState::Recovery(s) => recovery::current_form(s, messages),
        FlowState::Setup(s) => setup::form(s, messages, Vec::new(), Vec::new()),
    }
}

/// Display text for a message key. Unknown keys get a generic sentence.
pub fn message_text(key: &str) -> &'static str {
    match key {
        "login.invalid_credentials" => "The email address or password is incorrect.",
        "login.email_not_verified" => "Please confirm your email address before signing in.",
        "registration.disabled" => "Self-registration is not available.",
        "registration.email_taken" => "An account with this email address already exists.",
        "registration.check_email" => {
            "Your account was created. Check your email to confirm your address, then sign in."
        }
        "email.invalid" => "Enter a valid email address.",
        "password.too_short" => "The password is too short.",
        "password.too_long" => "The password is too long.",
        "password.breached" => {
            "This password has appeared in a data breach. Please choose a different one."
        }
        "recovery.sent" => {
            "If an account exists for that address, we have sent instructions to reset the password."
        }
        "recovery.invalid_token" => {
            "This password reset link is invalid or has expired. Please request a new one."
        }
        "recovery.done" => "Your password has been changed. You can now sign in.",
        "verification.invalid_token" => "This confirmation link is invalid or has expired.",
        "verification.done" => "Your email address is confirmed.",
        "flow.expired" => "This sign-in attempt expired. Please start again.",
        "flow.invalid_input" => "This form submission could not be processed. Please try again.",
        "service.overloaded" => "The service is busy. Please try again in a moment.",
        _ => "Something went wrong.",
    }
}

// ---- form helpers shared by the flow modules ----

pub(super) fn error(key: &str) -> FormMessage {
    message(MessageLevel::Error, key)
}

pub(super) fn message(level: MessageLevel, key: &str) -> FormMessage {
    FormMessage {
        level,
        key: key.to_owned(),
        text: message_text(key).to_owned(),
    }
}

pub(super) fn field(
    name: &str,
    kind: FieldKind,
    label: &str,
    value: Option<String>,
    required: bool,
    autocomplete: Option<&str>,
    messages: Vec<FormMessage>,
) -> FormField {
    FormField {
        name: name.to_owned(),
        kind,
        label: label.to_owned(),
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
        "Password",
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

    pub const IDS: [&str; 6] = [
        "login",
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
                    assert!(matches!(kind, FlowKind::Settings | FlowKind::Consent));
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
                    assert!(matches!(kind, FlowKind::Settings | FlowKind::Consent));
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
    fn every_listed_key_has_text() {
        for key in [
            "login.invalid_credentials",
            "registration.disabled",
            "registration.email_taken",
            "password.too_short",
            "password.too_long",
            "password.breached",
            "recovery.sent",
            "recovery.invalid_token",
            "verification.invalid_token",
            "verification.done",
            "flow.expired",
            "service.overloaded",
        ] {
            assert_ne!(message_text(key), message_text("unknown.key"), "{key}");
        }
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
