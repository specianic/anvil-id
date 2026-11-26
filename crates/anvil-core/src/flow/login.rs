//! Login flow: password (optionally followed by a second factor) and usernameless passkey
//! sign-in.
//!
//! # Steps
//!
//! - [`LoginStep::Identify`]: the email/password form. A correct password is followed by
//!   [`Effect::CheckSecondFactor`]: a user with a second factor (TOTP or a passkey,
//!   [`SecondFactorMethods::any`]) moves to [`LoginStep::SecondFactor`]
//!   ([`second_factor_required`]); a user without signs in with `amr = [pwd]`. The same step
//!   accepts a passkey assertion against the challenge stored in
//!   [`LoginState::passkey_challenge`] (put there by [`Effect::StartPasskey`]).
//! - [`LoginStep::SecondFactor`]: a TOTP code or a recovery code for the user whose password
//!   was verified; success signs in with `amr = [pwd, otp, mfa]`. A user with a passkey can
//!   instead present it: [`second_factor_passkey_user`] allows the assertion options (the
//!   service stores the discoverable challenge in [`LoginState::second_factor_passkey`], never in
//!   [`LoginState::passkey_challenge`], so an identify-step challenge is not accepted here), and
//!   [`take_second_factor_passkey`] takes it out before the assertion is verified (single use).
//!   The assertion must come from one of the step user's own passkeys; success signs in like a
//!   passkey sign-in, `amr = [hwk|swk, user, mfa]` ([`passkey_enrolment_finish`]).
//! - [`LoginStep::Enroll`]: the effective policy is `Required` and the user has no second factor.
//!   The page offers a choice:
//!   - an authenticator app (the sealed pending secret is in [`LoginState::pending_totp`]); the
//!     confirming code signs them in with `amr = [pwd, otp, mfa]`. Works without JavaScript.
//!   - a passkey: [`passkey_enrolment_user`] allows the registration options (the service stores
//!     the registration state in [`LoginState::enroll_passkey`] with a compare-and-swap), and
//!     [`take_passkey_enrolment`] takes that state out before the response is verified (single
//!     use). The stored passkey signs them in like a passkey sign-in:
//!     `amr = [hwk|swk, user, mfa]` ([`passkey_enrolment_finish`]).
//!
//! # MFA policy (AUTH-08)
//!
//! After the password, [`after_primary_auth`] applies
//! [`mfa_requirement`] to the effective policy (strictest of
//! tenant and client), the authorization request's `acr` and the user's factors: `Off` never
//! prompts, `Optional` prompts users who have a factor, `Required` prompts or forces enrolment.
//! An essential `acr` that cannot be met still signs the user in single-factor (truthful `acr`);
//! the authorization endpoint then answers `unmet_authentication_requirements`.
//!
//! # Step-up
//!
//! A flow started for a signed-in single-factor session ([`step_up`]) begins at
//! [`LoginStep::SecondFactor`] or [`LoginStep::Enroll`] for the session's user, with
//! [`LoginState::step_up_session`] set. Success then ends in [`Effect::UpgradeSession`] (the
//! session is upgraded in place) instead of [`Effect::CreateSession`].
//!
//! # Email code and magic link (AUTH-06)
//!
//! [`LoginStep::EmailCode`] (`flow::email_code`): a sign-in email was requested; the code or the
//! link signs in with `amr = [otp]` (single factor), then the MFA policy applies as after a
//! password, and a second factor after it ends in [`SessionAuth::EmailCodeSecondFactor`].
//!
//! # Identifier-first sign-in and home-realm discovery (ORG-04)
//!
//! A tenant with at least one verified, routed domain starts the login at
//! [`LoginStep::EmailFirst`] ([`email_first`], form [`IDENTIFY_FORM_ID`]); every other tenant
//! keeps the combined [`LoginStep::Identify`] form. The service routes the submitted email by its
//! **domain only** ([`crate::policy::home_realm::route`], no account lookup) into an [`HrdRoute`]
//! and [`routed`] decides:
//!
//! - [`HrdRoute::Local`]: the password step ([`LoginStep::Identify`] with
//!   [`LoginState::email_first`]: the email is carried in a hidden field and shown read-only). The
//!   same page for every non-routed address, known or unknown.
//! - [`HrdRoute::Sso`] with `allow_local_password = false`: [`Identified::StartIdp`] (the
//!   browser goes straight to the org's IdP).
//! - [`HrdRoute::Sso`] with `allow_local_password = true` (the default, decision Q6/Q7):
//!   [`LoginStep::SsoChoice`] ("Continue with single sign-on" or "Use password instead",
//!   [`IdentifyInput`]).
//!
//! Passkeys and upstream buttons are accepted in every primary step ([`LoginStep::is_primary`]).
//! Password, email-code and magic-link sign-in for an address whose domain forces SSO are refused
//! by the service with [`USE_SSO`].
//!
//! Inputs that do not belong to the current step re-render the step's form with
//! `flow.invalid_input` and plan no effects.
//!
//! # Enumeration safety
//!
//! Every password failure (unknown user, blocked user, user without a password, wrong password)
//! is reported as the same [`Failure::InvalidCredentials`] by the service, and renders the same
//! form with the single message `login.invalid_credentials`. Every passkey failure renders
//! `login.passkey_failed`.

use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use super::email_code::{self, EmailCodeState};
use super::engine::{
    Effect, Failure, FlowEnv, FlowState, SessionAuth, error, field, form as build_form,
    password_field, secret,
};
use super::form::{FieldKind, FormDescription, FormMessage, MessageLevel};
use super::upstream::{PendingLink, PendingUpstream};
use crate::model::{ConnectionId, MfaPolicy, SessionId, UserId, normalize_email};
use crate::policy::mfa::{AcrRequest, MfaRequirement, mfa_requirement};

/// Id of the second-factor form.
pub const SECOND_FACTOR_FORM_ID: &str = "second-factor";
/// Name of the hidden marker field of the second-factor form that offers a passkey
/// (`second_factor_form`).
pub const SECOND_FACTOR_PASSKEY_FIELD: &str = "passkey";
/// Id of the in-flow enrolment form.
pub const ENROLL_FORM_ID: &str = "mfa-enroll";
/// Id of the sign-in form shown while an upstream identity waits for link confirmation.
pub const UPSTREAM_LINK_FORM_ID: &str = "upstream-link";
/// Id of the email-first form ([`LoginStep::EmailFirst`]).
pub const IDENTIFY_FORM_ID: &str = "login-identify";
/// Id of the single-sign-on choice form ([`LoginStep::SsoChoice`]).
pub const SSO_CHOICE_FORM_ID: &str = "login-sso-choice";
/// Message key of a local sign-in (password, email code, magic link) refused because the email's
/// domain signs in through its organization's identity provider.
pub const USE_SSO: &str = "hrd.use_sso";

/// Login state, stored as flow JSON. Every field has a serde default so flow JSON written by
/// release 0.1 (`{"kind":"login","identifier":…}`) still decodes.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LoginState {
    /// The last identifier entered (echoed after a failure).
    #[serde(default)]
    pub identifier: Option<String>,
    #[serde(default)]
    pub step: LoginStep,
    /// Server-side state of the pending discoverable WebAuthn challenge (not a secret, but
    /// single-use: taken out with a compare-and-swap before verification).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passkey_challenge: Option<String>,
    /// Step-up: the signed-in session this flow upgrades instead of creating a new one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_up_session: Option<SessionId>,
    /// Enrolment: the pending TOTP secret, sealed with the KEK under the flow id (base64url).
    /// Taken out with a compare-and-swap when the confirming code is accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_totp: Option<String>,
    /// Enrolment: the server-side state of a pending passkey registration (webauthn-rs
    /// registration state for the step's user). Not a secret, but single-use: taken out with a
    /// compare-and-swap before the registration response is verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enroll_passkey: Option<String>,
    /// Second-factor step: the server-side state of a discoverable passkey challenge issued at
    /// this step for the step's user. Not a secret, but single-use: taken out with a
    /// compare-and-swap before the assertion is verified. Separate from
    /// [`Self::passkey_challenge`] so a challenge of the identify step is never accepted here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub second_factor_passkey: Option<String>,
    /// A started upstream sign-in (`flow::upstream`); taken out with a compare-and-swap by the
    /// callback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream: Option<Box<PendingUpstream>>,
    /// An upstream identity waiting for the user to sign in to an existing account: the account
    /// proved in this flow gets the link (`flow::upstream`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_link: Option<Box<PendingLink>>,
    /// The primary authentication was an upstream sign-in (`amr` `fed`, not `pwd`): a second
    /// factor ends in [`SessionAuth::FederatedSecondFactor`].
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub federated: bool,
    /// A requested sign-in email (`flow::email_code`): hashes of the code and the link only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_code: Option<Box<EmailCodeState>>,
    /// The primary authentication was an email code or link (`amr` `otp`, not `pwd`): a second
    /// factor ends in [`SessionAuth::EmailCodeSecondFactor`].
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub email_primary: bool,
    /// A started SAML sign-in ([`SamlPending`], 06-18): the pending `AuthnRequest`, then the
    /// verified identity until the continue step takes it out with a compare-and-swap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saml: Option<Box<SamlPending>>,
    /// The email was entered on the email-first page (home-realm discovery): the password step
    /// carries it in a hidden field and shows it read-only with a way back to the email page.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub email_first: bool,
    /// Where the sign-in returns when it is not bound to an authorization request (an allowlisted
    /// `policy::return_to::ReturnTarget`, the invitation page): sealed with the KEK under the
    /// tenant and the flow id (base64url), because it carries the invitation token. Set only by a
    /// fresh login started without an authorization request; resealed when the login continues
    /// in a new flow (`FlowService::continue_login`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_to_sealed: Option<String>,
}

/// Where the login stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "name", rename_all = "snake_case")]
pub enum LoginStep {
    /// Email and password (or a passkey).
    #[default]
    Identify,
    /// The password of `user_id` was verified; a second factor is required.
    SecondFactor {
        user_id: UserId,
        methods: SecondFactorMethods,
    },
    /// The policy requires a second factor `user_id` does not have: enrol one first.
    Enroll { user_id: UserId },
    /// A sign-in email was requested ([`LoginState::email_code`]): enter its code or open its link.
    EmailCode,
    /// Identifier-first sign-in (the tenant has a routed domain): the email alone, then routing by
    /// its domain (or a passkey / upstream button).
    EmailFirst,
    /// The email's domain routes to `connection_id` and its org still allows passwords: continue
    /// with single sign-on or use the password instead.
    SsoChoice { connection_id: ConnectionId },
}

impl LoginStep {
    /// Whether a primary authentication (password form, passkey, upstream or SAML start) may
    /// begin in this step.
    pub fn is_primary(self) -> bool {
        matches!(
            self,
            Self::Identify | Self::EmailFirst | Self::SsoChoice { .. }
        )
    }
}

/// What follows a successful primary authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfterPrimary {
    /// Sign in single-factor.
    SignIn,
    /// Ask for one of these second factors.
    SecondFactor(SecondFactorMethods),
    /// Enrol a second factor first.
    Enroll,
}

/// The policy decision after the password ([`mfa_requirement`] with a single-factor sign-in).
/// `Unmet` signs in (the authorization endpoint answers the RP); see the module docs.
pub fn after_primary_auth(
    policy: MfaPolicy,
    acr: AcrRequest,
    methods: SecondFactorMethods,
) -> AfterPrimary {
    match mfa_requirement(policy, acr, false, methods.any()) {
        MfaRequirement::None | MfaRequirement::Unmet => AfterPrimary::SignIn,
        MfaRequirement::SecondFactor => AfterPrimary::SecondFactor(methods),
        MfaRequirement::Enroll => AfterPrimary::Enroll,
    }
}

/// Second factors the user can use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SecondFactorMethods {
    /// The user has a TOTP credential.
    pub totp: bool,
    /// The user has unused recovery codes (they belong to the TOTP credential).
    pub recovery: bool,
    /// The user has at least one passkey. Absent in flow rows written before 0.4.
    #[serde(default)]
    pub passkey: bool,
}

impl SecondFactorMethods {
    /// Whether the user has a second factor at all (TOTP or a passkey; recovery codes only back
    /// up TOTP). The one answer the login engine, the step-up path and the authorization
    /// decision use.
    pub fn any(self) -> bool {
        self.totp || self.passkey
    }
}

pub(super) fn transition(
    mut state: LoginState,
    identifier: String,
    password: String,
    _env: &FlowEnv,
) -> (FlowState, Vec<Effect>) {
    if state.step != LoginStep::Identify {
        return invalid_input(state);
    }
    let identifier = identifier.trim().to_owned();
    state.identifier = (!identifier.is_empty()).then(|| identifier.clone());
    match normalize_email(&identifier) {
        Ok(email) if !password.is_empty() => {
            let effects = vec![
                Effect::VerifyPassword {
                    email,
                    password: secret(password),
                },
                Effect::CheckSecondFactor,
                Effect::CreateSession(SessionAuth::Password),
            ];
            (FlowState::Login(state), effects)
        }
        // A malformed identifier or empty password cannot match any account; this reveals
        // nothing about which accounts exist.
        _ => {
            let f = form(&state, vec![error("login.invalid_credentials")]);
            (FlowState::Login(state), vec![Effect::Render(f)])
        }
    }
}

/// Passkey options requested: the service creates the challenge and stores it in the state.
pub(super) fn passkey_options(state: LoginState) -> (FlowState, Vec<Effect>) {
    if !state.step.is_primary() {
        return invalid_input(state);
    }
    (FlowState::Login(state), vec![Effect::StartPasskey])
}

/// A passkey assertion: the stored challenge is taken out of the state (the service swaps the
/// state before verifying, so the challenge is single-use).
pub(super) fn passkey_assertion(
    mut state: LoginState,
    response_json: String,
) -> (FlowState, Vec<Effect>) {
    if !state.step.is_primary() {
        return invalid_input(state);
    }
    match state.passkey_challenge.take() {
        Some(challenge) if !response_json.is_empty() => (
            FlowState::Login(state),
            vec![
                Effect::FinishPasskey {
                    response_json,
                    challenge,
                },
                Effect::CreateSession(SessionAuth::Passkey),
            ],
        ),
        // No challenge (none requested, or already used) or an empty response: the same
        // generic passkey failure. A present challenge is kept for a retry.
        other => {
            state.passkey_challenge = other;
            let f = current_form(&state, vec![error("login.passkey_failed")]);
            (FlowState::Login(state), vec![Effect::Render(f)])
        }
    }
}

/// The terminal effect after a second factor: upgrade the step-up session, or sign in (after an
/// upstream sign-in with `[fed, otp, mfa]`).
fn finish(state: &LoginState) -> Effect {
    match state.step_up_session {
        Some(session) => Effect::UpgradeSession {
            session,
            auth: SessionAuth::SecondFactor,
        },
        None if state.federated => Effect::CreateSession(SessionAuth::FederatedSecondFactor),
        None if state.email_primary => Effect::CreateSession(SessionAuth::EmailCodeSecondFactor),
        None => Effect::CreateSession(SessionAuth::SecondFactor),
    }
}

pub(super) fn totp(state: LoginState, code: String) -> (FlowState, Vec<Effect>) {
    match state.step {
        LoginStep::SecondFactor { user_id, methods } if methods.totp => {
            let effects = vec![
                Effect::VerifyTotp {
                    user_id,
                    code: secret(code),
                },
                finish(&state),
            ];
            (FlowState::Login(state), effects)
        }
        LoginStep::Enroll { user_id } => match state.pending_totp.clone() {
            Some(pending) => {
                let effects = vec![
                    Effect::ConfirmTotpEnrolment {
                        user_id,
                        pending,
                        code: secret(code),
                    },
                    finish(&state),
                ];
                (FlowState::Login(state), effects)
            }
            None => invalid_input(state),
        },
        _ => invalid_input(state),
    }
}

pub(super) fn recovery_code(state: LoginState, code: String) -> (FlowState, Vec<Effect>) {
    match state.step {
        LoginStep::SecondFactor { user_id, methods } if methods.recovery => {
            let effects = vec![
                Effect::ConsumeRecoveryCode {
                    user_id,
                    code: secret(code),
                },
                finish(&state),
            ];
            (FlowState::Login(state), effects)
        }
        _ => invalid_input(state),
    }
}

/// The password of `user_id` was verified and the user has a second factor: move to the
/// second-factor step (no session yet) and render its form. Any pending passkey challenge is
/// dropped.
pub fn second_factor_required(
    mut state: LoginState,
    user_id: UserId,
    methods: SecondFactorMethods,
) -> (FlowState, FormDescription) {
    state.step = LoginStep::SecondFactor { user_id, methods };
    state.passkey_challenge = None;
    state.second_factor_passkey = None;
    let f = second_factor_form(methods, Vec::new());
    (FlowState::Login(state), f)
}

/// The policy requires enrolment for `user_id`: move to the enrolment step with the sealed
/// pending secret (no session yet) and render its form.
pub fn enroll_required(
    mut state: LoginState,
    user_id: UserId,
    pending_totp: String,
) -> (FlowState, FormDescription) {
    state.step = LoginStep::Enroll { user_id };
    state.passkey_challenge = None;
    state.enroll_passkey = None;
    state.second_factor_passkey = None;
    state.pending_totp = Some(pending_totp);
    (FlowState::Login(state), enroll_form(Vec::new()))
}

/// Message key of a refused passkey enrolment (abandoned, replayed, cross-flow or invalid
/// registration, or a passkey already registered).
pub const PASSKEY_ENROLMENT_FAILED: &str = "mfa_enroll.passkey_failed";

/// The user passkey registration options may be created for: the user of the enrolment step.
/// `None` in any other step (passkey enrolment is only offered there).
pub fn passkey_enrolment_user(state: &LoginState) -> Option<UserId> {
    match state.step {
        LoginStep::Enroll { user_id } => Some(user_id),
        _ => None,
    }
}

/// The state holding a new passkey registration challenge (replacing an earlier one).
pub fn with_passkey_enrolment(mut state: LoginState, registration_state: String) -> LoginState {
    state.enroll_passkey = Some(registration_state);
    state
}

/// A passkey registration response arrived: takes the pending registration state out of the
/// enrolment step. `Some((user, registration state))`: `state` no longer holds it, and the
/// service swaps the stored state to it before verifying (single use). `None`: not in the
/// enrolment step, or no registration pending (never requested, already used, or the user went
/// the authenticator-app way): refused with [`passkey_enrolment_failed`]; `state` is unchanged.
pub fn take_passkey_enrolment(state: &mut LoginState) -> Option<(UserId, String)> {
    let LoginStep::Enroll { user_id } = state.step else {
        return None;
    };
    state.enroll_passkey.take().map(|r| (user_id, r))
}

/// The terminal effect of a verified, stored passkey enrolment: the session is signed in (or the
/// step-up session upgraded) as a passkey sign-in, `amr = [hwk|swk, user, mfa]`, MFA `acr`.
/// Also the terminal effect of a verified second-factor passkey.
pub fn passkey_enrolment_finish(state: &LoginState) -> Effect {
    match state.step_up_session {
        Some(session) => Effect::UpgradeSession {
            session,
            auth: SessionAuth::Passkey,
        },
        None => Effect::CreateSession(SessionAuth::Passkey),
    }
}

/// The enrolment form after a refused passkey enrolment (the authenticator-app choice stays).
pub fn passkey_enrolment_failed() -> FormDescription {
    enroll_form(vec![error(PASSKEY_ENROLMENT_FAILED)])
}

/// Message key of a refused second-factor passkey (another user's or an unknown passkey, a
/// replayed, cross-flow or never-issued challenge, or an invalid assertion).
pub const SECOND_FACTOR_PASSKEY_FAILED: &str = "second_factor.passkey_failed";

/// The user passkey assertion options may be created for at the second-factor step: the step's
/// user, when they have a passkey. `None` in any other step.
pub fn second_factor_passkey_user(state: &LoginState) -> Option<UserId> {
    match state.step {
        LoginStep::SecondFactor { user_id, methods } if methods.passkey => Some(user_id),
        _ => None,
    }
}

/// The state holding a new second-factor passkey challenge (replacing an earlier one). `None`
/// outside a second-factor step that offers a passkey.
pub fn with_second_factor_passkey(mut state: LoginState, challenge: String) -> Option<LoginState> {
    second_factor_passkey_user(&state)?;
    state.second_factor_passkey = Some(challenge);
    Some(state)
}

/// A passkey assertion arrived at the second-factor step: takes the pending challenge out.
/// `Some((user, challenge))`: `state` no longer holds it, and the service swaps the stored state
/// to it before verifying (single use). `None`: not a second-factor step with a passkey, or no
/// challenge pending (never requested or already used); `state` is unchanged.
pub fn take_second_factor_passkey(state: &mut LoginState) -> Option<(UserId, String)> {
    let user_id = second_factor_passkey_user(state)?;
    state.second_factor_passkey.take().map(|c| (user_id, c))
}

/// The second-factor form after a refused passkey: the step's form with
/// [`SECOND_FACTOR_PASSKEY_FAILED`].
pub fn second_factor_passkey_failed(methods: SecondFactorMethods) -> FormDescription {
    second_factor_form(methods, vec![error(SECOND_FACTOR_PASSKEY_FAILED)])
}

/// The state of a step-up flow for `session` of `user`: the second-factor step, or (with a
/// sealed pending secret) the enrolment step.
pub fn step_up(
    session: SessionId,
    user: UserId,
    methods: SecondFactorMethods,
    pending_totp: Option<String>,
) -> (FlowState, FormDescription) {
    let state = LoginState {
        step_up_session: Some(session),
        ..LoginState::default()
    };
    match pending_totp {
        Some(p) => enroll_required(state, user, p),
        None => second_factor_required(state, user, methods),
    }
}

/// A fresh login state holding `link` (link confirmation, `flow::upstream`) and its form: the
/// identifier is prefilled with the candidate account's email only when the link exposes it.
pub fn link_confirmation(link: PendingLink) -> (FlowState, FormDescription) {
    let state = LoginState {
        identifier: link.candidate_email.clone(),
        pending_link: Some(Box::new(link)),
        ..LoginState::default()
    };
    let f = form(&state, Vec::new());
    (FlowState::Login(state), f)
}

/// How long a pending SAML request (and the verified identity after the ACS) stays usable.
pub const SAML_PENDING_TTL: Duration = Duration::minutes(10);

/// A SAML sign-in started from this login flow (06-18). Only hashes and a sealed value:
///
/// - `request_id`: the `AuthnRequest` ID; both `InResponseTo`s must equal it (not a secret);
/// - `relay_state_hash`: hash of the RelayState sent with the request (`{flow}.{nonce}`): the
///   IdP's cross-site POST carries no cookie, so the flow is found through RelayState and the
///   hash proves the value was issued for this request;
/// - `binding_hash`: hash of the browser-binding cookie (SameSite=Lax) set at the start; the
///   continue step requires it, so a response posted in another browser signs nobody in;
/// - `identity_sealed`: `None` while the request is pending; the ACS takes the pending request
///   out (single use), verifies the response and puts it back with the verified identity
///   sealed with the KEK, which the continue step takes out again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamlPending {
    pub connection_id: ConnectionId,
    pub request_id: String,
    pub relay_state_hash: String,
    pub binding_hash: String,
    /// Unix seconds of the start; the request and the identity expire [`SAML_PENDING_TTL`] after.
    pub created_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_sealed: Option<String>,
}

impl SamlPending {
    /// Whether the request (or the identity it produced) is still usable at `now`.
    pub fn is_fresh(&self, now: OffsetDateTime) -> bool {
        now.unix_timestamp()
            < self
                .created_at
                .saturating_add(SAML_PENDING_TTL.whole_seconds())
    }
}

/// The state holding a new pending SAML request (replacing an earlier SAML or upstream one).
/// `None` unless the login is in its identify step and not a step-up: a SAML sign-in is a
/// primary authentication.
pub fn with_saml(state: LoginState, pending: SamlPending) -> Option<LoginState> {
    if !state.step.is_primary() || state.step_up_session.is_some() {
        return None;
    }
    Some(LoginState {
        saml: Some(Box::new(pending)),
        upstream: None,
        ..state
    })
}

/// Takes the SAML sign-in out of `state` (the caller swaps the stored state to the result before
/// using it, so it is single use).
pub fn take_saml(state: &mut LoginState) -> Option<SamlPending> {
    state.saml.take().map(|b| *b)
}

pub(super) fn invalid_input(state: LoginState) -> (FlowState, Vec<Effect>) {
    let f = current_form(&state, vec![error("flow.invalid_input")]);
    (FlowState::Login(state), vec![Effect::Render(f)])
}

pub(super) fn on_failure(state: &LoginState, failure: Failure) -> FormDescription {
    match state.step {
        LoginStep::Identify => {
            let key = match failure {
                Failure::EmailNotVerified => "login.email_not_verified",
                Failure::Overloaded => "service.overloaded",
                Failure::PasskeyInvalid => "login.passkey_failed",
                _ => "login.invalid_credentials",
            };
            form(state, vec![error(key)])
        }
        LoginStep::SecondFactor { methods, .. } => {
            let key = match failure {
                Failure::Overloaded => "service.overloaded",
                _ => "login.second_factor_invalid",
            };
            second_factor_form(methods, vec![error(key)])
        }
        LoginStep::Enroll { .. } => {
            let key = match failure {
                Failure::Overloaded => "service.overloaded",
                _ => "mfa_enroll.code_invalid",
            };
            enroll_form(vec![error(key)])
        }
        LoginStep::EmailCode => {
            let key = match failure {
                Failure::Overloaded => "service.overloaded",
                _ => email_code::WRONG,
            };
            email_code::form_for(state.email_code.as_deref(), vec![error(key)])
        }
        LoginStep::EmailFirst | LoginStep::SsoChoice { .. } => {
            let key = match failure {
                Failure::Overloaded => "service.overloaded",
                Failure::PasskeyInvalid => "login.passkey_failed",
                _ => "flow.invalid_input",
            };
            current_form(state, vec![error(key)])
        }
    }
}

/// The form of the current step.
pub(super) fn current_form(state: &LoginState, messages: Vec<FormMessage>) -> FormDescription {
    match state.step {
        LoginStep::Identify => form(state, messages),
        LoginStep::SecondFactor { methods, .. } => second_factor_form(methods, messages),
        LoginStep::Enroll { .. } => enroll_form(messages),
        LoginStep::EmailCode => email_code::form_for(state.email_code.as_deref(), messages),
        LoginStep::EmailFirst => identify_form(state, messages),
        LoginStep::SsoChoice { .. } => sso_choice_form(state, messages),
    }
}

/// The form of the current step with `messages` (for the service's own refusals, e.g.
/// [`USE_SSO`]).
pub fn form_with(state: &LoginState, messages: Vec<FormMessage>) -> FormDescription {
    current_form(state, messages)
}

/// Where the service routed an email (by its domain only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HrdRoute {
    /// Not routed: local sign-in.
    Local,
    /// Routed to the org connection `connection_id`.
    Sso {
        connection_id: ConnectionId,
        /// The org still allows password (and email) sign-in for the domain.
        allow_local_password: bool,
    },
}

/// A submission of the email-first page or the single-sign-on choice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentifyInput {
    /// The email typed on the email-first page.
    Email(String),
    /// "Continue with single sign-on" (choice step).
    Sso,
    /// "Use password instead" (choice step).
    Password,
    /// Back to the email page (password step after the email page, or the choice step).
    Change,
}

/// What [`identify_input`] needs next.
#[derive(Debug)]
pub enum IdentifyStep {
    /// Route this normalised email by its domain, then call [`routed`] (`chose_sso`: the user
    /// pressed "Continue with single sign-on").
    Route {
        state: LoginState,
        email: String,
        chose_sso: bool,
    },
    /// Render this state's form (no routing needed).
    Render(LoginState, FormDescription),
}

/// The outcome of routing an email.
#[derive(Debug)]
pub enum Identified {
    /// Store this state and render the form.
    Render(Box<(LoginState, FormDescription)>),
    /// Start the sign-in at the IdP of this connection (the state is unchanged).
    StartIdp(ConnectionId),
}

/// The initial state of an identifier-first login and its email page.
pub fn email_first() -> (LoginState, FormDescription) {
    let state = LoginState {
        step: LoginStep::EmailFirst,
        ..LoginState::default()
    };
    let f = identify_form(&state, Vec::new());
    (state, f)
}

/// The email-first page or choice step received `input`. No lookup of any kind happens here.
pub fn identify_input(mut state: LoginState, input: IdentifyInput) -> IdentifyStep {
    let invalid = |state: LoginState| {
        let f = current_form(&state, vec![error("flow.invalid_input")]);
        IdentifyStep::Render(state, f)
    };
    if state.step_up_session.is_some() || state.pending_link.is_some() {
        return invalid(state);
    }
    match (input, state.step) {
        // The email-first form also answers from the password step after it (a brute-force
        // lock or CAPTCHA page of a routed tenant renders it bound to that flow): the email is
        // routed again, as after "change".
        (IdentifyInput::Email(raw), step)
            if step == LoginStep::EmailFirst
                || (step == LoginStep::Identify && state.email_first) =>
        {
            if step == LoginStep::Identify {
                state.step = LoginStep::EmailFirst;
                state.email_first = false;
                state.passkey_challenge = None;
            }
            let raw = raw.trim().to_owned();
            state.identifier = (!raw.is_empty()).then(|| raw.clone());
            match normalize_email(&raw) {
                Ok(email) => IdentifyStep::Route {
                    state,
                    email,
                    chose_sso: false,
                },
                Err(_) => {
                    let f = identify_form(&state, vec![error("email.invalid")]);
                    IdentifyStep::Render(state, f)
                }
            }
        }
        (IdentifyInput::Sso, LoginStep::SsoChoice { .. }) => {
            match state.identifier.as_deref().map(normalize_email) {
                Some(Ok(email)) => IdentifyStep::Route {
                    state,
                    email,
                    chose_sso: true,
                },
                _ => invalid(state),
            }
        }
        (IdentifyInput::Password, LoginStep::SsoChoice { .. }) => {
            let state = password_step(state);
            let f = form(&state, Vec::new());
            IdentifyStep::Render(state, f)
        }
        (IdentifyInput::Change, LoginStep::SsoChoice { .. })
        | (IdentifyInput::Change, LoginStep::Identify)
            if state.step != LoginStep::Identify || state.email_first =>
        {
            state.step = LoginStep::EmailFirst;
            state.email_first = false;
            state.passkey_challenge = None;
            let f = identify_form(&state, Vec::new());
            IdentifyStep::Render(state, f)
        }
        _ => invalid(state),
    }
}

/// Applies the routing decision for `email` (see the module docs). `state` carries the entered
/// identifier.
pub fn routed(state: LoginState, route: HrdRoute, chose_sso: bool) -> Identified {
    match route {
        HrdRoute::Sso {
            connection_id,
            allow_local_password,
        } if chose_sso || !allow_local_password => Identified::StartIdp(connection_id),
        HrdRoute::Sso { connection_id, .. } => {
            let state = LoginState {
                step: LoginStep::SsoChoice { connection_id },
                email_first: false,
                passkey_challenge: None,
                ..state
            };
            let f = sso_choice_form(&state, Vec::new());
            Identified::Render(Box::new((state, f)))
        }
        HrdRoute::Local => {
            let state = password_step(state);
            let f = form(&state, Vec::new());
            Identified::Render(Box::new((state, f)))
        }
    }
}

/// The password step after the email page: the identify step with the email locked.
fn password_step(state: LoginState) -> LoginState {
    LoginState {
        step: LoginStep::Identify,
        email_first: true,
        passkey_challenge: None,
        ..state
    }
}

/// The email-first form: the email alone, posted to `login/identify`.
pub(super) fn identify_form(state: &LoginState, messages: Vec<FormMessage>) -> FormDescription {
    build_form(
        IDENTIFY_FORM_ID,
        "login/identify",
        vec![field(
            "identifier",
            FieldKind::Email,
            "field.email",
            state.identifier.clone(),
            true,
            Some("username"),
            Vec::new(),
        )],
        messages,
    )
}

/// The single-sign-on choice form: the email (hidden, shown by the page) and `hrd.sso_explain`.
/// The page posts `choice=sso` or `choice=password` to `login/identify`.
pub(super) fn sso_choice_form(state: &LoginState, messages: Vec<FormMessage>) -> FormDescription {
    let mut all = vec![FormMessage::new(MessageLevel::Info, "hrd.sso_explain")];
    all.extend(messages);
    build_form(
        SSO_CHOICE_FORM_ID,
        "login/identify",
        vec![field(
            "identifier",
            FieldKind::Hidden,
            "field.email",
            state.identifier.clone(),
            false,
            None,
            Vec::new(),
        )],
        all,
    )
}

/// The enrolment form: the `code` of the newly added authenticator app.
pub(super) fn enroll_form(messages: Vec<FormMessage>) -> FormDescription {
    build_form(
        ENROLL_FORM_ID,
        "login",
        vec![field(
            "code",
            FieldKind::Text,
            "field.code",
            None,
            true,
            Some("one-time-code"),
            Vec::new(),
        )],
        messages,
    )
}

/// The sign-in form of the identify step. While an upstream identity waits for link
/// confirmation it is the [`UPSTREAM_LINK_FORM_ID`] form: the same fields, introduced by
/// `upstream.link_explain` (argument `provider`).
pub(super) fn form(state: &LoginState, messages: Vec<FormMessage>) -> FormDescription {
    let (id, messages) = match &state.pending_link {
        Some(link) => {
            let mut all = vec![
                FormMessage::new(MessageLevel::Info, "upstream.link_explain")
                    .with_arg("provider", &link.provider_name),
            ];
            all.extend(messages);
            (UPSTREAM_LINK_FORM_ID, all)
        }
        None => ("login", messages),
    };
    // After the email page the address is fixed: carried in a hidden field, shown by the page.
    let locked = state.email_first && state.pending_link.is_none();
    build_form(
        id,
        "login",
        vec![
            field(
                "identifier",
                if locked {
                    FieldKind::Hidden
                } else {
                    FieldKind::Email
                },
                "field.email",
                state.identifier.clone(),
                !locked,
                (!locked).then_some("username"),
                Vec::new(),
            ),
            password_field("current-password", Vec::new()),
        ],
        messages,
    )
}

/// The second-factor form: a `code` field (TOTP, `autocomplete=one-time-code`; themes render it
/// with `inputmode=numeric`) and, when the user has unused recovery codes, the alternative
/// `recovery_code` field. Exactly one of them is submitted. When the user has a passkey, the
/// form also carries the hidden marker field [`SECOND_FACTOR_PASSKEY_FIELD`] (never submitted):
/// it tells the presentation layer to show the passkey option, which posts to its own route. A
/// passkey-only user's form has no `code` or `recovery_code` field.
pub(super) fn second_factor_form(
    methods: SecondFactorMethods,
    messages: Vec<FormMessage>,
) -> FormDescription {
    let mut fields = Vec::new();
    if methods.totp {
        fields.push(field(
            "code",
            FieldKind::Text,
            "field.code",
            None,
            false,
            Some("one-time-code"),
            Vec::new(),
        ));
    }
    if methods.recovery {
        fields.push(field(
            "recovery_code",
            FieldKind::Text,
            "field.recovery_code",
            None,
            false,
            Some("off"),
            Vec::new(),
        ));
    }
    if methods.passkey {
        fields.push(field(
            SECOND_FACTOR_PASSKEY_FIELD,
            FieldKind::Hidden,
            "second_factor.passkey_heading",
            None,
            false,
            None,
            Vec::new(),
        ));
    }
    build_form(SECOND_FACTOR_FORM_ID, "login", fields, messages)
}

#[cfg(test)]
mod tests {
    use super::super::engine::test_support::*;
    use super::super::engine::{
        FlowInput, current_form as engine_current_form, on_failure as engine_on_failure,
        transition as engine_transition,
    };
    use super::*;

    const PW: &str = "correct horse battery";

    fn env() -> FlowEnv {
        FlowEnv::default()
    }

    fn submit(identifier: &str, password: &str) -> (FlowState, Vec<Effect>) {
        engine_transition(
            FlowState::Login(LoginState::default()),
            FlowInput::Login {
                identifier: identifier.into(),
                password: password.into(),
            },
            &env(),
        )
    }

    fn second_factor_state(methods: SecondFactorMethods) -> (UserId, LoginState) {
        let user = UserId::new_v7();
        let state = LoginState {
            identifier: Some("alice@example.com".into()),
            step: LoginStep::SecondFactor {
                user_id: user,
                methods,
            },
            passkey_challenge: None,
            ..LoginState::default()
        };
        (user, state)
    }

    const BOTH: SecondFactorMethods = SecondFactorMethods {
        totp: true,
        recovery: true,
        passkey: false,
    };
    const PASSKEY_ONLY: SecondFactorMethods = SecondFactorMethods {
        totp: false,
        recovery: false,
        passkey: true,
    };

    fn rendered(effects: &[Effect]) -> &FormDescription {
        assert_eq!(effects.len(), 1, "{effects:?}");
        match &effects[0] {
            Effect::Render(f) => f,
            other => panic!("{other:?}"),
        }
    }

    fn pending_link(email: Option<&str>) -> PendingLink {
        PendingLink {
            connection_id: crate::model::ConnectionId::new_v7(),
            identity_sealed: "sealed".into(),
            candidate_user: email.map(|_| UserId::new_v7()),
            provider_name: "Example ID".into(),
            candidate_email: email.map(str::to_owned),
        }
    }

    #[test]
    fn link_confirmation_is_the_sign_in_form_with_the_provider_named() {
        let (state, f) = link_confirmation(pending_link(Some("alice@example.com")));
        assert_eq!(f.id, UPSTREAM_LINK_FORM_ID);
        assert_eq!(f.action, "login");
        assert_eq!(f.messages[0].key, "upstream.link_explain");
        assert_eq!(f.messages[0].args["provider"], "Example ID");
        let ident = f.fields.iter().find(|x| x.name == "identifier").unwrap();
        assert_eq!(ident.value.as_deref(), Some("alice@example.com"));
        // A wrong password keeps the link form (and the pending link).
        let FlowState::Login(s) = state.clone() else {
            panic!()
        };
        let (next, effects) = engine_transition(
            state,
            FlowInput::Login {
                identifier: "alice@example.com".into(),
                password: PW.into(),
            },
            &env(),
        );
        let (after, f) = engine_on_failure(next, &effects, Failure::InvalidCredentials, &env());
        assert_eq!(f.id, UPSTREAM_LINK_FORM_ID);
        let FlowState::Login(after) = after else {
            panic!()
        };
        assert_eq!(after.pending_link, s.pending_link);
        // An unexposed candidate leaves the identifier empty.
        let (_, f) = link_confirmation(pending_link(None));
        let ident = f.fields.iter().find(|x| x.name == "identifier").unwrap();
        assert_eq!(ident.value, None);
    }

    #[test]
    fn second_factor_after_upstream_signs_in_federated() {
        let (user, mut state) = second_factor_state(BOTH);
        state.federated = true;
        let (_, effects) = totp(state.clone(), "123456".into());
        assert!(matches!(
            effects.last(),
            Some(Effect::CreateSession(SessionAuth::FederatedSecondFactor))
        ));
        let (_, effects) = recovery_code(state, "abcd".into());
        assert!(matches!(
            effects.last(),
            Some(Effect::CreateSession(SessionAuth::FederatedSecondFactor))
        ));
        let _ = user;
        // Old login JSON has no upstream fields.
        let old: LoginState = serde_json::from_str(r#"{"identifier":null}"#).unwrap();
        assert!(!old.federated && old.upstream.is_none() && old.pending_link.is_none());
        assert!(
            !serde_json::to_string(&LoginState::default())
                .unwrap()
                .contains("federated")
        );
    }

    #[test]
    fn second_factor_after_email_code_signs_in_with_otp_mfa_never_pwd() {
        let (_, mut state) = second_factor_state(BOTH);
        state.email_primary = true;
        for (_, effects) in [
            totp(state.clone(), "123456".into()),
            recovery_code(state.clone(), "abcd".into()),
        ] {
            assert!(matches!(
                effects.last(),
                Some(Effect::CreateSession(SessionAuth::EmailCodeSecondFactor))
            ));
        }
        // The email step's form follows the step; password input there is invalid.
        let s = LoginState {
            step: LoginStep::EmailCode,
            ..LoginState::default()
        };
        assert_eq!(
            current_form(&s, Vec::new()).id,
            email_code::EMAIL_CODE_FORM_ID
        );
        let (_, effects) = engine_transition(
            FlowState::Login(s.clone()),
            FlowInput::Login {
                identifier: "alice@example.com".into(),
                password: PW.into(),
            },
            &env(),
        );
        let f = rendered(&effects);
        assert_eq!(f.id, email_code::EMAIL_CODE_FORM_ID);
        assert_eq!(all_keys(f), vec!["flow.invalid_input"]);
        assert_eq!(
            all_keys(&on_failure(&s, Failure::Overloaded)),
            vec!["service.overloaded"]
        );
        assert!(
            !serde_json::to_string(&LoginState::default())
                .unwrap()
                .contains("email")
        );
    }

    #[test]
    fn submit_plans_verify_second_factor_check_then_password_session() {
        let (state, effects) = submit("  Alice@Example.com ", PW);
        assert_eq!(
            state,
            FlowState::Login(LoginState {
                identifier: Some("Alice@Example.com".into()),
                ..LoginState::default()
            })
        );
        assert_eq!(effects.len(), 3);
        match &effects[0] {
            Effect::VerifyPassword { email, password } => {
                assert_eq!(email, "alice@example.com");
                assert_eq!(secrecy::ExposeSecret::expose_secret(password), PW);
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(effects[1], Effect::CheckSecondFactor));
        assert!(matches!(
            effects[2],
            Effect::CreateSession(SessionAuth::Password)
        ));
    }

    #[test]
    fn invalid_result_renders_one_message_keeps_identifier_never_password() {
        let (state, effects) = submit("alice@example.com", PW);
        let (_, f) = engine_on_failure(state, &effects, Failure::InvalidCredentials, &env());
        assert_eq!(f.id, "login");
        assert_eq!(all_keys(&f), vec!["login.invalid_credentials"]);
        let ident = f.fields.iter().find(|x| x.name == "identifier").unwrap();
        assert_eq!(ident.value.as_deref(), Some("alice@example.com"));
        assert_form_invariants(&f, &[PW]);
    }

    #[test]
    fn wrong_password_for_existing_or_unknown_user_is_the_same_form() {
        // The service reports both as InvalidCredentials; with the identifier masked the forms
        // are identical.
        let (s1, e1) = submit("alice@example.com", PW);
        let (s2, e2) = submit("nobody@example.com", PW);
        let (_, mut f1) = engine_on_failure(s1, &e1, Failure::InvalidCredentials, &env());
        let (_, mut f2) = engine_on_failure(s2, &e2, Failure::InvalidCredentials, &env());
        for f in [&mut f1, &mut f2] {
            f.fields[0].value = None;
        }
        assert_eq!(f1, f2);
    }

    #[test]
    fn malformed_identifier_or_empty_password_renders_same_message() {
        for (id, pw) in [("", PW), ("not-an-email", PW), ("a@b.c", "")] {
            let (_, effects) = submit(id, pw);
            let f = rendered(&effects);
            assert_eq!(all_keys(f), vec!["login.invalid_credentials"]);
            assert_form_invariants(f, &[PW]);
        }
    }

    #[test]
    fn overloaded_and_unverified_keys() {
        let s = LoginState::default();
        assert_eq!(
            all_keys(&on_failure(&s, Failure::Overloaded)),
            vec!["service.overloaded"]
        );
        assert_eq!(
            all_keys(&on_failure(&s, Failure::EmailNotVerified)),
            vec!["login.email_not_verified"]
        );
    }

    #[test]
    fn user_with_totp_moves_to_second_factor_without_a_session() {
        let (state, _) = submit("alice@example.com", PW);
        let FlowState::Login(s) = state else {
            panic!("login state")
        };
        let user = UserId::new_v7();
        let (next, f) = second_factor_required(s, user, BOTH);
        let FlowState::Login(next) = next else {
            panic!("login state")
        };
        assert_eq!(
            next.step,
            LoginStep::SecondFactor {
                user_id: user,
                methods: BOTH
            }
        );
        assert_eq!(f.id, SECOND_FACTOR_FORM_ID);
        assert_eq!(f.action, "login");
        let code = f.fields.iter().find(|x| x.name == "code").unwrap();
        assert_eq!(code.autocomplete.as_deref(), Some("one-time-code"));
        assert_eq!(code.kind, FieldKind::Text);
        assert!(f.fields.iter().any(|x| x.name == "recovery_code"));
        assert!(f.messages.is_empty());
        assert_form_invariants(&f, &[]);

        // Without recovery codes left only the TOTP field is offered.
        let (_, f) = second_factor_required(
            LoginState::default(),
            user,
            SecondFactorMethods {
                totp: true,
                recovery: false,
                passkey: false,
            },
        );
        let names: Vec<_> = f.fields.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, vec!["code"]);
    }

    #[test]
    fn second_factor_required_drops_a_pending_passkey_challenge() {
        let s = LoginState {
            passkey_challenge: Some("{\"state\":1}".into()),
            ..LoginState::default()
        };
        let (next, _) = second_factor_required(s, UserId::new_v7(), BOTH);
        let FlowState::Login(next) = next else {
            panic!("login state")
        };
        assert_eq!(next.passkey_challenge, None);
    }

    #[test]
    fn totp_in_second_factor_plans_verify_then_mfa_session() {
        let (user, s) = second_factor_state(BOTH);
        let (next, effects) = engine_transition(
            FlowState::Login(s.clone()),
            FlowInput::Totp {
                code: "123456".into(),
            },
            &env(),
        );
        assert_eq!(next, FlowState::Login(s));
        assert_eq!(effects.len(), 2);
        match &effects[0] {
            Effect::VerifyTotp { user_id, code } => {
                assert_eq!(*user_id, user);
                assert_eq!(secrecy::ExposeSecret::expose_secret(code), "123456");
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            effects[1],
            Effect::CreateSession(SessionAuth::SecondFactor)
        ));
    }

    #[test]
    fn totp_failure_rerenders_second_factor_and_keeps_the_step() {
        let (_, s) = second_factor_state(BOTH);
        let (state, effects) = engine_transition(
            FlowState::Login(s.clone()),
            FlowInput::Totp {
                code: "000000".into(),
            },
            &env(),
        );
        let (state, f) = engine_on_failure(state, &effects, Failure::SecondFactorInvalid, &env());
        assert_eq!(state, FlowState::Login(s));
        assert_eq!(f.id, SECOND_FACTOR_FORM_ID);
        assert_eq!(all_keys(&f), vec!["login.second_factor_invalid"]);
        assert_form_invariants(&f, &["000000"]);
    }

    #[test]
    fn recovery_code_in_second_factor_plans_consume_then_mfa_session() {
        let (user, s) = second_factor_state(BOTH);
        let (_, effects) = engine_transition(
            FlowState::Login(s),
            FlowInput::RecoveryCode {
                code: "ABCD-EFGH-IJKL-MNOP".into(),
            },
            &env(),
        );
        assert_eq!(effects.len(), 2);
        match &effects[0] {
            Effect::ConsumeRecoveryCode { user_id, code } => {
                assert_eq!(*user_id, user);
                assert_eq!(
                    secrecy::ExposeSecret::expose_secret(code),
                    "ABCD-EFGH-IJKL-MNOP"
                );
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            effects[1],
            Effect::CreateSession(SessionAuth::SecondFactor)
        ));
    }

    #[test]
    fn recovery_code_without_codes_left_is_invalid_input() {
        let (_, s) = second_factor_state(SecondFactorMethods {
            totp: true,
            recovery: false,
            passkey: false,
        });
        let (next, effects) = engine_transition(
            FlowState::Login(s.clone()),
            FlowInput::RecoveryCode { code: "x".into() },
            &env(),
        );
        assert_eq!(next, FlowState::Login(s));
        let f = rendered(&effects);
        assert_eq!(f.id, SECOND_FACTOR_FORM_ID);
        assert_eq!(all_keys(f), vec!["flow.invalid_input"]);
    }

    #[test]
    fn inputs_of_another_step_render_invalid_input_without_effects() {
        // Second-factor inputs in Identify.
        for input in [
            FlowInput::Totp {
                code: "123456".into(),
            },
            FlowInput::RecoveryCode {
                code: "ABCD".into(),
            },
        ] {
            let s = LoginState::default();
            let (next, effects) = engine_transition(FlowState::Login(s.clone()), input, &env());
            assert_eq!(next, FlowState::Login(s));
            let f = rendered(&effects);
            assert_eq!(f.id, "login");
            assert_eq!(all_keys(f), vec!["flow.invalid_input"]);
        }
        // Identify and passkey inputs in SecondFactor.
        for input in [
            FlowInput::Login {
                identifier: "alice@example.com".into(),
                password: PW.into(),
            },
            FlowInput::PasskeyOptions,
            FlowInput::PasskeyAssertion {
                response_json: "{}".into(),
            },
        ] {
            let (_, s) = second_factor_state(BOTH);
            let (next, effects) = engine_transition(FlowState::Login(s.clone()), input, &env());
            assert_eq!(next, FlowState::Login(s));
            let f = rendered(&effects);
            assert_eq!(f.id, SECOND_FACTOR_FORM_ID);
            assert_eq!(all_keys(f), vec!["flow.invalid_input"]);
            assert_form_invariants(f, &[PW]);
        }
    }

    #[test]
    fn passkey_options_plans_start_passkey() {
        let s = LoginState::default();
        let (next, effects) = engine_transition(
            FlowState::Login(s.clone()),
            FlowInput::PasskeyOptions,
            &env(),
        );
        assert_eq!(next, FlowState::Login(s));
        assert_eq!(effects.len(), 1);
        assert!(matches!(effects[0], Effect::StartPasskey));
    }

    #[test]
    fn passkey_assertion_takes_the_challenge_out_of_the_state() {
        let s = LoginState {
            passkey_challenge: Some("challenge-state".into()),
            ..LoginState::default()
        };
        let (next, effects) = engine_transition(
            FlowState::Login(s),
            FlowInput::PasskeyAssertion {
                response_json: "{\"id\":\"x\"}".into(),
            },
            &env(),
        );
        let FlowState::Login(next) = next else {
            panic!("login state")
        };
        assert_eq!(
            next.passkey_challenge, None,
            "single-use: removed from state"
        );
        assert_eq!(effects.len(), 2);
        match &effects[0] {
            Effect::FinishPasskey {
                response_json,
                challenge,
            } => {
                assert_eq!(response_json, "{\"id\":\"x\"}");
                assert_eq!(challenge, "challenge-state");
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            effects[1],
            Effect::CreateSession(SessionAuth::Passkey)
        ));
    }

    #[test]
    fn passkey_assertion_without_challenge_is_the_generic_passkey_failure() {
        let s = LoginState::default();
        let (next, effects) = engine_transition(
            FlowState::Login(s.clone()),
            FlowInput::PasskeyAssertion {
                response_json: "{}".into(),
            },
            &env(),
        );
        assert_eq!(next, FlowState::Login(s));
        let f = rendered(&effects);
        assert_eq!(f.id, "login");
        assert_eq!(all_keys(f), vec!["login.passkey_failed"]);
        // The failure rendered by the service for a rejected assertion is the same form.
        let (_, f2) = engine_on_failure(
            FlowState::Login(LoginState::default()),
            &[],
            Failure::PasskeyInvalid,
            &env(),
        );
        assert_eq!(*f, f2);
    }

    #[test]
    fn current_form_follows_the_step() {
        let (_, s) = second_factor_state(BOTH);
        let f = engine_current_form(&FlowState::Login(s), Vec::new(), &env());
        assert_eq!(f.id, SECOND_FACTOR_FORM_ID);
        let f = engine_current_form(&FlowState::Login(LoginState::default()), Vec::new(), &env());
        assert_eq!(f.id, "login");
    }

    #[test]
    fn release_0_1_flow_json_still_decodes() {
        let old = r#"{"kind":"login","identifier":"alice@example.com"}"#;
        let s: FlowState = serde_json::from_str(old).unwrap();
        assert_eq!(
            s,
            FlowState::Login(LoginState {
                identifier: Some("alice@example.com".into()),
                step: LoginStep::Identify,
                ..LoginState::default()
            })
        );
        let old = r#"{"kind":"login","identifier":null}"#;
        assert_eq!(
            serde_json::from_str::<FlowState>(old).unwrap(),
            FlowState::Login(LoginState::default())
        );
    }

    #[test]
    fn second_factor_state_round_trips() {
        let (_, s) = second_factor_state(BOTH);
        let s = FlowState::Login(s);
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<FlowState>(&json).unwrap(), s);
        let s = FlowState::Login(LoginState {
            passkey_challenge: Some("c".into()),
            ..LoginState::default()
        });
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<FlowState>(&json).unwrap(), s);
    }

    #[test]
    fn policy_decides_what_follows_the_password() {
        use crate::model::MfaPolicy::{Off, Optional, Required};
        let none = SecondFactorMethods::default();
        let a = AcrRequest::None;
        assert_eq!(after_primary_auth(Off, a, BOTH), AfterPrimary::SignIn);
        assert_eq!(
            after_primary_auth(Optional, a, BOTH),
            AfterPrimary::SecondFactor(BOTH)
        );
        assert_eq!(after_primary_auth(Optional, a, none), AfterPrimary::SignIn);
        assert_eq!(after_primary_auth(Required, a, none), AfterPrimary::Enroll);
        assert_eq!(
            after_primary_auth(Required, a, BOTH),
            AfterPrimary::SecondFactor(BOTH)
        );
        // acr_values asks for MFA even under Off.
        assert_eq!(
            after_primary_auth(Off, AcrRequest::Voluntary, BOTH),
            AfterPrimary::SecondFactor(BOTH)
        );
        // An essential acr that cannot be met signs in single-factor; authorize answers unmet.
        assert_eq!(
            after_primary_auth(Optional, AcrRequest::Essential, none),
            AfterPrimary::SignIn
        );
    }

    #[test]
    fn enrolment_step_confirms_the_pending_secret_then_signs_in() {
        let user = UserId::new_v7();
        let (state, f) = enroll_required(
            LoginState {
                passkey_challenge: Some("c".into()),
                ..LoginState::default()
            },
            user,
            "sealed".into(),
        );
        assert_eq!(f.id, ENROLL_FORM_ID);
        assert_form_invariants(&f, &[]);
        let FlowState::Login(s) = state.clone() else {
            panic!("login state")
        };
        assert_eq!(s.step, LoginStep::Enroll { user_id: user });
        assert_eq!(s.passkey_challenge, None);
        assert_eq!(s.pending_totp.as_deref(), Some("sealed"));
        let (_, effects) = engine_transition(
            state.clone(),
            FlowInput::Totp {
                code: "123456".into(),
            },
            &env(),
        );
        assert_eq!(effects.len(), 2);
        match &effects[0] {
            Effect::ConfirmTotpEnrolment {
                user_id, pending, ..
            } => {
                assert_eq!(*user_id, user);
                assert_eq!(pending, "sealed");
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            effects[1],
            Effect::CreateSession(SessionAuth::SecondFactor)
        ));
        // A wrong code re-renders the enrolment form.
        let (state, f) = engine_on_failure(state, &effects, Failure::SecondFactorInvalid, &env());
        assert_eq!(f.id, ENROLL_FORM_ID);
        assert_eq!(all_keys(&f), vec!["mfa_enroll.code_invalid"]);
        // Recovery codes and passwords are not inputs of the enrolment step.
        for input in [
            FlowInput::RecoveryCode { code: "x".into() },
            FlowInput::Login {
                identifier: "alice@example.com".into(),
                password: PW.into(),
            },
        ] {
            let (_, effects) = engine_transition(state.clone(), input, &env());
            let f = rendered(&effects);
            assert_eq!(f.id, ENROLL_FORM_ID);
            assert_eq!(all_keys(f), vec!["flow.invalid_input"]);
        }
    }

    #[test]
    fn step_up_ends_in_upgrade_session_not_a_new_session() {
        let session = SessionId::new_v7();
        let user = UserId::new_v7();
        let (state, f) = step_up(session, user, BOTH, None);
        assert_eq!(f.id, SECOND_FACTOR_FORM_ID);
        for input in [
            FlowInput::Totp {
                code: "123456".into(),
            },
            FlowInput::RecoveryCode {
                code: "ABCD".into(),
            },
        ] {
            let (_, effects) = engine_transition(state.clone(), input, &env());
            assert_eq!(effects.len(), 2);
            assert!(matches!(
                effects[1],
                Effect::UpgradeSession {
                    session: s,
                    auth: SessionAuth::SecondFactor
                } if s == session
            ));
        }
        // Step-up into enrolment.
        let (state, f) = step_up(
            session,
            user,
            SecondFactorMethods::default(),
            Some("p".into()),
        );
        assert_eq!(f.id, ENROLL_FORM_ID);
        let (_, effects) = engine_transition(
            state.clone(),
            FlowInput::Totp {
                code: "123456".into(),
            },
            &env(),
        );
        assert!(matches!(effects[1], Effect::UpgradeSession { .. }));
        // The state round-trips through JSON.
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(serde_json::from_str::<FlowState>(&json).unwrap(), state);
    }

    fn enrol_state(user: UserId) -> LoginState {
        let (state, _) = enroll_required(LoginState::default(), user, "sealed".into());
        let FlowState::Login(s) = state else {
            panic!("login state")
        };
        s
    }

    #[test]
    fn passkey_enrolment_is_offered_only_in_the_enrolment_step() {
        let user = UserId::new_v7();
        assert_eq!(passkey_enrolment_user(&enrol_state(user)), Some(user));
        assert_eq!(passkey_enrolment_user(&LoginState::default()), None);
        let (_, second) = second_factor_state(BOTH);
        assert_eq!(passkey_enrolment_user(&second), None);
        let email = LoginState {
            step: LoginStep::EmailCode,
            ..LoginState::default()
        };
        assert_eq!(passkey_enrolment_user(&email), None);
    }

    #[test]
    fn passkey_enrolment_challenge_is_taken_out_once() {
        let user = UserId::new_v7();
        let pending = with_passkey_enrolment(enrol_state(user), "reg-1".into());
        // A newer challenge replaces an older one.
        let pending = with_passkey_enrolment(pending, "reg-2".into());
        let mut taken = pending;
        let (who, registration) = take_passkey_enrolment(&mut taken).expect("pending");
        assert_eq!(who, user);
        assert_eq!(registration, "reg-2");
        assert_eq!(taken.enroll_passkey, None);
        // The TOTP choice survives a passkey attempt.
        assert_eq!(taken.pending_totp.as_deref(), Some("sealed"));
        assert_eq!(taken.step, LoginStep::Enroll { user_id: user });
        // Used (replay), or never requested (the authenticator-app way): refused.
        assert_eq!(take_passkey_enrolment(&mut taken), None);
        assert_eq!(take_passkey_enrolment(&mut enrol_state(user)), None);
        // Outside the enrolment step a stray value is never used.
        let mut identify = LoginState {
            enroll_passkey: Some("reg".into()),
            ..LoginState::default()
        };
        assert_eq!(take_passkey_enrolment(&mut identify), None);
        assert_eq!(identify.enroll_passkey.as_deref(), Some("reg"));
    }

    #[test]
    fn a_fresh_enrolment_drops_an_earlier_passkey_challenge() {
        let user = UserId::new_v7();
        let pending = with_passkey_enrolment(enrol_state(user), "reg".into());
        let (state, _) = enroll_required(pending, user, "sealed-2".into());
        let FlowState::Login(s) = state else {
            panic!("login state")
        };
        assert_eq!(s.enroll_passkey, None);
    }

    #[test]
    fn passkey_enrolment_signs_in_as_a_passkey_or_upgrades_the_step_up_session() {
        let user = UserId::new_v7();
        assert!(matches!(
            passkey_enrolment_finish(&enrol_state(user)),
            Effect::CreateSession(SessionAuth::Passkey)
        ));
        let session = SessionId::new_v7();
        let (state, _) = step_up(
            session,
            user,
            SecondFactorMethods::default(),
            Some("p".into()),
        );
        let FlowState::Login(s) = state else {
            panic!("login state")
        };
        assert!(matches!(
            passkey_enrolment_finish(&s),
            Effect::UpgradeSession {
                session: x,
                auth: SessionAuth::Passkey
            } if x == session
        ));
        let f = passkey_enrolment_failed();
        assert_eq!(f.id, ENROLL_FORM_ID);
        assert_eq!(all_keys(&f), vec![PASSKEY_ENROLMENT_FAILED]);
        assert_form_invariants(&f, &[]);
    }

    #[test]
    fn enrolment_state_with_a_passkey_challenge_round_trips_and_old_json_decodes() {
        let state = FlowState::Login(with_passkey_enrolment(
            enrol_state(UserId::new_v7()),
            "{\"rs\":1}".into(),
        ));
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(serde_json::from_str::<FlowState>(&json).unwrap(), state);
        // Enrolment JSON written before this field existed still decodes (no challenge).
        let FlowState::Login(mut old) = state else {
            panic!()
        };
        old.enroll_passkey = None;
        let json = serde_json::to_string(&FlowState::Login(old.clone())).unwrap();
        assert!(!json.contains("enroll_passkey"), "{json}");
        assert_eq!(
            serde_json::from_str::<FlowState>(&json).unwrap(),
            FlowState::Login(old)
        );
    }

    #[test]
    fn a_passkey_counts_as_a_second_factor_like_totp() {
        use crate::model::MfaPolicy::{Off, Optional, Required};
        let a = AcrRequest::None;
        assert!(PASSKEY_ONLY.any());
        assert!(BOTH.any());
        // Recovery codes alone are not a factor (they back up TOTP).
        assert!(
            !SecondFactorMethods {
                totp: false,
                recovery: true,
                passkey: false
            }
            .any()
        );
        assert_eq!(
            after_primary_auth(Required, a, PASSKEY_ONLY),
            AfterPrimary::SecondFactor(PASSKEY_ONLY)
        );
        assert_eq!(
            after_primary_auth(Optional, a, PASSKEY_ONLY),
            AfterPrimary::SecondFactor(PASSKEY_ONLY)
        );
        assert_eq!(
            after_primary_auth(Off, a, PASSKEY_ONLY),
            AfterPrimary::SignIn
        );
        assert_eq!(
            after_primary_auth(Off, AcrRequest::Voluntary, PASSKEY_ONLY),
            AfterPrimary::SecondFactor(PASSKEY_ONLY)
        );
    }

    #[test]
    fn second_factor_methods_from_before_passkeys_decode_without_a_passkey() {
        let user = UserId::new_v7();
        let old = format!(
            "{{\"kind\":\"login\",\"step\":{{\"name\":\"second_factor\",\"user_id\":\"{user}\",\
             \"methods\":{{\"totp\":true,\"recovery\":false}}}}}}"
        );
        let FlowState::Login(s) = serde_json::from_str::<FlowState>(&old).unwrap() else {
            panic!("login state")
        };
        assert_eq!(
            s.step,
            LoginStep::SecondFactor {
                user_id: user,
                methods: SecondFactorMethods {
                    totp: true,
                    recovery: false,
                    passkey: false
                }
            }
        );
        assert_eq!(s.second_factor_passkey, None);
        // And the new state round-trips, without the field when no challenge is pending.
        let (_, s) = second_factor_state(PASSKEY_ONLY);
        let json = serde_json::to_string(&FlowState::Login(s.clone())).unwrap();
        assert!(!json.contains("second_factor_passkey"), "{json}");
        let with = with_second_factor_passkey(s, "{\"c\":1}".into()).unwrap();
        let json = serde_json::to_string(&FlowState::Login(with.clone())).unwrap();
        assert_eq!(
            serde_json::from_str::<FlowState>(&json).unwrap(),
            FlowState::Login(with)
        );
    }

    #[test]
    fn passkey_only_second_factor_form_has_no_code_fields_but_the_passkey_marker() {
        let (_, f) = second_factor_required(LoginState::default(), UserId::new_v7(), PASSKEY_ONLY);
        let names: Vec<_> = f.fields.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, vec![SECOND_FACTOR_PASSKEY_FIELD]);
        assert_eq!(f.fields[0].kind, FieldKind::Hidden);
        assert_form_invariants(&f, &[]);
        // TOTP and passkey: both; TOTP only: no marker (the page is unchanged).
        let both = SecondFactorMethods {
            passkey: true,
            ..BOTH
        };
        let (_, f) = second_factor_required(LoginState::default(), UserId::new_v7(), both);
        let names: Vec<_> = f.fields.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["code", "recovery_code", SECOND_FACTOR_PASSKEY_FIELD]
        );
        let (_, f) = second_factor_required(LoginState::default(), UserId::new_v7(), BOTH);
        assert!(
            f.fields
                .iter()
                .all(|x| x.name != SECOND_FACTOR_PASSKEY_FIELD)
        );
        // The refusal keeps the step's form with the one passkey message.
        let f = second_factor_passkey_failed(PASSKEY_ONLY);
        assert_eq!(f.id, SECOND_FACTOR_FORM_ID);
        assert_eq!(all_keys(&f), vec![SECOND_FACTOR_PASSKEY_FAILED]);
    }

    #[test]
    fn second_factor_passkey_challenge_is_taken_out_once_and_only_in_its_step() {
        let (user, s) = second_factor_state(PASSKEY_ONLY);
        assert_eq!(second_factor_passkey_user(&s), Some(user));
        let s = with_second_factor_passkey(s, "c-1".into()).unwrap();
        let mut s = with_second_factor_passkey(s, "c-2".into()).unwrap();
        assert_eq!(
            take_second_factor_passkey(&mut s),
            Some((user, "c-2".into()))
        );
        assert_eq!(s.second_factor_passkey, None);
        assert_eq!(
            s.step,
            LoginStep::SecondFactor {
                user_id: user,
                methods: PASSKEY_ONLY
            }
        );
        // Used (replay) or never requested: nothing to take.
        assert_eq!(take_second_factor_passkey(&mut s), None);
        // A TOTP-only step, the identify step and the enrolment step offer no passkey here, and a
        // stray value there (or the identify step's own challenge) is never used.
        let (_, totp_only) = second_factor_state(BOTH);
        assert_eq!(second_factor_passkey_user(&totp_only), None);
        assert_eq!(
            with_second_factor_passkey(totp_only.clone(), "c".into()),
            None
        );
        let mut stray = LoginState {
            second_factor_passkey: Some("c".into()),
            ..totp_only
        };
        assert_eq!(take_second_factor_passkey(&mut stray), None);
        let mut identify = LoginState {
            passkey_challenge: Some("identify".into()),
            second_factor_passkey: Some("c".into()),
            ..LoginState::default()
        };
        assert_eq!(
            with_second_factor_passkey(identify.clone(), "c".into()),
            None
        );
        assert_eq!(take_second_factor_passkey(&mut identify), None);
        assert_eq!(
            with_second_factor_passkey(enrol_state(user), "c".into()),
            None
        );
        // The identify step's challenge does not survive into the second-factor step, and the
        // second-factor step does not read it.
        let (next, _) = second_factor_required(identify, user, PASSKEY_ONLY);
        let FlowState::Login(mut next) = next else {
            panic!("login state")
        };
        assert_eq!(next.passkey_challenge, None);
        assert_eq!(next.second_factor_passkey, None);
        assert_eq!(take_second_factor_passkey(&mut next), None);
    }

    #[test]
    fn a_totp_code_at_a_passkey_only_step_is_invalid_input() {
        let (_, s) = second_factor_state(PASSKEY_ONLY);
        for input in [
            FlowInput::Totp {
                code: "123456".into(),
            },
            FlowInput::RecoveryCode {
                code: "ABCD-EFGH-IJKL-MNOP".into(),
            },
        ] {
            let (_, effects) = engine_transition(FlowState::Login(s.clone()), input, &env());
            let f = rendered(&effects);
            assert_eq!(all_keys(f), vec!["flow.invalid_input"]);
        }
    }

    #[test]
    fn a_second_factor_passkey_signs_in_as_a_passkey_or_upgrades_the_step_up_session() {
        let (_, s) = second_factor_state(PASSKEY_ONLY);
        assert!(matches!(
            passkey_enrolment_finish(&s),
            Effect::CreateSession(SessionAuth::Passkey)
        ));
        let session = SessionId::new_v7();
        let (state, f) = step_up(session, UserId::new_v7(), PASSKEY_ONLY, None);
        assert_eq!(f.id, SECOND_FACTOR_FORM_ID);
        let FlowState::Login(state) = state else {
            panic!("login state")
        };
        assert!(second_factor_passkey_user(&state).is_some());
        assert!(matches!(
            passkey_enrolment_finish(&state),
            Effect::UpgradeSession {
                session: s,
                auth: SessionAuth::Passkey
            } if s == session
        ));
    }

    fn saml_pending() -> SamlPending {
        SamlPending {
            connection_id: ConnectionId::new_v7(),
            request_id: "_00112233445566778899aabbccddeeff".into(),
            relay_state_hash: "relay".into(),
            binding_hash: "binding".into(),
            created_at: 1_000,
            identity_sealed: None,
        }
    }

    #[test]
    fn saml_pending_is_only_stored_in_the_identify_step() {
        let pending = saml_pending();
        let identify = LoginState {
            identifier: Some("a@example.test".into()),
            ..LoginState::default()
        };
        let stored = with_saml(identify, pending.clone()).expect("identify step");
        assert_eq!(stored.saml.as_deref(), Some(&pending));
        assert_eq!(stored.identifier.as_deref(), Some("a@example.test"));

        let user = UserId::new_v7();
        let second = LoginState {
            step: LoginStep::SecondFactor {
                user_id: user,
                methods: SecondFactorMethods::default(),
            },
            ..LoginState::default()
        };
        assert!(with_saml(second, pending.clone()).is_none());
        let enroll = LoginState {
            step: LoginStep::Enroll { user_id: user },
            ..LoginState::default()
        };
        assert!(with_saml(enroll, pending.clone()).is_none());
        let step_up = LoginState {
            step_up_session: Some(SessionId::new_v7()),
            ..LoginState::default()
        };
        assert!(with_saml(step_up, pending).is_none());
    }

    #[test]
    fn saml_pending_is_taken_once_and_round_trips() {
        let pending = saml_pending();
        let mut state = with_saml(LoginState::default(), pending.clone()).expect("identify");
        let json = serde_json::to_string(&FlowState::Login(state.clone())).expect("encode");
        assert!(json.contains("\"saml\""));
        assert!(!json.contains("identity_sealed"));
        let FlowState::Login(decoded) = serde_json::from_str(&json).expect("decode") else {
            panic!("login state");
        };
        assert_eq!(decoded, state);
        assert_eq!(take_saml(&mut state), Some(pending));
        assert_eq!(take_saml(&mut state), None);
        // Release 0.4 flow JSON (no `saml`) still decodes.
        let old: FlowState =
            serde_json::from_str(r#"{"kind":"login","identifier":null}"#).expect("old json");
        assert!(matches!(old, FlowState::Login(s) if s.saml.is_none()));
    }

    #[test]
    fn saml_pending_expires_after_ten_minutes() {
        let p = saml_pending();
        let at = |s: i64| OffsetDateTime::from_unix_timestamp(s).expect("ts");
        assert!(p.is_fresh(at(1_000)));
        assert!(p.is_fresh(at(1_000 + 599)));
        assert!(!p.is_fresh(at(1_000 + 600)));
    }

    #[test]
    fn return_to_sealed_is_optional_and_survives_the_steps() {
        // Flow rows written before 06-31 (no field) still decode; `None` is not written.
        let old: FlowState =
            serde_json::from_str(r#"{"kind":"login","identifier":null}"#).expect("old json");
        assert!(matches!(old, FlowState::Login(ref s) if s.return_to_sealed.is_none()));
        let json = serde_json::to_string(&FlowState::Login(LoginState::default())).unwrap();
        assert!(!json.contains("return_to_sealed"), "{json}");
        let state = LoginState {
            return_to_sealed: Some("c2VhbGVk".into()),
            ..LoginState::default()
        };
        let json = serde_json::to_string(&FlowState::Login(state.clone())).unwrap();
        let FlowState::Login(decoded) = serde_json::from_str(&json).unwrap() else {
            panic!("login state");
        };
        assert_eq!(decoded, state);
        // The steps of a login keep it (it is read from the stored state at sign-in).
        let (first, _) = email_first();
        let first = LoginState {
            return_to_sealed: state.return_to_sealed.clone(),
            ..first
        };
        let IdentifyStep::Route {
            state: routed_state,
            ..
        } = identify_input(first, IdentifyInput::Email("alice@example.com".into()))
        else {
            panic!("route");
        };
        let Identified::Render(b) = routed(routed_state, HrdRoute::Local, false) else {
            panic!("password step");
        };
        assert_eq!(b.0.return_to_sealed, state.return_to_sealed);
        let (FlowState::Login(second), _) = second_factor_required(
            b.0,
            UserId::new_v7(),
            SecondFactorMethods {
                totp: true,
                ..SecondFactorMethods::default()
            },
        ) else {
            panic!("login state");
        };
        assert_eq!(second.return_to_sealed, state.return_to_sealed);
    }

    // -----------------------------------------------------------------------------------------
    // Identifier-first sign-in (06-22)
    // -----------------------------------------------------------------------------------------

    fn conn() -> ConnectionId {
        ConnectionId::new_v7()
    }

    fn sso(connection_id: ConnectionId, allow_local_password: bool) -> HrdRoute {
        HrdRoute::Sso {
            connection_id,
            allow_local_password,
        }
    }

    /// The email page submitted with `email`: the routing request it produces.
    fn submitted(email: &str) -> (LoginState, String, bool) {
        let (state, _) = email_first();
        match identify_input(state, IdentifyInput::Email(email.into())) {
            IdentifyStep::Route {
                state,
                email,
                chose_sso,
            } => (state, email, chose_sso),
            IdentifyStep::Render(_, f) => panic!("{f:?}"),
        }
    }

    fn render(i: Identified) -> (LoginState, FormDescription) {
        match i {
            Identified::Render(b) => *b,
            Identified::StartIdp(c) => panic!("started {c:?}"),
        }
    }

    #[test]
    fn email_first_page_asks_for_the_email_alone() {
        let (state, f) = email_first();
        assert_eq!(state.step, LoginStep::EmailFirst);
        assert_eq!(f.id, IDENTIFY_FORM_ID);
        assert_eq!(f.action, "login/identify");
        let names: Vec<&str> = f.fields.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, ["identifier"]);
        assert_eq!(f.fields[0].kind, FieldKind::Email);
        // The default login state is still the combined form.
        let (FlowState::Login(s), f) =
            FlowState::initial(crate::model::FlowKind::Login, None, &env()).expect("initial")
        else {
            panic!("login");
        };
        assert_eq!(s.step, LoginStep::Identify);
        assert_eq!(f.id, "login");
        assert!(f.fields.iter().any(|x| x.name == "password"));
    }

    #[test]
    fn submitting_the_email_routes_its_normalised_address_only() {
        let (state, email, chose_sso) = submitted("  Alice@Example.COM ");
        assert_eq!(email, "alice@example.com");
        assert!(!chose_sso);
        assert_eq!(state.identifier.as_deref(), Some("Alice@Example.COM"));
        // A malformed email is re-rendered with an error, no routing.
        let (state, _) = email_first();
        match identify_input(state, IdentifyInput::Email("not an email".into())) {
            IdentifyStep::Render(s, f) => {
                assert_eq!(s.step, LoginStep::EmailFirst);
                assert_eq!(f.id, IDENTIFY_FORM_ID);
                assert_eq!(f.messages[0].key, "email.invalid");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn local_route_is_the_password_step_with_the_email_locked() {
        let (state, _, _) = submitted("bob@example.com");
        let (s, f) = render(routed(state, HrdRoute::Local, false));
        assert_eq!(s.step, LoginStep::Identify);
        assert!(s.email_first);
        assert_eq!(f.id, "login");
        let ident = f.fields.iter().find(|x| x.name == "identifier").unwrap();
        assert_eq!(ident.kind, FieldKind::Hidden);
        assert_eq!(ident.value.as_deref(), Some("bob@example.com"));
        assert!(f.fields.iter().any(|x| x.name == "password"));
        // The password POST works in that step.
        let (_, effects) = transition(s, "bob@example.com".into(), PW.into(), &env());
        assert!(matches!(effects[0], Effect::VerifyPassword { .. }));
    }

    #[test]
    fn local_route_page_is_identical_for_every_address_but_the_echo() {
        let (a, _, _) = submitted("known@example.com");
        let (b, _, _) = submitted("unknown@example.com");
        let (_, fa) = render(routed(a, HrdRoute::Local, false));
        let (_, fb) = render(routed(b, HrdRoute::Local, false));
        let mask = |f: &FormDescription| {
            let mut f = f.clone();
            for x in &mut f.fields {
                x.value = None;
            }
            f
        };
        assert_eq!(mask(&fa), mask(&fb));
    }

    #[test]
    fn routed_domain_without_local_password_starts_the_idp() {
        let c = conn();
        let (state, _, _) = submitted("alice@acme.example");
        assert!(matches!(
            routed(state, sso(c, false), false),
            Identified::StartIdp(id) if id == c
        ));
    }

    #[test]
    fn routed_domain_with_local_password_offers_the_choice() {
        let c = conn();
        let (state, _, _) = submitted("alice@acme.example");
        let (s, f) = render(routed(state, sso(c, true), false));
        assert_eq!(s.step, LoginStep::SsoChoice { connection_id: c });
        assert_eq!(f.id, SSO_CHOICE_FORM_ID);
        assert_eq!(f.messages[0].key, "hrd.sso_explain");
        assert!(!f.fields.iter().any(|x| x.name == "password"));

        // "Continue with single sign-on": routed again, then the IdP.
        match identify_input(s.clone(), IdentifyInput::Sso) {
            IdentifyStep::Route {
                state,
                email,
                chose_sso,
            } => {
                assert_eq!(email, "alice@acme.example");
                assert!(chose_sso);
                assert!(matches!(
                    routed(state, sso(c, true), true),
                    Identified::StartIdp(id) if id == c
                ));
            }
            other => panic!("{other:?}"),
        }
        // The route disappeared meanwhile: the password step.
        let (s2, _) = render(routed(s.clone(), HrdRoute::Local, true));
        assert_eq!(s2.step, LoginStep::Identify);

        // "Use password instead": the password step, email locked.
        match identify_input(s.clone(), IdentifyInput::Password) {
            IdentifyStep::Render(p, f) => {
                assert_eq!(p.step, LoginStep::Identify);
                assert!(p.email_first);
                assert_eq!(f.id, "login");
            }
            other => panic!("{other:?}"),
        }
        // "Change": back to the email page, prefilled.
        match identify_input(s, IdentifyInput::Change) {
            IdentifyStep::Render(p, f) => {
                assert_eq!(p.step, LoginStep::EmailFirst);
                assert_eq!(f.id, IDENTIFY_FORM_ID);
                assert_eq!(f.fields[0].value.as_deref(), Some("alice@acme.example"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn email_first_form_answers_from_the_password_step() {
        // The lock / CAPTCHA page of a routed tenant renders the email-first form bound to a
        // flow at the password step; its submission is routed again.
        let (state, _, _) = submitted("alice@acme.example");
        let (p, _) = render(routed(state, HrdRoute::Local, false));
        assert_eq!(p.step, LoginStep::Identify);
        assert!(p.email_first);
        match identify_input(p, IdentifyInput::Email(" bob@acme.example ".into())) {
            IdentifyStep::Route {
                state,
                email,
                chose_sso,
            } => {
                assert_eq!(email, "bob@acme.example");
                assert!(!chose_sso);
                assert_eq!(state.step, LoginStep::EmailFirst);
                assert!(!state.email_first);
                assert_eq!(state.identifier.as_deref(), Some("bob@acme.example"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn identify_inputs_outside_their_step_are_invalid() {
        let invalid = |state: LoginState, input: IdentifyInput| match identify_input(state, input) {
            IdentifyStep::Render(_, f) => {
                assert_eq!(
                    f.messages.last().unwrap().key,
                    "flow.invalid_input",
                    "{f:?}"
                );
            }
            other => panic!("{other:?}"),
        };
        // The combined form (no routing) takes no email-first input.
        invalid(
            LoginState::default(),
            IdentifyInput::Email("a@b.example".into()),
        );
        invalid(LoginState::default(), IdentifyInput::Change);
        let (first, _) = email_first();
        invalid(first.clone(), IdentifyInput::Sso);
        invalid(first.clone(), IdentifyInput::Password);
        invalid(first.clone(), IdentifyInput::Change);
        let (_, s) = second_factor_state(BOTH);
        invalid(s, IdentifyInput::Email("a@b.example".into()));
        let step_up = LoginState {
            step: LoginStep::EmailFirst,
            step_up_session: Some(SessionId::new_v7()),
            ..LoginState::default()
        };
        invalid(step_up, IdentifyInput::Email("a@b.example".into()));
        // A password POST on the email page is invalid input (the page has no password).
        let (_, effects) = engine_transition(
            FlowState::Login(first),
            FlowInput::Login {
                identifier: "a@b.example".into(),
                password: PW.into(),
            },
            &env(),
        );
        assert_eq!(rendered(&effects).id, IDENTIFY_FORM_ID);
    }

    #[test]
    fn passkeys_and_saml_starts_are_accepted_in_every_primary_step() {
        let (first, _) = email_first();
        let choice = LoginState {
            step: LoginStep::SsoChoice {
                connection_id: conn(),
            },
            ..LoginState::default()
        };
        for s in [LoginState::default(), first, choice] {
            let (_, effects) = passkey_options(s.clone());
            assert!(matches!(effects[..], [Effect::StartPasskey]), "{s:?}");
            assert!(with_saml(s, saml_pending()).is_some());
        }
        let (_, s) = second_factor_state(BOTH);
        assert!(!s.step.is_primary());
    }

    #[test]
    fn new_steps_round_trip_and_old_rows_decode() {
        let c = conn();
        for step in [
            LoginStep::EmailFirst,
            LoginStep::SsoChoice { connection_id: c },
        ] {
            let s = LoginState {
                identifier: Some("a@b.example".into()),
                step,
                email_first: step == LoginStep::EmailFirst,
                ..LoginState::default()
            };
            let json = serde_json::to_string(&FlowState::Login(s.clone())).expect("encode");
            let FlowState::Login(back) = serde_json::from_str(&json).expect("decode") else {
                panic!("login");
            };
            assert_eq!(back, s);
        }
        let old: FlowState = serde_json::from_str(r#"{"kind":"login","step":{"name":"identify"}}"#)
            .expect("old json");
        assert!(
            matches!(old, FlowState::Login(s) if !s.email_first && s.step == LoginStep::Identify)
        );
        // `email_first` is not written while false (old readers see the same JSON).
        let json = serde_json::to_string(&FlowState::Login(LoginState::default())).unwrap();
        assert!(!json.contains("email_first"));
    }

    #[test]
    fn failures_on_the_email_page_keep_the_page() {
        let (first, _) = email_first();
        let f = on_failure(&first, Failure::PasskeyInvalid);
        assert_eq!(f.id, IDENTIFY_FORM_ID);
        assert_eq!(f.messages[0].key, "login.passkey_failed");
        let refused = form_with(&first, vec![FormMessage::error(USE_SSO)]);
        assert_eq!(refused.id, IDENTIFY_FORM_ID);
    }
}
