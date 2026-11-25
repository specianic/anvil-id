//! Login flow: password (optionally followed by a second factor) and usernameless passkey
//! sign-in.
//!
//! # Steps
//!
//! - [`LoginStep::Identify`]: the email/password form. A correct password is followed by
//!   [`Effect::CheckSecondFactor`]: a user with TOTP moves to [`LoginStep::SecondFactor`]
//!   ([`second_factor_required`]); a user without signs in with `amr = [pwd]`. The same step
//!   accepts a passkey assertion against the challenge stored in
//!   [`LoginState::passkey_challenge`] (put there by [`Effect::StartPasskey`]).
//! - [`LoginStep::SecondFactor`]: a TOTP code or a recovery code for the user whose password
//!   was verified; success signs in with `amr = [pwd, otp, mfa]`.
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

use super::engine::{
    Effect, Failure, FlowEnv, FlowState, SessionAuth, error, field, form as build_form,
    password_field, secret,
};
use super::form::{FieldKind, FormDescription, FormMessage};
use crate::model::{UserId, normalize_email};

/// Id of the second-factor form.
pub const SECOND_FACTOR_FORM_ID: &str = "second-factor";

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
}

/// Second factors the user can use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SecondFactorMethods {
    /// The user has a TOTP credential.
    pub totp: bool,
    /// The user has unused recovery codes.
    pub recovery: bool,
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
    if state.step != LoginStep::Identify {
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
    if state.step != LoginStep::Identify {
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
            let f = form(&state, vec![error("login.passkey_failed")]);
            (FlowState::Login(state), vec![Effect::Render(f)])
        }
    }
}

pub(super) fn totp(state: LoginState, code: String) -> (FlowState, Vec<Effect>) {
    match state.step {
        LoginStep::SecondFactor { user_id, methods } if methods.totp => (
            FlowState::Login(state),
            vec![
                Effect::VerifyTotp {
                    user_id,
                    code: secret(code),
                },
                Effect::CreateSession(SessionAuth::SecondFactor),
            ],
        ),
        _ => invalid_input(state),
    }
}

pub(super) fn recovery_code(state: LoginState, code: String) -> (FlowState, Vec<Effect>) {
    match state.step {
        LoginStep::SecondFactor { user_id, methods } if methods.recovery => (
            FlowState::Login(state),
            vec![
                Effect::ConsumeRecoveryCode {
                    user_id,
                    code: secret(code),
                },
                Effect::CreateSession(SessionAuth::SecondFactor),
            ],
        ),
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
    let f = second_factor_form(methods, Vec::new());
    (FlowState::Login(state), f)
}

fn invalid_input(state: LoginState) -> (FlowState, Vec<Effect>) {
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
    }
}

/// The form of the current step.
pub(super) fn current_form(state: &LoginState, messages: Vec<FormMessage>) -> FormDescription {
    match state.step {
        LoginStep::Identify => form(state, messages),
        LoginStep::SecondFactor { methods, .. } => second_factor_form(methods, messages),
    }
}

pub(super) fn form(state: &LoginState, messages: Vec<FormMessage>) -> FormDescription {
    build_form(
        "login",
        "login",
        vec![
            field(
                "identifier",
                FieldKind::Email,
                "Email",
                state.identifier.clone(),
                true,
                Some("username"),
                Vec::new(),
            ),
            password_field("current-password", Vec::new()),
        ],
        messages,
    )
}

/// The second-factor form: a `code` field (TOTP, `autocomplete=one-time-code`; themes render it
/// with `inputmode=numeric`) and, when the user has unused recovery codes, the alternative
/// `recovery_code` field. Exactly one of them is submitted.
pub(super) fn second_factor_form(
    methods: SecondFactorMethods,
    messages: Vec<FormMessage>,
) -> FormDescription {
    let mut fields = Vec::new();
    if methods.totp {
        fields.push(field(
            "code",
            FieldKind::Text,
            "Authentication code",
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
            "Recovery code",
            None,
            false,
            Some("off"),
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
        };
        (user, state)
    }

    const BOTH: SecondFactorMethods = SecondFactorMethods {
        totp: true,
        recovery: true,
    };

    fn rendered(effects: &[Effect]) -> &FormDescription {
        assert_eq!(effects.len(), 1, "{effects:?}");
        match &effects[0] {
            Effect::Render(f) => f,
            other => panic!("{other:?}"),
        }
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
                passkey_challenge: None,
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
}
