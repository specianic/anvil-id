//! Password login flow.
//!
//! Every credential failure (unknown user, blocked user, user without a password, wrong
//! password) is reported as the same [`Failure::InvalidCredentials`] by the service, and renders
//! the same form with the single message `login.invalid_credentials`.

use serde::{Deserialize, Serialize};

use super::engine::{
    Effect, Failure, FlowEnv, FlowState, error, field, form as build_form, password_field, secret,
};
use super::form::{FieldKind, FormDescription, FormMessage};
use crate::model::normalize_email;

/// Login state: the last identifier entered (echoed after a failure).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LoginState {
    pub identifier: Option<String>,
}

pub(super) fn transition(
    mut state: LoginState,
    identifier: String,
    password: String,
    _env: &FlowEnv,
) -> (FlowState, Vec<Effect>) {
    let identifier = identifier.trim().to_owned();
    state.identifier = (!identifier.is_empty()).then(|| identifier.clone());
    match normalize_email(&identifier) {
        Ok(email) if !password.is_empty() => {
            let effects = vec![
                Effect::VerifyPassword {
                    email,
                    password: secret(password),
                },
                Effect::CreateSession,
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

pub(super) fn on_failure(state: &LoginState, failure: Failure) -> FormDescription {
    let key = match failure {
        Failure::EmailNotVerified => "login.email_not_verified",
        Failure::Overloaded => "service.overloaded",
        _ => "login.invalid_credentials",
    };
    form(state, vec![error(key)])
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

#[cfg(test)]
mod tests {
    use super::super::engine::test_support::*;
    use super::super::engine::{
        FlowInput, on_failure as engine_on_failure, transition as engine_transition,
    };
    use super::*;

    const PW: &str = "correct horse battery";

    fn submit(identifier: &str, password: &str) -> (FlowState, Vec<Effect>) {
        engine_transition(
            FlowState::Login(LoginState::default()),
            FlowInput::Login {
                identifier: identifier.into(),
                password: password.into(),
            },
            &FlowEnv::default(),
        )
    }

    #[test]
    fn submit_plans_verify_then_session() {
        let (state, effects) = submit("  Alice@Example.com ", PW);
        assert_eq!(
            state,
            FlowState::Login(LoginState {
                identifier: Some("Alice@Example.com".into())
            })
        );
        assert_eq!(effects.len(), 2);
        match &effects[0] {
            Effect::VerifyPassword { email, password } => {
                assert_eq!(email, "alice@example.com");
                assert_eq!(secrecy::ExposeSecret::expose_secret(password), PW);
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(effects[1], Effect::CreateSession));
    }

    #[test]
    fn invalid_result_renders_one_message_keeps_identifier_never_password() {
        let (state, effects) = submit("alice@example.com", PW);
        let env = FlowEnv::default();
        let (_, f) = engine_on_failure(state, &effects, Failure::InvalidCredentials, &env);
        assert_eq!(f.id, "login");
        assert_eq!(all_keys(&f), vec!["login.invalid_credentials"]);
        let ident = f.fields.iter().find(|x| x.name == "identifier").unwrap();
        assert_eq!(ident.value.as_deref(), Some("alice@example.com"));
        assert_form_invariants(&f, &[PW]);
    }

    #[test]
    fn malformed_identifier_or_empty_password_renders_same_message() {
        for (id, pw) in [("", PW), ("not-an-email", PW), ("a@b.c", "")] {
            let (_, effects) = submit(id, pw);
            assert_eq!(effects.len(), 1, "{id:?}");
            match &effects[0] {
                Effect::Render(f) => {
                    assert_eq!(all_keys(f), vec!["login.invalid_credentials"]);
                    assert_form_invariants(f, &[PW]);
                }
                other => panic!("{other:?}"),
            }
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
}
