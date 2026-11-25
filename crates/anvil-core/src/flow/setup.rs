//! First-run setup form (admin email and password).
//!
//! This flow only validates the input (email syntax, password policy). Completing setup (admin
//! user and management client) is `BootstrapService::complete_setup`, which the web handler
//! calls with the [`Effect::SubmitSetup`] values.

use serde::{Deserialize, Serialize};

use super::engine::{
    Effect, Failure, FlowEnv, FlowState, error, field, form as build_form, password_field, secret,
    validate_credentials,
};
use super::form::{FieldKind, FormDescription, FormMessage};

/// Setup state: the last admin email entered.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SetupState {
    pub email: Option<String>,
}

pub(super) fn transition(
    mut state: SetupState,
    email: String,
    password: String,
    env: &FlowEnv,
) -> (FlowState, Vec<Effect>) {
    let trimmed = email.trim().to_owned();
    state.email = (!trimmed.is_empty()).then_some(trimmed);
    match validate_credentials(&email, &password, &env.policy) {
        Ok(email) => (
            FlowState::Setup(state),
            vec![Effect::SubmitSetup {
                email,
                password: secret(password),
            }],
        ),
        Err((email_msgs, pw_msgs)) => {
            let f = form(&state, Vec::new(), email_msgs, pw_msgs);
            (FlowState::Setup(state), vec![Effect::Render(f)])
        }
    }
}

pub(super) fn on_failure(state: &SetupState, failure: Failure) -> FormDescription {
    let key = match failure {
        Failure::Overloaded => "service.overloaded",
        _ => "flow.invalid_input",
    };
    form(state, vec![error(key)], Vec::new(), Vec::new())
}

pub(super) fn form(
    state: &SetupState,
    messages: Vec<FormMessage>,
    email_msgs: Vec<FormMessage>,
    password_msgs: Vec<FormMessage>,
) -> FormDescription {
    build_form(
        "setup",
        "setup",
        vec![
            field(
                "email",
                FieldKind::Email,
                "field.admin_email",
                state.email.clone(),
                true,
                Some("email"),
                email_msgs,
            ),
            password_field("new-password", password_msgs),
        ],
        messages,
    )
}

#[cfg(test)]
mod tests {
    use super::super::engine::test_support::*;
    use super::*;

    #[test]
    fn valid_input_submits_normalised_email() {
        let (_, effects) = transition(
            SetupState::default(),
            " Admin@Example.com ".into(),
            "correct horse battery".into(),
            &FlowEnv::default(),
        );
        match &effects[..] {
            [Effect::SubmitSetup { email, .. }] => assert_eq!(email, "admin@example.com"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn invalid_input_renders_field_errors_without_password() {
        let (state, effects) = transition(
            SetupState::default(),
            "bad".into(),
            "short".into(),
            &FlowEnv::default(),
        );
        assert_eq!(
            state,
            FlowState::Setup(SetupState {
                email: Some("bad".into())
            })
        );
        match &effects[..] {
            [Effect::Render(f)] => {
                assert_eq!(f.id, "setup");
                assert_eq!(all_keys(f), vec!["email.invalid", "password.too_short"]);
                assert_form_invariants(f, &["short"]);
            }
            other => panic!("{other:?}"),
        }
    }
}
