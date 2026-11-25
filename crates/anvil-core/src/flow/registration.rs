//! Self-registration flow.
//!
//! Honours the tenant's [`RegistrationMode`] (only `Open` allows self-registration), the
//! password policy and the breach check. A valid submission creates the user together with the
//! verification token and email (one transaction), then signs the user in, unless the tenant
//! requires a verified email, in which case it shows `registration.check_email`.

use serde::{Deserialize, Serialize};

use super::engine::{
    Effect, EmailKind, Failure, FlowEnv, FlowState, SessionAuth, error, field, form as build_form,
    password_field, secret, validate_credentials,
};
use super::form::{FieldKind, FormDescription, FormMessage};
use crate::model::RegistrationMode;

/// Maximum length of the optional display name, in characters.
pub const MAX_NAME_LEN: usize = 200;

/// Registration state: the last non-secret values entered.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RegistrationState {
    pub email: Option<String>,
    pub name: Option<String>,
}

pub(super) fn initial(env: &FlowEnv) -> (FlowState, FormDescription) {
    let s = RegistrationState::default();
    let messages = if env.registration == RegistrationMode::Open {
        Vec::new()
    } else {
        vec![error("registration.disabled")]
    };
    let f = form(&s, messages, Vec::new(), Vec::new(), env);
    (FlowState::Registration(s), f)
}

pub(super) fn transition(
    mut state: RegistrationState,
    email: String,
    password: String,
    name: Option<String>,
    env: &FlowEnv,
) -> (FlowState, Vec<Effect>) {
    let email_trimmed = email.trim().to_owned();
    state.email = (!email_trimmed.is_empty()).then_some(email_trimmed);
    state.name = name
        .map(|n| n.trim().chars().take(MAX_NAME_LEN).collect::<String>())
        .filter(|n| !n.is_empty());

    if env.registration != RegistrationMode::Open {
        let f = form(
            &state,
            vec![error("registration.disabled")],
            Vec::new(),
            Vec::new(),
            env,
        );
        return (FlowState::Registration(state), vec![Effect::Render(f)]);
    }

    match validate_credentials(&email, &password, &env.policy) {
        Err((email_msgs, pw_msgs)) => {
            let f = form(&state, Vec::new(), email_msgs, pw_msgs, env);
            (FlowState::Registration(state), vec![Effect::Render(f)])
        }
        Ok(email) => {
            let mut effects = vec![
                Effect::CheckBreach {
                    password: secret(password.clone()),
                },
                Effect::CreateUser {
                    email,
                    name: state.name.clone(),
                    password: secret(password),
                },
                Effect::EnqueueEmail(EmailKind::Verification),
            ];
            effects.push(if env.require_verified_email {
                Effect::Message("registration.check_email")
            } else {
                Effect::CreateSession(SessionAuth::Password)
            });
            (FlowState::Registration(state), effects)
        }
    }
}

pub(super) fn on_failure(
    state: &RegistrationState,
    failure: Failure,
    env: &FlowEnv,
) -> FormDescription {
    match failure {
        Failure::EmailTaken => form(
            state,
            Vec::new(),
            vec![error("registration.email_taken")],
            Vec::new(),
            env,
        ),
        Failure::Breached => form(
            state,
            Vec::new(),
            Vec::new(),
            vec![error("password.breached")],
            env,
        ),
        Failure::Overloaded => form(
            state,
            vec![error("service.overloaded")],
            Vec::new(),
            Vec::new(),
            env,
        ),
        Failure::InvalidCredentials
        | Failure::EmailNotVerified
        | Failure::InvalidToken
        | Failure::SecondFactorInvalid
        | Failure::PasskeyInvalid => form(
            state,
            vec![error("flow.invalid_input")],
            Vec::new(),
            Vec::new(),
            env,
        ),
    }
}

pub(super) fn form(
    state: &RegistrationState,
    messages: Vec<FormMessage>,
    email_msgs: Vec<FormMessage>,
    password_msgs: Vec<FormMessage>,
    _env: &FlowEnv,
) -> FormDescription {
    build_form(
        "registration",
        "registration",
        vec![
            field(
                "email",
                FieldKind::Email,
                "field.email",
                state.email.clone(),
                true,
                Some("email"),
                email_msgs,
            ),
            field(
                "name",
                FieldKind::Text,
                "field.name",
                state.name.clone(),
                false,
                Some("name"),
                Vec::new(),
            ),
            password_field("new-password", password_msgs),
        ],
        messages,
    )
}

#[cfg(test)]
mod tests {
    use super::super::engine::test_support::*;
    use super::super::engine::{FlowInput, transition as engine_transition};
    use super::*;

    const PW: &str = "correct horse battery";

    fn submit(env: &FlowEnv, email: &str, password: &str) -> (FlowState, Vec<Effect>) {
        engine_transition(
            FlowState::Registration(RegistrationState::default()),
            FlowInput::Register {
                email: email.into(),
                password: password.into(),
                name: Some("  Alice ".into()),
            },
            env,
        )
    }

    fn rendered(effects: &[Effect]) -> &FormDescription {
        assert_eq!(effects.len(), 1, "{effects:?}");
        match &effects[0] {
            Effect::Render(f) => f,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn disabled_and_invite_only_refuse() {
        for mode in [RegistrationMode::Disabled, RegistrationMode::InviteOnly] {
            let env = FlowEnv {
                registration: mode,
                ..FlowEnv::default()
            };
            let (_, effects) = submit(&env, "a@example.com", PW);
            let f = rendered(&effects);
            assert_eq!(all_keys(f), vec!["registration.disabled"]);
            assert_form_invariants(f, &[PW]);
            let (_, initial_form) = initial(&env);
            assert_eq!(all_keys(&initial_form), vec!["registration.disabled"]);
        }
    }

    #[test]
    fn short_password_is_a_password_field_error() {
        let (_, effects) = submit(&FlowEnv::default(), "a@example.com", "1234567");
        let f = rendered(&effects);
        let pw = f.fields.iter().find(|x| x.name == "password").unwrap();
        assert_eq!(pw.messages.len(), 1);
        assert_eq!(pw.messages[0].key, "password.too_short");
        let email = f.fields.iter().find(|x| x.name == "email").unwrap();
        assert_eq!(email.value.as_deref(), Some("a@example.com"));
        assert!(email.messages.is_empty());
        assert_form_invariants(f, &["1234567"]);
    }

    #[test]
    fn invalid_email_is_an_email_field_error() {
        let (_, effects) = submit(&FlowEnv::default(), "not-an-email", PW);
        let f = rendered(&effects);
        let email = f.fields.iter().find(|x| x.name == "email").unwrap();
        assert_eq!(email.messages[0].key, "email.invalid");
        assert_eq!(email.value.as_deref(), Some("not-an-email"));
        assert_form_invariants(f, &[PW]);
    }

    #[test]
    fn valid_plans_breach_create_email_session() {
        let (state, effects) = submit(&FlowEnv::default(), " A@Example.com", PW);
        assert_eq!(
            state,
            FlowState::Registration(RegistrationState {
                email: Some("A@Example.com".into()),
                name: Some("Alice".into()),
            })
        );
        assert_eq!(effects.len(), 4);
        assert!(matches!(effects[0], Effect::CheckBreach { .. }));
        match &effects[1] {
            Effect::CreateUser { email, name, .. } => {
                assert_eq!(email, "a@example.com");
                assert_eq!(name.as_deref(), Some("Alice"));
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            effects[2],
            Effect::EnqueueEmail(EmailKind::Verification)
        ));
        assert!(matches!(
            effects[3],
            Effect::CreateSession(SessionAuth::Password)
        ));
    }

    #[test]
    fn require_verified_email_shows_check_email_instead_of_session() {
        let env = FlowEnv {
            require_verified_email: true,
            ..FlowEnv::default()
        };
        let (_, effects) = submit(&env, "a@example.com", PW);
        assert!(matches!(
            effects.last(),
            Some(Effect::Message("registration.check_email"))
        ));
    }

    #[test]
    fn failures_map_to_field_errors() {
        let env = FlowEnv::default();
        let s = RegistrationState {
            email: Some("a@example.com".into()),
            name: None,
        };
        let f = on_failure(&s, Failure::EmailTaken, &env);
        let email = f.fields.iter().find(|x| x.name == "email").unwrap();
        assert_eq!(email.messages[0].key, "registration.email_taken");
        assert_eq!(email.value.as_deref(), Some("a@example.com"));
        let f = on_failure(&s, Failure::Breached, &env);
        let pw = f.fields.iter().find(|x| x.name == "password").unwrap();
        assert_eq!(pw.messages[0].key, "password.breached");
        assert_eq!(
            all_keys(&on_failure(&s, Failure::Overloaded, &env)),
            vec!["service.overloaded"]
        );
    }
}
