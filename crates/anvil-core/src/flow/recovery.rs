//! Password recovery flow: request a reset link, then set a new password with it.
//!
//! - **Request:** any syntactically valid address yields the same visible outcome
//!   (`recovery.sent`). The [`Effect::IssueRecovery`] effect lets the service decide silently
//!   whether an active account exists.
//! - **Reset:** the emailed link starts the flow in the reset step with the token in a hidden
//!   field (never in the flow state). The token is consumed only by a POST that passes the
//!   password policy and the breach check; a policy violation does not consume it.

use serde::{Deserialize, Serialize};

use super::engine::{
    Effect, Failure, FlowState, error, field, form as build_form, password_error, password_field,
    secret,
};
use super::form::{FieldKind, FormDescription, FormMessage};
use super::verification::MAX_TOKEN_LEN;
use crate::model::normalize_email;

/// Recovery state.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RecoveryState {
    /// The flow was started from a reset link (shows the new-password form).
    pub reset: bool,
    /// The last address entered on the request form.
    pub email: Option<String>,
}

pub(super) fn initial(token: Option<String>) -> (FlowState, FormDescription) {
    match token {
        Some(token) => {
            let s = RecoveryState {
                reset: true,
                email: None,
            };
            let f = reset_form(Some(token), Vec::new(), Vec::new());
            (FlowState::Recovery(s), f)
        }
        None => {
            let s = RecoveryState::default();
            let f = request_form(&s, Vec::new(), Vec::new());
            (FlowState::Recovery(s), f)
        }
    }
}

pub(super) fn request(mut state: RecoveryState, email: String) -> (FlowState, Vec<Effect>) {
    let trimmed = email.trim().to_owned();
    state.email = (!trimmed.is_empty()).then_some(trimmed);
    state.reset = false;
    match normalize_email(&email) {
        Ok(email) => (
            FlowState::Recovery(state),
            vec![
                Effect::IssueRecovery { email },
                Effect::Message("recovery.sent"),
            ],
        ),
        Err(_) => {
            let f = request_form(&state, Vec::new(), vec![error("email.invalid")]);
            (FlowState::Recovery(state), vec![Effect::Render(f)])
        }
    }
}

pub(super) fn reset(
    state: RecoveryState,
    token: String,
    password: String,
    env: &super::engine::FlowEnv,
) -> (FlowState, Vec<Effect>) {
    let token = token.trim().to_owned();
    if token.is_empty() || token.len() > MAX_TOKEN_LEN {
        let f = request_form(&state, vec![error("recovery.invalid_token")], Vec::new());
        return (FlowState::Recovery(state), vec![Effect::Render(f)]);
    }
    if let Some(key) = password_error(&env.policy, &password) {
        // The token stays unconsumed: it goes back into the hidden field.
        let f = reset_form(Some(token), Vec::new(), vec![error(key)]);
        return (FlowState::Recovery(state), vec![Effect::Render(f)]);
    }
    let effects = vec![
        Effect::CheckBreach {
            password: secret(password.clone()),
        },
        Effect::CompleteRecovery {
            token: secret(token),
            password: secret(password),
        },
        Effect::Message("recovery.done"),
    ];
    (FlowState::Recovery(state), effects)
}

pub(super) fn on_failure(
    state: RecoveryState,
    pending: &[Effect],
    failure: Failure,
) -> (FlowState, FormDescription) {
    let f = match failure {
        // A dead token: offer to request a new link.
        Failure::InvalidToken => {
            request_form(&state, vec![error("recovery.invalid_token")], Vec::new())
        }
        Failure::Breached | Failure::Overloaded => {
            let key = if failure == Failure::Breached {
                "password.breached"
            } else {
                "service.overloaded"
            };
            if state.reset {
                // The failure happened before the token was consumed; let the user retry.
                let token = pending.iter().find_map(|e| match e {
                    Effect::CompleteRecovery { token, .. } => {
                        Some(secrecy::ExposeSecret::expose_secret(token).to_owned())
                    }
                    _ => None,
                });
                if failure == Failure::Breached {
                    reset_form(token, Vec::new(), vec![error(key)])
                } else {
                    reset_form(token, vec![error(key)], Vec::new())
                }
            } else {
                request_form(&state, vec![error(key)], Vec::new())
            }
        }
        Failure::InvalidCredentials | Failure::EmailNotVerified | Failure::EmailTaken => {
            current_form(&state, vec![error("flow.invalid_input")])
        }
    };
    (FlowState::Recovery(state), f)
}

pub(super) fn current_form(state: &RecoveryState, messages: Vec<FormMessage>) -> FormDescription {
    if state.reset {
        reset_form(None, messages, Vec::new())
    } else {
        request_form(state, messages, Vec::new())
    }
}

fn request_form(
    state: &RecoveryState,
    messages: Vec<FormMessage>,
    email_msgs: Vec<FormMessage>,
) -> FormDescription {
    build_form(
        "recovery",
        "recovery",
        vec![field(
            "email",
            FieldKind::Email,
            "Email",
            state.email.clone(),
            true,
            Some("email"),
            email_msgs,
        )],
        messages,
    )
}

fn reset_form(
    token: Option<String>,
    messages: Vec<FormMessage>,
    password_msgs: Vec<FormMessage>,
) -> FormDescription {
    build_form(
        "recovery-reset",
        "recovery",
        vec![
            field(
                "token",
                FieldKind::Hidden,
                "Token",
                token,
                true,
                None,
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
    use super::super::engine::{
        FlowEnv, FlowInput, on_failure as engine_on_failure, transition as engine_transition,
    };
    use super::*;

    const PW: &str = "correct horse battery";

    #[test]
    fn request_outcome_is_identical_for_any_valid_address() {
        let env = FlowEnv::default();
        let mut outcomes = Vec::new();
        for email in ["known@example.com", "nobody@example.com"] {
            let (_, effects) = engine_transition(
                FlowState::Recovery(RecoveryState::default()),
                FlowInput::RequestRecovery {
                    email: email.into(),
                },
                &env,
            );
            assert!(matches!(&effects[0], Effect::IssueRecovery { email: e } if e == email));
            match &effects[1] {
                Effect::Message(key) => outcomes.push(*key),
                other => panic!("{other:?}"),
            }
            assert_eq!(effects.len(), 2);
        }
        assert_eq!(outcomes, vec!["recovery.sent", "recovery.sent"]);
    }

    #[test]
    fn request_with_malformed_address_is_field_error() {
        let (_, effects) = request(RecoveryState::default(), "nope".into());
        match &effects[..] {
            [Effect::Render(f)] => {
                assert_eq!(f.id, "recovery");
                assert_eq!(all_keys(f), vec!["email.invalid"]);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn link_starts_reset_step_with_hidden_token_not_in_state() {
        let (state, f) = initial(Some("tok123".into()));
        assert!(!serde_json::to_string(&state).unwrap().contains("tok123"));
        assert_eq!(f.id, "recovery-reset");
        let t = f.fields.iter().find(|x| x.name == "token").unwrap();
        assert_eq!(
            (t.kind, t.value.as_deref()),
            (FieldKind::Hidden, Some("tok123"))
        );
        assert_form_invariants(&f, &[]);
    }

    #[test]
    fn policy_violation_does_not_consume_token() {
        let (state, _) = initial(Some("tok123".into()));
        let (_, effects) = engine_transition(
            state,
            FlowInput::ResetPassword {
                token: "tok123".into(),
                password: "short".into(),
            },
            &FlowEnv::default(),
        );
        assert!(
            !effects
                .iter()
                .any(|e| matches!(e, Effect::CompleteRecovery { .. }))
        );
        match &effects[..] {
            [Effect::Render(f)] => {
                assert_eq!(f.id, "recovery-reset");
                assert_eq!(all_keys(f), vec!["password.too_short"]);
                let t = f.fields.iter().find(|x| x.name == "token").unwrap();
                assert_eq!(t.value.as_deref(), Some("tok123"));
                assert_form_invariants(f, &["short"]);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn valid_reset_plans_breach_then_complete() {
        let (state, _) = initial(Some("tok123".into()));
        let (_, effects) = reset(
            match state {
                FlowState::Recovery(s) => s,
                _ => unreachable!(),
            },
            "tok123".into(),
            PW.into(),
            &FlowEnv::default(),
        );
        assert!(matches!(effects[0], Effect::CheckBreach { .. }));
        assert!(matches!(effects[1], Effect::CompleteRecovery { .. }));
        assert!(matches!(effects[2], Effect::Message("recovery.done")));
    }

    #[test]
    fn breach_failure_keeps_token_invalid_token_offers_new_request() {
        let env = FlowEnv::default();
        let (state, _) = initial(Some("tok123".into()));
        let pending = [
            Effect::CheckBreach {
                password: secret(PW.into()),
            },
            Effect::CompleteRecovery {
                token: secret("tok123".into()),
                password: secret(PW.into()),
            },
            Effect::Message("recovery.done"),
        ];
        let (_, f) = engine_on_failure(state.clone(), &pending, Failure::Breached, &env);
        let t = f.fields.iter().find(|x| x.name == "token").unwrap();
        assert_eq!(t.value.as_deref(), Some("tok123"));
        assert_eq!(f.id, "recovery-reset");
        assert_eq!(all_keys(&f), vec!["password.breached"]);
        assert_form_invariants(&f, &[PW]);
        let (_, f) = engine_on_failure(state, &pending[1..], Failure::InvalidToken, &env);
        assert_eq!(f.id, "recovery");
        assert_eq!(all_keys(&f), vec!["recovery.invalid_token"]);
    }
}
