//! Email verification flow.
//!
//! The emailed link (`GET .../ui/verification?token=…`) only starts the flow: the token goes into
//! a hidden form field and is not stored in the flow state. Only the POST
//! ([`super::engine::FlowInput::ConfirmVerification`]) consumes it, so link scanners that fetch
//! the URL cannot use the single-use token up.

use serde::{Deserialize, Serialize};

use super::engine::{Effect, Failure, FlowState, error, field, form as build_form, secret};
use super::form::{FieldKind, FormDescription, FormMessage};

/// Longest token accepted; issued tokens are 43 characters.
pub const MAX_TOKEN_LEN: usize = 256;

/// Verification state. Deliberately empty: the token lives only in the form.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct VerificationState {}

pub(super) fn initial(token: Option<String>) -> (FlowState, FormDescription) {
    let f = form(token, Vec::new());
    (FlowState::Verification(VerificationState {}), f)
}

pub(super) fn transition(state: VerificationState, token: String) -> (FlowState, Vec<Effect>) {
    let token = token.trim().to_owned();
    let effects = if token.is_empty() || token.len() > MAX_TOKEN_LEN {
        vec![Effect::Render(form(
            None,
            vec![error("verification.invalid_token")],
        ))]
    } else {
        vec![
            Effect::CompleteVerification {
                token: secret(token),
            },
            Effect::Message("verification.done"),
        ]
    };
    (FlowState::Verification(state), effects)
}

pub(super) fn on_failure(failure: Failure) -> FormDescription {
    let key = match failure {
        Failure::Overloaded => "service.overloaded",
        _ => "verification.invalid_token",
    };
    form(None, vec![error(key)])
}

pub(super) fn form(token: Option<String>, messages: Vec<FormMessage>) -> FormDescription {
    build_form(
        "verification",
        "verification",
        vec![field(
            "token",
            FieldKind::Hidden,
            "Token",
            token,
            true,
            None,
            Vec::new(),
        )],
        messages,
    )
}

#[cfg(test)]
mod tests {
    use super::super::engine::test_support::*;
    use super::super::engine::{FlowEnv, FlowInput, transition as engine_transition};
    use super::*;
    use crate::model::FlowKind;

    #[test]
    fn get_puts_token_in_hidden_field_only() {
        let (state, f) = FlowState::initial(
            FlowKind::Verification,
            Some("tok123".into()),
            &FlowEnv::default(),
        );
        assert_eq!(state, FlowState::Verification(VerificationState {}));
        assert!(!serde_json::to_string(&state).unwrap().contains("tok123"));
        let t = f.fields.iter().find(|x| x.name == "token").unwrap();
        assert_eq!(t.kind, FieldKind::Hidden);
        assert_eq!(t.value.as_deref(), Some("tok123"));
        assert_form_invariants(&f, &[]);
    }

    #[test]
    fn only_confirm_yields_complete_verification() {
        let env = FlowEnv::default();
        let (_, effects) = engine_transition(
            FlowState::Verification(VerificationState {}),
            FlowInput::ConfirmVerification {
                token: "tok123".into(),
            },
            &env,
        );
        assert!(matches!(effects[0], Effect::CompleteVerification { .. }));
        assert!(matches!(effects[1], Effect::Message("verification.done")));

        // Any other input never consumes.
        let (_, effects) = engine_transition(
            FlowState::Verification(VerificationState {}),
            FlowInput::ResetPassword {
                token: "tok123".into(),
                password: "x".repeat(10),
            },
            &env,
        );
        assert!(effects.iter().all(|e| matches!(e, Effect::Render(_))));
    }

    #[test]
    fn empty_or_oversized_token_renders_invalid() {
        for t in [String::new(), "x".repeat(MAX_TOKEN_LEN + 1)] {
            let (_, effects) = transition(VerificationState {}, t);
            match &effects[..] {
                [Effect::Render(f)] => {
                    assert_eq!(all_keys(f), vec!["verification.invalid_token"])
                }
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn invalid_token_failure_message() {
        assert_eq!(
            all_keys(&on_failure(Failure::InvalidToken)),
            vec!["verification.invalid_token"]
        );
    }
}
