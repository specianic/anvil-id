//! RP-initiated logout confirmation flow (OIDC-12).
//!
//! When the end-session endpoint cannot log out without asking (RP-Initiated Logout 1.0 §2: no
//! valid `id_token_hint` for the current session), the user gets a confirmation page. Like the
//! consent screen it is a small state machine of its own (`FlowKind::Logout`), separate from the
//! login engine: a flow row (flow cookie + CSRF token, 15 minutes) holds a [`LogoutState`] with
//! what the decision table resolved: the client the request named (if any) and the validated
//! post-logout redirect (if any). Confirming consumes the flow (it is deleted, so a second
//! submission finds nothing), revokes the browser session and returns the stored redirect.
//!
//! The state never stores the `id_token_hint`; the redirect was validated against the client's
//! registered list before the flow was created and is used verbatim.
//!
//! Everything here is pure; [`crate::service::logout::LogoutService`] orchestrates the ports.

use serde::{Deserialize, Serialize};

use crate::oauth::logout::PostLogoutRedirect;

/// Opaque state of a logout confirmation flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogoutState {
    /// Always `"logout"`: tells logout state apart from the other flow states.
    kind: LogoutTag,
    /// The client named by the request (`client_id` or the hint's audience), for the page and
    /// the audit event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// The validated post-logout redirect URI (registered for `client_id`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    redirect_uri: Option<String>,
    /// The RP's `state`, echoed on the redirect. Only stored together with `redirect_uri`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    state: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LogoutTag {
    Logout,
}

/// The stored state is not a logout state.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("corrupt logout flow state")]
pub struct CorruptLogoutState;

impl LogoutState {
    /// The state of a confirmation page for `client_id` with an optional validated redirect.
    pub fn new(client_id: Option<String>, redirect: Option<PostLogoutRedirect>) -> Self {
        let (redirect_uri, state) = match redirect {
            Some(r) => (Some(r.uri), r.state),
            None => (None, None),
        };
        Self {
            kind: LogoutTag::Logout,
            client_id,
            redirect_uri,
            state,
        }
    }

    /// The post-logout redirect to use after confirmation, if any.
    pub fn redirect(&self) -> Option<PostLogoutRedirect> {
        self.redirect_uri.as_ref().map(|uri| PostLogoutRedirect {
            uri: uri.clone(),
            state: self.state.clone(),
        })
    }

    pub fn to_json(&self) -> String {
        // Strings only: always serialises.
        serde_json::to_string(self).unwrap_or_default()
    }

    pub fn from_json(json: &str) -> Result<Self, CorruptLogoutState> {
        serde_json::from_str(json).map_err(|_| CorruptLogoutState)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_round_trips_and_is_tagged() {
        let state = LogoutState::new(
            Some("rp".into()),
            Some(PostLogoutRedirect {
                uri: "https://rp.example/bye?x=1".into(),
                state: Some("s t".into()),
            }),
        );
        let json = state.to_json();
        assert!(json.contains("\"kind\":\"logout\""), "{json}");
        let back = LogoutState::from_json(&json).expect("round trip");
        assert_eq!(back, state);
        assert_eq!(
            back.redirect().map(|r| r.to_url()).as_deref(),
            Some("https://rp.example/bye?x=1&state=s+t")
        );
        assert_eq!(back.client_id.as_deref(), Some("rp"));
    }

    #[test]
    fn no_redirect_means_no_state() {
        let state = LogoutState::new(None, None);
        let json = state.to_json();
        assert_eq!(json, r#"{"kind":"logout"}"#);
        assert_eq!(LogoutState::from_json(&json), Ok(state.clone()));
        assert_eq!(state.redirect(), None);
        assert_eq!(state.client_id, None);
    }

    #[test]
    fn other_flow_states_are_not_logout_states() {
        for other in [
            r#"{"kind":"consent","user":"0192d0b4-0000-7000-8000-000000000000"}"#,
            r#"{"identifier":null}"#,
            r#"{"kind":"logout","extra":1}"#,
            "",
        ] {
            assert_eq!(
                LogoutState::from_json(other),
                Err(CorruptLogoutState),
                "{other}"
            );
        }
    }
}
