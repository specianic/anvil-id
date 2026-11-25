//! Settings flow: the server-side state of the account security page (plan 03-14).
//!
//! A settings flow is a regular self-service flow row (`FlowKind::Settings`, flow cookie + CSRF
//! token, 15 minutes) whose opaque state is a [`SettingsState`]. It is bound to the signed-in user
//! that opened the page and holds at most one pending ceremony of each kind:
//!
//! - `pending_passkey`: the server-side WebAuthn registration state (`Challenge::state_json`).
//! - `pending_totp`: the not yet confirmed TOTP secret, **sealed with the KEK**
//!   ([`SETTINGS_TOTP_PURPOSE`], AAD [`settings_totp_aad`]) and base64url-encoded. The raw secret
//!   never appears in the state.
//!
//! The transitions are pure; [`crate::service::account::AccountService`] persists every change
//! with `FlowRepo::swap_state` (compare-and-swap), so a pending challenge or secret is consumed at
//! most once even under concurrent submissions.

use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::model::{FlowId, UserId};

/// Credential changes require a sign-in no older than this (session `auth_time`).
pub const REAUTH_WINDOW: Duration = Duration::minutes(15);

/// KEK purpose of a TOTP secret pending in a settings flow (not yet a credential).
pub const SETTINGS_TOTP_PURPOSE: &str = "anvilid/settings-totp/v1";

/// Longest passkey label, in characters.
pub const MAX_LABEL_CHARS: usize = 64;

/// Label given to a passkey when the user leaves the field empty.
pub const DEFAULT_PASSKEY_LABEL: &str = "Passkey";

/// AAD of a pending TOTP secret: `flow:{id}`, so a sealed secret cannot be moved to another flow.
pub fn settings_totp_aad(flow: FlowId) -> Vec<u8> {
    format!("flow:{flow}").into_bytes()
}

/// `true` if a session authenticated at `auth_time` may change credentials at `now`.
pub fn is_recent_auth(auth_time: OffsetDateTime, now: OffsetDateTime) -> bool {
    now - auth_time <= REAUTH_WINDOW
}

/// Trims a user-supplied passkey label. Empty → [`DEFAULT_PASSKEY_LABEL`]; more than
/// [`MAX_LABEL_CHARS`] characters or control characters → `None` (rejected).
pub fn normalize_label(input: &str) -> Option<String> {
    let label = input.trim();
    if label.is_empty() {
        return Some(DEFAULT_PASSKEY_LABEL.to_owned());
    }
    if label.chars().count() > MAX_LABEL_CHARS || label.chars().any(char::is_control) {
        return None;
    }
    Some(label.to_owned())
}

/// Opaque state of a settings flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsState {
    /// Always `"settings"`: tells settings state apart from the engine's flow states.
    kind: SettingsTag,
    /// The user the flow belongs to. Submissions from another session user are rejected.
    pub user: UserId,
    /// Server-side WebAuthn registration state awaiting the browser's response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_passkey: Option<String>,
    /// KEK-sealed (base64url) TOTP secret awaiting confirmation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_totp: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SettingsTag {
    Settings,
}

/// The stored state is not a settings state.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("corrupt settings flow state")]
pub struct CorruptSettingsState;

impl SettingsState {
    /// A fresh state for `user`: nothing pending.
    pub fn new(user: UserId) -> Self {
        Self {
            kind: SettingsTag::Settings,
            user,
            pending_passkey: None,
            pending_totp: None,
        }
    }

    /// Starts a passkey registration; replaces any earlier pending challenge.
    #[must_use]
    pub fn with_passkey_challenge(mut self, state_json: String) -> Self {
        self.pending_passkey = Some(state_json);
        self
    }

    /// Consumes the pending passkey challenge (the returned state no longer holds it).
    #[must_use]
    pub fn take_passkey(mut self) -> (Self, Option<String>) {
        let pending = self.pending_passkey.take();
        (self, pending)
    }

    /// Starts a TOTP enrolment with a sealed secret; replaces any earlier pending secret.
    #[must_use]
    pub fn with_totp_secret(mut self, sealed_b64: String) -> Self {
        self.pending_totp = Some(sealed_b64);
        self
    }

    /// Consumes the pending TOTP secret (the returned state no longer holds it).
    #[must_use]
    pub fn take_totp(mut self) -> (Self, Option<String>) {
        let pending = self.pending_totp.take();
        (self, pending)
    }

    pub fn to_json(&self) -> String {
        // A struct of strings and a UUID always serialises.
        serde_json::to_string(self).unwrap_or_default()
    }

    pub fn from_json(json: &str) -> Result<Self, CorruptSettingsState> {
        serde_json::from_str(json).map_err(|_| CorruptSettingsState)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-11-25 12:00 UTC);

    #[test]
    fn recent_auth_window_is_15_minutes() {
        assert!(is_recent_auth(NOW, NOW));
        assert!(is_recent_auth(NOW - Duration::minutes(15), NOW));
        assert!(!is_recent_auth(
            NOW - Duration::minutes(15) - Duration::seconds(1),
            NOW
        ));
        assert!(!is_recent_auth(NOW - Duration::minutes(16), NOW));
    }

    #[test]
    fn labels_are_trimmed_bounded_and_defaulted() {
        assert_eq!(normalize_label("  Laptop  ").as_deref(), Some("Laptop"));
        assert_eq!(normalize_label("   ").as_deref(), Some("Passkey"));
        assert_eq!(normalize_label("").as_deref(), Some("Passkey"));
        let max = "é".repeat(MAX_LABEL_CHARS);
        assert_eq!(normalize_label(&max), Some(max.clone()));
        assert_eq!(normalize_label(&format!("{max}x")), None);
        assert_eq!(normalize_label("bad\u{0}label"), None);
        assert_eq!(normalize_label("line\nbreak"), None);
    }

    #[test]
    fn passkey_challenge_is_taken_once() {
        let user = UserId::new_v7();
        let s = SettingsState::new(user).with_passkey_challenge("{\"c\":1}".into());
        let (s, first) = s.take_passkey();
        assert_eq!(first.as_deref(), Some("{\"c\":1}"));
        let (s, second) = s.take_passkey();
        assert_eq!(second, None);
        assert_eq!(s, SettingsState::new(user));
    }

    #[test]
    fn totp_secret_is_taken_once_and_independent_of_passkeys() {
        let user = UserId::new_v7();
        let s = SettingsState::new(user)
            .with_passkey_challenge("p".into())
            .with_totp_secret("sealed".into());
        let (s, totp) = s.take_totp();
        assert_eq!(totp.as_deref(), Some("sealed"));
        assert_eq!(s.pending_passkey.as_deref(), Some("p"));
        assert_eq!(s.take_totp().1, None);
    }

    #[test]
    fn a_new_challenge_replaces_the_old_one() {
        let s = SettingsState::new(UserId::new_v7())
            .with_passkey_challenge("old".into())
            .with_passkey_challenge("new".into());
        assert_eq!(s.take_passkey().1.as_deref(), Some("new"));
    }

    #[test]
    fn json_round_trips_and_is_tagged() {
        let s = SettingsState::new(UserId::new_v7()).with_totp_secret("c2VhbGVk".into());
        let json = s.to_json();
        assert!(json.contains("\"kind\":\"settings\""), "{json}");
        assert_eq!(SettingsState::from_json(&json), Ok(s.clone()));
        // An engine flow state (e.g. login) is not a settings state.
        assert_eq!(
            SettingsState::from_json(r#"{"kind":"login","identifier":null}"#),
            Err(CorruptSettingsState)
        );
        assert_eq!(SettingsState::from_json("{}"), Err(CorruptSettingsState));
        // Fresh state serialises without pending fields.
        let fresh = SettingsState::new(s.user).to_json();
        assert!(!fresh.contains("pending"), "{fresh}");
    }

    #[test]
    fn aad_binds_the_flow() {
        let a = FlowId::new_v7();
        assert_eq!(settings_totp_aad(a), format!("flow:{a}").into_bytes());
        assert_ne!(settings_totp_aad(a), settings_totp_aad(FlowId::new_v7()));
    }
}
