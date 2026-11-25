//! Consent flow (OIDC-13): when the consent screen is needed, and the server-side state of a
//! consent page.
//!
//! Consent is a small state machine of its own (`FlowKind::Consent`), separate from the login
//! engine: a consent flow row (flow cookie + CSRF token, 15 minutes) holds a [`ConsentState`]
//! bound to the signed-in user. A flow opened by the consent screen carries the pending
//! authorization request ([`PendingConsent`]); a flow opened by the connected-apps page carries
//! none and only binds revocations to the page. A decision (Allow or Deny) marks the state
//! `decided`; [`crate::service::consent::ConsentService`] persists that with
//! `FlowRepo::swap_state`, so a double submission cannot decide twice.
//!
//! Everything here is pure; the service orchestrates the ports.

use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::model::{AuthRequestId, ConsentMode, UserId};

/// Whether the consent screen must be shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentDecision {
    /// Issue the code without asking.
    Skip,
    /// Show the consent screen.
    Required,
}

/// The requested scope tokens of a `scope` parameter, in request order, without duplicates.
pub fn requested_scopes(scope: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for s in scope.split_ascii_whitespace() {
        if !out.iter().any(|o| o == s) {
            out.push(s.to_owned());
        }
    }
    out
}

/// The requested scopes not covered by `granted`.
pub fn missing_scopes<'a>(granted: &[String], requested: &'a [String]) -> Vec<&'a str> {
    requested
        .iter()
        .filter(|r| !granted.iter().any(|g| g == *r))
        .map(String::as_str)
        .collect()
}

/// Decides whether consent is needed:
///
/// - `skip_first_party` clients never ask;
/// - `prompt=consent` always asks;
/// - an active grant covering every requested scope skips the screen;
/// - otherwise the screen is required, and with `prompt=none` that is `consent_required`
///   (OIDC Core §3.1.2.6), delivered to the client through its response mode.
pub fn consent_decision(
    mode: ConsentMode,
    granted: Option<&[String]>,
    requested: &[String],
    prompt: &[String],
) -> Result<ConsentDecision, CoreError> {
    if mode == ConsentMode::SkipFirstParty {
        return Ok(ConsentDecision::Skip);
    }
    let forced = prompt.iter().any(|p| p == "consent");
    let covered = granted.is_some_and(|g| missing_scopes(g, requested).is_empty());
    if covered && !forced {
        return Ok(ConsentDecision::Skip);
    }
    if prompt.iter().any(|p| p == "none") {
        return Err(CoreError::ConsentRequired);
    }
    Ok(ConsentDecision::Required)
}

/// Plain-language description of a standard scope; `None` for custom scopes (shown by name).
pub fn scope_description(scope: &str) -> Option<&'static str> {
    Some(match scope {
        "openid" => "Sign you in",
        "profile" => "See your name and basic profile details",
        "email" => "See your email address",
        "phone" => "See your phone number",
        "address" => "See your postal address",
        "offline_access" => "Stay signed in",
        _ => return None,
    })
}

/// The authorization request a consent screen decides on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingConsent {
    pub request_id: AuthRequestId,
    pub client_id: String,
    /// The requested scopes, granted as a whole on Allow.
    pub scopes: Vec<String>,
}

/// Opaque state of a consent flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentState {
    /// Always `"consent"`: tells consent state apart from the other flow states.
    kind: ConsentTag,
    /// The user the flow belongs to. Submissions from another session user are rejected.
    pub user: UserId,
    /// The request being decided (consent screen); `None` for the connected-apps page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<PendingConsent>,
    /// Allow or Deny was submitted; the flow cannot decide again.
    #[serde(default)]
    pub decided: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ConsentTag {
    Consent,
}

/// The stored state is not a consent state.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("corrupt consent flow state")]
pub struct CorruptConsentState;

/// Why a consent state cannot take a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecideError {
    /// The flow belongs to the connected-apps page, not to an authorization request.
    NoRequest,
    /// Allow or Deny was already submitted.
    AlreadyDecided,
}

impl ConsentState {
    /// The state of a consent screen for `request`.
    pub fn for_request(user: UserId, request: PendingConsent) -> Self {
        Self {
            kind: ConsentTag::Consent,
            user,
            request: Some(request),
            decided: false,
        }
    }

    /// The state of a connected-apps page (binds revocations only).
    pub fn for_apps(user: UserId) -> Self {
        Self {
            kind: ConsentTag::Consent,
            user,
            request: None,
            decided: false,
        }
    }

    /// Takes the decision: the next state (decided) and the request decided on.
    pub fn decide(&self) -> Result<(Self, PendingConsent), DecideError> {
        let Some(request) = self.request.clone() else {
            return Err(DecideError::NoRequest);
        };
        if self.decided {
            return Err(DecideError::AlreadyDecided);
        }
        let mut next = self.clone();
        next.decided = true;
        Ok((next, request))
    }

    pub fn to_json(&self) -> String {
        // Strings, UUIDs and a bool always serialise.
        serde_json::to_string(self).unwrap_or_default()
    }

    pub fn from_json(json: &str) -> Result<Self, CorruptConsentState> {
        serde_json::from_str(json).map_err(|_| CorruptConsentState)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `consent_decision` with the error reduced to its OAuth code (CoreError is not `PartialEq`).
    fn decision(
        mode: ConsentMode,
        granted: Option<&[String]>,
        requested: &[String],
        prompt: &[String],
    ) -> Result<ConsentDecision, &'static str> {
        consent_decision(mode, granted, requested, prompt).map_err(|e| e.oauth_error())
    }

    fn s(list: &[&str]) -> Vec<String> {
        list.iter().map(|v| (*v).to_owned()).collect()
    }

    #[test]
    fn requested_scopes_split_and_dedupe_in_order() {
        assert_eq!(
            requested_scopes("openid  profile openid\temail"),
            s(&["openid", "profile", "email"])
        );
        assert!(requested_scopes("  ").is_empty());
    }

    #[test]
    fn skip_first_party_never_asks_even_with_prompt() {
        for prompt in [s(&[]), s(&["consent"]), s(&["none"])] {
            assert_eq!(
                decision(
                    ConsentMode::SkipFirstParty,
                    None,
                    &s(&["openid", "email"]),
                    &prompt
                ),
                Ok(ConsentDecision::Skip)
            );
        }
    }

    #[test]
    fn a_covering_grant_skips_unless_prompt_consent() {
        let granted = s(&["email", "openid", "profile"]);
        let requested = s(&["openid", "profile"]);
        assert_eq!(
            decision(ConsentMode::Required, Some(&granted), &requested, &[]),
            Ok(ConsentDecision::Skip)
        );
        assert_eq!(
            decision(
                ConsentMode::Required,
                Some(&granted),
                &requested,
                &s(&["none"])
            ),
            Ok(ConsentDecision::Skip)
        );
        assert_eq!(
            decision(
                ConsentMode::Required,
                Some(&granted),
                &requested,
                &s(&["consent"])
            ),
            Ok(ConsentDecision::Required)
        );
        assert_eq!(
            decision(
                ConsentMode::Required,
                Some(&granted),
                &requested,
                &s(&["login", "consent"])
            ),
            Ok(ConsentDecision::Required)
        );
    }

    #[test]
    fn no_grant_or_a_new_scope_requires_consent() {
        let requested = s(&["openid", "email"]);
        assert_eq!(
            decision(ConsentMode::Required, None, &requested, &[]),
            Ok(ConsentDecision::Required)
        );
        let granted = s(&["openid"]);
        assert_eq!(
            decision(ConsentMode::Required, Some(&granted), &requested, &[]),
            Ok(ConsentDecision::Required)
        );
        assert_eq!(missing_scopes(&granted, &requested), ["email"]);
    }

    #[test]
    fn required_with_prompt_none_is_consent_required() {
        let requested = s(&["openid"]);
        assert_eq!(
            decision(ConsentMode::Required, None, &requested, &s(&["none"])),
            Err("consent_required")
        );
        assert_eq!(
            decision(
                ConsentMode::Required,
                Some(&s(&[])),
                &requested,
                &s(&["none"])
            ),
            Err("consent_required")
        );
    }

    #[test]
    fn standard_scopes_have_descriptions() {
        assert_eq!(scope_description("openid"), Some("Sign you in"));
        assert_eq!(scope_description("offline_access"), Some("Stay signed in"));
        for scope in ["profile", "email", "phone", "address"] {
            assert!(scope_description(scope).is_some(), "{scope}");
        }
        assert_eq!(scope_description("api:read"), None);
    }

    fn pending() -> PendingConsent {
        PendingConsent {
            request_id: AuthRequestId::new_v7(),
            client_id: "rp".into(),
            scopes: s(&["openid", "email"]),
        }
    }

    #[test]
    fn a_request_is_decided_once() {
        let p = pending();
        let state = ConsentState::for_request(UserId::new_v7(), p.clone());
        let (next, decided) = state.decide().expect("first decision");
        assert_eq!(decided, p);
        assert!(next.decided);
        assert_eq!(next.decide(), Err(DecideError::AlreadyDecided));
        assert_eq!(
            ConsentState::for_apps(UserId::new_v7()).decide(),
            Err(DecideError::NoRequest)
        );
    }

    #[test]
    fn json_round_trips_and_is_tagged() {
        let state = ConsentState::for_request(UserId::new_v7(), pending());
        let json = state.to_json();
        assert!(json.contains("\"kind\":\"consent\""), "{json}");
        assert_eq!(ConsentState::from_json(&json), Ok(state.clone()));
        let decided = state.decide().expect("decide").0;
        assert_ne!(
            decided.to_json(),
            json,
            "a decision changes the stored state"
        );
        let apps = ConsentState::for_apps(state.user);
        assert!(!apps.to_json().contains("request"));
        assert_eq!(ConsentState::from_json(&apps.to_json()), Ok(apps));
        // Other flow states are not consent states.
        assert_eq!(
            ConsentState::from_json(
                r#"{"kind":"settings","user":"0192d0b4-0000-7000-8000-000000000000"}"#
            ),
            Err(CorruptConsentState)
        );
        assert_eq!(
            ConsentState::from_json(r#"{"identifier":null}"#),
            Err(CorruptConsentState)
        );
    }
}
