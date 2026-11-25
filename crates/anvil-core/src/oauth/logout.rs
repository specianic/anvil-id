//! RP-initiated logout request parsing and validation (`id_token_hint`,
//! `post_logout_redirect_uri`, `state`) and back-channel logout token claims and delivery
//! classification (OIDC-12).
//!
//! Pure functions; the service verifies the `id_token_hint` signature (any enabled algorithm,
//! expiry ignored, RP-Initiated Logout 1.0 §2), resolves the clients and performs the logout.
//!
//! Specs:
//! - OpenID Connect RP-Initiated Logout 1.0 (Final, 2022-09-12) §2, §3, §4.
//! - OpenID Connect Back-Channel Logout 1.0 (Final incl. errata, 2023-12-15) §2.4 (logout
//!   token), §2.8 (response handling).

use serde_json::{Map, Value};
use time::OffsetDateTime;

use crate::model::{Client, DeliveryResult, LOGOUT_DELIVERY_TTL};

/// The Back-Channel Logout 1.0 §2.4 event member name.
pub const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// Lifetime of a logout token (`exp - iat`).
pub const LOGOUT_TOKEN_TTL: time::Duration = time::Duration::minutes(2);

/// First retry delay of a back-channel delivery; doubles on every attempt.
pub const DELIVERY_BASE_DELAY: time::Duration = time::Duration::seconds(10);

/// Upper bound of the retry delay.
pub const DELIVERY_MAX_DELAY: time::Duration = time::Duration::hours(1);

/// Result of verifying the `id_token_hint` (done by the caller).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HintCheck {
    /// No `id_token_hint` was sent.
    Absent,
    /// The hint failed verification (bad signature, `alg: none`, wrong issuer, malformed).
    Invalid,
    /// The hint is an ID token this OP issued (expiry ignored).
    Valid {
        sub: String,
        sid: Option<String>,
        aud: Vec<String>,
    },
}

/// The end-session request parameters (RP-Initiated Logout 1.0 §2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndSessionRequest {
    pub id_token_hint: HintCheck,
    pub client_id: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
    pub ui_locales: Option<String>,
}

/// The browser session the request arrived with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentSession {
    pub user_id: String,
    pub session_id: String,
}

/// Where to send the browser after logout: a URI registered for the client, plus `state` iff the
/// RP sent one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostLogoutRedirect {
    pub uri: String,
    pub state: Option<String>,
}

impl PostLogoutRedirect {
    /// The final redirect URL (see [`build_post_logout_redirect`]).
    pub fn to_url(&self) -> String {
        build_post_logout_redirect(&self.uri, self.state.as_deref())
    }
}

/// Why an end-session request is refused. None of these log out or redirect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogoutError {
    /// The hint did not verify or names no known client.
    InvalidIdTokenHint,
    /// `post_logout_redirect_uri` is not exactly one of the client's registered values.
    RedirectUriNotRegistered,
    /// `post_logout_redirect_uri` was sent without `id_token_hint` and without `client_id`.
    IdTokenHintRequired,
    /// `client_id` does not match the hint's audience.
    ClientMismatch,
    /// `client_id` names no client of this tenant.
    UnknownClient,
}

impl LogoutError {
    /// Stable message key for the error page.
    pub fn key(self) -> &'static str {
        match self {
            Self::InvalidIdTokenHint => "logout.invalid_id_token_hint",
            Self::RedirectUriNotRegistered => "logout.redirect_uri_not_registered",
            Self::IdTokenHintRequired => "logout.id_token_hint_required",
            Self::ClientMismatch => "logout.client_mismatch",
            Self::UnknownClient => "logout.unknown_client",
        }
    }
}

/// What the end-session endpoint does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndSessionDecision {
    /// Log the current session out (if any) without asking, then redirect or show the
    /// signed-out page.
    LogoutNow {
        redirect: Option<PostLogoutRedirect>,
    },
    /// Ask the user to confirm (RP-Initiated Logout 1.0 §2: no valid hint for the current
    /// session); after confirmation, redirect or show the signed-out page.
    Confirm {
        client_id: Option<String>,
        redirect: Option<PostLogoutRedirect>,
    },
    /// Show an error page: no logout, no redirect.
    Error(LogoutError),
}

/// Decides an end-session request.
///
/// - `hint_client`: the client named by the hint's audience, looked up by the caller in the
///   request's tenant (`None` when unknown or when there is no valid hint).
/// - `client_by_id`: the client named by the `client_id` parameter in the tenant (`None` when
///   unknown or absent).
///
/// Decision table (RP-Initiated Logout 1.0 §2, §3):
///
/// | Input | Decision |
/// |---|---|
/// | hint `Invalid`, or valid hint whose client is unknown / not in `aud` | `Error(InvalidIdTokenHint)` |
/// | valid hint, `client_id` not in `aud` or not the hint's client | `Error(ClientMismatch)` |
/// | URI not exactly registered for the client (`?foo=bar` added fails) | `Error(RedirectUriNotRegistered)` |
/// | URI without hint and without `client_id` | `Error(IdTokenHintRequired)` |
/// | unknown `client_id` without hint | `Error(UnknownClient)` |
/// | valid hint, session matches `sub` (and `sid` if present) or no session | `LogoutNow` |
/// | valid hint for another session | `Confirm` without redirect |
/// | `client_id` (+ registered URI), no hint | `Confirm` (with redirect iff URI) |
/// | no parameters / only `state` | `Confirm` without redirect |
pub fn validate_end_session(
    req: &EndSessionRequest,
    hint_client: Option<&Client>,
    client_by_id: Option<&Client>,
    current_session: Option<&CurrentSession>,
) -> EndSessionDecision {
    let redirect_for = |client: &Client| -> Result<Option<PostLogoutRedirect>, LogoutError> {
        match &req.post_logout_redirect_uri {
            None => Ok(None),
            Some(uri) if client.post_logout_redirect_uris.iter().any(|r| r == uri) => {
                Ok(Some(PostLogoutRedirect {
                    uri: uri.clone(),
                    state: req.state.clone(),
                }))
            }
            Some(_) => Err(LogoutError::RedirectUriNotRegistered),
        }
    };

    match &req.id_token_hint {
        HintCheck::Invalid => EndSessionDecision::Error(LogoutError::InvalidIdTokenHint),
        HintCheck::Valid { sub, sid, aud } => {
            // The hint must name a known client: the one the caller resolved, and it must be in
            // the hint's audience (never trust the lookup alone).
            let Some(client) = hint_client.filter(|c| aud.contains(&c.client_id)) else {
                return EndSessionDecision::Error(LogoutError::InvalidIdTokenHint);
            };
            // RP-Initiated Logout 1.0 §2: `client_id` and the hint's `aud` must agree.
            if let Some(client_id) = &req.client_id
                && (*client_id != client.client_id || !aud.contains(client_id))
            {
                return EndSessionDecision::Error(LogoutError::ClientMismatch);
            }
            let redirect = match redirect_for(client) {
                Ok(r) => r,
                Err(e) => return EndSessionDecision::Error(e),
            };
            let belongs_to_session = current_session.is_none_or(|s| {
                s.user_id == *sub && sid.as_ref().is_none_or(|sid| *sid == s.session_id)
            });
            if belongs_to_session {
                EndSessionDecision::LogoutNow { redirect }
            } else {
                // A hint for another session or user: ask, and do not send that user's browser
                // to the RP afterwards.
                EndSessionDecision::Confirm {
                    client_id: Some(client.client_id.clone()),
                    redirect: None,
                }
            }
        }
        HintCheck::Absent => match &req.client_id {
            Some(client_id) => {
                let Some(client) = client_by_id.filter(|c| c.client_id == *client_id) else {
                    return EndSessionDecision::Error(LogoutError::UnknownClient);
                };
                match redirect_for(client) {
                    Ok(redirect) => EndSessionDecision::Confirm {
                        client_id: Some(client.client_id.clone()),
                        redirect,
                    },
                    Err(e) => EndSessionDecision::Error(e),
                }
            }
            None if req.post_logout_redirect_uri.is_some() => {
                EndSessionDecision::Error(LogoutError::IdTokenHintRequired)
            }
            None => EndSessionDecision::Confirm {
                client_id: None,
                redirect: None,
            },
        },
    }
}

/// Appends `state` (form-encoded) to a registered post-logout URI, keeping the URI's own query
/// and adding nothing else. The registered string is used verbatim, never re-serialised.
pub fn build_post_logout_redirect(uri: &str, state: Option<&str>) -> String {
    let Some(state) = state else {
        return uri.to_owned();
    };
    let encoded: String = url::form_urlencoded::byte_serialize(state.as_bytes()).collect();
    // A fragment (never registered in practice) stays last.
    let (base, fragment) = match uri.find('#') {
        Some(i) => uri.split_at(i),
        None => (uri, ""),
    };
    let sep = if !base.contains('?') {
        "?"
    } else if base.ends_with('?') || base.ends_with('&') {
        ""
    } else {
        "&"
    };
    format!("{base}{sep}state={encoded}{fragment}")
}

/// The claim set of a logout token (Back-Channel Logout 1.0 §2.4): exactly `iss`, `aud`, `iat`,
/// `exp` (`iat` + 2 min), `jti`, `sub`, `sid` and `events`; never `nonce`. The `typ: logout+jwt`
/// header is set by the signer.
pub fn logout_token_claims(
    issuer: &str,
    client_id: &str,
    sub: &str,
    sid: &str,
    jti: &str,
    now: OffsetDateTime,
) -> Map<String, Value> {
    let iat = now.unix_timestamp();
    let exp = (now + LOGOUT_TOKEN_TTL).unix_timestamp();
    let mut events = Map::new();
    events.insert(
        BACKCHANNEL_LOGOUT_EVENT.to_owned(),
        Value::Object(Map::new()),
    );
    let mut claims = Map::new();
    claims.insert("iss".to_owned(), Value::from(issuer));
    claims.insert("aud".to_owned(), Value::from(client_id));
    claims.insert("iat".to_owned(), Value::from(iat));
    claims.insert("exp".to_owned(), Value::from(exp));
    claims.insert("jti".to_owned(), Value::from(jti));
    claims.insert("sub".to_owned(), Value::from(sub));
    claims.insert("sid".to_owned(), Value::from(sid));
    claims.insert("events".to_owned(), Value::Object(events));
    claims
}

/// Outcome of one POST of a logout token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryOutcome {
    /// The RP answered with this HTTP status.
    Status(u16),
    /// Connection or TLS failure.
    Network,
    /// The request timed out.
    Timeout,
    /// The outbound policy (SSRF guard) refused the destination.
    Blocked,
}

/// Classifies a delivery attempt (Back-Channel Logout 1.0 §2.8): 200/204 delivered; any other
/// non-5xx status (including 400, "RP rejected") and a blocked destination are given up; 5xx,
/// network errors and timeouts are retried with [`next_attempt`] until
/// `created_at + LOGOUT_DELIVERY_TTL`.
///
/// `attempts` is the number of attempts made before this one.
pub fn classify_delivery(
    outcome: DeliveryOutcome,
    attempts: u32,
    created_at: OffsetDateTime,
    now: OffsetDateTime,
) -> DeliveryResult {
    let error = match outcome {
        DeliveryOutcome::Status(200 | 204) => return DeliveryResult::Delivered,
        DeliveryOutcome::Status(s @ 500..=599) => format!("status {s}"),
        DeliveryOutcome::Status(s) => {
            return DeliveryResult::GiveUp {
                error: format!("status {s}"),
            };
        }
        DeliveryOutcome::Blocked => {
            return DeliveryResult::GiveUp {
                error: "destination blocked by outbound policy".to_owned(),
            };
        }
        DeliveryOutcome::Network => "network error".to_owned(),
        DeliveryOutcome::Timeout => "timeout".to_owned(),
    };
    if now >= created_at + LOGOUT_DELIVERY_TTL {
        return DeliveryResult::GiveUp { error };
    }
    DeliveryResult::Retry {
        next_attempt_at: next_attempt(attempts, now),
        error,
    }
}

/// The next attempt time after `attempts` previous attempts: `now + min(10 s * 2^attempts, 1 h)`.
pub fn next_attempt(attempts: u32, now: OffsetDateTime) -> OffsetDateTime {
    // 10 s * 2^9 already exceeds the cap; clamping the exponent avoids overflow.
    let factor = 1_i32 << attempts.min(9);
    let delay = DELIVERY_BASE_DELAY * factor;
    now + delay.min(DELIVERY_MAX_DELAY)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::LOGOUT_DELIVERY_TTL;
    use proptest::prelude::*;
    use std::collections::BTreeSet;
    use time::macros::datetime;

    const POST: &str = "https://rp.example.test/post_logout";
    const POST_Q: &str = "https://rp.example.test/post_logout?tenant=a";

    fn rp() -> Client {
        let mut c = crate::oauth::authorize_request::tests::client();
        c.post_logout_redirect_uris = vec![POST.to_owned(), POST_Q.to_owned()];
        c
    }

    fn other() -> Client {
        let mut c = rp();
        c.client_id = "other".to_owned();
        c.post_logout_redirect_uris = vec!["https://other.example.test/bye".to_owned()];
        c
    }

    fn hint(sub: &str, sid: Option<&str>, aud: &[&str]) -> HintCheck {
        HintCheck::Valid {
            sub: sub.to_owned(),
            sid: sid.map(str::to_owned),
            aud: aud.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn req(
        id_token_hint: HintCheck,
        client_id: Option<&str>,
        uri: Option<&str>,
        state: Option<&str>,
    ) -> EndSessionRequest {
        EndSessionRequest {
            id_token_hint,
            client_id: client_id.map(str::to_owned),
            post_logout_redirect_uri: uri.map(str::to_owned),
            state: state.map(str::to_owned),
            ui_locales: None,
        }
    }

    fn session() -> CurrentSession {
        CurrentSession {
            user_id: "u1".to_owned(),
            session_id: "s1".to_owned(),
        }
    }

    fn redirect(uri: &str, state: Option<&str>) -> Option<PostLogoutRedirect> {
        Some(PostLogoutRedirect {
            uri: uri.to_owned(),
            state: state.map(str::to_owned),
        })
    }

    fn decide(r: &EndSessionRequest, sess: Option<&CurrentSession>) -> EndSessionDecision {
        let c = rp();
        let hint_client = match &r.id_token_hint {
            HintCheck::Valid { aud, .. } if aud.iter().any(|a| a == "rp") => Some(&c),
            _ => None,
        };
        let by_id = (r.client_id.as_deref() == Some("rp")).then_some(&c);
        validate_end_session(r, hint_client, by_id, sess)
    }

    // --- end-session decision table ---

    #[test]
    fn valid_hint_matching_session_with_registered_uri_logs_out_and_redirects_with_state() {
        let r = req(
            hint("u1", Some("s1"), &["rp"]),
            None,
            Some(POST),
            Some("xyz"),
        );
        assert_eq!(
            decide(&r, Some(&session())),
            EndSessionDecision::LogoutNow {
                redirect: redirect(POST, Some("xyz"))
            }
        );
    }

    #[test]
    fn valid_hint_without_state_redirects_without_state() {
        let r = req(hint("u1", Some("s1"), &["rp"]), None, Some(POST), None);
        assert_eq!(
            decide(&r, Some(&session())),
            EndSessionDecision::LogoutNow {
                redirect: redirect(POST, None)
            }
        );
    }

    #[test]
    fn valid_hint_without_uri_logs_out_to_signed_out_page() {
        let r = req(hint("u1", Some("s1"), &["rp"]), None, None, Some("xyz"));
        assert_eq!(
            decide(&r, Some(&session())),
            EndSessionDecision::LogoutNow { redirect: None }
        );
    }

    #[test]
    fn valid_hint_without_sid_matches_on_sub() {
        let r = req(hint("u1", None, &["rp"]), None, Some(POST), None);
        assert_eq!(
            decide(&r, Some(&session())),
            EndSessionDecision::LogoutNow {
                redirect: redirect(POST, None)
            }
        );
    }

    #[test]
    fn valid_hint_without_session_is_idempotent_logout() {
        let r = req(
            hint("u1", Some("s1"), &["rp"]),
            None,
            Some(POST),
            Some("st"),
        );
        assert_eq!(
            decide(&r, None),
            EndSessionDecision::LogoutNow {
                redirect: redirect(POST, Some("st"))
            }
        );
    }

    #[test]
    fn valid_hint_with_matching_client_id_logs_out() {
        let r = req(
            hint("u1", Some("s1"), &["rp"]),
            Some("rp"),
            Some(POST),
            None,
        );
        assert_eq!(
            decide(&r, Some(&session())),
            EndSessionDecision::LogoutNow {
                redirect: redirect(POST, None)
            }
        );
    }

    #[test]
    fn registered_uri_with_own_query_is_accepted() {
        let r = req(
            hint("u1", Some("s1"), &["rp"]),
            None,
            Some(POST_Q),
            Some("s"),
        );
        assert_eq!(
            decide(&r, Some(&session())),
            EndSessionDecision::LogoutNow {
                redirect: redirect(POST_Q, Some("s"))
            }
        );
    }

    #[test]
    fn hint_for_another_user_requires_confirmation_without_redirect() {
        let r = req(hint("u2", Some("s9"), &["rp"]), None, Some(POST), Some("x"));
        assert_eq!(
            decide(&r, Some(&session())),
            EndSessionDecision::Confirm {
                client_id: Some("rp".to_owned()),
                redirect: None
            }
        );
    }

    #[test]
    fn hint_for_another_session_of_same_user_requires_confirmation() {
        let r = req(hint("u1", Some("s-old"), &["rp"]), None, None, None);
        assert_eq!(
            decide(&r, Some(&session())),
            EndSessionDecision::Confirm {
                client_id: Some("rp".to_owned()),
                redirect: None
            }
        );
    }

    #[test]
    fn invalid_hint_is_rejected_without_logout_or_redirect() {
        for sess in [None, Some(session())] {
            let r = req(HintCheck::Invalid, None, Some(POST), Some("x"));
            assert_eq!(
                decide(&r, sess.as_ref()),
                EndSessionDecision::Error(LogoutError::InvalidIdTokenHint)
            );
            let r = req(HintCheck::Invalid, Some("rp"), None, None);
            assert_eq!(
                decide(&r, sess.as_ref()),
                EndSessionDecision::Error(LogoutError::InvalidIdTokenHint)
            );
        }
    }

    #[test]
    fn hint_for_unknown_client_is_invalid() {
        let r = req(hint("u1", Some("s1"), &["ghost"]), None, Some(POST), None);
        assert_eq!(
            decide(&r, Some(&session())),
            EndSessionDecision::Error(LogoutError::InvalidIdTokenHint)
        );
    }

    #[test]
    fn hint_client_not_in_aud_is_invalid() {
        // A caller bug must not turn a hint for another client into a valid one.
        let c = rp();
        let r = req(hint("u1", Some("s1"), &["other"]), None, Some(POST), None);
        assert_eq!(
            validate_end_session(&r, Some(&c), None, Some(&session())),
            EndSessionDecision::Error(LogoutError::InvalidIdTokenHint)
        );
    }

    #[test]
    fn client_id_not_in_hint_aud_is_a_mismatch() {
        let c = rp();
        let o = other();
        let r = req(hint("u1", Some("s1"), &["rp"]), Some("other"), None, None);
        assert_eq!(
            validate_end_session(&r, Some(&c), Some(&o), Some(&session())),
            EndSessionDecision::Error(LogoutError::ClientMismatch)
        );
        let r = req(hint("u1", Some("s1"), &["rp"]), Some("ghost"), None, None);
        assert_eq!(
            validate_end_session(&r, Some(&c), None, Some(&session())),
            EndSessionDecision::Error(LogoutError::ClientMismatch)
        );
    }

    #[test]
    fn client_id_in_aud_but_not_the_hint_client_is_a_mismatch() {
        let c = rp();
        let o = other();
        let r = req(
            hint("u1", Some("s1"), &["rp", "other"]),
            Some("other"),
            None,
            None,
        );
        assert_eq!(
            validate_end_session(&r, Some(&c), Some(&o), Some(&session())),
            EndSessionDecision::Error(LogoutError::ClientMismatch)
        );
    }

    #[test]
    fn unregistered_uri_is_rejected() {
        let r = req(
            hint("u1", Some("s1"), &["rp"]),
            None,
            Some("https://evil.example.test/"),
            None,
        );
        assert_eq!(
            decide(&r, Some(&session())),
            EndSessionDecision::Error(LogoutError::RedirectUriNotRegistered)
        );
    }

    #[test]
    fn query_added_to_registered_uri_is_rejected() {
        for uri in [
            format!("{POST}?foo=bar"),
            format!("{POST_Q}&foo=bar"),
            format!("{POST}/"),
            format!("{POST}#f"),
            POST.to_uppercase(),
        ] {
            let r = req(hint("u1", Some("s1"), &["rp"]), None, Some(&uri), None);
            assert_eq!(
                decide(&r, Some(&session())),
                EndSessionDecision::Error(LogoutError::RedirectUriNotRegistered),
                "{uri}"
            );
            let r = req(HintCheck::Absent, Some("rp"), Some(&uri), None);
            assert_eq!(
                decide(&r, Some(&session())),
                EndSessionDecision::Error(LogoutError::RedirectUriNotRegistered),
                "{uri}"
            );
        }
    }

    #[test]
    fn uri_registered_for_another_client_is_rejected() {
        let r = req(
            hint("u1", Some("s1"), &["rp"]),
            None,
            Some("https://other.example.test/bye"),
            None,
        );
        assert_eq!(
            decide(&r, Some(&session())),
            EndSessionDecision::Error(LogoutError::RedirectUriNotRegistered)
        );
    }

    #[test]
    fn uri_without_hint_or_client_id_requires_hint() {
        for sess in [None, Some(session())] {
            let r = req(HintCheck::Absent, None, Some(POST), Some("x"));
            assert_eq!(
                decide(&r, sess.as_ref()),
                EndSessionDecision::Error(LogoutError::IdTokenHintRequired)
            );
        }
    }

    #[test]
    fn client_id_with_registered_uri_without_hint_confirms_with_redirect() {
        let r = req(HintCheck::Absent, Some("rp"), Some(POST), Some("x"));
        assert_eq!(
            decide(&r, Some(&session())),
            EndSessionDecision::Confirm {
                client_id: Some("rp".to_owned()),
                redirect: redirect(POST, Some("x"))
            }
        );
    }

    #[test]
    fn client_id_alone_confirms_without_redirect() {
        let r = req(HintCheck::Absent, Some("rp"), None, None);
        assert_eq!(
            decide(&r, Some(&session())),
            EndSessionDecision::Confirm {
                client_id: Some("rp".to_owned()),
                redirect: None
            }
        );
    }

    #[test]
    fn unknown_client_id_without_hint_is_rejected() {
        let r = req(HintCheck::Absent, Some("ghost"), None, None);
        assert_eq!(
            decide(&r, Some(&session())),
            EndSessionDecision::Error(LogoutError::UnknownClient)
        );
        let r = req(HintCheck::Absent, Some("ghost"), Some(POST), None);
        assert_eq!(
            decide(&r, Some(&session())),
            EndSessionDecision::Error(LogoutError::UnknownClient)
        );
    }

    #[test]
    fn no_params_and_only_state_confirm_without_redirect() {
        for state in [None, Some("only")] {
            for sess in [None, Some(session())] {
                let r = req(HintCheck::Absent, None, None, state);
                assert_eq!(
                    decide(&r, sess.as_ref()),
                    EndSessionDecision::Confirm {
                        client_id: None,
                        redirect: None
                    }
                );
            }
        }
    }

    #[test]
    fn error_keys_are_stable() {
        assert_eq!(
            LogoutError::InvalidIdTokenHint.key(),
            "logout.invalid_id_token_hint"
        );
        assert_eq!(
            LogoutError::RedirectUriNotRegistered.key(),
            "logout.redirect_uri_not_registered"
        );
        assert_eq!(
            LogoutError::IdTokenHintRequired.key(),
            "logout.id_token_hint_required"
        );
    }

    fn decision_redirect(d: &EndSessionDecision) -> Option<&PostLogoutRedirect> {
        match d {
            EndSessionDecision::LogoutNow { redirect }
            | EndSessionDecision::Confirm { redirect, .. } => redirect.as_ref(),
            EndSessionDecision::Error(_) => None,
        }
    }

    fn arb_hint() -> impl Strategy<Value = HintCheck> {
        prop_oneof![
            Just(HintCheck::Absent),
            Just(HintCheck::Invalid),
            (
                prop_oneof![Just("u1"), Just("u2")],
                proptest::option::of(prop_oneof![Just("s1"), Just("s2")]),
                proptest::collection::vec(prop_oneof![Just("rp"), Just("other"), Just("x")], 0..3),
            )
                .prop_map(|(sub, sid, aud)| hint(sub, sid, &aud)),
        ]
    }

    fn arb_uri() -> impl Strategy<Value = String> {
        prop_oneof![
            Just(POST.to_owned()),
            Just(POST_Q.to_owned()),
            Just("https://other.example.test/bye".to_owned()),
            "[a-z]{1,8}".prop_map(|s| format!("{POST}?{s}=1")),
            "[a-z]{1,8}".prop_map(|s| format!("{POST}{s}")),
            "https?://[a-z.]{1,20}/[a-z/?=&#]{0,20}",
            ".{0,40}",
        ]
    }

    proptest! {
        #[test]
        fn never_redirects_to_an_unregistered_uri(
            h in arb_hint(),
            client_id in proptest::option::of(prop_oneof![Just("rp"), Just("other"), Just("ghost")]),
            uri in proptest::option::of(arb_uri()),
            state in proptest::option::of(".{0,20}"),
            with_session in any::<bool>(),
        ) {
            let c = rp();
            let o = other();
            let pick = |id: &str| match id {
                "rp" => Some(&c),
                "other" => Some(&o),
                _ => None,
            };
            let hint_client = match &h {
                HintCheck::Valid { aud, .. } => aud.first().and_then(|a| pick(a)),
                _ => None,
            };
            let by_id = client_id.and_then(pick);
            let r = req(h.clone(), client_id, uri.as_deref(), state.as_deref());
            let sess = session();
            let d = validate_end_session(&r, hint_client, by_id, with_session.then_some(&sess));
            if let Some(red) = decision_redirect(&d) {
                // The redirect is exactly the requested URI, registered for the effective client.
                prop_assert_eq!(Some(&red.uri), uri.as_ref());
                let effective = match &h {
                    HintCheck::Valid { .. } => hint_client,
                    _ => by_id,
                };
                let effective = effective.expect("a redirect needs a client");
                prop_assert!(effective.post_logout_redirect_uris.contains(&red.uri));
                prop_assert_eq!(red.state.as_deref(), state.as_deref());
            }
            if h == HintCheck::Invalid {
                prop_assert_eq!(d, EndSessionDecision::Error(LogoutError::InvalidIdTokenHint));
            } else if matches!(d, EndSessionDecision::LogoutNow { .. }) {
                // Logging out without confirmation needs a valid hint.
                let valid = matches!(h, HintCheck::Valid { .. });
                prop_assert!(valid, "LogoutNow without a valid hint");
            }
        }
    }

    // --- post-logout redirect building ---

    #[test]
    fn redirect_without_state_is_the_registered_uri() {
        assert_eq!(build_post_logout_redirect(POST, None), POST);
        assert_eq!(build_post_logout_redirect(POST_Q, None), POST_Q);
    }

    #[test]
    fn redirect_appends_only_state() {
        assert_eq!(
            build_post_logout_redirect(POST, Some("abc")),
            format!("{POST}?state=abc")
        );
        assert_eq!(
            build_post_logout_redirect(POST_Q, Some("abc")),
            format!("{POST_Q}&state=abc")
        );
    }

    #[test]
    fn redirect_encodes_state() {
        let url = build_post_logout_redirect(POST, Some("a b;c~d&e=f+g"));
        let parsed = url::Url::parse(&url).unwrap();
        let pairs: Vec<(String, String)> = parsed.query_pairs().into_owned().collect();
        assert_eq!(
            pairs,
            vec![("state".to_owned(), "a b;c~d&e=f+g".to_owned())]
        );
    }

    #[test]
    fn redirect_keeps_the_registered_query_verbatim() {
        let url = build_post_logout_redirect(POST_Q, Some("s"));
        let parsed = url::Url::parse(&url).unwrap();
        let pairs: Vec<(String, String)> = parsed.query_pairs().into_owned().collect();
        assert_eq!(
            pairs,
            vec![
                ("tenant".to_owned(), "a".to_owned()),
                ("state".to_owned(), "s".to_owned())
            ]
        );
    }

    #[test]
    fn post_logout_redirect_to_url_uses_builder() {
        let r = PostLogoutRedirect {
            uri: POST.to_owned(),
            state: Some("q".to_owned()),
        };
        assert_eq!(r.to_url(), format!("{POST}?state=q"));
    }

    // --- logout token ---

    #[test]
    fn logout_token_has_exactly_the_required_claims() {
        let now = datetime!(2026-11-25 12:00 UTC);
        let claims = logout_token_claims("https://id.example.test/t", "rp", "u1", "s1", "j1", now);
        let keys: BTreeSet<&str> = claims.keys().map(String::as_str).collect();
        let expected: BTreeSet<&str> = ["iss", "aud", "iat", "exp", "jti", "sub", "sid", "events"]
            .into_iter()
            .collect();
        assert_eq!(keys, expected);
        assert!(!claims.contains_key("nonce"));
        assert_eq!(claims["iss"], "https://id.example.test/t");
        assert_eq!(claims["aud"], "rp");
        assert_eq!(claims["sub"], "u1");
        assert_eq!(claims["sid"], "s1");
        assert_eq!(claims["jti"], "j1");
        let iat = now.unix_timestamp();
        assert_eq!(claims["iat"], iat);
        assert_eq!(claims["exp"], iat + 120);
        assert_eq!(
            claims["events"],
            serde_json::json!({ "http://schemas.openid.net/event/backchannel-logout": {} })
        );
    }

    // --- delivery classification ---

    fn t0() -> OffsetDateTime {
        datetime!(2026-11-25 12:00 UTC)
    }

    #[test]
    fn success_statuses_are_delivered() {
        for s in [200, 204] {
            assert_eq!(
                classify_delivery(DeliveryOutcome::Status(s), 0, t0(), t0()),
                DeliveryResult::Delivered
            );
        }
    }

    #[test]
    fn client_errors_and_unexpected_statuses_give_up() {
        for s in [400, 401, 403, 404, 410, 429, 201, 202, 301, 302, 100] {
            assert!(
                matches!(
                    classify_delivery(DeliveryOutcome::Status(s), 0, t0(), t0()),
                    DeliveryResult::GiveUp { .. }
                ),
                "{s}"
            );
        }
    }

    #[test]
    fn blocked_destination_gives_up() {
        assert!(matches!(
            classify_delivery(DeliveryOutcome::Blocked, 0, t0(), t0()),
            DeliveryResult::GiveUp { .. }
        ));
    }

    #[test]
    fn transient_failures_retry_with_backoff() {
        let now = t0() + time::Duration::minutes(5);
        for outcome in [
            DeliveryOutcome::Status(500),
            DeliveryOutcome::Status(502),
            DeliveryOutcome::Status(503),
            DeliveryOutcome::Status(599),
            DeliveryOutcome::Network,
            DeliveryOutcome::Timeout,
        ] {
            match classify_delivery(outcome, 2, t0(), now) {
                DeliveryResult::Retry {
                    next_attempt_at,
                    error,
                } => {
                    assert_eq!(next_attempt_at, now + time::Duration::seconds(40));
                    assert!(!error.is_empty());
                }
                other => panic!("{outcome:?}: {other:?}"),
            }
        }
    }

    #[test]
    fn transient_failures_give_up_after_ttl() {
        for now in [
            t0() + LOGOUT_DELIVERY_TTL,
            t0() + LOGOUT_DELIVERY_TTL + time::Duration::hours(1),
        ] {
            for outcome in [
                DeliveryOutcome::Status(503),
                DeliveryOutcome::Network,
                DeliveryOutcome::Timeout,
            ] {
                assert!(matches!(
                    classify_delivery(outcome, 30, t0(), now),
                    DeliveryResult::GiveUp { .. }
                ));
            }
        }
        // One second before the deadline still retries.
        let now = t0() + LOGOUT_DELIVERY_TTL - time::Duration::seconds(1);
        assert!(matches!(
            classify_delivery(DeliveryOutcome::Network, 30, t0(), now),
            DeliveryResult::Retry { .. }
        ));
    }

    #[test]
    fn backoff_doubles_and_caps_at_one_hour() {
        let expected = [10, 20, 40, 80, 160, 320, 640, 1280, 2560, 3600, 3600];
        for (n, secs) in expected.iter().enumerate() {
            let n = u32::try_from(n).unwrap();
            assert_eq!(
                next_attempt(n, t0()),
                t0() + time::Duration::seconds(*secs),
                "{n}"
            );
        }
        for n in [20, 31, 32, 64, 1000, u32::MAX] {
            assert_eq!(next_attempt(n, t0()), t0() + DELIVERY_MAX_DELAY, "{n}");
        }
    }

    proptest! {
        #[test]
        fn backoff_is_bounded_and_monotonic(n in 0u32..200) {
            let a = next_attempt(n, t0());
            let b = next_attempt(n + 1, t0());
            prop_assert!(a > t0());
            prop_assert!(a <= t0() + DELIVERY_MAX_DELAY);
            prop_assert!(b >= a);
        }
    }
}
