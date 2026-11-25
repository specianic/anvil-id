//! Email one-time code and magic-link sign-in (AUTH-06): a login-flow method.
//!
//! # Steps
//!
//! From the identify step the user asks for a sign-in email ([`request`]). The login moves to
//! [`LoginStep::EmailCode`] holding an [`EmailCodeState`] and the page always says "if an account
//! exists for that address, we sent a code" (no account enumeration). Only an active user with a
//! verified address gets the `login_code` email (a 6-digit code and a magic link,
//! [`EMAIL_CODE_TTL`]); an unknown, inactive or unverified address (which may not belong to the
//! account holder) gets the same state, the same work (a code and a link token are generated and hashed)
//! and the same page, but no email.
//!
//! # Code, link or both
//!
//! The tenant settings `email_otp` (the 6-digit code) and `magic_link` (the link) are independent.
//! The service always does the same work (a code, a link token and both hashes, for every
//! configuration and every address) but the email carries only the enabled methods, and the state
//! records which ones it carried ([`EmailCodeState::code`], [`EmailCodeState::link`]). A method the
//! email did not carry is refused here ([`check_code`], [`check_link`]) as well as by the service
//! and the routes (which also refuse a method switched off after the send). With the link only,
//! the "check your email" form has no `code` field ([`form_for`]).
//!
//! The code ([`verify`]) or the link ([`link`]) is then the primary authentication: single factor
//! (`amr` `[otp]`, pwd `acr`, never `mfa`), followed by the effective MFA policy like a password
//! (`flow::login::after_primary_auth`).
//!
//! # At rest
//!
//! The flow state holds only hashes: the code as `anvil_jose::email_code::email_code_hash` (HMAC
//! under the KEK-derived `anvilid/email-otp/v1` pepper, bound to the flow id) and the link token as
//! SHA-256 ([`anvil_jose::encoding::secret_hash`]). Both are cleared together when either is
//! accepted ([`check_code`], [`check_link`]; the service stores the result with a compare-and-swap,
//! so a code or link works once), and both are invalidated after [`MAX_FAILED_ATTEMPTS`] wrong
//! codes. A flow sends at most [`MAX_SENDS`] emails.
//!
//! # Magic link
//!
//! The emailed link `GET /ui/login/email-link?flow=&token=` only renders a "Continue signing in"
//! button (link scanners consume nothing). The button POSTs the token with the flow cookie and a
//! CSRF token derived from the flow id and the link token ([`link_csrf`]): the flow stores only the
//! hash of its form CSRF token, which the link page cannot show. A POST without the flow cookie
//! (another browser) consumes nothing.

use anvil_jose::Kek;
use anvil_jose::email_code::{email_code_hash, normalize_email_code};
use anvil_jose::encoding::{b64url, ct_eq, secret_hash};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use super::engine::{Effect, FlowEnv, FlowState, SessionAuth, error, field, form as build_form};
use super::form::{FieldKind, FormDescription, FormMessage, MessageLevel};
use super::login::{LoginState, LoginStep};
use crate::model::{FlowId, TenantId, UserId, normalize_email};

/// Id of the "check your email" form (the code field).
pub const EMAIL_CODE_FORM_ID: &str = "email-code";
/// Page path (below the UI base) the code form posts to.
pub const VERIFY_ACTION: &str = "login/email-code/verify";
/// How long a code and its link are valid.
pub const EMAIL_CODE_TTL: Duration = Duration::minutes(10);
/// Emails a login flow may send.
pub const MAX_SENDS: u8 = 3;
/// Wrong codes before the code and the link are invalidated.
pub const MAX_FAILED_ATTEMPTS: u8 = 5;
/// HKDF info of the key deriving the magic-link page's CSRF token.
pub const LINK_CSRF_INFO: &str = "anvilid/email-link-csrf/v1";
/// HKDF info of the key deriving the rate-limit subject of an address without an account.
pub const SUBJECT_INFO: &str = "anvilid/email-code-subject/v1";

/// Message keys.
pub const SENT: &str = "email_code.sent";
pub const WRONG: &str = "email_code.invalid";
pub const EXPIRED: &str = "email_code.expired";
pub const INVALIDATED: &str = "email_code.invalidated";
pub const TOO_MANY_SENDS: &str = "email_code.too_many_sends";
pub const LINK_INVALID: &str = "email_code.link_invalid";
pub const OTHER_BROWSER: &str = "email_code.other_browser";

/// A sent (or, for an unknown address, pretended) sign-in code. Holds no secret: hashes only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailCodeState {
    /// The normalised address the code was requested for.
    pub email: String,
    /// The active user with this verified address; `None` for an unknown, inactive or unverified
    /// address (same page, no email).
    #[serde(default)]
    pub user_id: Option<UserId>,
    /// `email_code_hash(kek, flow id, code)`; `None` once used or invalidated.
    #[serde(default)]
    pub code_hash: Option<[u8; 32]>,
    /// SHA-256 of the magic-link token; `None` once used or invalidated.
    #[serde(default)]
    pub link_hash: Option<[u8; 32]>,
    /// Unix seconds.
    pub sent_at: i64,
    /// Unix seconds.
    pub expires_at: i64,
    /// Emails sent in this flow (including this one).
    pub sends: u8,
    /// Wrong codes against the current code.
    #[serde(default)]
    pub failed_attempts: u8,
    /// Whether the email carried the code (tenant `email_otp` at send time). A state stored
    /// before this field existed carried both.
    #[serde(default = "carried")]
    pub code: bool,
    /// Whether the email carried the magic link (tenant `magic_link` at send time).
    #[serde(default = "carried")]
    pub link: bool,
}

fn carried() -> bool {
    true
}

impl EmailCodeState {
    /// The state of a new code for `email` sent at `now`, following `previous` (whose send count
    /// it continues). The failed-attempt count starts over with the new code.
    pub fn issue(
        previous: Option<&EmailCodeState>,
        email: &str,
        user_id: Option<UserId>,
        code_hash: [u8; 32],
        link_hash: [u8; 32],
        now: OffsetDateTime,
    ) -> Self {
        Self {
            email: email.to_owned(),
            user_id,
            code_hash: Some(code_hash),
            link_hash: Some(link_hash),
            sent_at: now.unix_timestamp(),
            expires_at: (now + EMAIL_CODE_TTL).unix_timestamp(),
            sends: previous.map_or(0, |p| p.sends).saturating_add(1),
            failed_attempts: 0,
            code: true,
            link: true,
        }
    }

    /// The same state recording which methods the email carries (`code`: the 6-digit code,
    /// `link`: the magic link).
    #[must_use]
    pub fn with_methods(self, code: bool, link: bool) -> Self {
        Self { code, link, ..self }
    }

    fn expired(&self, now: OffsetDateTime) -> bool {
        now.unix_timestamp() >= self.expires_at
    }

    fn consumed(&self) -> Self {
        Self {
            code_hash: None,
            link_hash: None,
            ..self.clone()
        }
    }
}

/// Result of checking a code or a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    /// Accepted: store the returned state (hashes cleared) with a compare-and-swap, then sign in.
    Accepted,
    /// Wrong code: store the returned state (one more failed attempt; at the cap the hashes are
    /// cleared and `invalidated` is set).
    Wrong { invalidated: bool },
    /// The code expired: nothing changes.
    Expired,
    /// Used, invalidated, or never issued: nothing changes.
    Unavailable,
}

/// Checks a presented code hash (`None`: input that cannot be a code, a wrong attempt). Returns the
/// verdict and the state to store. A code the email did not carry is [`Check::Unavailable`] and
/// counts no attempt.
pub fn check_code(
    state: &EmailCodeState,
    presented: Option<[u8; 32]>,
    now: OffsetDateTime,
) -> (Check, EmailCodeState) {
    let (true, Some(stored)) = (state.code, state.code_hash) else {
        return (Check::Unavailable, state.clone());
    };
    if state.expired(now) {
        return (Check::Expired, state.clone());
    }
    let matches = presented.is_some_and(|p| ct_eq(&p, &stored));
    if matches {
        return (Check::Accepted, state.consumed());
    }
    let mut next = state.clone();
    next.failed_attempts = next.failed_attempts.saturating_add(1);
    let invalidated = next.failed_attempts >= MAX_FAILED_ATTEMPTS;
    if invalidated {
        next = next.consumed();
    }
    (Check::Wrong { invalidated }, next)
}

/// Checks the SHA-256 of a presented link token. A wrong token changes nothing (it is 256 bits:
/// no attempt counting) and reports [`Check::Unavailable`]; so does any token when the email did
/// not carry the link.
pub fn check_link(
    state: &EmailCodeState,
    presented: [u8; 32],
    now: OffsetDateTime,
) -> (Check, EmailCodeState) {
    let (true, Some(stored)) = (state.link, state.link_hash) else {
        return (Check::Unavailable, state.clone());
    };
    if !ct_eq(&presented, &stored) {
        return (Check::Unavailable, state.clone());
    }
    if state.expired(now) {
        return (Check::Expired, state.clone());
    }
    (Check::Accepted, state.consumed())
}

/// The stored hash of a code as typed by the user: `None` if it cannot be a code. A malformed
/// input still costs one HMAC, so every attempt does the same work.
pub fn code_hash(kek: &Kek, flow: FlowId, input: &str) -> Option<[u8; 32]> {
    let flow = flow.to_string();
    match normalize_email_code(input) {
        Some(code) => Some(email_code_hash(kek, &flow, &code)),
        None => {
            let _ = email_code_hash(kek, &flow, "000000");
            None
        }
    }
}

/// SHA-256 of a magic-link token.
pub fn link_hash(token: &str) -> [u8; 32] {
    secret_hash(token)
}

/// A KEK-keyed PRF over `parts` (HKDF-SHA256 expand with the parts in the info string, each
/// length-prefixed so the encoding is unambiguous).
fn prf(kek: &Kek, info: &str, parts: &[&str]) -> [u8; 32] {
    let mut label = info.to_owned();
    for p in parts {
        label.push_str(&format!("|{}:{p}", p.len()));
    }
    *kek.derive_key(&label)
}

/// The CSRF token of the magic-link page of `flow` for `token` (base64url HMAC under a KEK-derived
/// key). Only someone holding the emailed token can produce it; the POST also needs the flow
/// cookie.
pub fn link_csrf(kek: &Kek, flow: FlowId, token: &str) -> String {
    b64url(&prf(kek, LINK_CSRF_INFO, &[&flow.to_string(), token]))
}

/// The rate-limit subject of a code: the user, or for an address without an active account a
/// stable pseudo user id derived from the tenant and the address (keyed with the KEK), so verify
/// attempts are throttled the same way either way.
pub fn limit_subject(kek: &Kek, tenant: TenantId, email: &str, user: Option<UserId>) -> UserId {
    if let Some(u) = user {
        return u;
    }
    let h = prf(kek, SUBJECT_INFO, &[&tenant.to_string(), email]);
    let mut b = [0u8; 16];
    b.copy_from_slice(&h[..16]);
    UserId(uuid::Uuid::from_bytes(b))
}

/// Whether the method can be used in this login state: the identify step (or the email step for a
/// new code), not a step-up, not while an upstream identity waits for link confirmation.
fn available(state: &LoginState) -> bool {
    matches!(state.step, LoginStep::Identify | LoginStep::EmailCode)
        && state.step_up_session.is_none()
        && state.pending_link.is_none()
}

/// A sign-in email is requested for `email` (`None`: a new code to the address of the current
/// code). Plans [`Effect::SendEmailCode`]; the service generates, hashes and stores the code and
/// sends the email only to an active user.
pub(super) fn request(
    mut state: LoginState,
    email: Option<String>,
    env: &FlowEnv,
) -> (FlowState, Vec<Effect>) {
    if !env.email_code || !available(&state) {
        return super::login::invalid_input(state);
    }
    let email = match email {
        Some(raw) => {
            let raw = raw.trim().to_owned();
            match normalize_email(&raw) {
                Ok(e) => {
                    state.identifier = Some(raw);
                    e
                }
                Err(_) => {
                    let f = super::login::current_form(&state, vec![error("email.invalid")]);
                    return (FlowState::Login(state), vec![Effect::Render(f)]);
                }
            }
        }
        None => match &state.email_code {
            Some(ec) if state.step == LoginStep::EmailCode => ec.email.clone(),
            _ => return super::login::invalid_input(state),
        },
    };
    if let Some(ec) = state.email_code.as_deref()
        && ec.sends >= MAX_SENDS
    {
        let f = form_for(Some(ec), vec![error(TOO_MANY_SENDS)]);
        return (FlowState::Login(state), vec![Effect::Render(f)]);
    }
    (
        FlowState::Login(state),
        vec![Effect::SendEmailCode { email }],
    )
}

/// A code was typed: verify it, apply the MFA policy, sign in with `[otp]`.
pub(super) fn verify(state: LoginState, code: String) -> (FlowState, Vec<Effect>) {
    if state.step != LoginStep::EmailCode || state.email_code.is_none() {
        return super::login::invalid_input(state);
    }
    let effects = vec![
        Effect::VerifyEmailCode {
            code: super::engine::secret(code),
        },
        Effect::CheckSecondFactor,
        Effect::CreateSession(SessionAuth::EmailCode),
    ];
    (FlowState::Login(state), effects)
}

/// The magic link was posted: consume it, apply the MFA policy, sign in with `[otp]`.
pub(super) fn link(state: LoginState, token: String) -> (FlowState, Vec<Effect>) {
    if state.step != LoginStep::EmailCode || state.email_code.is_none() || token.is_empty() {
        return super::login::invalid_input(state);
    }
    let effects = vec![
        Effect::ConsumeEmailLink {
            token: super::engine::secret(token),
        },
        Effect::CheckSecondFactor,
        Effect::CreateSession(SessionAuth::EmailCode),
    ];
    (FlowState::Login(state), effects)
}

/// The "check your email" form with the `code` field (themes render it with
/// `autocomplete=one-time-code` and `inputmode=numeric`).
pub fn form(messages: Vec<FormMessage>) -> FormDescription {
    form_for(None, messages)
}

/// The "check your email" form for the email described by `ec`: the `code` field only when the
/// email carried the code (`None`: the code field, as for a state without the method flags).
/// Without it the page only explains that the email holds a sign-in link (and offers a new
/// email).
pub fn form_for(ec: Option<&EmailCodeState>, messages: Vec<FormMessage>) -> FormDescription {
    let fields = if ec.is_none_or(|ec| ec.code) {
        vec![field(
            "code",
            FieldKind::Text,
            "field.code",
            None,
            true,
            Some("one-time-code"),
            Vec::new(),
        )]
    } else {
        Vec::new()
    };
    build_form(EMAIL_CODE_FORM_ID, VERIFY_ACTION, fields, messages)
}

/// The form after an email was requested for `ec`: the enumeration-safe "if an account exists"
/// message.
pub fn sent_form(ec: &EmailCodeState) -> FormDescription {
    form_for(Some(ec), vec![FormMessage::new(MessageLevel::Info, SENT)])
}

/// The key of the form answering a check that did not sign in.
pub fn failure_key(check: Check) -> &'static str {
    match check {
        Check::Wrong { invalidated: true } | Check::Unavailable => INVALIDATED,
        Check::Wrong { invalidated: false } => WRONG,
        Check::Expired => EXPIRED,
        Check::Accepted => WRONG,
    }
}

#[cfg(test)]
mod tests {
    use super::super::engine::test_support::*;
    use super::super::engine::{FlowInput, current_form, transition};
    use super::*;

    fn kek() -> Kek {
        Kek::generate()
    }

    fn env() -> FlowEnv {
        FlowEnv {
            email_code: true,
            ..FlowEnv::default()
        }
    }

    fn t0() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_795_608_000).unwrap()
    }

    fn issued(k: &Kek, flow: FlowId, code: &str, token: &str) -> EmailCodeState {
        EmailCodeState::issue(
            None,
            "alice@example.com",
            Some(UserId::new_v7()),
            code_hash(k, flow, code).unwrap(),
            link_hash(token),
            t0(),
        )
    }

    fn email_state(ec: EmailCodeState) -> LoginState {
        LoginState {
            step: LoginStep::EmailCode,
            email_code: Some(Box::new(ec)),
            ..LoginState::default()
        }
    }

    #[test]
    fn request_from_identify_plans_one_send_for_the_normalised_address() {
        let (state, effects) = transition(
            FlowState::Login(LoginState::default()),
            FlowInput::EmailCodeRequest {
                email: Some("  Alice@Example.com ".into()),
            },
            &env(),
        );
        assert_eq!(effects.len(), 1);
        assert!(
            matches!(&effects[0], Effect::SendEmailCode { email } if email == "alice@example.com")
        );
        let FlowState::Login(s) = state else { panic!() };
        assert_eq!(s.identifier.as_deref(), Some("Alice@Example.com"));
    }

    #[test]
    fn request_is_refused_when_disabled_or_in_another_step() {
        let input = || FlowInput::EmailCodeRequest {
            email: Some("a@example.com".into()),
        };
        // Disabled tenant.
        let (_, effects) = transition(
            FlowState::Login(LoginState::default()),
            input(),
            &FlowEnv::default(),
        );
        assert!(
            matches!(&effects[..], [Effect::Render(f)] if all_keys(f) == ["flow.invalid_input"])
        );
        // Step-up and link confirmation flows.
        for s in [
            LoginState {
                step_up_session: Some(crate::model::SessionId::new_v7()),
                ..LoginState::default()
            },
            LoginState {
                step: LoginStep::SecondFactor {
                    user_id: UserId::new_v7(),
                    methods: Default::default(),
                },
                ..LoginState::default()
            },
        ] {
            let (_, effects) = transition(FlowState::Login(s), input(), &env());
            assert!(
                matches!(&effects[..], [Effect::Render(f)] if all_keys(f) == ["flow.invalid_input"])
            );
        }
        // A malformed address renders an error, no effect.
        let (_, effects) = transition(
            FlowState::Login(LoginState::default()),
            FlowInput::EmailCodeRequest {
                email: Some("nope".into()),
            },
            &env(),
        );
        assert!(matches!(&effects[..], [Effect::Render(f)] if all_keys(f) == ["email.invalid"]));
        // A resend without a current code is invalid input.
        let (_, effects) = transition(
            FlowState::Login(LoginState::default()),
            FlowInput::EmailCodeRequest { email: None },
            &env(),
        );
        assert!(
            matches!(&effects[..], [Effect::Render(f)] if all_keys(f) == ["flow.invalid_input"])
        );
    }

    #[test]
    fn resend_uses_the_stored_address_and_stops_after_three_sends() {
        let k = kek();
        let flow = FlowId::new_v7();
        let mut ec = issued(&k, flow, "123456", "tok");
        let (_, effects) = transition(
            FlowState::Login(email_state(ec.clone())),
            FlowInput::EmailCodeRequest { email: None },
            &env(),
        );
        assert!(
            matches!(&effects[..], [Effect::SendEmailCode { email }] if email == "alice@example.com")
        );
        let second =
            EmailCodeState::issue(Some(&ec), &ec.email, ec.user_id, [1; 32], [2; 32], t0());
        assert_eq!(second.sends, 2);
        ec.sends = MAX_SENDS;
        let (_, effects) = transition(
            FlowState::Login(email_state(ec)),
            FlowInput::EmailCodeRequest { email: None },
            &env(),
        );
        let [Effect::Render(f)] = &effects[..] else {
            panic!("{effects:?}")
        };
        assert_eq!(f.id, EMAIL_CODE_FORM_ID);
        assert_eq!(all_keys(f), vec![TOO_MANY_SENDS]);
        assert_form_invariants(f, &[]);
    }

    #[test]
    fn verify_and_link_plan_primary_then_policy_then_otp_session() {
        let k = kek();
        let s = email_state(issued(&k, FlowId::new_v7(), "123456", "tok"));
        let (_, effects) = transition(
            FlowState::Login(s.clone()),
            FlowInput::EmailCode {
                code: "123456".into(),
            },
            &env(),
        );
        assert!(matches!(
            &effects[..],
            [
                Effect::VerifyEmailCode { .. },
                Effect::CheckSecondFactor,
                Effect::CreateSession(SessionAuth::EmailCode)
            ]
        ));
        let (_, effects) = transition(
            FlowState::Login(s),
            FlowInput::EmailLink {
                token: "tok".into(),
            },
            &env(),
        );
        assert!(matches!(
            &effects[..],
            [
                Effect::ConsumeEmailLink { .. },
                Effect::CheckSecondFactor,
                Effect::CreateSession(SessionAuth::EmailCode)
            ]
        ));
        // Not in the email step: invalid input.
        let (_, effects) = transition(
            FlowState::Login(LoginState::default()),
            FlowInput::EmailCode {
                code: "123456".into(),
            },
            &env(),
        );
        assert!(matches!(&effects[..], [Effect::Render(f)] if f.id == "login"));
    }

    #[test]
    fn right_code_is_accepted_once_and_clears_code_and_link() {
        let k = kek();
        let flow = FlowId::new_v7();
        let ec = issued(&k, flow, "123456", "tok");
        let (check, next) = check_code(&ec, code_hash(&k, flow, "123 456"), t0());
        assert_eq!(check, Check::Accepted);
        assert!(next.code_hash.is_none() && next.link_hash.is_none());
        // Single use: the stored result no longer accepts the code nor the link.
        let (again, _) = check_code(&next, code_hash(&k, flow, "123456"), t0());
        assert_eq!(again, Check::Unavailable);
        let (link, _) = check_link(&next, link_hash("tok"), t0());
        assert_eq!(link, Check::Unavailable);
    }

    #[test]
    fn code_is_bound_to_its_flow_and_kek() {
        let k = kek();
        let flow = FlowId::new_v7();
        let ec = issued(&k, flow, "123456", "tok");
        let (c, _) = check_code(&ec, code_hash(&k, FlowId::new_v7(), "123456"), t0());
        assert!(matches!(c, Check::Wrong { .. }));
        let (c, _) = check_code(&ec, code_hash(&kek(), flow, "123456"), t0());
        assert!(matches!(c, Check::Wrong { .. }));
    }

    #[test]
    fn five_wrong_codes_invalidate_code_and_link() {
        let k = kek();
        let flow = FlowId::new_v7();
        let mut ec = issued(&k, flow, "123456", "tok");
        for i in 1..=MAX_FAILED_ATTEMPTS {
            let (c, next) = check_code(&ec, code_hash(&k, flow, "654321"), t0());
            assert_eq!(
                c,
                Check::Wrong {
                    invalidated: i == MAX_FAILED_ATTEMPTS
                }
            );
            assert_eq!(next.failed_attempts, i);
            ec = next;
        }
        assert!(ec.code_hash.is_none() && ec.link_hash.is_none());
        let (c, _) = check_code(&ec, code_hash(&k, flow, "123456"), t0());
        assert_eq!(c, Check::Unavailable);
        assert_eq!(failure_key(c), INVALIDATED);
        // Malformed input counts as a wrong attempt.
        let fresh = issued(&k, flow, "123456", "tok");
        let (c, next) = check_code(&fresh, code_hash(&k, flow, "12345x"), t0());
        assert_eq!(c, Check::Wrong { invalidated: false });
        assert_eq!(next.failed_attempts, 1);
    }

    #[test]
    fn expired_code_and_link_are_refused_without_change() {
        let k = kek();
        let flow = FlowId::new_v7();
        let ec = issued(&k, flow, "123456", "tok");
        let late = t0() + EMAIL_CODE_TTL;
        let (c, next) = check_code(&ec, code_hash(&k, flow, "123456"), late);
        assert_eq!((c, &next), (Check::Expired, &ec));
        let (c, next) = check_link(&ec, link_hash("tok"), late);
        assert_eq!((c, &next), (Check::Expired, &ec));
        let (c, _) = check_code(
            &ec,
            code_hash(&k, flow, "123456"),
            late - Duration::seconds(1),
        );
        assert_eq!(c, Check::Accepted);
    }

    #[test]
    fn wrong_link_changes_nothing_right_link_works_once() {
        let k = kek();
        let ec = issued(&k, FlowId::new_v7(), "123456", "tok");
        let (c, next) = check_link(&ec, link_hash("other"), t0());
        assert_eq!((c, &next), (Check::Unavailable, &ec));
        let (c, next) = check_link(&ec, link_hash("tok"), t0());
        assert_eq!(c, Check::Accepted);
        assert_eq!(
            check_link(&next, link_hash("tok"), t0()).0,
            Check::Unavailable
        );
    }

    #[test]
    fn state_json_holds_no_code_or_token() {
        let k = kek();
        let flow = FlowId::new_v7();
        let s = FlowState::Login(email_state(issued(&k, flow, "123456", "the-link-token")));
        let json = serde_json::to_string(&s).unwrap();
        assert!(!json.contains("the-link-token"));
        let runs: Vec<&str> = json
            .split(|c: char| !c.is_ascii_digit())
            .filter(|r| !r.is_empty())
            .collect();
        assert!(!runs.contains(&"123456"), "{json}");
        assert_eq!(serde_json::from_str::<FlowState>(&json).unwrap(), s);
        // Release 0.3 flow JSON without email fields still decodes.
        let old: LoginState = serde_json::from_str(r#"{"identifier":null}"#).unwrap();
        assert!(old.email_code.is_none() && !old.email_primary);
    }

    #[test]
    fn link_csrf_and_subject_are_keyed_and_bound() {
        let k = kek();
        let flow = FlowId::new_v7();
        let a = link_csrf(&k, flow, "tok");
        assert_eq!(a, link_csrf(&k, flow, "tok"));
        assert_ne!(a, link_csrf(&k, flow, "tok2"));
        assert_ne!(a, link_csrf(&k, FlowId::new_v7(), "tok"));
        assert_ne!(a, link_csrf(&kek(), flow, "tok"));
        let t = TenantId::new_v7();
        let u = UserId::new_v7();
        assert_eq!(limit_subject(&k, t, "a@b.c", Some(u)), u);
        let p = limit_subject(&k, t, "a@b.c", None);
        assert_eq!(p, limit_subject(&k, t, "a@b.c", None));
        assert_ne!(p, limit_subject(&k, t, "x@b.c", None));
        assert_ne!(p, limit_subject(&k, TenantId::new_v7(), "a@b.c", None));
    }

    #[test]
    fn code_is_refused_when_the_email_carried_none() {
        let k = kek();
        let flow = FlowId::new_v7();
        let ec = issued(&k, flow, "123456", "tok").with_methods(false, true);
        // The right code: refused, nothing changes, no attempt counted.
        let (c, next) = check_code(&ec, code_hash(&k, flow, "123456"), t0());
        assert_eq!((c, &next), (Check::Unavailable, &ec));
        let (c, next) = check_code(&ec, code_hash(&k, flow, "654321"), t0());
        assert_eq!((c, &next), (Check::Unavailable, &ec));
        // The link still works.
        assert_eq!(check_link(&ec, link_hash("tok"), t0()).0, Check::Accepted);
    }

    #[test]
    fn link_is_refused_when_the_email_carried_none() {
        let k = kek();
        let flow = FlowId::new_v7();
        let ec = issued(&k, flow, "123456", "tok").with_methods(true, false);
        let (c, next) = check_link(&ec, link_hash("tok"), t0());
        assert_eq!((c, &next), (Check::Unavailable, &ec));
        // The code still works.
        assert_eq!(
            check_code(&ec, code_hash(&k, flow, "123456"), t0()).0,
            Check::Accepted
        );
    }

    #[test]
    fn state_without_method_flags_parses_as_both() {
        let k = kek();
        let ec = issued(&k, FlowId::new_v7(), "123456", "tok").with_methods(false, true);
        let mut json: serde_json::Value = serde_json::to_value(&ec).unwrap();
        assert_eq!(json["code"], false);
        assert_eq!(json["link"], true);
        let obj = json.as_object_mut().unwrap();
        obj.remove("code");
        obj.remove("link");
        let old: EmailCodeState = serde_json::from_value(json).unwrap();
        assert!(old.code && old.link);
        assert_eq!(old, ec.with_methods(true, true));
    }

    #[test]
    fn link_only_form_has_no_code_field() {
        let k = kek();
        let flow = FlowId::new_v7();
        let link_only = issued(&k, flow, "123456", "t").with_methods(false, true);
        let f = sent_form(&link_only);
        assert_eq!(f.id, EMAIL_CODE_FORM_ID);
        assert!(f.fields.is_empty(), "{f:?}");
        assert_eq!(all_keys(&f), vec![SENT]);
        let s = FlowState::Login(email_state(link_only.clone()));
        assert!(current_form(&s, Vec::new(), &env()).fields.is_empty());
        let code_only = issued(&k, flow, "123456", "t").with_methods(true, false);
        assert_eq!(sent_form(&code_only).fields[0].name, "code");
        // The too-many-sends form follows the state too.
        let capped = EmailCodeState {
            sends: MAX_SENDS,
            ..link_only
        };
        let (_, effects) = transition(
            FlowState::Login(email_state(capped)),
            FlowInput::EmailCodeRequest { email: None },
            &env(),
        );
        assert!(
            matches!(&effects[..], [Effect::Render(f)] if f.fields.is_empty() && all_keys(f) == [TOO_MANY_SENDS])
        );
    }

    #[test]
    fn forms_and_current_form_of_the_email_step() {
        let f = sent_form(&issued(&kek(), FlowId::new_v7(), "123456", "t"));
        assert_eq!(f.id, EMAIL_CODE_FORM_ID);
        assert_eq!(f.action, VERIFY_ACTION);
        assert_eq!(all_keys(&f), vec![SENT]);
        let code = &f.fields[0];
        assert_eq!(code.autocomplete.as_deref(), Some("one-time-code"));
        assert_form_invariants(&f, &[]);
        let k = kek();
        let s = FlowState::Login(email_state(issued(&k, FlowId::new_v7(), "123456", "t")));
        assert_eq!(current_form(&s, Vec::new(), &env()).id, EMAIL_CODE_FORM_ID);
        assert_eq!(failure_key(Check::Expired), EXPIRED);
        assert_eq!(failure_key(Check::Wrong { invalidated: false }), WRONG);
    }
}
