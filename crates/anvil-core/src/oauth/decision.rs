//! Whether an existing browser session can answer an authorization request (OIDC Core §3.1.2.1:
//! `prompt`, `max_age`, `id_token_hint`). Pure.

use time::{Duration, OffsetDateTime};

use crate::error::CoreError;
use crate::model::BrowserSession;

/// Outcome of [`decide`].
#[derive(Debug)]
pub enum SessionDecision {
    /// The session satisfies the request: issue a code.
    UseSession,
    /// The user must sign in (again).
    RequireLogin,
    /// The request cannot be answered without interaction (`prompt=none`): `LoginRequired`.
    Fail(CoreError),
}

/// Decides whether `session` satisfies the request.
///
/// - `prompt=login`: the session is usable only if `auth_time >= request_created_at`, that is, the
///   user signed in during this request. This is what lets `resume` succeed after the forced
///   login.
/// - `max_age`: usable only if `now - auth_time <= max_age`, or if the user signed in during this
///   request (so `max_age=0` behaves like `prompt=login` and cannot loop).
/// - `hint_sub` (the verified `id_token_hint` subject): a different session user is not usable.
/// - Not usable: `Fail(LoginRequired)` with `prompt=none`, else `RequireLogin`.
///
/// `prompt=none` combined with other values is rejected earlier, in validation.
pub fn decide(
    prompt: &[String],
    max_age: Option<i64>,
    session: Option<&BrowserSession>,
    hint_sub: Option<&str>,
    request_created_at: OffsetDateTime,
    now: OffsetDateTime,
) -> SessionDecision {
    let none = prompt.iter().any(|p| p == "none");
    let login = prompt.iter().any(|p| p == "login");
    let usable = session.is_some_and(|s| {
        let fresh = s.auth_time >= request_created_at;
        let hint_ok = hint_sub.is_none_or(|sub| s.user_id.to_string() == sub);
        let login_ok = !login || fresh;
        let max_age_ok = max_age.is_none_or(|m| fresh || now - s.auth_time <= Duration::seconds(m));
        hint_ok && login_ok && max_age_ok
    });
    if usable {
        SessionDecision::UseSession
    } else if none {
        SessionDecision::Fail(CoreError::LoginRequired)
    } else {
        SessionDecision::RequireLogin
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ACR_PWD, AMR_PWD, SecretHash, SessionId, TenantId, UserId};
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-11-25 12:00:00 UTC);

    fn session(auth_time: OffsetDateTime) -> BrowserSession {
        BrowserSession {
            id: SessionId::new_v7(),
            tenant_id: TenantId::new_v7(),
            user_id: UserId::new_v7(),
            token_hash: SecretHash([0; 32]),
            auth_time,
            acr: ACR_PWD.to_owned(),
            amr: vec![AMR_PWD.to_owned()],
            created_at: auth_time,
            last_seen_at: auth_time,
            expires_at: auth_time + Duration::days(1),
            idle_expires_at: auth_time + Duration::hours(1),
            revoked_at: None,
        }
    }

    fn p(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn no_session() {
        assert!(matches!(
            decide(&p(&["none"]), None, None, None, NOW, NOW),
            SessionDecision::Fail(CoreError::LoginRequired)
        ));
        assert!(matches!(
            decide(&[], None, None, None, NOW, NOW),
            SessionDecision::RequireLogin
        ));
    }

    #[test]
    fn session_without_prompt_is_used() {
        let s = session(NOW - Duration::hours(5));
        assert!(matches!(
            decide(&[], None, Some(&s), None, NOW, NOW),
            SessionDecision::UseSession
        ));
        assert!(matches!(
            decide(&p(&["none"]), None, Some(&s), None, NOW, NOW),
            SessionDecision::UseSession
        ));
    }

    #[test]
    fn prompt_login_needs_fresh_auth() {
        let created = NOW - Duration::seconds(30);
        let old = session(created - Duration::seconds(1));
        assert!(matches!(
            decide(&p(&["login"]), None, Some(&old), None, created, NOW),
            SessionDecision::RequireLogin
        ));
        let fresh = session(created);
        assert!(matches!(
            decide(&p(&["login"]), None, Some(&fresh), None, created, NOW),
            SessionDecision::UseSession
        ));
        let later = session(created + Duration::seconds(10));
        assert!(matches!(
            decide(&p(&["login"]), None, Some(&later), None, created, NOW),
            SessionDecision::UseSession
        ));
    }

    #[test]
    fn max_age() {
        let s = session(NOW - Duration::seconds(2));
        assert!(matches!(
            decide(&[], Some(1), Some(&s), None, NOW, NOW),
            SessionDecision::RequireLogin
        ));
        assert!(matches!(
            decide(&[], Some(10_000), Some(&s), None, NOW, NOW),
            SessionDecision::UseSession
        ));
        assert!(matches!(
            decide(&p(&["none"]), Some(1), Some(&s), None, NOW, NOW),
            SessionDecision::Fail(CoreError::LoginRequired)
        ));
    }

    #[test]
    fn max_age_zero_is_satisfied_by_a_login_during_the_request() {
        let created = NOW - Duration::seconds(20);
        let s = session(created + Duration::seconds(5));
        assert!(matches!(
            decide(&[], Some(0), Some(&s), None, created, NOW),
            SessionDecision::UseSession
        ));
        let old = session(created - Duration::seconds(1));
        assert!(matches!(
            decide(&[], Some(0), Some(&old), None, created, NOW),
            SessionDecision::RequireLogin
        ));
    }

    #[test]
    fn id_token_hint_subject() {
        let s = session(NOW - Duration::minutes(1));
        let other = UserId::new_v7().to_string();
        assert!(matches!(
            decide(&p(&["none"]), None, Some(&s), Some(&other), NOW, NOW),
            SessionDecision::Fail(CoreError::LoginRequired)
        ));
        assert!(matches!(
            decide(&[], None, Some(&s), Some(&other), NOW, NOW),
            SessionDecision::RequireLogin
        ));
        let same = s.user_id.to_string();
        assert!(matches!(
            decide(&p(&["none"]), None, Some(&s), Some(&same), NOW, NOW),
            SessionDecision::UseSession
        ));
    }
}
