//! Whether an existing browser session can answer an authorization request (OIDC Core §3.1.2.1:
//! `prompt`, `max_age`, `id_token_hint`, `acr_values`; §5.5.1.1 essential `acr`). Pure.
//!
//! # Step-up (AUTH-08)
//!
//! A session that is otherwise usable but single-factor (its `amr` has no `mfa`) is checked
//! against the request's MFA needs ([`MfaContext`]) when the RP asked for
//! [`ACR_MFA`](crate::model::ACR_MFA) (`acr_values` or an essential `acr` claim) or the effective
//! policy is `Required`. [`mfa_requirement`] then decides:
//!
//! | Requirement | `prompt=none` | Decision |
//! |---|---|---|
//! | `None` (voluntary request the user cannot meet) | any | `UseSession` (the lower `acr` is issued truthfully) |
//! | `SecondFactor` / `Enroll` | no | `StepUp` (second factor or enrolment for the session's user, no password) |
//! | `SecondFactor` / `Enroll` | yes | `Fail(UnmetAuthenticationRequirements)` if essential, else `Fail(InteractionRequired)` |
//! | `Unmet` (essential, no factor, policy not `Required`) | any | `Fail(UnmetAuthenticationRequirements)` |
//!
//! Under `Off`/`Optional` without an `acr` request an existing single-factor session is used as
//! it is: `Optional` prompts at sign-in, not on every authorization request.
//!
//! # Account chooser and registration (OIDC-14)
//!
//! `prompt=select_account` with a usable session that was not signed in during this request
//! answers [`SessionDecision::SelectAccount`] (the chooser: continue as the session's user or
//! sign in as someone else). Without a usable session it is `RequireLogin`, as before. After the
//! chooser the caller decides again without `select_account`; after a sign-in during the request
//! the session is fresh, so the chooser is not shown twice.
//!
//! `prompt=create` is answered by the service before [`decide`] (registration page). When the
//! request is resumed, `create` needs a session signed in during the request, like `login`: an
//! older session never answers a request that asked for a new account.

use time::{Duration, OffsetDateTime};

use crate::error::CoreError;
use crate::model::{AuthorizationParams, BrowserSession, MfaPolicy};
use crate::policy::mfa::{AcrRequest, MfaRequirement, acr_for, acr_request, mfa_requirement};

/// The MFA inputs of an authorization request for [`decide`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MfaContext {
    /// Effective policy (strictest of tenant and client, [`crate::policy::mfa::effective_policy`]).
    pub policy: MfaPolicy,
    /// How strongly the RP asked for MFA ([`requested_acr`]).
    pub acr: AcrRequest,
    /// The session's user has a second factor the second-factor step can use (TOTP).
    pub user_has_factor: bool,
}

impl MfaContext {
    /// No MFA needs at all (policy `Off`, nothing requested).
    pub const NONE: Self = Self {
        policy: MfaPolicy::Off,
        acr: AcrRequest::None,
        user_has_factor: false,
    };

    /// Whether a single-factor session must be checked against [`mfa_requirement`].
    pub fn wants_mfa(&self) -> bool {
        self.acr != AcrRequest::None || self.policy == MfaPolicy::Required
    }
}

/// The `acr` request of validated parameters: `acr_values` (voluntary) and an essential `acr`
/// claim in the `claims` parameter (`id_token` or `userinfo` member).
pub fn requested_acr(params: &AuthorizationParams) -> AcrRequest {
    let essential: Option<Vec<String>> = params.claims.as_ref().and_then(|c| {
        let requests: Vec<_> = c
            .id_token
            .iter()
            .chain(c.userinfo.iter())
            .filter(|r| r.name == "acr" && r.essential)
            .collect();
        (!requests.is_empty()).then(|| {
            requests
                .iter()
                .flat_map(|r| r.values.iter().cloned())
                .collect()
        })
    });
    acr_request(&params.acr_values, essential.as_deref())
}

/// Whether the session's `amr` records a multi-factor sign-in.
pub fn session_is_mfa(session: &BrowserSession) -> bool {
    acr_for(&session.amr) == crate::model::ACR_MFA
}

/// Outcome of [`decide`].
#[derive(Debug)]
pub enum SessionDecision {
    /// The session satisfies the request: issue a code.
    UseSession,
    /// The user must sign in (again).
    RequireLogin,
    /// The session's user is signed in but must add a second factor (or enrol one) first: the
    /// login flow starts at that step and upgrades the session in place.
    StepUp,
    /// `prompt=select_account` with a usable session: show the account chooser.
    SelectAccount,
    /// The request cannot be answered without interaction (`prompt=none`): `LoginRequired`.
    Fail(CoreError),
}

/// Decides whether `session` satisfies the request.
///
/// - `prompt=login` (and `prompt=create`): the session is usable only if
///   `auth_time >= request_created_at`, that is, the user signed in during this request. This is
///   what lets `resume` succeed after the forced login.
/// - `max_age`: usable only if `now - auth_time <= max_age`, or if the user signed in during this
///   request (so `max_age=0` behaves like `prompt=login` and cannot loop).
/// - `hint_sub` (the verified `id_token_hint` subject): a different session user is not usable.
/// - Not usable: `Fail(LoginRequired)` with `prompt=none`, else `RequireLogin`.
/// - Usable and `prompt=select_account` without a sign-in during this request: `SelectAccount`
///   (before any step-up: the chooser decides whose session is stepped up).
/// - Usable but single-factor while MFA is wanted: the step-up table in the module docs.
///
/// `prompt=none` combined with other values is rejected earlier, in validation.
pub fn decide(
    prompt: &[String],
    max_age: Option<i64>,
    session: Option<&BrowserSession>,
    hint_sub: Option<&str>,
    request_created_at: OffsetDateTime,
    now: OffsetDateTime,
    mfa: MfaContext,
) -> SessionDecision {
    let none = prompt.iter().any(|p| p == "none");
    let login = prompt.iter().any(|p| p == "login" || p == "create");
    let select = prompt.iter().any(|p| p == "select_account");
    let usable = session.is_some_and(|s| {
        let fresh = s.auth_time >= request_created_at;
        let hint_ok = hint_sub.is_none_or(|sub| s.user_id.to_string() == sub);
        let login_ok = !login || fresh;
        let max_age_ok = max_age.is_none_or(|m| fresh || now - s.auth_time <= Duration::seconds(m));
        hint_ok && login_ok && max_age_ok
    });
    if usable {
        match session {
            Some(s) if select && s.auth_time < request_created_at => SessionDecision::SelectAccount,
            Some(s) if !session_is_mfa(s) && mfa.wants_mfa() => step_up_decision(mfa, none),
            _ => SessionDecision::UseSession,
        }
    } else if none {
        SessionDecision::Fail(CoreError::LoginRequired)
    } else {
        SessionDecision::RequireLogin
    }
}

/// The decision for a usable single-factor session while MFA is wanted.
fn step_up_decision(mfa: MfaContext, prompt_none: bool) -> SessionDecision {
    match mfa_requirement(mfa.policy, mfa.acr, false, mfa.user_has_factor) {
        MfaRequirement::None => SessionDecision::UseSession,
        MfaRequirement::Unmet => SessionDecision::Fail(CoreError::UnmetAuthenticationRequirements),
        MfaRequirement::SecondFactor | MfaRequirement::Enroll if prompt_none => {
            if mfa.acr == AcrRequest::Essential {
                SessionDecision::Fail(CoreError::UnmetAuthenticationRequirements)
            } else {
                SessionDecision::Fail(CoreError::InteractionRequired)
            }
        }
        MfaRequirement::SecondFactor | MfaRequirement::Enroll => SessionDecision::StepUp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ACR_PWD, AMR_PWD, SecretHash, SessionId, TenantId, UserId};
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-11-25 12:00:00 UTC);
    const N: MfaContext = MfaContext::NONE;

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
            ip: None,
            user_agent: None,
        }
    }

    fn p(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn no_session() {
        assert!(matches!(
            decide(&p(&["none"]), None, None, None, NOW, NOW, N),
            SessionDecision::Fail(CoreError::LoginRequired)
        ));
        assert!(matches!(
            decide(&[], None, None, None, NOW, NOW, N),
            SessionDecision::RequireLogin
        ));
    }

    #[test]
    fn session_without_prompt_is_used() {
        let s = session(NOW - Duration::hours(5));
        assert!(matches!(
            decide(&[], None, Some(&s), None, NOW, NOW, N),
            SessionDecision::UseSession
        ));
        assert!(matches!(
            decide(&p(&["none"]), None, Some(&s), None, NOW, NOW, N),
            SessionDecision::UseSession
        ));
    }

    #[test]
    fn prompt_login_needs_fresh_auth() {
        let created = NOW - Duration::seconds(30);
        let old = session(created - Duration::seconds(1));
        assert!(matches!(
            decide(&p(&["login"]), None, Some(&old), None, created, NOW, N),
            SessionDecision::RequireLogin
        ));
        let fresh = session(created);
        assert!(matches!(
            decide(&p(&["login"]), None, Some(&fresh), None, created, NOW, N),
            SessionDecision::UseSession
        ));
        let later = session(created + Duration::seconds(10));
        assert!(matches!(
            decide(&p(&["login"]), None, Some(&later), None, created, NOW, N),
            SessionDecision::UseSession
        ));
    }

    #[test]
    fn max_age() {
        let s = session(NOW - Duration::seconds(2));
        assert!(matches!(
            decide(&[], Some(1), Some(&s), None, NOW, NOW, N),
            SessionDecision::RequireLogin
        ));
        assert!(matches!(
            decide(&[], Some(10_000), Some(&s), None, NOW, NOW, N),
            SessionDecision::UseSession
        ));
        assert!(matches!(
            decide(&p(&["none"]), Some(1), Some(&s), None, NOW, NOW, N),
            SessionDecision::Fail(CoreError::LoginRequired)
        ));
    }

    #[test]
    fn max_age_zero_is_satisfied_by_a_login_during_the_request() {
        let created = NOW - Duration::seconds(20);
        let s = session(created + Duration::seconds(5));
        assert!(matches!(
            decide(&[], Some(0), Some(&s), None, created, NOW, N),
            SessionDecision::UseSession
        ));
        let old = session(created - Duration::seconds(1));
        assert!(matches!(
            decide(&[], Some(0), Some(&old), None, created, NOW, N),
            SessionDecision::RequireLogin
        ));
    }

    #[test]
    fn id_token_hint_subject() {
        let s = session(NOW - Duration::minutes(1));
        let other = UserId::new_v7().to_string();
        assert!(matches!(
            decide(&p(&["none"]), None, Some(&s), Some(&other), NOW, NOW, N),
            SessionDecision::Fail(CoreError::LoginRequired)
        ));
        assert!(matches!(
            decide(&[], None, Some(&s), Some(&other), NOW, NOW, N),
            SessionDecision::RequireLogin
        ));
        let same = s.user_id.to_string();
        assert!(matches!(
            decide(&p(&["none"]), None, Some(&s), Some(&same), NOW, NOW, N),
            SessionDecision::UseSession
        ));
    }

    fn mfa_session(auth_time: OffsetDateTime) -> BrowserSession {
        let mut s = session(auth_time);
        s.acr = crate::model::ACR_MFA.to_owned();
        s.amr = p(&["pwd", "otp", "mfa"]);
        s
    }

    fn ctx(policy: MfaPolicy, acr: AcrRequest, user_has_factor: bool) -> MfaContext {
        MfaContext {
            policy,
            acr,
            user_has_factor,
        }
    }

    #[test]
    fn single_factor_session_with_mfa_requested_steps_up() {
        let s = session(NOW - Duration::minutes(5));
        for policy in [MfaPolicy::Off, MfaPolicy::Optional, MfaPolicy::Required] {
            for acr in [AcrRequest::Voluntary, AcrRequest::Essential] {
                assert!(
                    matches!(
                        decide(&[], None, Some(&s), None, NOW, NOW, ctx(policy, acr, true)),
                        SessionDecision::StepUp
                    ),
                    "{policy:?} {acr:?}"
                );
            }
        }
        // Required without a factor: step up into enrolment.
        assert!(matches!(
            decide(
                &[],
                None,
                Some(&s),
                None,
                NOW,
                NOW,
                ctx(MfaPolicy::Required, AcrRequest::None, false)
            ),
            SessionDecision::StepUp
        ));
    }

    #[test]
    fn mfa_session_never_steps_up() {
        let s = mfa_session(NOW - Duration::minutes(5));
        for policy in [MfaPolicy::Off, MfaPolicy::Optional, MfaPolicy::Required] {
            for acr in [
                AcrRequest::None,
                AcrRequest::Voluntary,
                AcrRequest::Essential,
            ] {
                for f in [false, true] {
                    assert!(matches!(
                        decide(&[], None, Some(&s), None, NOW, NOW, ctx(policy, acr, f)),
                        SessionDecision::UseSession
                    ));
                }
            }
        }
    }

    #[test]
    fn optional_policy_without_request_uses_the_single_factor_session() {
        let s = session(NOW - Duration::minutes(5));
        for policy in [MfaPolicy::Off, MfaPolicy::Optional] {
            assert!(matches!(
                decide(
                    &[],
                    None,
                    Some(&s),
                    None,
                    NOW,
                    NOW,
                    ctx(policy, AcrRequest::None, true)
                ),
                SessionDecision::UseSession
            ));
        }
    }

    #[test]
    fn voluntary_unmet_uses_the_session_essential_unmet_fails() {
        let s = session(NOW - Duration::minutes(5));
        assert!(matches!(
            decide(
                &[],
                None,
                Some(&s),
                None,
                NOW,
                NOW,
                ctx(MfaPolicy::Optional, AcrRequest::Voluntary, false)
            ),
            SessionDecision::UseSession
        ));
        assert!(matches!(
            decide(
                &[],
                None,
                Some(&s),
                None,
                NOW,
                NOW,
                ctx(MfaPolicy::Optional, AcrRequest::Essential, false)
            ),
            SessionDecision::Fail(CoreError::UnmetAuthenticationRequirements)
        ));
    }

    #[test]
    fn prompt_none_never_steps_up() {
        let s = session(NOW - Duration::minutes(5));
        let none = p(&["none"]);
        assert!(matches!(
            decide(
                &none,
                None,
                Some(&s),
                None,
                NOW,
                NOW,
                ctx(MfaPolicy::Optional, AcrRequest::Voluntary, true)
            ),
            SessionDecision::Fail(CoreError::InteractionRequired)
        ));
        assert!(matches!(
            decide(
                &none,
                None,
                Some(&s),
                None,
                NOW,
                NOW,
                ctx(MfaPolicy::Optional, AcrRequest::Essential, true)
            ),
            SessionDecision::Fail(CoreError::UnmetAuthenticationRequirements)
        ));
        assert!(matches!(
            decide(
                &none,
                None,
                Some(&s),
                None,
                NOW,
                NOW,
                ctx(MfaPolicy::Required, AcrRequest::None, false)
            ),
            SessionDecision::Fail(CoreError::InteractionRequired)
        ));
    }

    #[test]
    fn an_unusable_session_requires_login_before_any_step_up() {
        // prompt=login with an old session: the full sign-in (which applies the policy) wins.
        let created = NOW - Duration::seconds(30);
        let old = session(created - Duration::seconds(1));
        assert!(matches!(
            decide(
                &p(&["login"]),
                None,
                Some(&old),
                None,
                created,
                NOW,
                ctx(MfaPolicy::Optional, AcrRequest::Voluntary, true)
            ),
            SessionDecision::RequireLogin
        ));
        // max_age exceeded: the same.
        assert!(matches!(
            decide(
                &[],
                Some(1),
                Some(&old),
                None,
                created,
                NOW,
                ctx(MfaPolicy::Optional, AcrRequest::Voluntary, true)
            ),
            SessionDecision::RequireLogin
        ));
    }

    #[test]
    fn select_account_with_a_session_shows_the_chooser() {
        let s = session(NOW - Duration::hours(1));
        assert!(matches!(
            decide(&p(&["select_account"]), None, Some(&s), None, NOW, NOW, N),
            SessionDecision::SelectAccount
        ));
        // Combined with consent or login-satisfied max_age: still the chooser first.
        assert!(matches!(
            decide(
                &p(&["select_account", "consent"]),
                Some(10_000),
                Some(&s),
                None,
                NOW,
                NOW,
                N
            ),
            SessionDecision::SelectAccount
        ));
        // The chooser comes before a step-up: it decides whose session is stepped up.
        assert!(matches!(
            decide(
                &p(&["select_account"]),
                None,
                Some(&s),
                None,
                NOW,
                NOW,
                ctx(MfaPolicy::Required, AcrRequest::Voluntary, true)
            ),
            SessionDecision::SelectAccount
        ));
    }

    #[test]
    fn select_account_without_a_usable_session_requires_login() {
        assert!(matches!(
            decide(&p(&["select_account"]), None, None, None, NOW, NOW, N),
            SessionDecision::RequireLogin
        ));
        let old = session(NOW - Duration::hours(1));
        assert!(matches!(
            decide(
                &p(&["select_account"]),
                Some(1),
                Some(&old),
                None,
                NOW,
                NOW,
                N
            ),
            SessionDecision::RequireLogin
        ));
        let other = UserId::new_v7().to_string();
        assert!(matches!(
            decide(
                &p(&["select_account"]),
                None,
                Some(&old),
                Some(&other),
                NOW,
                NOW,
                N
            ),
            SessionDecision::RequireLogin
        ));
    }

    #[test]
    fn select_account_is_satisfied_by_a_sign_in_during_the_request() {
        let created = NOW - Duration::seconds(30);
        let fresh = session(created + Duration::seconds(5));
        assert!(matches!(
            decide(
                &p(&["select_account"]),
                None,
                Some(&fresh),
                None,
                created,
                NOW,
                N
            ),
            SessionDecision::UseSession
        ));
        // A fresh single-factor session still steps up when MFA is wanted.
        assert!(matches!(
            decide(
                &p(&["select_account"]),
                None,
                Some(&fresh),
                None,
                created,
                NOW,
                ctx(MfaPolicy::Optional, AcrRequest::Voluntary, true)
            ),
            SessionDecision::StepUp
        ));
    }

    #[test]
    fn create_needs_a_sign_in_during_the_request() {
        let created = NOW - Duration::seconds(30);
        let old = session(created - Duration::seconds(1));
        assert!(matches!(
            decide(&p(&["create"]), None, Some(&old), None, created, NOW, N),
            SessionDecision::RequireLogin
        ));
        let fresh = session(created + Duration::seconds(3));
        assert!(matches!(
            decide(&p(&["create"]), None, Some(&fresh), None, created, NOW, N),
            SessionDecision::UseSession
        ));
        assert!(matches!(
            decide(&p(&["create"]), None, None, None, created, NOW, N),
            SessionDecision::RequireLogin
        ));
    }

    #[test]
    fn requested_acr_reads_acr_values_and_essential_claims() {
        use crate::model::{ACR_MFA, ClaimsRequest, RequestedClaim};
        use crate::oauth::response_mode::ResponseMode;
        let mut params = AuthorizationParams {
            redirect_uri: "https://rp/cb".into(),
            scope: "openid".into(),
            state: None,
            nonce: None,
            code_challenge: None,
            prompt: vec![],
            max_age: None,
            login_hint: None,
            acr_values: vec![],
            ui_locales: None,
            claims: None,
            response_mode: ResponseMode::Query,
            resource: vec![],
        };
        assert_eq!(requested_acr(&params), AcrRequest::None);
        params.acr_values = vec![ACR_MFA.into()];
        assert_eq!(requested_acr(&params), AcrRequest::Voluntary);
        let claim = |essential: bool, values: &[&str]| RequestedClaim {
            name: "acr".into(),
            essential,
            values: values.iter().map(|v| (*v).to_owned()).collect(),
        };
        params.acr_values = vec![];
        params.claims = Some(ClaimsRequest {
            userinfo: vec![],
            id_token: vec![claim(true, &[ACR_MFA])],
        });
        assert_eq!(requested_acr(&params), AcrRequest::Essential);
        params.claims = Some(ClaimsRequest {
            userinfo: vec![],
            id_token: vec![claim(false, &[ACR_MFA])],
        });
        assert_eq!(requested_acr(&params), AcrRequest::None);
        params.claims = Some(ClaimsRequest {
            userinfo: vec![claim(true, &[ACR_MFA])],
            id_token: vec![],
        });
        assert_eq!(requested_acr(&params), AcrRequest::Essential);
    }
}
