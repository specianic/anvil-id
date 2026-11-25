//! MFA policy evaluation: effective policy across tenant and client (strictest wins) and the
//! step-up decision for `acr_values` (AUTH-08). Pure functions.
//!
//! Specs: OpenID Connect Core 1.0 §3.1.2.1 (`acr_values`, voluntary), §5.5.1.1 (`acr` as an
//! essential claim); OpenID Connect Unmet Authentication Requirements 1.0
//! (`unmet_authentication_requirements`); RFC 8176 (`amr` values).

use crate::model::{ACR_MFA, ACR_PWD, AMR_MFA, MfaPolicy};

/// The policy in force for a sign-in: the strictest of the tenant's and the client's
/// (`required` > `optional` > `off`). A client without its own policy inherits the tenant's.
/// Phase 6 adds the organization's policy as a third input to the same maximum.
pub fn effective_policy(tenant: MfaPolicy, client: Option<MfaPolicy>) -> MfaPolicy {
    client.map_or(tenant, |c| tenant.max(c))
}

/// How strongly the RP asked for a multi-factor sign-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcrRequest {
    /// [`ACR_MFA`] was not requested.
    None,
    /// [`ACR_MFA`] in `acr_values` (a voluntary claim, Core §3.1.2.1).
    Voluntary,
    /// [`ACR_MFA`] among the values of an essential `acr` claim request (Core §5.5.1.1).
    Essential,
}

/// Classifies the request: `claims_acr_essential` is `Some(values)` when the `claims` parameter
/// asks for `acr` with `essential: true` (`value` or `values`), `None` otherwise.
pub fn acr_request(acr_values: &[String], claims_acr_essential: Option<&[String]>) -> AcrRequest {
    let mfa = |values: &[String]| values.iter().any(|v| v == ACR_MFA);
    if claims_acr_essential.is_some_and(mfa) {
        AcrRequest::Essential
    } else if mfa(acr_values) {
        AcrRequest::Voluntary
    } else {
        AcrRequest::None
    }
}

/// What the login flow must do about a second factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfaRequirement {
    /// Nothing: finish the sign-in.
    None,
    /// Prompt for an enrolled second factor.
    SecondFactor,
    /// The policy requires a second factor the user does not have: enrol one first.
    Enroll,
    /// An essential MFA `acr` cannot be met: answer `unmet_authentication_requirements`.
    Unmet,
}

/// The second-factor decision.
///
/// | Session MFA | Policy | `acr` request | Has factor | Result |
/// |---|---|---|---|---|
/// | yes | any | any | any | `None` |
/// | no | any | any | yes | `SecondFactor`, except `Off` + no request -> `None` |
/// | no | `Required` | any | no | `Enroll` |
/// | no | `Off`/`Optional` | `Essential` | no | `Unmet` |
/// | no | `Off`/`Optional` | `None`/`Voluntary` | no | `None` |
///
/// `Off` + no request never prompts, so users who enrolled TOTP under 0.2 are not asked once
/// the tenant turns MFA off.
pub fn mfa_requirement(
    policy: MfaPolicy,
    acr: AcrRequest,
    session_is_mfa: bool,
    user_has_factor: bool,
) -> MfaRequirement {
    if session_is_mfa {
        return MfaRequirement::None;
    }
    if user_has_factor {
        return match (policy, acr) {
            (MfaPolicy::Off, AcrRequest::None) => MfaRequirement::None,
            _ => MfaRequirement::SecondFactor,
        };
    }
    match (policy, acr) {
        (MfaPolicy::Required, _) => MfaRequirement::Enroll,
        (_, AcrRequest::Essential) => MfaRequirement::Unmet,
        _ => MfaRequirement::None,
    }
}

/// The `acr` for a session's `amr`: [`ACR_MFA`] iff it contains `mfa`, else [`ACR_PWD`].
pub fn acr_for(amr: &[String]) -> &'static str {
    if amr.iter().any(|a| a == AMR_MFA) {
        ACR_MFA
    } else {
        ACR_PWD
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICIES: [MfaPolicy; 3] = [MfaPolicy::Off, MfaPolicy::Optional, MfaPolicy::Required];

    #[test]
    fn effective_policy_is_strictest() {
        use MfaPolicy::{Off, Optional, Required};
        let table = [
            (Off, None, Off),
            (Optional, None, Optional),
            (Required, None, Required),
            (Off, Some(Off), Off),
            (Off, Some(Optional), Optional),
            (Off, Some(Required), Required),
            (Optional, Some(Off), Optional),
            (Optional, Some(Optional), Optional),
            (Optional, Some(Required), Required),
            (Required, Some(Off), Required),
            (Required, Some(Optional), Required),
            (Required, Some(Required), Required),
        ];
        for (tenant, client, expected) in table {
            assert_eq!(
                effective_policy(tenant, client),
                expected,
                "{tenant:?} {client:?}"
            );
        }
    }

    #[test]
    fn effective_policy_never_weakens_tenant() {
        for t in POLICIES {
            for c in POLICIES {
                assert!(effective_policy(t, Some(c)) >= t);
                assert!(effective_policy(t, Some(c)) >= c);
            }
        }
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn acr_request_classification() {
        let mfa = s(&[ACR_MFA]);
        let pwd = s(&[ACR_PWD]);
        assert_eq!(acr_request(&[], None), AcrRequest::None);
        assert_eq!(acr_request(&pwd, None), AcrRequest::None);
        assert_eq!(acr_request(&s(&["urn:other"]), None), AcrRequest::None);
        assert_eq!(acr_request(&mfa, None), AcrRequest::Voluntary);
        assert_eq!(
            acr_request(&s(&[ACR_PWD, ACR_MFA]), None),
            AcrRequest::Voluntary
        );
        assert_eq!(acr_request(&[], Some(&mfa)), AcrRequest::Essential);
        assert_eq!(acr_request(&pwd, Some(&mfa)), AcrRequest::Essential);
        assert_eq!(acr_request(&mfa, Some(&mfa)), AcrRequest::Essential);
        assert_eq!(
            acr_request(&[], Some(&s(&[ACR_PWD, ACR_MFA]))),
            AcrRequest::Essential
        );
        // An essential acr that does not name MFA is satisfied without it.
        assert_eq!(acr_request(&[], Some(&pwd)), AcrRequest::None);
        assert_eq!(acr_request(&[], Some(&[])), AcrRequest::None);
        assert_eq!(acr_request(&mfa, Some(&pwd)), AcrRequest::Voluntary);
        // Exact match only.
        assert_eq!(
            acr_request(
                &s(&["urn:anvilid:acr:MFA"]),
                Some(&s(&[" urn:anvilid:acr:mfa"]))
            ),
            AcrRequest::None
        );
    }

    #[test]
    fn mfa_requirement_full_table() {
        use AcrRequest as A;
        use MfaPolicy::{Off, Optional, Required};
        use MfaRequirement::{Enroll, None as N, SecondFactor as F, Unmet};
        // (policy, acr, session_is_mfa, user_has_factor) -> expected
        let table = [
            // session already MFA: nothing to do
            (Off, A::None, true, true, N),
            (Off, A::None, true, false, N),
            (Off, A::Voluntary, true, true, N),
            (Off, A::Voluntary, true, false, N),
            (Off, A::Essential, true, true, N),
            (Off, A::Essential, true, false, N),
            (Optional, A::None, true, true, N),
            (Optional, A::None, true, false, N),
            (Optional, A::Voluntary, true, true, N),
            (Optional, A::Voluntary, true, false, N),
            (Optional, A::Essential, true, true, N),
            (Optional, A::Essential, true, false, N),
            (Required, A::None, true, true, N),
            (Required, A::None, true, false, N),
            (Required, A::Voluntary, true, true, N),
            (Required, A::Voluntary, true, false, N),
            (Required, A::Essential, true, true, N),
            (Required, A::Essential, true, false, N),
            // Off
            (Off, A::None, false, true, N),
            (Off, A::None, false, false, N),
            (Off, A::Voluntary, false, true, F),
            (Off, A::Voluntary, false, false, N),
            (Off, A::Essential, false, true, F),
            (Off, A::Essential, false, false, Unmet),
            // Optional
            (Optional, A::None, false, true, F),
            (Optional, A::None, false, false, N),
            (Optional, A::Voluntary, false, true, F),
            (Optional, A::Voluntary, false, false, N),
            (Optional, A::Essential, false, true, F),
            (Optional, A::Essential, false, false, Unmet),
            // Required
            (Required, A::None, false, true, F),
            (Required, A::None, false, false, Enroll),
            (Required, A::Voluntary, false, true, F),
            (Required, A::Voluntary, false, false, Enroll),
            (Required, A::Essential, false, true, F),
            (Required, A::Essential, false, false, Enroll),
        ];
        assert_eq!(table.len(), 3 * 3 * 2 * 2);
        for (policy, acr, sess, factor, expected) in table {
            assert_eq!(
                mfa_requirement(policy, acr, sess, factor),
                expected,
                "{policy:?} {acr:?} session_mfa={sess} factor={factor}"
            );
        }
    }

    #[test]
    fn mfa_requirement_never_prompts_without_factor() {
        for p in POLICIES {
            for a in [
                AcrRequest::None,
                AcrRequest::Voluntary,
                AcrRequest::Essential,
            ] {
                for sess in [false, true] {
                    assert_ne!(
                        mfa_requirement(p, a, sess, false),
                        MfaRequirement::SecondFactor
                    );
                    assert_ne!(mfa_requirement(p, a, sess, true), MfaRequirement::Enroll);
                    assert_ne!(mfa_requirement(p, a, sess, true), MfaRequirement::Unmet);
                }
            }
        }
    }

    #[test]
    fn acr_for_amr() {
        assert_eq!(acr_for(&s(&["pwd", "otp", "mfa"])), ACR_MFA);
        assert_eq!(acr_for(&s(&["mfa"])), ACR_MFA);
        assert_eq!(acr_for(&s(&["pwd"])), ACR_PWD);
        assert_eq!(acr_for(&s(&["pwd", "otp"])), ACR_PWD);
        assert_eq!(acr_for(&s(&["fed"])), ACR_PWD);
        assert_eq!(acr_for(&[]), ACR_PWD);
        assert_eq!(acr_for(&s(&["MFA"])), ACR_PWD);
    }
}
